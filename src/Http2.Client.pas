/// Public HTTP/2 client API: factory, IHttpClient, requests, responses,
/// connection pool and lease acquisition (plan S09).
// - this unit is part of the http2client project (see doc/design/client-api.md,
//   doc/design/messages.md, doc/design/transport.md "Connection lifecycle").
// - Send blocks only until the response status + HEADERS are decoded; the body
//   is streamed lazily through IHttpResponse.Body (doc/design/messages.md).
// - a connection-scoped HPACK encoder/decoder pair lives on each pooled
//   connection (doc/design/protocol.md "HPACK"). doc/design/transport.md
//   sanctions guarding codec use with the connection's critical section, so a
//   pooled connection serializes lease acquisition and body decoding; the
//   connection thread still multiplexes socket I/O across streams.
unit Http2.Client;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, SyncObjs, Generics.Collections, TypInfo,
  Http2.Errors, Http2.Frames, Http2.Headers, Http2.Hpack,
  Http2.Tls, Http2.Connection, Http2.Stream, Http2.Observer, Http2.Messages;

const
  /// documented factory defaults (doc/design/client-api.md "HttpClientFactory")
  cDefaultMaxConnections          = 4;
  cDefaultMaxStreamsPerConnection = 100;
  cDefaultFollowRedirects         = True;
  cDefaultMaxRedirects            = 10;
  cDefaultConnectTimeoutMs        = 10000;
  cDefaultHeaderTimeoutMs         = 30000;
  cDefaultIdleTimeoutMs           = 60000;
  /// the default TLS port; omitted from :authority when the URL port matches
  cDefaultHttpsPort               = 443;
  /// transparent retries allowed for an idempotent request on a refused stream
  cMaxTransparentRetries          = 2;
  /// a cancellable wait polls its token in slices of this many milliseconds
  cCancelPollSliceMs              = 20;
  /// default for the HTTP/1.1 ALPN fallback (doc/design/fallback.md)
  cDefaultHttp1Fallback           = False;

type
  /// how the client treats a cleartext ("http") origin (doc/design/
  /// fallback.md "Factory surface").  ctReject is the default: a cleartext
  /// request raises instead of silently sending bytes in the clear.
  TClearTextPolicy = (ctReject, ctPriorKnowledge, ctUpgrade);

  THttpResponse = class;

  /// dials the transport for one origin. Injected so pool tests need no real
  /// sockets (doc/design/client-api.md "Lease acquisition").
  IHttp2SocketFactory = interface
    function Dial(const AHost: string; const APort: Word;
      const ATimeoutMs: Integer): IHttp2Socket;
  end;

  /// cooperative cancellation for an in-flight Send (plan S10 task 10.8).
  /// Pass one via THttpRequest.WithCancelToken; when it flips to cancelled the
  /// stream is reset with RST_STREAM(CANCEL) and the lease released.
  ICancellationToken = interface
    ['{6B1C2D3E-4F50-4A61-9C72-0000000000C1}']
    function IsCancelled: Boolean;
  end;

  /// the default thread-safe token: Cancel() may be called from any thread
  TCancellationToken = class(TInterfacedObject, ICancellationToken)
  private
    FLock: TCriticalSection;
    FCancelled: Boolean;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Cancel;
    function IsCancelled: Boolean;
  end;

  /// the production factory: TCP then TLS handshake offering ALPN "h2"
  TDefaultSocketFactory = class(TInterfacedObject, IHttp2SocketFactory)
  private
    FCACertFile: string;
    FInsecure: Boolean;
  public
    constructor Create(const ACACertFile: string = '';
      const AInsecure: Boolean = False);
    function Dial(const AHost: string; const APort: Word;
      const ATimeoutMs: Integer): IHttp2Socket;
  end;

  /// an HTTP/2 response. Pseudo-headers
  /// are surfaced through StatusCode, not through Headers.
  // IHttpResponse moved to Http2.Messages.pas so a second codec (the HTTP/1.1
  // fallback) can implement it without depending on this unit (plan S13).

  /// a request built by the public fluent API (doc/design/messages.md
  /// "HttpRequest"). Pseudo-header mapping happens in ToStreamRequest.
  THttpRequest = record
  private
    FMethod: THttpMethod;
    FMethodOverride: string;   // extension verbs, uppercase token
    FUrl: string;
    FHeaders: IHttpHeaders;
    FBody: THttpBody;
    FBodyWriter: IBodyWriter;
    FCancelToken: ICancellationToken;
    FHeaderTimeoutMs: Integer; // per-request override; 0 = factory default
    function GetMethodToken: string;
    function GetAuthority: string;
    function GetPath: string;
  public
    class function Create(const AMethod: THttpMethod;
      const AUrl: string): THttpRequest; static;
    function WithMethod(const AMethod: THttpMethod): THttpRequest;
    /// escape hatch for extension verbs; the token is validated and uppercased
    function WithMethodToken(const AToken: string): THttpRequest;
    function WithHeader(const AName, AValue: string): THttpRequest;
    function WithBody(const ABody: THttpBody): THttpRequest;
    function WithBodyWriter(const AWriter: IBodyWriter): THttpRequest;
    /// attach a cancellation token; cancelling it resets the stream in flight
    function WithCancelToken(const AToken: ICancellationToken): THttpRequest;
    /// override the factory HeaderTimeoutMs for this request (0 = default)
    function WithTimeout(const AMs: Integer): THttpRequest;
    /// re-target the request at AUrl (used by the redirect loop)
    function WithUrl(const AUrl: string): THttpRequest;
    /// drop any request body (used when a redirect rewrites the method)
    function DropBody: THttpRequest;
    /// bridge to the S08 wire record: pseudo-header mapping at encode time
    function ToStreamRequest: TStreamRequest;

    function Url: string;
    function Method: THttpMethod;
    function Headers: IHttpHeaders;
    function Body: THttpBody;
    function BodyWriter: IBodyWriter;
    /// the uppercase wire method token (:method)
    property MethodToken: string read GetMethodToken;
    /// host[:port] with the default port omitted (:authority)
    property Authority: string read GetAuthority;
    /// path + query, '/' when empty (:path)
    property Path: string read GetPath;
    /// the cancellation token (nil when none was supplied)
    property CancelToken: ICancellationToken read FCancelToken;
    /// this request's header timeout in ms; 0 means "use the factory default"
    property HeaderTimeoutMs: Integer read FHeaderTimeoutMs;
  end;

  /// the public client: Send blocks until status + headers; Close drains
  IHttpClient = interface
    ['{6B1C2D3E-4F50-4A61-9C72-000000000001}']
    function Send(const ARequest: THttpRequest): IHttpResponse;
    procedure Close;
  end;

  /// the pure value builder (doc/design/client-api.md "HttpClientFactory").
  /// Every WithX returns a NEW record with one field changed, so a stored
  /// factory can be reused and forked without shared mutable state.
  THttpClientFactory = record
  private
    FMaxConnections: Integer;
    FMaxStreamsPerConnection: Integer;
    FFollowRedirects: Boolean;
    FMaxRedirects: Integer;
    FConnectTimeoutMs: Integer;
    FHeaderTimeoutMs: Integer;
    FIdleTimeoutMs: Integer;
    FProxyHost: string;
    FProxyPort: Word;
    FSocketFactory: IHttp2SocketFactory;
    FCACertFile: string;
    FInsecure: Boolean;
    FObserver: IHttp2Observer;
    FHttp1Fallback: Boolean;
    FClearTextPolicy: TClearTextPolicy;
  public
    class function Create: THttpClientFactory; static;
    function WithMaxConnections(const AMax: Integer): THttpClientFactory;
    function WithMaxStreamsPerConnection(const AMax: Integer): THttpClientFactory;
    function WithFollowRedirects(const AFollow: Boolean): THttpClientFactory;
    function WithMaxRedirects(const AMax: Integer): THttpClientFactory;
    function WithProxy(const AHost: string; const APort: Word): THttpClientFactory;
    /// the connect/header/idle deadlines are factory defaults
    function WithConnectTimeout(const AMs: Integer): THttpClientFactory;
    function WithHeaderTimeout(const AMs: Integer): THttpClientFactory;
    function WithIdleTimeout(const AMs: Integer): THttpClientFactory;
    /// test seam: inject the transport factory (no real sockets)
    function WithSocketFactory(const AFactory: IHttp2SocketFactory): THttpClientFactory;
    /// PEM bundle used to verify the peer's certificate; '' = system trust
    /// store. Needed whenever the origin uses a private CA.
    function WithCACertFile(const AFileName: string): THttpClientFactory;
    /// disable peer certificate verification. Dangerous, intended for test
    /// harnesses whose cert has no SAN (e.g. the h2 conformance harness,
    /// which self-signs with CN=localhost only).
    function WithInsecureTls(const AInsecure: Boolean = True): THttpClientFactory;
    /// offer "http/1.1" as an ALPN alternative and accept an HTTP/1.1
    /// response when the peer does not select "h2" (doc/design/fallback.md).
    /// Off by default: strict mode keeps failing loudly (interop A.9).
    function WithHttp1Fallback(const AEnable: Boolean = True): THttpClientFactory;
    /// select the cleartext policy for "http" origins.  The default ctReject
    /// raises EHttpProtocolError; ctPriorKnowledge speaks HTTP/2 at once;
    /// ctUpgrade tries the HTTP/1.1 Upgrade dance first (doc/design/fallback.md).
    function WithClearText(const APolicy: TClearTextPolicy): THttpClientFactory;
    /// observability seam: every connection opened by Build reports its
    /// connection/stream/frame events to AObserver (doc/design/
    /// testing-observability.md). Nil disables observation.
    function WithObserver(const AObserver: IHttp2Observer): THttpClientFactory;
    function Build: IHttpClient;

    property MaxConnections: Integer read FMaxConnections;
    property MaxStreamsPerConnection: Integer read FMaxStreamsPerConnection;
    property FollowRedirects: Boolean read FFollowRedirects;
    property MaxRedirects: Integer read FMaxRedirects;
    property ConnectTimeoutMs: Integer read FConnectTimeoutMs;
    property HeaderTimeoutMs: Integer read FHeaderTimeoutMs;
    property IdleTimeoutMs: Integer read FIdleTimeoutMs;
    property ProxyHost: string read FProxyHost;
    property ProxyPort: Word read FProxyPort;
    property CACertFile: string read FCACertFile;
    property InsecureTls: Boolean read FInsecure;
    property Observer: IHttp2Observer read FObserver;
    property Http1Fallback: Boolean read FHttp1Fallback;
    property ClearTextPolicy: TClearTextPolicy read FClearTextPolicy;
  end;

  /// one pooled connection, exposed as an interface so an outstanding response
  /// can keep it (and its TConnection) alive after the pool releases it.
  IPooledConnection = interface
    function ActiveStreams: Integer;
    /// eligible = open(ing) and below the per-connection stream cap
    function Eligible: Boolean;
    /// register a lease under the connection lock and block until response
    /// HEADERS are decoded. AAcquired is False when the connection became
    /// ineligible, so the pool retries with another connection.
    function Acquire(const ARequest: TStreamRequest;
      const ATimeoutMs: Integer; out AAcquired: Boolean): IHttpResponse;
    /// stop accepting new leases; close now when idle, else when the last
    /// outstanding body is released
    procedure Drain;
    /// close a drained connection once its last stream is gone (called when a
    /// response body is released)
    procedure ReleaseIfIdle;
    function GetConn: TConnection;
    function GetOrigin: string;
    function GetLock: TCriticalSection;
    property Conn: TConnection read GetConn;
    property Origin: string read GetOrigin;
    property Lock: TCriticalSection read GetLock;
  end;

  /// IHttpBodyStream facade over a lease body that holds the pooled
  /// connection's critical section, serializing HPACK decode across streams
  TGuardedBody = class(TInterfacedObject, IHttpBodyStream)
  private
    FInner: IHttpBodyStream;
    FLock: TCriticalSection;
  public
    constructor Create(const AInner: IHttpBodyStream;
      const ALock: TCriticalSection);
    function Read(var ABuffer; const ACount: LongInt): LongInt;
    function Eof: Boolean;
  end;

  /// the concrete response: typed status/headers plus a streamed body. It
  /// holds the pooled connection by interface so the underlying TConnection
  /// outlives the pool release while the body is still being read.
  THttpResponse = class(TInterfacedObject, IHttpResponse)
  private
    FLease: TStreamLease;
    FKeepAlive: IConnectionStream;   // keeps the lease alive after unregister
    FConnRef: IPooledConnection;     // keeps the TConnection alive
    FHeaders: IHttpHeaders;
    FBody: IHttpBodyStream;
    function GetStatusCode: LongInt;
    function GetHeaders: IHttpHeaders;
    function GetBody: IHttpBodyStream;
    function GetStreamId: LongWord;
  public
    constructor Create(const ALease: TStreamLease;
      const AKeepAlive: IConnectionStream; const AConnRef: IPooledConnection);
    destructor Destroy; override;
    /// the wire stream id (test seam)
    property StreamId: LongWord read GetStreamId;
  end;

  /// one pooled connection: the live TConnection plus its connection-scoped
  /// HPACK pair, stream-id allocator and a lock serializing codec access.
  THttpConnection = class(TInterfacedObject, IPooledConnection)
  private
    FConn: TConnection;
    FEncoder: THpackCodec;
    FDecoder: THpackCodec;
    FAllocator: TStreamIdAllocator;
    FLock: TCriticalSection;
    FOrigin: string;
    FMaxStreamsPerConnection: Integer;
    FClosing: Boolean;
    procedure MaybeClose;
  public
    constructor Create(const AConn: TConnection; const AOrigin: string;
      const AMaxStreamsPerConnection: Integer);
    destructor Destroy; override;
    function ActiveStreams: Integer;
    function Eligible: Boolean;
    function Acquire(const ARequest: TStreamRequest;
      const ATimeoutMs: Integer; out AAcquired: Boolean): IHttpResponse;
    /// acquire with a cancellation token: polls the lease wait so a cancel
    /// posts RST_STREAM(CANCEL) and releases the lease before returning
    function AcquireCancellable(const ARequest: TStreamRequest;
      const ATimeoutMs: Integer; const AToken: ICancellationToken;
      out AAcquired: Boolean): IHttpResponse;
    procedure Drain;
    procedure ReleaseIfIdle;
    function GetConn: TConnection;
    function GetOrigin: string;
    function GetLock: TCriticalSection;
  end;

  /// the connection pool (doc/design/client-api.md "Lease acquisition"):
  /// a TDictionary<string,TList<IPooledConnection>> guarded by a critical
  /// section, with a global MaxConnections cap and per-origin reuse.
  TConnectionPool = class
  private
    FLock: TCriticalSection;
    FByOrigin: TDictionary<string, TList<IPooledConnection>>;
    FFactory: IHttp2SocketFactory;
    FMaxConnections: Integer;
    FMaxStreamsPerConnection: Integer;
    FConnectTimeoutMs: Integer;
    FHeaderTimeoutMs: Integer;
    FIdleTimeoutMs: Integer;
    FTotalConnections: Integer;
    FClosed: Boolean;
    FObserver: IHttp2Observer;
    /// last time a pooled connection was used, keyed by its TConnection
    FIdleSince: TDictionary<Pointer, QWord>;
    procedure ReapClosed;
    procedure ReapIdleLocked;
    procedure MarkUsed(const C: IPooledConnection);
    function ListFor(const AOrigin: string): TList<IPooledConnection>;
    function OpenConnection(const AOrigin, AHost: string;
      const APort: Word): IPooledConnection;
    function PickEligible(const AOrigin: string): IPooledConnection;
    function CanOpenNew: Boolean;
  public
    constructor Create(const AFactory: IHttp2SocketFactory; const AMaxConnections,
      AMaxStreamsPerConnection, AConnectTimeoutMs, AHeaderTimeoutMs,
      AIdleTimeoutMs: Integer; const AObserver: IHttp2Observer = nil);
    destructor Destroy; override;
    /// acquire a lease on the least-loaded eligible connection, opening a new
    /// one or waiting for a slot per doc/design/client-api.md. When AToken is
    /// non-nil the wait is cancellable (plan S10 task 10.8).
    function Acquire(const AOrigin, AHost: string; const APort: Word;
      const ARequest: TStreamRequest; const AHeaderTimeoutMs: Integer;
      const AToken: ICancellationToken = nil): IHttpResponse;
    /// close and remove connections idle for longer than IdleTimeoutMs, so
    /// the pool stays within MaxConnections (plan S10 task 10.7).
    procedure ReapIdle;
    procedure Close;
    // test seams
    function ConnectionCount: Integer;
    function ConnectionCountForOrigin(const AOrigin: string): Integer;
    function ActiveStreamsForOrigin(const AOrigin: string): TArray<Integer>;
    /// choose the least-loaded eligible connection for AOrigin (test seam)
    function PickForTest(const AOrigin: string): IPooledConnection;
    /// add an externally-built connection under AOrigin (test seam)
    procedure AddForTest(const AOrigin: string;
      const AConn: IPooledConnection);
  end;

  /// the concrete client returned by THttpClientFactory.Build
  THttpClient = class(TInterfacedObject, IHttpClient)
  private
    FPool: TConnectionPool;
    FHeaderTimeoutMs: Integer;
    FFollowRedirects: Boolean;
    FMaxRedirects: Integer;
    FClosed: Boolean;
    FLock: TCriticalSection;
    FHttp1Fallback: Boolean;
    FClearTextPolicy: TClearTextPolicy;
    function SendOnce(const ARequest: THttpRequest): IHttpResponse;
  public
    constructor Create(const AFactory: IHttp2SocketFactory;
      const AMaxConnections, AMaxStreamsPerConnection: Integer;
      const AFollowRedirects: Boolean; const AMaxRedirects,
      AConnectTimeoutMs, AHeaderTimeoutMs, AIdleTimeoutMs: Integer;
      const AObserver: IHttp2Observer = nil;
      const AHttp1Fallback: Boolean = False;
      const AClearTextPolicy: TClearTextPolicy = ctReject);
    destructor Destroy; override;
    function Send(const ARequest: THttpRequest): IHttpResponse;
    procedure Close;
    /// the pool (test seam)
    property Pool: TConnectionPool read FPool;
  end;

  /// reads a whole response body and decodes it to T. Under {$mode delphi} a
  /// class-level generic compiles (doc/design/messages.md "Syntax note").
  TResponseReader<T> = class(TInterfacedObject, IResponseReader<T>)
  public
    function Read(const AResponse: IHttpResponse): T; overload;
    class procedure Read(const AResponse: IHttpResponse;
      out AValue: T); overload; static;
  end;

  /// pointer used by TResponseReader<T> to store a dynamic-array result
  PBytesValue = ^TBytes;

/// split a URL into host, port and path+query; default port is 443 (TLS)
procedure ParseHttpUrl(const AUrl: string; out AHost: string; out APort: Word;
  out APath: string);

/// origin key = host[:port] with the default port omitted (doc/design). A
/// non-https URL is prefixed with its scheme so an http redirect target cannot
/// share a pooled https connection (plan S10 task 10.4).
function OriginOfUrl(const AUrl: string): string;

/// lowercased scheme of AUrl ('https' when the URL carries none)
function SchemeOfUrl(const AUrl: string): string;

/// resolve a redirect Location against the URL that produced it: absolute,
/// protocol-relative, root-relative or path-relative (plan S10 task 10.1)
function ResolveLocation(const ABaseUrl, ALocation: string): string;

/// read a response body to EOF into a byte array (used by TResponseReader<T>)
function ReadAllBodyBytes(const ABody: IHttpBodyStream): TBytes;

{ ---- implementation ---- }

implementation

const
  cTokenChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' +
                '0123456789!#$%&''*+-.^_`|~';

function HttpMethodTokenOf(const AMethod: THttpMethod): string;
begin
  case AMethod of
    hmGet:     Result := 'GET';
    hmHead:    Result := 'HEAD';
    hmPost:    Result := 'POST';
    hmPut:     Result := 'PUT';
    hmDelete:  Result := 'DELETE';
    hmConnect: Result := 'CONNECT';
    hmOptions: Result := 'OPTIONS';
    hmTrace:   Result := 'TRACE';
    hmPatch:   Result := 'PATCH';
  else
    Result := 'GET';
  end;
end;

function IsValidMethodToken(const AToken: string): Boolean;
var
  I: Integer;
begin
  if AToken = '' then
    Exit(False);
  for I := 1 to Length(AToken) do
    if Pos(AToken[I], cTokenChars) = 0 then
      Exit(False);
  Result := True;
end;

procedure ParseHttpUrl(const AUrl: string; out AHost: string; out APort: Word;
  out APath: string);
var
  Rest, AuthorityPart, PathPart, PortStr: string;
  P, Colon: Integer;
  Port: LongInt;
begin
  AHost := '';
  APort := cDefaultHttpsPort;
  APath := '/';
  Rest := AUrl;
  P := Pos('://', Rest);
  if P > 0 then
    Rest := Copy(Rest, P + 3, Length(Rest));    // drop "scheme://"
  PathPart := '';
  P := Pos('/', Rest);
  Colon := Pos('?', Rest);
  if (P > 0) and ((Colon = 0) or (P < Colon)) then
  begin
    AuthorityPart := Copy(Rest, 1, P - 1);
    PathPart := Copy(Rest, P, Length(Rest));
  end
  else if Colon > 0 then
  begin
    AuthorityPart := Copy(Rest, 1, Colon - 1);
    PathPart := Copy(Rest, Colon, Length(Rest));
  end
  else
    AuthorityPart := Rest;

  Colon := Pos(':', AuthorityPart);
  if Colon > 0 then
  begin
    AHost := Copy(AuthorityPart, 1, Colon - 1);
    PortStr := Copy(AuthorityPart, Colon + 1, Length(AuthorityPart));
    Port := StrToIntDef(PortStr, cDefaultHttpsPort);
    if (Port <= 0) or (Port > 65535) then
      raise EHttpProtocolError.Create('invalid URL port: ' + PortStr,
        ecProtocolError);
    APort := Word(Port);
  end
  else
    AHost := AuthorityPart;

  if PathPart <> '' then
    APath := PathPart;
end;

function SchemeOfUrl(const AUrl: string): string;
var
  P: Integer;
begin
  P := Pos('://', AUrl);
  if P > 0 then
    Result := LowerCase(Copy(AUrl, 1, P - 1))
  else
    Result := 'https';
end;

function OriginOfUrl(const AUrl: string): string;
var
  Host, Path, Scheme: string;
  Port: Word;
begin
  ParseHttpUrl(AUrl, Host, Port, Path);
  if Port = cDefaultHttpsPort then
    Result := Host
  else
    Result := Host + ':' + IntToStr(Port);
  // a different scheme is a different origin even on the same host:port, so
  // an http redirect target never reuses a pooled https connection
  Scheme := SchemeOfUrl(AUrl);
  if Scheme <> 'https' then
    Result := Scheme + '://' + Result;
end;

function ResolveLocation(const ABaseUrl, ALocation: string): string;
var
  Base, Prefix, Rest, Path, Dir: string;
  P, Cut: Integer;
begin
  if ALocation = '' then
    Exit('');
  if Pos('://', ALocation) > 0 then
    Exit(ALocation);
  if Copy(ALocation, 1, 2) = '//' then
    Exit(SchemeOfUrl(ABaseUrl) + ':' + ALocation);

  Base := ABaseUrl;
  P := Pos('://', Base);
  if P > 0 then
    Prefix := Copy(Base, 1, P + 2)     // 'scheme://'
  else
    Prefix := 'https://';
  Rest := Copy(Base, Length(Prefix) + 1, Length(Base));  // authority + path

  // authority ends at the first '/' or '?'
  P := Pos('/', Rest);
  Cut := Pos('?', Rest);
  if (Cut > 0) and ((P = 0) or (Cut < P)) then
    P := Cut;
  if P = 0 then
  begin
    // no path at all: the base directory is the root
    if Copy(ALocation, 1, 1) <> '/' then
      Exit(Prefix + Rest + '/' + ALocation);
    Exit(Prefix + Rest + ALocation);
  end;

  Path := Copy(Rest, P, Length(Rest));   // '/...' incl. any query
  Cut := Pos('?', Path);
  if Cut > 0 then
    Path := Copy(Path, 1, Cut - 1);      // drop the base query

  if Copy(ALocation, 1, 1) = '/' then
    Exit(Prefix + Copy(Rest, 1, P - 1) + ALocation);

  // path-relative: drop the final path segment (RFC 3986 merge). A base with
  // a query but no path merges at the root.
  if Path = '' then
    Dir := '/'
  else
  begin
    Cut := Length(Path);
    while (Cut > 1) and (Path[Cut] <> '/') do
      Dec(Cut);
    Dir := Copy(Path, 1, Cut);
  end;
  Result := Prefix + Copy(Rest, 1, P - 1) + Dir + ALocation;
end;

function ReadAllBodyBytes(const ABody: IHttpBodyStream): TBytes;
var
  Buf: array[0..4095] of Byte;
  N, Total: Integer;
begin
  Result := nil;
  Total := 0;
  while True do
  begin
    N := ABody.Read(Buf, SizeOf(Buf));
    if N <= 0 then
      Break;
    SetLength(Result, Total + N);
    Move(Buf[0], Result[Total], N);
    Inc(Total, N);
  end;
end;

function HttpMethodIsIdempotent(const AToken: string): Boolean;
begin
  Result := (AToken = 'GET') or (AToken = 'HEAD') or (AToken = 'PUT') or
    (AToken = 'DELETE') or (AToken = 'OPTIONS') or (AToken = 'TRACE');
end;

function HttpStatusIsRedirect(const AStatus: LongInt): Boolean;
begin
  Result := (AStatus = 301) or (AStatus = 302) or (AStatus = 303) or
    (AStatus = 307) or (AStatus = 308);
end;

{ TCancellationToken }

constructor TCancellationToken.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FCancelled := False;
end;

destructor TCancellationToken.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

procedure TCancellationToken.Cancel;
begin
  FLock.Acquire;
  try
    FCancelled := True;
  finally
    FLock.Release;
  end;
end;

function TCancellationToken.IsCancelled: Boolean;
begin
  FLock.Acquire;
  try
    Result := FCancelled;
  finally
    FLock.Release;
  end;
end;

{ IHttp2SocketFactory }

constructor TDefaultSocketFactory.Create(const ACACertFile: string;
  const AInsecure: Boolean);
begin
  inherited Create;
  FCACertFile := ACACertFile;
  FInsecure := AInsecure;
end;

function TDefaultSocketFactory.Dial(const AHost: string; const APort: Word;
  const ATimeoutMs: Integer): IHttp2Socket;
begin
  Result := TTlsSocket.Dial(AHost, APort, FInsecure, ATimeoutMs, FCACertFile);
end;

{ THttpRequest }

class function THttpRequest.Create(const AMethod: THttpMethod;
  const AUrl: string): THttpRequest;
begin
  Result.FMethod := AMethod;
  Result.FMethodOverride := '';
  Result.FUrl := AUrl;
  Result.FHeaders := NewHttpHeaders;
  Result.FBody := Default(THttpBody);
  Result.FBodyWriter := nil;
  Result.FCancelToken := nil;
  Result.FHeaderTimeoutMs := 0;
end;

function THttpRequest.GetMethodToken: string;
begin
  if FMethodOverride <> '' then
    Result := FMethodOverride
  else
    Result := HttpMethodTokenOf(FMethod);
end;

function THttpRequest.GetAuthority: string;
var
  Host, Path: string;
  Port: Word;
begin
  ParseHttpUrl(FUrl, Host, Port, Path);
  if Port = cDefaultHttpsPort then
    Result := Host
  else
    Result := Host + ':' + IntToStr(Port);
end;

function THttpRequest.GetPath: string;
var
  Host: string;
  Port: Word;
begin
  ParseHttpUrl(FUrl, Host, Port, Result);
end;

function THttpRequest.WithMethod(const AMethod: THttpMethod): THttpRequest;
begin
  Result := Self;
  Result.FMethod := AMethod;
  Result.FMethodOverride := '';
end;

function THttpRequest.WithMethodToken(const AToken: string): THttpRequest;
begin
  if not IsValidMethodToken(AToken) then
    raise EHttpProtocolError.Create('invalid HTTP method token: ' + AToken,
      ecProtocolError);
  Result := Self;
  Result.FMethodOverride := UpperCase(AToken);
end;

function THttpRequest.WithHeader(const AName, AValue: string): THttpRequest;
begin
  Result := Self;
  if not Assigned(Result.FHeaders) then
    Result.FHeaders := NewHttpHeaders;
  Result.FHeaders.Add(AName, AValue);
end;

function THttpRequest.WithBody(const ABody: THttpBody): THttpRequest;
begin
  if FBodyWriter <> nil then
    raise EHttpError.Create(
      'a request body and a body writer are mutually exclusive',
      ecInternalError);
  Result := Self;
  Result.FBody := ABody;
end;

function THttpRequest.WithBodyWriter(const AWriter: IBodyWriter): THttpRequest;
begin
  if FBody.IsSet then
    raise EHttpError.Create(
      'a request body and a body writer are mutually exclusive',
      ecInternalError);
  Result := Self;
  Result.FBodyWriter := AWriter;
  Result.FBody := Default(THttpBody);
end;

function THttpRequest.WithCancelToken(
  const AToken: ICancellationToken): THttpRequest;
begin
  Result := Self;
  Result.FCancelToken := AToken;
end;

function THttpRequest.WithTimeout(const AMs: Integer): THttpRequest;
begin
  Result := Self;
  Result.FHeaderTimeoutMs := AMs;
end;

function THttpRequest.WithUrl(const AUrl: string): THttpRequest;
begin
  Result := Self;
  Result.FUrl := AUrl;
end;

function THttpRequest.DropBody: THttpRequest;
begin
  Result := Self;
  Result.FBody := Default(THttpBody);
  Result.FBodyWriter := nil;
end;

function THttpRequest.ToStreamRequest: TStreamRequest;
var
  Names, Vals: TArray<string>;
  I, J: Integer;
begin
  Result := TStreamRequest.Create(GetMethodToken, GetAuthority);
  Result := Result.WithScheme('https').WithPath(GetPath);
  if FHeaders <> nil then
  begin
    Names := FHeaders.Names;
    for I := 0 to High(Names) do
    begin
      Vals := FHeaders.GetValues(Names[I]);
      for J := 0 to High(Vals) do
        Result := Result.WithHeader(Names[I], Vals[J]);
    end;
  end;
  if FBody.IsSet then
    Result := Result.WithBody(FBody);
  if FBodyWriter <> nil then
    Result := Result.WithBodyWriter(FBodyWriter);
end;

function THttpRequest.Url: string;
begin
  Result := FUrl;
end;

function THttpRequest.Method: THttpMethod;
begin
  Result := FMethod;
end;

function THttpRequest.Headers: IHttpHeaders;
begin
  Result := FHeaders;
end;

function THttpRequest.Body: THttpBody;
begin
  Result := FBody;
end;

function THttpRequest.BodyWriter: IBodyWriter;
begin
  Result := FBodyWriter;
end;

{ THttpClientFactory }

class function THttpClientFactory.Create: THttpClientFactory;
begin
  Result.FMaxConnections := cDefaultMaxConnections;
  Result.FMaxStreamsPerConnection := cDefaultMaxStreamsPerConnection;
  Result.FFollowRedirects := cDefaultFollowRedirects;
  Result.FMaxRedirects := cDefaultMaxRedirects;
  Result.FConnectTimeoutMs := cDefaultConnectTimeoutMs;
  Result.FHeaderTimeoutMs := cDefaultHeaderTimeoutMs;
  Result.FIdleTimeoutMs := cDefaultIdleTimeoutMs;
  Result.FProxyHost := '';
  Result.FProxyPort := 0;
  Result.FCACertFile := '';
  Result.FInsecure := False;
  Result.FObserver := nil;
  Result.FHttp1Fallback := cDefaultHttp1Fallback;
  Result.FClearTextPolicy := ctReject;   // strict by default
  Result.FSocketFactory := TDefaultSocketFactory.Create;
end;

function THttpClientFactory.WithMaxConnections(
  const AMax: Integer): THttpClientFactory;
begin
  Result := Self;
  Result.FMaxConnections := AMax;
end;

function THttpClientFactory.WithMaxStreamsPerConnection(
  const AMax: Integer): THttpClientFactory;
begin
  Result := Self;
  Result.FMaxStreamsPerConnection := AMax;
end;

function THttpClientFactory.WithFollowRedirects(
  const AFollow: Boolean): THttpClientFactory;
begin
  Result := Self;
  Result.FFollowRedirects := AFollow;
end;

function THttpClientFactory.WithMaxRedirects(
  const AMax: Integer): THttpClientFactory;
begin
  Result := Self;
  Result.FMaxRedirects := AMax;
end;

function THttpClientFactory.WithProxy(const AHost: string;
  const APort: Word): THttpClientFactory;
begin
  Result := Self;
  Result.FProxyHost := AHost;
  Result.FProxyPort := APort;
end;

function THttpClientFactory.WithSocketFactory(
  const AFactory: IHttp2SocketFactory): THttpClientFactory;
begin
  Result := Self;
  Result.FSocketFactory := AFactory;
end;

function THttpClientFactory.WithCACertFile(
  const AFileName: string): THttpClientFactory;
begin
  Result := Self;
  Result.FCACertFile := AFileName;
  // an explicitly injected factory still wins; otherwise rebuild the default
  if not (Result.FSocketFactory is TDefaultSocketFactory) then
    Exit;
  Result.FSocketFactory := TDefaultSocketFactory.Create(AFileName, Result.FInsecure);
end;

function THttpClientFactory.WithInsecureTls(
  const AInsecure: Boolean): THttpClientFactory;
begin
  Result := Self;
  Result.FInsecure := AInsecure;
  if not (Result.FSocketFactory is TDefaultSocketFactory) then
    Exit;
  Result.FSocketFactory := TDefaultSocketFactory.Create(Result.FCACertFile, AInsecure);
end;

function THttpClientFactory.WithConnectTimeout(
  const AMs: Integer): THttpClientFactory;
begin
  Result := Self;
  Result.FConnectTimeoutMs := AMs;
end;

function THttpClientFactory.WithHeaderTimeout(
  const AMs: Integer): THttpClientFactory;
begin
  Result := Self;
  Result.FHeaderTimeoutMs := AMs;
end;

function THttpClientFactory.WithIdleTimeout(
  const AMs: Integer): THttpClientFactory;
begin
  Result := Self;
  Result.FIdleTimeoutMs := AMs;
end;

function THttpClientFactory.WithObserver(
  const AObserver: IHttp2Observer): THttpClientFactory;
begin
  Result := Self;
  Result.FObserver := AObserver;
end;

function THttpClientFactory.WithHttp1Fallback(
  const AEnable: Boolean): THttpClientFactory;
begin
  Result := Self;
  Result.FHttp1Fallback := AEnable;
end;

function THttpClientFactory.WithClearText(
  const APolicy: TClearTextPolicy): THttpClientFactory;
begin
  Result := Self;
  Result.FClearTextPolicy := APolicy;
end;

function THttpClientFactory.Build: IHttpClient;
begin
  Result := THttpClient.Create(FSocketFactory, FMaxConnections,
    FMaxStreamsPerConnection, FFollowRedirects, FMaxRedirects,
    FConnectTimeoutMs, FHeaderTimeoutMs, FIdleTimeoutMs, FObserver,
    FHttp1Fallback, FClearTextPolicy);
end;

{ TGuardedBody }

constructor TGuardedBody.Create(const AInner: IHttpBodyStream;
  const ALock: TCriticalSection);
begin
  inherited Create;
  FInner := AInner;
  FLock := ALock;
end;

function TGuardedBody.Read(var ABuffer; const ACount: LongInt): LongInt;
begin
  FLock.Acquire;
  try
    Result := FInner.Read(ABuffer, ACount);
  finally
    FLock.Release;
  end;
end;

function TGuardedBody.Eof: Boolean;
begin
  Result := FInner.Eof;
end;

{ THttpResponse }

constructor THttpResponse.Create(const ALease: TStreamLease;
  const AKeepAlive: IConnectionStream; const AConnRef: IPooledConnection);
begin
  inherited Create;
  FLease := ALease;
  FKeepAlive := AKeepAlive;
  FConnRef := AConnRef;
  FHeaders := ALease.ResponseHeaders;
  FBody := TGuardedBody.Create(ALease.Body, AConnRef.Lock);
end;

destructor THttpResponse.Destroy;
begin
  FLease.ReleaseLease;
  if FConnRef <> nil then
    FConnRef.ReleaseIfIdle;
  inherited Destroy;
end;

function THttpResponse.GetStatusCode: LongInt;
begin
  Result := FLease.StatusCode;
end;

function THttpResponse.GetStreamId: LongWord;
begin
  Result := FLease.StreamId;
end;

function THttpResponse.GetHeaders: IHttpHeaders;
begin
  Result := FHeaders;
end;

function THttpResponse.GetBody: IHttpBodyStream;
begin
  Result := FBody;
end;

{ THttpConnection }

constructor THttpConnection.Create(const AConn: TConnection;
  const AOrigin: string; const AMaxStreamsPerConnection: Integer);
begin
  inherited Create;
  FConn := AConn;
  FOrigin := AOrigin;
  FEncoder := THpackCodec.Create;
  FDecoder := THpackCodec.Create;
  FAllocator := TStreamIdAllocator.Create;
  FLock := TCriticalSection.Create;
  FMaxStreamsPerConnection := AMaxStreamsPerConnection;
  FClosing := False;
end;

destructor THttpConnection.Destroy;
begin
  FConn.Close;
  FConn.Free;
  FEncoder.Free;
  FDecoder.Free;
  FAllocator.Free;
  FLock.Free;
  inherited Destroy;
end;

function THttpConnection.GetConn: TConnection;
begin
  Result := FConn;
end;

function THttpConnection.GetOrigin: string;
begin
  Result := FOrigin;
end;

function THttpConnection.GetLock: TCriticalSection;
begin
  Result := FLock;
end;

function THttpConnection.ActiveStreams: Integer;
begin
  Result := FConn.StreamCount;
end;

function THttpConnection.Eligible: Boolean;
var
  St: TConnectionState;
  Peer, Cap: LongWord;
begin
  St := FConn.State;
  if (St <> csOpening) and (St <> csOpen) then
    Exit(False);
  Peer := FConn.PeerSettings.MaxConcurrentStreams;
  Cap := LongWord(FMaxStreamsPerConnection);
  if (Peer > 0) and (Peer < Cap) then
    Cap := Peer;
  Result := LongWord(FConn.StreamCount) < Cap;
end;

function THttpConnection.Acquire(const ARequest: TStreamRequest;
  const ATimeoutMs: Integer; out AAcquired: Boolean): IHttpResponse;
begin
  Result := AcquireCancellable(ARequest, ATimeoutMs, nil, AAcquired);
end;

function THttpConnection.AcquireCancellable(const ARequest: TStreamRequest;
  const ATimeoutMs: Integer; const AToken: ICancellationToken;
  out AAcquired: Boolean): IHttpResponse;
var
  Lease: TStreamLease;
  Keep: IConnectionStream;
  Deadline: QWord;
  Slice, Remaining: Integer;
  Ok: Boolean;
begin
  AAcquired := False;
  FLock.Acquire;
  try
    if FClosing or (not Eligible) then
      Exit;
    Lease := TStreamLease.Create(FConn, FAllocator, ARequest, FEncoder,
      FDecoder);
    Keep := Lease;
    Lease.TimeoutMs := ATimeoutMs;
    Lease.Start;
    AAcquired := True;
    Deadline := GetTickCount64 + QWord(ATimeoutMs);
    Ok := False;
    while True do
    begin
      if AToken = nil then
        Slice := ATimeoutMs
      else if AToken.IsCancelled then
        Break
      else
        Slice := cCancelPollSliceMs;
      if GetTickCount64 >= Deadline then
        Slice := 0;
      Ok := Lease.WaitForResponseHeader(Slice);
      if Ok then
        Break;
      if AToken = nil then
        Break;                       // a plain wait: the timeout is terminal
      if AToken.IsCancelled then
        Break;
      if GetTickCount64 >= Deadline then
        Break;
      Remaining := Integer(Deadline - GetTickCount64);
      if Remaining <= 0 then
        Break;
    end;
    if not Ok then
    begin
      // a cancelled or expired stream is RESET, never orphaned (10.5-10.8)
      FConn.PostFrame(BuildRstStreamFrame(Lease.StreamId, ecCancel));
      Lease.ReleaseLease;
      if (AToken <> nil) and AToken.IsCancelled then
        raise EHttpStreamError.Create('request cancelled', Lease.StreamId,
          ecCancel);
      raise EHttpTimeout.Create('timed out waiting for response headers');
    end;
    Result := THttpResponse.Create(Lease, Keep, Self);
  finally
    FLock.Release;
  end;
end;

procedure THttpConnection.MaybeClose;
begin
  if FClosing and (FConn.StreamCount = 0) then
    FConn.Close;
end;

procedure THttpConnection.Drain;
begin
  FLock.Acquire;
  try
    FClosing := True;
    MaybeClose;
  finally
    FLock.Release;
  end;
end;

procedure THttpConnection.ReleaseIfIdle;
begin
  FLock.Acquire;
  try
    MaybeClose;
  finally
    FLock.Release;
  end;
end;

{ TConnectionPool }

constructor TConnectionPool.Create(const AFactory: IHttp2SocketFactory;
  const AMaxConnections, AMaxStreamsPerConnection, AConnectTimeoutMs,
  AHeaderTimeoutMs, AIdleTimeoutMs: Integer;
  const AObserver: IHttp2Observer);
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FByOrigin := TDictionary<string, TList<IPooledConnection>>.Create;
  FIdleSince := TDictionary<Pointer, QWord>.Create;
  FFactory := AFactory;
  FObserver := AObserver;
  FMaxConnections := AMaxConnections;
  FMaxStreamsPerConnection := AMaxStreamsPerConnection;
  FConnectTimeoutMs := AConnectTimeoutMs;
  FHeaderTimeoutMs := AHeaderTimeoutMs;
  FIdleTimeoutMs := AIdleTimeoutMs;
  FTotalConnections := 0;
  FClosed := False;
end;

destructor TConnectionPool.Destroy;
var
  L: TList<IPooledConnection>;
begin
  Close;
  for L in FByOrigin.Values do
    L.Free;
  FByOrigin.Free;
  FIdleSince.Free;
  FLock.Free;
  inherited Destroy;
end;

procedure TConnectionPool.ReapClosed;
var
  Origin: string;
  L: TList<IPooledConnection>;
  I: Integer;
  C: IPooledConnection;
begin
  for Origin in FByOrigin.Keys do
  begin
    L := FByOrigin[Origin];
    for I := L.Count - 1 downto 0 do
    begin
      C := L[I];
      if (C.Conn.State = csClosed) and (C.ActiveStreams = 0) then
      begin
        FIdleSince.Remove(Pointer(C.Conn));
        L.Delete(I);
        Dec(FTotalConnections);
      end;
    end;
  end;
end;

procedure TConnectionPool.MarkUsed(const C: IPooledConnection);
begin
  FIdleSince.AddOrSetValue(Pointer(C.Conn), GetTickCount64);
end;

procedure TConnectionPool.ReapIdle;
begin
  FLock.Acquire;
  try
    ReapIdleLocked;
  finally
    FLock.Release;
  end;
end;

procedure TConnectionPool.ReapIdleLocked;
var
  Origin: string;
  L: TList<IPooledConnection>;
  I: Integer;
  C: IPooledConnection;
  Since: QWord;
  Now: QWord;
begin
  if FIdleTimeoutMs <= 0 then
    Exit;
  Now := GetTickCount64;
  for Origin in FByOrigin.Keys do
  begin
    L := FByOrigin[Origin];
    for I := L.Count - 1 downto 0 do
    begin
      C := L[I];
      if C.ActiveStreams > 0 then
        Continue;
      if not FIdleSince.TryGetValue(Pointer(C.Conn), Since) then
        Continue;
      if Now - Since < QWord(FIdleTimeoutMs) then
        Continue;
      C.Drain;                       // closes now, since it is idle
      FIdleSince.Remove(Pointer(C.Conn));
      L.Delete(I);
      Dec(FTotalConnections);
    end;
  end;
end;

function TConnectionPool.ListFor(
  const AOrigin: string): TList<IPooledConnection>;
begin
  if not FByOrigin.TryGetValue(AOrigin, Result) then
  begin
    Result := TList<IPooledConnection>.Create;
    FByOrigin.Add(AOrigin, Result);
  end;
end;

function TConnectionPool.CanOpenNew: Boolean;
begin
  Result := (not FClosed) and (FTotalConnections < FMaxConnections);
end;

function TConnectionPool.OpenConnection(const AOrigin, AHost: string;
  const APort: Word): IPooledConnection;
var
  Sock: IHttp2Socket;
  Conn: TConnection;
  Pooled: THttpConnection;
begin
  Sock := FFactory.Dial(AHost, APort, FConnectTimeoutMs);
  Conn := TConnection.Create(Sock);
  if FObserver <> nil then
    Conn.Observer := FObserver;
  if FIdleTimeoutMs > 0 then
  begin
    Conn.PingIntervalMs := FIdleTimeoutMs;
    Conn.PingTimeoutMs := FIdleTimeoutMs;
  end;
  Conn.Start;
  if not Conn.WaitForState(csOpen, FConnectTimeoutMs) then
  begin
    Conn.Free;
    raise EHttpConnectionError.Create('HTTP/2 connection did not open');
  end;
  Pooled := THttpConnection.Create(Conn, AOrigin, FMaxStreamsPerConnection);
  Result := Pooled;
  ListFor(AOrigin).Add(Result);
  Inc(FTotalConnections);
  MarkUsed(Result);
end;

function TConnectionPool.PickEligible(
  const AOrigin: string): IPooledConnection;
var
  L: TList<IPooledConnection>;
  I, Load, BestLoad: Integer;
  C, Best: IPooledConnection;
begin
  Best := nil;
  BestLoad := MaxInt;
  L := ListFor(AOrigin);
  for I := 0 to L.Count - 1 do
  begin
    C := L[I];
    if not C.Eligible then
      Continue;
    Load := C.ActiveStreams;
    if Load < BestLoad then
    begin
      BestLoad := Load;
      Best := C;
    end;
  end;
  Result := Best;
end;

function TConnectionPool.Acquire(const AOrigin, AHost: string;
  const APort: Word; const ARequest: TStreamRequest;
  const AHeaderTimeoutMs: Integer;
  const AToken: ICancellationToken): IHttpResponse;
var
  Deadline: QWord;
  Conn: IPooledConnection;
  Acquired: Boolean;
  Sliced: Integer;
begin
  Deadline := GetTickCount64 + QWord(AHeaderTimeoutMs);
  while True do
  begin
    if (AToken <> nil) and AToken.IsCancelled then
      raise EHttpStreamError.Create('request cancelled', 0, ecCancel);
    FLock.Acquire;
    try
      ReapClosed;
      ReapIdleLocked;
      Conn := PickEligible(AOrigin);
      if (Conn = nil) and CanOpenNew then
        Conn := OpenConnection(AOrigin, AHost, APort);
    finally
      FLock.Release;
    end;

    if Conn <> nil then
    begin
      if AToken <> nil then
      begin
        Sliced := AHeaderTimeoutMs;
        if Sliced <= 0 then
          Sliced := cDefaultHeaderTimeoutMs;
        Result := (Conn as THttpConnection).AcquireCancellable(ARequest,
          Sliced, AToken, Acquired);
      end
      else
        Result := Conn.Acquire(ARequest, AHeaderTimeoutMs, Acquired);
      if Acquired then
      begin
        FLock.Acquire;
        try
          MarkUsed(Conn);
        finally
          FLock.Release;
        end;
        Exit;
      end;
      // the connection filled up between selection and registration; retry
      Sleep(1);
    end
    else
    begin
      if FClosed then
        raise EHttpConnectionClosed.Create('client is closed');
      if GetTickCount64 >= Deadline then
        raise EHttpTimeout.Create(
          'timed out waiting for a connection slot (MaxConnections reached)');
      Sleep(2);
    end;
  end;
end;

procedure TConnectionPool.Close;
var
  Origin: string;
  L: TList<IPooledConnection>;
  C: IPooledConnection;
begin
  FLock.Acquire;
  try
    if FClosed then
      Exit;
    FClosed := True;
    for Origin in FByOrigin.Keys do
    begin
      L := FByOrigin[Origin];
      for C in L do
        C.Drain;
    end;
  finally
    FLock.Release;
  end;
end;

function TConnectionPool.ConnectionCount: Integer;
begin
  FLock.Acquire;
  try
    Result := FTotalConnections;
  finally
    FLock.Release;
  end;
end;

function TConnectionPool.ConnectionCountForOrigin(
  const AOrigin: string): Integer;
var
  L: TList<IPooledConnection>;
begin
  FLock.Acquire;
  try
    if FByOrigin.TryGetValue(AOrigin, L) then
      Result := L.Count
    else
      Result := 0;
  finally
    FLock.Release;
  end;
end;

function TConnectionPool.ActiveStreamsForOrigin(
  const AOrigin: string): TArray<Integer>;
var
  L: TList<IPooledConnection>;
  I: Integer;
begin
  Result := nil;
  FLock.Acquire;
  try
    if FByOrigin.TryGetValue(AOrigin, L) then
    begin
      SetLength(Result, L.Count);
      for I := 0 to L.Count - 1 do
        Result[I] := L[I].ActiveStreams;
    end;
  finally
    FLock.Release;
  end;
end;

function TConnectionPool.PickForTest(
  const AOrigin: string): IPooledConnection;
begin
  FLock.Acquire;
  try
    Result := PickEligible(AOrigin);
  finally
    FLock.Release;
  end;
end;

procedure TConnectionPool.AddForTest(const AOrigin: string;
  const AConn: IPooledConnection);
begin
  FLock.Acquire;
  try
    ListFor(AOrigin).Add(AConn);
    Inc(FTotalConnections);
  finally
    FLock.Release;
  end;
end;

{ THttpClient }

constructor THttpClient.Create(const AFactory: IHttp2SocketFactory;
  const AMaxConnections, AMaxStreamsPerConnection: Integer;
  const AFollowRedirects: Boolean; const AMaxRedirects, AConnectTimeoutMs,
  AHeaderTimeoutMs, AIdleTimeoutMs: Integer;
  const AObserver: IHttp2Observer;
  const AHttp1Fallback: Boolean; const AClearTextPolicy: TClearTextPolicy);
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FPool := TConnectionPool.Create(AFactory, AMaxConnections,
    AMaxStreamsPerConnection, AConnectTimeoutMs, AHeaderTimeoutMs,
    AIdleTimeoutMs, AObserver);
  FFollowRedirects := AFollowRedirects;
  FMaxRedirects := AMaxRedirects;
  FHeaderTimeoutMs := AHeaderTimeoutMs;
  FClosed := False;
  FHttp1Fallback := AHttp1Fallback;
  FClearTextPolicy := AClearTextPolicy;
end;

destructor THttpClient.Destroy;
begin
  Close;
  FPool.Free;
  FLock.Free;
  inherited Destroy;
end;

function THttpClient.Send(const ARequest: THttpRequest): IHttpResponse;
var
  Current: THttpRequest;
  Method: string;
  Location, Target: string;
  Redirects, Retries: Integer;
  Idempotent: Boolean;
begin
  if ARequest.Url = '' then
    raise EHttpProtocolError.Create('request URL is empty', ecProtocolError);
  FLock.Acquire;
  try
    if FClosed then
      raise EHttpConnectionClosed.Create('client is closed');
  finally
    FLock.Release;
  end;

  Current := ARequest;
  Method := ARequest.MethodToken;
  Idempotent := HttpMethodIsIdempotent(Method);
  Redirects := 0;
  Retries := 0;
  while True do
  begin
    try
      Result := SendOnce(Current);
    except
      // transparent retry: only an idempotent request with no body writer,
      // and only when the peer refused the stream or sent GOAWAY so the
      // stream was never processed (plan S10 task 10.9)
      on E: EHttpStreamError do
        if Idempotent and (E.ErrorCode = ecRefusedStream) and
          (Current.BodyWriter = nil) and
          (Retries < cMaxTransparentRetries) then
        begin
          Inc(Retries);
          Sleep(1);
          Continue;
        end
        else
          raise;
    end;

    if (not FFollowRedirects) or (not HttpStatusIsRedirect(Result.StatusCode)) then
      Break;
    Location := Result.Headers.GetFirst('location');
    if Location = '' then
      Break;

    Inc(Redirects);
    if Redirects > FMaxRedirects then
      raise EHttpTooManyRedirects.CreateFmt(
        'redirect chain exceeded MaxRedirects (%d)', [FMaxRedirects]);

    Target := ResolveLocation(Current.Url, Location);
    case Result.StatusCode of
      303:
        begin
          Method := 'GET';
          Current := Current.DropBody;
        end;
      301, 302:
        begin
          // spec errors-redirects.md leaves 301/302 method rewriting to the
          // "standard rules"; these preserve the method for GET/HEAD and
          // rewrite every other method to GET, dropping the body (the
          // behaviour every browser and curl use for a POST -> 301/302)
          if (Method <> 'GET') and (Method <> 'HEAD') then
          begin
            Method := 'GET';
            Current := Current.DropBody;
          end;
        end;
      307, 308:
        if Current.BodyWriter <> nil then
          raise EHttpNotReplayable.Create(
            'a body writer cannot be replayed on a ' +
            IntToStr(Result.StatusCode) + ' redirect');
    end;
    Current := Current.WithMethodToken(Method);
    Current := Current.WithUrl(Target);
  end;
end;

function THttpClient.SendOnce(const ARequest: THttpRequest): IHttpResponse;
var
  Origin, Host, Path: string;
  Port: Word;
  R: TStreamRequest;
  Timeout: Integer;
begin
  ParseHttpUrl(ARequest.Url, Host, Port, Path);
  Origin := OriginOfUrl(ARequest.Url);
  // cleartext policy (doc/design/fallback.md).  S13 task 13.1 enforces the
  // default only; the ctPriorKnowledge/ctUpgrade transports land in 13.2/13.3.
  // S13 task 13.1 enforces the strict default; the ctPriorKnowledge and
  // ctUpgrade transports land in tasks 13.2 and 13.3.
  if (SchemeOfUrl(ARequest.Url) = 'http') and (FClearTextPolicy = ctReject) then
    raise EHttpProtocolError.Create(
      'cleartext origin rejected (set WithClearText(ctPriorKnowledge) or ' +
      'WithClearText(ctUpgrade) to enable it)', ecProtocolError);
  R := ARequest.ToStreamRequest;
  Timeout := FHeaderTimeoutMs;
  if ARequest.HeaderTimeoutMs > 0 then
    Timeout := ARequest.HeaderTimeoutMs;
  Result := FPool.Acquire(Origin, Host, Port, R, Timeout,
    ARequest.CancelToken);
end;

procedure THttpClient.Close;
begin
  FLock.Acquire;
  try
    FClosed := True;
  finally
    FLock.Release;
  end;
  FPool.Close;
end;

{ TResponseReader<T> }

function TResponseReader<T>.Read(const AResponse: IHttpResponse): T;
begin
  Read(AResponse, Result);
end;

class procedure TResponseReader<T>.Read(const AResponse: IHttpResponse;
  out AValue: T);
var
  Raw: TBytes;
  PI: PTypeInfo;
  S: AnsiString;
begin
  if AResponse = nil then
    raise EHttpProtocolError.Create('response is nil', ecInternalError);
  Raw := ReadAllBodyBytes(AResponse.Body);
  PI := TypeInfo(T);
  case PI^.Kind of
    tkAString:
      begin
        SetLength(S, Length(Raw));
        if Length(Raw) > 0 then
          Move(Raw[0], S[1], Length(Raw));
        PAnsiString(@AValue)^ := S;
      end;
    tkDynArray:
      PBytesValue(@AValue)^ := Raw;
  else
    if Length(Raw) < SizeOf(T) then
      raise EHttpProtocolError.Create(
        'response body is too short to decode the requested value',
        ecProtocolError);
    Move(Raw[0], AValue, SizeOf(T));
  end;
end;

end.
