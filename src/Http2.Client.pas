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
  Http2.Tls, Http2.Connection, Http2.Stream;

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

type
  THttpConnection = class;
  THttpResponse = class;

  /// dials the transport for one origin. Injected so pool tests need no real
  /// sockets (doc/design/client-api.md "Lease acquisition").
  IHttp2SocketFactory = interface
    function Dial(const AHost: string; const APort: Word;
      const ATimeoutMs: Integer): IHttp2Socket;
  end;

  /// the production factory: TCP then TLS handshake offering ALPN "h2"
  TDefaultSocketFactory = class(TInterfacedObject, IHttp2SocketFactory)
  private
    FCACertFile: string;
  public
    constructor Create(const ACACertFile: string = '');
    function Dial(const AHost: string; const APort: Word;
      const ATimeoutMs: Integer): IHttp2Socket;
  end;

  /// an HTTP/2 response (doc/design/messages.md IHttpResponse). Pseudo-headers
  /// are surfaced through StatusCode, not through Headers.
  IHttpResponse = interface
    ['{8B1C2D3E-4F50-4A61-9C72-0123456789AB}']
    function GetStatusCode: LongInt;
    function GetHeaders: IHttpHeaders;
    function GetBody: IHttpBodyStream;
    property StatusCode: LongInt read GetStatusCode;
    property Headers: IHttpHeaders read GetHeaders;
    property Body: IHttpBodyStream read GetBody;
  end;

  /// bridges a response body into a value of T (doc/design/messages.md)
  IResponseReader<T> = interface
    function Read(const AResponse: IHttpResponse): T;
  end;

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
    procedure ReapClosed;
    function ListFor(const AOrigin: string): TList<IPooledConnection>;
    function OpenConnection(const AOrigin, AHost: string;
      const APort: Word): IPooledConnection;
    function PickEligible(const AOrigin: string): IPooledConnection;
    function CanOpenNew: Boolean;
  public
    constructor Create(const AFactory: IHttp2SocketFactory; const AMaxConnections,
      AMaxStreamsPerConnection, AConnectTimeoutMs, AHeaderTimeoutMs,
      AIdleTimeoutMs: Integer);
    destructor Destroy; override;
    /// acquire a lease on the least-loaded eligible connection, opening a new
    /// one or waiting for a slot per doc/design/client-api.md
    function Acquire(const AOrigin, AHost: string; const APort: Word;
      const ARequest: TStreamRequest;
      const AHeaderTimeoutMs: Integer): IHttpResponse;
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
  public
    constructor Create(const AFactory: IHttp2SocketFactory;
      const AMaxConnections, AMaxStreamsPerConnection: Integer;
      const AFollowRedirects: Boolean; const AMaxRedirects,
      AConnectTimeoutMs, AHeaderTimeoutMs, AIdleTimeoutMs: Integer);
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

/// origin key = host[:port] with the default port omitted (doc/design)
function OriginOfUrl(const AUrl: string): string;

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

function OriginOfUrl(const AUrl: string): string;
var
  Host, Path: string;
  Port: Word;
begin
  ParseHttpUrl(AUrl, Host, Port, Path);
  if Port = cDefaultHttpsPort then
    Result := Host
  else
    Result := Host + ':' + IntToStr(Port);
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

{ IHttp2SocketFactory }

constructor TDefaultSocketFactory.Create(const ACACertFile: string);
begin
  inherited Create;
  FCACertFile := ACACertFile;
end;

function TDefaultSocketFactory.Dial(const AHost: string; const APort: Word;
  const ATimeoutMs: Integer): IHttp2Socket;
begin
  Result := TTlsSocket.Dial(AHost, APort, False, ATimeoutMs, FCACertFile);
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
  // an explicitly injected factory still wins; otherwise use the PEM bundle
  if not (Result.FSocketFactory is TDefaultSocketFactory) then
    Exit;
  Result.FSocketFactory := TDefaultSocketFactory.Create(AFileName);
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

function THttpClientFactory.Build: IHttpClient;
begin
  Result := THttpClient.Create(FSocketFactory, FMaxConnections,
    FMaxStreamsPerConnection, FFollowRedirects, FMaxRedirects,
    FConnectTimeoutMs, FHeaderTimeoutMs, FIdleTimeoutMs);
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
var
  Lease: TStreamLease;
  Keep: IConnectionStream;
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
    if not Lease.WaitForResponseHeader(ATimeoutMs) then
    begin
      Lease.ReleaseLease;
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
  AHeaderTimeoutMs, AIdleTimeoutMs: Integer);
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FByOrigin := TDictionary<string, TList<IPooledConnection>>.Create;
  FFactory := AFactory;
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
        L.Delete(I);
        Dec(FTotalConnections);
      end;
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
  const AHeaderTimeoutMs: Integer): IHttpResponse;
var
  Deadline: QWord;
  Conn: IPooledConnection;
  Acquired: Boolean;
begin
  Deadline := GetTickCount64 + QWord(AHeaderTimeoutMs);
  while True do
  begin
    FLock.Acquire;
    try
      ReapClosed;
      Conn := PickEligible(AOrigin);
      if (Conn = nil) and CanOpenNew then
        Conn := OpenConnection(AOrigin, AHost, APort);
    finally
      FLock.Release;
    end;

    if Conn <> nil then
    begin
      Result := Conn.Acquire(ARequest, AHeaderTimeoutMs, Acquired);
      if Acquired then
        Exit;
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
  AHeaderTimeoutMs, AIdleTimeoutMs: Integer);
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FPool := TConnectionPool.Create(AFactory, AMaxConnections,
    AMaxStreamsPerConnection, AConnectTimeoutMs, AHeaderTimeoutMs,
    AIdleTimeoutMs);
  FFollowRedirects := AFollowRedirects;
  FMaxRedirects := AMaxRedirects;
  FHeaderTimeoutMs := AHeaderTimeoutMs;
  FClosed := False;
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
  Origin, Host, Path: string;
  Port: Word;
  R: TStreamRequest;
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
  ParseHttpUrl(ARequest.Url, Host, Port, Path);
  Origin := OriginOfUrl(ARequest.Url);
  R := ARequest.ToStreamRequest;
  Result := FPool.Acquire(Origin, Host, Port, R, FHeaderTimeoutMs);
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
