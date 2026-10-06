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
  SysUtils, Classes, SyncObjs, Generics.Collections, TypInfo, BaseUnix,
  Sockets,
  Http2.Errors, Http2.Frames, Http2.Headers, Http2.Hpack,
  Http2.Tls, Http2.Connection, Http2.Stream, Http2.Observer, Http2.Messages,
  Http2.Http1;

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
  /// the default cleartext port (doc/design/fallback.md "Terms")
  cDefaultHttpPort                = 80;
  /// transparent retries allowed for an idempotent request on a refused stream
  cMaxTransparentRetries          = 2;
  /// a cancellable wait polls its token in slices of this many milliseconds
  cCancelPollSliceMs              = 20;
  /// default for the HTTP/1.1 ALPN fallback (doc/design/fallback.md)
  cDefaultHttp1Fallback           = False;
  /// an HTTP/1.1 connection carries one request at a time (doc/design/
  /// fallback.md "HTTP/1.1 codec"): the effective stream limit is 1, so the
  /// pool opens more connections for concurrency, still capped by MaxConnections
  cHttp1StreamLimit               = 1;

type
  // TClearTextPolicy and TNegotiatedProtocol come from Http2.Messages.pas

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

  /// the production factory: TCP then TLS handshake offering ALPN "h2" (and
  /// "http/1.1" when fallback is on).  It also implements the extended
  /// ICleartextSocketFactory contract (plan S13) by delegating to an owned
  /// TProtocolSocketFactory, so the pool can select TLS vs cleartext and the
  /// HTTP/1.1 vs HTTP/2 codec from one call.  Dial keeps its original
  /// behaviour byte-for-byte: an injected test factory that only knows
  /// IHttp2SocketFactory still works unchanged on the https path.
  TDefaultSocketFactory = class(TInterfacedObject, IHttp2SocketFactory,
    ICleartextSocketFactory)
  private
    FCACertFile: string;
    FInsecure: Boolean;
    FProtocols: TProtocolSocketFactory;
  public
    constructor Create(const ACACertFile: string = '';
      const AInsecure: Boolean = False);
    function Dial(const AHost: string; const APort: Word;
      const ATimeoutMs: Integer): IHttp2Socket;
    function DialProtocol(const AHost: string; const APort: Word;
      const AScheme: string; const AHttp1Fallback: Boolean;
      const APolicy: TClearTextPolicy; const ATimeoutMs: Integer;
      out AProtocol: TNegotiatedProtocol): IHttp2Socket;
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
  ///
  /// Protocol-neutral (plan S13 task 13.5): both the HTTP/2 wrapper
  /// (THttpConnection) and the HTTP/1.1 wrapper (THttp1PooledConnection)
  /// satisfy it, so TConnectionPool never branches on the codec.  An HTTP/1.1
  /// entry has no TConnection: its Conn is nil.
  IPooledConnection = interface
    function ActiveStreams: Integer;
    /// eligible = open(ing) and below the per-connection stream cap
    function Eligible: Boolean;
    /// register a lease under the connection lock and block until response
    /// HEADERS are decoded. AAcquired is False when the connection became
    /// ineligible, so the pool retries with another connection.
    function Acquire(const ARequest: TStreamRequest;
      const ATimeoutMs: Integer; out AAcquired: Boolean): IHttpResponse;
    /// adopt the h2c upgrade request (RFC 7540 section 3.2): the peer already
    /// received it as stream 1, so nothing is re-sent and the response arrives
    /// on stream 1.  Only an HTTP/2 entry implements this (an HTTP/1.1 entry
    /// raises EHttpProtocolError).
    function AcquireUpgraded(const ARequest: TStreamRequest;
      const ATimeoutMs: Integer): IHttpResponse;
    /// the transport is finished (peer closed it, a failure was observed, or
    /// the codec consumed it); the pool may drop the entry once ActiveStreams
    /// is 0.  Protocol-neutral replacement for inspecting Conn.State.
    function Closed: Boolean;
    /// stop accepting new leases; close now when idle, else when the last
    /// outstanding body is released
    procedure Drain;
    /// close a drained connection once its last stream is gone (called when a
    /// response body is released)
    procedure ReleaseIfIdle;
    function GetConn: TConnection;
    function GetOrigin: string;
    function GetLock: TCriticalSection;
    /// stable per-connection identity used to key the idle-time map; an
    /// HTTP/1.1 entry has no TConnection, so it keys on its codec object
    function GetKey: Pointer;
    property Conn: TConnection read GetConn;
    property Origin: string read GetOrigin;
    property Lock: TCriticalSection read GetLock;
    property Key: Pointer read GetKey;
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
    /// adopt the h2c upgrade request: the peer already received it as stream 1
    /// during the HTTP/1.1 Upgrade, so no request frame is emitted and the 101
    /// is not the response; the response arrives on stream 1 (RFC 7540 s 3.2)
    function AcquireUpgraded(const ARequest: TStreamRequest;
      const ATimeoutMs: Integer): IHttpResponse;
    function Closed: Boolean;
    procedure Drain;
    procedure ReleaseIfIdle;
    function GetConn: TConnection;
    function GetOrigin: string;
    function GetLock: TCriticalSection;
    function GetKey: Pointer;
  end;

  /// an IHttp2Socket adapter that turns an exact-count Read into a SINGLE
  /// underlying read, returning as soon as ANY bytes are available.
  ///
  /// The HTTP/2 reader wants an exact-count Read (a partial frame must be read
  /// to completion), but the HTTP/1.1 codec's TBufferedReader.Fill asks for a
  /// whole 16 KiB buffer and a keep-alive peer (Apache) sends ~235 bytes and
  /// then waits: against an exact-count transport that Fill blocks until the
  /// read deadline expires.  Wrapping the cleartext transport for the HTTP/1.1
  /// path fixes that without touching the transport itself.  A transport with
  /// no exposed raw handle (TLS) is used unchanged.
  TSingleReadSocket = class(TInterfacedObject, IHttp2Socket)
  private
    FInner: IHttp2Socket;
    FFd: Integer;            // -1 when FInner exposes no raw socket handle
    FConnectTimeoutMs: Integer;
    FReadTimeoutMs: Integer;
    FWriteTimeoutMs: Integer;
  public
    constructor Create(const AInner: IHttp2Socket);
    destructor Destroy; override;
    function Read(var ABuffer; ACount: Integer): Integer;
    function Write(const ABuffer; ACount: Integer): Integer;
    procedure Close;
    function GetConnected: Boolean;
    function GetConnectTimeoutMs: Integer;
    procedure SetConnectTimeoutMs(const AValue: Integer);
    function GetReadTimeoutMs: Integer;
    procedure SetReadTimeoutMs(const AValue: Integer);
    function GetWriteTimeoutMs: Integer;
    procedure SetWriteTimeoutMs(const AValue: Integer);
  end;

  /// the HTTP/1.1 pooled connection (plan S13 task 13.5): the codec-selection
  /// counterpart of THttpConnection, so the pool stays protocol-neutral.  It
  /// carries one request at a time (cHttp1StreamLimit).
  THttp1PooledConnection = class(TInterfacedObject, IPooledConnection)
  private
    FH1: THttp1Connection;
    FLock: TCriticalSection;
    FOrigin: string;
    FClosing: Boolean;
    /// the in-flight response body, if any: the connection is only eligible
    /// for reuse once it is drained
    FLastBody: IHttpBodyStream;
  public
    constructor Create(const AH1: THttp1Connection; const AOrigin: string);
    destructor Destroy; override;
    function ActiveStreams: Integer;
    function Eligible: Boolean;
    function Acquire(const ARequest: TStreamRequest;
      const ATimeoutMs: Integer; out AAcquired: Boolean): IHttpResponse;
    /// an HTTP/1.1 entry never adopts an h2c stream: the upgrade only happens
    /// on a fresh connection (UnsupportedOperation is the honest answer)
    function AcquireUpgraded(const ARequest: TStreamRequest;
      const ATimeoutMs: Integer): IHttpResponse;
    function Closed: Boolean;
    procedure Drain;
    procedure ReleaseIfIdle;
    function GetConn: TConnection;
    function GetOrigin: string;
    function GetLock: TCriticalSection;
    function GetKey: Pointer;
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
    /// ALPN fallback and cleartext policy, applied to every request by scheme
    /// (doc/design/fallback.md)
    FHttp1Fallback: Boolean;
    FClearTextPolicy: TClearTextPolicy;
    /// last time a pooled connection was used, keyed by IPooledConnection.Key
    FIdleSince: TDictionary<Pointer, QWord>;
    /// the TCP+TLS-or-cleartext dial for ARequest's scheme (fallback on https,
    /// the policy on http); out AProtocol names the negotiated wire protocol.
    /// Uses the extended ICleartextSocketFactory contract when the factory
    /// supports it, else the legacy Dial (npHttp2Tls) so an injected test
    /// factory keeps working
    function DialFor(const AHost: string; const APort: Word;
      const AScheme: string; const ATimeoutMs: Integer;
      out AProtocol: TNegotiatedProtocol): IHttp2Socket;
    /// wrap Sock as an HTTP/2 pooled connection.  AStart True runs the thread
    /// and waits for csOpen (preface + SETTINGS written by DoPreface); False
    /// leaves it unstarted so the h2c upgrade can adopt stream 1 before any
    /// inbound frame is read
    function StartHttp2(const Sock: IHttp2Socket; const AOrigin: string;
      const AStart: Boolean): IPooledConnection;
    /// online the HTTP/1.1 codec over a socket and pool it
    function WrapHttp1(const Sock: IHttp2Socket;
      const AOrigin: string): IPooledConnection;
    /// the one transport-selection point (plan S13 tasks 13.2/13.3/13.5):
    /// dial, choose the codec from the negotiated protocol, run the h2c
    /// Upgrade when the policy asks for it, and register the result under
    /// AOrigin.  AUpgraded is True when the connection is an unstarted HTTP/2
    /// connection on which the caller must adopt stream 1 via AcquireUpgraded.
    function OpenForTxn(const AOrigin, AHost: string; const APort: Word;
      const ARequest: TStreamRequest; const AHeaderTimeoutMs: Integer;
      const AScheme: string; out AConn: IPooledConnection;
      out AUpgraded: Boolean): Boolean;
    /// write the h2c Upgrade request on Sock and read the whole response head
    /// byte by byte.  True => 101 and the socket sits exactly at the HTTP/2
    /// boundary; False => the peer declined and Sock must be discarded (its
    /// exchange is half-read), so the pool re-dials for plain HTTP/1.1.
    // (RFC 7540 section 3.2 / doc/design/fallback.md "h2c upgrade procedure")
    function TryH2cUpgrade(const Sock: IHttp2Socket;
      const ARequest: TStreamRequest): Boolean;
    procedure ReapClosed;
    procedure ReapIdleLocked;
    procedure MarkUsed(const C: IPooledConnection);
    function ListFor(const AOrigin: string): TList<IPooledConnection>;
    function PickEligible(const AOrigin: string): IPooledConnection;
    function CanOpenNew: Boolean;
    procedure Register(const AOrigin: string;
      const AConn: IPooledConnection);
  public
    constructor Create(const AFactory: IHttp2SocketFactory; const AMaxConnections,
      AMaxStreamsPerConnection, AConnectTimeoutMs, AHeaderTimeoutMs,
      AIdleTimeoutMs: Integer; const AObserver: IHttp2Observer = nil;
      const AHttp1Fallback: Boolean = False;
      const AClearTextPolicy: TClearTextPolicy = ctReject);
    destructor Destroy; override;
    /// acquire a lease on the least-loaded eligible connection, opening a new
    /// one or waiting for a slot per doc/design/client-api.md. When AToken is
    /// non-nil the wait is cancellable (plan S10 task 10.8).  The request's
    /// scheme selects TLS vs cleartext and the HTTP/2 vs HTTP/1.1 codec.
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

/// the default port for a scheme: 80 for http, 443 for anything else
function DefaultPortForScheme(const AScheme: string): Word;

/// resolve a redirect Location against the URL that produced it: absolute,
/// protocol-relative, root-relative or path-relative (plan S10 task 10.1)
function ResolveLocation(const ABaseUrl, ALocation: string): string;

/// read a response body to EOF into a byte array (used by TResponseReader<T>)
function ReadAllBodyBytes(const ABody: IHttpBodyStream): TBytes;

/// base64url (RFC 4648 section 5) of AData: standard base64 with '+'->'-',
/// '/'->'_' and NO '=' padding
function Base64UrlEncode(const AData: TBytes): string;

/// the value of the h2c `HTTP2-Settings` header: the base64url (unpadded)
/// encoding of the client's initial SETTINGS wire payload
// (RFC 7540 section 3.2.1).  It is exactly the payload the connection preface
// sends, so the client never later emits a conflicting SETTINGS frame.
function Http2SettingsBase64Url: string;

/// build the raw bytes of the h2c Upgrade request: request line, Host, the
/// caller's headers, then Upgrade/Connection/HTTP2-Settings
// (doc/design/fallback.md "h2c upgrade procedure").  The Upgrade and
// Connection headers cannot travel through TStreamRequest.Headers (the shared
// header map forbids connection-specific fields), so they are written here.
function BuildH2cUpgradeRequest(const ARequest: TStreamRequest): TBytes;

/// read one CRLF/LF-terminated line byte by byte from AScope, never reading
/// past the terminator, so an h2c upgrade leaves any following HTTP/2 bytes in
/// the socket.  False when the stream ends before any byte arrives.
function ReadHeadLineBytewise(const ASock: IHttp2Socket;
  out ALine: string): Boolean;

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
  APath := '/';
  Rest := AUrl;
  // the default port follows the scheme: 80 for http, 443 for https
  // (doc/design/fallback.md "Terms")
  P := Pos('://', Rest);
  if (P > 0) and (LowerCase(Copy(Rest, 1, P - 1)) = 'http') then
    APort := cDefaultHttpPort
  else
    APort := cDefaultHttpsPort;
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
    Port := StrToIntDef(PortStr, APort);
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

function DefaultPortForScheme(const AScheme: string): Word;
begin
  // the origin/authority omit the port only when it is the scheme default,
  // so 80 is default for http and 443 for everything else
  if LowerCase(AScheme) = 'http' then
    Result := cDefaultHttpPort
  else
    Result := cDefaultHttpsPort;
end;

function OriginOfUrl(const AUrl: string): string;
var
  Host, Path, Scheme: string;
  Port: Word;
begin
  ParseHttpUrl(AUrl, Host, Port, Path);
  Scheme := SchemeOfUrl(AUrl);
  if Port = DefaultPortForScheme(Scheme) then
    Result := Host
  else
    Result := Host + ':' + IntToStr(Port);
  // a different scheme is a different origin even on the same host:port, so
  // an http redirect target never reuses a pooled https connection
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

function Base64UrlEncode(const AData: TBytes): string;
const
  cStd = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
var
  I, N: Integer;
  B0, B1, B2: Byte;
begin
  Result := '';
  I := 0;
  N := Length(AData);
  while I < N do
  begin
    B0 := AData[I];
    if I + 1 < N then B1 := AData[I + 1] else B1 := 0;
    if I + 2 < N then B2 := AData[I + 2] else B2 := 0;
    Result := Result + cStd[(B0 shr 2) + 1];
    Result := Result + cStd[(((B0 and $03) shl 4) or (B1 shr 4)) + 1];
    if I + 1 < N then
      Result := Result + cStd[(((B1 and $0F) shl 2) or (B2 shr 6)) + 1];
    if I + 2 < N then
      Result := Result + cStd[(B2 and $3F) + 1];
    Inc(I, 3);
  end;
  // base64url alphabet, no '=' padding (RFC 4648 section 5)
  for N := 1 to Length(Result) do
    if Result[N] = '+' then
      Result[N] := '-'
    else if Result[N] = '/' then
      Result[N] := '_';
end;

function Http2SettingsBase64Url: string;
begin
  // exactly the SETTINGS payload DoPreface writes, so the HTTP2-Settings value
  // and the first SETTINGS frame carry the same settings (RFC 7540 s 3.2.1)
  Result := Base64UrlEncode(TConnectionSettings.Defaults.Encode);
end;

function BuildH2cUpgradeRequest(const ARequest: TStreamRequest): TBytes;
var
  Head, Host, Value: string;
  Names, Vals: TArray<string>;
  I, J: Integer;
  B: TBytes;
begin
  Head := ARequest.Method;
  if Head = '' then
    Head := 'GET';
  if ARequest.Path = '' then
    Head := Head + ' / HTTP/1.1' + #13#10
  else
    Head := Head + ' ' + ARequest.Path + ' HTTP/1.1' + #13#10;

  Host := '';
  if ARequest.Headers <> nil then
    Host := ARequest.Headers.GetFirst(HeaderHost);
  if Host = '' then
    Host := ARequest.Authority;
  if Host = '' then
    raise EHttpProtocolError.Create('h2c upgrade request has no Host',
      ecProtocolError);
  Head := Head + 'Host: ' + Host + #13#10;

  if ARequest.Headers <> nil then
  begin
    Names := ARequest.Headers.Names;
    for I := 0 to High(Names) do
    begin
      if SameText(Names[I], HeaderHost) then
        Continue;
      Vals := ARequest.Headers.GetValues(Names[I]);
      for J := 0 to High(Vals) do
      begin
        Value := Vals[J];
        Head := Head + Names[I] + ': ' + Value + #13#10;
      end;
    end;
  end;

  Head := Head + 'Upgrade: h2c' + #13#10;
  Head := Head + 'Connection: Upgrade, HTTP2-Settings' + #13#10;
  Head := Head + 'HTTP2-Settings: ' + Http2SettingsBase64Url + #13#10;
  Head := Head + #13#10;

  SetLength(B, Length(Head));
  if Length(B) > 0 then
    Move(Head[1], B[0], Length(B));
  Result := B;
end;

function ReadHeadLineBytewise(const ASock: IHttp2Socket;
  out ALine: string): Boolean;
var
  One: array[0..0] of Byte;
  Buf: TBytes;
  N: Integer;
begin
  ALine := '';
  Buf := nil;
  while True do
  begin
    N := ASock.Read(One[0], 1);
    if N <= 0 then
      Break;
    SetLength(Buf, Length(Buf) + 1);
    Buf[High(Buf)] := One[0];
    if One[0] = 10 then
      Break;
    if Length(Buf) > cHttp1MaxHeaderBytes then
      raise EHttpProtocolError.Create(
        'h2c upgrade status line exceeds the header-size limit',
        ecProtocolError);
  end;
  if Length(Buf) = 0 then
    Exit(False);
  if Buf[High(Buf)] = 10 then
    SetLength(Buf, Length(Buf) - 1);
  if (Length(Buf) > 0) and (Buf[High(Buf)] = 13) then
    SetLength(Buf, Length(Buf) - 1);
  SetLength(ALine, Length(Buf));
  if Length(Buf) > 0 then
    Move(Buf[0], ALine[1], Length(Buf));
  Result := True;
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
  FProtocols := TProtocolSocketFactory.Create(ACACertFile, AInsecure);
end;

function TDefaultSocketFactory.Dial(const AHost: string; const APort: Word;
  const ATimeoutMs: Integer): IHttp2Socket;
begin
  Result := TTlsSocket.Dial(AHost, APort, FInsecure, ATimeoutMs, FCACertFile);
end;

function TDefaultSocketFactory.DialProtocol(const AHost: string;
  const APort: Word; const AScheme: string; const AHttp1Fallback: Boolean;
  const APolicy: TClearTextPolicy; const ATimeoutMs: Integer;
  out AProtocol: TNegotiatedProtocol): IHttp2Socket;
var
  Sock: IHttp2Socket;
  TlsObj: TObject;
  Name: string;
begin
  // cleartext never involves ALPN, so the shared selector is correct there
  if AScheme = 'http' then
    Exit(FProtocols.DialProtocol(AHost, APort, AScheme, AHttp1Fallback,
      APolicy, ATimeoutMs, AProtocol));

  // https: offer the ALPN list the fallback policy asks for, then map the
  // selected name to a codec.  DialWithAlpn reports the name instead of
  // enforcing "h2", so the mapping happens here
  // (doc/design/fallback.md "Negotiation").
  Sock := TTlsSocket.DialWithAlpn(AHost, APort, AlpnOfferFor(AHttp1Fallback),
    FInsecure, ATimeoutMs, FCACertFile);
  // downcast with Supports, NOT a hard class cast: a hard cast reinterprets
  // the interface pointer (which is not the object base) and reads garbage
  Name := '';
  if Supports(Sock, TTlsSocket, TlsObj) then
    Name := TTlsSocket(TlsObj).SelectedProtocol;
  if Name = cHttp11AlpnProtocol then
    AProtocol := npHttp1Tls
  else if Name = cHttp2AlpnProtocol then
    AProtocol := npHttp2Tls
  else if AHttp1Fallback then
    // RFC 7301: no ALPN result means the peer speaks HTTP/1.1
    AProtocol := npHttp1Tls
  else
  begin
    Sock.Close;
    raise EHttpProtocolError.CreateFmt(
      'peer did not negotiate ALPN "%s" (selected "%s")',
      [cHttp2AlpnProtocol, Name]);
  end;
  Result := Sock;
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
  if Port = DefaultPortForScheme(SchemeOfUrl(FUrl)) then
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
  // the URL scheme drives transport selection and the codec (plan S13):
  // ':scheme' stays 'http'/'https' while a cleartext origin also picks the
  // cleartext policy path in the pool
  Result := Result.WithScheme(SchemeOfUrl(FUrl)).WithPath(GetPath);
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

function THttpConnection.Closed: Boolean;
begin
  Result := FConn.State = csClosed;
end;

function THttpConnection.GetKey: Pointer;
begin
  Result := Pointer(FConn);
end;

function THttpConnection.AcquireUpgraded(const ARequest: TStreamRequest;
  const ATimeoutMs: Integer): IHttpResponse;
var
  Lease: TStreamLease;
  Keep: IConnectionStream;
  Deadline: QWord;
  Slice: Integer;
  Ok: Boolean;
begin
  FLock.Acquire;
  try
    Lease := TStreamLease.Create(FConn, FAllocator, ARequest, FEncoder,
      FDecoder);
    Keep := Lease;
    Lease.TimeoutMs := ATimeoutMs;
    try
      Lease.AdoptUpgradedStream;
    except
      Lease.ReleaseLease;
      raise;
    end;
    // stream 1 is registered, so it is now safe to start the reader: the
    // preface is written and every inbound stream-1 frame routes to this
    // lease (never to the shared queue)
    FConn.Start;
    // AdoptUpgradedStream registered stream 1, so the response the peer
    // already produced during the Upgrade (RFC 7540 section 3.2) is routed to
    // this lease by the connection thread.
    Deadline := GetTickCount64 + QWord(ATimeoutMs);
    Ok := False;
    while True do
    begin
      if GetTickCount64 >= Deadline then
        Slice := 0
      else
        Slice := Integer(Deadline - GetTickCount64);
      Ok := Lease.WaitForResponseHeader(Slice);
      if Ok then
        Break;
      if GetTickCount64 >= Deadline then
        Break;
    end;
    if not Ok then
    begin
      // the adopted stream is RESET, never orphaned (mirrors AcquireCancellable)
      FConn.PostFrame(BuildRstStreamFrame(Lease.StreamId, ecCancel));
      Lease.ReleaseLease;
      raise EHttpTimeout.Create('timed out waiting for response headers');
    end;
    Result := THttpResponse.Create(Lease, Keep, Self);
  finally
    FLock.Release;
  end;
end;

{ TSingleReadSocket }

constructor TSingleReadSocket.Create(const AInner: IHttp2Socket);
var
  Plain: TObject;
  H: Integer;
begin
  inherited Create;
  FInner := AInner;
  FFd := -1;
  H := -1;
  // TPlainSocket is the only cleartext transport that exposes an OS handle;
  // reusing its fd lets a single fpRecv bypass the exact-count loop
  try
    if (AInner <> nil) and Supports(AInner, TPlainSocket, Plain) then
      H := TPlainSocket(Plain).Handle;
  except
    H := -1;
  end;
  if H >= 0 then
    FFd := H;
  FConnectTimeoutMs := cDefaultSocketTimeoutMs;
  FReadTimeoutMs := cDefaultSocketTimeoutMs;
  FWriteTimeoutMs := cDefaultSocketTimeoutMs;
end;

destructor TSingleReadSocket.Destroy;
begin
  // FInner is freed by its own reference (no Free here: it may be shared)
  inherited Destroy;
end;

function TSingleReadSocket.Read(var ABuffer; ACount: Integer): Integer;
var
  N: ssize_t;
  tv: TTimeVal;
begin
  if ACount <= 0 then
    Exit(0);
  if FFd < 0 then
    // no raw handle: fall back to the wrapped transport unchanged
    Exit(FInner.Read(ABuffer, ACount));
  tv.tv_sec := 0;
  if FReadTimeoutMs > 0 then
  begin
    tv.tv_sec := FReadTimeoutMs div 1000;
    tv.tv_usec := (FReadTimeoutMs mod 1000) * 1000;
  end;
  fpSetSockOpt(FFd, SOL_SOCKET, SO_RCVTIMEO, @tv, SizeOf(tv));
  repeat
    N := fpRecv(FFd, @ABuffer, ACount, 0);
    if N >= 0 then
      Exit(N);
    if (fpGetErrno = ESysEAGAIN) or (fpGetErrno = ESysEWOULDBLOCK) then
      raise EHttpTimeout.CreateFmt('read timed out after %d ms',
        [FReadTimeoutMs]);
    if fpGetErrno = ESysEINTR then
      Continue;
    raise EHttpConnectionClosed.CreateFmt('socket read failed (errno %d)',
      [fpGetErrno]);
  until False;
end;

function TSingleReadSocket.Write(const ABuffer; ACount: Integer): Integer;
begin
  Result := FInner.Write(ABuffer, ACount);
end;

procedure TSingleReadSocket.Close;
begin
  FInner.Close;
end;

function TSingleReadSocket.GetConnected: Boolean;
begin
  Result := FInner.Connected;
end;

function TSingleReadSocket.GetConnectTimeoutMs: Integer;
begin
  Result := FConnectTimeoutMs;
end;

procedure TSingleReadSocket.SetConnectTimeoutMs(const AValue: Integer);
begin
  FConnectTimeoutMs := AValue;
  FInner.ConnectTimeoutMs := AValue;
end;

function TSingleReadSocket.GetReadTimeoutMs: Integer;
begin
  Result := FReadTimeoutMs;
end;

procedure TSingleReadSocket.SetReadTimeoutMs(const AValue: Integer);
begin
  FReadTimeoutMs := AValue;
  FInner.ReadTimeoutMs := AValue;
end;

function TSingleReadSocket.GetWriteTimeoutMs: Integer;
begin
  Result := FWriteTimeoutMs;
end;

procedure TSingleReadSocket.SetWriteTimeoutMs(const AValue: Integer);
begin
  FWriteTimeoutMs := AValue;
  FInner.WriteTimeoutMs := AValue;
end;

{ THttp1PooledConnection }
constructor THttp1PooledConnection.Create(const AH1: THttp1Connection;
  const AOrigin: string);
begin
  inherited Create;
  FH1 := AH1;
  FOrigin := AOrigin;
  FLock := TCriticalSection.Create;
  FClosing := False;
  FLastBody := nil;
end;

destructor THttp1PooledConnection.Destroy;
begin
  FH1.Free;               // closes the socket
  FLock.Free;
  inherited Destroy;
end;

function THttp1PooledConnection.ActiveStreams: Integer;
begin
  // HTTP/1.1 carries one request at a time: a connection stays busy until the
  // current response body is drained (doc/design/fallback.md "HTTP/1.1 codec")
  if (FLastBody <> nil) and (not FLastBody.Eof) then
    Result := cHttp1StreamLimit
  else
    Result := 0;
end;

function THttp1PooledConnection.Eligible: Boolean;
begin
  Result := (not FClosing) and (ActiveStreams = 0);
end;

function THttp1PooledConnection.Closed: Boolean;
begin
  Result := FClosing or (not FH1.Reusable);
end;

function THttp1PooledConnection.Acquire(const ARequest: TStreamRequest;
  const ATimeoutMs: Integer; out AAcquired: Boolean): IHttpResponse;
begin
  AAcquired := False;
  Result := nil;
  FLock.Acquire;
  try
    if FClosing then
      Exit;
    if not Eligible then
      Exit;                // one request in flight: the pool tries another
    try
      FLastBody := nil;
      Result := FH1.Send(ARequest);
      FLastBody := Result.Body;
      AAcquired := True;
    except
      // a failed exchange leaves the HTTP/1.1 stream unusable (a half-read
      // response would desynchronize the next one): close and let the pool
      // drop the connection instead of reusing it
      FClosing := True;
      FH1.Close;
      raise;
    end;
  finally
    FLock.Release;
  end;
end;

function THttp1PooledConnection.AcquireUpgraded(const ARequest: TStreamRequest;
  const ATimeoutMs: Integer): IHttpResponse;
begin
  // an h2c upgrade only ever runs on a freshly created HTTP/2 connection; a
  // pooled HTTP/1.1 entry can never adopt stream 1
  raise EHttpProtocolError.Create(
    'an HTTP/1.1 pooled connection cannot adopt an h2c upgrade stream',
    ecProtocolError);
end;

procedure THttp1PooledConnection.Drain;
begin
  FLock.Acquire;
  try
    FClosing := True;
    if ActiveStreams = 0 then
      FH1.Close;
  finally
    FLock.Release;
  end;
end;

procedure THttp1PooledConnection.ReleaseIfIdle;
begin
  FLock.Acquire;
  try
    if FClosing and (ActiveStreams = 0) then
      FH1.Close;
  finally
    FLock.Release;
  end;
end;

function THttp1PooledConnection.GetConn: TConnection;
begin
  // an HTTP/1.1 connection has no TConnection; nil marks it non-HTTP/2
  Result := nil;
end;

function THttp1PooledConnection.GetOrigin: string;
begin
  Result := FOrigin;
end;

function THttp1PooledConnection.GetLock: TCriticalSection;
begin
  Result := FLock;
end;

function THttp1PooledConnection.GetKey: Pointer;
begin
  Result := Pointer(FH1);
end;

{ TConnectionPool }

constructor TConnectionPool.Create(const AFactory: IHttp2SocketFactory;
  const AMaxConnections, AMaxStreamsPerConnection, AConnectTimeoutMs,
  AHeaderTimeoutMs, AIdleTimeoutMs: Integer;
  const AObserver: IHttp2Observer;
  const AHttp1Fallback: Boolean; const AClearTextPolicy: TClearTextPolicy);
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
  FHttp1Fallback := AHttp1Fallback;
  FClearTextPolicy := AClearTextPolicy;
  FTotalConnections := 0;
  FClosed := False;
end;

procedure TConnectionPool.Register(const AOrigin: string;
  const AConn: IPooledConnection);
begin
  ListFor(AOrigin).Add(AConn);
  Inc(FTotalConnections);
  MarkUsed(AConn);
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
      if C.Closed and (C.ActiveStreams = 0) then
      begin
        FIdleSince.Remove(C.Key);
        L.Delete(I);
        Dec(FTotalConnections);
      end;
    end;
  end;
end;

procedure TConnectionPool.MarkUsed(const C: IPooledConnection);
begin
  FIdleSince.AddOrSetValue(C.Key, GetTickCount64);
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
      if not FIdleSince.TryGetValue(C.Key, Since) then
        Continue;
      if Now - Since < QWord(FIdleTimeoutMs) then
        Continue;
      C.Drain;                       // closes now, since it is idle
      FIdleSince.Remove(C.Key);
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

function TConnectionPool.DialFor(const AHost: string; const APort: Word;
  const AScheme: string; const ATimeoutMs: Integer;
  out AProtocol: TNegotiatedProtocol): IHttp2Socket;
var
  CF: ICleartextSocketFactory;
begin
  // the default factory (and any factory that opted into the extended
  // contract) selects TLS vs cleartext and the ALPN codec for us
  if Supports(FFactory, ICleartextSocketFactory, CF) then
    Exit(CF.DialProtocol(AHost, APort, AScheme, FHttp1Fallback,
      FClearTextPolicy, ATimeoutMs, AProtocol));

  // legacy factory (the injected test seam): it only knows TLS + h2, so an
  // https origin stays strict; a cleartext origin is dialled directly
  if AScheme = 'http' then
  begin
    if FClearTextPolicy = ctUpgrade then
      AProtocol := npHttp1Cleartext
    else
      AProtocol := npHttp2Cleartext;
    Result := TTlsSocket.DialCleartext(AHost, APort, ATimeoutMs);
  end
  else
  begin
    AProtocol := npHttp2Tls;
    Result := FFactory.Dial(AHost, APort, ATimeoutMs);
  end;
end;

function TConnectionPool.StartHttp2(const Sock: IHttp2Socket;
  const AOrigin: string; const AStart: Boolean): IPooledConnection;
var
  Conn: TConnection;
  Pooled: THttpConnection;
begin
  Conn := TConnection.Create(Sock);
  if FObserver <> nil then
    Conn.Observer := FObserver;
  if FIdleTimeoutMs > 0 then
  begin
    Conn.PingIntervalMs := FIdleTimeoutMs;
    Conn.PingTimeoutMs := FIdleTimeoutMs;
  end;
  Pooled := THttpConnection.Create(Conn, AOrigin, FMaxStreamsPerConnection);
  if AStart then
  begin
    Conn.Start;    // DoPreface writes the preface + the initial SETTINGS frame
    if not Conn.WaitForState(csOpen, FConnectTimeoutMs) then
    begin
      Pooled.Free;
      raise EHttpConnectionError.Create('HTTP/2 connection did not open');
    end;
  end;
  Result := Pooled;
  ListFor(AOrigin).Add(Result);
  Inc(FTotalConnections);
  MarkUsed(Result);
end;

function TConnectionPool.WrapHttp1(const Sock: IHttp2Socket;
  const AOrigin: string): IPooledConnection;
var
  H1: THttp1Connection;
begin
  // the HTTP/1.1 codec reads in 16 KiB fills; an exact-count transport would
  // block on a keep-alive peer, so single-read the underlying socket here
  H1 := THttp1Connection.Create(TSingleReadSocket.Create(Sock),
    FHeaderTimeoutMs);
  Result := THttp1PooledConnection.Create(H1, AOrigin);
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

function TConnectionPool.TryH2cUpgrade(const Sock: IHttp2Socket;
  const ARequest: TStreamRequest): Boolean;
var
  Raw: TBytes;
  Ofs, N: Integer;
  Line, Version, Reason: string;
  Status, Lines: Integer;
begin
  // write the Upgrade request and read the response head byte by byte, so a
  // 101 leaves the HTTP/2 frames that FOLLOW the head untouched in the
  // socket.  The Upgrade and Connection headers cannot travel through
  // TStreamRequest.Headers (the shared map forbids connection-specific
  // fields), so the wire bytes are built here (doc/design/fallback.md
  // "h2c upgrade procedure").
  Raw := BuildH2cUpgradeRequest(ARequest);
  Ofs := 0;
  while Ofs < Length(Raw) do
  begin
    N := Sock.Write(Raw[Ofs], Length(Raw) - Ofs);
    if N <= 0 then
      raise EHttpConnectionClosed.Create('h2c upgrade request write failed');
    Inc(Ofs, N);
  end;
  if not ReadHeadLineBytewise(Sock, Line) then
    raise EHttpProtocolError.Create('peer closed during the h2c upgrade',
      ecProtocolError);
  ParseStatusLine(Line, Version, Status, Reason);
  Result := Status = 101;
  if not Result then
    Exit;
  // the 101 head continues with Upgrade/Connection fields and the mandatory
  // empty line; consume them all before the socket becomes an HTTP/2
  // transport, else the connection thread frames those bytes as HTTP/2
  Lines := 0;
  while True do
  begin
    if not ReadHeadLineBytewise(Sock, Line) then
      raise EHttpProtocolError.Create('truncated 101 response head',
        ecProtocolError);
    if Line = '' then
      Break;
    Inc(Lines);
    if Lines > 64 then
      raise EHttpProtocolError.Create('101 response head is too large',
        ecProtocolError);
  end;
end;

function TConnectionPool.OpenForTxn(const AOrigin, AHost: string;
  const APort: Word; const ARequest: TStreamRequest;
  const AHeaderTimeoutMs: Integer; const AScheme: string;
  out AConn: IPooledConnection; out AUpgraded: Boolean): Boolean;
var
  Sock: IHttp2Socket;
  Protocol: TNegotiatedProtocol;
begin
  Result := False;
  AConn := nil;
  AUpgraded := False;
  Sock := DialFor(AHost, APort, AScheme, FConnectTimeoutMs, Protocol);
  try
    case Protocol of
      npHttp2Tls, npHttp2Cleartext:
        // prior knowledge writes no Upgrade; TConnection.DoPreface sends the
        // preface + SETTINGS itself
        AConn := StartHttp2(Sock, AOrigin, True);
      npHttp1Tls:
        AConn := WrapHttp1(Sock, AOrigin);
      npHttp1Cleartext:
        begin
          // the caller chose ctUpgrade.  A bodyless request is eligible for
          // the upgrade; a request with a body is NOT, because that would
          // transmit the body twice (once in the probe, once over HTTP/2).
          if ARequest.Body.IsSet or (ARequest.BodyWriter <> nil) then
            AConn := WrapHttp1(Sock, AOrigin)
          else if TryH2cUpgrade(Sock, ARequest) then
          begin
            // 101: the peer already answered the upgrade request and will
            // send its response on stream 1, so the socket is now an HTTP/2
            // transport.  Do NOT start the reader yet: the caller must adopt
            // stream 1 first, else the peer's stream-1 HEADERS could arrive
            // before a lease owns them and be dropped on the shared queue.
            AConn := StartHttp2(Sock, AOrigin, False);
            AUpgraded := True;
          end
          else
          begin
            // non-101: the peer answered over HTTP/1.1 and the response head
            // is already partly read, so this socket can no longer be handed
            // to a fresh HTTP/1.1 codec.  Close it and speak plain HTTP/1.1 on
            // a NEW connection (dialled through the same factory, so the
            // codec/policy selection is unchanged), which then gets pooled
            // (doc/design/fallback.md: "keep the HTTP/1.1 connection").
            Sock.Close;
            Sock := DialFor(AHost, APort, AScheme, FConnectTimeoutMs, Protocol);
            AConn := WrapHttp1(Sock, AOrigin);
          end;
        end;
    end;
  except
    // a failure mid-handshake leaves the socket unusable; StartHttp2/WrapHttp1
    // only own it once they have returned
    if AConn = nil then
      Sock.Close;
    raise;
  end;
  Result := AConn <> nil;
end;

function TConnectionPool.Acquire(const AOrigin, AHost: string;
  const APort: Word; const ARequest: TStreamRequest;
  const AHeaderTimeoutMs: Integer;
  const AToken: ICancellationToken): IHttpResponse;
var
  Deadline: QWord;
  Conn: IPooledConnection;
  Acquired, Upgraded: Boolean;
  Sliced: Integer;
begin
  Deadline := GetTickCount64 + QWord(AHeaderTimeoutMs);
  while True do
  begin
    if (AToken <> nil) and AToken.IsCancelled then
      raise EHttpStreamError.Create('request cancelled', 0, ecCancel);
    Upgraded := False;
    FLock.Acquire;
    try
      ReapClosed;
      ReapIdleLocked;
      Conn := PickEligible(AOrigin);
      if (Conn = nil) and CanOpenNew then
      begin
        // the one transport-selection point: TLS vs cleartext and the HTTP/2
        // vs HTTP/1.1 codec (doc/design/fallback.md "Negotiation")
        OpenForTxn(AOrigin, AHost, APort, ARequest, AHeaderTimeoutMs,
          ARequest.Scheme, Conn, Upgraded);
      end;
    finally
      FLock.Release;
    end;

    if Upgraded then
    begin
      // h2c upgrade: the 101 switch already happened inside the handshake, so
      // adopt stream 1 and wait for its response (RFC 7540 section 3.2: the
      // request is never re-sent).  FLock is released so a slow stream-1
      // response never blocks other origins.
      Result := (Conn as THttpConnection).AcquireUpgraded(ARequest,
        AHeaderTimeoutMs);
      Exit;
    end;

    if Conn <> nil then
    begin
      // an HTTP/1.1 pooled connection has no cancellable path (one request in
      // flight, no RST_STREAM); Acquire either returns at once or raises
      if (AToken <> nil) and (Conn.Conn <> nil) then
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
    AIdleTimeoutMs, AObserver, AHttp1Fallback, AClearTextPolicy);
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
  // the cleartext guard (doc/design/fallback.md): the default ctReject raises
  // before any socket is dialled; ctPriorKnowledge/ctUpgrade proceed and the
  // pool's DialProtocol applies the same policy again on the wire
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
