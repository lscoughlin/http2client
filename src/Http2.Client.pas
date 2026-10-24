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
  Sockets, DateUtils,
  Http2.Errors, Http2.ClientCert, Http2.Frames, Http2.Headers, Http2.Hpack,
  Http2.Tls, Http2.Connection, Http2.Stream, Http2.Observer, Http2.Messages,
  Http2.Http1, Http2.Encoding, Http2.Proxy, Http2.WebSocket,
  Http2.Clock, Http2.RequestObserver;

const
  /// documented factory defaults (doc/design/client-api.md "HttpClientFactory")
  ///
  /// Two connection caps apply (doc/design/architecture.md "resolved model"):
  /// MaxConnectionsPerHost is the reuse/parallelism budget for one authority
  /// (RFC 9113 section 9.1 says a client SHOULD NOT open more than one, but a
  /// small cap lets a small number of connections carry the load);
  /// MaxTotalConnections bounds the file descriptors and TLS memory across
  /// every origin.  MaxStreamsPerConnection is the per-connection request cap
  /// and is applied on top of the peer's SETTINGS_MAX_CONCURRENT_STREAMS.
  cDefaultMaxConnectionsPerHost   = 4;
  cDefaultMaxTotalConnections     = 32;
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
  /// pool opens more connections for concurrency, bounded per host by
  /// MaxConnectionsPerHost and pool-wide by MaxTotalConnections
  cHttp1StreamLimit               = 1;

type
  // TClearTextPolicy and TNegotiatedProtocol come from Http2.Messages.pas

  // the proxy types live in Http2.Proxy; re-exported so a caller that only
  // uses Http2.Client can name them (the TProxyKind VALUES need Http2.Proxy in
  // the uses clause, as with TClearTextPolicy)
  IProxy = Http2.Proxy.IProxy;
  IProxySelector = Http2.Proxy.IProxySelector;
  TProxy = Http2.Proxy.TProxy;
  TProxyKind = Http2.Proxy.TProxyKind;
  TEnvLookup = Http2.Proxy.TEnvLookup;

  // the WebSocket types live in Http2.WebSocket; re-exported so a caller that
  // only uses Http2.Client can name them and descend from TWebSocketListener
  IWebSocket = Http2.WebSocket.IWebSocket;
  IWebSocketListener = Http2.WebSocket.IWebSocketListener;
  IWebSocketRequest = Http2.WebSocket.IWebSocketRequest;
  TWebSocketListener = Http2.WebSocket.TWebSocketListener;
  TWebSocketRequest = Http2.WebSocket.TWebSocketRequest;

  THttpResponse = class;

  /// dials the transport for one origin. Injected so pool tests need no real
  /// sockets (doc/design/client-api.md "Lease acquisition").
  IHttp2SocketFactory = interface
    function Dial(const AHost: string; const APort: Word;
      const ATimeoutMs: Integer): IHttp2Socket;
  end;

  // ICancellationToken and TCancellationToken live in Http2.Stream.pas: the
  // lease polls the token on a blocked body read, so the type must sit at or
  // below the lease. This unit uses Http2.Stream, so they stay visible to
  // THttpRequest and to every existing caller unchanged.

  /// the production factory: TCP then TLS handshake offering ALPN "h2" (and
  /// "http/1.1" when fallback is on).  It also implements the extended
  /// ICleartextSocketFactory contract (plan S13) by delegating to an owned
  /// TProtocolSocketFactory, so the pool can select TLS vs cleartext and the
  /// HTTP/1.1 vs HTTP/2 codec from one call.  Dial keeps its original
  /// behaviour byte-for-byte: an injected test factory that only knows
  /// IHttp2SocketFactory still works unchanged on the https path.
  TDefaultSocketFactory = class(TInterfacedObject, IHttp2SocketFactory,
    ICleartextSocketFactory, IProxySocketFactory, IHttp1SocketFactory,
    IIdentitySocketFactory)
  private
    FCACertFile: string;
    FInsecure: Boolean;
    FProxyHost: string;
    FProxyPort: Word;
    FIdentity: IClientIdentity;
    FLogger: IHttpLogger;
    FProtocols: TProtocolSocketFactory;
    /// debug line naming the identity a dial to AHost:APort presents: the
    /// origin on a direct route, the proxy on an https proxy route, nothing on
    /// any other route
    procedure LogIdentity(const AHost: string; const APort: Word;
      const AProxy: IProxy; const AIdentity: IClientIdentity);
  public
    /// AIdentity is presented to the origin on a direct TLS connection and to
    /// an https proxy on a proxied one, never to both; ALogger (may be nil)
    /// receives the debug line that names the peer and the identity
    constructor Create(const ACACertFile: string = '';
      const AInsecure: Boolean = False; const AProxyHost: string = '';
      const AProxyPort: Word = 0; const AIdentity: IClientIdentity = nil;
      const ALogger: IHttpLogger = nil);
    /// a copy of this factory that presents the identity and logs to ALogger
    function WithIdentity(const AIdentity: IClientIdentity;
      const ALogger: IHttpLogger): TDefaultSocketFactory;
    function Dial(const AHost: string; const APort: Word;
      const ATimeoutMs: Integer): IHttp2Socket;
    function DialProtocol(const AHost: string; const APort: Word;
      const AScheme: string; const AHttp1Fallback: Boolean;
      const APolicy: TClearTextPolicy; const ATimeoutMs: Integer;
      out AProtocol: TNegotiatedProtocol): IHttp2Socket;
    /// the per-request-proxy entry point (doc/design/proxy.md); AProxy nil
    /// dials directly.  DialProtocol is this with the constructor's fixed proxy
    function DialProtocolVia(const AHost: string; const APort: Word;
      const AScheme: string; const AHttp1Fallback: Boolean;
      const APolicy: TClearTextPolicy; const ATimeoutMs: Integer;
      const AProxy: IProxy;
      out AProtocol: TNegotiatedProtocol): IHttp2Socket;
    /// an HTTP/1.1-only connection, for WebSocket
    function DialHttp1(const AHost: string; const APort: Word;
      const AScheme: string; const ATimeoutMs: Integer;
      const AProxy: IProxy): IHttp2Socket;
    /// DialProtocolVia and DialHttp1 with the identity chosen by the
    /// caller (the selector's answer) instead of the fixed one
    function DialProtocolViaAs(const AHost: string; const APort: Word;
      const AScheme: string; const AHttp1Fallback: Boolean;
      const APolicy: TClearTextPolicy; const ATimeoutMs: Integer;
      const AProxy: IProxy; const AIdentity: IClientIdentity;
      out AProtocol: TNegotiatedProtocol): IHttp2Socket;
    function DialHttp1As(const AHost: string; const APort: Word;
      const AScheme: string; const ATimeoutMs: Integer;
      const AProxy: IProxy; const AIdentity: IClientIdentity): IHttp2Socket;
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
    FBodyReadTimeoutMs: Integer; // per-request body-read deadline
    FBodyReadTimeoutSet: Boolean;
    FContext: IInterface;      // opaque, handed back in THttpAttempt.Context
    FAttemptKind: TAttemptKind;
    FStreamId: Int64;          // SSE reconnect loop id, 0 otherwise
    FReconnect: Integer;
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
    /// offer a content coding for the response body
    /// - the header `accept-encoding` carries AValue (for example
    ///  'gzip, deflate'). A response that answers with one of those codings
    ///  is decoded transparently, so a reader sees plain bytes either way.
    ///  The client offers nothing by default, which keeps a response body
    ///  byte-for-byte what the peer sent.
    function WithAcceptEncoding(const AValue: string): THttpRequest;
    function WithBody(const ABody: THttpBody): THttpRequest;
    function WithBodyWriter(const AWriter: IBodyWriter): THttpRequest;
    /// attach a cancellation token; cancelling it resets the stream in flight
    function WithCancelToken(const AToken: ICancellationToken): THttpRequest;
    /// override the factory HeaderTimeoutMs for this request (0 = default)
    function WithTimeout(const AMs: Integer): THttpRequest;
    /// set the RESPONSE BODY read deadline for this request.
    /// - distinct from WithTimeout, which bounds the wait for response
    ///   headers. 0 here means "wait indefinitely", which a Server-Sent
    ///   Events stream needs because it is idle between events; an unset
    ///   request keeps the header timeout as its body deadline (historic
    ///   behaviour). Use this only for a stream you intend to read lazily.
    function WithSseReadTimeout(const AMs: Integer): THttpRequest;
    /// attach an opaque context object.  The library never inspects it: an
    /// IHttpClientObserver receives it in THttpAttempt.Context for every
    /// attempt (each redirect hop and retry), so an adapter can find its
    /// parent span without a thread-local.  Clone, WithUrl, DropBody and
    /// WithMethodToken keep it.
    function WithContext(const AContext: IInterface): THttpRequest;
    /// mark what an observer sees as THttpAttempt.Kind (akRequest by default).
    /// SseRequest marks its request akSse.  Clone, WithUrl, DropBody and
    /// WithMethodToken keep it.
    function WithAttemptKind(const AKind: TAttemptKind): THttpRequest;
    /// stamp the identity of an SSE reconnect loop: AStreamId is shared by
    /// every connection of the loop and AReconnect counts them from 0.  They
    /// reach THttpAttempt.StreamId and Reconnect.  Kept like the context.
    function WithStream(const AStreamId: Int64;
      const AReconnect: Integer): THttpRequest;
    /// re-target the request at AUrl (used by the redirect loop)
    function WithUrl(const AUrl: string): THttpRequest;
    /// an independent copy, including a deep copy of the headers
    /// - THttpRequest is a value record but FHeaders is an INTERFACE, so a
    ///   plain assignment shares one mutable header map. Mutating a copy
    ///   through WithHeader would therefore also mutate the original. Clone
    ///   breaks that sharing; use it before adding headers to a request you
    ///   did not build yourself (TSseReconnectLoop echoes last-event-id onto
    ///   every reconnect and must not pollute the caller's request).
    function Clone: THttpRequest;
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
    /// the context set with WithContext (nil when none)
    property Context: IInterface read FContext;
    /// what an observer sees as THttpAttempt.Kind
    property AttemptKind: TAttemptKind read FAttemptKind;
    /// the SSE loop id and reconnect count (0 for any other request)
    property StreamId: Int64 read FStreamId;
    property Reconnect: Integer read FReconnect;
    /// this request's header timeout in ms; 0 means "use the factory default"
    property HeaderTimeoutMs: Integer read FHeaderTimeoutMs;
  end;

  /// the public client: Send blocks until status + headers; Close drains
  IHttpClient = interface
    ['{6B1C2D3E-4F50-4A61-9C72-000000000001}']
    function Send(const ARequest: THttpRequest): IHttpResponse; overload;
    /// open a WebSocket (doc/design/websocket.md); the connection is not
    /// pooled and outlives Close of this client until it is closed itself
    function Send(const ARequest: IWebSocketRequest): IWebSocket; overload;
    procedure Close;
  end;

  /// the pure value builder (doc/design/client-api.md "HttpClientFactory").
  /// Every WithX returns a NEW record with one field changed, so a stored
  /// factory can be reused and forked without shared mutable state.
  THttpClientFactory = record
  private
    FMaxConnectionsPerHost: Integer;
    FMaxTotalConnections: Integer;
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
    FProxySelector: IProxySelector;
    FAllProxy: string;
    FProxyEnvVars: Boolean;
    FNoProxy: string;
    FEnvLookup: TEnvLookup;
    FRequestObservers: TArray<IHttpClientObserver>;
    FLogger: IHttpLogger;
    FIdentity: IClientIdentity;
    FIdentityError: string;   // a deferred WithClientCertificateFiles failure
    FIdentitySelector: IClientIdentitySelector;
  public
    class function Create: THttpClientFactory; static;
    /// compatibility shim: sets BOTH the per-host and the total cap to AMax,
    /// so a single-authority pool keeps its historic meaning. Prefer the two
    /// explicit setters below.
    function WithMaxConnections(const AMax: Integer): THttpClientFactory;
    /// cap concurrent TCP connections to one authority (`host:port`)
    function WithMaxConnectionsPerHost(const AMax: Integer): THttpClientFactory;
    /// cap concurrent TCP connections across every authority combined
    function WithMaxTotalConnections(const AMax: Integer): THttpClientFactory;
    function WithMaxStreamsPerConnection(const AMax: Integer): THttpClientFactory;
    function WithFollowRedirects(const AFollow: Boolean): THttpClientFactory;
    function WithMaxRedirects(const AMax: Integer): THttpClientFactory;
    function WithProxy(const AHost: string; const APort: Word): THttpClientFactory;
    /// the proxy for the request is chosen by ASelector (nil = direct); it
    /// overrides every other proxy setting (doc/design/proxy.md)
    function WithProxySelector(const ASelector: IProxySelector): THttpClientFactory;
    /// one proxy URL ('[scheme://][user[:password]@]host[:port]', schemes
    /// http, https, socks5, socks5h) for every scheme without a more specific
    /// proxy; the manual form of all_proxy.  '' clears it.
    function WithAllProxy(const AUrl: string): THttpClientFactory;
    /// read http_proxy, https_proxy, all_proxy and no_proxy from the process
    /// environment when Build runs.  Off by default.
    function WithProxyEnvironmentVars(const AEnable: Boolean = True): THttpClientFactory;
    /// hosts that always connect directly: the no_proxy grammar (comma list;
    /// '*', domain suffixes, host:port, IP literals, CIDR).  Repeated calls
    /// append.
    function WithNoProxy(const AList: string): THttpClientFactory;
    /// test seam: read the proxy variables through ALookup instead of the
    /// process environment (nil restores the process environment)
    function WithProxyEnvironmentLookup(const ALookup: TEnvLookup): THttpClientFactory;
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
    /// present AIdentity (doc/design/mtls.md "Where it applies") to the peer
    /// the client dials: the origin on a direct TLS connection (HTTP/2,
    /// HTTP/1.1, SSE and wss), the proxy on the TLS leg of an https:// proxy
    /// route.  The origin leg inside a tunnel never presents it, and a route
    /// through an http:// or socks5:// proxy presents it nowhere.  Cleartext
    /// direct connections ignore it.  Build raises EHttpTlsConfigError when
    /// the leaf certificate has expired.  nil removes it.
    function WithClientIdentity(const AIdentity: IClientIdentity): THttpClientFactory;
    /// ask ASelector for the identity of each new connection that presents
    /// one (doc/design/mtls.md "Selector"), in place of a fixed identity.  It
    /// is called once per dial, on the dialling thread and outside the pool
    /// lock, with the host and port of the peer that receives the identity:
    /// the origin on a direct route, the proxy on an https:// proxy route, and
    /// never on a route that presents none; nil presents no
    /// certificate and an exception fails that dial with EHttpTlsConfigError.
    /// A selector that returns a fresh identity rotates the certificate: the
    /// next new connection presents it and older connections serve until they
    /// close.  The pool key then carries the identity fingerprint, so two
    /// identities never share a connection.  nil removes it.
    function WithClientIdentitySelector(
      const ASelector: IClientIdentitySelector): THttpClientFactory;
    /// load a PEM certificate chain (leaf first) and key, then WithClientIdentity.
    /// A file that cannot be loaded raises EHttpTlsConfigError from Build, so
    /// the passphrase is not kept past this call.
    function WithClientCertificateFiles(const ACertFile, AKeyFile: string;
      const APassphrase: string = ''): THttpClientFactory;
    /// offer "http/1.1" as an ALPN alternative and accept an HTTP/1.1
    /// response when the peer does not select "h2" (doc/design/fallback.md).
    /// Off by default: strict mode keeps failing loudly (interop A.9).
    function WithHttp1Fallback(const AEnable: Boolean = True): THttpClientFactory;
    /// select the cleartext policy for "http" origins.  The default ctReject
    /// raises EHttpProtocolError; ctPriorKnowledge speaks HTTP/2 at once;
    /// ctUpgrade tries the HTTP/1.1 Upgrade dance first (doc/design/fallback.md);
    /// ctHttp1 speaks cleartext HTTP/1.1 with no Upgrade probe.
    function WithClearText(const APolicy: TClearTextPolicy): THttpClientFactory;
    /// observability seam: every connection opened by Build reports its
    /// connection/stream/frame events to AObserver (doc/design/
    /// testing-observability.md). Nil disables observation.
    function WithObserver(const AObserver: IHttp2Observer): THttpClientFactory;
    /// request-level observability (doc/design/request-observability.md):
    /// AObserver is told when each attempt starts, gets response headers,
    /// redirects, retries and ends, and may inject headers into every attempt.
    /// Each call adds an observer; start callbacks run in registration order
    /// and end callbacks in reverse.  A nil observer is ignored.
    function WithRequestObserver(
      const AObserver: IHttpClientObserver): THttpClientFactory;
    /// receives library diagnostics, such as an observer that raised
    function WithLogger(const ALogger: IHttpLogger): THttpClientFactory;
    function Build: IHttpClient;

    /// compatibility alias for MaxConnectionsPerHost
    property MaxConnections: Integer read FMaxConnectionsPerHost;
    property MaxConnectionsPerHost: Integer read FMaxConnectionsPerHost;
    property MaxTotalConnections: Integer read FMaxTotalConnections;
    property MaxStreamsPerConnection: Integer read FMaxStreamsPerConnection;
    property FollowRedirects: Boolean read FFollowRedirects;
    property MaxRedirects: Integer read FMaxRedirects;
    property ConnectTimeoutMs: Integer read FConnectTimeoutMs;
    property HeaderTimeoutMs: Integer read FHeaderTimeoutMs;
    property IdleTimeoutMs: Integer read FIdleTimeoutMs;
    property ProxyHost: string read FProxyHost;
    property ProxyPort: Word read FProxyPort;
    property ProxySelector: IProxySelector read FProxySelector;
    property AllProxy: string read FAllProxy;
    property ProxyEnvironmentVars: Boolean read FProxyEnvVars;
    property NoProxy: string read FNoProxy;
    property CACertFile: string read FCACertFile;
    property InsecureTls: Boolean read FInsecure;
    property ClientIdentity: IClientIdentity read FIdentity;
    property ClientIdentitySelector: IClientIdentitySelector
      read FIdentitySelector;
    property Observer: IHttp2Observer read FObserver;
    property RequestObservers: TArray<IHttpClientObserver>
      read FRequestObservers;
    property Logger: IHttpLogger read FLogger;
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
  TGuardedBody = class(TInterfacedObject, IHttpBodyStream, IStampedBodyStream)
  private
    FInner: IHttpBodyStream;
    FLock: TCriticalSection;
    FLease: TStreamLease;    // weak; the response keeps the lease alive
  public
    constructor Create(const AInner: IHttpBodyStream;
      const ALock: TCriticalSection; const ALease: TStreamLease = nil);
    function Read(var ABuffer; const ACount: LongInt): LongInt;
    function Eof: Boolean;
    /// the stamp of the last Read's frame (0 when the inner body is not
    /// stamped)
    function LastReadArrivedUs: Int64;
  end;

  /// the concrete response: typed status/headers plus a streamed body. It
  /// holds the pooled connection by interface so the underlying TConnection
  /// outlives the pool release while the body is still being read.
  THttpResponse = class(TInterfacedObject, IHttpResponse, IAttemptProgress)
  private
    FLease: TStreamLease;
    FProgress: IAttemptProgress;
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
    /// the reporter a reader of the body uses (Supports(Response,
    /// IAttemptProgress)); it does nothing when the request is not observed
    property Progress: IAttemptProgress read FProgress
      implements IAttemptProgress;
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
  /// no exposed raw handle (TLS) is read through IPartialReader instead, which
  /// returns what is available.
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
    /// finish the response of a request already written on this socket (the
    /// declined h2c upgrade probe) and mark the connection busy until its body
    /// is drained
    function Resume(const ARequest: TStreamRequest;
      const AStatusLine: string): IHttpResponse;
    function Closed: Boolean;
    procedure Drain;
    procedure ReleaseIfIdle;
    function GetConn: TConnection;
    function GetOrigin: string;
    function GetLock: TCriticalSection;
    function GetKey: Pointer;
  end;

  /// one pooled connection in a pool snapshot (doc/design/request-observability.md
  /// "Pull-based pool statistics").  A value: it points at nothing in the pool.
  TConnectionStats = record
    Protocol: TNegotiatedProtocol;
    State: TConnectionState;
    AgeMs, IdleMs: Int64;
    ActiveStreams: Integer;
    /// the peer's settings; 0 for HTTP/1.1
    PeerMaxConcurrentStreams: LongWord;
    PeerInitialWindowSize: LongWord;
    PeerMaxFrameSize: LongWord;
  end;

  /// one pool key in a snapshot: the origin, including the proxy route
  TOriginStats = record
    Origin: string;
    Connections, IdleConnections, ActiveStreams, PendingAcquires: Integer;
    Details: TArray<TConnectionStats>;
  end;

  /// a point-in-time copy of the pool's counts, taken under the pool lock
  TPoolStats = record
    Connections, IdleConnections, ActiveStreams, PendingAcquires: Integer;
    PerOrigin: TArray<TOriginStats>;
  end;

  /// the connection pool (doc/design/client-api.md "Lease acquisition"):
  /// a TDictionary<string,TList<IPooledConnection>> guarded by a critical
  /// section, with a per-origin connection cap (MaxConnectionsPerHost), a
  /// pool-wide cap (MaxTotalConnections) and per-origin reuse.
  TConnectionPool = class
  private
    FLock: TCriticalSection;
    FByOrigin: TDictionary<string, TList<IPooledConnection>>;
    FFactory: IHttp2SocketFactory;
    FMaxConnectionsPerHost: Integer;
    FMaxTotalConnections: Integer;
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
    /// when a pooled connection was registered, keyed like FIdleSince
    FCreatedAt: TDictionary<Pointer, QWord>;
    /// callers parked in Acquire waiting for a slot, per origin key
    FPending: TDictionary<string, Integer>;
    /// the selector that chooses the origin identity of each new TLS
    /// connection (nil = the factory's fixed identity); set once by Build
    FIdentitySelector: IClientIdentitySelector;
    /// the fingerprint the last dial to a pool key presented, so a request
    /// finds its connections without calling the selector; guarded by FLock
    FIdentityKeys: TDictionary<string, string>;
    /// the TCP+TLS-or-cleartext dial for ARequest's scheme (fallback on https,
    /// the policy on http); out AProtocol names the negotiated wire protocol.
    /// Uses the extended ICleartextSocketFactory contract when the factory
    /// supports it, else the legacy Dial (npHttp2Tls) so an injected test
    /// factory keeps working
    // - AUseIdentity True hands AIdentity (the selector's answer, possibly
    //   nil) to a factory that takes the identity per dial
    function DialFor(const AHost: string; const APort: Word;
      const AScheme: string; const ATimeoutMs: Integer; const AProxy: IProxy;
      const AUseIdentity: Boolean; const AIdentity: IClientIdentity;
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
    /// AFirst is the response of a declined upgrade, already drawn from the
    /// pooled HTTP/1.1 connection by the request the probe carried.
    function OpenForTxn(const AOrigin, AHost: string; const APort: Word;
      const ARequest: TStreamRequest; const AHeaderTimeoutMs: Integer;
      const AScheme: string; const AProxy: IProxy;
      const AUseIdentity: Boolean; const AIdentity: IClientIdentity;
      out AConn: IPooledConnection; out AUpgraded: Boolean;
      out AFirst: IHttpResponse): Boolean;
    /// write the h2c Upgrade request on Sock and read the whole response head
    /// byte by byte.  True => 101 and the socket sits exactly at the HTTP/2
    /// boundary; False => the peer declined, AStatusLine is the status line it
    /// answered with and the socket sits right after it, so the pool carries
    /// on with the HTTP/1.1 codec on the same socket (the request is never
    /// written twice).
    // (RFC 7540 section 3.2 / doc/design/fallback.md "h2c upgrade procedure")
    function TryH2cUpgrade(const Sock: IHttp2Socket;
      const ARequest: TStreamRequest; out AStatusLine: string): Boolean;
    procedure ReapClosed;
    procedure ReapIdleLocked;
    procedure MarkUsed(const C: IPooledConnection);
    /// adjust the parked-caller count for AOrigin; the caller holds FLock
    procedure AddPendingLocked(const AOrigin: string; const ADelta: Integer);
    function ListFor(const AOrigin: string): TList<IPooledConnection>;
    function PickEligible(const AOrigin: string): IPooledConnection;
    /// can a new connection be opened for AOrigin? False when the origin is
    /// already at MaxConnectionsPerHost, or the pool is at MaxTotalConnections.
    function CanOpenNew(const AOrigin: string): Boolean;
    procedure Register(const AOrigin: string;
      const AConn: IPooledConnection);
  public
    constructor Create(const AFactory: IHttp2SocketFactory;
      const AMaxConnectionsPerHost, AMaxTotalConnections,
      AMaxStreamsPerConnection, AConnectTimeoutMs, AHeaderTimeoutMs,
      AIdleTimeoutMs: Integer; const AObserver: IHttp2Observer = nil;
      const AHttp1Fallback: Boolean = False;
      const AClearTextPolicy: TClearTextPolicy = ctReject);
    destructor Destroy; override;
    /// acquire a lease on the least-loaded eligible connection, opening a new
    /// one or waiting for a slot per doc/design/client-api.md. When AToken is
    /// non-nil the wait is cancellable (plan S10 task 10.8).  The request's
    /// scheme selects TLS vs cleartext and the HTTP/2 vs HTTP/1.1 codec.
    /// AOrigin is the pool key (the plain origin when direct, origin plus the
    /// proxy route otherwise); AProxy is the route to dial on a new connection.
    /// With an identity selector installed an https request is keyed by the
    /// identity fingerprint as well, and the selector is asked (outside FLock)
    /// only when a new connection has to be dialled
    function Acquire(const AOrigin, AHost: string; const APort: Word;
      const ARequest: TStreamRequest; const AHeaderTimeoutMs: Integer;
      const AToken: ICancellationToken = nil;
      const AProxy: IProxy = nil): IHttpResponse;
    /// close and remove connections idle for longer than IdleTimeoutMs, so
    /// the pool stays within MaxTotalConnections (plan S10 task 10.7).
    procedure ReapIdle;
    procedure Close;
    /// install the identity selector (called by Build, before any request)
    property IdentitySelector: IClientIdentitySelector
      read FIdentitySelector write FIdentitySelector;
    /// a snapshot of the counts, copied under FLock and returned by value
    function Stats: TPoolStats;
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
    /// nil = every route is direct (doc/design/proxy.md)
    FProxySelector: IProxySelector;
    FFactory: IHttp2SocketFactory;
    FConnectTimeoutMs: Integer;
    /// the request observers folded into one (nil when none is installed)
    FRequestObserver: IHttpClientObserver;
    FClonedAttempts: Integer;
    /// nil = the factory's fixed identity (or none)
    FIdentitySelector: IClientIdentitySelector;
    function SendOnce(const ARequest: THttpRequest;
      const AExchange: IExchangeObserver): IHttpResponse;
  public
    constructor Create(const AFactory: IHttp2SocketFactory;
      const AMaxConnectionsPerHost, AMaxTotalConnections,
      AMaxStreamsPerConnection: Integer;
      const AFollowRedirects: Boolean; const AMaxRedirects,
      AConnectTimeoutMs, AHeaderTimeoutMs, AIdleTimeoutMs: Integer;
      const AObserver: IHttp2Observer = nil;
      const AHttp1Fallback: Boolean = False;
      const AClearTextPolicy: TClearTextPolicy = ctReject;
      const AProxySelector: IProxySelector = nil);
    destructor Destroy; override;
    function Send(const ARequest: THttpRequest): IHttpResponse; overload;
    function Send(const ARequest: IWebSocketRequest): IWebSocket; overload;
    procedure Close;
    /// a snapshot of the connection pool for polling gauges; all zeros once the
    /// client is closed.  Safe from any thread.
    function PoolStats: TPoolStats;
    /// install the request-level observers and logger (called by Build)
    procedure InstallRequestObservers(
      const AObservers: TArray<IHttpClientObserver>;
      const ALogger: IHttpLogger);
    /// install the origin identity selector (called by Build)
    procedure InstallIdentitySelector(const ASelector: IClientIdentitySelector);
    /// the pool (test seam)
    property Pool: TConnectionPool read FPool;
    /// attempts that were cloned for an observer (test seam): stays 0 for a
    /// client with no request observer
    property ClonedAttempts: Integer read FClonedAttempts;
  end;

  /// reads a whole response body and decodes it to T. Under {$mode delphi} a
  /// class-level generic compiles (doc/design/messages.md "Syntax note").
  ///
  /// The decoded result depends on the type kind of T:
  /// - `string` / `AnsiString` / `UTF8String`: the raw body bytes as text
  ///   (UTF8String is an AnsiString on FPC 3.2.4, so it lands here too).
  /// - a dynamic array of bytes: the raw body bytes.
  /// - any other type: the raw body bytes are memcpy'd into T, so the body
  ///   must be at least SizeOf(T) bytes (a short body raises EHttpProtocolError).
  ///
  /// Structured formats (JSON, XML) live in Http2.Readers.pas so the 14-unit
  /// core library keeps no fpjson/fcl-xml dependency.
  TResponseReader<T> = class(TInterfacedObject, IResponseReader<T>)
  public
    function Read(const AResponse: IHttpResponse): T; overload;
    class procedure Read(const AResponse: IHttpResponse;
      out AValue: T); overload; static;
  end;

  /// pointer used by TResponseReader<T> to store a dynamic-array result
  PBytesValue = ^TBytes;

/// attach AText as the request body and set `content-type: text/plain` when the
/// request carries no content-type yet. The text bytes are copied verbatim (on
/// FPC 3.2.4 an AnsiString/string is UTF-8 on this platform).
function WithTextBody(const ARequest: THttpRequest;
  const AText: string): THttpRequest;

/// read a whole response body as text (the body bytes copied verbatim; UTF-8
/// when the peer sends UTF-8, which is the HTTP/2 default for text)
function ReadText(const AResponse: IHttpResponse): string;

/// split a URL into host, port and path+query; default port is 443 (TLS)
procedure ParseHttpUrl(const AUrl: string; out AHost: string; out APort: Word;
  out APath: string);

/// the host as written in a host[:port] string: an IPv6 literal (ParseHttpUrl
/// returns it without brackets) gets its brackets back
function BracketedHost(const AHost: string): string;

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

uses
  Http2.WebSocketClient;

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

  // userinfo never reaches :authority or the dial: drop everything up to the
  // last '@' (RFC 3986 section 3.2)
  for P := Length(AuthorityPart) downto 1 do
    if AuthorityPart[P] = '@' then
    begin
      AuthorityPart := Copy(AuthorityPart, P + 1, MaxInt);
      Break;
    end;

  PortStr := '';
  if Copy(AuthorityPart, 1, 1) = '[' then
  begin
    // bracketed IPv6 literal (RFC 3986): the host is returned WITHOUT the
    // brackets, which are re-added wherever a host:port string is written
    P := Pos(']', AuthorityPart);
    if P = 0 then
      raise EHttpProtocolError.Create('invalid URL host: unterminated "["',
        ecProtocolError);
    AHost := Copy(AuthorityPart, 2, P - 2);
    Rest := Copy(AuthorityPart, P + 1, MaxInt);
    if Rest <> '' then
    begin
      if Rest[1] <> ':' then
        raise EHttpProtocolError.Create('invalid URL host: junk after "]"',
          ecProtocolError);
      PortStr := Copy(Rest, 2, MaxInt);
    end;
  end
  else
  begin
    Colon := Pos(':', AuthorityPart);
    if Colon > 0 then
    begin
      AHost := Copy(AuthorityPart, 1, Colon - 1);
      PortStr := Copy(AuthorityPart, Colon + 1, Length(AuthorityPart));
    end
    else
      AHost := AuthorityPart;
  end;
  if PortStr <> '' then
  begin
    Port := StrToIntDef(PortStr, APort);
    if (Port <= 0) or (Port > 65535) then
      raise EHttpProtocolError.Create('invalid URL port: ' + PortStr,
        ecProtocolError);
    APort := Word(Port);
  end;

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

function BracketedHost(const AHost: string): string;
begin
  if (Pos(':', AHost) > 0) and (Copy(AHost, 1, 1) <> '[') then
    Result := '[' + AHost + ']'
  else
    Result := AHost;
end;

function OriginOfUrl(const AUrl: string): string;
var
  Host, Path, Scheme: string;
  Port: Word;
begin
  ParseHttpUrl(AUrl, Host, Port, Path);
  Host := BracketedHost(Host);
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

function WithTextBody(const ARequest: THttpRequest;
  const AText: string): THttpRequest;
var
  B: TBytes;
begin
  SetLength(B, Length(AText));
  if Length(B) > 0 then
    Move(AText[1], B[0], Length(B));
  Result := ARequest.WithBody(THttpBody.FromBytes(B));
  if (Result.Headers = nil) or (not Result.Headers.Contains(HeaderContentType)) then
    Result := Result.WithHeader(HeaderContentType, 'text/plain');
end;

function ReadText(const AResponse: IHttpResponse): string;
var
  Raw: TBytes;
begin
  if AResponse = nil then
    raise EHttpProtocolError.Create('response is nil', ecInternalError);
  Raw := ReadAllBodyBytes(AResponse.Body);
  SetLength(Result, Length(Raw));
  if Length(Raw) > 0 then
    Move(Raw[0], Result[1], Length(Raw));
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


type
  /// the header sink over the headers of one WebSocket handshake: it starts
  /// as the request's own list and keeps what the observers inject
  // - the names the handshake owns are refused the way
  //   IWebSocketRequest.WithHeader refuses them
  TWsHandshakeSink = class(TInterfacedObject, IHeaderSink)
  private
    FFields: TArray<TWsHeaderField>;
  public
    constructor Create(const AFields: TArray<TWsHeaderField>);
    procedure SetValue(const AName, AValue: string);
    function GetFirst(const AName: string): string;
    function Fields: TArray<TWsHeaderField>;
  end;

  /// follows one observed attempt from OnAttemptStart to OnAttemptEnd
  // - the codecs report the end of the exchange through IExchangeObserver
  //   from whichever thread finishes the body or releases the response; Send
  //   reports the start, the headers and any failure.  OnAttemptEnd fires
  //   once, after OnResponseHeaders: an end that arrives before Send has
  //   armed the tracker (a bodyless response, a connection failure in that
  //   window) is held until Arm.
  // - a reader of the body (the SSE source) reports its own messages through
  //   IAttemptProgress, which the response exposes.  Those aggregates replace
  //   the codec's per-frame ones, and a message observer that asked for the
  //   kind is called for each.  Because the codec delivers a clean end inside
  //   the Read that returns the last bytes, a reader brackets its reads with
  //   ReadBegin and ReadEnd and the end is held until ReadEnd, so the last
  //   messages are counted before OnAttemptEnd.
  // - a WebSocket session is one attempt too: the connection reports through
  //   IWebSocketAttempt (the handshake and the end) and IAttemptProgress (each
  //   message), and the end takes the same latch as every other end
  TAttemptTracker = class(TInterfacedObject, IExchangeObserver,
    IAttemptProgress, IWebSocketAttempt)
  private
    FObserver: IHttpClientObserver;
    FToken: IInterface;
    FStartUs: Int64;
    FCancelToken: ICancellationToken;
    FStatus: LongInt;
    FProtocol: TNegotiatedProtocol;
    FReused: Boolean;
    FBytesOut: Int64;
    FRequestSentUs: Int64;
    FRequestWritten: Boolean;
    FHeadersUs: Int64;
    // an end reported before Send armed the tracker
    FEndAbandoned: Boolean;
    // the body chunk arrivals the codec reported with the end
    FArrivals: TArrivalStats;
    FEndBytesIn: Int64;
    FEndBytesOut: Int64;
    FEndHasError: Boolean;
    FEndErrorText: string;
    FArmed: LongInt;
    FEnded: LongInt;
    FFired: LongInt;
    // the per-message path: asked once per attempt in Start
    FMessages: IHttpMessageObserver;
    FWanted: TMessageKinds;
    // what a reader reported; guarded by FProgressLock
    FProgressLock: TCriticalSection;
    FReaderIn: TArrivalStats;
    FReaderOut: Int64;
    FInIndex, FOutIndex: Int64;
    FInLastUs, FOutLastUs: Int64;
    // a clean end held back while a reader is inside a Read
    FInRead: LongInt;
    FHeld: LongInt;            // 0 none, 1 held, 2 claimed
    FHeldEnd: TExchangeEnd;
    // WebSocket: written by the thread that wins the end latch, or before
    // the reader thread exists
    FSink: TWsHandshakeSink;   // weak: FSinkRef holds it
    FSinkRef: IHeaderSink;
    FSubprotocol: string;
    FWsClosedBy: TCloseInitiator;
    FWsCloseCode: Integer;
    FWsCloseReason: string;
    procedure TryFireHeld;
    procedure Dispatch(const AError: Exception; const AAbandoned: Boolean;
      const ABytesIn, ABytesOut: Int64);
    procedure TryFireEarly;
    procedure BeginAttempt(const A: THttpAttempt);
  public
    constructor Create(const AObserver: IHttpClientObserver);
    destructor Destroy; override;
    /// build the attempt for ARequest (whose headers are a private clone) and
    /// run OnAttemptStart
    procedure Start(const ARequest: THttpRequest; const AHop,
      ARetry: Integer);
    /// the same for a WebSocket request, before it dials
    procedure StartSocket(const ARequest: IWebSocketRequest; const AHost: string;
      const APort: Word; const ASecure: Boolean);
    /// a WebSocket attempt failed before the session opened: end it with
    /// AError and, for a refused handshake, the status the server answered
    procedure FailHandshake(const AError: Exception);
    procedure GotResponse(const AResponse: IHttpResponse);
    procedure NotifyRedirect(const AFromUrl, AToUrl: string;
      const AStatus: LongInt);
    procedure NotifyRetry(const AReason: string);
    /// the attempt failed in Send: end it with AError (a no-op once ended)
    procedure Fail(const AError: Exception);
    /// Send is done reporting headers (and redirect): an end may now fire
    procedure Arm(const AResponse: IHttpResponse);
    /// Send dropped the response itself (a redirect hop): end now if the
    /// response's release did not
    procedure Drop;
    // IExchangeObserver
    procedure RouteChosen(const AProtocol: TNegotiatedProtocol;
      const AReused: Boolean);
    procedure RequestWritten(const ABytesOut: Int64);
    procedure ExchangeEnded(const AEnd: TExchangeEnd);
    // IAttemptProgress
    function WantedKinds: TMessageKinds;
    procedure ReportMessage(const AKind: TMessageKind;
      const ADirection: TDirection; const AArrivedUs: Int64;
      const ASize: Integer; const ASse: PSseEvent);
    procedure ReadBegin;
    procedure ReadEnd;
    procedure Finish(const ABytesIn: Int64);
    // IWebSocketAttempt
    function HandshakeHeaders: TArray<TWsHeaderField>;
    procedure HandshakeWritten;
    procedure HandshakeAccepted(const AStatus: Integer;
      const AFields: TArray<TWsHeaderField>; const ASubprotocol: string);
    procedure SessionEnded(const AEnd: TWsSessionEnd);
  end;

{ TWsHandshakeSink }

constructor TWsHandshakeSink.Create(const AFields: TArray<TWsHeaderField>);
begin
  inherited Create;
  FFields := Copy(AFields);
end;

procedure TWsHandshakeSink.SetValue(const AName, AValue: string);
var
  I, N: Integer;
begin
  if not WsIsHttpToken(AName) then
    raise EHttpWebSocketError.CreateFmt('"%s" is not a header name', [AName]);
  if WsIsRestrictedHeader(AName) then
    raise EHttpWebSocketError.CreateFmt(
      'header "%s" is set by the handshake and cannot be supplied', [AName]);
  if (Pos(#13, AValue) > 0) or (Pos(#10, AValue) > 0) then
    raise EHttpWebSocketError.Create('a header value cannot contain a line break');
  // replace every value: drop the old ones, then append the new one
  N := 0;
  for I := 0 to High(FFields) do
    if not SameText(FFields[I].Name, AName) then
    begin
      FFields[N] := FFields[I];
      Inc(N);
    end;
  SetLength(FFields, N + 1);
  FFields[N].Name := AName;
  FFields[N].Value := AValue;
end;

function TWsHandshakeSink.GetFirst(const AName: string): string;
var
  I: Integer;
begin
  for I := 0 to High(FFields) do
    if SameText(FFields[I].Name, AName) then
      Exit(FFields[I].Value);
  Result := '';
end;

function TWsHandshakeSink.Fields: TArray<TWsHeaderField>;
begin
  Result := Copy(FFields);
end;

constructor TAttemptTracker.Create(const AObserver: IHttpClientObserver);
begin
  inherited Create;
  FObserver := AObserver;
  FProgressLock := TCriticalSection.Create;
  FStartUs := NowUs;
end;

destructor TAttemptTracker.Destroy;
begin
  FProgressLock.Free;
  inherited Destroy;
end;

procedure TAttemptTracker.Start(const ARequest: THttpRequest; const AHop,
  ARetry: Integer);
var
  A: THttpAttempt;
  Path: string;
begin
  FCancelToken := ARequest.CancelToken;
  A.Kind := ARequest.AttemptKind;
  A.Method := ARequest.MethodToken;
  A.Url := ARequest.Url;
  A.Host := '';
  A.Port := 0;
  try
    ParseHttpUrl(ARequest.Url, A.Host, A.Port, Path);
  except
    // SendOnce raises the same error and the attempt then ends with it
  end;
  A.Hop := AHop;
  A.Retry := ARetry;
  A.StreamId := ARequest.StreamId;
  A.Reconnect := ARequest.Reconnect;
  A.Context := ARequest.Context;
  A.Headers := THeaderSink.Create(ARequest.Headers);
  BeginAttempt(A);
end;

procedure TAttemptTracker.StartSocket(const ARequest: IWebSocketRequest;
  const AHost: string; const APort: Word; const ASecure: Boolean);
var
  A: THttpAttempt;
begin
  FSink := TWsHandshakeSink.Create(ARequest.Headers);
  FSinkRef := FSink;
  // a WebSocket is on its own HTTP/1.1 connection, never a pooled one
  if ASecure then
    FProtocol := npHttp1Tls
  else
    FProtocol := npHttp1Cleartext;
  FReused := False;
  FCancelToken := nil;
  A.Kind := akWebSocket;
  A.Method := 'GET';
  A.Url := ARequest.Url;
  A.Host := AHost;
  A.Port := APort;
  A.Hop := 0;
  A.Retry := 0;
  A.StreamId := 0;
  A.Reconnect := 0;
  A.Context := ARequest.Context;
  A.Headers := FSinkRef;
  BeginAttempt(A);
end;

procedure TAttemptTracker.BeginAttempt(const A: THttpAttempt);
var
  Gate: IHttpMessageGate;
begin
  try
    FToken := FObserver.OnAttemptStart(A);
  except
    FToken := nil;
  end;
  // the message observer is asked once per attempt.  A composite already
  // collected its members' answers in OnAttemptStart; any other observer is
  // asked here.  An empty answer leaves the per-message path switched off.
  FWanted := [];
  FMessages := nil;
  try
    if Supports(FObserver, IHttpMessageObserver, FMessages) then
      if Supports(FObserver, IHttpMessageGate, Gate) then
        FWanted := Gate.WantedFor(FToken)
      else
        FWanted := FMessages.WantsMessages(A);
  except
    FWanted := [];
  end;
  if FWanted = [] then
    FMessages := nil;
end;

procedure TAttemptTracker.GotResponse(const AResponse: IHttpResponse);
begin
  FStatus := AResponse.StatusCode;
  FHeadersUs := NowUs - FStartUs;
  try
    FObserver.OnResponseHeaders(FToken, AResponse);
  except
    // the composite guards its members; this is the last line of defence
  end;
end;

procedure TAttemptTracker.NotifyRedirect(const AFromUrl, AToUrl: string;
  const AStatus: LongInt);
begin
  try
    FObserver.OnRedirect(FToken, AFromUrl, AToUrl, AStatus);
  except
  end;
end;

procedure TAttemptTracker.NotifyRetry(const AReason: string);
begin
  try
    FObserver.OnRetry(FToken, AReason);
  except
  end;
end;

procedure TAttemptTracker.Dispatch(const AError: Exception;
  const AAbandoned: Boolean; const ABytesIn, ABytesOut: Int64);
var
  O: THttpOutcome;
  Arrivals: TArrivalStats;
begin
  FillChar(O, SizeOf(O), 0);
  O.Subprotocol := FSubprotocol;
  O.ClosedBy := FWsClosedBy;
  O.CloseCode := FWsCloseCode;
  O.CloseReason := FWsCloseReason;
  O.StatusCode := FStatus;
  O.Protocol := FProtocol;
  O.ConnectionReused := FReused;
  O.Error := AError;
  O.Abandoned := AAbandoned;
  O.Cancelled := (AError <> nil) and (
    ((AError is EHttpStreamError) and
     (EHttpStreamError(AError).ErrorCode = ecCancel)) or
    ((FCancelToken <> nil) and FCancelToken.IsCancelled));
  O.BytesIn := ABytesIn;
  O.BytesOut := ABytesOut;
  if O.BytesOut < FBytesOut then
    O.BytesOut := FBytesOut;
  O.RequestSentUs := FRequestSentUs;
  O.HeadersUs := FHeadersUs;
  FProgressLock.Acquire;
  try
    // a reader that reported messages (an SSE event is a message, a DATA
    // frame is not) wins over the codec's per-frame arrivals
    if FReaderIn.Count > 0 then
      Arrivals := FReaderIn
    else
      Arrivals := FArrivals;
    O.MessagesOut := FReaderOut;
  finally
    FProgressLock.Release;
  end;
  if Arrivals.Count > 0 then
  begin
    // stamps are absolute clock values; the outcome is relative to the start
    O.FirstMessageUs := Arrivals.FirstUs - FStartUs;
    O.LastMessageUs := Arrivals.LastUs - FStartUs;
    O.MessagesIn := Arrivals.Count;
    O.MaxGapUs := Arrivals.MaxGapUs;
    O.SumGapUs := Arrivals.SumGapUs;
  end;
  O.EndUs := NowUs - FStartUs;
  try
    FObserver.OnAttemptEnd(FToken, O);
  except
  end;
end;

procedure TAttemptTracker.Fail(const AError: Exception);
begin
  if InterlockedCompareExchange(FFired, 1, 0) = 0 then
    Dispatch(AError, False, 0, 0);
end;

procedure TAttemptTracker.TryFireEarly;
var
  E: Exception;
begin
  if InterlockedCompareExchange(FFired, 1, 0) <> 0 then
    Exit;
  E := nil;
  if FEndHasError then
    // the original exception is gone; a connection failure that raced the
    // arming is reported by its text
    E := EHttpError.Create(FEndErrorText, ecInternalError);
  try
    Dispatch(E, FEndAbandoned, FEndBytesIn, FEndBytesOut);
  finally
    E.Free;
  end;
end;

procedure TAttemptTracker.Arm(const AResponse: IHttpResponse);
var
  Done: Boolean;
begin
  // a response that is already complete (HEAD, 204, END_STREAM on the
  // headers) has nothing left to read: end it now rather than at release
  Done := False;
  if (AResponse <> nil) and (AResponse.Body <> nil) then
    Done := AResponse.Body.Eof;
  if Done and (InterlockedCompareExchange(FEnded, 0, 0) = 0) then
  begin
    FEndAbandoned := False;
    FEndBytesIn := 0;
    FEndBytesOut := 0;
    FEndHasError := False;
    InterlockedExchange(FEnded, 1);
  end;
  InterlockedExchange(FArmed, 1);
  if InterlockedCompareExchange(FEnded, 0, 0) = 1 then
    TryFireEarly;
end;

procedure TAttemptTracker.Drop;
begin
  // the response was dropped; if nothing reported its end, it ends abandoned
  if InterlockedCompareExchange(FFired, 1, 0) = 0 then
    Dispatch(nil, True, 0, 0);
end;

procedure TAttemptTracker.RouteChosen(const AProtocol: TNegotiatedProtocol;
  const AReused: Boolean);
begin
  FProtocol := AProtocol;
  FReused := AReused;
end;

procedure TAttemptTracker.RequestWritten(const ABytesOut: Int64);
begin
  // the h2c paths report again after the response head was read (the probe
  // carried the request); the first report is the real write, so a later one
  // may only raise the byte count, never move the stamp
  if ABytesOut > FBytesOut then
    FBytesOut := ABytesOut;
  if FRequestWritten then
    Exit;
  FRequestWritten := True;
  FRequestSentUs := NowUs - FStartUs;
end;

procedure TAttemptTracker.ExchangeEnded(const AEnd: TExchangeEnd);
begin
  FArrivals := AEnd.Arrivals;
  if (AEnd.Error = nil) and (not AEnd.Abandoned) and
     (InterlockedCompareExchange(FArmed, 0, 0) = 1) and
     (InterlockedCompareExchange(FInRead, 0, 0) = 1) then
  begin
    // a reader is inside the Read that ended the body: let it report what
    // that Read returned first
    FHeldEnd := AEnd;
    InterlockedExchange(FHeld, 1);
    if InterlockedCompareExchange(FInRead, 0, 0) = 0 then
      TryFireHeld;
    Exit;
  end;
  if InterlockedCompareExchange(FArmed, 0, 0) = 1 then
  begin
    // armed: report with the live exception
    if InterlockedCompareExchange(FFired, 1, 0) = 0 then
      Dispatch(AEnd.Error, AEnd.Abandoned, AEnd.BytesIn, AEnd.BytesOut);
    Exit;
  end;
  FEndAbandoned := AEnd.Abandoned;
  FEndBytesIn := AEnd.BytesIn;
  FEndBytesOut := AEnd.BytesOut;
  FEndHasError := AEnd.Error <> nil;
  if FEndHasError then
    FEndErrorText := AEnd.Error.ClassName + ': ' + AEnd.Error.Message;
  InterlockedExchange(FEnded, 1);
  // Arm may have run between the check above and the store: look again
  if InterlockedCompareExchange(FArmed, 0, 0) = 1 then
    TryFireEarly;
end;

procedure TAttemptTracker.TryFireHeld;
begin
  if InterlockedCompareExchange(FHeld, 2, 1) <> 1 then
    Exit;
  if InterlockedCompareExchange(FFired, 1, 0) = 0 then
    Dispatch(nil, False, FHeldEnd.BytesIn, FHeldEnd.BytesOut);
end;

function TAttemptTracker.WantedKinds: TMessageKinds;
begin
  Result := FWanted;
end;

procedure TAttemptTracker.ReportMessage(const AKind: TMessageKind;
  const ADirection: TDirection; const AArrivedUs: Int64;
  const ASize: Integer; const ASse: PSseEvent);
var
  M: TMessageInfo;
  Deliver: Boolean;
begin
  // a message that a reader on another thread reports as the attempt ends is
  // not delivered: OnMessage never follows OnAttemptEnd
  if InterlockedCompareExchange(FFired, 0, 0) <> 0 then
    Exit;
  Deliver := AKind in FWanted;
  if Deliver then
    FillChar(M, SizeOf(M), 0);
  FProgressLock.Acquire;
  try
    if ADirection = mdIn then
    begin
      if Deliver then
      begin
        M.Index := FInIndex;
        if FInIndex > 0 then
          M.SinceLastUs := AArrivedUs - FInLastUs;
      end;
      Inc(FInIndex);
      FInLastUs := AArrivedUs;
      if AKind in [mkSseEvent, mkWsText, mkWsBinary] then
        FReaderIn.Note(AArrivedUs);
    end
    else
    begin
      if Deliver then
      begin
        M.Index := FOutIndex;
        if FOutIndex > 0 then
          M.SinceLastUs := AArrivedUs - FOutLastUs;
      end;
      Inc(FOutIndex);
      // senders on several threads may report slightly out of order
      if (Deliver) and (M.SinceLastUs < 0) then
        M.SinceLastUs := 0;
      if AArrivedUs > FOutLastUs then
        FOutLastUs := AArrivedUs;
      if AKind in [mkSseEvent, mkWsText, mkWsBinary] then
        Inc(FReaderOut);
    end;
  finally
    FProgressLock.Release;
  end;
  if not Deliver then
    Exit;
  M.Kind := AKind;
  M.Direction := ADirection;
  M.Size := ASize;
  M.ArrivedUs := AArrivedUs - FStartUs;
  if (AKind = mkSseEvent) and (ASse <> nil) then
  begin
    M.EventType := ASse^.EventType;
    M.EventId := ASse^.Id;
    M.Sse := ASse;
  end;
  // outside every lock; the composite guards its members
  try
    FMessages.OnMessage(FToken, M);
  except
  end;
end;

procedure TAttemptTracker.ReadBegin;
begin
  InterlockedExchange(FInRead, 1);
end;

procedure TAttemptTracker.ReadEnd;
begin
  InterlockedExchange(FInRead, 0);
  TryFireHeld;
end;

procedure TAttemptTracker.Finish(const ABytesIn: Int64);
begin
  if InterlockedCompareExchange(FFired, 1, 0) = 0 then
    Dispatch(nil, False, ABytesIn, 0);
end;

procedure TAttemptTracker.FailHandshake(const AError: Exception);
begin
  if InterlockedCompareExchange(FFired, 1, 0) <> 0 then
    Exit;
  // a refusal carries the status the server answered; no response headers
  // are reported for it
  if AError is EHttpWebSocketHandshakeError then
    FStatus := EHttpWebSocketHandshakeError(AError).StatusCode;
  FWsClosedBy := ciError;
  Dispatch(AError, False, 0, 0);
end;

function TAttemptTracker.HandshakeHeaders: TArray<TWsHeaderField>;
begin
  if FSink <> nil then
    Result := FSink.Fields
  else
    Result := nil;
end;

procedure TAttemptTracker.HandshakeWritten;
begin
  RequestWritten(0);
end;

procedure TAttemptTracker.HandshakeAccepted(const AStatus: Integer;
  const AFields: TArray<TWsHeaderField>; const ASubprotocol: string);
var
  Headers: IHttpHeaders;
  I: Integer;
begin
  FSubprotocol := ASubprotocol;
  Headers := NewHttpHeaders;
  for I := 0 to High(AFields) do
    try
      Headers.Add(AFields[I].Name, AFields[I].Value);
    except
      // a connection-specific name the header map refuses stays off it
    end;
  GotResponse(THttp1Response.Create('HTTP/1.1', AStatus, 'Switching Protocols',
    Headers, nil));
end;

procedure TAttemptTracker.SessionEnded(const AEnd: TWsSessionEnd);
begin
  if InterlockedCompareExchange(FFired, 1, 0) <> 0 then
    Exit;
  FWsClosedBy := AEnd.ClosedBy;
  FWsCloseCode := AEnd.CloseCode;
  FWsCloseReason := AEnd.CloseReason;
  Dispatch(AEnd.Error, AEnd.Abandoned, AEnd.BytesIn, AEnd.BytesOut);
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

/// whether a dial to the origin over AProxy presents a client identity, and
/// to which peer: the origin on a direct TLS route, the proxy on an https
/// proxy route (any origin scheme), nobody otherwise (doc/design/mtls.md
/// "Where it applies")
function IdentityPeer(const AProxy: IProxy; const ASecure: Boolean;
  const AHost: string; const APort: Word; out APeerHost: string;
  out APeerPort: Word): Boolean;
begin
  APeerHost := AHost;
  APeerPort := APort;
  if AProxy = nil then
    Exit(ASecure);
  APeerHost := AProxy.Host;
  APeerPort := AProxy.Port;
  Result := AProxy.Kind = pkHttps;
end;

/// ask ASelector for the identity of a dial to AHost:APort; any exception it
// raises fails the dial with EHttpTlsConfigError carrying its message
function ChooseClientIdentity(const ASelector: IClientIdentitySelector;
  const AHost: string; const APort: Word): IClientIdentity;
begin
  try
    Result := ASelector.Select(AHost, APort);
  except
    on E: Exception do
      raise EHttpTlsConfigError.CreateFmt(
        'the client identity selector failed for %s:%d: %s',
        [AHost, APort, E.Message]);
  end;
end;

type
  /// an HTTP/1.1 dialer that hands one selector answer to the factory, for a
  /// WebSocket dial (it never goes through the pool)
  TIdentityHttp1Dialer = class(TInterfacedObject, IHttp1SocketFactory)
  private
    FFactory: IIdentitySocketFactory;
    FIdentity: IClientIdentity;
  public
    constructor Create(const AFactory: IIdentitySocketFactory;
      const AIdentity: IClientIdentity);
    function DialHttp1(const AHost: string; const APort: Word;
      const AScheme: string; const ATimeoutMs: Integer;
      const AProxy: IProxy): IHttp2Socket;
  end;

constructor TIdentityHttp1Dialer.Create(const AFactory: IIdentitySocketFactory;
  const AIdentity: IClientIdentity);
begin
  inherited Create;
  FFactory := AFactory;
  FIdentity := AIdentity;
end;

function TIdentityHttp1Dialer.DialHttp1(const AHost: string; const APort: Word;
  const AScheme: string; const ATimeoutMs: Integer;
  const AProxy: IProxy): IHttp2Socket;
begin
  Result := FFactory.DialHttp1As(AHost, APort, AScheme, ATimeoutMs, AProxy,
    FIdentity);
end;

{ IHttp2SocketFactory }

constructor TDefaultSocketFactory.Create(const ACACertFile: string;
  const AInsecure: Boolean; const AProxyHost: string; const AProxyPort: Word;
  const AIdentity: IClientIdentity; const ALogger: IHttpLogger);
begin
  inherited Create;
  FCACertFile := ACACertFile;
  FInsecure := AInsecure;
  FProxyHost := AProxyHost;
  FProxyPort := AProxyPort;
  FIdentity := AIdentity;
  FLogger := ALogger;
  FProtocols := TProtocolSocketFactory.Create(ACACertFile, AInsecure, AProxyHost,
    AProxyPort, AIdentity);
end;

function TDefaultSocketFactory.WithIdentity(const AIdentity: IClientIdentity;
  const ALogger: IHttpLogger): TDefaultSocketFactory;
begin
  Result := TDefaultSocketFactory.Create(FCACertFile, FInsecure, FProxyHost,
    FProxyPort, AIdentity, ALogger);
end;

procedure TDefaultSocketFactory.LogIdentity(const AHost: string;
  const APort: Word; const AProxy: IProxy; const AIdentity: IClientIdentity);
var
  PeerHost: string;
  PeerPort: Word;
begin
  if (AIdentity = nil) or (FLogger = nil) then
    Exit;
  // the identity is only presented to the peer IdentityPeer names
  if not IdentityPeer(AProxy, True, AHost, APort, PeerHost, PeerPort) then
    Exit;
  // only the subject and the fingerprint: never the PEM, a path or a passphrase
  try
    FLogger.Log(llDebug, Format(
      'TLS to %s:%d presents client identity subject="%s" fingerprint=%s',
      [PeerHost, PeerPort, AIdentity.Subject, AIdentity.Fingerprint]));
  except
    // a logger that raises must not break a dial
  end;
end;

function TDefaultSocketFactory.Dial(const AHost: string; const APort: Word;
  const ATimeoutMs: Integer): IHttp2Socket;
begin
  LogIdentity(AHost, APort, nil, FIdentity);
  Result := TTlsSocket.Dial(AHost, APort, FInsecure, ATimeoutMs, FCACertFile,
    FProxyHost, FProxyPort, FIdentity);
end;

function TDefaultSocketFactory.DialProtocol(const AHost: string;
  const APort: Word; const AScheme: string; const AHttp1Fallback: Boolean;
  const APolicy: TClearTextPolicy; const ATimeoutMs: Integer;
  out AProtocol: TNegotiatedProtocol): IHttp2Socket;
begin
  Result := DialProtocolVia(AHost, APort, AScheme, AHttp1Fallback, APolicy,
    ATimeoutMs, nil, AProtocol);
end;

function TDefaultSocketFactory.DialHttp1(const AHost: string;
  const APort: Word; const AScheme: string; const ATimeoutMs: Integer;
  const AProxy: IProxy): IHttp2Socket;
begin
  Result := DialHttp1As(AHost, APort, AScheme, ATimeoutMs, AProxy, FIdentity);
end;

function TDefaultSocketFactory.DialHttp1As(const AHost: string;
  const APort: Word; const AScheme: string; const ATimeoutMs: Integer;
  const AProxy: IProxy; const AIdentity: IClientIdentity): IHttp2Socket;
begin
  LogIdentity(AHost, APort, AProxy, AIdentity);
  Result := FProtocols.DialHttp1As(AHost, APort, AScheme, ATimeoutMs, AProxy,
    AIdentity);
end;

function TDefaultSocketFactory.DialProtocolVia(const AHost: string;
  const APort: Word; const AScheme: string; const AHttp1Fallback: Boolean;
  const APolicy: TClearTextPolicy; const ATimeoutMs: Integer;
  const AProxy: IProxy;
  out AProtocol: TNegotiatedProtocol): IHttp2Socket;
begin
  Result := DialProtocolViaAs(AHost, APort, AScheme, AHttp1Fallback, APolicy,
    ATimeoutMs, AProxy, FIdentity, AProtocol);
end;

function TDefaultSocketFactory.DialProtocolViaAs(const AHost: string;
  const APort: Word; const AScheme: string; const AHttp1Fallback: Boolean;
  const APolicy: TClearTextPolicy; const ATimeoutMs: Integer;
  const AProxy: IProxy; const AIdentity: IClientIdentity;
  out AProtocol: TNegotiatedProtocol): IHttp2Socket;
var
  Sock: IHttp2Socket;
  TlsObj: TObject;
  Name: string;
  Proxy: IProxy;
begin
  // a factory built with a fixed proxy (the constructor parameters) keeps
  // tunnelling through it when the caller routes nothing per request, so an
  // injected TDefaultSocketFactory.Create(..., host, port) never falls back
  // to a direct connection
  Proxy := AProxy;
  if (Proxy = nil) and (FProxyHost <> '') then
    Proxy := TProxy.Create(FProxyHost, FProxyPort);

  // cleartext never involves ALPN, so the shared selector is correct there
  if AScheme = 'http' then
  begin
    // an https proxy still receives the identity on its own TLS leg
    if Proxy <> nil then
      LogIdentity(AHost, APort, Proxy, AIdentity);
    Exit(FProtocols.DialProtocolViaAs(AHost, APort, AScheme, AHttp1Fallback,
      APolicy, ATimeoutMs, Proxy, AIdentity, AProtocol));
  end;

  // https: offer the ALPN list the fallback policy asks for, then map the
  // selected name to a codec.  DialWithAlpn reports the name instead of
  // enforcing "h2", so the mapping happens here
  // (doc/design/fallback.md "Negotiation").
  LogIdentity(AHost, APort, Proxy, AIdentity);
  Sock := TTlsSocket.DialWithAlpnVia(AHost, APort, AlpnOfferFor(AHttp1Fallback),
    FInsecure, ATimeoutMs, FCACertFile, Proxy, AIdentity);
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
  Result.FBodyReadTimeoutMs := 0;
  Result.FBodyReadTimeoutSet := False;
  Result.FHeaderTimeoutMs := 0;
  Result.FContext := nil;
  Result.FAttemptKind := akRequest;
  Result.FStreamId := 0;
  Result.FReconnect := 0;
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
  Host := BracketedHost(Host);
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

function THttpRequest.WithAcceptEncoding(const AValue: string): THttpRequest;
begin
  Result := WithHeader(HeaderAcceptEncoding, AValue);
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

function THttpRequest.WithSseReadTimeout(const AMs: Integer): THttpRequest;
begin
  Result := Self;
  Result.FBodyReadTimeoutMs := AMs;
  Result.FBodyReadTimeoutSet := True;
end;

function THttpRequest.WithContext(const AContext: IInterface): THttpRequest;
begin
  Result := Self;
  Result.FContext := AContext;
end;

function THttpRequest.WithAttemptKind(const AKind: TAttemptKind): THttpRequest;
begin
  Result := Self;
  Result.FAttemptKind := AKind;
end;

function THttpRequest.WithStream(const AStreamId: Int64;
  const AReconnect: Integer): THttpRequest;
begin
  Result := Self;
  Result.FStreamId := AStreamId;
  Result.FReconnect := AReconnect;
end;

function THttpRequest.WithUrl(const AUrl: string): THttpRequest;
begin
  Result := Self;
  Result.FUrl := AUrl;
end;

function THttpRequest.Clone: THttpRequest;
var
  Names, Vals: TArray<string>;
  I, J: Integer;
begin
  Result := Self;
  Result.FHeaders := NewHttpHeaders;
  if FHeaders <> nil then
  begin
    Names := FHeaders.Names;
    for I := 0 to High(Names) do
    begin
      Vals := FHeaders.GetValues(Names[I]);
      for J := 0 to High(Vals) do
        Result.FHeaders.Add(Names[I], Vals[J]);
    end;
  end;
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
  if FCancelToken <> nil then
    Result := Result.WithCancelToken(FCancelToken);
  if FBodyReadTimeoutSet then
    Result := Result.WithBodyReadTimeout(FBodyReadTimeoutMs);
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
  Result.FMaxConnectionsPerHost := cDefaultMaxConnectionsPerHost;
  Result.FMaxTotalConnections := cDefaultMaxTotalConnections;
  Result.FMaxStreamsPerConnection := cDefaultMaxStreamsPerConnection;
  Result.FFollowRedirects := cDefaultFollowRedirects;
  Result.FMaxRedirects := cDefaultMaxRedirects;
  Result.FConnectTimeoutMs := cDefaultConnectTimeoutMs;
  Result.FHeaderTimeoutMs := cDefaultHeaderTimeoutMs;
  Result.FIdleTimeoutMs := cDefaultIdleTimeoutMs;
  Result.FProxyHost := '';
  Result.FProxyPort := 0;
  Result.FProxySelector := nil;
  Result.FAllProxy := '';
  Result.FProxyEnvVars := False;
  Result.FNoProxy := '';
  Result.FEnvLookup := nil;
  Result.FCACertFile := '';
  Result.FInsecure := False;
  Result.FIdentity := nil;
  Result.FIdentityError := '';
  Result.FIdentitySelector := nil;
  Result.FObserver := nil;
  Result.FRequestObservers := nil;
  Result.FLogger := nil;
  Result.FHttp1Fallback := cDefaultHttp1Fallback;
  Result.FClearTextPolicy := ctReject;   // strict by default
  Result.FSocketFactory := TDefaultSocketFactory.Create;
end;

function THttpClientFactory.WithMaxConnections(
  const AMax: Integer): THttpClientFactory;
begin
  Result := Self;
  Result.FMaxConnectionsPerHost := AMax;
  Result.FMaxTotalConnections := AMax;
end;

function THttpClientFactory.WithMaxConnectionsPerHost(
  const AMax: Integer): THttpClientFactory;
begin
  Result := Self;
  Result.FMaxConnectionsPerHost := AMax;
end;

function THttpClientFactory.WithMaxTotalConnections(
  const AMax: Integer): THttpClientFactory;
begin
  Result := Self;
  Result.FMaxTotalConnections := AMax;
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
  // the route is chosen per request at Build time (doc/design/proxy.md); the
  // socket factory no longer carries a proxy of its own
end;

function THttpClientFactory.WithProxySelector(
  const ASelector: IProxySelector): THttpClientFactory;
begin
  Result := Self;
  Result.FProxySelector := ASelector;
end;

function THttpClientFactory.WithAllProxy(const AUrl: string): THttpClientFactory;
begin
  Result := Self;
  Result.FAllProxy := Trim(AUrl);
end;

function THttpClientFactory.WithProxyEnvironmentVars(
  const AEnable: Boolean): THttpClientFactory;
begin
  Result := Self;
  Result.FProxyEnvVars := AEnable;
end;

function THttpClientFactory.WithNoProxy(const AList: string): THttpClientFactory;
begin
  Result := Self;
  if Trim(AList) = '' then
    Exit;
  if Result.FNoProxy = '' then
    Result.FNoProxy := Trim(AList)
  else
    Result.FNoProxy := Result.FNoProxy + ',' + Trim(AList);
end;

function THttpClientFactory.WithProxyEnvironmentLookup(
  const ALookup: TEnvLookup): THttpClientFactory;
begin
  Result := Self;
  Result.FEnvLookup := ALookup;
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
  Result.FSocketFactory := TDefaultSocketFactory.Create(AFileName,
    Result.FInsecure);
end;

function THttpClientFactory.WithInsecureTls(
  const AInsecure: Boolean): THttpClientFactory;
begin
  Result := Self;
  Result.FInsecure := AInsecure;
  if not (Result.FSocketFactory is TDefaultSocketFactory) then
    Exit;
  Result.FSocketFactory := TDefaultSocketFactory.Create(Result.FCACertFile,
    AInsecure);
end;

function THttpClientFactory.WithClientIdentity(
  const AIdentity: IClientIdentity): THttpClientFactory;
begin
  Result := Self;
  Result.FIdentity := AIdentity;
  Result.FIdentityError := '';
  Result.FIdentitySelector := nil;
end;

function THttpClientFactory.WithClientIdentitySelector(
  const ASelector: IClientIdentitySelector): THttpClientFactory;
begin
  Result := Self;
  Result.FIdentitySelector := ASelector;
  Result.FIdentity := nil;
  Result.FIdentityError := '';
end;

function THttpClientFactory.WithClientCertificateFiles(const ACertFile,
  AKeyFile: string; const APassphrase: string): THttpClientFactory;
begin
  Result := Self;
  try
    Result.FIdentity := TClientIdentity.FromPemFiles(ACertFile, AKeyFile,
      APassphrase);
    Result.FIdentityError := '';
    Result.FIdentitySelector := nil;
  except
    on E: EHttpTlsConfigError do
    begin
      Result.FIdentity := nil;
      Result.FIdentityError := E.Message;
    end;
  end;
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

function THttpClientFactory.WithRequestObserver(
  const AObserver: IHttpClientObserver): THttpClientFactory;
var
  N: Integer;
begin
  Result := Self;
  if AObserver = nil then
    Exit;
  // the array is shared by value copies of the record: copy before appending
  // so a forked factory never sees its sibling's observers
  N := Length(FRequestObservers);
  Result.FRequestObservers := Copy(FRequestObservers, 0, N);
  SetLength(Result.FRequestObservers, N + 1);
  Result.FRequestObservers[N] := AObserver;
end;

function THttpClientFactory.WithLogger(
  const ALogger: IHttpLogger): THttpClientFactory;
begin
  Result := Self;
  Result.FLogger := ALogger;
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
var
  Fixed: IProxy;
  Env: TProxyEnvironment;
  Selector: IProxySelector;
  Client: THttpClient;
  Factory: IHttp2SocketFactory;
begin
  // a bad identity fails here, not on the first request
  if FIdentityError <> '' then
    raise EHttpTlsConfigError.Create(FIdentityError);
  Factory := FSocketFactory;
  if FIdentity <> nil then
    if FIdentity.NotAfter < LocalTimeToUniversal(Now) then
      raise EHttpTlsConfigError.CreateFmt(
        'the client certificate expired on %s UTC',
        [FormatDateTime('yyyy-mm-dd hh:nn:ss', FIdentity.NotAfter)]);
  // an injected transport factory is the test seam and is left alone; with a
  // selector installed the fixed identity is nil and each dial is handed the
  // selector's answer instead
  if ((FIdentity <> nil) or (FIdentitySelector <> nil)) and
     (Factory is TDefaultSocketFactory) then
    Factory := TDefaultSocketFactory(Factory as TObject).WithIdentity(
      FIdentity, FLogger);
  // every proxy source collapses into one selector here (nil = all direct);
  // an unusable proxy value raises EHttpProxyConfigError before any request
  Fixed := nil;
  if FProxyHost <> '' then
    Fixed := TProxy.Create(FProxyHost, FProxyPort);
  FillChar(Env, SizeOf(Env), 0);
  if FProxyEnvVars then
    if Assigned(FEnvLookup) then
      Env := ReadProxyEnvironmentUsing(FEnvLookup)
    else
      Env := ReadProxyEnvironment;
  Selector := BuildProxySelector(FProxySelector, Fixed, FAllProxy,
    FProxyEnvVars, Env, FNoProxy);
  Client := THttpClient.Create(Factory, FMaxConnectionsPerHost,
    FMaxTotalConnections, FMaxStreamsPerConnection, FFollowRedirects,
    FMaxRedirects, FConnectTimeoutMs, FHeaderTimeoutMs, FIdleTimeoutMs,
    FObserver, FHttp1Fallback, FClearTextPolicy, Selector);
  Client.InstallRequestObservers(FRequestObservers, FLogger);
  Client.InstallIdentitySelector(FIdentitySelector);
  Result := Client;
end;

{ TGuardedBody }

constructor TGuardedBody.Create(const AInner: IHttpBodyStream;
  const ALock: TCriticalSection; const ALease: TStreamLease);
begin
  inherited Create;
  FInner := AInner;
  FLock := ALock;
  FLease := ALease;
end;

function TGuardedBody.Read(var ABuffer; const ACount: LongInt): LongInt;
begin
  try
    FLock.Acquire;
    try
      Result := FInner.Read(ABuffer, ACount);
    finally
      FLock.Release;
    end;
  finally
    // the lease only records the end of the exchange under the connection
    // lock; the observer is told here, once the lock is released
    if FLease <> nil then
      FLease.DeliverEnd;
  end;
end;

function TGuardedBody.Eof: Boolean;
begin
  Result := FInner.Eof;
end;

function TGuardedBody.LastReadArrivedUs: Int64;
var
  Stamped: IStampedBodyStream;
begin
  if Supports(FInner, IStampedBodyStream, Stamped) then
    Result := Stamped.LastReadArrivedUs
  else
    Result := 0;
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
  FProgress := ProgressOf(ALease.Exchange);
  ALease.DeferDelivery := True;
  FBody := TGuardedBody.Create(ALease.Body, AConnRef.Lock, ALease);
end;

destructor THttpResponse.Destroy;
begin
  // a response released before its body was read ends the attempt as
  // abandoned; this runs outside the connection lock
  FLease.AbandonExchange;
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
  Err: EHttpError;
begin
  AAcquired := False;
  FLock.Acquire;
  try
    if FClosing or (not Eligible) then
    begin
      // a server that rejected the client certificate ends the connection
      // right after it opened; that is final, not a reason for the pool to
      // dial again and repeat the rejection
      if (FConn <> nil) and (FConn.State = csClosed) then
      begin
        Err := FConn.FailureError(FConn.ErrorMessage, FConn.ErrorCode);
        if Err is EHttpTlsClientAuthError then
          raise Err;
        Err.Free;
      end;
      Exit;
    end;
    Lease := TStreamLease.Create(FConn, FAllocator, ARequest, FEncoder,
      FDecoder);
    Keep := Lease;
    Lease.TimeoutMs := ATimeoutMs;
    Lease.Start;
    AAcquired := True;
    if ARequest.Exchange <> nil then
      ARequest.Exchange.RequestWritten(Lease.BytesSent);
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
    // a body coded by the peer is decoded here, at the one place every
    // response is built, so ReadText and every typed reader inherit it
    Result := WrapDecodingResponse(THttpResponse.Create(Lease, Keep, Self));
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
    // a body coded by the peer is decoded here (mirrors AcquireCancellable)
    Result := WrapDecodingResponse(THttpResponse.Create(Lease, Keep, Self));
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
  PR: IPartialReader;
begin
  if ACount <= 0 then
    Exit(0);
  if FFd < 0 then
  begin
    // no raw handle (a TLS socket): take whatever the wrapped transport has
    // available.  Its Read insists on the full count, which on a keep-alive
    // connection would wait until the server gave up
    if Supports(FInner, IPartialReader, PR) then
      Exit(PR.ReadSome(ABuffer, ACount));
    Exit(FInner.Read(ABuffer, ACount));
  end;
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

function THttp1PooledConnection.Resume(const ARequest: TStreamRequest;
  const AStatusLine: string): IHttpResponse;
begin
  FLock.Acquire;
  try
    try
      Result := FH1.ResumeResponse(ARequest, AStatusLine);
      FLastBody := Result.Body;
    except
      // a half-read response leaves the stream unusable
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
  const AMaxConnectionsPerHost, AMaxTotalConnections,
  AMaxStreamsPerConnection, AConnectTimeoutMs, AHeaderTimeoutMs,
  AIdleTimeoutMs: Integer; const AObserver: IHttp2Observer;
  const AHttp1Fallback: Boolean; const AClearTextPolicy: TClearTextPolicy);
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FByOrigin := TDictionary<string, TList<IPooledConnection>>.Create;
  FIdleSince := TDictionary<Pointer, QWord>.Create;
  FCreatedAt := TDictionary<Pointer, QWord>.Create;
  FPending := TDictionary<string, Integer>.Create;
  FIdentityKeys := TDictionary<string, string>.Create;
  FFactory := AFactory;
  FObserver := AObserver;
  FMaxConnectionsPerHost := AMaxConnectionsPerHost;
  FMaxTotalConnections := AMaxTotalConnections;
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
  FCreatedAt.Free;
  FPending.Free;
  FIdentityKeys.Free;
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
        FCreatedAt.Remove(C.Key);
        L.Delete(I);
        Dec(FTotalConnections);
      end;
    end;
  end;
end;

procedure TConnectionPool.MarkUsed(const C: IPooledConnection);
begin
  // the first use is registration, which stamps the connection's age
  FCreatedAt.TryAdd(C.Key, GetTickCount64);
  FIdleSince.AddOrSetValue(C.Key, GetTickCount64);
end;

procedure TConnectionPool.AddPendingLocked(const AOrigin: string;
  const ADelta: Integer);
var
  N: Integer;
begin
  if not FPending.TryGetValue(AOrigin, N) then
    N := 0;
  Inc(N, ADelta);
  if N > 0 then
    FPending.AddOrSetValue(AOrigin, N)
  else
    FPending.Remove(AOrigin);
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
      FCreatedAt.Remove(C.Key);
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

function TConnectionPool.CanOpenNew(const AOrigin: string): Boolean;
begin
  Result := (not FClosed) and
            (ListFor(AOrigin).Count < FMaxConnectionsPerHost) and
            (FTotalConnections < FMaxTotalConnections);
end;

function TConnectionPool.DialFor(const AHost: string; const APort: Word;
  const AScheme: string; const ATimeoutMs: Integer; const AProxy: IProxy;
  const AUseIdentity: Boolean; const AIdentity: IClientIdentity;
  out AProtocol: TNegotiatedProtocol): IHttp2Socket;
var
  CF: ICleartextSocketFactory;
  PF: IProxySocketFactory;
  IdFactory: IIdentitySocketFactory;
begin
  // the selector's answer, nil included, replaces the factory's fixed identity
  if AUseIdentity and Supports(FFactory, IIdentitySocketFactory, IdFactory) then
    Exit(IdFactory.DialProtocolViaAs(AHost, APort, AScheme, FHttp1Fallback,
      FClearTextPolicy, ATimeoutMs, AProxy, AIdentity, AProtocol));

  // a factory that takes the route per dial (the default factory) gets the
  // proxy chosen for this request; nil dials directly
  if Supports(FFactory, IProxySocketFactory, PF) then
    Exit(PF.DialProtocolVia(AHost, APort, AScheme, FHttp1Fallback,
      FClearTextPolicy, ATimeoutMs, AProxy, AProtocol));

  // the default factory (and any factory that opted into the extended
  // contract) selects TLS vs cleartext and the ALPN codec for us
  if Supports(FFactory, ICleartextSocketFactory, CF) then
    Exit(CF.DialProtocol(AHost, APort, AScheme, FHttp1Fallback,
      FClearTextPolicy, ATimeoutMs, AProtocol));

  // legacy factory (the injected test seam): it only knows TLS + h2, so an
  // https origin stays strict; a cleartext origin is dialled directly.  Such a
  // factory predates per-request routing and is never given a proxy
  if AScheme = 'http' then
  begin
    if FClearTextPolicy in [ctUpgrade, ctHttp1] then
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
  Err: EHttpError;
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
      // a server that rejected the client certificate closes before the
      // connection opens; report that, not a generic open failure
      if Conn.State = csClosed then
      begin
        Err := Conn.FailureError(Conn.ErrorMessage, Conn.ErrorCode);
        if Err is EHttpTlsClientAuthError then
        begin
          Pooled.Free;
          raise Err;
        end;
        Err.Free;
      end;
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
  const ARequest: TStreamRequest; out AStatusLine: string): Boolean;
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
  AStatusLine := '';
  Raw := BuildH2cUpgradeRequest(ARequest);
  Ofs := 0;
  while Ofs < Length(Raw) do
  begin
    N := Sock.Write(Raw[Ofs], Length(Raw) - Ofs);
    if N <= 0 then
      raise EHttpConnectionClosed.Create('h2c upgrade request write failed');
    Inc(Ofs, N);
  end;
  // the probe carries the request, so this is the moment it was written; the
  // declined and accepted paths report again after the response head was read
  if ARequest.Exchange <> nil then
    ARequest.Exchange.RequestWritten(Length(ARequest.Body.Data));
  if not ReadHeadLineBytewise(Sock, Line) then
    raise EHttpProtocolError.Create('peer closed during the h2c upgrade',
      ecProtocolError);
  ParseStatusLine(Line, Version, Status, Reason);
  Result := Status = 101;
  if not Result then
  begin
    AStatusLine := Line;
    Exit;
  end;
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
  const AProxy: IProxy; const AUseIdentity: Boolean;
  const AIdentity: IClientIdentity;
  out AConn: IPooledConnection; out AUpgraded: Boolean;
  out AFirst: IHttpResponse): Boolean;
var
  Sock: IHttp2Socket;
  Protocol: TNegotiatedProtocol;
  StatusLine: string;
begin
  Result := False;
  AConn := nil;
  AUpgraded := False;
  AFirst := nil;
  Sock := DialFor(AHost, APort, AScheme, FConnectTimeoutMs, AProxy,
    AUseIdentity, AIdentity, Protocol);
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
          // ctUpgrade probes; ctHttp1 never does.  A bodyless request is
          // eligible for the probe; a request with a body is NOT, because
          // that would transmit the body twice (once in the probe, once over
          // HTTP/2).
          if (FClearTextPolicy <> ctUpgrade) or ARequest.Body.IsSet or
            (ARequest.BodyWriter <> nil) then
            AConn := WrapHttp1(Sock, AOrigin)
          else if TryH2cUpgrade(Sock, ARequest, StatusLine) then
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
            // non-101: the probe is a complete HTTP/1.1 request, so the
            // status line the peer answered with belongs to it.  Keep the
            // socket as the pooled HTTP/1.1 connection and finish that
            // response instead of sending the request again
            // (doc/design/fallback.md "h2c upgrade procedure").
            AConn := WrapHttp1(Sock, AOrigin);
            AFirst := (AConn as THttp1PooledConnection).Resume(ARequest,
              StatusLine);
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
  const AToken: ICancellationToken; const AProxy: IProxy): IHttpResponse;
var
  Deadline: QWord;
  Conn: IPooledConnection;
  Acquired, Upgraded: Boolean;
  Sliced: Integer;
  First: IHttpResponse;
  Waiting, Opened: Boolean;
  Protocol: TNegotiatedProtocol;
  Key, PendingKey, Remembered, Fingerprint: string;
  Selecting, Resolved, NeedSelect: Boolean;
  Identity: IClientIdentity;
  PeerHost: string;
  PeerPort: Word;
begin
  Deadline := GetTickCount64 + QWord(AHeaderTimeoutMs);
  Waiting := False;
  PendingKey := AOrigin;
  // a selector only applies to a route that presents an identity (a direct
  // TLS dial, or an https proxy) on a factory that can take it per dial;
  // every other route keeps the plain key, so it never varies by identity.
  // The selector is asked about the peer that receives the identity
  Selecting := (FIdentitySelector <> nil) and
    Supports(FFactory, IIdentitySocketFactory) and
    IdentityPeer(AProxy, ARequest.Scheme = 'https', AHost, APort, PeerHost,
      PeerPort);
  Resolved := False;
  Identity := nil;
  Fingerprint := '';
  try
    while True do
    begin
      if (AToken <> nil) and AToken.IsCancelled then
        raise EHttpStreamError.Create('request cancelled', 0, ecCancel);
      Upgraded := False;
      First := nil;
      Opened := False;
      NeedSelect := False;
      FLock.Acquire;
      try
        // with a selector the key carries the fingerprint: the one the
        // selector just answered, else the one the last dial here presented,
        // so a reused connection never asks the selector again
        Key := AOrigin;
        if Selecting then
        begin
          if Resolved then
            Remembered := Fingerprint
          else if not FIdentityKeys.TryGetValue(AOrigin, Remembered) then
            Remembered := '';
          Key := AOrigin + ' id=' + Remembered;
        end;
        if Waiting and (PendingKey <> Key) then
        begin
          AddPendingLocked(PendingKey, -1);
          AddPendingLocked(Key, 1);
        end;
        PendingKey := Key;
        ReapClosed;
        ReapIdleLocked;
        Conn := PickEligible(Key);
        if (Conn = nil) and CanOpenNew(Key) then
        begin
          if Selecting and not Resolved then
            // a dial is needed: ask the selector outside the lock, then come
            // back and key the new connection by its answer
            NeedSelect := True
          else
          begin
            // the one transport-selection point: TLS vs cleartext and the
            // HTTP/2 vs HTTP/1.1 codec (doc/design/fallback.md "Negotiation")
            OpenForTxn(Key, AHost, APort, ARequest, AHeaderTimeoutMs,
              ARequest.Scheme, AProxy, Selecting, Identity, Conn, Upgraded,
              First);
            Opened := Conn <> nil;
            if Opened and Selecting then
              FIdentityKeys.AddOrSetValue(AOrigin, Fingerprint);
          end;
        end;
        // a caller with no connection and no answer parks below: count it so
        // PoolStats can report the queue
        // (a caller about to ask the selector is not parked: it goes straight
        // round again)
        if not NeedSelect then
          if (Conn <> nil) or (First <> nil) then
          begin
            if Waiting then
              AddPendingLocked(Key, -1);
            Waiting := False;
          end
          else if not Waiting then
          begin
            AddPendingLocked(Key, 1);
            Waiting := True;
          end;
      finally
        FLock.Release;
      end;

      if NeedSelect then
      begin
        Identity := ChooseClientIdentity(FIdentitySelector, PeerHost,
          PeerPort);
        Fingerprint := '';
        if Identity <> nil then
          Fingerprint := Identity.Fingerprint;
        Resolved := True;
        Continue;
      end;

      if First <> nil then
      begin
        // a declined h2c upgrade: the probe carried the request, so its
        // response is the answer and the request is not written again
        if ARequest.Exchange <> nil then
        begin
          ARequest.Exchange.RouteChosen(npHttp1Cleartext, False);
          ARequest.Exchange.RequestWritten(0);
        end;
        Result := First;
        Exit;
      end;

      if Upgraded then
      begin
        // h2c upgrade: the 101 switch already happened inside the handshake, so
        // adopt stream 1 and wait for its response (RFC 7540 section 3.2: the
        // request is never re-sent).  FLock is released so a slow stream-1
        // response never blocks other origins.
        if ARequest.Exchange <> nil then
        begin
          ARequest.Exchange.RouteChosen(npHttp2Cleartext, False);
          ARequest.Exchange.RequestWritten(0);
        end;
        Result := (Conn as THttpConnection).AcquireUpgraded(ARequest,
          AHeaderTimeoutMs);
        Exit;
      end;

      if Conn <> nil then
      begin
        if ARequest.Exchange <> nil then
        begin
          // the codec follows the connection; the scheme picks TLS or not
          if Conn.Conn <> nil then
            Protocol := npHttp2Tls
          else
            Protocol := npHttp1Tls;
          if ARequest.Scheme <> 'https' then
            Inc(Protocol);
          ARequest.Exchange.RouteChosen(Protocol, not Opened);
        end;
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
            'timed out waiting for a connection slot ' +
            '(MaxConnectionsPerHost or MaxTotalConnections reached)');
        Sleep(2);
      end;
    end;
  finally
    if Waiting then
    begin
      FLock.Acquire;
      try
        AddPendingLocked(PendingKey, -1);
      finally
        FLock.Release;
      end;
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

function TConnectionPool.Stats: TPoolStats;
var
  Origin: string;
  L: TList<IPooledConnection>;
  C: IPooledConnection;
  O: TOriginStats;
  D: TConnectionStats;
  Peer: TConnectionSettings;
  Now, T: QWord;
  Pending, I, J: Integer;
  Tmp: TOriginStats;

  procedure AddOrigin;
  begin
    Inc(Result.Connections, O.Connections);
    Inc(Result.IdleConnections, O.IdleConnections);
    Inc(Result.ActiveStreams, O.ActiveStreams);
    Inc(Result.PendingAcquires, O.PendingAcquires);
    SetLength(Result.PerOrigin, Length(Result.PerOrigin) + 1);
    Result.PerOrigin[High(Result.PerOrigin)] := O;
  end;

begin
  Result := Default(TPoolStats);
  FLock.Acquire;
  try
    Now := GetTickCount64;
    for Origin in FByOrigin.Keys do
    begin
      L := FByOrigin[Origin];
      if not FPending.TryGetValue(Origin, Pending) then
        Pending := 0;
      if (L.Count = 0) and (Pending = 0) then
        Continue;
      O := Default(TOriginStats);
      O.Origin := Origin;
      O.PendingAcquires := Pending;
      SetLength(O.Details, L.Count);
      for I := 0 to L.Count - 1 do
      begin
        C := L[I];
        D := Default(TConnectionStats);
        D.ActiveStreams := C.ActiveStreams;
        if C.Conn <> nil then
        begin
          if Pos('http://', Origin) = 1 then
            D.Protocol := npHttp2Cleartext
          else
            D.Protocol := npHttp2Tls;
          D.State := C.Conn.State;
          Peer := C.Conn.PeerSettings;
          D.PeerMaxConcurrentStreams := Peer.MaxConcurrentStreams;
          D.PeerInitialWindowSize := Peer.InitialWindowSize;
          D.PeerMaxFrameSize := Peer.MaxFrameSize;
        end
        else
        begin
          if Pos('http://', Origin) = 1 then
            D.Protocol := npHttp1Cleartext
          else
            D.Protocol := npHttp1Tls;
          if C.Closed then
            D.State := csClosed
          else
            D.State := csOpen;
        end;
        if FCreatedAt.TryGetValue(C.Key, T) then
          D.AgeMs := Int64(Now - T);
        if (D.ActiveStreams = 0) and FIdleSince.TryGetValue(C.Key, T) then
          D.IdleMs := Int64(Now - T);
        O.Details[I] := D;
        Inc(O.Connections);
        Inc(O.ActiveStreams, D.ActiveStreams);
        if (D.ActiveStreams = 0) and (D.State <> csClosed) then
          Inc(O.IdleConnections);
      end;
      AddOrigin;
    end;
    // a caller can be parked on an origin that holds no list yet
    for Origin in FPending.Keys do
      if not FByOrigin.ContainsKey(Origin) then
      begin
        O := Default(TOriginStats);
        O.Origin := Origin;
        O.PendingAcquires := FPending[Origin];
        AddOrigin;
      end;
  finally
    FLock.Release;
  end;
  // a stable order for the caller (insertion sort: a handful of origins)
  for I := 1 to High(Result.PerOrigin) do
  begin
    Tmp := Result.PerOrigin[I];
    J := I - 1;
    while (J >= 0) and (Result.PerOrigin[J].Origin > Tmp.Origin) do
    begin
      Result.PerOrigin[J + 1] := Result.PerOrigin[J];
      Dec(J);
    end;
    Result.PerOrigin[J + 1] := Tmp;
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
    FCreatedAt.AddOrSetValue(AConn.Key, GetTickCount64);
  finally
    FLock.Release;
  end;
end;

{ THttpClient }

constructor THttpClient.Create(const AFactory: IHttp2SocketFactory;
  const AMaxConnectionsPerHost, AMaxTotalConnections,
  AMaxStreamsPerConnection: Integer;
  const AFollowRedirects: Boolean; const AMaxRedirects, AConnectTimeoutMs,
  AHeaderTimeoutMs, AIdleTimeoutMs: Integer;
  const AObserver: IHttp2Observer;
  const AHttp1Fallback: Boolean; const AClearTextPolicy: TClearTextPolicy;
  const AProxySelector: IProxySelector);
begin
  inherited Create;
  FProxySelector := AProxySelector;
  FFactory := AFactory;
  FConnectTimeoutMs := AConnectTimeoutMs;
  FLock := TCriticalSection.Create;
  FPool := TConnectionPool.Create(AFactory, AMaxConnectionsPerHost,
    AMaxTotalConnections, AMaxStreamsPerConnection, AConnectTimeoutMs,
    AHeaderTimeoutMs, AIdleTimeoutMs, AObserver, AHttp1Fallback,
    AClearTextPolicy);
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

function THttpClient.PoolStats: TPoolStats;
var
  IsClosed: Boolean;
begin
  FLock.Acquire;
  try
    IsClosed := FClosed;
  finally
    FLock.Release;
  end;
  if IsClosed then
    Exit(Default(TPoolStats));
  Result := FPool.Stats;
end;

procedure THttpClient.InstallIdentitySelector(
  const ASelector: IClientIdentitySelector);
begin
  FIdentitySelector := ASelector;
  FPool.IdentitySelector := ASelector;
end;

procedure THttpClient.InstallRequestObservers(
  const AObservers: TArray<IHttpClientObserver>; const ALogger: IHttpLogger);
begin
  if Length(AObservers) = 0 then
    FRequestObserver := nil
  else
    FRequestObserver := TCompositeObserver.Create(AObservers, ALogger);
end;

function THttpClient.Send(const ARequest: THttpRequest): IHttpResponse;
var
  Current, Req: THttpRequest;
  Method: string;
  Location, Target: string;
  Redirects, Retries, Hop, HopRetries, Status: Integer;
  Idempotent, RetryIt: Boolean;
  Tracker: TAttemptTracker;
  TrackerRef: IExchangeObserver;
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
  Hop := 0;
  HopRetries := 0;
  while True do
  begin
    Req := Current;
    Tracker := nil;
    TrackerRef := nil;
    if FRequestObserver <> nil then
    begin
      // the observer injects into a private copy of the headers, so the
      // caller's request and the next hop never carry this attempt's values
      Req := Current.Clone;
      InterlockedIncrement(FClonedAttempts);
      Tracker := TAttemptTracker.Create(FRequestObserver);
      TrackerRef := Tracker;
      Tracker.Start(Req, Hop, HopRetries);
    end;
    try
      Result := SendOnce(Req, TrackerRef);
    except
      // transparent retry: only an idempotent request with no body writer,
      // and only when the peer refused the stream or sent GOAWAY so the
      // stream was never processed (plan S10 task 10.9)
      on E: Exception do
      begin
        RetryIt := (E is EHttpStreamError) and Idempotent and
          (EHttpStreamError(E).ErrorCode = ecRefusedStream) and
          (Current.BodyWriter = nil) and (Retries < cMaxTransparentRetries);
        if Tracker <> nil then
        begin
          if RetryIt then
            Tracker.NotifyRetry('REFUSED_STREAM');
          Tracker.Fail(E);
        end;
        if not RetryIt then
          raise;
        Inc(Retries);
        Inc(HopRetries);
        Sleep(1);
        Continue;
      end;
    end;

    try
      if Tracker <> nil then
        Tracker.GotResponse(Result);
      if (not FFollowRedirects) or (not HttpStatusIsRedirect(Result.StatusCode)) then
      begin
        if Tracker <> nil then
          Tracker.Arm(Result);
        Break;
      end;
      Location := Result.Headers.GetFirst('location');
      if Location = '' then
      begin
        if Tracker <> nil then
          Tracker.Arm(Result);
        Break;
      end;

      Inc(Redirects);
      if Redirects > FMaxRedirects then
        raise EHttpTooManyRedirects.CreateFmt(
          'redirect chain exceeded MaxRedirects (%d)', [FMaxRedirects]);

      Target := ResolveLocation(Current.Url, Location);
      Status := Result.StatusCode;
      case Status of
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
              IntToStr(Status) + ' redirect');
      end;
      Current := Current.WithMethodToken(Method);
      Current := Current.WithUrl(Target);
      if Tracker <> nil then
      begin
        // the finished hop ends before the next one starts; its body is
        // discarded, so it ends abandoned unless it was already complete
        Tracker.NotifyRedirect(Req.Url, Target, Status);
        Tracker.Arm(Result);
        Result := nil;
        Tracker.Drop;
      end;
      Inc(Hop);
      HopRetries := 0;
    except
      on E: Exception do
      begin
        if Tracker <> nil then
          Tracker.Fail(E);
        raise;
      end;
    end;
  end;
end;

function THttpClient.SendOnce(const ARequest: THttpRequest;
  const AExchange: IExchangeObserver): IHttpResponse;
var
  Origin, Host, Path: string;
  Port: Word;
  R: TStreamRequest;
  Timeout: Integer;
  Proxy: IProxy;
begin
  ParseHttpUrl(ARequest.Url, Host, Port, Path);
  Origin := OriginOfUrl(ARequest.Url);
  // the cleartext guard (doc/design/fallback.md): the default ctReject raises
  // before any socket is dialled; ctPriorKnowledge/ctUpgrade proceed and the
  // pool's DialProtocol applies the same policy again on the wire
  if (SchemeOfUrl(ARequest.Url) = 'http') and (FClearTextPolicy = ctReject) then
    raise EHttpProtocolError.Create(
      'cleartext origin rejected (set WithClearText(ctPriorKnowledge) or ' +
      'WithClearText(ctUpgrade) or WithClearText(ctHttp1) to enable it)',
      ecProtocolError);
  // the route is chosen per hop (a redirect re-enters here), on this thread
  // and outside the pool lock; a selector exception reaches the caller of Send
  Proxy := nil;
  if FProxySelector <> nil then
  begin
    Proxy := FProxySelector.SelectProxy(ARequest.Url);
    ValidateProxy(Proxy);
  end;
  // the direct key stays the plain origin; a proxied route is its own bucket
  Origin := Origin + ProxyRouteKey(Proxy);
  R := ARequest.ToStreamRequest;
  if AExchange <> nil then
    R := R.WithExchange(AExchange);
  Timeout := FHeaderTimeoutMs;
  if ARequest.HeaderTimeoutMs > 0 then
    Timeout := ARequest.HeaderTimeoutMs;
  Result := FPool.Acquire(Origin, Host, Port, R, Timeout,
    ARequest.CancelToken, Proxy);
end;

function THttpClient.Send(const ARequest: IWebSocketRequest): IWebSocket;
var
  Secure: Boolean;
  Host, Target, Authority, Mapped, PeerHost: string;
  Port, PeerPort: Word;
  Proxy: IProxy;
  Identity: IClientIdentity;
  Dialer: IHttp1SocketFactory;
  IdFactory: IIdentitySocketFactory;
  Closed: Boolean;
  Tracker: TAttemptTracker;
  TrackerRef: IWebSocketAttempt;
begin
  FLock.Acquire;
  try
    Closed := FClosed;
  finally
    FLock.Release;
  end;
  if Closed then
    raise EHttpConnectionError.Create('the client is closed');
  WsParseUrl(ARequest.Url, Secure, Host, Port, Target, Authority);
  // the session is one attempt: it starts before anything is dialled, and
  // whatever fails below ends it with that failure
  Tracker := nil;
  TrackerRef := nil;
  if FRequestObserver <> nil then
  begin
    Tracker := TAttemptTracker.Create(FRequestObserver);
    TrackerRef := Tracker;
    Tracker.StartSocket(ARequest, Host, Port, Secure);
  end;
  try
    if not Supports(FFactory, IHttp1SocketFactory, Dialer) then
      raise EHttpWebSocketError.Create(
        'the socket factory cannot dial an HTTP/1.1 connection');
    // the route is chosen on the equivalent http(s) URL, so http_proxy,
    // https_proxy and no_proxy apply as they do for the same request
    Proxy := nil;
    if FProxySelector <> nil then
    begin
      if Secure then
        Mapped := 'https://' + Authority + Target
      else
        Mapped := 'http://' + Authority + Target;
      Proxy := FProxySelector.SelectProxy(Mapped);
      ValidateProxy(Proxy);
    end;
    // a selector chooses the identity of this dial, on this thread, once the
    // route says which peer (origin or https proxy) receives it
    if (FIdentitySelector <> nil) and
       Supports(FFactory, IIdentitySocketFactory, IdFactory) then
    begin
      if IdentityPeer(Proxy, Secure, Host, Port, PeerHost, PeerPort) then
        Identity := ChooseClientIdentity(FIdentitySelector, PeerHost, PeerPort)
      else
        Identity := nil;
      Dialer := TIdentityHttp1Dialer.Create(IdFactory, Identity);
    end;
    Result := OpenWebSocket(Dialer, ARequest, Proxy, FConnectTimeoutMs, nil,
      TrackerRef);
  except
    on E: Exception do
    begin
      if Tracker <> nil then
        Tracker.FailHandshake(E);
      raise;
    end;
  end;
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
        // string, AnsiString and UTF8String all report tkAString on FPC
        // 3.2.4, so this branch is the text reader for every string type.
        // The bytes are copied verbatim; no code-page conversion is applied.
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
