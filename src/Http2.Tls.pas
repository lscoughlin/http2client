/// TLS + ALPN socket abstraction over mormot OpenSSL (plan S05)
// - this unit is part of the http2client project (see doc/design/transport.md,
//   section "TLS and ALPN"): it provides a blocking byte-stream socket that
//   performs the TLS handshake, offers ALPN "h2", and fails loudly when the
//   peer does not select "h2".
// - FPC 3.2.4's bundled openssl/opensslsockets units expose no ALPN symbols,
//   so the TLS layer sits on mormot.lib.openssl11.pas (dynamically loaded).
//   OPENSSL_LIBPATH must point at the OpenSSL library directory at run time
//   (else OpenSslIsAvailable is FALSE and CreateSslContext raises).
unit Http2.Tls;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, Sockets, ssockets, BaseUnix,
  mormot.core.base, mormot.lib.openssl11,
  Http2.Errors, Http2.Proxy, Http2.Socks;

const
  /// the single ALPN protocol this client offers in strict mode (RFC 7540
  /// section 3.3)
  cHttp2AlpnProtocol = 'h2';
  /// HTTP/1.1's ALPN name, offered only when the caller enables fallback
  cHttp11AlpnProtocol = 'http/1.1';
  /// the ALPN offer in strict mode (fallback off): "h2" only
  cHttp2AlpnOffer: array[0..0] of string = (cHttp2AlpnProtocol);
  /// the ALPN offer when HTTP/1.1 fallback is on (doc/design/fallback.md
  /// "Negotiation", step 2)
  cHttp2Http1AlpnOffer: array[0..1] of string =
    (cHttp2AlpnProtocol, cHttp11AlpnProtocol);
  /// default connect/read/write deadline when none is set explicitly
  cDefaultSocketTimeoutMs = 30000;

type
  /// how the client treats a cleartext ("http") origin (doc/design/
  /// fallback.md "Factory surface").  ctReject is the default: a cleartext
  /// request raises instead of silently sending bytes in the clear.
  // Declared here, not in Http2.Messages.pas: the transport layer acts on the
  // policy, and Http2.Messages already uses this unit for IHttp2Socket, so a
  // declaration there would be a circular unit reference.  Http2.Messages
  // re-exports these as aliases for callers that only use that unit.
  TClearTextPolicy = (ctReject, ctPriorKnowledge, ctUpgrade);

  /// the transport selected for one origin (doc/design/fallback.md)
  TNegotiatedProtocol = (npHttp2Tls, npHttp2Cleartext, npHttp1Tls,
    npHttp1Cleartext);

  IHttp2Socket = interface;   // forward: declared in full just below

  /// implemented by a socket factory that also understands cleartext and the
  /// HTTP/1.1 fallback.  The base IHttp2SocketFactory (declared in
  /// Http2.Client) predates S13 and only knows "dial TLS, speak h2"; the
  /// client checks for this extended contract with Supports() so an injected
  /// test factory keeps working unchanged.
  ICleartextSocketFactory = interface
    ['{C13A0001-0000-4000-8000-000000000001}']
    /// dial AHost:APort for AScheme and return the socket plus the protocol
    /// the transport is committed to.  For TLS the protocol follows the ALPN
    /// result; for cleartext it follows APolicy.
    function DialProtocol(const AHost: string; const APort: Word;
      const AScheme: string; const AHttp1Fallback: Boolean;
      const APolicy: TClearTextPolicy; const ATimeoutMs: Integer;
      out AProtocol: TNegotiatedProtocol): IHttp2Socket;
  end;

  /// a blocking, connected byte stream carrying HTTP/2 frames
  // - Read returns the number of bytes read and returns 0 only at end of
  //   stream; it never assumes one transport read yields the whole request
  IHttp2Socket = interface
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
    property Connected: Boolean read GetConnected;
    property ConnectTimeoutMs: Integer read GetConnectTimeoutMs write SetConnectTimeoutMs;
    property ReadTimeoutMs: Integer read GetReadTimeoutMs write SetReadTimeoutMs;
    property WriteTimeoutMs: Integer read GetWriteTimeoutMs write SetWriteTimeoutMs;
  end;

/// encode an ALPN protocol list in wire form: each entry is one length byte
// followed by its bytes; ['h2'] encodes as 0x02,0x68,0x32
function AlpnProtocolList(const AProtocols: array of string): TBytes;

/// decode the protocol name returned by SSL_get0_alpn_selected (raw bytes,
// without a length prefix); returns '' when nothing was selected
function AlpnSelectedName(const AData: PByte; const ALen: Cardinal): string;

/// verify the negotiated ALPN protocol is exactly "h2", else raise
// EHttpProtocolError; a peer that selected nothing or "http/1.1" must fail
// here rather than silently continue on HTTP/1.1
procedure RequireH2Alpn(const AData: PByte; const ALen: Cardinal);

/// encode the ALPN offer for the caller's fallback policy: "h2" when fallback
// is off (the strict default), "h2" then "http/1.1" when it is on
// (doc/design/fallback.md "Negotiation")
function AlpnOfferFor(const AHttp1Fallback: Boolean): TBytes;

/// a 32-bit value from the OpenSSL CSPRNG.  A failing generator raises
/// EHttpConnectionError; there is no fallback to a non-secure source.
function SecureRandomCardinal: Cardinal;

/// normalise a selected ALPN name to one of "h2", "http/1.1" or "" (nothing
// selected, or a protocol this client does not know) so the caller can choose
// a codec (doc/design/fallback.md "Negotiation")
function AlpnNegotiatedName(const AName: string): string;

/// map the insecure toggle to the OpenSSL verify mode (NONE when insecure)
function SslVerifyModeFor(const AInsecure: Boolean): Integer;

/// read exactly ACount bytes, or up to EOF; returns the byte count (0 only at
// immediate EOF) and raises EHttpTimeout when the deadline expires
function SocketReadFully(AFd, ACount, ATimeoutMs: Integer;
  var ABuffer): Integer;

/// write all ACount bytes, raising EHttpTimeout when the deadline expires
function SocketWriteFully(AFd, ACount, ATimeoutMs: Integer;
  const ABuffer): Integer;

type
  /// a socket that can return whatever is available instead of insisting on
  /// the full count (IHttp2Socket.Read reads exactly ACount bytes or up to
  /// EOF).  A TLS layer carried over another stream needs this: records arrive
  /// in arbitrary sizes and waiting for a full buffer would stall the
  /// handshake.
  IPartialReader = interface
    ['{7B1D5E02-9F6A-4C57-8A31-5D2E0C4A9B21}']
    /// block until at least one byte is available, then return between 1 and
    /// ACount bytes; 0 means end of stream
    function ReadSome(var ABuffer; ACount: Integer): Integer;
  end;

  /// implemented by a socket factory that dials through a per-request proxy
  /// (doc/design/proxy.md).  A factory that lacks it is dialled without a
  /// proxy, as before.
  IProxySocketFactory = interface
    ['{7B1D5E02-9F6A-4C57-8A31-5D2E0C4A9B22}']
    /// like ICleartextSocketFactory.DialProtocol; AProxy nil dials directly
    function DialProtocolVia(const AHost: string; const APort: Word;
      const AScheme: string; const AHttp1Fallback: Boolean;
      const APolicy: TClearTextPolicy; const ATimeoutMs: Integer;
      const AProxy: IProxy;
      out AProtocol: TNegotiatedProtocol): IHttp2Socket;
  end;

  /// implemented by a socket factory that can dial a connection which will
  /// speak HTTP/1.1 only, as a WebSocket needs (doc/design/websocket.md).  TLS
  /// offers "http/1.1" alone in ALPN; a peer answering "h2" is refused, a peer
  /// without ALPN support is accepted.  AProxy nil dials directly.
  IHttp1SocketFactory = interface
    ['{7B1D5E02-9F6A-4C57-8A31-5D2E0C4A9B23}']
    function DialHttp1(const AHost: string; const APort: Word;
      const AScheme: string; const ATimeoutMs: Integer;
      const AProxy: IProxy): IHttp2Socket;
  end;

  /// the production transport selector (plan S13): picks TLS or cleartext and
  /// reports the wire protocol it committed to.  Https offers "h2", or
  /// "h2"+"http/1.1" when fallback is on; an empty ALPN result with fallback
  /// on means HTTP/1.1 (RFC 7301).  A cleartext origin honours the policy
  /// (doc/design/fallback.md "Negotiation").
  TProtocolSocketFactory = class(TInterfacedObject, ICleartextSocketFactory,
    IProxySocketFactory, IHttp1SocketFactory)
  private
    FCACertFile: string;
    FInsecure: Boolean;
    FProxyHost: string;
    FProxyPort: Word;
  public
    constructor Create(const ACACertFile: string = '';
      const AInsecure: Boolean = False; const AProxyHost: string = '';
      const AProxyPort: Word = 0);
    function DialProtocol(const AHost: string; const APort: Word;
      const AScheme: string; const AHttp1Fallback: Boolean;
      const APolicy: TClearTextPolicy; const ATimeoutMs: Integer;
      out AProtocol: TNegotiatedProtocol): IHttp2Socket;
    function DialProtocolVia(const AHost: string; const APort: Word;
      const AScheme: string; const AHttp1Fallback: Boolean;
      const APolicy: TClearTextPolicy; const ATimeoutMs: Integer;
      const AProxy: IProxy;
      out AProtocol: TNegotiatedProtocol): IHttp2Socket;
    function DialHttp1(const AHost: string; const APort: Word;
      const AScheme: string; const ATimeoutMs: Integer;
      const AProxy: IProxy): IHttp2Socket;
  end;

  /// a plain (cleartext) TCP socket over fcl-net's TInetSocket. When a proxy
  /// is configured the TCP connection goes to the proxy and a CONNECT tunnel
  /// to the real target is negotiated first, so every layer above (TLS, h2c,
  /// HTTP/1.1) sees a transparent byte stream to the origin.
  TPlainSocket = class(TInterfacedObject, IHttp2Socket, IPartialReader)
  private
    FSocket: TInetSocket;
    FHandle: Integer;
    FConnected: Boolean;
    FConnectTimeoutMs: Integer;
    FReadTimeoutMs: Integer;
    FWriteTimeoutMs: Integer;
  public
    constructor Create(const AHost: string; const APort: Word;
      const AConnectTimeoutMs: Integer = cDefaultSocketTimeoutMs;
      const AProxyHost: string = ''; const AProxyPort: Word = 0);
    destructor Destroy; override;
    /// the underlying OS socket handle (needed to hand the socket to OpenSSL)
    property Handle: Integer read FHandle;
    function Read(var ABuffer; ACount: Integer): Integer;
    function ReadSome(var ABuffer; ACount: Integer): Integer;
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

  /// a TLS socket over an existing connected IHttp2Socket (ALPN "h2")
  // - the crypto operations are exposed as virtual seams so tests can inject
  //   a scripted handshake result without touching the network
  TTlsSocket = class(TInterfacedObject, IHttp2Socket, IPartialReader)
  private
    /// True when the transport is another byte stream (for example a TLS
    /// connection to an https proxy) rather than a plain TCP socket: OpenSSL
    /// then runs on a pair of memory BIOs and this class moves the bytes
    FStreamMode: Boolean;
    FRbio: PBIO;
    FWbio: PBIO;
    FEofFed: Boolean;
    FTransport: IHttp2Socket;
    FHost: string;
    FInsecure: Boolean;
    FCACertFile: string;
    FCtx: PSSL_CTX;
    FSsl: PSSL;
    FHandshaked: Boolean;
    FSelectedProtocol: string;
    FAlpnOffer: TBytes;
    FRequireH2: Boolean;
    FConnectTimeoutMs: Integer;
    FReadTimeoutMs: Integer;
    FWriteTimeoutMs: Integer;
    procedure BioFlush;
    function BioFeed: Boolean;
    function StreamHandshake(const ASsl: PSSL): Integer;
  protected
    // --- crypto seams (overridden by tests) ---
    function CreateSslContext: PSSL_CTX; virtual;
    procedure DestroySslContext; virtual;
    function CreateSslHandle(const ACtx: PSSL_CTX): PSSL; virtual;
    procedure DestroySslHandle; virtual;
    function ApplyAlpnProtos(const ACtx: PSSL_CTX): Integer; virtual;
    procedure ApplyVerifyMode(const ACtx: PSSL_CTX; const AMode: Integer); virtual;
    function ApplyHostnameVerification(const ASsl: PSSL;
      const AHost: string): Integer; virtual;
    function ApplySniHost(const ASsl: PSSL;
      const AHost: string): Integer; virtual;
    function BindSocket(const ASsl: PSSL; const AFd: Integer): Integer; virtual;
    function HandshakeConnect(const ASsl: PSSL): Integer; virtual;
    function SelectedAlpnBytes(const ASsl: PSSL): TBytes; virtual;
    function LastSslError(const ASsl: PSSL; const AResult: Integer): Integer; virtual;
    function SslReadBytes(const ASsl: PSSL; const ABuffer: Pointer;
      const ACount: Integer): Integer; virtual;
    function SslWriteBytes(const ASsl: PSSL; const ABuffer: Pointer;
      const ACount: Integer): Integer; virtual;
    procedure SslShutdown(const ASsl: PSSL); virtual;
    function GetSocketFd: Integer; virtual;
  public
    constructor Create(const ATransport: IHttp2Socket; const AHost: string;
      const AInsecure: Boolean = False; const ACACertFile: string = '');
    destructor Destroy; override;
    /// perform the TLS handshake and verify ALPN; raises on failure
    procedure Establish;
    /// dial, connect, and TLS-wrap in one call; the insecure flag is the
    /// explicit verify-off toggle (default False = verify the peer)
    class function Dial(const AHost: string; const APort: Word;
      const AInsecure: Boolean = False;
      const AConnectTimeoutMs: Integer = cDefaultSocketTimeoutMs;
      const ACACertFile: string = ''; const AProxyHost: string = '';
      const AProxyPort: Word = 0): IHttp2Socket;
    /// dial and TLS-wrap while offering the caller's ALPN list (in wire form,
    /// e.g. AlpnOfferFor(True)); the negotiated name is in SelectedProtocol
    // - fallback is the caller's decision, so the strict ALPN check is skipped
    //   here and the protocol name is reported for the caller to map
    class function DialWithAlpn(const AHost: string; const APort: Word;
      const AAlpnOffer: TBytes; const AInsecure: Boolean = False;
      const AConnectTimeoutMs: Integer = cDefaultSocketTimeoutMs;
      const ACACertFile: string = ''; const AProxyHost: string = '';
      const AProxyPort: Word = 0): IHttp2Socket;
    /// dial a CLEARTEXT TCP socket for h2c prior knowledge
    // (doc/design/fallback.md "h2c prior knowledge"); the caller writes the
    // connection preface.  No TLS, no ALPN, so SelectedProtocol is not used.
    class function DialCleartext(const AHost: string; const APort: Word;
      const AConnectTimeoutMs: Integer = cDefaultSocketTimeoutMs;
      const AProxyHost: string = '';
      const AProxyPort: Word = 0): IHttp2Socket;
    /// override the ALPN offer this socket will send in Establish; ignored by
    /// the Dial overloads, which set it for you
    procedure SetAlpnOffer(const AOffer: TBytes);
    /// dial through AProxy (nil = direct): the proxy leg is TCP, or TCP+TLS for
    /// an https proxy, and a CONNECT or SOCKS5 tunnel to AHost:APort is
    /// negotiated before TLS to the origin begins
    class function DialVia(const AHost: string; const APort: Word;
      const AInsecure: Boolean; const AConnectTimeoutMs: Integer;
      const ACACertFile: string; const AProxy: IProxy): IHttp2Socket;
    class function DialWithAlpnVia(const AHost: string; const APort: Word;
      const AAlpnOffer: TBytes; const AInsecure: Boolean;
      const AConnectTimeoutMs: Integer; const ACACertFile: string;
      const AProxy: IProxy): IHttp2Socket;
    class function DialCleartextVia(const AHost: string; const APort: Word;
      const AConnectTimeoutMs: Integer; const AProxy: IProxy;
      const AInsecure: Boolean = False;
      const ACACertFile: string = ''): IHttp2Socket;
    function ReadSome(var ABuffer; ACount: Integer): Integer;
    property StreamMode: Boolean read FStreamMode write FStreamMode;
    property Insecure: Boolean read FInsecure;
    /// PEM bundle used to verify the peer; '' = the system trust store
    property CACertFile: string read FCACertFile;
    property SelectedProtocol: string read FSelectedProtocol;
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
    property Connected: Boolean read GetConnected;
    property ConnectTimeoutMs: Integer read GetConnectTimeoutMs write SetConnectTimeoutMs;
    property ReadTimeoutMs: Integer read GetReadTimeoutMs write SetReadTimeoutMs;
    property WriteTimeoutMs: Integer read GetWriteTimeoutMs write SetWriteTimeoutMs;
  end;

implementation

function AlpnProtocolList(const AProtocols: array of string): TBytes;
var
  i, n, p: Integer;
  s: UTF8String;
begin
  Result := nil;
  n := 0;
  for i := 0 to High(AProtocols) do
  begin
    if Length(AProtocols[i]) > 255 then
      raise EHttpProtocolError.Create('ALPN protocol name longer than 255 bytes');
    Inc(n, 1 + Length(AProtocols[i]));
  end;
  SetLength(Result, n);
  p := 0;
  for i := 0 to High(AProtocols) do
  begin
    s := UTF8String(AProtocols[i]);
    Result[p] := Byte(Length(s));
    Inc(p);
    if Length(s) > 0 then
    begin
      Move(s[1], Result[p], Length(s));
      Inc(p, Length(s));
    end;
  end;
end;

function AlpnSelectedName(const AData: PByte; const ALen: Cardinal): string;
var
  i: Cardinal;
  s: AnsiString;
begin
  if (AData = nil) or (ALen = 0) then
  begin
    Result := '';
    Exit;
  end;
  SetLength(s, ALen);
  for i := 0 to ALen - 1 do
    s[i + 1] := AnsiChar(AData[i]);
  Result := string(s);
end;

procedure RequireH2Alpn(const AData: PByte; const ALen: Cardinal);
var
  Selected: string;
begin
  Selected := AlpnSelectedName(AData, ALen);
  if Selected <> cHttp2AlpnProtocol then
    raise EHttpProtocolError.CreateFmt(
      'peer did not negotiate ALPN "%s" (selected "%s")',
      [cHttp2AlpnProtocol, Selected]);
end;

function AlpnOfferFor(const AHttp1Fallback: Boolean): TBytes;
begin
  if AHttp1Fallback then
    Result := AlpnProtocolList(cHttp2Http1AlpnOffer)
  else
    Result := AlpnProtocolList(cHttp2AlpnOffer);
end;

function AlpnNegotiatedName(const AName: string): string;
begin
  if (AName = cHttp2AlpnProtocol) or (AName = cHttp11AlpnProtocol) then
    Result := AName
  else
    Result := '';
end;

function SslVerifyModeFor(const AInsecure: Boolean): Integer;
begin
  if AInsecure then
    Result := SSL_VERIFY_NONE
  else
    Result := SSL_VERIFY_PEER;
end;

procedure SetSocketTimeout(AFd, ALevel, AOption, ATimeoutMs: Integer);
var
  tv: TTimeVal;
begin
  tv.tv_sec := ATimeoutMs div 1000;
  tv.tv_usec := (ATimeoutMs mod 1000) * 1000;
  fpSetSockOpt(AFd, ALevel, AOption, @tv, SizeOf(tv));
end;

function SocketTimedOut: Boolean;
var
  e: Integer;
begin
  e := fpGetErrno;
  Result := (e = ESysEAGAIN) or (e = ESysEWOULDBLOCK);
end;

function SocketReadFully(AFd, ACount, ATimeoutMs: Integer;
  var ABuffer): Integer;
var
  n: ssize_t;
  base: PByte;
begin
  if ACount <= 0 then
    Exit(0);
  SetSocketTimeout(AFd, SOL_SOCKET, SO_RCVTIMEO, ATimeoutMs);
  base := PByte(@ABuffer);
  Result := 0;
  while Result < ACount do
  begin
    n := fpRecv(AFd, base + Result, ACount - Result, 0);
    if n > 0 then
      Inc(Result, n)
    else if n = 0 then
      Exit // EOF: return whatever was read so far
    else if SocketTimedOut then
      raise EHttpTimeout.CreateFmt('read timed out after %d ms', [ATimeoutMs])
    else if fpGetErrno = ESysEINTR then
      Continue
    else
      raise EHttpConnectionClosed.CreateFmt('socket read failed (errno %d)',
        [fpGetErrno]);
  end;
end;

function SocketWriteFully(AFd, ACount, ATimeoutMs: Integer;
  const ABuffer): Integer;
var
  n: ssize_t;
  base: PByte;
begin
  if ACount <= 0 then
    Exit(0);
  SetSocketTimeout(AFd, SOL_SOCKET, SO_SNDTIMEO, ATimeoutMs);
  base := PByte(@ABuffer);
  Result := 0;
  while Result < ACount do
  begin
    n := fpSend(AFd, base + Result, ACount - Result, 0);
    if n > 0 then
      Inc(Result, n)
    else if SocketTimedOut then
      raise EHttpTimeout.CreateFmt('write timed out after %d ms', [ATimeoutMs])
    else if fpGetErrno = ESysEINTR then
      Continue
    else
      raise EHttpConnectionClosed.CreateFmt('socket write failed (errno %d)',
        [fpGetErrno]);
  end;
end;

type
  /// the proxy exchange over a raw descriptor
  TFdChannel = class(TInterfacedObject, ISocksChannel)
  private
    FFd: Integer;
    FTimeoutMs: Integer;
  public
    constructor Create(const AFd, ATimeoutMs: Integer);
    procedure WriteAll(const AData: TBytes);
    function ReadSome(var ABuffer; const ACount: Integer): Integer;
  end;

  /// the proxy exchange over an IHttp2Socket (for example a TLS socket to an
  /// https proxy)
  TSocketChannel = class(TInterfacedObject, ISocksChannel)
  private
    FSock: IHttp2Socket;
  public
    constructor Create(const ASock: IHttp2Socket);
    procedure WriteAll(const AData: TBytes);
    function ReadSome(var ABuffer; const ACount: Integer): Integer;
  end;

constructor TFdChannel.Create(const AFd, ATimeoutMs: Integer);
begin
  inherited Create;
  FFd := AFd;
  FTimeoutMs := ATimeoutMs;
end;

procedure TFdChannel.WriteAll(const AData: TBytes);
begin
  if Length(AData) > 0 then
    SocketWriteFully(FFd, Length(AData), FTimeoutMs, AData[0]);
end;

function TFdChannel.ReadSome(var ABuffer; const ACount: Integer): Integer;
begin
  // reads exactly ACount (or to EOF): callers ask for exactly what the
  // protocol still needs, so nothing past the proxy reply is consumed
  Result := SocketReadFully(FFd, ACount, FTimeoutMs, ABuffer);
end;

constructor TSocketChannel.Create(const ASock: IHttp2Socket);
begin
  inherited Create;
  FSock := ASock;
end;

procedure TSocketChannel.WriteAll(const AData: TBytes);
begin
  if Length(AData) > 0 then
    FSock.Write(AData[0], Length(AData));
end;

function TSocketChannel.ReadSome(var ABuffer; const ACount: Integer): Integer;
begin
  Result := FSock.Read(ABuffer, ACount);
end;

/// read one CRLF/LF-terminated line from the tunnel handshake; False only at
// EOF.  Byte-at-a-time so it never consumes bytes past the CONNECT response
// (any payload beyond the blank line belongs to the tunnel)
function ProxyReadLineCh(const ACh: ISocksChannel;
  out ALine: AnsiString): Boolean;
var
  C: AnsiChar;
begin
  ALine := '';
  repeat
    if ACh.ReadSome(C, 1) <= 0 then
      Exit(False);
    if C = #10 then
      Exit(True);
    if C <> #13 then
      ALine := ALine + C;
  until Length(ALine) > 16384;
  Result := True;
end;

/// parse the 3-digit status code from an HTTP status line (the token after
// the version, e.g. "HTTP/1.1 200 OK")
function ProxyStatusCode(const ALine: AnsiString): Integer;
var
  I: Integer;
  Digits: AnsiString;
begin
  Result := 0;
  Digits := '';
  I := 1;
  // skip the HTTP-version token
  while (I <= Length(ALine)) and (ALine[I] <> ' ') do
    Inc(I);
  while (I <= Length(ALine)) and (ALine[I] = ' ') do
    Inc(I);
  // collect the status-code digits
  while (I <= Length(ALine)) and (ALine[I] >= '0') and (ALine[I] <= '9') do
  begin
    Digits := Digits + ALine[I];
    Inc(I);
  end;
  if Length(Digits) = 3 then
    Result := StrToIntDef(string(Digits), 0);
end;

function ConnectAuthority(const AHost: string; const APort: Word): AnsiString;
begin
  // an IPv6 literal is bracketed in a request target (RFC 3986)
  if (Pos(':', AHost) > 0) and (Copy(AHost, 1, 1) <> '[') then
    Result := '[' + AnsiString(AHost) + ']'
  else
    Result := AnsiString(AHost);
  Result := Result + ':' + AnsiString(IntToStr(APort));
end;

/// negotiate an HTTP CONNECT tunnel to AHost:APort over ACh.  Sends
/// Proxy-Authorization: Basic when AUserName is not empty.  Raises
/// EHttpConnectionError unless the proxy answers a 2xx status; a non-2xx or a
/// truncated response is a connection failure, not a fallback.  Credentials
/// never appear in a message.
procedure EstablishConnectTunnel(const ACh: ISocksChannel; const AHost: string;
  const APort: Word; const AUserName, APassword: string);
var
  Req, Line, Auth: AnsiString;
  Code: Integer;
  Bytes: TBytes;
begin
  Auth := ConnectAuthority(AHost, APort);
  Req := 'CONNECT ' + Auth + ' HTTP/1.1'#13#10'Host: ' + Auth + #13#10;
  if AUserName <> '' then
    Req := Req + 'Proxy-Authorization: Basic ' +
      AnsiString(ProxyBasicCredentials(AUserName, APassword)) + #13#10;
  Req := Req + #13#10;
  SetLength(Bytes, Length(Req));
  Move(Req[1], Bytes[0], Length(Req));
  ACh.WriteAll(Bytes);
  // skip any informational (1xx) response and any blank separators, then
  // require a 2xx; a blank line must not be treated as a status
  Code := 100;
  repeat
    if not ProxyReadLineCh(ACh, Line) then
      raise EHttpConnectionError.Create(
        'proxy closed the connection during CONNECT');
    if Line = '' then
      Continue;
    Code := ProxyStatusCode(Line);
  until (Code < 100) or (Code >= 200);
  if (Code < 200) or (Code >= 300) then
    raise EHttpConnectionError.CreateFmt('proxy CONNECT failed: %s',
      [string(Line)]);
  // drain the response headers up to the blank line
  repeat
    if not ProxyReadLineCh(ACh, Line) then
      Break;
  until Line = '';
end;

procedure EstablishProxyTunnelFd(AFd: Integer; const AHost: string;
  const APort: Word; const ATimeoutMs: Integer;
  const AUserName: string; const APassword: string);
begin
  EstablishConnectTunnel(TFdChannel.Create(AFd, ATimeoutMs), AHost, APort,
    AUserName, APassword);
end;

/// run the tunnel exchange the proxy kind calls for over ACh
procedure EstablishTunnelOver(const ACh: ISocksChannel; const AProxy: IProxy;
  const AHost: string; const APort: Word);
begin
  if AProxy.Kind = pkSocks5 then
    EstablishSocksTunnel(ACh, AProxy, AHost, APort)
  else
    EstablishConnectTunnel(ACh, AHost, APort, AProxy.UserName,
      AProxy.Password);
end;

{ TPlainSocket }

constructor TPlainSocket.Create(const AHost: string; const APort: Word;
  const AConnectTimeoutMs: Integer;
  const AProxyHost: string; const AProxyPort: Word);
var
  opt: LongInt;
  DialHost: string;
  DialPort: Word;
begin
  inherited Create;
  FConnectTimeoutMs := AConnectTimeoutMs;
  FReadTimeoutMs := cDefaultSocketTimeoutMs;
  FWriteTimeoutMs := cDefaultSocketTimeoutMs;
  // with a proxy the TCP connection goes to the proxy; everything above then
  // talks to the origin through a CONNECT tunnel
  if AProxyHost <> '' then
  begin
    DialHost := AProxyHost;
    DialPort := AProxyPort;
  end
  else
  begin
    DialHost := AHost;
    DialPort := APort;
  end;
  try
    FSocket := TInetSocket.Create(DialHost, DialPort, AConnectTimeoutMs);
  except
    on E: ESocketError do
      if E.Code = seConnectTimeOut then
        raise EHttpTimeout.CreateFmt('connect timed out after %d ms',
          [AConnectTimeoutMs])
      else
        raise EHttpConnectionError.CreateFmt('connect to %s:%d failed: %s',
          [DialHost, DialPort, E.Message]);
  end;
  FHandle := FSocket.Handle;
  FConnected := True;
  opt := 1;
{$IFDEF DARWIN}
  fpSetSockOpt(FHandle, SOL_SOCKET, SO_NOSIGPIPE, @opt, SizeOf(opt));
{$ENDIF}
  if AProxyHost <> '' then
    try
      EstablishProxyTunnelFd(FHandle, AHost, APort, AConnectTimeoutMs, '', '');
    except
      Close;
      raise;
    end;
end;

destructor TPlainSocket.Destroy;
begin
  Close;
  inherited Destroy;
end;

procedure TPlainSocket.Close;
begin
  // TInetSocket.Free owns the OS close; calling fpClose here as well would
  // close the descriptor twice (and could close an unrelated reused fd)
  if FSocket <> nil then
  begin
    FSocket.Free;
    FSocket := nil;
  end;
  FHandle := -1;
  FConnected := False;
end;

function TPlainSocket.Read(var ABuffer; ACount: Integer): Integer;
begin
  if not FConnected then
    raise EHttpConnectionClosed.Create('socket is closed');
  Result := SocketReadFully(FHandle, ACount, FReadTimeoutMs, ABuffer);
end;

function TPlainSocket.ReadSome(var ABuffer; ACount: Integer): Integer;
var
  n: ssize_t;
begin
  if not FConnected then
    raise EHttpConnectionClosed.Create('socket is closed');
  if ACount <= 0 then
    Exit(0);
  SetSocketTimeout(FHandle, SOL_SOCKET, SO_RCVTIMEO, FReadTimeoutMs);
  while True do
  begin
    n := fpRecv(FHandle, @ABuffer, ACount, 0);
    if n >= 0 then
      Exit(n);
    if SocketTimedOut then
      raise EHttpTimeout.CreateFmt('read timed out after %d ms',
        [FReadTimeoutMs])
    else if fpGetErrno <> ESysEINTR then
      raise EHttpConnectionClosed.CreateFmt('socket read failed (errno %d)',
        [fpGetErrno]);
  end;
end;

function TPlainSocket.Write(const ABuffer; ACount: Integer): Integer;
begin
  if not FConnected then
    raise EHttpConnectionClosed.Create('socket is closed');
  Result := SocketWriteFully(FHandle, ACount, FWriteTimeoutMs, ABuffer);
end;

function TPlainSocket.GetConnected: Boolean;
begin
  Result := FConnected;
end;

function TPlainSocket.GetConnectTimeoutMs: Integer;
begin
  Result := FConnectTimeoutMs;
end;

procedure TPlainSocket.SetConnectTimeoutMs(const AValue: Integer);
begin
  FConnectTimeoutMs := AValue;
end;

function TPlainSocket.GetReadTimeoutMs: Integer;
begin
  Result := FReadTimeoutMs;
end;

procedure TPlainSocket.SetReadTimeoutMs(const AValue: Integer);
begin
  FReadTimeoutMs := AValue;
end;

function TPlainSocket.GetWriteTimeoutMs: Integer;
begin
  Result := FWriteTimeoutMs;
end;

procedure TPlainSocket.SetWriteTimeoutMs(const AValue: Integer);
begin
  FWriteTimeoutMs := AValue;
end;

{ routed dialing }

/// connect AHost:APort through AProxy (nil = direct).  The result is the
/// socket the origin protocol runs on: after a CONNECT or SOCKS5 tunnel it is
/// a transparent byte stream to the origin.  AStream is True when that socket
/// is not a plain TCP socket (an https proxy), so a TLS layer above must run
/// in memory-BIO mode.
function DialRoutedTransport(const AHost: string; const APort: Word;
  const AConnectTimeoutMs: Integer; const AProxy: IProxy;
  const AInsecure: Boolean; const ACACertFile: string;
  out AStream: Boolean): IHttp2Socket;
var
  Plain: TPlainSocket;
  Leg: TTlsSocket;
  Who: string;
begin
  AStream := False;
  if AProxy = nil then
  begin
    Result := TPlainSocket.Create(AHost, APort, AConnectTimeoutMs);
    Exit;
  end;
  ValidateProxy(AProxy);
  Who := Format('%s:%d', [AProxy.Host, AProxy.Port]);
  // plain TCP to the proxy first: no tunnel is requested by the constructor
  Plain := TPlainSocket.Create(AProxy.Host, AProxy.Port, AConnectTimeoutMs);
  Result := Plain;
  Plain.SetReadTimeoutMs(AConnectTimeoutMs);
  Plain.SetWriteTimeoutMs(AConnectTimeoutMs);
  try
    if AProxy.Kind = pkHttps then
    begin
      // TLS to the proxy, verified against the proxy's host name; no ALPN, the
      // CONNECT exchange is HTTP/1.1
      Leg := TTlsSocket.Create(Plain, AProxy.Host, AInsecure, ACACertFile);
      Leg.FAlpnOffer := nil;
      Leg.FRequireH2 := False;
      Leg.ConnectTimeoutMs := AConnectTimeoutMs;
      Leg.ReadTimeoutMs := AConnectTimeoutMs;
      Leg.WriteTimeoutMs := AConnectTimeoutMs;
      try
        Leg.Establish;
      except
        on E: EHttpConnectionError do
        begin
          Leg.Free;
          raise EHttpConnectionError.CreateFmt(
            'TLS to proxy %s failed: %s', [Who, E.Message]);
        end;
        on E: Exception do
        begin
          Leg.Free;
          raise;
        end;
      end;
      Result := Leg;
      AStream := True;
      EstablishTunnelOver(TSocketChannel.Create(Leg), AProxy, AHost, APort);
    end
    else
      EstablishTunnelOver(TFdChannel.Create(Plain.Handle, AConnectTimeoutMs),
        AProxy, AHost, APort);
  except
    Result.Close;
    raise;
  end;
end;

{ TTlsSocket }

constructor TTlsSocket.Create(const ATransport: IHttp2Socket;
  const AHost: string; const AInsecure: Boolean; const ACACertFile: string);
begin
  inherited Create;
  FTransport := ATransport;
  FHost := AHost;
  FInsecure := AInsecure;
  FCACertFile := ACACertFile;
  FAlpnOffer := AlpnOfferFor(False); // strict default: offer "h2" alone
  FRequireH2 := True;
  FConnectTimeoutMs := cDefaultSocketTimeoutMs;
  FReadTimeoutMs := cDefaultSocketTimeoutMs;
  FWriteTimeoutMs := cDefaultSocketTimeoutMs;
end;

procedure TTlsSocket.SetAlpnOffer(const AOffer: TBytes);
begin
  FAlpnOffer := AOffer;
end;

destructor TTlsSocket.Destroy;
begin
  Close;
  inherited Destroy;
end;

function TTlsSocket.CreateSslContext: PSSL_CTX;
begin
  if not OpenSslIsAvailable then
    raise EHttpConnectionError.Create(
      'OpenSSL is not available: set OPENSSL_LIBPATH to the OpenSSL library ' +
      'directory (e.g. /opt/homebrew/opt/openssl@3/lib)');
  Result := SSL_CTX_new(TLS_client_method());
  if Result = nil then
    raise EHttpConnectionError.Create('SSL_CTX_new failed');
end;

procedure TTlsSocket.DestroySslContext;
begin
  if FCtx <> nil then
  begin
    SSL_CTX_free(FCtx);
    FCtx := nil;
  end;
end;

function TTlsSocket.CreateSslHandle(const ACtx: PSSL_CTX): PSSL;
begin
  Result := SSL_new(ACtx);
  if Result = nil then
    raise EHttpConnectionError.Create('SSL_new failed');
end;

procedure TTlsSocket.DestroySslHandle;
begin
  if FSsl <> nil then
  begin
    SSL_free(FSsl);
    FSsl := nil;
  end;
end;

function TTlsSocket.ApplyAlpnProtos(const ACtx: PSSL_CTX): Integer;
begin
  if Length(FAlpnOffer) = 0 then
    Exit(0);
  Result := SSL_CTX_set_alpn_protos(ACtx, @FAlpnOffer[0], Length(FAlpnOffer));
end;

procedure TTlsSocket.ApplyVerifyMode(const ACtx: PSSL_CTX;
  const AMode: Integer);
begin
  if AMode <> SSL_VERIFY_NONE then
    // an explicit PEM bundle (private CA, or a test certificate) replaces the
    // system trust store rather than adding to it
    if FCACertFile <> '' then
    begin
      if SSL_CTX_load_verify_locations(ACtx, PUtf8Char(UTF8String(FCACertFile)),
         nil) <> 1 then
        raise EHttpConnectionError.CreateFmt(
          'SSL_CTX_load_verify_locations failed for "%s"', [FCACertFile]);
    end
    else
      SSL_CTX_set_default_verify_paths(ACtx);
  SSL_CTX_set_verify(ACtx, AMode, nil);
end;

function TTlsSocket.ApplyHostnameVerification(const ASsl: PSSL;
  const AHost: string): Integer;
begin
  Result := SSL_set1_host(ASsl, PUtf8Char(UTF8String(AHost)));
end;

function TTlsSocket.ApplySniHost(const ASsl: PSSL;
  const AHost: string): Integer;
begin
  Result := SSL_set_tlsext_host_name(ASsl, UTF8String(AHost));
end;

function TTlsSocket.BindSocket(const ASsl: PSSL; const AFd: Integer): Integer;
begin
  Result := SSL_set_fd(ASsl, AFd);
end;

function TTlsSocket.HandshakeConnect(const ASsl: PSSL): Integer;
begin
  Result := SSL_connect(ASsl);
end;

function TTlsSocket.SelectedAlpnBytes(const ASsl: PSSL): TBytes;
var
  data: PByte;
  len: Cardinal;
  i: Cardinal;
begin
  Result := nil;
  data := nil;
  len := 0;
  SSL_get0_alpn_selected(ASsl, @data, @len);
  if (data = nil) or (len = 0) then
    Exit;
  SetLength(Result, len);
  for i := 0 to len - 1 do
    Result[i] := data[i];
end;

function TTlsSocket.LastSslError(const ASsl: PSSL;
  const AResult: Integer): Integer;
begin
  Result := SSL_get_error(ASsl, AResult);
end;

function TTlsSocket.SslReadBytes(const ASsl: PSSL; const ABuffer: Pointer;
  const ACount: Integer): Integer;
begin
  Result := SSL_read(ASsl, ABuffer, ACount);
end;

function TTlsSocket.SslWriteBytes(const ASsl: PSSL; const ABuffer: Pointer;
  const ACount: Integer): Integer;
begin
  Result := SSL_write(ASsl, ABuffer, ACount);
end;

procedure TTlsSocket.SslShutdown(const ASsl: PSSL);
begin
  SSL_shutdown(ASsl);
end;

function TTlsSocket.GetSocketFd: Integer;
var
  Obj: TObject;
begin
  if (FTransport = nil) or
     (not Supports(FTransport, TPlainSocket, Obj)) then
    raise EHttpConnectionError.Create(
      'TLS requires a plain TCP transport exposing a socket handle');
  Result := TPlainSocket(Obj).Handle;
end;

procedure TTlsSocket.Establish;
var
  r: Integer;
  Alpn: TBytes;
begin
  if FHandshaked then
    Exit;
  try
    FCtx := CreateSslContext;
    ApplyVerifyMode(FCtx, SslVerifyModeFor(FInsecure));
    if ApplyAlpnProtos(FCtx) <> 0 then
      raise EHttpConnectionError.Create('SSL_CTX_set_alpn_protos failed');
    FSsl := CreateSslHandle(FCtx);
    if not FInsecure then
      if ApplyHostnameVerification(FSsl, FHost) <> 1 then
        raise EHttpConnectionError.Create('SSL_set1_host failed');
    if ApplySniHost(FSsl, FHost) <> 1 then
      raise EHttpConnectionError.Create('SSL_set_tlsext_host_name failed');
    if FStreamMode then
    begin
      // the transport is another byte stream: OpenSSL gets two memory BIOs
      // (SSL_set_bio takes ownership of both) and StreamHandshake moves the
      // bytes; deadlines are the transport's own
      FRbio := BIO_new(BIO_s_mem());
      FWbio := BIO_new(BIO_s_mem());
      if (FRbio = nil) or (FWbio = nil) then
        raise EHttpConnectionError.Create('BIO_new failed');
      SSL_set_bio(FSsl, FRbio, FWbio);
      FTransport.ReadTimeoutMs := FConnectTimeoutMs;
      FTransport.WriteTimeoutMs := FConnectTimeoutMs;
      r := StreamHandshake(FSsl);
      FTransport.ReadTimeoutMs := FReadTimeoutMs;
      FTransport.WriteTimeoutMs := FWriteTimeoutMs;
    end
    else
    begin
      if BindSocket(FSsl, GetSocketFd) <> 1 then
        raise EHttpConnectionError.Create('SSL_set_fd failed');
      // SSL_connect recv()s/send()s directly on the fd, so install the
      // deadline there as well: a stalled handshake must not block forever
      SetSocketTimeout(GetSocketFd, SOL_SOCKET, SO_RCVTIMEO, FConnectTimeoutMs);
      SetSocketTimeout(GetSocketFd, SOL_SOCKET, SO_SNDTIMEO, FConnectTimeoutMs);
      r := HandshakeConnect(FSsl);
    end;
    if r <> 1 then
      if (not FStreamMode) and SocketTimedOut then
        raise EHttpTimeout.CreateFmt('TLS handshake timed out after %d ms',
          [FConnectTimeoutMs])
      else
        raise EHttpConnectionError.CreateFmt(
          'TLS handshake failed (SSL_get_error=%d)', [LastSslError(FSsl, r)]);
    Alpn := SelectedAlpnBytes(FSsl);
    // strict mode still fails when the peer does not select "h2" (interop
    // A.9); a fallback dial skips the check and reports the name instead
    if FRequireH2 then
      RequireH2Alpn(PByte(Alpn), Length(Alpn));
    FSelectedProtocol := AlpnNegotiatedName(
      AlpnSelectedName(PByte(Alpn), Length(Alpn)));
    FHandshaked := True;
  except
    DestroySslHandle;
    FRbio := nil;
    FWbio := nil;
    DestroySslContext;
    raise;
  end;
end;

class function TTlsSocket.Dial(const AHost: string; const APort: Word;
  const AInsecure: Boolean; const AConnectTimeoutMs: Integer;
  const ACACertFile: string; const AProxyHost: string;
  const AProxyPort: Word): IHttp2Socket;
var
  Transport: TPlainSocket;
  Sock: TTlsSocket;
begin
  Transport := TPlainSocket.Create(AHost, APort, AConnectTimeoutMs, AProxyHost,
    AProxyPort);
  Sock := TTlsSocket.Create(Transport, AHost, AInsecure, ACACertFile);
  Sock.ConnectTimeoutMs := AConnectTimeoutMs;
  Sock.ReadTimeoutMs := AConnectTimeoutMs;
  try
    Sock.Establish;
  except
    Sock.Free;
    raise;
  end;
  Result := Sock;
end;

class function TTlsSocket.DialWithAlpn(const AHost: string; const APort: Word;
  const AAlpnOffer: TBytes; const AInsecure: Boolean;
  const AConnectTimeoutMs: Integer;
  const ACACertFile: string; const AProxyHost: string;
  const AProxyPort: Word): IHttp2Socket;
var
  Transport: TPlainSocket;
  Sock: TTlsSocket;
begin
  Transport := TPlainSocket.Create(AHost, APort, AConnectTimeoutMs, AProxyHost,
    AProxyPort);
  Sock := TTlsSocket.Create(Transport, AHost, AInsecure, ACACertFile);
  Sock.ConnectTimeoutMs := AConnectTimeoutMs;
  Sock.ReadTimeoutMs := AConnectTimeoutMs;
  // the caller supplies the offer and applies its own ALPN policy afterwards
  Sock.FAlpnOffer := AAlpnOffer;
  Sock.FRequireH2 := False;
  try
    Sock.Establish;
  except
    Sock.Free;
    raise;
  end;
  Result := Sock;
end;

class function TTlsSocket.DialCleartext(const AHost: string; const APort: Word;
  const AConnectTimeoutMs: Integer; const AProxyHost: string;
  const AProxyPort: Word): IHttp2Socket;
var
  Sock: TPlainSocket;
begin
  Sock := TPlainSocket.Create(AHost, APort, AConnectTimeoutMs, AProxyHost,
    AProxyPort);
  Sock.SetConnectTimeoutMs(AConnectTimeoutMs);
  Sock.SetReadTimeoutMs(AConnectTimeoutMs);
  Sock.SetWriteTimeoutMs(AConnectTimeoutMs);
  Result := Sock;
end;

class function TTlsSocket.DialVia(const AHost: string; const APort: Word;
  const AInsecure: Boolean; const AConnectTimeoutMs: Integer;
  const ACACertFile: string; const AProxy: IProxy): IHttp2Socket;
var
  Transport: IHttp2Socket;
  Stream: Boolean;
  Sock: TTlsSocket;
begin
  Transport := DialRoutedTransport(AHost, APort, AConnectTimeoutMs, AProxy,
    AInsecure, ACACertFile, Stream);
  Sock := TTlsSocket.Create(Transport, AHost, AInsecure, ACACertFile);
  Sock.FStreamMode := Stream;
  Sock.ConnectTimeoutMs := AConnectTimeoutMs;
  Sock.ReadTimeoutMs := AConnectTimeoutMs;
  try
    Sock.Establish;
  except
    Sock.Free;
    raise;
  end;
  Result := Sock;
end;

class function TTlsSocket.DialWithAlpnVia(const AHost: string;
  const APort: Word; const AAlpnOffer: TBytes; const AInsecure: Boolean;
  const AConnectTimeoutMs: Integer; const ACACertFile: string;
  const AProxy: IProxy): IHttp2Socket;
var
  Transport: IHttp2Socket;
  Stream: Boolean;
  Sock: TTlsSocket;
begin
  Transport := DialRoutedTransport(AHost, APort, AConnectTimeoutMs, AProxy,
    AInsecure, ACACertFile, Stream);
  Sock := TTlsSocket.Create(Transport, AHost, AInsecure, ACACertFile);
  Sock.FStreamMode := Stream;
  Sock.ConnectTimeoutMs := AConnectTimeoutMs;
  Sock.ReadTimeoutMs := AConnectTimeoutMs;
  // the caller supplies the offer and applies its own ALPN policy afterwards
  Sock.FAlpnOffer := AAlpnOffer;
  Sock.FRequireH2 := False;
  try
    Sock.Establish;
  except
    Sock.Free;
    raise;
  end;
  Result := Sock;
end;

class function TTlsSocket.DialCleartextVia(const AHost: string;
  const APort: Word; const AConnectTimeoutMs: Integer; const AProxy: IProxy;
  const AInsecure: Boolean; const ACACertFile: string): IHttp2Socket;
var
  Stream: Boolean;
begin
  Result := DialRoutedTransport(AHost, APort, AConnectTimeoutMs, AProxy,
    AInsecure, ACACertFile, Stream);
  Result.ConnectTimeoutMs := AConnectTimeoutMs;
  Result.ReadTimeoutMs := AConnectTimeoutMs;
  Result.WriteTimeoutMs := AConnectTimeoutMs;
end;

function TTlsSocket.Read(var ABuffer; ACount: Integer): Integer;
var
  n, err: Integer;
  base: PByte;
begin
  if not FHandshaked then
    raise EHttpConnectionError.Create('TLS handshake not completed');
  if ACount <= 0 then
    Exit(0);
  // SSL_read ultimately recv()s on the underlying fd, so the read deadline
  // must be installed there for a stalled peer to surface as EHttpTimeout
  if not FStreamMode then
    SetSocketTimeout(GetSocketFd, SOL_SOCKET, SO_RCVTIMEO, FReadTimeoutMs);
  base := PByte(@ABuffer);
  Result := 0;
  while Result < ACount do
  begin
    n := SslReadBytes(FSsl, base + Result, ACount - Result);
    if n > 0 then
      Inc(Result, n)
    else
    begin
      err := LastSslError(FSsl, n);
      if FStreamMode and (err = SSL_ERROR_WANT_READ) then
      begin
        BioFlush;
        BioFeed;            // at EOF the next SSL_read reports the close
      end
      else if FStreamMode and (err = SSL_ERROR_WANT_WRITE) then
        BioFlush
      else if (err = SSL_ERROR_ZERO_RETURN) or
         ((err = SSL_ERROR_SYSCALL) and (n = 0)) or
         (FStreamMode and FEofFed and (err = SSL_ERROR_SSL)) then
        Exit // clean close_notify, or peer closed the transport without one
      else if (not FStreamMode) and SocketTimedOut then
        raise EHttpTimeout.CreateFmt('TLS read timed out after %d ms',
          [FReadTimeoutMs])
      else
        raise EHttpConnectionClosed.CreateFmt(
          'TLS read failed (SSL_get_error=%d)', [err]);
    end;
  end;
end;

function TTlsSocket.Write(const ABuffer; ACount: Integer): Integer;
var
  n, err: Integer;
  base: PByte;
begin
  if not FHandshaked then
    raise EHttpConnectionError.Create('TLS handshake not completed');
  if ACount <= 0 then
    Exit(0);
  if not FStreamMode then
    SetSocketTimeout(GetSocketFd, SOL_SOCKET, SO_SNDTIMEO, FWriteTimeoutMs);
  base := PByte(@ABuffer);
  Result := 0;
  while Result < ACount do
  begin
    n := SslWriteBytes(FSsl, base + Result, ACount - Result);
    if n > 0 then
    begin
      Inc(Result, n);
      if FStreamMode then
        BioFlush;
    end
    else
    begin
      err := LastSslError(FSsl, n);
      if FStreamMode and (err = SSL_ERROR_WANT_READ) then
      begin
        BioFlush;
        BioFeed;
      end
      else if FStreamMode and (err = SSL_ERROR_WANT_WRITE) then
        BioFlush
      else if (not FStreamMode) and SocketTimedOut then
        raise EHttpTimeout.CreateFmt('TLS write timed out after %d ms',
          [FWriteTimeoutMs])
      else
        raise EHttpConnectionClosed.CreateFmt(
          'TLS write failed (SSL_get_error=%d)', [err]);
    end;
  end;
end;

function TTlsSocket.ReadSome(var ABuffer; ACount: Integer): Integer;
var
  n, err: Integer;
begin
  if not FHandshaked then
    raise EHttpConnectionError.Create('TLS handshake not completed');
  if ACount <= 0 then
    Exit(0);
  if not FStreamMode then
    SetSocketTimeout(GetSocketFd, SOL_SOCKET, SO_RCVTIMEO, FReadTimeoutMs);
  while True do
  begin
    n := SslReadBytes(FSsl, @ABuffer, ACount);
    if n > 0 then
      Exit(n);
    err := LastSslError(FSsl, n);
    if FStreamMode and (err = SSL_ERROR_WANT_READ) then
    begin
      BioFlush;
      BioFeed;
    end
    else if FStreamMode and (err = SSL_ERROR_WANT_WRITE) then
      BioFlush
    else if (err = SSL_ERROR_ZERO_RETURN) or
       ((err = SSL_ERROR_SYSCALL) and (n = 0)) or
       (FStreamMode and FEofFed and (err = SSL_ERROR_SSL)) then
      Exit(0)
    else if (not FStreamMode) and SocketTimedOut then
      raise EHttpTimeout.CreateFmt('TLS read timed out after %d ms',
        [FReadTimeoutMs])
    else
      raise EHttpConnectionClosed.CreateFmt(
        'TLS read failed (SSL_get_error=%d)', [err]);
  end;
end;

{ memory-BIO plumbing for a TLS layer carried over another byte stream }

procedure TTlsSocket.BioFlush;
var
  Buf: array[0..16383] of Byte;
  N: Integer;
begin
  if FWbio = nil then
    Exit;
  while BIO_ctrl(FWbio, _BIO_CTRL_PENDING, 0, nil) > 0 do
  begin
    N := BIO_read(FWbio, @Buf[0], SizeOf(Buf));
    if N <= 0 then
      Break;
    FTransport.Write(Buf[0], N);
  end;
end;

function TTlsSocket.BioFeed: Boolean;
var
  Buf: array[0..16383] of Byte;
  N: Integer;
  PR: IPartialReader;
begin
  if Supports(FTransport, IPartialReader, PR) then
    N := PR.ReadSome(Buf[0], SizeOf(Buf))
  else
    N := FTransport.Read(Buf[0], 1);
  if N <= 0 then
  begin
    // an empty read BIO now reports end of stream instead of "try again"
    BIO_ctrl(FRbio, BIO_C_SET_BUF_MEM_EOF_RETURN, 0, nil);
    FEofFed := True;
    Exit(False);
  end;
  if BIO_write(FRbio, @Buf[0], N) <> N then
    raise EHttpConnectionError.Create('BIO_write failed');
  Result := True;
end;

function TTlsSocket.StreamHandshake(const ASsl: PSSL): Integer;
var
  r, err: Integer;
begin
  repeat
    r := HandshakeConnect(ASsl);
    BioFlush;
    if r = 1 then
      Exit(1);
    err := LastSslError(ASsl, r);
    if err = SSL_ERROR_WANT_READ then
    begin
      if not BioFeed then
        Exit(r);            // the proxy closed during the handshake
    end
    else if err <> SSL_ERROR_WANT_WRITE then
      Exit(r);
  until False;
end;

procedure TTlsSocket.Close;
begin
  if FSsl <> nil then
    SslShutdown(FSsl);
  if FStreamMode and FHandshaked then
    try
      BioFlush;             // deliver close_notify through the tunnel
    except
      // the transport may already be gone
    end;
  DestroySslHandle;
  FRbio := nil;
  FWbio := nil;
  DestroySslContext;
  FHandshaked := False;
  if FTransport <> nil then
    FTransport.Close;
end;

function TTlsSocket.GetConnected: Boolean;
begin
  Result := FHandshaked and (FTransport <> nil) and FTransport.Connected;
end;

function TTlsSocket.GetConnectTimeoutMs: Integer;
begin
  Result := FConnectTimeoutMs;
end;

procedure TTlsSocket.SetConnectTimeoutMs(const AValue: Integer);
begin
  FConnectTimeoutMs := AValue;
end;

function TTlsSocket.GetReadTimeoutMs: Integer;
begin
  Result := FReadTimeoutMs;
end;

procedure TTlsSocket.SetReadTimeoutMs(const AValue: Integer);
begin
  FReadTimeoutMs := AValue;
  if FTransport <> nil then
    FTransport.ReadTimeoutMs := AValue;
end;

function TTlsSocket.GetWriteTimeoutMs: Integer;
begin
  Result := FWriteTimeoutMs;
end;

procedure TTlsSocket.SetWriteTimeoutMs(const AValue: Integer);
begin
  FWriteTimeoutMs := AValue;
  if FTransport <> nil then
    FTransport.WriteTimeoutMs := AValue;
end;

{ TProtocolSocketFactory }

constructor TProtocolSocketFactory.Create(const ACACertFile: string;
  const AInsecure: Boolean; const AProxyHost: string;
  const AProxyPort: Word);
begin
  inherited Create;
  FCACertFile := ACACertFile;
  FInsecure := AInsecure;
  FProxyHost := AProxyHost;
  FProxyPort := AProxyPort;
end;

function TProtocolSocketFactory.DialProtocol(const AHost: string;
  const APort: Word; const AScheme: string; const AHttp1Fallback: Boolean;
  const APolicy: TClearTextPolicy; const ATimeoutMs: Integer;
  out AProtocol: TNegotiatedProtocol): IHttp2Socket;
var
  Proxy: IProxy;
begin
  // the proxy given to the constructor is a fixed HTTP proxy for every dial
  Proxy := nil;
  if FProxyHost <> '' then
    Proxy := TProxy.Create(FProxyHost, FProxyPort);
  Result := DialProtocolVia(AHost, APort, AScheme, AHttp1Fallback, APolicy,
    ATimeoutMs, Proxy, AProtocol);
end;

function TProtocolSocketFactory.DialProtocolVia(const AHost: string;
  const APort: Word; const AScheme: string; const AHttp1Fallback: Boolean;
  const APolicy: TClearTextPolicy; const ATimeoutMs: Integer;
  const AProxy: IProxy;
  out AProtocol: TNegotiatedProtocol): IHttp2Socket;
var
  Sock: IHttp2Socket;
  Name: string;
begin
  AProtocol := npHttp2Tls;
  if AScheme = 'http' then
  begin
    // cleartext: the policy decides (doc/design/fallback.md "http origins")
    case APolicy of
      ctReject:
        raise EHttpProtocolError.Create(
          'cleartext origin rejected (set WithClearText to enable it)',
          ecProtocolError);
      ctUpgrade:
        // task 13.3 layers the HTTP/1.1 Upgrade dance on the cleartext socket;
        // until then the caller drives HTTP/1.1 directly on this transport
        begin
          AProtocol := npHttp1Cleartext;
          Result := TTlsSocket.DialCleartextVia(AHost, APort, ATimeoutMs, AProxy,
            FInsecure, FCACertFile);
        end;
    else
      // ctPriorKnowledge: speak HTTP/2 at once, the caller writes the preface
      begin
        AProtocol := npHttp2Cleartext;
        Result := TTlsSocket.DialCleartextVia(AHost, APort, ATimeoutMs, AProxy,
          FInsecure, FCACertFile);
      end;
    end;
    Exit;
  end;

  // https: the ALPN offer follows the fallback flag, then the result maps to a
  // codec.  DialWithAlpn skips the strict check so we can map the name here.
  Sock := TTlsSocket.DialWithAlpnVia(AHost, APort, AlpnOfferFor(AHttp1Fallback),
    FInsecure, ATimeoutMs, FCACertFile, AProxy);
  // $interfaces com: an interface reference points past the object's VMT, so
  // `TTlsSocket(Sock)` (a raw hard cast) would read the wrong memory.  Recover
  // the object with `as TObject` before the class cast so the property read
  // returns the name Establish recorded.
  Name := TTlsSocket(Sock as TObject).SelectedProtocol;
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

function SecureRandomCardinal: Cardinal;
begin
  if not OpenSslIsAvailable then
    raise EHttpConnectionError.Create('OpenSSL is not available');
  if RAND_bytes(@Result, SizeOf(Result)) <> 1 then
    raise EHttpConnectionError.Create('the secure random generator failed');
end;

function TProtocolSocketFactory.DialHttp1(const AHost: string;
  const APort: Word; const AScheme: string; const ATimeoutMs: Integer;
  const AProxy: IProxy): IHttp2Socket;
var
  Proxy: IProxy;
  TlsObj: TObject;
  Name: string;
begin
  Proxy := AProxy;
  if (Proxy = nil) and (FProxyHost <> '') then
    Proxy := TProxy.Create(FProxyHost, FProxyPort);
  if AScheme = 'http' then
    Exit(TTlsSocket.DialCleartextVia(AHost, APort, ATimeoutMs, Proxy,
      FInsecure, FCACertFile));
  Result := TTlsSocket.DialWithAlpnVia(AHost, APort,
    AlpnProtocolList([cHttp11AlpnProtocol]), FInsecure, ATimeoutMs,
    FCACertFile, Proxy);
  Name := '';
  if Supports(Result, TTlsSocket, TlsObj) then
    Name := TTlsSocket(TlsObj).SelectedProtocol;
  // a server without ALPN support answers nothing and speaks HTTP/1.1; one
  // that picked h2 anyway cannot carry an Upgrade
  if (Name <> '') and (Name <> cHttp11AlpnProtocol) then
  begin
    Result.Close;
    raise EHttpProtocolError.Create(Format(
      'peer selected ALPN "%s" for a connection that needs HTTP/1.1', [Name]),
      ecProtocolError);
  end;
end;

end.
