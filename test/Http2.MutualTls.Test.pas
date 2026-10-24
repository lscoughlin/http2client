/// Mutual TLS tests against an in-process OpenSSL server (doc/design/mtls.md)
// - the server requires a client certificate (SSL_VERIFY_PEER with
//   FAIL_IF_NO_PEER_CERT, trust store = the fixture CA) and pins TLS 1.2 or
//   1.3, so both ways a rejection surfaces are exercised: the handshake fails
//   (1.2) or the first read fails after the handshake "succeeded" (1.3).
// - it answers one canned HTTP/2 or HTTP/1.1 exchange, an event stream or a
//   WebSocket upgrade, so the whole client path runs; a small tunnel proxy
//   (CONNECT, SOCKS5, TLS to the proxy) covers the routed dials.
// - the fixtures come from tools/validate/make-mtls-certs.sh.
unit Http2.MutualTls.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, SyncObjs, Sockets, BaseUnix, fpcunit, testregistry,
  mormot.core.base, mormot.core.os, mormot.lib.openssl11,
  Http2.Errors, Http2.ClientCert, Http2.Proxy, Http2.Tls, Http2.Messages,
  Http2.Stream,
  Http2.Client,
  Http2.Sse, Http2.WebSocket, Http2.RequestObserver,
  Http2.RequestObserver.Test;

type
  TMtlsKind = (mkH2, mkHttp1, mkSse, mkWebSocket, mkPlain);

  /// the ALPN protocol the server selects when the client offers it
  TAlpnChoice = record
    Len: Byte;
    Name: array[0..15] of AnsiChar;
  end;

  TMtlsServer = class;

  /// serves one HTTP/2 connection beside the others, so a client that opens a
  /// second connection to the same origin is not blocked behind the first
  TMtlsConnThread = class(TThread)
  private
    FServer: TMtlsServer;
    FFd: Integer;
  protected
    procedure Execute; override;
  public
    constructor Create(const AServer: TMtlsServer; const AFd: Integer);
  end;

  TMtlsServer = class(TThread)
  private
    FActive: Integer;
    FListenFd: Integer;
    FCtx: PSSL_CTX;
    FKind: TMtlsKind;
    FAlpn: TAlpnChoice;
    FPort: Word;
    procedure Serve(const AFd: Integer);
    procedure ServeAndClose(const AFd: Integer);
    procedure ServeTls(const AFd: Integer);
  protected
    procedure Execute; override;
  public
    /// TCP connections accepted, handshakes completed and refused
    Connections, Handshakes, Refused, Requests: Integer;
    /// subject of the last client certificate the server accepted
    LastSubject: string;
    /// a client certificate was offered on any accepted handshake
    SawClientCert: Boolean;
    /// every accepted handshake in order, as '|<subject>' or '|none'
    AllSubjects: string;
    /// an HTTP/1.1 request for a path starting with /redir is answered 302
    /// to this Location
    RedirectTo: string;
    /// AOptionalCert asks for a certificate without insisting on one, so a
    /// client that presents none still completes the handshake
    constructor Create(const AKind: TMtlsKind; const AVersion: Integer;
      const AOptionalCert: Boolean = False);
    destructor Destroy; override;
    procedure Stop;
    property Port: Word read FPort;
  end;

  TTunnelMode = (tmConnect, tmSocks5, tmHttps);

  /// who chooses the origin identity of a wss dial
  TIdentitySource = (isFixed, isSelector, isRequest);

  /// forwards one connection at a time to the origin port; for tmHttps the
  /// client leg is TLS and the proxy notes whether a certificate was offered
  TTunnelProxy = class(TThread)
  private
    FListenFd: Integer;
    FCtx: PSSL_CTX;
    FMode: TTunnelMode;
    FOriginPort: Word;
    FRequireCert: Boolean;
    FPort: Word;
    procedure Handle(const AFd: Integer);
  protected
    procedure Execute; override;
  public
    Tunnels, Refused: Integer;
    SawClientCert: Boolean;
    /// subject of the last client certificate the proxy accepted
    LastSubject: string;
    /// ARequireCert makes an https proxy refuse a client that offers none
    /// AVersion pins the https leg to one TLS version (0 = any)
    constructor Create(const AMode: TTunnelMode; const AOriginPort: Word;
      const ARequireCert: Boolean = False; const AVersion: Integer = 0);
    destructor Destroy; override;
    procedure Stop;
    property Port: Word read FPort;
  end;

  /// answers a fixed identity per port and counts the calls; the optional
  /// probe checks, from another thread, that the pool lock is free during it
  TCountingSelector = class(TInterfacedObject, IClientIdentitySelector)
  private
    FProbe: THttpClient;
  public
    Calls: Integer;
    LastHost: string;
    LastPort: Word;
    LastThread: TThreadID;
    Answer: IClientIdentity;
    /// when ForPort is set, that port gets PortAnswer instead of Answer
    ForPort: Word;
    PortAnswer: IClientIdentity;
    Fail: Boolean;
    LockWasFree: Boolean;
    /// the call takes this long, so a concurrent request can arrive meanwhile
    DelayMs: Integer;
    function Select(const AHost: string; const APort: Word): IClientIdentity;
    procedure ProbeLockWith(const AClient: IHttpClient);
  end;

  /// one Send of a GET and a body read on its own thread
  TFetchThread = class(TThread)
  private
    FClient: IHttpClient;
    FUrl: string;
  protected
    procedure Execute; override;
  public
    Status: Integer;
    Failed: Boolean;
    constructor Create(const AClient: IHttpClient; const AUrl: string);
  end;

  /// an injected socket factory that cannot present identities (it does not
  /// implement IIdentitySocketFactory); counts its dials
  TPlainSocketFactory = class(TInterfacedObject, IHttp2SocketFactory)
  public
    Dials: Integer;
    function Dial(const AHost: string; const APort: Word;
      const ATimeoutMs: Integer): IHttp2Socket;
  end;

  /// routes every request, loopback included, through one proxy
  TFixedSelector = class(TInterfacedObject, IProxySelector)
  private
    FProxy: IProxy;
  public
    constructor Create(const AKind: TProxyKind; const APort: Word);
    function SelectProxy(const AUri: string): IProxy;
  end;

  TWsRecorder = class(TWebSocketListener)
  private
    FEvent: TEvent;
  public
    Text: string;
    constructor Create;
    destructor Destroy; override;
    procedure OnText(const ASocket: IWebSocket; const AText: string;
      const ALast: Boolean); override;
    function WaitText(const AMs: Integer): Boolean;
  end;

  TMutualTlsTest = class(TTestCase)
  private
    FServer: TMtlsServer;
    FProxy: TTunnelProxy;
    /// the identity for the TLS leg to an https proxy (nil = none)
    FProxyIdentity: IClientIdentity;
    function StartServer(const AKind: TMtlsKind; const AVersion: Integer;
      const AOptionalCert: Boolean = False): TMtlsServer;
    function RouteVia(const AFactory: THttpClientFactory): THttpClientFactory;
    function Url(const AScheme: string = 'https'): string;
    function GoodIdentity: IClientIdentity;
    function NewClient(const AIdentity: IClientIdentity;
      const AFallback: Boolean = False): IHttpClient;
    function Fetch(const AClient: IHttpClient; out ABody: string): Integer;
    function AlertOfFetch(const AClient: IHttpClient): string;
    procedure RunAccepts(const AKind: TMtlsKind; const AVersion: Integer;
      const AFallback: Boolean);
    procedure RunSse(const AVersion: Integer);
    procedure RunWebSocket(const AVersion: Integer);
    procedure RunNoIdentity(const AKind: TMtlsKind; const AVersion: Integer;
      const AFallback: Boolean; const AExpected: string);
    procedure RunWrongCa(const AVersion: Integer);
    procedure RunExpiredOnTheWire(const AVersion: Integer;
      const AExpected: string);
    procedure RunTunnel(const AMode: TTunnelMode; const AVersion: Integer);
    function ServerUrl(const AServer: TMtlsServer): string;
    function SendTo(const AClient: IHttpClient; const AUrl: string): IHttpResponse;
    function ReadBody(const AResponse: IHttpResponse): string;
    function Client2Identity: IClientIdentity;
    function SubjectIs(const ASubject, AName: string): Boolean;
    procedure RunSelectorVia(const AMode: TTunnelMode);
    procedure RunWssVia(const AMode: TTunnelMode; const AWho: TIdentitySource;
      const AViaProxy: Boolean);
    procedure RunRequestVia(const AViaProxy: Boolean; const AMode: TTunnelMode);
    function KeysOf(const AClient: IHttpClient): string;
    function CountOf(const ASub, AText: string): Integer;
    function SelectorClient(const ASelector: IClientIdentitySelector): IHttpClient;
    function ProbeAlert(const AVersion: Integer;
      const AIdentity: IClientIdentity; const AKind: TMtlsKind): string;
  protected
    procedure TearDown; override;
  published
    // accepted identity, TLS 1.2 and 1.3
    procedure TestHttp2WithTheIdentityTls12;
    procedure TestHttp2WithTheIdentityTls13;
    procedure TestHttp11FallbackWithTheIdentityTls12;
    procedure TestHttp11FallbackWithTheIdentityTls13;
    procedure TestSseWithTheIdentityTls12;
    procedure TestSseWithTheIdentityTls13;
    procedure TestWssWithTheIdentityTls12;
    procedure TestWssWithTheIdentityTls13;
    procedure TestPkcs12IdentityIsAccepted;
    // rejection, TLS 1.2 and 1.3
    procedure TestNoIdentityIsRejectedOnceTls12;
    procedure TestNoIdentityIsRejectedOnceTls13;
    procedure TestNoIdentityOverHttp11IsRejectedTls13;
    procedure TestNoIdentityWithFallbackOnDoesNotFallBackTls13;
    procedure TestNoIdentityOnWssIsRejectedTls13;
    procedure TestWrongCaIsRejectedTls12;
    procedure TestWrongCaIsRejectedTls13;
    procedure TestExpiredIsRejectedOnTheWireTls12;
    procedure TestExpiredIsRejectedOnTheWireTls13;
    procedure TestRejectionIsNotRetried;
    // routed dials
    procedure TestConnectTunnelOriginSeesTheOriginIdentityTls13;
    procedure TestSocks5TunnelOriginSeesTheOriginIdentityTls13;
    procedure TestHttpsProxySeesOnlyTheProxyIdentityTls13;
    procedure TestHttpsProxySeesOnlyTheProxyIdentityTls12;
    procedure TestSelectorIsAskedForTheOriginThroughAnHttpsProxy;
    procedure TestSelectorIsAskedForTheOriginThroughAConnectProxy;
    procedure TestSelectorIsAskedForTheOriginThroughASocks5Proxy;
    procedure TestWssThroughAnHttpsProxySplitsTheIdentities;
    procedure TestWssThroughAConnectProxyPresentsTheOriginIdentity;
    procedure TestWssSelectorThroughAnHttpsProxyAsksForTheOrigin;
    // every dial helper
    procedure TestEveryDialHelperPresentsTheIdentity;
    procedure TestEveryTlsSocketConstructionCarriesTheIdentity;
    // selector
    procedure TestFixedIdentitySelectorAnswersTheIdentity;
    procedure TestSelectorIsCalledOncePerDialNotPerRequest;
    procedure TestSelectorRunsOnTheDiallingThreadOutsideThePoolLock;
    procedure TestSelectorChoosesTheIdentityPerOrigin;
    procedure TestNilAnswerPresentsNoCertificate;
    procedure TestThrowingSelectorFailsTheDial;
    procedure TestRotationOpensANewConnectionAndTheOldOneStillAnswers;
    procedure TestNilAnswerNeverSharesAConnectionWithAnIdentity;
    procedure TestSelectorAppliesToWss;
    procedure TestSelectorIsNotCalledForCleartext;
    procedure TestSelectorAndFixedIdentityReplaceEachOther;
    procedure TestOriginIdentityAloneIsRefusedByAnHttpsProxyThatAsksForOne;
    procedure TestProxyIdentityAloneIsNotPresentedToTheOrigin;
    procedure TestHttpsProxyToACleartextOriginGetsTheProxyIdentity;
    procedure TestSelectorKeyForACleartextOriginBehindAnHttpsProxy;
    procedure TestExpiredProxyIdentityFailsBuild;
    // per-request identity
    procedure TestRequestIdentityAccessorsAndClone;
    procedure TestRequestIdentityDirect;
    procedure TestRequestIdentityThroughConnect;
    procedure TestRequestIdentityThroughSocks5;
    procedure TestRequestIdentityThroughAnHttpsProxy;
    procedure TestTwoRequestIdentitiesOnOneOriginDoNotShareAConnection;
    procedure TestRequestIdentityWinsOverTheSelector;
    procedure TestRequestIdentityWinsOverTheFixedIdentity;
    procedure TestRequestWithoutIdentityKeepsThePlainKey;
    procedure TestRedirectToTheSameOriginKeepsTheRequestIdentity;
    procedure TestRedirectToAnotherOriginDropsTheRequestIdentity;
    procedure TestWssRequestIdentityDirect;
    procedure TestWssRequestIdentityThroughAnHttpsProxy;
    procedure TestSseRequestIdentity;
    procedure TestExpiredRequestIdentityRaisesBeforeDialling;
    procedure TestExpiredWssRequestIdentityRaisesBeforeDialling;
    // other
    procedure TestInjectedFactoryWithFixedIdentityFailsBuild;
    procedure TestInjectedFactoryWithSelectorFailsBuild;
    procedure TestInjectedFactoryWithProxyIdentityFailsBuild;
    procedure TestInjectedFactoryWithRequestIdentityFailsBeforeDialling;
    procedure TestInjectedFactoryWithWssRequestIdentityFailsBeforeDialling;
    procedure TestInjectedFactoryWithoutIdentitiesStillWorks;
    procedure TestExpiredSelectorAnswerFailsTheDialBeforeDialling;
    procedure TestExpiredSelectorAnswerFailsWssBeforeDialling;
    procedure TestRotationAtThePerHostCapEvictsTheIdleOldIdentity;
    procedure TestRotationAtTheTotalCapEvictsTheIdleOldIdentity;
    procedure TestBusyOldIdentityIsNeverEvicted;
    procedure TestTwoIdentitiesShareThePerHostCap;
    procedure TestConcurrentColdRequestsAskTheSelectorOnce;
    procedure TestCleartextIgnoresTheIdentity;
    procedure TestLogLineHasSubjectAndFingerprintButNoSecrets;
  end;

implementation

const
  cPass = 'mtls-test-pass';
  cTls12 = TLS1_2_VERSION;
  cTls13 = TLS1_3_VERSION;

function Fixture(const AName: string): string;
begin
  Result := ExtractFilePath(ParamStr(0)) + '../test/certs/mtls/' + AName;
  if FileExists(Result) then
    Exit;
  Result := 'test/certs/mtls/' + AName;
end;

{ one accepted connection, TLS or plain }

type
  TConn = record
    Ssl: PSSL;
    Fd: Integer;
  end;

function ConnRead(const C: TConn; var ABuf; const N: Integer): Integer;
begin
  if C.Ssl <> nil then
    Result := SSL_read(C.Ssl, @ABuf, N)
  else
    Result := fpRecv(C.Fd, @ABuf, N, 0);
  if Result < 0 then
    Result := 0;
end;

procedure ConnWrite(const C: TConn; const ABuf; const N: Integer);
var
  Sent, R: Integer;
begin
  Sent := 0;
  while Sent < N do
  begin
    if C.Ssl <> nil then
      R := SSL_write(C.Ssl, PByte(@ABuf) + Sent, N - Sent)
    else
      R := fpSend(C.Fd, PByte(@ABuf) + Sent, N - Sent, 0);
    if R <= 0 then
      Exit;
    Inc(Sent, R);
  end;
end;

procedure ConnWriteText(const C: TConn; const AText: AnsiString);
begin
  if AText <> '' then
    ConnWrite(C, AText[1], Length(AText));
end;

function ConnReadFull(const C: TConn; var ABuf; const N: Integer): Boolean;
var
  Got, R: Integer;
begin
  Got := 0;
  while Got < N do
  begin
    R := ConnRead(C, (PByte(@ABuf) + Got)^, N - Got);
    if R <= 0 then
      Exit(False);
    Inc(Got, R);
  end;
  Result := True;
end;

function ConnReadHead(const C: TConn): AnsiString;
var
  B: Byte;
begin
  Result := '';
  while ConnRead(C, B, 1) = 1 do
  begin
    Result := Result + AnsiChar(B);
    if (Length(Result) >= 4) and
       (Copy(Result, Length(Result) - 3, 4) = #13#10#13#10) then
      Exit;
    if Length(Result) > 16384 then
      Exit;
  end;
end;

procedure SetTimeouts(const AFd: Integer; const AMs: Integer);
var
  Tv: TTimeVal;
  One: Integer;
begin
  // a write to a connection the client already closed must not kill the run
  One := 1;
  {$IFDEF DARWIN}
  fpSetSockOpt(AFd, SOL_SOCKET, SO_NOSIGPIPE, @One, SizeOf(One));
  {$ENDIF}
  Tv.tv_sec := AMs div 1000;
  Tv.tv_usec := (AMs mod 1000) * 1000;
  fpSetSockOpt(AFd, SOL_SOCKET, SO_RCVTIMEO, @Tv, SizeOf(Tv));
  fpSetSockOpt(AFd, SOL_SOCKET, SO_SNDTIMEO, @Tv, SizeOf(Tv));
end;

function ListenOnLoopback(out APort: Word): Integer;
var
  Addr: TSockAddr;
  Len: LongInt;
begin
  Result := fpsocket(AF_INET, SOCK_STREAM, 0);
  FillChar(Addr, SizeOf(Addr), 0);
  Addr.sin_family := AF_INET;
  Addr.sin_port := htons(0);
  Addr.sin_addr.s_addr := htonl($7F000001);
  fpbind(Result, @Addr, SizeOf(Addr));
  fplisten(Result, 8);
  Len := SizeOf(Addr);
  fpgetsockname(Result, @Addr, @Len);
  APort := ntohs(Addr.sin_port);
end;

function WaitReadable(const AFd: Integer; const AMs: Integer): Boolean;
var
  P: TPollFd;
begin
  P.fd := AFd;
  P.events := POLLIN;
  P.revents := 0;
  Result := fpPoll(@P, 1, AMs) > 0;
end;

type
  TAlpnSelectCb = function(ssl: PSSL; out_: PPByte; outlen: PByte;
    in_: PByte; inlen: Cardinal; arg: Pointer): Integer; cdecl;
  TSetAlpnSelectCb = procedure(ctx: PSSL_CTX; cb: TAlpnSelectCb;
    arg: Pointer); cdecl;

function ResolveSslProc(const AName: PAnsiChar): Pointer;
var
  Dir: string;
  Lib: TLibHandle;
begin
  Result := nil;
  Dir := GetEnvironmentVariable('OPENSSL_LIBPATH');
  if Dir <> '' then
    Dir := IncludeTrailingPathDelimiter(Dir);
  Lib := LibraryOpen(Dir + LIB_SSL3);
  if Lib <> 0 then
    Result := LibraryResolve(Lib, AName);
end;

/// picks the server's configured protocol when the client offered it
function AlpnSelect(ssl: PSSL; out_: PPByte; outlen: PByte; in_: PByte;
  inlen: Cardinal; arg: Pointer): Integer; cdecl;
var
  Choice: ^TAlpnChoice;
  P: PByte;
  Left: Cardinal;
  L: Byte;
begin
  Choice := arg;
  P := in_;
  Left := inlen;
  while Left > 0 do
  begin
    L := P^;
    if (L = Choice^.Len) and (Left > L) and
       (CompareByte((P + 1)^, Choice^.Name[0], L) = 0) then
    begin
      out_^ := PByte(@Choice^.Name[0]);
      outlen^ := L;
      Exit(SSL_TLSEXT_ERR_OK);
    end;
    if Left < Cardinal(L) + 1 then
      Break;
    Dec(Left, Cardinal(L) + 1);
    Inc(P, Integer(L) + 1);
  end;
  Result := SSL_TLSEXT_ERR_NOACK;
end;

{ TMtlsServer }

constructor TMtlsServer.Create(const AKind: TMtlsKind; const AVersion: Integer;
  const AOptionalCert: Boolean);
var
  SetCb: TSetAlpnSelectCb;
  Name: AnsiString;
begin
  FKind := AKind;
  FListenFd := ListenOnLoopback(FPort);
  FCtx := SSL_CTX_new(TLS_server_method());
  SSL_CTX_use_certificate_file(FCtx, PUtf8Char(UTF8String(Fixture('server.crt'))),
    SSL_FILETYPE_PEM);
  SSL_CTX_use_PrivateKey_file(FCtx, PUtf8Char(UTF8String(Fixture('server.key'))),
    SSL_FILETYPE_PEM);
  SSL_CTX_load_verify_locations(FCtx,
    PUtf8Char(UTF8String(Fixture('ca.crt'))), nil);
  if AOptionalCert then
    SSL_CTX_set_verify(FCtx, SSL_VERIFY_PEER, nil)
  else
    SSL_CTX_set_verify(FCtx,
      SSL_VERIFY_PEER or SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nil);
  if AVersion <> 0 then
  begin
    SSL_CTX_set_min_proto_version(FCtx, AVersion);
    SSL_CTX_set_max_proto_version(FCtx, AVersion);
  end;
  // ALPN: h2 for the HTTP/2 server, http/1.1 for the HTTP/1.1 kinds
  if AKind = mkH2 then
    Name := 'h2'
  else
    Name := 'http/1.1';
  FAlpn.Len := Length(Name);
  Move(Name[1], FAlpn.Name[0], Length(Name));
  SetCb := ResolveSslProc('SSL_CTX_set_alpn_select_cb');
  if Assigned(SetCb) and (AKind <> mkPlain) then
    SetCb(FCtx, AlpnSelect, @FAlpn);
  inherited Create(False);
end;

destructor TMtlsServer.Destroy;
begin
  if FCtx <> nil then
    SSL_CTX_free(FCtx);
  if FListenFd >= 0 then
    fpClose(FListenFd);
  inherited Destroy;
end;

procedure TMtlsServer.Stop;
var
  I: Integer;
begin
  Terminate;
  WaitFor;
  // connection threads end when their client closes or the socket times out
  for I := 1 to 400 do
  begin
    if FActive = 0 then
      Break;
    Sleep(25);
  end;
end;

procedure TMtlsServer.ServeAndClose(const AFd: Integer);
begin
  try
    Serve(AFd);
  except
    // a failed exchange is visible to the client as an error
  end;
  fpClose(AFd);
end;

{ TMtlsConnThread }

constructor TMtlsConnThread.Create(const AServer: TMtlsServer;
  const AFd: Integer);
begin
  FServer := AServer;
  FFd := AFd;
  FreeOnTerminate := True;
  inherited Create(False);
end;

procedure TMtlsConnThread.Execute;
begin
  try
    FServer.ServeAndClose(FFd);
  finally
    InterlockedDecrement(FServer.FActive);
  end;
end;

procedure TMtlsServer.Execute;
var
  Fd: Integer;
begin
  while not Terminated do
  begin
    if not WaitReadable(FListenFd, 50) then
      Continue;
    Fd := fpAccept(FListenFd, nil, nil);
    if Fd < 0 then
      Continue;
    InterlockedIncrement(Connections);
    SetTimeouts(Fd, 3000);
    if FKind = mkH2 then
    begin
      InterlockedIncrement(FActive);
      TMtlsConnThread.Create(Self, Fd);
    end
    else
      ServeAndClose(Fd);
  end;
end;

procedure TMtlsServer.Serve(const AFd: Integer);
var
  C: TConn;
  Head: AnsiString;
begin
  if FKind <> mkPlain then
  begin
    ServeTls(AFd);
    Exit;
  end;
  C.Ssl := nil;
  C.Fd := AFd;
  Head := ConnReadHead(C);
  if Head <> '' then
  begin
    InterlockedIncrement(Requests);
    ConnWriteText(C, 'HTTP/1.1 200 OK'#13#10'Content-Length: 2'#13#10 +
      'Connection: close'#13#10#13#10'ok');
  end;
end;

procedure TMtlsServer.ServeTls(const AFd: Integer);
var
  C: TConn;
  Peer: PX509;
  Head, Key: AnsiString;
  P: Integer;
  Hdr: array[0..8] of Byte;
  Payload: array of Byte;
  Len: Integer;
  Sid: LongWord;
  Resp: array[0..8] of Byte;
  Preface: array[0..23] of Byte;
  Buf: array[0..255] of Byte;
  Closed: Boolean;

  procedure H2Frame(const AType, AFlags: Byte; const AStream: LongWord;
    const APayload: array of Byte);
  var
    F: array of Byte;
    I: Integer;
  begin
    SetLength(F, 9 + Length(APayload));
    F[0] := 0;
    F[1] := Length(APayload) shr 8;
    F[2] := Length(APayload) and $FF;
    F[3] := AType;
    F[4] := AFlags;
    F[5] := AStream shr 24;
    F[6] := (AStream shr 16) and $FF;
    F[7] := (AStream shr 8) and $FF;
    F[8] := AStream and $FF;
    for I := 0 to High(APayload) do
      F[9 + I] := APayload[I];
    ConnWrite(C, F[0], Length(F));
  end;

begin
  C.Fd := AFd;
  C.Ssl := SSL_new(FCtx);
  SSL_set_fd(C.Ssl, AFd);
  try
    if SSL_accept(C.Ssl) <> 1 then
    begin
      InterlockedIncrement(Refused);
      // the alert is already sent; read what the client wrote after its
      // handshake before closing, so the close does not reset the connection
      // and take the alert with it
      fpShutdown(AFd, SHUT_WR);
      SetTimeouts(AFd, 300);
      while fpRecv(AFd, @Buf[0], SizeOf(Buf), 0) > 0 do;
      Exit;
    end;
    InterlockedIncrement(Handshakes);
    Peer := SSL_get_peer_certificate(C.Ssl);
    if Peer <> nil then
    begin
      SawClientCert := True;
      LastSubject := string(Peer^.SubjectName);
      AllSubjects := AllSubjects + '|' + LastSubject;
      X509_free(Peer);
    end
    else
      AllSubjects := AllSubjects + '|none';
    case FKind of
      mkH2:
        begin
          if not ConnReadFull(C, Preface[0], SizeOf(Preface)) then
            Exit;
          H2Frame(4, 0, 0, []);                 // our SETTINGS (empty)
          while ConnReadFull(C, Hdr[0], 9) do
          begin
            Len := (Hdr[0] shl 16) or (Hdr[1] shl 8) or Hdr[2];
            Sid := (LongWord(Hdr[5] and $7F) shl 24) or (LongWord(Hdr[6]) shl 16) or
              (LongWord(Hdr[7]) shl 8) or Hdr[8];
            SetLength(Payload, Len);
            if (Len > 0) and (not ConnReadFull(C, Payload[0], Len)) then
              Exit;
            case Hdr[3] of
              4: if (Hdr[4] and 1) = 0 then
                   H2Frame(4, 1, 0, []);        // ACK the client's SETTINGS
              1: begin                          // HEADERS: answer 200 'ok'
                   InterlockedIncrement(Requests);
                   H2Frame(1, 4, Sid, [$88]);
                   H2Frame(0, 1, Sid, [Ord('o'), Ord('k')]);
                 end;
              7: Exit;                          // GOAWAY
            end;
          end;
        end;
      mkHttp1:
        begin
          Head := ConnReadHead(C);
          if Head <> '' then
          begin
            InterlockedIncrement(Requests);
            if (RedirectTo <> '') and (Pos('GET /redir', string(Head)) = 1) then
              ConnWriteText(C, 'HTTP/1.1 302 Found'#13#10'Location: ' +
                AnsiString(RedirectTo) + #13#10'Content-Length: 0'#13#10 +
                'Connection: close'#13#10#13#10)
            else
              ConnWriteText(C, 'HTTP/1.1 200 OK'#13#10'Content-Length: 2'#13#10 +
                'Connection: close'#13#10#13#10'ok');
          end;
        end;
      mkSse:
        begin
          Head := ConnReadHead(C);
          if Head <> '' then
          begin
            InterlockedIncrement(Requests);
            ConnWriteText(C, 'HTTP/1.1 200 OK'#13#10 +
              'Content-Type: text/event-stream'#13#10 +
              'Connection: close'#13#10#13#10'data: hello'#10#10);
          end;
        end;
      mkWebSocket:
        begin
          Head := ConnReadHead(C);
          P := Pos('sec-websocket-key:', LowerCase(Head));
          if P = 0 then
            Exit;
          Key := Trim(Copy(Head, P + 18, Pos(#13, Copy(Head, P, MaxInt)) - 19));
          InterlockedIncrement(Requests);
          ConnWriteText(C, 'HTTP/1.1 101 Switching Protocols'#13#10 +
            'Upgrade: websocket'#13#10'Connection: Upgrade'#13#10 +
            'Sec-WebSocket-Accept: ' + AnsiString(WsComputeAccept(string(Key))) +
            #13#10#13#10 + #$81#$05'hello');
          // answer the client's close frame, then end
          Closed := False;
          while (not Closed) and ConnReadFull(C, Resp[0], 2) do
          begin
            Len := Resp[1] and $7F;
            if (Resp[1] and $80) <> 0 then
              ConnReadFull(C, Buf[0], 4);
            if (Len > 0) and (Len < 126) then
              ConnReadFull(C, Buf[0], Len);
            if (Resp[0] and $0F) = 8 then
            begin
              ConnWriteText(C, #$88#$00);
              Closed := True;
            end;
          end;
        end;
    end;
    SSL_shutdown(C.Ssl);
  finally
    SSL_free(C.Ssl);
  end;
end;

{ TTunnelProxy }

constructor TTunnelProxy.Create(const AMode: TTunnelMode;
  const AOriginPort: Word; const ARequireCert: Boolean;
  const AVersion: Integer);
begin
  FMode := AMode;
  FOriginPort := AOriginPort;
  FRequireCert := ARequireCert;
  FListenFd := ListenOnLoopback(FPort);
  if AMode = tmHttps then
  begin
    FCtx := SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate_file(FCtx,
      PUtf8Char(UTF8String(Fixture('server.crt'))), SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(FCtx,
      PUtf8Char(UTF8String(Fixture('server.key'))), SSL_FILETYPE_PEM);
    // ask for a certificate and trust the fixture CA, so one offered to the
    // proxy would be seen (and verified) rather than abort the handshake
    SSL_CTX_load_verify_locations(FCtx,
      PUtf8Char(UTF8String(Fixture('ca.crt'))), nil);
    if ARequireCert then
      SSL_CTX_set_verify(FCtx,
        SSL_VERIFY_PEER or SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nil)
    else
      SSL_CTX_set_verify(FCtx, SSL_VERIFY_PEER, nil);
    if AVersion <> 0 then
    begin
      SSL_CTX_set_min_proto_version(FCtx, AVersion);
      SSL_CTX_set_max_proto_version(FCtx, AVersion);
    end;
  end;
  inherited Create(False);
end;

destructor TTunnelProxy.Destroy;
begin
  if FCtx <> nil then
    SSL_CTX_free(FCtx);
  if FListenFd >= 0 then
    fpClose(FListenFd);
  inherited Destroy;
end;

procedure TTunnelProxy.Stop;
begin
  Terminate;
  WaitFor;
end;

procedure TTunnelProxy.Execute;
var
  Fd: Integer;
begin
  while not Terminated do
  begin
    if not WaitReadable(FListenFd, 50) then
      Continue;
    Fd := fpAccept(FListenFd, nil, nil);
    if Fd < 0 then
      Continue;
    SetTimeouts(Fd, 3000);
    try
      Handle(Fd);
    except
      // the client sees the tunnel break
    end;
    fpClose(Fd);
  end;
end;

procedure TTunnelProxy.Handle(const AFd: Integer);
var
  C: TConn;
  Origin: Integer;
  Addr: TSockAddr;
  Head: AnsiString;
  B: array[0..255] of Byte;
  Buf: array[0..16383] of Byte;
  N, I: Integer;
  Peer: PX509;
  Fds: array[0..1] of TPollFd;
  Ready: Boolean;
begin
  C.Fd := AFd;
  C.Ssl := nil;
  try
    if FMode = tmHttps then
    begin
      C.Ssl := SSL_new(FCtx);
      SSL_set_fd(C.Ssl, AFd);
      if SSL_accept(C.Ssl) <> 1 then
      begin
        InterlockedIncrement(Refused);
        // let the client read the alert before the close
        fpShutdown(AFd, SHUT_WR);
        SetTimeouts(AFd, 300);
        while fpRecv(AFd, @B[0], SizeOf(B), 0) > 0 do;
        Exit;
      end;
      Peer := SSL_get_peer_certificate(C.Ssl);
      if Peer <> nil then
      begin
        SawClientCert := True;
        LastSubject := string(Peer^.SubjectName);
        X509_free(Peer);
      end;
    end;
    if FMode = tmSocks5 then
    begin
      // greeting, then the CONNECT request: both consumed, target ignored
      if not ConnReadFull(C, B[0], 2) then
        Exit;
      if not ConnReadFull(C, B[2], B[1]) then
        Exit;
      B[0] := 5;
      B[1] := 0;
      ConnWrite(C, B[0], 2);
      if not ConnReadFull(C, B[0], 4) then
        Exit;
      case B[3] of
        1: N := 4;
        4: N := 16;
      else
        begin
          if not ConnReadFull(C, B[4], 1) then
            Exit;
          N := B[4];
        end;
      end;
      if not ConnReadFull(C, B[5], N + 2) then
        Exit;
    end
    else
    begin
      Head := ConnReadHead(C);
      if Pos('CONNECT ', Head) <> 1 then
        Exit;
    end;
    Origin := fpsocket(AF_INET, SOCK_STREAM, 0);
    FillChar(Addr, SizeOf(Addr), 0);
    Addr.sin_family := AF_INET;
    Addr.sin_port := htons(FOriginPort);
    Addr.sin_addr.s_addr := htonl($7F000001);
    if fpconnect(Origin, @Addr, SizeOf(Addr)) <> 0 then
    begin
      fpClose(Origin);
      Exit;
    end;
    SetTimeouts(Origin, 3000);
    try
      InterlockedIncrement(Tunnels);
      if FMode = tmSocks5 then
      begin
        FillChar(B, SizeOf(B), 0);
        B[0] := 5;
        B[3] := 1;
        ConnWrite(C, B[0], 10);
      end
      else
        ConnWriteText(C, 'HTTP/1.1 200 Connection established'#13#10#13#10);
      // pump both ways until either side ends
      Fds[0].fd := AFd;
      Fds[0].events := POLLIN;
      Fds[1].fd := Origin;
      Fds[1].events := POLLIN;
      repeat
        Ready := (C.Ssl <> nil) and (SSL_pending(C.Ssl) > 0);
        Fds[0].revents := 0;
        Fds[1].revents := 0;
        if Ready then
          Fds[0].revents := POLLIN
        else if fpPoll(@Fds[0], 2, 4000) <= 0 then
          Break;
        if Fds[0].revents <> 0 then
        begin
          N := ConnRead(C, Buf[0], SizeOf(Buf));
          if N <= 0 then
            Break;
          I := 0;
          while I < N do
          begin
            I := I + fpSend(Origin, @Buf[I], N - I, 0);
            if I < 0 then
              Break;
          end;
        end;
        if Fds[1].revents <> 0 then
        begin
          N := fpRecv(Origin, @Buf[0], SizeOf(Buf), 0);
          if N <= 0 then
            Break;
          ConnWrite(C, Buf[0], N);
        end;
      until False;
    finally
      fpClose(Origin);
    end;
  finally
    if C.Ssl <> nil then
    begin
      SSL_shutdown(C.Ssl);
      SSL_free(C.Ssl);
    end;
  end;
end;

{ TCountingSelector }

type
  /// reads the pool statistics from a second thread: the read waits for the
  /// pool lock, so it finishes only if the lock is free
  TStatsProbe = class(TThread)
  private
    FClient: THttpClient;
  protected
    procedure Execute; override;
  public
    constructor Create(const AClient: THttpClient);
  end;

constructor TStatsProbe.Create(const AClient: THttpClient);
begin
  FClient := AClient;
  inherited Create(False);
end;

procedure TStatsProbe.Execute;
begin
  FClient.PoolStats;
end;

function TCountingSelector.Select(const AHost: string;
  const APort: Word): IClientIdentity;
var
  Probe: TStatsProbe;
  Waited: Integer;
begin
  InterlockedIncrement(Calls);
  LastHost := AHost;
  LastPort := APort;
  LastThread := GetCurrentThreadId;
  if FProbe <> nil then
  begin
    Probe := TStatsProbe.Create(FProbe);
    Waited := 0;
    while (not Probe.Finished) and (Waited < 2000) do
    begin
      Sleep(5);
      Inc(Waited, 5);
    end;
    LockWasFree := Probe.Finished;
    Probe.WaitFor;
    Probe.Free;
  end;
  if DelayMs > 0 then
    Sleep(DelayMs);
  if Fail then
    raise Exception.Create('selector refused');
  if (ForPort <> 0) and (APort = ForPort) then
    Result := PortAnswer
  else
    Result := Answer;
end;

procedure TCountingSelector.ProbeLockWith(const AClient: IHttpClient);
begin
  FProbe := AClient as THttpClient;
end;

{ TFixedSelector }

constructor TFetchThread.Create(const AClient: IHttpClient;
  const AUrl: string);
begin
  FClient := AClient;
  FUrl := AUrl;
  inherited Create(False);
end;

procedure TFetchThread.Execute;
var
  Resp: IHttpResponse;
begin
  try
    Resp := FClient.Send(THttpRequest.Create(hmGet, FUrl));
    Status := Resp.StatusCode;
    ReadAllBodyBytes(Resp.Body);
  except
    Failed := True;
  end;
end;

function TPlainSocketFactory.Dial(const AHost: string; const APort: Word;
  const ATimeoutMs: Integer): IHttp2Socket;
begin
  InterlockedIncrement(Dials);
  raise EHttpConnectionError.Create('plain factory: no dialling in a test');
end;

constructor TFixedSelector.Create(const AKind: TProxyKind; const APort: Word);
begin
  inherited Create;
  FProxy := TProxy.Create(AKind, 'localhost', APort);
end;

function TFixedSelector.SelectProxy(const AUri: string): IProxy;
begin
  Result := FProxy;
end;

{ TWsRecorder }

constructor TWsRecorder.Create;
begin
  inherited Create;
  FEvent := TEvent.Create(nil, True, False, '');
end;

destructor TWsRecorder.Destroy;
begin
  FEvent.Free;
  inherited Destroy;
end;

procedure TWsRecorder.OnText(const ASocket: IWebSocket; const AText: string;
  const ALast: Boolean);
begin
  Text := AText;
  FEvent.SetEvent;
end;

function TWsRecorder.WaitText(const AMs: Integer): Boolean;
begin
  Result := FEvent.WaitFor(AMs) = wrSignaled;
end;

{ TMutualTlsTest }

procedure TMutualTlsTest.TearDown;
begin
  FProxyIdentity := nil;
  if FProxy <> nil then
  begin
    FProxy.Stop;
    FreeAndNil(FProxy);
  end;
  if FServer <> nil then
  begin
    FServer.Stop;
    FreeAndNil(FServer);
  end;
end;

function TMutualTlsTest.StartServer(const AKind: TMtlsKind;
  const AVersion: Integer; const AOptionalCert: Boolean): TMtlsServer;
begin
  if not OpenSslIsAvailable then
    Fail('OpenSSL is not available: set OPENSSL_LIBPATH');
  FServer := TMtlsServer.Create(AKind, AVersion, AOptionalCert);
  Result := FServer;
end;

function TMutualTlsTest.Url(const AScheme: string): string;
begin
  Result := Format('%s://localhost:%d/', [AScheme, FServer.Port]);
end;

function TMutualTlsTest.GoodIdentity: IClientIdentity;
begin
  Result := TClientIdentity.FromPemFiles(Fixture('client-chain.pem'),
    Fixture('client.key'));
end;

function TMutualTlsTest.NewClient(const AIdentity: IClientIdentity;
  const AFallback: Boolean): IHttpClient;
var
  F: THttpClientFactory;
begin
  F := THttpClientFactory.Create
    .WithCACertFile(Fixture('ca.crt'))
    .WithConnectTimeout(3000)
    .WithHeaderTimeout(5000);
  if AIdentity <> nil then
    F := F.WithClientIdentity(AIdentity);
  if AFallback then
    F := F.WithHttp1Fallback(True);
  Result := RouteVia(F).Build;
end;

/// loopback origins bypass the built-in selectors, so route through FProxy
/// explicitly when there is one
function TMutualTlsTest.RouteVia(
  const AFactory: THttpClientFactory): THttpClientFactory;
begin
  Result := AFactory;
  if FProxyIdentity <> nil then
    Result := Result.WithProxyClientIdentity(FProxyIdentity);
  if FProxy <> nil then
    case FProxy.FMode of
      tmConnect: Result := Result.WithProxySelector(
        TFixedSelector.Create(pkHttp, FProxy.Port));
      tmSocks5: Result := Result.WithProxySelector(
        TFixedSelector.Create(pkSocks5, FProxy.Port));
      tmHttps: Result := Result.WithProxySelector(
        TFixedSelector.Create(pkHttps, FProxy.Port));
    end;
end;

function TMutualTlsTest.Fetch(const AClient: IHttpClient;
  out ABody: string): Integer;
var
  Resp: IHttpResponse;
  Raw: TBytes;
begin
  Resp := AClient.Send(THttpRequest.Create(hmGet, Url));
  Result := Resp.StatusCode;
  Raw := ReadAllBodyBytes(Resp.Body);
  SetString(ABody, PAnsiChar(@Raw[0]), Length(Raw));
end;

function TMutualTlsTest.AlertOfFetch(const AClient: IHttpClient): string;
var
  Body: string;
begin
  Result := '';
  try
    Fetch(AClient, Body);
    Fail('the request must be rejected');
  except
    on E: EHttpTlsClientAuthError do
      Result := E.Alert;
  end;
end;

procedure TMutualTlsTest.RunAccepts(const AKind: TMtlsKind;
  const AVersion: Integer; const AFallback: Boolean);
var
  Client: IHttpClient;
  Body: string;
begin
  StartServer(AKind, AVersion);
  Client := NewClient(GoodIdentity, AFallback);
  AssertEquals('status', 200, Fetch(Client, Body));
  AssertEquals('body', 'ok', Body);
  Client.Close;
  FServer.Stop;
  AssertEquals('one handshake completed', 1, FServer.Handshakes);
  AssertEquals('one request', 1, FServer.Requests);
  AssertTrue('the server saw the client certificate',
    Pos('mtls client', FServer.LastSubject) > 0);
end;

procedure TMutualTlsTest.RunSse(const AVersion: Integer);
var
  Client: IHttpClient;
  Source: TSseSource;
  Event: TSseEvent;
begin
  StartServer(mkSse, AVersion);
  Client := NewClient(GoodIdentity, True);
  Source := TSseSource.Create(Client.Send(SseRequest(Url)));
  try
    AssertTrue('an event arrived', Source.ReadEvent(Event));
    AssertEquals('data', 'hello', Event.Data);
  finally
    Source.Close;
  end;
  Client.Close;
  FServer.Stop;
  AssertEquals('one handshake completed', 1, FServer.Handshakes);
  AssertTrue('the server saw the client certificate',
    Pos('mtls client', FServer.LastSubject) > 0);
end;

procedure TMutualTlsTest.RunWebSocket(const AVersion: Integer);
var
  Client: IHttpClient;
  Rec: TWsRecorder;
  RecRef: IWebSocketListener;
  Sock: IWebSocket;
begin
  StartServer(mkWebSocket, AVersion);
  Client := NewClient(GoodIdentity);
  Rec := TWsRecorder.Create;
  RecRef := Rec;
  Sock := Client.Send(TWebSocketRequest.Create(
    Format('wss://localhost:%d/chat', [FServer.Port]), RecRef).WithAutoRequest);
  AssertTrue('the server sent a message', Rec.WaitText(4000));
  AssertEquals('text', 'hello', Rec.Text);
  Sock.Close;
  Sleep(50);
  Client.Close;
  FServer.Stop;
  AssertEquals('one handshake completed', 1, FServer.Handshakes);
  AssertTrue('the server saw the client certificate',
    Pos('mtls client', FServer.LastSubject) > 0);
end;

procedure TMutualTlsTest.RunNoIdentity(const AKind: TMtlsKind;
  const AVersion: Integer; const AFallback: Boolean; const AExpected: string);
var
  Client: IHttpClient;
  Alert: string;
begin
  StartServer(AKind, AVersion);
  Client := NewClient(nil, AFallback);
  Alert := AlertOfFetch(Client);
  Client.Close;
  FServer.Stop;
  AssertEquals('the alert', AExpected, Alert);
  AssertEquals('one connection: no retry, no fallback dial', 1,
    FServer.Connections);
  AssertEquals('the handshake never completed', 0, FServer.Handshakes);
end;

procedure TMutualTlsTest.RunWrongCa(const AVersion: Integer);
var
  Client: IHttpClient;
  Alert: string;
begin
  StartServer(mkH2, AVersion);
  Client := NewClient(TClientIdentity.FromPemFiles(Fixture('other-client.crt'),
    Fixture('other-client.key')));
  Alert := AlertOfFetch(Client);
  Client.Close;
  FServer.Stop;
  AssertEquals('the alert', 'unknown ca', Alert);
  AssertEquals('one connection', 1, FServer.Connections);
end;

/// dial straight through TTlsSocket (Build refuses an expired identity) and
/// report the alert, whether it surfaces in the handshake or on the first read
function TMutualTlsTest.ProbeAlert(const AVersion: Integer;
  const AIdentity: IClientIdentity; const AKind: TMtlsKind): string;
var
  Sock: IHttp2Socket;
  B: array[0..8] of Byte;
begin
  Result := '';
  try
    Sock := TTlsSocket.DialWithAlpn('localhost', FServer.Port,
      AlpnProtocolList([cHttp2AlpnProtocol, cHttp11AlpnProtocol]), False, 3000,
      Fixture('ca.crt'), '', 0, AIdentity);
    B[0] := 0;
    Sock.Write(B[0], 1);
    Sock.Read(B[0], 9);
    Fail('the server must reject the certificate');
  except
    on E: EHttpTlsClientAuthError do
      Result := E.Alert;
  end;
end;

procedure TMutualTlsTest.RunExpiredOnTheWire(const AVersion: Integer;
  const AExpected: string);
var
  Alert: string;
begin
  StartServer(mkH2, AVersion);
  Alert := ProbeAlert(AVersion, TClientIdentity.FromPemFiles(
    Fixture('expired.crt'), Fixture('expired.key')), mkH2);
  FServer.Stop;
  AssertEquals('the alert', AExpected, Alert);
end;

/// the origin identity reaches the origin through every kind of proxy; an
/// https proxy sees only the proxy identity on its own leg
procedure TMutualTlsTest.RunTunnel(const AMode: TTunnelMode;
  const AVersion: Integer);
var
  Client: IHttpClient;
  Body: string;
begin
  StartServer(mkH2, AVersion);
  FProxy := TTunnelProxy.Create(AMode, FServer.Port, AMode = tmHttps,
    AVersion);
  if AMode = tmHttps then
    FProxyIdentity := Client2Identity;
  Client := NewClient(GoodIdentity);
  AssertEquals('status', 200, Fetch(Client, Body));
  AssertEquals('body', 'ok', Body);
  Client.Close;
  FProxy.Stop;
  FServer.Stop;
  AssertEquals('one tunnel', 1, FProxy.Tunnels);
  AssertEquals('one origin handshake', 1, FServer.Handshakes);
  AssertTrue('the origin saw the origin identity',
    SubjectIs(FServer.LastSubject, 'mtls client'));
  AssertFalse('the origin never sees the proxy identity',
    SubjectIs(FServer.LastSubject, 'mtls client two'));
  if AMode = tmHttps then
  begin
    AssertTrue('the https proxy saw a certificate', FProxy.SawClientCert);
    AssertTrue('the proxy saw the proxy identity',
      SubjectIs(FProxy.LastSubject, 'mtls client two'));
    AssertFalse('the proxy never sees the origin identity',
      SubjectIs(FProxy.LastSubject, 'mtls client'));
  end
  else
    AssertFalse('there is no TLS to this proxy to present one on',
      FProxy.SawClientCert);
end;

function TMutualTlsTest.ServerUrl(const AServer: TMtlsServer): string;
begin
  Result := Format('https://localhost:%d/', [AServer.Port]);
end;

function TMutualTlsTest.SendTo(const AClient: IHttpClient;
  const AUrl: string): IHttpResponse;
begin
  Result := AClient.Send(THttpRequest.Create(hmGet, AUrl));
end;

function TMutualTlsTest.ReadBody(const AResponse: IHttpResponse): string;
var
  Raw: TBytes;
begin
  Raw := ReadAllBodyBytes(AResponse.Body);
  Result := '';
  if Length(Raw) > 0 then
    SetString(Result, PAnsiChar(@Raw[0]), Length(Raw));
end;

function TMutualTlsTest.Client2Identity: IClientIdentity;
begin
  Result := TClientIdentity.FromPemFiles(Fixture('client2-chain.pem'),
    Fixture('client2.key'));
end;

/// the subject's common name is exactly AName ('mtls client' is not a match
/// for 'mtls client two')
function TMutualTlsTest.SubjectIs(const ASubject, AName: string): Boolean;
var
  P, After: Integer;
begin
  P := Pos('CN=' + AName, ASubject);
  After := P + Length('CN=' + AName);
  Result := (P > 0) and ((After > Length(ASubject)) or
    (ASubject[After] in [',', '/']));
end;

/// a client whose identity comes only from ASelector; HTTP/1.1 is allowed so
/// one connection serves one request and the next request dials again
function TMutualTlsTest.SelectorClient(
  const ASelector: IClientIdentitySelector): IHttpClient;
begin
  Result := RouteVia(THttpClientFactory.Create
    .WithCACertFile(Fixture('ca.crt'))
    .WithConnectTimeout(3000)
    .WithHeaderTimeout(5000)
    .WithHttp1Fallback(True)
    .WithClientIdentitySelector(ASelector))
    .Build;
end;

function TMutualTlsTest.KeysOf(const AClient: IHttpClient): string;
var
  Stats: TPoolStats;
  I: Integer;
begin
  Stats := (AClient as THttpClient).PoolStats;
  Result := '';
  for I := 0 to High(Stats.PerOrigin) do
    Result := Result + Stats.PerOrigin[I].Origin + '|';
end;

function TMutualTlsTest.CountOf(const ASub, AText: string): Integer;
var
  P: Integer;
  Rest: string;
begin
  Result := 0;
  Rest := AText;
  repeat
    P := Pos(ASub, Rest);
    if P = 0 then
      Break;
    Inc(Result);
    Rest := Copy(Rest, P + Length(ASub), MaxInt);
  until False;
end;

/// the selector is asked with the origin's host and port on every route, the
/// origin sees its answer, and an https proxy sees the proxy identity only;
/// the key carries the origin identity fingerprint
procedure TMutualTlsTest.RunSelectorVia(const AMode: TTunnelMode);
var
  Sel: TCountingSelector;
  SelRef: IClientIdentitySelector;
  Client: IHttpClient;
  Keys: string;
begin
  StartServer(mkH2, cTls13);
  FProxy := TTunnelProxy.Create(AMode, FServer.Port, AMode = tmHttps);
  if AMode = tmHttps then
    FProxyIdentity := GoodIdentity;
  Sel := TCountingSelector.Create;
  SelRef := Sel;
  Sel.Answer := Client2Identity;
  Client := SelectorClient(SelRef);
  AssertEquals('status', 200, SendTo(Client, Url).StatusCode);
  AssertEquals('pooled', 200, SendTo(Client, Url).StatusCode);
  Keys := KeysOf(Client);
  Client.Close;
  FProxy.Stop;
  FServer.Stop;
  AssertEquals('one dial, one call', 1, Sel.Calls);
  AssertEquals('asked for the origin host', 'localhost', Sel.LastHost);
  AssertEquals('asked for the origin port', FServer.Port, Sel.LastPort);
  AssertTrue('the origin saw the selector identity',
    SubjectIs(FServer.LastSubject, 'mtls client two'));
  AssertTrue('the key carries the origin identity fingerprint',
    Pos(Client2Identity.Fingerprint, Keys) > 0);
  if AMode = tmHttps then
  begin
    AssertTrue('the proxy saw the proxy identity only',
      SubjectIs(FProxy.LastSubject, 'mtls client'));
    AssertFalse('the proxy never sees the selector identity',
      SubjectIs(FProxy.LastSubject, 'mtls client two'));
  end
  else
    AssertFalse('no TLS to the proxy', FProxy.SawClientCert);
  AssertEquals('one tunnel, one pooled connection', 1, FProxy.Tunnels);
end;

{ accepted identity }

procedure TMutualTlsTest.TestHttp2WithTheIdentityTls12;
begin
  RunAccepts(mkH2, cTls12, False);
end;

procedure TMutualTlsTest.TestHttp2WithTheIdentityTls13;
begin
  RunAccepts(mkH2, cTls13, False);
end;

procedure TMutualTlsTest.TestHttp11FallbackWithTheIdentityTls12;
begin
  RunAccepts(mkHttp1, cTls12, True);
end;

procedure TMutualTlsTest.TestHttp11FallbackWithTheIdentityTls13;
begin
  RunAccepts(mkHttp1, cTls13, True);
end;

procedure TMutualTlsTest.TestSseWithTheIdentityTls12;
begin
  RunSse(cTls12);
end;

procedure TMutualTlsTest.TestSseWithTheIdentityTls13;
begin
  RunSse(cTls13);
end;

procedure TMutualTlsTest.TestWssWithTheIdentityTls12;
begin
  RunWebSocket(cTls12);
end;

procedure TMutualTlsTest.TestWssWithTheIdentityTls13;
begin
  RunWebSocket(cTls13);
end;

procedure TMutualTlsTest.TestPkcs12IdentityIsAccepted;
var
  Client: IHttpClient;
  Body: string;
begin
  StartServer(mkH2, cTls13);
  Client := NewClient(TClientIdentity.FromPkcs12File(Fixture('client-chain.p12'),
    cPass));
  AssertEquals('status', 200, Fetch(Client, Body));
  Client.Close;
  FServer.Stop;
  AssertEquals('handshake', 1, FServer.Handshakes);
end;

{ rejection }

procedure TMutualTlsTest.TestNoIdentityIsRejectedOnceTls12;
begin
  RunNoIdentity(mkH2, cTls12, False, 'handshake failure');
end;

procedure TMutualTlsTest.TestNoIdentityIsRejectedOnceTls13;
begin
  RunNoIdentity(mkH2, cTls13, False, 'certificate required');
end;

procedure TMutualTlsTest.TestNoIdentityOverHttp11IsRejectedTls13;
begin
  RunNoIdentity(mkHttp1, cTls13, True, 'certificate required');
end;

procedure TMutualTlsTest.TestNoIdentityWithFallbackOnDoesNotFallBackTls13;
begin
  // fallback is on, the server is HTTP/2: the rejection is final
  RunNoIdentity(mkH2, cTls13, True, 'certificate required');
end;

procedure TMutualTlsTest.TestNoIdentityOnWssIsRejectedTls13;
var
  Client: IHttpClient;
  Rec: TWsRecorder;
  RecRef: IWebSocketListener;
  Alert: string;
begin
  StartServer(mkWebSocket, cTls13);
  Client := NewClient(nil);
  Rec := TWsRecorder.Create;
  RecRef := Rec;
  Alert := '';
  try
    Client.Send(TWebSocketRequest.Create(
      Format('wss://localhost:%d/chat', [FServer.Port]), RecRef));
    Fail('the upgrade must be rejected');
  except
    on E: EHttpTlsClientAuthError do
      Alert := E.Alert;
  end;
  Client.Close;
  FServer.Stop;
  AssertEquals('certificate required', Alert);
  AssertEquals('one connection', 1, FServer.Connections);
end;

procedure TMutualTlsTest.TestWrongCaIsRejectedTls12;
begin
  RunWrongCa(cTls12);
end;

procedure TMutualTlsTest.TestWrongCaIsRejectedTls13;
begin
  RunWrongCa(cTls13);
end;

procedure TMutualTlsTest.TestExpiredIsRejectedOnTheWireTls12;
begin
  RunExpiredOnTheWire(cTls12, 'certificate expired');
end;

procedure TMutualTlsTest.TestExpiredIsRejectedOnTheWireTls13;
begin
  RunExpiredOnTheWire(cTls13, 'certificate expired');
end;

procedure TMutualTlsTest.TestRejectionIsNotRetried;
var
  Client: IHttpClient;
  Alert1, Alert2: string;
begin
  // an idempotent GET is the retry candidate; the client must not repeat it
  StartServer(mkH2, cTls13);
  Client := NewClient(nil);
  Alert1 := AlertOfFetch(Client);
  AssertEquals('first attempt', 'certificate required', Alert1);
  AssertEquals('exactly one connection for one request', 1, FServer.Connections);
  Alert2 := AlertOfFetch(Client);
  Client.Close;
  FServer.Stop;
  AssertEquals('second request', 'certificate required', Alert2);
  AssertEquals('one more connection for the second request', 2,
    FServer.Connections);
end;

{ routed dials }

procedure TMutualTlsTest.TestConnectTunnelOriginSeesTheOriginIdentityTls13;
begin
  RunTunnel(tmConnect, cTls13);
end;

procedure TMutualTlsTest.TestSocks5TunnelOriginSeesTheOriginIdentityTls13;
begin
  RunTunnel(tmSocks5, cTls13);
end;

procedure TMutualTlsTest.TestHttpsProxySeesOnlyTheProxyIdentityTls13;
begin
  RunTunnel(tmHttps, cTls13);
end;

procedure TMutualTlsTest.TestHttpsProxySeesOnlyTheProxyIdentityTls12;
begin
  RunTunnel(tmHttps, cTls12);
end;

procedure TMutualTlsTest.TestSelectorIsAskedForTheOriginThroughAnHttpsProxy;
begin
  RunSelectorVia(tmHttps);
end;

procedure TMutualTlsTest.TestSelectorIsAskedForTheOriginThroughAConnectProxy;
begin
  RunSelectorVia(tmConnect);
end;

procedure TMutualTlsTest.TestSelectorIsAskedForTheOriginThroughASocks5Proxy;
begin
  RunSelectorVia(tmSocks5);
end;

/// a wss dial follows the same rules as a request: the origin identity (fixed,
/// selected or per request) goes to the origin, the proxy identity to an https
/// proxy only
procedure TMutualTlsTest.RunWssVia(const AMode: TTunnelMode;
  const AWho: TIdentitySource; const AViaProxy: Boolean);
var
  Sel: TCountingSelector;
  SelRef: IClientIdentitySelector;
  Client: IHttpClient;
  Rec: TWsRecorder;
  RecRef: IWebSocketListener;
  Sock: IWebSocket;
  Req: IWebSocketRequest;
begin
  StartServer(mkWebSocket, cTls13);
  if AViaProxy then
  begin
    FProxy := TTunnelProxy.Create(AMode, FServer.Port, AMode = tmHttps);
    if AMode = tmHttps then
      FProxyIdentity := GoodIdentity;
  end;
  Sel := TCountingSelector.Create;
  SelRef := Sel;
  Sel.Answer := Client2Identity;
  case AWho of
    isSelector: Client := SelectorClient(SelRef);
    isRequest: Client := NewClient(nil);
  else
    Client := NewClient(Client2Identity);
  end;
  Rec := TWsRecorder.Create;
  RecRef := Rec;
  Req := TWebSocketRequest.Create(
    Format('wss://localhost:%d/chat', [FServer.Port]), RecRef).WithAutoRequest;
  if AWho = isRequest then
    Req := Req.WithClientIdentity(Client2Identity);
  Sock := Client.Send(Req);
  AssertTrue('the server sent a message', Rec.WaitText(4000));
  Sock.Close;
  Sleep(50);
  Client.Close;
  if FProxy <> nil then
    FProxy.Stop;
  FServer.Stop;
  AssertTrue('the origin saw the origin identity',
    SubjectIs(FServer.LastSubject, 'mtls client two'));
  if AWho = isSelector then
  begin
    AssertEquals('one selector call', 1, Sel.Calls);
    AssertEquals('asked for the origin port', FServer.Port, Sel.LastPort);
  end
  else
    AssertEquals('no selector call', 0, Sel.Calls);
  if AViaProxy and (AMode = tmHttps) then
  begin
    AssertTrue('the proxy saw the proxy identity only',
      SubjectIs(FProxy.LastSubject, 'mtls client'));
    AssertFalse('the proxy never sees the origin identity',
      SubjectIs(FProxy.LastSubject, 'mtls client two'));
  end
  else if AViaProxy then
    AssertFalse('no TLS to the proxy', FProxy.SawClientCert);
end;

procedure TMutualTlsTest.TestWssThroughAnHttpsProxySplitsTheIdentities;
begin
  RunWssVia(tmHttps, isFixed, True);
end;

procedure TMutualTlsTest.TestWssThroughAConnectProxyPresentsTheOriginIdentity;
begin
  RunWssVia(tmConnect, isFixed, True);
end;

procedure TMutualTlsTest.TestWssSelectorThroughAnHttpsProxyAsksForTheOrigin;
begin
  RunWssVia(tmHttps, isSelector, True);
end;

{ dial helpers }

procedure TMutualTlsTest.TestEveryDialHelperPresentsTheIdentity;
var
  Id: IClientIdentity;
  Sock: IHttp2Socket;
  Offer: TBytes;
  Before: Integer;

  procedure Check(const AWhat: string);
  begin
    Sock.Close;
    Sock := nil;
    // the server handshake counter moves once the client has finished
    Sleep(50);
    Inc(Before);
    AssertEquals(AWhat + ': the server accepted the identity', Before,
      FServer.Handshakes);
  end;

begin
  StartServer(mkH2, cTls13);
  Id := GoodIdentity;
  Offer := AlpnOfferFor(False);
  Before := 0;
  Sock := TTlsSocket.Dial('localhost', FServer.Port, False, 3000,
    Fixture('ca.crt'), '', 0, Id);
  Check('Dial');
  Sock := TTlsSocket.DialWithAlpn('localhost', FServer.Port, Offer, False, 3000,
    Fixture('ca.crt'), '', 0, Id);
  Check('DialWithAlpn');
  Sock := TTlsSocket.DialVia('localhost', FServer.Port, False, 3000,
    Fixture('ca.crt'), nil, Id);
  Check('DialVia');
  Sock := TTlsSocket.DialWithAlpnVia('localhost', FServer.Port, Offer, False,
    3000, Fixture('ca.crt'), nil, Id);
  Check('DialWithAlpnVia');
  Sock := TProtocolSocketFactory.Create(Fixture('ca.crt'), False, '', 0, Id)
    .DialHttp1('localhost', FServer.Port, 'https', 3000, nil);
  Check('TProtocolSocketFactory.DialHttp1');
end;

/// enumeration check: every TTlsSocket construction is handed an identity
/// parameter (the dial helpers decide which leg may present it)
procedure TMutualTlsTest.TestEveryTlsSocketConstructionCarriesTheIdentity;
var
  Names: array[0..1] of string;
  Calls: array[0..3] of string;
  I, J, P, Q, E, Seen: Integer;
  Text, Stmt, Path: string;
  L: TStringList;
begin
  Names[0] := 'src/Http2.Tls.pas';
  Names[1] := 'src/Http2.Client.pas';
  Calls[0] := 'TTlsSocket.Create(';
  Calls[1] := 'TTlsSocket.Dial(';
  Calls[2] := 'TTlsSocket.DialWithAlpnVia(';
  Calls[3] := 'TTlsSocket.DialWithAlpn(';
  Seen := 0;
  for I := 0 to High(Names) do
  begin
    Path := ExtractFilePath(ParamStr(0)) + '../' + Names[I];
    if not FileExists(Path) then
      Path := Names[I];
    if not FileExists(Path) then
    begin
      Fail('cannot find ' + Names[I] + ' from ' + GetCurrentDir);
    end;
    L := TStringList.Create;
    try
      L.LoadFromFile(Path);
      Text := L.Text;
    finally
      L.Free;
    end;
    for J := 0 to High(Calls) do
    begin
      P := 1;
      while True do
      begin
        Q := Pos(Calls[J], Copy(Text, P, MaxInt));
        if Q = 0 then
          Break;
        P := P + Q - 1;
        E := Pos(';', Copy(Text, P, MaxInt)) + P - 1;
        Stmt := Copy(Text, P, E - P);
        // a declaration or a method heading, not a call
        if Pos('const ', Stmt) = 0 then
          Inc(Seen);
        if Pos('const ', Stmt) = 0 then
          AssertTrue(Names[I] + ': ' + Calls[J] + ' passes the identity: ' +
            Stmt, Pos('Identity', Stmt) > 0);
        P := E;
      end;
    end;
  end;
  AssertTrue('the scan found the dial sites (' + IntToStr(Seen) + ')', Seen >= 9);
end;

{ selector }

procedure TMutualTlsTest.TestFixedIdentitySelectorAnswersTheIdentity;
var
  Id: IClientIdentity;
  Sel: IClientIdentitySelector;
  Client: IHttpClient;
  Body: string;
begin
  Id := GoodIdentity;
  Sel := FixedIdentitySelector(Id);
  AssertTrue('the helper answers the identity it wraps',
    Sel.Select('a.example', 443) = Id);
  AssertTrue('and the same one for any origin', Sel.Select('b.example', 8443) = Id);
  AssertTrue('a nil identity gives a nil answer',
    FixedIdentitySelector(nil).Select('a.example', 443) = nil);
  // and it behaves as the fixed identity on the wire
  StartServer(mkH2, cTls13);
  Client := SelectorClient(Sel);
  AssertEquals('status', 200, Fetch(Client, Body));
  Client.Close;
  FServer.Stop;
  AssertTrue('the server saw the client certificate',
    SubjectIs(FServer.LastSubject, 'mtls client'));
end;

procedure TMutualTlsTest.TestSelectorIsCalledOncePerDialNotPerRequest;
var
  Sel: TCountingSelector;
  SelRef: IClientIdentitySelector;
  Client: IHttpClient;
  Body: string;
  I: Integer;
begin
  StartServer(mkH2, cTls13);
  Sel := TCountingSelector.Create;
  SelRef := Sel;
  Sel.Answer := GoodIdentity;
  Client := SelectorClient(SelRef);
  for I := 1 to 3 do
    AssertEquals('status', 200, Fetch(Client, Body));
  Client.Close;
  FServer.Stop;
  AssertEquals('three requests', 3, FServer.Requests);
  AssertEquals('one connection', 1, FServer.Connections);
  AssertEquals('one selector call for the one dial', 1, Sel.Calls);
  AssertEquals('asked for the origin host', 'localhost', Sel.LastHost);
  AssertEquals('asked for the origin port', FServer.Port, Sel.LastPort);
end;

procedure TMutualTlsTest.TestSelectorRunsOnTheDiallingThreadOutsideThePoolLock;
var
  Sel: TCountingSelector;
  SelRef: IClientIdentitySelector;
  Client: IHttpClient;
  Body: string;
begin
  StartServer(mkH2, cTls13);
  Sel := TCountingSelector.Create;
  SelRef := Sel;
  Sel.Answer := GoodIdentity;
  Client := SelectorClient(SelRef);
  Sel.ProbeLockWith(Client);
  AssertEquals('status', 200, Fetch(Client, Body));
  Client.Close;
  FServer.Stop;
  AssertEquals('one call', 1, Sel.Calls);
  AssertTrue('on the thread that sent the request',
    Sel.LastThread = GetCurrentThreadId);
  AssertTrue('another thread could take the pool lock meanwhile',
    Sel.LockWasFree);
end;

procedure TMutualTlsTest.TestSelectorChoosesTheIdentityPerOrigin;
var
  Other: TMtlsServer;
  Sel: TCountingSelector;
  SelRef: IClientIdentitySelector;
  Client: IHttpClient;
begin
  StartServer(mkH2, cTls13);
  Other := TMtlsServer.Create(mkH2, cTls13);
  try
    Sel := TCountingSelector.Create;
    SelRef := Sel;
    Sel.Answer := GoodIdentity;
    Sel.ForPort := Other.Port;
    Sel.PortAnswer := Client2Identity;
    Client := SelectorClient(SelRef);
    AssertEquals('first origin', 200, SendTo(Client, ServerUrl(FServer)).StatusCode);
    AssertEquals('second origin', 200, SendTo(Client, ServerUrl(Other)).StatusCode);
    AssertEquals('first again, pooled', 200,
      SendTo(Client, ServerUrl(FServer)).StatusCode);
    Client.Close;
    FServer.Stop;
    Other.Stop;
    AssertEquals('two dials, two selector calls', 2, Sel.Calls);
    AssertTrue('first origin saw the first identity',
      SubjectIs(FServer.LastSubject, 'mtls client'));
    AssertTrue('second origin saw the second identity',
      SubjectIs(Other.LastSubject, 'mtls client two'));
    AssertEquals('first origin: one handshake', 1, FServer.Handshakes);
    AssertEquals('second origin: one handshake', 1, Other.Handshakes);
  finally
    Other.Stop;
    Other.Free;
  end;
end;

procedure TMutualTlsTest.TestNilAnswerPresentsNoCertificate;
var
  Sel: TCountingSelector;
  SelRef: IClientIdentitySelector;
  Client: IHttpClient;
begin
  StartServer(mkH2, cTls13);
  Sel := TCountingSelector.Create;
  SelRef := Sel;
  Client := SelectorClient(SelRef);
  AssertEquals('the server asks for a certificate and gets none',
    'certificate required', AlertOfFetch(Client));
  Client.Close;
  FServer.Stop;
  AssertEquals('one selector call', 1, Sel.Calls);
  AssertEquals('no handshake completed', 0, FServer.Handshakes);
end;

procedure TMutualTlsTest.TestThrowingSelectorFailsTheDial;
var
  Sel: TCountingSelector;
  SelRef: IClientIdentitySelector;
  Client: IHttpClient;
  Body, Msg: string;
begin
  StartServer(mkH2, cTls13);
  Sel := TCountingSelector.Create;
  SelRef := Sel;
  Sel.Fail := True;
  Client := SelectorClient(SelRef);
  Msg := '';
  try
    Fetch(Client, Body);
    Fail('the dial must fail');
  except
    on E: EHttpTlsConfigError do
      Msg := E.Message;
  end;
  AssertTrue('the selector message is carried: ' + Msg,
    Pos('selector refused', Msg) > 0);
  AssertEquals('the failed dial opened no connection', 0, FServer.Connections);
  // the next request asks again and, once the selector recovers, succeeds
  Sel.Fail := False;
  Sel.Answer := GoodIdentity;
  AssertEquals('status', 200, Fetch(Client, Body));
  Client.Close;
  FServer.Stop;
  AssertEquals('two calls', 2, Sel.Calls);
  AssertEquals('one connection in all', 1, FServer.Connections);
end;

procedure TMutualTlsTest.TestRotationOpensANewConnectionAndTheOldOneStillAnswers;
var
  Sel: TCountingSelector;
  SelRef: IClientIdentitySelector;
  Client: IHttpClient;
  Old, Fresh: IHttpResponse;
  Stats: TPoolStats;
  FpOld, FpNew: string;
begin
  StartServer(mkHttp1, cTls13);
  Sel := TCountingSelector.Create;
  SelRef := Sel;
  Sel.Answer := GoodIdentity;
  FpOld := Sel.Answer.Fingerprint;
  Client := SelectorClient(SelRef);
  // the first response is held open, so its connection stays in use
  Old := SendTo(Client, Url);
  AssertEquals('first status', 200, Old.StatusCode);
  AssertTrue('the first connection presented the first identity',
    SubjectIs(FServer.LastSubject, 'mtls client'));
  // rotate: the next dial presents the new identity
  Sel.Answer := Client2Identity;
  FpNew := Sel.Answer.Fingerprint;
  Fresh := SendTo(Client, Url);
  AssertEquals('second status', 200, Fresh.StatusCode);
  AssertEquals('two selector calls: one per dial', 2, Sel.Calls);
  AssertTrue('the new connection presented the new identity',
    SubjectIs(FServer.LastSubject, 'mtls client two'));
  // the pool keeps the identities apart
  Stats := (Client as THttpClient).PoolStats;
  AssertEquals('two pool keys', 2, Length(Stats.PerOrigin));
  AssertTrue('keys carry the fingerprints',
    ((Pos(FpOld, Stats.PerOrigin[0].Origin) > 0) and
     (Pos(FpNew, Stats.PerOrigin[1].Origin) > 0)) or
    ((Pos(FpNew, Stats.PerOrigin[0].Origin) > 0) and
     (Pos(FpOld, Stats.PerOrigin[1].Origin) > 0)));
  // the connection of the replaced certificate still delivers its response
  AssertEquals('old connection still answers', 'ok', ReadBody(Old));
  AssertEquals('new connection answers', 'ok', ReadBody(Fresh));
  Client.Close;
  FServer.Stop;
  AssertEquals('two handshakes', 2, FServer.Handshakes);
end;

procedure TMutualTlsTest.TestNilAnswerNeverSharesAConnectionWithAnIdentity;
var
  Sel: TCountingSelector;
  SelRef: IClientIdentitySelector;
  Client: IHttpClient;
  Old: IHttpResponse;
begin
  StartServer(mkHttp1, cTls13);
  Sel := TCountingSelector.Create;
  SelRef := Sel;
  Sel.Answer := GoodIdentity;
  Client := SelectorClient(SelRef);
  Old := SendTo(Client, Url);
  AssertEquals('first status', 200, Old.StatusCode);
  // the selector now answers nil; the open connection holds an identity, so
  // it must not be used for a request that is to present none
  Sel.Answer := nil;
  AssertEquals('the new dial presented no certificate',
    'certificate required', AlertOfFetch(Client));
  AssertEquals('two selector calls', 2, Sel.Calls);
  AssertEquals('old connection still answers', 'ok', ReadBody(Old));
  Client.Close;
  FServer.Stop;
  AssertEquals('one handshake completed', 1, FServer.Handshakes);
end;

procedure TMutualTlsTest.TestSelectorAppliesToWss;
var
  Sel: TCountingSelector;
  SelRef: IClientIdentitySelector;
  Client: IHttpClient;
  Rec: TWsRecorder;
  RecRef: IWebSocketListener;
  Sock: IWebSocket;
begin
  StartServer(mkWebSocket, cTls13);
  Sel := TCountingSelector.Create;
  SelRef := Sel;
  Sel.Answer := Client2Identity;
  Client := SelectorClient(SelRef);
  Rec := TWsRecorder.Create;
  RecRef := Rec;
  Sock := Client.Send(TWebSocketRequest.Create(
    Format('wss://localhost:%d/chat', [FServer.Port]), RecRef).WithAutoRequest);
  AssertTrue('the server sent a message', Rec.WaitText(4000));
  Sock.Close;
  Sleep(50);
  Client.Close;
  FServer.Stop;
  AssertEquals('one selector call', 1, Sel.Calls);
  AssertEquals('asked for the wss origin', FServer.Port, Sel.LastPort);
  AssertTrue('the server saw the selector identity',
    SubjectIs(FServer.LastSubject, 'mtls client two'));
end;

procedure TMutualTlsTest.TestSelectorIsNotCalledForCleartext;
var
  Sel: TCountingSelector;
  SelRef: IClientIdentitySelector;
  Client: IHttpClient;
begin
  StartServer(mkPlain, 0);
  Sel := TCountingSelector.Create;
  SelRef := Sel;
  Sel.Answer := GoodIdentity;
  Client := THttpClientFactory.Create
    .WithClientIdentitySelector(SelRef)
    .WithClearText(ctHttp1)
    .WithConnectTimeout(3000)
    .WithHeaderTimeout(5000)
    .Build;
  AssertEquals('status', 200,
    SendTo(Client, Format('http://localhost:%d/', [FServer.Port])).StatusCode);
  Client.Close;
  FServer.Stop;
  AssertEquals('no handshake, so no question', 0, Sel.Calls);
end;

procedure TMutualTlsTest.TestSelectorAndFixedIdentityReplaceEachOther;
var
  Id: IClientIdentity;
  Sel: IClientIdentitySelector;
  F: THttpClientFactory;
begin
  Id := GoodIdentity;
  Sel := FixedIdentitySelector(Id);
  F := THttpClientFactory.Create.WithClientIdentity(Id)
    .WithClientIdentitySelector(Sel);
  AssertTrue('the selector is installed', F.ClientIdentitySelector = Sel);
  AssertTrue('the fixed identity is gone', F.ClientIdentity = nil);
  F := F.WithClientIdentity(Id);
  AssertTrue('the fixed identity is back', F.ClientIdentity = Id);
  AssertTrue('the selector is gone', F.ClientIdentitySelector = nil);
  F := F.WithClientIdentitySelector(Sel).WithClientIdentitySelector(nil);
  AssertTrue('nil removes the selector', F.ClientIdentitySelector = nil);
end;

/// the proxy asks for a certificate and the client has only an origin identity
procedure TMutualTlsTest.TestOriginIdentityAloneIsRefusedByAnHttpsProxyThatAsksForOne;
var
  Client: IHttpClient;
  Body: string;
  Failed: Boolean;
begin
  StartServer(mkH2, cTls13);
  FProxy := TTunnelProxy.Create(tmHttps, FServer.Port, True);
  Client := NewClient(GoodIdentity);
  Failed := False;
  try
    Fetch(Client, Body);
  except
    on E: EHttpConnectionError do
      Failed := True;
  end;
  AssertTrue('the proxy must refuse a client without a proxy identity', Failed);
  Client.Close;
  FProxy.Stop;
  FServer.Stop;
  AssertEquals('the proxy accepted no certificate', '', FProxy.LastSubject);
  AssertEquals('no tunnel', 0, FProxy.Tunnels);
  AssertEquals('the origin was never reached', 0, FServer.Connections);
end;

/// the proxy identity never goes to the origin, on a direct route either
procedure TMutualTlsTest.TestProxyIdentityAloneIsNotPresentedToTheOrigin;
var
  Client: IHttpClient;
begin
  StartServer(mkH2, cTls13);
  FProxyIdentity := Client2Identity;
  Client := NewClient(nil);
  AssertEquals('the origin demands a certificate', 'certificate required',
    AlertOfFetch(Client));
  Client.Close;
  FServer.Stop;
  AssertFalse('the origin was offered no certificate', FServer.SawClientCert);
end;

procedure TMutualTlsTest.TestHttpsProxyToACleartextOriginGetsTheProxyIdentity;
var
  Client: IHttpClient;
begin
  // http origin through an https proxy: the TLS leg is the proxy's, and it
  // gets the proxy identity; there is no origin handshake to hand the origin
  // identity to
  StartServer(mkPlain, 0);
  FProxy := TTunnelProxy.Create(tmHttps, FServer.Port, True);
  Client := THttpClientFactory.Create
    .WithCACertFile(Fixture('ca.crt'))
    .WithClientIdentity(GoodIdentity)
    .WithProxyClientIdentity(Client2Identity)
    .WithProxySelector(TFixedSelector.Create(pkHttps, FProxy.Port))
    .WithClearText(ctHttp1)
    .WithConnectTimeout(3000)
    .WithHeaderTimeout(5000)
    .Build;
  AssertEquals('status', 200,
    SendTo(Client, Format('http://localhost:%d/', [FServer.Port])).StatusCode);
  Client.Close;
  FProxy.Stop;
  FServer.Stop;
  AssertTrue('the proxy saw the proxy identity',
    SubjectIs(FProxy.LastSubject, 'mtls client two'));
  AssertEquals('one origin request', 1, FServer.Requests);
end;

/// a cleartext origin behind an https proxy has no origin identity: the
/// selector is not asked and the key has no identity part
procedure TMutualTlsTest.TestSelectorKeyForACleartextOriginBehindAnHttpsProxy;
var
  Sel: TCountingSelector;
  SelRef: IClientIdentitySelector;
  Client: IHttpClient;
  Keys: string;
begin
  StartServer(mkPlain, 0);
  FProxy := TTunnelProxy.Create(tmHttps, FServer.Port, True);
  Sel := TCountingSelector.Create;
  SelRef := Sel;
  Sel.Answer := GoodIdentity;
  Client := THttpClientFactory.Create
    .WithCACertFile(Fixture('ca.crt'))
    .WithClientIdentitySelector(SelRef)
    .WithProxyClientIdentity(Client2Identity)
    .WithProxySelector(TFixedSelector.Create(pkHttps, FProxy.Port))
    .WithClearText(ctHttp1)
    .WithConnectTimeout(3000)
    .WithHeaderTimeout(5000)
    .Build;
  AssertEquals('status', 200,
    SendTo(Client, Format('http://localhost:%d/', [FServer.Port])).StatusCode);
  Keys := KeysOf(Client);
  Client.Close;
  FProxy.Stop;
  FServer.Stop;
  AssertEquals('the selector is not asked', 0, Sel.Calls);
  AssertEquals('no identity part in the key', 0, Pos(' id=', Keys));
  AssertTrue('the proxy saw the proxy identity',
    SubjectIs(FProxy.LastSubject, 'mtls client two'));
end;

procedure TMutualTlsTest.TestExpiredProxyIdentityFailsBuild;
var
  Failed: Boolean;
begin
  Failed := False;
  try
    THttpClientFactory.Create
      .WithProxyClientIdentity(TClientIdentity.FromPemFiles(
        Fixture('expired.crt'), Fixture('expired.key')))
      .Build;
  except
    on E: EHttpTlsConfigError do
      Failed := True;
  end;
  AssertTrue('Build refuses an expired proxy identity', Failed);
end;

{ per-request identity }

procedure TMutualTlsTest.TestRequestIdentityAccessorsAndClone;
var
  Id, Id2: IClientIdentity;
  R, R2: THttpRequest;
  W: IWebSocketRequest;
begin
  Id := GoodIdentity;
  R := THttpRequest.Create(hmGet, 'https://localhost/');
  AssertTrue('none by default', R.ClientIdentity = nil);
  R2 := R.WithClientIdentity(Id);
  AssertTrue('the original is unchanged', R.ClientIdentity = nil);
  AssertTrue('set', R2.ClientIdentity = Id);
  AssertTrue('Clone keeps it', R2.Clone.ClientIdentity = Id);
  AssertTrue('WithUrl keeps it', R2.WithUrl('https://x/').ClientIdentity = Id);
  AssertTrue('DropBody keeps it', R2.DropBody.ClientIdentity = Id);
  AssertTrue('WithMethodToken keeps it',
    R2.WithMethodToken('GET').ClientIdentity = Id);
  AssertTrue('WithHeader keeps it',
    R2.WithHeader('x', 'y').ClientIdentity = Id);
  AssertTrue('nil clears it', R2.WithClientIdentity(nil).ClientIdentity = nil);
  W := TWebSocketRequest.Create('wss://localhost/', TWsRecorder.Create);
  AssertTrue('ws none by default', W.ClientIdentity = nil);
  Id2 := GoodIdentity;
  AssertTrue('ws set', Supports(W.WithClientIdentity(Id).ClientIdentity,
    IClientIdentity, Id2) and (Id2 = Id));
  AssertTrue('ws original unchanged', W.ClientIdentity = nil);
  AssertTrue('ws other With keeps it',
    Supports(W.WithClientIdentity(Id).WithAutoRequest.WithHeader('x', 'y')
      .ClientIdentity, IClientIdentity, Id2) and (Id2 = Id));
end;

/// the request identity reaches the origin on every route and never the proxy
/// leg; the selector would have answered the client's other identity
procedure TMutualTlsTest.RunRequestVia(const AViaProxy: Boolean;
  const AMode: TTunnelMode);
var
  Sel: TCountingSelector;
  SelRef: IClientIdentitySelector;
  Client: IHttpClient;
  Keys: string;
begin
  StartServer(mkH2, cTls13);
  if AViaProxy then
  begin
    FProxy := TTunnelProxy.Create(AMode, FServer.Port, AMode = tmHttps);
    if AMode = tmHttps then
      FProxyIdentity := GoodIdentity;
  end;
  Sel := TCountingSelector.Create;
  SelRef := Sel;
  Sel.Answer := GoodIdentity;
  Client := SelectorClient(SelRef);
  AssertEquals('status', 200, Client.Send(THttpRequest.Create(hmGet, Url)
    .WithClientIdentity(Client2Identity)).StatusCode);
  AssertEquals('pooled', 200, Client.Send(THttpRequest.Create(hmGet, Url)
    .WithClientIdentity(Client2Identity)).StatusCode);
  Keys := KeysOf(Client);
  Client.Close;
  if FProxy <> nil then
    FProxy.Stop;
  FServer.Stop;
  AssertEquals('the selector is not asked', 0, Sel.Calls);
  AssertTrue('the origin saw the request identity',
    SubjectIs(FServer.LastSubject, 'mtls client two'));
  AssertEquals('one origin handshake: the second request reused it', 1,
    FServer.Handshakes);
  AssertTrue('the key carries the request identity fingerprint',
    Pos(Client2Identity.Fingerprint, Keys) > 0);
  if AViaProxy and (AMode = tmHttps) then
  begin
    AssertTrue('the proxy saw the proxy identity only',
      SubjectIs(FProxy.LastSubject, 'mtls client'));
    AssertFalse('the proxy never sees the request identity',
      SubjectIs(FProxy.LastSubject, 'mtls client two'));
  end
  else if AViaProxy then
    AssertFalse('no TLS to the proxy', FProxy.SawClientCert);
end;

procedure TMutualTlsTest.TestRequestIdentityDirect;
begin
  RunRequestVia(False, tmConnect);
end;

procedure TMutualTlsTest.TestRequestIdentityThroughConnect;
begin
  RunRequestVia(True, tmConnect);
end;

procedure TMutualTlsTest.TestRequestIdentityThroughSocks5;
begin
  RunRequestVia(True, tmSocks5);
end;

procedure TMutualTlsTest.TestRequestIdentityThroughAnHttpsProxy;
begin
  RunRequestVia(True, tmHttps);
end;

procedure TMutualTlsTest.TestTwoRequestIdentitiesOnOneOriginDoNotShareAConnection;
var
  Client: IHttpClient;
  Keys: string;
begin
  StartServer(mkH2, cTls13);
  Client := NewClient(nil);
  AssertEquals('a', 200, Client.Send(THttpRequest.Create(hmGet, Url)
    .WithClientIdentity(GoodIdentity)).StatusCode);
  AssertEquals('b', 200, Client.Send(THttpRequest.Create(hmGet, Url)
    .WithClientIdentity(Client2Identity)).StatusCode);
  AssertEquals('a again', 200, Client.Send(THttpRequest.Create(hmGet, Url)
    .WithClientIdentity(GoodIdentity)).StatusCode);
  Keys := KeysOf(Client);
  Client.Close;
  FServer.Stop;
  AssertEquals('two handshakes, the third request reused the first', 2,
    FServer.Handshakes);
  AssertEquals('three requests', 3, FServer.Requests);
  AssertEquals('the second identity handshook once', 1,
    CountOf('mtls client two', FServer.AllSubjects));
  AssertTrue('two keys, one per identity',
    (Pos(GoodIdentity.Fingerprint, Keys) > 0) and
    (Pos(Client2Identity.Fingerprint, Keys) > 0));
end;

procedure TMutualTlsTest.TestRequestIdentityWinsOverTheSelector;
var
  Sel: TCountingSelector;
  SelRef: IClientIdentitySelector;
  Client: IHttpClient;
begin
  StartServer(mkHttp1, cTls13);
  Sel := TCountingSelector.Create;
  SelRef := Sel;
  Sel.Answer := GoodIdentity;
  Client := SelectorClient(SelRef);
  AssertEquals('request identity', 200, Client.Send(
    THttpRequest.Create(hmGet, Url).WithClientIdentity(Client2Identity))
    .StatusCode);
  AssertEquals('selector not asked', 0, Sel.Calls);
  AssertEquals('no identity on the request', 200, SendTo(Client, Url).StatusCode);
  AssertEquals('selector asked once', 1, Sel.Calls);
  Client.Close;
  FServer.Stop;
  AssertEquals('request identity once, selector answer once',
    1, CountOf('mtls client two', FServer.AllSubjects));
  AssertTrue('the selector answered last',
    SubjectIs(FServer.LastSubject, 'mtls client'));
end;

procedure TMutualTlsTest.TestRequestIdentityWinsOverTheFixedIdentity;
var
  Client: IHttpClient;
begin
  StartServer(mkHttp1, cTls13);
  Client := NewClient(GoodIdentity, True);
  AssertEquals('request identity', 200, Client.Send(
    THttpRequest.Create(hmGet, Url).WithClientIdentity(Client2Identity))
    .StatusCode);
  AssertTrue('the origin saw the request identity',
    SubjectIs(FServer.LastSubject, 'mtls client two'));
  AssertEquals('no identity on the request', 200, SendTo(Client, Url).StatusCode);
  Client.Close;
  FServer.Stop;
  AssertTrue('the fixed identity is the fallback',
    SubjectIs(FServer.LastSubject, 'mtls client'));
  AssertEquals('two handshakes', 2, FServer.Handshakes);
end;

procedure TMutualTlsTest.TestRequestWithoutIdentityKeepsThePlainKey;
var
  Client: IHttpClient;
  Keys: string;
begin
  StartServer(mkH2, cTls13);
  Client := NewClient(GoodIdentity);
  AssertEquals('status', 200, SendTo(Client, Url).StatusCode);
  Keys := KeysOf(Client);
  AssertEquals('a request with none keeps the plain key', 0, Pos(' id=', Keys));
  AssertEquals('with identity', 200, Client.Send(THttpRequest.Create(hmGet, Url)
    .WithClientIdentity(Client2Identity)).StatusCode);
  Keys := KeysOf(Client);
  Client.Close;
  FServer.Stop;
  AssertTrue('the identity request has its own key',
    Pos(' id=' + Client2Identity.Fingerprint, Keys) > 0);
  AssertEquals('two handshakes, no sharing', 2, FServer.Handshakes);
end;

procedure TMutualTlsTest.TestRedirectToTheSameOriginKeepsTheRequestIdentity;
var
  Client: IHttpClient;
begin
  StartServer(mkHttp1, cTls13);
  FServer.RedirectTo := '/final';
  Client := NewClient(GoodIdentity, True);
  AssertEquals('status', 200, Client.Send(THttpRequest.Create(hmGet,
    Url + 'redir').WithClientIdentity(Client2Identity)).StatusCode);
  Client.Close;
  FServer.Stop;
  AssertEquals('both hops handshook', 2, FServer.Handshakes);
  AssertEquals('both hops presented the request identity', 2,
    CountOf('mtls client two', FServer.AllSubjects));
end;

procedure TMutualTlsTest.TestRedirectToAnotherOriginDropsTheRequestIdentity;
var
  Other: TMtlsServer;
  Client: IHttpClient;
begin
  StartServer(mkHttp1, cTls13);
  Other := TMtlsServer.Create(mkHttp1, cTls13);
  try
    FServer.RedirectTo := Format('https://localhost:%d/', [Other.Port]);
    Client := NewClient(GoodIdentity, True);
    AssertEquals('status', 200, Client.Send(THttpRequest.Create(hmGet,
      Url + 'redir').WithClientIdentity(Client2Identity)).StatusCode);
    Client.Close;
    FServer.Stop;
    Other.Stop;
    AssertTrue('the first origin saw the request identity',
      SubjectIs(FServer.LastSubject, 'mtls client two'));
    AssertEquals('the other origin handshook once', 1, Other.Handshakes);
    AssertTrue('the other origin saw the client identity',
      SubjectIs(Other.LastSubject, 'mtls client'));
    AssertEquals('the request identity did not follow', 0,
      CountOf('mtls client two', Other.AllSubjects));
  finally
    Other.Stop;
    Other.Free;
  end;
end;

procedure TMutualTlsTest.TestWssRequestIdentityDirect;
begin
  RunWssVia(tmConnect, isRequest, False);
end;

procedure TMutualTlsTest.TestWssRequestIdentityThroughAnHttpsProxy;
begin
  RunWssVia(tmHttps, isRequest, True);
end;

procedure TMutualTlsTest.TestSseRequestIdentity;
var
  Client: IHttpClient;
  Source: TSseSource;
  Event: TSseEvent;
begin
  StartServer(mkSse, cTls13);
  Client := NewClient(GoodIdentity, True);
  Source := TSseSource.Create(Client.Send(
    SseRequest(Url).WithClientIdentity(Client2Identity)));
  try
    AssertTrue('an event arrived', Source.ReadEvent(Event));
  finally
    Source.Close;
  end;
  Client.Close;
  FServer.Stop;
  AssertTrue('the server saw the request identity',
    SubjectIs(FServer.LastSubject, 'mtls client two'));
end;

procedure TMutualTlsTest.TestExpiredRequestIdentityRaisesBeforeDialling;
var
  Client: IHttpClient;
  Failed: Boolean;
begin
  StartServer(mkH2, cTls13);
  Client := NewClient(GoodIdentity);
  Failed := False;
  try
    Client.Send(THttpRequest.Create(hmGet, Url).WithClientIdentity(
      TClientIdentity.FromPemFiles(Fixture('expired.crt'),
        Fixture('expired.key'))));
  except
    on E: EHttpTlsConfigError do
      Failed := True;
  end;
  Client.Close;
  FServer.Stop;
  AssertTrue('EHttpTlsConfigError', Failed);
  AssertEquals('nothing was dialled', 0, FServer.Connections);
end;

procedure TMutualTlsTest.TestExpiredWssRequestIdentityRaisesBeforeDialling;
var
  Client: IHttpClient;
  Failed: Boolean;
begin
  StartServer(mkWebSocket, cTls13);
  Client := NewClient(GoodIdentity);
  Failed := False;
  try
    Client.Send(TWebSocketRequest.Create(
      Format('wss://localhost:%d/chat', [FServer.Port]), TWsRecorder.Create)
      .WithClientIdentity(TClientIdentity.FromPemFiles(
        Fixture('expired.crt'), Fixture('expired.key'))));
  except
    on E: EHttpTlsConfigError do
      Failed := True;
  end;
  Client.Close;
  FServer.Stop;
  AssertTrue('EHttpTlsConfigError', Failed);
  AssertEquals('nothing was dialled', 0, FServer.Connections);
end;


{ injected factory, selector expiry and the connection cap }

procedure TMutualTlsTest.TestInjectedFactoryWithFixedIdentityFailsBuild;
var
  Raised: Boolean;
begin
  Raised := False;
  try
    THttpClientFactory.Create
      .WithSocketFactory(TPlainSocketFactory.Create)
      .WithClientIdentity(GoodIdentity)
      .Build;
  except
    on E: EHttpTlsConfigError do
      Raised := True;
  end;
  AssertTrue('Build refuses an identity the injected factory cannot present',
    Raised);
end;

procedure TMutualTlsTest.TestInjectedFactoryWithSelectorFailsBuild;
var
  Raised: Boolean;
begin
  Raised := False;
  try
    THttpClientFactory.Create
      .WithSocketFactory(TPlainSocketFactory.Create)
      .WithClientIdentitySelector(FixedIdentitySelector(GoodIdentity))
      .Build;
  except
    on E: EHttpTlsConfigError do
      Raised := True;
  end;
  AssertTrue('Build refuses a selector the injected factory cannot use',
    Raised);
end;

procedure TMutualTlsTest.TestInjectedFactoryWithProxyIdentityFailsBuild;
var
  Raised: Boolean;
begin
  Raised := False;
  try
    THttpClientFactory.Create
      .WithSocketFactory(TPlainSocketFactory.Create)
      .WithProxyClientIdentity(GoodIdentity)
      .Build;
  except
    on E: EHttpTlsConfigError do
      Raised := True;
  end;
  AssertTrue('Build refuses a proxy identity the factory cannot present',
    Raised);
end;

procedure TMutualTlsTest.TestInjectedFactoryWithRequestIdentityFailsBeforeDialling;
var
  Plain: TPlainSocketFactory;
  PlainRef: IHttp2SocketFactory;
  Client: IHttpClient;
  Raised: Boolean;
begin
  Plain := TPlainSocketFactory.Create;
  PlainRef := Plain;
  Client := THttpClientFactory.Create.WithSocketFactory(PlainRef).Build;
  Raised := False;
  try
    Client.Send(THttpRequest.Create(hmGet, 'https://localhost:9/')
      .WithClientIdentity(GoodIdentity));
  except
    on E: EHttpTlsConfigError do
      Raised := True;
  end;
  Client.Close;
  AssertTrue('Send refuses a request identity the factory cannot present',
    Raised);
  AssertEquals('nothing was dialled', 0, Plain.Dials);
end;

procedure TMutualTlsTest.TestInjectedFactoryWithWssRequestIdentityFailsBeforeDialling;
var
  Plain: TPlainSocketFactory;
  PlainRef: IHttp2SocketFactory;
  Client: IHttpClient;
  Raised: Boolean;
begin
  Plain := TPlainSocketFactory.Create;
  PlainRef := Plain;
  Client := THttpClientFactory.Create.WithSocketFactory(PlainRef).Build;
  Raised := False;
  try
    Client.Send(TWebSocketRequest.Create('wss://localhost:9/chat',
      TWsRecorder.Create).WithClientIdentity(GoodIdentity));
  except
    on E: EHttpTlsConfigError do
      Raised := True;
  end;
  Client.Close;
  AssertTrue('Send refuses a wss request identity the factory cannot present',
    Raised);
  AssertEquals('nothing was dialled', 0, Plain.Dials);
end;

procedure TMutualTlsTest.TestInjectedFactoryWithoutIdentitiesStillWorks;
var
  Plain: TPlainSocketFactory;
  PlainRef: IHttp2SocketFactory;
  Client: IHttpClient;
  Dialled: Boolean;
begin
  Plain := TPlainSocketFactory.Create;
  PlainRef := Plain;
  Client := THttpClientFactory.Create.WithSocketFactory(PlainRef).Build;
  Dialled := False;
  try
    Client.Send(THttpRequest.Create(hmGet, 'https://localhost:9/'));
  except
    on E: EHttpConnectionError do
      Dialled := True;
  end;
  Client.Close;
  AssertTrue('a request with no identity reaches the factory', Dialled);
  AssertEquals('dialled once', 1, Plain.Dials);
end;

procedure TMutualTlsTest.TestExpiredSelectorAnswerFailsTheDialBeforeDialling;
var
  Sel: TCountingSelector;
  SelRef: IClientIdentitySelector;
  Client: IHttpClient;
  Msg: string;
begin
  StartServer(mkH2, cTls13);
  Sel := TCountingSelector.Create;
  SelRef := Sel;
  Sel.Answer := TClientIdentity.FromPemFiles(Fixture('expired.crt'),
    Fixture('expired.key'));
  Client := SelectorClient(SelRef);
  Msg := '';
  try
    SendTo(Client, Url);
  except
    on E: EHttpTlsConfigError do
      Msg := E.Message;
  end;
  Client.Close;
  FServer.Stop;
  AssertTrue('EHttpTlsConfigError naming the expiry: ' + Msg,
    Pos('expired on', Msg) > 0);
  AssertEquals('no key material in the message', 0, Pos('PRIVATE', Msg));
  AssertEquals('the selector was asked once', 1, Sel.Calls);
  AssertEquals('nothing was dialled', 0, FServer.Connections);
end;

procedure TMutualTlsTest.TestExpiredSelectorAnswerFailsWssBeforeDialling;
var
  Sel: TCountingSelector;
  SelRef: IClientIdentitySelector;
  Client: IHttpClient;
  Failed: Boolean;
begin
  StartServer(mkWebSocket, cTls13);
  Sel := TCountingSelector.Create;
  SelRef := Sel;
  Sel.Answer := TClientIdentity.FromPemFiles(Fixture('expired.crt'),
    Fixture('expired.key'));
  Client := SelectorClient(SelRef);
  Failed := False;
  try
    Client.Send(TWebSocketRequest.Create(
      Format('wss://localhost:%d/chat', [FServer.Port]), TWsRecorder.Create));
  except
    on E: EHttpTlsConfigError do
      Failed := True;
  end;
  Client.Close;
  FServer.Stop;
  AssertTrue('EHttpTlsConfigError', Failed);
  AssertEquals('nothing was dialled', 0, FServer.Connections);
end;

procedure TMutualTlsTest.TestRotationAtThePerHostCapEvictsTheIdleOldIdentity;
var
  Client: IHttpClient;
  Stats: TPoolStats;
  Id2: IClientIdentity;
begin
  StartServer(mkH2, cTls13);
  Client := RouteVia(THttpClientFactory.Create
    .WithCACertFile(Fixture('ca.crt'))
    .WithConnectTimeout(3000)
    .WithHeaderTimeout(1500)
    .WithMaxConnectionsPerHost(1)).Build;
  Id2 := Client2Identity;
  AssertEquals('first body', 'ok', ReadBody(Client.Send(
    THttpRequest.Create(hmGet, Url).WithClientIdentity(GoodIdentity))));
  AssertEquals('second body', 'ok', ReadBody(Client.Send(
    THttpRequest.Create(hmGet, Url).WithClientIdentity(Id2))));
  Stats := (Client as THttpClient).PoolStats;
  AssertEquals('the cap holds across identities', 1, Stats.Connections);
  AssertEquals('one pool key', 1, Length(Stats.PerOrigin));
  AssertTrue('the surviving connection is the new identity',
    Pos(Id2.Fingerprint, Stats.PerOrigin[0].Origin) > 0);
  AssertTrue('the origin saw the new identity',
    SubjectIs(FServer.LastSubject, 'mtls client two'));
  Client.Close;
  FServer.Stop;
  AssertEquals('two connections were opened', 2, FServer.Connections);
end;

procedure TMutualTlsTest.TestRotationAtTheTotalCapEvictsTheIdleOldIdentity;
var
  Client: IHttpClient;
  Stats: TPoolStats;
  Id2: IClientIdentity;
begin
  StartServer(mkH2, cTls13);
  Client := RouteVia(THttpClientFactory.Create
    .WithCACertFile(Fixture('ca.crt'))
    .WithConnectTimeout(3000)
    .WithHeaderTimeout(1500)
    .WithMaxTotalConnections(1)).Build;
  Id2 := Client2Identity;
  AssertEquals('first body', 'ok', ReadBody(Client.Send(
    THttpRequest.Create(hmGet, Url).WithClientIdentity(GoodIdentity))));
  AssertEquals('second body', 'ok', ReadBody(Client.Send(
    THttpRequest.Create(hmGet, Url).WithClientIdentity(Id2))));
  Stats := (Client as THttpClient).PoolStats;
  AssertEquals('the total cap holds', 1, Stats.Connections);
  Client.Close;
  FServer.Stop;
  AssertEquals('two connections were opened', 2, FServer.Connections);
end;

procedure TMutualTlsTest.TestBusyOldIdentityIsNeverEvicted;
var
  Client: IHttpClient;
  Old: IHttpResponse;
  Stats: TPoolStats;
  TimedOut: Boolean;
begin
  StartServer(mkHttp1, cTls13);
  Client := RouteVia(THttpClientFactory.Create
    .WithCACertFile(Fixture('ca.crt'))
    .WithConnectTimeout(3000)
    .WithHeaderTimeout(300)
    .WithHttp1Fallback(True)
    .WithMaxConnectionsPerHost(1)).Build;
  // the first response is held open, so its connection is busy
  Old := Client.Send(THttpRequest.Create(hmGet, Url)
    .WithClientIdentity(GoodIdentity));
  TimedOut := False;
  try
    Client.Send(THttpRequest.Create(hmGet, Url)
      .WithClientIdentity(Client2Identity));
  except
    on E: EHttpTimeout do
      TimedOut := True;
  end;
  AssertTrue('the new identity waits for a slot and times out', TimedOut);
  Stats := (Client as THttpClient).PoolStats;
  AssertEquals('the busy connection is still pooled', 1, Stats.Connections);
  AssertEquals('the old connection still answers', 'ok', ReadBody(Old));
  Client.Close;
  FServer.Stop;
  AssertEquals('no second connection was dialled', 1, FServer.Connections);
end;

procedure TMutualTlsTest.TestTwoIdentitiesShareThePerHostCap;
var
  Client: IHttpClient;
  Old, Second: IHttpResponse;
  Stats: TPoolStats;
  TimedOut: Boolean;
begin
  StartServer(mkHttp1, cTls13);
  Client := RouteVia(THttpClientFactory.Create
    .WithCACertFile(Fixture('ca.crt'))
    .WithConnectTimeout(3000)
    .WithHeaderTimeout(300)
    .WithHttp1Fallback(True)
    .WithMaxConnectionsPerHost(2)).Build;
  // two busy connections, one per identity, fill the cap of two
  Old := Client.Send(THttpRequest.Create(hmGet, Url)
    .WithClientIdentity(GoodIdentity));
  Second := Client.Send(THttpRequest.Create(hmGet, Url)
    .WithClientIdentity(Client2Identity));
  AssertEquals('second identity fits', 200, Second.StatusCode);
  TimedOut := False;
  try
    // a third request of the first identity cannot open another connection
    Client.Send(THttpRequest.Create(hmGet, Url)
      .WithClientIdentity(GoodIdentity));
  except
    on E: EHttpTimeout do
      TimedOut := True;
  end;
  AssertTrue('the origin never exceeds MaxConnectionsPerHost', TimedOut);
  Stats := (Client as THttpClient).PoolStats;
  AssertEquals('two connections in all', 2, Stats.Connections);
  AssertEquals('under two keys', 2, Length(Stats.PerOrigin));
  ReadBody(Old);
  ReadBody(Second);
  Client.Close;
  FServer.Stop;
  AssertEquals('two connections were opened', 2, FServer.Connections);
end;

procedure TMutualTlsTest.TestConcurrentColdRequestsAskTheSelectorOnce;
var
  Sel: TCountingSelector;
  SelRef: IClientIdentitySelector;
  Client: IHttpClient;
  A, B: TFetchThread;
begin
  StartServer(mkH2, cTls13);
  Sel := TCountingSelector.Create;
  SelRef := Sel;
  Sel.Answer := GoodIdentity;
  Sel.DelayMs := 500;
  Client := SelectorClient(SelRef);
  A := TFetchThread.Create(Client, Url);
  Sleep(100);                   // B arrives while A's selector call runs
  B := TFetchThread.Create(Client, Url);
  A.WaitFor;
  B.WaitFor;
  AssertFalse('A succeeded', A.Failed);
  AssertFalse('B succeeded', B.Failed);
  AssertEquals('A status', 200, A.Status);
  AssertEquals('B status', 200, B.Status);
  A.Free;
  B.Free;
  Client.Close;
  FServer.Stop;
  AssertEquals('the selector is asked once for one dial', 1, Sel.Calls);
  AssertEquals('one connection serves both', 1, FServer.Connections);
end;

{ other }

procedure TMutualTlsTest.TestCleartextIgnoresTheIdentity;
var
  Client: IHttpClient;
  Body: string;
begin
  StartServer(mkPlain, 0);
  Client := THttpClientFactory.Create
    .WithClientIdentity(GoodIdentity)
    .WithClearText(ctHttp1)
    .WithConnectTimeout(3000)
    .WithHeaderTimeout(5000)
    .Build;
  AssertEquals('status', 200,
    Client.Send(THttpRequest.Create(hmGet, Url('http'))).StatusCode);
  Client.Close;
  FServer.Stop;
  AssertEquals('one request', 1, FServer.Requests);
  Body := '';
  AssertEquals('no handshake', 0, FServer.Handshakes);
end;

procedure TMutualTlsTest.TestLogLineHasSubjectAndFingerprintButNoSecrets;
var
  Logger: TRecordingLogger;
  LoggerRef: IHttpLogger;
  Client: IHttpClient;
  Body, Joined, Fingerprint: string;
  I: Integer;
  Id: IClientIdentity;
  Found: Boolean;
begin
  StartServer(mkH2, cTls13);
  Logger := TRecordingLogger.Create;
  LoggerRef := Logger;
  Id := TClientIdentity.FromPemFiles(Fixture('client-chain.pem'),
    Fixture('client-encrypted.key'), cPass);
  Fingerprint := Id.Fingerprint;
  Client := THttpClientFactory.Create
    .WithCACertFile(Fixture('ca.crt'))
    .WithClientCertificateFiles(Fixture('client-chain.pem'),
      Fixture('client-encrypted.key'), cPass)
    .WithLogger(LoggerRef)
    .Build;
  AssertEquals('status', 200, Fetch(Client, Body));
  Client.Close;
  FServer.Stop;
  Found := False;
  Joined := '';
  for I := 0 to Logger.Count - 1 do
  begin
    Joined := Joined + Logger.MessageAt(I) + #10;
    if (Pos(Id.Subject, Logger.MessageAt(I)) > 0) and
       (Pos(Fingerprint, Logger.MessageAt(I)) > 0) then
    begin
      Found := True;
      AssertTrue('at debug level', Logger.LevelAt(I) = llDebug);
    end;
  end;
  AssertTrue('a line names the subject and fingerprint', Found);
  AssertEquals('no passphrase logged', 0, Pos(cPass, Joined));
  AssertEquals('no key path logged', 0, Pos('client-encrypted.key', Joined));
  AssertEquals('no PEM logged', 0, Pos('-----BEGIN', Joined));
end;

initialization
  RegisterTest(TMutualTlsTest);
end.
