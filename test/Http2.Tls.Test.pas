/// Unit tests for Http2.Tls (plan story S05, tasks 05.1-05.8)
// - the TLS handshake seams are exercised with injected results so the bulk
//   of the suite needs no network; one in-process handshake proves the real
//   OpenSSL path when it is available.
// - a live nghttpd check is opt-in behind HTTP2_TLS_ITEST=1.
unit Http2.Tls.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, fpcunit, testregistry, sockets, baseunix,
  mormot.lib.openssl11, Http2.Errors, Http2.Tls;

type
  /// a trivial mock byte stream; proves at compile time that a small class can
  /// satisfy IHttp2Socket for later stories
  TMockSocket = class(TInterfacedObject, IHttp2Socket)
  private
    FConnected: Boolean;
    FConnectTimeoutMs: Integer;
    FReadTimeoutMs: Integer;
    FWriteTimeoutMs: Integer;
  public
    constructor Create;
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

  /// exposes the protected crypto seams of TTlsSocket and scripts their
  /// results, so Establish can be tested without OpenSSL or the network
  TFakeTlsSocket = class(TTlsSocket)
  private
    FVerifyMode: Integer;
    FSniHost: string;
    FHostnameVerified: Boolean;
    FAlpnBytes: TBytes;
    FReadChunks: array of TBytes;
    FReadIndex: Integer;
    FShutdownCalled: Boolean;
  protected
    function CreateSslContext: PSSL_CTX; override;
    procedure DestroySslContext; override;
    function CreateSslHandle(const ACtx: PSSL_CTX): PSSL; override;
    procedure DestroySslHandle; override;
    function ApplyAlpnProtos(const ACtx: PSSL_CTX): Integer; override;
    procedure ApplyVerifyMode(const ACtx: PSSL_CTX; const AMode: Integer); override;
    function ApplyHostnameVerification(const ASsl: PSSL;
      const AHost: string): Integer; override;
    function ApplySniHost(const ASsl: PSSL;
      const AHost: string): Integer; override;
    function BindSocket(const ASsl: PSSL; const AFd: Integer): Integer; override;
    function HandshakeConnect(const ASsl: PSSL): Integer; override;
    function SelectedAlpnBytes(const ASsl: PSSL): TBytes; override;
    function LastSslError(const ASsl: PSSL; const AResult: Integer): Integer; override;
    function SslReadBytes(const ASsl: PSSL; const ABuffer: Pointer;
      const ACount: Integer): Integer; override;
    function SslWriteBytes(const ASsl: PSSL; const ABuffer: Pointer;
      const ACount: Integer): Integer; override;
    procedure SslShutdown(const ASsl: PSSL); override;
    function GetSocketFd: Integer; override;
  public
    constructor Create(const ATransport: IHttp2Socket; const AHost: string;
      const AInsecure: Boolean = False);
    procedure SetAlpnBytes(const ABytes: array of Byte);
    procedure AddReadChunk(const ABytes: array of Byte);
    property VerifyMode: Integer read FVerifyMode;
    property SniHost: string read FSniHost;
    property HostnameVerified: Boolean read FHostnameVerified;
    property ShutdownCalled: Boolean read FShutdownCalled;
  end;

  TWriterThread = class(TThread)
  private
    FFd: Integer;
    FData: TBytes;
    FDelayMs: Integer;
  protected
    procedure Execute; override;
  public
    constructor Create(const AFd: Integer; const AData: TBytes;
      const ADelayMs: Integer);
  end;

  /// outcome of a real loopback TLS handshake used by the verification tests
  TRealHandshakeResult = record
    Skipped: Boolean;
    Raised: Boolean;
    WasProtocolError: Boolean;
    Connected: Boolean;
  end;

  /// accepts one connection on a loopback listener and runs a real OpenSSL
  /// server handshake with the test certificate (no ALPN selection)
  TLoopbackTlsServer = class(TThread)
  private
    FListenFd: Integer;
    FAcceptedFd: Integer;
    FHandshakeResult: Integer;
    FCertFile: string;
    FKeyFile: string;
  protected
    procedure Execute; override;
  public
    constructor Create(const AListenFd: Integer;
      const ACertFile, AKeyFile: string);
    property HandshakeResult: Integer read FHandshakeResult;
  end;

  TTlsTest = class(TTestCase)
  protected
    procedure SetUp; override;
  published
    // 05.1 interface / mock proof
    procedure TestMockSatisfiesIHttp2Socket;
    // 05.4 ALPN wire bytes and verification
    procedure TestAlpnWireBytesAreExact;
    procedure TestAlpnProtocolListOfTwo;
    procedure TestAlpnOfferForStrictOffersH2Only;          // 13.5
    procedure TestAlpnOfferForFallbackOffersHttp11Too;     // 13.5
    procedure TestAlpnNegotiatedNameMapsKnownAndUnknown;   // 13.5
    procedure TestAlpnNameDecodes;
    procedure TestRequireH2AlpnAcceptsH2;
    procedure TestRequireH2AlpnRejectsHttp11;
    procedure TestRequireH2AlpnRejectsNothing;
    procedure TestEstablishWithHttp11Raises;
    procedure TestEstablishWithNothingRaises;
    procedure TestEstablishWithH2Succeeds;
    // 05.6 SNI
    procedure TestSniHostPropagated;
    // 05.5 verification toggle
    procedure TestVerifyModeForInsecureIsNone;
    procedure TestVerifyModeForSecureIsPeer;
    procedure TestInsecureToggleReachesCtx;
    procedure TestSecureDefaultRejectsSelfSigned;
    procedure TestInsecureAcceptsSelfSigned;    // 05.7 timeouts / short reads
    procedure TestSocketReadFullyReassemblesSplitPayload;
    procedure TestSocketReadFullyMapsTimeout;
    procedure TestTlsReadReassemblesChunks;
    // 05.8 OpenSSL availability
    procedure TestOpenSslAvailability;
    // integration (opt-in)
    procedure TestLiveNghttpdAlpnIfEnabled;
  end;

implementation

{ TMockSocket }

constructor TMockSocket.Create;
begin
  inherited Create;
  FConnected := True;
  FConnectTimeoutMs := 1000;
  FReadTimeoutMs := 1000;
  FWriteTimeoutMs := 1000;
end;

function TMockSocket.Read(var ABuffer; ACount: Integer): Integer;
begin
  Result := 0;
end;

function TMockSocket.Write(const ABuffer; ACount: Integer): Integer;
begin
  Result := ACount;
end;

procedure TMockSocket.Close;
begin
  FConnected := False;
end;

function TMockSocket.GetConnected: Boolean;
begin
  Result := FConnected;
end;

function TMockSocket.GetConnectTimeoutMs: Integer;
begin
  Result := FConnectTimeoutMs;
end;

procedure TMockSocket.SetConnectTimeoutMs(const AValue: Integer);
begin
  FConnectTimeoutMs := AValue;
end;

function TMockSocket.GetReadTimeoutMs: Integer;
begin
  Result := FReadTimeoutMs;
end;

procedure TMockSocket.SetReadTimeoutMs(const AValue: Integer);
begin
  FReadTimeoutMs := AValue;
end;

function TMockSocket.GetWriteTimeoutMs: Integer;
begin
  Result := FWriteTimeoutMs;
end;

procedure TMockSocket.SetWriteTimeoutMs(const AValue: Integer);
begin
  FWriteTimeoutMs := AValue;
end;

{ TFakeTlsSocket }

constructor TFakeTlsSocket.Create(const ATransport: IHttp2Socket;
  const AHost: string; const AInsecure: Boolean);
begin
  inherited Create(ATransport, AHost, AInsecure);
  FAlpnBytes := nil;
  FReadIndex := 0;
end;

procedure TFakeTlsSocket.SetAlpnBytes(const ABytes: array of Byte);
var
  i: Integer;
begin
  SetLength(FAlpnBytes, Length(ABytes));
  for i := 0 to High(ABytes) do
    FAlpnBytes[i] := ABytes[i];
end;

procedure TFakeTlsSocket.AddReadChunk(const ABytes: array of Byte);
var
  i: Integer;
begin
  SetLength(FReadChunks, Length(FReadChunks) + 1);
  SetLength(FReadChunks[High(FReadChunks)], Length(ABytes));
  for i := 0 to High(ABytes) do
    FReadChunks[High(FReadChunks)][i] := ABytes[i];
end;

function TFakeTlsSocket.CreateSslContext: PSSL_CTX;
begin
  Result := PSSL_CTX(1);
end;

procedure TFakeTlsSocket.DestroySslContext;
begin
end;

function TFakeTlsSocket.CreateSslHandle(const ACtx: PSSL_CTX): PSSL;
begin
  Result := PSSL(2);
end;

procedure TFakeTlsSocket.DestroySslHandle;
begin
end;

function TFakeTlsSocket.ApplyAlpnProtos(const ACtx: PSSL_CTX): Integer;
begin
  Result := 0;
end;

procedure TFakeTlsSocket.ApplyVerifyMode(const ACtx: PSSL_CTX;
  const AMode: Integer);
begin
  FVerifyMode := AMode;
end;

function TFakeTlsSocket.ApplyHostnameVerification(const ASsl: PSSL;
  const AHost: string): Integer;
begin
  FHostnameVerified := True;
  Result := 1;
end;

function TFakeTlsSocket.ApplySniHost(const ASsl: PSSL;
  const AHost: string): Integer;
begin
  FSniHost := AHost;
  Result := 1;
end;

function TFakeTlsSocket.BindSocket(const ASsl: PSSL;
  const AFd: Integer): Integer;
begin
  Result := 1;
end;

function TFakeTlsSocket.HandshakeConnect(const ASsl: PSSL): Integer;
begin
  Result := 1;
end;

function TFakeTlsSocket.SelectedAlpnBytes(const ASsl: PSSL): TBytes;
begin
  Result := FAlpnBytes;
end;

function TFakeTlsSocket.LastSslError(const ASsl: PSSL;
  const AResult: Integer): Integer;
begin
  Result := 0;
end;

function TFakeTlsSocket.SslReadBytes(const ASsl: PSSL; const ABuffer: Pointer;
  const ACount: Integer): Integer;
var
  chunk: TBytes;
  n: Integer;
begin
  if FReadIndex > High(FReadChunks) then
    Exit(0);
  chunk := FReadChunks[FReadIndex];
  n := Length(chunk);
  if n > ACount then
    n := ACount;
  Move(chunk[0], ABuffer^, n);
  Inc(FReadIndex);
  Result := n;
end;

function TFakeTlsSocket.SslWriteBytes(const ASsl: PSSL; const ABuffer: Pointer;
  const ACount: Integer): Integer;
begin
  Result := ACount;
end;

procedure TFakeTlsSocket.SslShutdown(const ASsl: PSSL);
begin
  FShutdownCalled := True;
end;

function TFakeTlsSocket.GetSocketFd: Integer;
begin
  Result := -1;
end;

{ TWriterThread }

constructor TWriterThread.Create(const AFd: Integer; const AData: TBytes;
  const ADelayMs: Integer);
begin
  inherited Create(True);
  FFd := AFd;
  FData := AData;
  FDelayMs := ADelayMs;
  FreeOnTerminate := False;
end;

procedure TWriterThread.Execute;
begin
  if FDelayMs > 0 then
    Sleep(FDelayMs);
  if Length(FData) > 0 then
    fpSend(FFd, @FData[0], Length(FData), 0);
end;

{ TLoopbackTlsServer }

constructor TLoopbackTlsServer.Create(const AListenFd: Integer;
  const ACertFile, AKeyFile: string);
begin
  inherited Create(True);
  FListenFd := AListenFd;
  FCertFile := ACertFile;
  FKeyFile := AKeyFile;
  FAcceptedFd := -1;
  FHandshakeResult := -99;
  FreeOnTerminate := False;
end;

procedure TLoopbackTlsServer.Execute;
var
  ctx: PSSL_CTX;
  ssl: PSSL;
  opt: LongInt;
begin
  // ensure the OpenSSL library is loaded before calling any raw SSL_* symbol;
  // the thread may otherwise race the client thread's first load
  if not OpenSslIsAvailable then
    Exit;
  FAcceptedFd := fpAccept(FListenFd, nil, nil);
  if FAcceptedFd < 0 then
    Exit;
  opt := 1;
{$IFDEF DARWIN}
  fpSetSockOpt(FAcceptedFd, SOL_SOCKET, SO_NOSIGPIPE, @opt, SizeOf(opt));
{$ENDIF}
  ctx := SSL_CTX_new(TLS_server_method());
  try
    SSL_CTX_use_certificate_file(ctx, PUtf8Char(UTF8String(FCertFile)),
      SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, PUtf8Char(UTF8String(FKeyFile)),
      SSL_FILETYPE_PEM);
    ssl := SSL_new(ctx);
    SSL_set_fd(ssl, FAcceptedFd);
    FHandshakeResult := SSL_accept(ssl);
    Sleep(100);
    SSL_free(ssl);
  finally
    SSL_CTX_free(ctx);
    fpClose(FAcceptedFd);
  end;
end;

{ helpers }

function BytesOf(const S: AnsiString): TBytes;
var
  i: Integer;
begin
  Result := nil;
  SetLength(Result, Length(S));
  for i := 1 to Length(S) do
    Result[i - 1] := Ord(S[i]);
end;

procedure RawSend(const AFd: Integer; const S: AnsiString);
var
  B: TBytes;
begin
  B := BytesOf(S);
  if Length(B) > 0 then
    fpSend(AFd, @B[0], Length(B), 0);
end;

function RawPtrOf(const B: TBytes): PByte;
begin
  if Length(B) = 0 then
    Result := nil
  else
    Result := @B[0];
end;

function MakeSocketPair(out A, B: Integer): Boolean;
var
  fds: array[0..1] of cint;
  opt: LongInt;
begin
  Result := fpsocketpair(AF_UNIX, SOCK_STREAM, 0, @fds[0]) = 0;
  if Result then
  begin
    A := fds[0];
    B := fds[1];
    // writing to a peer that has already closed must not kill the process
    opt := 1;
{$IFDEF DARWIN}
    fpSetSockOpt(A, SOL_SOCKET, SO_NOSIGPIPE, @opt, SizeOf(opt));
    fpSetSockOpt(B, SOL_SOCKET, SO_NOSIGPIPE, @opt, SizeOf(opt));
{$ENDIF}
  end;
end;

function TestCertPath(const AName: string): string;
begin
  Result := ExtractFilePath(ParamStr(0)) + '../../test/certs/' + AName;
  if FileExists(Result) then
    Exit;
  Result := 'test/certs/' + AName;
end;

// run one real loopback TLS handshake against the self-signed test cert and
// report how TTlsSocket.Dial behaved; spills the failure class into the record
function RunRealHandshake(const AInsecure: Boolean): TRealHandshakeResult;
var
  listenFd: Integer;
  addr: TSockAddr;
  alen: LongInt;
  port: Word;
  server: TLoopbackTlsServer;
  Sock: IHttp2Socket;
  certFile, keyFile: string;
begin
  Result.Skipped := False;
  Result.Raised := False;
  Result.WasProtocolError := False;
  Result.Connected := False;
  certFile := TestCertPath('localhost.crt');
  keyFile := TestCertPath('localhost.key');
  if (not FileExists(certFile)) or (not FileExists(keyFile)) then
  begin
    Result.Skipped := True;
    Exit;
  end;
  listenFd := fpsocket(AF_INET, SOCK_STREAM, 0);
  if listenFd < 0 then
  begin
    Result.Skipped := True;
    Exit;
  end;
  FillChar(addr, SizeOf(addr), 0);
  addr.sin_family := AF_INET;
  addr.sin_port := htons(0);
  addr.sin_addr.s_addr := htonl($7f000001);
  fpbind(listenFd, @addr, SizeOf(addr));
  fplisten(listenFd, 1);
  alen := SizeOf(addr);
  fpgetsockname(listenFd, @addr, @alen);
  port := ntohs(addr.sin_port);
  server := TLoopbackTlsServer.Create(listenFd, certFile, keyFile);
  server.Start;
  Sleep(30);
  try
    try
      Sock := TTlsSocket.Dial('localhost', port, AInsecure, 2000);
      Result.Connected := Sock.Connected;
      Sock.Close;
    except
      on E: EHttpProtocolError do
      begin
        Result.Raised := True;
        Result.WasProtocolError := True;
      end;
      on E: EHttpError do
        Result.Raised := True;
    end;
  finally
    server.WaitFor;
    server.Free;
    fpClose(listenFd);
  end;
end;

{ tests }

procedure TTlsTest.SetUp;
begin
  // load OpenSSL once on the main thread before any worker thread calls into
  // it; OpenSslIsAvailable is documented thread-safe but the first load must
  // not race two callers
  if not OpenSslIsAvailable then
  begin
    // nothing to do; the tests that need TLS self-skip
  end;
end;

procedure TTlsTest.TestMockSatisfiesIHttp2Socket;
var
  Sock: IHttp2Socket;
begin
  Sock := TMockSocket.Create;
  AssertTrue('mock reports connected', Sock.Connected);
  Sock.ConnectTimeoutMs := 7;
  AssertEquals('connect timeout round-trip', 7, Sock.ConnectTimeoutMs);
  Sock.Close;
  AssertFalse('mock reports closed', Sock.Connected);
  AssertEquals('mock write echoes count', 4, Sock.Write(Pointer(nil)^, 4));
end;

procedure TTlsTest.TestAlpnWireBytesAreExact;
var
  Wire: TBytes;
begin
  Wire := AlpnProtocolList(['h2']);
  AssertEquals('wire length', 3, Length(Wire));
  AssertEquals('length byte', $02, Wire[0]);
  AssertEquals('h', $68, Wire[1]);
  AssertEquals('2', $32, Wire[2]);
end;

procedure TTlsTest.TestAlpnProtocolListOfTwo;
var
  Wire: TBytes;
begin
  Wire := AlpnProtocolList(['h2', 'http/1.1']);
  AssertEquals('total length', 1 + 2 + 1 + 8, Length(Wire));
  AssertEquals('h2 length', $02, Wire[0]);
  AssertEquals('second length', 8, Wire[3]);
  AssertEquals('second first char', Ord('h'), Wire[4]);
end;

procedure TTlsTest.TestAlpnOfferForStrictOffersH2Only;
var
  Wire: TBytes;
begin
  // fallback off (the strict default) offers "h2" alone (doc/design/fallback.md
  // "Negotiation" step 2)
  Wire := AlpnOfferFor(False);
  AssertEquals('strict offer is 3 bytes', 3, Length(Wire));
  AssertEquals('strict offer length byte', $02, Wire[0]);
  AssertEquals('strict offer spells h2', 'h2',
    AlpnSelectedName(RawPtrOf(Wire) + 1, 2));
end;

procedure TTlsTest.TestAlpnOfferForFallbackOffersHttp11Too;
var
  Wire: TBytes;
begin
  // fallback on offers "h2" then "http/1.1", in that preference order
  Wire := AlpnOfferFor(True);
  AssertEquals('fallback offer is 12 bytes', 1 + 2 + 1 + 8, Length(Wire));
  AssertEquals('h2 is first', $02, Wire[0]);
  AssertEquals(' then http/1.1', 8, Wire[3]);
  AssertEquals('http/1.1 bytes follow', 'http/1.1',
    AlpnSelectedName(RawPtrOf(Wire) + 4, 8));
end;

procedure TTlsTest.TestAlpnNegotiatedNameMapsKnownAndUnknown;
begin
  // only the two known names survive; anything else (including the empty
  // selection) normalises to '' so the caller applies its fallback policy
  AssertEquals('h2 is kept', 'h2', AlpnNegotiatedName('h2'));
  AssertEquals('http/1.1 is kept', 'http/1.1', AlpnNegotiatedName('http/1.1'));
  AssertEquals('empty maps to empty', '', AlpnNegotiatedName(''));
  AssertEquals('an unknown protocol maps to empty', '',
    AlpnNegotiatedName('spdy/3.1'));
end;

procedure TTlsTest.TestAlpnNameDecodes;
var
  B: TBytes;
begin
  B := BytesOf('h2');
  AssertEquals('decodes h2', 'h2', AlpnSelectedName(RawPtrOf(B), Length(B)));
  B := nil;
  AssertEquals('nil decodes empty', '', AlpnSelectedName(RawPtrOf(B), 0));
end;

procedure TTlsTest.TestRequireH2AlpnAcceptsH2;
var
  B: TBytes;
begin
  B := BytesOf('h2');
  RequireH2Alpn(RawPtrOf(B), Length(B)); // must not raise
  AssertTrue('h2 accepted', True);
end;

procedure TTlsTest.TestRequireH2AlpnRejectsHttp11;
var
  B: TBytes;
  Raised: Boolean;
begin
  B := BytesOf('http/1.1');
  Raised := False;
  try
    RequireH2Alpn(RawPtrOf(B), Length(B));
  except
    on E: EHttpProtocolError do
      Raised := True;
  end;
  AssertTrue('http/1.1 raises EHttpProtocolError', Raised);
end;

procedure TTlsTest.TestRequireH2AlpnRejectsNothing;
var
  Raised: Boolean;
begin
  Raised := False;
  try
    RequireH2Alpn(nil, 0);
  except
    on E: EHttpProtocolError do
      Raised := True;
  end;
  AssertTrue('no selection raises EHttpProtocolError', Raised);
end;

procedure TTlsTest.TestEstablishWithHttp11Raises;
var
  Sock: TFakeTlsSocket;
  Raised: Boolean;
begin
  Sock := TFakeTlsSocket.Create(TMockSocket.Create, 'example.com', True);
  try
    Sock.SetAlpnBytes(BytesOf('http/1.1'));
    Raised := False;
    try
      Sock.Establish;
    except
      on E: EHttpProtocolError do
        Raised := True;
    end;
    AssertTrue('http/1.1 peer fails the handshake', Raised);
    AssertFalse('not connected after ALPN failure', Sock.Connected);
  finally
    Sock.Free;
  end;
end;

procedure TTlsTest.TestEstablishWithNothingRaises;
var
  Sock: TFakeTlsSocket;
  Raised: Boolean;
begin
  Sock := TFakeTlsSocket.Create(TMockSocket.Create, 'example.com', True);
  try
    Raised := False;
    try
      Sock.Establish;
    except
      on E: EHttpProtocolError do
        Raised := True;
    end;
    AssertTrue('peer selecting nothing fails the handshake', Raised);
  finally
    Sock.Free;
  end;
end;

procedure TTlsTest.TestEstablishWithH2Succeeds;
var
  Sock: TFakeTlsSocket;
begin
  Sock := TFakeTlsSocket.Create(TMockSocket.Create, 'example.com', True);
  try
    Sock.SetAlpnBytes(BytesOf('h2'));
    Sock.Establish;
    AssertEquals('selected protocol recorded', 'h2', Sock.SelectedProtocol);
    AssertTrue('connected after successful handshake', Sock.Connected);
  finally
    Sock.Free;
  end;
end;

procedure TTlsTest.TestSniHostPropagated;
var
  Sock: TFakeTlsSocket;
begin
  Sock := TFakeTlsSocket.Create(TMockSocket.Create, 'origin.example', False);
  try
    Sock.SetAlpnBytes(BytesOf('h2'));
    Sock.Establish;
    AssertEquals('SNI host set from origin host', 'origin.example', Sock.SniHost);
    AssertTrue('hostname verification applied in secure mode',
      Sock.HostnameVerified);
  finally
    Sock.Free;
  end;
end;

procedure TTlsTest.TestVerifyModeForInsecureIsNone;
begin
  AssertEquals('insecure maps to SSL_VERIFY_NONE', SSL_VERIFY_NONE,
    SslVerifyModeFor(True));
end;

procedure TTlsTest.TestVerifyModeForSecureIsPeer;
begin
  AssertEquals('secure maps to SSL_VERIFY_PEER', SSL_VERIFY_PEER,
    SslVerifyModeFor(False));
end;

procedure TTlsTest.TestInsecureToggleReachesCtx;
var
  Sock: TFakeTlsSocket;
begin
  Sock := TFakeTlsSocket.Create(TMockSocket.Create, 'example.com', True);
  try
    Sock.SetAlpnBytes(BytesOf('h2'));
    Sock.Establish;
    AssertEquals('insecure context uses SSL_VERIFY_NONE', SSL_VERIFY_NONE,
      Sock.VerifyMode);
    AssertFalse('hostname verification skipped when insecure',
      Sock.HostnameVerified);
  finally
    Sock.Free;
  end;
end;

procedure TTlsTest.TestSecureDefaultRejectsSelfSigned;
var
  R: TRealHandshakeResult;
begin
  if not OpenSslIsAvailable then
  begin
    AssertTrue('OpenSSL unavailable; skipped', True);
    Exit;
  end;
  R := RunRealHandshake(False);
  if R.Skipped then
  begin
    AssertTrue('test certs unavailable; skipped', True);
    Exit;
  end;
  AssertTrue('secure client rejected the self-signed server', R.Raised);
  AssertFalse('rejection is a crypto/connection failure, not just ALPN',
    R.WasProtocolError);
end;

procedure TTlsTest.TestInsecureAcceptsSelfSigned;
var
  R: TRealHandshakeResult;
begin
  if not OpenSslIsAvailable then
  begin
    AssertTrue('OpenSSL unavailable; skipped', True);
    Exit;
  end;
  R := RunRealHandshake(True);
  if R.Skipped then
  begin
    AssertTrue('test certs unavailable; skipped', True);
    Exit;
  end;
  // in insecure mode the self-signed certificate is accepted: the handshake
  // reaches the ALPN check, which is the only thing still missing here
  AssertTrue('insecure client got past certificate verification',
    R.WasProtocolError);
end;

procedure TTlsTest.TestSocketReadFullyReassemblesSplitPayload;
var
  a, b: Integer;
  got: array[0..4] of Byte;
  th: TWriterThread;
begin
  AssertTrue('socketpair created', MakeSocketPair(a, b));
  try
    // first fragment available immediately, second arrives after a delay, so
    // a single recv cannot satisfy the request and the read loop must iterate
    RawSend(b, 'AB');
    th := TWriterThread.Create(b, BytesOf('CDE'), 40);
    th.Start;
    AssertEquals('read fully reassembles split payload',
      5, SocketReadFully(a, 5, 2000, got));
    AssertTrue('first byte A', got[0] = Ord('A'));
    AssertTrue('last byte E', got[4] = Ord('E'));
    th.WaitFor;
    th.Free;
  finally
    fpClose(a);
    fpClose(b);
  end;
end;

procedure TTlsTest.TestSocketReadFullyMapsTimeout;
var
  a, b: Integer;
  buf: array[0..0] of Byte;
  Raised: Boolean;
  t0: QWord;
begin
  AssertTrue('socketpair created', MakeSocketPair(a, b));
  try
    // idle socket: the deadline must surface as EHttpTimeout
    t0 := GetTickCount64;
    Raised := False;
    try
      SocketReadFully(a, 1, 120, buf);
    except
      on E: EHttpTimeout do
        Raised := True;
    end;
    AssertTrue('stalled read raises EHttpTimeout', Raised);
    AssertTrue('timeout honoured roughly', GetTickCount64 - t0 >= 100);
  finally
    fpClose(a);
    fpClose(b);
  end;
end;

procedure TTlsTest.TestTlsReadReassemblesChunks;
var
  Sock: TFakeTlsSocket;
  got: array[0..4] of Byte;
begin
  Sock := TFakeTlsSocket.Create(TMockSocket.Create, 'example.com', True);
  try
    Sock.SetAlpnBytes(BytesOf('h2'));
    Sock.Establish;
    // the TLS read loop must reassemble two short SSL_read results
    Sock.AddReadChunk(BytesOf('AB'));
    Sock.AddReadChunk(BytesOf('CDE'));
    AssertEquals('TLS read reassembles chunks', 5, Sock.Read(got, 5));
    AssertTrue('first byte A', got[0] = Ord('A'));
    AssertTrue('last byte E', got[4] = Ord('E'));
  finally
    Sock.Free;
  end;
end;

procedure TTlsTest.TestOpenSslAvailability;
begin
  // documents the runtime contract: OPENSSL_LIBPATH drives dynamic loading
  if OpenSslIsAvailable then
    AssertTrue('OpenSSL version reported', OpenSslVersionText <> '')
  else
    AssertTrue('OpenSSL absent without OPENSSL_LIBPATH (documented)', True);
end;

procedure TTlsTest.TestLiveNghttpdAlpnIfEnabled;
var
  Sock: IHttp2Socket;
begin
  if GetEnvironmentVariable('HTTP2_TLS_ITEST') <> '1' then
  begin
    AssertTrue('live nghttpd test skipped (set HTTP2_TLS_ITEST=1)', True);
    Exit;
  end;
  Sock := TTlsSocket.Dial('127.0.0.1', 8443, True, 3000);
  try
    AssertTrue('live TLS connection established', Sock.Connected);
    AssertEquals('nghttpd negotiated h2',
      'h2', (Sock as TTlsSocket).SelectedProtocol);
  finally
    Sock.Close;
  end;
end;

initialization
  RegisterTest(TTlsTest);
end.
