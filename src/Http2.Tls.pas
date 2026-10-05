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
  Http2.Errors;

const
  /// the single ALPN protocol this client offers (RFC 7540 section 3.3)
  cHttp2AlpnProtocol = 'h2';
  /// default connect/read/write deadline when none is set explicitly
  cDefaultSocketTimeoutMs = 30000;

type
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
  /// a plain (cleartext) TCP socket over fcl-net's TInetSocket
  TPlainSocket = class(TInterfacedObject, IHttp2Socket)
  private
    FSocket: TInetSocket;
    FHandle: Integer;
    FConnected: Boolean;
    FConnectTimeoutMs: Integer;
    FReadTimeoutMs: Integer;
    FWriteTimeoutMs: Integer;
  public
    constructor Create(const AHost: string; const APort: Word;
      const AConnectTimeoutMs: Integer = cDefaultSocketTimeoutMs);
    destructor Destroy; override;
    /// the underlying OS socket handle (needed to hand the socket to OpenSSL)
    property Handle: Integer read FHandle;
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

  /// a TLS socket over an existing connected IHttp2Socket (ALPN "h2")
  // - the crypto operations are exposed as virtual seams so tests can inject
  //   a scripted handshake result without touching the network
  TTlsSocket = class(TInterfacedObject, IHttp2Socket)
  private
    FTransport: IHttp2Socket;
    FHost: string;
    FInsecure: Boolean;
    FCtx: PSSL_CTX;
    FSsl: PSSL;
    FHandshaked: Boolean;
    FSelectedProtocol: string;
    FConnectTimeoutMs: Integer;
    FReadTimeoutMs: Integer;
    FWriteTimeoutMs: Integer;
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
      const AInsecure: Boolean = False);
    destructor Destroy; override;
    /// perform the TLS handshake and verify ALPN; raises on failure
    procedure Establish;
    /// dial, connect, and TLS-wrap in one call; the insecure flag is the
    /// explicit verify-off toggle (default False = verify the peer)
    class function Dial(const AHost: string; const APort: Word;
      const AInsecure: Boolean = False;
      const AConnectTimeoutMs: Integer = cDefaultSocketTimeoutMs): IHttp2Socket;
    property Insecure: Boolean read FInsecure;
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

const
  cTlsAlpnOffer: array[0..0] of string = (cHttp2AlpnProtocol);

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

{ TPlainSocket }

constructor TPlainSocket.Create(const AHost: string; const APort: Word;
  const AConnectTimeoutMs: Integer);
var
  opt: LongInt;
begin
  inherited Create;
  FConnectTimeoutMs := AConnectTimeoutMs;
  FReadTimeoutMs := cDefaultSocketTimeoutMs;
  FWriteTimeoutMs := cDefaultSocketTimeoutMs;
  try
    FSocket := TInetSocket.Create(AHost, APort, AConnectTimeoutMs);
  except
    on E: ESocketError do
      if E.Code = seConnectTimeOut then
        raise EHttpTimeout.CreateFmt('connect timed out after %d ms',
          [AConnectTimeoutMs])
      else
        raise EHttpConnectionError.CreateFmt('connect to %s:%d failed: %s',
          [AHost, APort, E.Message]);
  end;
  FHandle := FSocket.Handle;
  FConnected := True;
  opt := 1;
{$IFDEF DARWIN}
  fpSetSockOpt(FHandle, SOL_SOCKET, SO_NOSIGPIPE, @opt, SizeOf(opt));
{$ENDIF}
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

{ TTlsSocket }

constructor TTlsSocket.Create(const ATransport: IHttp2Socket;
  const AHost: string; const AInsecure: Boolean);
begin
  inherited Create;
  FTransport := ATransport;
  FHost := AHost;
  FInsecure := AInsecure;
  FConnectTimeoutMs := cDefaultSocketTimeoutMs;
  FReadTimeoutMs := cDefaultSocketTimeoutMs;
  FWriteTimeoutMs := cDefaultSocketTimeoutMs;
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
var
  Wire: TBytes;
begin
  Wire := AlpnProtocolList(cTlsAlpnOffer);
  Result := SSL_CTX_set_alpn_protos(ACtx, @Wire[0], Length(Wire));
end;

procedure TTlsSocket.ApplyVerifyMode(const ACtx: PSSL_CTX;
  const AMode: Integer);
begin
  if AMode <> SSL_VERIFY_NONE then
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
    if BindSocket(FSsl, GetSocketFd) <> 1 then
      raise EHttpConnectionError.Create('SSL_set_fd failed');
    // SSL_connect recv()s/send()s directly on the fd, so install the deadline
    // there as well: a stalled handshake must not block forever
    SetSocketTimeout(GetSocketFd, SOL_SOCKET, SO_RCVTIMEO, FConnectTimeoutMs);
    SetSocketTimeout(GetSocketFd, SOL_SOCKET, SO_SNDTIMEO, FConnectTimeoutMs);
    r := HandshakeConnect(FSsl);
    if r <> 1 then
      if SocketTimedOut then
        raise EHttpTimeout.CreateFmt('TLS handshake timed out after %d ms',
          [FConnectTimeoutMs])
      else
        raise EHttpConnectionError.CreateFmt(
          'TLS handshake failed (SSL_get_error=%d)', [LastSslError(FSsl, r)]);
    Alpn := SelectedAlpnBytes(FSsl);
    RequireH2Alpn(PByte(Alpn), Length(Alpn));
    FSelectedProtocol := AlpnSelectedName(PByte(Alpn), Length(Alpn));
    FHandshaked := True;
  except
    DestroySslHandle;
    DestroySslContext;
    raise;
  end;
end;

class function TTlsSocket.Dial(const AHost: string; const APort: Word;
  const AInsecure: Boolean; const AConnectTimeoutMs: Integer): IHttp2Socket;
var
  Transport: TPlainSocket;
  Sock: TTlsSocket;
begin
  Transport := TPlainSocket.Create(AHost, APort, AConnectTimeoutMs);
  Sock := TTlsSocket.Create(Transport, AHost, AInsecure);
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
      if (err = SSL_ERROR_ZERO_RETURN) or
         ((err = SSL_ERROR_SYSCALL) and (n = 0)) then
        Exit // clean close_notify, or peer closed the transport without one
      else if SocketTimedOut then
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
  SetSocketTimeout(GetSocketFd, SOL_SOCKET, SO_SNDTIMEO, FWriteTimeoutMs);
  base := PByte(@ABuffer);
  Result := 0;
  while Result < ACount do
  begin
    n := SslWriteBytes(FSsl, base + Result, ACount - Result);
    if n > 0 then
      Inc(Result, n)
    else
    begin
      err := LastSslError(FSsl, n);
      if SocketTimedOut then
        raise EHttpTimeout.CreateFmt('TLS write timed out after %d ms',
          [FWriteTimeoutMs])
      else
        raise EHttpConnectionClosed.CreateFmt(
          'TLS write failed (SSL_get_error=%d)', [err]);
    end;
  end;
end;

procedure TTlsSocket.Close;
begin
  if FSsl <> nil then
    SslShutdown(FSsl);
  DestroySslHandle;
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

end.
