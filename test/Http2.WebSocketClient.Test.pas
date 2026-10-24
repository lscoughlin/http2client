/// WebSocket client tests against a scripted loopback server
/// (doc/design/websocket.md).
// - the server is a raw TCP socket that plays one connection from a script
//   method: it checks the handshake bytes, reads masked client frames and
//   sends unmasked server frames, so every wire rule is observed rather than
//   assumed.
// - no test sleeps to wait for another thread; listener events signal an
//   event and the tests wait on it with a bounded timeout.
unit Http2.WebSocketClient.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$interfaces com}

interface

uses
  SysUtils, Classes, SyncObjs, Sockets, BaseUnix, fpcunit, testregistry,
  Http2.Errors, Http2.Proxy, Http2.Tls, Http2.Client, Http2.WebSocket,
  Http2.WebSocketClient;

type
  TWsTestServer = class;
  TWsScript = procedure(const S: TWsTestServer) of object;

  /// plays one accepted connection from a script
  TWsTestServer = class(TThread)
  private
    FListenFd: Integer;
    FFd: Integer;
    FParser: TWebSocketFrameParser;
    FScript: TWsScript;
  protected
    procedure Execute; override;
  public
    Port: Word;
    Head: string;           // the request head the client sent
    Failure: string;        // a script exception, for the test to assert on
    Done: TEvent;
    Release: TEvent;        // set by the test when the script may end
    constructor Create(const AScript: TWsScript);
    destructor Destroy; override;
    procedure ReadHead;
    function FdForTest: Integer;
    function HeaderValue(const AName: string): string;
    procedure SendRaw(const AData: AnsiString); overload;
    procedure SendRaw(const AData: TBytes); overload;
    procedure Accept(const AExtra: string = ''; const ATail: TBytes = nil);
    procedure SendFrame(const AOp: Byte; const AFin: Boolean; const A: TBytes);
    procedure SendText(const S: string);
    function ReadFrame: TWsFrame;
    function TryReadFrame(out F: TWsFrame): Boolean;
    procedure CloseConnection;
    /// wake a script thread still blocked in accept
    procedure ShutdownListener;
  end;

  /// records listener events; waits are bounded
  TRecorder = class(TWebSocketListener)
  private
    FKeepSocket: Boolean;
    FLock: TCriticalSection;
    FEvent: TEvent;
    FLog: TStringList;
    FRequestOnOpen: Integer;
    procedure Add(const S: string);
  public
    Socket: IWebSocket;
    ErrorClass: string;
    ErrorCode: Integer;
    property KeepSocket: Boolean read FKeepSocket write FKeepSocket;
    constructor Create(const ARequestOnOpen: Integer = 0);
    destructor Destroy; override;
    function Count: Integer;
    function Item(const I: Integer): string;
    function WaitCount(const N: Integer; const AMs: Integer = 5000): Boolean;
    function WaitFor(const APrefix: string; const AMs: Integer = 5000): Boolean;
    procedure OnOpen(const ASocket: IWebSocket); override;
    procedure OnText(const ASocket: IWebSocket; const AText: string;
      const ALast: Boolean); override;
    procedure OnBytes(const ASocket: IWebSocket; const AData: TBytes;
      const ALast: Boolean); override;
    procedure OnPing(const ASocket: IWebSocket; const AData: TBytes); override;
    procedure OnPong(const ASocket: IWebSocket; const AData: TBytes); override;
    procedure OnClose(const ASocket: IWebSocket; const AStatusCode: Integer;
      const AReason: string); override;
    procedure OnError(const ASocket: IWebSocket;
      const AError: Exception); override;
  end;

  TWebSocketClientTest = class(TTestCase)
  private
    FServer: TWsTestServer;
    FRec: TRecorder;
    FRecRef: IWebSocketListener;
    FClient: IHttpClient;
    procedure Start(const AScript: TWsScript; const ARequestOnOpen: Integer = 0);
    function Url(const APath: string = '/'): string;
    function Open(const ARequest: IWebSocketRequest = nil): IWebSocket;
    procedure Finish;
    // scripts
    procedure ScriptEcho(const S: TWsTestServer);
    procedure ScriptThreeTexts(const S: TWsTestServer);
    procedure ScriptPing(const S: TWsTestServer);
    procedure ScriptClientClose(const S: TWsTestServer);
    procedure ScriptServerClose(const S: TWsTestServer);
    procedure ScriptMaskedFrame(const S: TWsTestServer);
    procedure ScriptBadUtf8(const S: TWsTestServer);
    procedure ScriptReject401(const S: TWsTestServer);
    procedure ScriptWrongAccept(const S: TWsTestServer);
    procedure ScriptSubprotocol(const S: TWsTestServer);
    procedure ScriptLeftover(const S: TWsTestServer);
    procedure ScriptCollect(const S: TWsTestServer);
    procedure ScriptSilent(const S: TWsTestServer);
    procedure ScriptBigEcho(const S: TWsTestServer);
    procedure ScriptDrop(const S: TWsTestServer);
    procedure ScriptFragments(const S: TWsTestServer);
    procedure ScriptFragmentedText(const S: TWsTestServer);
    procedure ScriptNoReply(const S: TWsTestServer);
    procedure ScriptCountPings(const S: TWsTestServer);
    procedure ScriptTooBig(const S: TWsTestServer);
    procedure ScriptOneText(const S: TWsTestServer);
    procedure ScriptStreamIgnoreClose(const S: TWsTestServer);
    procedure ScriptCloseThenHalfClose(const S: TWsTestServer);
  protected
    procedure TearDown; override;
  published
    procedure TestHandshakeRequestAndEchoWithMasking;
    procedure TestDemandHoldsBackDelivery;
    procedure TestPingIsAnsweredBeforeTheCallback;
    procedure TestClientCloseHandshake;
    procedure TestServerCloseIsEchoed;
    procedure TestMaskedServerFrameClosesWith1002;
    procedure TestBadUtf8ClosesWith1007;
    procedure TestHandshakeRefusalCarriesTheResponse;
    procedure TestWrongAcceptIsRefused;
    procedure TestSubprotocolIsReported;
    procedure TestBytesAfterTheUpgradeHeadAreKept;
    procedure TestConcurrentSendsAreWrittenWhole;
    procedure TestFragmentedSend;
    procedure TestMixedKindsInOneMessageRaise;
    procedure TestLargeBinaryEcho;
    procedure TestAbortStopsEverything;
    procedure TestSendAfterCloseRaises;
    procedure TestConnectTimeout;
    procedure TestDropWithoutCloseIsAnError;
    procedure TestFragmentedReceive;
    procedure TestSelectorSeesTheMappedUrl;
    procedure TestFactoryWithoutHttp1DialIsRefused;
    procedure TestAutoRequest;
    procedure TestCloseWithoutAnswerTimesOut;
    procedure TestPingIntervalSendsPingsAndGivesUp;
    procedure TestListenerExceptionIsReportedAndAborts;
    procedure TestOverLimitMessageClosesWith1009;
    procedure TestDroppedSocketKeepsDeliveringUntilItEnds;
    procedure TestMaskKeyIsDrawnPerFrame;
    procedure TestCloseTimeoutFiresWhileFramesKeepArriving;
    procedure TestServerCloseWithNoDemandReleasesTheSocket;
    procedure TestListenerHoldingTheSocketDoesNotLeakTheConnection;
  end;

implementation

{ TWsTestServer }

constructor TWsTestServer.Create(const AScript: TWsScript);
var
  Addr: TSockAddr;
  ALen, One: LongInt;
begin
  inherited Create(True);
  FScript := AScript;
  FFd := -1;
  Done := TEvent.Create(nil, True, False, '');
  Release := TEvent.Create(nil, True, False, '');
  FParser := TWebSocketFrameParser.Create;
  FParser.RequireMasked := True;
  FListenFd := fpsocket(AF_INET, SOCK_STREAM, 0);
  One := 1;
  fpSetSockOpt(FListenFd, SOL_SOCKET, SO_REUSEADDR, @One, SizeOf(One));
  FillChar(Addr, SizeOf(Addr), 0);
  Addr.sin_family := AF_INET;
  Addr.sin_port := htons(0);
  Addr.sin_addr.s_addr := htonl($7f000001);
  if (fpbind(FListenFd, @Addr, SizeOf(Addr)) <> 0) or
     (fplisten(FListenFd, 4) <> 0) then
    raise Exception.Create('cannot listen on loopback');
  ALen := SizeOf(Addr);
  fpgetsockname(FListenFd, @Addr, @ALen);
  Port := ntohs(Addr.sin_port);
end;

destructor TWsTestServer.Destroy;
begin
  if FFd >= 0 then
  begin
    fpshutdown(FFd, SHUT_RDWR);
    fpclose(FFd);
  end;
  if FListenFd >= 0 then
  begin
    fpshutdown(FListenFd, SHUT_RDWR);
    fpclose(FListenFd);
  end;
  FParser.Free;
  Release.Free;
  Done.Free;
  inherited Destroy;
end;

procedure TWsTestServer.Execute;
var
  One: LongInt;
begin
  try
    FFd := fpaccept(FListenFd, nil, nil);
    if FFd < 0 then
      Exit;
    One := 1;
    {$IFDEF DARWIN}
    fpSetSockOpt(FFd, SOL_SOCKET, SO_NOSIGPIPE, @One, SizeOf(One));
    {$ENDIF}
    FScript(Self);
  except
    on E: Exception do
      Failure := E.ClassName + ': ' + E.Message;
  end;
  Done.SetEvent;
end;

function TWsTestServer.FdForTest: Integer;
begin
  Result := FFd;
end;

procedure TWsTestServer.ReadHead;
var
  C: AnsiChar;
  N: Integer;
begin
  Head := '';
  while Pos(#13#10#13#10, Head) = 0 do
  begin
    N := fprecv(FFd, @C, 1, 0);
    if N <= 0 then
      raise Exception.Create('client closed before the head ended');
    Head := Head + C;
  end;
end;

function TWsTestServer.HeaderValue(const AName: string): string;
var
  L: TStringList;
  I, P: Integer;
begin
  Result := '';
  L := TStringList.Create;
  try
    L.Text := Head;
    for I := 1 to L.Count - 1 do
    begin
      P := Pos(':', L[I]);
      if (P > 0) and SameText(Trim(Copy(L[I], 1, P - 1)), AName) then
        Exit(Trim(Copy(L[I], P + 1, MaxInt)));
    end;
  finally
    L.Free;
  end;
end;

procedure TWsTestServer.SendRaw(const AData: AnsiString);
var
  Sent, N: Integer;
begin
  Sent := 0;
  while Sent < Length(AData) do
  begin
    N := fpsend(FFd, @AData[1 + Sent], Length(AData) - Sent, 0);
    if N <= 0 then
      raise Exception.Create('send failed');
    Inc(Sent, N);
  end;
end;

procedure TWsTestServer.SendRaw(const AData: TBytes);
var
  S: AnsiString;
begin
  SetLength(S, Length(AData));
  if Length(AData) > 0 then
    Move(AData[0], S[1], Length(AData));
  SendRaw(S);
end;

procedure TWsTestServer.Accept(const AExtra: string; const ATail: TBytes);
var
  Key, Resp: string;
  Wire: TBytes;
begin
  Key := HeaderValue('Sec-WebSocket-Key');
  Resp := 'HTTP/1.1 101 Switching Protocols'#13#10 +
    'Upgrade: websocket'#13#10'Connection: Upgrade'#13#10 +
    'Sec-WebSocket-Accept: ' + WsComputeAccept(Key) + #13#10 + AExtra + #13#10;
  SetLength(Wire, Length(Resp) + Length(ATail));
  Move(Resp[1], Wire[0], Length(Resp));
  if Length(ATail) > 0 then
    Move(ATail[0], Wire[Length(Resp)], Length(ATail));
  SendRaw(Wire);
end;

procedure TWsTestServer.SendFrame(const AOp: Byte; const AFin: Boolean;
  const A: TBytes);
var
  K: TWsMaskKey;
begin
  FillChar(K, SizeOf(K), 0);
  SendRaw(WsEncodeFrame(AOp, AFin, A, False, K));
end;

procedure TWsTestServer.SendText(const S: string);
var
  B: TBytes;
begin
  SetLength(B, Length(S));
  if S <> '' then
    Move(S[1], B[0], Length(S));
  SendFrame(cWsOpText, True, B);
end;

function TWsTestServer.TryReadFrame(out F: TWsFrame): Boolean;
var
  Buf: array[0..16383] of Byte;
  N: Integer;
begin
  while not FParser.Next(F) do
  begin
    N := fprecv(FFd, @Buf[0], SizeOf(Buf), 0);
    if N <= 0 then
      Exit(False);
    FParser.Feed(Buf[0], N);
  end;
  Result := True;
end;

function TWsTestServer.ReadFrame: TWsFrame;
begin
  if not TryReadFrame(Result) then
    raise Exception.Create('client closed before a frame arrived');
end;

procedure TWsTestServer.CloseConnection;
begin
  if FFd >= 0 then
  begin
    fpshutdown(FFd, SHUT_RDWR);
    fpclose(FFd);
    FFd := -1;
  end;
end;

procedure TWsTestServer.ShutdownListener;
begin
  if FListenFd >= 0 then
    fpshutdown(FListenFd, SHUT_RDWR);
end;

{ TRecorder }

constructor TRecorder.Create(const ARequestOnOpen: Integer);
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FEvent := TEvent.Create(nil, True, False, '');
  FLog := TStringList.Create;
  FRequestOnOpen := ARequestOnOpen;
  FKeepSocket := True;
end;

destructor TRecorder.Destroy;
begin
  FLog.Free;
  FEvent.Free;
  FLock.Free;
  inherited Destroy;
end;

procedure TRecorder.Add(const S: string);
begin
  FLock.Enter;
  try
    FLog.Add(S);
  finally
    FLock.Leave;
  end;
  FEvent.SetEvent;
end;

function TRecorder.Count: Integer;
begin
  FLock.Enter;
  try
    Result := FLog.Count;
  finally
    FLock.Leave;
  end;
end;

function TRecorder.Item(const I: Integer): string;
begin
  FLock.Enter;
  try
    if I < FLog.Count then Result := FLog[I] else Result := '';
  finally
    FLock.Leave;
  end;
end;

function TRecorder.WaitCount(const N: Integer; const AMs: Integer): Boolean;
var
  Deadline: QWord;
begin
  Deadline := GetTickCount64 + QWord(AMs);
  while Count < N do
  begin
    if GetTickCount64 >= Deadline then
      Exit(False);
    FEvent.ResetEvent;
    if Count >= N then
      Break;
    FEvent.WaitFor(50);
  end;
  Result := True;
end;

function TRecorder.WaitFor(const APrefix: string; const AMs: Integer): Boolean;
var
  Deadline: QWord;
  I: Integer;
begin
  Deadline := GetTickCount64 + QWord(AMs);
  repeat
    FEvent.ResetEvent;
    for I := 0 to Count - 1 do
      if Copy(Item(I), 1, Length(APrefix)) = APrefix then
        Exit(True);
    FEvent.WaitFor(50);
  until GetTickCount64 >= Deadline;
  Result := False;
end;

procedure TRecorder.OnOpen(const ASocket: IWebSocket);
begin
  if FKeepSocket then
    Socket := ASocket;
  Add('open');
  if FRequestOnOpen > 0 then
    ASocket.Request(FRequestOnOpen);
end;

procedure TRecorder.OnText(const ASocket: IWebSocket; const AText: string;
  const ALast: Boolean);
begin
  Add('text:' + AText + ':' + IntToStr(Ord(ALast)));
end;

procedure TRecorder.OnBytes(const ASocket: IWebSocket; const AData: TBytes;
  const ALast: Boolean);
begin
  Add('bytes:' + IntToStr(Length(AData)) + ':' + IntToStr(Ord(ALast)));
end;

procedure TRecorder.OnPing(const ASocket: IWebSocket; const AData: TBytes);
begin
  Add('ping:' + IntToStr(Length(AData)));
end;

procedure TRecorder.OnPong(const ASocket: IWebSocket; const AData: TBytes);
begin
  Add('pong:' + IntToStr(Length(AData)));
end;

procedure TRecorder.OnClose(const ASocket: IWebSocket;
  const AStatusCode: Integer; const AReason: string);
begin
  Add('close:' + IntToStr(AStatusCode) + ':' + AReason);
end;

procedure TRecorder.OnError(const ASocket: IWebSocket; const AError: Exception);
begin
  ErrorClass := AError.ClassName;
  if AError is EHttpWebSocketProtocolError then
    ErrorCode := EHttpWebSocketProtocolError(AError).CloseCode;
  Add('error:' + AError.ClassName);
end;

{ TWebSocketClientTest }

procedure TWebSocketClientTest.TearDown;
begin
  Finish;
  inherited TearDown;
end;

procedure TWebSocketClientTest.Finish;
begin
  if FRec <> nil then
  begin
    if FRec.Socket <> nil then
    begin
      FRec.Socket.Abort;
      FRec.Socket := nil;
    end;
  end;
  if FServer <> nil then
  begin
    FServer.Terminate;
    FServer.Release.SetEvent;
    FServer.CloseConnection;
    fpshutdown(FServer.FListenFd, SHUT_RDWR);
    FServer.Done.WaitFor(3000);
    FServer.Free;
    FServer := nil;
  end;
  FRecRef := nil;
  FRec := nil;
  FClient := nil;
end;

procedure TWebSocketClientTest.Start(const AScript: TWsScript;
  const ARequestOnOpen: Integer);
begin
  FServer := TWsTestServer.Create(AScript);
  FServer.Start;
  FRec := TRecorder.Create(ARequestOnOpen);
  FRecRef := FRec;
  FClient := THttpClientFactory.Create.Build;
end;

function TWebSocketClientTest.Url(const APath: string): string;
begin
  Result := 'ws://127.0.0.1:' + IntToStr(FServer.Port) + APath;
end;

function TWebSocketClientTest.Open(const ARequest: IWebSocketRequest): IWebSocket;
var
  R: IWebSocketRequest;
begin
  R := ARequest;
  if R = nil then
    R := TWebSocketRequest.Create(Url('/chat?room=1'), FRecRef);
  Result := FClient.Send(R);
end;

procedure TWebSocketClientTest.ScriptEcho(const S: TWsTestServer);
var
  F: TWsFrame;
begin
  S.ReadHead;
  S.Accept;
  while S.TryReadFrame(F) do
  begin
    if F.Opcode = cWsOpClose then
    begin
      S.SendFrame(cWsOpClose, True, F.Payload);
      Break;
    end;
    S.SendFrame(F.Opcode, F.Fin, F.Payload);
  end;
end;

procedure TWebSocketClientTest.TestHandshakeRequestAndEchoWithMasking;
var
  Sock: IWebSocket;
  Name: string;
  Raw: TBytes;
begin
  Start(ScriptEcho, 4);
  Sock := Open;
  AssertTrue('open', FRec.WaitCount(1));
  Sock.SendText('hello');
  AssertTrue('echo', FRec.WaitCount(2));
  AssertEquals('text:hello:1', FRec.Item(1));
  SetLength(Raw, 3);
  Raw[0] := 1; Raw[1] := 2; Raw[2] := 3;
  Sock.SendBinary(Raw);
  AssertTrue('echo bytes', FRec.WaitCount(3));
  AssertEquals('bytes:3:1', FRec.Item(2));
  Name := FServer.Head;
  AssertTrue('request line', Pos('GET /chat?room=1 HTTP/1.1'#13#10, Name) = 1);
  AssertEquals('127.0.0.1:' + IntToStr(FServer.Port), FServer.HeaderValue('Host'));
  AssertEquals('websocket', FServer.HeaderValue('Upgrade'));
  AssertEquals('Upgrade', FServer.HeaderValue('Connection'));
  AssertEquals('13', FServer.HeaderValue('Sec-WebSocket-Version'));
  AssertEquals('key is 16 octets', 24, Length(FServer.HeaderValue('Sec-WebSocket-Key')));
  AssertEquals('no subprotocol sent', '', FServer.HeaderValue('Sec-WebSocket-Protocol'));
  AssertEquals('', FServer.Failure);
end;

procedure TWebSocketClientTest.ScriptThreeTexts(const S: TWsTestServer);
begin
  S.ReadHead;
  S.Accept;
  S.SendText('one');
  S.SendText('two');
  S.SendText('three');
  S.Release.WaitFor(3000);
end;

procedure TWebSocketClientTest.TestDemandHoldsBackDelivery;
var
  Sock: IWebSocket;
begin
  Start(ScriptThreeTexts, 0);
  Sock := Open;
  AssertTrue('open', FRec.WaitCount(1));
  AssertFalse('nothing without demand', FRec.WaitCount(2, 300));
  Sock.Request(2);
  AssertTrue('two delivered', FRec.WaitCount(3));
  AssertEquals('text:one:1', FRec.Item(1));
  AssertEquals('text:two:1', FRec.Item(2));
  AssertFalse('third waits', FRec.WaitCount(4, 300));
  Sock.Request(1);
  AssertTrue('third delivered', FRec.WaitCount(4));
  AssertEquals('text:three:1', FRec.Item(3));
  try
    Sock.Request(0);
    Fail('Request(0) must raise');
  except
    on EHttpWebSocketError do ;
  end;
end;

procedure TWebSocketClientTest.ScriptPing(const S: TWsTestServer);
var
  F: TWsFrame;
  B: TBytes;
begin
  S.ReadHead;
  S.Accept;
  SetLength(B, 3);
  B[0] := 97; B[1] := 98; B[2] := 99;
  S.SendFrame(cWsOpPing, True, B);
  F := S.ReadFrame;
  if (F.Opcode <> cWsOpPong) or (Length(F.Payload) <> 3) or (F.Payload[0] <> 97) then
    S.Failure := 'expected a pong echoing abc';
  S.Release.WaitFor(1000);
end;

procedure TWebSocketClientTest.TestPingIsAnsweredBeforeTheCallback;
begin
  // demand stays 0: the pong still goes out, the callback waits
  Start(ScriptPing, 0);
  Open;
  AssertTrue('open', FRec.WaitCount(1));
  AssertTrue('server saw the pong', FServer.Done.WaitFor(3000) = wrSignaled);
  AssertEquals('', FServer.Failure);
  AssertEquals('callback held back', 1, FRec.Count);
  FRec.Socket.Request(1);
  AssertTrue('ping delivered', FRec.WaitCount(2));
  AssertEquals('ping:3', FRec.Item(1));
end;

procedure TWebSocketClientTest.ScriptClientClose(const S: TWsTestServer);
var
  F: TWsFrame;
begin
  S.ReadHead;
  S.Accept;
  F := S.ReadFrame;
  if (F.Opcode <> cWsOpClose) or (Length(F.Payload) < 2) or
     (F.Payload[0] <> $03) or (F.Payload[1] <> $E8) then
    S.Failure := 'expected close 1000';
  S.SendFrame(cWsOpClose, True, F.Payload);
  S.CloseConnection;
end;

procedure TWebSocketClientTest.TestClientCloseHandshake;
var
  Sock: IWebSocket;
begin
  Start(ScriptClientClose, 1);
  Sock := Open;
  AssertTrue('open', FRec.WaitCount(1));
  Sock.Close(1000, 'bye');
  AssertTrue('output closed at once', Sock.OutputClosed);
  AssertTrue('close reported', FRec.WaitCount(2));
  AssertEquals('close:1000:bye', FRec.Item(1));
  AssertTrue('input closed', Sock.InputClosed);
  AssertEquals('', FServer.Failure);
  Sock.Close;                       // a second close does nothing
  AssertEquals('one terminal callback', 2, FRec.Count);
end;

procedure TWebSocketClientTest.ScriptServerClose(const S: TWsTestServer);
var
  F: TWsFrame;
begin
  S.ReadHead;
  S.Accept;
  S.SendFrame(cWsOpClose, True, WsBuildClosePayload(1001, 'going'));
  F := S.ReadFrame;
  if (F.Opcode <> cWsOpClose) or (Length(F.Payload) <> 2) or
     (F.Payload[1] <> $E9) then
    S.Failure := 'expected an echoed 1001';
  S.CloseConnection;
end;

procedure TWebSocketClientTest.TestServerCloseIsEchoed;
begin
  Start(ScriptServerClose, 0);
  Open;
  AssertTrue('open', FRec.WaitCount(1));
  // the echo does not wait for demand; the report does
  AssertTrue('server saw the echo', FServer.Done.WaitFor(3000) = wrSignaled);
  AssertEquals('', FServer.Failure);
  FRec.Socket.Request(1);
  AssertTrue(FRec.WaitCount(2));
  AssertEquals('close:1001:going', FRec.Item(1));
  AssertTrue(FRec.Socket.InputClosed);
  AssertTrue(FRec.Socket.OutputClosed);
end;

procedure TWebSocketClientTest.ScriptMaskedFrame(const S: TWsTestServer);
var
  F: TWsFrame;
  K: TWsMaskKey;
  Raw: TBytes;
  B: TBytes;
begin
  S.ReadHead;
  S.Accept;
  K[0] := 1; K[1] := 2; K[2] := 3; K[3] := 4;
  SetLength(B, 1);
  B[0] := 65;
  Raw := WsEncodeFrame(cWsOpText, True, B, True, K);
  S.SendRaw(Raw);
  F := S.ReadFrame;
  if (F.Opcode <> cWsOpClose) or (Length(F.Payload) < 2) or
     (F.Payload[0] * 256 + F.Payload[1] <> 1002) then
    S.Failure := 'expected close 1002';
  S.CloseConnection;
end;

procedure TWebSocketClientTest.TestMaskedServerFrameClosesWith1002;
begin
  Start(ScriptMaskedFrame, 1);
  Open;
  AssertTrue('error reported', FRec.WaitCount(2));
  AssertEquals('error:EHttpWebSocketProtocolError', FRec.Item(1));
  AssertEquals(1002, FRec.ErrorCode);
  AssertTrue('server saw 1002', FServer.Done.WaitFor(3000) = wrSignaled);
  AssertEquals('', FServer.Failure);
  AssertEquals('no OnClose after a failure', 2, FRec.Count);
end;

procedure TWebSocketClientTest.ScriptBadUtf8(const S: TWsTestServer);
var
  F: TWsFrame;
  B: TBytes;
begin
  S.ReadHead;
  S.Accept;
  SetLength(B, 2);
  B[0] := 65; B[1] := $FF;
  S.SendFrame(cWsOpText, True, B);
  F := S.ReadFrame;
  if (F.Opcode <> cWsOpClose) or (Length(F.Payload) < 2) or
     (F.Payload[0] * 256 + F.Payload[1] <> 1007) then
    S.Failure := 'expected close 1007';
  S.CloseConnection;
end;

procedure TWebSocketClientTest.TestBadUtf8ClosesWith1007;
begin
  Start(ScriptBadUtf8, 1);
  Open;
  AssertTrue(FRec.WaitCount(2));
  AssertEquals(1007, FRec.ErrorCode);
  AssertTrue(FServer.Done.WaitFor(3000) = wrSignaled);
  AssertEquals('', FServer.Failure);
end;

procedure TWebSocketClientTest.ScriptReject401(const S: TWsTestServer);
begin
  S.ReadHead;
  S.SendRaw('HTTP/1.1 401 Unauthorized'#13#10'WWW-Authenticate: Basic'#13#10 +
    'Content-Length: 6'#13#10#13#10'denied');
end;

procedure TWebSocketClientTest.TestHandshakeRefusalCarriesTheResponse;
var
  Raised: Boolean;
begin
  Start(ScriptReject401);
  Raised := False;
  try
    Open;
  except
    on E: EHttpWebSocketHandshakeError do
    begin
      Raised := True;
      AssertEquals(401, E.StatusCode);
      AssertEquals('denied', E.Body);
      AssertEquals('Basic', E.Header('www-authenticate'));
    end;
  end;
  AssertTrue('raised', Raised);
  AssertEquals('listener never opened', 0, FRec.Count);
end;

procedure TWebSocketClientTest.ScriptWrongAccept(const S: TWsTestServer);
begin
  S.ReadHead;
  S.SendRaw('HTTP/1.1 101 Switching Protocols'#13#10'Upgrade: websocket'#13#10 +
    'Connection: Upgrade'#13#10'Sec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA='#13#10#13#10);
end;

procedure TWebSocketClientTest.TestWrongAcceptIsRefused;
var
  Raised: Boolean;
begin
  Start(ScriptWrongAccept);
  Raised := False;
  try
    Open;
  except
    on EHttpWebSocketHandshakeError do
      Raised := True;
  end;
  AssertTrue(Raised);
end;

procedure TWebSocketClientTest.ScriptSubprotocol(const S: TWsTestServer);
begin
  S.ReadHead;
  if S.HeaderValue('Sec-WebSocket-Protocol') <> 'chat, superchat' then
    S.Failure := 'subprotocols not offered as a list';
  S.Accept('Sec-WebSocket-Protocol: superchat'#13#10);
  S.Release.WaitFor(1000);
end;

procedure TWebSocketClientTest.TestSubprotocolIsReported;
var
  Sock: IWebSocket;
  Names: TArray<string>;
begin
  Start(ScriptSubprotocol);
  SetLength(Names, 2);
  Names[0] := 'chat'; Names[1] := 'superchat';
  Sock := Open(TWebSocketRequest.Create(Url, FRecRef).WithSubprotocols(Names));
  AssertEquals('superchat', Sock.Subprotocol);
  AssertTrue(FRec.WaitCount(1));
  AssertEquals('', FServer.Failure);
end;

procedure TWebSocketClientTest.ScriptLeftover(const S: TWsTestServer);
var
  K: TWsMaskKey;
  B: TBytes;
begin
  S.ReadHead;
  FillChar(K, SizeOf(K), 0);
  SetLength(B, 2);
  B[0] := 104; B[1] := 105;
  // the first frame rides in the same write as the upgrade head
  S.Accept('', WsEncodeFrame(cWsOpText, True, B, False, K));
  S.Release.WaitFor(1000);
end;

procedure TWebSocketClientTest.TestBytesAfterTheUpgradeHeadAreKept;
begin
  Start(ScriptLeftover, 1);
  Open;
  AssertTrue(FRec.WaitCount(2));
  AssertEquals('text:hi:1', FRec.Item(1));
end;

procedure TWebSocketClientTest.ScriptCollect(const S: TWsTestServer);
var
  F: TWsFrame;
  N: Integer;
  Seen: TStringList;
  I: Integer;
  Msg: string;
begin
  S.ReadHead;
  S.Accept;
  Seen := TStringList.Create;
  try
    Seen.Sorted := True;
    for N := 1 to 200 do
    begin
      F := S.ReadFrame;
      if (F.Opcode <> cWsOpText) or (not F.Fin) then
        S.Failure := 'unexpected frame';
      begin
        SetString(Msg, PAnsiChar(@F.Payload[0]), Length(F.Payload));
        Seen.Add(Msg);
      end;
    end;
    for I := 0 to 199 do
      if Seen.IndexOf(Format('t%d-m%.3d', [I div 50, I mod 50])) < 0 then
        S.Failure := 'a message arrived damaged or missing';
  finally
    Seen.Free;
  end;
  S.SendText('done');
end;

type
  TSender = class(TThread)
  private
    FSock: IWebSocket;
    FIndex: Integer;
  protected
    procedure Execute; override;
  public
    constructor Create(const ASock: IWebSocket; const AIndex: Integer);
  end;

constructor TSender.Create(const ASock: IWebSocket; const AIndex: Integer);
begin
  FSock := ASock;
  FIndex := AIndex;
  inherited Create(False);
  FreeOnTerminate := False;
end;

procedure TSender.Execute;
var
  I: Integer;
begin
  for I := 0 to 49 do
    FSock.SendText(Format('t%d-m%.3d', [FIndex, I]));
end;

procedure TWebSocketClientTest.TestConcurrentSendsAreWrittenWhole;
var
  Sock: IWebSocket;
  T: array[0..3] of TSender;
  I: Integer;
begin
  Start(ScriptCollect, 1);
  Sock := Open;
  AssertTrue(FRec.WaitCount(1));
  for I := 0 to 3 do
    T[I] := TSender.Create(Sock, I);
  for I := 0 to 3 do
  begin
    T[I].WaitFor;
    T[I].Free;
  end;
  AssertTrue('server finished', FRec.WaitCount(2, 10000));
  AssertEquals('text:done:1', FRec.Item(1));
  AssertEquals('', FServer.Failure);
end;

procedure TWebSocketClientTest.ScriptFragments(const S: TWsTestServer);
var
  F1, F2, F3: TWsFrame;
begin
  S.ReadHead;
  S.Accept;
  F1 := S.ReadFrame;
  F2 := S.ReadFrame;
  F3 := S.ReadFrame;
  if (F1.Opcode <> cWsOpText) or F1.Fin or (F2.Opcode <> cWsOpContinuation) or
     F2.Fin or (F3.Opcode <> cWsOpContinuation) or (not F3.Fin) then
    S.Failure := 'fragmentation not as sent';
  S.Release.WaitFor(1000);
end;

procedure TWebSocketClientTest.TestFragmentedSend;
var
  Sock: IWebSocket;
begin
  Start(ScriptFragments);
  Sock := Open;
  Sock.SendText('a', False);
  Sock.SendText('b', False);
  Sock.SendText('c', True);
  AssertTrue(FServer.Done.WaitFor(3000) = wrSignaled);
  AssertEquals('', FServer.Failure);
end;

procedure TWebSocketClientTest.TestMixedKindsInOneMessageRaise;
var
  Sock: IWebSocket;
  Raised: Boolean;
  B: TBytes;
begin
  Start(ScriptFragments);
  Sock := Open;
  Sock.SendText('a', False);
  Raised := False;
  SetLength(B, 1);
  try
    Sock.SendBinary(B);
  except
    on EHttpWebSocketError do
      Raised := True;
  end;
  AssertTrue('binary inside an open text message', Raised);
  // an invalid text payload is refused before anything is written
  Raised := False;
  try
    Sock.SendText(#$FF#$FE, True);
  except
    on EHttpWebSocketError do
      Raised := True;
  end;
  AssertTrue('invalid UTF-8', Raised);
  Sock.SendText('b', False);
  Sock.SendText('c', True);
  AssertTrue(FServer.Done.WaitFor(3000) = wrSignaled);
  AssertEquals('', FServer.Failure);
end;

procedure TWebSocketClientTest.ScriptBigEcho(const S: TWsTestServer);
var
  F: TWsFrame;
begin
  S.ReadHead;
  S.Accept;
  F := S.ReadFrame;
  S.SendFrame(cWsOpBinary, True, F.Payload);
  S.Release.WaitFor(2000);
end;

procedure TWebSocketClientTest.TestLargeBinaryEcho;
var
  Sock: IWebSocket;
  B: TBytes;
begin
  Start(ScriptBigEcho, 1);
  Sock := Open;
  SetLength(B, 1024 * 1024);
  FillChar(B[0], Length(B), $A5);
  Sock.SendBinary(B);
  AssertTrue(FRec.WaitCount(2, 10000));
  AssertEquals('bytes:1048576:1', FRec.Item(1));
end;

procedure TWebSocketClientTest.TestAbortStopsEverything;
var
  Sock: IWebSocket;
  Raised: Boolean;
begin
  Start(ScriptThreeTexts);
  Sock := Open;
  AssertTrue(FRec.WaitCount(1));
  Sock.Abort;
  AssertTrue(Sock.InputClosed);
  AssertTrue(Sock.OutputClosed);
  Raised := False;
  try
    Sock.SendText('x');
  except
    on EHttpWebSocketClosedError do
      Raised := True;
  end;
  AssertTrue('send after abort', Raised);
  AssertFalse('no delivery after abort', FRec.WaitCount(2, 300));
end;

procedure TWebSocketClientTest.TestSendAfterCloseRaises;
var
  Sock: IWebSocket;
  Raised: Boolean;
begin
  Start(ScriptClientClose);
  Sock := Open;
  Sock.Close(1000, '');
  Raised := False;
  try
    Sock.SendText('late');
  except
    on EHttpWebSocketClosedError do
      Raised := True;
  end;
  AssertTrue(Raised);
  Raised := False;
  try
    Sock.Close(1005, '');
  except
    on EHttpWebSocketError do
      Raised := True;
  end;
  AssertTrue('1005 cannot be sent', Raised);
end;

procedure TWebSocketClientTest.ScriptSilent(const S: TWsTestServer);
begin
  S.ReadHead;
  S.Release.WaitFor(3000);
end;

procedure TWebSocketClientTest.TestConnectTimeout;
var
  Raised: Boolean;
  Started: QWord;
begin
  Start(ScriptSilent);
  Raised := False;
  Started := GetTickCount64;
  try
    Open(TWebSocketRequest.Create(Url, FRecRef).WithConnectTimeoutMs(400));
  except
    on EHttpTimeout do
      Raised := True;
  end;
  AssertTrue('timed out', Raised);
  AssertTrue('promptly', GetTickCount64 - Started < 3000);
  AssertEquals(0, FRec.Count);
end;

procedure TWebSocketClientTest.ScriptDrop(const S: TWsTestServer);
begin
  S.ReadHead;
  S.Accept;
  S.CloseConnection;
end;

procedure TWebSocketClientTest.TestDropWithoutCloseIsAnError;
begin
  Start(ScriptDrop, 1);
  Open;
  AssertTrue(FRec.WaitCount(2));
  AssertEquals('error:EHttpConnectionError', FRec.Item(1));
end;

procedure TWebSocketClientTest.ScriptFragmentedText(const S: TWsTestServer);
var
  A, B: TBytes;
begin
  S.ReadHead;
  S.Accept;
  SetLength(A, 3);
  A[0] := 65; A[1] := $E2; A[2] := $82;
  SetLength(B, 2);
  B[0] := $AC; B[1] := 66;
  S.SendFrame(cWsOpText, False, A);
  S.SendFrame(cWsOpContinuation, True, B);
  S.Release.WaitFor(2000);
end;

procedure TWebSocketClientTest.TestFragmentedReceive;
begin
  // a character split across fragments is delivered whole, in the next one
  Start(ScriptFragmentedText, 2);
  Open;
  AssertTrue(FRec.WaitCount(3));
  AssertEquals('text:A:0', FRec.Item(1));
  AssertEquals('text:'#$E2#$82#$AC'B:1', FRec.Item(2));
end;

type
  TRecordingSelector = class(TInterfacedObject, IProxySelector)
  public
    Seen: string;
    function SelectProxy(const AUri: string): IProxy;
  end;

function TRecordingSelector.SelectProxy(const AUri: string): IProxy;
begin
  Seen := AUri;
  Result := nil;
end;

procedure TWebSocketClientTest.TestSelectorSeesTheMappedUrl;
var
  Sel: TRecordingSelector;
  SelRef: IProxySelector;
begin
  Start(ScriptEcho, 1);
  Sel := TRecordingSelector.Create;
  SelRef := Sel;
  FClient := THttpClientFactory.Create.WithProxySelector(SelRef).Build;
  Open;
  AssertTrue(FRec.WaitCount(1));
  AssertEquals('http://127.0.0.1:' + IntToStr(FServer.Port) + '/chat?room=1',
    Sel.Seen);
end;

type
  TNoDialFactory = class(TInterfacedObject, IHttp2SocketFactory)
  public
    function Dial(const AHost: string; const APort: Word;
      const ATimeoutMs: Integer): IHttp2Socket;
  end;

function TNoDialFactory.Dial(const AHost: string; const APort: Word;
  const ATimeoutMs: Integer): IHttp2Socket;
begin
  raise Exception.Create('not expected');
end;

procedure TWebSocketClientTest.TestFactoryWithoutHttp1DialIsRefused;
var
  Raised: Boolean;
  F: IHttp2SocketFactory;
begin
  FRec := TRecorder.Create;
  FRecRef := FRec;
  F := TNoDialFactory.Create;
  FClient := THttpClientFactory.Create.WithSocketFactory(F).Build;
  Raised := False;
  try
    FClient.Send(TWebSocketRequest.Create('ws://127.0.0.1:1/', FRecRef));
  except
    on EHttpWebSocketError do
      Raised := True;
  end;
  AssertTrue(Raised);
end;

procedure TWebSocketClientTest.TestAutoRequest;
begin
  Start(ScriptThreeTexts, 0);
  Open(TWebSocketRequest.Create(Url, FRecRef).WithAutoRequest);
  AssertTrue('all three without a Request call', FRec.WaitCount(4));
  AssertEquals('text:three:1', FRec.Item(3));
end;

procedure TWebSocketClientTest.ScriptNoReply(const S: TWsTestServer);
begin
  S.ReadHead;
  S.Accept;
  S.Release.WaitFor(5000);
end;

procedure TWebSocketClientTest.TestCloseWithoutAnswerTimesOut;
var
  Sock: IWebSocket;
  Started: QWord;
begin
  Start(ScriptNoReply, 1);
  Started := GetTickCount64;
  Sock := Open(TWebSocketRequest.Create(Url, FRecRef).WithCloseTimeoutMs(300));
  AssertTrue(FRec.WaitCount(1));
  Sock.Close(1000, '');
  AssertTrue('reported', FRec.WaitCount(2, 4000));
  AssertEquals('error:EHttpTimeout', FRec.Item(1));
  AssertTrue('after the close timeout, not long after',
    GetTickCount64 - Started < 3000);
end;

procedure TWebSocketClientTest.ScriptCountPings(const S: TWsTestServer);
var
  F: TWsFrame;
  Pings: Integer;
begin
  S.ReadHead;
  S.Accept;
  Pings := 0;
  while S.TryReadFrame(F) do
    if F.Opcode = cWsOpPing then
      Inc(Pings)
    else if F.Opcode = cWsOpClose then
      Break;
  if Pings < 1 then
    S.Failure := 'no ping arrived';
end;

procedure TWebSocketClientTest.TestPingIntervalSendsPingsAndGivesUp;
begin
  Start(ScriptCountPings, 1);
  Open(TWebSocketRequest.Create(Url, FRecRef).WithPingIntervalMs(150));
  AssertTrue('gave up on a silent peer', FRec.WaitCount(2, 4000));
  AssertEquals('error:EHttpTimeout', FRec.Item(1));
  AssertTrue(FServer.Done.WaitFor(3000) = wrSignaled);
  AssertEquals('', FServer.Failure);
end;

procedure TWebSocketClientTest.ScriptOneText(const S: TWsTestServer);
begin
  S.ReadHead;
  S.Accept;
  S.SendText('boom');
  S.Release.WaitFor(3000);
end;

type
  TThrower = class(TRecorder)
  public
    procedure OnText(const ASocket: IWebSocket; const AText: string;
      const ALast: Boolean); override;
  end;

procedure TThrower.OnText(const ASocket: IWebSocket; const AText: string;
  const ALast: Boolean);
begin
  raise Exception.Create('listener failed');
end;

procedure TWebSocketClientTest.TestListenerExceptionIsReportedAndAborts;
var
  Sock: IWebSocket;
  T: TThrower;
begin
  Start(ScriptOneText, 1);
  FRecRef := nil;
  T := TThrower.Create(1);
  FRec := T;
  FRecRef := T;
  Sock := Open(TWebSocketRequest.Create(Url, FRecRef));
  AssertTrue(FRec.WaitCount(2));
  AssertEquals('error:Exception', FRec.Item(1));
  AssertTrue('aborted', Sock.InputClosed and Sock.OutputClosed);
end;

procedure TWebSocketClientTest.ScriptTooBig(const S: TWsTestServer);
var
  F: TWsFrame;
  B: TBytes;
begin
  S.ReadHead;
  S.Accept;
  SetLength(B, 11);
  S.SendFrame(cWsOpBinary, True, B);
  F := S.ReadFrame;
  if (F.Opcode <> cWsOpClose) or (Length(F.Payload) < 2) or
     (F.Payload[0] * 256 + F.Payload[1] <> 1009) then
    S.Failure := 'expected close 1009';
  S.CloseConnection;
end;

procedure TWebSocketClientTest.TestOverLimitMessageClosesWith1009;
begin
  Start(ScriptTooBig, 1);
  Open(TWebSocketRequest.Create(Url, FRecRef).WithMaxMessageBytes(10));
  AssertTrue(FRec.WaitCount(2));
  AssertEquals(1009, FRec.ErrorCode);
  AssertTrue(FServer.Done.WaitFor(3000) = wrSignaled);
  AssertEquals('', FServer.Failure);
end;

procedure TWebSocketClientTest.TestDroppedSocketKeepsDeliveringUntilItEnds;
var
  Sock: IWebSocket;
begin
  Start(ScriptOneText, 1);
  FRec.KeepSocket := False;
  Sock := Open;
  Sock := nil;                      // the caller keeps no reference
  AssertTrue('still delivering', FRec.WaitCount(2));
  AssertEquals('text:boom:1', FRec.Item(1));
  FServer.Release.SetEvent;
  FServer.CloseConnection;
  AssertTrue('ends with one terminal callback', FRec.WaitCount(3));
  AssertEquals('error:EHttpConnectionError', FRec.Item(2));
end;

var
  GMaskCalls: Integer;

function CountingMask: Cardinal;
begin
  Inc(GMaskCalls);
  Result := Cardinal(GMaskCalls) * $01010101;
end;

procedure TWebSocketClientTest.TestMaskKeyIsDrawnPerFrame;
var
  Sock: IWebSocket;
  F: TProtocolSocketFactory;
  Dial: IHttp1SocketFactory;
  Before: Integer;
begin
  Start(ScriptEcho, 4);
  F := TProtocolSocketFactory.Create;
  Dial := F;
  GMaskCalls := 0;
  Sock := OpenWebSocket(Dial, TWebSocketRequest.Create(Url, FRecRef), nil,
    5000, CountingMask);
  AssertTrue(FRec.WaitCount(1));
  Before := GMaskCalls;
  AssertEquals('four draws for the 16-octet handshake key', 4, Before);
  Sock.SendText('a');
  Sock.SendText('b');
  Sock.SendText('c');
  AssertTrue(FRec.WaitCount(4));
  AssertEquals('one key per frame', Before + 3, GMaskCalls);
  AssertEquals('', FServer.Failure);
end;

procedure TWebSocketClientTest.ScriptStreamIgnoreClose(const S: TWsTestServer);
var
  I: Integer;
begin
  S.ReadHead;
  S.Accept;
  // a chatty server that never answers the close frame
  for I := 1 to 400 do
  begin
    if S.Release.WaitFor(20) = wrSignaled then
      Break;
    S.SendText('x');
  end;
end;

procedure TWebSocketClientTest.TestCloseTimeoutFiresWhileFramesKeepArriving;
var
  Sock: IWebSocket;
  Started: QWord;
begin
  Start(ScriptStreamIgnoreClose, 1);
  Sock := Open(TWebSocketRequest.Create(Url, FRecRef).WithAutoRequest
    .WithCloseTimeoutMs(300));
  AssertTrue(FRec.WaitCount(1));
  Started := GetTickCount64;
  Sock.Close(1000, '');
  AssertTrue('timed out although data kept arriving',
    FRec.WaitFor('error:EHttpTimeout', 3000));
  AssertTrue('promptly', GetTickCount64 - Started < 2000);
end;

procedure TWebSocketClientTest.ScriptCloseThenHalfClose(const S: TWsTestServer);
var
  F: TWsFrame;
  Tv: record
    Sec: Int64;
    Usec: LongInt;
  end;
  C: Byte;
begin
  S.ReadHead;
  S.Accept;
  S.SendFrame(cWsOpClose, True, WsBuildClosePayload(1000, ''));
  F := S.ReadFrame;
  if F.Opcode <> cWsOpClose then
    S.Failure := 'expected the close echo';
  fpshutdown(S.FdForTest, SHUT_WR);
  // the client must close its side without being asked for more input
  Tv.Sec := 3;
  Tv.Usec := 0;
  fpSetSockOpt(S.FdForTest, SOL_SOCKET, SO_RCVTIMEO, @Tv, SizeOf(Tv));
  if fprecv(S.FdForTest, @C, 1, 0) <> 0 then
    S.Failure := 'the client did not close TCP';
end;

procedure TWebSocketClientTest.TestServerCloseWithNoDemandReleasesTheSocket;
begin
  Start(ScriptCloseThenHalfClose, 0);
  Open;
  AssertTrue('open', FRec.WaitCount(1));
  AssertTrue('the server saw the client close TCP',
    FServer.Done.WaitFor(5000) = wrSignaled);
  AssertEquals('', FServer.Failure);
  AssertEquals('no demand, so no report yet', 1, FRec.Count);
  FRec.Socket.Request(1);
  AssertTrue('reported once demand arrives', FRec.WaitCount(2));
  AssertEquals('close:1000:', FRec.Item(1));
end;

type
  /// keeps the socket it is given and signals when it is freed
  TLeakProbe = class(TWebSocketListener)
  private
    FDestroyed: TEvent;
    FOpened: TEvent;
    FClosed: TEvent;
    FSocket: IWebSocket;
  public
    constructor Create(const ADestroyed, AOpened, AClosed: TEvent);
    destructor Destroy; override;
    procedure OnOpen(const ASocket: IWebSocket); override;
    procedure OnClose(const ASocket: IWebSocket; const AStatusCode: Integer;
      const AReason: string); override;
  end;

constructor TLeakProbe.Create(const ADestroyed, AOpened, AClosed: TEvent);
begin
  inherited Create;
  FDestroyed := ADestroyed;
  FOpened := AOpened;
  FClosed := AClosed;
end;

destructor TLeakProbe.Destroy;
begin
  FSocket := nil;
  FDestroyed.SetEvent;
  inherited Destroy;
end;

procedure TLeakProbe.OnOpen(const ASocket: IWebSocket);
begin
  FSocket := ASocket;               // the usual JDK pattern
  ASocket.Request(1);
  FOpened.SetEvent;
end;

procedure TLeakProbe.OnClose(const ASocket: IWebSocket;
  const AStatusCode: Integer; const AReason: string);
begin
  FClosed.SetEvent;
end;

procedure TWebSocketClientTest.TestListenerHoldingTheSocketDoesNotLeakTheConnection;
var
  Destroyed, Opened, Closed: TEvent;
  Probe: IWebSocketListener;
  Req: IWebSocketRequest;
  Sock: IWebSocket;
begin
  Destroyed := TEvent.Create(nil, True, False, '');
  Opened := TEvent.Create(nil, True, False, '');
  Closed := TEvent.Create(nil, True, False, '');
  try
    Start(ScriptServerClose, 0);
    Probe := TLeakProbe.Create(Destroyed, Opened, Closed);
    Req := TWebSocketRequest.Create(Url, Probe);
    Sock := FClient.Send(Req);
    AssertTrue(Opened.WaitFor(3000) = wrSignaled);
    Sock.Request(1);
    AssertTrue('close delivered', Closed.WaitFor(5000) = wrSignaled);
    Sock := nil;
    Req := nil;
    Probe := nil;
    AssertTrue('the listener, and with it the connection, is released',
      Destroyed.WaitFor(5000) = wrSignaled);
  finally
    Destroyed.Free;
    Opened.Free;
    Closed.Free;
  end;
end;

initialization
  RegisterTest(TWebSocketClientTest);
end.
