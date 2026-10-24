/// WebSocket observability tests (doc/design/request-observability.md,
/// section "WebSocket")
// - the sessions run against the scripted loopback server of
//   Http2.WebSocketClient.Test through a client with a recording request
//   observer; the cases that need an exact clock install a scripted one.
// - non-vacuous by construction: header injection is asserted from the
//   handshake bytes the server received, the end of a session from the
//   outcomes a recording observer saw, and every end is counted, so a missing
//   or duplicated OnAttemptEnd fails a test.
// - no test sleeps to wait for another thread: the script threads and the
//   tests hand each other events and wait on them with bounded timeouts.
unit Http2.WebSocketObservability.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$interfaces com}

interface

uses
  SysUtils, Classes, SyncObjs, fpcunit, testregistry,
  Http2.Errors, Http2.Tls, Http2.Headers, Http2.Messages, Http2.Http1,
  Http2.Client, Http2.Clock, Http2.RequestObserver, Http2.WebSocket,
  Http2.WebSocketClient, Http2.MockSocket,
  Http2.RequestObserver.Test, Http2.WebSocketClient.Test;

type
  /// a message-recording observer that also keeps what the handshake showed
  /// and can try to inject the names the handshake owns
  TWsObserver = class(TMessageRecordingObserver, IHttpMessageObserver)
  private
    FMsgEvent: PRTLEvent;
  public
    /// the status and chosen subprotocol OnResponseHeaders saw
    SeenStatus: Integer;
    SeenSubprotocol: string;
    SeenHeaders: Integer;
    /// names OnAttemptStart tries to inject, and what each attempt raised
    TryNames: TStringList;
    Rejected: TStringList;
    constructor Create(const AWants: TMessageKinds);
    destructor Destroy; override;
    function OnAttemptStart(const A: THttpAttempt): IInterface; override;
    procedure OnResponseHeaders(const AToken: IInterface;
      const AResponse: IHttpResponse); override;
    procedure OnMessage(const AToken: IInterface; const M: TMessageInfo);
    function WaitMessages(const ACount, ATimeoutMs: Integer): Boolean;
  end;

  /// an IWebSocketAttempt that only counts, to drive a connection directly
  TFakeWsAttempt = class(TInterfacedObject, IWebSocketAttempt, IAttemptProgress)
  private
    FEnds: LongInt;
    FLast: TWsSessionEnd;
    FLastErrorClass: string;
  public
    function HandshakeHeaders: TArray<TWsHeaderField>;
    procedure HandshakeWritten;
    procedure HandshakeAccepted(const AStatus: Integer;
      const AFields: TArray<TWsHeaderField>; const ASubprotocol: string);
    procedure SessionEnded(const AEnd: TWsSessionEnd);
    function WantedKinds: TMessageKinds;
    procedure ReportMessage(const AKind: TMessageKind;
      const ADirection: TDirection; const AArrivedUs: Int64;
      const ASize: Integer; const ASse: PSseEvent);
    procedure ReadBegin;
    procedure ReadEnd;
    procedure Finish(const ABytesIn: Int64);
    property Ends: LongInt read FEnds;
    property Last: TWsSessionEnd read FLast;
    property LastErrorClass: string read FLastErrorClass;
  end;

  /// a listener whose OnText raises
  TRaisingListener = class(TWebSocketListener)
  public
    procedure OnText(const ASocket: IWebSocket; const AText: string;
      const ALast: Boolean); override;
  end;

  TWsSendThread = class(TThread)
  private
    FSocket: IWebSocket;
    FCount: Integer;
    FStart: TEvent;
  protected
    procedure Execute; override;
  public
    Failure: string;
    constructor Create(const ASocket: IWebSocket; const ACount: Integer;
      const AStart: TEvent);
  end;

  /// runs one ending path (0 Abort, 1 Close) once released
  TWsActThread = class(TThread)
  private
    FSocket: IWebSocket;
    FMode: Integer;
    FStart: TEvent;
  protected
    procedure Execute; override;
  public
    constructor Create(const ASocket: IWebSocket; const AMode: Integer;
      const AStart: TEvent);
  end;

  TWsRequestContextTest = class(TTestCase)
  published
    procedure TestContextIsReturnedAndTheOriginalIsUnchanged;
    procedure TestContextSurvivesTheOtherWithMethods;
  end;

  TWsObservabilityTest = class(TTestCase)
  private
    FServer: TWsTestServer;
    FRec: TRecorder;
    FRecRef: IWebSocketListener;
    FObs: TWsObserver;
    FObsRef: IHttpClientObserver;
    FClient: IHttpClient;
    FGo: TEvent;
    FSeen: TEvent;
    FStartedBeforeHead: Boolean;
    FSrvTexts: LongInt;
    FSrvBytes: LongInt;
    procedure Start(const AScript: TWsScript; const AWants: TMessageKinds);
    function Url: string;
    function Req: IWebSocketRequest;
    function Open(const ARequest: IWebSocketRequest = nil): IWebSocket;
    function Ended(const AMs: Integer = 5000): Boolean;
    /// the callbacks the observer saw, as 'S0 H0 E0'
    function Flow: string;
    function KindsOf(const ADirection: TDirection): string;
    procedure StopServer;
    // scripts
    procedure ScriptHold(const S: TWsTestServer);
    procedure ScriptHoldSubprotocol(const S: TWsTestServer);
    procedure ScriptHeadCheck(const S: TWsTestServer);
    procedure ScriptRefuse403(const S: TWsTestServer);
    procedure ScriptEchoClose(const S: TWsTestServer);
    procedure ScriptRemoteClose(const S: TWsTestServer);
    procedure ScriptDrop(const S: TWsTestServer);
    procedure ScriptSeven(const S: TWsTestServer);
    procedure ScriptKinds(const S: TWsTestServer);
    procedure ScriptStamps(const S: TWsTestServer);
    procedure ScriptFragmentStamp(const S: TWsTestServer);
    procedure ScriptPingThenText(const S: TWsTestServer);
    procedure ScriptCountFrames(const S: TWsTestServer);
    procedure ScriptBadUtf8(const S: TWsTestServer);
    procedure ScriptNoReply(const S: TWsTestServer);
    procedure ScriptOneText(const S: TWsTestServer);
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    // 21.2
    procedure TestInjectedHeaderReachesTheHandshakeAndReplacesTheCallers;
    procedure TestTheSinkRefusesTheNamesTheHandshakeOwns;
    // 21.3
    procedure TestAttemptStartsBeforeTheHandshakeIsWritten;
    // 21.4, 21.10
    procedure TestAcceptReportsTheHeadersTheSubprotocolAndAnUnpooledSession;
    procedure TestRefusedHandshakeEndsWithTheStatusAndTheError;
    procedure TestFailedDialPairsStartWithOneEnd;
    // 21.5, 21.6
    procedure TestLocalCloseEndsOnceWithTheServersCode;
    procedure TestRemoteCloseEndsOnceEvenWithNoDemand;
    procedure TestAbortEndsOnceAsAbort;
    procedure TestDroppedConnectionEndsAsAnError;
    procedure TestProtocolErrorReportsTheCodeItClosedWith;
    procedure TestCloseWithoutAnswerEndsAsATimeout;
    procedure TestRaisingListenerEndsOnceWithItsException;
    procedure TestReleasedUnstartedConnectionEndsAbandoned;
    procedure TestEndAfterAbortDoesNotReportAgainOnRelease;
    procedure TestEndingPathsRacingEachOtherEndOnce;
    // 21.7
    procedure TestCountersSeparateMessagesFromPingsAndBytes;
    procedure TestConcurrentSendersLoseNoCounts;
    // 21.8
    procedure TestWireStampsGiveTheAggregates;
    procedure TestFragmentedMessageTakesTheStampOfItsLastRead;
    // 21.9
    procedure TestOptedInObserverSeesEveryKindInOrder;
    procedure TestEmptySetAndOtherKindsSeeNothing;
    // 21.11
    procedure TestStampsIncludeTheConsumersWaitWithoutDemand;
    procedure TestAutoRequestKeepsTheConsumersWaitOutOfTheStamps;
    // 21.12
    procedure TestRaisingObserverNeverBreaksTheSession;
  end;

implementation

const
  cCrLf = #13#10;

var
  GFakeNowUs: Int64;

function FakeNow: Int64;
begin
  Result := GFakeNowUs;
end;

function ZeroMask: Cardinal;
begin
  Result := 0;
end;

function BytesOf(const S: string): TBytes;
begin
  Result := nil;
  SetLength(Result, Length(S));
  if S <> '' then
    Move(S[1], Result[0], Length(S));
end;

function KindName(const AKind: TMessageKind): string;
begin
  case AKind of
    mkSseEvent: Result := 'event';
    mkWsText: Result := 'text';
    mkWsBinary: Result := 'binary';
    mkWsPing: Result := 'ping';
    mkWsPong: Result := 'pong';
    mkWsClose: Result := 'close';
  else
    Result := '?';
  end;
end;

{ TWsObserver }

constructor TWsObserver.Create(const AWants: TMessageKinds);
begin
  inherited Create(AWants);
  FMsgEvent := RTLEventCreate;
  TryNames := TStringList.Create;
  Rejected := TStringList.Create;
end;

destructor TWsObserver.Destroy;
begin
  Rejected.Free;
  TryNames.Free;
  RTLEventDestroy(FMsgEvent);
  inherited Destroy;
end;

function TWsObserver.OnAttemptStart(const A: THttpAttempt): IInterface;
var
  I: Integer;
begin
  Result := inherited OnAttemptStart(A);
  for I := 0 to TryNames.Count - 1 do
    try
      A.Headers.SetValue(TryNames[I], 'x');
      Rejected.Add('');
    except
      on E: Exception do
        Rejected.Add(E.ClassName);
    end;
end;

procedure TWsObserver.OnResponseHeaders(const AToken: IInterface;
  const AResponse: IHttpResponse);
begin
  SeenStatus := AResponse.StatusCode;
  SeenSubprotocol := AResponse.Headers.GetFirst('sec-websocket-protocol');
  Inc(SeenHeaders);
  inherited OnResponseHeaders(AToken, AResponse);
end;

procedure TWsObserver.OnMessage(const AToken: IInterface;
  const M: TMessageInfo);
begin
  try
    inherited OnMessage(AToken, M);
  finally
    RTLEventSetEvent(FMsgEvent);
  end;
end;

function TWsObserver.WaitMessages(const ACount, ATimeoutMs: Integer): Boolean;
var
  Deadline: QWord;
begin
  Deadline := GetTickCount64 + QWord(ATimeoutMs);
  while True do
  begin
    if MessageCount >= ACount then
      Exit(True);
    if GetTickCount64 >= Deadline then
      Exit(False);
    RTLEventWaitFor(FMsgEvent, 20);
  end;
end;

{ TFakeWsAttempt }

function TFakeWsAttempt.HandshakeHeaders: TArray<TWsHeaderField>;
begin
  Result := nil;
end;

procedure TFakeWsAttempt.HandshakeWritten;
begin
end;

procedure TFakeWsAttempt.HandshakeAccepted(const AStatus: Integer;
  const AFields: TArray<TWsHeaderField>; const ASubprotocol: string);
begin
end;

procedure TFakeWsAttempt.SessionEnded(const AEnd: TWsSessionEnd);
begin
  FLast := AEnd;
  FLast.Error := nil;
  if AEnd.Error <> nil then
    FLastErrorClass := AEnd.Error.ClassName;
  InterlockedIncrement(FEnds);
end;

function TFakeWsAttempt.WantedKinds: TMessageKinds;
begin
  Result := [];
end;

procedure TFakeWsAttempt.ReportMessage(const AKind: TMessageKind;
  const ADirection: TDirection; const AArrivedUs: Int64; const ASize: Integer;
  const ASse: PSseEvent);
begin
end;

procedure TFakeWsAttempt.ReadBegin;
begin
end;

procedure TFakeWsAttempt.ReadEnd;
begin
end;

procedure TFakeWsAttempt.Finish(const ABytesIn: Int64);
begin
end;

{ TRaisingListener }

procedure TRaisingListener.OnText(const ASocket: IWebSocket;
  const AText: string; const ALast: Boolean);
begin
  raise EListError.Create('the listener failed');
end;

{ TWsSendThread }

constructor TWsSendThread.Create(const ASocket: IWebSocket;
  const ACount: Integer; const AStart: TEvent);
begin
  FSocket := ASocket;
  FCount := ACount;
  FStart := AStart;
  inherited Create(False);
end;

procedure TWsSendThread.Execute;
var
  I: Integer;
begin
  FStart.WaitFor(5000);
  try
    for I := 1 to FCount do
      FSocket.SendText('abc');
  except
    on E: Exception do
      Failure := E.ClassName + ': ' + E.Message;
  end;
end;

{ TWsActThread }

constructor TWsActThread.Create(const ASocket: IWebSocket; const AMode: Integer;
  const AStart: TEvent);
begin
  FSocket := ASocket;
  FMode := AMode;
  FStart := AStart;
  inherited Create(False);
end;

procedure TWsActThread.Execute;
begin
  FStart.WaitFor(5000);
  try
    if FMode = 0 then
      FSocket.Abort
    else
      FSocket.Close(1000, 'r');
  except
    // a send on a socket another path just closed may raise; only the end
    // is under test
  end;
end;

{ TWsRequestContextTest }

type
  TTag = class(TInterfacedObject)
  end;

procedure TWsRequestContextTest.TestContextIsReturnedAndTheOriginalIsUnchanged;
var
  L: IWebSocketListener;
  R, R2: IWebSocketRequest;
  Tag: IInterface;
begin
  L := TWebSocketListener.Create;
  R := TWebSocketRequest.Create('ws://127.0.0.1:1/', L);
  AssertTrue('no context by default', R.Context = nil);
  Tag := TTag.Create;
  R2 := R.WithContext(Tag);
  AssertTrue('the new request carries it', R2.Context = Tag);
  AssertTrue('GetContext agrees', R2.GetContext = Tag);
  AssertTrue('the original is unchanged', R.Context = nil);
  AssertTrue('nil clears it', R2.WithContext(nil).Context = nil);
  AssertTrue('and leaves R2 alone', R2.Context = Tag);
end;

procedure TWsRequestContextTest.TestContextSurvivesTheOtherWithMethods;
var
  L: IWebSocketListener;
  R: IWebSocketRequest;
  Tag: IInterface;
begin
  L := TWebSocketListener.Create;
  Tag := TTag.Create;
  R := TWebSocketRequest.Create('ws://127.0.0.1:1/', L).WithContext(Tag)
    .WithHeader('x-a', '1').WithSubprotocol('chat').WithAutoRequest
    .WithPingIntervalMs(1000).WithCloseTimeoutMs(10).WithMaxMessageBytes(10)
    .WithConnectTimeoutMs(10);
  AssertTrue('context kept through every copy', R.Context = Tag);
  AssertEquals('headers kept', 1, Length(R.Headers));
end;

{ TWsObservabilityTest }

procedure TWsObservabilityTest.SetUp;
begin
  inherited SetUp;
  FGo := TEvent.Create(nil, False, False, '');
  FSeen := TEvent.Create(nil, True, False, '');
end;

procedure TWsObservabilityTest.TearDown;
begin
  ResetNowUsHook;
  if (FRec <> nil) and (FRec.Socket <> nil) then
  begin
    FRec.Socket.Abort;
    FRec.Socket := nil;
  end;
  StopServer;
  FRecRef := nil;
  FRec := nil;
  FObsRef := nil;
  FObs := nil;
  FClient := nil;
  FSeen.Free;
  FGo.Free;
  inherited TearDown;
end;

procedure TWsObservabilityTest.StopServer;
begin
  if FServer <> nil then
  begin
    FServer.Terminate;
    FServer.Release.SetEvent;
    FGo.SetEvent;
    FServer.CloseConnection;
    FServer.ShutdownListener;
    FServer.Done.WaitFor(3000);
    FServer.Free;
    FServer := nil;
  end;
end;

procedure TWsObservabilityTest.Start(const AScript: TWsScript;
  const AWants: TMessageKinds);
begin
  FServer := TWsTestServer.Create(AScript);
  FServer.Start;
  FRec := TRecorder.Create(0);
  FRecRef := FRec;
  FObs := TWsObserver.Create(AWants);
  FObsRef := FObs;
  FClient := THttpClientFactory.Create.WithRequestObserver(FObsRef).Build;
end;

function TWsObservabilityTest.Url: string;
begin
  Result := 'ws://127.0.0.1:' + IntToStr(FServer.Port) + '/obs';
end;

function TWsObservabilityTest.Req: IWebSocketRequest;
begin
  Result := TWebSocketRequest.Create(Url, FRecRef).WithAutoRequest;
end;

function TWsObservabilityTest.Open(const ARequest: IWebSocketRequest): IWebSocket;
var
  R: IWebSocketRequest;
begin
  R := ARequest;
  if R = nil then
    R := Req;
  Result := FClient.Send(R);
end;

function TWsObservabilityTest.Ended(const AMs: Integer): Boolean;
begin
  Result := FObs.WaitForEnds(1, AMs);
end;

function TWsObservabilityTest.Flow: string;
begin
  Result := Trim(StringReplace(FObs.Order, sLineBreak, ' ', [rfReplaceAll]));
end;

function TWsObservabilityTest.KindsOf(const ADirection: TDirection): string;
var
  I: Integer;
  M: TMessageInfo;
begin
  Result := '';
  for I := 0 to FObs.MessageCount - 1 do
  begin
    M := FObs.MessageAt(I);
    if M.Direction = ADirection then
    begin
      if Result <> '' then
        Result := Result + ',';
      Result := Result + KindName(M.Kind);
    end;
  end;
end;

{ scripts }

procedure TWsObservabilityTest.ScriptHold(const S: TWsTestServer);
begin
  S.ReadHead;
  S.Accept;
  S.Release.WaitFor(5000);
end;

procedure TWsObservabilityTest.ScriptHoldSubprotocol(const S: TWsTestServer);
begin
  S.ReadHead;
  S.Accept('Sec-WebSocket-Protocol: chat' + cCrLf);
  S.Release.WaitFor(5000);
end;

procedure TWsObservabilityTest.ScriptHeadCheck(const S: TWsTestServer);
begin
  S.ReadHead;
  // the observer's start must already have run when the head arrives
  FStartedBeforeHead := FObs.StartCount >= 1;
  S.Accept;
  S.Release.WaitFor(5000);
end;

procedure TWsObservabilityTest.ScriptRefuse403(const S: TWsTestServer);
begin
  S.ReadHead;
  S.SendRaw('HTTP/1.1 403 Forbidden' + cCrLf + 'Content-Length: 0' + cCrLf +
    cCrLf);
  S.Release.WaitFor(2000);
end;

procedure TWsObservabilityTest.ScriptEchoClose(const S: TWsTestServer);
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
  S.CloseConnection;
end;

procedure TWsObservabilityTest.ScriptRemoteClose(const S: TWsTestServer);
begin
  S.ReadHead;
  S.Accept;
  S.SendFrame(cWsOpClose, True, WsBuildClosePayload(1001, 'going'));
  S.ReadFrame;                       // the echo
  S.CloseConnection;
end;

procedure TWsObservabilityTest.ScriptDrop(const S: TWsTestServer);
begin
  S.ReadHead;
  S.Accept;
  S.CloseConnection;
end;

procedure TWsObservabilityTest.ScriptSeven(const S: TWsTestServer);
var
  F: TWsFrame;
  I, Data: Integer;
begin
  S.ReadHead;
  S.Accept;
  for I := 1 to 7 do
  begin
    S.SendText('m' + IntToStr(I));
    if (I = 3) or (I = 5) then
      S.SendFrame(cWsOpPing, True, nil);
  end;
  // wait for the client's ten messages, then close from this side
  Data := 0;
  while Data < 10 do
  begin
    F := S.ReadFrame;
    if F.Opcode = cWsOpText then
      Inc(Data);
  end;
  S.SendFrame(cWsOpClose, True, WsBuildClosePayload(1000, 'done'));
  while S.TryReadFrame(F) do
    if F.Opcode = cWsOpClose then
      Break;
  S.CloseConnection;
end;

procedure TWsObservabilityTest.ScriptKinds(const S: TWsTestServer);
var
  F: TWsFrame;
  Got: Integer;
begin
  S.ReadHead;
  S.Accept;
  S.SendText('one');
  S.SendFrame(cWsOpBinary, True, BytesOf('bb'));
  S.SendFrame(cWsOpPing, True, BytesOf('p'));
  S.SendFrame(cWsOpPong, True, BytesOf('q'));
  // let the client's two data messages arrive, then close from this side
  Got := 0;
  while Got < 2 do
  begin
    F := S.ReadFrame;
    if (F.Opcode = cWsOpText) or (F.Opcode = cWsOpBinary) then
      Inc(Got);
  end;
  S.SendFrame(cWsOpClose, True, WsBuildClosePayload(1000, 'bye'));
  while S.TryReadFrame(F) do
    if F.Opcode = cWsOpClose then
      Break;
  S.CloseConnection;
end;

procedure TWsObservabilityTest.ScriptStamps(const S: TWsTestServer);
begin
  S.ReadHead;
  S.Accept;
  S.SendText('m1');
  FGo.WaitFor(5000);
  S.SendText('m2');
  FGo.WaitFor(5000);
  S.SendText('m3');
  S.Release.WaitFor(5000);
end;

procedure TWsObservabilityTest.ScriptFragmentStamp(const S: TWsTestServer);
begin
  S.ReadHead;
  S.Accept;
  S.SendFrame(cWsOpText, False, BytesOf('ab'));
  FSeen.SetEvent;
  FGo.WaitFor(5000);
  S.SendFrame(cWsOpContinuation, True, BytesOf('cd'));
  S.Release.WaitFor(5000);
end;

procedure TWsObservabilityTest.ScriptPingThenText(const S: TWsTestServer);
var
  F: TWsFrame;
begin
  S.ReadHead;
  S.Accept;
  S.SendFrame(cWsOpPing, True, nil);
  F := S.ReadFrame;                  // the pong: the reader has read the ping
  if F.Opcode <> cWsOpPong then
    S.Failure := 'expected a pong';
  FSeen.SetEvent;
  S.SendText('m2');
  S.Release.WaitFor(5000);
end;

procedure TWsObservabilityTest.ScriptCountFrames(const S: TWsTestServer);
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
    if F.Opcode = cWsOpText then
    begin
      InterlockedIncrement(FSrvTexts);
      InterlockedExchangeAdd(FSrvBytes, Length(F.Payload));
    end;
  end;
  S.CloseConnection;
end;

procedure TWsObservabilityTest.ScriptBadUtf8(const S: TWsTestServer);
var
  F: TWsFrame;
begin
  S.ReadHead;
  S.Accept;
  S.SendFrame(cWsOpText, True, BytesOf(#$FF));
  S.TryReadFrame(F);                 // the client's 1007 close
  S.CloseConnection;
end;

procedure TWsObservabilityTest.ScriptNoReply(const S: TWsTestServer);
begin
  S.ReadHead;
  S.Accept;
  S.ReadFrame;                       // the close, which is never answered
  S.Release.WaitFor(5000);
end;

procedure TWsObservabilityTest.ScriptOneText(const S: TWsTestServer);
begin
  S.ReadHead;
  S.Accept;
  S.SendText('boom');
  S.Release.WaitFor(5000);
end;

{ 21.2 }

procedure TWsObservabilityTest.
  TestInjectedHeaderReachesTheHandshakeAndReplacesTheCallers;
var
  Sock: IWebSocket;
  Lines: TStringList;
  I, Seen: Integer;
  Original: IWebSocketRequest;
begin
  Start(ScriptHold, []);
  FObs.InjectName := 'traceparent';
  FObs.InjectPrefix := 'injected';
  Original := Req.WithHeader('traceparent', 'from-the-caller')
    .WithHeader('x-keep', 'yes');
  Sock := Open(Original);
  AssertTrue('open', FRec.WaitCount(1));
  Lines := TStringList.Create;
  try
    Lines.Text := FServer.Head;
    Seen := 0;
    for I := 0 to Lines.Count - 1 do
      if SameText(Copy(Lines[I], 1, 12), 'traceparent:') then
        Inc(Seen);
  finally
    Lines.Free;
  end;
  AssertEquals('exactly one traceparent line', 1, Seen);
  AssertEquals('the injected value won', 'injected-1',
    FServer.HeaderValue('traceparent'));
  AssertEquals('the caller header stays', 'yes', FServer.HeaderValue('x-keep'));
  AssertEquals('the observer saw the caller value first', 'from-the-caller',
    FObs.SeenBefore[0]);
  AssertEquals('the caller request is untouched', 2, Length(Original.Headers));
  AssertEquals('from-the-caller', Original.Headers[0].Value);
  Sock.Abort;
end;

procedure TWsObservabilityTest.TestTheSinkRefusesTheNamesTheHandshakeOwns;
var
  Sock: IWebSocket;
begin
  Start(ScriptHold, []);
  FObs.TryNames.CommaText := 'Upgrade,connection,Host,Sec-WebSocket-Key,' +
    'sec-websocket-protocol,Sec-WebSocket-Version,Content-Length';
  Sock := Open;
  AssertTrue('open', FRec.WaitCount(1));
  AssertEquals('every name was tried', 7, FObs.Rejected.Count);
  AssertEquals('upgrade', 'EHttpWebSocketError', FObs.Rejected[0]);
  AssertEquals('connection', 'EHttpWebSocketError', FObs.Rejected[1]);
  AssertEquals('host', 'EHttpWebSocketError', FObs.Rejected[2]);
  AssertEquals('sec-websocket-key', 'EHttpWebSocketError', FObs.Rejected[3]);
  AssertEquals('sec-websocket-protocol', 'EHttpWebSocketError',
    FObs.Rejected[4]);
  AssertEquals('sec-websocket-version', 'EHttpWebSocketError',
    FObs.Rejected[5]);
  AssertEquals('content-length', 'EHttpWebSocketError', FObs.Rejected[6]);
  AssertEquals('the handshake still has its own upgrade', 'websocket',
    FServer.HeaderValue('Upgrade'));
  AssertEquals('and its own host', '127.0.0.1:' + IntToStr(FServer.Port),
    FServer.HeaderValue('Host'));
  Sock.Abort;
end;

{ 21.3 }

procedure TWsObservabilityTest.TestAttemptStartsBeforeTheHandshakeIsWritten;
var
  Sock: IWebSocket;
  A: THttpAttempt;
  Ctx: IInterface;
begin
  Start(ScriptHeadCheck, []);
  Ctx := TTag.Create;
  Sock := Open(Req.WithContext(Ctx));
  AssertTrue('open', FRec.WaitCount(1));
  AssertTrue('the start ran before the server read the head',
    FStartedBeforeHead);
  AssertEquals('one start', 1, FObs.StartCount);
  A := FObs.Attempt(0);
  AssertTrue('kind', A.Kind = akWebSocket);
  AssertEquals('method', 'GET', A.Method);
  AssertEquals('url', Url, A.Url);
  AssertEquals('host', '127.0.0.1', A.Host);
  AssertEquals('port', Integer(FServer.Port), Integer(A.Port));
  AssertEquals('hop', 0, A.Hop);
  AssertEquals('retry', 0, A.Retry);
  AssertTrue('context', A.Context = Ctx);
  AssertTrue('a header sink', A.Headers <> nil);
  Sock.Abort;
end;

{ 21.4, 21.10 }

procedure TWsObservabilityTest.
  TestAcceptReportsTheHeadersTheSubprotocolAndAnUnpooledSession;
var
  Sock: IWebSocket;
  O: THttpOutcome;
begin
  Start(ScriptHoldSubprotocol, []);
  Sock := Open(Req.WithSubprotocol('chat'));
  AssertTrue('open', FRec.WaitCount(1));
  AssertEquals('headers reported once', 1, FObs.SeenHeaders);
  AssertEquals('at the 101', 101, FObs.SeenStatus);
  AssertEquals('with the subprotocol known', 'chat', FObs.SeenSubprotocol);
  AssertEquals('not ended yet', 0, FObs.EndCount);
  Sock.Abort;
  AssertTrue('ended', Ended);
  AssertEquals('order', 'S0 H0 E0', Flow);
  O := FObs.Outcome(0).O;
  AssertEquals('status', 101, O.StatusCode);
  AssertEquals('subprotocol', 'chat', O.Subprotocol);
  AssertTrue('HTTP/1.1', O.Protocol = npHttp1Cleartext);
  AssertFalse('never a pooled connection', O.ConnectionReused);
  AssertTrue('headers came after the request was sent',
    (O.RequestSentUs > 0) and (O.HeadersUs >= O.RequestSentUs));
  AssertTrue('the session outlasts the handshake', O.EndUs >= O.HeadersUs);
end;

procedure TWsObservabilityTest.TestRefusedHandshakeEndsWithTheStatusAndTheError;
var
  Raised: string;
  O: TRecordedOutcome;
begin
  Start(ScriptRefuse403, []);
  Raised := '';
  try
    Open;
    Fail('a refused handshake must raise');
  except
    on E: EHttpWebSocketHandshakeError do
      Raised := E.ClassName;
  end;
  AssertEquals('EHttpWebSocketHandshakeError', Raised);
  AssertTrue('ended', Ended);
  AssertEquals('one start, one end, no headers callback', 'S0 E0', Flow);
  O := FObs.Outcome(0);
  AssertEquals('status of the refusal', 403, O.O.StatusCode);
  AssertEquals('error class', 'EHttpWebSocketHandshakeError', O.ErrorClass);
  AssertTrue('closed by error', O.O.ClosedBy = ciError);
  AssertFalse('not abandoned', O.O.Abandoned);
  AssertEquals('no session', 0, O.O.MessagesIn);
end;

procedure TWsObservabilityTest.TestFailedDialPairsStartWithOneEnd;
var
  Raised: Boolean;
  O: TRecordedOutcome;
  Closed: IWebSocketRequest;
begin
  // a loopback port with no listener: the server object is shut down first
  Start(ScriptHold, []);
  Closed := TWebSocketRequest.Create(Url, FRecRef);
  StopServer;
  Raised := False;
  try
    FClient.Send(Closed);
  except
    on Exception do
      Raised := True;
  end;
  AssertTrue('the dial failed', Raised);
  AssertTrue('ended', Ended);
  AssertEquals('S0 E0', Flow);
  O := FObs.Outcome(0);
  AssertEquals('no status', 0, O.O.StatusCode);
  AssertTrue('an error', O.ErrorClass <> '');
  AssertTrue('closed by error', O.O.ClosedBy = ciError);
end;

{ 21.5, 21.6 }

procedure TWsObservabilityTest.TestLocalCloseEndsOnceWithTheServersCode;
var
  Sock: IWebSocket;
  O: THttpOutcome;
begin
  Start(ScriptEchoClose, []);
  Sock := Open;
  AssertTrue('open', FRec.WaitCount(1));
  Sock.Close(1000, 'bye');
  AssertTrue('ended', Ended);
  O := FObs.Outcome(0).O;
  AssertTrue('local', O.ClosedBy = ciLocal);
  AssertEquals('code', 1000, O.CloseCode);
  AssertEquals('reason', 'bye', O.CloseReason);
  AssertFalse('deliberate, not abandoned', O.Abandoned);
  AssertTrue('no error', FObs.Outcome(0).ErrorClass = '');
  Sock.Abort;                        // after the end: nothing more
  AssertEquals('exactly one end', 1, FObs.EndCount);
end;

procedure TWsObservabilityTest.TestRemoteCloseEndsOnceEvenWithNoDemand;
var
  O: THttpOutcome;
begin
  Start(ScriptRemoteClose, []);
  // no demand: OnClose is never delivered, the attempt still ends
  Open(TWebSocketRequest.Create(Url, FRecRef));
  AssertTrue('ended', Ended);
  O := FObs.Outcome(0).O;
  AssertTrue('remote', O.ClosedBy = ciRemote);
  AssertEquals('code', 1001, O.CloseCode);
  AssertEquals('reason', 'going', O.CloseReason);
  AssertFalse('not abandoned', O.Abandoned);
  AssertEquals('exactly one end', 1, FObs.EndCount);
end;

procedure TWsObservabilityTest.TestAbortEndsOnceAsAbort;
var
  Sock: IWebSocket;
  O: THttpOutcome;
begin
  Start(ScriptHold, []);
  Sock := Open;
  AssertTrue('open', FRec.WaitCount(1));
  Sock.Abort;
  AssertTrue('ended', Ended);
  Sock.Abort;
  O := FObs.Outcome(0).O;
  AssertTrue('abort', O.ClosedBy = ciAbort);
  AssertEquals('abnormal', cWsCloseAbnormal, O.CloseCode);
  AssertEquals('no reason', '', O.CloseReason);
  AssertFalse('a deliberate end', O.Abandoned);
  AssertEquals('exactly one end', 1, FObs.EndCount);
end;

procedure TWsObservabilityTest.TestDroppedConnectionEndsAsAnError;
var
  O: TRecordedOutcome;
begin
  Start(ScriptDrop, []);
  Open;
  AssertTrue('ended', Ended);
  O := FObs.Outcome(0);
  AssertTrue('error', O.O.ClosedBy = ciError);
  AssertEquals('EHttpConnectionError', O.ErrorClass);
  AssertEquals('abnormal', cWsCloseAbnormal, O.O.CloseCode);
  AssertFalse('not abandoned', O.O.Abandoned);
  AssertEquals('exactly one end', 1, FObs.EndCount);
end;

procedure TWsObservabilityTest.TestProtocolErrorReportsTheCodeItClosedWith;
var
  O: TRecordedOutcome;
begin
  Start(ScriptBadUtf8, []);
  Open;
  AssertTrue('ended', Ended);
  O := FObs.Outcome(0);
  AssertTrue('error', O.O.ClosedBy = ciError);
  AssertEquals('EHttpWebSocketProtocolError', O.ErrorClass);
  AssertEquals('the 1007 it closed with', cWsCloseBadData, O.O.CloseCode);
end;

procedure TWsObservabilityTest.TestCloseWithoutAnswerEndsAsATimeout;
var
  Sock: IWebSocket;
  O: TRecordedOutcome;
begin
  Start(ScriptNoReply, []);
  Sock := Open(Req.WithCloseTimeoutMs(200));
  AssertTrue('open', FRec.WaitCount(1));
  Sock.Close(1000, 'x');
  AssertTrue('ended', Ended);
  O := FObs.Outcome(0);
  AssertTrue('error', O.O.ClosedBy = ciError);
  AssertEquals('EHttpTimeout', O.ErrorClass);
  AssertEquals('abnormal', cWsCloseAbnormal, O.O.CloseCode);
  AssertEquals('exactly one end', 1, FObs.EndCount);
end;

procedure TWsObservabilityTest.TestRaisingListenerEndsOnceWithItsException;
var
  O: TRecordedOutcome;
begin
  Start(ScriptOneText, []);
  FRecRef := TRaisingListener.Create;
  Open;
  AssertTrue('ended', Ended);
  O := FObs.Outcome(0);
  AssertTrue('error, not abort', O.O.ClosedBy = ciError);
  AssertEquals('the listener exception', 'EListError', O.ErrorClass);
  AssertEquals('the message', 'the listener failed', O.ErrorMessage);
  AssertEquals('exactly one end', 1, FObs.EndCount);
end;

function NewDirectConnection(const AAttempt: IWebSocketAttempt): IWebSocket;
var
  Mock: IHttp2Socket;
  L: IWebSocketListener;
begin
  Mock := TMockSocket.Create;
  L := TWebSocketListener.Create;
  Result := TWebSocketConnection.Create(Mock, TBufferedReader.Create(Mock),
    TWebSocketRequest.Create('ws://127.0.0.1:1/', L), '', ZeroMask, False,
    AAttempt);
end;

procedure TWsObservabilityTest.TestReleasedUnstartedConnectionEndsAbandoned;
var
  Fake: TFakeWsAttempt;
  FakeRef: IWebSocketAttempt;
  W: IWebSocket;
begin
  Fake := TFakeWsAttempt.Create;
  FakeRef := Fake;
  W := NewDirectConnection(FakeRef);
  AssertEquals('open session, no end', 0, Fake.Ends);
  W := nil;                          // released with no close, abort or failure
  AssertEquals('one end', 1, Fake.Ends);
  AssertTrue('abandoned', Fake.Last.Abandoned);
  AssertTrue('nobody closed it', Fake.Last.ClosedBy = ciNone);
end;

procedure TWsObservabilityTest.TestEndAfterAbortDoesNotReportAgainOnRelease;
var
  Fake: TFakeWsAttempt;
  FakeRef: IWebSocketAttempt;
  W: IWebSocket;
begin
  Fake := TFakeWsAttempt.Create;
  FakeRef := Fake;
  W := NewDirectConnection(FakeRef);
  W.Abort;
  W.Abort;
  AssertEquals('one end after two aborts', 1, Fake.Ends);
  AssertTrue('abort', Fake.Last.ClosedBy = ciAbort);
  W := nil;
  AssertEquals('release adds nothing', 1, Fake.Ends);
  AssertFalse('a deliberate end', Fake.Last.Abandoned);
end;

procedure TWsObservabilityTest.TestEndingPathsRacingEachOtherEndOnce;
const
  cRounds = 12;
var
  I: Integer;
  Srv: TWsTestServer;
  Rec: TRecorder;
  RecRef: IWebSocketListener;
  Obs: TWsObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  Sock: IWebSocket;
  Start1: TEvent;
  Th1, Th2: TWsActThread;
begin
  for I := 1 to cRounds do
  begin
    Srv := TWsTestServer.Create(ScriptHold);
    Srv.Start;
    Rec := TRecorder.Create(0);
    RecRef := Rec;
    Obs := TWsObserver.Create([]);
    ObsRef := Obs;
    Client := THttpClientFactory.Create.WithRequestObserver(ObsRef).Build;
    Start1 := TEvent.Create(nil, True, False, '');
    try
      Sock := Client.Send(TWebSocketRequest.Create(
        'ws://127.0.0.1:' + IntToStr(Srv.Port) + '/race', RecRef)
        .WithAutoRequest.WithCloseTimeoutMs(50));
      AssertTrue('open', Rec.WaitCount(1));
      // Abort and Close race on two threads while the server drops the
      // connection and this thread releases the socket
      Th1 := TWsActThread.Create(Sock, 0, Start1);
      Th2 := TWsActThread.Create(Sock, 1, Start1);
      Start1.SetEvent;
      try
        case I mod 3 of
          0: Sock.Abort;
          1: Sock.Close(1000, 'r');
        else
          Srv.CloseConnection;
        end;
      except
        // see TWsActThread
      end;
      Sock.Abort;
      Th1.WaitFor;
      Th2.WaitFor;
      Th1.Free;
      Th2.Free;
      Sock := nil;
      AssertTrue('ended in round ' + IntToStr(I), Obs.WaitForEnds(1, 5000));
      AssertEquals('one start', 1, Obs.StartCount);
      AssertEquals('exactly one end in round ' + IntToStr(I), 1, Obs.EndCount);
    finally
      Start1.Free;
      Srv.Terminate;
      Srv.Release.SetEvent;
      Srv.CloseConnection;
      Srv.ShutdownListener;
      Srv.Done.WaitFor(3000);
      Srv.Free;
    end;
  end;
end;

{ 21.7 }

procedure TWsObservabilityTest.TestCountersSeparateMessagesFromPingsAndBytes;
var
  Sock: IWebSocket;
  I: Integer;
  O: THttpOutcome;
begin
  Start(ScriptSeven, []);
  Sock := Open;
  AssertTrue('open', FRec.WaitCount(1));
  for I := 1 to 10 do
    Sock.SendText('xyz');
  AssertTrue('ended', Ended);
  O := FObs.Outcome(0).O;
  AssertEquals('seven messages in, two pings not counted', 7, O.MessagesIn);
  AssertEquals('ten messages out', 10, O.MessagesOut);
  AssertEquals('bytes in are the data payloads', 14, O.BytesIn);
  AssertEquals('bytes out are the data payloads', 30, O.BytesOut);
  AssertTrue('remote close', O.ClosedBy = ciRemote);
  AssertEquals('done', 'done', O.CloseReason);
end;

procedure TWsObservabilityTest.TestConcurrentSendersLoseNoCounts;
const
  cThreads = 4;
  cEach = 50;
var
  Sock: IWebSocket;
  Threads: array[0..cThreads - 1] of TWsSendThread;
  Go: TEvent;
  I: Integer;
  O: THttpOutcome;
begin
  Start(ScriptCountFrames, []);
  Sock := Open;
  AssertTrue('open', FRec.WaitCount(1));
  Go := TEvent.Create(nil, True, False, '');
  try
    for I := 0 to cThreads - 1 do
      Threads[I] := TWsSendThread.Create(Sock, cEach, Go);
    Go.SetEvent;
    for I := 0 to cThreads - 1 do
    begin
      Threads[I].WaitFor;
      AssertEquals('sender ' + IntToStr(I), '', Threads[I].Failure);
      Threads[I].Free;
    end;
  finally
    Go.Free;
  end;
  Sock.Close(1000, '');
  AssertTrue('ended', Ended);
  O := FObs.Outcome(0).O;
  AssertEquals('every message counted', cThreads * cEach, O.MessagesOut);
  AssertEquals('every byte counted', cThreads * cEach * 3, O.BytesOut);
  AssertEquals('and the server received them all', cThreads * cEach, FSrvTexts);
  AssertEquals(cThreads * cEach * 3, FSrvBytes);
end;

{ 21.8 }

procedure TWsObservabilityTest.TestWireStampsGiveTheAggregates;
const
  T0 = 1000000;
var
  Sock: IWebSocket;
  O: THttpOutcome;
begin
  GFakeNowUs := T0;
  SetNowUsHook(FakeNow);
  Start(ScriptStamps, [mkWsText]);
  Sock := Open;
  // each message is read at the clock the test holds when the server sends it
  AssertTrue('m1', FObs.WaitMessages(1, 5000));
  GFakeNowUs := T0 + 250;
  FGo.SetEvent;
  AssertTrue('m2', FObs.WaitMessages(2, 5000));
  GFakeNowUs := T0 + 260;
  FGo.SetEvent;
  AssertTrue('m3', FObs.WaitMessages(3, 5000));
  AssertEquals('first has no predecessor', 0, FObs.MessageAt(0).SinceLastUs);
  AssertEquals('first arrival', 0, FObs.MessageAt(0).ArrivedUs);
  AssertEquals('second gap', 250, FObs.MessageAt(1).SinceLastUs);
  AssertEquals('second arrival', 250, FObs.MessageAt(1).ArrivedUs);
  AssertEquals('third gap', 10, FObs.MessageAt(2).SinceLastUs);
  AssertEquals('indexes', 2, FObs.MessageAt(2).Index);
  AssertEquals('size', 2, FObs.MessageAt(2).Size);
  GFakeNowUs := T0 + 400;
  Sock.Abort;
  AssertTrue('ended', Ended);
  O := FObs.Outcome(0).O;
  AssertEquals('three messages', 3, O.MessagesIn);
  AssertEquals('first message time', 0, O.FirstMessageUs);
  AssertEquals('last message time', 260, O.LastMessageUs);
  AssertEquals('largest gap', 250, O.MaxGapUs);
  AssertEquals('summed gaps', 260, O.SumGapUs);
  AssertEquals('end time', 400, O.EndUs);
end;

procedure TWsObservabilityTest.TestFragmentedMessageTakesTheStampOfItsLastRead;
const
  T0 = 2000000;
var
  Sock: IWebSocket;
  O: THttpOutcome;
begin
  GFakeNowUs := T0;
  SetNowUsHook(FakeNow);
  Start(ScriptFragmentStamp, [mkWsText]);
  Sock := Open;
  AssertTrue('first fragment sent', FSeen.WaitFor(5000) = wrSignaled);
  // the first fragment arrived at T0; the message completes 300 us later
  GFakeNowUs := T0 + 300;
  FGo.SetEvent;
  AssertTrue('message', FObs.WaitMessages(1, 5000));
  AssertEquals('one message for two fragments', 1, FObs.MessageCount);
  AssertEquals('stamp of the final frame', 300, FObs.MessageAt(0).ArrivedUs);
  AssertEquals('size is the whole message', 4, FObs.MessageAt(0).Size);
  Sock.Abort;
  AssertTrue('ended', Ended);
  O := FObs.Outcome(0).O;
  AssertEquals('counted once', 1, O.MessagesIn);
  AssertEquals(4, O.BytesIn);
end;

{ 21.9 }

procedure TWsObservabilityTest.TestOptedInObserverSeesEveryKindInOrder;
var
  Sock: IWebSocket;
  I, N: Integer;
  Prev: Int64;
  M: TMessageInfo;
  O: THttpOutcome;
begin
  Start(ScriptKinds, [mkWsText, mkWsBinary, mkWsPing, mkWsPong, mkWsClose]);
  Sock := Open;
  AssertTrue('open', FRec.WaitCount(1));
  Sock.SendText('hi');
  Sock.SendBinary(BytesOf('abc'));
  AssertTrue('ended', Ended);
  AssertEquals('what arrived, in wire order', 'text,binary,ping,pong,close',
    KindsOf(mdIn));
  // outbound: the two data messages, the automatic pong and the echoed close
  AssertTrue('data out in order',
    (Pos('text', KindsOf(mdOut)) > 0) and
    (Pos('text', KindsOf(mdOut)) < Pos('binary', KindsOf(mdOut))));
  AssertTrue('the pong for the ping', Pos('pong', KindsOf(mdOut)) > 0);
  AssertTrue('the echoed close ends the outbound side',
    Copy(KindsOf(mdOut), Length(KindsOf(mdOut)) - 4, 5) = 'close');
  // per direction: index counts every kind, sizes are payload bytes
  N := 0;
  Prev := -1;
  for I := 0 to FObs.MessageCount - 1 do
  begin
    M := FObs.MessageAt(I);
    if M.Direction <> mdIn then
      Continue;
    AssertEquals('inbound index ' + IntToStr(N), N, M.Index);
    if N = 0 then
      AssertEquals('first inbound has no predecessor', 0, M.SinceLastUs)
    else
      AssertTrue('stamps never go backwards', M.ArrivedUs >= Prev);
    Prev := M.ArrivedUs;
    case N of
      0: AssertEquals('text size', 3, M.Size);
      1: AssertEquals('binary size', 2, M.Size);
      2: AssertEquals('ping size', 1, M.Size);
      3: AssertEquals('pong size', 1, M.Size);
      4: AssertEquals('close size: code and reason', 5, M.Size);
    end;
    Inc(N);
  end;
  AssertEquals('five inbound messages', 5, N);
  O := FObs.Outcome(0).O;
  AssertEquals('ping, pong and close are not data messages', 2, O.MessagesIn);
  AssertEquals('two data messages out', 2, O.MessagesOut);
  AssertTrue('remote close', O.ClosedBy = ciRemote);
end;

procedure TWsObservabilityTest.TestEmptySetAndOtherKindsSeeNothing;
var
  Sock: IWebSocket;
  O: THttpOutcome;
  I: Integer;
begin
  // an observer that wants nothing sees no message, but the aggregates stand
  Start(ScriptKinds, []);
  Sock := Open;
  AssertTrue('open', FRec.WaitCount(1));
  Sock.SendText('hi');
  Sock.SendBinary(BytesOf('abc'));
  AssertTrue('ended', Ended);
  AssertEquals('no OnMessage with an empty set', 0, FObs.MessageCount);
  O := FObs.Outcome(0).O;
  AssertEquals('aggregates in', 2, O.MessagesIn);
  AssertEquals('aggregates out', 2, O.MessagesOut);
  StopServer;
  FRec.Socket := nil;
  FObsRef := nil;
  FObs := nil;
  FClient := nil;
  // an observer that wants text only is not called for the other kinds
  Start(ScriptKinds, [mkWsText]);
  Sock := Open;
  AssertTrue('open', FRec.WaitCount(1));
  Sock.SendText('hi');
  Sock.SendBinary(BytesOf('abc'));
  AssertTrue('ended', Ended);
  AssertEquals('text in and text out only', 'text', KindsOf(mdIn));
  AssertEquals('text out', 'text', KindsOf(mdOut));
  AssertEquals('two messages', 2, FObs.MessageCount);
  // the two reports come from two threads (the reader and the sender), so
  // their order in the record is not fixed: look each up by direction.  The
  // automatic pong for the server's ping is outbound too, and takes index 0
  // when it is written before the text is, so the text is 0 or 1 and the
  // inbound text, the server's first message, is always 0
  AssertTrue('one in and one out',
    FObs.MessageAt(0).Direction <> FObs.MessageAt(1).Direction);
  for I := 0 to 1 do
    if FObs.MessageAt(I).Direction = mdIn then
      AssertEquals('inbound text is the first inbound message', 0,
        FObs.MessageAt(I).Index)
    else
      AssertTrue('outbound text comes first or just after the pong',
        FObs.MessageAt(I).Index in [0, 1]);
end;

{ 21.11 }

procedure TWsObservabilityTest.TestStampsIncludeTheConsumersWaitWithoutDemand;
const
  T0 = 3000000;
var
  Sock: IWebSocket;
begin
  GFakeNowUs := T0;
  SetNowUsHook(FakeNow);
  Start(ScriptPingThenText, [mkWsPing, mkWsText]);
  // no WithAutoRequest and no Request(n): the reader reads the ping, answers
  // it, and parks until the consumer asks for the notification
  Sock := Open(TWebSocketRequest.Create(Url, FRecRef));
  AssertTrue('the server saw the pong', FSeen.WaitFor(5000) = wrSignaled);
  AssertTrue('the ping was reported at the wire', FObs.WaitMessages(1, 5000));
  AssertEquals('the text has not been read yet', 1, FObs.MessageCount);
  // the text is already on the socket, but the reader will not read it until
  // the consumer has made demand, and the consumer is slow
  GFakeNowUs := T0 + 500;
  Sock.Request(2);
  AssertTrue('the text', FObs.WaitMessages(2, 5000));
  AssertEquals('kinds in order', 'ping,text', KindsOf(mdIn));
  AssertEquals('the text carries the consumer''s wait', 500,
    FObs.MessageAt(1).SinceLastUs);
  Sock.Abort;
end;

procedure TWsObservabilityTest.TestAutoRequestKeepsTheConsumersWaitOutOfTheStamps;
const
  T0 = 4000000;
var
  Sock: IWebSocket;
begin
  GFakeNowUs := T0;
  SetNowUsHook(FakeNow);
  Start(ScriptPingThenText, [mkWsPing, mkWsText]);
  Sock := Open;                      // WithAutoRequest
  AssertTrue('the server saw the pong', FSeen.WaitFor(5000) = wrSignaled);
  // the reader keeps reading: the text is stamped when it arrives, so the
  // slow consumer (the clock moving afterwards) changes nothing
  AssertTrue('ping and text reported', FObs.WaitMessages(2, 5000));
  GFakeNowUs := T0 + 500;
  AssertEquals('kinds in order', 'ping,text', KindsOf(mdIn));
  AssertEquals('no gap between the two arrivals', 0,
    FObs.MessageAt(1).SinceLastUs);
  Sock.Abort;
end;

{ 21.12 }

procedure TWsObservabilityTest.TestRaisingObserverNeverBreaksTheSession;
var
  Sock: IWebSocket;
begin
  Start(ScriptEchoClose, [mkWsText, mkWsClose]);
  FObs.RaiseOn := 'OnResponseHeaders,OnAttemptEnd';
  FObs.RaiseOnMessage := True;
  Sock := Open;
  AssertTrue('open', FRec.WaitCount(1));
  Sock.SendText('echo me');
  AssertTrue('the echo reaches the listener', FRec.WaitCount(2));
  AssertEquals('text:echo me:1', FRec.Item(1));
  Sock.Close(1000, 'ok');
  AssertTrue('the listener still gets the close', FRec.WaitCount(3));
  AssertEquals('close:1000:ok', FRec.Item(2));
  AssertTrue('and the attempt ends', Ended);
  AssertEquals('once', 1, FObs.EndCount);
  AssertTrue('local', FObs.Outcome(0).O.ClosedBy = ciLocal);
end;

initialization
  RegisterTest(TWsRequestContextTest);
  RegisterTest(TWsObservabilityTest);
end.
