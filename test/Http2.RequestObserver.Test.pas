/// Request observer tests (doc/design/request-observability.md)
// - NOTHING here opens a real socket: the HTTP/2 cases run against the scripted
//   frame-level peer of Http2.Redirects.Test, the cleartext and HTTP/1.1 cases
//   against the scripted sockets of Http2.ClearText.Test.
// - non-vacuous by construction: the injected header values are asserted from
//   the DECODED request HEADERS the peer captured, the attempt order from the
//   events a recording observer saw, and every end is counted, so a missing,
//   duplicated or premature OnAttemptEnd fails a test.
// - waits are event-driven with bounded timeouts; nothing sleeps to wait for
//   another thread.
unit Http2.RequestObserver.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, SyncObjs, Generics.Collections, fpcunit, testregistry,
  Http2.Errors, Http2.Headers, Http2.Tls, Http2.Stream, Http2.Messages,
  Http2.Client, Http2.Clock, Http2.RequestObserver, Http2.Redirects.Test,
  Http2.ClearText.Test, Http2.Http1, Http2.Http1.Test;

type
  /// a thread-safe ordered log shared by several observers
  TEventLog = class
  private
    FLock: TCriticalSection;
    FItems: TStringList;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Add(const AItem: string);
    function Text: string;
    function Count: Integer;
  end;

  /// one recorded outcome with the exception reduced to its class name
  TRecordedOutcome = record
    O: THttpOutcome;
    ErrorClass: string;
    ErrorMessage: string;
  end;

  /// an observer that records every callback.  Attempt n gets token n, and the
  /// log reads 'S0 H0 R0 E0 S1 ...' (Start, Headers, Redirect, reTry, End).
  TRecordingRequestObserver = class(TBaseRequestObserver)
  private
    FLock: TCriticalSection;
    FChanged: PRTLEvent;
    FLog: TEventLog;
    FOwnLog: Boolean;
    FTag: string;
    FAttempts: TList<THttpAttempt>;
    FOutcomes: TList<TRecordedOutcome>;
    FEndCount: Integer;
    FStarts: Integer;
    procedure Note(const AKind: Char; const AToken: IInterface);
    procedure MaybeRaise(const ACallback: string);
  public
    /// header to inject on every attempt ('' = none); the value is
    /// '<prefix>-<n>', fresh per attempt
    InjectName: string;
    InjectPrefix: string;
    /// the first value of InjectName seen before the injection, per attempt
    SeenBefore: TStringList;
    /// callbacks (comma separated, e.g. 'OnAttemptEnd') that raise
    RaiseOn: string;
    constructor Create(const ALog: TEventLog = nil; const ATag: string = '');
    destructor Destroy; override;
    function OnAttemptStart(const A: THttpAttempt): IInterface; override;
    procedure OnResponseHeaders(const AToken: IInterface;
      const AResponse: IHttpResponse); override;
    procedure OnRedirect(const AToken: IInterface; const AFromUrl,
      AToUrl: string; const AStatus: LongInt); override;
    procedure OnRetry(const AToken: IInterface;
      const AReason: string); override;
    procedure OnAttemptEnd(const AToken: IInterface;
      const O: THttpOutcome); override;
    /// the callbacks seen, as 'S0 H0 R0 E0 S1 ...'
    function Order: string;
    function Attempt(const AIndex: Integer): THttpAttempt;
    function Outcome(const AIndex: Integer): TRecordedOutcome;
    function StartCount: Integer;
    function EndCount: Integer;
    /// bounded wait until at least ACount ends were recorded
    function WaitForEnds(const ACount, ATimeoutMs: Integer): Boolean;
  end;

  /// a logger that keeps its messages
  TRecordingLogger = class(TInterfacedObject, IHttpLogger)
  private
    FLock: TCriticalSection;
    FLevels: TList<TLogLevel>;
    FMessages: TStringList;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Log(const ALevel: TLogLevel; const AMessage: string);
    function Count: Integer;
    function MessageAt(const AIndex: Integer): string;
    function LevelAt(const AIndex: Integer): TLogLevel;
  end;

  /// counts how often a codec reports an end
  TCountingExchange = class(TInterfacedObject, IExchangeObserver)
  private
    FEnds: LongInt;
    FAbandoned: LongInt;
  public
    procedure RouteChosen(const AProtocol: TNegotiatedProtocol;
      const AReused: Boolean);
    procedure RequestWritten(const ABytesOut: Int64);
    procedure ExchangeEnded(const AEnd: TExchangeEnd);
    property Ends: LongInt read FEnds;
    property Abandoned: LongInt read FAbandoned;
  end;

  TClockTest = class(TTestCase)
  published
    procedure TestNowUsNeverDecreases;
    procedure TestNowUsMeasuresElapsedTime;
  end;

  TRequestContextTest = class(TTestCase)
  published
    procedure TestContextSurvivesCloneWithUrlDropBodyAndMethodToken;
    procedure TestHeaderSinkSetValueReplaces;
  end;

  TRequestObserverTest = class(TTestCase)
  private
    function Build(const AFactory: TFakeFrameFactory;
      const AObserver: IHttpClientObserver;
      const ALogger: IHttpLogger = nil): IHttpClient;
    function ReadToEnd(const AResponse: IHttpResponse): Integer;
  published
    // 18.5 / 18.6 / 18.7
    procedure TestCompositeRunsStartInOrderAndEndInReverse;
    procedure TestCompositeSkipsAMemberThatRaises;
    procedure TestFactoryAccumulatesObserversAndForksStayApart;
    procedure TestRaisingObserverDoesNotFailSendAndIsLogged;
    // 18.8 / 18.9 / 18.14
    procedure TestRedirectChainYieldsOneAttemptPerHop;
    procedure TestContextReachesEveryHop;
    procedure TestCallerAndObserverHeadersCoexistAsOneValue;
    procedure TestRefusedStreamRetryIsItsOwnAttempt;
    procedure TestNoObserverClonesNothing;
    procedure TestRequestFailureBeforeSendStillEnds;
    procedure TestCancelledRequestReportsCancelled;
    // 18.10 / 18.12 / 18.13
    procedure TestBodyEofEndsTheAttemptOnce;
    procedure TestSecondRequestReportsAReusedConnection;
    procedure TestBodylessResponseEndsAtOnce;
    procedure TestResetStreamEndsWithTheError;
    procedure TestConnectionLossEndsWithTheError;
    procedure TestUnreadResponseDroppedEndsAbandoned;
    procedure TestRequestBodySizeIsReported;
    procedure TestEndsRacingConnectionFailureFireOnce;
  end;

  THttp1ObserverTest = class(TTestCase)
  private
    function Send(const AFactory: IHttp2SocketFactory;
      const AObserver: IHttpClientObserver; const AUrl: string;
      const APolicy: TClearTextPolicy; out AClient: IHttpClient): IHttpResponse;
  published
    // 18.11
    procedure TestContentLengthBodyEndsAtEof;
    procedure TestChunkedBodyEndsAtEof;
    procedure TestUntilCloseBodyEndsAtEof;
    procedure TestDroppedHttp1ResponseIsAbandoned;
    procedure TestEmptyHttp1BodyEndsAtOnce;
    procedure TestBodyStreamReportsOnceForEofAndRelease;
    // 18.16
    procedure TestHttp1TlsFallbackProducesStartAndEnd;
    procedure TestPriorKnowledgeH2cProducesStartAndEnd;
    procedure TestDeclinedUpgradeProducesStartAndEnd;
    procedure TestCleartextHttp1ProducesStartAndEnd;
    procedure TestHttp1RequestBodySizeIsReported;
  end;

implementation

function BytesOf(const S: string): TBytes;
var
  I: Integer;
begin
  Result := nil;
  SetLength(Result, Length(S));
  for I := 1 to Length(S) do
    Result[I - 1] := Ord(S[I]);
end;

{ TEventLog }

constructor TEventLog.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FItems := TStringList.Create;
end;

destructor TEventLog.Destroy;
begin
  FItems.Free;
  FLock.Free;
  inherited Destroy;
end;

procedure TEventLog.Add(const AItem: string);
begin
  FLock.Acquire;
  try
    FItems.Add(AItem);
  finally
    FLock.Release;
  end;
end;

function TEventLog.Text: string;
var
  I: Integer;
begin
  FLock.Acquire;
  try
    Result := '';
    for I := 0 to FItems.Count - 1 do
    begin
      if I > 0 then
        Result := Result + ' ';
      Result := Result + FItems[I];
    end;
  finally
    FLock.Release;
  end;
end;

function TEventLog.Count: Integer;
begin
  FLock.Acquire;
  try
    Result := FItems.Count;
  finally
    FLock.Release;
  end;
end;

type
  IAttemptIndex = interface
    ['{7D1E5A02-3B94-4C6F-8E21-5A0C9B3D6FA1}']
    function GetIndex: Integer;
  end;

  /// the token an observer hands back: the attempt's index
  TAttemptToken = class(TInterfacedObject, IAttemptIndex)
  public
    Index: Integer;
    function GetIndex: Integer;
  end;

function TAttemptToken.GetIndex: Integer;
begin
  Result := Index;
end;

{ TRecordingRequestObserver }

constructor TRecordingRequestObserver.Create(const ALog: TEventLog;
  const ATag: string);
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FChanged := RTLEventCreate;
  FAttempts := TList<THttpAttempt>.Create;
  FOutcomes := TList<TRecordedOutcome>.Create;
  SeenBefore := TStringList.Create;
  FTag := ATag;
  if ALog = nil then
  begin
    FLog := TEventLog.Create;
    FOwnLog := True;
  end
  else
    FLog := ALog;
end;

destructor TRecordingRequestObserver.Destroy;
begin
  if FOwnLog then
    FLog.Free;
  SeenBefore.Free;
  FOutcomes.Free;
  FAttempts.Free;
  RTLEventDestroy(FChanged);
  FLock.Free;
  inherited Destroy;
end;

procedure TRecordingRequestObserver.Note(const AKind: Char;
  const AToken: IInterface);
var
  Index: Integer;
begin
  Index := -1;
  if AToken <> nil then
    Index := (AToken as IAttemptIndex).GetIndex;
  if FTag <> '' then
    FLog.Add(FTag + '.' + AKind)
  else
    FLog.Add(AKind + IntToStr(Index));
end;

procedure TRecordingRequestObserver.MaybeRaise(const ACallback: string);
begin
  if Pos(ACallback, RaiseOn) > 0 then
    raise Exception.Create('observer failed in ' + ACallback);
end;

function TRecordingRequestObserver.OnAttemptStart(
  const A: THttpAttempt): IInterface;
var
  T: TAttemptToken;
  N: Integer;
begin
  FLock.Acquire;
  try
    N := FStarts;
    Inc(FStarts);
    FAttempts.Add(A);
  finally
    FLock.Release;
  end;
  T := TAttemptToken.Create;
  T.Index := N;
  Result := T;
  if FTag <> '' then
    FLog.Add(FTag + '.S')
  else
    FLog.Add('S' + IntToStr(N));
  MaybeRaise('OnAttemptStart');
  if InjectName <> '' then
  begin
    SeenBefore.Add(A.Headers.GetFirst(InjectName));
    A.Headers.SetValue(InjectName, InjectPrefix + '-' + IntToStr(N + 1));
  end;
end;

procedure TRecordingRequestObserver.OnResponseHeaders(const AToken: IInterface;
  const AResponse: IHttpResponse);
begin
  Note('H', AToken);
  MaybeRaise('OnResponseHeaders');
end;

procedure TRecordingRequestObserver.OnRedirect(const AToken: IInterface;
  const AFromUrl, AToUrl: string; const AStatus: LongInt);
begin
  Note('R', AToken);
  MaybeRaise('OnRedirect');
end;

procedure TRecordingRequestObserver.OnRetry(const AToken: IInterface;
  const AReason: string);
begin
  Note('T', AToken);
  MaybeRaise('OnRetry');
end;

procedure TRecordingRequestObserver.OnAttemptEnd(const AToken: IInterface;
  const O: THttpOutcome);
var
  Rec: TRecordedOutcome;
begin
  Rec.O := O;
  Rec.O.Error := nil;
  Rec.ErrorClass := '';
  Rec.ErrorMessage := '';
  if O.Error <> nil then
  begin
    Rec.ErrorClass := O.Error.ClassName;
    Rec.ErrorMessage := O.Error.Message;
  end;
  FLock.Acquire;
  try
    FOutcomes.Add(Rec);
    Inc(FEndCount);
  finally
    FLock.Release;
  end;
  Note('E', AToken);
  RTLEventSetEvent(FChanged);
  MaybeRaise('OnAttemptEnd');
end;

function TRecordingRequestObserver.Order: string;
begin
  Result := FLog.Text;
end;

function TRecordingRequestObserver.Attempt(const AIndex: Integer): THttpAttempt;
begin
  FLock.Acquire;
  try
    Result := FAttempts[AIndex];
  finally
    FLock.Release;
  end;
end;

function TRecordingRequestObserver.Outcome(
  const AIndex: Integer): TRecordedOutcome;
begin
  FLock.Acquire;
  try
    Result := FOutcomes[AIndex];
  finally
    FLock.Release;
  end;
end;

function TRecordingRequestObserver.StartCount: Integer;
begin
  FLock.Acquire;
  try
    Result := FStarts;
  finally
    FLock.Release;
  end;
end;

function TRecordingRequestObserver.EndCount: Integer;
begin
  FLock.Acquire;
  try
    Result := FEndCount;
  finally
    FLock.Release;
  end;
end;

function TRecordingRequestObserver.WaitForEnds(const ACount,
  ATimeoutMs: Integer): Boolean;
var
  Deadline: QWord;
begin
  Deadline := GetTickCount64 + QWord(ATimeoutMs);
  while True do
  begin
    if EndCount >= ACount then
      Exit(True);
    if GetTickCount64 >= Deadline then
      Exit(False);
    RTLEventWaitFor(FChanged, 20);
  end;
end;

{ TRecordingLogger }

constructor TRecordingLogger.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FLevels := TList<TLogLevel>.Create;
  FMessages := TStringList.Create;
end;

destructor TRecordingLogger.Destroy;
begin
  FMessages.Free;
  FLevels.Free;
  FLock.Free;
  inherited Destroy;
end;

procedure TRecordingLogger.Log(const ALevel: TLogLevel;
  const AMessage: string);
begin
  FLock.Acquire;
  try
    FLevels.Add(ALevel);
    FMessages.Add(AMessage);
  finally
    FLock.Release;
  end;
end;

function TRecordingLogger.Count: Integer;
begin
  FLock.Acquire;
  try
    Result := FMessages.Count;
  finally
    FLock.Release;
  end;
end;

function TRecordingLogger.MessageAt(const AIndex: Integer): string;
begin
  FLock.Acquire;
  try
    Result := FMessages[AIndex];
  finally
    FLock.Release;
  end;
end;

function TRecordingLogger.LevelAt(const AIndex: Integer): TLogLevel;
begin
  FLock.Acquire;
  try
    Result := FLevels[AIndex];
  finally
    FLock.Release;
  end;
end;

{ TCountingExchange }

procedure TCountingExchange.RouteChosen(const AProtocol: TNegotiatedProtocol;
  const AReused: Boolean);
begin
end;

procedure TCountingExchange.RequestWritten(const ABytesOut: Int64);
begin
end;

procedure TCountingExchange.ExchangeEnded(const AEnd: TExchangeEnd);
begin
  InterlockedIncrement(FEnds);
  if AEnd.Abandoned then
    InterlockedIncrement(FAbandoned);
end;

{ TClockTest }

procedure TClockTest.TestNowUsNeverDecreases;
var
  I: Integer;
  Prev, Cur: Int64;
begin
  Prev := NowUs;
  for I := 1 to 1000000 do
  begin
    Cur := NowUs;
    if Cur < Prev then
      Fail('the clock stepped backwards at read ' + IntToStr(I));
    Prev := Cur;
  end;
end;

procedure TClockTest.TestNowUsMeasuresElapsedTime;
var
  A, B: Int64;
begin
  A := NowUs;
  Sleep(10);      // the sleep is the thing measured, not a wait on a thread
  B := NowUs;
  AssertTrue('at least 9 ms elapsed', B - A >= 9000);
  AssertTrue('at most 50 ms elapsed', B - A <= 50000);
end;

{ TRequestContextTest }

procedure TRequestContextTest.TestContextSurvivesCloneWithUrlDropBodyAndMethodToken;
var
  Ctx: IInterface;
  R: THttpRequest;
begin
  Ctx := TInterfacedObject.Create;
  R := THttpRequest.Create(hmPost, 'https://a.example/x')
    .WithBody(THttpBody.FromString('x')).WithContext(Ctx);
  AssertTrue('context is set', R.Context = Ctx);
  AssertTrue('Clone keeps it', R.Clone.Context = Ctx);
  AssertTrue('WithUrl keeps it', R.WithUrl('https://b.example/').Context = Ctx);
  AssertTrue('DropBody keeps it', R.DropBody.Context = Ctx);
  AssertTrue('WithMethodToken keeps it', R.WithMethodToken('PURGE').Context = Ctx);
  AssertTrue('a fresh request has none',
    THttpRequest.Create(hmGet, 'https://a.example/').Context = nil);
end;

procedure TRequestContextTest.TestHeaderSinkSetValueReplaces;
var
  H: IHttpHeaders;
  Sink: IHeaderSink;
begin
  H := NewHttpHeaders;
  H.Add('traceparent', 'caller-1');
  H.Add('traceparent', 'caller-2');
  Sink := THeaderSink.Create(H);
  AssertEquals('the sink reads the first value', 'caller-1',
    Sink.GetFirst('traceparent'));
  Sink.SetValue('traceparent', 'observer');
  AssertEquals('one value remains', 1, Length(H.GetValues('traceparent')));
  AssertEquals('it is the observer''s', 'observer', H.GetFirst('traceparent'));
  Sink.SetValue('baggage', 'k=v');
  AssertEquals('a new header is added', 'k=v', H.GetFirst('baggage'));
end;

{ TRequestObserverTest }

function TRequestObserverTest.Build(const AFactory: TFakeFrameFactory;
  const AObserver: IHttpClientObserver; const ALogger: IHttpLogger): IHttpClient;
var
  F: THttpClientFactory;
begin
  F := THttpClientFactory.Create.WithSocketFactory(AFactory);
  if AObserver <> nil then
    F := F.WithRequestObserver(AObserver);
  if ALogger <> nil then
    F := F.WithLogger(ALogger);
  Result := F.Build;
end;

function TRequestObserverTest.ReadToEnd(const AResponse: IHttpResponse): Integer;
var
  Buf: array[0..255] of Byte;
  N: LongInt;
begin
  Result := 0;
  repeat
    N := AResponse.Body.Read(Buf, SizeOf(Buf));
    if N > 0 then
      Inc(Result, N);
  until N <= 0;
end;

procedure TRequestObserverTest.TestCompositeRunsStartInOrderAndEndInReverse;
var
  Log: TEventLog;
  A, B, C: IHttpClientObserver;
  Comp: IHttpClientObserver;
  Att: THttpAttempt;
  Tok: IInterface;
  O: THttpOutcome;
begin
  Log := TEventLog.Create;
  try
    A := TRecordingRequestObserver.Create(Log, 'A');
    B := TRecordingRequestObserver.Create(Log, 'B');
    C := TRecordingRequestObserver.Create(Log, 'C');
    Comp := TCompositeObserver.Create([A, B, C]);
    FillChar(Att, SizeOf(Att), 0);
    Att.Headers := nil;
    Tok := Comp.OnAttemptStart(Att);
    Comp.OnResponseHeaders(Tok, nil);
    FillChar(O, SizeOf(O), 0);
    Comp.OnAttemptEnd(Tok, O);
    AssertEquals('start and headers in registration order, end reversed',
      'A.S B.S C.S A.H B.H C.H C.E B.E A.E', Log.Text);
  finally
    Log.Free;
  end;
end;

procedure TRequestObserverTest.TestCompositeSkipsAMemberThatRaises;
var
  Log: TEventLog;
  Logger: TRecordingLogger;
  LoggerRef: IHttpLogger;
  A, B, C: TRecordingRequestObserver;
  IA, IB, IC: IHttpClientObserver;
  Comp: IHttpClientObserver;
  Att: THttpAttempt;
  Tok: IInterface;
  O: THttpOutcome;
begin
  Log := TEventLog.Create;
  try
    Logger := TRecordingLogger.Create;
    LoggerRef := Logger;
    A := TRecordingRequestObserver.Create(Log, 'A');
    B := TRecordingRequestObserver.Create(Log, 'B');
    C := TRecordingRequestObserver.Create(Log, 'C');
    IA := A; IB := B; IC := C;
    FillChar(Att, SizeOf(Att), 0);
    FillChar(O, SizeOf(O), 0);

    // a member whose start raises gets no further callback
    B.RaiseOn := 'OnAttemptStart';
    Comp := TCompositeObserver.Create([IA, IB, IC], LoggerRef);
    Tok := Comp.OnAttemptStart(Att);
    Comp.OnAttemptEnd(Tok, O);
    AssertEquals('the raising member is skipped', 'A.S B.S C.S C.E A.E',
      Log.Text);
    AssertEquals('one warning', 1, Logger.Count);
    AssertTrue('at warn level', Logger.LevelAt(0) = llWarn);
    AssertTrue('naming the callback',
      Pos('OnAttemptStart', Logger.MessageAt(0)) > 0);

    // a member that raises later does not stop the rest
    Tok := nil;
    B.RaiseOn := 'OnResponseHeaders,OnAttemptEnd';
    Tok := Comp.OnAttemptStart(Att);
    Comp.OnResponseHeaders(Tok, nil);
    Comp.OnAttemptEnd(Tok, O);
    AssertEquals('later members still run',
      'A.S B.S C.S C.E A.E A.S B.S C.S A.H B.H C.H C.E B.E A.E', Log.Text);
    AssertEquals('two more warnings', 3, Logger.Count);
  finally
    Log.Free;
  end;
end;

procedure TRequestObserverTest.TestFactoryAccumulatesObserversAndForksStayApart;
var
  F0, F1, F2, F3: THttpClientFactory;
  O1, O2, O3: IHttpClientObserver;
begin
  O1 := TBaseRequestObserver.Create;
  O2 := TBaseRequestObserver.Create;
  O3 := TBaseRequestObserver.Create;
  F0 := THttpClientFactory.Create;
  AssertEquals('an unset factory has none', 0, Length(F0.RequestObservers));
  F1 := F0.WithRequestObserver(O1);
  F2 := F1.WithRequestObserver(O2);
  F3 := F1.WithRequestObserver(O3);
  AssertEquals('the base is untouched', 0, Length(F0.RequestObservers));
  AssertEquals('one call installs one', 1, Length(F1.RequestObservers));
  AssertEquals('two calls install two', 2, Length(F2.RequestObservers));
  AssertTrue('in registration order', F2.RequestObservers[0] = O1);
  AssertTrue('second is the second', F2.RequestObservers[1] = O2);
  AssertEquals('a fork has its own list', 2, Length(F3.RequestObservers));
  AssertTrue('a fork does not see its sibling', F3.RequestObservers[1] = O3);
  AssertTrue('the sibling kept its own', F2.RequestObservers[1] = O2);
end;

procedure TRequestObserverTest.TestRaisingObserverDoesNotFailSendAndIsLogged;
var
  Factory: TFakeFrameFactory;
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Logger: TRecordingLogger;
  LoggerRef: IHttpLogger;
  Client: IHttpClient;
  R: IHttpResponse;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([HdrSpec('200')]));
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  Obs.RaiseOn := 'OnAttemptStart';
  Logger := TRecordingLogger.Create;
  LoggerRef := Logger;
  Client := Build(Factory, ObsRef, LoggerRef);
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  AssertEquals('the request succeeded', 200, R.StatusCode);
  AssertEquals('one warning', 1, Logger.Count);
  AssertTrue('at warn level', Logger.LevelAt(0) = llWarn);
  AssertTrue('naming the callback',
    Pos('OnAttemptStart', Logger.MessageAt(0)) > 0);
  Client.Close;
end;

procedure TRequestObserverTest.TestRedirectChainYieldsOneAttemptPerHop;
var
  Factory: TFakeFrameFactory;
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  Req: THttpRequest;
  R: IHttpResponse;
  Sock: TFakeFrameSocket;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([
    HdrSpec('302', '/b'), HdrSpec('302', '/c'), HdrSpec('200')]));
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  Obs.InjectName := 'traceparent';
  Obs.InjectPrefix := 'tp';
  Client := Build(Factory, ObsRef);
  Req := THttpRequest.Create(hmGet, 'https://a.example/a')
    .WithHeader('x-caller', 'yes');
  R := Client.Send(Req);
  AssertEquals('final status', 200, R.StatusCode);
  AssertEquals('three starts', 3, Obs.StartCount);
  AssertEquals('three ends', 3, Obs.EndCount);
  AssertEquals('hop 0', 0, Obs.Attempt(0).Hop);
  AssertEquals('hop 1', 1, Obs.Attempt(1).Hop);
  AssertEquals('hop 2', 2, Obs.Attempt(2).Hop);
  AssertEquals('hop 1 url', 'https://a.example/b', Obs.Attempt(1).Url);
  AssertEquals('host', 'a.example', Obs.Attempt(0).Host);
  AssertEquals('port', 443, Obs.Attempt(0).Port);
  AssertEquals('method', 'GET', Obs.Attempt(0).Method);
  AssertTrue('a plain request', Obs.Attempt(0).Kind = akRequest);
  AssertEquals('the callbacks interleave as the design gives',
    'S0 H0 R0 E0 S1 H1 R1 E1 S2 H2 E2', Obs.Order);
  Sock := Factory.SocketAt(0);
  AssertTrue('three requests were sent', Sock.WaitForRequests(3, 2000));
  AssertTrue('hop 0 carried a fresh value',
    Pos('traceparent: tp-1', Sock.RequestAt(0).HeaderLines) > 0);
  AssertTrue('hop 1 carried a fresh value',
    Pos('traceparent: tp-2', Sock.RequestAt(1).HeaderLines) > 0);
  AssertTrue('hop 2 carried a fresh value',
    Pos('traceparent: tp-3', Sock.RequestAt(2).HeaderLines) > 0);
  AssertTrue('hop 1 did not carry hop 0''s value',
    Pos('tp-1', Sock.RequestAt(1).HeaderLines) = 0);
  AssertTrue('no hop saw a header before the observer set it',
    (Obs.SeenBefore.Count = 3) and (Obs.SeenBefore[0] = '') and
    (Obs.SeenBefore[1] = '') and (Obs.SeenBefore[2] = ''));
  AssertTrue('the caller header travelled on every hop',
    Pos('x-caller: yes', Sock.RequestAt(2).HeaderLines) > 0);
  AssertFalse('the caller''s request is unchanged',
    Req.Headers.Contains('traceparent'));
  AssertEquals('the caller still has one header', 1, Length(Req.Headers.Names));
  AssertEquals('hop 0 status', 302, Obs.Outcome(0).O.StatusCode);
  AssertFalse('hop 0 dialled', Obs.Outcome(0).O.ConnectionReused);
  AssertTrue('hop 1 reused the connection', Obs.Outcome(1).O.ConnectionReused);
  AssertTrue('over TLS HTTP/2', Obs.Outcome(0).O.Protocol = npHttp2Tls);
  Client.Close;
end;

type
  TContextProbe = class(TInterfacedObject)
  end;

procedure TRequestObserverTest.TestContextReachesEveryHop;
var
  Factory: TFakeFrameFactory;
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  Ctx: IInterface;
  R: IHttpResponse;
  I: Integer;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([
    HdrSpec('302', '/b'), HdrSpec('307', '/c'), HdrSpec('200')]));
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  Client := Build(Factory, ObsRef);
  Ctx := TContextProbe.Create;
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/a')
    .WithContext(Ctx));
  AssertEquals(200, R.StatusCode);
  for I := 0 to 2 do
    AssertTrue('hop ' + IntToStr(I) + ' carries the context',
      Obs.Attempt(I).Context = Ctx);
  Client.Close;
end;

procedure TRequestObserverTest.TestCallerAndObserverHeadersCoexistAsOneValue;
var
  Factory: TFakeFrameFactory;
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  Req: THttpRequest;
  Lines: string;
  First, Second: Integer;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([HdrSpec('200')]));
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  Obs.InjectName := 'traceparent';
  Obs.InjectPrefix := 'obs';
  Client := Build(Factory, ObsRef);
  Req := THttpRequest.Create(hmGet, 'https://a.example/x')
    .WithHeader('traceparent', 'from-caller')
    .WithHeader('baggage', 'k=v');
  Client.Send(Req);
  AssertTrue('the sink saw the caller''s value first',
    (Obs.SeenBefore.Count = 1) and (Obs.SeenBefore[0] = 'from-caller'));
  AssertTrue('the request was sent',
    Factory.SocketAt(0).WaitForRequests(1, 2000));
  Lines := Factory.SocketAt(0).RequestAt(0).HeaderLines;
  First := Pos('traceparent:', Lines);
  AssertTrue('traceparent is on the wire', First > 0);
  Second := Pos('traceparent:', Copy(Lines, First + 1, MaxInt));
  AssertEquals('exactly one traceparent', 0, Second);
  AssertTrue('and it is the observer''s', Pos('traceparent: obs-1', Lines) > 0);
  AssertTrue('the caller''s other header coexists', Pos('baggage: k=v', Lines) > 0);
  AssertEquals('the caller''s own request keeps its value', 'from-caller',
    Req.Headers.GetFirst('traceparent'));
  Client.Close;
end;

procedure TRequestObserverTest.TestRefusedStreamRetryIsItsOwnAttempt;
var
  Factory: TFakeFrameFactory;
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([RstSpec(ecRefusedStream), HdrSpec('200')]));
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  Client := Build(Factory, ObsRef);
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  AssertEquals('the retry succeeded', 200, R.StatusCode);
  AssertEquals('two attempts', 2, Obs.StartCount);
  AssertEquals('retry counter, first', 0, Obs.Attempt(0).Retry);
  AssertEquals('retry counter, second', 1, Obs.Attempt(1).Retry);
  AssertEquals('both on hop 0', 0, Obs.Attempt(1).Hop);
  AssertEquals('retry fires before the failed attempt ends',
    'S0 T0 E0 S1 H1 E1', Obs.Order);
  AssertEquals('the refused attempt has no status', 0,
    Obs.Outcome(0).O.StatusCode);
  AssertEquals('it failed with the stream error', 'EHttpStreamError',
    Obs.Outcome(0).ErrorClass);
  AssertEquals('the retry ended clean', '', Obs.Outcome(1).ErrorClass);
  Client.Close;
end;

procedure TRequestObserverTest.TestNoObserverClonesNothing;
var
  Factory: TFakeFrameFactory;
  Obs: IHttpClientObserver;
  Plain, Observed: IHttpClient;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([HdrSpec('200')]));
  Plain := Build(Factory, nil);
  Plain.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  AssertEquals('no observer, no clone', 0, (Plain as THttpClient).ClonedAttempts);
  Plain.Close;
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([HdrSpec('200')]));
  Obs := TBaseRequestObserver.Create;
  Observed := Build(Factory, Obs);
  Observed.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  AssertEquals('an observer clones once per attempt', 1,
    (Observed as THttpClient).ClonedAttempts);
  Observed.Close;
end;

procedure TRequestObserverTest.TestRequestFailureBeforeSendStillEnds;
var
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  Raised: Boolean;
begin
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  // the strict cleartext default refuses the request before any dial
  Client := THttpClientFactory.Create.WithSocketFactory(TNeverDialFactory.Create)
    .WithRequestObserver(ObsRef).Build;
  Raised := False;
  try
    Client.Send(THttpRequest.Create(hmGet, 'http://plain.example/x'));
  except
    on E: EHttpProtocolError do Raised := True;
  end;
  AssertTrue('the request failed', Raised);
  AssertEquals('a start is paired with one end', 'S0 E0', Obs.Order);
  AssertEquals('no status', 0, Obs.Outcome(0).O.StatusCode);
  AssertEquals('the error reached the outcome', 'EHttpProtocolError',
    Obs.Outcome(0).ErrorClass);
  Client.Close;
end;

procedure TRequestObserverTest.TestCancelledRequestReportsCancelled;
var
  Factory: TFakeFrameFactory;
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  Token: TCancellationToken;
  TokenRef: ICancellationToken;
  Raised: Boolean;
begin
  Factory := TFakeFrameFactory.Create;
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  Client := Build(Factory, ObsRef);
  Token := TCancellationToken.Create;
  TokenRef := Token;
  Token.Cancel;
  Raised := False;
  try
    Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x')
      .WithCancelToken(TokenRef));
  except
    on E: EHttpStreamError do Raised := True;
  end;
  AssertTrue('the request was cancelled', Raised);
  AssertEquals('S0 E0', Obs.Order);
  AssertTrue('the outcome says cancelled', Obs.Outcome(0).O.Cancelled);
  Client.Close;
end;

procedure TRequestObserverTest.TestBodyEofEndsTheAttemptOnce;
var
  Factory: TFakeFrameFactory;
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  O: THttpOutcome;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([
    HdrSpec('200', '', BytesOf('hello'), True)]));
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  Client := Build(Factory, ObsRef);
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  AssertEquals('the body is unread, so the attempt is open', 0, Obs.EndCount);
  AssertEquals('five bytes', 5, ReadToEnd(R));
  AssertEquals('EOF ended the attempt', 1, Obs.EndCount);
  AssertEquals('order', 'S0 H0 E0', Obs.Order);
  O := Obs.Outcome(0).O;
  AssertEquals('status', 200, O.StatusCode);
  AssertEquals('bytes in', 5, O.BytesIn);
  AssertEquals('no request body', 0, O.BytesOut);
  AssertFalse('read to the end', O.Abandoned);
  AssertFalse('not cancelled', O.Cancelled);
  AssertEquals('no error', '', Obs.Outcome(0).ErrorClass);
  AssertFalse('a fresh connection', O.ConnectionReused);
  AssertTrue('HTTP/2 over TLS', O.Protocol = npHttp2Tls);
  AssertTrue('request written before headers', O.RequestSentUs <= O.HeadersUs);
  AssertTrue('headers before the end', O.HeadersUs <= O.EndUs);
  R := nil;
  AssertEquals('releasing the finished response adds no second end', 1,
    Obs.EndCount);
  Client.Close;
end;

procedure TRequestObserverTest.TestSecondRequestReportsAReusedConnection;
var
  Factory: TFakeFrameFactory;
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([HdrSpec('200')]));
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  Client := Build(Factory, ObsRef);
  Client.Send(THttpRequest.Create(hmGet, 'https://a.example/1'));
  Client.Send(THttpRequest.Create(hmGet, 'https://a.example/2'));
  AssertFalse('first dialled', Obs.Outcome(0).O.ConnectionReused);
  AssertTrue('second reused', Obs.Outcome(1).O.ConnectionReused);
  Client.Close;
end;

procedure TRequestObserverTest.TestBodylessResponseEndsAtOnce;
var
  Factory: TFakeFrameFactory;
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([HdrSpec('204')]));
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  Client := Build(Factory, ObsRef);
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  AssertEquals('nothing is left to read: the attempt ended', 1, Obs.EndCount);
  AssertEquals('headers precede the end', 'S0 H0 E0', Obs.Order);
  AssertFalse('not abandoned', Obs.Outcome(0).O.Abandoned);
  AssertEquals('status', 204, Obs.Outcome(0).O.StatusCode);
  R := nil;
  AssertEquals('release adds nothing', 1, Obs.EndCount);
  Client.Close;
end;

procedure TRequestObserverTest.TestResetStreamEndsWithTheError;
var
  Factory: TFakeFrameFactory;
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  Buf: array[0..15] of Byte;
  Raised: Boolean;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([HdrRstSpec(ecInternalError)]));
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  Client := Build(Factory, ObsRef);
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  AssertEquals('headers arrived, the attempt is open', 0, Obs.EndCount);
  Raised := False;
  try
    R.Body.Read(Buf, SizeOf(Buf));
  except
    on E: EHttpStreamError do Raised := True;
  end;
  AssertTrue('the read failed', Raised);
  AssertEquals('one end', 1, Obs.EndCount);
  AssertEquals('the stream error', 'EHttpStreamError',
    Obs.Outcome(0).ErrorClass);
  AssertEquals('headers had arrived', 200, Obs.Outcome(0).O.StatusCode);
  AssertFalse('an error is not abandonment', Obs.Outcome(0).O.Abandoned);
  AssertFalse('not a cancel', Obs.Outcome(0).O.Cancelled);
  R := nil;
  AssertEquals('release adds nothing', 1, Obs.EndCount);
  Client.Close;
end;

procedure TRequestObserverTest.TestConnectionLossEndsWithTheError;
var
  Factory: TFakeFrameFactory;
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
begin
  Factory := TFakeFrameFactory.Create;
  // a response head that never ends: the body stays open
  Factory.SetDialScript(0, SpecArray([HdrSpec('200', '', nil, False)]));
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  Client := Build(Factory, ObsRef);
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  AssertEquals('open while the body is pending', 0, Obs.EndCount);
  Factory.SocketAt(0).Close;
  AssertTrue('the connection failure ends the attempt',
    Obs.WaitForEnds(1, 5000));
  AssertTrue('with an error', Obs.Outcome(0).ErrorClass <> '');
  AssertEquals('headers had arrived', 200, Obs.Outcome(0).O.StatusCode);
  R := nil;
  AssertEquals('release adds nothing', 1, Obs.EndCount);
  Client.Close;
end;

procedure TRequestObserverTest.TestUnreadResponseDroppedEndsAbandoned;
var
  Factory: TFakeFrameFactory;
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([
    HdrSpec('200', '', BytesOf('unread body'), True)]));
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  Client := Build(Factory, ObsRef);
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  AssertEquals('open while held', 0, Obs.EndCount);
  R := nil;
  AssertEquals('release ends it', 1, Obs.EndCount);
  AssertTrue('abandoned', Obs.Outcome(0).O.Abandoned);
  AssertEquals('no error', '', Obs.Outcome(0).ErrorClass);
  Client.Close;
end;

procedure TRequestObserverTest.TestRequestBodySizeIsReported;
var
  Factory: TFakeFrameFactory;
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([HdrSpec('200')]));
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  Client := Build(Factory, ObsRef);
  Client.Send(THttpRequest.Create(hmPost, 'https://a.example/x')
    .WithBody(THttpBody.FromString('payload')));
  AssertEquals('seven body bytes went out', 7, Obs.Outcome(0).O.BytesOut);
  Client.Close;
end;

type
  TBodyReaderThread = class(TThread)
  private
    FBody: IHttpBodyStream;
  protected
    procedure Execute; override;
  public
    constructor Create(const ABody: IHttpBodyStream);
  end;

constructor TBodyReaderThread.Create(const ABody: IHttpBodyStream);
begin
  FBody := ABody;
  inherited Create(False);
end;

procedure TBodyReaderThread.Execute;
var
  Buf: array[0..63] of Byte;
  N: LongInt;
begin
  try
    repeat
      N := FBody.Read(Buf, SizeOf(Buf));
    until N <= 0;
  except
    // the connection may fail under the reader: that is the race under test
  end;
end;

procedure TRequestObserverTest.TestEndsRacingConnectionFailureFireOnce;
var
  I: Integer;
  Factory: TFakeFrameFactory;
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  T: TBodyReaderThread;
begin
  for I := 1 to 40 do
  begin
    Factory := TFakeFrameFactory.Create;
    Factory.SetDialScript(0, SpecArray([
      HdrSpec('200', '', BytesOf('some body bytes'), True)]));
    Obs := TRecordingRequestObserver.Create;
    ObsRef := Obs;
    Client := Build(Factory, ObsRef);
    R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
    // the body is read on one thread while the connection fails and the
    // response is released on this one
    T := TBodyReaderThread.Create(R.Body);
    Factory.SocketAt(0).Close;
    T.WaitFor;
    T.Free;
    R := nil;
    AssertTrue('an end arrived', Obs.WaitForEnds(1, 5000));
    Client.Close;
    AssertEquals('exactly one end per start (round ' + IntToStr(I) + ')',
      Obs.StartCount, Obs.EndCount);
    Client := nil;
    ObsRef := nil;
  end;
end;

{ THttp1ObserverTest }

function THttp1ObserverTest.Send(const AFactory: IHttp2SocketFactory;
  const AObserver: IHttpClientObserver; const AUrl: string;
  const APolicy: TClearTextPolicy; out AClient: IHttpClient): IHttpResponse;
begin
  AClient := THttpClientFactory.Create
    .WithSocketFactory(AFactory)
    .WithHttp1Fallback
    .WithClearText(APolicy)
    .WithConnectTimeout(2000).WithHeaderTimeout(2000)
    .WithRequestObserver(AObserver)
    .Build;
  Result := AClient.Send(THttpRequest.Create(hmGet, AUrl));
end;

function ReadAll(const AResponse: IHttpResponse): Integer;
var
  Buf: array[0..63] of Byte;
  N: LongInt;
begin
  Result := 0;
  repeat
    N := AResponse.Body.Read(Buf, SizeOf(Buf));
    if N > 0 then
      Inc(Result, N);
  until N <= 0;
end;

procedure THttp1ObserverTest.TestContentLengthBodyEndsAtEof;
var
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
begin
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  R := Send(TScriptProtocolFactory.Create(npHttp1Tls,
    'HTTP/1.1 200 OK'#13#10'Content-Length: 5'#13#10#13#10'hello'), ObsRef,
    'https://secure.example/x', ctReject, Client);
  AssertEquals('open until read', 0, Obs.EndCount);
  AssertEquals('five bytes', 5, ReadAll(R));
  AssertEquals('one end at EOF', 1, Obs.EndCount);
  AssertEquals('order', 'S0 H0 E0', Obs.Order);
  AssertEquals('bytes in', 5, Obs.Outcome(0).O.BytesIn);
  AssertEquals('status', 200, Obs.Outcome(0).O.StatusCode);
  AssertFalse('not abandoned', Obs.Outcome(0).O.Abandoned);
  AssertTrue('HTTP/1.1 over TLS', Obs.Outcome(0).O.Protocol = npHttp1Tls);
  AssertFalse('a fresh connection', Obs.Outcome(0).O.ConnectionReused);
  R := nil;
  AssertEquals('release adds nothing', 1, Obs.EndCount);
  Client.Close;
end;

procedure THttp1ObserverTest.TestChunkedBodyEndsAtEof;
var
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
begin
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  R := Send(TScriptProtocolFactory.Create(npHttp1Tls,
    'HTTP/1.1 200 OK'#13#10'Transfer-Encoding: chunked'#13#10#13#10 +
    '5'#13#10'hello'#13#10'0'#13#10#13#10), ObsRef,
    'https://secure.example/x', ctReject, Client);
  AssertEquals('open until read', 0, Obs.EndCount);
  AssertEquals('five decoded bytes', 5, ReadAll(R));
  AssertEquals('one end at EOF', 1, Obs.EndCount);
  AssertEquals('bytes in', 5, Obs.Outcome(0).O.BytesIn);
  AssertFalse('not abandoned', Obs.Outcome(0).O.Abandoned);
  Client.Close;
end;

procedure THttp1ObserverTest.TestUntilCloseBodyEndsAtEof;
var
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
begin
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  R := Send(TScriptProtocolFactory.Create(npHttp1Tls,
    'HTTP/1.1 200 OK'#13#10#13#10'hello'), ObsRef,
    'https://secure.example/x', ctReject, Client);
  AssertEquals('open until read', 0, Obs.EndCount);
  AssertEquals('five bytes', 5, ReadAll(R));
  AssertEquals('one end at EOF', 1, Obs.EndCount);
  AssertEquals('bytes in', 5, Obs.Outcome(0).O.BytesIn);
  AssertFalse('not abandoned', Obs.Outcome(0).O.Abandoned);
  Client.Close;
end;

procedure THttp1ObserverTest.TestDroppedHttp1ResponseIsAbandoned;
var
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
begin
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  R := Send(TScriptProtocolFactory.Create(npHttp1Tls,
    'HTTP/1.1 200 OK'#13#10'Content-Length: 5'#13#10#13#10'hello'), ObsRef,
    'https://secure.example/x', ctReject, Client);
  AssertEquals('open while held', 0, Obs.EndCount);
  R := nil;
  AssertEquals('release ends it', 1, Obs.EndCount);
  AssertTrue('abandoned', Obs.Outcome(0).O.Abandoned);
  Client.Close;
end;

procedure THttp1ObserverTest.TestEmptyHttp1BodyEndsAtOnce;
var
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
begin
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  R := Send(TScriptProtocolFactory.Create(npHttp1Tls,
    'HTTP/1.1 204 No Content'#13#10#13#10), ObsRef,
    'https://secure.example/x', ctReject, Client);
  AssertEquals('nothing to read: ended', 1, Obs.EndCount);
  AssertEquals('headers precede the end', 'S0 H0 E0', Obs.Order);
  AssertFalse('not abandoned', Obs.Outcome(0).O.Abandoned);
  R := nil;
  AssertEquals('release adds nothing', 1, Obs.EndCount);
  Client.Close;
end;

procedure THttp1ObserverTest.TestBodyStreamReportsOnceForEofAndRelease;
var
  Exch: TCountingExchange;
  ExchRef: IExchangeObserver;
  Conn: THttp1Connection;
  Script: TSocketScript;
  ScriptRef: IHttp2Socket;
  R: IHttpResponse;
  Req: TStreamRequest;
begin
  // the codec-level latch: EOF and a later release report one end between them
  Exch := TCountingExchange.Create;
  ExchRef := Exch;
  Script := TSocketScript.Create;
  ScriptRef := Script;
  Script.Feed('HTTP/1.1 200 OK'#13#10'Content-Length: 3'#13#10#13#10'abc');
  Conn := THttp1Connection.Create(ScriptRef);
  try
    Req := TStreamRequest.Create('GET', 'h.example').WithExchange(ExchRef);
    R := Conn.Send(Req);
    AssertEquals('three bytes', 3, ReadAll(R));
    AssertEquals('EOF reported once', 1, Exch.Ends);
    R := nil;
    AssertEquals('release adds none', 1, Exch.Ends);
    AssertEquals('and was not abandoned', 0, Exch.Abandoned);
  finally
    Conn.Free;
  end;
end;

procedure THttp1ObserverTest.TestHttp1TlsFallbackProducesStartAndEnd;
var
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
begin
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  R := Send(TScriptProtocolFactory.Create(npHttp1Tls,
    'HTTP/1.1 200 OK'#13#10'Content-Length: 2'#13#10#13#10'ok'), ObsRef,
    'https://secure.example/x', ctReject, Client);
  ReadAll(R);
  AssertEquals('start, headers, end', 'S0 H0 E0', Obs.Order);
  AssertTrue('HTTP/1.1 over TLS', Obs.Outcome(0).O.Protocol = npHttp1Tls);
  Client.Close;
end;

procedure THttp1ObserverTest.TestPriorKnowledgeH2cProducesStartAndEnd;
var
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
begin
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  R := Send(TFramePeerPlainFactory.Create('200', BytesOf('0123456789')), ObsRef,
    'http://127.0.0.1:28080/small.txt', ctPriorKnowledge, Client);
  AssertEquals('ten bytes', 10, ReadAll(R));
  AssertEquals('start, headers, end', 'S0 H0 E0', Obs.Order);
  AssertTrue('HTTP/2 over cleartext',
    Obs.Outcome(0).O.Protocol = npHttp2Cleartext);
  AssertEquals('bytes in', 10, Obs.Outcome(0).O.BytesIn);
  Client.Close;
end;

procedure THttp1ObserverTest.TestDeclinedUpgradeProducesStartAndEnd;
var
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
begin
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  R := Send(TScriptProtocolFactory.Create(npHttp1Cleartext,
    'HTTP/1.1 200 OK'#13#10'Content-Length: 5'#13#10#13#10'hello'), ObsRef,
    'http://plain.example/x', ctUpgrade, Client);
  AssertEquals('five bytes', 5, ReadAll(R));
  AssertEquals('start, headers, end', 'S0 H0 E0', Obs.Order);
  AssertTrue('the declined upgrade is HTTP/1.1',
    Obs.Outcome(0).O.Protocol = npHttp1Cleartext);
  AssertEquals('bytes in', 5, Obs.Outcome(0).O.BytesIn);
  AssertFalse('not abandoned', Obs.Outcome(0).O.Abandoned);
  Client.Close;
end;

procedure THttp1ObserverTest.TestCleartextHttp1ProducesStartAndEnd;
var
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
begin
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  R := Send(TScriptProtocolFactory.Create(npHttp1Cleartext,
    'HTTP/1.1 200 OK'#13#10'Content-Length: 5'#13#10#13#10'hello'), ObsRef,
    'http://plain.example/x', ctHttp1, Client);
  AssertEquals('five bytes', 5, ReadAll(R));
  AssertEquals('start, headers, end', 'S0 H0 E0', Obs.Order);
  AssertTrue('cleartext HTTP/1.1', Obs.Outcome(0).O.Protocol = npHttp1Cleartext);
  Client.Close;
end;

procedure THttp1ObserverTest.TestHttp1RequestBodySizeIsReported;
var
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
begin
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  Client := THttpClientFactory.Create
    .WithSocketFactory(TScriptProtocolFactory.Create(npHttp1Tls,
      'HTTP/1.1 200 OK'#13#10'Content-Length: 2'#13#10#13#10'ok'))
    .WithHttp1Fallback.WithRequestObserver(ObsRef).Build;
  R := Client.Send(THttpRequest.Create(hmPost, 'https://secure.example/x')
    .WithBody(THttpBody.FromString('payload')));
  ReadAll(R);
  AssertEquals('the body, not the head, is counted', 7,
    Obs.Outcome(0).O.BytesOut);
  Client.Close;
end;

initialization
  RegisterTest(TClockTest);
  RegisterTest(TRequestContextTest);
  RegisterTest(TRequestObserverTest);
  RegisterTest(THttp1ObserverTest);
end.
