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
  Http2.Errors, Http2.Frames, Http2.Headers, Http2.Tls, Http2.Stream,
  Http2.Messages,
  Http2.Client, Http2.Clock, Http2.RequestObserver, Http2.Redirects.Test,
  Http2.ClearText.Test, Http2.Http1, Http2.Http1.Test, Http2.Sse;

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
  protected
    procedure TearDown; override;
  published
    procedure TestNowUsNeverDecreases;
    procedure TestNowUsMeasuresElapsedTime;
    procedure TestHookReplacesTheClockUntilReset;
  end;

  /// arrival stamps on HTTP/2: frames are injected into the scripted peer
  /// under a scripted clock, and a barrier PING makes sure the reader thread
  /// has stamped and routed each frame before the clock moves on
  TArrivalStampTest = class(TTestCase)
  private
    function Build(const AFactory: TFakeFrameFactory;
      const AObserver: IHttpClientObserver): IHttpClient;
    procedure Barrier(const ASocket: TFakeFrameSocket);
    procedure Push(const ASocket: TFakeFrameSocket; const AText: string;
      const AEndStream: Boolean; const AStampUs: Int64);
  protected
    procedure TearDown; override;
  published
    // 19.1 - 19.4
    procedure TestBuiltFramesCarryNoStamp;
    procedure TestReaderStampsFramesFromTheClock;
    procedure TestStampSurvivesTheQueue;
    procedure TestEachReadMapsToOneFrameAndOneStamp;
    procedure TestAReadInsideOneFrameKeepsItsStamp;
    // 19.6 / 19.7
    procedure TestPlainResponseAggregatesComeFromWireStamps;
    procedure TestUnreadResponseReportsNoMessages;
    procedure TestSlowConsumerDoesNotChangeTheGaps;
    procedure TestSlowConsumerOnTheRealClock;
  end;

  /// arrival stamps on HTTP/1.1
  THttp1ArrivalTest = class(TTestCase)
  protected
    procedure TearDown; override;
  published
    // 19.5 / 19.6
    procedure TestTwoTransportReadsYieldTwoStamps;
    procedure TestChunkedBodyAgreesWithContentLength;
    procedure TestBufferMixingTwoReadsAttributesBytesCorrectly;
    procedure TestAggregatesFollowTheTransportReads;
    procedure TestResponseThroughTheClientReportsAggregates;
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
    procedure TestDeclinedUpgradeKeepsTheRealWriteStamp;
    procedure TestCleartextHttp1ProducesStartAndEnd;
    procedure TestHttp1RequestBodySizeIsReported;
  end;

  /// a request observer that also opts in to per-message callbacks
  TMessageRecordingObserver = class(TRecordingRequestObserver,
    IHttpMessageObserver)
  private
    FMsgLock: TCriticalSection;
    FMessages: TList<TMessageInfo>;
    FData: TStringList;       // the Sse^.Data read inside each callback
    FWantsCalls: Integer;
  public
    /// what WantsMessages answers
    Wants: TMessageKinds;
    /// OnMessage raises (after recording)
    RaiseOnMessage: Boolean;
    constructor Create(const AWants: TMessageKinds);
    destructor Destroy; override;
    function WantsMessages(const A: THttpAttempt): TMessageKinds;
    procedure OnMessage(const AToken: IInterface; const M: TMessageInfo);
    function MessageCount: Integer;
    function MessageAt(const AIndex: Integer): TMessageInfo;
    function DataAt(const AIndex: Integer): string;
    property WantsCalls: Integer read FWantsCalls;
  end;

  /// the progress interface and the message observer plumbing, without any
  /// transport
  TMessageObserverTest = class(TTestCase)
  protected
    procedure TearDown; override;
  published
    // 20.1
    procedure TestAttemptKindStreamAndReconnectSurviveTheCopies;
    // 20.4
    procedure TestReaderReportsThreeMessagesAndTheOutcomeShowsThem;
    procedure TestFrameAggregatesStandWhenTheReaderReportsNothing;
    procedure TestDecodingResponseForwardsTheProgress;
    procedure TestUnobservedResponseAnswersAndIgnores;
    // 20.7
    procedure TestCompositeForwardsOnlyToMembersThatWantTheKind;
    procedure TestCompositeAsksEachMemberOncePerAttempt;
    procedure TestCompositeSkipsAMessageObserverThatRaises;
  end;

  /// Server-Sent Events attempts over HTTP/2: frames are injected under a
  /// scripted clock, so the stamps and gaps are exact
  TSseObservabilityTest = class(TTestCase)
  private
    function Build(const AFactory: TFakeFrameFactory;
      const AObserver: IHttpClientObserver;
      const ALogger: IHttpLogger = nil): IHttpClient;
    procedure Barrier(const ASocket: TFakeFrameSocket);
    procedure Push(const ASocket: TFakeFrameSocket; const AText: string;
      const AEndStream: Boolean; const AStampUs: Int64);
    function OpenFactory: TFakeFrameFactory;
  protected
    procedure TearDown; override;
  published
    // 20.1
    procedure TestSseRequestIsReportedAsSseAndAPlainOneIsNot;
    // 20.2 / 20.3
    procedure TestReconnectingStreamSharesOneStreamIdAndCountsReconnects;
    procedure TestEveryReconnectCarriesTheContext;
    procedure TestTwoLoopsGetTwoStreamIds;
    // 20.5 / 20.6
    procedure TestEventsTakeTheStampOfTheChunkThatCompletedThem;
    procedure TestEventsInOneFrameShareItsStamp;
    procedure TestTheLastFrameOfTheBodyIsCountedBeforeTheEnd;
    procedure TestCommentsAndKeepAlivesAreNotMessages;
    // 20.8 / 20.9
    procedure TestObserverThatWantsNothingReceivesNothing;
    procedure TestObserverReceivesEveryEventWithItsDetail;
    procedure TestWantsMessagesIsAskedOncePerAttempt;
    // 20.10
    procedure TestCloseMidStreamEndsOnceAndNotAbandoned;
    procedure TestDroppingTheSourceUnreadIsAbandoned;
    procedure TestReadingToTheEndEndsOnceNotAbandoned;
    // 20.12
    procedure TestSlowConsumerDoesNotChangeTheStamps;
    procedure TestRaisingOnMessageDoesNotBreakTheStream;
  end;

  /// the same behaviour over the HTTP/1.1 fallback
  TSseHttp1ObservabilityTest = class(TTestCase)
  protected
    procedure TearDown; override;
  published
    // 20.11
    procedure TestEventsTakeTheStampOfTheTransportReadThatCompletedThem;
    procedure TestChunkedStreamKeepsTheSameStamps;
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
  // a loaded host can oversleep; the bound only has to separate ms from s
  AssertTrue('well under a second elapsed', B - A <= 1000000);
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

var
  GTickUs: Int64;

function TickingClock: Int64;
begin
  Result := InterlockedExchangeAdd64(GTickUs, 100) + 100;
end;

procedure THttp1ObserverTest.TestDeclinedUpgradeKeepsTheRealWriteStamp;
var
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  O: THttpOutcome;
begin
  // the probe carries the request, and the pool reports "request written"
  // again once the declined response head was read; the stamp must stay at
  // the real write, which precedes the read that delivered the response
  GTickUs := 0;
  SetNowUsHook(TickingClock);
  try
    Obs := TRecordingRequestObserver.Create;
    ObsRef := Obs;
    R := Send(TScriptProtocolFactory.Create(npHttp1Cleartext,
      'HTTP/1.1 200 OK'#13#10'Content-Length: 5'#13#10#13#10'hello'), ObsRef,
      'http://plain.example/x', ctUpgrade, Client);
    AssertEquals('five bytes', 5, ReadAll(R));
    O := Obs.Outcome(0).O;
    AssertTrue('the first message arrived', O.FirstMessageUs > 0);
    AssertTrue('request written before the first byte arrived: ' +
      IntToStr(O.RequestSentUs) + ' vs ' + IntToStr(O.FirstMessageUs),
      O.RequestSentUs < O.FirstMessageUs);
    AssertTrue('request written before headers',
      O.RequestSentUs <= O.HeadersUs);
  finally
    ResetNowUsHook;
  end;
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

{ arrival stamping }

var
  /// the scripted clock the stamp tests install
  GScriptedUs: Int64;

function ScriptedClock: Int64;
begin
  Result := GScriptedUs;
end;

procedure TClockTest.TearDown;
begin
  ResetNowUsHook;
  inherited TearDown;
end;

procedure TClockTest.TestHookReplacesTheClockUntilReset;
begin
  GScriptedUs := 123456;
  SetNowUsHook(ScriptedClock);
  AssertEquals('the hook answers', 123456, NowUs);
  GScriptedUs := 7;
  AssertEquals('and follows the script', 7, NowUs);
  ResetNowUsHook;
  AssertTrue('the system clock is back', NowUs <> 7);
  GScriptedUs := 8;
  SetNowUsHook(ScriptedClock);
  AssertEquals(8, NowUs);
  SetNowUsHook(nil);
  AssertTrue('nil restores it too', NowUs <> 8);
end;

{ TArrivalStampTest }

procedure TArrivalStampTest.TearDown;
begin
  ResetNowUsHook;
  inherited TearDown;
end;

function TArrivalStampTest.Build(const AFactory: TFakeFrameFactory;
  const AObserver: IHttpClientObserver): IHttpClient;
begin
  Result := THttpClientFactory.Create.WithSocketFactory(AFactory)
    .WithRequestObserver(AObserver).Build;
end;

function CountPingAcks(const AFrames: TArray<TFrame>): Integer;
var
  K: Integer;
begin
  Result := 0;
  for K := 0 to High(AFrames) do
    if (AFrames[K].Header.FrameType = ftPing) and AFrames[K].IsAck then
      Inc(Result);
end;

procedure TArrivalStampTest.Barrier(const ASocket: TFakeFrameSocket);
var
  Before: Integer;
  Deadline: QWord;
begin
  // frames are read and routed in order, so the ACK of a PING queued behind
  // them proves the reader thread is done with every earlier frame
  Before := CountPingAcks(ASocket.WrittenFrames);
  ASocket.InjectFrame(BuildPingFrame(BytesOf('barrier!'), False));
  Deadline := GetTickCount64 + 5000;
  repeat
    if CountPingAcks(ASocket.WrittenFrames) > Before then
      Exit;
    Sleep(1);   // bounded poll on the peer's written bytes
  until GetTickCount64 >= Deadline;
  Fail('the barrier PING was never acknowledged');
end;

procedure TArrivalStampTest.Push(const ASocket: TFakeFrameSocket;
  const AText: string; const AEndStream: Boolean; const AStampUs: Int64);
begin
  GScriptedUs := AStampUs;
  ASocket.InjectFrame(BuildDataFrame(1, BytesOf(AText), AEndStream));
  Barrier(ASocket);
end;

procedure TArrivalStampTest.TestBuiltFramesCarryNoStamp;
var
  F: TFrame;
begin
  F := TFrame.Create(ftData, [], 1, BytesOf('x'));
  AssertEquals('Create', 0, F.ArrivedUs);
  AssertEquals('data builder', 0, BuildDataFrame(1, BytesOf('x'), True).ArrivedUs);
  AssertEquals('ping builder', 0,
    BuildPingFrame(BytesOf('12345678'), False).ArrivedUs);
end;

procedure TArrivalStampTest.TestReaderStampsFramesFromTheClock;
var
  Factory: TFakeFrameFactory;
  Obs: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  Sock: TFakeFrameSocket;
  Stamped: IStampedBodyStream;
  Buf: array[0..15] of Byte;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([HdrSpec('200', '', nil, False)]));
  Obs := TRecordingRequestObserver.Create;
  GScriptedUs := 1000;
  SetNowUsHook(ScriptedClock);
  Client := Build(Factory, Obs);
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  Sock := Factory.SocketAt(0);
  AssertTrue('the body is stamped', Supports(R.Body, IStampedBodyStream, Stamped));
  AssertEquals('nothing read yet', 0, Stamped.LastReadArrivedUs);
  Push(Sock, 'aaa', False, 5000);
  AssertEquals('3 bytes', 3, R.Body.Read(Buf, SizeOf(Buf)));
  AssertEquals('stamp of the first frame', 5000, Stamped.LastReadArrivedUs);
  Push(Sock, 'bb', False, 7500);
  AssertEquals('2 bytes', 2, R.Body.Read(Buf, SizeOf(Buf)));
  AssertEquals('stamp of the second frame', 7500, Stamped.LastReadArrivedUs);
  GScriptedUs := 99999;   // the consumer's clock must not matter
  R := nil;
  Client.Close;
end;

procedure TArrivalStampTest.TestStampSurvivesTheQueue;
var
  Factory: TFakeFrameFactory;
  Obs: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  Stamped: IStampedBodyStream;
  Buf: array[0..15] of Byte;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([HdrSpec('200', '', nil, False)]));
  Obs := TRecordingRequestObserver.Create;
  GScriptedUs := 1000;
  SetNowUsHook(ScriptedClock);
  Client := Build(Factory, Obs);
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  Push(Factory.SocketAt(0), 'queued', False, 4242);
  // the frame sits in the lease's queue while time passes; the delay is the
  // thing under test, not a wait on another thread
  Sleep(200);
  GScriptedUs := 4242 + 200000;
  AssertTrue(Supports(R.Body, IStampedBodyStream, Stamped));
  AssertEquals('6 bytes', 6, R.Body.Read(Buf, SizeOf(Buf)));
  AssertEquals('the arrival stamp, not the read time', 4242,
    Stamped.LastReadArrivedUs);
  R := nil;
  Client.Close;
end;

procedure TArrivalStampTest.TestEachReadMapsToOneFrameAndOneStamp;
var
  Factory: TFakeFrameFactory;
  Obs: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  Sock: TFakeFrameSocket;
  Stamped: IStampedBodyStream;
  Buf: array[0..63] of Byte;
  Stamps: array of Int64;
  Sizes: array of Integer;
  N: LongInt;
begin
  Stamps := nil;
  Sizes := nil;
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([HdrSpec('200', '', nil, False)]));
  Obs := TRecordingRequestObserver.Create;
  GScriptedUs := 1000;
  SetNowUsHook(ScriptedClock);
  Client := Build(Factory, Obs);
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  Sock := Factory.SocketAt(0);
  Push(Sock, 'one', False, 2000);
  Push(Sock, 'three', False, 2600);
  Push(Sock, '', True, 3000);
  AssertTrue(Supports(R.Body, IStampedBodyStream, Stamped));
  // a buffer large enough for both frames still gets one frame per Read
  repeat
    N := R.Body.Read(Buf, SizeOf(Buf));
    if N > 0 then
    begin
      SetLength(Stamps, Length(Stamps) + 1);
      SetLength(Sizes, Length(Sizes) + 1);
      Stamps[High(Stamps)] := Stamped.LastReadArrivedUs;
      Sizes[High(Sizes)] := N;
    end;
  until N <= 0;
  AssertEquals('two Reads returned bytes', 2, Length(Stamps));
  AssertEquals('first frame size', 3, Sizes[0]);
  AssertEquals('second frame size', 5, Sizes[1]);
  AssertEquals('first stamp', 2000, Stamps[0]);
  AssertEquals('second stamp', 2600, Stamps[1]);
  R := nil;
  Client.Close;
end;

procedure TArrivalStampTest.TestAReadInsideOneFrameKeepsItsStamp;
var
  Factory: TFakeFrameFactory;
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  Stamped: IStampedBodyStream;
  Buf: array[0..1] of Byte;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([HdrSpec('200', '', nil, False)]));
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  GScriptedUs := 1000;
  SetNowUsHook(ScriptedClock);
  Client := Build(Factory, ObsRef);
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  Push(Factory.SocketAt(0), 'abcde', False, 3000);
  Push(Factory.SocketAt(0), '', True, 3500);
  AssertTrue(Supports(R.Body, IStampedBodyStream, Stamped));
  // 5 bytes in a 2-byte buffer: three Reads of one frame, one stamp
  AssertEquals(2, R.Body.Read(Buf, 2));
  AssertEquals(3000, Stamped.LastReadArrivedUs);
  AssertEquals(2, R.Body.Read(Buf, 2));
  AssertEquals(3000, Stamped.LastReadArrivedUs);
  AssertEquals(1, R.Body.Read(Buf, 2));
  AssertEquals(3000, Stamped.LastReadArrivedUs);
  AssertEquals('EOF', 0, R.Body.Read(Buf, 2));
  R := nil;
  AssertTrue(Obs.WaitForEnds(1, 5000));
  AssertEquals('one frame is one message', 1, Obs.Outcome(0).O.MessagesIn);
  AssertEquals('so no gap', 0, Obs.Outcome(0).O.MaxGapUs);
  Client.Close;
end;

procedure TArrivalStampTest.TestPlainResponseAggregatesComeFromWireStamps;
var
  Factory: TFakeFrameFactory;
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  Sock: TFakeFrameSocket;
  O: THttpOutcome;
  Buf: array[0..63] of Byte;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([HdrSpec('200', '', nil, False)]));
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  GScriptedUs := 1000000;           // the attempt starts here
  SetNowUsHook(ScriptedClock);
  Client := Build(Factory, ObsRef);
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  Sock := Factory.SocketAt(0);
  Push(Sock, 'aaaa', False, 1000100);
  Push(Sock, 'bb', False, 1000400);
  Push(Sock, 'c', False, 1000450);
  Push(Sock, '', True, 1000500);
  GScriptedUs := 1000600;
  while R.Body.Read(Buf, SizeOf(Buf)) > 0 do ;
  AssertTrue('the attempt ended', Obs.WaitForEnds(1, 5000));
  O := Obs.Outcome(0).O;
  AssertEquals('bytes', 7, O.BytesIn);
  AssertEquals('three messages', 3, O.MessagesIn);
  AssertEquals('first message', 100, O.FirstMessageUs);
  AssertEquals('last message', 450, O.LastMessageUs);
  AssertEquals('largest gap', 300, O.MaxGapUs);
  AssertEquals('summed gaps', 350, O.SumGapUs);
  R := nil;
  Client.Close;
end;

procedure TArrivalStampTest.TestUnreadResponseReportsNoMessages;
var
  Factory: TFakeFrameFactory;
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([
    HdrSpec('200', '', BytesOf('never read'), True)]));
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  Client := Build(Factory, ObsRef);
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  R := nil;
  AssertTrue(Obs.WaitForEnds(1, 5000));
  AssertTrue(Obs.Outcome(0).O.Abandoned);
  AssertEquals('nothing was consumed', 0, Obs.Outcome(0).O.MessagesIn);
  AssertEquals(0, Obs.Outcome(0).O.FirstMessageUs);
  Client.Close;
end;

procedure TArrivalStampTest.TestSlowConsumerDoesNotChangeTheGaps;
var
  Factory: TFakeFrameFactory;
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  Sock: TFakeFrameSocket;
  I: Integer;
  Buf: array[0..63] of Byte;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([HdrSpec('200', '', nil, False)]));
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  GScriptedUs := 0;
  SetNowUsHook(ScriptedClock);
  Client := Build(Factory, ObsRef);
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  Sock := Factory.SocketAt(0);
  // ten frames, 10 ms apart on the wire, all queued before the consumer
  // reads a byte (fewer than the queue's 128)
  for I := 1 to 10 do
    Push(Sock, 'frame', False, Int64(I) * 10000);
  Push(Sock, '', True, 100500);
  for I := 1 to 10 do
  begin
    // the consumer is 100 ms behind the wire on every frame
    GScriptedUs := 100500 + Int64(I) * 100000;
    AssertEquals(5, R.Body.Read(Buf, SizeOf(Buf)));
  end;
  AssertEquals(0, R.Body.Read(Buf, SizeOf(Buf)));
  AssertTrue(Obs.WaitForEnds(1, 5000));
  AssertEquals('ten messages', 10, Obs.Outcome(0).O.MessagesIn);
  AssertEquals('the wire gap, not the consumer gap', 10000,
    Obs.Outcome(0).O.MaxGapUs);
  AssertEquals(90000, Obs.Outcome(0).O.SumGapUs);
  R := nil;
  Client.Close;
end;

type
  /// reads a body with a pause after every Read, like a slow consumer
  TSlowReaderThread = class(TThread)
  private
    FBody: IHttpBodyStream;
    FPauseMs: Integer;
    FDone: PRTLEvent;
  protected
    procedure Execute; override;
  public
    constructor Create(const ABody: IHttpBodyStream; const APauseMs: Integer;
      const ADone: PRTLEvent);
  end;

constructor TSlowReaderThread.Create(const ABody: IHttpBodyStream;
  const APauseMs: Integer; const ADone: PRTLEvent);
begin
  FBody := ABody;
  FPauseMs := APauseMs;
  FDone := ADone;
  inherited Create(False);
end;

procedure TSlowReaderThread.Execute;
var
  Buf: array[0..63] of Byte;
  N: LongInt;
begin
  try
    repeat
      N := FBody.Read(Buf, SizeOf(Buf));
      Sleep(FPauseMs);   // the consumer's lateness, not a wait on a thread
    until N <= 0;
  except
  end;
  RTLEventSetEvent(FDone);
end;

procedure TArrivalStampTest.TestSlowConsumerOnTheRealClock;
var
  Factory: TFakeFrameFactory;
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  Sock: TFakeFrameSocket;
  Done: PRTLEvent;
  T: TSlowReaderThread;
  I: Integer;
  O: THttpOutcome;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([HdrSpec('200', '', nil, False)]));
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  Client := Build(Factory, ObsRef);
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  Sock := Factory.SocketAt(0);
  Done := RTLEventCreate;
  T := TSlowReaderThread.Create(R.Body, 100, Done);
  try
    for I := 1 to 6 do
    begin
      Sock.InjectFrame(BuildDataFrame(1, BytesOf('frame'), False));
      Barrier(Sock);
      Sleep(10);   // scripted 10 ms wire spacing
    end;
    Sock.InjectFrame(BuildDataFrame(1, nil, True));
    RTLEventWaitFor(Done, 15000);   // bounded; the end is asserted below
    T.WaitFor;
  finally
    T.Free;
    RTLEventDestroy(Done);
  end;
  AssertTrue(Obs.WaitForEnds(1, 5000));
  O := Obs.Outcome(0).O;
  AssertEquals('six messages', 6, O.MessagesIn);
  // the consumer lags 100 ms per frame; the wire spacing is about 10 ms. The
  // upper bound sits below the consumer's lag, not tight against the wire
  // spacing, so scheduler jitter on a loaded machine cannot fail it while a
  // gap measured at the consumer (100 ms or more) still would.
  AssertTrue('gap reflects the wire, not the consumer: ' + IntToStr(O.MaxGapUs),
    (O.MaxGapUs >= 9000) and (O.MaxGapUs < 90000));
  R := nil;
  Client.Close;
end;

{ THttp1ArrivalTest }

type
  /// a socket that hands out scripted chunks, one per read, setting the
  /// scripted clock to the chunk's stamp as the read returns
  TStagedSocket = class(TInterfacedObject, IHttp2Socket, IPartialReader)
  private
    FChunks: TArray<string>;
    FStamps: TArray<Int64>;
    FIndex: Integer;
    FOffset: Integer;
  public
    procedure Add(const AChunk: string; const AStampUs: Int64);
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

  /// keeps the last end a codec reported
  TCapturedExchange = class(TInterfacedObject, IExchangeObserver)
  public
    Ends: Integer;
    Last: TExchangeEnd;
    procedure RouteChosen(const AProtocol: TNegotiatedProtocol;
      const AReused: Boolean);
    procedure RequestWritten(const ABytesOut: Int64);
    procedure ExchangeEnded(const AEnd: TExchangeEnd);
  end;

procedure TStagedSocket.Add(const AChunk: string; const AStampUs: Int64);
begin
  SetLength(FChunks, Length(FChunks) + 1);
  SetLength(FStamps, Length(FStamps) + 1);
  FChunks[High(FChunks)] := AChunk;
  FStamps[High(FStamps)] := AStampUs;
end;

function TStagedSocket.ReadSome(var ABuffer; ACount: Integer): Integer;
var
  Rest: Integer;
begin
  if FIndex >= Length(FChunks) then
    Exit(0);
  if FOffset = 0 then
    GScriptedUs := FStamps[FIndex];
  Rest := Length(FChunks[FIndex]) - FOffset;
  Result := ACount;
  if Result > Rest then
    Result := Rest;
  Move(FChunks[FIndex][FOffset + 1], PByte(@ABuffer)^, Result);
  Inc(FOffset, Result);
  if FOffset >= Length(FChunks[FIndex]) then
  begin
    Inc(FIndex);
    FOffset := 0;
  end;
end;

function TStagedSocket.Read(var ABuffer; ACount: Integer): Integer;
begin
  Result := ReadSome(ABuffer, ACount);
end;

function TStagedSocket.Write(const ABuffer; ACount: Integer): Integer;
begin
  Result := ACount;
end;

procedure TStagedSocket.Close;
begin
end;

function TStagedSocket.GetConnected: Boolean;
begin
  Result := True;
end;

function TStagedSocket.GetConnectTimeoutMs: Integer;
begin
  Result := 1000;
end;

procedure TStagedSocket.SetConnectTimeoutMs(const AValue: Integer);
begin
end;

function TStagedSocket.GetReadTimeoutMs: Integer;
begin
  Result := 1000;
end;

procedure TStagedSocket.SetReadTimeoutMs(const AValue: Integer);
begin
end;

function TStagedSocket.GetWriteTimeoutMs: Integer;
begin
  Result := 1000;
end;

procedure TStagedSocket.SetWriteTimeoutMs(const AValue: Integer);
begin
end;

procedure TCapturedExchange.RouteChosen(const AProtocol: TNegotiatedProtocol;
  const AReused: Boolean);
begin
end;

procedure TCapturedExchange.RequestWritten(const ABytesOut: Int64);
begin
end;

procedure TCapturedExchange.ExchangeEnded(const AEnd: TExchangeEnd);
begin
  Inc(Ends);
  Last := AEnd;
end;

procedure THttp1ArrivalTest.TearDown;
begin
  ResetNowUsHook;
  inherited TearDown;
end;

procedure THttp1ArrivalTest.TestTwoTransportReadsYieldTwoStamps;
var
  Sock: TStagedSocket;
  SockRef: IHttp2Socket;
  Reader: TBufferedReader;
  BodyRef: IHttpBodyStream;
  Stamped: IStampedBodyStream;
  Buf: array[0..63] of Byte;
begin
  Sock := TStagedSocket.Create;
  SockRef := Sock;
  Sock.Add('abc', 100);     // 3 bytes, then a pause, then 5 more
  Sock.Add('defgh', 750);
  SetNowUsHook(ScriptedClock);
  Reader := TBufferedReader.Create(SockRef);
  try
    BodyRef := THttp1BodyStream.Create(Reader, bfContentLength, 8, nil);
    AssertTrue(Supports(BodyRef, IStampedBodyStream, Stamped));
    AssertEquals('first Read', 3, BodyRef.Read(Buf, SizeOf(Buf)));
    AssertEquals('first stamp', 100, Stamped.LastReadArrivedUs);
    AssertEquals('second Read', 5, BodyRef.Read(Buf, SizeOf(Buf)));
    AssertEquals('second stamp', 750, Stamped.LastReadArrivedUs);
    AssertEquals('EOF', 0, BodyRef.Read(Buf, SizeOf(Buf)));
  finally
    Stamped := nil;
    BodyRef := nil;
    Reader.Free;
  end;
end;

procedure THttp1ArrivalTest.TestChunkedBodyAgreesWithContentLength;
var
  Sock: TStagedSocket;
  SockRef: IHttp2Socket;
  Reader: TBufferedReader;
  BodyRef: IHttpBodyStream;
  Stamped: IStampedBodyStream;
  Buf: array[0..63] of Byte;
begin
  Sock := TStagedSocket.Create;
  SockRef := Sock;
  // the same 3 + 5 bytes, framed as chunks that split across the two reads
  Sock.Add('3'#13#10'abc'#13#10'5'#13#10'de', 100);
  Sock.Add('fgh'#13#10'0'#13#10#13#10, 750);
  SetNowUsHook(ScriptedClock);
  Reader := TBufferedReader.Create(SockRef);
  try
    BodyRef := THttp1BodyStream.Create(Reader, bfChunked, 0, nil);
    AssertTrue(Supports(BodyRef, IStampedBodyStream, Stamped));
    AssertEquals('first Read', 3, BodyRef.Read(Buf, SizeOf(Buf)));
    AssertEquals('first stamp', 100, Stamped.LastReadArrivedUs);
    AssertEquals('chunk bytes from the first read', 2,
      BodyRef.Read(Buf, SizeOf(Buf)));
    AssertEquals('same read, same stamp', 100, Stamped.LastReadArrivedUs);
    AssertEquals('the rest of the chunk', 3, BodyRef.Read(Buf, SizeOf(Buf)));
    AssertEquals('second read', 750, Stamped.LastReadArrivedUs);
    AssertEquals('EOF', 0, BodyRef.Read(Buf, SizeOf(Buf)));
  finally
    Stamped := nil;
    BodyRef := nil;
    Reader.Free;
  end;
end;

procedure THttp1ArrivalTest.TestBufferMixingTwoReadsAttributesBytesCorrectly;
var
  Sock: TStagedSocket;
  SockRef: IHttp2Socket;
  Reader: TBufferedReader;
  Line: string;
  Buf: array[0..63] of Byte;
begin
  Sock := TStagedSocket.Create;
  SockRef := Sock;
  Sock.Add('head'#13#10'ab', 10);
  Sock.Add('cd', 20);
  Sock.Add('ef', 30);
  SetNowUsHook(ScriptedClock);
  Reader := TBufferedReader.Create(SockRef);
  try
    AssertTrue(Reader.ReadLine(Line));
    AssertEquals('head', Line);
    // the buffer holds 'ab' from read 1; each later Fill appends a read
    AssertEquals(2, Reader.ReadBytes(Buf, 64));
    AssertEquals('bytes of read 1', 10, Reader.LastReadUs);
    AssertEquals(2, Reader.ReadBytes(Buf, 64));
    AssertEquals('bytes of read 2', 20, Reader.LastReadUs);
    AssertEquals(2, Reader.ReadBytes(Buf, 64));
    AssertEquals('bytes of read 3', 30, Reader.LastReadUs);
  finally
    Reader.Free;
  end;
end;

procedure THttp1ArrivalTest.TestAggregatesFollowTheTransportReads;
var
  Sock: TStagedSocket;
  SockRef: IHttp2Socket;
  Reader: TBufferedReader;
  Body: THttp1BodyStream;
  BodyRef: IHttpBodyStream;
  Cap: TCapturedExchange;
  CapRef: IExchangeObserver;
  Buf: array[0..63] of Byte;
begin
  Sock := TStagedSocket.Create;
  SockRef := Sock;
  Sock.Add('ab', 1000);
  Sock.Add('cd', 1300);
  Sock.Add('ef', 1350);
  SetNowUsHook(ScriptedClock);
  Cap := TCapturedExchange.Create;
  CapRef := Cap;
  Reader := TBufferedReader.Create(SockRef);
  try
    Body := THttp1BodyStream.Create(Reader, bfUntilClose, 0, nil);
    BodyRef := Body;
    Body.AttachExchange(CapRef, 0);
    // a 1-byte buffer: two Reads per transport read, still one arrival each
    while BodyRef.Read(Buf, 1) > 0 do ;
    AssertEquals('one end', 1, Cap.Ends);
    AssertEquals('three arrivals', 3, Cap.Last.Arrivals.Count);
    AssertEquals('first', 1000, Cap.Last.Arrivals.FirstUs);
    AssertEquals('last', 1350, Cap.Last.Arrivals.LastUs);
    AssertEquals('max gap', 300, Cap.Last.Arrivals.MaxGapUs);
    AssertEquals('sum', 350, Cap.Last.Arrivals.SumGapUs);
  finally
    BodyRef := nil;
    Reader.Free;
  end;
end;

procedure THttp1ArrivalTest.TestResponseThroughTheClientReportsAggregates;
var
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  Buf: array[0..63] of Byte;
  O: THttpOutcome;
begin
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  GScriptedUs := 500000;
  SetNowUsHook(ScriptedClock);
  Client := THttpClientFactory.Create
    .WithSocketFactory(TScriptProtocolFactory.Create(npHttp1Tls,
      'HTTP/1.1 200 OK'#13#10'Content-Length: 5'#13#10#13#10'hello'))
    .WithHttp1Fallback.WithClearText(ctReject)
    .WithRequestObserver(ObsRef).Build;
  R := Client.Send(THttpRequest.Create(hmGet, 'https://secure.example/x'));
  GScriptedUs := 500900;
  while R.Body.Read(Buf, SizeOf(Buf)) > 0 do ;
  AssertTrue(Obs.WaitForEnds(1, 5000));
  O := Obs.Outcome(0).O;
  AssertEquals('head and body came in one read: one message', 1, O.MessagesIn);
  AssertEquals(O.FirstMessageUs, O.LastMessageUs);
  AssertEquals(0, O.MaxGapUs);
  AssertEquals(5, O.BytesIn);
  R := nil;
  Client.Close;
end;

{ Server-Sent Events observation }

const
  /// gzip of 'hello'
  cGzipHello: array[0..24] of Byte = (31, 139, 8, 0, 0, 0, 0, 0, 2, 19, 203,
    72, 205, 201, 201, 7, 0, 134, 166, 16, 54, 5, 0, 0, 0);
  cEventStreamType = 'text/event-stream';
  cStreamUrl = 'https://a.example/events';

/// a 200 event-stream head that stays open
function SseOpenSpec: TRespSpec;
begin
  Result := WithContentType(HdrSpec('200', '', nil, False), cEventStreamType);
end;

/// a 200 event-stream response whose body ends the stream
function SseBodySpec(const ABody: string): TRespSpec;
begin
  Result := WithContentType(HdrSpec('200', '', BytesOf(ABody), True),
    cEventStreamType);
end;

/// a 200 event-stream response with a body and the stream left open
function SseOpenBodySpec(const ABody: string): TRespSpec;
begin
  Result := WithOpenBody(SseBodySpec(ABody));
end;

function NewIntf(const A: array of IHttpClientObserver):
  TArray<IHttpClientObserver>;
var
  I: Integer;
begin
  Result := nil;
  SetLength(Result, Length(A));
  for I := 0 to High(A) do
    Result[I] := A[I];
end;

{ TMessageRecordingObserver }

constructor TMessageRecordingObserver.Create(const AWants: TMessageKinds);
begin
  inherited Create;
  Wants := AWants;
  FMsgLock := TCriticalSection.Create;
  FMessages := TList<TMessageInfo>.Create;
  FData := TStringList.Create;
end;

destructor TMessageRecordingObserver.Destroy;
begin
  FData.Free;
  FMessages.Free;
  FMsgLock.Free;
  inherited Destroy;
end;

function TMessageRecordingObserver.WantsMessages(
  const A: THttpAttempt): TMessageKinds;
begin
  FMsgLock.Acquire;
  try
    Inc(FWantsCalls);
  finally
    FMsgLock.Release;
  end;
  Result := Wants;
end;

procedure TMessageRecordingObserver.OnMessage(const AToken: IInterface;
  const M: TMessageInfo);
var
  Data: string;
begin
  // the pointer is valid only here: read what the test needs now
  Data := '';
  if M.Sse <> nil then
    Data := M.Sse^.Data;
  FMsgLock.Acquire;
  try
    FMessages.Add(M);
    FData.Add(Data);
  finally
    FMsgLock.Release;
  end;
  if RaiseOnMessage then
    raise Exception.Create('observer failed in OnMessage');
end;

function TMessageRecordingObserver.MessageCount: Integer;
begin
  FMsgLock.Acquire;
  try
    Result := FMessages.Count;
  finally
    FMsgLock.Release;
  end;
end;

function TMessageRecordingObserver.MessageAt(
  const AIndex: Integer): TMessageInfo;
begin
  FMsgLock.Acquire;
  try
    Result := FMessages[AIndex];
  finally
    FMsgLock.Release;
  end;
end;

function TMessageRecordingObserver.DataAt(const AIndex: Integer): string;
begin
  FMsgLock.Acquire;
  try
    Result := FData[AIndex];
  finally
    FMsgLock.Release;
  end;
end;

{ TMessageObserverTest }

procedure TMessageObserverTest.TearDown;
begin
  ResetNowUsHook;
  inherited TearDown;
end;

procedure TMessageObserverTest.TestAttemptKindStreamAndReconnectSurviveTheCopies;
var
  Ctx: IInterface;
  R: THttpRequest;
begin
  Ctx := TInterfacedObject.Create;
  R := SseRequest(cStreamUrl).WithContext(Ctx).WithStream(7, 2);
  AssertTrue('SseRequest marks it', R.AttemptKind = akSse);
  AssertEquals(7, R.StreamId);
  AssertEquals(2, R.Reconnect);
  AssertTrue('Clone keeps the kind', R.Clone.AttemptKind = akSse);
  AssertEquals('Clone keeps the id', 7, R.Clone.StreamId);
  AssertEquals('Clone keeps the count', 2, R.Clone.Reconnect);
  AssertTrue('WithUrl', R.WithUrl('https://b.example/').AttemptKind = akSse);
  AssertEquals('WithUrl id', 7, R.WithUrl('https://b.example/').StreamId);
  AssertTrue('DropBody', R.DropBody.AttemptKind = akSse);
  AssertEquals('DropBody count', 2, R.DropBody.Reconnect);
  AssertTrue('WithMethodToken', R.WithMethodToken('PURGE').AttemptKind = akSse);
  AssertEquals('WithMethodToken id', 7, R.WithMethodToken('PURGE').StreamId);
  AssertTrue('the context is still there', R.Clone.Context = Ctx);
  R := THttpRequest.Create(hmGet, cStreamUrl);
  AssertTrue('a plain request is akRequest', R.AttemptKind = akRequest);
  AssertEquals(0, R.StreamId);
  AssertEquals(0, R.Reconnect);
end;

procedure TMessageObserverTest.TestReaderReportsThreeMessagesAndTheOutcomeShowsThem;
var
  Factory: TFakeFrameFactory;
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  P: IAttemptProgress;
  O: THttpOutcome;
  Buf: array[0..63] of Byte;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([HdrSpec('200', '', BytesOf('abcdefg'),
    True)]));
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  GScriptedUs := 1000000;
  SetNowUsHook(ScriptedClock);
  Client := THttpClientFactory.Create.WithSocketFactory(Factory)
    .WithRequestObserver(ObsRef).Build;
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  AssertTrue('the response exposes the progress',
    Supports(R, IAttemptProgress, P));
  AssertTrue('nobody asked for messages', P.WantedKinds = []);
  P.ReportMessage(mkSseEvent, mdIn, 1000100, 3, nil);
  P.ReportMessage(mkSseEvent, mdIn, 1000400, 2, nil);
  P.ReportMessage(mkSseEvent, mdIn, 1000450, 2, nil);
  P.ReportMessage(mkWsPing, mdIn, 1000460, 0, nil);   // not a data message
  P.ReportMessage(mkWsText, mdOut, 1000470, 4, nil);
  while R.Body.Read(Buf, SizeOf(Buf)) > 0 do ;
  AssertTrue('the attempt ended', Obs.WaitForEnds(1, 5000));
  O := Obs.Outcome(0).O;
  AssertEquals('three messages in (the single frame would say one)', 3,
    O.MessagesIn);
  AssertEquals('first', 100, O.FirstMessageUs);
  AssertEquals('last', 450, O.LastMessageUs);
  AssertEquals('largest gap', 300, O.MaxGapUs);
  AssertEquals('summed gaps', 350, O.SumGapUs);
  AssertEquals('one data message out', 1, O.MessagesOut);
  AssertEquals('the codec still counts the bytes', 7, O.BytesIn);
  R := nil;
  P := nil;
  Client.Close;
end;

procedure TMessageObserverTest.TestFrameAggregatesStandWhenTheReaderReportsNothing;
var
  Factory: TFakeFrameFactory;
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  Buf: array[0..63] of Byte;
begin
  // the counterpart: a reader that reports nothing leaves the codec's frame
  // aggregates in force
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([HdrSpec('200', '', BytesOf('abcdefg'),
    True)]));
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  Client := THttpClientFactory.Create.WithSocketFactory(Factory)
    .WithRequestObserver(ObsRef).Build;
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  while R.Body.Read(Buf, SizeOf(Buf)) > 0 do ;
  AssertTrue(Obs.WaitForEnds(1, 5000));
  AssertEquals('one frame, one message', 1, Obs.Outcome(0).O.MessagesIn);
  AssertEquals(0, Obs.Outcome(0).O.MessagesOut);
  R := nil;
  Client.Close;
end;

procedure TMessageObserverTest.TestDecodingResponseForwardsTheProgress;
var
  Factory: TFakeFrameFactory;
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  P: IAttemptProgress;
  Gz: TBytes;
  Buf: array[0..63] of Byte;
  N, Total: LongInt;
begin
  Gz := nil;
  SetLength(Gz, Length(cGzipHello));
  for N := 0 to High(cGzipHello) do
    Gz[N] := cGzipHello[N];
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([WithContentType(
    HdrSpec('200', '', Gz, True), 'text/plain', 'gzip')]));
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  GScriptedUs := 1000000;
  SetNowUsHook(ScriptedClock);
  Client := THttpClientFactory.Create.WithSocketFactory(Factory)
    .WithRequestObserver(ObsRef).Build;
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  AssertTrue('the decoding wrapper answers for the response it wraps',
    Supports(R, IAttemptProgress, P));
  P.ReportMessage(mkSseEvent, mdIn, 1000100, 1, nil);
  P.ReportMessage(mkSseEvent, mdIn, 1000200, 1, nil);
  Total := 0;
  repeat
    N := R.Body.Read(Buf, SizeOf(Buf));
    if N > 0 then
      Inc(Total, N);
  until N <= 0;
  AssertEquals('the body was decoded', 5, Total);
  AssertTrue(Obs.WaitForEnds(1, 5000));
  AssertEquals('the reports reached the attempt', 2,
    Obs.Outcome(0).O.MessagesIn);
  R := nil;
  P := nil;
  Client.Close;
end;

procedure TMessageObserverTest.TestUnobservedResponseAnswersAndIgnores;
var
  Factory: TFakeFrameFactory;
  Client: IHttpClient;
  R: IHttpResponse;
  P: IAttemptProgress;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([HdrSpec('200', '', BytesOf('x'), True)]));
  Client := THttpClientFactory.Create.WithSocketFactory(Factory).Build;
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  AssertTrue(Supports(R, IAttemptProgress, P));
  AssertTrue(P.WantedKinds = []);
  P.ReadBegin;
  P.ReportMessage(mkSseEvent, mdIn, 5, 1, nil);
  P.ReadEnd;
  P.Finish(1);
  R := nil;
  Client.Close;
end;

procedure TMessageObserverTest.TestCompositeForwardsOnlyToMembersThatWantTheKind;
var
  A, B, C: TMessageRecordingObserver;
  Comp: IHttpClientObserver;
  MO: IHttpMessageObserver;
  Gate: IHttpMessageGate;
  Att: THttpAttempt;
  Tok: IInterface;
  M: TMessageInfo;
begin
  A := TMessageRecordingObserver.Create([mkSseEvent]);
  B := TMessageRecordingObserver.Create([mkWsText]);
  C := TMessageRecordingObserver.Create([]);
  Comp := TCompositeObserver.Create(NewIntf([A, B, C]));
  AssertTrue(Supports(Comp, IHttpMessageObserver, MO));
  AssertTrue(Supports(Comp, IHttpMessageGate, Gate));
  FillChar(Att, SizeOf(Att), 0);
  Tok := Comp.OnAttemptStart(Att);
  AssertTrue('the gate is the union', Gate.WantedFor(Tok) = [mkSseEvent, mkWsText]);
  FillChar(M, SizeOf(M), 0);
  M.Kind := mkSseEvent;
  MO.OnMessage(Tok, M);
  AssertEquals('A wanted events', 1, A.MessageCount);
  AssertEquals('B did not', 0, B.MessageCount);
  AssertEquals('C wanted nothing', 0, C.MessageCount);
  M.Kind := mkWsText;
  MO.OnMessage(Tok, M);
  AssertEquals(1, A.MessageCount);
  AssertEquals('B wanted text', 1, B.MessageCount);
  M.Kind := mkWsPing;
  MO.OnMessage(Tok, M);
  AssertEquals(1, A.MessageCount);
  AssertEquals(1, B.MessageCount);
  AssertEquals(0, C.MessageCount);
end;

procedure TMessageObserverTest.TestCompositeAsksEachMemberOncePerAttempt;
var
  A, B: TMessageRecordingObserver;
  Comp: IHttpClientObserver;
  MO: IHttpMessageObserver;
  Att: THttpAttempt;
  T1, T2: IInterface;
  M: TMessageInfo;
  I: Integer;
begin
  A := TMessageRecordingObserver.Create([mkSseEvent]);
  B := TMessageRecordingObserver.Create([]);
  Comp := TCompositeObserver.Create(NewIntf([A, B]));
  Supports(Comp, IHttpMessageObserver, MO);
  FillChar(Att, SizeOf(Att), 0);
  T1 := Comp.OnAttemptStart(Att);
  T2 := Comp.OnAttemptStart(Att);
  FillChar(M, SizeOf(M), 0);
  M.Kind := mkSseEvent;
  for I := 1 to 5 do
  begin
    MO.OnMessage(T1, M);
    MO.OnMessage(T2, M);
  end;
  AssertEquals('A was asked once per attempt', 2, A.WantsCalls);
  AssertEquals('B too', 2, B.WantsCalls);
  AssertEquals(10, A.MessageCount);
end;

procedure TMessageObserverTest.TestCompositeSkipsAMessageObserverThatRaises;
var
  A, B: TMessageRecordingObserver;
  Logger: TRecordingLogger;
  LoggerRef: IHttpLogger;
  Comp: IHttpClientObserver;
  MO: IHttpMessageObserver;
  Att: THttpAttempt;
  Tok: IInterface;
  M: TMessageInfo;
begin
  A := TMessageRecordingObserver.Create([mkSseEvent]);
  A.RaiseOnMessage := True;
  B := TMessageRecordingObserver.Create([mkSseEvent]);
  Logger := TRecordingLogger.Create;
  LoggerRef := Logger;
  Comp := TCompositeObserver.Create(NewIntf([A, B]), LoggerRef);
  Supports(Comp, IHttpMessageObserver, MO);
  FillChar(Att, SizeOf(Att), 0);
  Tok := Comp.OnAttemptStart(Att);
  FillChar(M, SizeOf(M), 0);
  M.Kind := mkSseEvent;
  MO.OnMessage(Tok, M);
  MO.OnMessage(Tok, M);
  AssertEquals('A saw both', 2, A.MessageCount);
  AssertEquals('B was not affected', 2, B.MessageCount);
  AssertEquals('each failure was logged', 2, Logger.Count);
  AssertTrue(Pos('OnMessage', Logger.MessageAt(0)) > 0);
end;

{ TSseObservabilityTest }

procedure TSseObservabilityTest.TearDown;
begin
  ResetNowUsHook;
  inherited TearDown;
end;

function TSseObservabilityTest.Build(const AFactory: TFakeFrameFactory;
  const AObserver: IHttpClientObserver;
  const ALogger: IHttpLogger): IHttpClient;
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

function TSseObservabilityTest.OpenFactory: TFakeFrameFactory;
begin
  Result := TFakeFrameFactory.Create;
  Result.SetDialScript(0, SpecArray([SseOpenSpec]));
end;

procedure TSseObservabilityTest.Barrier(const ASocket: TFakeFrameSocket);
var
  Before: Integer;
  Deadline: QWord;
begin
  // frames are read and routed in order, so the ACK of a PING queued behind
  // them proves the reader thread is done with every earlier frame
  Before := CountPingAcks(ASocket.WrittenFrames);
  ASocket.InjectFrame(BuildPingFrame(BytesOf('barrier!'), False));
  Deadline := GetTickCount64 + 5000;
  repeat
    if CountPingAcks(ASocket.WrittenFrames) > Before then
      Exit;
    Sleep(1);   // bounded poll on the peer's written bytes
  until GetTickCount64 >= Deadline;
  Fail('the barrier PING was never acknowledged');
end;

procedure TSseObservabilityTest.Push(const ASocket: TFakeFrameSocket;
  const AText: string; const AEndStream: Boolean; const AStampUs: Int64);
begin
  GScriptedUs := AStampUs;
  ASocket.InjectFrame(BuildDataFrame(1, BytesOf(AText), AEndStream));
  Barrier(ASocket);
end;

procedure TSseObservabilityTest.TestSseRequestIsReportedAsSseAndAPlainOneIsNot;
var
  Factory: TFakeFrameFactory;
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R1, R2: IHttpResponse;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([SseOpenSpec, HdrSpec('200')]));
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  Client := Build(Factory, ObsRef);
  R1 := Client.Send(SseRequest(cStreamUrl));
  R2 := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  AssertTrue('SseRequest is akSse', Obs.Attempt(0).Kind = akSse);
  AssertTrue('a plain request is akRequest', Obs.Attempt(1).Kind = akRequest);
  AssertEquals('no stream id without a loop', 0, Obs.Attempt(0).StreamId);
  AssertEquals(0, Obs.Attempt(0).Reconnect);
  R1 := nil;
  R2 := nil;
  Client.Close;
end;

/// run a reconnect loop through three connections, one event each
procedure RunThreeConnections(const AClient: IHttpClient;
  const ARequest: THttpRequest; out AStreamId: Int64);
var
  Loop: TSseReconnectLoop;
  Ev: TSseEvent;
  I: Integer;
begin
  Loop := TSseReconnectLoop.Create(AClient, ARequest, 10);
  try
    AStreamId := Loop.StreamId;
    for I := 1 to 3 do
      if not Loop.Next(Ev) then
        raise Exception.Create('the loop ended early');
    Loop.Close;
  finally
    Loop.Free;
  end;
end;

function ThreeStreamFactory: TFakeFrameFactory;
begin
  Result := TFakeFrameFactory.Create;
  // `retry: 1` keeps the reconnect delay at a millisecond
  Result.SetDialScript(0, SpecArray([
    SseBodySpec('retry: 1'#10'id: 1'#10'data: a'#10#10),
    SseBodySpec('retry: 1'#10'id: 2'#10'data: b'#10#10),
    SseBodySpec('retry: 1'#10'id: 3'#10'data: c'#10#10)]));
end;

procedure TSseObservabilityTest.TestReconnectingStreamSharesOneStreamIdAndCountsReconnects;
var
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  Id: Int64;
  I: Integer;
begin
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  Client := Build(ThreeStreamFactory, ObsRef);
  RunThreeConnections(Client, SseRequest(cStreamUrl), Id);
  AssertTrue('three ends', Obs.WaitForEnds(3, 5000));
  AssertEquals('three attempts', 3, Obs.StartCount);
  AssertTrue('the library chose an id', Id <> 0);
  for I := 0 to 2 do
  begin
    AssertTrue('akSse', Obs.Attempt(I).Kind = akSse);
    AssertEquals('one stream id', Id, Obs.Attempt(I).StreamId);
    AssertEquals('reconnect count', I, Obs.Attempt(I).Reconnect);
  end;
  Client.Close;
end;

procedure TSseObservabilityTest.TestEveryReconnectCarriesTheContext;
var
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  Ctx: IInterface;
  Id: Int64;
  I: Integer;
begin
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  Ctx := TInterfacedObject.Create;
  Client := Build(ThreeStreamFactory, ObsRef);
  RunThreeConnections(Client, SseRequest(cStreamUrl).WithContext(Ctx), Id);
  AssertTrue(Obs.WaitForEnds(3, 5000));
  for I := 0 to 2 do
    AssertTrue('the same context in attempt ' + IntToStr(I),
      Obs.Attempt(I).Context = Ctx);
  Client.Close;
end;

procedure TSseObservabilityTest.TestTwoLoopsGetTwoStreamIds;
var
  Client: IHttpClient;
  A, B: TSseReconnectLoop;
begin
  Client := Build(TFakeFrameFactory.Create, nil);
  A := TSseReconnectLoop.Create(Client, SseRequest(cStreamUrl));
  B := TSseReconnectLoop.Create(Client, SseRequest(cStreamUrl));
  try
    AssertTrue('ids are never 0', (A.StreamId <> 0) and (B.StreamId <> 0));
    AssertTrue('and differ', A.StreamId <> B.StreamId);
  finally
    A.Free;
    B.Free;
  end;
  Client.Close;
end;

procedure TSseObservabilityTest.TestEventsTakeTheStampOfTheChunkThatCompletedThem;
var
  Factory: TFakeFrameFactory;
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  Src: IHttpSseSource;
  Sock: TFakeFrameSocket;
  Ev: TSseEvent;
  O: THttpOutcome;
  I: Integer;
begin
  Factory := OpenFactory;
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  GScriptedUs := 1000000;           // the attempt starts here
  SetNowUsHook(ScriptedClock);
  Client := Build(Factory, ObsRef);
  R := Client.Send(SseRequest(cStreamUrl));
  Sock := Factory.SocketAt(0);
  // the second event is split across the frames: it completes in the second
  Push(Sock, 'data: one'#10#10'data: tw', False, 1000100);
  Push(Sock, 'o'#10#10'data: three'#10#10, False, 1000400);
  Push(Sock, '', True, 1000500);
  Src := TSseSource.Create(R);
  for I := 1 to 3 do
    AssertTrue('event ' + IntToStr(I), Src.ReadEvent(Ev));
  AssertFalse('the stream ended', Src.ReadEvent(Ev));
  AssertTrue('the attempt ended', Obs.WaitForEnds(1, 5000));
  O := Obs.Outcome(0).O;
  AssertEquals('three events', 3, O.MessagesIn);
  AssertEquals('first event', 100, O.FirstMessageUs);
  AssertEquals('last event', 400, O.LastMessageUs);
  AssertEquals('largest gap', 300, O.MaxGapUs);
  AssertEquals('summed gaps', 300, O.SumGapUs);
  AssertEquals('bytes on the wire', 19 + 16, O.BytesIn);
  AssertFalse(O.Abandoned);
  AssertEquals(200, O.StatusCode);
  Src := nil;
  R := nil;
  Client.Close;
end;

procedure TSseObservabilityTest.TestEventsInOneFrameShareItsStamp;
var
  Factory: TFakeFrameFactory;
  Obs: TMessageRecordingObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  Src: IHttpSseSource;
  Ev: TSseEvent;
  I: Integer;
  M: TMessageInfo;
begin
  Factory := OpenFactory;
  Obs := TMessageRecordingObserver.Create([mkSseEvent]);
  ObsRef := Obs;
  GScriptedUs := 1000000;
  SetNowUsHook(ScriptedClock);
  Client := Build(Factory, ObsRef);
  R := Client.Send(SseRequest(cStreamUrl));
  Push(Factory.SocketAt(0), 'data: a'#10#10'data: bb'#10#10'data: ccc'#10#10 +
    'data: dddd'#10#10, False, 1000250);
  Push(Factory.SocketAt(0), '', True, 1000300);
  Src := TSseSource.Create(R);
  for I := 1 to 4 do
    AssertTrue(Src.ReadEvent(Ev));
  AssertFalse(Src.ReadEvent(Ev));
  AssertTrue(Obs.WaitForEnds(1, 5000));
  AssertEquals('four events', 4, Obs.Outcome(0).O.MessagesIn);
  AssertEquals('no gap inside a frame', 0, Obs.Outcome(0).O.MaxGapUs);
  AssertEquals(0, Obs.Outcome(0).O.SumGapUs);
  AssertEquals(250, Obs.Outcome(0).O.FirstMessageUs);
  AssertEquals(250, Obs.Outcome(0).O.LastMessageUs);
  AssertEquals('four callbacks', 4, Obs.MessageCount);
  for I := 0 to 3 do
  begin
    M := Obs.MessageAt(I);
    AssertEquals('index', I, M.Index);
    AssertEquals('size of event ' + IntToStr(I), I + 1, M.Size);
    AssertEquals('the chunk''s stamp', 250, M.ArrivedUs);
    AssertEquals('no gap', 0, M.SinceLastUs);
    AssertTrue('inbound', M.Direction = mdIn);
    AssertTrue('an event', M.Kind = mkSseEvent);
  end;
  Src := nil;
  R := nil;
  Client.Close;
end;

procedure TSseObservabilityTest.TestTheLastFrameOfTheBodyIsCountedBeforeTheEnd;
var
  Factory: TFakeFrameFactory;
  Obs: TMessageRecordingObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  Src: IHttpSseSource;
  Ev: TSseEvent;
  O: THttpOutcome;
begin
  Factory := OpenFactory;
  Obs := TMessageRecordingObserver.Create([mkSseEvent]);
  ObsRef := Obs;
  GScriptedUs := 1000000;
  SetNowUsHook(ScriptedClock);
  Client := Build(Factory, ObsRef);
  R := Client.Send(SseRequest(cStreamUrl));
  Push(Factory.SocketAt(0), 'data: a'#10#10, False, 1000100);
  // the final event rides the frame that carries END_STREAM, so the codec
  // ends the exchange inside the very Read that returns it
  Push(Factory.SocketAt(0), 'data: b'#10#10, True, 1000300);
  Src := TSseSource.Create(R);
  AssertTrue(Src.ReadEvent(Ev));
  AssertTrue(Src.ReadEvent(Ev));
  AssertTrue('the attempt ended', Obs.WaitForEnds(1, 5000));
  O := Obs.Outcome(0).O;
  AssertEquals('both events are in the outcome', 2, O.MessagesIn);
  AssertEquals(300, O.LastMessageUs);
  AssertEquals(200, O.MaxGapUs);
  AssertEquals('and were delivered before the end', 2, Obs.MessageCount);
  AssertFalse(O.Abandoned);
  Src := nil;
  R := nil;
  Client.Close;
end;

procedure TSseObservabilityTest.TestCommentsAndKeepAlivesAreNotMessages;
var
  Factory: TFakeFrameFactory;
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  Src: IHttpSseSource;
  Ev: TSseEvent;
  O: THttpOutcome;
begin
  Factory := OpenFactory;
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  GScriptedUs := 1000000;
  SetNowUsHook(ScriptedClock);
  Client := Build(Factory, ObsRef);
  R := Client.Send(SseRequest(cStreamUrl));
  Push(Factory.SocketAt(0), ': keep-alive'#10#10, False, 1000100);
  Push(Factory.SocketAt(0), 'data: x'#10#10, False, 1000900);
  Push(Factory.SocketAt(0), '', True, 1000950);
  Src := TSseSource.Create(R);
  AssertTrue(Src.ReadEvent(Ev));
  AssertFalse(Src.ReadEvent(Ev));
  AssertTrue(Obs.WaitForEnds(1, 5000));
  O := Obs.Outcome(0).O;
  AssertEquals('an event is a message, a frame is not', 1, O.MessagesIn);
  AssertEquals('the event''s stamp', 900, O.FirstMessageUs);
  AssertEquals(0, O.MaxGapUs);
  Src := nil;
  R := nil;
  Client.Close;
end;

procedure TSseObservabilityTest.TestObserverThatWantsNothingReceivesNothing;
var
  Factory: TFakeFrameFactory;
  Obs: TMessageRecordingObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  P: IAttemptProgress;
  Src: IHttpSseSource;
  Ev: TSseEvent;
begin
  Factory := OpenFactory;
  Obs := TMessageRecordingObserver.Create([]);
  ObsRef := Obs;
  Client := Build(Factory, ObsRef);
  R := Client.Send(SseRequest(cStreamUrl));
  AssertTrue(Supports(R, IAttemptProgress, P));
  AssertTrue('the attempt wants no messages', P.WantedKinds = []);
  Push(Factory.SocketAt(0), 'data: a'#10#10'data: b'#10#10, False, 5);
  Push(Factory.SocketAt(0), '', True, 6);
  Src := TSseSource.Create(R);
  AssertTrue(Src.ReadEvent(Ev));
  AssertTrue(Src.ReadEvent(Ev));
  AssertFalse(Src.ReadEvent(Ev));
  AssertTrue(Obs.WaitForEnds(1, 5000));
  AssertEquals('asked once', 1, Obs.WantsCalls);
  AssertEquals('no callbacks', 0, Obs.MessageCount);
  AssertEquals('the aggregates are collected anyway', 2,
    Obs.Outcome(0).O.MessagesIn);
  P := nil;
  Src := nil;
  R := nil;
  Client.Close;
end;

procedure TSseObservabilityTest.TestObserverReceivesEveryEventWithItsDetail;
var
  Factory: TFakeFrameFactory;
  Obs: TMessageRecordingObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  P: IAttemptProgress;
  Src: IHttpSseSource;
  Ev: TSseEvent;
  M: TMessageInfo;
begin
  Factory := OpenFactory;
  Obs := TMessageRecordingObserver.Create([mkSseEvent]);
  ObsRef := Obs;
  GScriptedUs := 1000000;
  SetNowUsHook(ScriptedClock);
  Client := Build(Factory, ObsRef);
  R := Client.Send(SseRequest(cStreamUrl));
  AssertTrue(Supports(R, IAttemptProgress, P));
  AssertTrue('the attempt wants events', mkSseEvent in P.WantedKinds);
  Push(Factory.SocketAt(0), 'event: tick'#10'id: 7'#10'data: hello'#10#10 +
    'data: second'#10#10, False, 1000100);
  Push(Factory.SocketAt(0), 'id: 8'#10'data: third'#10#10, False, 1000600);
  Push(Factory.SocketAt(0), '', True, 1000700);
  Src := TSseSource.Create(R);
  AssertTrue(Src.ReadEvent(Ev));
  AssertTrue(Src.ReadEvent(Ev));
  AssertTrue(Src.ReadEvent(Ev));
  AssertFalse(Src.ReadEvent(Ev));
  AssertTrue(Obs.WaitForEnds(1, 5000));
  AssertEquals('one callback per event', 3, Obs.MessageCount);
  M := Obs.MessageAt(0);
  AssertEquals('type', 'tick', M.EventType);
  AssertEquals('id', '7', M.EventId);
  AssertEquals('size', 5, M.Size);
  AssertEquals('index', 0, M.Index);
  AssertEquals('arrival', 100, M.ArrivedUs);
  AssertEquals('first has no gap', 0, M.SinceLastUs);
  AssertEquals('the event data was readable in the callback', 'hello',
    Obs.DataAt(0));
  M := Obs.MessageAt(1);
  AssertEquals('default type', 'message', M.EventType);
  AssertEquals('the id in force', '7', M.EventId);
  AssertEquals('size', 6, M.Size);
  AssertEquals('same frame, same stamp', 100, M.ArrivedUs);
  AssertEquals('so no gap', 0, M.SinceLastUs);
  AssertEquals('second', Obs.DataAt(1));
  M := Obs.MessageAt(2);
  AssertEquals('index', 2, M.Index);
  AssertEquals('new id', '8', M.EventId);
  AssertEquals('arrival', 600, M.ArrivedUs);
  AssertEquals('gap since the previous frame', 500, M.SinceLastUs);
  AssertEquals('third', Obs.DataAt(2));
  P := nil;
  Src := nil;
  R := nil;
  Client.Close;
end;

procedure TSseObservabilityTest.TestWantsMessagesIsAskedOncePerAttempt;
var
  Obs: TMessageRecordingObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  Id: Int64;
begin
  Obs := TMessageRecordingObserver.Create([mkSseEvent]);
  ObsRef := Obs;
  Client := Build(ThreeStreamFactory, ObsRef);
  RunThreeConnections(Client, SseRequest(cStreamUrl), Id);
  AssertTrue(Obs.WaitForEnds(3, 5000));
  AssertEquals('once for each of the three attempts', 3, Obs.WantsCalls);
  AssertEquals('one event per connection', 3, Obs.MessageCount);
  Client.Close;
end;

procedure TSseObservabilityTest.TestCloseMidStreamEndsOnceAndNotAbandoned;
var
  Factory: TFakeFrameFactory;
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  Loop: TSseReconnectLoop;
  Ev: TSseEvent;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([SseOpenBodySpec('id: 1'#10'data: a'#10#10)]));
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  Client := Build(Factory, ObsRef);
  Loop := TSseReconnectLoop.Create(Client, SseRequest(cStreamUrl), 0);
  try
    AssertTrue(Loop.Next(Ev));
    Loop.Close;
    AssertTrue('Close ended the attempt', Obs.WaitForEnds(1, 5000));
    AssertFalse('a deliberate Close is not an abandonment',
      Obs.Outcome(0).O.Abandoned);
    AssertTrue('and not an error', Obs.Outcome(0).ErrorClass = '');
    AssertEquals(1, Obs.Outcome(0).O.MessagesIn);
  finally
    Loop.Free;
  end;
  Client.Close;
  AssertEquals('releasing the response did not end it again', 1, Obs.EndCount);
end;

procedure TSseObservabilityTest.TestDroppingTheSourceUnreadIsAbandoned;
var
  Factory: TFakeFrameFactory;
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  Src: IHttpSseSource;
  Ev: TSseEvent;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([SseOpenBodySpec('data: a'#10#10)]));
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  Client := Build(Factory, ObsRef);
  R := Client.Send(SseRequest(cStreamUrl));
  Src := TSseSource.Create(R);
  AssertTrue(Src.ReadEvent(Ev));
  R := nil;
  Src := nil;                     // the last reference to the response
  AssertTrue('the drop ended the attempt', Obs.WaitForEnds(1, 5000));
  AssertTrue('abandoned', Obs.Outcome(0).O.Abandoned);
  AssertEquals(1, Obs.EndCount);
  Client.Close;
end;

procedure TSseObservabilityTest.TestReadingToTheEndEndsOnceNotAbandoned;
var
  Factory: TFakeFrameFactory;
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  Src: IHttpSseSource;
  Ev: TSseEvent;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([SseBodySpec('data: a'#10#10)]));
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  Client := Build(Factory, ObsRef);
  R := Client.Send(SseRequest(cStreamUrl));
  Src := TSseSource.Create(R);
  AssertTrue(Src.ReadEvent(Ev));
  AssertFalse(Src.ReadEvent(Ev));
  Src.Close;
  R := nil;
  Src := nil;
  AssertTrue(Obs.WaitForEnds(1, 5000));
  AssertFalse(Obs.Outcome(0).O.Abandoned);
  AssertEquals('once however it ended', 1, Obs.EndCount);
  Client.Close;
end;

procedure TSseObservabilityTest.TestSlowConsumerDoesNotChangeTheStamps;
var
  Factory: TFakeFrameFactory;
  Obs: TMessageRecordingObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  Src: IHttpSseSource;
  Ev: TSseEvent;
  I: Integer;
  O: THttpOutcome;
begin
  Factory := OpenFactory;
  Obs := TMessageRecordingObserver.Create([mkSseEvent]);
  ObsRef := Obs;
  GScriptedUs := 1000000;
  SetNowUsHook(ScriptedClock);
  Client := Build(Factory, ObsRef);
  R := Client.Send(SseRequest(cStreamUrl));
  for I := 1 to 3 do
    Push(Factory.SocketAt(0), 'data: n'#10#10, False, 1000000 + Int64(I) * 100);
  Push(Factory.SocketAt(0), '', True, 1000350);
  Src := TSseSource.Create(R);
  for I := 1 to 3 do
  begin
    // the consumer is a second behind the wire on every event
    GScriptedUs := 2000000 + Int64(I) * 1000000;
    AssertTrue(Src.ReadEvent(Ev));
  end;
  AssertFalse(Src.ReadEvent(Ev));
  AssertTrue(Obs.WaitForEnds(1, 5000));
  O := Obs.Outcome(0).O;
  AssertEquals(3, O.MessagesIn);
  AssertEquals('the wire gap, not the consumer''s', 100, O.MaxGapUs);
  AssertEquals(200, O.SumGapUs);
  AssertEquals(100, Obs.MessageAt(0).ArrivedUs);
  AssertEquals(300, Obs.MessageAt(2).ArrivedUs);
  AssertEquals(100, Obs.MessageAt(2).SinceLastUs);
  Src := nil;
  R := nil;
  Client.Close;
end;

procedure TSseObservabilityTest.TestRaisingOnMessageDoesNotBreakTheStream;
var
  Factory: TFakeFrameFactory;
  Obs: TMessageRecordingObserver;
  ObsRef: IHttpClientObserver;
  Logger: TRecordingLogger;
  LoggerRef: IHttpLogger;
  Client: IHttpClient;
  R: IHttpResponse;
  Src: IHttpSseSource;
  Ev: TSseEvent;
begin
  Factory := OpenFactory;
  Obs := TMessageRecordingObserver.Create([mkSseEvent]);
  Obs.RaiseOnMessage := True;
  ObsRef := Obs;
  Logger := TRecordingLogger.Create;
  LoggerRef := Logger;
  Client := Build(Factory, ObsRef, LoggerRef);
  R := Client.Send(SseRequest(cStreamUrl));
  Push(Factory.SocketAt(0), 'data: a'#10#10'data: b'#10#10, False, 5);
  Push(Factory.SocketAt(0), 'data: c'#10#10, True, 9);
  Src := TSseSource.Create(R);
  AssertTrue(Src.ReadEvent(Ev));
  AssertEquals('a', Ev.Data);
  AssertTrue(Src.ReadEvent(Ev));
  AssertEquals('b', Ev.Data);
  AssertTrue(Src.ReadEvent(Ev));
  AssertEquals('c', Ev.Data);
  AssertFalse(Src.ReadEvent(Ev));
  AssertTrue(Obs.WaitForEnds(1, 5000));
  AssertEquals('every event reached the observer', 3, Obs.MessageCount);
  AssertEquals('the aggregates are intact', 3, Obs.Outcome(0).O.MessagesIn);
  AssertEquals('each failure was logged', 3, Logger.Count);
  Src := nil;
  R := nil;
  Client.Close;
end;

{ TSseHttp1ObservabilityTest }

type
  /// hands out one staged socket whatever is dialled
  TStagedFactory = class(TInterfacedObject, IHttp2SocketFactory,
    ICleartextSocketFactory)
  private
    FSocket: IHttp2Socket;
  public
    constructor Create(const ASocket: IHttp2Socket);
    function Dial(const AHost: string; const APort: Word;
      const ATimeoutMs: Integer): IHttp2Socket;
    function DialProtocol(const AHost: string; const APort: Word;
      const AScheme: string; const AHttp1Fallback: Boolean;
      const APolicy: TClearTextPolicy; const ATimeoutMs: Integer;
      out AProtocol: TNegotiatedProtocol): IHttp2Socket;
  end;

constructor TStagedFactory.Create(const ASocket: IHttp2Socket);
begin
  inherited Create;
  FSocket := ASocket;
end;

function TStagedFactory.Dial(const AHost: string; const APort: Word;
  const ATimeoutMs: Integer): IHttp2Socket;
begin
  Result := FSocket;
end;

function TStagedFactory.DialProtocol(const AHost: string; const APort: Word;
  const AScheme: string; const AHttp1Fallback: Boolean;
  const APolicy: TClearTextPolicy; const ATimeoutMs: Integer;
  out AProtocol: TNegotiatedProtocol): IHttp2Socket;
begin
  AProtocol := npHttp1Tls;
  Result := FSocket;
end;

procedure TSseHttp1ObservabilityTest.TearDown;
begin
  ResetNowUsHook;
  inherited TearDown;
end;

/// read the three events of the staged stream and return the outcome
function ReadStagedStream(const ASocket: TStagedSocket;
  out AOutcome: THttpOutcome): Boolean;
var
  SockRef: IHttp2Socket;
  Obs: TRecordingRequestObserver;
  ObsRef: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  Src: IHttpSseSource;
  Ev: TSseEvent;
  I: Integer;
begin
  SockRef := ASocket;
  Obs := TRecordingRequestObserver.Create;
  ObsRef := Obs;
  GScriptedUs := 1000000;
  SetNowUsHook(ScriptedClock);
  Client := THttpClientFactory.Create
    .WithSocketFactory(TStagedFactory.Create(SockRef))
    .WithHttp1Fallback.WithClearText(ctReject)
    .WithRequestObserver(ObsRef).Build;
  R := Client.Send(SseRequest(cStreamUrl));
  Src := TSseSource.Create(R);
  Result := True;
  for I := 1 to 3 do
    Result := Result and Src.ReadEvent(Ev);
  Result := Result and (not Src.ReadEvent(Ev));
  Result := Result and Obs.WaitForEnds(1, 5000);
  AOutcome := Obs.Outcome(0).O;
  Src := nil;
  R := nil;
  Client.Close;
end;

procedure TSseHttp1ObservabilityTest.TestEventsTakeTheStampOfTheTransportReadThatCompletedThem;
var
  Sock: TStagedSocket;
  O: THttpOutcome;
begin
  Sock := TStagedSocket.Create;
  Sock.Add('HTTP/1.1 200 OK'#13#10'Content-Type: text/event-stream'#13#10 +
    'Connection: close'#13#10#13#10, 1000050);
  Sock.Add('data: one'#10#10'data: tw', 1000100);
  Sock.Add('o'#10#10'data: three'#10#10, 1000400);
  AssertTrue('three events, then the end', ReadStagedStream(Sock, O));
  AssertEquals('three events', 3, O.MessagesIn);
  AssertEquals('first', 100, O.FirstMessageUs);
  AssertEquals('last', 400, O.LastMessageUs);
  AssertEquals('largest gap', 300, O.MaxGapUs);
  AssertEquals('summed gaps', 300, O.SumGapUs);
  AssertEquals(19 + 16, O.BytesIn);
  AssertFalse(O.Abandoned);
end;

procedure TSseHttp1ObservabilityTest.TestChunkedStreamKeepsTheSameStamps;
var
  Sock: TStagedSocket;
  O: THttpOutcome;
  P1, P2: string;
begin
  P1 := 'data: one'#10#10'data: tw';
  P2 := 'o'#10#10'data: three'#10#10;
  Sock := TStagedSocket.Create;
  Sock.Add('HTTP/1.1 200 OK'#13#10'Content-Type: text/event-stream'#13#10 +
    'Transfer-Encoding: chunked'#13#10#13#10, 1000050);
  Sock.Add(IntToHex(Length(P1), 1) + #13#10 + P1 + #13#10, 1000100);
  Sock.Add(IntToHex(Length(P2), 1) + #13#10 + P2 + #13#10'0'#13#10#13#10,
    1000400);
  AssertTrue('three events, then the end', ReadStagedStream(Sock, O));
  AssertEquals('three events', 3, O.MessagesIn);
  AssertEquals('first', 100, O.FirstMessageUs);
  AssertEquals('last', 400, O.LastMessageUs);
  AssertEquals('largest gap', 300, O.MaxGapUs);
  AssertFalse(O.Abandoned);
end;

initialization
  RegisterTest(TClockTest);
  RegisterTest(TArrivalStampTest);
  RegisterTest(THttp1ArrivalTest);
  RegisterTest(TRequestContextTest);
  RegisterTest(TRequestObserverTest);
  RegisterTest(THttp1ObserverTest);
  RegisterTest(TMessageObserverTest);
  RegisterTest(TSseObservabilityTest);
  RegisterTest(TSseHttp1ObservabilityTest);
end.
