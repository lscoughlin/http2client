/// Observer adapter tests (doc/design/request-observability.md, "Writing an
/// adapter")
// - the adapters under test are the example units in examples/
//   (observer_tracing, observer_metrics, observer_logging).  They are driven
//   through the real client, so these tests are the integration test for the
//   whole observer seam.
// - NOTHING here needs a live server: the HTTP/2 cases run against the scripted
//   frame-level peer of Http2.Redirects.Test under a scripted clock (so every
//   derived number is exact), and the one WebSocket case against the scripted
//   loopback server of Http2.WebSocketClient.Test.
// - non-vacuous by construction: header injection is asserted from the DECODED
//   request headers the peer captured, derived numbers against the stamps the
//   test scripted, and every end is awaited with a bounded timeout on a
//   recording observer registered FIRST (end callbacks run in reverse, so it
//   fires last and the adapters have finished by then).
unit Http2.ObserverAdapters.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, SyncObjs, fpcunit, testregistry,
  Http2.Errors, Http2.Frames, Http2.Headers, Http2.Tls, Http2.Stream,
  Http2.Messages, Http2.Client, Http2.Clock, Http2.RequestObserver, Http2.Sse,
  Http2.WebSocket, Http2.WebSocketClient,
  Http2.Redirects.Test, Http2.RequestObserver.Test, Http2.WebSocketClient.Test,
  observer_tracing, observer_metrics, observer_logging;

type
  /// forwards to another observer and notes each start, headers and end in a
  /// shared log, so the order the composite ran the REAL adapters in is seen
  TOrderSpy = class(TBaseRequestObserver)
  private
    FInner: IHttpClientObserver;
    FTag: string;
    FLog: TEventLog;
  public
    constructor Create(const AInner: IHttpClientObserver; const ATag: string;
      const ALog: TEventLog);
    function OnAttemptStart(const A: THttpAttempt): IInterface; override;
    procedure OnResponseHeaders(const AToken: IInterface;
      const AResponse: IHttpResponse); override;
    procedure OnAttemptEnd(const AToken: IInterface;
      const O: THttpOutcome); override;
  end;

  /// moves the scripted clock when an attempt starts, so the request is
  /// written (and the response headers arrive) AFTER the attempt began
  TClockTicker = class(TBaseRequestObserver)
  private
    FAtUs: Int64;
  public
    constructor Create(const AAtUs: Int64);
    function OnAttemptStart(const A: THttpAttempt): IInterface; override;
  end;

  TTracingAdapterTest = class(TTestCase)
  private
    FTracer: TTracer;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestRedirectHopsAreSiblingsUnderTheCallersSpan;
    procedure TestEachHopSendsExactlyOneTraceparentNamingItsSpan;
    procedure TestWithoutAParentTheAttemptStartsATrace;
    procedure TestServerErrorStatusSetsTheSpanStatus;
    procedure TestStreamFailureSetsErrorAndEndsTheSpan;
    procedure TestRetryIsASiblingSpanWithAnEvent;
    procedure TestSseReconnectsAreSiblingsOfOneStream;
    procedure TestAbandonedResponseIsMarkedOnTheSpan;
  end;

  TMetricsAdapterTest = class(TTestCase)
  private
    FRegistry: TMetricRegistry;
    FRec: TRecordingRequestObserver;
    FRecRef: IHttpClientObserver;
    FOutcome: THttpOutcome;
    FWanted: TMessageKinds;
    FInFlightDuring: Double;
    procedure RunScriptedStream(const APerEvent: Boolean);
    procedure AssertHist(const AName: string; const ACount: Int64;
      const ASum: Double);
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestScriptedStreamTimesAreDerivedExactly;
    procedure TestScriptedStreamRatesAndTotalsAreDerivedExactly;
    procedure TestInFlightGaugeAndCountByStatus;
    procedure TestRequestCountsByStatusAcrossARedirectChain;
    procedure TestErrorsAndAbandonedAreCounted;
    procedure TestPerEventHistogramMatchesTheScriptedGaps;
    procedure TestHistogramIsEmptyWhileTheGateIsOff;
    procedure TestPoolStatsGaugeReadsOneSnapshotPerCollection;
  end;

  TLoggingAdapterTest = class(TTestCase)
  private
    FLogger: TMemoryLogger;
    FLoggerRef: IHttpLogger;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestRedirectLinesAreExact;
    procedure TestRetryLinesCarryTheReasonAndTheError;
    procedure TestAbandonedResponseIsAWarning;
    procedure TestStreamFailureIsAnError;
    procedure TestRequestRefusedBeforeSendIsAnError;
    procedure TestLogValueQuotesWhatNeedsIt;
  end;

  /// the three adapters installed together through WithRequestObserver
  TObserverCompositionTest = class(TTestCase)
  private
    FTracer: TTracer;
    FRegistry: TMetricRegistry;
    FLogger: TMemoryLogger;
    FLoggerRef: IHttpLogger;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestStartRunsInRegistrationOrderAndEndInReverse;
    procedure TestTracerRegisteredFirstSeesHeadersLaterObserversInject;
    procedure TestLaterObserversSeeWhatTheTracerInjected;
    procedure TestThreeAdaptersAgreeOnARedirectChain;
    procedure TestThreeAdaptersOnASseStreamWithAReconnect;
  end;

  TAdaptersWebSocketTest = class(TTestCase)
  private
    FServer: TWsTestServer;
    procedure ScriptTwoTextsThenEchoClose(const S: TWsTestServer);
  protected
    procedure TearDown; override;
  published
    procedure TestThreeAdaptersOnAWebSocketSession;
  end;

implementation

const
  cStreamUrl = 'https://a.example/events';
  cEventStream = 'text/event-stream';

var
  /// the scripted clock the tests install
  GScriptedUs: Int64;

function ScriptedClock: Int64;
begin
  Result := GScriptedUs;
end;

function BytesOf(const S: string): TBytes;
var
  I: Integer;
begin
  Result := nil;
  SetLength(Result, Length(S));
  for I := 1 to Length(S) do
    Result[I - 1] := Ord(S[I]);
end;

function CountOf(const ASub, AText: string): Integer;
var
  P: Integer;
  Rest: string;
begin
  Result := 0;
  Rest := AText;
  repeat
    P := Pos(ASub, Rest);
    if P > 0 then
    begin
      Inc(Result);
      Rest := Copy(Rest, P + Length(ASub), MaxInt);
    end;
  until P = 0;
end;

function StartsWith(const APrefix, AText: string): Boolean;
begin
  Result := Copy(AText, 1, Length(APrefix)) = APrefix;
end;

/// a client over the scripted peer with the observers in registration order
function BuildClient(const AFactory: TFakeFrameFactory;
  const AObservers: array of IHttpClientObserver): IHttpClient;
var
  F: THttpClientFactory;
  I: Integer;
begin
  F := THttpClientFactory.Create.WithSocketFactory(AFactory);
  for I := 0 to High(AObservers) do
    F := F.WithRequestObserver(AObservers[I]);
  Result := F.Build;
end;

/// a 200 event-stream head that stays open
function SseOpen: TRespSpec;
begin
  Result := WithContentType(HdrSpec('200', '', nil, False), cEventStream);
end;

/// a 200 event-stream response whose body ends the stream
function SseBody(const ABody: string): TRespSpec;
begin
  Result := WithContentType(HdrSpec('200', '', BytesOf(ABody), True),
    cEventStream);
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

/// frames are read and routed in order, so the ACK of a PING queued behind them
/// proves the reader thread is done with every earlier frame
procedure Barrier(const ASocket: TFakeFrameSocket);
var
  Before: Integer;
  Deadline: QWord;
begin
  Before := CountPingAcks(ASocket.WrittenFrames);
  ASocket.InjectFrame(BuildPingFrame(BytesOf('barrier!'), False));
  Deadline := GetTickCount64 + 5000;
  repeat
    if CountPingAcks(ASocket.WrittenFrames) > Before then
      Exit;
    Sleep(1);   // bounded poll on the peer's written bytes
  until GetTickCount64 >= Deadline;
  raise Exception.Create('the barrier PING was never acknowledged');
end;

/// the peer delivers AText at the scripted instant AStampUs
procedure Push(const ASocket: TFakeFrameSocket; const AText: string;
  const AEndStream: Boolean; const AStampUs: Int64);
begin
  GScriptedUs := AStampUs;
  ASocket.InjectFrame(BuildDataFrame(1, BytesOf(AText), AEndStream));
  Barrier(ASocket);
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
    SseBody('retry: 1'#10'id: 1'#10'data: a'#10#10),
    SseBody('retry: 1'#10'id: 2'#10'data: b'#10#10),
    SseBody('retry: 1'#10'id: 3'#10'data: c'#10#10)]));
end;

{ TOrderSpy }

constructor TOrderSpy.Create(const AInner: IHttpClientObserver;
  const ATag: string; const ALog: TEventLog);
begin
  inherited Create;
  FInner := AInner;
  FTag := ATag;
  FLog := ALog;
end;

function TOrderSpy.OnAttemptStart(const A: THttpAttempt): IInterface;
begin
  FLog.Add(FTag + '.S');
  Result := FInner.OnAttemptStart(A);
end;

procedure TOrderSpy.OnResponseHeaders(const AToken: IInterface;
  const AResponse: IHttpResponse);
begin
  FLog.Add(FTag + '.H');
  FInner.OnResponseHeaders(AToken, AResponse);
end;

procedure TOrderSpy.OnAttemptEnd(const AToken: IInterface;
  const O: THttpOutcome);
begin
  FLog.Add(FTag + '.E');
  FInner.OnAttemptEnd(AToken, O);
end;

{ TClockTicker }

constructor TClockTicker.Create(const AAtUs: Int64);
begin
  inherited Create;
  FAtUs := AAtUs;
end;

function TClockTicker.OnAttemptStart(const A: THttpAttempt): IInterface;
begin
  GScriptedUs := FAtUs;
  Result := nil;
end;

{ TTracingAdapterTest }

procedure TTracingAdapterTest.SetUp;
begin
  inherited SetUp;
  FTracer := TTracer.Create;
end;

procedure TTracingAdapterTest.TearDown;
begin
  FTracer.Free;
  inherited TearDown;
end;

procedure TTracingAdapterTest.TestRedirectHopsAreSiblingsUnderTheCallersSpan;
var
  Factory: TFakeFrameFactory;
  Root: ISpan;
  Obs: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  I, J: Integer;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([
    HdrSpec('302', '/b'), HdrSpec('302', '/c'), HdrSpec('200')]));
  Obs := TTracingObserver.Create(FTracer);
  Client := BuildClient(Factory, [Obs]);
  Root := FTracer.StartSpan('caller', nil);
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/a')
    .WithContext(Root));
  AssertEquals('final status', 200, R.StatusCode);
  AssertEquals('the caller span and one span per hop', 4, FTracer.Count);
  for I := 1 to 3 do
  begin
    AssertEquals('hop ' + IntToStr(I - 1) + ' is a child of the caller',
      Root.SpanId, FTracer.SpanAt(I).ParentSpanId);
    AssertEquals('same trace', Root.TraceId, FTracer.SpanAt(I).TraceId);
    AssertTrue('the hop span ended', FTracer.SpanAt(I).Ended);
    for J := 1 to I - 1 do
      AssertTrue('siblings have distinct ids',
        FTracer.SpanAt(I).SpanId <> FTracer.SpanAt(J).SpanId);
  end;
  AssertEquals('a hop is not the parent of the next',
    Root.SpanId, FTracer.SpanAt(3).ParentSpanId);
  AssertEquals('hop 0 status', '302',
    FTracer.SpanAt(1).GetAttribute('http.response.status_code'));
  AssertEquals('hop 2 status', '200',
    FTracer.SpanAt(3).GetAttribute('http.response.status_code'));
  AssertEquals('hop numbers', '1',
    FTracer.SpanAt(2).GetAttribute('http.request.hop'));
  AssertEquals('one redirect event on a finished hop', 1,
    FTracer.SpanAt(1).EventCount);
  AssertEquals('redirect event', 'redirect 302 to https://a.example/b',
    FTracer.SpanAt(1).EventAt(0));
  AssertEquals('the last hop was not redirected', 0, FTracer.SpanAt(3).EventCount);
  AssertTrue('redirects are not errors', FTracer.SpanAt(1).Status = ssOk);
  AssertFalse('the caller owns its span', Root.Ended);
  R := nil;
  Client.Close;
end;

procedure TTracingAdapterTest.TestEachHopSendsExactlyOneTraceparentNamingItsSpan;
var
  Factory: TFakeFrameFactory;
  Root: ISpan;
  Obs: IHttpClientObserver;
  Client: IHttpClient;
  Sock: TFakeFrameSocket;
  Lines: string;
  I: Integer;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([
    HdrSpec('302', '/b'), HdrSpec('307', '/c'), HdrSpec('200')]));
  Obs := TTracingObserver.Create(FTracer);
  Client := BuildClient(Factory, [Obs]);
  Root := FTracer.StartSpan('caller', nil);
  // a traceparent the caller set must not travel next to the adapter's
  Client.Send(THttpRequest.Create(hmGet, 'https://a.example/a')
    .WithHeader('traceparent', '00-caller-header-01')
    .WithHeader('x-caller', 'yes').WithContext(Root));
  Sock := Factory.SocketAt(0);
  AssertTrue('three requests were sent', Sock.WaitForRequests(3, 2000));
  for I := 0 to 2 do
  begin
    Lines := Sock.RequestAt(I).HeaderLines;
    AssertEquals('one traceparent on hop ' + IntToStr(I), 1,
      CountOf('traceparent:', Lines));
    AssertTrue('it names the hop''s own span',
      Pos('traceparent: ' + FTracer.SpanAt(I + 1).Traceparent, Lines) > 0);
    AssertEquals('the caller''s value was replaced', 0,
      CountOf('caller-header', Lines));
    AssertTrue('other headers are untouched', Pos('x-caller: yes', Lines) > 0);
  end;
  AssertTrue('version 00, 32 hex trace id, 16 hex span id, sampled flag',
    (Length(FTracer.SpanAt(1).Traceparent) = 55) and
    (Copy(FTracer.SpanAt(1).Traceparent, 1, 3) = '00-') and
    (Copy(FTracer.SpanAt(1).Traceparent, 53, 3) = '-01'));
  Client.Close;
end;

procedure TTracingAdapterTest.TestWithoutAParentTheAttemptStartsATrace;
var
  Factory: TFakeFrameFactory;
  Obs: IHttpClientObserver;
  Client: IHttpClient;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([HdrSpec('200'), HdrSpec('200')]));
  Obs := TTracingObserver.Create(FTracer);
  Client := BuildClient(Factory, [Obs]);
  Client.Send(THttpRequest.Create(hmGet, 'https://a.example/a'));
  Client.Send(THttpRequest.Create(hmGet, 'https://a.example/b'));
  AssertEquals(2, FTracer.Count);
  AssertEquals('a root has no parent', '', FTracer.SpanAt(0).ParentSpanId);
  AssertTrue('unrelated requests are separate traces',
    FTracer.SpanAt(0).TraceId <> FTracer.SpanAt(1).TraceId);
  AssertEquals('named after the method', 'GET', FTracer.SpanAt(0).Name);
  AssertEquals('server.address', 'a.example',
    FTracer.SpanAt(0).GetAttribute('server.address'));
  AssertEquals('server.port', '443',
    FTracer.SpanAt(0).GetAttribute('server.port'));
  Client.Close;
end;

procedure TTracingAdapterTest.TestServerErrorStatusSetsTheSpanStatus;
var
  Factory: TFakeFrameFactory;
  Obs: IHttpClientObserver;
  Client: IHttpClient;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([HdrSpec('503')]));
  Obs := TTracingObserver.Create(FTracer);
  Client := BuildClient(Factory, [Obs]);
  Client.Send(THttpRequest.Create(hmGet, 'https://a.example/a'));
  AssertTrue('error status', FTracer.SpanAt(0).Status = ssError);
  AssertEquals('message', 'HTTP 503', FTracer.SpanAt(0).StatusMessage);
  AssertEquals('status attribute', '503',
    FTracer.SpanAt(0).GetAttribute('http.response.status_code'));
  AssertTrue('ended', FTracer.SpanAt(0).Ended);
  Client.Close;
end;

procedure TTracingAdapterTest.TestStreamFailureSetsErrorAndEndsTheSpan;
var
  Factory: TFakeFrameFactory;
  Obs: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  Buf: array[0..15] of Byte;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([HdrRstSpec(ecInternalError)]));
  Obs := TTracingObserver.Create(FTracer);
  Client := BuildClient(Factory, [Obs]);
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/a'));
  AssertFalse('open while the body is unread', FTracer.SpanAt(0).Ended);
  try
    R.Body.Read(Buf, SizeOf(Buf));
    Fail('the read should fail');
  except
    on E: EHttpStreamError do ;
  end;
  AssertTrue('ended by the failure', FTracer.SpanAt(0).Ended);
  AssertTrue('error status', FTracer.SpanAt(0).Status = ssError);
  AssertTrue('the message came from the exception',
    FTracer.SpanAt(0).StatusMessage <> '');
  AssertEquals('error type', 'EHttpStreamError',
    FTracer.SpanAt(0).GetAttribute('error.type'));
  AssertEquals('headers had arrived', '200',
    FTracer.SpanAt(0).GetAttribute('http.response.status_code'));
  R := nil;
  Client.Close;
end;

procedure TTracingAdapterTest.TestRetryIsASiblingSpanWithAnEvent;
var
  Factory: TFakeFrameFactory;
  Root: ISpan;
  Obs: IHttpClientObserver;
  Client: IHttpClient;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([RstSpec(ecRefusedStream), HdrSpec('200')]));
  Obs := TTracingObserver.Create(FTracer);
  Client := BuildClient(Factory, [Obs]);
  Root := FTracer.StartSpan('caller', nil);
  Client.Send(THttpRequest.Create(hmGet, 'https://a.example/a')
    .WithContext(Root));
  AssertEquals('caller, refused attempt, retry', 3, FTracer.Count);
  AssertEquals('both under the caller', Root.SpanId,
    FTracer.SpanAt(1).ParentSpanId);
  AssertEquals(Root.SpanId, FTracer.SpanAt(2).ParentSpanId);
  AssertEquals('first attempt', '0',
    FTracer.SpanAt(1).GetAttribute('http.request.resend_count'));
  AssertEquals('the retry', '1',
    FTracer.SpanAt(2).GetAttribute('http.request.resend_count'));
  AssertEquals('retry event on the refused attempt', 1,
    FTracer.SpanAt(1).EventCount);
  AssertTrue(StartsWith('retry: ', FTracer.SpanAt(1).EventAt(0)));
  AssertTrue('the refused attempt failed', FTracer.SpanAt(1).Status = ssError);
  AssertTrue('and ended', FTracer.SpanAt(1).Ended);
  AssertTrue('the retry succeeded', FTracer.SpanAt(2).Status = ssOk);
  Client.Close;
end;

procedure TTracingAdapterTest.TestSseReconnectsAreSiblingsOfOneStream;
var
  Rec: TRecordingRequestObserver;
  RecRef, Obs: IHttpClientObserver;
  Client: IHttpClient;
  Root: ISpan;
  Id: Int64;
  I: Integer;
begin
  Rec := TRecordingRequestObserver.Create;
  RecRef := Rec;
  Obs := TTracingObserver.Create(FTracer);
  Client := BuildClient(ThreeStreamFactory, [RecRef, Obs]);
  Root := FTracer.StartSpan('caller', nil);
  RunThreeConnections(Client, SseRequest(cStreamUrl).WithContext(Root), Id);
  AssertTrue('three ends', Rec.WaitForEnds(3, 5000));
  AssertEquals(4, FTracer.Count);
  for I := 1 to 3 do
  begin
    AssertEquals('sibling', Root.SpanId, FTracer.SpanAt(I).ParentSpanId);
    AssertEquals('one stream id', IntToStr(Id),
      FTracer.SpanAt(I).GetAttribute('sse.stream_id'));
    AssertEquals('reconnect count', IntToStr(I - 1),
      FTracer.SpanAt(I).GetAttribute('sse.reconnect'));
    AssertEquals('kind', 'sse', FTracer.SpanAt(I).GetAttribute('http.attempt.kind'));
    AssertTrue('ended', FTracer.SpanAt(I).Ended);
    AssertEquals('one event each', '1',
      FTracer.SpanAt(I).GetAttribute('messaging.received'));
  end;
  Client.Close;
end;

procedure TTracingAdapterTest.TestAbandonedResponseIsMarkedOnTheSpan;
var
  Factory: TFakeFrameFactory;
  Obs: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([
    HdrSpec('200', '', BytesOf('unread body'), True)]));
  Obs := TTracingObserver.Create(FTracer);
  Client := BuildClient(Factory, [Obs]);
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/a'));
  AssertFalse('open while held', FTracer.SpanAt(0).Ended);
  R := nil;
  AssertTrue('release ended it', FTracer.SpanAt(0).Ended);
  AssertEquals('abandoned', 'true',
    FTracer.SpanAt(0).GetAttribute('http.response.abandoned'));
  AssertTrue('an abandonment alone is not an error',
    FTracer.SpanAt(0).Status = ssOk);
  Client.Close;
end;

{ TMetricsAdapterTest }

procedure TMetricsAdapterTest.SetUp;
begin
  inherited SetUp;
  FRegistry := TMetricRegistry.Create;
end;

procedure TMetricsAdapterTest.TearDown;
begin
  ResetNowUsHook;
  FRecRef := nil;
  FRec := nil;
  FRegistry.Free;
  inherited TearDown;
end;

procedure TMetricsAdapterTest.AssertHist(const AName: string;
  const ACount: Int64; const ASum: Double);
begin
  AssertTrue(AName + ' exists', FRegistry.HasHistogram(AName));
  AssertEquals(AName + ' count', ACount,
    FRegistry.Histogram(AName, cLatencyBoundsUs).Count);
  AssertEquals(AName + ' sum', ASum,
    FRegistry.Histogram(AName, cLatencyBoundsUs).Sum, 0.001);
end;

/// one SSE attempt under the scripted clock.  The attempt starts at 1000000,
/// the ticker moves the clock to 1000050 (request written, headers received),
/// then the peer delivers three events:
///   1000100  'data: one' and the start of the second event
///   1000400  the rest of the second event and the whole third event
///   1000500  the end of the stream
procedure TMetricsAdapterTest.RunScriptedStream(const APerEvent: Boolean);
var
  Factory: TFakeFrameFactory;
  Metrics, Ticker: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  P: IAttemptProgress;
  Src: IHttpSseSource;
  Ev: TSseEvent;
  I: Integer;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([SseOpen]));
  FRec := TRecordingRequestObserver.Create;
  FRecRef := FRec;
  Metrics := TMetricsObserver.Create(FRegistry, APerEvent);
  Ticker := TClockTicker.Create(1000050);
  GScriptedUs := 1000000;
  SetNowUsHook(ScriptedClock);
  Client := BuildClient(Factory, [FRecRef, Metrics, Ticker]);
  R := Client.Send(SseRequest(cStreamUrl));
  FInFlightDuring := FRegistry.Gauge('http_client_in_flight').Value;
  AssertTrue(Supports(R, IAttemptProgress, P));
  FWanted := P.WantedKinds;
  P := nil;
  Push(Factory.SocketAt(0), 'data: one'#10#10'data: tw', False, 1000100);
  Push(Factory.SocketAt(0), 'o'#10#10'data: three'#10#10, False, 1000400);
  Push(Factory.SocketAt(0), '', True, 1000500);
  Src := TSseSource.Create(R);
  for I := 1 to 3 do
    AssertTrue('event ' + IntToStr(I), Src.ReadEvent(Ev));
  AssertFalse('the stream ended', Src.ReadEvent(Ev));
  AssertTrue('the attempt ended', FRec.WaitForEnds(1, 5000));
  FOutcome := FRec.Outcome(0).O;
  Src := nil;
  R := nil;
  Client.Close;
end;

procedure TMetricsAdapterTest.TestScriptedStreamTimesAreDerivedExactly;
begin
  RunScriptedStream(False);
  AssertEquals('the request was written after the attempt began', 50,
    FOutcome.RequestSentUs);
  AssertEquals('headers arrived then too', 50, FOutcome.HeadersUs);
  AssertEquals('three events', 3, FOutcome.MessagesIn);
  // time to first byte: HeadersUs - RequestSentUs
  AssertHist('http_sse_ttfb_us', 1, 0);
  // time to first event: FirstMessageUs (100) - RequestSentUs (50)
  AssertHist('http_sse_first_message_us', 1, 50);
  // mean inter-event latency: SumGapUs (300) / (MessagesIn - 1)
  AssertHist('http_sse_mean_gap_us', 1, 150);
  // the stall: the largest gap
  AssertHist('http_sse_max_gap_us', 1, 300);
  // stream duration: LastMessageUs (400) - FirstMessageUs (100)
  AssertHist('http_sse_stream_duration_us', 1, 300);
  // total latency: EndUs
  AssertHist('http_sse_total_us', 1, 500);
  AssertHist('http_sse_request_bytes', 1, 0);
  AssertFalse('an event stream stays out of the request-latency histograms',
    FRegistry.HasHistogram('http_request_total_us'));
end;

procedure TMetricsAdapterTest.TestScriptedStreamRatesAndTotalsAreDerivedExactly;
begin
  RunScriptedStream(False);
  AssertEquals('bytes on the wire', 35, FOutcome.BytesIn);
  // event rate: (MessagesIn - 1) / (LastMessageUs - FirstMessageUs), per second
  AssertHist('http_sse_message_rate_per_s', 1, 2 * 1000000.0 / 300);
  // byte rate: BytesIn / (EndUs - HeadersUs), per second
  AssertHist('http_sse_byte_rate_per_s', 1, 35 * 1000000.0 / 450);
end;

procedure TMetricsAdapterTest.TestInFlightGaugeAndCountByStatus;
begin
  RunScriptedStream(False);
  AssertEquals('one attempt in flight while the stream is open', 1,
    FInFlightDuring, 0.001);
  AssertEquals('none after it ended', 0,
    FRegistry.Gauge('http_client_in_flight').Value, 0.001);
  AssertEquals('counted by kind and status', 1,
    FRegistry.Counter('http_client_requests_total').Value(
      'kind="sse",status="200"'));
  AssertEquals('only that one', 0,
    FRegistry.Counter('http_client_requests_total').Value(
      'kind="request",status="200"'));
end;

procedure TMetricsAdapterTest.TestRequestCountsByStatusAcrossARedirectChain;
var
  Factory: TFakeFrameFactory;
  Metrics: IHttpClientObserver;
  Client: IHttpClient;
  C: TCounter;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([
    HdrSpec('302', '/b'), HdrSpec('302', '/c'), HdrSpec('404'),
    HdrSpec('500')]));
  Metrics := TMetricsObserver.Create(FRegistry);
  Client := BuildClient(Factory, [Metrics]);
  Client.Send(THttpRequest.Create(hmGet, 'https://a.example/a'));
  Client.Send(THttpRequest.Create(hmGet, 'https://a.example/z'));
  C := FRegistry.Counter('http_client_requests_total');
  AssertEquals('each redirect hop is an attempt', 2,
    C.Value('kind="request",status="302"'));
  AssertEquals(1, C.Value('kind="request",status="404"'));
  AssertEquals(1, C.Value('kind="request",status="500"'));
  AssertEquals('nothing else', 0, C.Value('kind="request",status="200"'));
  AssertEquals('all done', 0, FRegistry.Gauge('http_client_in_flight').Value,
    0.001);
  Client.Close;
end;

procedure TMetricsAdapterTest.TestErrorsAndAbandonedAreCounted;
var
  Factory: TFakeFrameFactory;
  Metrics: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  Buf: array[0..15] of Byte;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([
    HdrRstSpec(ecInternalError), HdrSpec('200', '', BytesOf('unread'), True)]));
  Metrics := TMetricsObserver.Create(FRegistry);
  Client := BuildClient(Factory, [Metrics]);
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/a'));
  AssertEquals('in flight while open', 1,
    FRegistry.Gauge('http_client_in_flight').Value, 0.001);
  try
    R.Body.Read(Buf, SizeOf(Buf));
    Fail('the read should fail');
  except
    on E: EHttpStreamError do ;
  end;
  R := nil;
  AssertEquals('the failure was counted by class', 1,
    FRegistry.Counter('http_client_errors_total').Value(
      'kind="request",type="EHttpStreamError"'));
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/b'));
  AssertEquals('not abandoned while held', 0,
    FRegistry.Counter('http_client_abandoned_total').Value('kind="request"'));
  R := nil;
  AssertEquals('released unread', 1,
    FRegistry.Counter('http_client_abandoned_total').Value('kind="request"'));
  AssertEquals('in flight is back to zero', 0,
    FRegistry.Gauge('http_client_in_flight').Value, 0.001);
  Client.Close;
end;

procedure TMetricsAdapterTest.TestPerEventHistogramMatchesTheScriptedGaps;
var
  H: THistogram;
  I: Integer;
begin
  RunScriptedStream(True);
  AssertTrue('the attempt asked for events', mkSseEvent in FWanted);
  // events arrive at 100, 400 and 400: the first has no gap, then 300 and 0
  AssertTrue(FRegistry.HasHistogram(GapHistogramName(akSse)));
  H := FRegistry.Histogram(GapHistogramName(akSse), cLatencyBoundsUs);
  AssertEquals('two gaps', 2, H.Count);
  AssertEquals('their sum', 300, H.Sum, 0.001);
  AssertEquals('the largest', 300, H.Max, 0.001);
  AssertEquals('the 0 gap is in the first bucket (<= 100)', 1, H.CountAt(0));
  AssertEquals('the 300 gap is in the second bucket (<= 500)', 1, H.CountAt(1));
  for I := 2 to H.BucketCount - 1 do
    AssertEquals('bucket ' + IntToStr(I) + ' is empty', 0, H.CountAt(I));
  // the aggregates are unaffected by the gate
  AssertHist('http_sse_mean_gap_us', 1, 150);
end;

procedure TMetricsAdapterTest.TestHistogramIsEmptyWhileTheGateIsOff;
begin
  RunScriptedStream(False);
  AssertTrue('the attempt asked for nothing', FWanted = []);
  AssertFalse('so the histogram was never fed',
    FRegistry.HasHistogram(GapHistogramName(akSse)));
  AssertHist('http_sse_max_gap_us', 1, 300);
end;

procedure TMetricsAdapterTest.TestPoolStatsGaugeReadsOneSnapshotPerCollection;
var
  Factory: TFakeFrameFactory;
  Client: IHttpClient;
  R: IHttpResponse;
  Lines: TStringList;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([
    HdrSpec('200', '', BytesOf('held'), True)]));
  Client := BuildClient(Factory, []);
  FRegistry.AddCollector(TPoolStatsCollector.Create(Client));
  FRegistry.Collect;
  AssertEquals('no connection yet', 0,
    FRegistry.Gauge('http_pool_connections').Value, 0.001);
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/a'));
  FRegistry.Collect;
  AssertEquals('one connection', 1,
    FRegistry.Gauge('http_pool_connections').Value, 0.001);
  AssertEquals('with a stream in flight', 1,
    FRegistry.Gauge('http_pool_active_streams').Value, 0.001);
  AssertEquals('so it is not idle', 0,
    FRegistry.Gauge('http_pool_idle_connections').Value, 0.001);
  Lines := TStringList.Create;
  try
    FRegistry.Dump(Lines);
    AssertTrue('the dump collects first and lists the gauge',
      Lines.IndexOf('http_pool_active_streams 1') >= 0);
  finally
    Lines.Free;
  end;
  R := nil;
  FRegistry.Collect;
  AssertEquals('the stream was released', 0,
    FRegistry.Gauge('http_pool_active_streams').Value, 0.001);
  AssertEquals('and the connection is idle', 1,
    FRegistry.Gauge('http_pool_idle_connections').Value, 0.001);
  Client.Close;
end;

{ TLoggingAdapterTest }

procedure TLoggingAdapterTest.SetUp;
begin
  inherited SetUp;
  FLogger := TMemoryLogger.Create;
  FLoggerRef := FLogger;
  // a frozen clock makes every time in a line 0, so the lines are exact
  GScriptedUs := 1000000;
  SetNowUsHook(ScriptedClock);
end;

procedure TLoggingAdapterTest.TearDown;
begin
  ResetNowUsHook;
  FLoggerRef := nil;
  FLogger := nil;
  inherited TearDown;
end;

procedure TLoggingAdapterTest.TestRedirectLinesAreExact;
var
  Factory: TFakeFrameFactory;
  Obs: IHttpClientObserver;
  Client: IHttpClient;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([HdrSpec('302', '/b'), HdrSpec('200')]));
  Obs := TLoggingObserver.Create(FLoggerRef);
  Client := BuildClient(Factory, [Obs]);
  Client.Send(THttpRequest.Create(hmGet, 'https://a.example/a'));
  AssertEquals('seven lines', 7, FLogger.Count);
  AssertEquals('evt=attempt.start id=1 kind=request method=GET ' +
    'url=https://a.example/a hop=0 retry=0', FLogger.LineAt(0));
  AssertEquals('evt=attempt.headers id=1 status=302', FLogger.LineAt(1));
  AssertEquals('evt=attempt.redirect id=1 status=302 ' +
    'from=https://a.example/a to=https://a.example/b', FLogger.LineAt(2));
  AssertEquals('evt=attempt.end id=1 status=302 proto=h2 reused=false ' +
    'dur_us=0 bytes_out=0 bytes_in=0 msgs_in=0 msgs_out=0', FLogger.LineAt(3));
  AssertEquals('evt=attempt.start id=2 kind=request method=GET ' +
    'url=https://a.example/b hop=1 retry=0', FLogger.LineAt(4));
  AssertEquals('evt=attempt.headers id=2 status=200', FLogger.LineAt(5));
  AssertEquals('evt=attempt.end id=2 status=200 proto=h2 reused=true ' +
    'dur_us=0 bytes_out=0 bytes_in=0 msgs_in=0 msgs_out=0', FLogger.LineAt(6));
  AssertTrue('start is debug', FLogger.LevelAt(0) = llDebug);
  AssertTrue('a redirect is info', FLogger.LevelAt(2) = llInfo);
  AssertTrue('a clean end is info', FLogger.LevelAt(6) = llInfo);
  Client.Close;
end;

procedure TLoggingAdapterTest.TestRetryLinesCarryTheReasonAndTheError;
var
  Factory: TFakeFrameFactory;
  Obs: IHttpClientObserver;
  Client: IHttpClient;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([RstSpec(ecRefusedStream), HdrSpec('200')]));
  Obs := TLoggingObserver.Create(FLoggerRef);
  Client := BuildClient(Factory, [Obs]);
  Client.Send(THttpRequest.Create(hmGet, 'https://a.example/a'));
  AssertEquals('start, retry, end, start, headers, end', 6, FLogger.Count);
  AssertTrue(StartsWith('evt=attempt.start id=1 ', FLogger.LineAt(0)));
  AssertTrue('the retry names the attempt it refers to',
    StartsWith('evt=attempt.retry id=1 reason=', FLogger.LineAt(1)));
  AssertTrue('a retry is a warning', FLogger.LevelAt(1) = llWarn);
  AssertTrue(StartsWith('evt=attempt.end id=1 status=0 ', FLogger.LineAt(2)));
  AssertTrue('the refused attempt carries the error',
    Pos(' error=EHttpStreamError message=', FLogger.LineAt(2)) > 0);
  AssertTrue('and is an error line', FLogger.LevelAt(2) = llError);
  AssertTrue('the retry is the next attempt, one retry in',
    Pos('id=2 kind=request method=GET url=https://a.example/a hop=0 retry=1',
      FLogger.LineAt(3)) > 0);
  AssertEquals('evt=attempt.headers id=2 status=200', FLogger.LineAt(4));
  AssertTrue('it ended clean', Pos(' error=', FLogger.LineAt(5)) = 0);
  Client.Close;
end;

procedure TLoggingAdapterTest.TestAbandonedResponseIsAWarning;
var
  Factory: TFakeFrameFactory;
  Obs: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([
    HdrSpec('200', '', BytesOf('unread body'), True)]));
  Obs := TLoggingObserver.Create(FLoggerRef);
  Client := BuildClient(Factory, [Obs]);
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/a'));
  AssertEquals('no end line while the response is held', 2, FLogger.Count);
  R := nil;
  AssertEquals(3, FLogger.Count);
  AssertTrue(StartsWith('evt=attempt.end id=1 status=200 ', FLogger.LineAt(2)));
  AssertTrue('marked abandoned', Pos(' abandoned=true', FLogger.LineAt(2)) > 0);
  AssertTrue('and a warning', FLogger.LevelAt(2) = llWarn);
  Client.Close;
end;

procedure TLoggingAdapterTest.TestStreamFailureIsAnError;
var
  Factory: TFakeFrameFactory;
  Obs: IHttpClientObserver;
  Client: IHttpClient;
  R: IHttpResponse;
  Buf: array[0..15] of Byte;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([HdrRstSpec(ecInternalError)]));
  Obs := TLoggingObserver.Create(FLoggerRef);
  Client := BuildClient(Factory, [Obs]);
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/a'));
  try
    R.Body.Read(Buf, SizeOf(Buf));
    Fail('the read should fail');
  except
    on E: EHttpStreamError do ;
  end;
  AssertEquals(3, FLogger.Count);
  AssertTrue(StartsWith('evt=attempt.end id=1 status=200 ', FLogger.LineAt(2)));
  AssertTrue(Pos(' error=EHttpStreamError message=', FLogger.LineAt(2)) > 0);
  AssertTrue('an error is not an abandonment',
    Pos('abandoned', FLogger.LineAt(2)) = 0);
  AssertTrue(FLogger.LevelAt(2) = llError);
  R := nil;
  AssertEquals('release adds no line', 3, FLogger.Count);
  Client.Close;
end;

procedure TLoggingAdapterTest.TestRequestRefusedBeforeSendIsAnError;
var
  Obs: IHttpClientObserver;
  Client: IHttpClient;
begin
  Obs := TLoggingObserver.Create(FLoggerRef);
  // the strict cleartext default refuses the request before any dial
  Client := BuildClient(TFakeFrameFactory.Create, [Obs]);
  try
    Client.Send(THttpRequest.Create(hmGet, 'http://plain.example/x'));
    Fail('the request should be refused');
  except
    on E: EHttpProtocolError do ;
  end;
  AssertEquals('a start is paired with an end', 2, FLogger.Count);
  AssertTrue(StartsWith('evt=attempt.end id=1 status=0 ', FLogger.LineAt(1)));
  AssertTrue(Pos(' error=EHttpProtocolError message=', FLogger.LineAt(1)) > 0);
  AssertTrue(FLogger.LevelAt(1) = llError);
  Client.Close;
end;

procedure TLoggingAdapterTest.TestLogValueQuotesWhatNeedsIt;
begin
  AssertEquals('plain', 'https://a.example/x', LogValue('https://a.example/x'));
  AssertEquals('"a b"', LogValue('a b'));
  AssertEquals('"x=y"', LogValue('x=y'));
  AssertEquals('"say \"hi\""', LogValue('say "hi"'));
  AssertEquals('"line\nbreak"', LogValue('line'#10'break'));
  AssertEquals('empty', '""', LogValue(''));
end;

{ TObserverCompositionTest }

procedure TObserverCompositionTest.SetUp;
begin
  inherited SetUp;
  FTracer := TTracer.Create;
  FRegistry := TMetricRegistry.Create;
  FLogger := TMemoryLogger.Create;
  FLoggerRef := FLogger;
end;

procedure TObserverCompositionTest.TearDown;
begin
  ResetNowUsHook;
  FLoggerRef := nil;
  FLogger := nil;
  FRegistry.Free;
  FTracer.Free;
  inherited TearDown;
end;

procedure TObserverCompositionTest.TestStartRunsInRegistrationOrderAndEndInReverse;
var
  Log: TEventLog;
  Factory: TFakeFrameFactory;
  T, M, L: IHttpClientObserver;
  Client: IHttpClient;
begin
  Log := TEventLog.Create;
  try
    Factory := TFakeFrameFactory.Create;
    Factory.SetDialScript(0, SpecArray([HdrSpec('200')]));
    // each real adapter behind a spy that notes the callback in one shared log
    T := TOrderSpy.Create(TTracingObserver.Create(FTracer), 'tracing', Log);
    M := TOrderSpy.Create(TMetricsObserver.Create(FRegistry), 'metrics', Log);
    L := TOrderSpy.Create(TLoggingObserver.Create(FLoggerRef), 'logging', Log);
    Client := BuildClient(Factory, [T, M, L]);
    Client.Send(THttpRequest.Create(hmGet, 'https://a.example/a'));
    AssertEquals('start and headers in registration order, end reversed',
      'tracing.S metrics.S logging.S tracing.H metrics.H logging.H ' +
      'logging.E metrics.E tracing.E', Log.Text);
    // and each adapter did its own job behind its spy
    AssertEquals('a span', 1, FTracer.Count);
    AssertTrue('ended', FTracer.SpanAt(0).Ended);
    AssertEquals('a counted request', 1, FRegistry.Counter(
      'http_client_requests_total').Value('kind="request",status="200"'));
    AssertEquals('three log lines', 3, FLogger.Count);
    Client.Close;
  finally
    Log.Free;
  end;
end;

procedure TObserverCompositionTest.TestTracerRegisteredFirstSeesHeadersLaterObserversInject;
var
  Factory: TFakeFrameFactory;
  Tracing: TTracingObserver;
  T, Inject: IHttpClientObserver;
  Injector: TRecordingRequestObserver;
  Client: IHttpClient;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([HdrSpec('200')]));
  Tracing := TTracingObserver.Create(FTracer);
  Tracing.RecordRequestHeader('x-correlation-id');
  T := Tracing;
  Injector := TRecordingRequestObserver.Create;
  Injector.InjectName := 'x-correlation-id';
  Injector.InjectPrefix := 'corr';
  Inject := Injector;
  // the tracer first: its start runs before the injector's, yet the span still
  // carries the header, because the tracer reads it once every start ran
  Client := BuildClient(Factory, [T, Inject]);
  Client.Send(THttpRequest.Create(hmGet, 'https://a.example/a'));
  AssertTrue('the request was sent', Factory.SocketAt(0).WaitForRequests(1, 2000));
  AssertTrue('the injector''s header is on the wire',
    Pos('x-correlation-id: corr-1', Factory.SocketAt(0).RequestAt(0).HeaderLines) > 0);
  AssertEquals('and on the span', 'corr-1',
    FTracer.SpanAt(0).GetAttribute('http.request.header.x-correlation-id'));
  AssertEquals('one traceparent too', 1,
    CountOf('traceparent:', Factory.SocketAt(0).RequestAt(0).HeaderLines));
  Client.Close;
end;

procedure TObserverCompositionTest.TestLaterObserversSeeWhatTheTracerInjected;
var
  Factory: TFakeFrameFactory;
  T, Inject: IHttpClientObserver;
  Injector: TRecordingRequestObserver;
  Client: IHttpClient;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([HdrSpec('200')]));
  T := TTracingObserver.Create(FTracer);
  // this one reads the first value of `traceparent` before it injects its own
  Injector := TRecordingRequestObserver.Create;
  Injector.InjectName := 'traceparent';
  Injector.InjectPrefix := 'later';
  Inject := Injector;
  Client := BuildClient(Factory, [T, Inject]);
  Client.Send(THttpRequest.Create(hmGet, 'https://a.example/a'));
  AssertEquals(1, Injector.SeenBefore.Count);
  AssertEquals('the sink already held the tracer''s traceparent',
    FTracer.SpanAt(0).Traceparent, Injector.SeenBefore[0]);
  Client.Close;
end;

procedure TObserverCompositionTest.TestThreeAdaptersAgreeOnARedirectChain;
var
  Factory: TFakeFrameFactory;
  Rec: TRecordingRequestObserver;
  RecRef, T, M, L: IHttpClientObserver;
  Client: IHttpClient;
  Root: ISpan;
  I: Integer;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([
    HdrSpec('302', '/b'), HdrSpec('302', '/c'), HdrSpec('200')]));
  Rec := TRecordingRequestObserver.Create;
  RecRef := Rec;
  T := TTracingObserver.Create(FTracer);
  M := TMetricsObserver.Create(FRegistry);
  L := TLoggingObserver.Create(FLoggerRef);
  Client := BuildClient(Factory, [RecRef, T, M, L]);
  Root := FTracer.StartSpan('caller', nil);
  Client.Send(THttpRequest.Create(hmGet, 'https://a.example/a')
    .WithContext(Root));
  AssertTrue(Rec.WaitForEnds(3, 5000));
  AssertEquals('three hop spans and the caller', 4, FTracer.Count);
  for I := 1 to 3 do
    AssertTrue('hop span ended', FTracer.SpanAt(I).Ended);
  AssertEquals('metrics saw three attempts', 2, FRegistry.Counter(
    'http_client_requests_total').Value('kind="request",status="302"'));
  AssertEquals(1, FRegistry.Counter('http_client_requests_total').Value(
    'kind="request",status="200"'));
  AssertEquals('nothing in flight', 0,
    FRegistry.Gauge('http_client_in_flight').Value, 0.001);
  // 3 starts + 3 headers + 3 ends + 2 redirects
  AssertEquals('the log covers every callback', 11, FLogger.Count);
  Client.Close;
end;

procedure TObserverCompositionTest.TestThreeAdaptersOnASseStreamWithAReconnect;
var
  Rec: TRecordingRequestObserver;
  RecRef, T, M, L: IHttpClientObserver;
  Client: IHttpClient;
  Root: ISpan;
  Id: Int64;
  I, Ends: Integer;
begin
  Rec := TRecordingRequestObserver.Create;
  RecRef := Rec;
  T := TTracingObserver.Create(FTracer);
  M := TMetricsObserver.Create(FRegistry, True);
  L := TLoggingObserver.Create(FLoggerRef);
  Client := BuildClient(ThreeStreamFactory, [RecRef, T, M, L]);
  Root := FTracer.StartSpan('caller', nil);
  RunThreeConnections(Client, SseRequest(cStreamUrl).WithContext(Root), Id);
  AssertTrue(Rec.WaitForEnds(3, 5000));
  AssertEquals('one span per connection under the caller', 4, FTracer.Count);
  Ends := 0;
  for I := 1 to 3 do
    if FTracer.SpanAt(I).Ended then
      Inc(Ends);
  AssertEquals('every span ended', 3, Ends);
  AssertEquals('three SSE attempts counted', 3, FRegistry.Counter(
    'http_client_requests_total').Value('kind="sse",status="200"'));
  AssertEquals('the reconnect is in the log', 1,
    CountOf('reconnect=2', FLogger.Text));
  AssertEquals('each log line carries the stream id', 3,
    CountOf('stream=' + IntToStr(Id) + ' ', FLogger.Text));
  Client.Close;
end;

{ TAdaptersWebSocketTest }

procedure TAdaptersWebSocketTest.TearDown;
begin
  if FServer <> nil then
  begin
    FServer.Terminate;
    FServer.Release.SetEvent;
    FServer.CloseConnection;
    FServer.ShutdownListener;
    FServer.Done.WaitFor(3000);
    FServer.Free;
    FServer := nil;
  end;
  inherited TearDown;
end;

procedure TAdaptersWebSocketTest.ScriptTwoTextsThenEchoClose(
  const S: TWsTestServer);
var
  F: TWsFrame;
begin
  S.ReadHead;
  S.Accept;
  S.SendText('m1');
  S.SendText('m2');
  while S.TryReadFrame(F) do
    if F.Opcode = cWsOpClose then
    begin
      S.SendFrame(cWsOpClose, True, F.Payload);
      Break;
    end;
  S.CloseConnection;
end;

procedure TAdaptersWebSocketTest.TestThreeAdaptersOnAWebSocketSession;
var
  Tracer: TTracer;
  Registry: TMetricRegistry;
  Logger: TMemoryLogger;
  LoggerRef: IHttpLogger;
  Rec: TRecordingRequestObserver;
  RecRef, T, M, L: IHttpClientObserver;
  Listener: TRecorder;
  ListenerRef: IWebSocketListener;
  Client: IHttpClient;
  Sock: IWebSocket;
  Root: ISpan;
  Gaps: THistogram;
begin
  Tracer := TTracer.Create;
  Registry := TMetricRegistry.Create;
  Logger := TMemoryLogger.Create;
  LoggerRef := Logger;
  try
    FServer := TWsTestServer.Create(ScriptTwoTextsThenEchoClose);
    FServer.Start;
    Rec := TRecordingRequestObserver.Create;
    RecRef := Rec;
    T := TTracingObserver.Create(Tracer);
    M := TMetricsObserver.Create(Registry, True);
    L := TLoggingObserver.Create(LoggerRef);
    Client := THttpClientFactory.Create.WithRequestObserver(RecRef)
      .WithRequestObserver(T).WithRequestObserver(M)
      .WithRequestObserver(L).Build;
    Listener := TRecorder.Create(0);
    ListenerRef := Listener;
    Root := Tracer.StartSpan('caller', nil);
    Sock := Client.Send(TWebSocketRequest.Create('ws://127.0.0.1:' +
      IntToStr(FServer.Port) + '/obs', ListenerRef).WithAutoRequest
      .WithContext(Root));
    AssertTrue('open and both texts arrived', Listener.WaitCount(3));
    Sock.Close(1000, 'bye');
    AssertTrue('closed', Listener.WaitCount(4));
    AssertTrue('the attempt ended', Rec.WaitForEnds(1, 5000));
    // tracing: one span under the caller, the handshake status, the close
    AssertEquals(2, Tracer.Count);
    AssertEquals('child of the caller', Root.SpanId, Tracer.SpanAt(1).ParentSpanId);
    AssertEquals('WEBSOCKET', Tracer.SpanAt(1).Name);
    AssertEquals('101', Tracer.SpanAt(1).GetAttribute('http.response.status_code'));
    AssertEquals('1000', Tracer.SpanAt(1).GetAttribute('websocket.close_code'));
    AssertTrue('a clean close', Tracer.SpanAt(1).Status = ssOk);
    AssertTrue(Tracer.SpanAt(1).Ended);
    AssertEquals('the traceparent reached the handshake', 1,
      CountOf('traceparent: ' + Tracer.SpanAt(1).Traceparent,
        FServer.Head));
    // metrics: counted by kind and status, and the per-message gate fed the
    // inbound gap histogram (the second text has one gap)
    AssertEquals(1, Registry.Counter('http_client_requests_total').Value(
      'kind="websocket",status="101"'));
    Gaps := Registry.Histogram(GapHistogramName(akWebSocket), cLatencyBoundsUs);
    AssertEquals('one gap between two texts', 1, Gaps.Count);
    AssertEquals('nothing in flight', 0,
      Registry.Gauge('http_client_in_flight').Value, 0.001);
    // logging: the end line names who closed and with what
    AssertEquals('start, headers, end', 3, Logger.Count);
    AssertTrue('closed locally with 1000',
      Pos(' closed_by=local close_code=1000 close_reason=bye', Logger.LineAt(2)) > 0);
    AssertTrue('two messages in', Pos(' msgs_in=2 ', Logger.LineAt(2)) > 0);
    Sock := nil;
    Client.Close;
  finally
    Root := nil;
    LoggerRef := nil;
    Registry.Free;
    Tracer.Free;
  end;
end;

initialization
  RegisterTest(TTracingAdapterTest);
  RegisterTest(TMetricsAdapterTest);
  RegisterTest(TLoggingAdapterTest);
  RegisterTest(TObserverCompositionTest);
  RegisterTest(TAdaptersWebSocketTest);
end.
