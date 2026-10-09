/// Server-Sent Events tests (plan story S14).
// - the parser tests are pure: no socket, no transport. The single most
//   important assertion is chunk-split invariance — the same byte stream fed
//   at EVERY offset must produce the same events (doc/design/
//   server-sent-events.md "Testing"). A parser that only works when a chunk
//   boundary happens to fall on a line break is the classic SSE defect.
// - the transport tests run against the real connection thread over a
//   TMockSocket, so credit flushing and frame routing are genuine; the
//   reconnect tests use a scripted IHttpClient and no transport at all.
unit Http2.Sse.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, SyncObjs, Generics.Collections, fpcunit, testregistry,
  Http2.Errors, Http2.Frames, Http2.Headers, Http2.Hpack, Http2.Tls,
  Http2.Connection, Http2.Stream, Http2.Messages, Http2.Client,
  Http2.Sse, Http2.MockSocket;

type
  /// a body stream over a fixed byte array that hands out at most AChunk
  /// bytes per Read, so a source cannot accidentally depend on a whole event
  /// arriving in one call
  TDripBodyStream = class(TInterfacedObject, IHttpBodyStream)
  private
    FData: TBytes;
    FPos: Integer;
    FChunk: Integer;
  public
    constructor Create(const AData: TBytes; const AChunk: Integer = 1);
    function Read(var ABuffer; const ACount: LongInt): LongInt;
    function Eof: Boolean;
  end;

  /// the least IHttpResponse that can carry headers and a body
  TStubResponse = class(TInterfacedObject, IHttpResponse)
  private
    FStatus: LongInt;
    FHeaders: IHttpHeaders;
    FBody: IHttpBodyStream;
  public
    constructor Create(const AStatus: LongInt; const AHeaders: IHttpHeaders;
      const ABody: IHttpBodyStream);
    function GetStatusCode: LongInt;
    function GetHeaders: IHttpHeaders;
    function GetBody: IHttpBodyStream;
  end;

  /// an IHttpClient that answers from a script of canned event streams, so the
  /// reconnect loop can be tested without a transport
  // - deliberately NOT reference counted (_AddRef/_Release return -1): the
  /// test owns the instance and frees it with Free, while other interfaces
  /// just hold a non-owning reference. Without this the final Free plus the
  /// interface's release double-free the object (EBusError).
  TScriptedClient = class(TInterfacedObject, IHttpClient)
  private
    FBodies: TList<string>;
    FRequests: TList<THttpRequest>;
    FIndex: Integer;
    FRefuseConnection: Boolean;
    FRejectResponse: Boolean;
    FFailNext: Integer;
  public
    function QueryInterface(constref AID: TGUID; out AObj): LongInt; cdecl;
    function _AddRef: LongInt; cdecl;
    function _Release: LongInt; cdecl;
    constructor Create;
    destructor Destroy; override;
    procedure AddBody(const AText: string);
    /// every Send raises EHttpConnectionClosed (a persistent transport fault)
    procedure RefuseConnection;
    /// the next ACount Sends raise EHttpConnectionClosed, then it recovers
    procedure FailNextRequests(const ACount: Integer);
    /// every Send raises EHttpProtocolError (the response is not an event
    /// stream; reconnecting cannot fix it)
    procedure RejectResponse;
    function Send(const ARequest: THttpRequest): IHttpResponse;
    procedure Close;
    function RequestCount: Integer;
    function RequestAt(const AIndex: Integer): THttpRequest;
  end;

  /// one thread blocked in TStreamLease.ReadBody, so a test can assert that
  /// the read is still parked and then unblock it
  TSseReadDriver = class(TThread)
  private
    FLease: TStreamLease;
    FBytes: Integer;
    FRaised: Boolean;
    FError: string;
    FFinished: Boolean;
    FDone: PRTLEvent;
  protected
    procedure Execute; override;
  public
    constructor Create(const ALease: TStreamLease);
    destructor Destroy; override;
    /// True when the read finished within ATimeoutMs
    function WaitDone(const ATimeoutMs: Integer): Boolean;
    property Bytes: Integer read FBytes;
    property Raised: Boolean read FRaised;
    property Error: string read FError;
  end;

  /// drives a cancel from another thread while ReadBody is blocked
  TSseCancelDriver = class(TThread)
  private
    FToken: TCancellationToken;
    FDelayMs: Integer;
  public
    constructor Create(const AToken: TCancellationToken;
      const ADelayMs: Integer);
    procedure Execute; override;
  end;

  TSseParserTest = class(TTestCase)
  private
    procedure ParseAll(const AText: string; out AEvents: TArray<TSseEvent>);
  published
    procedure TestSingleEvent;
    procedure TestDataLinesAreJoinedWithNewline;
    procedure TestIncompleteEventAtEofIsDiscarded;
    procedure TestDefaultEventTypeIsMessage;
    procedure TestNamedEventType;
    procedure TestIdSetsLastEventId;
    procedure TestIdWithNulIsIgnored;
    procedure TestRetryIsParsed;
    procedure TestRetryRejectsNonDigits;
    procedure TestCommentIsIgnoredButKeepsAlive;
    procedure TestBlankLineWithoutDataDispatchesNothing;
    procedure TestEventOnlyFieldDoesNotDispatch;
    procedure TestUnknownFieldIsIgnored;
    procedure TestLeadingSpaceIsStrippedOnce;
    procedure TestNoSpaceAfterColon;
    procedure TestValueMayContainColons;
    procedure TestEmptyValue;
    procedure TestCrlfTerminatedStream;
    procedure TestCrOnlyTerminatedStream;
    procedure TestBomIsStrippedOnce;
    procedure TestBomOnlyAtStart;
    procedure TestChunkSplitInvariance;
    procedure TestChunkSplitInvarianceWithCrlfPairs;
    procedure TestSplitUtf8SequenceSurvivesAcrossFeeds;
    procedure TestInvalidUtf8Raises;
    procedure TestOverlongUtf8Raises;
    procedure TestSurrogateUtf8Raises;
    procedure TestRetryMsSurvivesDispatch;
    procedure TestResetClearsState;
  end;

  TSseSourceTest = class(TTestCase)
  private
    function ResponseOf(const AText: string;
      const AContentType: string = cSseContentType;
      const AStatus: LongInt = 200;
      const AEncoding: string = ''): IHttpResponse;
  published
    procedure TestValidateAcceptsEventStream;
    procedure TestValidateAcceptsParametersAndCase;
    procedure TestValidateRejectsOtherStatus;
    procedure TestValidateRejectsOtherContentType;
    procedure TestValidateRejectsNonUtf8Charset;
    procedure TestValidateRejectsContentCoding;
    procedure TestReadEventsFromBody;
    procedure TestReadEventIsIncrementalPerBlankLine;
    procedure TestReadEventReturnsFalseAtEof;
    procedure TestLastEventIdTracksTheStream;
    procedure TestRetryMsTracksTheStream;
    procedure TestCloseStopsFurtherEvents;
  end;

  TSseReconnectTest = class(TTestCase)
  published
    procedure TestReconnectEchoesLastEventId;
    procedure TestReconnectDropsTheReplayedEvent;
    procedure TestRetryBoundRaises;
    procedure TestZeroBoundReconnectsForever;
    procedure TestProtocolErrorIsTerminal;
    procedure TestTransientFailureReconnects;
    procedure TestFirstConnectFailureIsReported;
    procedure TestHonoursServerRetry;
  end;

  TSseRequestTest = class(TTestCase)
  published
    procedure TestSseRequestSetsAcceptAndIdentity;
    procedure TestSseRequestWaitsIndefinitelyForTheBody;
    procedure TestOrdinaryRequestKeepsTheLegacyBodyDeadline;
  end;

  TSseTransportTest = class(TTestCase)
  private
    function MakeLease(const AConn: TConnection;
      const ARequest: TStreamRequest; out AAlloc: TStreamIdAllocator;
      out ALease: TStreamLease; out AIL: IConnectionStream): Boolean;
  published
    // an idle event stream must NOT inherit the 30s header timeout
    procedure TestIdleBodyReadWaitsIndefinitely;
    // an explicit body-read deadline still fires (opt-in liveness)
    procedure TestExplicitBodyReadTimeoutRaises;
    // a blocked body read unblocks on Cancel and resets the stream
    procedure TestBlockedBodyReadCancelsWithRst;
    // flow control: a long-lived stream's data is credited back
    procedure TestSseStreamReturnsWindowCredit;
  end;

  /// the opt-in live case: skipped unless SSE_TEST_URL points at a
  /// tools/validate/sse_server.py instance (the same gate idiom the other
  /// live tests use). It proves the whole stack end to end: incremental
  /// delivery, reconnect, last-event-id resume, and retry: adoption.
  TSseLiveTest = class(TTestCase)
  published
    procedure TestLiveStreamDeliversEventsAndResumes;
  end;

implementation

function BytesOf(const A: string): TBytes;
var
  I: Integer;
begin
  Result := nil;
  SetLength(Result, Length(A));
  for I := 1 to Length(A) do
    Result[I - 1] := Ord(A[I]);
end;

function RawBytes(const A: array of Byte): TBytes;
var
  I: Integer;
begin
  SetLength(Result, Length(A));
  for I := 0 to High(A) do
    Result[I] := A[I];
end;

function U32BE(const AData: TBytes; const AOffset: Integer): LongWord;
begin
  // ReadUInt32BE lives in the Http2.Frames implementation section, so decode
  // the 4-byte big-endian payload here
  Result := (LongWord(AData[AOffset]) shl 24) or
            (LongWord(AData[AOffset + 1]) shl 16) or
            (LongWord(AData[AOffset + 2]) shl 8) or
            LongWord(AData[AOffset + 3]);
end;

function NewHeaders(const APairs: array of string): IHttpHeaders;
var
  I: Integer;
begin
  Result := NewHttpHeaders;
  I := 0;
  while I + 1 <= High(APairs) do
  begin
    Result.Add(APairs[I], APairs[I + 1]);
    Inc(I, 2);
  end;
end;

function ResponseHeadersFor(const ACodec: THpackCodec;
  const AStatus: string; const AStreamId: LongWord;
  const AEndStream: Boolean): TFrame;
var
  Block: THeaderBlock;
begin
  SetLength(Block, 1);
  Block[0].Name := ':status';
  Block[0].Value := AStatus;
  Block[0].Sensitive := False;
  Result := BuildHeadersFrame(AStreamId, ACodec.Encode(Block), True,
    AEndStream);
end;

function DataFrameOf(const AStreamId: LongWord; const AText: string;
  const AEndStream: Boolean): TFrame;
begin
  Result := BuildDataFrame(AStreamId, BytesOf(AText), AEndStream);
end;

{ TDripBodyStream }

constructor TDripBodyStream.Create(const AData: TBytes;
  const AChunk: Integer);
begin
  inherited Create;
  FData := Copy(AData, 0, Length(AData));
  FPos := 0;
  FChunk := AChunk;
end;

function TDripBodyStream.Read(var ABuffer; const ACount: LongInt): LongInt;
var
  P: PByte;
  Left, Take: Integer;
begin
  P := @ABuffer;
  Left := Length(FData) - FPos;
  if Left <= 0 then
    Exit(0);
  Take := FChunk;
  if Take > ACount then
    Take := ACount;
  if Take > Left then
    Take := Left;
  Move(FData[FPos], P[0], Take);
  Inc(FPos, Take);
  Result := Take;
end;

function TDripBodyStream.Eof: Boolean;
begin
  Result := FPos >= Length(FData);
end;

{ TStubResponse }

constructor TStubResponse.Create(const AStatus: LongInt;
  const AHeaders: IHttpHeaders; const ABody: IHttpBodyStream);
begin
  inherited Create;
  FStatus := AStatus;
  if AHeaders <> nil then
    FHeaders := AHeaders
  else
    FHeaders := NewHttpHeaders;
  FBody := ABody;
end;

function TStubResponse.GetStatusCode: LongInt;
begin
  Result := FStatus;
end;

function TStubResponse.GetHeaders: IHttpHeaders;
begin
  Result := FHeaders;
end;

function TStubResponse.GetBody: IHttpBodyStream;
begin
  Result := FBody;
end;

{ TScriptedClient }

constructor TScriptedClient.Create;
begin
  inherited Create;
  FBodies := TList<string>.Create;
  FRequests := TList<THttpRequest>.Create;
  FIndex := 0;
end;

function TScriptedClient.QueryInterface(constref AID: TGUID;
  out AObj): LongInt;
begin
  if GetInterface(AID, AObj) then
    Result := 0
  else
    Result := LongInt($80004002);        // E_NOINTERFACE
end;

function TScriptedClient._AddRef: LongInt;
begin
  Result := -1;                          // the test owns the instance
end;

function TScriptedClient._Release: LongInt;
begin
  Result := -1;                          // the test owns the instance
end;

destructor TScriptedClient.Destroy;
begin
  FBodies.Free;
  FRequests.Free;
  inherited Destroy;
end;

procedure TScriptedClient.AddBody(const AText: string);
begin
  FBodies.Add(AText);
end;

procedure TScriptedClient.RefuseConnection;
begin
  FRefuseConnection := True;
end;

procedure TScriptedClient.FailNextRequests(const ACount: Integer);
begin
  FFailNext := ACount;
end;

procedure TScriptedClient.RejectResponse;
begin
  FRejectResponse := True;
end;

function TScriptedClient.Send(const ARequest: THttpRequest): IHttpResponse;
var
  Body: string;
begin
  FRequests.Add(ARequest);
  if FFailNext > 0 then
  begin
    Dec(FFailNext);
    raise EHttpConnectionClosed.Create('scripted transient transport failure');
  end;
  if FRefuseConnection then
    raise EHttpConnectionClosed.Create('scripted transport failure');
  if FRejectResponse then
    raise EHttpProtocolError.Create('scripted: not an event stream',
      ecProtocolError);
  if (FIndex < 0) or (FIndex >= FBodies.Count) then
    Body := ''
  else
    Body := FBodies[FIndex];
  Inc(FIndex);
  Result := TStubResponse.Create(200,
    NewHeaders([HeaderContentType, cSseContentType]),
    TDripBodyStream.Create(BytesOf(Body), 4096));
end;

procedure TScriptedClient.Close;
begin
  // nothing to release
end;

function TScriptedClient.RequestCount: Integer;
begin
  Result := FRequests.Count;
end;

function TScriptedClient.RequestAt(const AIndex: Integer): THttpRequest;
begin
  Result := FRequests[AIndex];
end;

{ TSseReadDriver }

constructor TSseReadDriver.Create(const ALease: TStreamLease);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FLease := ALease;
  FDone := RTLEventCreate;
end;

destructor TSseReadDriver.Destroy;
begin
  RTLEventDestroy(FDone);
  inherited Destroy;
end;

procedure TSseReadDriver.Execute;
var
  Buf: array[0..15] of Byte;
begin
  FBytes := 0;
  FRaised := False;
  try
    try
      FBytes := FLease.ReadBody(Buf, SizeOf(Buf));
    except
      on E: Exception do
      begin
        FRaised := True;
        FError := E.ClassName + ': ' + E.Message;
      end;
    end;
  finally
    FFinished := True;
    RTLEventSetEvent(FDone);
  end;
end;

function TSseReadDriver.WaitDone(const ATimeoutMs: Integer): Boolean;
var
  Deadline: QWord;
  Remaining: Integer;
begin
  Deadline := GetTickCount64 + QWord(ATimeoutMs);
  while not FFinished do
  begin
    if GetTickCount64 >= Deadline then
      Exit(False);
    Remaining := Integer(Deadline - GetTickCount64);
    RTLEventWaitFor(FDone, Remaining);
  end;
  Result := True;
end;

{ TSseCancelDriver }

constructor TSseCancelDriver.Create(const AToken: TCancellationToken;
  const ADelayMs: Integer);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FToken := AToken;
  FDelayMs := ADelayMs;
end;

procedure TSseCancelDriver.Execute;
begin
  Sleep(FDelayMs);
  FToken.Cancel;
end;

{ TSseParserTest }

procedure TSseParserTest.ParseAll(const AText: string;
  out AEvents: TArray<TSseEvent>);
var
  P: TSseEventParser;
  List: TList<TSseEvent>;
  I: Integer;
begin
  List := TList<TSseEvent>.Create;
  P := TSseEventParser.Create;
  try
    P.Feed(BytesOf(AText), List);
    SetLength(AEvents, List.Count);
    for I := 0 to List.Count - 1 do
      AEvents[I] := List[I];
  finally
    P.Free;
    List.Free;
  end;
end;

procedure TSseParserTest.TestSingleEvent;
var
  Ev: TArray<TSseEvent>;
begin
  ParseAll('data: hello' + #10 + #10, Ev);
  AssertEquals('one event dispatched', 1, Length(Ev));
  AssertEquals('the data payload', 'hello', Ev[0].Data);
  AssertEquals('the default event type', 'message', Ev[0].EventType);
  AssertEquals('no id was set', '', Ev[0].Id);
  AssertEquals('no retry was set', 0, Ev[0].RetryMs);
end;

procedure TSseParserTest.TestDataLinesAreJoinedWithNewline;
var
  Ev: TArray<TSseEvent>;
begin
  ParseAll('data: a' + #10 + 'data: b' + #10 + #10, Ev);
  AssertEquals('one event dispatched', 1, Length(Ev));
  AssertEquals('the lines are joined with a newline', 'a' + #10 + 'b',
    Ev[0].Data);
end;

procedure TSseParserTest.TestIncompleteEventAtEofIsDiscarded;
var
  Ev: TArray<TSseEvent>;
begin
  // WHATWG: the event is dispatched only on the blank line. A stream that
  // ends mid-event (no final blank line) must NOT dispatch the partial
  // event, so a truncated reconnect cannot deliver half an event.
  ParseAll('data: tail', Ev);
  AssertEquals('an unterminated event is not dispatched', 0, Length(Ev));
  ParseAll('data: a' + #10 + #10 + 'data: tail', Ev);
  AssertEquals('only the terminated event is dispatched', 1, Length(Ev));
  AssertEquals('and it is the complete one', 'a', Ev[0].Data);
end;

procedure TSseParserTest.TestDefaultEventTypeIsMessage;
var
  Ev: TArray<TSseEvent>;
begin
  ParseAll('data: x' + #10 + #10, Ev);
  AssertEquals('default event type', cSseDefaultEventType, Ev[0].EventType);
end;

procedure TSseParserTest.TestNamedEventType;
var
  Ev: TArray<TSseEvent>;
begin
  ParseAll('event: ping' + #10 + 'data: x' + #10 + #10, Ev);
  AssertEquals('the named event type', 'ping', Ev[0].EventType);
end;

procedure TSseParserTest.TestIdSetsLastEventId;
var
  Ev: TArray<TSseEvent>;
  P: TSseEventParser;
  L: TList<TSseEvent>;
begin
  ParseAll('id: 42' + #10 + 'data: x' + #10 + #10, Ev);
  AssertEquals('the id is carried on the event', '42', Ev[0].Id);
  // and it survives the dispatch that follows
  P := TSseEventParser.Create;
  L := TList<TSseEvent>.Create;
  try
    P.Feed(BytesOf('id: 42' + #10 + 'data: a' + #10 + #10 +
      'data: b' + #10 + #10), L);
    AssertEquals('two events', 2, L.Count);
    AssertEquals('the id survives the following dispatch', '42',
      P.LastEventId);
    AssertEquals('the second event reports the same id', '42', L[1].Id);
  finally
    P.Free;
    L.Free;
  end;
end;

procedure TSseParserTest.TestIdWithNulIsIgnored;
var
  P: TSseEventParser;
  L: TList<TSseEvent>;
  Raw: TBytes;
begin
  // a value containing a NUL byte makes the whole id field ignored, so the
  // previous id stays in force (WHATWG "id" field)
  P := TSseEventParser.Create;
  L := TList<TSseEvent>.Create;
  try
    Raw := BytesOf('id: ok' + #10 + 'data: a' + #10 + #10 + 'id: bad');
    Raw := Raw + RawBytes([$00]);
    Raw := Raw + BytesOf('x' + #10 + 'data: b' + #10 + #10);
    P.Feed(Raw, L);
    AssertEquals('two events dispatched', 2, L.Count);
    AssertEquals('the NUL id is ignored, the earlier id stays', 'ok',
      P.LastEventId);
    AssertEquals('the first event reports the good id', 'ok', L[0].Id);
    AssertEquals('the second event still reports it', 'ok', L[1].Id);
  finally
    P.Free;
    L.Free;
  end;
end;

procedure TSseParserTest.TestRetryIsParsed;
var
  P: TSseEventParser;
  L: TList<TSseEvent>;
begin
  P := TSseEventParser.Create;
  L := TList<TSseEvent>.Create;
  try
    P.Feed(BytesOf('retry: 1500' + #10 + #10), L);
    AssertEquals('retry alone dispatches nothing', 0, L.Count);
    AssertEquals('the retry value', 1500, P.RetryMs);
  finally
    P.Free;
    L.Free;
  end;
end;

procedure TSseParserTest.TestRetryRejectsNonDigits;
var
  P: TSseEventParser;
  L: TList<TSseEvent>;
begin
  P := TSseEventParser.Create;
  L := TList<TSseEvent>.Create;
  try
    P.Feed(BytesOf('retry: 1500' + #10 + #10), L);
    P.Feed(BytesOf('retry: 12x' + #10 + #10), L);
    AssertEquals('a non-numeric retry is ignored', 1500, P.RetryMs);
  finally
    P.Free;
    L.Free;
  end;
end;

procedure TSseParserTest.TestCommentIsIgnoredButKeepsAlive;
var
  Ev: TArray<TSseEvent>;
begin
  ParseAll(': keep-alive' + #10 + #10 + 'data: x' + #10 + #10, Ev);
  AssertEquals('only the data event dispatched', 1, Length(Ev));
  AssertEquals('the payload', 'x', Ev[0].Data);
end;

procedure TSseParserTest.TestBlankLineWithoutDataDispatchesNothing;
var
  Ev: TArray<TSseEvent>;
begin
  ParseAll('event: ping' + #10 + #10, Ev);
  AssertEquals('an event name without data dispatches nothing', 0,
    Length(Ev));
end;

procedure TSseParserTest.TestEventOnlyFieldDoesNotDispatch;
var
  Ev: TArray<TSseEvent>;
begin
  ParseAll('id: 7' + #10 + 'retry: 100' + #10 + #10, Ev);
  AssertEquals('state-only fields dispatch nothing', 0, Length(Ev));
end;

procedure TSseParserTest.TestUnknownFieldIsIgnored;
var
  Ev: TArray<TSseEvent>;
begin
  ParseAll('foo: bar' + #10 + 'data: x' + #10 + #10, Ev);
  AssertEquals('one event dispatched', 1, Length(Ev));
  AssertEquals('the unknown field is ignored', 'x', Ev[0].Data);
end;

procedure TSseParserTest.TestLeadingSpaceIsStrippedOnce;
var
  Ev: TArray<TSseEvent>;
begin
  // exactly ONE leading space is removed; a second is part of the value
  ParseAll('data:  two' + #10 + #10, Ev);
  AssertEquals('only one leading space is stripped', ' two', Ev[0].Data);
end;

procedure TSseParserTest.TestNoSpaceAfterColon;
var
  Ev: TArray<TSseEvent>;
begin
  ParseAll('data:no-space' + #10 + #10, Ev);
  AssertEquals('a value may follow the colon directly', 'no-space',
    Ev[0].Data);
end;

procedure TSseParserTest.TestValueMayContainColons;
var
  Ev: TArray<TSseEvent>;
begin
  ParseAll('data: a:b:c' + #10 + #10, Ev);
  AssertEquals('only the first colon separates field from value', 'a:b:c',
    Ev[0].Data);
end;

procedure TSseParserTest.TestEmptyValue;
var
  Ev: TArray<TSseEvent>;
begin
  ParseAll('data:' + #10 + #10, Ev);
  AssertEquals('an empty data line still counts as data', 1, Length(Ev));
  AssertEquals('the payload is empty', '', Ev[0].Data);
end;

procedure TSseParserTest.TestCrlfTerminatedStream;
var
  Ev: TArray<TSseEvent>;
begin
  ParseAll('data: a' + #13 + #10 + 'data: b' + #13 + #10 + #13 + #10, Ev);
  AssertEquals('one event dispatched', 1, Length(Ev));
  AssertEquals('CRLF is a line terminator', 'a' + #10 + 'b', Ev[0].Data);
end;

procedure TSseParserTest.TestCrOnlyTerminatedStream;
var
  Ev: TArray<TSseEvent>;
begin
  ParseAll('data: a' + #13 + 'data: b' + #13 + #13, Ev);
  AssertEquals('one event dispatched', 1, Length(Ev));
  AssertEquals('a lone CR is a line terminator', 'a' + #10 + 'b', Ev[0].Data);
end;

procedure TSseParserTest.TestBomIsStrippedOnce;
var
  Ev: TArray<TSseEvent>;
begin
  ParseAll(#$EF + #$BB + #$BF + 'data: x' + #10 + #10, Ev);
  AssertEquals('one event dispatched', 1, Length(Ev));
  AssertEquals('the BOM is not part of the field name', 'x', Ev[0].Data);
end;

procedure TSseParserTest.TestBomOnlyAtStart;
var
  P: TSseEventParser;
  L: TList<TSseEvent>;
  Raw: TBytes;
begin
  // a BOM-looking sequence that is not at the very start is data
  P := TSseEventParser.Create;
  L := TList<TSseEvent>.Create;
  try
    Raw := BytesOf('data: x' + #10 + #10 + 'data: ');
    Raw := Raw + RawBytes([$EF, $BB, $BF]);
    Raw := Raw + BytesOf(#10 + #10);
    P.Feed(Raw, L);
    AssertEquals('two events', 2, L.Count);
    AssertEquals('the later BOM bytes are part of the data',
      #$EF + #$BB + #$BF, L[1].Data);
  finally
    P.Free;
    L.Free;
  end;
end;

procedure TSseParserTest.TestChunkSplitInvariance;
var
  Stream: string;
  Raw: TBytes;
  Canonical: TArray<TSseEvent>;
  P: TSseEventParser;
  L: TList<TSseEvent>;
  Part: TBytes;
  I, J, K: Integer;
  Same: Boolean;

  function SameAs(AList: TList<TSseEvent>): Boolean;
  var
    M: Integer;
  begin
    Result := AList.Count = Length(Canonical);
    if Result then
      for M := 0 to AList.Count - 1 do
        if (AList[M].Data <> Canonical[M].Data) or
           (AList[M].EventType <> Canonical[M].EventType) or
           (AList[M].Id <> Canonical[M].Id) or
           (AList[M].RetryMs <> Canonical[M].RetryMs) then
        begin
          Result := False;
          Break;
        end;
  end;

begin
  Stream := ': this is a test stream' + #10 + #10 +
    'event: greeting' + #10 +
    'data: hello' + #10 +
    'data: world' + #10 +
    'id: 1' + #10 +
    'retry: 500' + #10 + #10 +
    'data: second' + #10 +
    'id: 2' + #10 + #10 +
    'data: third' + #10 + #10;
  Raw := BytesOf(Stream);
  ParseAll(Stream, Canonical);
  AssertEquals('the reference stream yields three events', 3,
    Length(Canonical));
  AssertEquals('first event data', 'hello' + #10 + 'world',
    Canonical[0].Data);
  AssertEquals('first event type', 'greeting', Canonical[0].EventType);
  AssertEquals('second event id', '2', Canonical[1].Id);
  AssertEquals('second event retry', 500, Canonical[1].RetryMs);

  // feed the same stream one byte at a time
  Same := True;
  P := TSseEventParser.Create;
  L := TList<TSseEvent>.Create;
  try
    for I := 0 to High(Raw) do
    begin
      SetLength(Part, 1);
      Part[0] := Raw[I];
      P.Feed(Part, L);
    end;
    Same := SameAs(L);
  finally
    P.Free;
    L.Free;
  end;
  AssertTrue('byte-at-a-time feeding yields identical events', Same);

  // and at every two-way split point
  Same := True;
  for I := 0 to Length(Raw) do
  begin
    P := TSseEventParser.Create;
    L := TList<TSseEvent>.Create;
    try
      P.Feed(Copy(Raw, 0, I), L);
      P.Feed(Copy(Raw, I, Length(Raw) - I), L);
      if not SameAs(L) then
        Same := False;
    finally
      P.Free;
      L.Free;
    end;
    if not Same then
      Break;
  end;
  AssertTrue('every two-way split yields identical events', Same);
end;

procedure TSseParserTest.TestChunkSplitInvarianceWithCrlfPairs;
var
  Stream: string;
  Raw: TBytes;
  Events: TArray<TSseEvent>;
  P: TSseEventParser;
  L: TList<TSseEvent>;
  Part: TBytes;
  I, K: Integer;
  Same: Boolean;
begin
  // the hard case: the CR and its LF land in different chunks
  Stream := 'data: a' + #13 + #10 + 'data: b' + #13 + #10 + #13 + #10 +
    'data: c' + #13 + #10 + #13 + #10;
  Raw := BytesOf(Stream);
  ParseAll(Stream, Events);
  AssertEquals('the reference stream yields two events', 2, Length(Events));
  AssertEquals('the first payload', 'a' + #10 + 'b', Events[0].Data);
  Same := True;
  P := TSseEventParser.Create;
  L := TList<TSseEvent>.Create;
  try
    for I := 0 to High(Raw) do
    begin
      SetLength(Part, 1);
      Part[0] := Raw[I];
      P.Feed(Part, L);
    end;
    Same := L.Count = Length(Events);
    if Same then
      for K := 0 to L.Count - 1 do
        if L[K].Data <> Events[K].Data then
          Same := False;
  finally
    P.Free;
    L.Free;
  end;
  AssertTrue('a CR/LF split across chunks is not a double terminator', Same);
end;

procedure TSseParserTest.TestSplitUtf8SequenceSurvivesAcrossFeeds;
var
  P: TSseEventParser;
  L: TList<TSseEvent>;
  Raw, Part: TBytes;
  I: Integer;
  Expected: string;
begin
  // a two-byte sequence fed one byte at a time must be reassembled, not
  // rejected and not corrupted
  Expected := 'ann' + #$C3 + #$A9 + 'e';
  Raw := BytesOf('data: ' + Expected + #10 + #10);
  P := TSseEventParser.Create;
  L := TList<TSseEvent>.Create;
  try
    for I := 0 to High(Raw) do
    begin
      SetLength(Part, 1);
      Part[0] := Raw[I];
      P.Feed(Part, L);
    end;
    AssertEquals('one event', 1, L.Count);
    AssertEquals('a split multi-byte sequence is reassembled', Expected,
      L[0].Data);
  finally
    P.Free;
    L.Free;
  end;
end;

procedure TSseParserTest.TestInvalidUtf8Raises;
var
  P: TSseEventParser;
  L: TList<TSseEvent>;
  Raw: TBytes;
  Raised: Boolean;
begin
  P := TSseEventParser.Create;
  L := TList<TSseEvent>.Create;
  try
    // $FF is never a legal UTF-8 byte
    Raw := BytesOf('data: ');
    Raw := Raw + RawBytes([$FF]);
    Raw := Raw + BytesOf(#10 + #10);
    Raised := False;
    try
      P.Feed(Raw, L);
    except
      on E: EHttpProtocolError do Raised := True;
    end;
    AssertTrue('invalid UTF-8 raises EHttpProtocolError', Raised);
  finally
    P.Free;
    L.Free;
  end;
end;

procedure TSseParserTest.TestOverlongUtf8Raises;
var
  P: TSseEventParser;
  L: TList<TSseEvent>;
  Raw: TBytes;
  Raised: Boolean;
begin
  P := TSseEventParser.Create;
  L := TList<TSseEvent>.Create;
  try
    // C0 80 is an overlong encoding of NUL; C2 is the shortest legal lead
    Raw := BytesOf('data: ');
    Raw := Raw + RawBytes([$C0, $80]);
    Raw := Raw + BytesOf(#10 + #10);
    Raised := False;
    try
      P.Feed(Raw, L);
    except
      on E: EHttpProtocolError do Raised := True;
    end;
    AssertTrue('an overlong form raises EHttpProtocolError', Raised);
  finally
    P.Free;
    L.Free;
  end;
end;

procedure TSseParserTest.TestSurrogateUtf8Raises;
var
  P: TSseEventParser;
  L: TList<TSseEvent>;
  Raw: TBytes;
  Raised: Boolean;
begin
  P := TSseEventParser.Create;
  L := TList<TSseEvent>.Create;
  try
    // ED A0 80 encodes U+D800, a surrogate: illegal in UTF-8
    Raw := BytesOf('data: ');
    Raw := Raw + RawBytes([$ED, $A0, $80]);
    Raw := Raw + BytesOf(#10 + #10);
    Raised := False;
    try
      P.Feed(Raw, L);
    except
      on E: EHttpProtocolError do Raised := True;
    end;
    AssertTrue('a surrogate raises EHttpProtocolError', Raised);
  finally
    P.Free;
    L.Free;
  end;
end;

procedure TSseParserTest.TestRetryMsSurvivesDispatch;
var
  L: TList<TSseEvent>;
  P: TSseEventParser;
begin
  P := TSseEventParser.Create;
  L := TList<TSseEvent>.Create;
  try
    P.Feed(BytesOf('retry: 250' + #10 + 'data: a' + #10 + #10 +
      'data: b' + #10 + #10), L);
    AssertEquals('two events', 2, L.Count);
    AssertEquals('the first event carries the retry in force', 250,
      L[0].RetryMs);
    AssertEquals('the retry survives dispatch', 250, L[1].RetryMs);
    AssertEquals('the parser still reports it', 250, P.RetryMs);
  finally
    P.Free;
    L.Free;
  end;
end;

procedure TSseParserTest.TestResetClearsState;
var
  P: TSseEventParser;
  L: TList<TSseEvent>;
begin
  P := TSseEventParser.Create;
  L := TList<TSseEvent>.Create;
  try
    P.Feed(BytesOf('id: 9' + #10 + 'retry: 400' + #10 + 'data: a' + #10 + #10),
      L);
    AssertEquals('id before reset', '9', P.LastEventId);
    AssertEquals('retry before reset', 400, P.RetryMs);
    P.Reset;
    AssertEquals('id cleared', '', P.LastEventId);
    AssertEquals('retry cleared', 0, P.RetryMs);
    // a partial line left over from before the reset must not resurface
    P.Feed(BytesOf('data: b' + #10 + #10), L);
    AssertEquals('the post-reset event is clean', 'b', L[L.Count - 1].Data);
  finally
    P.Free;
    L.Free;
  end;
end;

{ TSseSourceTest }

function TSseSourceTest.ResponseOf(const AText: string;
  const AContentType: string; const AStatus: LongInt;
  const AEncoding: string): IHttpResponse;
var
  H: IHttpHeaders;
begin
  H := NewHttpHeaders;
  if AContentType <> '' then
    H.Add(HeaderContentType, AContentType);
  if AEncoding <> '' then
    H.Add(HeaderContentEncoding, AEncoding);
  Result := TStubResponse.Create(AStatus, H,
    TDripBodyStream.Create(BytesOf(AText), 3));
end;

procedure TSseSourceTest.TestValidateAcceptsEventStream;
var
  R: IHttpResponse;
begin
  R := ResponseOf('data: x' + #10 + #10);
  AssertTrue('a 200 text/event-stream passes',
    TSseSource.ValidateResponse(R));
end;

procedure TSseSourceTest.TestValidateAcceptsParametersAndCase;
begin
  AssertTrue('media type is case-insensitive',
    TSseSource.IsEventStreamContentType('TEXT/Event-Stream'));
  AssertTrue('a charset parameter is allowed',
    TSseSource.IsEventStreamContentType('text/event-stream; charset=utf-8'));
  AssertTrue('a quoted utf-8 charset is allowed',
    TSseSource.IsEventStreamContentType(
      'text/event-stream; charset="UTF-8"'));
  AssertFalse('a non-utf-8 charset is not',
    TSseSource.IsEventStreamContentType(
      'text/event-stream; charset=iso-8859-1'));
end;

procedure TSseSourceTest.TestValidateRejectsOtherStatus;
var
  R: IHttpResponse;
  Raised: Boolean;
begin
  R := ResponseOf('', cSseContentType, 404);
  Raised := False;
  try
    TSseSource.ValidateResponse(R);
  except
    on E: EHttpProtocolError do Raised := True;
  end;
  AssertTrue('a non-200 status is rejected', Raised);
end;

procedure TSseSourceTest.TestValidateRejectsOtherContentType;
var
  R: IHttpResponse;
  Raised: Boolean;
begin
  R := ResponseOf('{}', 'application/json');
  Raised := False;
  try
    TSseSource.ValidateResponse(R);
  except
    on E: EHttpProtocolError do Raised := True;
  end;
  AssertTrue('a non-event-stream content type is rejected', Raised);
end;

procedure TSseSourceTest.TestValidateRejectsNonUtf8Charset;
var
  R: IHttpResponse;
  Raised: Boolean;
begin
  R := ResponseOf('data: x' + #10 + #10,
    'text/event-stream; charset=iso-8859-1');
  Raised := False;
  try
    TSseSource.ValidateResponse(R);
  except
    on E: EHttpProtocolError do Raised := True;
  end;
  AssertTrue('a non-utf-8 charset is rejected', Raised);
end;

procedure TSseSourceTest.TestValidateRejectsContentCoding;
var
  R: IHttpResponse;
  Raised: Boolean;
begin
  // transparent decoding buffers to the coding footer, so a coded event
  // stream cannot deliver events incrementally: it must be refused
  R := ResponseOf('data: x' + #10 + #10, cSseContentType, 200, 'gzip');
  Raised := False;
  try
    TSseSource.ValidateResponse(R);
  except
    on E: EHttpProtocolError do Raised := True;
  end;
  AssertTrue('a gzip-coded event stream is rejected', Raised);
  R := ResponseOf('data: x' + #10 + #10, cSseContentType, 200, 'identity');
  AssertTrue('identity coding is accepted', TSseSource.ValidateResponse(R));
end;

procedure TSseSourceTest.TestReadEventsFromBody;
var
  S: IHttpSseSource;
  E: TSseEvent;
begin
  S := TSseSource.Create(ResponseOf(
    'data: one' + #10 + #10 + 'event: two' + #10 + 'data: 2' + #10 + #10));
  AssertTrue('first event', S.ReadEvent(E));
  AssertEquals('first payload', 'one', E.Data);
  AssertEquals('first type', 'message', E.EventType);
  AssertTrue('second event', S.ReadEvent(E));
  AssertEquals('second payload', '2', E.Data);
  AssertEquals('second type', 'two', E.EventType);
  AssertFalse('then the stream ends', S.ReadEvent(E));
end;

procedure TSseSourceTest.TestReadEventIsIncrementalPerBlankLine;
var
  S: IHttpSseSource;
  E: TSseEvent;
begin
  // the body hands out three bytes at a time, so an implementation that
  // waits for the end of the body cannot pass this test
  S := TSseSource.Create(ResponseOf(
    'data: a' + #10 + #10 + 'data: b' + #10 + #10));
  AssertTrue('the first event arrives before the whole body is read',
    S.ReadEvent(E));
  AssertEquals('the first payload', 'a', E.Data);
  AssertTrue('the second event', S.ReadEvent(E));
  AssertEquals('the second payload', 'b', E.Data);
  AssertFalse('end of stream', S.ReadEvent(E));
end;

procedure TSseSourceTest.TestReadEventReturnsFalseAtEof;
var
  S: IHttpSseSource;
  E: TSseEvent;
begin
  S := TSseSource.Create(ResponseOf(''));
  AssertFalse('an empty body has no events', S.ReadEvent(E));
  AssertFalse('and it stays ended', S.ReadEvent(E));
end;

procedure TSseSourceTest.TestLastEventIdTracksTheStream;
var
  S: IHttpSseSource;
  E: TSseEvent;
begin
  S := TSseSource.Create(ResponseOf(
    'id: 11' + #10 + 'data: a' + #10 + #10 + 'data: b' + #10 + #10));
  AssertTrue('first event', S.ReadEvent(E));
  AssertEquals('the id is reported', '11', S.LastEventId);
  AssertTrue('second event', S.ReadEvent(E));
  AssertEquals('the id is still in force', '11', S.LastEventId);
end;

procedure TSseSourceTest.TestRetryMsTracksTheStream;
var
  S: IHttpSseSource;
  E: TSseEvent;
begin
  S := TSseSource.Create(ResponseOf(
    'retry: 750' + #10 + 'data: a' + #10 + #10));
  AssertTrue('first event', S.ReadEvent(E));
  AssertEquals('retry reported', 750, S.RetryMs);
end;

procedure TSseSourceTest.TestCloseStopsFurtherEvents;
var
  S: IHttpSseSource;
  E: TSseEvent;
begin
  S := TSseSource.Create(ResponseOf(
    'data: a' + #10 + #10 + 'data: b' + #10 + #10));
  AssertTrue('first event', S.ReadEvent(E));
  S.Close;
  AssertFalse('a closed source yields no further events', S.ReadEvent(E));
end;

{ TSseReconnectTest }

/// every scripted body opens with a 1 ms retry so a reconnect test does not
/// sleep out the 3000 ms default
function FastBody(const AText: string): string;
begin
  Result := 'retry: 1' + #10 + AText;
end;

procedure TSseReconnectTest.TestReconnectEchoesLastEventId;
var
  C: TScriptedClient;
  Loop: TSseReconnectLoop;
  E: TSseEvent;
  First, Second: THttpRequest;
begin
  C := TScriptedClient.Create;
  C.AddBody(FastBody('id: 5' + #10 + 'data: a' + #10 + #10));
  C.AddBody(FastBody('data: b' + #10 + #10));
  Loop := TSseReconnectLoop.Create(C,
    SseRequest('https://a.example/sse'), 5);
  try
    AssertTrue('first event', Loop.Next(E));
    AssertEquals('the first payload', 'a', E.Data);
    AssertTrue('the event after the reconnect', Loop.Next(E));
    AssertEquals('the second payload', 'b', E.Data);
    AssertEquals('a second request was issued', 2, C.RequestCount);
    First := C.RequestAt(0);
    Second := C.RequestAt(1);
    AssertEquals('the first request carries no last-event-id', '',
      First.Headers.GetFirst(HeaderLastEventId));
    AssertEquals('the reconnect echoes last-event-id', '5',
      Second.Headers.GetFirst(HeaderLastEventId));
    AssertEquals('one reconnect was counted', 1, Loop.Reconnects);
  finally
    Loop.Free;
    C.Free;
  end;
end;

procedure TSseReconnectTest.TestReconnectDropsTheReplayedEvent;
var
  C: TScriptedClient;
  Loop: TSseReconnectLoop;
  E: TSseEvent;
begin
  C := TScriptedClient.Create;
  // the server resumes unhelpfully and replays the same id
  C.AddBody(FastBody('id: 1' + #10 + 'data: first' + #10 + #10));
  C.AddBody(FastBody('id: 1' + #10 + 'data: first' + #10 + #10 +
    'id: 2' + #10 + 'data: second' + #10 + #10));
  Loop := TSseReconnectLoop.Create(C,
    SseRequest('https://a.example/sse'), 5);
  try
    AssertTrue('first event', Loop.Next(E));
    AssertEquals('the payload', 'first', E.Data);
    AssertTrue('the next distinct event', Loop.Next(E));
    AssertEquals('the replayed event was dropped', 'second', E.Data);
  finally
    Loop.Free;
    C.Free;
  end;
end;

procedure TSseReconnectTest.TestRetryBoundRaises;
var
  C: TScriptedClient;
  Loop: TSseReconnectLoop;
  E: TSseEvent;
  Raised: Boolean;
  I: Integer;
begin
  C := TScriptedClient.Create;
  for I := 0 to 9 do
    C.AddBody(FastBody('data: x' + #10 + #10));
  Loop := TSseReconnectLoop.Create(C,
    SseRequest('https://a.example/sse'), 2);
  try
    AssertTrue('first event', Loop.Next(E));
    AssertTrue('event after the first reconnect', Loop.Next(E));
    AssertTrue('event after the second reconnect', Loop.Next(E));
    Raised := False;
    try
      Loop.Next(E);           // the third reconnect is over the bound
    except
      on Ex: EHttpTooManySseRetries do Raised := True;
    end;
    AssertTrue('the retry bound raises EHttpTooManySseRetries', Raised);
  finally
    Loop.Free;
    C.Free;
  end;
end;

procedure TSseReconnectTest.TestZeroBoundReconnectsForever;
var
  C: TScriptedClient;
  Loop: TSseReconnectLoop;
  E: TSseEvent;
  I: Integer;
begin
  C := TScriptedClient.Create;
  for I := 0 to 5 do
    C.AddBody(FastBody('data: x' + #10 + #10));
  Loop := TSseReconnectLoop.Create(C,
    SseRequest('https://a.example/sse'), 0);
  try
    for I := 0 to 4 do
      AssertTrue('event ' + IntToStr(I), Loop.Next(E));
    AssertTrue('a zero bound keeps going', Loop.Next(E));
    AssertTrue('more reconnects than any finite bound would allow',
      Loop.Reconnects > 3);
  finally
    Loop.Free;
    C.Free;
  end;
end;

procedure TSseReconnectTest.TestProtocolErrorIsTerminal;
var
  C: TScriptedClient;
  Loop: TSseReconnectLoop;
  E: TSseEvent;
  Raised: Boolean;
begin
  C := TScriptedClient.Create;
  C.AddBody(FastBody('data: x' + #10 + #10));
  Loop := TSseReconnectLoop.Create(C,
    SseRequest('https://a.example/sse'), 5);
  try
    AssertTrue('first event', Loop.Next(E));
    C.RejectResponse;      // the peer now answers with the wrong content type
    Raised := False;
    try
      Loop.Next(E);
    except
      on Ex: EHttpProtocolError do Raised := True;
    end;
    AssertTrue('a protocol error propagates and does not reconnect', Raised);
    AssertEquals('no further request was made', 2, C.RequestCount);
  finally
    Loop.Free;
    C.Free;
  end;
end;

procedure TSseReconnectTest.TestTransientFailureReconnects;
var
  C: TScriptedClient;
  Loop: TSseReconnectLoop;
  E: TSseEvent;
begin
  C := TScriptedClient.Create;
  C.AddBody(FastBody('data: a' + #10 + #10));
  Loop := TSseReconnectLoop.Create(C,
    SseRequest('https://a.example/sse'), 5);
  try
    AssertTrue('first event', Loop.Next(E));
    // one reconnect fails at the transport, the next succeeds: the loop must
    // retry rather than give up, and must still deliver the next event
    C.FailNextRequests(1);
    C.AddBody(FastBody('data: b' + #10 + #10));
    AssertTrue('an event arrives after the transient failure', Loop.Next(E));
    AssertEquals('and it is the recovered event', 'b', E.Data);
    AssertTrue('the session was re-established', Loop.Reconnects >= 2);
    AssertEquals('the failed attempt was counted too', 3, C.RequestCount);
  finally
    Loop.Free;
    C.Free;
  end;
end;

procedure TSseReconnectTest.TestFirstConnectFailureIsReported;
var
  C: TScriptedClient;
  Loop: TSseReconnectLoop;
  E: TSseEvent;
  Raised: Boolean;
begin
  C := TScriptedClient.Create;
  C.RefuseConnection;
  Loop := TSseReconnectLoop.Create(C,
    SseRequest('https://a.example/sse'), 5);
  try
    Raised := False;
    try
      Loop.Next(E);
    except
      on Ex: EHttpError do Raised := True;
    end;
    AssertTrue('a failing FIRST connection is reported to the caller',
      Raised);
    AssertEquals('exactly one attempt was made', 1, C.RequestCount);
    AssertEquals('and it is not counted as a reconnect', 0, Loop.Reconnects);
  finally
    Loop.Free;
    C.Free;
  end;
end;

procedure TSseReconnectTest.TestHonoursServerRetry;
var
  C: TScriptedClient;
  Loop: TSseReconnectLoop;
  E: TSseEvent;
  T0: QWord;
  Elapsed: Int64;
begin
  C := TScriptedClient.Create;
  C.AddBody('retry: 150' + #10 + 'data: a' + #10 + #10);
  C.AddBody('data: b' + #10 + #10);
  Loop := TSseReconnectLoop.Create(C,
    SseRequest('https://a.example/sse'), 5);
  try
    AssertTrue('first event', Loop.Next(E));
    AssertEquals('the server retry is adopted', 150, Loop.RetryMs);
    T0 := GetTickCount64;
    AssertTrue('event after the reconnect', Loop.Next(E));
    Elapsed := Int64(GetTickCount64 - T0);
    AssertTrue('the loop waited about the server delay, not the default',
      Elapsed >= 120);
    AssertTrue('and not the 3000 ms default', Elapsed < cSseDefaultRetryMs);
  finally
    Loop.Free;
    C.Free;
  end;
end;

{ TSseRequestTest }

procedure TSseRequestTest.TestSseRequestSetsAcceptAndIdentity;
var
  R: THttpRequest;
begin
  R := SseRequest('https://a.example/events');
  AssertEquals('method is GET', 'GET', R.MethodToken);
  AssertEquals('accept is text/event-stream', cSseContentType,
    R.Headers.GetFirst(HeaderAccept));
  AssertEquals('no-store cache control', 'no-store',
    R.Headers.GetFirst(HeaderCacheControl));
  AssertEquals('identity encoding', 'identity',
    R.Headers.GetFirst(HeaderAcceptEncoding));
end;

procedure TSseRequestTest.TestSseRequestWaitsIndefinitelyForTheBody;
var
  S: TStreamRequest;
begin
  S := SseRequest('https://a.example/events').ToStreamRequest;
  AssertTrue('the body read deadline is set explicitly',
    S.BodyReadTimeoutSet);
  AssertEquals('and it means wait indefinitely', 0, S.BodyReadTimeoutMs);
  AssertEquals('the lease request still carries identity', 'identity',
    S.Headers.GetFirst(HeaderAcceptEncoding));
end;

procedure TSseRequestTest.TestOrdinaryRequestKeepsTheLegacyBodyDeadline;
var
  S: TStreamRequest;
begin
  // the default path must be byte-for-byte the historic behaviour: an
  // unset deadline falls back to the header timeout inside the lease
  S := THttpRequest.Create(hmGet, 'https://a.example/x').ToStreamRequest;
  AssertFalse('an ordinary request does not set a body deadline',
    S.BodyReadTimeoutSet);
end;

{ TSseTransportTest }

function TSseTransportTest.MakeLease(const AConn: TConnection;
  const ARequest: TStreamRequest; out AAlloc: TStreamIdAllocator;
  out ALease: TStreamLease; out AIL: IConnectionStream): Boolean;
begin
  AAlloc := TStreamIdAllocator.Create;
  ALease := TStreamLease.Create(AConn, AAlloc, ARequest);
  AIL := ALease;
  AConn.ApplyPeerSettingsValue(AConn.PeerSettings);
  Result := True;
end;

procedure TSseTransportTest.TestIdleBodyReadWaitsIndefinitely;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Lease: TStreamLease;
  IL: IConnectionStream;
  Alloc: TStreamIdAllocator;
  Req: TStreamRequest;
  Enc: THpackCodec;
  Driver: TSseReadDriver;
begin
  // This is the central SSE transport defect: the body read inherited the
  // 30 s header timeout, so a quiet-but-alive stream died. A request that
  // sets its OWN deadline of 0 must not see a timeout at all.
  // Non-vacuous: the pre-fix code raised EHttpTimeout after Lease.TimeoutMs,
  // so the "still blocked" assertion below fails if the deadline returns.
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Conn.Start;
    AssertTrue('connection opened', Conn.WaitForState(csOpen, 2000));
    Req := TStreamRequest.WithMethod(hmGet, 'api.example')
      .WithBodyReadTimeout(0);
    MakeLease(Conn, Req, Alloc, Lease, IL);
    try
      Lease.Start;
      Enc := THpackCodec.Create;
      try
        Sock.FeedFrame(ResponseHeadersFor(Enc, '200', Lease.StreamId,
          False));
      finally
        Enc.Free;
      end;
      AssertTrue('headers arrived', Lease.WaitForResponseHeader(2000));
      Lease.TimeoutMs := 60;          // the legacy deadline
      Driver := TSseReadDriver.Create(Lease);
      try
        Driver.Start;
        AssertFalse('the read is still parked well past the legacy deadline',
          Driver.WaitDone(400));
        Sock.FeedFrame(DataFrameOf(Lease.StreamId, 'x', True));
        AssertTrue('the read completes once data arrives',
          Driver.WaitDone(2000));
        AssertFalse('and it did not fail', Driver.Raised);
        AssertEquals('one byte was read', 1, Driver.Bytes);
      finally
        Driver.WaitFor;
        Driver.Free;
      end;
    finally
      Lease.ReleaseLease;
      IL := nil;
      Alloc.Free;
    end;
  finally
    Conn.Free;
  end;
end;

procedure TSseTransportTest.TestExplicitBodyReadTimeoutRaises;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Lease: TStreamLease;
  IL: IConnectionStream;
  Alloc: TStreamIdAllocator;
  Req: TStreamRequest;
  Enc: THpackCodec;
  Buf: array[0..7] of Byte;
  Raised: Boolean;
begin
  // liveness is still available when asked for: an explicit body deadline
  // fires even though the legacy timeout would not
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Conn.Start;
    AssertTrue('connection opened', Conn.WaitForState(csOpen, 2000));
    Req := TStreamRequest.WithMethod(hmGet, 'api.example')
      .WithBodyReadTimeout(80);
    MakeLease(Conn, Req, Alloc, Lease, IL);
    try
      Lease.Start;
      Enc := THpackCodec.Create;
      try
        Sock.FeedFrame(ResponseHeadersFor(Enc, '200', Lease.StreamId,
          False));
      finally
        Enc.Free;
      end;
      AssertTrue('headers arrived', Lease.WaitForResponseHeader(2000));
      Raised := False;
      try
        Lease.ReadBody(Buf, SizeOf(Buf));
      except
        on E: EHttpTimeout do Raised := True;
      end;
      AssertTrue('an explicit body deadline raises EHttpTimeout', Raised);
    finally
      Lease.ReleaseLease;
      IL := nil;
      Alloc.Free;
    end;
  finally
    Conn.Free;
  end;
end;

procedure TSseTransportTest.TestBlockedBodyReadCancelsWithRst;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Lease: TStreamLease;
  IL: IConnectionStream;
  Alloc: TStreamIdAllocator;
  Req: TStreamRequest;
  Enc: THpackCodec;
  Driver: TSseCancelDriver;
  Token: TCancellationToken;
  Buf: array[0..7] of Byte;
  IsCancel: Boolean;
  IsTimeout: Boolean;
  Frames: TArray<TFrame>;
  I, J: Integer;
  SawRst: Boolean;
  RstCode: LongWord;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Conn.Start;
    AssertTrue('connection opened', Conn.WaitForState(csOpen, 2000));
    Token := TCancellationToken.Create;
    // indefinite body read: only the token can end it
    Req := TStreamRequest.WithMethod(hmGet, 'api.example')
      .WithBodyReadTimeout(0)
      .WithCancelToken(Token);
    MakeLease(Conn, Req, Alloc, Lease, IL);
    try
      Lease.Start;
      Enc := THpackCodec.Create;
      try
        Sock.FeedFrame(ResponseHeadersFor(Enc, '200', Lease.StreamId,
          False));
      finally
        Enc.Free;
      end;
      AssertTrue('headers arrived', Lease.WaitForResponseHeader(2000));
      Driver := TSseCancelDriver.Create(Token, 120);
      try
        Driver.Start;
        IsCancel := False;
        IsTimeout := False;
        try
          Lease.ReadBody(Buf, SizeOf(Buf));
        except
          on E: EHttpStreamError do
            IsCancel := E.ErrorCode = ecCancel;
          on E: EHttpTimeout do IsTimeout := True;
        end;
      finally
        Driver.WaitFor;
        Driver.Free;
      end;
      AssertFalse('a cancel is not reported as a timeout', IsTimeout);
      AssertTrue('the cancel surfaces as EHttpStreamError(ecCancel)',
        IsCancel);
      // the stream must be reset, not orphaned
      SawRst := False;
      RstCode := 0;
      for J := 1 to 40 do
      begin
        Frames := Sock.OutboundFrames;
        for I := 0 to High(Frames) do
          if Frames[I].Header.FrameType = ftRstStream then
          begin
            SawRst := True;
            if Length(Frames[I].Payload) >= 4 then
              RstCode := U32BE(Frames[I].Payload, 0);
          end;
        if SawRst then
          Break;
        Sleep(25);
      end;
      AssertTrue('the cancelled read resets the stream', SawRst);
      AssertEquals('with CANCEL', Ord(ecCancel), RstCode);
    finally
      Lease.ReleaseLease;
      IL := nil;
      Alloc.Free;
    end;
  finally
    Conn.Free;
  end;
end;

procedure TSseTransportTest.TestSseStreamReturnsWindowCredit;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Lease: TStreamLease;
  IL: IConnectionStream;
  Alloc: TStreamIdAllocator;
  Req: TStreamRequest;
  Enc: THpackCodec;
  S: IHttpSseSource;
  Resp: IHttpResponse;
  E: TSseEvent;
  Frames: TArray<TFrame>;
  I, J, F: Integer;
  WindowUpdates: Integer;
  Payload: string;
  Last: Boolean;
begin
  // a long-lived stream must keep the peer's send window open: the DATA it
  // consumes has to come back as WINDOW_UPDATE, or the server stalls forever.
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Conn.Start;
    AssertTrue('connection opened', Conn.WaitForState(csOpen, 2000));
    Req := TStreamRequest.WithMethod(hmGet, 'api.example')
      .WithBodyReadTimeout(0);
    MakeLease(Conn, Req, Alloc, Lease, IL);
    try
      Lease.Start;
      Enc := THpackCodec.Create;
      try
        Sock.FeedFrame(ResponseHeadersFor(Enc, '200', Lease.StreamId,
          False));
      finally
        Enc.Free;
      end;
      AssertTrue('headers arrived', Lease.WaitForResponseHeader(2000));
      // 40 KiB of events in ten 4 KiB DATA frames, well past the 32768-byte
      // credit batch, each frame inside the default 16384-byte frame limit
      for F := 0 to 9 do
      begin
        Payload := '';
        for I := 1 to 130 do
          Payload := Payload + 'data: ' + StringOfChar('x', 25) + #10 + #10;
        // trim to a whole number of events within the frame budget
        Last := F = 9;
        Sock.FeedFrame(DataFrameOf(Lease.StreamId, Payload, Last));
      end;
      Resp := TStubResponse.Create(200,
        NewHeaders([HeaderContentType, cSseContentType]), Lease.Body);
      S := TSseSource.Create(Resp);
      try
        AssertTrue('an event arrived', S.ReadEvent(E));
        AssertTrue('and another', S.ReadEvent(E));
      finally
        S.Close;
      end;
      WindowUpdates := 0;
      for J := 1 to 60 do
      begin
        Frames := Sock.OutboundFrames;
        WindowUpdates := 0;
        for I := 0 to High(Frames) do
          if Frames[I].Header.FrameType = ftWindowUpdate then
            Inc(WindowUpdates);
        if WindowUpdates > 0 then
          Break;
        Sleep(25);
      end;
      AssertTrue('a long-lived stream returns WINDOW_UPDATE credit',
        WindowUpdates > 0);
    finally
      Lease.ReleaseLease;
      IL := nil;
      Alloc.Free;
    end;
  finally
    Conn.Free;
  end;
end;

{ TSseLiveTest }

procedure TSseLiveTest.TestLiveStreamDeliversEventsAndResumes;
var
  Url: string;
  F: THttpClientFactory;
  Client: IHttpClient;
  Loop: TSseReconnectLoop;
  E: TSseEvent;
  Seen: TStringList;
  Limit: Integer;
begin
  // opt-in: point SSE_TEST_URL at tools/validate/sse_server.py; the default
  // suite stays hermetic. The scripted stream ends after id 3 and answers a
  // resumed request (last-event-id: 3) with a single id 4 event, so the test
  // proves delivery, reconnect, resume, and retry: adoption in one run.
  Url := GetEnvironmentVariable('SSE_TEST_URL');
  if Url = '' then
    Exit;

  F := THttpClientFactory.Create
    .WithMaxConnectionsPerHost(1)
    .WithMaxTotalConnections(2)
    .WithMaxStreamsPerConnection(100);
  // the reference server is cleartext on localhost; h2c upgrade is the
  // supported cleartext mode (prior knowledge needs a server that speaks it)
  if Pos('http://', LowerCase(Url)) = 1 then
    F := F.WithClearText(ctUpgrade).WithHttp1Fallback(True);
  Client := F.Build;

  Seen := TStringList.Create;
  try
    Loop := TSseReconnectLoop.Create(Client, SseRequest(Url), 3);
    try
      Limit := 0;
      while Limit < 12 do
      begin
        try
          if not Loop.Next(E) then
            Break;
        except
          // reaching the reconnect bound is a normal terminal state for this
          // scripted server (it closes the stream after id 3), not a failure
          on E2: EHttpTooManySseRetries do
            Break;
        end;
        Inc(Limit);
        Seen.Add(E.Id + '=' + E.EventType + ':' + E.Data);
      end;
      AssertTrue('the live stream delivered events', Seen.Count > 0);
      AssertTrue('the multi-line greeting arrived',
        Seen.IndexOf('=greeting:hello'#10'world') >= 0);
      AssertTrue('the id 1 event arrived',
        Seen.IndexOf('1=message:first') >= 0);
      AssertTrue('the UTF-8 event arrived',
        Seen.IndexOf('2=message:café — naïve') >= 0);
      AssertTrue('the id 3 event arrived',
        Seen.IndexOf('3=message:last') >= 0);
      // resume: the reconnect echoed last-event-id: 3 and the scripted server
      // answered with only the id 4 event, which a stale resume could not get
      AssertTrue('the reconnect resumed past the last id',
        Seen.IndexOf('4=message:after-resume') >= 0);
      AssertTrue('a reconnect actually happened', Loop.Reconnects >= 1);
      AssertEquals('the server retry: value was adopted', 250, Loop.RetryMs);
    finally
      Loop.Free;
    end;
  finally
    Client.Close;
    Seen.Free;
  end;
end;

initialization
  RegisterTest(TSseParserTest);
  RegisterTest(TSseSourceTest);
  RegisterTest(TSseReconnectTest);
  RegisterTest(TSseRequestTest);
  RegisterTest(TSseTransportTest);
  RegisterTest(TSseLiveTest);
end.
