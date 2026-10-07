/// In-memory mock IHttp2Socket, frame-level assertions, and reusable scripted
/// HTTP/2 server scenarios (plan S11 tasks 11.2, 11.3, 11.4).
// - this unit is part of the http2client project (see doc/design/
//   testing-observability.md): "IHttp2Socket has a mock implementation (an
//   in-memory duplex of TFrames) so the whole connection loop runs without a
//   socket."
// - NOTHING here opens a real socket or touches the network. The mock feeds
//   canned inbound bytes to the connection thread and captures every outbound
//   byte; helpers parse the capture back into TFrames so a test can assert the
//   EXACT frame sequence (type, flags, stream id, payload), not merely that
//   "something was written".
//
// Oracle hook (plan task 11.8) — comparing against `nghttp -nv`:
//   1. run the scenario against a TMockSocket and call
//      `FrameSequenceSummary(Mock.OutboundFrames)`; it prints one line per
//      frame as `#n TYPE flags=0xXX stream=N len=L payload=<hex>`.
//   2. run the equivalent request against `nghttp -nv https://host/...` and
//      read its `recv (stream_id=N) SETTINGS/HEADERS/DATA ...` / `send ...`
//      lines (nghttp's direction labels are from the client's point of view).
//   3. compare frame TYPE, stream id, flags and payload length frame by frame;
//      HPACK payload bytes differ because Huffman/table state differs, so
//      compare decoded header lists, not raw HEADERS octets.
//   `TScriptedServer.SendResponse` uses the same static-table-only encoding as
//   nghttp for a bare `:status`, so status frames are byte-comparable.
unit Http2.MockSocket;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, SyncObjs, Generics.Collections, fpcunit, testregistry,
  Http2.Errors, Http2.Frames, Http2.Hpack, Http2.Tls, Http2.Observer,
  Http2.Connection, Http2.Stream, Http2.Messages, Http2.Client;

type
  /// how the mock answers a Read when no canned bytes are available:
  ///   mrmTimeout — raise EHttpTimeout (an idle poll; the default)
  ///   mrmEof     — return 0 (the peer closed the transport)
  ///   mrmStall   — block without returning, so no deadline can fire
  TMockReadMode = (mrmTimeout, mrmEof, mrmStall);

  /// an in-memory duplex IHttp2Socket that feeds canned inbound bytes and
  /// captures outbound bytes. Thread-safe: the connection thread reads/writes
  /// while the test thread scripts and asserts.
  TMockSocket = class(TInterfacedObject, IHttp2Socket)
  private
    FLock: TCriticalSection;
    FWroteEvent: PRTLEvent;
    FDataEvent: PRTLEvent;
    FWritten: TBytes;
    FWrites: Integer;
    FReadData: TBytes;
    FReadPos: Integer;
    FReadMode: TMockReadMode;
    FConnected: Boolean;
    FConnectTimeoutMs: Integer;
    FReadTimeoutMs: Integer;
    FWriteTimeoutMs: Integer;
    FAutoRespond: Boolean;
    FResponseStatus: string;
    FResponseBody: TBytes;
    FResponseEndStream: Boolean;
    FParsePos: Integer;
    FPrefaceDone: Boolean;
    FCodec: THpackCodec;
    FResponseCount: Integer;
    procedure AppendWritten(const ABuffer; const ACount: Integer);
    procedure AppendReadLocked(const ABytes: TBytes);
    procedure ParseAvailable;
    procedure EmitResponse(const AStreamId: LongWord);
  public
    constructor Create;
    destructor Destroy; override;

    // ---- scripting the inbound direction ----
    /// append raw canned bytes the connection thread may read
    procedure Feed(const ABytes: TBytes); overload;
    procedure FeedFrame(const AFrame: TFrame); overload;
    procedure FeedFrames(const AFrames: array of TFrame);
    procedure EnqueueSettings(const ASettings: TConnectionSettings); overload;
    procedure EnqueueSettingsAck;
    procedure EnqueueHeaders(const AStreamId: LongWord; const ABlock: TBytes;
      const AEndHeaders, AEndStream: Boolean);
    /// encode `:status` with the mock's own HPACK codec and feed HEADERS
    procedure EnqueueResponseHeaders(const AStreamId: LongWord;
      const AStatus: string; const AEndStream: Boolean);
    procedure EnqueueData(const AStreamId: LongWord; const AData: TBytes;
      const AEndStream: Boolean);
    procedure EnqueueRstStream(const AStreamId: LongWord;
      const ACode: THttp2ErrorCode);
    procedure EnqueueGoAway(const ALastStreamId: LongWord;
      const ACode: THttp2ErrorCode; const ADebug: TBytes);
    procedure EnqueuePing(const AData: TBytes; const AAck: Boolean);
    procedure EnqueueWindowUpdate(const AStreamId, AIncrement: LongWord);
    /// a frame header whose declared length exceeds any legal
    /// SETTINGS_MAX_FRAME_SIZE, so ReadFrame raises EHttpProtocolError
    procedure EnqueueOversizedFrameHeader;
    /// a PUSH_PROMISE frame addressed to AStreamId promising APromisedId;
    /// since we advertise ENABLE_PUSH = 0 the peer must not send this
    procedure EnqueuePushPromise(const AStreamId, APromisedId: LongWord;
      const ABlock: TBytes);

    /// behave like a scripted server: answer each request HEADERS with a
    /// `:status` (+ body) response. Pass AEndStream=False to answer with
    /// HEADERS only, leaving the lease registered.
    procedure AutoRespondToRequestHeaders(const AStatus: string;
      const ABody: TBytes; const AEndStream: Boolean);

    // ---- capturing the outbound direction ----
    /// every byte written, a copy
    function WrittenBytes: TBytes;
    /// how many Write calls have happened (frames + pieces)
    function WriteCount: Integer;
    /// the captured bytes with (or without) the 24-byte client preface
    function OutboundBytes(const ASkipPreface: Boolean): TBytes;
    /// the captured bytes parsed into frames
    function OutboundFrames(const ASkipPreface: Boolean = True): TArray<TFrame>;
    procedure ClearWritten;
    /// wait until at least ACount frame-writing calls have happened
    function WaitForWrites(const ACount, ATimeoutMs: Integer): Boolean;
    /// wait until at least ACount outbound frames (after the preface) exist
    function WaitForFrames(const ACount, ATimeoutMs: Integer): Boolean;

    // ---- stall mode ----
    /// reads park without returning until UnstallReads/Close
    procedure StallReads;
    procedure UnstallReads;
    property ReadMode: TMockReadMode read FReadMode write FReadMode;
    /// how many auto-responded requests the mock has answered
    property AutoResponseCount: Integer read FResponseCount;

    // IHttp2Socket
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

{ ---- frame serialization + exact-sequence assertion helpers (11.3) ---- }

/// serialize one frame to its wire bytes
function FrameToBytes(const AFrame: TFrame): TBytes;
/// append a serialized frame to a byte accumulator
function AppendFrame(const AAcc: TBytes; const AFrame: TFrame): TBytes;
/// parse one frame starting at AOffset; returns False when not enough bytes
function ParseFrameAt(const ABytes: TBytes; const AOffset: Integer;
  out AFrame: TFrame; out ANextOffset: Integer): Boolean;
/// parse every complete frame, optionally skipping the 24-byte preface
function ParseFrameSequence(const ABytes: TBytes;
  const ASkipPreface: Boolean): TArray<TFrame>;

/// one-line human-readable frame description (also the oracle dump format)
function FrameSummary(const AFrame: TFrame): string;
/// one line per frame, in order
function FrameSequenceSummary(const AFrames: TArray<TFrame>): string;

/// assert AActual matches AExpected frame for frame (type, flags, stream id,
/// payload length and bytes)
procedure AssertFrameSequence(const AExpected, AActual: TArray<TFrame>;
  const ALabel: string);

type
  /// a reusable scripted peer: builds and feeds canned server frame sequences
  /// over a TMockSocket, encoding response headers with its own HPACK codec
TScriptedServer = class
private
  FMock: TMockSocket;
  FCodec: THpackCodec;
  FStatus: string;
public
  constructor Create(const AMock: TMockSocket); overload;
  constructor Create(const AMock: TMockSocket;
    const AStatus: string); overload;
  destructor Destroy; override;

  procedure SendSettings(const ASettings: TConnectionSettings);
  procedure SendSettingsAck;
  procedure SendHeaders(const AStreamId: LongWord; const AStatus: string;
    const AEndStream: Boolean);
  procedure SendResponse(const AStreamId: LongWord; const AStatus: string;
    const ABody: TBytes; const AEndStream: Boolean = True);
  procedure SendGoAway(const ALastStreamId: LongWord;
    const ACode: THttp2ErrorCode = ecNoError);
  procedure SendRstStream(const AStreamId: LongWord;
    const ACode: THttp2ErrorCode);
  procedure SendPing(const AData: TBytes; const AAck: Boolean = False);
  procedure SendWindowUpdate(const AStreamId, AIncrement: LongWord);

  // ---- named reusable scenarios (11.4) ----
  procedure ScenarioNormalGet(const AStreamId: LongWord; const ABody: TBytes);
  procedure ScenarioMultiplex(const AStreamIds: array of LongWord);
  procedure ScenarioGoAway(const ALastStreamId: LongWord);
  procedure ScenarioRstStream(const AStreamId: LongWord;
    const ACode: THttp2ErrorCode);
  // peer advertises a zero initial window and withholds WINDOW_UPDATE, then
  // stalls so the client's read cannot make progress (flow-control stall)
  procedure ScenarioZeroWindow(const AStreamId: LongWord);
  // an oversized frame header, so the connection must fail the read
  procedure ScenarioMalformedFrame;
  /// send PUSH_PROMISE even though the client disabled push (case 8.2/1)
  procedure ScenarioPushPromise(const AStreamId,
    APromisedId: LongWord);
end;

/// a worker that performs exactly one Read on a socket
TReadProbe = class(TThread)
private
  FSocket: IHttp2Socket;
  FDone: PRTLEvent;
  FDoneFlag: Boolean;
  FCount: Integer;
  FRaised: Boolean;
  FError: string;
protected
  procedure Execute; override;
public
  constructor Create(const ASocket: IHttp2Socket);
  destructor Destroy; override;
  function WaitDone(const ATimeoutMs: Integer): Boolean;
  property Count: Integer read FCount;
  property Raised: Boolean read FRaised;
  property Error: string read FError;
end;

/// a do-nothing IConnectionStream, so the observer tests can register and
/// unregister a stream without pulling in another test unit's fake lease
type
  TObserverTestLease = class(TInterfacedObject, IConnectionStream)
  public
    procedure OnConnectionFailed(const AMessage: string;
      const ACode: THttp2ErrorCode);
    procedure OnConnectionGoAway(const ALastStreamId: LongWord);
    procedure OnStreamFrame(const AFrame: TFrame);
  end;

/// bounded wait until at least ACount events of AKind are recorded
function WaitForObserverEvent(const AObs: TRecordingObserver;
  const AKind: TObserverEventKind; const ACount, ATimeoutMs: Integer): Boolean;

type
  /// hands out a fresh TMockSocket on every Dial, so the PUBLIC client
  /// (THttpClientFactory.WithSocketFactory) can drive the whole Send path
  /// with no real socket (plan S11 "Done when: the mock socket can drive the
  /// full Send path to completion").
  TMockSocketFactory = class(TInterfacedObject, IHttp2SocketFactory)
  private
    FLock: TCriticalSection;
    /// non-owning raw pointers, only for assertions from the test thread
    FSockets: TList<TMockSocket>;
    /// owning interface references, so a handed-out socket stays alive even
    /// after every connection released it (TMockSocket is refcounted)
    FKeepAlive: TList<IHttp2Socket>;
    FDials: Integer;
    FStatus: string;
    FBody: TBytes;
    FEndStream: Boolean;
  public
    constructor Create;
    destructor Destroy; override;
    /// configure the canned response every handed-out socket will produce
    procedure SetResponse(const AStatus: string; const ABody: TBytes;
      const AEndStream: Boolean);
    function Dial(const AHost: string; const APort: Word;
      const ATimeoutMs: Integer): IHttp2Socket;
    function Dials: Integer;
    /// the socket handed out on the 0-based AIndex-th dial
    function Socket(const AIndex: Integer): TMockSocket;
  end;

type
  /// recorded observer events (11.1)
TObserverEmissionTest = class(TTestCase)
private
  function MakeConn(out ASock: TMockSocket;
    out AObs: TRecordingObserver): TConnection;
published
  procedure TestConnectionOpenAndCloseObserved;
  procedure TestFrameOutObserved;
  procedure TestFrameInObserved;
  procedure TestGoAwayAndStreamLifecycleObserved;
  procedure TestWindowUpdateObserved;
  procedure TestDiscardedUnknownFrameObserved;
  procedure TestRetryObserved;
  procedure TestRaisingObserverDoesNotBreakConnection;
end;

/// mock socket capture + frame-level assertions (11.2, 11.3)
TMockSocketTest = class(TTestCase)
published
  procedure TestCapturesExactOutboundFrameSequence;
  procedure TestOutboundBytesSkipPreface;
  procedure TestStalledReadNeverReturnsUntilReleased;
  procedure TestMalformedFrameEnqueueFailsTheConnection;
end;

/// reusable scripted scenarios (11.4)
TScriptedScenarioTest = class(TTestCase)
published
  procedure TestScenarioNormalGet;
  procedure TestScenarioMultiplex;
  procedure TestScenarioGoAway;
  procedure TestScenarioRstStream;
  procedure TestScenarioZeroWindowStallsBodyRead;
  /// regression: received DATA must return window credit to the peer, else a
  /// body larger than the initial window stalls (interop A.7)
  procedure TestScenarioLargeBodyEmitsWindowUpdate;
  procedure TestScenarioMalformedFrameClosesConnection;
  /// RFC 9113 section 6.6: we advertise ENABLE_PUSH = 0, so a PUSH_PROMISE
  /// from the peer is a connection PROTOCOL_ERROR (harness case 8.2/1)
  procedure TestScenarioPushPromiseRejected;
  /// the contractual one: the PUBLIC Send path over the mock socket
  procedure TestScenarioFullSendPathOverMockSocket;
end;

implementation

{ ---- frame helpers ---- }

function FrameToBytes(const AFrame: TFrame): TBytes;
var
  MS: TMemoryStream;
begin
  Result := nil;
  MS := TMemoryStream.Create;
  try
    WriteFrame(MS, AFrame);
    SetLength(Result, MS.Size);
    if MS.Size > 0 then
      Move(MS.Memory^, Result[0], MS.Size);
  finally
    MS.Free;
  end;
end;

function AppendFrame(const AAcc: TBytes; const AFrame: TFrame): TBytes;
var
  B: TBytes;
  N: Integer;
begin
  Result := nil;
  B := FrameToBytes(AFrame);
  N := Length(AAcc);
  SetLength(Result, N + Length(B));
  if N > 0 then
    Move(AAcc[0], Result[0], N);
  if Length(B) > 0 then
    Move(B[0], Result[N], Length(B));
end;

function ParseFrameAt(const ABytes: TBytes; const AOffset: Integer;
  out AFrame: TFrame; out ANextOffset: Integer): Boolean;
var
  Hdr: TBytes;
  Total: Integer;
begin
  AFrame.Header.Clear;
  AFrame.Payload := nil;
  ANextOffset := AOffset;
  if AOffset + FrameHeaderSize > Length(ABytes) then
    Exit(False);
  Hdr := Copy(ABytes, AOffset, FrameHeaderSize);
  AFrame.Header := TFrameHeader.ReadFrom(Hdr);
  Total := FrameHeaderSize + Integer(AFrame.Header.Length);
  if AOffset + Total > Length(ABytes) then
    Exit(False);
  AFrame.Payload := Copy(ABytes, AOffset + FrameHeaderSize,
    AFrame.Header.Length);
  ANextOffset := AOffset + Total;
  Result := True;
end;

function ParseFrameSequence(const ABytes: TBytes;
  const ASkipPreface: Boolean): TArray<TFrame>;
var
  Ofs: Integer;
  F: TFrame;
begin
  Result := nil;
  if ASkipPreface then
    Ofs := 24
  else
    Ofs := 0;
  while ParseFrameAt(ABytes, Ofs, F, Ofs) do
  begin
    SetLength(Result, Length(Result) + 1);
    Result[High(Result)] := F;
  end;
end;

function FrameSummary(const AFrame: TFrame): string;
var
  B: TBytes;
  I: Integer;
  Hex: string;
begin
  B := AFrame.Payload;
  Hex := '';
  for I := 0 to High(B) do
    Hex := Hex + IntToHex(B[I], 2);
  Result := Format('%s flags=0x%.2x stream=%d len=%d payload=%s',
    [FrameTypeName(AFrame.Header.FrameType),
     FrameFlagsToByte(AFrame.Header.Flags), AFrame.Header.StreamId,
     Length(B), Hex]);
end;

function FrameSequenceSummary(const AFrames: TArray<TFrame>): string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to High(AFrames) do
  begin
    if I > 0 then
      Result := Result + LineEnding;
    Result := Result + '#' + IntToStr(I) + ' ' + FrameSummary(AFrames[I]);
  end;
end;

procedure AssertFrameSequence(const AExpected, AActual: TArray<TFrame>;
  const ALabel: string);
var
  I: Integer;
begin
  TAssert.AssertEquals(ALabel + ': frame count', Length(AExpected), Length(AActual));
  for I := 0 to High(AExpected) do
  begin
    TAssert.AssertEquals(ALabel + ': frame ' + IntToStr(I) + ' type',
      Ord(AExpected[I].Header.FrameType), Ord(AActual[I].Header.FrameType));
    TAssert.AssertEquals(ALabel + ': frame ' + IntToStr(I) + ' flags',
      FrameFlagsToByte(AExpected[I].Header.Flags),
      FrameFlagsToByte(AActual[I].Header.Flags));
    TAssert.AssertEquals(ALabel + ': frame ' + IntToStr(I) + ' stream id',
      AExpected[I].Header.StreamId, AActual[I].Header.StreamId);
    TAssert.AssertEquals(ALabel + ': frame ' + IntToStr(I) + ' payload length',
      Length(AExpected[I].Payload), Length(AActual[I].Payload));
    if Length(AExpected[I].Payload) > 0 then
      TAssert.AssertTrue(ALabel + ': frame ' + IntToStr(I) + ' payload bytes',
        CompareMem(@AExpected[I].Payload[0], @AActual[I].Payload[0],
          Length(AExpected[I].Payload)));
  end;
end;

{ TMockSocket }

constructor TMockSocket.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FWroteEvent := RTLEventCreate;
  FDataEvent := RTLEventCreate;
  FCodec := THpackCodec.Create;
  FConnected := True;
  FConnectTimeoutMs := 1000;
  FReadTimeoutMs := 1000;
  FWriteTimeoutMs := 1000;
  FReadMode := mrmTimeout;
  FReadPos := 0;
  FResponseEndStream := True;
end;

destructor TMockSocket.Destroy;
begin
  FCodec.Free;
  RTLEventDestroy(FWroteEvent);
  RTLEventDestroy(FDataEvent);
  FLock.Free;
  inherited Destroy;
end;

procedure TMockSocket.AppendWritten(const ABuffer;
  const ACount: Integer);
var
  P: PByte;
  N: Integer;
begin
  if ACount <= 0 then
    Exit;
  P := @ABuffer;
  N := Length(FWritten);
  SetLength(FWritten, N + ACount);
  Move(P^, FWritten[N], ACount);
end;

procedure TMockSocket.Feed(const ABytes: TBytes);
var
  N: Integer;
begin
  FLock.Acquire;
  try
    N := Length(FReadData);
    SetLength(FReadData, N + Length(ABytes));
    if Length(ABytes) > 0 then
      Move(ABytes[0], FReadData[N], Length(ABytes));
  finally
    FLock.Release;
  end;
  RTLEventSetEvent(FDataEvent);
end;

procedure TMockSocket.FeedFrame(const AFrame: TFrame);
begin
  Feed(FrameToBytes(AFrame));
end;

procedure TMockSocket.FeedFrames(const AFrames: array of TFrame);
var
  I: Integer;
  Acc: TBytes;
begin
  Acc := nil;
  for I := 0 to High(AFrames) do
    Acc := AppendFrame(Acc, AFrames[I]);
  Feed(Acc);
end;

procedure TMockSocket.EnqueueSettings(const ASettings: TConnectionSettings);
begin
  FeedFrame(BuildSettingsFrame(ASettings));
end;

procedure TMockSocket.EnqueueSettingsAck;
begin
  FeedFrame(BuildSettingsAck);
end;

procedure TMockSocket.EnqueueHeaders(const AStreamId: LongWord;
  const ABlock: TBytes; const AEndHeaders, AEndStream: Boolean);
begin
  FeedFrame(BuildHeadersFrame(AStreamId, ABlock, AEndHeaders, AEndStream));
end;

procedure TMockSocket.EnqueueResponseHeaders(const AStreamId: LongWord;
  const AStatus: string; const AEndStream: Boolean);
var
  Block: THeaderBlock;
  Enc: TBytes;
begin
  SetLength(Block, 1);
  Block[0].Name := ':status';
  Block[0].Value := AStatus;
  Block[0].Sensitive := False;
  Enc := FCodec.Encode(Block);
  FeedFrame(BuildHeadersFrame(AStreamId, Enc, True, AEndStream));
end;

procedure TMockSocket.EnqueueData(const AStreamId: LongWord;
  const AData: TBytes; const AEndStream: Boolean);
begin
  FeedFrame(BuildDataFrame(AStreamId, AData, AEndStream));
end;

procedure TMockSocket.EnqueueRstStream(const AStreamId: LongWord;
  const ACode: THttp2ErrorCode);
begin
  FeedFrame(BuildRstStreamFrame(AStreamId, ACode));
end;

procedure TMockSocket.EnqueueGoAway(const ALastStreamId: LongWord;
  const ACode: THttp2ErrorCode; const ADebug: TBytes);
begin
  FeedFrame(BuildGoAwayFrame(ALastStreamId, ACode, ADebug));
end;

procedure TMockSocket.EnqueuePing(const AData: TBytes; const AAck: Boolean);
begin
  FeedFrame(BuildPingFrame(AData, AAck));
end;

procedure TMockSocket.EnqueueWindowUpdate(const AStreamId,
  AIncrement: LongWord);
begin
  FeedFrame(BuildWindowUpdateFrame(AStreamId, AIncrement));
end;

procedure TMockSocket.EnqueueOversizedFrameHeader;
var
  Hdr: TBytes;
begin
  // declared length 0xFFFFFF (16777215) exceeds every legal max frame size,
  // so the connection's ReadFrame must raise EHttpProtocolError
  SetLength(Hdr, FrameHeaderSize);
  Hdr[0] := $FF;
  Hdr[1] := $FF;
  Hdr[2] := $FF;
  Hdr[3] := Ord(ftData);
  Hdr[4] := 0;
  Hdr[5] := 0;
  Hdr[6] := 0;
  Hdr[7] := 0;
  Hdr[8] := 0;
  Feed(Hdr);
end;

procedure TMockSocket.EnqueuePushPromise(const AStreamId,
  APromisedId: LongWord; const ABlock: TBytes);
var
  Payload: TBytes;
begin
  // PUSH_PROMISE payload: R + promised-stream-id (4 bytes), then the header
  // block fragment. We advertise ENABLE_PUSH = 0, so any such frame must be
  // rejected as a connection PROTOCOL_ERROR (RFC 9113 section 6.6).
  SetLength(Payload, 4 + Length(ABlock));
  Payload[0] := (APromisedId shr 24) and $FF;
  Payload[1] := (APromisedId shr 16) and $FF;
  Payload[2] := (APromisedId shr 8) and $FF;
  Payload[3] := APromisedId and $FF;
  if Length(ABlock) > 0 then
    Move(ABlock[0], Payload[4], Length(ABlock));
  FeedFrame(TFrame.Create(ftPushPromise, [ffEndHeaders], AStreamId, Payload));
end;

procedure TMockSocket.AutoRespondToRequestHeaders(const AStatus: string;
  const ABody: TBytes; const AEndStream: Boolean);
begin
  FLock.Acquire;
  try
    FAutoRespond := True;
    FResponseStatus := AStatus;
    FResponseBody := ABody;
    FResponseEndStream := AEndStream;
  finally
    FLock.Release;
  end;
end;

procedure TMockSocket.EmitResponse(const AStreamId: LongWord);
var
  Block: THeaderBlock;
  Enc: TBytes;
  F: TFrame;
begin
  // reached from ParseAvailable while FLock is held: append directly
  SetLength(Block, 1);
  Block[0].Name := ':status';
  Block[0].Value := FResponseStatus;
  Block[0].Sensitive := False;
  Enc := FCodec.Encode(Block);
  if Length(FResponseBody) = 0 then
  begin
    F := BuildHeadersFrame(AStreamId, Enc, True, FResponseEndStream);
    AppendReadLocked(FrameToBytes(F));
  end
  else
  begin
    F := BuildHeadersFrame(AStreamId, Enc, True, False);
    AppendReadLocked(FrameToBytes(F));
    F := BuildDataFrame(AStreamId, FResponseBody, FResponseEndStream);
    AppendReadLocked(FrameToBytes(F));
  end;
  Inc(FResponseCount);
end;

procedure TMockSocket.AppendReadLocked(const ABytes: TBytes);
var
  N: Integer;
begin
  // caller already holds FLock (used by ParseAvailable's auto-respond path)
  N := Length(FReadData);
  SetLength(FReadData, N + Length(ABytes));
  if Length(ABytes) > 0 then
    Move(ABytes[0], FReadData[N], Length(ABytes));
end;

procedure TMockSocket.ParseAvailable;
var
  Len, Typ, Total: Integer;
  StreamId: LongWord;
begin
  if not FPrefaceDone then
  begin
    if Length(FWritten) < 24 then
      Exit;
    FParsePos := 24;
    FPrefaceDone := True;
  end;
  while Length(FWritten) - FParsePos >= FrameHeaderSize do
  begin
    Len := (FWritten[FParsePos] shl 16) or (FWritten[FParsePos + 1] shl 8) or
      FWritten[FParsePos + 2];
    Typ := FWritten[FParsePos + 3];
    StreamId := (LongWord(FWritten[FParsePos + 5]) shl 24) or
      (LongWord(FWritten[FParsePos + 6]) shl 16) or
      (LongWord(FWritten[FParsePos + 7]) shl 8) or
      LongWord(FWritten[FParsePos + 8]);
    if Length(FWritten) - FParsePos < FrameHeaderSize + Len then
      Exit;
    Total := FrameHeaderSize + Len;
    Inc(FParsePos, Total);
    if FAutoRespond and (Typ = Ord(ftHeaders)) and (StreamId <> 0) then
      EmitResponse(StreamId);
  end;
end;

function TMockSocket.WrittenBytes: TBytes;
begin
  FLock.Acquire;
  try
    Result := Copy(FWritten, 0, Length(FWritten));
  finally
    FLock.Release;
  end;
end;

function TMockSocket.WriteCount: Integer;
begin
  FLock.Acquire;
  try
    Result := FWrites;
  finally
    FLock.Release;
  end;
end;

function TMockSocket.OutboundBytes(const ASkipPreface: Boolean): TBytes;
var
  All: TBytes;
  Start: Integer;
begin
  All := WrittenBytes;
  if ASkipPreface then
    Start := 24
  else
    Start := 0;
  if Start >= Length(All) then
    Result := nil
  else
    Result := Copy(All, Start, Length(All) - Start);
end;

function TMockSocket.OutboundFrames(
  const ASkipPreface: Boolean): TArray<TFrame>;
begin
  Result := ParseFrameSequence(WrittenBytes, ASkipPreface);
end;

procedure TMockSocket.ClearWritten;
begin
  FLock.Acquire;
  try
    FWritten := nil;
    FWrites := 0;
    FParsePos := 0;
    FPrefaceDone := False;
  finally
    FLock.Release;
  end;
end;

function TMockSocket.WaitForWrites(const ACount, ATimeoutMs: Integer): Boolean;
var
  Deadline: QWord;
  Remaining: Integer;
begin
  Deadline := GetTickCount64 + QWord(ATimeoutMs);
  while WriteCount < ACount do
  begin
    if GetTickCount64 >= Deadline then
      Exit(False);
    Remaining := Integer(Deadline - GetTickCount64);
    RTLEventWaitFor(FWroteEvent, Remaining);
  end;
  Result := True;
end;

function TMockSocket.WaitForFrames(const ACount, ATimeoutMs: Integer): Boolean;
var
  Deadline: QWord;
  Remaining: Integer;
begin
  Result := False;
  Deadline := GetTickCount64 + QWord(ATimeoutMs);
  while True do
  begin
    if Length(OutboundFrames(True)) >= ACount then
      Exit(True);
    if GetTickCount64 >= Deadline then
      Exit(False);
    Remaining := Integer(Deadline - GetTickCount64);
    RTLEventWaitFor(FWroteEvent, Remaining);
  end;
end;

procedure TMockSocket.StallReads;
begin
  FLock.Acquire;
  try
    FReadMode := mrmStall;
  finally
    FLock.Release;
  end;
end;

procedure TMockSocket.UnstallReads;
begin
  FLock.Acquire;
  try
    if FReadMode = mrmStall then
      FReadMode := mrmTimeout;
  finally
    FLock.Release;
  end;
  RTLEventSetEvent(FDataEvent);
end;

function TMockSocket.Read(var ABuffer; ACount: Integer): Integer;
var
  Avail, N: Integer;
  P: PByte;
begin
  if not FConnected then
    raise EHttpConnectionClosed.Create('mock socket closed');
  FLock.Acquire;
  try
    while True do
    begin
      Avail := Length(FReadData) - FReadPos;
      if Avail > 0 then
      begin
        N := ACount;
        if N > Avail then
          N := Avail;
        P := @ABuffer;
        Move(FReadData[FReadPos], P^, N);
        Inc(FReadPos, N);
        Exit(N);
      end;
      if FReadMode = mrmEof then
        Exit(0);
      if FReadMode = mrmStall then
      begin
        // park without returning; the connection thread stays blocked in
        // Read, so no deadline can fire. Close/Unstall releases us.
        FLock.Release;
        try
          RTLEventWaitFor(FDataEvent, 100);
        finally
          FLock.Acquire;
        end;
        if (not FConnected) or (FReadMode <> mrmStall) then
          raise EHttpTimeout.Create('mock read unstalled');
        Continue;
      end;
      raise EHttpTimeout.Create('mock read idle');
    end;
    Result := 0;
  finally
    FLock.Release;
  end;
end;

function TMockSocket.Write(const ABuffer; ACount: Integer): Integer;
begin
  if not FConnected then
    raise EHttpConnectionClosed.Create('mock socket closed');
  FLock.Acquire;
  try
    AppendWritten(ABuffer, ACount);
    Inc(FWrites);
    ParseAvailable;
  finally
    FLock.Release;
  end;
  RTLEventSetEvent(FWroteEvent);
  Result := ACount;
end;

procedure TMockSocket.Close;
begin
  FLock.Acquire;
  try
    FConnected := False;
  finally
    FLock.Release;
  end;
  RTLEventSetEvent(FDataEvent);
  RTLEventSetEvent(FWroteEvent);
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

{ TScriptedServer }

constructor TScriptedServer.Create(const AMock: TMockSocket);
begin
  Create(AMock, '200');
end;

constructor TScriptedServer.Create(const AMock: TMockSocket;
  const AStatus: string);
begin
  inherited Create;
  FMock := AMock;
  FCodec := THpackCodec.Create;
  FStatus := AStatus;
end;

destructor TScriptedServer.Destroy;
begin
  FCodec.Free;
  inherited Destroy;
end;

procedure TScriptedServer.SendSettings(const ASettings: TConnectionSettings);
begin
  FMock.EnqueueSettings(ASettings);
end;

procedure TScriptedServer.SendSettingsAck;
begin
  FMock.EnqueueSettingsAck;
end;

procedure TScriptedServer.SendHeaders(const AStreamId: LongWord;
  const AStatus: string; const AEndStream: Boolean);
var
  Block: THeaderBlock;
  Enc: TBytes;
begin
  SetLength(Block, 1);
  Block[0].Name := ':status';
  Block[0].Value := AStatus;
  Block[0].Sensitive := False;
  Enc := FCodec.Encode(Block);
  FMock.EnqueueHeaders(AStreamId, Enc, True, AEndStream);
end;

procedure TScriptedServer.SendResponse(const AStreamId: LongWord;
  const AStatus: string; const ABody: TBytes; const AEndStream: Boolean);
begin
  SendHeaders(AStreamId, AStatus, AEndStream and (Length(ABody) = 0));
  if Length(ABody) > 0 then
    FMock.EnqueueData(AStreamId, ABody, AEndStream);
end;

procedure TScriptedServer.SendGoAway(const ALastStreamId: LongWord;
  const ACode: THttp2ErrorCode);
begin
  FMock.EnqueueGoAway(ALastStreamId, ACode, nil);
end;

procedure TScriptedServer.SendRstStream(const AStreamId: LongWord;
  const ACode: THttp2ErrorCode);
begin
  FMock.EnqueueRstStream(AStreamId, ACode);
end;

procedure TScriptedServer.SendPing(const AData: TBytes; const AAck: Boolean);
begin
  FMock.EnqueuePing(AData, AAck);
end;

procedure TScriptedServer.SendWindowUpdate(const AStreamId,
  AIncrement: LongWord);
begin
  FMock.EnqueueWindowUpdate(AStreamId, AIncrement);
end;

procedure TScriptedServer.ScenarioNormalGet(const AStreamId: LongWord;
  const ABody: TBytes);
begin
  SendSettings(TConnectionSettings.Defaults);
  SendResponse(AStreamId, FStatus, ABody, True);
end;

procedure TScriptedServer.ScenarioMultiplex(
  const AStreamIds: array of LongWord);
var
  I: Integer;
begin
  SendSettings(TConnectionSettings.Defaults);
  for I := 0 to High(AStreamIds) do
    SendResponse(AStreamIds[I], FStatus, nil, True);
end;

procedure TScriptedServer.ScenarioGoAway(const ALastStreamId: LongWord);
begin
  SendGoAway(ALastStreamId, ecNoError);
end;

procedure TScriptedServer.ScenarioRstStream(const AStreamId: LongWord;
  const ACode: THttp2ErrorCode);
begin
  SendRstStream(AStreamId, ACode);
end;

procedure TScriptedServer.ScenarioZeroWindow(const AStreamId: LongWord);
var
  S: TConnectionSettings;
begin
  S := TConnectionSettings.Defaults;
  S.InitialWindowSize := 0;      // peer grants no stream window
  SendSettings(S);
  // answer the request headers but never replenish the window
  SendHeaders(AStreamId, FStatus, False);
  FMock.StallReads;
end;

procedure TScriptedServer.ScenarioMalformedFrame;
begin
  FMock.EnqueueOversizedFrameHeader;
end;

procedure TScriptedServer.ScenarioPushPromise(const AStreamId,
  APromisedId: LongWord);
begin
  FMock.EnqueuePushPromise(AStreamId, APromisedId, nil);
end;

{ TObserverTestLease }

procedure TObserverTestLease.OnConnectionFailed(const AMessage: string;
  const ACode: THttp2ErrorCode);
begin
end;

procedure TObserverTestLease.OnConnectionGoAway(
  const ALastStreamId: LongWord);
begin
end;

procedure TObserverTestLease.OnStreamFrame(const AFrame: TFrame);
begin
end;

{ TReadProbe }

constructor TReadProbe.Create(const ASocket: IHttp2Socket);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FSocket := ASocket;
  FDone := RTLEventCreate;
end;

destructor TReadProbe.Destroy;
begin
  RTLEventDestroy(FDone);
  inherited Destroy;
end;

procedure TReadProbe.Execute;
var
  Buf: array[0..31] of Byte;
begin
  try
    try
      FCount := FSocket.Read(Buf, SizeOf(Buf));
    except
      on E: Exception do
      begin
        FRaised := True;
        FError := E.ClassName + ': ' + E.Message;
      end;
    end;
  finally
    FDoneFlag := True;
    RTLEventSetEvent(FDone);
  end;
end;

function TReadProbe.WaitDone(const ATimeoutMs: Integer): Boolean;
var
  Deadline: QWord;
  Remaining: Integer;
begin
  Deadline := GetTickCount64 + QWord(ATimeoutMs);
  while not FDoneFlag do
  begin
    if GetTickCount64 >= Deadline then
      Exit(False);
    Remaining := Integer(Deadline - GetTickCount64);
    RTLEventWaitFor(FDone, Remaining);
  end;
  Result := True;
end;

{ WaitForObserverEvent }

function WaitForObserverEvent(const AObs: TRecordingObserver;
  const AKind: TObserverEventKind; const ACount, ATimeoutMs: Integer): Boolean;
begin
  Result := AObs.WaitForCount(AKind, ACount, ATimeoutMs);
end;

{ shared test helpers }

function BytesOfString(const A: string): TBytes;
var
  I: Integer;
begin
  Result := nil;
  SetLength(Result, Length(A));
  for I := 1 to Length(A) do
    Result[I - 1] := Ord(A[I]);
end;

function ReadAllBodyText(const ABody: IHttpBodyStream): string;
var
  Buf: array[0..63] of Byte;
  N, I: LongInt;
begin
  Result := '';
  while True do
  begin
    N := ABody.Read(Buf, SizeOf(Buf));
    if N = 0 then
      Break;
    for I := 0 to N - 1 do
      Result := Result + Chr(Buf[I]);
  end;
end;

{ TObserverEmissionTest }

function TObserverEmissionTest.MakeConn(out ASock: TMockSocket;
  out AObs: TRecordingObserver): TConnection;
begin
  ASock := TMockSocket.Create;
  AObs := TRecordingObserver.Create;
  Result := TConnection.Create(ASock);
  Result.Observer := AObs;
end;

procedure TObserverEmissionTest.TestConnectionOpenAndCloseObserved;
var
  Conn: TConnection;
  Sock: TMockSocket;
  Obs: TRecordingObserver;
  Lease: TObserverTestLease;
  IL: IConnectionStream;
begin
  Conn := MakeConn(Sock, Obs);
  try
    Conn.Start;
    AssertTrue('connection opens', Conn.WaitForState(csOpen, 2000));
    AssertTrue('connection-open observed',
      Obs.WaitForCount(oekConnectionOpen, 1, 2000));

    // register then unregister a stream and observe the lifecycle
    Lease := TObserverTestLease.Create;
    IL := Lease;
    Conn.RegisterStream(7, IL);
    AssertTrue('stream-open observed',
      Obs.WaitForCount(oekStreamOpen, 1, 2000));
    Conn.UnregisterStream(7);
    AssertTrue('stream-close observed',
      Obs.WaitForCount(oekStreamClose, 1, 2000));

    Conn.Close;
    AssertTrue('connection-close observed',
      Obs.WaitForCount(oekConnectionClose, 1, 2000));
    AssertEquals('exactly one close event', 1,
      Obs.CountOf(oekConnectionClose));
  finally
    Conn.Free;
  end;
end;

procedure TObserverEmissionTest.TestFrameOutObserved;
var
  Conn: TConnection;
  Sock: TMockSocket;
  Obs: TRecordingObserver;
  I: Integer;
  FoundPing: Boolean;
begin
  Conn := MakeConn(Sock, Obs);
  try
    Conn.Start;
    AssertTrue('connection opens', Conn.WaitForState(csOpen, 2000));
    AssertTrue('initial SETTINGS frame-out observed',
      Obs.WaitForCount(oekFrameOut, 1, 2000));
    // an explicitly posted frame must also be observed as frame-out
    AssertTrue('frame posted', Conn.PostFrame(BuildPingFrame(nil, False)));
    AssertTrue('posted frame-out observed',
      Obs.WaitForCount(oekFrameOut, 2, 2000));
    FoundPing := False;
    for I := 0 to Obs.Count - 1 do
      if (Obs.Event(I).Kind = oekFrameOut) and
         (Obs.Event(I).FrameType = ftPing) then
        FoundPing := True;
    AssertTrue('the PING frame-out event carries its type', FoundPing);
  finally
    Conn.Free;
  end;
end;

procedure TObserverEmissionTest.TestFrameInObserved;
var
  Conn: TConnection;
  Sock: TMockSocket;
  Obs: TRecordingObserver;
  Idx: Integer;
begin
  Conn := MakeConn(Sock, Obs);
  try
    Conn.Start;
    AssertTrue('connection opens', Conn.WaitForState(csOpen, 2000));
    Sock.EnqueuePing(nil, False);
    AssertTrue('frame-in observed',
      Obs.WaitForCount(oekFrameIn, 1, 2000));
    Idx := Obs.IndexOf(oekFrameIn);
    AssertEquals('the inbound frame event is the PING', Ord(ftPing),
      Ord(Obs.Event(Idx).FrameType));
  finally
    Conn.Free;
  end;
end;

procedure TObserverEmissionTest.TestGoAwayAndStreamLifecycleObserved;
var
  Conn: TConnection;
  Sock: TMockSocket;
  Obs: TRecordingObserver;
  Idx: Integer;
begin
  Conn := MakeConn(Sock, Obs);
  try
    Conn.Start;
    AssertTrue('connection opens', Conn.WaitForState(csOpen, 2000));
    Sock.EnqueueGoAway(5, ecNoError, nil);
    AssertTrue('GOAWAY observed', Obs.WaitForCount(oekGoAway, 1, 2000));
    AssertTrue('connection reaches goaway state',
      Conn.WaitForState(csGoAway, 2000));
    Idx := Obs.IndexOf(oekGoAway);
    AssertEquals('GOAWAY event carries the last-stream-id', LongWord(5),
      Obs.Event(Idx).StreamId);
  finally
    Conn.Free;
  end;
end;

procedure TObserverEmissionTest.TestWindowUpdateObserved;
var
  Conn: TConnection;
  Sock: TMockSocket;
  Obs: TRecordingObserver;
  Idx: Integer;
begin
  Conn := MakeConn(Sock, Obs);
  try
    Conn.Start;
    AssertTrue('connection opens', Conn.WaitForState(csOpen, 2000));
    Sock.EnqueueWindowUpdate(1, 4096);
    AssertTrue('window-update observed',
      Obs.WaitForCount(oekWindowUpdate, 1, 2000));
    Idx := Obs.IndexOf(oekWindowUpdate);
    AssertEquals('window-update stream id', LongWord(1),
      Obs.Event(Idx).StreamId);
    AssertEquals('window-update increment', LongWord(4096),
      Obs.Event(Idx).Increment);
  finally
    Conn.Free;
  end;
end;

procedure TObserverEmissionTest.TestDiscardedUnknownFrameObserved;
var
  Conn: TConnection;
  Sock: TMockSocket;
  Obs: TRecordingObserver;
  Raw: TBytes;
begin
  Conn := MakeConn(Sock, Obs);
  try
    Conn.Start;
    AssertTrue('connection opens', Conn.WaitForState(csOpen, 2000));
    // a frame type that RFC 7540 does not define (0x0A) must be reported
    // as discarded, not silently swallowed
    SetLength(Raw, FrameHeaderSize);
    Raw[0] := 0; Raw[1] := 0; Raw[2] := 0;
    Raw[3] := $0A; Raw[4] := 0;
    Raw[5] := 0; Raw[6] := 0; Raw[7] := 0; Raw[8] := 0;
    Sock.Feed(Raw);
    AssertTrue('discarded frame observed',
      Obs.WaitForCount(oekDiscarded, 1, 2000));
    AssertEquals('discard reason mentions unknown type', True,
      Pos('unknown', Obs.Event(Obs.IndexOf(oekDiscarded)).Reason) > 0);
  finally
    Conn.Free;
  end;
end;

procedure TObserverEmissionTest.TestRetryObserved;
var
  Conn: TConnection;
  Sock: TMockSocket;
  Obs: TRecordingObserver;
  Idx: Integer;
begin
  Conn := MakeConn(Sock, Obs);
  try
    Conn.Start;
    AssertTrue('connection opens', Conn.WaitForState(csOpen, 2000));
    Sock.EnqueueGoAway(5, ecNoError, nil);
    AssertTrue('connection reaches goaway state',
      Conn.WaitForState(csGoAway, 2000));
    // a stream above the peer's last-stream-id is retryable, which emits
    AssertTrue('stream 7 is retryable', Conn.IsStreamRetryable(7));
    AssertTrue('retry observed', Obs.WaitForCount(oekRetry, 1, 2000));
    Idx := Obs.IndexOf(oekRetry);
    AssertEquals('retry event carries the stream id', LongWord(7),
      Obs.Event(Idx).StreamId);
    AssertFalse('stream at last id is not retryable', Conn.IsStreamRetryable(5));
  finally
    Conn.Free;
  end;
end;

procedure TObserverEmissionTest.TestRaisingObserverDoesNotBreakConnection;
var
  Conn: TConnection;
  Sock: TMockSocket;
  Obs: TRecordingObserver;
begin
  Conn := MakeConn(Sock, Obs);
  Obs.RaiseOnEvent := True;
  try
    Conn.Start;
    // every observer callback raises; the connection loop must survive
    AssertTrue('connection still opens despite a raising observer',
      Conn.WaitForState(csOpen, 2000));
    Sock.EnqueuePing(nil, False);
    // feed a frame so frame-in, frame-out (the ping ack) and drop paths run
    AssertTrue('the ping is still acknowledged on the wire',
      Sock.WaitForFrames(2, 2000));
    AssertEquals('connection remains open after a raising observer',
      Ord(csOpen), Ord(Conn.State));
    Conn.Close;
    AssertEquals('a raising observer does not block Close',
      Ord(csClosed), Ord(Conn.State));
  finally
    Conn.Free;
  end;
end;

{ TMockSocketTest }

procedure TMockSocketTest.TestCapturesExactOutboundFrameSequence;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Expected, Actual: TArray<TFrame>;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Conn.Start;
    AssertTrue('SETTINGS written', Sock.WaitForFrames(1, 2000));
    AssertTrue('data frame posted',
      Conn.PostFrame(BuildDataFrame(1, BytesOfString('hi'), True)));
    AssertTrue('data frame written', Sock.WaitForFrames(2, 2000));

    SetLength(Expected, 2);
    Expected[0] := BuildSettingsFrame(TConnectionSettings.Defaults);
    Expected[1] := BuildDataFrame(1, BytesOfString('hi'), True);
    Actual := Sock.OutboundFrames(True);
    AssertFrameSequence(Expected, Actual, 'client preface + data');
  finally
    Conn.Free;
  end;
end;

procedure TMockSocketTest.TestOutboundBytesSkipPreface;
var
  Sock: TMockSocket;
  Conn: TConnection;
  All, NoPreface: TBytes;
  Pre: TBytes;
  I: Integer;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Conn.Start;
    AssertTrue('SETTINGS written', Sock.WaitForFrames(1, 2000));
    All := Sock.OutboundBytes(False);
    NoPreface := Sock.OutboundBytes(True);
    Pre := ClientPrefaceBytes;
    AssertEquals('full capture includes 24-byte preface plus frames',
      24 + Length(NoPreface), Length(All));
    for I := 0 to 23 do
      AssertEquals('preface byte ' + IntToStr(I), Pre[I], All[I]);
    // the skipped capture begins at the SETTINGS frame header
    AssertEquals('no-preface capture starts with SETTINGS type', Ord(ftSettings),
      Ord(NoPreface[3]));
  finally
    Conn.Free;
  end;
end;

procedure TMockSocketTest.TestStalledReadNeverReturnsUntilReleased;
var
  Sock: TMockSocket;
  ISock: IHttp2Socket;
  Probe: TReadProbe;
begin
  Sock := TMockSocket.Create;
  ISock := Sock;          // hold the interface ref; TReadProbe also holds one
  Sock.StallReads;
  Probe := TReadProbe.Create(Sock);
  try
    Probe.Start;
    // a stalled read must NOT complete within the bounded window
    AssertFalse('a stalled read does not return on its own',
      Probe.WaitDone(300));
    // releasing the stall lets the parked read surface a timeout
    Sock.UnstallReads;
    AssertTrue('the released read returns', Probe.WaitDone(2000));
  finally
    Probe.Free;
    Sock.Close;
    ISock := nil;         // release the socket last, through its interface
  end;
end;

procedure TMockSocketTest.TestMalformedFrameEnqueueFailsTheConnection;
var
  Sock: TMockSocket;
  Conn: TConnection;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Conn.Start;
    AssertTrue('connection opens', Conn.WaitForState(csOpen, 2000));
    Sock.EnqueueOversizedFrameHeader;
    AssertTrue('an oversized frame closes the connection',
      Conn.WaitForState(csClosed, 2000));
    AssertTrue('an error code was recorded',
      Conn.ErrorCode = ecFrameSizeError);
  finally
    Conn.Free;
  end;
end;

{ TScriptedScenarioTest }

function StartLease(const AConn: TConnection; const AAlloc: TStreamIdAllocator;
  const AReq: TStreamRequest; out ALease: TStreamLease;
  out AIL: IConnectionStream): Boolean;
begin
  ALease := TStreamLease.Create(AConn, AAlloc, AReq);
  AIL := ALease;
  ALease.Start;
  Result := True;
end;

procedure TScriptedScenarioTest.TestScenarioNormalGet;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Server: TScriptedServer;
  Alloc: TStreamIdAllocator;
  Lease: TStreamLease;
  IL: IConnectionStream;
  Req: TStreamRequest;
  Body: string;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  Server := TScriptedServer.Create(Sock);
  Alloc := TStreamIdAllocator.Create;
  try
    Conn.Start;
    AssertTrue('connection opens', Conn.WaitForState(csOpen, 2000));
    Server.SendSettings(TConnectionSettings.Defaults);
    Req := TStreamRequest.WithMethod(hmGet, 'api.example:443').WithPath('/');
    StartLease(Conn, Alloc, Req, Lease, IL);
    try
      Server.SendResponse(1, '200', BytesOfString('hello'), True);
      AssertTrue('response headers received',
        Lease.WaitForResponseHeader(2000));
      AssertEquals('status 200', 200, Lease.StatusCode);
      Body := ReadAllBodyText(Lease.Body);
      AssertEquals('response body', 'hello', Body);
      AssertTrue('body complete', Lease.Body.Eof);
    finally
      IL := nil;
    end;
  finally
    Alloc.Free;
    Server.Free;
    Conn.Free;
  end;
end;

procedure TScriptedScenarioTest.TestScenarioMultiplex;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Server: TScriptedServer;
  Alloc: TStreamIdAllocator;
  L1, L2: TStreamLease;
  I1, I2: IConnectionStream;
  Req: TStreamRequest;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  Server := TScriptedServer.Create(Sock);
  Alloc := TStreamIdAllocator.Create;
  try
    Conn.Start;
    AssertTrue('connection opens', Conn.WaitForState(csOpen, 2000));
    Server.SendSettings(TConnectionSettings.Defaults);
    Req := TStreamRequest.WithMethod(hmGet, 'api.example:443');
    StartLease(Conn, Alloc, Req, L1, I1);
    StartLease(Conn, Alloc, Req, L2, I2);
    try
      AssertTrue('both streams registered', Conn.StreamCount = 2);
      Server.ScenarioMultiplex([1, 3]);
      AssertTrue('stream 1 headers', L1.WaitForResponseHeader(2000));
      AssertTrue('stream 3 headers', L2.WaitForResponseHeader(2000));
      AssertEquals('stream 1 status', 200, L1.StatusCode);
      AssertEquals('stream 3 status', 200, L2.StatusCode);
    finally
      I1 := nil;
      I2 := nil;
    end;
  finally
    Alloc.Free;
    Server.Free;
    Conn.Free;
  end;
end;

procedure TScriptedScenarioTest.TestScenarioGoAway;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Server: TScriptedServer;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  Server := TScriptedServer.Create(Sock);
  try
    Conn.Start;
    AssertTrue('connection opens', Conn.WaitForState(csOpen, 2000));
    Server.ScenarioGoAway(5);
    AssertTrue('GOAWAY moves the connection', Conn.WaitForState(csGoAway, 2000));
    AssertFalse('no new streams after GOAWAY', Conn.CanOpenStream);
    AssertEquals('last-stream-id recorded', LongWord(5),
      Conn.GoAwayLastStreamId);
    AssertTrue('a higher stream is retryable', Conn.IsStreamRetryable(7));
    AssertFalse('a lower stream is not retryable', Conn.IsStreamRetryable(3));
  finally
    Server.Free;
    Conn.Free;
  end;
end;

procedure TScriptedScenarioTest.TestScenarioRstStream;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Server: TScriptedServer;
  Alloc: TStreamIdAllocator;
  Lease: TStreamLease;
  IL: IConnectionStream;
  Req: TStreamRequest;
  Buf: array[0..7] of Byte;
  Raised: Boolean;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  Server := TScriptedServer.Create(Sock);
  Alloc := TStreamIdAllocator.Create;
  try
    Conn.Start;
    AssertTrue('connection opens', Conn.WaitForState(csOpen, 2000));
    Server.SendSettings(TConnectionSettings.Defaults);
    Req := TStreamRequest.WithMethod(hmGet, 'api.example:443');
    StartLease(Conn, Alloc, Req, Lease, IL);
    try
      Server.SendHeaders(1, '200', False);
      AssertTrue('headers received before the reset',
        Lease.WaitForResponseHeader(2000));
      Server.ScenarioRstStream(1, ecCancel);
      Raised := False;
      try
        Lease.ReadBody(Buf, SizeOf(Buf));
      except
        on E: EHttpStreamError do Raised := True;
      end;
      AssertTrue('RST surfaces from the body read', Raised);
      AssertTrue('lease records the reset', Lease.RstReceived);
      AssertEquals('wire code recorded', Ord(ecCancel), Ord(Lease.RstCode));
    finally
      IL := nil;
    end;
  finally
    Alloc.Free;
    Server.Free;
    Conn.Free;
  end;
end;

procedure TScriptedScenarioTest.TestScenarioZeroWindowStallsBodyRead;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Server: TScriptedServer;
  Alloc: TStreamIdAllocator;
  Lease: TStreamLease;
  IL: IConnectionStream;
  Req: TStreamRequest;
  Buf: array[0..7] of Byte;
  Raised: Boolean;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  Server := TScriptedServer.Create(Sock);
  Alloc := TStreamIdAllocator.Create;
  try
    Conn.Start;
    AssertTrue('connection opens', Conn.WaitForState(csOpen, 2000));
    Req := TStreamRequest.WithMethod(hmGet, 'api.example:443');
    StartLease(Conn, Alloc, Req, Lease, IL);
    try
      Lease.TimeoutMs := 300;
      // peer grants a zero window, answers headers, and withholds DATA
      Server.ScenarioZeroWindow(1);
      AssertTrue('headers received', Lease.WaitForResponseHeader(2000));
      Raised := False;
      try
        Lease.ReadBody(Buf, SizeOf(Buf));
      except
        on E: EHttpTimeout do Raised := True;
      end;
      AssertTrue('a starved body read times out rather than blocking forever',
        Raised);
    finally
      // the stream was never completed (headers only, no END_STREAM), so it
      // is still registered; release it BEFORE the connection tears down its
      // stream dictionary, or the lease's destructor re-enters a half-freed
      // connection
      Lease.ReleaseLease;
      Sock.UnstallReads;
      IL := nil;
    end;
  finally
    Alloc.Free;
    Server.Free;
    Conn.Free;
  end;
end;

procedure TScriptedScenarioTest.TestScenarioLargeBodyEmitsWindowUpdate;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Server: TScriptedServer;
  Alloc: TStreamIdAllocator;
  Lease: TStreamLease;
  IL: IConnectionStream;
  Req: TStreamRequest;
  Frames: TArray<TFrame>;
  I, N, Ofs: Integer;
  Body: TBytes;
  Conns, Streams: Boolean;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  Server := TScriptedServer.Create(Sock);
  Alloc := TStreamIdAllocator.Create;
  try
    Conn.Start;
    AssertTrue('connection opens', Conn.WaitForState(csOpen, 2000));
    Server.SendSettings(TConnectionSettings.Defaults);
    Req := TStreamRequest.WithMethod(hmGet, 'api.example:443').WithPath('/');
    StartLease(Conn, Alloc, Req, Lease, IL);
    try
      // a body well past cWindowUpdateBatchSize (32768) forces the client to
      // replenish the consumed window; without the wiring the peer would
      // stall and the read would time out (interop A.7). The body is split
      // into frames no larger than the default SETTINGS_MAX_FRAME_SIZE.
      SetLength(Body, 100000);
      FillChar(Body[0], Length(Body), Ord('x'));
      Server.SendHeaders(1, '200', False);
      Ofs := 0;
      while Ofs < Length(Body) do
      begin
        N := Length(Body) - Ofs;
        if N > 16000 then
          N := 16000;
        Sock.EnqueueData(1, Copy(Body, Ofs, N),
          Ofs + N >= Length(Body));
        Inc(Ofs, N);
      end;
      AssertTrue('response headers received',
        Lease.WaitForResponseHeader(2000));
      AssertEquals('status 200', 200, Lease.StatusCode);
      AssertEquals('full body read', 100000,
        Length(ReadAllBodyBytes(Lease.Body)));
      AssertTrue('body complete', Lease.Body.Eof);
      Frames := Sock.OutboundFrames(True);
      Conns := False;
      Streams := False;
      for I := 0 to Length(Frames) - 1 do
        if Frames[I].Header.FrameType = ftWindowUpdate then
        begin
          if Frames[I].Header.StreamId = 0 then
            Conns := True;
          if Frames[I].Header.StreamId = 1 then
            Streams := True;
        end;
      AssertTrue('a connection-level WINDOW_UPDATE was emitted', Conns);
      AssertTrue('a stream-level WINDOW_UPDATE was emitted', Streams);
    finally
      IL := nil;
    end;
  finally
    Alloc.Free;
    Server.Free;
    Conn.Free;
  end;
end;

procedure TScriptedScenarioTest.TestScenarioMalformedFrameClosesConnection;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Server: TScriptedServer;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  Server := TScriptedServer.Create(Sock);
  try
    Conn.Start;
    AssertTrue('connection opens', Conn.WaitForState(csOpen, 2000));
    Server.ScenarioMalformedFrame;
    AssertTrue('the malformed frame closes the connection',
      Conn.WaitForState(csClosed, 2000));
    AssertEquals('a frame-size error was recorded', Ord(ecFrameSizeError),
      Ord(Conn.ErrorCode));
  finally
    Server.Free;
    Conn.Free;
  end;
end;

procedure TScriptedScenarioTest.TestScenarioPushPromiseRejected;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Server: TScriptedServer;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  Server := TScriptedServer.Create(Sock);
  try
    AssertFalse('we advertise ENABLE_PUSH = 0',
      TConnectionSettings.Defaults.EnablePush);
    Conn.Start;
    AssertTrue('connection opens', Conn.WaitForState(csOpen, 2000));
    Server.ScenarioPushPromise(1, 3);
    AssertTrue('the PUSH_PROMISE closes the connection',
      Conn.WaitForState(csClosed, 2000));
    AssertEquals('a protocol error was recorded', Ord(ecProtocolError),
      Ord(Conn.ErrorCode));
  finally
    Server.Free;
    Conn.Free;
  end;
end;

{ TMockSocketFactory }

constructor TMockSocketFactory.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FSockets := TList<TMockSocket>.Create;
  FKeepAlive := TList<IHttp2Socket>.Create;
  FDials := 0;
  FStatus := '200';
  FBody := nil;
  FEndStream := True;
end;

destructor TMockSocketFactory.Destroy;
begin
  // release our owning interface references; the sockets are refcounted and
  // must never be Free'd directly
  FKeepAlive.Clear;
  FKeepAlive.Free;
  FSockets.Free;
  FLock.Free;
  inherited Destroy;
end;

procedure TMockSocketFactory.SetResponse(const AStatus: string;
  const ABody: TBytes; const AEndStream: Boolean);
begin
  FLock.Acquire;
  try
    FStatus := AStatus;
    FBody := ABody;
    FEndStream := AEndStream;
  finally
    FLock.Release;
  end;
end;

function TMockSocketFactory.Dial(const AHost: string; const APort: Word;
  const ATimeoutMs: Integer): IHttp2Socket;
var
  S: TMockSocket;
  St: string;
  Bd: TBytes;
  ES: Boolean;
begin
  S := TMockSocket.Create;
  FLock.Acquire;
  try
    Inc(FDials);
    FSockets.Add(S);
    St := FStatus;
    Bd := FBody;
    ES := FEndStream;
  finally
    FLock.Release;
  end;
  // the mock answers the client preface + SETTINGS and every request HEADERS
  S.AutoRespondToRequestHeaders(St, Bd, ES);
  // a real server's first frame is its own SETTINGS; the client must apply it
  // before it may send DATA, so answer the client preface + SETTINGS exchange
  // here
  S.EnqueueSettings(TConnectionSettings.Defaults);
  Result := S;
  FLock.Acquire;
  try
    FKeepAlive.Add(Result);
  finally
    FLock.Release;
  end;
end;

function TMockSocketFactory.Dials: Integer;
begin
  FLock.Acquire;
  try
    Result := FDials;
  finally
    FLock.Release;
  end;
end;

function TMockSocketFactory.Socket(const AIndex: Integer): TMockSocket;
begin
  FLock.Acquire;
  try
    if (AIndex >= 0) and (AIndex < FSockets.Count) then
      Result := FSockets[AIndex]
    else
      Result := nil;
  finally
    FLock.Release;
  end;
end;

procedure TScriptedScenarioTest.TestScenarioFullSendPathOverMockSocket;
var
  Factory: TMockSocketFactory;      // non-owning view, valid while FactoryRef lives
  FactoryRef: IHttp2SocketFactory;  // owns the factory
  Client: IHttpClient;
  R: IHttpResponse;
  Sock: TMockSocket;
  Frames: TArray<TFrame>;
  SawHeaders, SawGoAway: Boolean;
  I: Integer;
begin
  // the S11 contract: the mock socket drives the FULL public Send path to
  // completion, with no real socket anywhere (IHttp2SocketFactory seam).
  FactoryRef := TMockSocketFactory.Create;
  Factory := FactoryRef as TMockSocketFactory;
  Factory.SetResponse('200', BytesOfString('payload'), True);
  Client := THttpClientFactory.Create
    .WithSocketFactory(FactoryRef)
    .Build;
  R := Client.Send(THttpRequest.Create(hmGet, 'https://api.example/x'));
  AssertEquals('public Send returned the mock status', 200, R.StatusCode);
  AssertEquals('public Send streamed the mock body', 'payload',
    ReadAllBodyText(R.Body));
  AssertEquals('exactly one connection was dialled', 1, Factory.Dials);

  Sock := Factory.Socket(0);
  AssertTrue('the mock captured the client preface',
    Sock.WaitForWrites(2, 3000));
  Frames := Sock.OutboundFrames(True);
  SawHeaders := False;
  for I := 0 to Length(Frames) - 1 do
    if Frames[I].Header.FrameType = ftHeaders then
      SawHeaders := True;
  AssertTrue('the request HEADERS frame was captured on the wire',
    SawHeaders);

  Client.Close;
  Frames := Sock.OutboundFrames(True);
  SawGoAway := False;
  for I := 0 to Length(Frames) - 1 do
    if Frames[I].Header.FrameType = ftGoAway then
      SawGoAway := True;
  AssertTrue('Close sent a GOAWAY on the mock connection', SawGoAway);
  // ownership is entirely by interface; nothing to Free (the factory and its
  // handed-out mock sockets are refcounted)
  R := nil;
  Client := nil;
  FactoryRef := nil;
end;

initialization
  RegisterTest(TObserverEmissionTest);
  RegisterTest(TMockSocketTest);
  RegisterTest(TScriptedScenarioTest);
end.
