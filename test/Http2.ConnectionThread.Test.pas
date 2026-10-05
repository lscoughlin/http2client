/// Unit tests for TConnectionThread and the connection lifecycle
/// (plan story S06 task 06.6/06.7 and story S07 tasks 07.1-07.7)
// - run with `make test`.
// - a recording mock socket proves the sole-writer invariant: only the
//   connection thread ever calls IHttp2Socket.Write; callers only enqueue.
// - synchronisation is bounded and event-driven (RTLEvent), never Sleep.
unit Http2.ConnectionThread.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, SyncObjs, fpcunit, testregistry,
  Http2.Errors, Http2.Frames, Http2.Tls, Http2.Connection;

type
  /// when the read script is exhausted, either surface a timeout (so the
  /// connection thread keeps polling) or end the stream (abrupt failure)
  TReadExhausted = (reTimeout, reEof);

  /// an in-memory IHttp2Socket that records every write and its thread id
  TMockSocket = class(TInterfacedObject, IHttp2Socket)
  private
    FLock: TCriticalSection;
    FWroteEvent: PRTLEvent;
    FDataEvent: PRTLEvent;
    FWritten: TBytes;
    FWriteThreadIds: array of TThreadID;
    FReadData: TBytes;
    FReadPos: Integer;
    FReadLock: TCriticalSection;
    FReadExhausted: TReadExhausted;
    FConnected: Boolean;
    FConnectTimeoutMs, FReadTimeoutMs, FWriteTimeoutMs: Integer;
  public
    constructor Create;
    destructor Destroy; override;
    /// append scripted inbound bytes
    procedure Feed(const ABytes: TBytes); overload;
    procedure FeedFrame(const AFrame: TFrame);
    /// bytes handed to Write so far (a copy)
    function WrittenBytes: TBytes;
    function WriteThreadCount: Integer;
    function WriteThreadId(const AIndex: Integer): TThreadID;
    /// wait until at least ACount write calls have happened
    function WaitForWrites(const ACount, ATimeoutMs: Integer): Boolean;
    property ReadExhausted: TReadExhausted read FReadExhausted write FReadExhausted;
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

  /// worker that performs exactly one blocked Pop on an inbound queue
  TInboundWaiter = class(TThread)
  private
    FQ: IBlockingQueue<TFrame>;
    FDone: PRTLEvent;
    FDoneFlag: Boolean;
    FGot: Boolean;
  protected
    procedure Execute; override;
  public
    constructor Create(const AQ: IBlockingQueue<TFrame>);
    destructor Destroy; override;
    function WaitDone(const ATimeoutMs: Integer): Boolean;
    property Got: Boolean read FGot;
  end;

  TConnectionThreadTest = class(TTestCase)
  published
    // 07.1 client preface + initial SETTINGS
    procedure TestPrefaceBytesAreExact;
    procedure TestPrefaceAndInitialSettingsEmitted;
    // 06.6 sole-writer invariant
    procedure TestOnlyConnectionThreadWrites;
    // 06.5 clean start/stop
    procedure TestCleanStartAndStop;
    // 06.7 error propagation unblocks waiters
    procedure TestErrorPropagationUnblocksWaiters;
    // 07.2 SETTINGS exchange
    procedure TestPeerSettingsAppliedAndAcked;
    // 07.3 PING
    procedure TestIncomingPingIsAcked;
    procedure TestMissingPingAckClosesConnection;
    // 07.4 / 07.7 GOAWAY handling and state
    procedure TestGoAwayStopsNewStreamsAndStaysOpenForDrain;
    procedure TestGoAwayMarksHigherStreamsRetryable;
    // 07.5 graceful shutdown sends GOAWAY
    procedure TestCloseSendsGoAwayWithHighestStream;
  end;

implementation

{ helpers }

function Concat(const A, B: TBytes): TBytes;
var
  N, I: Integer;
begin
  Result := nil;
  N := Length(A);
  SetLength(Result, N + Length(B));
  for I := 0 to N - 1 do
    Result[I] := A[I];
  for I := 0 to High(B) do
    Result[N + I] := B[I];
end;

function FrameBytes(const AFrame: TFrame): TBytes;
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

{ TMockSocket }

constructor TMockSocket.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FReadLock := TCriticalSection.Create;
  FWroteEvent := RTLEventCreate;
  FDataEvent := RTLEventCreate;
  FConnected := True;
  FConnectTimeoutMs := 1000;
  FReadTimeoutMs := 1000;
  FWriteTimeoutMs := 1000;
  FReadPos := 0;
  FReadExhausted := reTimeout;
end;

destructor TMockSocket.Destroy;
begin
  RTLEventDestroy(FWroteEvent);
  RTLEventDestroy(FDataEvent);
  FReadLock.Free;
  FLock.Free;
  inherited Destroy;
end;

procedure TMockSocket.Feed(const ABytes: TBytes);
begin
  FReadLock.Acquire;
  try
    FReadData := Concat(FReadData, ABytes);
  finally
    FReadLock.Release;
  end;
  RTLEventSetEvent(FDataEvent);
end;

procedure TMockSocket.FeedFrame(const AFrame: TFrame);
begin
  Feed(FrameBytes(AFrame));
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

function TMockSocket.WriteThreadCount: Integer;
begin
  FLock.Acquire;
  try
    Result := Length(FWriteThreadIds);
  finally
    FLock.Release;
  end;
end;

function TMockSocket.WriteThreadId(const AIndex: Integer): TThreadID;
begin
  FLock.Acquire;
  try
    Result := FWriteThreadIds[AIndex];
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
  while WriteThreadCount < ACount do
  begin
    if GetTickCount64 >= Deadline then
      Exit(False);
    Remaining := Integer(Deadline - GetTickCount64);
    RTLEventWaitFor(FWroteEvent, Remaining);
  end;
  Result := True;
end;

function TMockSocket.Read(var ABuffer; ACount: Integer): Integer;
var
  Avail, N: Integer;
  P: PByte;
begin
  if not FConnected then
    raise EHttpConnectionClosed.Create('mock socket closed');
  FReadLock.Acquire;
  try
    Avail := Length(FReadData) - FReadPos;
    if Avail <= 0 then
    begin
      if FReadExhausted = reEof then
        Exit(0);                       // abrupt end of stream
      raise EHttpTimeout.Create('mock read idle');   // idle poll
    end;
    N := ACount;
    if N > Avail then
      N := Avail;
    P := @ABuffer;
    Move(FReadData[FReadPos], P^, N);
    Inc(FReadPos, N);
    Result := N;
  finally
    FReadLock.Release;
  end;
end;

function TMockSocket.Write(const ABuffer; ACount: Integer): Integer;
var
  P: PByte;
begin
  if not FConnected then
    raise EHttpConnectionClosed.Create('mock socket closed');
  FLock.Acquire;
  try
    P := @ABuffer;
    SetLength(FWritten, Length(FWritten) + ACount);
    if ACount > 0 then
      Move(P^, FWritten[Length(FWritten) - ACount], ACount);
    SetLength(FWriteThreadIds, Length(FWriteThreadIds) + 1);
    FWriteThreadIds[High(FWriteThreadIds)] := GetCurrentThreadId;
  finally
    FLock.Release;
  end;
  RTLEventSetEvent(FWroteEvent);
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

{ TInboundWaiter }

constructor TInboundWaiter.Create(const AQ: IBlockingQueue<TFrame>);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FQ := AQ;
  FDone := RTLEventCreate;
end;

destructor TInboundWaiter.Destroy;
begin
  RTLEventDestroy(FDone);
  inherited Destroy;
end;

procedure TInboundWaiter.Execute;
var
  F: TFrame;
begin
  FGot := FQ.Pop(F);
  FDoneFlag := True;
  RTLEventSetEvent(FDone);
end;

function TInboundWaiter.WaitDone(const ATimeoutMs: Integer): Boolean;
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

{ tests }

procedure TConnectionThreadTest.TestPrefaceBytesAreExact;
const
  Expected: array[0..23] of AnsiChar =
    'PRI * HTTP/2.0'#13#10#13#10'SM'#13#10#13#10;
var
  B: TBytes;
  I: Integer;
begin
  B := ClientPrefaceBytes;
  AssertEquals('preface is 24 bytes', 24, Length(B));
  for I := 0 to 23 do
    AssertEquals('preface byte ' + IntToStr(I), Ord(Expected[I]), B[I]);
end;

procedure TConnectionThreadTest.TestPrefaceAndInitialSettingsEmitted;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Written: TBytes;
  Hdr: TFrameHeader;
  HdrBuf: TBytes;
  I: Integer;
  Settings: TConnectionSettings;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Conn.Start;
    AssertTrue('preface + settings frame written',
      Sock.WaitForWrites(2, 2000));
    AssertTrue('connection reaches open', Conn.WaitForState(csOpen, 2000));
    Written := Sock.WrittenBytes;
    // 24-byte preface followed by a SETTINGS frame
    for I := 0 to 23 do
      AssertEquals('preface byte ' + IntToStr(I),
        ClientPrefaceBytes[I], Written[I]);
    SetLength(HdrBuf, FrameHeaderSize);
    for I := 0 to FrameHeaderSize - 1 do
      HdrBuf[I] := Written[24 + I];
    Hdr := TFrameHeader.ReadFrom(HdrBuf);
    AssertEquals('initial frame is SETTINGS', Ord(ftSettings), Ord(Hdr.FrameType));
    AssertEquals('SETTINGS uses stream 0', 0, Hdr.StreamId);
    Settings := TConnectionSettings.Defaults;
    AssertEquals('SETTINGS carries the six settings',
      Length(Settings.Encode), Hdr.Length);
  finally
    Conn.Free;
  end;
end;

procedure TConnectionThreadTest.TestOnlyConnectionThreadWrites;
var
  Sock: TMockSocket;
  Conn: TConnection;
  I: Integer;
  WorkerId: TThreadID;
  AllFromWorker: Boolean;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Conn.Start;
    AssertTrue('preface written', Sock.WaitForWrites(2, 2000));
    WorkerId := Conn.Thread.ThreadID;
    // a caller only enqueues; it must never touch the socket
    for I := 0 to 9 do
      AssertTrue('frame enqueued', Conn.PostFrame(
        BuildPingFrame(nil, False)));
    AssertTrue('all queued frames written', Sock.WaitForWrites(23, 2000));
    AllFromWorker := True;
    for I := 0 to Sock.WriteThreadCount - 1 do
      if Sock.WriteThreadId(I) <> WorkerId then
        AllFromWorker := False;
    AssertTrue('every Write happened on the connection thread', AllFromWorker);
    AssertTrue('the test thread never wrote',
      Sock.WriteThreadId(0) <> GetCurrentThreadId);
  finally
    Conn.Free;
  end;
end;

procedure TConnectionThreadTest.TestCleanStartAndStop;
var
  Sock: TMockSocket;
  Conn: TConnection;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Conn.Start;
    AssertTrue('connection opens', Conn.WaitForState(csOpen, 2000));
    Conn.Close;
    AssertEquals('connection is closed', Ord(csClosed), Ord(Conn.State));
    AssertFalse('socket is closed', Sock.GetConnected);
    AssertTrue('thread reference released', Conn.Thread = nil);
  finally
    Conn.Free;
  end;
end;

procedure TConnectionThreadTest.TestErrorPropagationUnblocksWaiters;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Waiter: TInboundWaiter;
  EmptyFrame: TFrame;
  Raised: Boolean;
begin
  Sock := TMockSocket.Create;
  Sock.ReadExhausted := reEof;      // the peer closes the transport at once
  Conn := TConnection.Create(Sock);
  Waiter := TInboundWaiter.Create(Conn.Inbound);
  try
    Conn.Start;
    Waiter.Start;
    // the inbound waiter must be released with False when the thread fails
    AssertTrue('blocked waiter is released', Waiter.WaitDone(2000));
    AssertFalse('released waiter got False', Waiter.Got);
    AssertEquals('connection moved to closed', Ord(csClosed), Ord(Conn.State));
    AssertTrue('an error message was recorded', Conn.ErrorMessage <> '');
    // a Pop on the failed inbound queue returns False, not a block
    AssertFalse('inbound Pop after failure returns False',
      Conn.Inbound.Pop(EmptyFrame));
    Raised := False;
    try
      Conn.PostFrame(BuildPingFrame(nil, False));
    except
      Raised := True;
    end;
    AssertFalse('PostFrame does not raise on a failed connection', Raised);
  finally
    Waiter.Free;
    Conn.Free;
  end;
end;

procedure TConnectionThreadTest.TestPeerSettingsAppliedAndAcked;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Peer: TConnectionSettings;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Conn.Start;
    AssertTrue('preface emitted', Sock.WaitForWrites(2, 2000));
    Peer := TConnectionSettings.Defaults;
    Peer.MaxConcurrentStreams := 7;
    Peer.MaxFrameSize := 32768;
    Sock.FeedFrame(BuildSettingsFrame(Peer));
    // thread applies peer settings then writes a SETTINGS ACK; once the ACK
    // is observed the applied settings are visible
    AssertTrue('ACK written', Sock.WaitForWrites(4, 2000));
    AssertEquals('peer max concurrent streams applied', LongWord(7),
      Conn.PeerSettings.MaxConcurrentStreams);
    AssertEquals('peer max frame size applied', LongWord(32768),
      Conn.PeerSettings.MaxFrameSize);
  finally
    Conn.Free;
  end;
end;

procedure TConnectionThreadTest.TestIncomingPingIsAcked;
var
  Sock: TMockSocket;
  Conn: TConnection;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Conn.Start;
    AssertTrue('preface emitted', Sock.WaitForWrites(2, 2000));
    Sock.FeedFrame(BuildPingFrame(nil, False));
    AssertTrue('ping ack written', Sock.WaitForWrites(5, 2000));
  finally
    Conn.Free;
  end;
end;

procedure TConnectionThreadTest.TestMissingPingAckClosesConnection;
var
  Sock: TMockSocket;
  Conn: TConnection;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Conn.PingIntervalMs := 30;
    Conn.PingTimeoutMs := 60;
    Conn.Start;
    AssertTrue('preface emitted', Sock.WaitForWrites(2, 2000));
    // no PING ACK is ever fed back; the keep-alive must give up
    AssertTrue('connection closes on a missing PING ack',
      Conn.WaitForState(csClosed, 3000));
  finally
    Conn.Free;
  end;
end;

procedure TConnectionThreadTest.TestGoAwayStopsNewStreamsAndStaysOpenForDrain;
var
  Sock: TMockSocket;
  Conn: TConnection;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Conn.Start;
    AssertTrue('preface emitted', Sock.WaitForWrites(2, 2000));
    Sock.FeedFrame(BuildGoAwayFrame(5, ecNoError, nil));
    AssertTrue('goaway observed', Conn.WaitForState(csGoAway, 2000));
    AssertFalse('new streams are refused after GOAWAY', Conn.CanOpenStream);
    AssertEquals('last-stream-id recorded', LongWord(5),
      Conn.GoAwayLastStreamId);
    // in-flight work still drains: a queued frame is written after GOAWAY
    AssertTrue('post-GOAWAY frame enqueued',
      Conn.PostFrame(BuildDataFrame(1, nil, True)));
    AssertTrue('in-flight frame still written', Sock.WaitForWrites(4, 2000));
  finally
    Conn.Free;
  end;
end;

procedure TConnectionThreadTest.TestGoAwayMarksHigherStreamsRetryable;
var
  Sock: TMockSocket;
  Conn: TConnection;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Conn.Start;
    AssertTrue('preface emitted', Sock.WaitForWrites(2, 2000));
    Sock.FeedFrame(BuildGoAwayFrame(5, ecNoError, nil));
    AssertTrue('goaway observed', Conn.WaitForState(csGoAway, 2000));
    AssertFalse('stream at the last id must not be retried',
      Conn.IsStreamRetryable(5));
    AssertFalse('stream below the last id must not be retried',
      Conn.IsStreamRetryable(3));
    AssertTrue('stream above the last id MAY be retried',
      Conn.IsStreamRetryable(7));
  finally
    Conn.Free;
  end;
end;

procedure TConnectionThreadTest.TestCloseSendsGoAwayWithHighestStream;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Written: TBytes;
  Hdr: TFrameHeader;
  Ofs: Integer;
  FoundGoAway: Boolean;
  Id: LongWord;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Conn.Start;
    AssertTrue('preface emitted', Sock.WaitForWrites(2, 2000));
    Conn.HighestStreamId := 9;
    Conn.Close;
    Written := Sock.WrittenBytes;
    // walk the frames; preface is 24 bytes, then SETTINGS (36) then GOAWAY
    FoundGoAway := False;
    Ofs := 24;
    while Ofs + FrameHeaderSize <= Length(Written) do
    begin
      Hdr := TFrameHeader.ReadFrom(Copy(Written, Ofs, FrameHeaderSize));
      if Hdr.FrameType = ftGoAway then
      begin
        FoundGoAway := True;
        Id := (LongWord(Written[Ofs + 9]) shl 24) or
              (LongWord(Written[Ofs + 10]) shl 16) or
              (LongWord(Written[Ofs + 11]) shl 8) or
               LongWord(Written[Ofs + 12]);
        AssertEquals('GOAWAY last-stream-id is the highest processed',
          LongWord(9), Id and MaxStreamId);
        Break;
      end;
      Inc(Ofs, FrameHeaderSize + Integer(Hdr.Length));
    end;
    AssertTrue('graceful Close sent a GOAWAY frame', FoundGoAway);
  finally
    Conn.Free;
  end;
end;

initialization
  RegisterTest(TConnectionThreadTest);
end.
