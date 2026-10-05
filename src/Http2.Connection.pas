/// Connection, blocking queue, and connection thread (plan S06/S07)
// - this unit is part of the http2client project (see doc/design/transport.md,
//   sections "Threading and queues" and "Connection lifecycle").
// - FPC 3.2.4 has no TThreadedQueue<T> and no TMonitor; TEvent/TSimpleEvent
//   raise ESyncObjectException on macOS. The bounded queue is therefore built
//   from TQueue<T> + TCriticalSection + two RTLEvents (see probe12.pas).
// - one TConnectionThread owns BOTH directions of one socket: callers only
//   enqueue frames onto the outbound queue, the thread is the sole writer.
unit Http2.Connection;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, SyncObjs, Generics.Collections,
  Http2.Errors, Http2.Frames, Http2.Tls, Http2.Observer, Http2.FlowControl;

const
  /// connection-level receive window we advertise (RFC 7540 section 6.9.2)
  cDefaultConnectionWindowSize = 65535;
  /// per-stream receive window we advertise
  cDefaultStreamWindowSize = 65535;
  /// emit a WINDOW_UPDATE once this many bytes have accrued (half the window)
  cWindowUpdateBatchSize = 32768;
  /// default bound on either frame queue (backpressure instead of growth)
  cDefaultQueueCapacity = 128;
  /// how long a socket read blocks before the thread re-checks outbound work
  cDefaultReadPollMs = 20;

type
  /// an ARC-safe, bounded, blocking queue of T
  // - Shutdown releases every blocked waiter; a later Pop returns False
  IBlockingQueue<T> = interface
    procedure Push(const AItem: T);
    /// block until an item is available or the queue is shut down + empty
    function Pop(out AItem: T): Boolean;
    /// return an item only if one is already available (never blocks)
    function TryPop(out AItem: T): Boolean;
    /// wake every blocked waiter; pending and future operations fail fast
    procedure Shutdown;
  end;

  /// TQueue<T> + TCriticalSection + two RTLEvents (TThreadedQueue is absent
  /// in FPC 3.2.4). A capacity <= 0 means unbounded.
  TBlockingQueue<T> = class(TInterfacedObject, IBlockingQueue<T>)
  private
    FLock: TCriticalSection;
    FNotEmpty: PRTLEvent;
    FNotFull: PRTLEvent;
    FItems: TQueue<T>;
    FCapacity: Integer;
    FShutdown: Boolean;
    FWaitersParked: Integer;
  public
    constructor Create(const ACapacity: Integer = cDefaultQueueCapacity);
    destructor Destroy; override;
    procedure Push(const AItem: T);
    function Pop(out AItem: T): Boolean;
    function TryPop(out AItem: T): Boolean;
    procedure Shutdown;
    /// items currently buffered (introspection for tests)
    function Count: Integer;
    /// number of consumers currently blocked inside Pop (test seam)
    function WaitersParked: Integer;
    /// bounded, event-driven wait until at least one item is available;
    /// returns False on shutdown or when the deadline expires
    function WaitForItem(const ATimeoutMs: Integer): Boolean;
    function IsShutdown: Boolean;
  end;

  TConnection = class;

  /// the lifecycle state exposed for connection-pool eligibility
  TConnectionState = (csOpening, csOpen, csGoAway, csClosed);

  /// one background thread per connection; it is the sole writer to the
  /// socket. It holds ONLY a weak (raw Pointer) reference to TConnection so
  /// the TConnection <-> thread pair cannot form an ARC cycle.
  TConnectionThread = class(TThread)
  private
    FConn: Pointer;                    // weak ref to TConnection, never AddRef'd
    FOutbound: IBlockingQueue<TFrame>;
    FInbound: IBlockingQueue<TFrame>;
    FSocket: IHttp2Socket;
    FSockStream: TStream;              // IHttp2Socket -> TStream adapter
    FLocalSettings: TConnectionSettings;
    FReadPollMs: Integer;
    FPeerMaxFrameSize: LongWord;
    FPendingPing: Boolean;
    FPendingPingPayload: TBytes;
    FPingSentAt: QWord;
  protected
    procedure Execute; override;
    procedure DoPreface;
    procedure ApplyPeerSettings(const ASettings: TConnectionSettings);
    procedure RouteInbound(const AFrame: TFrame);
    procedure DrainOutbound;
    /// write one frame and emit the observer's frame-out event for it
    procedure WriteTracked(const AFrame: TFrame);
    procedure CheckPingKeepAlive;
    procedure HandlePingAck(const APayload: TBytes);
    procedure Fail(const AMessage: string; const ACode: THttp2ErrorCode);
  public
    constructor Create(AConn: TConnection);
  end;

  /// the seam S08's stream lease registers with, so a dying connection can
  /// terminate every in-flight stream exactly once
  IConnectionStream = interface
    /// the connection failed: terminate any pending read/write with this error
    procedure OnConnectionFailed(const AMessage: string;
      const ACode: THttp2ErrorCode);
    /// the peer sent GOAWAY: streams above ALastStreamId are retryable
    procedure OnConnectionGoAway(const ALastStreamId: LongWord);
    /// a frame addressed to this stream arrived from the peer
    procedure OnStreamFrame(const AFrame: TFrame);
  end;

  /// the minimal connection object S06/S07 need: state, the two frame queues,
  /// the socket, and the thread. S08 extends it with stream leases.
  TConnection = class
  private
    FLock: TCriticalSection;

    FStreams: TDictionary<LongWord, IConnectionStream>;
    FStateEvent: PRTLEvent;
    FSocket: IHttp2Socket;
    FOutbound: IBlockingQueue<TFrame>;
    FInbound: IBlockingQueue<TFrame>;
    FThread: TConnectionThread;
    FState: TConnectionState;
    FLocalSettings: TConnectionSettings;
    FPeerSettings: TConnectionSettings;
    FSettingsAcked: Boolean;
    FGoAwayLastStreamId: LongWord;
    FHighestStreamId: LongWord;
    FError: string;
    FErrorCode: THttp2ErrorCode;
    FClosed: Boolean;
    FReadPollMs: Integer;
    FPingIntervalMs: Integer;
    FPingTimeoutMs: Integer;
    FLastActivity: QWord;
    FObserver: IHttp2Observer;
    FCloseObserved: Boolean;
    FFlowControl: TFlowControl;
    /// per-stream bytes received since the last stream WINDOW_UPDATE
    FPendingStreamCredit: TDictionary<LongWord, LongWord>;
    /// connection bytes received since the last connection WINDOW_UPDATE
    FPendingConnCredit: LongWord;
    function GetState: TConnectionState;
    function GetPeerSettings: TConnectionSettings;
    procedure SetState(const AValue: TConnectionState);
    function GetObserver: IHttp2Observer;
    procedure SetObserver(const AValue: IHttp2Observer);
    // observer fan-out helpers: each snapshots the observer reference under
    // FLock, then invokes the callback OUTSIDE the lock (it may re-enter) and
    // inside a try/except (a raising observer must not break the loop)
    procedure EmitConnectionOpen;
    procedure EmitConnectionClose(const AMessage: string;
      const ACode: THttp2ErrorCode);
    procedure EmitGoAway(const ALastStreamId: LongWord;
      const ACode: THttp2ErrorCode);
    procedure EmitStreamOpen(const AStreamId: LongWord);
    procedure EmitStreamClose(const AStreamId: LongWord);
    procedure EmitFrameIn(const AFrame: TFrame);
    procedure EmitFrameOut(const AFrame: TFrame);
    procedure EmitWindowUpdate(const AStreamId, AIncrement: LongWord);
    procedure EmitRetry(const AStreamId: LongWord);
    procedure EmitDiscarded(const AFrame: TFrame; const AReason: string);
    /// account for received DATA and return window credit to the peer when
    /// enough has accrued (RFC 7540 section 6.9). Called for every inbound
    /// DATA frame, stream-scoped or not.
    procedure TrackReceivedData(const AStreamId: LongWord;
      const ALength: LongWord);
    /// emit any still-pending WINDOW_UPDATEs (e.g. when a stream ends)
    procedure FlushStreamCredit(const AStreamId: LongWord);
  public
    constructor Create(const ASocket: IHttp2Socket); overload;
    constructor Create(const ASocket: IHttp2Socket;
      const ALocalSettings: TConnectionSettings); overload;
    destructor Destroy; override;
    /// spawn the connection thread (sends preface + initial SETTINGS)
    procedure Start;
    /// graceful, idempotent shutdown: sends GOAWAY (highest processed
    /// stream), Terminate+WaitFor the thread, then closes the socket
    procedure Close;
    /// enqueue a frame for the thread to write; False once closed
    function PostFrame(const AFrame: TFrame): Boolean;
    /// connection + per-stream flow-control state (plan S04/S10 seam)
    property FlowControl: TFlowControl read FFlowControl;
    /// emit a WINDOW_UPDATE for AStreamId now, returning any pending credit
    procedure SendWindowUpdate(const AStreamId: LongWord);
    /// may a new stream still be opened on this connection?
    function CanOpenStream: Boolean;
    /// RFC 7540 section 6.8: after GOAWAY, a stream with an id strictly above
    /// last-stream-id was never processed and MAY be safely retried
    function IsStreamRetryable(const AStreamId: LongWord): Boolean;
    /// bounded, event-driven wait for a lifecycle state (test/pool seam)
    function WaitForState(const AState: TConnectionState;
      const ATimeoutMs: Integer): Boolean;
    /// record a peer GOAWAY; stops new streams, marks higher ids retryable
    procedure MarkGoAway(const ALastStreamId: LongWord);
    /// move to a failed state and unblock every waiter (thread-internal seam)
    procedure FailWith(const AMessage: string; const ACode: THttp2ErrorCode);
    /// record peer SETTINGS under the connection lock (thread-internal seam)
    procedure ApplyPeerSettingsValue(const ASettings: TConnectionSettings);
    /// record the peer's SETTINGS ACK (thread-internal seam)
    procedure MarkSettingsAcked;
    /// update the idle clock used by the PING keep-alive schedule
    procedure TouchActivity;
    /// register a stream lease for connection-failure fan-out
    procedure RegisterStream(const AStreamId: LongWord;
      const AStream: IConnectionStream);
    /// remove a stream lease (idempotent); call exactly once per stream
    procedure UnregisterStream(const AStreamId: LongWord);
    /// number of in-flight stream leases (test seam)
    function StreamCount: Integer;
    /// hand a stream-scoped frame to its lease; False when nobody owns it
    /// (the frame is then left on the shared inbound queue)
    function DispatchStreamFrame(const AFrame: TFrame): Boolean;

    property State: TConnectionState read GetState;
    property PeerSettings: TConnectionSettings read GetPeerSettings;
    property Thread: TConnectionThread read FThread;
    property Outbound: IBlockingQueue<TFrame> read FOutbound;
    property Inbound: IBlockingQueue<TFrame> read FInbound;
    property Socket: IHttp2Socket read FSocket;
    property SettingsAcked: Boolean read FSettingsAcked;
    property GoAwayLastStreamId: LongWord read FGoAwayLastStreamId;
    property HighestStreamId: LongWord read FHighestStreamId
      write FHighestStreamId;
    property ErrorMessage: string read FError;
    property ErrorCode: THttp2ErrorCode read FErrorCode;
    property ReadPollMs: Integer read FReadPollMs write FReadPollMs;
    property PingIntervalMs: Integer read FPingIntervalMs write FPingIntervalMs;
    property PingTimeoutMs: Integer read FPingTimeoutMs write FPingTimeoutMs;
    /// optional observability sink; nil (the default) means no overhead
    property Observer: IHttp2Observer read GetObserver write SetObserver;
  end;

/// the 24-byte client connection preface (RFC 7540 section 3.5)
function ClientPrefaceBytes: TBytes;

implementation

const
  cClientPreface: array[0..23] of Byte = (
    $50, $52, $49, $20, $2A, $20, $48, $54, $54, $50, $2F, $32, $2E, $30,
    $0D, $0A, $0D, $0A, $53, $4D, $0D, $0A, $0D, $0A);

function ClientPrefaceBytes: TBytes;
var
  I: Integer;
begin
  Result := nil;
  SetLength(Result, SizeOf(cClientPreface));
  for I := 0 to High(cClientPreface) do
    Result[I] := cClientPreface[I];
end;

{ TSocketStream: adapts an IHttp2Socket to the TStream ReadFrame/WriteFrame
  API. A read timeout with no bytes yet is re-raised so the thread can poll
  outbound work; once a frame has started arriving the read blocks through to
  completion so no partial frame is ever abandoned. }

type
  TSocketStream = class(TStream)
  private
    FSocket: IHttp2Socket;
  public
    constructor Create(const ASocket: IHttp2Socket);
    function Read(var ABuffer; ACount: LongInt): LongInt; override;
    function Write(const ABuffer; ACount: LongInt): LongInt; override;
    function Seek(const AOffset: Int64; AOrigin: TSeekOrigin): Int64;
      override;
  end;

constructor TSocketStream.Create(const ASocket: IHttp2Socket);
begin
  inherited Create;
  FSocket := ASocket;
end;

function TSocketStream.Read(var ABuffer; ACount: LongInt): LongInt;
var
  Got, N: LongInt;
  P: PByte;
begin
  if ACount <= 0 then
    Exit(0);
  Result := 0;
  P := @ABuffer;
  Got := 0;
  while Got < ACount do
  begin
    try
      N := FSocket.Read(P[Got], ACount - Got);
    except
      on E: EHttpTimeout do
        if Got = 0 then
          raise                 // idle poll: no bytes yet, surface the timeout
        else
          Break;                // partial frame; caller re-invokes Read
    end;
    if N <= 0 then
    begin
      if Got = 0 then
        Exit(0);              // end of stream, nothing buffered
      Break;                  // partial read; caller re-invokes Read
    end;
    Inc(Got, N);
  end;
  Result := Got;
end;

function TSocketStream.Write(const ABuffer; ACount: LongInt): LongInt;
begin
  Result := FSocket.Write(ABuffer, ACount);
end;

function TSocketStream.Seek(const AOffset: Int64;
  AOrigin: TSeekOrigin): Int64;
begin
  Result := 0;
  raise EStreamError.Create('TSocketStream is not seekable');
end;

{ TBlockingQueue<T> }

constructor TBlockingQueue<T>.Create(const ACapacity: Integer);
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FNotEmpty := RTLEventCreate;
  FNotFull := RTLEventCreate;
  FItems := TQueue<T>.Create;
  FCapacity := ACapacity;
  FShutdown := False;
end;

destructor TBlockingQueue<T>.Destroy;
begin
  FItems.Free;
  RTLEventDestroy(FNotEmpty);
  RTLEventDestroy(FNotFull);
  FLock.Free;
  inherited Destroy;
end;

procedure TBlockingQueue<T>.Push(const AItem: T);
var
  WokenByShutdown: Boolean;
begin
  WokenByShutdown := False;
  FLock.Acquire;
  try
    while (not FShutdown) and (FCapacity > 0) and (FItems.Count >= FCapacity) do
    begin
      FLock.Release;
      try
        RTLEventWaitFor(FNotFull);
      finally
        FLock.Acquire;
      end;
    end;
    if not FShutdown then
      FItems.Enqueue(AItem)
    else
      WokenByShutdown := True;
  finally
    FLock.Release;
  end;
  // chain-wake the next blocked producer on the SAME event, then a consumer
  if WokenByShutdown then
    RTLEventSetEvent(FNotFull);
  RTLEventSetEvent(FNotEmpty);
end;

function TBlockingQueue<T>.Pop(out AItem: T): Boolean;
var
  WokenByShutdown: Boolean;
begin
  Result := False;
  WokenByShutdown := False;
  FLock.Acquire;
  try
    while (not FShutdown) and (FItems.Count = 0) do
    begin
      Inc(FWaitersParked);
      FLock.Release;
      try
        RTLEventWaitFor(FNotEmpty);
      finally
        FLock.Acquire;
        Dec(FWaitersParked);
      end;
    end;
    if FItems.Count > 0 then
    begin
      AItem := FItems.Dequeue;
      Result := True;
    end
    else if FShutdown then
      WokenByShutdown := True;
  finally
    FLock.Release;
  end;
  // chain-wake the next blocked consumer on the SAME event, then release a
  // producer slot. Signalling FNotFull here would leave sibling consumers
  // waiting on FNotEmpty blocked forever after Shutdown.
  if WokenByShutdown then
    RTLEventSetEvent(FNotEmpty);
  RTLEventSetEvent(FNotFull);
end;

function TBlockingQueue<T>.TryPop(out AItem: T): Boolean;
begin
  FLock.Acquire;
  try
    Result := FItems.Count > 0;
    if Result then
      AItem := FItems.Dequeue;
  finally
    FLock.Release;
  end;
  if Result then
    RTLEventSetEvent(FNotFull);
end;

procedure TBlockingQueue<T>.Shutdown;
begin
  FLock.Acquire;
  try
    FShutdown := True;
  finally
    FLock.Release;
  end;
  // RTLEvent wakes one waiter at a time; each released waiter re-signals
  // the SAME event in its Pop/Push epilogue, so the full set unblocks.
  RTLEventSetEvent(FNotEmpty);
  RTLEventSetEvent(FNotFull);
end;

function TBlockingQueue<T>.Count: Integer;
begin
  FLock.Acquire;
  try
    Result := FItems.Count;
  finally
    FLock.Release;
  end;
end;

function TBlockingQueue<T>.WaitersParked: Integer;
begin
  FLock.Acquire;
  try
    Result := FWaitersParked;
  finally
    FLock.Release;
  end;
end;

function TBlockingQueue<T>.WaitForItem(const ATimeoutMs: Integer): Boolean;
var
  Deadline: QWord;
  Remaining: Integer;
begin
  Deadline := GetTickCount64 + QWord(ATimeoutMs);
  while True do
  begin
    FLock.Acquire;
    try
      if FItems.Count > 0 then
        Exit(True);
      if FShutdown then
        Exit(False);
    finally
      FLock.Release;
    end;
    if GetTickCount64 >= Deadline then
      Exit(False);
    Remaining := Integer(Deadline - GetTickCount64);
    RTLEventWaitFor(FNotEmpty, Remaining);
  end;
end;

function TBlockingQueue<T>.IsShutdown: Boolean;
begin
  FLock.Acquire;
  try
    Result := FShutdown;
  finally
    FLock.Release;
  end;
end;

{ TConnectionThread }

constructor TConnectionThread.Create(AConn: TConnection);
begin
  inherited Create(True);           // start suspended; caller calls Start
  FreeOnTerminate := False;
  FConn := AConn;                   // weak reference: no AddRef
  FSocket := AConn.FSocket;
  FOutbound := AConn.FOutbound;
  FInbound := AConn.FInbound;
  FLocalSettings := AConn.FLocalSettings;
  FReadPollMs := AConn.FReadPollMs;
  FPeerMaxFrameSize := DefaultMaxFrameSize;
  FPendingPing := False;
  FSockStream := TSocketStream.Create(FSocket);
end;

procedure TConnectionThread.Execute;
var
  Frame: TFrame;
begin
  try
    DoPreface;
    TConnection(FConn).SetState(csOpen);
    TConnection(FConn).EmitConnectionOpen;
    while not Terminated do
    begin
      DrainOutbound;
      if Terminated then
        Break;
      CheckPingKeepAlive;
      if Terminated then
        Break;
      try
        Frame := ReadFrame(FSockStream, FPeerMaxFrameSize);
        // RFC 7540 structural rules the decoder cannot enforce on its own:
        // frame-type/stream-id pairing, mandatory payload sizes, zero
        // WINDOW_UPDATE increments. A violation is a connection error.
        ValidateFrame(Frame, FPeerMaxFrameSize);
        // routing can also raise EHttpError (malformed SETTINGS/GOAWAY,
        // PUSH_PROMISE while push is disabled); keep it inside this handler
        // so the frame's own error code is reported rather than being
        // downgraded to ecInternalError by the outer catch-all.
        RouteInbound(Frame);
      except
        on E: EHttpTimeout do
          Continue;                 // idle poll: loop back to outbound work
        on E: EHttpError do
        begin
          Fail(E.Message, E.ErrorCode);
          Break;
        end;
      end;
    end;
    DrainOutbound;                  // flush anything pending after Terminate
  except
    on E: Exception do
      Fail(E.ClassName + ': ' + E.Message, ecInternalError);
  end;
end;

procedure TConnectionThread.DoPreface;
begin
  FSocket.ReadTimeoutMs := FReadPollMs;
  FSocket.Write(cClientPreface, SizeOf(cClientPreface));
  WriteTracked(BuildSettingsFrame(FLocalSettings));
end;

procedure TConnectionThread.WriteTracked(const AFrame: TFrame);
begin
  WriteFrame(FSockStream, AFrame);
  TConnection(FConn).EmitFrameOut(AFrame);
end;

procedure TConnectionThread.ApplyPeerSettings(
  const ASettings: TConnectionSettings);
begin
  TConnection(FConn).ApplyPeerSettingsValue(ASettings);
  FPeerMaxFrameSize := ASettings.MaxFrameSize;
end;

procedure TConnectionThread.RouteInbound(const AFrame: TFrame);
var
  LastStreamId: LongWord;
  Code: THttp2ErrorCode;
  Debug: TBytes;
  Increment: LongWord;
begin
  TConnection(FConn).EmitFrameIn(AFrame);
  case AFrame.Header.FrameType of
    ftSettings:
      if AFrame.IsAck then
        TConnection(FConn).MarkSettingsAcked
      else
      begin
        ApplyPeerSettings(TConnectionSettings.Decode(AFrame.Payload));
        WriteTracked(BuildSettingsAck);
      end;
    ftPing:
      if AFrame.IsAck then
        HandlePingAck(AFrame.Payload)
      else
        WriteTracked(BuildPingFrame(AFrame.Payload, True));
    ftGoAway:
      begin
        ParseGoAway(AFrame, LastStreamId, Code, Debug);
        TConnection(FConn).MarkGoAway(LastStreamId);
      end;
    ftPushPromise:
      // We advertise SETTINGS_ENABLE_PUSH = 0 (see TConnectionSettings.Defaults),
      // so a PUSH_PROMISE is a connection error (RFC 9113 section 6.6). Fail
      // loudly instead of silently discarding the frame — otherwise the
      // request simply hangs until the header timeout.
      raise EHttpProtocolError.Create(
        'peer sent PUSH_PROMISE although push is disabled',
        ecProtocolError);
  else
  begin
    // purely additive observability: report flow-control updates and frames
    // the switch above ignores, then keep the original routing unchanged
    if AFrame.Header.FrameType = ftWindowUpdate then
    begin
      try
        Increment := ParseWindowUpdate(AFrame);
        TConnection(FConn).EmitWindowUpdate(AFrame.Header.StreamId, Increment);
      except
        // a malformed WINDOW_UPDATE is left to the normal error path
      end;
    end;
    if not IsKnownFrameType(AFrame.Header.FrameType) then
      TConnection(FConn).EmitDiscarded(AFrame,
        'unknown frame type ' + FrameTypeName(AFrame.Header.FrameType))
    else if AFrame.Header.StreamId = 0 then
      TConnection(FConn).EmitDiscarded(AFrame,
        FrameTypeName(AFrame.Header.FrameType) + ' arrived on stream 0');
    // account for received DATA and return window credit to the peer; this
    // must happen for connection-level DATA (stream 0) as well as the
    // stream-scoped case, else a large response stalls on the peer's window
    if AFrame.Header.FrameType = ftData then
      TConnection(FConn).TrackReceivedData(AFrame.Header.StreamId,
        AFrame.DataLength);
    // route stream-scoped frames to their owning lease; anything unclaimed
    // (no lease registered yet) stays on the shared inbound queue
    if AFrame.Header.StreamId <> 0 then
    begin
      if not TConnection(FConn).DispatchStreamFrame(AFrame) then
        FInbound.Push(AFrame);
    end;
  end;
  end;
end;

procedure TConnectionThread.DrainOutbound;
var
  Frame: TFrame;
begin
  while FOutbound.TryPop(Frame) do
  begin
    WriteFrame(FSockStream, Frame);
    TConnection(FConn).EmitFrameOut(Frame);
  end;
end;

procedure TConnectionThread.CheckPingKeepAlive;
var
  Now: QWord;
  Interval, Timeout: Integer;
begin
  Interval := TConnection(FConn).FPingIntervalMs;
  if Interval <= 0 then
    Exit;
  Timeout := TConnection(FConn).FPingTimeoutMs;
  Now := GetTickCount64;
  if FPendingPing then
  begin
    if (Timeout > 0) and (Now - FPingSentAt >= QWord(Timeout)) then
    begin
      Fail('PING acknowledgement timed out', ecNoError);
      Terminate;
    end;
    Exit;
  end;
  if Now - TConnection(FConn).FLastActivity >= QWord(Interval) then
  begin
    SetLength(FPendingPingPayload, 8);
    FPendingPingPayload[0] := 8;
    FPendingPing := True;
    FPingSentAt := Now;
    WriteTracked(BuildPingFrame(FPendingPingPayload, False));
    TConnection(FConn).TouchActivity;
  end;
end;

procedure TConnectionThread.HandlePingAck(const APayload: TBytes);
begin
  if FPendingPing and (Length(APayload) = 8) and
     (CompareMem(@APayload[0], @FPendingPingPayload[0], 8)) then
  begin
    FPendingPing := False;
    TConnection(FConn).TouchActivity;
  end;
end;

procedure TConnectionThread.Fail(const AMessage: string;
  const ACode: THttp2ErrorCode);
begin
  if FConn <> nil then
    TConnection(FConn).FailWith(AMessage, ACode);
end;

{ TConnection }

constructor TConnection.Create(const ASocket: IHttp2Socket);
begin
  Create(ASocket, TConnectionSettings.Defaults);
end;

constructor TConnection.Create(const ASocket: IHttp2Socket;
  const ALocalSettings: TConnectionSettings);
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FStateEvent := RTLEventCreate;
  FSocket := ASocket;
  FOutbound := TBlockingQueue<TFrame>.Create(cDefaultQueueCapacity);
  FInbound := TBlockingQueue<TFrame>.Create(cDefaultQueueCapacity);
  FLocalSettings := ALocalSettings;
  FPeerSettings := TConnectionSettings.Defaults;
  FState := csOpening;
  FSettingsAcked := False;
  FGoAwayLastStreamId := MaxStreamId;
  FHighestStreamId := 0;
  FError := '';
  FErrorCode := ecNoError;
  FClosed := False;
  FReadPollMs := cDefaultReadPollMs;
  FPingIntervalMs := 0;
  FPingTimeoutMs := 0;
  FLastActivity := GetTickCount64;
  FObserver := nil;
  FCloseObserved := False;
  FFlowControl := TFlowControl.Create(cDefaultConnectionWindowSize,
    cDefaultStreamWindowSize);
  FPendingStreamCredit := TDictionary<LongWord, LongWord>.Create;
  FPendingConnCredit := 0;
  FStreams := TDictionary<LongWord, IConnectionStream>.Create;
end;

destructor TConnection.Destroy;
begin
  Close;
  FreeAndNil(FPendingStreamCredit);
  FreeAndNil(FFlowControl);
  FreeAndNil(FStreams);
  RTLEventDestroy(FStateEvent);
  FLock.Free;
  inherited Destroy;
end;

procedure TConnection.Start;
begin
  if FThread = nil then
  begin
    FThread := TConnectionThread.Create(Self);
    FThread.Start;
  end;
end;

procedure TConnection.Close;
begin
  if FClosed then
    Exit;
  FClosed := True;
  // GOAWAY must be queued even while the preface is still being written: the
  // worker sets csOpen only *after* DoPreface returns, so a Close racing with
  // startup would otherwise skip the GOAWAY entirely. Queued frames are
  // drained after the preface, preserving the wire ordering (preface,
  // SETTINGS, then GOAWAY).
  if (FThread <> nil) and (GetState in [csOpening, csOpen]) then
    FOutbound.Push(BuildGoAwayFrame(FHighestStreamId, ecNoError, nil));
  if FThread <> nil then
  begin
    FThread.Terminate;
    FThread.WaitFor;
    FThread.Free;
    FThread := nil;
  end;
  FOutbound.Shutdown;
  FInbound.Shutdown;
  if FSocket <> nil then
    FSocket.Close;
  SetState(csClosed);
  EmitConnectionClose('', ecNoError);
end;

function TConnection.PostFrame(const AFrame: TFrame): Boolean;
begin
  Result := not FClosed;
  if Result then
    FOutbound.Push(AFrame);
end;

function TConnection.CanOpenStream: Boolean;
begin
  Result := GetState = csOpen;
end;

function TConnection.IsStreamRetryable(const AStreamId: LongWord): Boolean;
var
  S: TConnectionState;
begin
  S := GetState;
  Result := ((S = csGoAway) or (S = csClosed)) and
            (AStreamId > FGoAwayLastStreamId);
  if Result then
    EmitRetry(AStreamId);
end;

function TConnection.WaitForState(const AState: TConnectionState;
  const ATimeoutMs: Integer): Boolean;
var
  Deadline: QWord;
  Remaining: Integer;
begin
  Deadline := GetTickCount64 + QWord(ATimeoutMs);
  while True do
  begin
    if GetState = AState then
      Exit(True);
    if GetTickCount64 >= Deadline then
      Exit(False);
    Remaining := Integer(Deadline - GetTickCount64);
    RTLEventWaitFor(FStateEvent, Remaining);
  end;
end;

function TConnection.GetState: TConnectionState;
begin
  FLock.Acquire;
  try
    Result := FState;
  finally
    FLock.Release;
  end;
end;

function TConnection.GetPeerSettings: TConnectionSettings;
begin
  FLock.Acquire;
  try
    Result := FPeerSettings;
  finally
    FLock.Release;
  end;
end;

procedure TConnection.SetState(const AValue: TConnectionState);
begin
  FLock.Acquire;
  try
    FState := AValue;
  finally
    FLock.Release;
  end;
  RTLEventSetEvent(FStateEvent);
end;

procedure TConnection.MarkSettingsAcked;
begin
  FLock.Acquire;
  try
    FSettingsAcked := True;
  finally
    FLock.Release;
  end;
end;

procedure TConnection.ApplyPeerSettingsValue(
  const ASettings: TConnectionSettings);
var
  Delta: Int64;
begin
  FLock.Acquire;
  try
    // a SETTINGS_INITIAL_WINDOW_SIZE change adjusts every open stream window
    Delta := ASettings.InitialWindowSize - FPeerSettings.InitialWindowSize;
    FPeerSettings := ASettings;
    if Delta <> 0 then
      FFlowControl.ApplyInitialWindowDelta(Delta);
  finally
    FLock.Release;
  end;
end;

procedure TConnection.MarkGoAway(const ALastStreamId: LongWord);
var
  Snapshot: TArray<IConnectionStream>;
  S: IConnectionStream;
begin
  FLock.Acquire;
  try
    FGoAwayLastStreamId := ALastStreamId;
    if FState = csOpen then
      FState := csGoAway;
    Snapshot := FStreams.Values.ToArray;
  finally
    FLock.Release;
  end;
  RTLEventSetEvent(FStateEvent);
  EmitGoAway(ALastStreamId, ecNoError);
  // notify OUTSIDE the lock: a lease must never call back into TConnection
  // (RegisterStream/UnregisterStream) while we hold FLock, or it deadlocks
  for S in Snapshot do
    S.OnConnectionGoAway(ALastStreamId);
end;

procedure TConnection.RegisterStream(const AStreamId: LongWord;
  const AStream: IConnectionStream);
begin
  FLock.Acquire;
  try
    FStreams.AddOrSetValue(AStreamId, AStream);
    FFlowControl.OpenStream(AStreamId);
  finally
    FLock.Release;
  end;
  EmitStreamOpen(AStreamId);
end;

procedure TConnection.UnregisterStream(const AStreamId: LongWord);
begin
  // return the stream's outstanding receive credit before it disappears
  SendWindowUpdate(AStreamId);
  FLock.Acquire;
  try
    FStreams.Remove(AStreamId);
    FFlowControl.CloseStream(AStreamId);
    FPendingStreamCredit.Remove(AStreamId);
  finally
    FLock.Release;
  end;
  EmitStreamClose(AStreamId);
end;

function TConnection.StreamCount: Integer;
begin
  FLock.Acquire;
  try
    Result := FStreams.Count;
  finally
    FLock.Release;
  end;
end;

function TConnection.DispatchStreamFrame(const AFrame: TFrame): Boolean;
var
  S: IConnectionStream;
begin
  FLock.Acquire;
  try
    Result := FStreams.TryGetValue(AFrame.Header.StreamId, S);
  finally
    FLock.Release;
  end;
  // deliver OUTSIDE the lock: a lease callback must never re-enter FLock
  if Result then
    S.OnStreamFrame(AFrame);
end;

procedure TConnection.FailWith(const AMessage: string;
  const ACode: THttp2ErrorCode);
var
  Snapshot: TArray<IConnectionStream>;
  S: IConnectionStream;
begin
  FLock.Acquire;
  try
    if FState <> csClosed then
    begin
      FState := csClosed;
      FError := AMessage;
      FErrorCode := ACode;
    end;
    Snapshot := FStreams.Values.ToArray;
  finally
    FLock.Release;
  end;
  RTLEventSetEvent(FStateEvent);
  // fail every in-flight stream and release every blocked waiter
  FOutbound.Shutdown;
  FInbound.Shutdown;
  for S in Snapshot do
    S.OnConnectionFailed(AMessage, ACode);
  EmitConnectionClose(AMessage, ACode);
end;

procedure TConnection.TouchActivity;
begin
  FLock.Acquire;
  try
    FLastActivity := GetTickCount64;
  finally
    FLock.Release;
  end;
end;

procedure TConnection.TrackReceivedData(const AStreamId: LongWord;
  const ALength: LongWord);
var
  Pending: LongWord;
  StreamId: LongWord;
  Win: TWindow;
  EmitConn, EmitStream: Boolean;
  EmitConnInc, EmitStreamInc: LongWord;
begin
  if ALength = 0 then
    Exit;
  EmitConn := False;
  EmitStream := False;
  StreamId := AStreamId;
  EmitConnInc := 0;
  EmitStreamInc := 0;
  FLock.Acquire;
  try
    // connection window: DATA counts against it regardless of the stream
    FPendingConnCredit := FPendingConnCredit + ALength;
    if FPendingConnCredit >= cWindowUpdateBatchSize then
    begin
      FPendingConnCredit := 0;
      EmitConnInc := cWindowUpdateBatchSize;
    end;
    // stream window: only for a stream we still track (an open lease)
    if (StreamId <> 0) and FFlowControl.TryGetStream(StreamId, Win) then
    begin
      if not FPendingStreamCredit.TryGetValue(StreamId, Pending) then
        Pending := 0;
      Pending := Pending + ALength;
      if Pending >= cWindowUpdateBatchSize then
      begin
        FPendingStreamCredit.AddOrSetValue(StreamId, 0);
        EmitStreamInc := Pending;
      end
      else
        FPendingStreamCredit.AddOrSetValue(StreamId, Pending);
    end;
  finally
    FLock.Release;
  end;
  if EmitConnInc > 0 then
  begin
    PostFrame(BuildWindowUpdateFrame(0, EmitConnInc));
    EmitWindowUpdate(0, EmitConnInc);
  end;
  if EmitStreamInc > 0 then
  begin
    PostFrame(BuildWindowUpdateFrame(StreamId, EmitStreamInc));
    EmitWindowUpdate(StreamId, EmitStreamInc);
  end;
end;

procedure TConnection.SendWindowUpdate(const AStreamId: LongWord);
var
  Pending: LongWord;
begin
  FLock.Acquire;
  try
    if not FPendingStreamCredit.TryGetValue(AStreamId, Pending) then
      Exit;
    if Pending = 0 then
      Exit;
    FPendingStreamCredit.AddOrSetValue(AStreamId, 0);
  finally
    FLock.Release;
  end;
  PostFrame(BuildWindowUpdateFrame(AStreamId, Pending));
  EmitWindowUpdate(AStreamId, Pending);
end;

procedure TConnection.FlushStreamCredit(const AStreamId: LongWord);
begin
  SendWindowUpdate(AStreamId);
end;

{ observer fan-out }

function TConnection.GetObserver: IHttp2Observer;
begin
  FLock.Acquire;
  try
    Result := FObserver;
  finally
    FLock.Release;
  end;
end;

procedure TConnection.SetObserver(const AValue: IHttp2Observer);
begin
  FLock.Acquire;
  try
    FObserver := AValue;
  finally
    FLock.Release;
  end;
end;

procedure TConnection.EmitConnectionOpen;
var
  Obs: IHttp2Observer;
begin
  Obs := GetObserver;
  if Obs = nil then
    Exit;
  try
    Obs.OnConnectionOpen;
  except
    // an observer must never break the connection loop
  end;
end;

procedure TConnection.EmitConnectionClose(const AMessage: string;
  const ACode: THttp2ErrorCode);
var
  Obs: IHttp2Observer;
  Send: Boolean;
begin
  Obs := GetObserver;
  if Obs = nil then
    Exit;
  FLock.Acquire;
  try
    Send := not FCloseObserved;
    FCloseObserved := True;
  finally
    FLock.Release;
  end;
  if not Send then
    Exit;
  try
    Obs.OnConnectionClose(AMessage, ACode);
  except
  end;
end;

procedure TConnection.EmitGoAway(const ALastStreamId: LongWord;
  const ACode: THttp2ErrorCode);
var
  Obs: IHttp2Observer;
begin
  Obs := GetObserver;
  if Obs = nil then
    Exit;
  try
    Obs.OnGoAway(ALastStreamId, ACode);
  except
  end;
end;

procedure TConnection.EmitStreamOpen(const AStreamId: LongWord);
var
  Obs: IHttp2Observer;
begin
  Obs := GetObserver;
  if Obs = nil then
    Exit;
  try
    Obs.OnStreamOpen(AStreamId);
  except
  end;
end;

procedure TConnection.EmitStreamClose(const AStreamId: LongWord);
var
  Obs: IHttp2Observer;
begin
  Obs := GetObserver;
  if Obs = nil then
    Exit;
  try
    Obs.OnStreamClose(AStreamId);
  except
  end;
end;

procedure TConnection.EmitFrameIn(const AFrame: TFrame);
var
  Obs: IHttp2Observer;
begin
  Obs := GetObserver;
  if Obs = nil then
    Exit;
  try
    Obs.OnFrameIn(AFrame);
  except
  end;
end;

procedure TConnection.EmitFrameOut(const AFrame: TFrame);
var
  Obs: IHttp2Observer;
begin
  Obs := GetObserver;
  if Obs = nil then
    Exit;
  try
    Obs.OnFrameOut(AFrame);
  except
  end;
end;

procedure TConnection.EmitWindowUpdate(const AStreamId, AIncrement: LongWord);
var
  Obs: IHttp2Observer;
begin
  Obs := GetObserver;
  if Obs = nil then
    Exit;
  try
    Obs.OnWindowUpdate(AStreamId, AIncrement);
  except
  end;
end;

procedure TConnection.EmitRetry(const AStreamId: LongWord);
var
  Obs: IHttp2Observer;
begin
  Obs := GetObserver;
  if Obs = nil then
    Exit;
  try
    Obs.OnRetry(AStreamId);
  except
  end;
end;

procedure TConnection.EmitDiscarded(const AFrame: TFrame;
  const AReason: string);
var
  Obs: IHttp2Observer;
begin
  Obs := GetObserver;
  if Obs = nil then
    Exit;
  try
    Obs.OnDiscarded(AFrame, AReason);
  except
  end;
end;

end.
