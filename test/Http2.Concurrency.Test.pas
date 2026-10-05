/// Concurrency tests for the connection, stream lease and blocking queue
/// (plan S11 task 11.7)
// - part of the http2client project (see doc/design/testing-observability.md:
//   "Concurrency tests: many threads calling Send against a slow streaming
//   server to prove MaxConnections/stream-cap accounting and that backpressure
//   throttles instead of buffering").
// - deterministic and race-free: synchronisation is bounded, event-driven
//   (RTLEvent) waits on counters, never sleeps-as-synchronisation. Every
//   assertion observes a positive result (a decoded status, a counted pop)
//   rather than the absence of a crash.
// - the critical fact pinned here (learned in this repo): RTLEventSetEvent
//   wakes exactly ONE waiter, so Shutdown must chain-wake the SAME event.
//   TestShutdownReleasesEveryBlockedWaiter would hang (and time out) if the
//   chain-wake in TBlockingQueue regressed.
unit Http2.Concurrency.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, SyncObjs, Generics.Collections, fpcunit, testregistry,
  Http2.Errors, Http2.Frames, Http2.Connection, Http2.Stream, Http2.Observer,
  Http2.MockSocket;

type
  /// one thread runs N independent stream leases over the shared connection;
  /// each lease starts, waits for its response, reads the body and releases.
  TLeaseWorker = class(TThread)
  private
    FConn: TConnection;
    FAlloc: TStreamIdAllocator;
    FLeases: Integer;
    FDone: PRTLEvent;
    FDoneFlag: Boolean;
    FCompleted: Integer;
    FBadStatus: Integer;
    FErrors: Integer;
    FLastError: string;
  protected
    procedure Execute; override;
  public
    constructor Create(const AConn: TConnection;
      const AAlloc: TStreamIdAllocator; const ALeases: Integer);
    destructor Destroy; override;
    function WaitDone(const ATimeoutMs: Integer): Boolean;
    property Completed: Integer read FCompleted;
    property BadStatus: Integer read FBadStatus;
    property Errors: Integer read FErrors;
    property LastError: string read FLastError;
  end;

  /// one thread blocks in IBlockingQueue<T>.Pop until released; every
  /// successful pop increments a shared, interlocked counter
  TQueueWaiter = class(TThread)
  private
    FQueue: IBlockingQueue<TFrame>;
    FCounter: PInteger;
    FDone: PRTLEvent;
    FDoneFlag: Boolean;
    FResult: Boolean;
  protected
    procedure Execute; override;
  public
    constructor Create(const AQueue: IBlockingQueue<TFrame>;
      const ACounter: PInteger);
    destructor Destroy; override;
    function WaitDone(const ATimeoutMs: Integer): Boolean;
    property Result: Boolean read FResult;
  end;

  /// one thread pushes ACount frames onto the queue after a shared start event
  TQueueProducer = class(TThread)
  private
    FQueue: IBlockingQueue<TFrame>;
    FStart: PRTLEvent;
    FCount: Integer;
    FDone: PRTLEvent;
    FDoneFlag: Boolean;
  protected
    procedure Execute; override;
  public
    constructor Create(const AQueue: IBlockingQueue<TFrame>; const ACount: Integer;
      const AStart: PRTLEvent);
    destructor Destroy; override;
    function WaitDone(const ATimeoutMs: Integer): Boolean;
  end;

  /// register/unregister streams on one connection, concurrently, so the
  /// observer fan-out is exercised from many threads at once
  TStreamChurnWorker = class(TThread)
  private
    FConn: TConnection;
    FRounds: Integer;
    FDone: PRTLEvent;
    FDoneFlag: Boolean;
  protected
    procedure Execute; override;
  public
    constructor Create(const AConn: TConnection; const ARounds: Integer);
    destructor Destroy; override;
    function WaitDone(const ATimeoutMs: Integer): Boolean;
  end;

  TConcurrencyTest = class(TTestCase)
  published
    /// many stream leases multiplexed over ONE connection thread
    procedure TestManyStreamLeasesOverOneConnectionThread;
    /// the blocking queue never loses an item under producer/consumer contention
    procedure TestManyProducersAndConsumersNoLossNoDuplicate;
    /// Shutdown must release EVERY blocked waiter (chain-wake invariant)
    procedure TestShutdownReleasesEveryBlockedWaiter;
    /// concurrent stream churn emits a balanced observer event stream
    procedure TestConcurrentStreamChurnIsRaceFree;
  end;

implementation

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

{ TLeaseWorker }

constructor TLeaseWorker.Create(const AConn: TConnection;
  const AAlloc: TStreamIdAllocator; const ALeases: Integer);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FConn := AConn;
  FAlloc := AAlloc;
  FLeases := ALeases;
  FDone := RTLEventCreate;
end;

destructor TLeaseWorker.Destroy;
begin
  RTLEventDestroy(FDone);
  inherited Destroy;
end;

procedure TLeaseWorker.Execute;
var
  I: Integer;
  Req: TStreamRequest;
  Lease: TStreamLease;
  IL: IConnectionStream;
  Body: string;
begin
  try
    Req := TStreamRequest.WithMethod(hmGet, 'api.example:443').WithPath('/');
    for I := 0 to FLeases - 1 do
    begin
      Lease := TStreamLease.Create(FConn, FAlloc, Req);
      IL := Lease;
      try
        try
          Lease.Start;
          if Lease.WaitForResponseHeader(5000) and (Lease.StatusCode = 200) then
          begin
            Body := ReadAllBodyText(Lease.Body);
            if Body = 'ok' then
              Inc(FCompleted)
            else
              Inc(FBadStatus);
          end
          else
            Inc(FBadStatus);
        except
          on E: Exception do
          begin
            Inc(FErrors);
            FLastError := E.ClassName + ': ' + E.Message;
          end;
        end;
      finally
        Lease.ReleaseLease;
        IL := nil;
      end;
    end;
  finally
    FDoneFlag := True;
    RTLEventSetEvent(FDone);
  end;
end;

function TLeaseWorker.WaitDone(const ATimeoutMs: Integer): Boolean;
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

{ TQueueWaiter }

constructor TQueueWaiter.Create(const AQueue: IBlockingQueue<TFrame>;
  const ACounter: PInteger);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FQueue := AQueue;
  FCounter := ACounter;
  FDone := RTLEventCreate;
end;

destructor TQueueWaiter.Destroy;
begin
  RTLEventDestroy(FDone);
  inherited Destroy;
end;

procedure TQueueWaiter.Execute;
var
  F: TFrame;
begin
  while FQueue.Pop(F) do
    InterLockedIncrement(FCounter^);
  FResult := True;
  FDoneFlag := True;
  RTLEventSetEvent(FDone);
end;

function TQueueWaiter.WaitDone(const ATimeoutMs: Integer): Boolean;
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

{ TQueueProducer }

constructor TQueueProducer.Create(const AQueue: IBlockingQueue<TFrame>;
  const ACount: Integer; const AStart: PRTLEvent);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FQueue := AQueue;
  FCount := ACount;
  FStart := AStart;
  FDone := RTLEventCreate;
end;

destructor TQueueProducer.Destroy;
begin
  RTLEventDestroy(FDone);
  inherited Destroy;
end;

procedure TQueueProducer.Execute;
var
  I: Integer;
begin
  // RTLEventSetEvent wakes exactly ONE waiter, so every producer re-signals
  // the SAME start event after waking to chain-wake the rest (the repo rule).
  RTLEventWaitFor(FStart);
  RTLEventSetEvent(FStart);
  for I := 0 to FCount - 1 do
    FQueue.Push(BuildPingFrame(nil, False));
  FDoneFlag := True;
  RTLEventSetEvent(FDone);
end;

function TQueueProducer.WaitDone(const ATimeoutMs: Integer): Boolean;
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

{ TStreamChurnWorker }

constructor TStreamChurnWorker.Create(const AConn: TConnection;
  const ARounds: Integer);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FConn := AConn;
  FRounds := ARounds;
  FDone := RTLEventCreate;
end;

destructor TStreamChurnWorker.Destroy;
begin
  RTLEventDestroy(FDone);
  inherited Destroy;
end;

procedure TStreamChurnWorker.Execute;
var
  I: Integer;
  Lease: TObserverTestLease;
  IL: IConnectionStream;
begin
  try
    for I := 0 to FRounds - 1 do
    begin
      Lease := TObserverTestLease.Create;
      IL := Lease;
      FConn.RegisterStream(LongWord(I * 2 + 1), IL);
      FConn.UnregisterStream(LongWord(I * 2 + 1));
      IL := nil;
    end;
  finally
    FDoneFlag := True;
    RTLEventSetEvent(FDone);
  end;
end;

function TStreamChurnWorker.WaitDone(const ATimeoutMs: Integer): Boolean;
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

{ TConcurrencyTest }

procedure TConcurrencyTest.TestManyStreamLeasesOverOneConnectionThread;
const
  WorkerCount = 4;
  LeasesPerWorker = 25;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Alloc: TStreamIdAllocator;
  Workers: array[0..WorkerCount - 1] of TLeaseWorker;
  I, Completed, Bad, Errs: Integer;
  AllDone: Boolean;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  Alloc := TStreamIdAllocator.Create;
  // the mock answers every request HEADERS with a 200 + 'ok' body
  Sock.AutoRespondToRequestHeaders('200', BytesOfString('ok'), True);
  try
    Conn.Start;
    AssertTrue('connection opens', Conn.WaitForState(csOpen, 2000));
    for I := 0 to WorkerCount - 1 do
      Workers[I] := TLeaseWorker.Create(Conn, Alloc, LeasesPerWorker);
    for I := 0 to WorkerCount - 1 do
      Workers[I].Start;

    AllDone := True;
    for I := 0 to WorkerCount - 1 do
      if not Workers[I].WaitDone(20000) then
        AllDone := False;
    AssertTrue('every lease worker finished', AllDone);

    Completed := 0;
    Bad := 0;
    Errs := 0;
    for I := 0 to WorkerCount - 1 do
    begin
      Inc(Completed, Workers[I].Completed);
      Inc(Bad, Workers[I].BadStatus);
      Inc(Errs, Workers[I].Errors);
      if Workers[I].Errors > 0 then
        AssertEquals('worker error is empty on success', '', Workers[I].LastError);
    end;
    AssertEquals('no lease reported an exception', 0, Errs);
    AssertEquals('no lease got a non-200 or bad body', 0, Bad);
    AssertEquals('every lease completed end to end',
      WorkerCount * LeasesPerWorker, Completed);
    AssertEquals('no stream leaked after all leases released', 0,
      Conn.StreamCount);

    for I := 0 to WorkerCount - 1 do
      Workers[I].Free;
  finally
    Conn.Close;
    Alloc.Free;
    Conn.Free;
  end;
end;

procedure TConcurrencyTest.TestManyProducersAndConsumersNoLossNoDuplicate;
const
  ProducerCount = 4;
  ConsumerCount = 4;
  PerProducer = 200;
  Total = ProducerCount * PerProducer;
var
  Q: TBlockingQueue<TFrame>;
  Producers: array[0..ProducerCount - 1] of TQueueProducer;
  Consumers: array[0..ConsumerCount - 1] of TQueueWaiter;
  Start: PRTLEvent;
  Counter: Integer;
  I: Integer;
  AllDone: Boolean;
  QI: IBlockingQueue<TFrame>;
begin
  Q := TBlockingQueue<TFrame>.Create(16);
  QI := Q;
  Start := RTLEventCreate;
  Counter := 0;
  try
    for I := 0 to ProducerCount - 1 do
      Producers[I] := TQueueProducer.Create(QI, PerProducer, Start);
    for I := 0 to ConsumerCount - 1 do
      Consumers[I] := TQueueWaiter.Create(QI, @Counter);

    for I := 0 to ProducerCount - 1 do
      Producers[I].Start;
    for I := 0 to ConsumerCount - 1 do
      Consumers[I].Start;
    RTLEventSetEvent(Start);          // release all producers at once

    AllDone := True;
    for I := 0 to ProducerCount - 1 do
      if not Producers[I].WaitDone(20000) then
        AllDone := False;
    AssertTrue('every producer finished', AllDone);

    // producers are done; the consumers drain concurrently until Shutdown.
    // Once the item count reaches Total the queue is empty; Shutdown then
    // releases the consumers.
    Q.Shutdown;
    AllDone := True;
    for I := 0 to ConsumerCount - 1 do
      if not Consumers[I].WaitDone(10000) then
        AllDone := False;
    AssertTrue('every consumer thread stopped', AllDone);

    // Conservation: every produced item was popped exactly once (no loss or
    // duplication). q.Count must be zero after the consumers drained.
    AssertEquals('every produced item was consumed exactly once', Total,
      Counter);
    AssertEquals('queue is empty after drain', 0, Q.Count);

    for I := 0 to ProducerCount - 1 do
      Producers[I].Free;
    for I := 0 to ConsumerCount - 1 do
      Consumers[I].Free;
  finally
    RTLEventDestroy(Start);
    // QI is the only interface ref; dropping it frees the queue (TInterfacedObject)
    QI := nil;
  end;
end;

procedure TConcurrencyTest.TestShutdownReleasesEveryBlockedWaiter;
const
  Waiters = 8;
var
  Q: TBlockingQueue<TFrame>;
  QI: IBlockingQueue<TFrame>;
  Threads: array[0..Waiters - 1] of TQueueWaiter;
  Tick: PRTLEvent;
  Counter, I, Released: Integer;
  Deadline: QWord;
begin
  Q := TBlockingQueue<TFrame>.Create(4);
  QI := Q;
  Tick := RTLEventCreate;
  Counter := 0;
  try
    for I := 0 to Waiters - 1 do
      Threads[I] := TQueueWaiter.Create(QI, @Counter);
    for I := 0 to Waiters - 1 do
      Threads[I].Start;

    // bounded, event-driven wait for every waiter to park inside Pop
    Deadline := GetTickCount64 + 5000;
    while (Q.WaitersParked < Waiters) and (GetTickCount64 < Deadline) do
      RTLEventWaitFor(Tick, 5);
    AssertEquals('all waiters are parked in Pop', Waiters, Q.WaitersParked);

    // ONE Shutdown call must chain-wake ALL of them
    Q.Shutdown;
    Released := 0;
    for I := 0 to Waiters - 1 do
      if Threads[I].WaitDone(5000) then
        Inc(Released);
    AssertEquals('Shutdown released every blocked waiter', Waiters, Released);
    for I := 0 to Waiters - 1 do
    begin
      AssertTrue('a released waiter returns from Pop', Threads[I].Result);
      AssertEquals('a released waiter consumed nothing', 0, Counter);
      Threads[I].Free;
    end;
  finally
    RTLEventDestroy(Tick);
    // QI is the only interface ref; dropping it frees the queue (TInterfacedObject)
    QI := nil;
  end;
end;

procedure TConcurrencyTest.TestConcurrentStreamChurnIsRaceFree;
const
  WorkerCount = 6;
  Rounds = 200;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Obs: TRecordingObserver;
  Workers: array[0..WorkerCount - 1] of TStreamChurnWorker;
  I: Integer;
  AllDone: Boolean;
begin
  Sock := TMockSocket.Create;
  Obs := TRecordingObserver.Create;
  Conn := TConnection.Create(Sock);
  Conn.Observer := Obs;
  try
    for I := 0 to WorkerCount - 1 do
      Workers[I] := TStreamChurnWorker.Create(Conn, Rounds);
    for I := 0 to WorkerCount - 1 do
      Workers[I].Start;
    AllDone := True;
    for I := 0 to WorkerCount - 1 do
      if not Workers[I].WaitDone(10000) then
        AllDone := False;
    AssertTrue('every churn worker finished', AllDone);

    AssertEquals('no stream left registered', 0, Conn.StreamCount);
    // every register emits stream-open and every unregister stream-close, so
    // the two counts must be balanced even from many threads
    AssertEquals('stream-open events balance stream-close events',
      Obs.CountOf(oekStreamOpen), Obs.CountOf(oekStreamClose));
    AssertEquals('every registration was observed',
      WorkerCount * Rounds, Obs.CountOf(oekStreamOpen));

    for I := 0 to WorkerCount - 1 do
      Workers[I].Free;
  finally
    Conn.Free;
  end;
end;

initialization
  RegisterTest(TConcurrencyTest);
end.
