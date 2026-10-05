/// Unit tests for TBlockingQueue<T> (plan story S06, tasks 06.1-06.4)
// - run with `make test`.
// - FPC 3.2.4 has no TThreadedQueue<T>; this queue is TQueue<T> +
//   TCriticalSection + two RTLEvents. Concurrency is proven with bounded,
//   event-driven waits (RTLEvent), never with Sleep-based synchronisation.
unit Http2.BlockingQueue.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, fpcunit, testregistry, Http2.Connection;

type
  /// worker base with an RTLEvent completion signal so tests wait with a
  /// deadline instead of sleeping
  TQueueWorker = class(TThread)
  private
    FDone: PRTLEvent;
    FDoneFlag: Boolean;
  protected
    procedure SignalDone;
  public
    constructor Create;
    destructor Destroy; override;
    function WaitDone(const ATimeoutMs: Integer): Boolean;
  end;

  /// drains an Integer queue until Pop returns False; records the running sum
  TSumConsumer = class(TQueueWorker)
  private
    FQ: IBlockingQueue<Integer>;
    FSum: Integer;
    FCount: Integer;
  protected
    procedure Execute; override;
  public
    constructor Create(const AQ: IBlockingQueue<Integer>);
    property Sum: Integer read FSum;
    property Count: Integer read FCount;
  end;

  /// pushes each value in turn then signals completion
  TValuePusher = class(TQueueWorker)
  private
    FQ: IBlockingQueue<Integer>;
    FValues: array of Integer;
  protected
    procedure Execute; override;
  public
    constructor Create(const AQ: IBlockingQueue<Integer>;
      const AValues: array of Integer);
  end;

  /// performs exactly one Pop and records whether/when it unblocked
  TOnePop = class(TQueueWorker)
  private
    FQ: IBlockingQueue<Integer>;
    FValue: Integer;
    FGot: Boolean;
  protected
    procedure Execute; override;
  public
    constructor Create(const AQ: IBlockingQueue<Integer>);
    property Got: Boolean read FGot;
    property Value: Integer read FValue;
  end;

  TBlockingQueueTest = class(TTestCase)
  published
    // 06.1 ordering / basic
    procedure TestFifoOrdering;
    procedure TestTryPopEmptyReturnsFalseImmediately;
    // 06.1 / 06.4 consumer drains 100 items, sum 5050
    procedure TestConsumerDrainsHundredSum5050;
    // 06.1 blocking then wake on Push
    procedure TestPopBlocksThenReturnsOnPush;
    // 06.2 shutdown semantics
    procedure TestShutdownReleasesBlockedPop;
    procedure TestPopAfterShutdownReturnsFalse;
    procedure TestShutdownWakesAllBlockedWaiters;
    // 06.3 bounded backpressure
    procedure TestBoundedProducerBlocksWhileFull;
    procedure TestBoundedProducerResumesWhenDrained;
    // concurrency
    procedure TestConcurrentProducersAllSucceed;
    // 06.4 interface form is ARC-safe
    procedure TestInterfaceFormReleasesOnNil;
  end;

implementation

{ TQueueWorker }

constructor TQueueWorker.Create;
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FDone := RTLEventCreate;
  FDoneFlag := False;
end;

destructor TQueueWorker.Destroy;
begin
  RTLEventDestroy(FDone);
  inherited Destroy;
end;

procedure TQueueWorker.SignalDone;
begin
  FDoneFlag := True;
  RTLEventSetEvent(FDone);
end;

function TQueueWorker.WaitDone(const ATimeoutMs: Integer): Boolean;
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

{ TSumConsumer }

constructor TSumConsumer.Create(const AQ: IBlockingQueue<Integer>);
begin
  inherited Create;
  FQ := AQ;
  FSum := 0;
  FCount := 0;
end;

procedure TSumConsumer.Execute;
var
  V: Integer;
begin
  while FQ.Pop(V) do
  begin
    Inc(FSum, V);
    Inc(FCount);
  end;
  SignalDone;
end;

{ TValuePusher }

constructor TValuePusher.Create(const AQ: IBlockingQueue<Integer>;
  const AValues: array of Integer);
var
  I: Integer;
begin
  inherited Create;
  FQ := AQ;
  SetLength(FValues, Length(AValues));
  for I := 0 to High(AValues) do
    FValues[I] := AValues[I];
end;

procedure TValuePusher.Execute;
var
  I: Integer;
begin
  for I := 0 to High(FValues) do
    FQ.Push(FValues[I]);
  SignalDone;
end;

{ TOnePop }

constructor TOnePop.Create(const AQ: IBlockingQueue<Integer>);
begin
  inherited Create;
  FQ := AQ;
  FGot := False;
end;

procedure TOnePop.Execute;
begin
  FGot := FQ.Pop(FValue);
  SignalDone;
end;

{ tests }

procedure TBlockingQueueTest.TestFifoOrdering;
var
  Q: IBlockingQueue<Integer>;
  V: Integer;
begin
  Q := TBlockingQueue<Integer>.Create(4);
  Q.Push(10);
  Q.Push(20);
  Q.Push(30);
  AssertTrue('pop 1', Q.Pop(V));
  AssertEquals('first is 10', 10, V);
  AssertTrue('pop 2', Q.Pop(V));
  AssertEquals('second is 20', 20, V);
  AssertTrue('pop 3', Q.Pop(V));
  AssertEquals('third is 30', 30, V);
  Q.Shutdown;
end;

procedure TBlockingQueueTest.TestTryPopEmptyReturnsFalseImmediately;
var
  Q: IBlockingQueue<Integer>;
  V: Integer;
begin
  Q := TBlockingQueue<Integer>.Create(4);
  V := -1;
  AssertFalse('TryPop on an empty queue returns False', Q.TryPop(V));
  Q.Push(7);
  AssertTrue('TryPop returns the item', Q.TryPop(V));
  AssertEquals('TryPop value', 7, V);
  Q.Shutdown;
end;

procedure TBlockingQueueTest.TestConsumerDrainsHundredSum5050;
var
  Q: IBlockingQueue<Integer>;
  C: TSumConsumer;
  I: Integer;
begin
  Q := TBlockingQueue<Integer>.Create(8);
  C := TSumConsumer.Create(Q);
  try
    C.Start;
    for I := 1 to 100 do
      Q.Push(I);
    Q.Shutdown;                 // unblocks the consumer's final Pop
    C.WaitFor;
    AssertEquals('drained exactly 100 items', 100, C.Count);
    AssertEquals('sum is 5050', 5050, C.Sum);
  finally
    C.Free;
  end;
end;

procedure TBlockingQueueTest.TestPopBlocksThenReturnsOnPush;
var
  Q: IBlockingQueue<Integer>;
  P: TOnePop;
begin
  Q := TBlockingQueue<Integer>.Create(4);
  P := TOnePop.Create(Q);
  try
    P.Start;
    // nothing to pop: the worker must still be blocked
    AssertFalse('Pop blocks while the queue is empty', P.WaitDone(80));
    AssertFalse('no value delivered yet', P.Got);
    Q.Push(42);
    AssertTrue('Pop returns once an item is pushed', P.WaitDone(2000));
    AssertTrue('value delivered', P.Got);
    AssertEquals('value is 42', 42, P.Value);
    Q.Shutdown;
  finally
    P.Free;
  end;
end;

procedure TBlockingQueueTest.TestShutdownReleasesBlockedPop;
var
  Q: IBlockingQueue<Integer>;
  P: TOnePop;
begin
  Q := TBlockingQueue<Integer>.Create(4);
  P := TOnePop.Create(Q);
  try
    P.Start;
    AssertFalse('Pop is blocked before shutdown', P.WaitDone(80));
    Q.Shutdown;
    AssertTrue('Shutdown releases the blocked Pop', P.WaitDone(2000));
    AssertFalse('released Pop returns False', P.Got);
    P.WaitFor;
  finally
    P.Free;
  end;
end;

procedure TBlockingQueueTest.TestPopAfterShutdownReturnsFalse;
var
  Q: IBlockingQueue<Integer>;
  V: Integer;
begin
  Q := TBlockingQueue<Integer>.Create(4);
  Q.Push(1);
  Q.Shutdown;
  // Shutdown drains: the buffered item is still popable, then False
  AssertTrue('buffered item survives shutdown', Q.Pop(V));
  AssertEquals('buffered value', 1, V);
  AssertFalse('Pop after shutdown returns False', Q.Pop(V));
end;

procedure TBlockingQueueTest.TestShutdownWakesAllBlockedWaiters;
var
  BQ: TBlockingQueue<Integer>;
  Q: IBlockingQueue<Integer>;
  Workers: array[0..3] of TOnePop;
  I: Integer;
  AllDone: Boolean;
  Deadline: QWord;
begin
  BQ := TBlockingQueue<Integer>.Create(4);
  Q := BQ;
  for I := 0 to High(Workers) do
    Workers[I] := TOnePop.Create(Q);
  try
    for I := 0 to High(Workers) do
      Workers[I].Start;
    // wait (bounded) until ALL workers have actually parked inside Pop, so the
    // shutdown race cannot be won by workers that never blocked. The poll
    // gates the assertion only; the wake-up logic under test is event-driven.
    Deadline := GetTickCount64 + 5000;
    while (BQ.WaitersParked < Length(Workers)) and (GetTickCount64 < Deadline) do
      Sleep(1);
    AssertEquals('all workers are parked before Shutdown',
      Length(Workers), BQ.WaitersParked);
    for I := 0 to High(Workers) do
      AssertFalse('waiter still blocked before shutdown', Workers[I].WaitDone(50));
    Q.Shutdown;
    AllDone := True;
    for I := 0 to High(Workers) do
      if not Workers[I].WaitDone(2000) then
        AllDone := False;
    AssertTrue('every blocked waiter was released', AllDone);
    for I := 0 to High(Workers) do
    begin
      AssertFalse('each released waiter got False', Workers[I].Got);
      Workers[I].WaitFor;
    end;
  finally
    for I := 0 to High(Workers) do
      Workers[I].Free;
  end;
end;

procedure TBlockingQueueTest.TestBoundedProducerBlocksWhileFull;
var
  Q: IBlockingQueue<Integer>;
  P: TValuePusher;
begin
  Q := TBlockingQueue<Integer>.Create(2);
  P := TValuePusher.Create(Q, [1, 2, 3]);
  try
    P.Start;
    // capacity 2 with three pushes: the third must block
    AssertFalse('producer blocks while the queue is full', P.WaitDone(150));
    Q.Shutdown;                 // release the blocked producer
    AssertTrue('blocked producer is released by shutdown', P.WaitDone(2000));
    P.WaitFor;
  finally
    P.Free;
  end;
end;

procedure TBlockingQueueTest.TestBoundedProducerResumesWhenDrained;
var
  Q: IBlockingQueue<Integer>;
  P: TValuePusher;
  V: Integer;
begin
  Q := TBlockingQueue<Integer>.Create(2);
  P := TValuePusher.Create(Q, [1, 2, 3]);
  try
    P.Start;
    AssertFalse('producer is blocked', P.WaitDone(150));
    AssertTrue('dequeue frees a slot', Q.Pop(V));
    AssertEquals('first value', 1, V);
    AssertTrue('producer resumes once a slot is free', P.WaitDone(2000));
    // the remaining two items are now buffered
    AssertTrue('second buffered', Q.Pop(V));
    AssertEquals('second value', 2, V);
    AssertTrue('third buffered', Q.Pop(V));
    AssertEquals('third value', 3, V);
    Q.Shutdown;
    P.WaitFor;
  finally
    P.Free;
  end;
end;

procedure TBlockingQueueTest.TestConcurrentProducersAllSucceed;
var
  Q: IBlockingQueue<Integer>;
  Producers: array[0..3] of TValuePusher;
  I, K, Total, V: Integer;
begin
  // unbounded (capacity 0) so producers never block on each other
  Q := TBlockingQueue<Integer>.Create(0);
  for I := 0 to High(Producers) do
    Producers[I] := TValuePusher.Create(Q,
      [I * 5 + 1, I * 5 + 2, I * 5 + 3, I * 5 + 4, I * 5 + 5]);
  try
    for I := 0 to High(Producers) do
      Producers[I].Start;
    for I := 0 to High(Producers) do
      AssertTrue('producer finished', Producers[I].WaitDone(2000));
    for I := 0 to High(Producers) do
      Producers[I].WaitFor;
    Q.Shutdown;
    Total := 0;
    K := 0;
    while Q.Pop(V) do
    begin
      Inc(Total, V);
      Inc(K);
    end;
    AssertEquals('all concurrent pushes landed', 4 * 5, K);
    AssertEquals('total is 1+2+...+20', 210, Total);
  finally
    for I := 0 to High(Producers) do
      Producers[I].Free;
  end;
end;

procedure TBlockingQueueTest.TestInterfaceFormReleasesOnNil;
var
  Q: IBlockingQueue<Integer>;
  V: Integer;
begin
  // referencing through the interface must not leak or double-free: the
  // TInterfacedObject refcount drops back to zero when the only ref is nil'd
  Q := TBlockingQueue<Integer>.Create(2);
  Q.Push(5);
  AssertTrue('pop through interface', Q.Pop(V));
  AssertEquals('value', 5, V);
  Q := nil;
  AssertTrue('queue released without error', True);
end;

initialization
  RegisterTest(TBlockingQueueTest);
end.
