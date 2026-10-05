{$mode delphi}{$H+}
program probe12;
uses {$IFDEF UNIX}cthreads,{$ENDIF} SysUtils, Classes, SyncObjs, Generics.Collections;

type
  { Blocking bounded queue: TThreadedQueue does NOT exist in FPC 3.2.4.
    Built from TQueue<T> + TCriticalSection + RTLEvent. }
  TBlockingQueue<T> = class
  private
    FLock: TCriticalSection;
    FNotEmpty: PRTLEvent;
    FNotFull: PRTLEvent;
    FItems: TQueue<T>;
    FCapacity: Integer;
    FShutdown: Boolean;
  public
    constructor Create(const ACapacity: Integer = 128);
    destructor Destroy; override;
    procedure Push(const AItem: T);
    function Pop(out AItem: T): Boolean;   // False on shutdown+empty
    procedure Shutdown;
  end;

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
  inherited;
end;

procedure TBlockingQueue<T>.Push(const AItem: T);
begin
  FLock.Acquire;
  try
    while (not FShutdown) and (FItems.Count >= FCapacity) do
    begin
      FLock.Release;
      try
        RTLEventWaitFor(FNotFull);
      finally
        FLock.Acquire;
      end;
    end;
    if FShutdown then Exit;
    FItems.Enqueue(AItem);
  finally
    FLock.Release;
  end;
  RTLEventSetEvent(FNotEmpty);
end;

function TBlockingQueue<T>.Pop(out AItem: T): Boolean;
begin
  Result := False;
  FLock.Acquire;
  try
    while (not FShutdown) and (FItems.Count = 0) do
    begin
      FLock.Release;
      try
        RTLEventWaitFor(FNotEmpty);
      finally
        FLock.Acquire;
      end;
    end;
    if FItems.Count > 0 then
    begin
      AItem := FItems.Dequeue;
      Result := True;
    end;
  finally
    FLock.Release;
  end;
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
  RTLEventSetEvent(FNotEmpty);
  RTLEventSetEvent(FNotFull);
end;

type
  TConsumer = class(TThread)
  private
    FQ: TBlockingQueue<Integer>;
    FSum: Integer;
  protected
    procedure Execute; override;
  public
    constructor Create(const AQ: TBlockingQueue<Integer>);
    property Sum: Integer read FSum;
  end;

constructor TConsumer.Create(const AQ: TBlockingQueue<Integer>);
begin
  inherited Create(True);
  FQ := AQ;
  FSum := 0;
  FreeOnTerminate := False;
end;

procedure TConsumer.Execute;
var
  V: Integer;
begin
  while FQ.Pop(V) do
    FSum := FSum + V;
end;

var
  Q: TBlockingQueue<Integer>;
  C: TConsumer;
  I: Integer;
begin
  Q := TBlockingQueue<Integer>.Create(4);
  C := TConsumer.Create(Q);
  C.Start;
  for I := 1 to 100 do
    Q.Push(I);
  Q.Shutdown;          // unblocks the consumer's Pop
  C.WaitFor;
  WriteLn('blocking queue + thread sum=', C.Sum, ' (expect 5050)');
  C.Free;
  Q.Free;
  WriteLn('done');
end.
