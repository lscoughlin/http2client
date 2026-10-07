/// http2client example: many threads sharing ONE client.
// - build: `task examples`
// - run:   bin/threaded_get https://nghttp2.org/ [threads] [requests-per-thread]
// - shows: `IHttpClient.Send` is thread-safe. Every worker shares the same
//   client (and therefore the same connection pool); the pool hands each Send
//   its own stream lease, bounded by MaxStreamsPerConnection. Counting is
//   guarded by a TCriticalSection, and every thread is WaitFor'd before the
//   summary is printed.
// - on Unix link `cthreads` (the first unit in the uses clause) or threads do
//   not start.
program example_threaded;

{$mode delphi}{$H+}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils, Classes, SyncObjs,
  Http2.Errors, Http2.Headers, Http2.Stream, Http2.Messages, Http2.Client;

type
  /// one worker issues ACount GETs and records the outcome under a shared lock
  TGetWorker = class(TThread)
  private
    FClient: IHttpClient;
    FUrl: string;
    FCount: Integer;
    FLock: TCriticalSection;
    FSuccess: PInteger;
    FFailure: PInteger;
    FFirstError: PString;
    procedure NoteResult(const AOk: Boolean; const AError: string);
  protected
    procedure Execute; override;
  public
    constructor Create(const AClient: IHttpClient; const AUrl: string;
      const ACount: Integer; const ALock: TCriticalSection;
      const ASuccess, AFailure: PInteger; const AFirstError: PString);
  end;

constructor TGetWorker.Create(const AClient: IHttpClient; const AUrl: string;
  const ACount: Integer; const ALock: TCriticalSection;
  const ASuccess, AFailure: PInteger; const AFirstError: PString);
begin
  inherited Create(False);
  FClient := AClient;
  FUrl := AUrl;
  FCount := ACount;
  FLock := ALock;
  FSuccess := ASuccess;
  FFailure := AFailure;
  FFirstError := AFirstError;
end;

procedure TGetWorker.NoteResult(const AOk: Boolean; const AError: string);
begin
  FLock.Acquire;
  try
    if AOk then
      Inc(FSuccess^)
    else
    begin
      Inc(FFailure^);
      if FFirstError^ = '' then
        FFirstError^ := AError;
    end;
  finally
    FLock.Release;
  end;
end;

procedure TGetWorker.Execute;
var
  I: Integer;
  Response: IHttpResponse;
begin
  for I := 1 to FCount do
  begin
    if Terminated then
      Exit;
    try
      Response := FClient.Send(
        THttpRequest.Create(hmGet, FUrl)
          .WithHeader('user-agent', 'http2client-example-threaded'));
      // drain the body so the stream lease is released for the next request
      ReadText(Response);
      NoteResult(Response.StatusCode >= 200, '');
    except
      on E: EHttpError do
        NoteResult(False, E.ClassName + ': ' + E.Message);
    end;
  end;
end;

var
  Client: IHttpClient;
  Url: string;
  ThreadCount, PerThread: Integer;
  Workers: array of TGetWorker;
  Lock: TCriticalSection;
  Success, Failure: Integer;
  FirstError: string;
  I: Integer;
begin
  if ParamCount < 1 then
  begin
    WriteLn(StdErr, 'usage: example_threaded <https-url> [threads] [per-thread]');
    Halt(2);
  end;
  Url := ParamStr(1);
  ThreadCount := 8;
  PerThread := 25;
  if ParamCount >= 2 then
    ThreadCount := StrToIntDef(ParamStr(2), ThreadCount);
  if ParamCount >= 3 then
    PerThread := StrToIntDef(ParamStr(3), PerThread);

  // One client, shared by every thread. A high-concurrency recipe bounds each
  // host tightly and multiplexes widely rather than opening many connections.
  Client := THttpClientFactory.Create
    .WithMaxConnectionsPerHost(2)
    .WithMaxTotalConnections(128)
    .WithMaxStreamsPerConnection(30)
    .Build;

  Lock := TCriticalSection.Create;
  try
    Success := 0;
    Failure := 0;
    FirstError := '';

    SetLength(Workers, ThreadCount);
    for I := 0 to ThreadCount - 1 do
      Workers[I] := TGetWorker.Create(Client, Url, PerThread, Lock,
        @Success, @Failure, @FirstError);

    for I := 0 to High(Workers) do
      Workers[I].WaitFor;
    for I := 0 to High(Workers) do
      Workers[I].Free;

    WriteLn(Format('%d threads x %d requests: %d ok, %d failed',
      [ThreadCount, PerThread, Success, Failure]));
    if FirstError <> '' then
      WriteLn('first error: ', FirstError);
  finally
    Lock.Free;
    // Close after every worker has joined; outstanding bodies stay readable.
    Client.Close;
  end;
end.
