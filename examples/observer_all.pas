/// http2client example: the tracing, metrics and logging adapters together.
// - build: `make examples`
// - run:   against the reference fixtures in tools/validate (cleartext, so the
//          h2c-upgrade policy is enabled for http:// and ws:// URLs):
//            python3 tools/validate/sse_server.py --port 8091 &
//            python3 tools/validate/ws_servers.py --log /tmp/ws.log --plain-port 8601 &
//            bin/observer_all http://127.0.0.1:8091 ws://127.0.0.1:8601/echo
//          (both arguments are optional and default to those addresses)
// - shows: THttpClientFactory.WithRequestObserver installing three adapters
//   side by side (examples/observer_tracing.pas, observer_metrics.pas and
//   observer_logging.pas), the caller's span travelling in WithContext, and
//   one run of each kind of attempt: a plain request, an SSE stream that
//   reconnects, and a WebSocket session.  It prints one trace, the derived
//   metrics and the log lines.  See doc/design/request-observability.md.
program example_observer_all;

{$mode delphi}{$H+}
{$interfaces com}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils, Classes, SyncObjs, Http2.Errors, Http2.Stream, Http2.Messages,
  Http2.Client, Http2.Tls, Http2.Sse, Http2.WebSocket, Http2.RequestObserver,
  observer_tracing, observer_metrics, observer_logging;

type
  /// sends one message, closes when the echo arrives, and signals the end
  TEchoOnce = class(TWebSocketListener)
  public
    Finished: TEvent;
    constructor Create;
    destructor Destroy; override;
    procedure OnOpen(const ASocket: IWebSocket); override;
    procedure OnText(const ASocket: IWebSocket; const AText: string;
      const ALast: Boolean); override;
    procedure OnClose(const ASocket: IWebSocket; const AStatusCode: Integer;
      const AReason: string); override;
    procedure OnError(const ASocket: IWebSocket;
      const AError: Exception); override;
  end;

constructor TEchoOnce.Create;
begin
  inherited Create;
  Finished := TEvent.Create(nil, True, False, '');
end;

destructor TEchoOnce.Destroy;
begin
  Finished.Free;
  inherited Destroy;
end;

procedure TEchoOnce.OnOpen(const ASocket: IWebSocket);
begin
  ASocket.Request(4);
  ASocket.SendText('hello');
end;

procedure TEchoOnce.OnText(const ASocket: IWebSocket; const AText: string;
  const ALast: Boolean);
begin
  ASocket.Close(1000, 'done');
end;

procedure TEchoOnce.OnClose(const ASocket: IWebSocket;
  const AStatusCode: Integer; const AReason: string);
begin
  Finished.SetEvent;
end;

procedure TEchoOnce.OnError(const ASocket: IWebSocket; const AError: Exception);
begin
  WriteLn(StdErr, 'websocket failed: ', AError.ClassName, ': ', AError.Message);
  Finished.SetEvent;
end;

/// read a body to its end and return how many bytes it held
function Drain(const AResponse: IHttpResponse): Int64;
var
  Buf: array[0..4095] of Byte;
  N: LongInt;
begin
  Result := 0;
  repeat
    N := AResponse.Body.Read(Buf, SizeOf(Buf));
    if N > 0 then
      Inc(Result, N);
  until N <= 0;
end;

function StatusText(const AStatus: TSpanStatus): string;
begin
  case AStatus of
    ssOk: Result := 'ok';
    ssError: Result := 'error';
  else
    Result := 'unset';
  end;
end;

/// the attempts end on whichever thread finishes them, so give the last ones a
/// moment before the trace is printed
function WaitForSpans(const ATracer: TTracer; const ATimeoutMs: Integer): Boolean;
var
  Deadline: QWord;
  I: Integer;
  AllEnded: Boolean;
begin
  Deadline := GetTickCount64 + QWord(ATimeoutMs);
  repeat
    AllEnded := True;
    // span 0 is the caller's own and ends when the caller is done
    for I := 1 to ATracer.Count - 1 do
      if not ATracer.SpanAt(I).Ended then
        AllEnded := False;
    if AllEnded then
      Exit(True);
    Sleep(10);
  until GetTickCount64 >= Deadline;
  Result := False;
end;

procedure PrintTrace(const ATracer: TTracer);
var
  I: Integer;
  S: ISpan;
begin
  WriteLn('== trace ==');
  for I := 0 to ATracer.Count - 1 do
  begin
    S := ATracer.SpanAt(I);
    Write('  ', S.Name, ' trace=', Copy(S.TraceId, 25, 8), ' span=', S.SpanId);
    if S.ParentSpanId <> '' then
      Write(' parent=', S.ParentSpanId);
    Write(' status=', StatusText(S.Status));
    if S.GetAttribute('http.response.status_code') <> '' then
      Write(' http=', S.GetAttribute('http.response.status_code'));
    if S.GetAttribute('sse.reconnect') <> '' then
      Write(' reconnect=', S.GetAttribute('sse.reconnect'));
    if S.StatusMessage <> '' then
      Write(' message=', S.StatusMessage);
    WriteLn;
  end;
end;

var
  Base, WsUrl: string;
  Tracer: TTracer;
  Registry: TMetricRegistry;
  Logger: TMemoryLogger;
  LoggerRef: IHttpLogger;
  Metrics: IHttpClientObserver;
  Factory: THttpClientFactory;
  Client: IHttpClient;
  Root: ISpan;
  R: IHttpResponse;
  Loop: TSseReconnectLoop;
  Event: TSseEvent;
  Echo: TEchoOnce;
  Listener: IWebSocketListener;
  Socket: IWebSocket;
  Lines: TStringList;
  Events: Integer;
begin
  Base := 'http://127.0.0.1:8091';
  WsUrl := 'ws://127.0.0.1:8601/echo';
  if ParamCount >= 1 then
    Base := ParamStr(1);
  if ParamCount >= 2 then
    WsUrl := ParamStr(2);

  Tracer := TTracer.Create;
  Registry := TMetricRegistry.Create;
  Logger := TMemoryLogger.Create;
  LoggerRef := Logger;
  Echo := TEchoOnce.Create;
  Listener := Echo;
  try
    // the tracer is registered first, so it wraps the others; the metrics
    // adapter has the per-event histogram switched on
    Metrics := TMetricsObserver.Create(Registry, True);
    Factory := THttpClientFactory.Create
      .WithRequestObserver(TTracingObserver.Create(Tracer))
      .WithRequestObserver(Metrics)
      .WithRequestObserver(TLoggingObserver.Create(LoggerRef))
      .WithClearText(ctUpgrade).WithHttp1Fallback(True);
    Client := Factory.Build;
    Registry.AddCollector(TPoolStatsCollector.Create(Client));

    // the caller's own span: every attempt below becomes its child
    Root := Tracer.StartSpan('observer_all', nil);
    try
      // 1. a plain request: five events written 20 ms apart, read as a body
      R := Client.Send(THttpRequest.Create(hmGet,
        Base + '/cadence?interval_ms=20&count=5').WithContext(Root));
      WriteLn('plain request: status ', R.StatusCode, ', ', Drain(R), ' bytes');
      R := nil;

      // 2. an SSE stream: /events ends after one round, so the loop
      //    reconnects with last-event-id and the server answers the resume
      Loop := TSseReconnectLoop.Create(Client,
        SseRequest(Base + '/events').WithContext(Root), 3);
      try
        Events := 0;
        while Loop.Next(Event) do
        begin
          Inc(Events);
          if Event.Id = '4' then
            Break;
        end;
        WriteLn('sse: ', Events, ' events over ', Loop.StreamId, ' (stream id)');
        Loop.Close;
      finally
        Loop.Free;
      end;

      // 3. a WebSocket session
      Socket := Client.Send(TWebSocketRequest.Create(WsUrl, Listener)
        .WithContext(Root));
      if Echo.Finished.WaitFor(15000) <> wrSignaled then
      begin
        WriteLn(StdErr, 'no WebSocket answer within 15 seconds');
        Socket.Abort;
      end;
      Socket := nil;
    except
      on E: EHttpError do
        WriteLn(StdErr, 'failed: ', E.ClassName, ': ', E.Message);
    end;

    WaitForSpans(Tracer, 5000);
    Root.EndSpan;
    PrintTrace(Tracer);

    WriteLn('== metrics ==');
    Lines := TStringList.Create;
    try
      Registry.Dump(Lines);
      WriteLn(Lines.Text);
    finally
      Lines.Free;
    end;

    WriteLn('== log ==');
    Write(Logger.Text);
    Client.Close;
  finally
    Root := nil;
    Socket := nil;
    LoggerRef := nil;
    Registry.Free;
    Tracer.Free;
  end;
end.
