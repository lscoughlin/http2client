/// http2client example: what the request observers cost on loopback.
// - build and run: `make measure-observer`
//   or by hand:    bin/observer_overhead [requests-per-round [rounds]]
//   (defaults: 3000 requests in each of 3 rounds; the traffic is cleartext
//   HTTP/1.1, so there is no TLS handshake)
// - measures the wall time of one request with no observer, with the tracing,
//   metrics and logging adapters (examples/observer_*.pas) installed, and,
//   for an event stream, with the metrics adapter's per-event gate on.  It
//   starts a small HTTP/1.1 server on a loopback port of its own, so no
//   fixture is needed.  The method and the table are in
//   doc/verification/observer-overhead.md.
// - two workloads: a plain GET of a short body, and an event stream of 20
//   events (one chunked response read through TSseSource).
program example_observer_overhead;

{$mode delphi}{$H+}
{$interfaces com}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils, Classes, Sockets, BaseUnix, Generics.Collections, Generics.Defaults,
  Http2.Stream, Http2.Messages, Http2.Client, Http2.Clock, Http2.Tls, Http2.Sse,
  Http2.RequestObserver,
  observer_tracing, observer_metrics, observer_logging;

type
  TWorkload = (wlPlain, wlSse);
  TConfig = (cfNone, cfAdapters, cfAdaptersGate);

  /// a logger that only counts, so the logging adapter formats its lines
  /// without the run keeping them
  TCountingLogger = class(TInterfacedObject, IHttpLogger)
  public
    Lines: LongInt;
    procedure Log(const ALevel: TLogLevel; const AMessage: string);
  end;

  /// a keep-alive HTTP/1.1 server on a loopback port: /plain answers a
  /// five-byte body, /sse a chunked stream of 20 events.  One connection at a
  /// time is enough, because the measurement runs one client at a time.
  TLoopbackServer = class(TThread)
  private
    FListenFd: Integer;
    FPlain, FSse: AnsiString;
    procedure Serve(const AFd: Integer);
  protected
    procedure Execute; override;
  public
    Port: Word;
    property ListenFd: Integer read FListenFd;
    constructor Create;
    procedure Stop;
  end;

procedure TCountingLogger.Log(const ALevel: TLogLevel; const AMessage: string);
begin
  InterlockedIncrement(Lines);
end;

{ TLoopbackServer }

constructor TLoopbackServer.Create;
var
  Addr: TSockAddr;
  ALen, One, I: LongInt;
  Chunk: AnsiString;
begin
  inherited Create(True);
  FListenFd := fpsocket(AF_INET, SOCK_STREAM, 0);
  One := 1;
  fpSetSockOpt(FListenFd, SOL_SOCKET, SO_REUSEADDR, @One, SizeOf(One));
  FillChar(Addr, SizeOf(Addr), 0);
  Addr.sin_family := AF_INET;
  Addr.sin_port := htons(0);
  Addr.sin_addr.s_addr := htonl($7f000001);
  if (fpbind(FListenFd, @Addr, SizeOf(Addr)) <> 0) or
     (fplisten(FListenFd, 4) <> 0) then
    raise Exception.Create('cannot listen on loopback');
  ALen := SizeOf(Addr);
  fpgetsockname(FListenFd, @Addr, @ALen);
  Port := ntohs(Addr.sin_port);
  FPlain := 'HTTP/1.1 200 OK'#13#10'Content-Type: text/plain'#13#10 +
    'Content-Length: 5'#13#10#13#10'hello';
  // the 20 events go out in one write, as chunks of one event each
  Chunk := '';
  for I := 1 to 20 do
    Chunk := Chunk + '15'#13#10 + Format('id: %.2d'#10'data: tick%.2d'#10#10,
      [I, I]) + #13#10;
  FSse := 'HTTP/1.1 200 OK'#13#10'Content-Type: text/event-stream'#13#10 +
    'Transfer-Encoding: chunked'#13#10#13#10 + Chunk + '0'#13#10#13#10;
end;

procedure TLoopbackServer.Stop;
var
  Addr: TSockAddr;
  Fd: LongInt;
begin
  Terminate;
  // wake the accept: a connection that closes at once
  Fd := fpsocket(AF_INET, SOCK_STREAM, 0);
  FillChar(Addr, SizeOf(Addr), 0);
  Addr.sin_family := AF_INET;
  Addr.sin_port := htons(Port);
  Addr.sin_addr.s_addr := htonl($7f000001);
  fpconnect(Fd, @Addr, SizeOf(Addr));
  fpclose(Fd);
end;

procedure TLoopbackServer.Serve(const AFd: Integer);
var
  Buf: array[0..4095] of AnsiChar;
  Req, Resp: AnsiString;
  N, Sent, K: Integer;
begin
  Req := '';
  while not Terminated do
  begin
    // one request per read: the client waits for each response
    while Pos(#13#10#13#10, Req) = 0 do
    begin
      N := fprecv(AFd, @Buf[0], SizeOf(Buf), 0);
      if N <= 0 then
        Exit;
      SetLength(Req, Length(Req) + N);
      Move(Buf[0], Req[Length(Req) - N + 1], N);
    end;
    if Pos('GET /sse ', Req) = 1 then
      Resp := FSse
    else
      Resp := FPlain;
    Req := '';
    Sent := 0;
    while Sent < Length(Resp) do
    begin
      K := fpsend(AFd, @Resp[1 + Sent], Length(Resp) - Sent, 0);
      if K <= 0 then
        Exit;
      Inc(Sent, K);
    end;
  end;
end;

procedure TLoopbackServer.Execute;
var
  Fd, One: LongInt;
begin
  while not Terminated do
  begin
    Fd := fpaccept(FListenFd, nil, nil);
    if Fd < 0 then
      Break;
    One := 1;
    {$IFDEF DARWIN}
    fpSetSockOpt(Fd, SOL_SOCKET, SO_NOSIGPIPE, @One, SizeOf(One));
    {$ENDIF}
    fpSetSockOpt(Fd, IPPROTO_TCP, TCP_NODELAY, @One, SizeOf(One));
    try
      Serve(Fd);
    finally
      fpshutdown(Fd, SHUT_RDWR);
      fpclose(Fd);
    end;
  end;
end;

function WorkloadName(const AWorkload: TWorkload): string;
begin
  if AWorkload = wlPlain then
    Result := 'plain GET'
  else
    Result := 'SSE, 20 events';
end;

function ConfigName(const AConfig: TConfig): string;
begin
  case AConfig of
    cfNone: Result := 'no observer';
    cfAdapters: Result := 'tracing + metrics + logging';
  else
    Result := 'all three, per-event gate on';
  end;
end;

/// a client with the observers a configuration calls for; the tracer, registry
/// and logger it feeds are freed with the run
function BuildClient(const AConfig: TConfig; out ATracer: TTracer;
  out ARegistry: TMetricRegistry): IHttpClient;
var
  F: THttpClientFactory;
  Logger: TCountingLogger;
begin
  ATracer := nil;
  ARegistry := nil;
  F := THttpClientFactory.Create.WithClearText(ctHttp1);
  if AConfig <> cfNone then
  begin
    ATracer := TTracer.Create;
    ARegistry := TMetricRegistry.Create;
    Logger := TCountingLogger.Create;
    F := F.WithRequestObserver(TTracingObserver.Create(ATracer))
      .WithRequestObserver(TMetricsObserver.Create(ARegistry,
        AConfig = cfAdaptersGate))
      .WithRequestObserver(TLoggingObserver.Create(Logger));
  end;
  Result := F.Build;
end;

procedure RunOnce(const AClient: IHttpClient; const AWorkload: TWorkload;
  const APort: Word);
var
  Url: string;
  R: IHttpResponse;
  Src: IHttpSseSource;
  Ev: TSseEvent;
  Buf: array[0..1023] of Byte;
begin
  Url := 'http://127.0.0.1:' + IntToStr(APort);
  if AWorkload = wlPlain then
  begin
    R := AClient.Send(THttpRequest.Create(hmGet, Url + '/plain'));
    while R.Body.Read(Buf, SizeOf(Buf)) > 0 do ;
  end
  else
  begin
    R := AClient.Send(SseRequest(Url + '/sse'));
    Src := TSseSource.Create(R);
    while Src.ReadEvent(Ev) do ;
    Src := nil;
  end;
  R := nil;
end;

/// the per-request times of ACount requests, in microseconds, appended to
/// ASamples; the first AWarmup are run and dropped
procedure Measure(const AConfig: TConfig; const AWorkload: TWorkload;
  const APort: Word; const AWarmup, ACount: Integer;
  const ASamples: TList<Int64>);
var
  Client: IHttpClient;
  Tracer: TTracer;
  Registry: TMetricRegistry;
  I: Integer;
  T0: Int64;
begin
  Client := BuildClient(AConfig, Tracer, Registry);
  try
    for I := 1 to AWarmup do
      RunOnce(Client, AWorkload, APort);
    for I := 1 to ACount do
    begin
      T0 := NowUs;
      RunOnce(Client, AWorkload, APort);
      ASamples.Add(NowUs - T0);
    end;
  finally
    Client.Close;
    Client := nil;
    Registry.Free;
    Tracer.Free;
  end;
end;

function Percentile(const ASorted: TArray<Int64>; const AP: Double): Int64;
var
  K: Integer;
begin
  K := Trunc(AP * (Length(ASorted) - 1));
  Result := ASorted[K];
end;

var
  Server: TLoopbackServer;
  Count, Rounds, Round: Integer;
  W: TWorkload;
  C: TConfig;
  Samples: array[TWorkload, TConfig] of TList<Int64>;
  Sorted: TArray<Int64>;
  Sum: Int64;
  V: Int64;
  Mean, BaseMean: Double;
begin
  Count := 3000;
  Rounds := 3;
  if ParamCount >= 1 then
    Count := StrToIntDef(ParamStr(1), Count);
  if ParamCount >= 2 then
    Rounds := StrToIntDef(ParamStr(2), Rounds);
  for W := Low(TWorkload) to High(TWorkload) do
    for C := Low(TConfig) to High(TConfig) do
      Samples[W, C] := TList<Int64>.Create;
  Server := TLoopbackServer.Create;
  Server.Start;
  try
    WriteLn('observer overhead on loopback: ', Count, ' requests per round, ',
      Rounds, ' rounds, ', Server.Port, ' (server port)');
    // the configurations run in turn within a round, so a drifting machine
    // load touches every configuration alike
    for Round := 1 to Rounds do
      for W := Low(TWorkload) to High(TWorkload) do
        for C := Low(TConfig) to High(TConfig) do
        begin
          // the gate only matters for an event stream
          if (W = wlPlain) and (C = cfAdaptersGate) then
            Continue;
          Measure(C, W, Server.Port, 200, Count, Samples[W, C]);
        end;
    WriteLn;
    WriteLn('| workload | configuration | requests | mean us | p50 us | p99 us | ',
      'mean overhead us | mean overhead % |');
    WriteLn('|---|---|---|---|---|---|---|---|');
    for W := Low(TWorkload) to High(TWorkload) do
    begin
      BaseMean := 0;
      for C := Low(TConfig) to High(TConfig) do
      begin
        if Samples[W, C].Count = 0 then
          Continue;
        Samples[W, C].Sort;
        Sorted := Samples[W, C].ToArray;
        Sum := 0;
        for V in Sorted do
          Inc(Sum, V);
        Mean := Sum / Length(Sorted);
        if C = cfNone then
        begin
          BaseMean := Mean;
          WriteLn(Format('| %s | %s | %d | %.1f | %d | %d | - | - |',
            [WorkloadName(W), ConfigName(C), Length(Sorted), Mean,
             Percentile(Sorted, 0.5), Percentile(Sorted, 0.99)]));
        end
        else
          WriteLn(Format('| %s | %s | %d | %.1f | %d | %d | %.1f | %.1f |',
            [WorkloadName(W), ConfigName(C), Length(Sorted), Mean,
             Percentile(Sorted, 0.5), Percentile(Sorted, 0.99),
             Mean - BaseMean, (Mean - BaseMean) * 100 / BaseMean]));
      end;
    end;
  finally
    Server.Stop;
    Server.WaitFor;
    fpclose(Server.ListenFd);
    Server.Free;
    for W := Low(TWorkload) to High(TWorkload) do
      for C := Low(TConfig) to High(TConfig) do
        Samples[W, C].Free;
  end;
end.
