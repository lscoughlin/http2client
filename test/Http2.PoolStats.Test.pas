/// Pull-based pool statistics (doc/design/request-observability.md
/// "Pull-based pool statistics").
// - the mock socket answers each request with a headers-only response while a
//   worker holds it, so a stream stays registered and the caps bind; the
//   snapshot is then compared with what the pool enforces.
// - waits are bounded and event-driven; the only timed delay is the one the
//   idle-time case measures.
unit Http2.PoolStats.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, SyncObjs, Generics.Collections, fpcunit, testregistry,
  Http2.Errors, Http2.Frames, Http2.Tls, Http2.Connection, Http2.Stream,
  Http2.Messages, Http2.Proxy, Http2.Client, Http2.MockSocket,
  Http2.ProxyClient.Test;

type
  /// a mock factory whose server SETTINGS carry distinctive values, answering
  /// every request with a body-less 200
  TSettingsMockFactory = class(TInterfacedObject, IHttp2SocketFactory)
  private
    FLock: TCriticalSection;
    FKeepAlive: TList<IHttp2Socket>;
    FEndStream: Boolean;
  public
    constructor Create(const AEndStream: Boolean);
    destructor Destroy; override;
    function Dial(const AHost: string; const APort: Word;
      const ATimeoutMs: Integer): IHttp2Socket;
  end;

  /// one Send that keeps its response until released, so the stream stays
  /// registered while the test takes a snapshot
  THoldWorker = class(TThread)
  private
    FClient: IHttpClient;
    FUrl: string;
    FGot: PRTLEvent;
    FRelease: PRTLEvent;
    FDone: PRTLEvent;
    FRaised: Boolean;
  protected
    procedure Execute; override;
  public
    constructor Create(const AClient: IHttpClient; const AUrl: string);
    destructor Destroy; override;
    function WaitGot(const ATimeoutMs: Integer): Boolean;
    function WaitDone(const ATimeoutMs: Integer): Boolean;
    procedure Release;
    property Raised: Boolean read FRaised;
  end;

  /// sends ACount requests in a row, reading every body
  TLoopWorker = class(TThread)
  private
    FClient: IHttpClient;
    FCount: Integer;
    FRaised: Boolean;
  protected
    procedure Execute; override;
  public
    constructor Create(const AClient: IHttpClient; const ACount: Integer);
    property Raised: Boolean read FRaised;
  end;

  /// calls PoolStats until told to stop
  TPollWorker = class(TThread)
  private
    FClient: THttpClient;
    FStop: Boolean;
    FRaised: Boolean;
    FPolls: Integer;
  protected
    procedure Execute; override;
  public
    constructor Create(const AClient: THttpClient);
    procedure Stop;
    property Raised: Boolean read FRaised;
    property Polls: Integer read FPolls;
  end;

  /// an HTTP/1.1-shaped pooled entry: no TConnection behind it
  TH1FakeConnection = class(TInterfacedObject, IPooledConnection)
  public
    function ActiveStreams: Integer;
    function Eligible: Boolean;
    function Acquire(const ARequest: TStreamRequest; const ATimeoutMs: Integer;
      out AAcquired: Boolean): IHttpResponse;
    function AcquireUpgraded(const ARequest: TStreamRequest;
      const ATimeoutMs: Integer): IHttpResponse;
    function Closed: Boolean;
    procedure Drain;
    procedure ReleaseIfIdle;
    function GetConn: TConnection;
    function GetOrigin: string;
    function GetLock: TCriticalSection;
    function GetKey: Pointer;
  end;

  TPoolStatsTest = class(TTestCase)
  private
    function WaitPending(const AClient: THttpClient;
      const AWant: Integer): Boolean;
  published
    procedure TestDefaultSnapshotIsAllZeros;
    procedure TestCountsMatchTheCapsUnderLoad;
    procedure TestDirectAndProxiedRoutesAreSeparateEntries;
    procedure TestConnectionReportsPeerSettingsAndState;
    procedure TestIdleConnectionReportsIdleTime;
    procedure TestHttp1EntryReportsZeroSettings;
    procedure TestClosedClientReturnsZeros;
    procedure TestPollingFromFourThreadsDuringRequests;
  end;

implementation

const
  cWaitMs = 10000;
  cPeerStreams = 7;
  cPeerWindow = 32768;
  cPeerFrame = 20000;

{ TSettingsMockFactory }

constructor TSettingsMockFactory.Create(const AEndStream: Boolean);
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FKeepAlive := TList<IHttp2Socket>.Create;
  FEndStream := AEndStream;
end;

destructor TSettingsMockFactory.Destroy;
begin
  FKeepAlive.Free;
  FLock.Free;
  inherited Destroy;
end;

function TSettingsMockFactory.Dial(const AHost: string; const APort: Word;
  const ATimeoutMs: Integer): IHttp2Socket;
var
  S: TMockSocket;
  Settings: TConnectionSettings;
begin
  S := TMockSocket.Create;
  S.AutoRespondToRequestHeaders('200', nil, FEndStream);
  Settings := TConnectionSettings.Defaults;
  Settings.MaxConcurrentStreams := cPeerStreams;
  Settings.InitialWindowSize := cPeerWindow;
  Settings.MaxFrameSize := cPeerFrame;
  S.EnqueueSettings(Settings);
  Result := S;
  FLock.Acquire;
  try
    FKeepAlive.Add(Result);
  finally
    FLock.Release;
  end;
end;

{ THoldWorker }

constructor THoldWorker.Create(const AClient: IHttpClient; const AUrl: string);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FClient := AClient;
  FUrl := AUrl;
  FGot := RTLEventCreate;
  FRelease := RTLEventCreate;
  FDone := RTLEventCreate;
end;

destructor THoldWorker.Destroy;
begin
  RTLEventDestroy(FGot);
  RTLEventDestroy(FRelease);
  RTLEventDestroy(FDone);
  inherited Destroy;
end;

procedure THoldWorker.Execute;
var
  R: IHttpResponse;
begin
  try
    R := FClient.Send(THttpRequest.Create(hmGet, FUrl));
    RTLEventSetEvent(FGot);
    RTLEventWaitFor(FRelease, cWaitMs);
    R := nil;
  except
    FRaised := True;
    RTLEventSetEvent(FGot);
  end;
  RTLEventSetEvent(FDone);
end;

function THoldWorker.WaitGot(const ATimeoutMs: Integer): Boolean;
begin
  RTLEventWaitFor(FGot, ATimeoutMs);
  Result := not FRaised;
end;

function THoldWorker.WaitDone(const ATimeoutMs: Integer): Boolean;
begin
  RTLEventWaitFor(FDone, ATimeoutMs);
  Result := Finished;
end;

procedure THoldWorker.Release;
begin
  RTLEventSetEvent(FRelease);
end;

{ TLoopWorker }

constructor TLoopWorker.Create(const AClient: IHttpClient;
  const ACount: Integer);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FClient := AClient;
  FCount := ACount;
end;

procedure TLoopWorker.Execute;
var
  I: Integer;
  R: IHttpResponse;
begin
  try
    for I := 1 to FCount do
    begin
      R := FClient.Send(THttpRequest.Create(hmGet, 'https://api.example/x'));
      ReadAllBodyBytes(R.Body);
      R := nil;
    end;
  except
    FRaised := True;
  end;
end;

{ TPollWorker }

constructor TPollWorker.Create(const AClient: THttpClient);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FClient := AClient;
end;

procedure TPollWorker.Execute;
var
  S: TPoolStats;
begin
  try
    while not FStop do
    begin
      S := FClient.PoolStats;
      if (S.Connections < 0) or (S.PendingAcquires < 0) then
        FRaised := True;
      Inc(FPolls);
    end;
  except
    FRaised := True;
  end;
end;

procedure TPollWorker.Stop;
begin
  FStop := True;
end;

{ TH1FakeConnection }

function TH1FakeConnection.ActiveStreams: Integer;
begin
  Result := 0;
end;

function TH1FakeConnection.Eligible: Boolean;
begin
  Result := True;
end;

function TH1FakeConnection.Acquire(const ARequest: TStreamRequest;
  const ATimeoutMs: Integer; out AAcquired: Boolean): IHttpResponse;
begin
  AAcquired := False;
  Result := nil;
end;

function TH1FakeConnection.AcquireUpgraded(const ARequest: TStreamRequest;
  const ATimeoutMs: Integer): IHttpResponse;
begin
  Result := nil;
end;

function TH1FakeConnection.Closed: Boolean;
begin
  Result := False;
end;

procedure TH1FakeConnection.Drain;
begin
end;

procedure TH1FakeConnection.ReleaseIfIdle;
begin
end;

function TH1FakeConnection.GetConn: TConnection;
begin
  Result := nil;
end;

function TH1FakeConnection.GetOrigin: string;
begin
  Result := 'h1.example';
end;

function TH1FakeConnection.GetLock: TCriticalSection;
begin
  Result := nil;
end;

function TH1FakeConnection.GetKey: Pointer;
begin
  Result := Pointer(Self);
end;

{ TPoolStatsTest }

function TPoolStatsTest.WaitPending(const AClient: THttpClient;
  const AWant: Integer): Boolean;
var
  Tick: PRTLEvent;
  Waited: Integer;
begin
  // bounded poll: nothing signals "a caller parked", so re-read the snapshot
  Tick := RTLEventCreate;
  try
    Waited := 0;
    while AClient.PoolStats.PendingAcquires <> AWant do
    begin
      if Waited >= cWaitMs then
        Exit(False);
      RTLEventWaitFor(Tick, 5);
      Inc(Waited, 5);
    end;
    Result := True;
  finally
    RTLEventDestroy(Tick);
  end;
end;

procedure TPoolStatsTest.TestDefaultSnapshotIsAllZeros;
var
  S: TPoolStats;
  O: TOriginStats;
  D: TConnectionStats;
begin
  S := Default(TPoolStats);
  AssertEquals(0, S.Connections);
  AssertEquals(0, S.IdleConnections);
  AssertEquals(0, S.ActiveStreams);
  AssertEquals(0, S.PendingAcquires);
  AssertEquals(0, Length(S.PerOrigin));
  O := Default(TOriginStats);
  AssertEquals('', O.Origin);
  AssertEquals(0, O.Connections);
  AssertEquals(0, Length(O.Details));
  D := Default(TConnectionStats);
  AssertEquals(0, D.AgeMs);
  AssertEquals(0, D.IdleMs);
  AssertEquals(0, D.ActiveStreams);
  AssertEquals(0, Integer(D.PeerMaxConcurrentStreams));
end;

procedure TPoolStatsTest.TestCountsMatchTheCapsUnderLoad;
var
  Client: IHttpClient;
  Http: THttpClient;
  Workers: array[0..4] of THoldWorker;
  I: Integer;
  S: TPoolStats;
begin
  Client := THttpClientFactory.Create
    .WithSocketFactory(TSettingsMockFactory.Create(False))
    .WithMaxConnections(2)
    .WithMaxStreamsPerConnection(1)
    .WithHeaderTimeout(cWaitMs)
    .Build;
  Http := Client as THttpClient;
  for I := 0 to High(Workers) do
  begin
    Workers[I] := THoldWorker.Create(Client, 'https://api.example/x');
    Workers[I].Start;
  end;
  AssertTrue('three callers park behind the two connections',
    WaitPending(Http, 3));
  S := Http.PoolStats;
  AssertEquals('connections at the cap', 2, S.Connections);
  AssertEquals('every connection is busy', 0, S.IdleConnections);
  AssertEquals('one stream each', 2, S.ActiveStreams);
  AssertEquals('pending acquires', 3, S.PendingAcquires);
  AssertEquals('one origin', 1, Length(S.PerOrigin));
  AssertEquals('api.example', S.PerOrigin[0].Origin);
  AssertEquals(2, Length(S.PerOrigin[0].Details));
  AssertEquals(3, S.PerOrigin[0].PendingAcquires);

  for I := 0 to High(Workers) do
    Workers[I].Release;
  for I := 0 to High(Workers) do
  begin
    AssertTrue('worker finished', Workers[I].WaitDone(cWaitMs));
    AssertFalse('worker did not raise', Workers[I].Raised);
  end;
  S := Http.PoolStats;
  AssertEquals('no one is parked at the end', 0, S.PendingAcquires);
  AssertEquals('still at most two connections', 2, S.Connections);
  for I := 0 to High(Workers) do
    Workers[I].Free;
  Client.Close;
end;

procedure TPoolStatsTest.TestDirectAndProxiedRoutesAreSeparateEntries;
var
  Factory: TMockSocketFactory;
  FactoryRef: IHttp2SocketFactory;
  Sel: TRecordingSelector;
  Client: IHttpClient;
  S: TPoolStats;
begin
  Factory := TMockSocketFactory.Create;
  FactoryRef := Factory;
  Factory.SetResponse('200', nil, True);
  Sel := TRecordingSelector.Create;
  Sel.ProxiedMarker := '/via';
  Sel.ProxyHost := 'sel.corp';
  Sel.ProxyPort := 7;
  Client := THttpClientFactory.Create.WithSocketFactory(FactoryRef)
    .WithProxySelector(Sel).Build;
  AssertEquals(200, Client.Send(
    THttpRequest.Create(hmGet, 'https://a.example/direct')).StatusCode);
  AssertEquals(200, Client.Send(
    THttpRequest.Create(hmGet, 'https://a.example/via')).StatusCode);
  S := (Client as THttpClient).PoolStats;
  AssertEquals('two entries', 2, Length(S.PerOrigin));
  AssertEquals('a.example', S.PerOrigin[0].Origin);
  AssertEquals('a.example via sel.corp:7', S.PerOrigin[1].Origin);
  AssertEquals(1, S.PerOrigin[0].Connections);
  AssertEquals(1, S.PerOrigin[1].Connections);
  AssertEquals('totals add up', 2, S.Connections);
  Client.Close;
end;

procedure TPoolStatsTest.TestConnectionReportsPeerSettingsAndState;
var
  Client: IHttpClient;
  R: IHttpResponse;
  S: TPoolStats;
  D: TConnectionStats;
begin
  Client := THttpClientFactory.Create
    .WithSocketFactory(TSettingsMockFactory.Create(False)).Build;
  R := Client.Send(THttpRequest.Create(hmGet, 'https://api.example/x'));
  S := (Client as THttpClient).PoolStats;
  AssertEquals(1, Length(S.PerOrigin));
  AssertEquals(1, Length(S.PerOrigin[0].Details));
  D := S.PerOrigin[0].Details[0];
  AssertEquals('protocol', Ord(npHttp2Tls), Ord(D.Protocol));
  AssertEquals('state', Ord(csOpen), Ord(D.State));
  AssertEquals('the held stream', 1, D.ActiveStreams);
  AssertEquals('peer streams', cPeerStreams, Integer(D.PeerMaxConcurrentStreams));
  AssertEquals('peer window', cPeerWindow, Integer(D.PeerInitialWindowSize));
  AssertEquals('peer frame', cPeerFrame, Integer(D.PeerMaxFrameSize));
  AssertEquals('a busy connection has no idle time', 0, D.IdleMs);
  R := nil;
  Client.Close;
end;

procedure TPoolStatsTest.TestIdleConnectionReportsIdleTime;
var
  Client: IHttpClient;
  Http: THttpClient;
  Delay: PRTLEvent;
  S: TPoolStats;
  D: TConnectionStats;
begin
  Client := THttpClientFactory.Create
    .WithSocketFactory(TSettingsMockFactory.Create(True)).Build;
  Http := Client as THttpClient;
  ReadAllBodyBytes(Client.Send(
    THttpRequest.Create(hmGet, 'https://api.example/x')).Body);
  // the stream is released, so the connection is idle; let 50 ms pass
  Delay := RTLEventCreate;
  try
    RTLEventWaitFor(Delay, 50);
  finally
    RTLEventDestroy(Delay);
  end;
  S := Http.PoolStats;
  AssertEquals(1, S.Connections);
  AssertEquals('idle connection counted', 1, S.IdleConnections);
  D := S.PerOrigin[0].Details[0];
  AssertEquals('no active streams', 0, D.ActiveStreams);
  AssertTrue('idle for at least 40 ms, got ' + IntToStr(D.IdleMs),
    D.IdleMs >= 40);
  AssertTrue('idle for under 200 ms, got ' + IntToStr(D.IdleMs),
    D.IdleMs <= 200);
  AssertTrue('age covers the idle time', D.AgeMs >= D.IdleMs);
  Client.Close;
end;

procedure TPoolStatsTest.TestHttp1EntryReportsZeroSettings;
var
  Client: IHttpClient;
  S: TPoolStats;
  D: TConnectionStats;
begin
  Client := THttpClientFactory.Create
    .WithSocketFactory(TSettingsMockFactory.Create(True)).Build;
  (Client as THttpClient).Pool.AddForTest('h1.example',
    TH1FakeConnection.Create);
  S := (Client as THttpClient).PoolStats;
  AssertEquals(1, S.Connections);
  AssertEquals(1, S.IdleConnections);
  D := S.PerOrigin[0].Details[0];
  AssertEquals('protocol', Ord(npHttp1Tls), Ord(D.Protocol));
  AssertEquals('state', Ord(csOpen), Ord(D.State));
  AssertEquals(0, Integer(D.PeerMaxConcurrentStreams));
  AssertEquals(0, Integer(D.PeerInitialWindowSize));
  AssertEquals(0, Integer(D.PeerMaxFrameSize));
  Client.Close;
end;

procedure TPoolStatsTest.TestClosedClientReturnsZeros;
var
  Client: IHttpClient;
  S: TPoolStats;
begin
  Client := THttpClientFactory.Create
    .WithSocketFactory(TSettingsMockFactory.Create(True)).Build;
  ReadAllBodyBytes(Client.Send(
    THttpRequest.Create(hmGet, 'https://api.example/x')).Body);
  AssertEquals(1, (Client as THttpClient).PoolStats.Connections);
  Client.Close;
  S := (Client as THttpClient).PoolStats;
  AssertEquals(0, S.Connections);
  AssertEquals(0, S.IdleConnections);
  AssertEquals(0, S.ActiveStreams);
  AssertEquals(0, S.PendingAcquires);
  AssertEquals(0, Length(S.PerOrigin));
end;

procedure TPoolStatsTest.TestPollingFromFourThreadsDuringRequests;
var
  Client: IHttpClient;
  Pollers: array[0..3] of TPollWorker;
  Senders: array[0..9] of TLoopWorker;
  I: Integer;
begin
  Client := THttpClientFactory.Create
    .WithSocketFactory(TSettingsMockFactory.Create(True))
    .WithHeaderTimeout(cWaitMs).Build;
  for I := 0 to High(Pollers) do
  begin
    Pollers[I] := TPollWorker.Create(Client as THttpClient);
    Pollers[I].Start;
  end;
  for I := 0 to High(Senders) do
  begin
    Senders[I] := TLoopWorker.Create(Client, 10);
    Senders[I].Start;
  end;
  for I := 0 to High(Senders) do
  begin
    Senders[I].WaitFor;
    AssertFalse('sender raised', Senders[I].Raised);
  end;
  for I := 0 to High(Pollers) do
  begin
    Pollers[I].Stop;
    Pollers[I].WaitFor;
    AssertFalse('poller raised', Pollers[I].Raised);
    AssertTrue('poller ran', Pollers[I].Polls > 0);
  end;
  for I := 0 to High(Senders) do
    Senders[I].Free;
  for I := 0 to High(Pollers) do
    Pollers[I].Free;
  Client.Close;
end;

initialization
  RegisterTest(TPoolStatsTest);
end.
