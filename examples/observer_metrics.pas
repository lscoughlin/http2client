/// http2client example adapter: metrics over IHttpClientObserver.
// - this unit is NOT part of the library.  It shows how a consumer derives
//   metrics from THttpOutcome, from the per-message seam and from
//   THttpClient.PoolStats.  The registry is a small in-memory stand-in for a
//   metrics library (Prometheus, OpenTelemetry metrics): counters and gauges
//   with a label string, histograms with fixed buckets, collectors that run at
//   collection time.  Nothing is exported.
// - the derived numbers follow the table "Metrics an adapter derives" in
//   doc/design/request-observability.md.  They are histograms named
//   `http_<kind>_<metric>` (kind: request, sse or websocket), so a six-hour
//   event stream never lands in the request-latency histogram.
// - the per-event histogram is opt-in: the adapter is an IHttpMessageObserver
//   whose WantsMessages answers an empty set while PerEvent is False, so the
//   library builds no per-message record for the attempt.
unit observer_metrics;

{$mode delphi}{$H+}
{$interfaces com}

interface

uses
  SysUtils, Classes, SyncObjs, Generics.Collections,
  Http2.Client, Http2.RequestObserver;

type
  /// a monotonic count per label set; a label is a preformatted string such as
  /// 'kind="request",status="200"' ('' for none)
  TCounter = class
  private
    FLock: TCriticalSection;
    FValues: TDictionary<string, Int64>;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Inc(const ALabels: string = ''; const ABy: Int64 = 1);
    function Value(const ALabels: string = ''): Int64;
    /// the label sets seen so far, sorted
    function LabelSets: TStringList;
  end;

  TGauge = class
  private
    FLock: TCriticalSection;
    FValue: Double;
  public
    constructor Create;
    destructor Destroy; override;
    procedure SetValue(const AValue: Double);
    procedure Inc;
    procedure Dec;
    function Value: Double;
  end;

  /// fixed upper bounds (a value goes to the first bound it does not exceed)
  /// and one overflow bucket; the counts are per bucket, not cumulative
  THistogram = class
  private
    FLock: TCriticalSection;
    FBounds: TArray<Double>;
    FCounts: TArray<Int64>;
    FCount: Int64;
    FSum, FMax: Double;
  public
    constructor Create(const ABounds: array of Double);
    destructor Destroy; override;
    procedure Observe(const AValue: Double);
    function Count: Int64;
    function Sum: Double;
    function Max: Double;
    /// the number of buckets, the overflow bucket included
    function BucketCount: Integer;
    /// the upper bound of bucket AIndex; the overflow bucket has none
    function BoundAt(const AIndex: Integer): Double;
    function CountAt(const AIndex: Integer): Int64;
  end;

  TMetricRegistry = class;

  /// something that sets gauges when the registry is collected
  IMetricCollector = interface
    ['{4D6B7C10-5A3E-4E7B-9F52-3C1A8E0D2B02}']
    procedure Collect(const ARegistry: TMetricRegistry);
  end;

  TMetricRegistry = class
  private
    FLock: TCriticalSection;
    FCounters: TObjectDictionary<string, TCounter>;
    FGauges: TObjectDictionary<string, TGauge>;
    FHistograms: TObjectDictionary<string, THistogram>;
    FCollectors: TList<IMetricCollector>;
  public
    constructor Create;
    destructor Destroy; override;
    /// get or create
    function Counter(const AName: string): TCounter;
    function Gauge(const AName: string): TGauge;
    /// get or create; ABounds apply to the first call only
    function Histogram(const AName: string;
      const ABounds: array of Double): THistogram;
    function HasHistogram(const AName: string): Boolean;
    procedure AddCollector(const ACollector: IMetricCollector);
    /// run every collector once (one pull per cycle)
    procedure Collect;
    /// collect, then write every instrument as text, one line per sample
    procedure Dump(const AOut: TStrings);
  end;

  /// reads PoolStats once per collection and sets the pool gauges from that
  /// one snapshot.  PoolStats is on THttpClient, not on IHttpClient, so the
  /// adapter casts the client the factory built.
  TPoolStatsCollector = class(TInterfacedObject, IMetricCollector)
  private
    FClient: IHttpClient;
    FPool: THttpClient;
  public
    constructor Create(const AClient: IHttpClient);
    procedure Collect(const ARegistry: TMetricRegistry);
  end;

  /// the metrics adapter
  TMetricsObserver = class(TBaseRequestObserver, IHttpMessageObserver)
  private
    FRegistry: TMetricRegistry;
  public
    /// feed the inter-event histogram from SinceLastUs.  Read once per
    /// attempt (WantsMessages), so flip it between attempts.
    PerEvent: Boolean;
    constructor Create(const ARegistry: TMetricRegistry;
      const APerEvent: Boolean = False);
    function OnAttemptStart(const A: THttpAttempt): IInterface; override;
    procedure OnAttemptEnd(const AToken: IInterface;
      const O: THttpOutcome); override;
    function WantsMessages(const A: THttpAttempt): TMessageKinds;
    procedure OnMessage(const AToken: IInterface; const M: TMessageInfo);
  end;

const
  /// microsecond bounds for latency-shaped histograms
  cLatencyBoundsUs: array[0..9] of Double = (100, 500, 1000, 5000, 10000,
    50000, 100000, 500000, 1000000, 5000000);

/// the name of the derived histogram: http_<kind>_<metric>
function MetricName(const AKind: TAttemptKind; const AMetric: string): string;

/// the histogram of gaps between consecutive events (SSE) or inbound messages
/// (WebSocket), fed only while PerEvent is on
function GapHistogramName(const AKind: TAttemptKind): string;

implementation

type
  /// what the adapter keeps per attempt
  TMetricsToken = class(TInterfacedObject)
  public
    Kind: TAttemptKind;
  end;

function KindLabel(const AKind: TAttemptKind): string;
begin
  case AKind of
    akSse: Result := 'sse';
    akWebSocket: Result := 'websocket';
  else
    Result := 'request';
  end;
end;

function MetricName(const AKind: TAttemptKind; const AMetric: string): string;
begin
  Result := 'http_' + KindLabel(AKind) + '_' + AMetric;
end;

function GapHistogramName(const AKind: TAttemptKind): string;
begin
  Result := MetricName(AKind, 'message_gap_us');
end;

{ TCounter }

constructor TCounter.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FValues := TDictionary<string, Int64>.Create;
end;

destructor TCounter.Destroy;
begin
  FValues.Free;
  FLock.Free;
  inherited Destroy;
end;

procedure TCounter.Inc(const ALabels: string; const ABy: Int64);
var
  V: Int64;
begin
  FLock.Acquire;
  try
    if not FValues.TryGetValue(ALabels, V) then
      V := 0;
    FValues.AddOrSetValue(ALabels, V + ABy);
  finally
    FLock.Release;
  end;
end;

function TCounter.Value(const ALabels: string): Int64;
begin
  FLock.Acquire;
  try
    if not FValues.TryGetValue(ALabels, Result) then
      Result := 0;
  finally
    FLock.Release;
  end;
end;

function TCounter.LabelSets: TStringList;
var
  K: string;
begin
  Result := TStringList.Create;
  FLock.Acquire;
  try
    for K in FValues.Keys do
      Result.Add(K);
  finally
    FLock.Release;
  end;
  Result.Sort;
end;

{ TGauge }

constructor TGauge.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
end;

destructor TGauge.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

procedure TGauge.SetValue(const AValue: Double);
begin
  FLock.Acquire;
  try
    FValue := AValue;
  finally
    FLock.Release;
  end;
end;

procedure TGauge.Inc;
begin
  FLock.Acquire;
  try
    FValue := FValue + 1;
  finally
    FLock.Release;
  end;
end;

procedure TGauge.Dec;
begin
  FLock.Acquire;
  try
    FValue := FValue - 1;
  finally
    FLock.Release;
  end;
end;

function TGauge.Value: Double;
begin
  FLock.Acquire;
  try
    Result := FValue;
  finally
    FLock.Release;
  end;
end;

{ THistogram }

constructor THistogram.Create(const ABounds: array of Double);
var
  I: Integer;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  SetLength(FBounds, Length(ABounds));
  for I := 0 to High(ABounds) do
    FBounds[I] := ABounds[I];
  SetLength(FCounts, Length(ABounds) + 1);
end;

destructor THistogram.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

procedure THistogram.Observe(const AValue: Double);
var
  I: Integer;
begin
  FLock.Acquire;
  try
    I := 0;
    while (I < Length(FBounds)) and (AValue > FBounds[I]) do
      System.Inc(I);
    System.Inc(FCounts[I]);
    System.Inc(FCount);
    FSum := FSum + AValue;
    if (FCount = 1) or (AValue > FMax) then
      FMax := AValue;
  finally
    FLock.Release;
  end;
end;

function THistogram.Count: Int64;
begin
  FLock.Acquire;
  try
    Result := FCount;
  finally
    FLock.Release;
  end;
end;

function THistogram.Sum: Double;
begin
  FLock.Acquire;
  try
    Result := FSum;
  finally
    FLock.Release;
  end;
end;

function THistogram.Max: Double;
begin
  FLock.Acquire;
  try
    Result := FMax;
  finally
    FLock.Release;
  end;
end;

function THistogram.BucketCount: Integer;
begin
  Result := Length(FCounts);
end;

function THistogram.BoundAt(const AIndex: Integer): Double;
begin
  Result := FBounds[AIndex];
end;

function THistogram.CountAt(const AIndex: Integer): Int64;
begin
  FLock.Acquire;
  try
    Result := FCounts[AIndex];
  finally
    FLock.Release;
  end;
end;

{ TMetricRegistry }

constructor TMetricRegistry.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FCounters := TObjectDictionary<string, TCounter>.Create([doOwnsValues]);
  FGauges := TObjectDictionary<string, TGauge>.Create([doOwnsValues]);
  FHistograms := TObjectDictionary<string, THistogram>.Create([doOwnsValues]);
  FCollectors := TList<IMetricCollector>.Create;
end;

destructor TMetricRegistry.Destroy;
begin
  FCollectors.Free;
  FHistograms.Free;
  FGauges.Free;
  FCounters.Free;
  FLock.Free;
  inherited Destroy;
end;

function TMetricRegistry.Counter(const AName: string): TCounter;
begin
  FLock.Acquire;
  try
    if not FCounters.TryGetValue(AName, Result) then
    begin
      Result := TCounter.Create;
      FCounters.Add(AName, Result);
    end;
  finally
    FLock.Release;
  end;
end;

function TMetricRegistry.Gauge(const AName: string): TGauge;
begin
  FLock.Acquire;
  try
    if not FGauges.TryGetValue(AName, Result) then
    begin
      Result := TGauge.Create;
      FGauges.Add(AName, Result);
    end;
  finally
    FLock.Release;
  end;
end;

function TMetricRegistry.Histogram(const AName: string;
  const ABounds: array of Double): THistogram;
begin
  FLock.Acquire;
  try
    if not FHistograms.TryGetValue(AName, Result) then
    begin
      Result := THistogram.Create(ABounds);
      FHistograms.Add(AName, Result);
    end;
  finally
    FLock.Release;
  end;
end;

function TMetricRegistry.HasHistogram(const AName: string): Boolean;
begin
  FLock.Acquire;
  try
    Result := FHistograms.ContainsKey(AName);
  finally
    FLock.Release;
  end;
end;

procedure TMetricRegistry.AddCollector(const ACollector: IMetricCollector);
begin
  FLock.Acquire;
  try
    FCollectors.Add(ACollector);
  finally
    FLock.Release;
  end;
end;

procedure TMetricRegistry.Collect;
var
  Members: TArray<IMetricCollector>;
  I: Integer;
begin
  // run the collectors outside the lock: they create gauges
  FLock.Acquire;
  try
    Members := FCollectors.ToArray;
  finally
    FLock.Release;
  end;
  for I := 0 to High(Members) do
    Members[I].Collect(Self);
end;

function Num(const AValue: Double): string;
begin
  Result := FormatFloat('0.###', AValue);
end;

procedure TMetricRegistry.Dump(const AOut: TStrings);
var
  Names, Sets: TStringList;
  I, J: Integer;
  H: THistogram;
  Cum: Int64;
  C: TCounter;
  Le: string;
begin
  Collect;
  Names := TStringList.Create;
  try
    FLock.Acquire;
    try
      for Le in FCounters.Keys do
        Names.Add('c' + Le);
      for Le in FGauges.Keys do
        Names.Add('g' + Le);
      for Le in FHistograms.Keys do
        Names.Add('h' + Le);
    finally
      FLock.Release;
    end;
    Names.Sort;
    for I := 0 to Names.Count - 1 do
      case Names[I][1] of
        'c':
          begin
            C := Counter(Copy(Names[I], 2, MaxInt));
            Sets := C.LabelSets;
            try
              for J := 0 to Sets.Count - 1 do
                if Sets[J] = '' then
                  AOut.Add(Copy(Names[I], 2, MaxInt) + ' ' +
                    IntToStr(C.Value(Sets[J])))
                else
                  AOut.Add(Copy(Names[I], 2, MaxInt) + '{' + Sets[J] + '} ' +
                    IntToStr(C.Value(Sets[J])));
            finally
              Sets.Free;
            end;
          end;
        'g':
          AOut.Add(Copy(Names[I], 2, MaxInt) + ' ' +
            Num(Gauge(Copy(Names[I], 2, MaxInt)).Value));
        'h':
          begin
            H := Histogram(Copy(Names[I], 2, MaxInt), []);
            Cum := 0;
            for J := 0 to H.BucketCount - 1 do
            begin
              Cum := Cum + H.CountAt(J);
              if J < H.BucketCount - 1 then
                Le := Num(H.BoundAt(J))
              else
                Le := '+Inf';
              AOut.Add(Copy(Names[I], 2, MaxInt) + '_bucket{le="' + Le + '"} ' +
                IntToStr(Cum));
            end;
            AOut.Add(Copy(Names[I], 2, MaxInt) + '_sum ' + Num(H.Sum));
            AOut.Add(Copy(Names[I], 2, MaxInt) + '_count ' + IntToStr(H.Count));
          end;
      end;
  finally
    Names.Free;
  end;
end;

{ TPoolStatsCollector }

constructor TPoolStatsCollector.Create(const AClient: IHttpClient);
begin
  inherited Create;
  FClient := AClient;
  // raises EInvalidCast for a client that is not the library's own
  FPool := AClient as THttpClient;
end;

procedure TPoolStatsCollector.Collect(const ARegistry: TMetricRegistry);
var
  S: TPoolStats;
begin
  // one snapshot per cycle; the totals are read, the per-connection detail
  // (which allocates) is ignored
  S := FPool.PoolStats;
  ARegistry.Gauge('http_pool_connections').SetValue(S.Connections);
  ARegistry.Gauge('http_pool_idle_connections').SetValue(S.IdleConnections);
  ARegistry.Gauge('http_pool_active_streams').SetValue(S.ActiveStreams);
  ARegistry.Gauge('http_pool_pending_acquires').SetValue(S.PendingAcquires);
end;

{ TMetricsObserver }

constructor TMetricsObserver.Create(const ARegistry: TMetricRegistry;
  const APerEvent: Boolean);
begin
  inherited Create;
  FRegistry := ARegistry;
  PerEvent := APerEvent;
end;

function TMetricsObserver.OnAttemptStart(const A: THttpAttempt): IInterface;
var
  T: TMetricsToken;
begin
  T := TMetricsToken.Create;
  T.Kind := A.Kind;
  FRegistry.Gauge('http_client_in_flight').Inc;
  Result := T;
end;

procedure TMetricsObserver.OnAttemptEnd(const AToken: IInterface;
  const O: THttpOutcome);
var
  Kind: TAttemptKind;
  SinceRequest: Int64;
  Span: Int64;

  procedure Hist(const AMetric: string; const AValue: Double);
  begin
    FRegistry.Histogram(MetricName(Kind, AMetric), cLatencyBoundsUs)
      .Observe(AValue);
  end;

begin
  Kind := akRequest;
  if AToken is TMetricsToken then
    Kind := (AToken as TMetricsToken).Kind;
  FRegistry.Gauge('http_client_in_flight').Dec;
  FRegistry.Counter('http_client_requests_total').Inc(
    'kind="' + KindLabel(Kind) + '",status="' + IntToStr(O.StatusCode) + '"');
  if O.Abandoned then
    FRegistry.Counter('http_client_abandoned_total').Inc(
      'kind="' + KindLabel(Kind) + '"');
  if O.Error <> nil then
    FRegistry.Counter('http_client_errors_total').Inc(
      'kind="' + KindLabel(Kind) + '",type="' + O.Error.ClassName + '"');

  // the derived numbers, from the table in the design note
  Hist('total_us', O.EndUs);
  Hist('request_bytes', O.BytesOut);
  if O.HeadersUs > 0 then
    Hist('ttfb_us', O.HeadersUs - O.RequestSentUs);
  if O.MessagesIn > 0 then
  begin
    SinceRequest := O.FirstMessageUs - O.RequestSentUs;
    Hist('first_message_us', SinceRequest);
  end;
  if O.MessagesIn > 1 then
  begin
    Span := O.LastMessageUs - O.FirstMessageUs;
    Hist('mean_gap_us', O.SumGapUs / (O.MessagesIn - 1));
    Hist('max_gap_us', O.MaxGapUs);
    Hist('stream_duration_us', Span);
    if Span > 0 then
      Hist('message_rate_per_s', (O.MessagesIn - 1) * 1000000.0 / Span);
  end;
  if (O.BytesIn > 0) and (O.HeadersUs > 0) and (O.EndUs > O.HeadersUs) then
    Hist('byte_rate_per_s', O.BytesIn * 1000000.0 / (O.EndUs - O.HeadersUs));
end;

function TMetricsObserver.WantsMessages(const A: THttpAttempt): TMessageKinds;
begin
  Result := [];
  if not PerEvent then
    Exit;
  case A.Kind of
    akSse: Result := [mkSseEvent];
    akWebSocket: Result := [mkWsText, mkWsBinary];
  end;
end;

procedure TMetricsObserver.OnMessage(const AToken: IInterface;
  const M: TMessageInfo);
var
  Kind: TAttemptKind;
begin
  // the first message of a direction has no gap
  if (M.Direction <> mdIn) or (M.Index = 0) then
    Exit;
  if M.Kind = mkSseEvent then
    Kind := akSse
  else
    Kind := akWebSocket;
  FRegistry.Histogram(GapHistogramName(Kind), cLatencyBoundsUs)
    .Observe(M.SinceLastUs);
end;

end.
