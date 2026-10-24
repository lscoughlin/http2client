/// http2client example adapter: tracing over IHttpClientObserver.
// - this unit is NOT part of the library.  It shows how a consumer turns the
//   request observer seam (src/Http2.RequestObserver.pas) into spans for a
//   tracer of its own (OpenTelemetry, say).  The tracer here is a small
//   in-memory stand-in: ids come from counters, spans are kept in a list, and
//   nothing is exported.
// - what the adapter does (doc/design/request-observability.md, "Writing an
//   adapter"):
//   * OnAttemptStart reads the parent span from A.Context, starts a client
//     span and injects a W3C `traceparent` through A.Headers.SetValue.  Every
//     attempt (a redirect hop, a transparent retry, an SSE reconnect, a
//     WebSocket session) is its own span, and all of them are siblings under
//     the caller's parent because they share A.Context.
//   * OnResponseHeaders records the status, OnRedirect and OnRetry add span
//     events, and OnAttemptEnd records the outcome, sets status and error and
//     ends the span.
// - registered first with WithRequestObserver, the tracer sees every header
//   the observers registered after it inject (start callbacks run in
//   registration order).
unit observer_tracing;

{$mode delphi}{$H+}
{$interfaces com}

interface

uses
  SysUtils, Classes, SyncObjs, Generics.Collections,
  Http2.Messages, Http2.RequestObserver;

type
  TSpanStatus = (ssUnset, ssOk, ssError);

  /// the stand-in for a tracer's span.  A caller puts one in WithContext to
  /// make it the parent of every attempt of the request.
  ISpan = interface
    ['{4D6B7C10-5A3E-4E7B-9F52-3C1A8E0D2B01}']
    function GetTraceId: string;
    function GetSpanId: string;
    function GetParentSpanId: string;
    function GetName: string;
    function GetStatus: TSpanStatus;
    function GetStatusMessage: string;
    function GetEnded: Boolean;
    procedure SetAttribute(const AName, AValue: string);
    /// the attribute's value, or '' when it was never set
    function GetAttribute(const AName: string): string;
    procedure AddEvent(const AText: string);
    function EventCount: Integer;
    function EventAt(const AIndex: Integer): string;
    procedure SetStatus(const AStatus: TSpanStatus; const AMessage: string = '');
    procedure EndSpan;
    /// the W3C trace-context header value naming this span
    function Traceparent: string;
    property TraceId: string read GetTraceId;
    property SpanId: string read GetSpanId;
    /// '' for a root span
    property ParentSpanId: string read GetParentSpanId;
    property Name: string read GetName;
    property Status: TSpanStatus read GetStatus;
    property StatusMessage: string read GetStatusMessage;
    property Ended: Boolean read GetEnded;
  end;

  /// an in-memory tracer: it hands out spans and remembers every one
  TTracer = class
  private
    FLock: TCriticalSection;
    FSpans: TList<ISpan>;
    FNextTrace: Int64;
    FNextSpan: Int64;
    function GetCount: Integer;
  public
    constructor Create;
    destructor Destroy; override;
    /// a span under AParent (same trace, AParent's span id as parent), or the
    /// root of a new trace when AParent is nil
    function StartSpan(const AName: string; const AParent: ISpan): ISpan;
    function SpanAt(const AIndex: Integer): ISpan;
    property Count: Integer read GetCount;
  end;

  /// the tracing adapter
  TTracingObserver = class(TBaseRequestObserver)
  private
    FTracer: TTracer;
    FRecordedHeaders: TStringList;
  public
    constructor Create(const ATracer: TTracer);
    destructor Destroy; override;
    /// put the request header AName on every span as
    /// `http.request.header.<name>`.  The value is read when the response
    /// headers arrive, after every start callback has run, so it includes what
    /// the observers registered after this one injected.  Call before the
    /// first request.
    procedure RecordRequestHeader(const AName: string);
    function OnAttemptStart(const A: THttpAttempt): IInterface; override;
    procedure OnResponseHeaders(const AToken: IInterface;
      const AResponse: IHttpResponse); override;
    procedure OnRedirect(const AToken: IInterface; const AFromUrl,
      AToUrl: string; const AStatus: LongInt); override;
    procedure OnRetry(const AToken: IInterface;
      const AReason: string); override;
    procedure OnAttemptEnd(const AToken: IInterface;
      const O: THttpOutcome); override;
  end;

/// the textual form of an attempt kind, as the adapters name it
function AttemptKindName(const AKind: TAttemptKind): string;

implementation

type
  /// what the adapter keeps per attempt: the span and the attempt's header
  /// sink, which stays readable after the start callbacks
  TTraceToken = class(TInterfacedObject)
  public
    Span: ISpan;
    Headers: IHeaderSink;
  end;

  TSpan = class(TInterfacedObject, ISpan)
  private
    FLock: TCriticalSection;
    FTraceId, FSpanId, FParentSpanId, FName: string;
    FAttributes: TStringList;
    FEvents: TStringList;
    FStatus: TSpanStatus;
    FStatusMessage: string;
    FEnded: Boolean;
  public
    constructor Create(const ATraceId, ASpanId, AParentSpanId, AName: string);
    destructor Destroy; override;
    function GetTraceId: string;
    function GetSpanId: string;
    function GetParentSpanId: string;
    function GetName: string;
    function GetStatus: TSpanStatus;
    function GetStatusMessage: string;
    function GetEnded: Boolean;
    procedure SetAttribute(const AName, AValue: string);
    function GetAttribute(const AName: string): string;
    procedure AddEvent(const AText: string);
    function EventCount: Integer;
    function EventAt(const AIndex: Integer): string;
    procedure SetStatus(const AStatus: TSpanStatus; const AMessage: string);
    procedure EndSpan;
    function Traceparent: string;
  end;

function AttemptKindName(const AKind: TAttemptKind): string;
begin
  case AKind of
    akSse: Result := 'sse';
    akWebSocket: Result := 'websocket';
  else
    Result := 'request';
  end;
end;

{ TSpan }

constructor TSpan.Create(const ATraceId, ASpanId, AParentSpanId, AName: string);
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FAttributes := TStringList.Create;
  FEvents := TStringList.Create;
  FTraceId := ATraceId;
  FSpanId := ASpanId;
  FParentSpanId := AParentSpanId;
  FName := AName;
end;

destructor TSpan.Destroy;
begin
  FEvents.Free;
  FAttributes.Free;
  FLock.Free;
  inherited Destroy;
end;

function TSpan.GetTraceId: string;
begin
  Result := FTraceId;
end;

function TSpan.GetSpanId: string;
begin
  Result := FSpanId;
end;

function TSpan.GetParentSpanId: string;
begin
  Result := FParentSpanId;
end;

function TSpan.GetName: string;
begin
  Result := FName;
end;

function TSpan.GetStatus: TSpanStatus;
begin
  Result := FStatus;
end;

function TSpan.GetStatusMessage: string;
begin
  Result := FStatusMessage;
end;

function TSpan.GetEnded: Boolean;
begin
  FLock.Acquire;
  try
    Result := FEnded;
  finally
    FLock.Release;
  end;
end;

procedure TSpan.SetAttribute(const AName, AValue: string);
begin
  FLock.Acquire;
  try
    FAttributes.Values[AName] := AValue;
  finally
    FLock.Release;
  end;
end;

function TSpan.GetAttribute(const AName: string): string;
begin
  FLock.Acquire;
  try
    Result := FAttributes.Values[AName];
  finally
    FLock.Release;
  end;
end;

procedure TSpan.AddEvent(const AText: string);
begin
  FLock.Acquire;
  try
    FEvents.Add(AText);
  finally
    FLock.Release;
  end;
end;

function TSpan.EventCount: Integer;
begin
  FLock.Acquire;
  try
    Result := FEvents.Count;
  finally
    FLock.Release;
  end;
end;

function TSpan.EventAt(const AIndex: Integer): string;
begin
  FLock.Acquire;
  try
    Result := FEvents[AIndex];
  finally
    FLock.Release;
  end;
end;

procedure TSpan.SetStatus(const AStatus: TSpanStatus; const AMessage: string);
begin
  FLock.Acquire;
  try
    FStatus := AStatus;
    FStatusMessage := AMessage;
  finally
    FLock.Release;
  end;
end;

procedure TSpan.EndSpan;
begin
  FLock.Acquire;
  try
    FEnded := True;
  finally
    FLock.Release;
  end;
end;

function TSpan.Traceparent: string;
begin
  // version 00, sampled
  Result := '00-' + FTraceId + '-' + FSpanId + '-01';
end;

{ TTracer }

constructor TTracer.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FSpans := TList<ISpan>.Create;
end;

destructor TTracer.Destroy;
begin
  FSpans.Free;
  FLock.Free;
  inherited Destroy;
end;

function TTracer.GetCount: Integer;
begin
  FLock.Acquire;
  try
    Result := FSpans.Count;
  finally
    FLock.Release;
  end;
end;

function TTracer.StartSpan(const AName: string; const AParent: ISpan): ISpan;
var
  TraceId, ParentId: string;
begin
  FLock.Acquire;
  try
    if AParent <> nil then
    begin
      TraceId := AParent.TraceId;
      ParentId := AParent.SpanId;
    end
    else
    begin
      // ids are counters here (never all zero, as W3C requires); a real
      // tracer draws them at random
      Inc(FNextTrace);
      TraceId := LowerCase(IntToHex(FNextTrace, 32));
      ParentId := '';
    end;
    Inc(FNextSpan);
    Result := TSpan.Create(TraceId, LowerCase(IntToHex(FNextSpan, 16)),
      ParentId, AName);
    FSpans.Add(Result);
  finally
    FLock.Release;
  end;
end;

function TTracer.SpanAt(const AIndex: Integer): ISpan;
begin
  FLock.Acquire;
  try
    Result := FSpans[AIndex];
  finally
    FLock.Release;
  end;
end;

{ TTracingObserver }

constructor TTracingObserver.Create(const ATracer: TTracer);
begin
  inherited Create;
  FTracer := ATracer;
  FRecordedHeaders := TStringList.Create;
end;

destructor TTracingObserver.Destroy;
begin
  FRecordedHeaders.Free;
  inherited Destroy;
end;

procedure TTracingObserver.RecordRequestHeader(const AName: string);
begin
  FRecordedHeaders.Add(AName);
end;

function TTracingObserver.OnAttemptStart(const A: THttpAttempt): IInterface;
var
  Parent, Span: ISpan;
  Name: string;
  T: TTraceToken;
begin
  // the parent travels in the request context, not in a thread-local
  if not Supports(A.Context, ISpan, Parent) then
    Parent := nil;
  if A.Kind = akWebSocket then
    Name := 'WEBSOCKET'
  else
    Name := A.Method;
  Span := FTracer.StartSpan(Name, Parent);
  Span.SetAttribute('http.request.method', A.Method);
  Span.SetAttribute('url.full', A.Url);
  Span.SetAttribute('server.address', A.Host);
  Span.SetAttribute('server.port', IntToStr(A.Port));
  Span.SetAttribute('http.attempt.kind', AttemptKindName(A.Kind));
  Span.SetAttribute('http.request.hop', IntToStr(A.Hop));
  Span.SetAttribute('http.request.resend_count', IntToStr(A.Retry));
  if A.Kind = akSse then
  begin
    Span.SetAttribute('sse.stream_id', IntToStr(A.StreamId));
    Span.SetAttribute('sse.reconnect', IntToStr(A.Reconnect));
  end;
  // SetValue replaces: a traceparent the caller set is never duplicated
  if A.Headers <> nil then
    A.Headers.SetValue('traceparent', Span.Traceparent);
  T := TTraceToken.Create;
  T.Span := Span;
  T.Headers := A.Headers;
  Result := T;
end;

procedure TTracingObserver.OnResponseHeaders(const AToken: IInterface;
  const AResponse: IHttpResponse);
var
  Span: ISpan;
  T: TTraceToken;
  I: Integer;
begin
  if (AResponse = nil) or not (AToken is TTraceToken) then
    Exit;
  T := AToken as TTraceToken;
  Span := T.Span;
  Span.SetAttribute('http.response.status_code', IntToStr(AResponse.StatusCode));
  if T.Headers <> nil then
    for I := 0 to FRecordedHeaders.Count - 1 do
      if T.Headers.GetFirst(FRecordedHeaders[I]) <> '' then
        Span.SetAttribute('http.request.header.' + LowerCase(FRecordedHeaders[I]),
          T.Headers.GetFirst(FRecordedHeaders[I]));
  // a header an adapter wants on the span is read from the response here
  if (AResponse.Headers <> nil) and AResponse.Headers.Contains('x-request-id') then
    Span.SetAttribute('http.response.header.x-request-id',
      AResponse.Headers.GetFirst('x-request-id'));
end;

procedure TTracingObserver.OnRedirect(const AToken: IInterface;
  const AFromUrl, AToUrl: string; const AStatus: LongInt);
var
  Span: ISpan;
begin
  if not (AToken is TTraceToken) then
    Exit;
  Span := (AToken as TTraceToken).Span;
  Span.SetAttribute('http.redirect.location', AToUrl);
  Span.AddEvent('redirect ' + IntToStr(AStatus) + ' to ' + AToUrl);
end;

procedure TTracingObserver.OnRetry(const AToken: IInterface;
  const AReason: string);
begin
  if AToken is TTraceToken then
    (AToken as TTraceToken).Span.AddEvent('retry: ' + AReason);
end;

procedure TTracingObserver.OnAttemptEnd(const AToken: IInterface;
  const O: THttpOutcome);
var
  Span: ISpan;
begin
  if not (AToken is TTraceToken) then
    Exit;
  Span := (AToken as TTraceToken).Span;
  if O.StatusCode > 0 then
    Span.SetAttribute('http.response.status_code', IntToStr(O.StatusCode));
  Span.SetAttribute('http.request.body.size', IntToStr(O.BytesOut));
  Span.SetAttribute('http.response.body.size', IntToStr(O.BytesIn));
  Span.SetAttribute('http.connection.reused', BoolToStr(O.ConnectionReused, True));
  if O.Abandoned then
    Span.SetAttribute('http.response.abandoned', 'true');
  if O.MessagesIn > 0 then
    Span.SetAttribute('messaging.received', IntToStr(O.MessagesIn));
  if O.Subprotocol <> '' then
    Span.SetAttribute('websocket.subprotocol', O.Subprotocol);
  if O.ClosedBy <> ciNone then
  begin
    Span.SetAttribute('websocket.close_code', IntToStr(O.CloseCode));
    Span.SetAttribute('websocket.close_reason', O.CloseReason);
  end;
  // Error is borrowed: read it here, never keep the reference
  if O.Error <> nil then
  begin
    Span.SetAttribute('error.type', O.Error.ClassName);
    Span.SetStatus(ssError, O.Error.Message);
  end
  else if O.Cancelled then
    Span.SetStatus(ssError, 'cancelled')
  else if O.StatusCode >= 400 then
    // the OpenTelemetry convention: a 4xx or 5xx is an error for a client span
    Span.SetStatus(ssError, 'HTTP ' + IntToStr(O.StatusCode))
  else
    Span.SetStatus(ssOk);
  Span.EndSpan;
end;

end.
