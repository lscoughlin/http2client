/// Request-level observer seam: attempts, outcomes, header injection, logger
// - this unit is part of the http2client project (see doc/design/
//   request-observability.md).
// - an adapter (tracing, metrics, logging) implements IHttpClientObserver and
//   is installed with THttpClientFactory.WithRequestObserver.  The core knows
//   nothing of any tracing system: it hands the adapter neutral facts.
// - every callback runs outside every library lock and must not block.  A
//   callback that raises is swallowed and reported to the IHttpLogger.
unit Http2.RequestObserver;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils,
  Http2.Headers, Http2.Tls, Http2.Messages;

type
  /// what kind of exchange an attempt is
  TAttemptKind = (akRequest, akSse, akWebSocket);

  /// who ended a WebSocket session (akWebSocket only)
  TCloseInitiator = (ciNone, ciLocal, ciRemote, ciAbort, ciError);

  /// the writer an observer uses to inject headers into one attempt
  IHeaderSink = interface
    ['{7D1E5A02-3B94-4C6F-8E21-5A0C9B3D6F01}']
    /// replace every value of AName with AValue
    procedure SetValue(const AName, AValue: string);
    /// the first value of AName, or '' (a prior observer may have set it)
    function GetFirst(const AName: string): string;
  end;

  /// one HTTP exchange on the wire.  A redirect hop and a transparent retry
  /// are each an attempt.
  THttpAttempt = record
    Kind: TAttemptKind;
    Method, Url, Host: string;
    Port: Word;
    /// 0 for the first request, +1 per redirect followed
    Hop: Integer;
    /// transparent retries already made on this hop
    Retry: Integer;
    /// SSE: the id of the reconnect loop and the reconnect count; 0 otherwise
    StreamId: Int64;
    Reconnect: Integer;
    /// the opaque object the caller attached with WithContext
    Context: IInterface;
    Headers: IHeaderSink;
  end;

  /// how an attempt ended.  Times are microseconds from the start of the
  /// attempt on the monotonic clock; 0 means "never happened".
  THttpOutcome = record
    /// 0 when the attempt failed before response headers
    StatusCode: LongInt;
    Protocol: TNegotiatedProtocol;
    ConnectionReused: Boolean;
    /// borrowed; nil on success; valid only during the callback, do not free
    Error: Exception;
    Cancelled: Boolean;
    /// the response was released without being read to its end
    Abandoned: Boolean;
    /// request and response body bytes carried on the wire
    BytesOut, BytesIn: Int64;
    RequestSentUs: Int64;
    HeadersUs: Int64;
    FirstMessageUs: Int64;
    LastMessageUs: Int64;
    EndUs: Int64;
    MessagesIn, MessagesOut: Int64;
    MaxGapUs, SumGapUs: Int64;
    /// akWebSocket only
    Subprotocol: string;
    CloseCode: Integer;
    CloseReason: string;
    ClosedBy: TCloseInitiator;
  end;

  /// the request-level observer
  IHttpClientObserver = interface
    ['{7D1E5A02-3B94-4C6F-8E21-5A0C9B3D6F02}']
    /// before the attempt is sent; may inject headers through A.Headers.  The
    /// returned token is passed to every later callback of this attempt.
    function OnAttemptStart(const A: THttpAttempt): IInterface;
    /// response headers received
    procedure OnResponseHeaders(const AToken: IInterface;
      const AResponse: IHttpResponse);
    /// a redirect is about to be followed (AToken belongs to the finished hop)
    procedure OnRedirect(const AToken: IInterface; const AFromUrl,
      AToUrl: string; const AStatus: LongInt);
    /// a transparent retry is about to be made
    procedure OnRetry(const AToken: IInterface; const AReason: string);
    /// the attempt is over; fires exactly once per OnAttemptStart
    procedure OnAttemptEnd(const AToken: IInterface; const O: THttpOutcome);
  end;

  /// an observer with empty virtual methods, so a subclass overrides only the
  /// events it cares about
  TBaseRequestObserver = class(TInterfacedObject, IHttpClientObserver)
  public
    function OnAttemptStart(const A: THttpAttempt): IInterface; virtual;
    procedure OnResponseHeaders(const AToken: IInterface;
      const AResponse: IHttpResponse); virtual;
    procedure OnRedirect(const AToken: IInterface; const AFromUrl,
      AToUrl: string; const AStatus: LongInt); virtual;
    procedure OnRetry(const AToken: IInterface;
      const AReason: string); virtual;
    procedure OnAttemptEnd(const AToken: IInterface;
      const O: THttpOutcome); virtual;
  end;

  TLogLevel = (llDebug, llInfo, llWarn, llError);

  /// receives library diagnostics that are not request events (an observer
  /// that raised, a cleartext origin, a protocol fallback)
  IHttpLogger = interface
    ['{7D1E5A02-3B94-4C6F-8E21-5A0C9B3D6F03}']
    procedure Log(const ALevel: TLogLevel; const AMessage: string);
  end;

  /// the header sink over one attempt's own copy of the request headers
  THeaderSink = class(TInterfacedObject, IHeaderSink)
  private
    FHeaders: IHttpHeaders;
  public
    constructor Create(const AHeaders: IHttpHeaders);
    procedure SetValue(const AName, AValue: string);
    function GetFirst(const AName: string): string;
  end;

  /// runs several observers as one.  Start-side callbacks run in registration
  /// order and OnAttemptEnd in reverse, so the observer registered first wraps
  /// the rest (a tracer registered first sees every header the later ones
  /// inject).  A member that raises is skipped for that callback and reported
  /// to the logger; a member whose OnAttemptStart raised gets no further
  /// callbacks for that attempt.  Members never see each other's tokens.
  TCompositeObserver = class(TInterfacedObject, IHttpClientObserver)
  private
    FMembers: TArray<IHttpClientObserver>;
    FLogger: IHttpLogger;
    procedure Report(const ACallback: string; const AError: Exception);
  public
    constructor Create(const AMembers: TArray<IHttpClientObserver>;
      const ALogger: IHttpLogger = nil);
    function OnAttemptStart(const A: THttpAttempt): IInterface;
    procedure OnResponseHeaders(const AToken: IInterface;
      const AResponse: IHttpResponse);
    procedure OnRedirect(const AToken: IInterface; const AFromUrl,
      AToUrl: string; const AStatus: LongInt);
    procedure OnRetry(const AToken: IInterface; const AReason: string);
    procedure OnAttemptEnd(const AToken: IInterface; const O: THttpOutcome);
  end;

implementation

type
  TCompositeToken = class;

  ICompositeToken = interface
    ['{7D1E5A02-3B94-4C6F-8E21-5A0C9B3D6F04}']
    function Instance: TCompositeToken;
  end;

  /// the composite's token: one slot per member
  TCompositeToken = class(TInterfacedObject, ICompositeToken)
  public
    Tokens: TArray<IInterface>;
    Live: TArray<Boolean>;
    function Instance: TCompositeToken;
  end;

function TCompositeToken.Instance: TCompositeToken;
begin
  Result := Self;
end;

function SlotsOf(const AToken: IInterface): TCompositeToken;
var
  C: ICompositeToken;
begin
  if Supports(AToken, ICompositeToken, C) then
    Result := C.Instance
  else
    Result := nil;
end;

{ TBaseRequestObserver }

function TBaseRequestObserver.OnAttemptStart(const A: THttpAttempt): IInterface;
begin
  Result := nil;
end;

procedure TBaseRequestObserver.OnResponseHeaders(const AToken: IInterface;
  const AResponse: IHttpResponse);
begin
end;

procedure TBaseRequestObserver.OnRedirect(const AToken: IInterface;
  const AFromUrl, AToUrl: string; const AStatus: LongInt);
begin
end;

procedure TBaseRequestObserver.OnRetry(const AToken: IInterface;
  const AReason: string);
begin
end;

procedure TBaseRequestObserver.OnAttemptEnd(const AToken: IInterface;
  const O: THttpOutcome);
begin
end;

{ THeaderSink }

constructor THeaderSink.Create(const AHeaders: IHttpHeaders);
begin
  inherited Create;
  FHeaders := AHeaders;
end;

procedure THeaderSink.SetValue(const AName, AValue: string);
begin
  FHeaders.SetValue(AName, AValue);
end;

function THeaderSink.GetFirst(const AName: string): string;
begin
  Result := FHeaders.GetFirst(AName);
end;

{ TCompositeObserver }

constructor TCompositeObserver.Create(
  const AMembers: TArray<IHttpClientObserver>; const ALogger: IHttpLogger);
begin
  inherited Create;
  FMembers := Copy(AMembers);
  FLogger := ALogger;
end;

procedure TCompositeObserver.Report(const ACallback: string;
  const AError: Exception);
begin
  if FLogger = nil then
    Exit;
  try
    FLogger.Log(llWarn, 'request observer raised in ' + ACallback + ': ' +
      AError.ClassName + ': ' + AError.Message);
  except
    // a failing logger must not fail a request either
  end;
end;

function TCompositeObserver.OnAttemptStart(const A: THttpAttempt): IInterface;
var
  T: TCompositeToken;
  I: Integer;
begin
  T := TCompositeToken.Create;
  Result := T;
  SetLength(T.Tokens, Length(FMembers));
  SetLength(T.Live, Length(FMembers));
  for I := 0 to High(FMembers) do
    try
      T.Tokens[I] := FMembers[I].OnAttemptStart(A);
      T.Live[I] := True;
    except
      on E: Exception do
      begin
        T.Live[I] := False;
        Report('OnAttemptStart', E);
      end;
    end;
end;

procedure TCompositeObserver.OnResponseHeaders(const AToken: IInterface;
  const AResponse: IHttpResponse);
var
  T: TCompositeToken;
  I: Integer;
begin
  T := SlotsOf(AToken);
  if T = nil then
    Exit;
  for I := 0 to High(FMembers) do
    if T.Live[I] then
      try
        FMembers[I].OnResponseHeaders(T.Tokens[I], AResponse);
      except
        on E: Exception do Report('OnResponseHeaders', E);
      end;
end;

procedure TCompositeObserver.OnRedirect(const AToken: IInterface;
  const AFromUrl, AToUrl: string; const AStatus: LongInt);
var
  T: TCompositeToken;
  I: Integer;
begin
  T := SlotsOf(AToken);
  if T = nil then
    Exit;
  for I := 0 to High(FMembers) do
    if T.Live[I] then
      try
        FMembers[I].OnRedirect(T.Tokens[I], AFromUrl, AToUrl, AStatus);
      except
        on E: Exception do Report('OnRedirect', E);
      end;
end;

procedure TCompositeObserver.OnRetry(const AToken: IInterface;
  const AReason: string);
var
  T: TCompositeToken;
  I: Integer;
begin
  T := SlotsOf(AToken);
  if T = nil then
    Exit;
  for I := 0 to High(FMembers) do
    if T.Live[I] then
      try
        FMembers[I].OnRetry(T.Tokens[I], AReason);
      except
        on E: Exception do Report('OnRetry', E);
      end;
end;

procedure TCompositeObserver.OnAttemptEnd(const AToken: IInterface;
  const O: THttpOutcome);
var
  T: TCompositeToken;
  I: Integer;
begin
  T := SlotsOf(AToken);
  if T = nil then
    Exit;
  for I := High(FMembers) downto 0 do
    if T.Live[I] then
      try
        FMembers[I].OnAttemptEnd(T.Tokens[I], O);
      except
        on E: Exception do Report('OnAttemptEnd', E);
      end;
end;

end.
