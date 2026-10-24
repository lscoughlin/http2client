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

  /// what a per-message callback describes
  TMessageKind = (mkSseEvent, mkWsText, mkWsBinary, mkWsPing, mkWsPong,
    mkWsClose);
  TMessageKinds = set of TMessageKind;
  TDirection = (mdIn, mdOut);

  /// one message, as an IHttpMessageObserver sees it
  TMessageInfo = record
    Kind: TMessageKind;
    Direction: TDirection;
    /// 0-based, per direction
    Index: Int64;
    /// payload bytes
    Size: Integer;
    /// microseconds from the start of the attempt, taken at the wire
    ArrivedUs: Int64;
    /// since the previous message in this direction; 0 for the first
    SinceLastUs: Int64;
    /// mkSseEvent only
    EventType, EventId: string;
    /// mkSseEvent only: the parsed event.  Valid only during the callback;
    /// an observer that needs it later copies it.
    Sse: PSseEvent;
  end;

  /// the opt-in per-message seam.  An observer implements it in addition to
  /// IHttpClientObserver; the library finds it with Supports, so an ordinary
  /// observer pays nothing.
  IHttpMessageObserver = interface
    ['{7D1E5A02-3B94-4C6F-8E21-5A0C9B3D6F05}']
    /// asked once per attempt, after OnAttemptStart; an empty set costs
    /// nothing for that attempt (no TMessageInfo is built)
    function WantsMessages(const A: THttpAttempt): TMessageKinds;
    /// runs inline on the thread that finished reading the message, so it
    /// must be fast.  AToken is the one OnAttemptStart returned.
    procedure OnMessage(const AToken: IInterface; const M: TMessageInfo);
  end;

  /// how a composite tells the library which kinds an attempt's members
  /// asked for, without asking them a second time
  IHttpMessageGate = interface
    ['{7D1E5A02-3B94-4C6F-8E21-5A0C9B3D6F06}']
    /// the union of what the members of the attempt AToken belongs to want
    function WantedFor(const AToken: IInterface): TMessageKinds;
  end;

  /// how a reader of an attempt's messages reports to the attempt
  // - the response of an observed request exposes it
  //   (Supports(Response, IAttemptProgress)); a response that is not observed
  //   still answers, and every call does nothing.  The reader (SSE source,
  //   WebSocket) owns neither the connection nor the attempt, so it reports
  //   what it saw and the attempt turns that into THttpOutcome aggregates and
  //   IHttpMessageObserver callbacks.
  // - the aggregates a reader reports replace the frame-level ones the codec
  //   gathers: for SSE a "message" is an event, not a DATA frame.
  IAttemptProgress = interface
    ['{7D1E5A02-3B94-4C6F-8E21-5A0C9B3D6F07}']
    /// the kinds the attempt's observers asked for; empty when none did
    function WantedKinds: TMessageKinds;
    /// one message.  AArrivedUs is a clock value (Http2.Clock) taken at the
    /// wire.  Data kinds (event, text, binary) count in MessagesIn or
    /// MessagesOut and feed the gap aggregates; ping, pong and close do not.
    /// ASse is read only for mkSseEvent and need not outlive the call.
    procedure ReportMessage(const AKind: TMessageKind;
      const ADirection: TDirection; const AArrivedUs: Int64;
      const ASize: Integer; const ASse: PSseEvent);
    /// the reader is about to read the transport.  A clean end of the body
    /// that this read causes is held back until ReadEnd, so the messages the
    /// read delivered are reported before OnAttemptEnd.
    procedure ReadBegin;
    /// the reader has reported everything the read returned
    procedure ReadEnd;
    /// the reader is done on purpose (Close): end the attempt now as a clean
    /// local end rather than an abandoned one.  ABytesIn is what it read.
    procedure Finish(const ABytesIn: Int64);
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
  /// the rest (its start runs first and its end last, so a tracer registered
  /// first reads the headers the later ones inject from OnResponseHeaders on,
  /// and they see what it injected).  A member that raises is skipped for that callback and reported
  /// to the logger; a member whose OnAttemptStart raised gets no further
  /// callbacks for that attempt.  Members never see each other's tokens.
  // - it is also the IHttpMessageObserver of its members: it asks each member
  //   that implements the interface once per attempt (in OnAttemptStart, with
  //   the attempt) and forwards OnMessage only to members whose answer
  //   included the message's kind.
  TCompositeObserver = class(TInterfacedObject, IHttpClientObserver,
    IHttpMessageObserver, IHttpMessageGate)
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
    /// the union of what the members want, asked afresh.  The library does not
    /// use this: it reads the answers OnAttemptStart already collected
    /// through IHttpMessageGate.
    function WantsMessages(const A: THttpAttempt): TMessageKinds;
    procedure OnMessage(const AToken: IInterface; const M: TMessageInfo);
    function WantedFor(const AToken: IInterface): TMessageKinds;
  end;

/// an IAttemptProgress that ignores everything, for a response that is not
/// observed
function NullAttemptProgress: IAttemptProgress;

/// the IAttemptProgress AObject exposes, or the null one.  A response asks
/// its exchange hook (the attempt tracker) for it.
function ProgressOf(const AObject: IInterface): IAttemptProgress;

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
    /// the per-message observer of each member (nil when it is not one) and
    /// the kinds it asked for
    Messages: TArray<IHttpMessageObserver>;
    Wants: TArray<TMessageKinds>;
    Wanted: TMessageKinds;
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
  SetLength(T.Messages, Length(FMembers));
  SetLength(T.Wants, Length(FMembers));
  T.Wanted := [];
  for I := 0 to High(FMembers) do
  begin
    T.Wants[I] := [];
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
    // asked once per attempt, after the member saw the start
    if T.Live[I] and Supports(FMembers[I], IHttpMessageObserver,
      T.Messages[I]) then
      try
        T.Wants[I] := T.Messages[I].WantsMessages(A);
        T.Wanted := T.Wanted + T.Wants[I];
      except
        on E: Exception do
        begin
          T.Wants[I] := [];
          Report('WantsMessages', E);
        end;
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

function TCompositeObserver.WantsMessages(
  const A: THttpAttempt): TMessageKinds;
var
  I: Integer;
  M: IHttpMessageObserver;
begin
  Result := [];
  for I := 0 to High(FMembers) do
    if Supports(FMembers[I], IHttpMessageObserver, M) then
      try
        Result := Result + M.WantsMessages(A);
      except
        on E: Exception do Report('WantsMessages', E);
      end;
end;

function TCompositeObserver.WantedFor(const AToken: IInterface): TMessageKinds;
var
  T: TCompositeToken;
begin
  T := SlotsOf(AToken);
  if T = nil then
    Result := []
  else
    Result := T.Wanted;
end;

procedure TCompositeObserver.OnMessage(const AToken: IInterface;
  const M: TMessageInfo);
var
  T: TCompositeToken;
  I: Integer;
begin
  T := SlotsOf(AToken);
  if T = nil then
    Exit;
  for I := 0 to High(FMembers) do
    if T.Live[I] and (T.Messages[I] <> nil) and (M.Kind in T.Wants[I]) then
      try
        T.Messages[I].OnMessage(T.Tokens[I], M);
      except
        on E: Exception do Report('OnMessage', E);
      end;
end;

{ TNullAttemptProgress }

type
  TNullAttemptProgress = class(TInterfacedObject, IAttemptProgress)
  public
    function WantedKinds: TMessageKinds;
    procedure ReportMessage(const AKind: TMessageKind;
      const ADirection: TDirection; const AArrivedUs: Int64;
      const ASize: Integer; const ASse: PSseEvent);
    procedure ReadBegin;
    procedure ReadEnd;
    procedure Finish(const ABytesIn: Int64);
  end;

function TNullAttemptProgress.WantedKinds: TMessageKinds;
begin
  Result := [];
end;

procedure TNullAttemptProgress.ReportMessage(const AKind: TMessageKind;
  const ADirection: TDirection; const AArrivedUs: Int64;
  const ASize: Integer; const ASse: PSseEvent);
begin
end;

procedure TNullAttemptProgress.ReadBegin;
begin
end;

procedure TNullAttemptProgress.ReadEnd;
begin
end;

procedure TNullAttemptProgress.Finish(const ABytesIn: Int64);
begin
end;

var
  GNullProgress: IAttemptProgress;

function NullAttemptProgress: IAttemptProgress;
begin
  Result := GNullProgress;
end;

function ProgressOf(const AObject: IInterface): IAttemptProgress;
begin
  if (AObject = nil) or not Supports(AObject, IAttemptProgress, Result) then
    Result := GNullProgress;
end;

initialization
  GNullProgress := TNullAttemptProgress.Create;

finalization
  GNullProgress := nil;

end.
