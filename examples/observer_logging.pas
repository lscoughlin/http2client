/// http2client example adapter: structured logging over IHttpClientObserver.
// - this unit is NOT part of the library.  It shows how a consumer writes one
//   line per callback, as `key=value` pairs, to a logger of its own.  The sink
//   is the library's own IHttpLogger interface, so a real adapter forwards to
//   its logging framework by implementing that one method.
// - every line carries `id`, the adapter's own number for the attempt (the
//   token it returned from OnAttemptStart), so the lines of one attempt can be
//   joined.  Levels: start and headers are debug, a redirect is info, a retry
//   is warn, and the end line is info, warn (abandoned, cancelled or a 5xx
//   status) or error (the attempt failed).
unit observer_logging;

{$mode delphi}{$H+}
{$interfaces com}

interface

uses
  SysUtils, Classes, SyncObjs,
  Http2.Tls, Http2.Messages, Http2.RequestObserver;

type
  /// an IHttpLogger that keeps its lines (and optionally echoes them)
  TMemoryLogger = class(TInterfacedObject, IHttpLogger)
  private
    FLock: TCriticalSection;
    FLines: TStringList;
    FLevels: array of TLogLevel;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Log(const ALevel: TLogLevel; const AMessage: string);
    function Count: Integer;
    function LineAt(const AIndex: Integer): string;
    function LevelAt(const AIndex: Integer): TLogLevel;
    /// every line, one per row
    function Text: string;
  end;

  /// the logging adapter
  TLoggingObserver = class(TBaseRequestObserver)
  private
    FLogger: IHttpLogger;
    FNextId: LongInt;
  public
    constructor Create(const ALogger: IHttpLogger);
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

/// AValue as a log value: bare when it is a plain word, quoted and escaped
/// when it holds a space, a quote, an equals sign or a control character
function LogValue(const AValue: string): string;

implementation

type
  TLogToken = class(TInterfacedObject)
  public
    Id: LongInt;
  end;

function LogValue(const AValue: string): string;
var
  I: Integer;
  Plain: Boolean;
begin
  Plain := AValue <> '';
  for I := 1 to Length(AValue) do
    if (AValue[I] <= ' ') or (AValue[I] in ['"', '=', '\']) then
      Plain := False;
  if Plain then
    Exit(AValue);
  Result := '"';
  for I := 1 to Length(AValue) do
    case AValue[I] of
      '"': Result := Result + '\"';
      '\': Result := Result + '\\';
      #10: Result := Result + '\n';
      #13: Result := Result + '\r';
    else
      if AValue[I] < ' ' then
        Result := Result + ' '
      else
        Result := Result + AValue[I];
    end;
  Result := Result + '"';
end;

function ProtocolName(const AProtocol: TNegotiatedProtocol): string;
begin
  case AProtocol of
    npHttp2Tls: Result := 'h2';
    npHttp2Cleartext: Result := 'h2c';
    npHttp1Tls: Result := 'http/1.1+tls';
    npHttp1Cleartext: Result := 'http/1.1';
  else
    Result := '?';
  end;
end;

function KindText(const AKind: TAttemptKind): string;
begin
  case AKind of
    akSse: Result := 'sse';
    akWebSocket: Result := 'websocket';
  else
    Result := 'request';
  end;
end;

function ClosedByText(const AClosedBy: TCloseInitiator): string;
begin
  case AClosedBy of
    ciLocal: Result := 'local';
    ciRemote: Result := 'remote';
    ciAbort: Result := 'abort';
    ciError: Result := 'error';
  else
    Result := 'none';
  end;
end;

{ TMemoryLogger }

constructor TMemoryLogger.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FLines := TStringList.Create;
end;

destructor TMemoryLogger.Destroy;
begin
  FLines.Free;
  FLock.Free;
  inherited Destroy;
end;

procedure TMemoryLogger.Log(const ALevel: TLogLevel; const AMessage: string);
begin
  FLock.Acquire;
  try
    FLines.Add(AMessage);
    SetLength(FLevels, FLines.Count);
    FLevels[FLines.Count - 1] := ALevel;
  finally
    FLock.Release;
  end;
end;

function TMemoryLogger.Count: Integer;
begin
  FLock.Acquire;
  try
    Result := FLines.Count;
  finally
    FLock.Release;
  end;
end;

function TMemoryLogger.LineAt(const AIndex: Integer): string;
begin
  FLock.Acquire;
  try
    Result := FLines[AIndex];
  finally
    FLock.Release;
  end;
end;

function TMemoryLogger.LevelAt(const AIndex: Integer): TLogLevel;
begin
  FLock.Acquire;
  try
    Result := FLevels[AIndex];
  finally
    FLock.Release;
  end;
end;

function TMemoryLogger.Text: string;
begin
  FLock.Acquire;
  try
    Result := FLines.Text;
  finally
    FLock.Release;
  end;
end;

{ TLoggingObserver }

constructor TLoggingObserver.Create(const ALogger: IHttpLogger);
begin
  inherited Create;
  FLogger := ALogger;
end;

function IdOf(const AToken: IInterface): LongInt;
begin
  if AToken is TLogToken then
    Result := (AToken as TLogToken).Id
  else
    Result := 0;
end;

function TLoggingObserver.OnAttemptStart(const A: THttpAttempt): IInterface;
var
  T: TLogToken;
  Line: string;
begin
  T := TLogToken.Create;
  T.Id := InterlockedIncrement(FNextId);
  Line := 'evt=attempt.start id=' + IntToStr(T.Id) + ' kind=' + KindText(A.Kind) +
    ' method=' + A.Method + ' url=' + LogValue(A.Url) + ' hop=' + IntToStr(A.Hop) +
    ' retry=' + IntToStr(A.Retry);
  if A.Kind = akSse then
    Line := Line + ' stream=' + IntToStr(A.StreamId) + ' reconnect=' +
      IntToStr(A.Reconnect);
  FLogger.Log(llDebug, Line);
  Result := T;
end;

procedure TLoggingObserver.OnResponseHeaders(const AToken: IInterface;
  const AResponse: IHttpResponse);
begin
  if AResponse = nil then
    Exit;
  // the response headers are open here: pick what the log should carry
  FLogger.Log(llDebug, 'evt=attempt.headers id=' + IntToStr(IdOf(AToken)) +
    ' status=' + IntToStr(AResponse.StatusCode));
end;

procedure TLoggingObserver.OnRedirect(const AToken: IInterface;
  const AFromUrl, AToUrl: string; const AStatus: LongInt);
begin
  FLogger.Log(llInfo, 'evt=attempt.redirect id=' + IntToStr(IdOf(AToken)) +
    ' status=' + IntToStr(AStatus) + ' from=' + LogValue(AFromUrl) +
    ' to=' + LogValue(AToUrl));
end;

procedure TLoggingObserver.OnRetry(const AToken: IInterface;
  const AReason: string);
begin
  FLogger.Log(llWarn, 'evt=attempt.retry id=' + IntToStr(IdOf(AToken)) +
    ' reason=' + LogValue(AReason));
end;

procedure TLoggingObserver.OnAttemptEnd(const AToken: IInterface;
  const O: THttpOutcome);
var
  Line: string;
  Level: TLogLevel;
begin
  Level := llInfo;
  Line := 'evt=attempt.end id=' + IntToStr(IdOf(AToken)) + ' status=' +
    IntToStr(O.StatusCode) + ' proto=' + ProtocolName(O.Protocol) +
    ' reused=' + LowerCase(BoolToStr(O.ConnectionReused, True)) +
    ' dur_us=' + IntToStr(O.EndUs) + ' bytes_out=' + IntToStr(O.BytesOut) +
    ' bytes_in=' + IntToStr(O.BytesIn) + ' msgs_in=' + IntToStr(O.MessagesIn) +
    ' msgs_out=' + IntToStr(O.MessagesOut);
  if O.HeadersUs > 0 then
    Line := Line + ' ttfb_us=' + IntToStr(O.HeadersUs - O.RequestSentUs);
  if O.MessagesIn > 1 then
    Line := Line + ' max_gap_us=' + IntToStr(O.MaxGapUs);
  if O.ClosedBy <> ciNone then
  begin
    Line := Line + ' closed_by=' + ClosedByText(O.ClosedBy) + ' close_code=' +
      IntToStr(O.CloseCode);
    if O.CloseReason <> '' then
      Line := Line + ' close_reason=' + LogValue(O.CloseReason);
  end;
  if O.StatusCode >= 500 then
    Level := llWarn;
  if O.Abandoned then
  begin
    Line := Line + ' abandoned=true';
    Level := llWarn;
  end;
  if O.Cancelled then
  begin
    Line := Line + ' cancelled=true';
    Level := llWarn;
  end;
  // Error is borrowed: the text is taken here, inside the callback
  if O.Error <> nil then
  begin
    Line := Line + ' error=' + O.Error.ClassName + ' message=' +
      LogValue(O.Error.Message);
    Level := llError;
  end;
  FLogger.Log(Level, Line);
end;

end.
