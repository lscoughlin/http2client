/// Single-shot HTTP/2 conformance probe CLI (plan story S12, deliverable B.1).
// - usage: h2probe --url=https://127.0.0.1:8080/ [--insecure]
//                    [--method=GET] [--body=...] [--timeout-ms=N]
//                    [--keep-open-ms=N] [--parallel=N] [--trace-frames]
// - it builds one client, performs ONE request (or N parallel requests with
//   --parallel), reads each response body to EOF, and maps the observed
//   OUTCOME to an exit code that mirrors the h2-client-test-harness verifier
//   classes (see Http2.ProbeOutcome):
//       0 = success              (HTTP 200)     ExpectSuccessfulRequest
//       2 = connection-level error              ExpectConnectionError
//       3 = stream-level error                  ExpectStreamError
//       1 = usage error / anything else
// - the single machine-readable line on stdout is what tools/validate/
//   harness.sh parses; it MUST NOT hang (every wait is bounded).
program h2probe;

{$mode delphi}{$H+}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils, Classes, TypInfo, Http2.Errors, Http2.Messages, Http2.Client, Http2.Stream,
  Http2.ProbeOutcome, Http2.Frames, Http2.Observer;

const
  cDefaultTimeoutMs  = 5000;
  cDefaultKeepOpenMs = 200;

var
  GUrl: string;
  GMethod: string;
  GBody: string;
  GInsecure: Boolean;
  GTimeoutMs: Integer;
  GKeepOpenMs: Integer;
  GParallel: Integer;
  GBodySet: Boolean;
  GBodyWriterSet: Boolean;
  GTraceFrames: Boolean;

function ReadOptionValue(const AArg: string): string;
var
  P: Integer;
begin
  P := Pos('=', AArg);
  if P > 0 then
    Result := Copy(AArg, P + 1, Length(AArg))
  else
    Result := '';
end;

procedure UsageError(const AMessage: string);
begin
  WriteLn(StdErr, 'h2probe: ', AMessage);
  WriteLn(StdErr,
    'usage: h2probe --url=<https-url> [--insecure] [--method=GET] ' +
    '[--body=...] [--timeout-ms=N] [--keep-open-ms=N] [--parallel=N]');
  Halt(ExitCodeOf(poUsage));
end;

procedure ParseArgs;
var
  I: Integer;
  Arg, Name, Value: string;
begin
  GUrl := '';
  GMethod := 'GET';
  GBody := '';
  GBodySet := False;
  GBodyWriterSet := False;
  GInsecure := False;
  GTraceFrames := False;
  GTimeoutMs := cDefaultTimeoutMs;
  GKeepOpenMs := cDefaultKeepOpenMs;
  GParallel := 1;
  for I := 1 to ParamCount do
  begin
    Arg := ParamStr(I);
    Name := Arg;
    if Pos('=', Name) > 0 then
      Name := Copy(Name, 1, Pos('=', Name) - 1);
    Value := ReadOptionValue(Arg);
    if (Arg = '--insecure') then
      GInsecure := True
    else if (Arg = '--trace-frames') then
      GTraceFrames := True
    else if Name = '--url' then
      GUrl := Value
    else if Name = '--method' then
      GMethod := UpperCase(Value)
    else if Name = '--body' then
    begin
      GBody := Value;
      GBodySet := True;
    end
    else if Name = '--body-writer' then
    begin
      GBody := Value;
      GBodySet := True;
      GBodyWriterSet := True;
    end
    else if Name = '--timeout-ms' then
      GTimeoutMs := StrToIntDef(Value, cDefaultTimeoutMs)
    else if Name = '--keep-open-ms' then
      GKeepOpenMs := StrToIntDef(Value, cDefaultKeepOpenMs)
    else if Name = '--parallel' then
      GParallel := StrToIntDef(Value, 1)
    else
      UsageError('unknown option: ' + Arg);
  end;
  if GUrl = '' then
    UsageError('--url is required');
  if GTimeoutMs <= 0 then
    GTimeoutMs := cDefaultTimeoutMs;
  if GKeepOpenMs < 0 then
    GKeepOpenMs := 0;
  if GParallel < 1 then
    GParallel := 1;
end;

function MethodOf(const AToken: string): THttpMethod;
begin
  if AToken = 'GET' then Result := hmGet
  else if AToken = 'HEAD' then Result := hmHead
  else if AToken = 'POST' then Result := hmPost
  else if AToken = 'PUT' then Result := hmPut
  else if AToken = 'DELETE' then Result := hmDelete
  else if AToken = 'OPTIONS' then Result := hmOptions
  else if AToken = 'PATCH' then Result := hmPatch
  else Result := hmGet;
end;

function IsKnownMethod(const AToken: string): Boolean;
begin
  Result := (AToken = 'GET') or (AToken = 'HEAD') or (AToken = 'POST') or
            (AToken = 'PUT') or (AToken = 'DELETE') or (AToken = 'OPTIONS') or
            (AToken = 'PATCH');
end;

/// one worker: send one request and read its body to EOF; return a RESULT line
/// plus the raw exception (nil on success) so the main thread can aggregate
type
  TProbeResult = record
    Outcome: TProbeOutcome;
    Status: Integer;
    Bytes: Integer;
    Line: string;
    Error: Exception;
  end;

  /// feeds AData to the client in fixed-size chunks, exercising the
  /// IBodyWriter (streaming DATA) path instead of a single THttpBody.
  TChunkWriter = class(TInterfacedObject, IBodyWriter)
  private
    FData: TBytes;
    FChunk: Integer;
    FPos: Integer;
  public
    constructor Create(const AData: string; const AChunk: Integer);
    function NextChunk(out ABuffer: TBytes): Boolean;
  end;

constructor TChunkWriter.Create(const AData: string; const AChunk: Integer);
begin
  inherited Create;
  FData := TEncoding.UTF8.GetBytes(AData);
  FChunk := AChunk;
  if FChunk < 1 then
    FChunk := 1;
  FPos := 0;
end;

type
  /// prints every frame the client writes and reads in an nghttp -nv-comparable
  /// one-line form, so the S12 section E differential oracle can diff our wire
  /// behaviour against nghttp for the same request.
  TFrameTraceObserver = class(TBaseObserver)
private
  class function FrameLine(const ADirection: string;
    const AFrame: TFrame): string; static;
public
  procedure OnFrameIn(const AFrame: TFrame); override;
  procedure OnFrameOut(const AFrame: TFrame); override;
end;

class function TFrameTraceObserver.FrameLine(const ADirection: string;
  const AFrame: TFrame): string;
var
  F: TFrameFlag;
  Flags: string;
begin
  Flags := '';
  for F := Low(TFrameFlag) to High(TFrameFlag) do
    if F in AFrame.Header.Flags then
      Flags := Flags + UpperCase(Copy(
        GetEnumName(TypeInfo(TFrameFlag), Ord(F)), 3, MaxInt)) + ',';
  if Flags <> '' then
    Flags := Copy(Flags, 1, Length(Flags) - 1);
  Result := Format('%s %s stream=%d len=%d flags=[%s]',
    [ADirection, FrameTypeName(AFrame.Header.FrameType),
     AFrame.Header.StreamId, Length(AFrame.Payload), Flags]);
end;

procedure TFrameTraceObserver.OnFrameIn(const AFrame: TFrame);
begin
  WriteLn('FRAME in  ', FrameLine('', AFrame));
end;

procedure TFrameTraceObserver.OnFrameOut(const AFrame: TFrame);
begin
  WriteLn('FRAME out ', FrameLine('', AFrame));
end;

function TChunkWriter.NextChunk(out ABuffer: TBytes): Boolean;
var
  N: Integer;
begin
  ABuffer := nil;
  N := Length(FData) - FPos;
  if N <= 0 then
    Exit(False);
  if N > FChunk then
    N := FChunk;
  ABuffer := Copy(FData, FPos, N);
  Inc(FPos, N);
  Result := True;
end;

function OneRequest(const AClient: IHttpClient; const AUrl, AMethod: string;
  const ABody: string; const ABodySet: Boolean; const ATimeoutMs,
  AKeepOpenMs: Integer): TProbeResult;
var
  Request: THttpRequest;
  Response: IHttpResponse;
  Buf: array[0..4095] of Byte;
  N: LongInt;
begin
  Result.Outcome := poUsage;
  Result.Status := 0;
  Result.Bytes := 0;
  Result.Error := nil;
  Result.Line := '';

  if IsKnownMethod(AMethod) then
    Request := THttpRequest.Create(MethodOf(AMethod), AUrl)
  else
    Request := THttpRequest.Create(hmGet, AUrl).WithMethodToken(AMethod);
  Request := Request.WithTimeout(ATimeoutMs);
  Request := Request.WithHeader('user-agent', 'http2client-h2probe');
  if ABodySet then
  begin
    if GBodyWriterSet then
      Request := Request.WithBodyWriter(TChunkWriter.Create(ABody, 7))
    else
      Request := Request.WithBody(THttpBody.FromString(ABody));
  end;
  try
    Response := AClient.Send(Request);
    // read to EOF: a stream error may surface only during body reads
    while True do
    begin
      N := Response.Body.Read(Buf, SizeOf(Buf));
      if N <= 0 then
        Break;
      Inc(Result.Bytes, N);
    end;
    Result.Status := Response.StatusCode;
    if Response.StatusCode = 200 then
    begin
      Result.Outcome := poSuccess;
      Result.Line := FormatSuccess(Result.Status, Result.Bytes);
    end
    else
    begin
      Result.Outcome := poUsage;
      Result.Line := 'RESULT=non-200 status=' + IntToStr(Response.StatusCode) +
        ' bytes=' + IntToStr(Result.Bytes);
    end;
  except
    on E: Exception do
    begin
      Result.Outcome := ClassifyError(E);
      Result.Line := FormatError(E);
      Result.Error := E;
    end;
  end;
  if AKeepOpenMs > 0 then
    Sleep(AKeepOpenMs);
end;

type
  TProbeWorker = class(TThread)
  private
    FClient: IHttpClient;
    FUrl, FMethod, FBody: string;
    FBodySet: Boolean;
    FTimeoutMs, FKeepOpenMs: Integer;
    FResult: TProbeResult;
  protected
    procedure Execute; override;
  public
    constructor Create(const AClient: IHttpClient; const AUrl, AMethod,
      ABody: string; const ABodySet: Boolean; const ATimeoutMs,
      AKeepOpenMs: Integer);
    property Result: TProbeResult read FResult;
  end;

constructor TProbeWorker.Create(const AClient: IHttpClient; const AUrl,
  AMethod, ABody: string; const ABodySet: Boolean; const ATimeoutMs,
  AKeepOpenMs: Integer);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FClient := AClient;
  FUrl := AUrl;
  FMethod := AMethod;
  FBody := ABody;
  FBodySet := ABodySet;
  FTimeoutMs := ATimeoutMs;
  FKeepOpenMs := AKeepOpenMs;
end;

procedure TProbeWorker.Execute;
begin
  FResult := OneRequest(FClient, FUrl, FMethod, FBody, FBodySet, FTimeoutMs,
    FKeepOpenMs);
end;

var
  Client: IHttpClient;
  Factory: THttpClientFactory;
  Workers: array of TProbeWorker;
  I, Succeeded: Integer;
  FinalOutcome: TProbeOutcome;
  Worst: Exception;
  R: TProbeResult;
begin
  ParseArgs;

  Factory := THttpClientFactory.Create
    .WithMaxConnections(GParallel)
    .WithMaxStreamsPerConnection(GParallel)
    .WithFollowRedirects(False)
    .WithConnectTimeout(GTimeoutMs)
    .WithHeaderTimeout(GTimeoutMs)
    .WithIdleTimeout(0)
    .WithInsecureTls(GInsecure);
  if GTraceFrames then
    Factory := Factory.WithObserver(TFrameTraceObserver.Create);
  Client := Factory.Build;

  FinalOutcome := poSuccess;
  Worst := nil;
  Succeeded := 0;
  try
    SetLength(Workers, GParallel);
    for I := 0 to GParallel - 1 do
    begin
      Workers[I] := TProbeWorker.Create(Client, GUrl, GMethod, GBody, GBodySet,
        GTimeoutMs, GKeepOpenMs);
      Workers[I].Start;
    end;
    for I := 0 to GParallel - 1 do
    begin
      Workers[I].WaitFor;
      R := Workers[I].Result;
      WriteLn(R.Line);
      if R.Outcome = poSuccess then
        Inc(Succeeded)
      else
      begin
        if FinalOutcome = poSuccess then
          FinalOutcome := R.Outcome;
        if Worst = nil then
          Worst := R.Error;
      end;
      Workers[I].Free;
    end;
    if GParallel > 1 then
    begin
      if Succeeded = GParallel then
        FinalOutcome := poSuccess
      else
        FinalOutcome := poConnError;
      WriteLn('SUMMARY parallel=', GParallel, ' ok=', Succeeded);
    end;
  finally
    Client.Close;
  end;

  Halt(ExitCodeOf(FinalOutcome));
end.
