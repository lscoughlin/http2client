/// Outcome classification and RESULT-line grammar shared by the h2probe CLI
/// (test/h2probe.pas) and its unit test (plan story S12, deliverable B.1).
// - keeps ONE spelling of the exit-code mapping (0 success / 1 usage /
//   2 connection error / 3 stream error) and of the machine-readable stdout
//   line that tools/validate/harness.sh parses.
unit Http2.ProbeOutcome;

{$mode delphi}{$H+}

interface

uses
  SysUtils, Http2.Errors;

type
  /// mirrors the three h2-client-test-harness verifier classes plus usage
  TProbeOutcome = (poSuccess, poConnError, poStreamError, poUsage);

/// the documented process exit code for an outcome
function ExitCodeOf(const AOutcome: TProbeOutcome): Integer;

/// short lowercase token used inside the RESULT= line
function OutcomeToken(const AOutcome: TProbeOutcome): string;

/// classify an exception: EHttpStreamError is a stream error, every other
/// EHttpError is a connection error, anything else is a usage error
function ClassifyError(const AE: Exception): TProbeOutcome;

/// collapse newlines/tabs so the stdout line stays single-line and parseable
function OneLine(const AMessage: string): string;

/// the stdout line for a successful exchange
function FormatSuccess(const AStatus, ABytes: Integer): string;

/// the stdout line for a failed exchange (uses ClassifyError + ErrorCode)
function FormatError(const AE: Exception): string;

implementation

function ExitCodeOf(const AOutcome: TProbeOutcome): Integer;
begin
  case AOutcome of
    poSuccess:     Result := 0;
    poConnError:   Result := 2;
    poStreamError: Result := 3;
  else
    Result := 1;
  end;
end;

function OutcomeToken(const AOutcome: TProbeOutcome): string;
begin
  case AOutcome of
    poSuccess:     Result := 'success';
    poConnError:   Result := 'conn-error';
    poStreamError: Result := 'stream-error';
  else
    Result := 'usage';
  end;
end;

function ClassifyError(const AE: Exception): TProbeOutcome;
begin
  if AE is EHttpStreamError then
    Result := poStreamError
  else if AE is EHttpError then
    Result := poConnError
  else
    Result := poUsage;
end;

function OneLine(const AMessage: string): string;
var
  I: Integer;
begin
  Result := AMessage;
  for I := 1 to Length(Result) do
    if (Result[I] = #10) or (Result[I] = #13) or (Result[I] = #9) then
      Result[I] := ' ';
end;

function FormatSuccess(const AStatus, ABytes: Integer): string;
begin
  Result := 'RESULT=success status=' + IntToStr(AStatus) +
    ' bytes=' + IntToStr(ABytes);
end;

function FormatError(const AE: Exception): string;
var
  CodeName: string;
begin
  CodeName := '';
  if AE is EHttpError then
    CodeName := Http2ErrorCodeName(EHttpError(AE).ErrorCode);
  if CodeName = '' then
    CodeName := 'n/a';
  Result := 'RESULT=' + OutcomeToken(ClassifyError(AE)) +
    ' class=' + AE.ClassName + ' code=' + CodeName +
    ' msg=' + OneLine(AE.Message);
end;

end.
