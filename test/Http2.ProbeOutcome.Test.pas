/// Unit test for the h2probe outcome classification and RESULT-line grammar
/// (plan story S12, deliverable B.1). Proves the exit-code contract the
/// validation runner depends on: connection/stream errors must be
/// distinguishable, and a RESULT line must stay single-line.
unit Http2.ProbeOutcome.Test;

{$mode delphi}{$H+}

interface

uses
  SysUtils, fpcunit, testregistry, Http2.Errors, Http2.ProbeOutcome;

type
  TProbeOutcomeTest = class(TTestCase)
  published
    procedure TestExitCodesMatchVerifierClasses;
    procedure TestClassifyConnectionError;
    procedure TestClassifyStreamError;
    procedure TestClassifyOpaqueErrorIsUsage;
    procedure TestFormatErrorIsSingleLine;
    procedure TestFormatErrorNamesStreamErrorCode;
    procedure TestFormatSuccessLine;
  end;

implementation

procedure TProbeOutcomeTest.TestExitCodesMatchVerifierClasses;
begin
  AssertTrue('success exits 0', ExitCodeOf(poSuccess) = 0);
  AssertTrue('connection error exits 2', ExitCodeOf(poConnError) = 2);
  AssertTrue('stream error exits 3', ExitCodeOf(poStreamError) = 3);
  AssertTrue('usage exits 1', ExitCodeOf(poUsage) = 1);
end;

procedure TProbeOutcomeTest.TestClassifyConnectionError;
var
  E: EHttpConnectionError;
begin
  E := EHttpConnectionError.Create('boom', ecProtocolError);
  try
    AssertTrue('EHttpConnectionError is a connection error',
      ClassifyError(E) = poConnError);
  finally
    E.Free;
  end;
end;

procedure TProbeOutcomeTest.TestClassifyStreamError;
var
  E: EHttpStreamError;
begin
  E := EHttpStreamError.Create('reset', 1, ecCancel);
  try
    AssertTrue('EHttpStreamError is a stream error',
      ClassifyError(E) = poStreamError);
  finally
    E.Free;
  end;
end;

procedure TProbeOutcomeTest.TestClassifyOpaqueErrorIsUsage;
var
  E: Exception;
begin
  E := Exception.Create('not an http2 error');
  try
    AssertTrue('a plain exception is a usage error',
      ClassifyError(E) = poUsage);
  finally
    E.Free;
  end;
end;

procedure TProbeOutcomeTest.TestFormatErrorIsSingleLine;
var
  E: Exception;
  Line: string;
begin
  E := EHttpConnectionError.Create('line one' + #10 + 'line two' + #13 + 'three',
    ecProtocolError);
  try
    Line := FormatError(E);
    AssertTrue('RESULT prefix present', Pos('RESULT=', Line) = 1);
    AssertTrue('no LF in the line', Pos(#10, Line) = 0);
    AssertTrue('no CR in the line', Pos(#13, Line) = 0);
    AssertTrue('conn-error token', Pos('conn-error', Line) > 0);
  finally
    E.Free;
  end;
end;

procedure TProbeOutcomeTest.TestFormatErrorNamesStreamErrorCode;
var
  E: EHttpStreamError;
  Line: string;
begin
  E := EHttpStreamError.Create('peer reset', 3, ecCancel);
  try
    Line := FormatError(E);
    AssertTrue('stream-error token', Pos('stream-error', Line) > 0);
    AssertTrue('code name present', Pos('CANCEL', Line) > 0);
  finally
    E.Free;
  end;
end;

procedure TProbeOutcomeTest.TestFormatSuccessLine;
begin
  AssertEquals('success line', 'RESULT=success status=200 bytes=42',
    FormatSuccess(200, 42));
end;

initialization
  RegisterTest(TProbeOutcomeTest);
end.
