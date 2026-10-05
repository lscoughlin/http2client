/// Unit tests for Http2.Errors (plan story S01, task 01.1)
// - run with `make test`
unit Http2.Errors.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$interfaces com}

interface

uses
  SysUtils, fpcunit, testregistry, Http2.Errors;

type
  TErrorsTest = class(TTestCase)
  published
    procedure TestHierarchyIsComplete;
    procedure TestDefaultErrorCodeIsInternal;
    procedure TestExplicitErrorCodeIsKept;
    procedure TestStreamErrorCarriesStreamId;
    procedure TestExceptionRaiseAndCatchByBase;
    procedure TestErrorCodeNames;
  end;

implementation

procedure TErrorsTest.TestHierarchyIsComplete;
begin
  AssertTrue('EHttpConnectionError is EHttpError',
    EHttpConnectionError.InheritsFrom(EHttpError));
  AssertTrue('EHttpProtocolError is EHttpError',
    EHttpProtocolError.InheritsFrom(EHttpError));
  AssertTrue('EHttpStreamError is EHttpError',
    EHttpStreamError.InheritsFrom(EHttpError));
  AssertTrue('EHttpTimeout is EHttpError',
    EHttpTimeout.InheritsFrom(EHttpError));
  AssertTrue('EHttpConnectionClosed is EHttpError',
    EHttpConnectionClosed.InheritsFrom(EHttpError));
  AssertTrue('EHttpTooManyRedirects is EHttpError',
    EHttpTooManyRedirects.InheritsFrom(EHttpError));
  AssertTrue('EHttpNotReplayable is EHttpError',
    EHttpNotReplayable.InheritsFrom(EHttpError));
  AssertTrue('EHttpError is Exception',
    EHttpError.InheritsFrom(Exception));
end;

procedure TErrorsTest.TestDefaultErrorCodeIsInternal;
var
  E: EHttpError;
begin
  E := EHttpError.Create('boom');
  try
    AssertEquals('default code', Ord(ecInternalError), Ord(E.ErrorCode));
    AssertEquals('message', 'boom', E.Message);
  finally
    E.Free;
  end;
end;

procedure TErrorsTest.TestExplicitErrorCodeIsKept;
var
  E: EHttpProtocolError;
begin
  E := EHttpProtocolError.Create('bad frame', ecFrameSizeError);
  try
    AssertEquals('code', Ord(ecFrameSizeError), Ord(E.ErrorCode));
  finally
    E.Free;
  end;
end;

procedure TErrorsTest.TestStreamErrorCarriesStreamId;
var
  E: EHttpStreamError;
begin
  E := EHttpStreamError.Create('reset', 7, ecRefusedStream);
  try
    AssertEquals('stream id', 7, E.StreamId);
    AssertEquals('code', Ord(ecRefusedStream), Ord(E.ErrorCode));
  finally
    E.Free;
  end;
end;

procedure TErrorsTest.TestExceptionRaiseAndCatchByBase;
var
  Caught: Boolean;
  Code: THttp2ErrorCode;
begin
  Caught := False;
  try
    raise EHttpStreamError.Create('nope', 3, ecCancel);
  except
    on E: EHttpError do
    begin
      Caught := True;
      Code := E.ErrorCode;
      AssertEquals('stream id survived polymorphic catch', 3,
        (E as EHttpStreamError).StreamId);
    end;
  end;
  AssertTrue('caught via base class', Caught);
  AssertEquals('code survived', Ord(ecCancel), Ord(Code));
end;

procedure TErrorsTest.TestErrorCodeNames;
begin
  AssertEquals('NO_ERROR', Http2ErrorCodeName(ecNoError));
  AssertEquals('PROTOCOL_ERROR', Http2ErrorCodeName(ecProtocolError));
  AssertEquals('FLOW_CONTROL_ERROR', Http2ErrorCodeName(ecFlowControlError));
  AssertEquals('FRAME_SIZE_ERROR', Http2ErrorCodeName(ecFrameSizeError));
  AssertEquals('COMPRESSION_ERROR', Http2ErrorCodeName(ecCompressionError));
  AssertEquals('HTTP_1_1_REQUIRED', Http2ErrorCodeName(ecHttp11Required));
end;

initialization
  RegisterTest(TErrorsTest);
end.
