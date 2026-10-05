/// fpcunit console runner for the http2client test suite
// - run with `make test`; returns exit code 0 when all tests pass
unit Http2.TestRunner;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$interfaces com}

interface

implementation

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils, fpcunit, testregistry, consoletestrunner,
  Http2.Errors.Test, Http2.Frames.Test, Http2.Headers.Test, Http2.Hpack.Test,
  Http2.FlowControl.Test, Http2.Tls.Test, Http2.BlockingQueue.Test,
  Http2.ConnectionThread.Test;

type
  TTestProbe = class(TTestCase)
  published
    procedure TestSkeletonIsWired;
  end;

procedure TTestProbe.TestSkeletonIsWired;
begin
  AssertTrue('fpcunit runner is wired', True);
end;

initialization
  RegisterTest(TTestProbe);
end.
