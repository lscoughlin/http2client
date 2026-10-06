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
  Http2.ConnectionThread.Test, Http2.ConnectionLifecycle.Test,
  Http2.Stream.Test, Http2.Client.Test, Http2.Request.Test,
  Http2.Redirects.Test, Http2.Timeouts.Test,
  Http2.MockSocket, Http2.HpackProps.Test, Http2.Concurrency.Test,
  Http2.ProbeOutcome.Test, Http2.ClearText.Test;

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
