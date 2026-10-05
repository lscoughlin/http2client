/// Program entry point for the http2client test suite (`make test`)
program Http2.RunTests;

{$mode delphi}{$H+}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils, consoletestrunner, Http2.TestRunner;

var
  App: TTestRunner;
begin
  App := TTestRunner.Create(nil);
  try
    App.Initialize;
    App.Title := 'http2client test suite';
    App.Run;
  finally
    App.Free;
  end;
end.
