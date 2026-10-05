{$mode objfpc}{$H+}
program probe7;
uses SysUtils, Classes;
var
  Ev: PRTLEvent;
  T: TThread;
begin
  Ev := RTLEventCreate;
  RTLEventSetEvent(Ev);
  RTLEventWaitFor(Ev, 0); WriteLn('RTLEvent ok');
  RTLEventDestroy(Ev);
  WriteLn('done');
end.
