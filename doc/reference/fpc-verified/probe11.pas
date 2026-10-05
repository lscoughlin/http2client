{$mode objfpc}{$H+}
program probe11;
uses SysUtils, SyncObjs;
var
  Ev: TSimpleEvent;
begin
  Ev := TSimpleEvent.Create;
  Ev.SetEvent;
  WriteLn('TSimpleEvent ok, wait=', Ev.WaitFor(0));
  Ev.Free;
  WriteLn('done');
end.
