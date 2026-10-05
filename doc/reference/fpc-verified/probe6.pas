{$mode objfpc}{$H+}
program probe6;
uses SysUtils, Classes, SyncObjs;
var
  E: TEvent;
  C: TCriticalSection;
begin
  C := TCriticalSection.Create;
  C.Enter; C.Leave; WriteLn('critical section ok'); C.Free;

  E := TEvent.Create(nil, True, False, 'probe-ev');
  WriteLn('named TEvent ok');
  E.SetEvent;
  WriteLn('wait state=', E.WaitFor(0));
  E.Free;
  WriteLn('done');
end.
