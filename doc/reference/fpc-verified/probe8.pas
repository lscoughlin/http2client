{$mode objfpc}{$H+}
program probe8;
uses SysUtils, Classes, SyncObjs, Generics.Collections;
var
  C: TCriticalSection;
  Q: specialize TQueue<Integer>;
begin
  C := TCriticalSection.Create;
  C.Acquire; C.Release; WriteLn('TCriticalSection Acquire/Release ok'); C.Free;

  Q := specialize TQueue<Integer>.Create;
  Q.Enqueue(1);
  WriteLn('TQueue threadsafety: Count=', Q.Count);
  Q.Free;
  WriteLn('done');
end.
