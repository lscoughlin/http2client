{$mode objfpc}{$H+}
{$modeswitch genericmethods}
program probe10;
uses SysUtils;
type
  TUtil = class
  public
    class procedure Foo<T>(out AValue: T); static;
  end;
class procedure TUtil.Foo<T>(out AValue: T);
begin
  FillChar(AValue, SizeOf(T), 0);
end;
var
  I: Integer;
begin
  specialize TUtil.Foo<Integer>(I);
  WriteLn('objfpc genericmethod ok: ', I);
end.
