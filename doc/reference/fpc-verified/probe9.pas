{$mode delphi}
program probe9;
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
  TUtil.Foo<Integer>(I);
  WriteLn('delphi generic method ok: ', I);
end.
