{$mode objfpc}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}
program probe;

uses SysUtils, Classes, Generics.Collections, SyncObjs;

type
  IGreeter = interface
    function Hello: string;
  end;

  TGreeter = class(TInterfacedObject, IGreeter)
  public
    function Hello: string;
  end;

  TPointRec = record
  private
    FX: LongInt;
  public
    class function Create(const AX: LongInt): TPointRec; static;
    function WithX(const AX: LongInt): TPointRec;
    function X: LongInt;
  end;

  { generic *class* with a generic method }
  TResponseReader = class
  public
    class procedure Read<T>(const AResponse: IGreeter; out AValue: T); static;
  end;

  { generic class }
  generic TBox<T> = class
  public
    class function Echo(const AValue: T): T;
  end;

function TGreeter.Hello: string;
begin
  Result := 'hi';
end;

class function TPointRec.Create(const AX: LongInt): TPointRec;
begin
  Result.FX := AX;
end;

function TPointRec.WithX(const AX: LongInt): TPointRec;
begin
  Result := Self;
  Result.FX := AX;
end;

function TPointRec.X: LongInt;
begin
  Result := FX;
end;

class procedure TResponseReader.Read<T>(const AResponse: IGreeter;
  out AValue: T);
var
  S: string;
begin
  S := AResponse.Hello;
  if SizeOf(T) = SizeOf(string) then
    PString(@AValue)^ := S
  else
    FillChar(AValue, SizeOf(T), 0);
end;

class function TBox.Echo(const AValue: T): T;
begin
  Result := AValue;
end;

var
  P: TPointRec;
  G: IGreeter;
  V: string;
  Q: TThreadedQueue<Integer>;
  CS: TCriticalSection;
begin
  P := TPointRec.Create(1).WithX(2);
  WriteLn('record fluent X=', P.X);
  G := TGreeter.Create;
  TResponseReader.Read<string>(G, V);
  WriteLn('generic method V=', V);
  WriteLn('generic class Echo=', specialize TBox<Integer>.Echo(7));
  Q := TThreadedQueue<Integer>.Create(4);
  Q.PushItem(5);
  WriteLn('queue pop=', Q.PopItem);
  Q.Free;
  CS := TCriticalSection.Create;
  CS.Enter; CS.Leave; CS.Free;
  WriteLn('all ok');
end.
