{$mode objfpc}{$H+}
{$modeswitch advancedrecords}
{$interfaces com}
program probe2;
uses SysUtils, Classes, Generics.Collections, SyncObjs;

type
  IGreeter = interface
    function Hello: string;
  end;
  TGreeter = class(TInterfacedObject, IGreeter)
  public
    function Hello: string;
  end;

  { generic class with a method that uses T }
  generic TResponseReader<T> = class
  public
    class procedure Read(const AResponse: IGreeter; out AValue: T);
  end;

  { generic record }
  generic TRecBox<T> = record
  private
    FValue: T;
  public
    class function Create(const AValue: T): TRecBox; static;
    function Value: T;
  end;

function TGreeter.Hello: string;
begin
  Result := 'hi';
end;

class procedure TResponseReader.Read(const AResponse: IGreeter; out AValue: T);
var
  S: string;
begin
  S := AResponse.Hello;
  PString(@AValue)^ := S;   // only valid when T=string, for probe purposes
end;

class function TRecBox.Create(const AValue: T): TRecBox;
begin
  Result.FValue := AValue;
end;

function TRecBox.Value: T;
begin
  Result := FValue;
end;

var
  G: IGreeter;
  V: string;
  B: specialize TRecBox<Integer>;
begin
  G := TGreeter.Create;
  specialize TResponseReader<string>.Read(G, V);
  WriteLn('generic class method V=', V);
  B := specialize TRecBox<Integer>.Create(42);
  WriteLn('generic record B=', B.Value);
  WriteLn('all ok');
end.
