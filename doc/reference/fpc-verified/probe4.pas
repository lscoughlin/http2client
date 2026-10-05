{$mode objfpc}{$H+}
{$modeswitch advancedrecords}
{$interfaces com}
program probe4;
uses SysUtils, Classes;

type
  IThing = interface ['{11111111-2222-3333-4444-555555555555}']
    function Name: string;
  end;
  TThing = class(TInterfacedObject, IThing)
  public
    destructor Destroy; override;
    function Name: string;
  end;

destructor TThing.Destroy;
begin
  WriteLn('TThing destroyed (ARC reached 0)');
  inherited;
end;
function TThing.Name: string;
begin
  Result := 'thing';
end;

var
  T: IThing;
  S: TStringList;
begin
  T := TThing.Create;
  WriteLn('created, name=', T.Name);
  T := nil;
  WriteLn('after nil');

  S := TStringList.Create;
  try
    try
      WriteLn('skipped Remove probe');
      WriteLn('TStringList.Remove EXISTS');
    except
      WriteLn('TStringList.Remove raised');
    end;
  finally
    S.Free;
  end;
  WriteLn('done');
end.
