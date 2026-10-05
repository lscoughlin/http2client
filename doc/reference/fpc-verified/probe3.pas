{$mode objfpc}{$H+}
{$modeswitch advancedrecords}
{$interfaces com}
program probe3;
uses SysUtils, Classes, Generics.Collections, SyncObjs;

type
  TProbe = class(TInterfacedObject)
  public
    destructor Destroy; override;
  end;

  TFrameRec = record
    StreamId: LongWord;
    Flags: set of (ffEndStream, ffEndHeaders, ffAck);
  end;

destructor TProbe.Destroy;
begin
  WriteLn('TProbe destroyed (refcount reached 0)');
  inherited;
end;

var
  Q: specialize TQueue<TFrameRec>;
  Item: TFrameRec;
  O: TObject;
  S: TStringList;
  D: specialize TDictionary<string, Integer>;
begin
  { TQueue basic API }
  Q := specialize TQueue<TFrameRec>.Create;
  Item.StreamId := 7;
  Item.Flags := [ffEndHeaders];
  Q.Enqueue(Item);
  WriteLn('queue count=', Q.Count);
  Item := Q.Dequeue;
  WriteLn('dequeued streamid=', Item.StreamId);
  Q.Free;

  { interface refcount release }
  O := TProbe.Create;
  WriteLn('obj created');
  O := nil;
  WriteLn('after nil');

  { TStringList: does Remove exist in FPC 3.2.4? }
  S := TStringList.Create;
  S.Add('a');
  try
    S.Delete(S.IndexOf('a'));
    WriteLn('IndexOf+Delete ok');
  finally
    S.Free;
  end;

  { dictionary }
  D := specialize TDictionary<string, Integer>.Create;
  D.Add('a', 1);
  WriteLn('dict a=', D['a']);
  D.Free;
  WriteLn('done');
end.
