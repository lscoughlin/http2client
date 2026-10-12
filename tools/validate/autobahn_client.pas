/// Autobahn|Testsuite client driver (doc/design/websocket.md).
// - connects to a running `wstest -m fuzzingserver`, runs every case with an
//   echo listener, then asks the server to write its report.
//   usage: autobahn_client host:port   (see tools/validate/websocket-live.sh)
program autobahn_client;

{$mode delphi}{$H+}
{$interfaces com}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils, SyncObjs, Http2.Errors, Http2.Client, Http2.WebSocket;

type
  /// echoes whole messages back, re-assembling fragments first
  TEcho = class(TWebSocketListener)
  private
    FText: string;
    FBin: TBytes;
  public
    Done: TEvent;
    Last: string;       // the first text message (the case count)
    Failed: string;
    constructor Create;
    destructor Destroy; override;
    procedure OnText(const ASocket: IWebSocket; const AText: string;
      const ALast: Boolean); override;
    procedure OnBytes(const ASocket: IWebSocket; const AData: TBytes;
      const ALast: Boolean); override;
    procedure OnClose(const ASocket: IWebSocket; const AStatusCode: Integer;
      const AReason: string); override;
    procedure OnError(const ASocket: IWebSocket;
      const AError: Exception); override;
  end;

constructor TEcho.Create;
begin
  inherited Create;
  Done := TEvent.Create(nil, True, False, '');
end;

destructor TEcho.Destroy;
begin
  Done.Free;
  inherited Destroy;
end;

procedure TEcho.OnText(const ASocket: IWebSocket; const AText: string;
  const ALast: Boolean);
begin
  FText := FText + AText;
  if ALast then
  begin
    if Last = '' then
      Last := FText;
    ASocket.SendText(FText);
    FText := '';
  end;
end;

procedure TEcho.OnBytes(const ASocket: IWebSocket; const AData: TBytes;
  const ALast: Boolean);
var
  N: Integer;
begin
  N := Length(FBin);
  SetLength(FBin, N + Length(AData));
  if Length(AData) > 0 then
    Move(AData[0], FBin[N], Length(AData));
  if ALast then
  begin
    ASocket.SendBinary(FBin);
    SetLength(FBin, 0);
  end;
end;

procedure TEcho.OnClose(const ASocket: IWebSocket; const AStatusCode: Integer;
  const AReason: string);
begin
  Done.SetEvent;
end;

procedure TEcho.OnError(const ASocket: IWebSocket; const AError: Exception);
begin
  Failed := AError.ClassName + ': ' + AError.Message;
  Done.SetEvent;
end;

var
  Client: IHttpClient;
  Server: string;

function Run(const APath: string; const ATimeoutMs: Integer): TEcho;
var
  Sock: IWebSocket;
begin
  Result := TEcho.Create;
  Result._AddRef;                 // the request holds it too
  try
    Sock := Client.Send(TWebSocketRequest.Create('ws://' + Server + APath, Result)
      .WithMaxMessageBytes(0).WithAutoRequest.WithCloseTimeoutMs(2000));
    if Result.Done.WaitFor(ATimeoutMs) <> wrSignaled then
    begin
      Result.Failed := 'timed out';
      Sock.Abort;
    end;
  except
    on E: Exception do
      Result.Failed := E.ClassName + ': ' + E.Message;
  end;
end;

var
  Count, I: Integer;
  E: TEcho;
  Errors: Integer;
begin
  if ParamCount < 1 then
  begin
    WriteLn('usage: autobahn_client host:port');
    Halt(2);
  end;
  Server := ParamStr(1);
  Client := THttpClientFactory.Create.WithConnectTimeout(10000).Build;
  E := Run('/getCaseCount', 20000);
  Count := StrToIntDef(E.Last, 0);
  if Count = 0 then
  begin
    WriteLn('could not read the case count: ', E.Failed);
    Halt(2);
  end;
  WriteLn('cases: ', Count);
  Errors := 0;
  for I := 1 to Count do
  begin
    E := Run(Format('/runCase?case=%d&agent=http2client', [I]), 90000);
    if E.Failed <> '' then
    begin
      Inc(Errors);
      WriteLn('case ', I, ': ', E.Failed);
    end;
  end;
  Run('/updateReports?agent=http2client', 30000);
  WriteLn('driver finished; connection-level errors: ', Errors);
end.
