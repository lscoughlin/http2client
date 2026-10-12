/// The opt-in live WebSocket gate (doc/design/websocket.md;
/// tools/validate/websocket-live.sh).
// - skipped unless WS_LIVE_PORTS ("<ws base>,<proxy base>") and WS_LIVE_CA are
//   set.  The script starts tools/validate/ws_servers.py (plain and TLS) and
//   tools/validate/proxy_servers.py, then reads the servers' logs to prove
//   what each connection did: the mask bit of every client frame, the close
//   codes, the route through each proxy kind.
unit Http2.WebSocketLive.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$interfaces com}

interface

uses
  SysUtils, Classes, fpcunit, testregistry, Http2.Errors, Http2.Client,
  Http2.WebSocket, Http2.WebSocketClient.Test;

type
  TWebSocketLiveTest = class(TTestCase)
  private
    FCa: string;
    FWs, FProxy: Integer;
    function Enabled: Boolean;
    function NewClient(const AFactory: THttpClientFactory): IHttpClient;
    function Connect(const AClient: IHttpClient; const AUrl: string;
      const ARec: TRecorder; const AListener: IWebSocketListener): IWebSocket;
    procedure EchoAndClose(const AClient: IHttpClient; const AUrl: string);
  published
    procedure TestEchoPlainTextBinaryAndLarge;
    procedure TestEchoOverTlsSurvivesIdlePolling;
    procedure TestConcurrentSendsOverTls;
    procedure TestServerPingIsAnsweredAndReported;
    procedure TestClientCloseCarriesCodeAndReason;
    procedure TestServerCloseIsEchoedWithItsCode;
    procedure TestFragmentedReceiveWithInterleavedPing;
    procedure TestBadUtf8IsAnsweredWith1007;
    procedure TestDropIsReportedAsAnError;
    procedure TestSubprotocolIsNegotiated;
    procedure TestThroughHttpConnectProxy;
    procedure TestThroughHttpsProxyTlsInsideTls;
    procedure TestThroughSocks5Proxy;
    procedure TestEnvironmentProxyAppliesToWs;
  end;

implementation

type
  TTlsSender = class(TThread)
  private
    FSock: IWebSocket;
    FIndex: Integer;
  protected
    procedure Execute; override;
  public
    constructor Create(const ASock: IWebSocket; const AIndex: Integer);
  end;

constructor TTlsSender.Create(const ASock: IWebSocket; const AIndex: Integer);
begin
  FSock := ASock;
  FIndex := AIndex;
  inherited Create(False);
  FreeOnTerminate := False;
end;

procedure TTlsSender.Execute;
var
  I: Integer;
begin
  for I := 0 to 49 do
    FSock.SendText(Format('s%d-%.3d', [FIndex, I]));
end;

var
  GHttpProxy: string;

function LiveLookup(const AName: string): string;
begin
  Result := '';
  if AName = 'http_proxy' then
    Result := GHttpProxy;
end;

function TWebSocketLiveTest.Enabled: Boolean;
var
  Ports: string;
  P: Integer;
begin
  Result := False;
  Ports := GetEnvironmentVariable('WS_LIVE_PORTS');
  FCa := GetEnvironmentVariable('WS_LIVE_CA');
  if (Ports = '') or (FCa = '') then
    Exit;
  P := Pos(',', Ports);
  FWs := StrToIntDef(Copy(Ports, 1, P - 1), 0);
  FProxy := StrToIntDef(Copy(Ports, P + 1, MaxInt), 0);
  Result := (FWs > 0) and (FProxy > 0);
end;

function TWebSocketLiveTest.NewClient(const AFactory: THttpClientFactory): IHttpClient;
begin
  Result := AFactory.WithCACertFile(FCa).WithConnectTimeout(5000).Build;
end;

function TWebSocketLiveTest.Connect(const AClient: IHttpClient;
  const AUrl: string; const ARec: TRecorder;
  const AListener: IWebSocketListener): IWebSocket;
begin
  Result := AClient.Send(TWebSocketRequest.Create(AUrl, AListener)
    .WithMaxMessageBytes(0));
end;

procedure TWebSocketLiveTest.EchoAndClose(const AClient: IHttpClient;
  const AUrl: string);
var
  Rec: TRecorder;
  Ref: IWebSocketListener;
  Sock: IWebSocket;
begin
  Rec := TRecorder.Create(8);
  Ref := Rec;
  Sock := Connect(AClient, AUrl, Rec, Ref);
  AssertTrue('open', Rec.WaitCount(1));
  Sock.SendText('through ' + AUrl);
  AssertTrue('echo', Rec.WaitCount(2));
  AssertEquals('text:through ' + AUrl + ':1', Rec.Item(1));
  Sock.Close(1000, 'done');
  AssertTrue('close', Rec.WaitCount(3));
  AssertEquals('close:1000:done', Rec.Item(2));
end;

procedure TWebSocketLiveTest.TestEchoPlainTextBinaryAndLarge;
var
  Rec: TRecorder;
  Ref: IWebSocketListener;
  Sock: IWebSocket;
  B: TBytes;
  C: IHttpClient;
begin
  if not Enabled then Exit;
  C := NewClient(THttpClientFactory.Create);
  Rec := TRecorder.Create(100);
  Ref := Rec;
  Sock := Connect(C, 'ws://127.0.0.1:' + IntToStr(FWs) + '/echo', Rec, Ref);
  AssertTrue(Rec.WaitCount(1));
  Sock.SendText('hello');
  SetLength(B, 1024);
  Sock.SendBinary(B);
  SetLength(B, 1024 * 1024);
  Sock.SendBinary(B);
  AssertTrue('three echoes', Rec.WaitCount(4, 15000));
  AssertEquals('text:hello:1', Rec.Item(1));
  AssertEquals('bytes:1024:1', Rec.Item(2));
  AssertEquals('bytes:1048576:1', Rec.Item(3));
  Sock.Close;
  AssertTrue(Rec.WaitCount(5));
end;

procedure TWebSocketLiveTest.TestEchoOverTlsSurvivesIdlePolling;
var
  Rec: TRecorder;
  Ref: IWebSocketListener;
  Sock: IWebSocket;
  B: TBytes;
  C: IHttpClient;
begin
  if not Enabled then Exit;
  C := NewClient(THttpClientFactory.Create);
  Rec := TRecorder.Create(100);
  Ref := Rec;
  Sock := Connect(C, 'wss://127.0.0.1:' + IntToStr(FWs + 1) + '/echo', Rec, Ref);
  AssertTrue(Rec.WaitCount(1));
  // silence for several poll intervals: the TLS state must stay usable
  Sleep(250);
  Sock.SendText('after silence');
  AssertTrue(Rec.WaitCount(2));
  AssertEquals('text:after silence:1', Rec.Item(1));
  SetLength(B, 1024 * 1024);
  Sock.SendBinary(B);
  AssertTrue('large echo over TLS', Rec.WaitCount(3, 15000));
  Sleep(250);
  Sock.SendText('and again');
  AssertTrue(Rec.WaitCount(4));
  Sock.Close;
  AssertTrue(Rec.WaitCount(5));
end;

procedure TWebSocketLiveTest.TestConcurrentSendsOverTls;
var
  Rec: TRecorder;
  Ref: IWebSocketListener;
  Sock: IWebSocket;
  T: array[0..3] of TTlsSender;
  I: Integer;
begin
  if not Enabled then Exit;
  Rec := TRecorder.Create(1000);
  Ref := Rec;
  Sock := Connect(NewClient(THttpClientFactory.Create),
    'wss://127.0.0.1:' + IntToStr(FWs + 1) + '/echo', Rec, Ref);
  AssertTrue(Rec.WaitCount(1));
  // senders and the reader share one TLS state
  for I := 0 to 3 do
    T[I] := TTlsSender.Create(Sock, I);
  for I := 0 to 3 do
  begin
    T[I].WaitFor;
    T[I].Free;
  end;
  AssertTrue('all 200 echoes arrived', Rec.WaitCount(201, 15000));
  Sock.Close;
end;

procedure TWebSocketLiveTest.TestServerPingIsAnsweredAndReported;
var
  Rec: TRecorder;
  Ref: IWebSocketListener;
  Sock: IWebSocket;
begin
  if not Enabled then Exit;
  Rec := TRecorder.Create(5);
  Ref := Rec;
  Sock := Connect(NewClient(THttpClientFactory.Create),
    'ws://127.0.0.1:' + IntToStr(FWs) + '/serverping', Rec, Ref);
  AssertTrue(Rec.WaitCount(2));
  AssertEquals('ping:3', Rec.Item(1));
  Sock.SendPing(nil);
  AssertTrue('pong for our ping', Rec.WaitCount(3));
  AssertEquals('pong:0', Rec.Item(2));
  Sock.Close;
end;

procedure TWebSocketLiveTest.TestClientCloseCarriesCodeAndReason;
begin
  if not Enabled then Exit;
  EchoAndClose(NewClient(THttpClientFactory.Create),
    'ws://127.0.0.1:' + IntToStr(FWs) + '/echo');
end;

procedure TWebSocketLiveTest.TestServerCloseIsEchoedWithItsCode;
var
  Rec: TRecorder;
  Ref: IWebSocketListener;
begin
  if not Enabled then Exit;
  Rec := TRecorder.Create(2);
  Ref := Rec;
  Connect(NewClient(THttpClientFactory.Create),
    'ws://127.0.0.1:' + IntToStr(FWs) + '/serverclose', Rec, Ref);
  AssertTrue(Rec.WaitCount(2));
  AssertEquals('close:1001:going', Rec.Item(1));
end;

procedure TWebSocketLiveTest.TestFragmentedReceiveWithInterleavedPing;
var
  Rec: TRecorder;
  Ref: IWebSocketListener;
begin
  if not Enabled then Exit;
  Rec := TRecorder.Create(5);
  Ref := Rec;
  Connect(NewClient(THttpClientFactory.Create),
    'ws://127.0.0.1:' + IntToStr(FWs) + '/frag', Rec, Ref);
  AssertTrue(Rec.WaitCount(4));
  AssertEquals('text:he:0', Rec.Item(1));
  AssertEquals('ping:1', Rec.Item(2));
  AssertEquals('text:llo:1', Rec.Item(3));
end;

procedure TWebSocketLiveTest.TestBadUtf8IsAnsweredWith1007;
var
  Rec: TRecorder;
  Ref: IWebSocketListener;
begin
  if not Enabled then Exit;
  Rec := TRecorder.Create(2);
  Ref := Rec;
  Connect(NewClient(THttpClientFactory.Create),
    'ws://127.0.0.1:' + IntToStr(FWs) + '/badutf8', Rec, Ref);
  AssertTrue(Rec.WaitCount(2));
  AssertEquals('error:EHttpWebSocketProtocolError', Rec.Item(1));
  AssertEquals(1007, Rec.ErrorCode);
end;

procedure TWebSocketLiveTest.TestDropIsReportedAsAnError;
var
  Rec: TRecorder;
  Ref: IWebSocketListener;
begin
  if not Enabled then Exit;
  Rec := TRecorder.Create(2);
  Ref := Rec;
  Connect(NewClient(THttpClientFactory.Create),
    'ws://127.0.0.1:' + IntToStr(FWs) + '/drop', Rec, Ref);
  AssertTrue(Rec.WaitCount(2));
  AssertEquals('error:EHttpConnectionError', Rec.Item(1));
end;

procedure TWebSocketLiveTest.TestSubprotocolIsNegotiated;
var
  Rec: TRecorder;
  Ref: IWebSocketListener;
  Sock: IWebSocket;
begin
  if not Enabled then Exit;
  Rec := TRecorder.Create(1);
  Ref := Rec;
  Sock := NewClient(THttpClientFactory.Create).Send(
    TWebSocketRequest.Create('ws://127.0.0.1:' + IntToStr(FWs) + '/protocol', Ref)
      .WithSubprotocol('chat').WithSubprotocol('superchat'));
  AssertEquals('chat', Sock.Subprotocol);
  Sock.Abort;
end;

procedure TWebSocketLiveTest.TestThroughHttpConnectProxy;
var
  C: IHttpClient;
begin
  if not Enabled then Exit;
  C := NewClient(THttpClientFactory.Create
    .WithProxy('127.0.0.1', FProxy + 2));
  EchoAndClose(C, 'ws://other.example/echo');
  EchoAndClose(C, 'wss://other.example/echo');
end;

procedure TWebSocketLiveTest.TestThroughHttpsProxyTlsInsideTls;
var
  C: IHttpClient;
begin
  if not Enabled then Exit;
  C := NewClient(THttpClientFactory.Create
    .WithAllProxy('https://127.0.0.1:' + IntToStr(FProxy + 3)));
  EchoAndClose(C, 'ws://other.example/echo');
  EchoAndClose(C, 'wss://other.example/echo');
end;

procedure TWebSocketLiveTest.TestThroughSocks5Proxy;
var
  C: IHttpClient;
begin
  if not Enabled then Exit;
  C := NewClient(THttpClientFactory.Create
    .WithAllProxy('socks5://127.0.0.1:' + IntToStr(FProxy + 4)));
  EchoAndClose(C, 'ws://other.example/echo');
  EchoAndClose(C, 'wss://other.example/echo');
end;

procedure TWebSocketLiveTest.TestEnvironmentProxyAppliesToWs;
var
  C: IHttpClient;
begin
  if not Enabled then Exit;
  GHttpProxy := 'http://127.0.0.1:' + IntToStr(FProxy + 2);
  C := NewClient(THttpClientFactory.Create
    .WithProxyEnvironmentLookup(LiveLookup).WithProxyEnvironmentVars);
  // ws maps to http, so http_proxy applies; loopback is still direct
  EchoAndClose(C, 'ws://other.example/echo');
  EchoAndClose(C, 'ws://127.0.0.1:' + IntToStr(FWs) + '/echo');
end;

initialization
  RegisterTest(TWebSocketLiveTest);
end.
