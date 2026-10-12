/// The opt-in live proxy gate (doc/design/proxy.md; tools/validate/proxy-live.sh).
// - skipped unless PROXY_LIVE_PORTS and PROXY_LIVE_CA are set; the default
//   suite stays hermetic.  The script starts tools/validate/proxy_servers.py
//   twice (open proxies, and proxies that require bob:pw), points these
//   variables at them, runs this suite, then checks the servers' logs to prove
//   which route every request took.
unit Http2.ProxyLive.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$interfaces com}

interface

uses
  SysUtils, Classes, fpcunit, testregistry, Http2.Errors, Http2.Tls,
  Http2.Stream, Http2.Messages, Http2.Proxy, Http2.Client;

type
  TProxyLiveTest = class(TTestCase)
  private
    FCa: string;
    FOpen, FAuth: Integer;      // base ports of the two server instances
    function Enabled: Boolean;
    function Get(const AFactory: THttpClientFactory; const AUrl: string): string;
    function Base(const AFactory: THttpClientFactory): THttpClientFactory;
    procedure CheckHttp2(const AProxyUrl: string);
  published
    procedure TestHttpConnectProxy;
    procedure TestProxyEnvironmentVariables;
    procedure TestSocks5ProxyTunnelsHttpsAndHttp;
    procedure TestHttpsProxyCarriesTlsInsideTls;
    procedure TestBasicAuthAcceptedAndRejected;
    procedure TestSocks5AuthAcceptedAndRejected;
    procedure TestLoopbackBypassesTheProxy;
    // HTTP/2 end to end: strict mode (no fallback), so a connection that did
    // not negotiate h2 fails loudly, over nghttpd with a 100 KB body
    procedure TestHttp2ThroughAnHttpConnectProxy;
    procedure TestHttp2ThroughAnHttpsProxy;
    procedure TestHttp2ThroughASocks5Proxy;
  end;

implementation

var
  GEnvLookupHttps: string;

function LiveLookup(const AName: string): string;
begin
  Result := '';
  if AName = 'https_proxy' then
    Result := GEnvLookupHttps;
end;

function TProxyLiveTest.Enabled: Boolean;
var
  Ports: string;
  P: Integer;
begin
  Result := False;
  Ports := GetEnvironmentVariable('PROXY_LIVE_PORTS');
  FCa := GetEnvironmentVariable('PROXY_LIVE_CA');
  if (Ports = '') or (FCa = '') then
    Exit;
  P := Pos(',', Ports);
  FOpen := StrToIntDef(Copy(Ports, 1, P - 1), 0);
  FAuth := StrToIntDef(Copy(Ports, P + 1, MaxInt), 0);
  Result := (FOpen > 0) and (FAuth > 0);
end;

function TProxyLiveTest.Base(const AFactory: THttpClientFactory): THttpClientFactory;
begin
  // the origins speak HTTP/1.1 only: take the fallback; trust the test CA
  // bundle (it names other.example and localhost)
  Result := AFactory.WithHttp1Fallback(True).WithClearText(ctUpgrade)
    .WithCACertFile(FCa).WithConnectTimeout(5000).WithHeaderTimeout(8000);
end;

function TProxyLiveTest.Get(const AFactory: THttpClientFactory;
  const AUrl: string): string;
var
  Client: IHttpClient;
  R: IHttpResponse;
  B: TBytes;
  I: Integer;
begin
  Client := Base(AFactory).Build;
  try
    R := Client.Send(THttpRequest.Create(hmGet, AUrl));
    AssertEquals(AUrl + ' status', 200, R.StatusCode);
    B := ReadAllBodyBytes(R.Body);
    SetLength(Result, Length(B));
    for I := 0 to High(B) do
      Result[I + 1] := Chr(B[I]);
  finally
    Client.Close;
  end;
end;

procedure TProxyLiveTest.TestHttpConnectProxy;
begin
  if not Enabled then Exit;
  AssertEquals('origin-tls', Get(THttpClientFactory.Create
    .WithProxy('127.0.0.1', FOpen + 2), 'https://other.example/'));
  AssertEquals('origin-plain', Get(THttpClientFactory.Create
    .WithProxy('127.0.0.1', FOpen + 2), 'http://other.example/'));
end;

procedure TProxyLiveTest.TestProxyEnvironmentVariables;
begin
  if not Enabled then Exit;
  GEnvLookupHttps := 'http://127.0.0.1:' + IntToStr(FOpen + 2);
  AssertEquals('origin-tls', Get(THttpClientFactory.Create
    .WithProxyEnvironmentLookup(LiveLookup).WithProxyEnvironmentVars,
    'https://other.example/'));
end;

procedure TProxyLiveTest.TestSocks5ProxyTunnelsHttpsAndHttp;
begin
  if not Enabled then Exit;
  AssertEquals('origin-tls', Get(THttpClientFactory.Create
    .WithAllProxy('socks5://127.0.0.1:' + IntToStr(FOpen + 4)),
    'https://other.example/'));
  AssertEquals('origin-plain', Get(THttpClientFactory.Create
    .WithAllProxy('socks5h://127.0.0.1:' + IntToStr(FOpen + 4)),
    'http://other.example/'));
end;

procedure TProxyLiveTest.TestHttpsProxyCarriesTlsInsideTls;
begin
  if not Enabled then Exit;
  AssertEquals('origin-tls', Get(THttpClientFactory.Create
    .WithAllProxy('https://127.0.0.1:' + IntToStr(FOpen + 3)),
    'https://other.example/'));
end;

procedure TProxyLiveTest.TestBasicAuthAcceptedAndRejected;
var
  Msg: string;
begin
  if not Enabled then Exit;
  AssertEquals('origin-tls', Get(THttpClientFactory.Create
    .WithAllProxy('http://bob:pw@127.0.0.1:' + IntToStr(FAuth + 2)),
    'https://other.example/'));
  Msg := '';
  try
    Get(THttpClientFactory.Create
      .WithAllProxy('http://bob:WRONGPW@127.0.0.1:' + IntToStr(FAuth + 2)),
      'https://other.example/');
  except
    on E: EHttpConnectionError do
      Msg := E.Message;
  end;
  AssertTrue('407 reported: ' + Msg, Pos('407', Msg) > 0);
  AssertEquals('password not in the message', 0, Pos('WRONGPW', Msg));
end;

procedure TProxyLiveTest.TestSocks5AuthAcceptedAndRejected;
var
  Msg: string;
begin
  if not Enabled then Exit;
  AssertEquals('origin-tls', Get(THttpClientFactory.Create
    .WithAllProxy('socks5://bob:pw@127.0.0.1:' + IntToStr(FAuth + 4)),
    'https://other.example/'));
  Msg := '';
  try
    Get(THttpClientFactory.Create
      .WithAllProxy('socks5://bob:WRONGPW@127.0.0.1:' + IntToStr(FAuth + 4)),
      'https://other.example/');
  except
    on E: EHttpConnectionError do
      Msg := E.Message;
  end;
  AssertTrue('rejection reported: ' + Msg, Pos('rejected the credentials', Msg) > 0);
  AssertEquals('password not in the message', 0, Pos('WRONGPW', Msg));
end;

procedure TProxyLiveTest.TestLoopbackBypassesTheProxy;
begin
  if not Enabled then Exit;
  // the proxy here refuses everything but other.example, so success proves the
  // request never went through it
  AssertEquals('origin-tls', Get(THttpClientFactory.Create
    .WithProxy('127.0.0.1', FOpen + 2).WithInsecureTls,
    'https://localhost:' + IntToStr(FOpen) + '/'));
end;

procedure TProxyLiveTest.CheckHttp2(const AProxyUrl: string);
var
  H2Base: Integer;
  Client: IHttpClient;
  R: IHttpResponse;
  B: TBytes;
  I: Integer;
begin
  if not Enabled then Exit;
  H2Base := StrToIntDef(GetEnvironmentVariable('PROXY_LIVE_H2_BASE'), 0);
  if H2Base = 0 then Exit;           // nghttpd was not available
  // strict: no WithHttp1Fallback, so anything but ALPN h2 raises
  Client := THttpClientFactory.Create.WithCACertFile(FCa)
    .WithConnectTimeout(5000).WithHeaderTimeout(10000)
    .WithAllProxy(StringReplace(AProxyUrl, '%d', IntToStr(H2Base), [])).Build;
  try
    // two requests: the second reuses the tunnelled h2 connection
    for I := 1 to 2 do
    begin
      R := Client.Send(THttpRequest.Create(hmGet, 'https://other.example/big.bin'));
      AssertEquals('status', 200, R.StatusCode);
      B := ReadAllBodyBytes(R.Body);
      AssertEquals('100 KB body arrived whole (flow control through the tunnel)',
        100000, Length(B));
    end;
    AssertEquals('one TCP connection carried both requests', 1,
      (Client as THttpClient).Pool.ConnectionCount);
  finally
    Client.Close;
  end;
end;

procedure TProxyLiveTest.TestHttp2ThroughAnHttpConnectProxy;
begin
  CheckHttp2('http://127.0.0.1:' + IntToStr(StrToIntDef(
    GetEnvironmentVariable('PROXY_LIVE_H2_BASE'), 0) + 2));
end;

procedure TProxyLiveTest.TestHttp2ThroughAnHttpsProxy;
begin
  CheckHttp2('https://127.0.0.1:' + IntToStr(StrToIntDef(
    GetEnvironmentVariable('PROXY_LIVE_H2_BASE'), 0) + 3));
end;

procedure TProxyLiveTest.TestHttp2ThroughASocks5Proxy;
begin
  CheckHttp2('socks5://127.0.0.1:' + IntToStr(StrToIntDef(
    GetEnvironmentVariable('PROXY_LIVE_H2_BASE'), 0) + 4));
end;

initialization
  RegisterTest(TProxyLiveTest);
end.
