/// Proxy routing through the client (doc/design/proxy.md): the builder
/// surface, the per-request selection, and the route-keyed pool.
// - no socket is opened: the frame-level fake from Http2.Redirects.Test
//   answers requests, wrapped in a factory that records the proxy each dial
//   received.  Environment cases use an injected lookup, never the process
//   environment.
unit Http2.ProxyClient.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$interfaces com}

interface

uses
  SysUtils, Classes, SyncObjs, Generics.Collections, fpcunit, testregistry,
  Http2.Errors, Http2.Tls, Http2.Stream, Http2.Messages, Http2.Proxy, Http2.Client,
  Http2.Redirects.Test;

type
  /// a socket factory that takes the route per dial (IProxySocketFactory) and
  /// remembers what it was given, delegating the sockets to the frame fake
  TRouteRecordingFactory = class(TInterfacedObject, IHttp2SocketFactory,
    IProxySocketFactory)
  private
    FInner: TFakeFrameFactory;
    FInnerRef: IHttp2SocketFactory;
    FLock: TCriticalSection;
    FProxies: array of IProxy;
  public
    constructor Create(const AInner: TFakeFrameFactory);
    destructor Destroy; override;
    function Dial(const AHost: string; const APort: Word;
      const ATimeoutMs: Integer): IHttp2Socket;
    function DialProtocolVia(const AHost: string; const APort: Word;
      const AScheme: string; const AHttp1Fallback: Boolean;
      const APolicy: TClearTextPolicy; const ATimeoutMs: Integer;
      const AProxy: IProxy;
      out AProtocol: TNegotiatedProtocol): IHttp2Socket;
    function Dials: Integer;
    /// 'direct' or 'kind:host:port'
    function RouteAt(const AIndex: Integer): string;
  end;

  /// records every URI it is asked about and answers from a rule
  TRecordingSelector = class(TInterfacedObject, IProxySelector)
  private
    FLock: TCriticalSection;
    FUris: TStringList;
  public
    /// URIs containing this text are proxied through ProxyHost:ProxyPort
    ProxiedMarker: string;
    ProxyHost: string;
    ProxyPort: Word;
    RaiseMessage: string;
    BadHost: Boolean;
    constructor Create;
    destructor Destroy; override;
    function SelectProxy(const AUri: string): IProxy;
    function Count: Integer;
    function UriAt(const AIndex: Integer): string;
  end;

  TProxyBuilderTest = class(TTestCase)
  published
    procedure TestDefaults;
    procedure TestWithXReturnsANewRecordAndLeavesTheReceiverUnchanged;
    procedure TestWithNoProxyAppends;
    procedure TestWithNoProxyIgnoresEmpty;
    procedure TestWithAllProxyTrimsAndClears;
    procedure TestBuildRejectsABadAllProxy;
    procedure TestBuildRejectsABadEnvironmentValueOnlyWhenEnabled;
    procedure TestBuildNeverReadsTheEnvironmentWhenOff;
    procedure TestWithProxyKeepsTheProxyHostAndPortProperties;
  end;

  /// a transport with no raw handle (like a TLS socket) on a keep-alive
  /// connection: Read for more than what is buffered would wait for the
  /// server to give up, ReadSome returns at once
  TKeepAliveTlsLike = class(TInterfacedObject, IHttp2Socket, IPartialReader)
  private
    FData: AnsiString;
    FPos: Integer;
  public
    constructor Create(const AData: AnsiString);
    function Read(var ABuffer; ACount: Integer): Integer;
    function ReadSome(var ABuffer; ACount: Integer): Integer;
    function Write(const ABuffer; ACount: Integer): Integer;
    procedure Close;
    function GetConnected: Boolean;
    function GetConnectTimeoutMs: Integer;
    procedure SetConnectTimeoutMs(const AValue: Integer);
    function GetReadTimeoutMs: Integer;
    procedure SetReadTimeoutMs(const AValue: Integer);
    function GetWriteTimeoutMs: Integer;
    procedure SetWriteTimeoutMs(const AValue: Integer);
  end;

  TSingleReadSocketTest = class(TTestCase)
  published
    procedure TestATransportWithoutAHandleIsReadThroughReadSome;
  end;

  TUrlIpv6Test = class(TTestCase)
  private
    procedure AssertParsed(const AUrl, AHost: string; const APort: Word;
      const APath: string);
  published
    procedure TestBracketedHostIsReturnedWithoutBrackets;
    procedure TestPortAndPathAfterBrackets;
    procedure TestUserinfoIsDropped;
    procedure TestMalformedBracketsRaise;
    procedure TestAuthorityAndOriginKeepTheBrackets;
    procedure TestExistingFormsAreUnchanged;
    procedure TestAnIpv6OriginIsDialledAndRouted;
  end;

  TProxyRoutingTest = class(TTestCase)
  private
    function Run(const AFactory: THttpClientFactory; const AUrl: string;
      out ARoutes: TRouteRecordingFactory): IHttpClient;
  published
    procedure TestNoConfigurationDialsDirectlyWithThePlainOriginKey;
    procedure TestWithProxyReachesTheDialAndKeysThePool;
    procedure TestWithAllProxyHttpsProxyAndSocks5;
    procedure TestEnvironmentLookupDrivesTheRoute;
    procedure TestEnvironmentIsIgnoredUnlessSwitchedOn;
    procedure TestWithNoProxyForcesDirectForTheFixedProxy;
    procedure TestLoopbackIsAlwaysDirect;
    procedure TestSelectorBeatsEveryOtherSetting;
    procedure TestEachRedirectHopIsRoutedAgain;
    procedure TestDirectAndProxiedRoutesToOneOriginAreSeparateBuckets;
    procedure TestTwoProxiesAreSeparateBuckets;
    procedure TestSelectorExceptionReachesTheCaller;
    procedure TestSelectorReturningAnUnusableProxyIsAConfigError;
    procedure TestLegacyFactoryIsStillDialledWithoutAProxy;
    procedure TestConcurrentSendsCallTheSelectorOncePerRequest;
  end;

implementation

{ TRouteRecordingFactory }

constructor TRouteRecordingFactory.Create(const AInner: TFakeFrameFactory);
begin
  inherited Create;
  FInner := AInner;
  FInnerRef := AInner;
  FLock := TCriticalSection.Create;
end;

destructor TRouteRecordingFactory.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

function TRouteRecordingFactory.Dial(const AHost: string; const APort: Word;
  const ATimeoutMs: Integer): IHttp2Socket;
begin
  Result := FInnerRef.Dial(AHost, APort, ATimeoutMs);
end;

function TRouteRecordingFactory.DialProtocolVia(const AHost: string;
  const APort: Word; const AScheme: string; const AHttp1Fallback: Boolean;
  const APolicy: TClearTextPolicy; const ATimeoutMs: Integer;
  const AProxy: IProxy; out AProtocol: TNegotiatedProtocol): IHttp2Socket;
begin
  FLock.Acquire;
  try
    SetLength(FProxies, Length(FProxies) + 1);
    FProxies[High(FProxies)] := AProxy;
  finally
    FLock.Release;
  end;
  AProtocol := npHttp2Tls;
  Result := FInnerRef.Dial(AHost, APort, ATimeoutMs);
end;

function TRouteRecordingFactory.Dials: Integer;
begin
  FLock.Acquire;
  try
    Result := Length(FProxies);
  finally
    FLock.Release;
  end;
end;

function TRouteRecordingFactory.RouteAt(const AIndex: Integer): string;
const
  cKind: array[TProxyKind] of string = ('http', 'https', 'socks5');
var
  P: IProxy;
begin
  FLock.Acquire;
  try
    P := FProxies[AIndex];
  finally
    FLock.Release;
  end;
  if P = nil then
    Exit('direct');
  Result := Format('%s:%s:%d', [cKind[P.Kind], P.Host, P.Port]);
end;

{ TRecordingSelector }

constructor TRecordingSelector.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FUris := TStringList.Create;
end;

destructor TRecordingSelector.Destroy;
begin
  FUris.Free;
  FLock.Free;
  inherited Destroy;
end;

function TRecordingSelector.SelectProxy(const AUri: string): IProxy;
begin
  FLock.Acquire;
  try
    FUris.Add(AUri);
  finally
    FLock.Release;
  end;
  if RaiseMessage <> '' then
    raise Exception.Create(RaiseMessage);
  Result := nil;
  if BadHost then
    Exit(TProxy.Create('', 3128));
  if (ProxiedMarker <> '') and (Pos(ProxiedMarker, AUri) > 0) then
    Result := TProxy.Create(ProxyHost, ProxyPort);
end;

function TRecordingSelector.Count: Integer;
begin
  FLock.Acquire;
  try
    Result := FUris.Count;
  finally
    FLock.Release;
  end;
end;

function TRecordingSelector.UriAt(const AIndex: Integer): string;
begin
  FLock.Acquire;
  try
    Result := FUris[AIndex];
  finally
    FLock.Release;
  end;
end;

var
  GLookupValues: TStringList;
  GLookupCalls: Integer;

function ScriptedLookup(const AName: string): string;
var
  I: Integer;
begin
  Inc(GLookupCalls);
  Result := '';
  if GLookupValues = nil then
    Exit;
  for I := 0 to GLookupValues.Count - 1 do
    if GLookupValues.Names[I] = AName then
      Exit(GLookupValues.ValueFromIndex[I]);
end;

function SomeResponses(const ACount: Integer): TArray<TRespSpec>;
var
  I: Integer;
begin
  SetLength(Result, ACount);
  for I := 0 to ACount - 1 do
    Result[I] := HdrSpec('200');
end;

{ TProxyBuilderTest }

procedure TProxyBuilderTest.TestDefaults;
var
  F: THttpClientFactory;
begin
  F := THttpClientFactory.Create;
  AssertEquals('', F.ProxyHost);
  AssertEquals(0, Integer(F.ProxyPort));
  AssertTrue(F.ProxySelector = nil);
  AssertEquals('', F.AllProxy);
  AssertFalse(F.ProxyEnvironmentVars);
  AssertEquals('', F.NoProxy);
end;

procedure TProxyBuilderTest.TestWithXReturnsANewRecordAndLeavesTheReceiverUnchanged;
var
  A, B: THttpClientFactory;
begin
  A := THttpClientFactory.Create;
  B := A.WithAllProxy('socks5://p:1').WithProxyEnvironmentVars.WithNoProxy('x')
    .WithProxySelector(TRecordingSelector.Create);
  AssertEquals('', A.AllProxy);
  AssertFalse(A.ProxyEnvironmentVars);
  AssertEquals('', A.NoProxy);
  AssertTrue(A.ProxySelector = nil);
  AssertEquals('socks5://p:1', B.AllProxy);
  AssertTrue(B.ProxyEnvironmentVars);
  AssertEquals('x', B.NoProxy);
  AssertTrue(B.ProxySelector <> nil);
  AssertFalse('switch can be turned off again',
    B.WithProxyEnvironmentVars(False).ProxyEnvironmentVars);
end;

procedure TProxyBuilderTest.TestWithNoProxyAppends;
var
  F: THttpClientFactory;
begin
  F := THttpClientFactory.Create.WithNoProxy('a.example').WithNoProxy('b.example,c');
  AssertEquals('a.example,b.example,c', F.NoProxy);
end;

procedure TProxyBuilderTest.TestWithNoProxyIgnoresEmpty;
begin
  AssertEquals('', THttpClientFactory.Create.WithNoProxy('').NoProxy);
  AssertEquals('', THttpClientFactory.Create.WithNoProxy('   ').NoProxy);
  AssertEquals('a', THttpClientFactory.Create.WithNoProxy('a').WithNoProxy('').NoProxy);
end;

procedure TProxyBuilderTest.TestWithAllProxyTrimsAndClears;
var
  F: THttpClientFactory;
begin
  F := THttpClientFactory.Create.WithAllProxy('  http://p:1  ');
  AssertEquals('http://p:1', F.AllProxy);
  AssertEquals('', F.WithAllProxy('').AllProxy);
end;

procedure TProxyBuilderTest.TestBuildRejectsABadAllProxy;
var
  Raised: Boolean;
begin
  Raised := False;
  try
    THttpClientFactory.Create.WithAllProxy('socks4://p:1').Build;
  except
    on EHttpProxyConfigError do
      Raised := True;
  end;
  AssertTrue(Raised);
end;

procedure TProxyBuilderTest.TestBuildRejectsABadEnvironmentValueOnlyWhenEnabled;
var
  Raised: Boolean;
begin
  GLookupValues := TStringList.Create;
  try
    GLookupValues.CaseSensitive := True;
    GLookupValues.Add('https_proxy=ftp://nope:1');
    // switch off: the value is never read
    THttpClientFactory.Create.WithProxyEnvironmentLookup(ScriptedLookup).Build.Close;
    Raised := False;
    try
      THttpClientFactory.Create.WithProxyEnvironmentLookup(ScriptedLookup)
        .WithProxyEnvironmentVars.Build;
    except
      on EHttpProxyConfigError do
        Raised := True;
    end;
    AssertTrue('switch on: raised at Build', Raised);
  finally
    FreeAndNil(GLookupValues);
  end;
end;

procedure TProxyBuilderTest.TestBuildNeverReadsTheEnvironmentWhenOff;
begin
  GLookupValues := TStringList.Create;
  try
    GLookupValues.Add('http_proxy=http://x:1');
    GLookupCalls := 0;
    THttpClientFactory.Create.WithProxyEnvironmentLookup(ScriptedLookup)
      .Build.Close;
    AssertEquals('switch off: the environment is never read', 0, GLookupCalls);
    THttpClientFactory.Create.WithProxyEnvironmentLookup(ScriptedLookup)
      .WithProxyEnvironmentVars.Build.Close;
    AssertTrue('switch on: it is read once at Build', GLookupCalls > 0);
  finally
    FreeAndNil(GLookupValues);
  end;
end;

procedure TProxyBuilderTest.TestWithProxyKeepsTheProxyHostAndPortProperties;
var
  F: THttpClientFactory;
begin
  F := THttpClientFactory.Create.WithProxy('proxy.corp', 3128);
  AssertEquals('proxy.corp', F.ProxyHost);
  AssertEquals(3128, Integer(F.ProxyPort));
end;

{ TKeepAliveTlsLike }

constructor TKeepAliveTlsLike.Create(const AData: AnsiString);
begin
  inherited Create;
  FData := AData;
end;

function TKeepAliveTlsLike.Read(var ABuffer; ACount: Integer): Integer;
begin
  if (Length(FData) - FPos) < ACount then
    raise EHttpTimeout.Create('Read waited for bytes a keep-alive server never sends');
  Move(FData[FPos + 1], ABuffer, ACount);
  Inc(FPos, ACount);
  Result := ACount;
end;

function TKeepAliveTlsLike.ReadSome(var ABuffer; ACount: Integer): Integer;
begin
  Result := Length(FData) - FPos;
  if Result > ACount then
    Result := ACount;
  if Result > 0 then
  begin
    Move(FData[FPos + 1], ABuffer, Result);
    Inc(FPos, Result);
  end;
end;

function TKeepAliveTlsLike.Write(const ABuffer; ACount: Integer): Integer;
begin
  Result := ACount;
end;

procedure TKeepAliveTlsLike.Close;
begin
end;

function TKeepAliveTlsLike.GetConnected: Boolean;
begin
  Result := True;
end;

function TKeepAliveTlsLike.GetConnectTimeoutMs: Integer;
begin
  Result := 1000;
end;

procedure TKeepAliveTlsLike.SetConnectTimeoutMs(const AValue: Integer);
begin
end;

function TKeepAliveTlsLike.GetReadTimeoutMs: Integer;
begin
  Result := 1000;
end;

procedure TKeepAliveTlsLike.SetReadTimeoutMs(const AValue: Integer);
begin
end;

function TKeepAliveTlsLike.GetWriteTimeoutMs: Integer;
begin
  Result := 1000;
end;

procedure TKeepAliveTlsLike.SetWriteTimeoutMs(const AValue: Integer);
begin
end;

{ TSingleReadSocketTest }

procedure TSingleReadSocketTest.TestATransportWithoutAHandleIsReadThroughReadSome;
var
  Wrapped: IHttp2Socket;
  Buf: array[0..4095] of Byte;
begin
  Wrapped := TSingleReadSocket.Create(TKeepAliveTlsLike.Create('hello'));
  // 4096 asked for, 5 available, connection stays open: must return the 5
  AssertEquals(5, Wrapped.Read(Buf[0], SizeOf(Buf)));
  AssertEquals(Ord('h'), Buf[0]);
end;

{ TUrlIpv6Test }

procedure TUrlIpv6Test.AssertParsed(const AUrl, AHost: string;
  const APort: Word; const APath: string);
var
  H, P: string;
  N: Word;
begin
  ParseHttpUrl(AUrl, H, N, P);
  AssertEquals(AUrl + ' host', AHost, H);
  AssertEquals(AUrl + ' port', Integer(APort), Integer(N));
  AssertEquals(AUrl + ' path', APath, P);
end;

procedure TUrlIpv6Test.TestBracketedHostIsReturnedWithoutBrackets;
begin
  AssertParsed('https://[::1]/x', '::1', 443, '/x');
  AssertParsed('http://[2001:db8::7]/', '2001:db8::7', 80, '/');
  AssertParsed('https://[fe80::1%25eth0]/', 'fe80::1%25eth0', 443, '/');
end;

procedure TUrlIpv6Test.TestPortAndPathAfterBrackets;
begin
  AssertParsed('https://[::1]:8443/a/b?q=1', '::1', 8443, '/a/b?q=1');
  AssertParsed('http://[::1]:8080', '::1', 8080, '/');
  AssertParsed('https://[::1]?q=1', '::1', 443, '?q=1');
end;

procedure TUrlIpv6Test.TestUserinfoIsDropped;
begin
  AssertParsed('https://user:pw@example.com:8443/x', 'example.com', 8443, '/x');
  AssertParsed('https://user@[::1]:9/x', '::1', 9, '/x');
end;

procedure TUrlIpv6Test.TestMalformedBracketsRaise;
var
  Raised: Boolean;
  H, P: string;
  N: Word;
begin
  Raised := False;
  try
    ParseHttpUrl('https://[::1/x', H, N, P);
  except
    on EHttpProtocolError do Raised := True;
  end;
  AssertTrue('unterminated', Raised);
  Raised := False;
  try
    ParseHttpUrl('https://[::1]junk/x', H, N, P);
  except
    on EHttpProtocolError do Raised := True;
  end;
  AssertTrue('junk after bracket', Raised);
  Raised := False;
  try
    ParseHttpUrl('https://[::1]:99999/x', H, N, P);
  except
    on EHttpProtocolError do Raised := True;
  end;
  AssertTrue('bad port', Raised);
end;

procedure TUrlIpv6Test.TestAuthorityAndOriginKeepTheBrackets;
begin
  AssertEquals('[::1]', THttpRequest.Create(hmGet, 'https://[::1]/x').Authority);
  AssertEquals('[::1]:8443',
    THttpRequest.Create(hmGet, 'https://[::1]:8443/x').Authority);
  AssertEquals('[::1]', OriginOfUrl('https://[::1]/x'));
  AssertEquals('[::1]:8443', OriginOfUrl('https://[::1]:8443/x'));
  AssertEquals('http://[::1]', OriginOfUrl('http://[::1]/x'));
  AssertEquals('[::1]', BracketedHost('::1'));
  AssertEquals('[::1]', BracketedHost('[::1]'));
  AssertEquals('example.com', BracketedHost('example.com'));
end;

procedure TUrlIpv6Test.TestExistingFormsAreUnchanged;
begin
  AssertParsed('https://example.com/x', 'example.com', 443, '/x');
  AssertParsed('http://example.com:8080/x', 'example.com', 8080, '/x');
  AssertParsed('example.com/x', 'example.com', 443, '/x');
  AssertParsed('https://example.com', 'example.com', 443, '/');
  AssertParsed('https://example.com?q=1', 'example.com', 443, '?q=1');
end;

procedure TUrlIpv6Test.TestAnIpv6OriginIsDialledAndRouted;
var
  Fake: TFakeFrameFactory;
  Routes: TRouteRecordingFactory;
  Client: IHttpClient;
begin
  Fake := TFakeFrameFactory.Create;
  Fake.SetDialScript(0, SomeResponses(2));
  Fake.SetDialScript(1, SomeResponses(2));
  Routes := TRouteRecordingFactory.Create(Fake);
  Client := THttpClientFactory.Create.WithSocketFactory(Routes)
    .WithProxy('proxy.corp', 3128).WithNoProxy('fd00::/8').Build;
  // inside the no-proxy CIDR: direct, dialled by the unbracketed literal
  AssertEquals(200, Client.Send(THttpRequest.Create(hmGet,
    'https://[fd00::9]:8443/x')).StatusCode);
  AssertEquals('direct', Routes.RouteAt(0));
  AssertEquals('fd00::9', Fake.HostAt(0));
  AssertEquals(8443, Integer(Fake.PortAt(0)));
  AssertEquals(1, (Client as THttpClient).Pool.ConnectionCountForOrigin(
    '[fd00::9]:8443'));
  // outside it: through the proxy
  AssertEquals(200, Client.Send(THttpRequest.Create(hmGet,
    'https://[2001:db8::9]/x')).StatusCode);
  AssertEquals('http:proxy.corp:3128', Routes.RouteAt(1));
  AssertEquals(1, (Client as THttpClient).Pool.ConnectionCountForOrigin(
    '[2001:db8::9] via proxy.corp:3128'));
  Client.Close;
end;

{ TProxyRoutingTest }

function TProxyRoutingTest.Run(const AFactory: THttpClientFactory;
  const AUrl: string; out ARoutes: TRouteRecordingFactory): IHttpClient;
var
  Fake: TFakeFrameFactory;
  Spec: TArray<TRespSpec>;
begin
  Fake := TFakeFrameFactory.Create;
  Spec := SomeResponses(8);
  Fake.SetDialScript(0, Spec);
  Fake.SetDialScript(1, Spec);
  Fake.SetDialScript(2, Spec);
  ARoutes := TRouteRecordingFactory.Create(Fake);
  Result := AFactory.WithSocketFactory(ARoutes).Build;
  AssertEquals('status', 200, Result.Send(
    THttpRequest.Create(hmGet, AUrl)).StatusCode);
end;

procedure TProxyRoutingTest.TestNoConfigurationDialsDirectlyWithThePlainOriginKey;
var
  Routes: TRouteRecordingFactory;
  Client: IHttpClient;
begin
  Client := Run(THttpClientFactory.Create, 'https://a.example/x', Routes);
  AssertEquals(1, Routes.Dials);
  AssertEquals('direct', Routes.RouteAt(0));
  AssertEquals('direct key is the plain origin', 1,
    (Client as THttpClient).Pool.ConnectionCountForOrigin('a.example'));
  Client.Close;
end;

procedure TProxyRoutingTest.TestWithProxyReachesTheDialAndKeysThePool;
var
  Routes: TRouteRecordingFactory;
  Client: IHttpClient;
  Pool: TConnectionPool;
begin
  Client := Run(THttpClientFactory.Create.WithProxy('proxy.corp', 3128),
    'https://a.example/x', Routes);
  Pool := (Client as THttpClient).Pool;
  AssertEquals('http:proxy.corp:3128', Routes.RouteAt(0));
  AssertEquals('proxied route has its own key', 1,
    Pool.ConnectionCountForOrigin('a.example via proxy.corp:3128'));
  AssertEquals('the plain key is untouched', 0,
    Pool.ConnectionCountForOrigin('a.example'));
  Client.Close;
end;

procedure TProxyRoutingTest.TestWithAllProxyHttpsProxyAndSocks5;
var
  Routes: TRouteRecordingFactory;
  Client: IHttpClient;
begin
  Client := Run(THttpClientFactory.Create.WithAllProxy('socks5://u:pw@s.corp'),
    'https://a.example/x', Routes);
  AssertEquals('socks5:s.corp:1080', Routes.RouteAt(0));
  AssertEquals(1, (Client as THttpClient).Pool.ConnectionCountForOrigin(
    'a.example via socks5:u@s.corp:1080'));
  Client.Close;
  Client := Run(THttpClientFactory.Create.WithAllProxy('https://t.corp'),
    'https://a.example/x', Routes);
  AssertEquals('https:t.corp:443', Routes.RouteAt(0));
  AssertEquals(1, (Client as THttpClient).Pool.ConnectionCountForOrigin(
    'a.example via tls:t.corp:443'));
  Client.Close;
end;

procedure TProxyRoutingTest.TestEnvironmentLookupDrivesTheRoute;
var
  Routes: TRouteRecordingFactory;
  Client: IHttpClient;
begin
  GLookupValues := TStringList.Create;
  try
    GLookupValues.CaseSensitive := True;
    GLookupValues.Add('https_proxy=http://envs.corp:8080');
    GLookupValues.Add('http_proxy=http://envh.corp:8081');
    Client := Run(THttpClientFactory.Create.WithProxyEnvironmentLookup(
      ScriptedLookup).WithProxyEnvironmentVars, 'https://a.example/x', Routes);
    AssertEquals('http:envs.corp:8080', Routes.RouteAt(0));
    Client.Close;
    GLookupValues.Clear;
    GLookupValues.Add('all_proxy=socks5://all.corp:1081');
    Client := Run(THttpClientFactory.Create.WithProxyEnvironmentLookup(
      ScriptedLookup).WithProxyEnvironmentVars, 'https://a.example/x', Routes);
    AssertEquals('socks5:all.corp:1081', Routes.RouteAt(0));
    Client.Close;
    GLookupValues.Clear;
    GLookupValues.Add('https_proxy=http://envs.corp:8080');
    GLookupValues.Add('no_proxy=.example');
    Client := Run(THttpClientFactory.Create.WithProxyEnvironmentLookup(
      ScriptedLookup).WithProxyEnvironmentVars, 'https://a.example/x', Routes);
    AssertEquals('env no_proxy exempts the host', 'direct', Routes.RouteAt(0));
    Client.Close;
  finally
    FreeAndNil(GLookupValues);
  end;
end;

procedure TProxyRoutingTest.TestEnvironmentIsIgnoredUnlessSwitchedOn;
var
  Routes: TRouteRecordingFactory;
  Client: IHttpClient;
begin
  GLookupValues := TStringList.Create;
  try
    GLookupValues.Add('https_proxy=http://envs.corp:8080');
    Client := Run(THttpClientFactory.Create.WithProxyEnvironmentLookup(
      ScriptedLookup), 'https://a.example/x', Routes);
    AssertEquals('direct', Routes.RouteAt(0));
    Client.Close;
  finally
    FreeAndNil(GLookupValues);
  end;
end;

procedure TProxyRoutingTest.TestWithNoProxyForcesDirectForTheFixedProxy;
var
  Routes: TRouteRecordingFactory;
  Client: IHttpClient;
begin
  Client := Run(THttpClientFactory.Create.WithProxy('proxy.corp', 3128)
    .WithNoProxy('a.example'), 'https://a.example/x', Routes);
  AssertEquals('direct', Routes.RouteAt(0));
  Client.Close;
  Client := Run(THttpClientFactory.Create.WithProxy('proxy.corp', 3128)
    .WithNoProxy('other.example'), 'https://a.example/x', Routes);
  AssertEquals('http:proxy.corp:3128', Routes.RouteAt(0));
  Client.Close;
end;

procedure TProxyRoutingTest.TestLoopbackIsAlwaysDirect;
var
  Routes: TRouteRecordingFactory;
  Client: IHttpClient;
begin
  Client := Run(THttpClientFactory.Create.WithProxy('proxy.corp', 3128),
    'https://localhost/x', Routes);
  AssertEquals('direct', Routes.RouteAt(0));
  Client.Close;
  Client := Run(THttpClientFactory.Create.WithAllProxy('socks5://s.corp'),
    'https://127.0.0.1:8443/x', Routes);
  AssertEquals('direct', Routes.RouteAt(0));
  Client.Close;
end;

procedure TProxyRoutingTest.TestSelectorBeatsEveryOtherSetting;
var
  Routes: TRouteRecordingFactory;
  Client: IHttpClient;
  Sel: TRecordingSelector;
begin
  Sel := TRecordingSelector.Create;
  Sel.ProxiedMarker := 'a.example';
  Sel.ProxyHost := 'sel.corp';
  Sel.ProxyPort := 1;
  GLookupValues := TStringList.Create;
  try
    GLookupValues.Add('https_proxy=http://envs.corp:8080');
    Client := Run(THttpClientFactory.Create.WithProxy('fixed.corp', 2)
      .WithAllProxy('socks5://all.corp').WithProxyEnvironmentLookup(ScriptedLookup)
      .WithProxyEnvironmentVars.WithNoProxy('*').WithProxySelector(Sel),
      'https://a.example/x', Routes);
    // the selector is the sole authority: no_proxy '*' is not applied to it
    AssertEquals('http:sel.corp:1', Routes.RouteAt(0));
    Client.Close;
  finally
    FreeAndNil(GLookupValues);
  end;
end;

procedure TProxyRoutingTest.TestEachRedirectHopIsRoutedAgain;
var
  Fake: TFakeFrameFactory;
  Routes: TRouteRecordingFactory;
  Client: IHttpClient;
  Sel: TRecordingSelector;
  R: IHttpResponse;
begin
  Sel := TRecordingSelector.Create;
  Sel.ProxiedMarker := 'a.example';      // only the first hop is proxied
  Sel.ProxyHost := 'sel.corp';
  Sel.ProxyPort := 7;
  Fake := TFakeFrameFactory.Create;
  Fake.SetDialScript(0, SpecArray([HdrSpec('301', 'https://b.example/y')]));
  Fake.SetDialScript(1, SpecArray([HdrSpec('200')]));
  Routes := TRouteRecordingFactory.Create(Fake);
  Client := THttpClientFactory.Create.WithSocketFactory(Routes)
    .WithProxySelector(Sel).Build;
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  AssertEquals(200, R.StatusCode);
  AssertEquals('the selector saw both hops', 2, Sel.Count);
  AssertEquals('https://a.example/x', Sel.UriAt(0));
  AssertEquals('https://b.example/y', Sel.UriAt(1));
  AssertEquals(2, Routes.Dials);
  AssertEquals('hop 1 proxied', 'http:sel.corp:7', Routes.RouteAt(0));
  AssertEquals('hop 2 direct', 'direct', Routes.RouteAt(1));
  Client.Close;
end;

procedure TProxyRoutingTest.TestDirectAndProxiedRoutesToOneOriginAreSeparateBuckets;
var
  Fake: TFakeFrameFactory;
  Routes: TRouteRecordingFactory;
  Client: IHttpClient;
  Sel: TRecordingSelector;
  Pool: TConnectionPool;
begin
  Sel := TRecordingSelector.Create;
  Sel.ProxiedMarker := '/via';
  Sel.ProxyHost := 'sel.corp';
  Sel.ProxyPort := 7;
  Fake := TFakeFrameFactory.Create;
  Fake.SetDialScript(0, SomeResponses(4));
  Fake.SetDialScript(1, SomeResponses(4));
  Routes := TRouteRecordingFactory.Create(Fake);
  Client := THttpClientFactory.Create.WithSocketFactory(Routes)
    .WithProxySelector(Sel).Build;
  AssertEquals(200, Client.Send(THttpRequest.Create(hmGet, 'https://a.example/direct')).StatusCode);
  AssertEquals(200, Client.Send(THttpRequest.Create(hmGet, 'https://a.example/via')).StatusCode);
  Pool := (Client as THttpClient).Pool;
  AssertEquals('two connections, one per route', 2, Routes.Dials);
  AssertEquals(1, Pool.ConnectionCountForOrigin('a.example'));
  AssertEquals(1, Pool.ConnectionCountForOrigin('a.example via sel.corp:7'));
  // and the next request of each kind reuses its own bucket
  AssertEquals(200, Client.Send(THttpRequest.Create(hmGet, 'https://a.example/direct')).StatusCode);
  AssertEquals(200, Client.Send(THttpRequest.Create(hmGet, 'https://a.example/via')).StatusCode);
  AssertEquals('no extra dials', 2, Routes.Dials);
  Client.Close;
end;

procedure TProxyRoutingTest.TestTwoProxiesAreSeparateBuckets;
var
  Fake: TFakeFrameFactory;
  Routes: TRouteRecordingFactory;
  Client: IHttpClient;
  Sel: TRecordingSelector;
  Pool: TConnectionPool;
begin
  Sel := TRecordingSelector.Create;
  Sel.ProxiedMarker := '/p1';
  Sel.ProxyHost := 'one.corp';
  Sel.ProxyPort := 1;
  Fake := TFakeFrameFactory.Create;
  Fake.SetDialScript(0, SomeResponses(3));
  Fake.SetDialScript(1, SomeResponses(3));
  Routes := TRouteRecordingFactory.Create(Fake);
  Client := THttpClientFactory.Create.WithSocketFactory(Routes)
    .WithProxySelector(Sel).Build;
  AssertEquals(200, Client.Send(THttpRequest.Create(hmGet, 'https://a.example/p1')).StatusCode);
  Sel.ProxiedMarker := '/p2';
  Sel.ProxyHost := 'two.corp';
  AssertEquals(200, Client.Send(THttpRequest.Create(hmGet, 'https://a.example/p2')).StatusCode);
  Pool := (Client as THttpClient).Pool;
  AssertEquals(1, Pool.ConnectionCountForOrigin('a.example via one.corp:1'));
  AssertEquals(1, Pool.ConnectionCountForOrigin('a.example via two.corp:1'));
  Client.Close;
end;

procedure TProxyRoutingTest.TestSelectorExceptionReachesTheCaller;
var
  Routes: TRouteRecordingFactory;
  Fake: TFakeFrameFactory;
  Sel: TRecordingSelector;
  Client: IHttpClient;
  Msg: string;
begin
  Sel := TRecordingSelector.Create;
  Sel.RaiseMessage := 'selector boom';
  Fake := TFakeFrameFactory.Create;
  Routes := TRouteRecordingFactory.Create(Fake);
  Client := THttpClientFactory.Create.WithSocketFactory(Routes)
    .WithProxySelector(Sel).Build;
  Msg := '';
  try
    Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  except
    on E: Exception do
      Msg := E.ClassName + ':' + E.Message;
  end;
  AssertEquals('Exception:selector boom', Msg);
  AssertEquals('nothing was dialled', 0, Routes.Dials);
  Client.Close;
end;

procedure TProxyRoutingTest.TestSelectorReturningAnUnusableProxyIsAConfigError;
var
  Routes: TRouteRecordingFactory;
  Fake: TFakeFrameFactory;
  Sel: TRecordingSelector;
  Client: IHttpClient;
  Raised: Boolean;
begin
  Sel := TRecordingSelector.Create;
  Sel.BadHost := True;
  Fake := TFakeFrameFactory.Create;
  Routes := TRouteRecordingFactory.Create(Fake);
  Client := THttpClientFactory.Create.WithSocketFactory(Routes)
    .WithProxySelector(Sel).Build;
  Raised := False;
  try
    Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  except
    on EHttpProxyConfigError do
      Raised := True;
  end;
  AssertTrue(Raised);
  AssertEquals(0, Routes.Dials);
  Client.Close;
end;

procedure TProxyRoutingTest.TestLegacyFactoryIsStillDialledWithoutAProxy;
var
  Fake: TFakeFrameFactory;
  Client: IHttpClient;
begin
  // a factory that does not implement IProxySocketFactory predates routing:
  // it is dialled exactly as before, with no proxy
  Fake := TFakeFrameFactory.Create;
  Fake.SetDialScript(0, SomeResponses(2));
  Client := THttpClientFactory.Create.WithSocketFactory(Fake)
    .WithProxy('proxy.corp', 3128).Build;
  AssertEquals(200, Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x')).StatusCode);
  AssertEquals(1, Fake.Dials);
  AssertEquals('a.example', Fake.HostAt(0));
  AssertEquals('the route is still part of the pool key', 1,
    (Client as THttpClient).Pool.ConnectionCountForOrigin(
      'a.example via proxy.corp:3128'));
  Client.Close;
end;

type
  TSendThread = class(TThread)
  private
    FClient: IHttpClient;
    FUrl: string;
  public
    Status: Integer;
    constructor Create(const AClient: IHttpClient; const AUrl: string);
    procedure Execute; override;
  end;

constructor TSendThread.Create(const AClient: IHttpClient; const AUrl: string);
begin
  inherited Create(True);
  FClient := AClient;
  FUrl := AUrl;
  Status := -1;
end;

procedure TSendThread.Execute;
begin
  try
    Status := FClient.Send(THttpRequest.Create(hmGet, FUrl)).StatusCode;
  except
    Status := -2;
  end;
end;

procedure TProxyRoutingTest.TestConcurrentSendsCallTheSelectorOncePerRequest;
const
  cThreads = 6;
var
  Fake: TFakeFrameFactory;
  Routes: TRouteRecordingFactory;
  Client: IHttpClient;
  Sel: TRecordingSelector;
  T: array[0..cThreads - 1] of TSendThread;
  I: Integer;
begin
  Sel := TRecordingSelector.Create;
  Sel.ProxiedMarker := 'a.example';
  Sel.ProxyHost := 'sel.corp';
  Sel.ProxyPort := 7;
  Fake := TFakeFrameFactory.Create;
  Fake.SetDialScript(0, SomeResponses(cThreads * 2));
  Routes := TRouteRecordingFactory.Create(Fake);
  Client := THttpClientFactory.Create.WithSocketFactory(Routes)
    .WithProxySelector(Sel).Build;
  for I := 0 to cThreads - 1 do
    T[I] := TSendThread.Create(Client, 'https://a.example/x' + IntToStr(I));
  for I := 0 to cThreads - 1 do
    T[I].Start;
  for I := 0 to cThreads - 1 do
  begin
    T[I].WaitFor;
    AssertEquals('thread ' + IntToStr(I), 200, T[I].Status);
    T[I].Free;
  end;
  AssertEquals('one selection per request', cThreads, Sel.Count);
  Client.Close;
end;

initialization
  RegisterTest(TProxyBuilderTest);
  RegisterTest(TUrlIpv6Test);
  RegisterTest(TSingleReadSocketTest);
  RegisterTest(TProxyRoutingTest);
end.
