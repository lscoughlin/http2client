/// Proxy routing tests (doc/design/proxy.md).
// - everything here is pure: no socket and no read of the real process
//   environment, so a developer machine with https_proxy set cannot change a
//   result.  Environment cases feed a scripted lookup.
unit Http2.Proxy.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$interfaces com}

interface

uses
  SysUtils, Classes, fpcunit, testregistry, Http2.Errors, Http2.Proxy;

type
  TProxyUrlTest = class(TTestCase)
  private
    procedure AssertProxy(const AValue: string; const AKind: TProxyKind;
      const AHost: string; const APort: Word; const AUser, APass: string);
    procedure AssertRejected(const AValue: string);
  published
    procedure TestBareHostPortIsHttp;
    procedure TestHttpUrlWithTrailingPath;
    procedure TestDefaultPortsFollowTheScheme;
    procedure TestHttpsProxyIsSecureKind;
    procedure TestSocks5AndSocks5hAreTheSame;
    procedure TestCredentialsArePercentDecoded;
    procedure TestUserWithoutPassword;
    procedure TestBracketedIpv6Host;
    procedure TestEmptyValueIsNil;
    procedure TestUnsupportedSchemesAreRejected;
    procedure TestBadPortsAreRejected;
    procedure TestEmptyHostIsRejected;
    procedure TestBadPercentEncodingIsRejected;
    procedure TestSocksCredentialLengthLimit;
    procedure TestErrorMessagesNeverContainThePassword;
    procedure TestRouteKeyShapes;
    procedure TestBasicCredentialsBase64;
  end;

  TNoProxyTest = class(TTestCase)
  private
    function Matches(const AList, AHost: string; const APort: Word = 443): Boolean;
  published
    procedure TestStarMatchesEverything;
    procedure TestSuffixWithAndWithoutDot;
    procedure TestSuffixIsOnALabelBoundary;
    procedure TestExactHostAndSubdomain;
    procedure TestHostPortConstrainsThePort;
    procedure TestIpv4LiteralAndCidr;
    procedure TestIpv6LiteralBracketedAndBare;
    procedure TestIpv6Cidr;
    procedure TestCaseInsensitiveWhitespaceAndEmptyEntries;
    procedure TestMalformedEntriesAreSkipped;
    procedure TestNameEntryNeverMatchesAnIpLiteral;
  end;

  TProxyLiteralTest = class(TTestCase)
  published
    procedure TestIp4Parsing;
    procedure TestIp6Parsing;
    procedure TestLoopbackHosts;
    procedure TestSplitProxyTarget;
  end;

  TProxyEnvironmentTest = class(TTestCase)
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestLowercaseWinsOverUppercase;
    procedure TestUppercaseHttpProxyIsIgnored;
    procedure TestUppercaseAllProxyAndHttpsProxyAreHonoured;
    procedure TestEmptyValueIsUnset;
    procedure TestNothingConfiguredYieldsNilSelector;
  end;

  TProxySelectorTest = class(TTestCase)
  private
    function Pick(const ASel: IProxySelector; const AUri: string): string;
  published
    procedure TestEnvironmentSchemeSpecificThenAll;
    procedure TestAllProxyServesSchemesWithoutTheirOwn;
    procedure TestPrecedenceMatrix;
    procedure TestCustomSelectorIsTheSoleAuthority;
    procedure TestLoopbackAlwaysConnectsDirectly;
    procedure TestNoProxyAppliesToFixedAndEnvironment;
    procedure TestNoProxyUnionsWithEnvironmentNoProxy;
    procedure TestEnvironmentIgnoredWhenSwitchIsOff;
    procedure TestBadEnvironmentValueFailsAtBuild;
    procedure TestBadAllProxyFailsAtBuild;
    procedure TestIpv6AuthorityIsParsed;
  end;

implementation

var
  GEnv: TStringList;

function ScriptedLookup(const AName: string): string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to GEnv.Count - 1 do
    if GEnv.Names[I] = AName then
      Exit(GEnv.ValueFromIndex[I]);
end;

type
  TFixedSelector = class(TInterfacedObject, IProxySelector)
  public
    function SelectProxy(const AUri: string): IProxy;
  end;

function TFixedSelector.SelectProxy(const AUri: string): IProxy;
begin
  Result := TProxy.Create('custom.example', 1111);
end;

function EmptyEnv: TProxyEnvironment;
begin
  Result.HttpProxy := '';
  Result.HttpsProxy := '';
  Result.AllProxy := '';
  Result.NoProxy := '';
end;

function Describe(const AProxy: IProxy): string;
begin
  if AProxy = nil then
    Exit('direct');
  Result := AProxy.Host + ':' + IntToStr(AProxy.Port);
end;

{ TProxyUrlTest }

procedure TProxyUrlTest.AssertProxy(const AValue: string; const AKind: TProxyKind;
  const AHost: string; const APort: Word; const AUser, APass: string);
var
  P: IProxy;
begin
  P := ParseProxyUrl(AValue);
  AssertTrue(AValue + ': not nil', P <> nil);
  AssertEquals(AValue + ': kind', Ord(AKind), Ord(P.Kind));
  AssertEquals(AValue + ': host', AHost, P.Host);
  AssertEquals(AValue + ': port', Integer(APort), Integer(P.Port));
  AssertEquals(AValue + ': user', AUser, P.UserName);
  AssertEquals(AValue + ': password', APass, P.Password);
end;

procedure TProxyUrlTest.AssertRejected(const AValue: string);
var
  Raised: Boolean;
begin
  Raised := False;
  try
    ParseProxyUrl(AValue);
  except
    on EHttpProxyConfigError do
      Raised := True;
  end;
  AssertTrue('rejected: ' + AValue, Raised);
end;

procedure TProxyUrlTest.TestBareHostPortIsHttp;
begin
  AssertProxy('proxy.corp:3128', pkHttp, 'proxy.corp', 3128, '', '');
end;

procedure TProxyUrlTest.TestHttpUrlWithTrailingPath;
begin
  AssertProxy('http://proxy.corp:3128/', pkHttp, 'proxy.corp', 3128, '', '');
  AssertProxy('http://proxy.corp:3128/x?y=1', pkHttp, 'proxy.corp', 3128, '', '');
end;

procedure TProxyUrlTest.TestDefaultPortsFollowTheScheme;
begin
  AssertProxy('proxy.corp', pkHttp, 'proxy.corp', 80, '', '');
  AssertProxy('http://proxy.corp', pkHttp, 'proxy.corp', 80, '', '');
  AssertProxy('https://proxy.corp', pkHttps, 'proxy.corp', 443, '', '');
  AssertProxy('socks5://proxy.corp', pkSocks5, 'proxy.corp', 1080, '', '');
end;

procedure TProxyUrlTest.TestHttpsProxyIsSecureKind;
begin
  AssertProxy('https://proxy.corp:3129', pkHttps, 'proxy.corp', 3129, '', '');
end;

procedure TProxyUrlTest.TestSocks5AndSocks5hAreTheSame;
begin
  AssertProxy('socks5://p:1', pkSocks5, 'p', 1, '', '');
  AssertProxy('socks5h://p:1', pkSocks5, 'p', 1, '', '');
  AssertProxy('SOCKS5H://p:1', pkSocks5, 'p', 1, '', '');
end;

procedure TProxyUrlTest.TestCredentialsArePercentDecoded;
begin
  AssertProxy('http://user:p%40ss@proxy.corp:3128', pkHttp, 'proxy.corp',
    3128, 'user', 'p@ss');
  AssertProxy('socks5://a%3Ab:c%2Fd@h:9', pkSocks5, 'h', 9, 'a:b', 'c/d');
end;

procedure TProxyUrlTest.TestUserWithoutPassword;
begin
  AssertProxy('http://user@proxy.corp:3128', pkHttp, 'proxy.corp', 3128,
    'user', '');
end;

procedure TProxyUrlTest.TestBracketedIpv6Host;
begin
  AssertProxy('http://[::1]:3128', pkHttp, '::1', 3128, '', '');
  AssertProxy('socks5://u:p@[fd00::5]', pkSocks5, 'fd00::5', 1080, 'u', 'p');
end;

procedure TProxyUrlTest.TestEmptyValueIsNil;
begin
  AssertTrue(ParseProxyUrl('') = nil);
  AssertTrue(ParseProxyUrl('   ') = nil);
end;

procedure TProxyUrlTest.TestUnsupportedSchemesAreRejected;
begin
  AssertRejected('socks4://proxy.corp');
  AssertRejected('socks4a://proxy.corp');
  AssertRejected('socks://proxy.corp');
  AssertRejected('ftp://proxy.corp');
end;

procedure TProxyUrlTest.TestBadPortsAreRejected;
begin
  AssertRejected('proxy.corp:0');
  AssertRejected('proxy.corp:70000');
  AssertRejected('proxy.corp:abc');
  AssertRejected('proxy.corp:');
end;

procedure TProxyUrlTest.TestEmptyHostIsRejected;
begin
  AssertRejected('http://');
  AssertRejected('http://:3128');
  AssertRejected('http://user:pw@');
end;

procedure TProxyUrlTest.TestBadPercentEncodingIsRejected;
begin
  AssertRejected('http://us%zz:pw@proxy.corp');
  AssertRejected('http://user:pw%@proxy.corp');
end;

procedure TProxyUrlTest.TestSocksCredentialLengthLimit;
var
  Long: string;
begin
  Long := StringOfChar('a', 256);
  AssertRejected('socks5://' + Long + ':pw@h');
  AssertRejected('socks5://u:' + Long + '@h');
  AssertProxy('socks5://' + StringOfChar('a', 255) + ':pw@h', pkSocks5, 'h',
    1080, StringOfChar('a', 255), 'pw');
  // the HTTP kinds have no such limit
  AssertTrue(ParseProxyUrl('http://' + Long + ':pw@h') <> nil);
end;

procedure TProxyUrlTest.TestErrorMessagesNeverContainThePassword;
var
  Msg: string;
begin
  Msg := '';
  try
    ParseProxyUrl('socks5://user:TOPSECRET@h:abc');
  except
    on E: EHttpProxyConfigError do
      Msg := E.Message;
  end;
  AssertTrue('raised', Msg <> '');
  AssertEquals('no secret', 0, Pos('TOPSECRET', Msg));
  Msg := '';
  try
    ParseProxyUrl('socks5://user:TOPSECRET%zz@h');
  except
    on E: EHttpProxyConfigError do
      Msg := E.Message;
  end;
  AssertTrue('raised 2', Msg <> '');
  AssertEquals('no secret 2', 0, Pos('TOPSECRET', Msg));
end;

procedure TProxyUrlTest.TestRouteKeyShapes;
begin
  AssertEquals('direct', '', ProxyRouteKey(nil));
  AssertEquals('http', ' via proxy.corp:3128',
    ProxyRouteKey(ParseProxyUrl('http://proxy.corp:3128')));
  AssertEquals('tls', ' via tls:proxy.corp:443',
    ProxyRouteKey(ParseProxyUrl('https://proxy.corp')));
  AssertEquals('socks', ' via socks5:u@h:1080',
    ProxyRouteKey(ParseProxyUrl('socks5://u:secret@h')));
  AssertEquals('ipv6', ' via [::1]:3128',
    ProxyRouteKey(ParseProxyUrl('http://[::1]:3128')));
  AssertEquals('password never in key', 0,
    Pos('secret', ProxyRouteKey(ParseProxyUrl('socks5://u:secret@h'))));
end;

procedure TProxyUrlTest.TestBasicCredentialsBase64;
begin
  // RFC 7617 example
  AssertEquals('Aladdin:open sesame', 'QWxhZGRpbjpvcGVuIHNlc2FtZQ==',
    ProxyBasicCredentials('Aladdin', 'open sesame'));
  AssertEquals('pad 1', 'YTpi', ProxyBasicCredentials('a', 'b'));
  AssertEquals('pad 2', 'YTpiYw==', ProxyBasicCredentials('a', 'bc'));
  AssertEquals('pad 3', 'YTpiY2Q=', ProxyBasicCredentials('a', 'bcd'));
end;

{ TNoProxyTest }

function TNoProxyTest.Matches(const AList, AHost: string;
  const APort: Word): Boolean;
var
  L: TNoProxyList;
begin
  L := TNoProxyList.Create;
  try
    L.Add(AList);
    Result := L.Matches(AHost, APort);
  finally
    L.Free;
  end;
end;

procedure TNoProxyTest.TestStarMatchesEverything;
begin
  AssertTrue(Matches('*', 'anything.example'));
  AssertTrue(Matches('a.example,*', '10.0.0.1'));
end;

procedure TNoProxyTest.TestSuffixWithAndWithoutDot;
begin
  AssertTrue('plain', Matches('example.com', 'a.example.com'));
  AssertTrue('dot', Matches('.example.com', 'a.example.com'));
  AssertTrue('star dot', Matches('*.example.com', 'a.b.example.com'));
  AssertTrue('exact', Matches('.example.com', 'example.com'));
end;

procedure TNoProxyTest.TestSuffixIsOnALabelBoundary;
begin
  AssertFalse('notexample.com', Matches('example.com', 'notexample.com'));
  AssertFalse('example.com.evil', Matches('example.com', 'example.com.evil'));
end;

procedure TNoProxyTest.TestExactHostAndSubdomain;
begin
  AssertTrue(Matches('internal', 'internal'));
  AssertTrue(Matches('internal', 'db.internal'));
  AssertFalse(Matches('internal', 'internal2'));
end;

procedure TNoProxyTest.TestHostPortConstrainsThePort;
begin
  AssertTrue('port hit', Matches('example.com:8443', 'example.com', 8443));
  AssertFalse('port miss', Matches('example.com:8443', 'example.com', 443));
  AssertTrue('subdomain port hit',
    Matches('example.com:8443', 'a.example.com', 8443));
  AssertTrue('no port = any', Matches('example.com', 'example.com', 9999));
end;

procedure TNoProxyTest.TestIpv4LiteralAndCidr;
begin
  AssertTrue('literal', Matches('10.1.2.3', '10.1.2.3'));
  AssertFalse('literal miss', Matches('10.1.2.3', '10.1.2.4'));
  AssertTrue('cidr in', Matches('10.0.0.0/8', '10.200.1.1'));
  AssertFalse('cidr out', Matches('10.0.0.0/8', '11.0.0.1'));
  AssertTrue('/24', Matches('192.168.1.0/24', '192.168.1.77'));
  AssertFalse('/24 out', Matches('192.168.1.0/24', '192.168.2.77'));
  AssertTrue('/0 matches all ip4', Matches('0.0.0.0/0', '8.8.8.8'));
  AssertTrue('/32', Matches('1.2.3.4/32', '1.2.3.4'));
  AssertFalse('host name vs cidr', Matches('10.0.0.0/8', 'ten.example'));
end;

procedure TNoProxyTest.TestIpv6LiteralBracketedAndBare;
begin
  AssertTrue('bare', Matches('::1', '::1'));
  AssertTrue('bracketed', Matches('[::1]', '::1'));
  AssertTrue('bracketed port', Matches('[::1]:8443', '::1', 8443));
  AssertFalse('bracketed port miss', Matches('[::1]:8443', '::1', 443));
  AssertTrue('equal forms', Matches('::1', '0:0:0:0:0:0:0:1'));
  AssertFalse('different', Matches('::1', '::2'));
end;

procedure TNoProxyTest.TestIpv6Cidr;
begin
  AssertTrue('fd00::/8 in', Matches('fd00::/8', 'fd12:3456::1'));
  AssertFalse('fd00::/8 out', Matches('fd00::/8', 'fe80::1'));
  AssertTrue('fe80::/10 in', Matches('fe80::/10', 'febf::1'));
  AssertFalse('fe80::/10 out', Matches('fe80::/10', 'fec0::1'));
  AssertTrue('/0', Matches('::/0', '2001:db8::1'));
  AssertTrue('/128', Matches('2001:db8::1/128', '2001:db8::1'));
  AssertFalse('/128 miss', Matches('2001:db8::1/128', '2001:db8::2'));
  AssertFalse('ip4 host vs ip6 cidr', Matches('fd00::/8', '10.0.0.1'));
end;

procedure TNoProxyTest.TestCaseInsensitiveWhitespaceAndEmptyEntries;
begin
  AssertTrue(Matches('  Example.COM , ,, other ', 'A.EXAMPLE.com'));
  AssertTrue(Matches('  Example.COM , ,, other ', 'other'));
end;

procedure TNoProxyTest.TestMalformedEntriesAreSkipped;
var
  L: TNoProxyList;
begin
  L := TNoProxyList.Create;
  try
    L.Add('host:notaport,10.0.0.0/33,[::1,a.example/8,10.0.0.0/x');
    AssertEquals('all skipped', 0, L.Count);
    L.Add('good.example');
    AssertEquals('one good', 1, L.Count);
  finally
    L.Free;
  end;
end;

procedure TNoProxyTest.TestNameEntryNeverMatchesAnIpLiteral;
begin
  AssertFalse(Matches('0.1', '10.0.0.1'));
  AssertFalse(Matches('example.com', '1.2.3.4'));
end;

{ TProxyLiteralTest }

procedure TProxyLiteralTest.TestIp4Parsing;
var
  V: LongWord;
begin
  AssertTrue(ParseIp4Literal('1.2.3.4', V));
  AssertEquals(LongWord($01020304), V);
  AssertTrue(ParseIp4Literal('255.255.255.255', V));
  AssertFalse(ParseIp4Literal('256.1.1.1', V));
  AssertFalse(ParseIp4Literal('1.2.3', V));
  AssertFalse(ParseIp4Literal('1.2.3.4.5', V));
  AssertFalse(ParseIp4Literal('1..3.4', V));
  AssertFalse(ParseIp4Literal('a.b.c.d', V));
  AssertFalse(ParseIp4Literal('', V));
end;

procedure TProxyLiteralTest.TestIp6Parsing;
var
  B: array[0..15] of Byte;
begin
  AssertTrue(ParseIp6Literal('::1', B));
  AssertEquals(1, B[15]);
  AssertEquals(0, B[0]);
  AssertTrue(ParseIp6Literal('::', B));
  AssertTrue(ParseIp6Literal('2001:db8::ff00:42:8329', B));
  AssertEquals($20, B[0]);
  AssertEquals($01, B[1]);
  AssertEquals($83, B[14]);
  AssertEquals($29, B[15]);
  AssertTrue(ParseIp6Literal('1:2:3:4:5:6:7:8', B));
  AssertEquals(8, B[15]);
  AssertTrue('v4 tail', ParseIp6Literal('::ffff:1.2.3.4', B));
  AssertEquals(1, B[12]);
  AssertEquals(4, B[15]);
  AssertEquals($FF, B[10]);
  AssertFalse('two ::', ParseIp6Literal('1::2::3', B));
  AssertFalse('too many groups', ParseIp6Literal('1:2:3:4:5:6:7:8:9', B));
  AssertFalse('group too long', ParseIp6Literal('12345::1', B));
  AssertFalse('not hex', ParseIp6Literal('g::1', B));
  AssertFalse('no colon', ParseIp6Literal('1234', B));
  AssertFalse('seven groups no ::', ParseIp6Literal('1:2:3:4:5:6:7', B));
end;

procedure TProxyLiteralTest.TestLoopbackHosts;
begin
  AssertTrue(IsLoopbackHost('localhost'));
  AssertTrue(IsLoopbackHost('127.0.0.1'));
  AssertTrue(IsLoopbackHost('127.255.0.9'));
  AssertTrue(IsLoopbackHost('::1'));
  AssertTrue(IsLoopbackHost('0:0:0:0:0:0:0:1'));
  AssertFalse('prefix test is not enough', IsLoopbackHost('127.example.com'));
  AssertFalse(IsLoopbackHost('128.0.0.1'));
  AssertFalse(IsLoopbackHost('::2'));
  AssertFalse(IsLoopbackHost('notlocalhost'));
  AssertFalse(IsLoopbackHost('localhost.example'));
end;

procedure TProxyLiteralTest.TestSplitProxyTarget;
var
  Scheme, Host: string;
  Port: Word;
begin
  AssertTrue(SplitProxyTarget('https://Example.COM/a/b?x=1', Scheme, Host, Port));
  AssertEquals('https', Scheme);
  AssertEquals('example.com', Host);
  AssertEquals(443, Integer(Port));
  AssertTrue(SplitProxyTarget('http://example.com', Scheme, Host, Port));
  AssertEquals(80, Integer(Port));
  AssertTrue(SplitProxyTarget('http://u:p@example.com:8080/x', Scheme, Host, Port));
  AssertEquals('example.com', Host);
  AssertEquals(8080, Integer(Port));
  AssertTrue(SplitProxyTarget('https://[::1]:8443/x', Scheme, Host, Port));
  AssertEquals('::1', Host);
  AssertEquals(8443, Integer(Port));
  AssertTrue('no scheme counts as https',
    SplitProxyTarget('example.com/x', Scheme, Host, Port));
  AssertEquals('https', Scheme);
  AssertFalse(SplitProxyTarget('http://', Scheme, Host, Port));
  AssertFalse(SplitProxyTarget('http://example.com:99999/', Scheme, Host, Port));
end;

{ TProxyEnvironmentTest }

procedure TProxyEnvironmentTest.SetUp;
begin
  GEnv := TStringList.Create;
  GEnv.CaseSensitive := True;
  GEnv.NameValueSeparator := '=';
end;

procedure TProxyEnvironmentTest.TearDown;
begin
  FreeAndNil(GEnv);
end;

procedure TProxyEnvironmentTest.TestLowercaseWinsOverUppercase;
var
  E: TProxyEnvironment;
begin
  GEnv.Add('https_proxy=http://lower:1');
  GEnv.Add('HTTPS_PROXY=http://upper:2');
  GEnv.Add('all_proxy=http://alow:3');
  GEnv.Add('ALL_PROXY=http://aup:4');
  GEnv.Add('no_proxy=low.example');
  GEnv.Add('NO_PROXY=up.example');
  E := ReadProxyEnvironmentUsing(ScriptedLookup);
  AssertEquals('http://lower:1', E.HttpsProxy);
  AssertEquals('http://alow:3', E.AllProxy);
  AssertEquals('low.example', E.NoProxy);
end;

procedure TProxyEnvironmentTest.TestUppercaseHttpProxyIsIgnored;
var
  E: TProxyEnvironment;
begin
  GEnv.Add('HTTP_PROXY=http://evil:1');
  E := ReadProxyEnvironmentUsing(ScriptedLookup);
  AssertEquals('', E.HttpProxy);
  GEnv.Add('http_proxy=http://good:2');
  E := ReadProxyEnvironmentUsing(ScriptedLookup);
  AssertEquals('http://good:2', E.HttpProxy);
end;

procedure TProxyEnvironmentTest.TestUppercaseAllProxyAndHttpsProxyAreHonoured;
var
  E: TProxyEnvironment;
begin
  GEnv.Add('HTTPS_PROXY=http://up:1');
  GEnv.Add('ALL_PROXY=socks5://up:2');
  GEnv.Add('NO_PROXY=x.example');
  E := ReadProxyEnvironmentUsing(ScriptedLookup);
  AssertEquals('http://up:1', E.HttpsProxy);
  AssertEquals('socks5://up:2', E.AllProxy);
  AssertEquals('x.example', E.NoProxy);
end;

procedure TProxyEnvironmentTest.TestEmptyValueIsUnset;
var
  E: TProxyEnvironment;
begin
  GEnv.Add('https_proxy=');
  GEnv.Add('HTTPS_PROXY=http://fallback:1');
  E := ReadProxyEnvironmentUsing(ScriptedLookup);
  AssertEquals('empty lowercase falls through to uppercase',
    'http://fallback:1', E.HttpsProxy);
end;

procedure TProxyEnvironmentTest.TestNothingConfiguredYieldsNilSelector;
var
  E: TProxyEnvironment;
begin
  E := ReadProxyEnvironmentUsing(ScriptedLookup);
  AssertTrue(BuildProxySelector(nil, nil, '', True, E, '') = nil);
  AssertTrue(BuildProxySelector(nil, nil, '', False, E, 'a.example') = nil);
end;

{ TProxySelectorTest }

function TProxySelectorTest.Pick(const ASel: IProxySelector;
  const AUri: string): string;
begin
  if ASel = nil then
    Exit('direct');
  Result := Describe(ASel.SelectProxy(AUri));
end;

procedure TProxySelectorTest.TestEnvironmentSchemeSpecificThenAll;
var
  E: TProxyEnvironment;
  S: IProxySelector;
begin
  E.HttpProxy := 'http://hp:1';
  E.HttpsProxy := 'http://sp:2';
  E.AllProxy := 'socks5://ap:3';
  E.NoProxy := '';
  S := BuildProxySelector(nil, nil, '', True, E, '');
  AssertEquals('hp:1', Pick(S, 'http://example.com/'));
  AssertEquals('sp:2', Pick(S, 'https://example.com/'));
  E.HttpProxy := '';
  S := BuildProxySelector(nil, nil, '', True, E, '');
  AssertEquals('all fills the http gap', 'ap:3', Pick(S, 'http://example.com/'));
  AssertEquals('https keeps its own', 'sp:2', Pick(S, 'https://example.com/'));
end;

procedure TProxySelectorTest.TestAllProxyServesSchemesWithoutTheirOwn;
var
  E: TProxyEnvironment;
  S: IProxySelector;
begin
  E.HttpProxy := '';
  E.HttpsProxy := '';
  E.AllProxy := 'socks5://user:pw@ap:3';
  E.NoProxy := '';
  S := BuildProxySelector(nil, nil, '', True, E, '');
  AssertEquals('ap:3', Pick(S, 'http://example.com/'));
  AssertEquals('ap:3', Pick(S, 'https://example.com/'));
  AssertEquals(Ord(pkSocks5),
    Ord(S.SelectProxy('https://example.com/').Kind));
  AssertEquals('user', S.SelectProxy('https://example.com/').UserName);
end;

procedure TProxySelectorTest.TestPrecedenceMatrix;
var
  E: TProxyEnvironment;
  Fixed: IProxy;
  Custom: IProxySelector;
  S: IProxySelector;
  Mask: Integer;
  Expect, AllUrl: string;
  UseCustom: IProxySelector;
  UseFixed: IProxy;
begin
  // every combination of {custom, fixed, WithAllProxy, env scheme, env all}
  Fixed := TProxy.Create('fixed', 1);
  Custom := TFixedSelector.Create;
  for Mask := 0 to 31 do
  begin
    E.HttpProxy := '';
    E.HttpsProxy := '';
    E.AllProxy := '';
    E.NoProxy := '';
    if (Mask and 8) <> 0 then E.HttpsProxy := 'http://envs:4';
    if (Mask and 16) <> 0 then E.AllProxy := 'http://enva:5';
    UseCustom := nil;
    UseFixed := nil;
    AllUrl := '';
    if (Mask and 1) <> 0 then UseCustom := Custom;
    if (Mask and 2) <> 0 then UseFixed := Fixed;
    if (Mask and 4) <> 0 then AllUrl := 'http://allb:3';
    S := BuildProxySelector(UseCustom, UseFixed, AllUrl, True, E, '');
    if (Mask and 1) <> 0 then Expect := 'custom.example:1111'
    else if (Mask and 2) <> 0 then Expect := 'fixed:1'
    else if (Mask and 4) <> 0 then Expect := 'allb:3'
    else if (Mask and 8) <> 0 then Expect := 'envs:4'
    else if (Mask and 16) <> 0 then Expect := 'enva:5'
    else Expect := 'direct';
    AssertEquals('mask ' + IntToStr(Mask), Expect,
      Pick(S, 'https://example.com/'));
  end;
end;

procedure TProxySelectorTest.TestCustomSelectorIsTheSoleAuthority;
var
  E: TProxyEnvironment;
  S: IProxySelector;
begin
  E.HttpProxy := 'http://envh:1';
  E.HttpsProxy := '';
  E.AllProxy := '';
  E.NoProxy := '*';
  S := BuildProxySelector(TFixedSelector.Create, nil, '', True, E, '*');
  // neither no_proxy '*' nor loopback is consulted for a custom selector
  AssertEquals('custom.example:1111', Pick(S, 'http://example.com/'));
  AssertEquals('custom.example:1111', Pick(S, 'http://localhost/'));
end;

procedure TProxySelectorTest.TestLoopbackAlwaysConnectsDirectly;
var
  S: IProxySelector;
begin
  S := BuildProxySelector(nil, TProxy.Create('p', 1), '', False,
    EmptyEnv, '');
  AssertEquals('direct', Pick(S, 'http://localhost/'));
  AssertEquals('direct', Pick(S, 'https://localhost:8443/'));
  AssertEquals('direct', Pick(S, 'http://127.0.0.1:9000/'));
  AssertEquals('direct', Pick(S, 'http://[::1]:9000/'));
  AssertEquals('p:1', Pick(S, 'http://127.example.com/'));
end;

procedure TProxySelectorTest.TestNoProxyAppliesToFixedAndEnvironment;
var
  E: TProxyEnvironment;
  S: IProxySelector;
begin
  S := BuildProxySelector(nil, TProxy.Create('p', 1), '', False,
    EmptyEnv, '.corp');
  AssertEquals('direct', Pick(S, 'https://a.corp/'));
  AssertEquals('p:1', Pick(S, 'https://a.example/'));
  E.HttpProxy := 'http://envh:1';
  E.HttpsProxy := '';
  E.AllProxy := '';
  E.NoProxy := '';
  S := BuildProxySelector(nil, nil, '', True, E, '10.0.0.0/8');
  AssertEquals('direct', Pick(S, 'http://10.9.9.9/'));
  AssertEquals('envh:1', Pick(S, 'http://11.9.9.9/'));
end;

procedure TProxySelectorTest.TestNoProxyUnionsWithEnvironmentNoProxy;
var
  E: TProxyEnvironment;
  S: IProxySelector;
begin
  E.HttpProxy := 'http://envh:1';
  E.HttpsProxy := '';
  E.AllProxy := '';
  E.NoProxy := 'env.example';
  S := BuildProxySelector(nil, nil, '', True, E, 'manual.example');
  AssertEquals('direct', Pick(S, 'http://env.example/'));
  AssertEquals('direct', Pick(S, 'http://manual.example/'));
  AssertEquals('envh:1', Pick(S, 'http://other.example/'));
end;

procedure TProxySelectorTest.TestEnvironmentIgnoredWhenSwitchIsOff;
var
  E: TProxyEnvironment;
begin
  E.HttpProxy := 'http://envh:1';
  E.HttpsProxy := 'http://envs:2';
  E.AllProxy := 'http://enva:3';
  E.NoProxy := '';
  AssertTrue(BuildProxySelector(nil, nil, '', False, E, '') = nil);
end;

procedure TProxySelectorTest.TestBadEnvironmentValueFailsAtBuild;
var
  E: TProxyEnvironment;
  Raised: Boolean;
begin
  E.HttpProxy := '';
  E.HttpsProxy := 'socks4://p:1';
  E.AllProxy := '';
  E.NoProxy := '';
  Raised := False;
  try
    BuildProxySelector(nil, nil, '', True, E, '');
  except
    on EHttpProxyConfigError do
      Raised := True;
  end;
  AssertTrue(Raised);
  // and a bad value is only read when the switch is on
  AssertTrue(BuildProxySelector(nil, nil, '', False, E, '') = nil);
end;

procedure TProxySelectorTest.TestBadAllProxyFailsAtBuild;
var
  E: TProxyEnvironment;
  Raised: Boolean;
begin
  FillChar(E, SizeOf(E), 0);
  Raised := False;
  try
    BuildProxySelector(nil, nil, 'ftp://p:1', False, E, '');
  except
    on EHttpProxyConfigError do
      Raised := True;
  end;
  AssertTrue(Raised);
end;

procedure TProxySelectorTest.TestIpv6AuthorityIsParsed;
var
  S: IProxySelector;
  E: TProxyEnvironment;
begin
  FillChar(E, SizeOf(E), 0);
  S := BuildProxySelector(nil, TProxy.Create('p', 1), '', False, E, 'fd00::/8');
  AssertEquals('direct', Pick(S, 'https://[fd00::9]:8443/x'));
  AssertEquals('p:1', Pick(S, 'https://[2001:db8::9]:8443/x'));
end;

initialization
  RegisterTest(TProxyUrlTest);
  RegisterTest(TNoProxyTest);
  RegisterTest(TProxyLiteralTest);
  RegisterTest(TProxyEnvironmentTest);
  RegisterTest(TProxySelectorTest);
end.
