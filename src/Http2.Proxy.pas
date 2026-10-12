/// Proxy routing: proxy values, URL parsing, the no-proxy list, the proxy
/// environment variables, and the built-in selectors
// - this unit is part of the http2client project (see doc/design/proxy.md).
// - it depends on the RTL and Http2.Errors only.  mORMot2 (TUri, TIp4SubNet,
//   NetIsIP4/6, IsLocalHost, TCrtSocket.DoOpenTunnel) is the design reference
//   for the parsers below, not a dependency.
unit Http2.Proxy;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$interfaces com}

interface

uses
  SysUtils, Classes, Http2.Errors;

const
  cProxyDefaultHttpPort   = 80;
  cProxyDefaultHttpsPort  = 443;
  cProxyDefaultSocksPort  = 1080;
  /// RFC 1929: user name and password are each at most 255 octets
  cSocksMaxCredentialLen  = 255;

type
  /// pkHttp: HTTP CONNECT over TCP; pkHttps: HTTP CONNECT over TLS;
  /// pkSocks5: SOCKS5 CONNECT over TCP
  TProxyKind = (pkHttp, pkHttps, pkSocks5);

  /// one proxy endpoint.  Credentials are optional.
  IProxy = interface
    ['{7B1D5E02-9F6A-4C57-8A31-5D2E0C4A9B11}']
    function GetHost: string;
    function GetPort: Word;
    function GetKind: TProxyKind;
    function GetUserName: string;
    function GetPassword: string;
    property Host: string read GetHost;
    property Port: Word read GetPort;
    /// how the proxy is spoken to; also decides whether the leg to it is TLS
    property Kind: TProxyKind read GetKind;
    property UserName: string read GetUserName;
    property Password: string read GetPassword;
  end;

  /// chooses the route for one request URI
  IProxySelector = interface
    ['{7B1D5E02-9F6A-4C57-8A31-5D2E0C4A9B12}']
    /// the proxy to use for AUri, or nil for a direct connection
    function SelectProxy(const AUri: string): IProxy;
  end;

  TProxy = class(TInterfacedObject, IProxy)
  private
    FHost: string;
    FPort: Word;
    FKind: TProxyKind;
    FUserName: string;
    FPassword: string;
  public
    constructor Create(const AHost: string; const APort: Word); overload;
    constructor Create(const AHost: string; const APort: Word;
      const AUserName, APassword: string); overload;
    constructor Create(const AKind: TProxyKind; const AHost: string;
      const APort: Word); overload;
    constructor Create(const AKind: TProxyKind; const AHost: string;
      const APort: Word; const AUserName, APassword: string); overload;
    function GetHost: string;
    function GetPort: Word;
    function GetKind: TProxyKind;
    function GetUserName: string;
    function GetPassword: string;
  end;

  /// the proxy variables of the process environment, captured once
  TProxyEnvironment = record
    HttpProxy: string;
    HttpsProxy: string;
    AllProxy: string;
    NoProxy: string;
  end;

  /// reads one environment variable by exact name ('' when unset)
  TEnvLookup = function(const AName: string): string;

  /// the no-proxy list (doc/design/proxy.md "The no-proxy list")
  TNoProxyList = class
  private
    type
      TEntryKind = (ekAll, ekName, ekIp4, ekIp6);
      TEntry = record
        Kind: TEntryKind;
        Name: string;            // lowercase suffix, no leading dot
        Port: Integer;           // 0 = any
        Ip4: LongWord;           // masked network
        Mask4: LongWord;
        Ip6: array[0..15] of Byte;
        Prefix6: Integer;
      end;
    var
      FEntries: array of TEntry;
    procedure AddEntry(const AText: string);
  public
    /// add every entry of a comma-separated list; malformed entries are skipped
    procedure Add(const AList: string);
    function Count: Integer;
    /// does AHost (lowercase, no brackets) on APort match any entry?
    function Matches(const AHost: string; const APort: Word): Boolean;
  end;

/// parse '[scheme://][user[:password]@]host[:port][/...]' (doc/design/proxy.md
/// "Proxy URL values").  Raises EHttpProxyConfigError; messages never contain
/// the password.  An empty AValue yields nil.
function ParseProxyUrl(const AValue: string): IProxy;

/// the pool-key suffix of a proxied route: '' for nil, else
/// ' via [tls:|socks5:][user@]host:port'.  The password is never included.
function ProxyRouteKey(const AProxy: IProxy): string;

/// validate a proxy returned by a selector (non-empty host, non-zero port,
/// SOCKS5 credential lengths); raises EHttpProxyConfigError
procedure ValidateProxy(const AProxy: IProxy);

/// split an absolute URL into lowercase scheme, host (brackets removed) and
/// effective port.  A URL without a scheme counts as https.
function SplitProxyTarget(const AUri: string; out AScheme, AHost: string;
  out APort: Word): Boolean;

/// parse a dotted IPv4 literal
function ParseIp4Literal(const AText: string; out AValue: LongWord): Boolean;
/// parse an IPv6 literal (no brackets) into 16 bytes; accepts '::' and an
/// embedded IPv4 tail
function ParseIp6Literal(const AText: string; out ABytes: array of Byte): Boolean;

/// is AHost 'localhost' or a loopback literal (127.0.0.0/8, ::1)?
function IsLoopbackHost(const AHost: string): Boolean;

/// base64 of 'user:password' for Proxy-Authorization: Basic
function ProxyBasicCredentials(const AUserName, APassword: string): string;

/// resolve the proxy variables through ALookup.  Lowercase names win over
/// uppercase; uppercase HTTP_PROXY is ignored; an empty value is unset.
function ReadProxyEnvironmentUsing(const ALookup: TEnvLookup): TProxyEnvironment;
/// resolve the proxy variables of the process environment
function ReadProxyEnvironment: TProxyEnvironment;

/// collapse every proxy source into one selector (doc/design/proxy.md
/// "Precedence"): ACustom wins outright; else AFixed, then AAllProxyUrl, then
/// the environment AEnv (when AUseEnv), all filtered by loopback and the
/// no-proxy list ANoProxy.  Returns nil when no source is configured, i.e. the
/// route is direct for every request.  Raises EHttpProxyConfigError for an
/// unusable proxy value.
function BuildProxySelector(const ACustom: IProxySelector;
  const AFixed: IProxy; const AAllProxyUrl: string; const AUseEnv: Boolean;
  const AEnv: TProxyEnvironment; const ANoProxy: string): IProxySelector;

implementation

{ ---- small helpers ---- }

function HexVal(C: Char): Integer;
begin
  case C of
    '0'..'9': Result := Ord(C) - Ord('0');
    'a'..'f': Result := Ord(C) - Ord('a') + 10;
    'A'..'F': Result := Ord(C) - Ord('A') + 10;
  else
    Result := -1;
  end;
end;

function PercentDecode(const S: string; out OK: Boolean): string;
var
  I, H, L: Integer;
begin
  Result := '';
  OK := True;
  I := 1;
  while I <= Length(S) do
  begin
    if S[I] = '%' then
    begin
      if I + 2 > Length(S) then
      begin
        OK := False;
        Exit;
      end;
      H := HexVal(S[I + 1]);
      L := HexVal(S[I + 2]);
      if (H < 0) or (L < 0) then
      begin
        OK := False;
        Exit;
      end;
      Result := Result + Chr(H * 16 + L);
      Inc(I, 3);
    end
    else
    begin
      Result := Result + S[I];
      Inc(I);
    end;
  end;
end;

function ParsePort(const S: string; out APort: Integer): Boolean;
var
  I: Integer;
begin
  Result := (S <> '') and (Length(S) <= 5);
  if not Result then
    Exit;
  for I := 1 to Length(S) do
    if not (S[I] in ['0'..'9']) then
      Exit(False);
  APort := StrToInt(S);
  Result := (APort >= 1) and (APort <= 65535);
end;

{ ---- TProxy ---- }

constructor TProxy.Create(const AHost: string; const APort: Word);
begin
  Create(pkHttp, AHost, APort, '', '');
end;

constructor TProxy.Create(const AHost: string; const APort: Word;
  const AUserName, APassword: string);
begin
  Create(pkHttp, AHost, APort, AUserName, APassword);
end;

constructor TProxy.Create(const AKind: TProxyKind; const AHost: string;
  const APort: Word);
begin
  Create(AKind, AHost, APort, '', '');
end;

constructor TProxy.Create(const AKind: TProxyKind; const AHost: string;
  const APort: Word; const AUserName, APassword: string);
begin
  inherited Create;
  FKind := AKind;
  FHost := AHost;
  FPort := APort;
  FUserName := AUserName;
  FPassword := APassword;
end;

function TProxy.GetHost: string;
begin
  Result := FHost;
end;

function TProxy.GetPort: Word;
begin
  Result := FPort;
end;

function TProxy.GetKind: TProxyKind;
begin
  Result := FKind;
end;

function TProxy.GetUserName: string;
begin
  Result := FUserName;
end;

function TProxy.GetPassword: string;
begin
  Result := FPassword;
end;

{ ---- literals ---- }

function ParseIp4Literal(const AText: string; out AValue: LongWord): Boolean;
var
  I, Part, Digits, Dots: Integer;
  C: Char;
  Acc: LongWord;
begin
  Result := False;
  AValue := 0;
  if AText = '' then
    Exit;
  Acc := 0;
  Part := 0;
  Digits := 0;
  Dots := 0;
  for I := 1 to Length(AText) do
  begin
    C := AText[I];
    if C in ['0'..'9'] then
    begin
      Part := Part * 10 + (Ord(C) - Ord('0'));
      Inc(Digits);
      if (Digits > 3) or (Part > 255) then
        Exit;
    end
    else if C = '.' then
    begin
      if Digits = 0 then
        Exit;
      Acc := (Acc shl 8) or LongWord(Part);
      Part := 0;
      Digits := 0;
      Inc(Dots);
      if Dots > 3 then
        Exit;
    end
    else
      Exit;
  end;
  if (Dots <> 3) or (Digits = 0) then
    Exit;
  AValue := (Acc shl 8) or LongWord(Part);
  Result := True;
end;

function ParseIp6Literal(const AText: string; out ABytes: array of Byte): Boolean;
var
  Groups: array[0..7] of Word;
  Head, Tail: array[0..7] of Word;
  NHead, NTail, I, P, Start, Skip: Integer;
  Part: string;
  DoubleColon: Integer;
  Text: string;
  Seg: array of string;
  N, K, Val: Integer;
  Ip4: LongWord;
  HasV4: Boolean;
begin
  Result := False;
  if Length(ABytes) < 16 then
    Exit;
  FillChar(ABytes[0], 16, 0);
  Text := AText;
  if (Text = '') or (Pos(':', Text) = 0) then
    Exit;
  DoubleColon := Pos('::', Text);
  if (DoubleColon > 0) and (Pos('::', Copy(Text, DoubleColon + 1, MaxInt)) > 0) then
    Exit;   // two '::'
  NHead := 0;
  NTail := 0;
  HasV4 := False;
  Ip4 := 0;
  // split into head (before ::) and tail (after ::), or one run without ::
  if DoubleColon > 0 then
  begin
    Part := Copy(Text, 1, DoubleColon - 1);
    Text := Copy(Text, DoubleColon + 2, MaxInt);
    // head groups
    SetLength(Seg, 0);
    if Part <> '' then
    begin
      Start := 1;
      for I := 1 to Length(Part) + 1 do
        if (I > Length(Part)) or (Part[I] = ':') then
        begin
          K := Length(Seg);
          SetLength(Seg, K + 1);
          Seg[K] := Copy(Part, Start, I - Start);
          Start := I + 1;
        end;
    end;
    for I := 0 to High(Seg) do
    begin
      if (Seg[I] = '') or (Length(Seg[I]) > 4) or (NHead >= 8) then
        Exit;
      Val := 0;
      for P := 1 to Length(Seg[I]) do
      begin
        if HexVal(Seg[I][P]) < 0 then
          Exit;
        Val := Val * 16 + HexVal(Seg[I][P]);
      end;
      Head[NHead] := Val;
      Inc(NHead);
    end;
    // tail groups (the last may be an IPv4 literal)
    SetLength(Seg, 0);
    if Text <> '' then
    begin
      Start := 1;
      for I := 1 to Length(Text) + 1 do
        if (I > Length(Text)) or (Text[I] = ':') then
        begin
          K := Length(Seg);
          SetLength(Seg, K + 1);
          Seg[K] := Copy(Text, Start, I - Start);
          Start := I + 1;
        end;
    end;
    N := Length(Seg);
    for I := 0 to N - 1 do
    begin
      if Seg[I] = '' then
        Exit;
      if (I = N - 1) and (Pos('.', Seg[I]) > 0) then
      begin
        if not ParseIp4Literal(Seg[I], Ip4) then
          Exit;
        HasV4 := True;
        Break;
      end;
      if (Length(Seg[I]) > 4) or (NTail >= 8) then
        Exit;
      Val := 0;
      for P := 1 to Length(Seg[I]) do
      begin
        if HexVal(Seg[I][P]) < 0 then
          Exit;
        Val := Val * 16 + HexVal(Seg[I][P]);
      end;
      Tail[NTail] := Val;
      Inc(NTail);
    end;
    Skip := NHead + NTail + Ord(HasV4) * 2;
    if Skip > 7 then
      Exit;   // '::' must stand for at least one group
    for I := 0 to 7 do
      Groups[I] := 0;
    for I := 0 to NHead - 1 do
      Groups[I] := Head[I];
    if HasV4 then
    begin
      Groups[6] := Word(Ip4 shr 16);
      Groups[7] := Word(Ip4 and $FFFF);
      for I := 0 to NTail - 1 do
        Groups[6 - NTail + I] := Tail[I];
    end
    else
      for I := 0 to NTail - 1 do
        Groups[8 - NTail + I] := Tail[I];
  end
  else
  begin
    SetLength(Seg, 0);
    Start := 1;
    for I := 1 to Length(Text) + 1 do
      if (I > Length(Text)) or (Text[I] = ':') then
      begin
        K := Length(Seg);
        SetLength(Seg, K + 1);
        Seg[K] := Copy(Text, Start, I - Start);
        Start := I + 1;
      end;
    N := Length(Seg);
    if (N <> 8) and not ((N = 7) and (Pos('.', Seg[6]) > 0)) then
      Exit;
    K := 0;
    for I := 0 to N - 1 do
    begin
      if Seg[I] = '' then
        Exit;
      if (I = N - 1) and (Pos('.', Seg[I]) > 0) then
      begin
        if not ParseIp4Literal(Seg[I], Ip4) then
          Exit;
        Groups[K] := Word(Ip4 shr 16);
        Groups[K + 1] := Word(Ip4 and $FFFF);
        Inc(K, 2);
        Break;
      end;
      if Length(Seg[I]) > 4 then
        Exit;
      Val := 0;
      for P := 1 to Length(Seg[I]) do
      begin
        if HexVal(Seg[I][P]) < 0 then
          Exit;
        Val := Val * 16 + HexVal(Seg[I][P]);
      end;
      Groups[K] := Val;
      Inc(K);
    end;
    if K <> 8 then
      Exit;
  end;
  for I := 0 to 7 do
  begin
    ABytes[I * 2] := Groups[I] shr 8;
    ABytes[I * 2 + 1] := Groups[I] and $FF;
  end;
  Result := True;
end;

function IsLoopbackHost(const AHost: string): Boolean;
var
  V: LongWord;
  B: array[0..15] of Byte;
  I: Integer;
begin
  if AHost = 'localhost' then
    Exit(True);
  if ParseIp4Literal(AHost, V) then
    Exit((V shr 24) = 127);
  if ParseIp6Literal(AHost, B) then
  begin
    for I := 0 to 14 do
      if B[I] <> 0 then
        Exit(False);
    Exit(B[15] = 1);
  end;
  Result := False;
end;

{ ---- URL splitting ---- }

/// split an authority 'userinfo@host:port' into its parts; host has no
/// brackets and keeps its case.  APortText is '' when absent.
function SplitAuthority(const AAuthority: string; out AUserInfo, AHost,
  APortText: string): Boolean;
var
  Auth: string;
  At, P, Close: Integer;
begin
  Result := False;
  AUserInfo := '';
  AHost := '';
  APortText := '';
  Auth := AAuthority;
  At := 0;
  for P := Length(Auth) downto 1 do
    if Auth[P] = '@' then
    begin
      At := P;
      Break;
    end;
  if At > 0 then
  begin
    AUserInfo := Copy(Auth, 1, At - 1);
    Auth := Copy(Auth, At + 1, MaxInt);
  end;
  if Auth = '' then
    Exit;
  if Auth[1] = '[' then
  begin
    Close := Pos(']', Auth);
    if Close = 0 then
      Exit;
    AHost := Copy(Auth, 2, Close - 2);
    Auth := Copy(Auth, Close + 1, MaxInt);
    if Auth <> '' then
    begin
      if Auth[1] <> ':' then
        Exit;
      APortText := Copy(Auth, 2, MaxInt);
      if APortText = '' then
        Exit;
    end;
  end
  else
  begin
    P := Pos(':', Auth);
    if P > 0 then
    begin
      AHost := Copy(Auth, 1, P - 1);
      APortText := Copy(Auth, P + 1, MaxInt);
      if APortText = '' then
        Exit;
    end
    else
      AHost := Auth;
  end;
  Result := AHost <> '';
end;

function SplitProxyTarget(const AUri: string; out AScheme, AHost: string;
  out APort: Word): Boolean;
var
  Rest, Auth, UserInfo, PortText: string;
  P, Port, Q: Integer;
begin
  Result := False;
  AScheme := 'https';
  AHost := '';
  APort := 0;
  Rest := AUri;
  P := Pos('://', Rest);
  if P > 0 then
  begin
    AScheme := LowerCase(Copy(Rest, 1, P - 1));
    Rest := Copy(Rest, P + 3, MaxInt);
  end;
  // the authority ends at the first '/', '?' or '#'
  Q := 0;
  for P := 1 to Length(Rest) do
    if Rest[P] in ['/', '?', '#'] then
    begin
      Q := P;
      Break;
    end;
  if Q > 0 then
    Auth := Copy(Rest, 1, Q - 1)
  else
    Auth := Rest;
  if not SplitAuthority(Auth, UserInfo, AHost, PortText) then
    Exit;
  AHost := LowerCase(AHost);
  if PortText <> '' then
  begin
    if not ParsePort(PortText, Port) then
      Exit;
    APort := Word(Port);
  end
  else if AScheme = 'http' then
    APort := cProxyDefaultHttpPort
  else
    APort := cProxyDefaultHttpsPort;
  Result := True;
end;

{ ---- proxy URL ---- }

function ParseProxyUrl(const AValue: string): IProxy;
var
  Text, Scheme, Rest, Auth, UserInfo, Host, PortText, User, Pass: string;
  P, Q, Port: Integer;
  Kind: TProxyKind;
  OK: Boolean;
begin
  Text := Trim(AValue);
  if Text = '' then
    Exit(nil);
  Scheme := 'http';
  Rest := Text;
  P := Pos('://', Rest);
  if P > 0 then
  begin
    Scheme := LowerCase(Copy(Rest, 1, P - 1));
    Rest := Copy(Rest, P + 3, MaxInt);
  end;
  if Scheme = 'http' then
    Kind := pkHttp
  else if Scheme = 'https' then
    Kind := pkHttps
  else if (Scheme = 'socks5') or (Scheme = 'socks5h') then
    Kind := pkSocks5
  else
    raise EHttpProxyConfigError.CreateFmt(
      'unsupported proxy scheme "%s" (supported: http, https, socks5, socks5h)',
      [Scheme]);
  Q := 0;
  for P := 1 to Length(Rest) do
    if Rest[P] in ['/', '?', '#'] then
    begin
      Q := P;
      Break;
    end;
  if Q > 0 then
    Auth := Copy(Rest, 1, Q - 1)
  else
    Auth := Rest;
  if not SplitAuthority(Auth, UserInfo, Host, PortText) then
    raise EHttpProxyConfigError.Create('proxy value has no usable host');
  if PortText <> '' then
  begin
    if not ParsePort(PortText, Port) then
      raise EHttpProxyConfigError.CreateFmt(
        'proxy %s has an invalid port "%s"', [Host, PortText]);
  end
  else
    case Kind of
      pkHttp:   Port := cProxyDefaultHttpPort;
      pkHttps:  Port := cProxyDefaultHttpsPort;
    else
      Port := cProxyDefaultSocksPort;
    end;
  User := '';
  Pass := '';
  if UserInfo <> '' then
  begin
    P := Pos(':', UserInfo);
    if P > 0 then
    begin
      User := Copy(UserInfo, 1, P - 1);
      Pass := Copy(UserInfo, P + 1, MaxInt);
    end
    else
      User := UserInfo;
    User := PercentDecode(User, OK);
    if not OK then
      raise EHttpProxyConfigError.CreateFmt(
        'proxy %s has an invalid percent-encoded user name', [Host]);
    Pass := PercentDecode(Pass, OK);
    if not OK then
      raise EHttpProxyConfigError.CreateFmt(
        'proxy %s has an invalid percent-encoded credential', [Host]);
  end;
  Result := TProxy.Create(Kind, Host, Word(Port), User, Pass);
  ValidateProxy(Result);
end;

procedure ValidateProxy(const AProxy: IProxy);
begin
  if AProxy = nil then
    Exit;
  if AProxy.Host = '' then
    raise EHttpProxyConfigError.Create('proxy has an empty host');
  if AProxy.Port = 0 then
    raise EHttpProxyConfigError.CreateFmt('proxy %s has port 0', [AProxy.Host]);
  if (AProxy.Kind = pkSocks5) and
     ((Length(AProxy.UserName) > cSocksMaxCredentialLen) or
      (Length(AProxy.Password) > cSocksMaxCredentialLen)) then
    raise EHttpProxyConfigError.CreateFmt(
      'SOCKS5 proxy %s: user name and password are limited to %d octets',
      [AProxy.Host, cSocksMaxCredentialLen]);
end;

function ProxyRouteKey(const AProxy: IProxy): string;
var
  Host: string;
begin
  if AProxy = nil then
    Exit('');
  Host := AProxy.Host;
  if Pos(':', Host) > 0 then
    Host := '[' + Host + ']';
  Result := ' via ';
  case AProxy.Kind of
    pkHttps:  Result := Result + 'tls:';
    pkSocks5: Result := Result + 'socks5:';
  end;
  if AProxy.UserName <> '' then
    Result := Result + AProxy.UserName + '@';
  Result := Result + Host + ':' + IntToStr(AProxy.Port);
end;

function ProxyBasicCredentials(const AUserName, APassword: string): string;
const
  cAlphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
var
  Src: string;
  I, N: Integer;
  B0, B1, B2: Byte;
begin
  Src := AUserName + ':' + APassword;
  Result := '';
  I := 1;
  while I <= Length(Src) do
  begin
    N := Length(Src) - I + 1;
    B0 := Ord(Src[I]);
    if N > 1 then B1 := Ord(Src[I + 1]) else B1 := 0;
    if N > 2 then B2 := Ord(Src[I + 2]) else B2 := 0;
    Result := Result + cAlphabet[(B0 shr 2) + 1];
    Result := Result + cAlphabet[(((B0 and 3) shl 4) or (B1 shr 4)) + 1];
    if N > 1 then
      Result := Result + cAlphabet[(((B1 and 15) shl 2) or (B2 shr 6)) + 1]
    else
      Result := Result + '=';
    if N > 2 then
      Result := Result + cAlphabet[(B2 and 63) + 1]
    else
      Result := Result + '=';
    Inc(I, 3);
  end;
end;

{ ---- no-proxy list ---- }

procedure TNoProxyList.Add(const AList: string);
var
  I, Start: Integer;
begin
  Start := 1;
  for I := 1 to Length(AList) + 1 do
    if (I > Length(AList)) or (AList[I] = ',') then
    begin
      AddEntry(Trim(Copy(AList, Start, I - Start)));
      Start := I + 1;
    end;
end;

function TNoProxyList.Count: Integer;
begin
  Result := Length(FEntries);
end;

procedure TNoProxyList.AddEntry(const AText: string);
var
  Text, HostPart, PortText, PrefixText: string;
  E: TEntry;
  Port, Prefix, P, ColonCount, I: Integer;
  V: LongWord;
  B: array[0..15] of Byte;
  Bracketed: Boolean;
begin
  Text := LowerCase(AText);
  if Text = '' then
    Exit;
  FillChar(E, SizeOf(E), 0);
  if Text = '*' then
  begin
    E.Kind := ekAll;
    SetLength(FEntries, Length(FEntries) + 1);
    FEntries[High(FEntries)] := E;
    Exit;
  end;
  Port := 0;
  Bracketed := False;
  PrefixText := '';
  HostPart := Text;
  // CIDR suffix
  P := Pos('/', HostPart);
  if P > 0 then
  begin
    PrefixText := Copy(HostPart, P + 1, MaxInt);
    HostPart := Copy(HostPart, 1, P - 1);
  end;
  if (HostPart <> '') and (HostPart[1] = '[') then
  begin
    P := Pos(']', HostPart);
    if P = 0 then
      Exit;
    PortText := Copy(HostPart, P + 1, MaxInt);
    HostPart := Copy(HostPart, 2, P - 2);
    Bracketed := True;
    if PortText <> '' then
    begin
      if PortText[1] <> ':' then
        Exit;
      if not ParsePort(Copy(PortText, 2, MaxInt), Port) then
        Exit;
    end;
  end
  else
  begin
    ColonCount := 0;
    for I := 1 to Length(HostPart) do
      if HostPart[I] = ':' then
        Inc(ColonCount);
    if ColonCount = 1 then
    begin
      P := Pos(':', HostPart);
      if not ParsePort(Copy(HostPart, P + 1, MaxInt), Port) then
        Exit;
      HostPart := Copy(HostPart, 1, P - 1);
    end;
    // more than one colon: a bare IPv6 literal
  end;
  if HostPart = '' then
    Exit;
  E.Port := Port;
  if ParseIp4Literal(HostPart, V) then
  begin
    Prefix := 32;
    if PrefixText <> '' then
      if (not ParsePort(PrefixText, Prefix)) and (PrefixText <> '0') then
        Exit
      else if PrefixText = '0' then
        Prefix := 0;
    if Prefix > 32 then
      Exit;
    E.Kind := ekIp4;
    if Prefix = 0 then
      E.Mask4 := 0
    else
      E.Mask4 := LongWord($FFFFFFFF) shl (32 - Prefix);
    E.Ip4 := V and E.Mask4;
  end
  else if ParseIp6Literal(HostPart, B) then
  begin
    Prefix := 128;
    if PrefixText <> '' then
      if (not ParsePort(PrefixText, Prefix)) and (PrefixText <> '0') then
        Exit
      else if PrefixText = '0' then
        Prefix := 0;
    if Prefix > 128 then
      Exit;
    E.Kind := ekIp6;
    E.Prefix6 := Prefix;
    Move(B[0], E.Ip6[0], 16);
  end
  else
  begin
    if (PrefixText <> '') or Bracketed then
      Exit;     // a CIDR or bracket on a name is malformed
    // '*.example.com' and '.example.com' mean 'example.com'
    if Copy(HostPart, 1, 2) = '*.' then
      HostPart := Copy(HostPart, 3, MaxInt)
    else if Copy(HostPart, 1, 1) = '.' then
      HostPart := Copy(HostPart, 2, MaxInt);
    if HostPart = '' then
      Exit;
    E.Kind := ekName;
    E.Name := HostPart;
  end;
  SetLength(FEntries, Length(FEntries) + 1);
  FEntries[High(FEntries)] := E;
end;

function TNoProxyList.Matches(const AHost: string; const APort: Word): Boolean;
var
  I, J, FullBytes, RemBits: Integer;
  Host: string;
  V4: LongWord;
  B6: array[0..15] of Byte;
  Is4, Is6, Eq: Boolean;
  E: TEntry;
  Mask: Byte;
begin
  Result := False;
  Host := LowerCase(AHost);
  Is4 := ParseIp4Literal(Host, V4);
  Is6 := (not Is4) and ParseIp6Literal(Host, B6);
  for I := 0 to High(FEntries) do
  begin
    E := FEntries[I];
    if (E.Port <> 0) and (E.Port <> APort) then
      Continue;
    case E.Kind of
      ekAll:
        Exit(True);
      ekName:
        if (not Is4) and (not Is6) then
        begin
          if Host = E.Name then
            Exit(True);
          if (Length(Host) > Length(E.Name)) and
             (Copy(Host, Length(Host) - Length(E.Name) + 1, MaxInt) = E.Name) and
             (Host[Length(Host) - Length(E.Name)] = '.') then
            Exit(True);
        end;
      ekIp4:
        if Is4 and ((V4 and E.Mask4) = E.Ip4) then
          Exit(True);
      ekIp6:
        if Is6 then
        begin
          FullBytes := E.Prefix6 div 8;
          RemBits := E.Prefix6 mod 8;
          Eq := True;
          for J := 0 to FullBytes - 1 do
            if B6[J] <> E.Ip6[J] then
            begin
              Eq := False;
              Break;
            end;
          if Eq and (RemBits > 0) then
          begin
            Mask := Byte($FF shl (8 - RemBits));
            Eq := (B6[FullBytes] and Mask) = (E.Ip6[FullBytes] and Mask);
          end;
          if Eq then
            Exit(True);
        end;
    end;
  end;
end;

{ ---- environment ---- }

function Pick(const ALookup: TEnvLookup; const ALower, AUpper: string): string;
begin
  Result := ALookup(ALower);
  if (Result = '') and (AUpper <> '') then
    Result := ALookup(AUpper);
end;

function ReadProxyEnvironmentUsing(const ALookup: TEnvLookup): TProxyEnvironment;
begin
  // uppercase HTTP_PROXY is never read: in a CGI process the Proxy: request
  // header surfaces under that name (httpoxy)
  Result.HttpProxy := Pick(ALookup, 'http_proxy', '');
  Result.HttpsProxy := Pick(ALookup, 'https_proxy', 'HTTPS_PROXY');
  Result.AllProxy := Pick(ALookup, 'all_proxy', 'ALL_PROXY');
  Result.NoProxy := Pick(ALookup, 'no_proxy', 'NO_PROXY');
end;

function ProcessEnvLookup(const AName: string): string;
begin
  Result := GetEnvironmentVariable(AName);
end;

function ReadProxyEnvironment: TProxyEnvironment;
begin
  Result := ReadProxyEnvironmentUsing(ProcessEnvLookup);
end;

{ ---- built-in selector ---- }

type
  TBuiltinProxySelector = class(TInterfacedObject, IProxySelector)
  private
    FFixed: IProxy;
    FAll: IProxy;
    FEnvHttp: IProxy;
    FEnvHttps: IProxy;
    FEnvAll: IProxy;
    FNoProxy: TNoProxyList;
  public
    destructor Destroy; override;
    function SelectProxy(const AUri: string): IProxy;
  end;

destructor TBuiltinProxySelector.Destroy;
begin
  FNoProxy.Free;
  inherited Destroy;
end;

function TBuiltinProxySelector.SelectProxy(const AUri: string): IProxy;
var
  Scheme, Host: string;
  Port: Word;
begin
  Result := nil;
  if not SplitProxyTarget(AUri, Scheme, Host, Port) then
    Exit;
  // loopback and the no-proxy list always connect directly
  if IsLoopbackHost(Host) then
    Exit;
  if (FNoProxy <> nil) and FNoProxy.Matches(Host, Port) then
    Exit;
  if FFixed <> nil then
    Exit(FFixed);
  if FAll <> nil then
    Exit(FAll);
  if Scheme = 'http' then
    Result := FEnvHttp
  else if Scheme = 'https' then
    Result := FEnvHttps;
  if Result = nil then
    Result := FEnvAll;
end;

function BuildProxySelector(const ACustom: IProxySelector;
  const AFixed: IProxy; const AAllProxyUrl: string; const AUseEnv: Boolean;
  const AEnv: TProxyEnvironment; const ANoProxy: string): IProxySelector;
var
  Sel: TBuiltinProxySelector;
  Env: TProxyEnvironment;
  NoProxy: string;
begin
  if ACustom <> nil then
    Exit(ACustom);
  ValidateProxy(AFixed);
  Sel := TBuiltinProxySelector.Create;
  Result := Sel;      // the interface now owns Sel
  Sel.FNoProxy := TNoProxyList.Create;
  Sel.FFixed := AFixed;
  Sel.FAll := ParseProxyUrl(AAllProxyUrl);
  NoProxy := ANoProxy;
  if AUseEnv then
  begin
    Env := AEnv;
    Sel.FEnvHttp := ParseProxyUrl(Env.HttpProxy);
    Sel.FEnvHttps := ParseProxyUrl(Env.HttpsProxy);
    Sel.FEnvAll := ParseProxyUrl(Env.AllProxy);
    if Env.NoProxy <> '' then
      if NoProxy <> '' then
        NoProxy := NoProxy + ',' + Env.NoProxy
      else
        NoProxy := Env.NoProxy;
  end;
  Sel.FNoProxy.Add(NoProxy);
  if (Sel.FFixed = nil) and (Sel.FAll = nil) and (Sel.FEnvHttp = nil) and
     (Sel.FEnvHttps = nil) and (Sel.FEnvAll = nil) then
    Result := nil;   // nothing configured: every route is direct
end;

end.
