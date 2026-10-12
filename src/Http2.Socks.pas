/// SOCKS5 client (RFC 1928) with username/password authentication (RFC 1929)
// - this unit is part of the http2client project (see doc/design/proxy.md
//   "SOCKS5").
// - the byte builders and the reply parser are pure (no I/O) so every layout
//   can be asserted exactly; EstablishSocksTunnel drives them over an
//   ISocksChannel supplied by the transport.
// - only the CONNECT command is implemented.  The target host is always sent
//   as given (a name as ATYP 3, an IP literal as ATYP 1 or 4); the client
//   never resolves it, so DNS happens at the proxy.
unit Http2.Socks;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$interfaces com}

interface

uses
  SysUtils, Http2.Errors, Http2.Proxy;

const
  cSocksVersion         = 5;
  cSocksAuthVersion     = 1;      // RFC 1929 sub-negotiation version
  cSocksMethodNone      = $00;
  cSocksMethodGssapi    = $01;
  cSocksMethodUserPass  = $02;
  cSocksMethodRefused   = $FF;
  cSocksCmdConnect      = $01;
  cSocksAtypIp4         = $01;
  cSocksAtypName        = $03;
  cSocksAtypIp6         = $04;
  cSocksRepSucceeded    = $00;
  /// a domain name is sent with a one-octet length
  cSocksMaxNameLen      = 255;

type
  /// the transport under a SOCKS5 exchange
  ISocksChannel = interface
    ['{7B1D5E02-9F6A-4C57-8A31-5D2E0C4A9B13}']
    /// write all of AData or raise
    procedure WriteAll(const AData: TBytes);
    /// read between 1 and ACount bytes into ABuffer; 0 means the peer closed
    function ReadSome(var ABuffer; const ACount: Integer): Integer;
  end;

  /// incremental parser for 'VER REP RSV ATYP BND.ADDR BND.PORT'
  // - it never asks for more bytes than the reply holds, so none of the
  //   origin's stream is consumed
  TSocksReplyParser = record
  private
    FState: Integer;       // 0 header, 1 name length, 2 address+port, 3 done
    FHeader: array[0..3] of Byte;
    FHave: Integer;
    FNeed: Integer;
    FRep: Byte;
    FFailed: Boolean;
    FError: string;
    FBound: TBytes;
  public
    procedure Reset;
    /// feed the next bytes of the reply
    procedure Feed(const AData: array of Byte);
    /// number of bytes the parser needs next (0 once complete or failed)
    function Need: Integer;
    function Complete: Boolean;
    /// True when the reply was malformed (a bad VER or ATYP); Error says why
    property Failed: Boolean read FFailed;
    property Error: string read FError;
    /// the REP field
    property Rep: Byte read FRep;
    /// BND.ADDR followed by BND.PORT, as received
    property Bound: TBytes read FBound;
  end;

/// '05 01 00' without credentials, '05 02 00 02' with them
function BuildSocksGreeting(const AHasCredentials: Boolean): TBytes;
/// RFC 1929: '01 ULEN user PLEN password'
function BuildSocksAuthRequest(const AUserName, APassword: string): TBytes;
/// '05 01 00 ATYP addr port' for AHost:APort
// - raises EHttpConnectionError for a name longer than 255 octets
function BuildSocksConnect(const AHost: string; const APort: Word): TBytes;
/// the RFC 1928 wording for a REP code (1..8), else 'unassigned reply code N'
function SocksReplyText(const ARep: Byte): string;

/// run the SOCKS5 CONNECT exchange to AHost:APort over AChannel.  Raises
/// EHttpConnectionError naming the proxy host and port; the message never
/// contains the credentials.
procedure EstablishSocksTunnel(const AChannel: ISocksChannel;
  const AProxy: IProxy; const AHost: string; const APort: Word);

implementation

{ TSocksReplyParser }

procedure TSocksReplyParser.Reset;
begin
  FState := 0;
  FHave := 0;
  FNeed := 4;
  FRep := 0;
  FFailed := False;
  FError := '';
  FBound := nil;
end;

function TSocksReplyParser.Need: Integer;
begin
  if FFailed or (FState = 3) then
    Result := 0
  else
    Result := FNeed;
end;

function TSocksReplyParser.Complete: Boolean;
begin
  Result := (FState = 3) and (not FFailed);
end;

procedure TSocksReplyParser.Feed(const AData: array of Byte);
var
  I, N: Integer;
  B: Byte;
begin
  for I := 0 to High(AData) do
  begin
    if FFailed or (FState = 3) then
      Exit;
    B := AData[I];
    case FState of
      0:
        begin
          FHeader[FHave] := B;
          Inc(FHave);
          Dec(FNeed);
          if FNeed = 0 then
          begin
            if FHeader[0] <> cSocksVersion then
            begin
              FFailed := True;
              FError := Format('reply has version %d, expected 5', [FHeader[0]]);
              Exit;
            end;
            FRep := FHeader[1];
            case FHeader[3] of
              cSocksAtypIp4:
                begin FState := 2; FNeed := 4 + 2; end;
              cSocksAtypIp6:
                begin FState := 2; FNeed := 16 + 2; end;
              cSocksAtypName:
                begin FState := 1; FNeed := 1; end;
            else
              FFailed := True;
              FError := Format('reply has unknown address type %d', [FHeader[3]]);
              Exit;
            end;
            FHave := 0;
          end;
        end;
      1:
        begin
          // the length octet of a domain-name BND.ADDR
          N := B;
          SetLength(FBound, 0);
          FState := 2;
          FNeed := N + 2;
          FHave := 0;
        end;
      2:
        begin
          SetLength(FBound, Length(FBound) + 1);
          FBound[High(FBound)] := B;
          Dec(FNeed);
          if FNeed = 0 then
            FState := 3;
        end;
    end;
  end;
end;

{ builders }

function BuildSocksGreeting(const AHasCredentials: Boolean): TBytes;
begin
  Result := nil;
  if AHasCredentials then
  begin
    SetLength(Result, 4);
    Result[0] := cSocksVersion;
    Result[1] := 2;
    Result[2] := cSocksMethodNone;
    Result[3] := cSocksMethodUserPass;
  end
  else
  begin
    SetLength(Result, 3);
    Result[0] := cSocksVersion;
    Result[1] := 1;
    Result[2] := cSocksMethodNone;
  end;
end;

function BuildSocksAuthRequest(const AUserName, APassword: string): TBytes;
var
  I, P: Integer;
begin
  Result := nil;
  if (Length(AUserName) < 1) or (Length(AUserName) > cSocksMaxCredentialLen) or
     (Length(APassword) > cSocksMaxCredentialLen) then
    raise EHttpProxyConfigError.Create(
      'SOCKS5 user name must be 1..255 octets and the password at most 255');
  SetLength(Result, 3 + Length(AUserName) + Length(APassword));
  P := 0;
  Result[P] := cSocksAuthVersion; Inc(P);
  Result[P] := Length(AUserName); Inc(P);
  for I := 1 to Length(AUserName) do
  begin
    Result[P] := Ord(AUserName[I]);
    Inc(P);
  end;
  Result[P] := Length(APassword); Inc(P);
  for I := 1 to Length(APassword) do
  begin
    Result[P] := Ord(APassword[I]);
    Inc(P);
  end;
end;

function BuildSocksConnect(const AHost: string; const APort: Word): TBytes;
var
  V4: LongWord;
  B6: array[0..15] of Byte;
  I, P: Integer;
begin
  Result := nil;
  if ParseIp4Literal(AHost, V4) then
  begin
    SetLength(Result, 4 + 4 + 2);
    Result[3] := cSocksAtypIp4;
    Result[4] := V4 shr 24;
    Result[5] := (V4 shr 16) and $FF;
    Result[6] := (V4 shr 8) and $FF;
    Result[7] := V4 and $FF;
    P := 8;
  end
  else if ParseIp6Literal(AHost, B6) then
  begin
    SetLength(Result, 4 + 16 + 2);
    Result[3] := cSocksAtypIp6;
    for I := 0 to 15 do
      Result[4 + I] := B6[I];
    P := 20;
  end
  else
  begin
    if (AHost = '') or (Length(AHost) > cSocksMaxNameLen) then
      raise EHttpConnectionError.Create(
        'host name is empty or longer than 255 octets for SOCKS5');
    SetLength(Result, 4 + 1 + Length(AHost) + 2);
    Result[3] := cSocksAtypName;
    Result[4] := Length(AHost);
    for I := 1 to Length(AHost) do
      Result[4 + I] := Ord(AHost[I]);
    P := 5 + Length(AHost);
  end;
  Result[0] := cSocksVersion;
  Result[1] := cSocksCmdConnect;
  Result[2] := 0;
  Result[P] := APort shr 8;
  Result[P + 1] := APort and $FF;
end;

function SocksReplyText(const ARep: Byte): string;
begin
  case ARep of
    1: Result := 'general SOCKS server failure';
    2: Result := 'connection not allowed by ruleset';
    3: Result := 'network unreachable';
    4: Result := 'host unreachable';
    5: Result := 'connection refused';
    6: Result := 'TTL expired';
    7: Result := 'command not supported';
    8: Result := 'address type not supported';
  else
    Result := Format('unassigned reply code %d', [ARep]);
  end;
end;

{ driver }

procedure ReadExactly(const AChannel: ISocksChannel; var ABuf: array of Byte;
  const ACount: Integer; const AWho, AWhat: string);
var
  Got, N: Integer;
begin
  Got := 0;
  while Got < ACount do
  begin
    N := AChannel.ReadSome(ABuf[Got], ACount - Got);
    if N <= 0 then
      raise EHttpConnectionError.CreateFmt(
        '%s closed the connection during %s', [AWho, AWhat]);
    Inc(Got, N);
  end;
end;

procedure EstablishSocksTunnel(const AChannel: ISocksChannel;
  const AProxy: IProxy; const AHost: string; const APort: Word);
var
  Who: string;
  HasCreds: Boolean;
  Buf: array[0..255] of Byte;
  Parser: TSocksReplyParser;
  Need, I: Integer;
  Chunk: array of Byte;
begin
  Who := Format('SOCKS5 proxy %s:%d', [AProxy.Host, AProxy.Port]);
  HasCreds := AProxy.UserName <> '';

  // 1. method selection
  AChannel.WriteAll(BuildSocksGreeting(HasCreds));
  ReadExactly(AChannel, Buf, 2, Who, 'method selection');
  if Buf[0] <> cSocksVersion then
    raise EHttpConnectionError.CreateFmt(
      '%s answered method selection with version %d', [Who, Buf[0]]);
  case Buf[1] of
    cSocksMethodNone:
      ;
    cSocksMethodUserPass:
      begin
        if not HasCreds then
          raise EHttpConnectionError.CreateFmt(
            '%s requires authentication but no credentials were given', [Who]);
        // 2. RFC 1929 sub-negotiation
        AChannel.WriteAll(BuildSocksAuthRequest(AProxy.UserName,
          AProxy.Password));
        ReadExactly(AChannel, Buf, 2, Who, 'authentication');
        if (Buf[0] <> cSocksAuthVersion) or (Buf[1] <> 0) then
          raise EHttpConnectionError.CreateFmt(
            '%s rejected the credentials', [Who]);
      end;
    cSocksMethodRefused:
      raise EHttpConnectionError.CreateFmt(
        '%s offered no acceptable authentication method', [Who]);
  else
    raise EHttpConnectionError.CreateFmt(
      '%s selected authentication method %d, which was not offered',
      [Who, Buf[1]]);
  end;

  // 3. CONNECT request
  AChannel.WriteAll(BuildSocksConnect(AHost, APort));

  // 4. reply, read exactly as long as it is
  Parser.Reset;
  while Parser.Need > 0 do
  begin
    Need := Parser.Need;
    if Need > Length(Buf) then
      Need := Length(Buf);
    ReadExactly(AChannel, Buf, Need, Who, 'CONNECT');
    SetLength(Chunk, Need);
    for I := 0 to Need - 1 do
      Chunk[I] := Buf[I];
    Parser.Feed(Chunk);
  end;
  if Parser.Failed then
    raise EHttpConnectionError.CreateFmt('%s: %s', [Who, Parser.Error]);
  if Parser.Rep <> cSocksRepSucceeded then
    raise EHttpConnectionError.CreateFmt('%s CONNECT failed: %s',
      [Who, SocksReplyText(Parser.Rep)]);
end;

end.
