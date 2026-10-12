/// SOCKS5 client tests (RFC 1928 / RFC 1929; doc/design/proxy.md "SOCKS5").
// - the layouts are asserted byte for byte; the reply parser is fed one byte
//   at a time and in one piece and must agree; the driver runs against a
//   scripted channel that records everything the client writes.
unit Http2.Socks.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$interfaces com}

interface

uses
  SysUtils, Classes, fpcunit, testregistry, Http2.Errors, Http2.Proxy,
  Http2.Socks;

type
  /// replies with a fixed byte script, at most AChunk bytes per read
  TScriptChannel = class(TInterfacedObject, ISocksChannel)
  private
    FIn: TBytes;
    FInPos: Integer;
    FChunk: Integer;
  public
    Written: TBytes;
    constructor Create(const AReply: TBytes; const AChunk: Integer = 1000);
    procedure WriteAll(const AData: TBytes);
    function ReadSome(var ABuffer; const ACount: Integer): Integer;
    function Unread: Integer;
  end;

  TSocksBytesTest = class(TTestCase)
  private
    procedure AssertBytes(const AMsg: string; const AExpected: array of Byte;
      const AActual: TBytes);
  published
    procedure TestGreetingWithoutCredentials;
    procedure TestGreetingWithCredentials;
    procedure TestAuthRequestLayout;
    procedure TestAuthRequestRejectsBadLengths;
    procedure TestConnectIpv4;
    procedure TestConnectIpv6;
    procedure TestConnectNameSendsTheNameUnresolved;
    procedure TestConnectName255Ok256Rejected;
    procedure TestConnectPortIsBigEndian;
    procedure TestReplyTextForEveryCode;
  end;

  TSocksReplyParserTest = class(TTestCase)
  private
    procedure FeedAllAtOnce(var P: TSocksReplyParser; const AData: array of Byte);
    procedure FeedOneByOne(var P: TSocksReplyParser; const AData: array of Byte);
  published
    procedure TestIpv4ReplyOneByteAtATimeAgreesWithWhole;
    procedure TestIpv6Reply;
    procedure TestNameReply;
    procedure TestNeedNeverExceedsTheReply;
    procedure TestBadVersionFails;
    procedure TestBadAtypFails;
    procedure TestErrorRepIsReportedAfterTheFullReply;
  end;

  TSocksDriverTest = class(TTestCase)
  private
    function Reply(const AParts: array of Byte): TBytes;
    procedure ExpectConnectionError(const AChannel: ISocksChannel;
      const AProxy: IProxy; const AMustContain: string);
  published
    procedure TestNoAuthHappyPath;
    procedure TestUserPassHappyPath;
    procedure TestDripFedRepliesWork;
    procedure TestNoBytesBeyondTheReplyAreConsumed;
    procedure TestNoAcceptableMethod;
    procedure TestServerSelectsUnofferedMethod;
    procedure TestServerDemandsAuthWithoutCredentials;
    procedure TestAuthRejected;
    procedure TestWrongVersionInMethodReply;
    procedure TestEveryFailureReplyCode;
    procedure TestTruncatedReplyIsAConnectionError;
    procedure TestErrorsNameTheProxyAndNeverThePassword;
  end;

implementation

{ TScriptChannel }

constructor TScriptChannel.Create(const AReply: TBytes; const AChunk: Integer);
begin
  inherited Create;
  FIn := AReply;
  FChunk := AChunk;
end;

procedure TScriptChannel.WriteAll(const AData: TBytes);
var
  N: Integer;
begin
  N := Length(Written);
  SetLength(Written, N + Length(AData));
  if Length(AData) > 0 then
    Move(AData[0], Written[N], Length(AData));
end;

function TScriptChannel.ReadSome(var ABuffer; const ACount: Integer): Integer;
var
  N: Integer;
begin
  N := Length(FIn) - FInPos;
  if N > ACount then N := ACount;
  if N > FChunk then N := FChunk;
  if N <= 0 then
    Exit(0);
  Move(FIn[FInPos], ABuffer, N);
  Inc(FInPos, N);
  Result := N;
end;

function TScriptChannel.Unread: Integer;
begin
  Result := Length(FIn) - FInPos;
end;

{ TSocksBytesTest }

procedure TSocksBytesTest.AssertBytes(const AMsg: string;
  const AExpected: array of Byte; const AActual: TBytes);
var
  I: Integer;
begin
  AssertEquals(AMsg + ': length', Length(AExpected), Length(AActual));
  for I := 0 to High(AExpected) do
    AssertEquals(AMsg + ': byte ' + IntToStr(I), AExpected[I], AActual[I]);
end;

procedure TSocksBytesTest.TestGreetingWithoutCredentials;
begin
  AssertBytes('greeting', [$05, $01, $00], BuildSocksGreeting(False));
end;

procedure TSocksBytesTest.TestGreetingWithCredentials;
begin
  AssertBytes('greeting', [$05, $02, $00, $02], BuildSocksGreeting(True));
end;

procedure TSocksBytesTest.TestAuthRequestLayout;
begin
  AssertBytes('auth', [$01, 3, Ord('b'), Ord('o'), Ord('b'), 2, Ord('p'), Ord('w')],
    BuildSocksAuthRequest('bob', 'pw'));
  AssertBytes('empty password', [$01, 1, Ord('u'), 0],
    BuildSocksAuthRequest('u', ''));
end;

procedure TSocksBytesTest.TestAuthRequestRejectsBadLengths;
var
  Raised: Boolean;
begin
  Raised := False;
  try
    BuildSocksAuthRequest('', 'pw');
  except
    on EHttpProxyConfigError do Raised := True;
  end;
  AssertTrue('empty user', Raised);
  Raised := False;
  try
    BuildSocksAuthRequest(StringOfChar('a', 256), 'pw');
  except
    on EHttpProxyConfigError do Raised := True;
  end;
  AssertTrue('256-octet user', Raised);
  AssertEquals(3 + 255 + 255,
    Length(BuildSocksAuthRequest(StringOfChar('a', 255), StringOfChar('b', 255))));
end;

procedure TSocksBytesTest.TestConnectIpv4;
begin
  AssertBytes('connect ip4', [$05, $01, $00, $01, 10, 0, 0, 7, $01, $BB],
    BuildSocksConnect('10.0.0.7', 443));
end;

procedure TSocksBytesTest.TestConnectIpv6;
begin
  AssertBytes('connect ip6',
    [$05, $01, $00, $04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, $1F, $90],
    BuildSocksConnect('::1', 8080));
end;

procedure TSocksBytesTest.TestConnectNameSendsTheNameUnresolved;
begin
  AssertBytes('connect name',
    [$05, $01, $00, $03, 11, Ord('e'), Ord('x'), Ord('a'), Ord('m'), Ord('p'),
     Ord('l'), Ord('e'), Ord('.'), Ord('c'), Ord('o'), Ord('m'), $00, $50],
    BuildSocksConnect('example.com', 80));
end;

procedure TSocksBytesTest.TestConnectName255Ok256Rejected;
var
  B: TBytes;
  Raised: Boolean;
begin
  B := BuildSocksConnect(StringOfChar('a', 255), 1);
  AssertEquals(4 + 1 + 255 + 2, Length(B));
  AssertEquals(255, B[4]);
  Raised := False;
  try
    BuildSocksConnect(StringOfChar('a', 256), 1);
  except
    on EHttpConnectionError do Raised := True;
  end;
  AssertTrue(Raised);
end;

procedure TSocksBytesTest.TestConnectPortIsBigEndian;
var
  B: TBytes;
begin
  B := BuildSocksConnect('10.0.0.1', $1234);
  AssertEquals($12, B[8]);
  AssertEquals($34, B[9]);
end;

procedure TSocksBytesTest.TestReplyTextForEveryCode;
var
  I: Integer;
begin
  AssertEquals('general SOCKS server failure', SocksReplyText(1));
  AssertEquals('connection not allowed by ruleset', SocksReplyText(2));
  AssertEquals('network unreachable', SocksReplyText(3));
  AssertEquals('host unreachable', SocksReplyText(4));
  AssertEquals('connection refused', SocksReplyText(5));
  AssertEquals('TTL expired', SocksReplyText(6));
  AssertEquals('command not supported', SocksReplyText(7));
  AssertEquals('address type not supported', SocksReplyText(8));
  AssertEquals('unassigned reply code 9', SocksReplyText(9));
  AssertEquals('unassigned reply code 255', SocksReplyText(255));
  for I := 1 to 255 do
    AssertTrue('non-empty ' + IntToStr(I), SocksReplyText(I) <> '');
end;

{ TSocksReplyParserTest }

procedure TSocksReplyParserTest.FeedAllAtOnce(var P: TSocksReplyParser;
  const AData: array of Byte);
begin
  P.Reset;
  P.Feed(AData);
end;

procedure TSocksReplyParserTest.FeedOneByOne(var P: TSocksReplyParser;
  const AData: array of Byte);
var
  I: Integer;
begin
  P.Reset;
  for I := 0 to High(AData) do
    P.Feed([AData[I]]);
end;

procedure TSocksReplyParserTest.TestIpv4ReplyOneByteAtATimeAgreesWithWhole;
const
  R: array[0..9] of Byte = (5, 0, 0, 1, 127, 0, 0, 1, $04, $38);
var
  A, B: TSocksReplyParser;
  I: Integer;
begin
  FeedAllAtOnce(A, R);
  FeedOneByOne(B, R);
  AssertTrue(A.Complete);
  AssertTrue(B.Complete);
  AssertEquals(A.Rep, B.Rep);
  AssertEquals(Length(A.Bound), Length(B.Bound));
  AssertEquals(6, Length(B.Bound));
  for I := 0 to High(A.Bound) do
    AssertEquals(A.Bound[I], B.Bound[I]);
end;

procedure TSocksReplyParserTest.TestIpv6Reply;
var
  P: TSocksReplyParser;
  R: array[0..21] of Byte;
begin
  FillChar(R, SizeOf(R), 0);
  R[0] := 5; R[3] := 4; R[19] := 1; R[20] := $1F; R[21] := $90;
  FeedOneByOne(P, R);
  AssertTrue(P.Complete);
  AssertEquals(18, Length(P.Bound));
  AssertEquals($90, P.Bound[17]);
end;

procedure TSocksReplyParserTest.TestNameReply;
var
  P: TSocksReplyParser;
begin
  FeedOneByOne(P, [5, 0, 0, 3, 3, Ord('a'), Ord('b'), Ord('c'), $00, $50]);
  AssertTrue(P.Complete);
  AssertEquals(5, Length(P.Bound));
  AssertEquals(Ord('a'), P.Bound[0]);
  AssertEquals($50, P.Bound[4]);
  // an empty name still carries the port
  FeedOneByOne(P, [5, 0, 0, 3, 0, $00, $50]);
  AssertTrue(P.Complete);
  AssertEquals(2, Length(P.Bound));
end;

procedure TSocksReplyParserTest.TestNeedNeverExceedsTheReply;
var
  P: TSocksReplyParser;
begin
  // header first, then address and port
  P.Reset;
  AssertEquals(4, P.Need);
  P.Feed([5, 0, 0, 1]);
  AssertEquals(6, P.Need);
  P.Feed([1, 2, 3, 4, 0, 80]);
  AssertEquals(0, P.Need);
  AssertTrue(P.Complete);
  P.Reset;
  P.Feed([5, 0, 0, 3]);
  AssertEquals(1, P.Need);
  P.Feed([4]);
  AssertEquals(6, P.Need);
end;

procedure TSocksReplyParserTest.TestBadVersionFails;
var
  P: TSocksReplyParser;
begin
  FeedAllAtOnce(P, [4, 0, 0, 1]);
  AssertTrue(P.Failed);
  AssertFalse(P.Complete);
  AssertEquals(0, P.Need);
  AssertTrue(Pos('version', P.Error) > 0);
end;

procedure TSocksReplyParserTest.TestBadAtypFails;
var
  P: TSocksReplyParser;
begin
  FeedAllAtOnce(P, [5, 0, 0, 9]);
  AssertTrue(P.Failed);
  AssertTrue(Pos('address type', P.Error) > 0);
end;

procedure TSocksReplyParserTest.TestErrorRepIsReportedAfterTheFullReply;
var
  P: TSocksReplyParser;
begin
  FeedOneByOne(P, [5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
  AssertTrue(P.Complete);
  AssertEquals(5, P.Rep);
end;

{ TSocksDriverTest }

function TSocksDriverTest.Reply(const AParts: array of Byte): TBytes;
var
  I: Integer;
begin
  SetLength(Result, Length(AParts));
  for I := 0 to High(AParts) do
    Result[I] := AParts[I];
end;

procedure TSocksDriverTest.ExpectConnectionError(const AChannel: ISocksChannel;
  const AProxy: IProxy; const AMustContain: string);
var
  Msg: string;
begin
  Msg := '';
  try
    EstablishSocksTunnel(AChannel, AProxy, 'example.com', 443);
  except
    on E: EHttpConnectionError do
      Msg := E.Message;
  end;
  AssertTrue('raised EHttpConnectionError', Msg <> '');
  AssertTrue('message "' + Msg + '" contains "' + AMustContain + '"',
    Pos(AMustContain, Msg) > 0);
end;

procedure TSocksDriverTest.TestNoAuthHappyPath;
var
  Ch: TScriptChannel;
  Ref: ISocksChannel;
  P: IProxy;
begin
  Ch := TScriptChannel.Create(Reply([5, 0, 5, 0, 0, 1, 1, 2, 3, 4, 0, 80]));
  Ref := Ch;
  P := TProxy.Create(pkSocks5, 'proxy.corp', 1080);
  EstablishSocksTunnel(Ref, P, 'example.com', 443);
  // greeting then CONNECT, nothing else
  AssertEquals(3 + (4 + 1 + 11 + 2), Length(Ch.Written));
  AssertEquals(5, Ch.Written[0]);
  AssertEquals(1, Ch.Written[1]);
  AssertEquals(0, Ch.Written[2]);
  AssertEquals(3, Ch.Written[6]);       // ATYP name
  AssertEquals(0, Ch.Unread);
end;

procedure TSocksDriverTest.TestUserPassHappyPath;
var
  Ch: TScriptChannel;
  Ref: ISocksChannel;
  P: IProxy;
begin
  Ch := TScriptChannel.Create(
    Reply([5, 2, 1, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]));
  Ref := Ch;
  P := TProxy.Create(pkSocks5, 'proxy.corp', 1080, 'bob', 'pw');
  EstablishSocksTunnel(Ref, P, 'example.com', 443);
  AssertEquals(5, Ch.Written[0]);
  AssertEquals(2, Ch.Written[1]);       // two methods offered
  AssertEquals(1, Ch.Written[4]);       // RFC 1929 sub-negotiation version
  AssertEquals(3, Ch.Written[5]);       // ULEN
  AssertEquals(Ord('b'), Ch.Written[6]);
  AssertEquals(0, Ch.Unread);
end;

procedure TSocksDriverTest.TestDripFedRepliesWork;
var
  Ch: TScriptChannel;
  Ref: ISocksChannel;
begin
  Ch := TScriptChannel.Create(
    Reply([5, 0, 5, 0, 0, 3, 3, 97, 98, 99, 0, 80]), 1);
  Ref := Ch;
  EstablishSocksTunnel(Ref, TProxy.Create(pkSocks5, 'p', 1), 'h', 1);
  AssertEquals(0, Ch.Unread);
end;

procedure TSocksDriverTest.TestNoBytesBeyondTheReplyAreConsumed;
var
  Ch: TScriptChannel;
  Ref: ISocksChannel;
begin
  // 'ORIGIN' stands for the first bytes of the tunnelled stream
  Ch := TScriptChannel.Create(
    Reply([5, 0, 5, 0, 0, 1, 1, 2, 3, 4, 0, 80, 79, 82, 73, 71, 73, 78]));
  Ref := Ch;
  EstablishSocksTunnel(Ref, TProxy.Create(pkSocks5, 'p', 1), 'h', 1);
  AssertEquals('origin bytes left untouched', 6, Ch.Unread);
end;

procedure TSocksDriverTest.TestNoAcceptableMethod;
begin
  ExpectConnectionError(TScriptChannel.Create(Reply([5, $FF])),
    TProxy.Create(pkSocks5, 'proxy.corp', 1080), 'no acceptable authentication');
end;

procedure TSocksDriverTest.TestServerSelectsUnofferedMethod;
begin
  ExpectConnectionError(TScriptChannel.Create(Reply([5, 1])),
    TProxy.Create(pkSocks5, 'proxy.corp', 1080), 'not offered');
end;

procedure TSocksDriverTest.TestServerDemandsAuthWithoutCredentials;
begin
  ExpectConnectionError(TScriptChannel.Create(Reply([5, 2])),
    TProxy.Create(pkSocks5, 'proxy.corp', 1080), 'no credentials');
end;

procedure TSocksDriverTest.TestAuthRejected;
begin
  ExpectConnectionError(TScriptChannel.Create(Reply([5, 2, 1, 1])),
    TProxy.Create(pkSocks5, 'proxy.corp', 1080, 'bob', 'pw'),
    'rejected the credentials');
end;

procedure TSocksDriverTest.TestWrongVersionInMethodReply;
begin
  ExpectConnectionError(TScriptChannel.Create(Reply([4, 0])),
    TProxy.Create(pkSocks5, 'proxy.corp', 1080), 'version 4');
end;

procedure TSocksDriverTest.TestEveryFailureReplyCode;
var
  Rep: Integer;
  Ch: TScriptChannel;
begin
  for Rep := 1 to 255 do
  begin
    Ch := TScriptChannel.Create(
      Reply([5, 0, 5, Rep, 0, 1, 0, 0, 0, 0, 0, 0]));
    ExpectConnectionError(Ch, TProxy.Create(pkSocks5, 'p', 1),
      SocksReplyText(Rep));
  end;
end;

procedure TSocksDriverTest.TestTruncatedReplyIsAConnectionError;
begin
  ExpectConnectionError(TScriptChannel.Create(Reply([5, 0, 5, 0, 0, 1, 1, 2])),
    TProxy.Create(pkSocks5, 'p', 1), 'closed the connection');
  ExpectConnectionError(TScriptChannel.Create(Reply([])),
    TProxy.Create(pkSocks5, 'p', 1), 'closed the connection');
end;

procedure TSocksDriverTest.TestErrorsNameTheProxyAndNeverThePassword;
var
  Msg: string;
begin
  Msg := '';
  try
    EstablishSocksTunnel(TScriptChannel.Create(Reply([5, 2, 1, 1])),
      TProxy.Create(pkSocks5, 'proxy.corp', 1080, 'bob', 'TOPSECRET'),
      'example.com', 443);
  except
    on E: EHttpConnectionError do
      Msg := E.Message;
  end;
  AssertTrue('raised', Msg <> '');
  AssertTrue('names proxy', Pos('proxy.corp:1080', Msg) > 0);
  AssertEquals('no password', 0, Pos('TOPSECRET', Msg));
  AssertEquals('no user name', 0, Pos('bob', Msg));
end;

initialization
  RegisterTest(TSocksBytesTest);
  RegisterTest(TSocksReplyParserTest);
  RegisterTest(TSocksDriverTest);
end.
