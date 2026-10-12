/// WebSocket codec, assembly, handshake and request-value tests
/// (RFC 6455; doc/design/websocket.md).
// - frames are asserted against the RFC 6455 section 5.7 examples; the parser
//   is fed one byte at a time, in random chunks and whole and must agree.
unit Http2.WebSocket.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$interfaces com}

interface

uses
  SysUtils, Classes, fpcunit, testregistry, Http2.Errors, Http2.WebSocket;

type
  TWsFrameTest = class(TTestCase)
  private
    function Bytes(const A: array of Byte): TBytes;
    procedure AssertBytes(const AMsg: string; const AExpected: array of Byte;
      const AActual: TBytes);
    function ParseCode(const A: array of Byte; const AClient: Boolean = False): Integer;
  published
    procedure TestRfcMaskedHello;
    procedure TestRfcUnmaskedHello;
    procedure TestRfcPingAndFragments;
    procedure TestLengthForms;
    procedure TestMaskPhaseAcrossChunks;
    procedure TestChunkSplitInvariance;
    procedure TestServerFrameMaskedIs1002;
    procedure TestClientFrameUnmaskedIs1002OnServerSide;
    procedure TestReservedBitsAre1002;
    procedure TestReservedOpcodesAre1002;
    procedure TestFragmentedControlIs1002;
    procedure TestLongControlIs1002;
    procedure TestNonMinimalLengthIs1002;
    procedure TestLength64TopBitIs1002;
    procedure TestOversizeFrameIs1009;
    procedure TestPartialHeaderWaits;
  end;

  TWsMessageTest = class(TTestCase)
  private
    function Frame(const AOp: Byte; const AFin: Boolean; const A: array of Byte): TWsFrame;
    function AcceptCode(const AAsm: TWebSocketMessageAssembler; const AF: TWsFrame): Integer;
  published
    procedure TestUtf8Table;
    procedure TestUtf8UnfinishedTailIsReported;
    procedure TestCloseCodeTable;
    procedure TestClosePayload;
    procedure TestClosePayloadOneOctetIs1002;
    procedure TestClosePayloadBadReasonIs1007;
    procedure TestFragmentedBinary;
    procedure TestContinuationWithoutStartIs1002;
    procedure TestDataInsideOpenMessageIs1002;
    procedure TestTextSplitInsideCharacterIsHeldBack;
    procedure TestTextBadPrefixFailsEarly;
    procedure TestTextEndingInsideCharacterIs1007;
    procedure TestMessageLimitIs1009;
  end;

  TWsHandshakeTest = class(TTestCase)
  private
    function Fields(const A: array of string): TArray<TWsHeaderField>;
    function Ok(const AStatus: Integer; const AExtra: array of string;
      const AOffered: TArray<string>; out AChosen: string): string;
  published
    procedure TestRfcAcceptVector;
    procedure TestKeyIs16OctetsBase64;
    procedure TestUrlForms;
    procedure TestUrlErrors;
    procedure TestRequestBytes;
    procedure TestRequestBytesIpv6AndSubprotocols;
    procedure TestAcceptMatrix;
    procedure TestSubprotocolMatrix;
    procedure TestRestrictedHeadersRejectedAtWithHeader;
  end;

  TWsRequestTest = class(TTestCase)
  published
    procedure TestWithXReturnsNewValues;
    procedure TestRequiresListener;
    procedure TestArgumentChecks;
    procedure TestUnitDependsOnRtlOnly;
  end;

implementation

function FixedKey: TWsMaskKey;
begin
  Result[0] := $37; Result[1] := $fa; Result[2] := $21; Result[3] := $3d;
end;

{ TWsFrameTest }

function TWsFrameTest.Bytes(const A: array of Byte): TBytes;
begin
  SetLength(Result, Length(A));
  if Length(A) > 0 then
    Move(A[0], Result[0], Length(A));
end;

procedure TWsFrameTest.AssertBytes(const AMsg: string;
  const AExpected: array of Byte; const AActual: TBytes);
var
  I: Integer;
begin
  AssertEquals(AMsg + ' length', Length(AExpected), Length(AActual));
  for I := 0 to High(AExpected) do
    AssertEquals(AMsg + ' byte ' + IntToStr(I), AExpected[I], AActual[I]);
end;

function TWsFrameTest.ParseCode(const A: array of Byte;
  const AClient: Boolean): Integer;
var
  P: TWebSocketFrameParser;
  F: TWsFrame;
begin
  Result := 0;
  P := TWebSocketFrameParser.Create;
  try
    P.RequireMasked := AClient;
    P.MaxFrameBytes := 1000000;
    P.Feed(A[0], Length(A));
    try
      P.Next(F);
    except
      on E: EHttpWebSocketProtocolError do
        Result := E.CloseCode;
    end;
  finally
    P.Free;
  end;
end;

procedure TWsFrameTest.TestRfcMaskedHello;
var
  Hello: TBytes;
begin
  Hello := Bytes([$48, $65, $6c, $6c, $6f]);
  AssertBytes('masked Hello', [$81, $85, $37, $fa, $21, $3d, $7f, $9f, $4d,
    $51, $58], WsEncodeFrame(cWsOpText, True, Hello, True, FixedKey));
end;

procedure TWsFrameTest.TestRfcUnmaskedHello;
var
  P: TWebSocketFrameParser;
  F: TWsFrame;
  Wire: TBytes;
begin
  Wire := Bytes([$81, $05, $48, $65, $6c, $6c, $6f]);
  AssertBytes('unmasked Hello', [$81, $05, $48, $65, $6c, $6c, $6f],
    WsEncodeFrame(cWsOpText, True, Bytes([$48, $65, $6c, $6c, $6f]), False,
      FixedKey));
  P := TWebSocketFrameParser.Create;
  try
    P.Feed(Wire[0], Length(Wire));
    AssertTrue('frame', P.Next(F));
    AssertTrue('fin', F.Fin);
    AssertEquals('op', cWsOpText, F.Opcode);
    AssertBytes('payload', [$48, $65, $6c, $6c, $6f], F.Payload);
  finally
    P.Free;
  end;
  // a masked client frame parses on the server side
  P := TWebSocketFrameParser.Create;
  try
    P.RequireMasked := True;
    Wire := Bytes([$81, $85, $37, $fa, $21, $3d, $7f, $9f, $4d, $51, $58]);
    P.Feed(Wire[0], Length(Wire));
    AssertTrue('frame', P.Next(F));
    AssertBytes('unmasked payload', [$48, $65, $6c, $6c, $6f], F.Payload);
  finally
    P.Free;
  end;
end;

procedure TWsFrameTest.TestRfcPingAndFragments;
begin
  AssertBytes('ping', [$89, $05, $48, $65, $6c, $6c, $6f],
    WsEncodeFrame(cWsOpPing, True, Bytes([$48, $65, $6c, $6c, $6f]), False,
      FixedKey));
  AssertBytes('first fragment', [$01, $03, $48, $65, $6c],
    WsEncodeFrame(cWsOpText, False, Bytes([$48, $65, $6c]), False, FixedKey));
  AssertBytes('last fragment', [$80, $02, $6c, $6f],
    WsEncodeFrame(cWsOpContinuation, True, Bytes([$6c, $6f]), False, FixedKey));
end;

procedure TWsFrameTest.TestLengthForms;
var
  Sizes: array[0..6] of Integer;
  I: Integer;
  Pl, Wire: TBytes;
  P: TWebSocketFrameParser;
  F: TWsFrame;
begin
  Sizes[0] := 0; Sizes[1] := 125; Sizes[2] := 126; Sizes[3] := 127;
  Sizes[4] := 65535; Sizes[5] := 65536; Sizes[6] := 100000;
  for I := 0 to High(Sizes) do
  begin
    SetLength(Pl, Sizes[I]);
    if Sizes[I] > 0 then
      FillChar(Pl[0], Sizes[I], $5A);
    Wire := WsEncodeFrame(cWsOpBinary, True, Pl, True, FixedKey);
    P := TWebSocketFrameParser.Create;
    try
      P.RequireMasked := True;
      P.Feed(Wire[0], Length(Wire));
      AssertTrue('frame ' + IntToStr(Sizes[I]), P.Next(F));
      AssertEquals('len ' + IntToStr(Sizes[I]), Sizes[I], Length(F.Payload));
      if Sizes[I] > 0 then
        AssertEquals('content', $5A, F.Payload[Sizes[I] - 1]);
    finally
      P.Free;
    end;
  end;
  SetLength(Pl, 256);
  Wire := WsEncodeFrame(cWsOpBinary, True, Pl, False, FixedKey);
  AssertEquals('256 header 0', $82, Wire[0]);
  AssertEquals('256 header 1', $7E, Wire[1]);
  AssertEquals('256 header 2', $01, Wire[2]);
  AssertEquals('256 header 3', $00, Wire[3]);
  SetLength(Pl, 65536);
  Wire := WsEncodeFrame(cWsOpBinary, True, Pl, False, FixedKey);
  AssertEquals('64k header 1', $7F, Wire[1]);
  AssertEquals('64k header 7', $01, Wire[7]);
  AssertEquals('64k header 8', $00, Wire[8]);
end;

procedure TWsFrameTest.TestMaskPhaseAcrossChunks;
var
  A, B: TBytes;
  I: Integer;
begin
  SetLength(A, 23);
  SetLength(B, 23);
  for I := 0 to 22 do
  begin
    A[I] := I * 7;
    B[I] := I * 7;
  end;
  WsApplyMask(FixedKey, A[0], 23, 0);
  WsApplyMask(FixedKey, B[0], 5, 0);
  WsApplyMask(FixedKey, B[5], 18, 5);
  for I := 0 to 22 do
    AssertEquals('byte ' + IntToStr(I), A[I], B[I]);
  // masking twice restores the data
  WsApplyMask(FixedKey, A[0], 23, 0);
  for I := 0 to 22 do
    AssertEquals('restored ' + IntToStr(I), Byte(I * 7), A[I]);
end;

procedure TWsFrameTest.TestChunkSplitInvariance;
var
  Wire, Pl: TBytes;
  Sizes: array[0..5] of Integer;
  I, J, N, Pos, Count: Integer;
  P: TWebSocketFrameParser;
  F: TWsFrame;
  Seen: array of Integer;
  Mode: Integer;
begin
  Sizes[0] := 0; Sizes[1] := 3; Sizes[2] := 125; Sizes[3] := 126;
  Sizes[4] := 300; Sizes[5] := 70000;
  SetLength(Wire, 0);
  for I := 0 to High(Sizes) do
  begin
    SetLength(Pl, Sizes[I]);
    for J := 0 to Sizes[I] - 1 do
      Pl[J] := Byte(J + I);
    Pl := WsEncodeFrame(cWsOpBinary, True, Pl, False, FixedKey);
    N := Length(Wire);
    SetLength(Wire, N + Length(Pl));
    Move(Pl[0], Wire[N], Length(Pl));
  end;
  RandSeed := 1234;
  for Mode := 0 to 2 do
  begin
    P := TWebSocketFrameParser.Create;
    try
      SetLength(Seen, 0);
      Pos := 0;
      while Pos < Length(Wire) do
      begin
        case Mode of
          0: Count := 1;
          1: Count := 1 + Random(97);
        else
          Count := Length(Wire);
        end;
        if Pos + Count > Length(Wire) then
          Count := Length(Wire) - Pos;
        P.Feed(Wire[Pos], Count);
        Inc(Pos, Count);
        while P.Next(F) do
        begin
          SetLength(Seen, Length(Seen) + 1);
          Seen[High(Seen)] := Length(F.Payload);
          if Length(F.Payload) > 0 then
            AssertEquals('content', Byte(Length(F.Payload) - 1 + High(Seen)),
              F.Payload[Length(F.Payload) - 1]);
        end;
      end;
      AssertEquals('count mode ' + IntToStr(Mode), 6, Length(Seen));
      for I := 0 to High(Sizes) do
        AssertEquals('size', Sizes[I], Seen[I]);
    finally
      P.Free;
    end;
  end;
end;

procedure TWsFrameTest.TestServerFrameMaskedIs1002;
begin
  AssertEquals(1002, ParseCode([$81, $81, 1, 2, 3, 4, 5]));
end;

procedure TWsFrameTest.TestClientFrameUnmaskedIs1002OnServerSide;
begin
  AssertEquals(1002, ParseCode([$81, $01, $41], True));
end;

procedure TWsFrameTest.TestReservedBitsAre1002;
begin
  AssertEquals('rsv1', 1002, ParseCode([$C1, $00]));
  AssertEquals('rsv2', 1002, ParseCode([$A1, $00]));
  AssertEquals('rsv3', 1002, ParseCode([$91, $00]));
end;

procedure TWsFrameTest.TestReservedOpcodesAre1002;
var
  Op: Integer;
begin
  for Op := 3 to 7 do
    AssertEquals('data op ' + IntToStr(Op), 1002, ParseCode([$80 or Op, $00]));
  for Op := $B to $F do
    AssertEquals('control op ' + IntToStr(Op), 1002, ParseCode([$80 or Op, $00]));
end;

procedure TWsFrameTest.TestFragmentedControlIs1002;
begin
  AssertEquals(1002, ParseCode([$09, $00]));
  AssertEquals(1002, ParseCode([$08, $00]));
end;

procedure TWsFrameTest.TestLongControlIs1002;
begin
  AssertEquals(1002, ParseCode([$89, 126, 0, 126]));
end;

procedure TWsFrameTest.TestNonMinimalLengthIs1002;
begin
  AssertEquals('126 form for 5', 1002, ParseCode([$82, 126, 0, 5]));
  AssertEquals('127 form for 5', 1002,
    ParseCode([$82, 127, 0, 0, 0, 0, 0, 0, 0, 5]));
  AssertEquals('127 form for 65535', 1002,
    ParseCode([$82, 127, 0, 0, 0, 0, 0, 0, $FF, $FF]));
end;

procedure TWsFrameTest.TestLength64TopBitIs1002;
begin
  AssertEquals(1002, ParseCode([$82, 127, $80, 0, 0, 0, 0, 0, 0, 0]));
end;

procedure TWsFrameTest.TestOversizeFrameIs1009;
begin
  AssertEquals(1009, ParseCode([$82, 127, 0, 0, 0, 0, 0, $20, 0, 0]));
end;

procedure TWsFrameTest.TestPartialHeaderWaits;
var
  P: TWebSocketFrameParser;
  F: TWsFrame;
  B: Byte;
begin
  P := TWebSocketFrameParser.Create;
  try
    B := $81;
    P.Feed(B, 1);
    AssertFalse('one byte', P.Next(F));
    B := 126;
    P.Feed(B, 1);
    AssertFalse('length incomplete', P.Next(F));
  finally
    P.Free;
  end;
end;

{ TWsMessageTest }

function TWsMessageTest.Frame(const AOp: Byte; const AFin: Boolean;
  const A: array of Byte): TWsFrame;
begin
  Result.Fin := AFin;
  Result.Opcode := AOp;
  SetLength(Result.Payload, Length(A));
  if Length(A) > 0 then
    Move(A[0], Result.Payload[0], Length(A));
end;

function TWsMessageTest.AcceptCode(const AAsm: TWebSocketMessageAssembler;
  const AF: TWsFrame): Integer;
var
  K: TWsDataKind;
  D: TBytes;
  L: Boolean;
begin
  Result := 0;
  try
    AAsm.Accept(AF, K, D, L);
  except
    on E: EHttpWebSocketProtocolError do
      Result := E.CloseCode;
  end;
end;

procedure TWsMessageTest.TestUtf8Table;
  procedure Check(const AName: string; const A: array of Byte;
    const AValid: Boolean);
  var
    Safe: Integer;
    R: Boolean;
  begin
    R := WsUtf8Check(@A[0], Length(A), Safe) and (Safe = Length(A));
    AssertEquals(AName, AValid, R);
  end;
begin
  Check('ascii', [$41, $7F], True);
  Check('2 octets', [$C2, $80], True);
  Check('C3 A9', [$C3, $A9], True);
  Check('overlong C0 80', [$C0, $80], False);
  Check('overlong C1 BF', [$C1, $BF], False);
  Check('3 octets U+0800', [$E0, $A0, $80], True);
  Check('overlong E0 9F BF', [$E0, $9F, $BF], False);
  Check('U+D7FF', [$ED, $9F, $BF], True);
  Check('surrogate ED A0 80', [$ED, $A0, $80], False);
  Check('surrogate ED BF BF', [$ED, $BF, $BF], False);
  Check('U+E000', [$EE, $80, $80], True);
  Check('U+FFFF', [$EF, $BF, $BF], True);
  Check('4 octets U+10000', [$F0, $90, $80, $80], True);
  Check('overlong F0 8F BF BF', [$F0, $8F, $BF, $BF], False);
  Check('U+10FFFF', [$F4, $8F, $BF, $BF], True);
  Check('above 10FFFF F4 90', [$F4, $90, $80, $80], False);
  Check('F5', [$F5, $80, $80, $80], False);
  Check('FF', [$FF], False);
  Check('lone continuation', [$80], False);
  Check('bad continuation', [$C3, $41], False);
end;

procedure TWsMessageTest.TestUtf8UnfinishedTailIsReported;
var
  A: array[0..3] of Byte;
  Safe: Integer;
begin
  A[0] := $41; A[1] := $E2; A[2] := $82;
  AssertTrue('valid so far', WsUtf8Check(@A[0], 3, Safe));
  AssertEquals('safe prefix', 1, Safe);
  A[3] := $41;
  A[0] := $E2; A[1] := $41;
  AssertFalse('bad second byte', WsUtf8Check(@A[0], 2, Safe));
end;

procedure TWsMessageTest.TestCloseCodeTable;
const
  Valid: array[0..12] of Integer = (1000, 1001, 1002, 1003, 1007, 1008, 1009,
    1010, 1011, 3000, 3999, 4000, 4999);
  Invalid: array[0..13] of Integer = (0, 999, 1004, 1005, 1006, 1012, 1013,
    1014, 1015, 1016, 1100, 2000, 2999, 5000);
var
  I: Integer;
begin
  for I := 0 to High(Valid) do
    AssertTrue('valid ' + IntToStr(Valid[I]), WsIsWireCloseCode(Valid[I]));
  for I := 0 to High(Invalid) do
    AssertFalse('invalid ' + IntToStr(Invalid[I]), WsIsWireCloseCode(Invalid[I]));
end;

procedure TWsMessageTest.TestClosePayload;
var
  Code: Integer;
  Reason: string;
  P: TBytes;
begin
  SetLength(P, 0);
  WsParseClosePayload(P, Code, Reason);
  AssertEquals(1005, Code);
  P := WsBuildClosePayload(1000, 'bye');
  WsParseClosePayload(P, Code, Reason);
  AssertEquals(1000, Code);
  AssertEquals('bye', Reason);
  AssertEquals(5, Length(P));
  AssertEquals($03, P[0]);
  AssertEquals($E8, P[1]);
end;

procedure TWsMessageTest.TestClosePayloadOneOctetIs1002;
var
  P: TBytes;
  Code: Integer;
  Reason: string;
  Got: Integer;
begin
  SetLength(P, 1);
  Got := 0;
  try
    WsParseClosePayload(P, Code, Reason);
  except
    on E: EHttpWebSocketProtocolError do
      Got := E.CloseCode;
  end;
  AssertEquals(1002, Got);
  P := WsBuildClosePayload(1004, '');
  try
    WsParseClosePayload(P, Code, Reason);
  except
    on E: EHttpWebSocketProtocolError do
      Got := E.CloseCode;
  end;
  AssertEquals('bad code', 1002, Got);
end;

procedure TWsMessageTest.TestClosePayloadBadReasonIs1007;
var
  P: TBytes;
  Code, Got: Integer;
  Reason: string;
begin
  P := WsBuildClosePayload(1000, 'ab');
  P[2] := $FF;
  Got := 0;
  try
    WsParseClosePayload(P, Code, Reason);
  except
    on E: EHttpWebSocketProtocolError do
      Got := E.CloseCode;
  end;
  AssertEquals(1007, Got);
end;

procedure TWsMessageTest.TestFragmentedBinary;
var
  A: TWebSocketMessageAssembler;
  K: TWsDataKind;
  D: TBytes;
  L: Boolean;
begin
  A := TWebSocketMessageAssembler.Create(0);
  try
    AssertTrue(A.Accept(Frame(cWsOpBinary, False, [1, 2]), K, D, L));
    AssertTrue(K = wkBinary);
    AssertFalse(L);
    AssertTrue(A.Accept(Frame(cWsOpContinuation, True, [3]), K, D, L));
    AssertTrue(L);
    AssertEquals(1, Length(D));
    // a new message may start again
    AssertTrue(A.Accept(Frame(cWsOpText, True, [$41]), K, D, L));
    AssertTrue(K = wkText);
  finally
    A.Free;
  end;
end;

procedure TWsMessageTest.TestContinuationWithoutStartIs1002;
var
  A: TWebSocketMessageAssembler;
begin
  A := TWebSocketMessageAssembler.Create(0);
  try
    AssertEquals(1002, AcceptCode(A, Frame(cWsOpContinuation, True, [1])));
  finally
    A.Free;
  end;
end;

procedure TWsMessageTest.TestDataInsideOpenMessageIs1002;
var
  A: TWebSocketMessageAssembler;
  K: TWsDataKind;
  D: TBytes;
  L: Boolean;
begin
  A := TWebSocketMessageAssembler.Create(0);
  try
    A.Accept(Frame(cWsOpBinary, False, [1]), K, D, L);
    AssertEquals(1002, AcceptCode(A, Frame(cWsOpText, True, [$41])));
  finally
    A.Free;
  end;
end;

procedure TWsMessageTest.TestTextSplitInsideCharacterIsHeldBack;
var
  A: TWebSocketMessageAssembler;
  K: TWsDataKind;
  D: TBytes;
  L: Boolean;
begin
  A := TWebSocketMessageAssembler.Create(0);
  try
    // U+20AC is E2 82 AC; split after the first two octets
    AssertTrue(A.Accept(Frame(cWsOpText, False, [$41, $E2, $82]), K, D, L));
    AssertEquals('only the complete prefix', 1, Length(D));
    AssertTrue(A.Accept(Frame(cWsOpContinuation, True, [$AC, $42]), K, D, L));
    AssertEquals('character completed', 4, Length(D));
    AssertEquals($E2, D[0]);
    AssertEquals($AC, D[2]);
    AssertTrue(L);
    // a fragment holding only part of a character delivers nothing yet
    AssertFalse(A.Accept(Frame(cWsOpText, False, [$E2]), K, D, L));
    AssertFalse(A.Accept(Frame(cWsOpContinuation, False, [$82]), K, D, L));
    AssertTrue(A.Accept(Frame(cWsOpContinuation, True, [$AC]), K, D, L));
    AssertEquals(3, Length(D));
  finally
    A.Free;
  end;
end;

procedure TWsMessageTest.TestTextBadPrefixFailsEarly;
var
  A: TWebSocketMessageAssembler;
begin
  A := TWebSocketMessageAssembler.Create(0);
  try
    AssertEquals(1007, AcceptCode(A, Frame(cWsOpText, False, [$41, $FF])));
  finally
    A.Free;
  end;
end;

procedure TWsMessageTest.TestTextEndingInsideCharacterIs1007;
var
  A: TWebSocketMessageAssembler;
begin
  A := TWebSocketMessageAssembler.Create(0);
  try
    AssertEquals(1007, AcceptCode(A, Frame(cWsOpText, True, [$41, $E2, $82])));
  finally
    A.Free;
  end;
end;

procedure TWsMessageTest.TestMessageLimitIs1009;
var
  A: TWebSocketMessageAssembler;
  K: TWsDataKind;
  D: TBytes;
  L: Boolean;
begin
  A := TWebSocketMessageAssembler.Create(4);
  try
    A.Accept(Frame(cWsOpBinary, False, [1, 2, 3]), K, D, L);
    AssertEquals(1009, AcceptCode(A, Frame(cWsOpContinuation, True, [4, 5])));
  finally
    A.Free;
  end;
end;

{ TWsHandshakeTest }

function TWsHandshakeTest.Fields(const A: array of string): TArray<TWsHeaderField>;
var
  I: Integer;
begin
  SetLength(Result, Length(A) div 2);
  for I := 0 to High(Result) do
  begin
    Result[I].Name := A[I * 2];
    Result[I].Value := A[I * 2 + 1];
  end;
end;

function TWsHandshakeTest.Ok(const AStatus: Integer;
  const AExtra: array of string; const AOffered: TArray<string>;
  out AChosen: string): string;
const
  Key = 'dGhlIHNhbXBsZSBub25jZQ==';
var
  F: TArray<TWsHeaderField>;
  Base: TArray<TWsHeaderField>;
  I: Integer;
begin
  Base := Fields(['Upgrade', 'websocket', 'Connection', 'Upgrade',
    'Sec-WebSocket-Accept', 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=']);
  F := Fields(AExtra);
  SetLength(Base, Length(Base) + Length(F));
  for I := 0 to High(F) do
    Base[Length(Base) - Length(F) + I] := F[I];
  Result := WsCheckResponse(AStatus, Base, Key, AOffered, AChosen);
end;

function FixedRandom: Cardinal;
begin
  Result := $01020304;
end;

procedure TWsHandshakeTest.TestRfcAcceptVector;
begin
  AssertEquals('s3pPLMBiTxaQ9kYGzzhZRbK+xOo=',
    WsComputeAccept('dGhlIHNhbXBsZSBub25jZQ=='));
end;

procedure TWsHandshakeTest.TestKeyIs16OctetsBase64;
var
  K: string;
begin
  K := WsNewKey(FixedRandom);
  AssertEquals('24 base64 characters', 24, Length(K));
  AssertEquals('padding', '==', Copy(K, 23, 2));
end;

procedure TWsHandshakeTest.TestUrlForms;
var
  Secure: Boolean;
  Host, Target, Auth: string;
  Port: Word;
begin
  WsParseUrl('ws://example.com', Secure, Host, Port, Target, Auth);
  AssertFalse(Secure); AssertEquals('example.com', Host);
  AssertEquals(80, Port); AssertEquals('/', Target); AssertEquals('example.com', Auth);
  WsParseUrl('wss://example.com:8443/chat?room=1', Secure, Host, Port, Target, Auth);
  AssertTrue(Secure); AssertEquals(8443, Port);
  AssertEquals('/chat?room=1', Target); AssertEquals('example.com:8443', Auth);
  WsParseUrl('wss://example.com:443/x', Secure, Host, Port, Target, Auth);
  AssertEquals('default port omitted', 'example.com', Auth);
  WsParseUrl('https://example.com?a=b', Secure, Host, Port, Target, Auth);
  AssertTrue(Secure); AssertEquals('/?a=b', Target);
  WsParseUrl('ws://[::1]:9000/x', Secure, Host, Port, Target, Auth);
  AssertEquals('::1', Host); AssertEquals(9000, Port);
  AssertEquals('[::1]:9000', Auth);
  WsParseUrl('ws://[2001:db8::1]/', Secure, Host, Port, Target, Auth);
  AssertEquals('[2001:db8::1]', Auth);
  WsParseUrl('ws://user:pw@host/p', Secure, Host, Port, Target, Auth);
  AssertEquals('userinfo dropped', 'host', Auth);
end;

procedure TWsHandshakeTest.TestUrlErrors;
  procedure Bad(const AUrl: string);
  var
    Secure: Boolean;
    Host, Target, Auth: string;
    Port: Word;
    Raised: Boolean;
  begin
    Raised := False;
    try
      WsParseUrl(AUrl, Secure, Host, Port, Target, Auth);
    except
      on EHttpWebSocketError do
        Raised := True;
    end;
    AssertTrue(AUrl, Raised);
  end;
begin
  Bad('ftp://host/');
  Bad('host/path');
  Bad('ws://');
  Bad('ws://host#frag');
  Bad('ws://host:0/');
  Bad('ws://host:99999/');
  Bad('ws://[::1/');
end;

procedure TWsHandshakeTest.TestRequestBytes;
var
  B: TBytes;
  S: string;
  H: TArray<TWsHeaderField>;
begin
  H := Fields(['Authorization', 'Bearer x']);
  B := WsBuildHandshake('/chat?x=1', 'example.com:8080',
    'dGhlIHNhbXBsZSBub25jZQ==', nil, H);
  SetString(S, PChar(@B[0]), Length(B));
  AssertEquals('GET /chat?x=1 HTTP/1.1'#13#10 +
    'Host: example.com:8080'#13#10 +
    'Upgrade: websocket'#13#10 +
    'Connection: Upgrade'#13#10 +
    'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=='#13#10 +
    'Sec-WebSocket-Version: 13'#13#10 +
    'Authorization: Bearer x'#13#10#13#10, S);
end;

procedure TWsHandshakeTest.TestRequestBytesIpv6AndSubprotocols;
var
  B: TBytes;
  S: string;
  P: TArray<string>;
begin
  SetLength(P, 2);
  P[0] := 'chat'; P[1] := 'superchat';
  B := WsBuildHandshake('/', '[::1]:9000', 'K', P, nil);
  SetString(S, PChar(@B[0]), Length(B));
  AssertTrue('host', Pos('Host: [::1]:9000'#13#10, S) > 0);
  AssertTrue('protocols', Pos('Sec-WebSocket-Protocol: chat, superchat'#13#10, S) > 0);
  AssertTrue('ends with blank line', Copy(S, Length(S) - 3, 4) = #13#10#13#10);
end;

procedure TWsHandshakeTest.TestAcceptMatrix;
var
  Chosen: string;
  Key: string;
begin
  Key := 'dGhlIHNhbXBsZSBub25jZQ==';
  AssertEquals('accepted', '', Ok(101, [], nil, Chosen));
  AssertTrue('200', Ok(200, [], nil, Chosen) <> '');
  AssertTrue('301', Ok(301, [], nil, Chosen) <> '');
  AssertTrue('401', Ok(401, [], nil, Chosen) <> '');
  AssertTrue('426', Ok(426, [], nil, Chosen) <> '');
  AssertEquals('Connection list', '',
    WsCheckResponse(101, Fields(['upgrade', 'WebSocket',
      'CONNECTION', 'keep-alive, Upgrade',
      'sec-websocket-accept', 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=']), Key, nil, Chosen));
  AssertTrue('Connection keep-alive only',
    WsCheckResponse(101, Fields(['Upgrade', 'websocket',
      'Connection', 'keep-alive',
      'Sec-WebSocket-Accept', 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=']), Key, nil, Chosen) <> '');
  AssertTrue('missing Upgrade',
    WsCheckResponse(101, Fields(['Connection', 'Upgrade',
      'Sec-WebSocket-Accept', 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=']), Key, nil, Chosen) <> '');
  AssertTrue('wrong accept',
    WsCheckResponse(101, Fields(['Upgrade', 'websocket', 'Connection', 'Upgrade',
      'Sec-WebSocket-Accept', 'AAAAAAAAAAAAAAAAAAAAAAAAAAA=']), Key, nil, Chosen) <> '');
  AssertTrue('missing accept',
    WsCheckResponse(101, Fields(['Upgrade', 'websocket', 'Connection', 'Upgrade']),
      Key, nil, Chosen) <> '');
  AssertTrue('extension not offered', Ok(101,
    ['Sec-WebSocket-Extensions', 'permessage-deflate'], nil, Chosen) <> '');
end;

procedure TWsHandshakeTest.TestSubprotocolMatrix;
var
  Chosen: string;
  Offered: TArray<string>;
begin
  SetLength(Offered, 2);
  Offered[0] := 'chat'; Offered[1] := 'other';
  AssertEquals('listed', '', Ok(101, ['Sec-WebSocket-Protocol', 'chat'],
    Offered, Chosen));
  AssertEquals('chosen', 'chat', Chosen);
  AssertTrue('unlisted', Ok(101, ['Sec-WebSocket-Protocol', 'nope'],
    Offered, Chosen) <> '');
  AssertTrue('unsolicited', Ok(101, ['Sec-WebSocket-Protocol', 'chat'],
    nil, Chosen) <> '');
  AssertTrue('two in one line', Ok(101, ['Sec-WebSocket-Protocol', 'chat, other'],
    Offered, Chosen) <> '');
  AssertTrue('two lines', Ok(101, ['Sec-WebSocket-Protocol', 'chat',
    'Sec-WebSocket-Protocol', 'other'], Offered, Chosen) <> '');
  AssertEquals('none selected', '', Ok(101, [], Offered, Chosen));
  AssertEquals('', Chosen);
end;

procedure TWsHandshakeTest.TestRestrictedHeadersRejectedAtWithHeader;
var
  R: IWebSocketRequest;
  Names: array[0..8] of string;
  I: Integer;
  Raised: Boolean;
begin
  R := TWebSocketRequest.Create('ws://h/', TWebSocketListener.Create);
  Names[0] := 'Host'; Names[1] := 'Upgrade'; Names[2] := 'connection';
  Names[3] := 'Content-Length'; Names[4] := 'Sec-WebSocket-Key';
  Names[5] := 'sec-websocket-version'; Names[6] := 'Sec-WebSocket-Protocol';
  Names[7] := 'Sec-WebSocket-Extensions'; Names[8] := 'Sec-WebSocket-Accept';
  for I := 0 to High(Names) do
  begin
    Raised := False;
    try
      R.WithHeader(Names[I], 'x');
    except
      on EHttpWebSocketError do
        Raised := True;
    end;
    AssertTrue(Names[I], Raised);
  end;
  AssertEquals('other headers pass', 1,
    Length(R.WithHeader('Origin', 'http://h').Headers));
end;

{ TWsRequestTest }

procedure TWsRequestTest.TestWithXReturnsNewValues;
var
  A, B: IWebSocketRequest;
  Names: TArray<string>;
begin
  A := TWebSocketRequest.Create('ws://h/p', TWebSocketListener.Create);
  AssertEquals(5000, A.CloseTimeoutMs);
  AssertEquals(0, A.ConnectTimeoutMs);
  AssertEquals(cWsDefaultMaxMessageBytes, A.MaxMessageBytes);
  AssertFalse(A.AutoRequest);
  B := A.WithConnectTimeoutMs(250).WithSubprotocol('chat')
    .WithHeader('X-A', '1').WithAutoRequest.WithPingIntervalMs(900)
    .WithCloseTimeoutMs(10).WithMaxMessageBytes(77);
  AssertEquals('original unchanged', 0, A.ConnectTimeoutMs);
  AssertEquals(0, Length(A.Subprotocols));
  AssertEquals(0, Length(A.Headers));
  AssertEquals(250, B.ConnectTimeoutMs);
  AssertEquals('chat', B.Subprotocols[0]);
  AssertEquals('X-A', B.Headers[0].Name);
  AssertTrue(B.AutoRequest);
  AssertEquals(900, B.PingIntervalMs);
  AssertEquals(10, B.CloseTimeoutMs);
  AssertEquals(77, B.MaxMessageBytes);
  AssertEquals('ws://h/p', B.Url);
  Names := nil;
  SetLength(Names, 2);
  Names[0] := 'a'; Names[1] := 'b';
  AssertEquals(3, Length(B.WithSubprotocols(Names).Subprotocols));
end;

procedure TWsRequestTest.TestRequiresListener;
var
  Raised: Boolean;
begin
  Raised := False;
  try
    TWebSocketRequest.Create('ws://h/', nil);
  except
    on EHttpWebSocketError do
      Raised := True;
  end;
  AssertTrue(Raised);
end;

procedure TWsRequestTest.TestArgumentChecks;
var
  R: IWebSocketRequest;
  function Raises(const AWhat: Integer): Boolean;
  begin
    Result := False;
    try
      case AWhat of
        0: R.WithConnectTimeoutMs(-1);
        1: R.WithSubprotocol('has space');
        2: R.WithSubprotocol('');
        3: R.WithSubprotocol('a,b');
        4: R.WithHeader('bad name', 'v');
        5: R.WithHeader('X', 'a'#13#10'b');
        6: R.WithMaxMessageBytes(-1);
        7: R.WithPingIntervalMs(-1);
        8: TWebSocketRequest.Create('ftp://h/', TWebSocketListener.Create);
      end;
    except
      on EHttpWebSocketError do
        Result := True;
    end;
  end;
var
  I: Integer;
begin
  R := TWebSocketRequest.Create('ws://h/', TWebSocketListener.Create);
  for I := 0 to 8 do
    AssertTrue('case ' + IntToStr(I), Raises(I));
end;

procedure TWsRequestTest.TestUnitDependsOnRtlOnly;
var
  L: TStringList;
  I: Integer;
  S, Uses_: string;
  InUses: Boolean;
begin
  L := TStringList.Create;
  try
    L.LoadFromFile('src/Http2.WebSocket.pas');
    InUses := False;
    Uses_ := '';
    for I := 0 to L.Count - 1 do
    begin
      S := Trim(L[I]);
      if (not InUses) and (LowerCase(S) = 'uses') then
      begin
        InUses := True;
        Continue;
      end;
      if InUses then
      begin
        Uses_ := Uses_ + ' ' + S;
        if Pos(';', S) > 0 then
          Break;
      end;
    end;
    AssertTrue('RTL and Errors only: ' + Uses_,
      Pos('Http2.', StringReplace(Uses_, 'Http2.Errors', '', [])) = 0);
    AssertTrue('does not call Random', Pos('Random(', L.Text) = 0);
  finally
    L.Free;
  end;
end;

initialization
  RegisterTest(TWsFrameTest);
  RegisterTest(TWsMessageTest);
  RegisterTest(TWsHandshakeTest);
  RegisterTest(TWsRequestTest);
end.
