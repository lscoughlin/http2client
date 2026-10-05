/// Unit tests for Http2.Hpack (plan story S03, tasks 03.1-03.8)
// - RFC 7541 Appendix C vectors, Huffman round-trip, dynamic table rules
unit Http2.Hpack.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, fpcunit, testregistry, Http2.Errors, Http2.Hpack;

type
  THpackTest = class(TTestCase)
  private
    function HexToBytes(const AHex: string): TBytes;
    function BytesToHex(const AData: TBytes): string;
    function Field(const AName, AValue: string;
      const ASensitive: Boolean = False): THttpHeaderField;
    procedure AssertHexEquals(const AExpected, AActual: string;
      const AMsg: string);
    procedure AssertBlockEquals(const AExpected, AActual: THeaderBlock;
      const AMsg: string);
    function EncodeToHex(const ACodec: THpackCodec;
      const AHeaders: THeaderBlock): string;
  published
    // 03.1 static table
    procedure TestStaticTableLookupViaDecode;
    // 03.3 integer coding
    procedure TestIntegerSevenBitPrefixBoundaries;
    procedure TestIntegerOverflowRaises;
    // 03.4 string literal coding
    procedure TestRawStringLiteralRoundTrip;
    procedure TestHuffmanStringLiteralRoundTrip;
    // 03.5 Huffman
    procedure TestHuffmanRoundTripAscii;
    procedure TestHuffmanRoundTripLongAndEmpty;
    procedure TestHuffmanBadPaddingRaises;
    // 03.6 representations
    procedure TestLiteralWithIncrementalIndexing;
    procedure TestLiteralWithoutIndexing;
    procedure TestLiteralNeverIndexedRoundTrip;
    procedure TestDynamicTableSizeUpdateMidStream;
    procedure TestDynamicTableSizeUpdateAfterFieldRaises;
    procedure TestDynamicTableSizeUpdateExceedsSettingRaises;
    // 03.2 dynamic table
    procedure TestOversizedEntryClearsTable;
    procedure TestDynamicTableEviction;
    // 03.7 per-instance state
    procedure TestTwoCodecsHaveIndependentTables;
    // 03.8 errors
    procedure TestMalformedIndexRaises;
    procedure TestMalformedZeroIndexRaises;
    // Appendix C vectors
    procedure TestAppendixC2LiteralRepresentations;
    procedure TestAppendixC3RequestsNoHuffman;
    procedure TestAppendixC4RequestsHuffman;
    procedure TestAppendixC5ResponsesNoHuffman;
    procedure TestAppendixC6ResponsesHuffman;
  end;

implementation

function THpackTest.HexToBytes(const AHex: string): TBytes;
var
  Clean: string;
  i, N: Integer;
begin
  Clean := '';
  for i := 1 to Length(AHex) do
    if AHex[i] in ['0'..'9', 'a'..'f', 'A'..'F'] then
      Clean := Clean + AHex[i];
  N := Length(Clean) div 2;
  Result := nil;
  SetLength(Result, N);
  for i := 0 to N - 1 do
    Result[i] := StrToInt('$' + Copy(Clean, i * 2 + 1, 2));
end;

function THpackTest.BytesToHex(const AData: TBytes): string;
var
  i: Integer;
begin
  Result := '';
  for i := 0 to High(AData) do
    Result := Result + LowerCase(IntToHex(AData[i], 2));
end;

function THpackTest.Field(const AName, AValue: string;
  const ASensitive: Boolean): THttpHeaderField;
begin
  Result.Name := AName;
  Result.Value := AValue;
  Result.Sensitive := ASensitive;
end;

procedure THpackTest.AssertHexEquals(const AExpected, AActual: string;
  const AMsg: string);
begin
  AssertEquals(AMsg, LowerCase(AExpected), LowerCase(AActual));
end;

procedure THpackTest.AssertBlockEquals(const AExpected, AActual: THeaderBlock;
  const AMsg: string);
var
  i: Integer;
begin
  AssertEquals(AMsg + ': field count', Length(AExpected), Length(AActual));
  for i := 0 to High(AExpected) do
  begin
    AssertEquals(Format('%s: field %d name', [AMsg, i]),
      AExpected[i].Name, AActual[i].Name);
    AssertEquals(Format('%s: field %d value', [AMsg, i]),
      AExpected[i].Value, AActual[i].Value);
    AssertEquals(Format('%s: field %d sensitive', [AMsg, i]),
      AExpected[i].Sensitive, AActual[i].Sensitive);
  end;
end;

function THpackTest.EncodeToHex(const ACodec: THpackCodec;
  const AHeaders: THeaderBlock): string;
begin
  Result := BytesToHex(ACodec.Encode(AHeaders));
end;

{ ---------- 03.1 static table ---------- }

procedure THpackTest.TestStaticTableLookupViaDecode;
var
  Codec: THpackCodec;
  Block: THeaderBlock;
begin
  Codec := THpackCodec.Create;
  try
    // 0x82 = indexed field, static index 2 -> :method GET
    Block := Codec.Decode(HexToBytes('82'));
    AssertEquals('count', 1, Length(Block));
    AssertEquals('name', ':method', Block[0].Name);
    AssertEquals('value', 'GET', Block[0].Value);
    // 0xbe = indexed field, static index 62 is first dynamic slot -> invalid
    // on a fresh codec because no dynamic entries exist
  finally
    Codec.Free;
  end;
end;

{ ---------- 03.3 integer coding ---------- }

procedure THpackTest.TestIntegerSevenBitPrefixBoundaries;
var
  Codec: THpackCodec;
  V, H: string;
begin
  // a static-table name keeps the literal prefix immediately after 0x44, so the
  // value-length integer lands at a known offset
  Codec := THpackCodec.Create;
  try
    Codec.Huffman := False;
    V := StringOfChar('a', 126);
    H := EncodeToHex(Codec, [Field(':path', V)]);
    AssertEquals('len 126 prefix', '447e', Copy(H, 1, 4));
  finally
    Codec.Free;
  end;
  Codec := THpackCodec.Create;
  try
    Codec.Huffman := False;
    V := StringOfChar('a', 127);
    H := EncodeToHex(Codec, [Field(':path', V)]);
    AssertEquals('len 127 prefix', '447f00', Copy(H, 1, 6));
  finally
    Codec.Free;
  end;
  Codec := THpackCodec.Create;
  try
    Codec.Huffman := False;
    V := StringOfChar('a', 128);
    H := EncodeToHex(Codec, [Field(':path', V)]);
    AssertEquals('len 128 prefix', '447f01', Copy(H, 1, 6));
  finally
    Codec.Free;
  end;
  Codec := THpackCodec.Create;
  try
    Codec.Huffman := False;
    V := StringOfChar('a', 1337);
    H := EncodeToHex(Codec, [Field(':path', V)]);
    AssertEquals('len 1337 prefix', '447fba09', Copy(H, 1, 8));
  finally
    Codec.Free;
  end;
end;

procedure THpackTest.TestIntegerOverflowRaises;
var
  Codec: THpackCodec;
  Raised: Boolean;
begin
  Codec := THpackCodec.Create;
  try
    Raised := False;
    try
      // 0x7f = indexed, prefix 127 then a continuation that overflows 32 bits
      Codec.Decode(HexToBytes('ff ff ff ff ff ff 7f'));
    except
      on E: EHttpProtocolError do
      begin
        Raised := True;
        AssertEquals('code', Ord(ecCompressionError), Ord(E.ErrorCode));
      end;
    end;
    AssertTrue('overflow raised', Raised);
  finally
    Codec.Free;
  end;
end;

{ ---------- 03.4 string literal coding ---------- }

procedure THpackTest.TestRawStringLiteralRoundTrip;
var
  Codec: THpackCodec;
  Block, Decoded: THeaderBlock;
begin
  Codec := THpackCodec.Create;
  try
    Codec.Huffman := False;
    Block := [Field('x-raw', 'plain value')];
    Decoded := Codec.Decode(Codec.Encode(Block));
    AssertBlockEquals(Block, Decoded, 'raw literal');
  finally
    Codec.Free;
  end;
end;

procedure THpackTest.TestHuffmanStringLiteralRoundTrip;
var
  Codec: THpackCodec;
  Block, Decoded: THeaderBlock;
begin
  Codec := THpackCodec.Create;
  try
    Codec.Huffman := True;
    Block := [Field('x-huff', 'huffman value 123')];
    Decoded := Codec.Decode(Codec.Encode(Block));
    AssertBlockEquals(Block, Decoded, 'huffman literal');
  finally
    Codec.Free;
  end;
end;

{ ---------- 03.5 Huffman ---------- }

procedure THpackTest.TestHuffmanRoundTripAscii;
var
  Codec: THpackCodec;
  Block, Decoded: THeaderBlock;
  i: Integer;
  S: string;
begin
  // deterministic pseudo-random ASCII range
  S := '';
  for i := 0 to 400 do
    S := S + Chr(32 + ((i * 37 + 11) mod 95));
  Codec := THpackCodec.Create;
  try
    Codec.Huffman := True;
    Block := [Field('x', S)];
    Decoded := Codec.Decode(Codec.Encode(Block));
    AssertBlockEquals(Block, Decoded, 'huffman ascii');
  finally
    Codec.Free;
  end;
end;

procedure THpackTest.TestHuffmanRoundTripLongAndEmpty;
var
  Codec: THpackCodec;
  Block, Decoded: THeaderBlock;
begin
  Codec := THpackCodec.Create;
  try
    Codec.Huffman := True;
    Block := [Field('empty', ''), Field('long', StringOfChar('z', 300))];
    Decoded := Codec.Decode(Codec.Encode(Block));
    AssertBlockEquals(Block, Decoded, 'huffman long/empty');
  finally
    Codec.Free;
  end;
end;

procedure THpackTest.TestHuffmanBadPaddingRaises;
var
  Codec: THpackCodec;
  Raised: Boolean;
begin
  Codec := THpackCodec.Create;
  try
    Raised := False;
    // 0x40 = literal indexed, name idx 0, name length 0 (empty name),
    // value flagged Huffman len 1 = 0x81, payload 0x00 -> 3 zero padding bits
    try
      Codec.Decode(HexToBytes('40 00 81 00'));
    except
      on E: EHttpProtocolError do
      begin
        Raised := True;
        AssertEquals('code', Ord(ecCompressionError), Ord(E.ErrorCode));
      end;
    end;
    AssertTrue('bad padding raised', Raised);
  finally
    Codec.Free;
  end;
end;

{ ---------- 03.6 representations ---------- }

procedure THpackTest.TestLiteralWithIncrementalIndexing;
var
  Codec: THpackCodec;
  Block, Decoded: THeaderBlock;
  Data: TBytes;
begin
  Codec := THpackCodec.Create;
  try
    Codec.Huffman := False;
    Block := [Field('custom-key', 'custom-value')];
    Data := Codec.Encode(Block);
    AssertHexEquals('400a637573746f6d2d6b65790c637573746f6d2d76616c7565',
      BytesToHex(Data), 'incremental indexing bytes');
    AssertEquals('inserted into encoder table', 54, Codec.EncoderTableSize);
    Decoded := Codec.Decode(Data);
    AssertBlockEquals(Block, Decoded, 'incremental indexing');
  finally
    Codec.Free;
  end;
end;

procedure THpackTest.TestLiteralWithoutIndexing;
var
  Codec: THpackCodec;
  Block: THeaderBlock;
begin
  Codec := THpackCodec.Create;
  try
    Codec.Huffman := False;
    // sensitive is not it; C.2.2 is a plain "without indexing" choice, but our
    // encoder prefers incremental indexing. Assert it does NOT enter the table
    // when decoded from RFC bytes and the value is right.
    Block := Codec.Decode(HexToBytes('040c2f73616d706c652f70617468'));
    AssertEquals('count', 1, Length(Block));
    AssertEquals('name', ':path', Block[0].Name);
    AssertEquals('value', '/sample/path', Block[0].Value);
    AssertEquals('table empty', 0, Codec.DecoderTableSize);
  finally
    Codec.Free;
  end;
end;

procedure THpackTest.TestLiteralNeverIndexedRoundTrip;
var
  Codec: THpackCodec;
  Block, Decoded: THeaderBlock;
begin
  Codec := THpackCodec.Create;
  try
    Codec.Huffman := False;
    Block := [Field('password', 'secret', True)];
    // never-indexed uses 4-bit prefix with 0x10
    AssertEquals('never indexed prefix', '10',
      Copy(EncodeToHex(Codec, Block), 1, 2));
    Decoded := Codec.Decode(Codec.Encode(Block));
    AssertBlockEquals(Block, Decoded, 'never indexed');
    AssertEquals('not inserted', 0, Codec.EncoderTableSize);
  finally
    Codec.Free;
  end;
end;

procedure THpackTest.TestDynamicTableSizeUpdateMidStream;
var
  Codec: THpackCodec;
  Data: TBytes;
  Block: THeaderBlock;
begin
  Codec := THpackCodec.Create;
  try
    // size update to 100: 0x3f 0x45, then indexed :method GET (0x82)
    Data := HexToBytes('3f 45 82');
    Block := Codec.Decode(Data);
    AssertEquals('decoder cap', 100, Codec.DecoderMaxSize);
    AssertEquals('count', 1, Length(Block));
    AssertEquals('name', ':method', Block[0].Name);
  finally
    Codec.Free;
  end;
end;

procedure THpackTest.TestDynamicTableSizeUpdateAfterFieldRaises;
var
  Codec: THpackCodec;
  Raised: Boolean;
begin
  Codec := THpackCodec.Create;
  try
    Raised := False;
    // 0x82 (a header field) then 0x20 (size update) - illegal ordering
    try
      Codec.Decode(HexToBytes('82 20'));
    except
      on E: EHttpProtocolError do
      begin
        Raised := True;
        AssertEquals('code', Ord(ecCompressionError), Ord(E.ErrorCode));
      end;
    end;
    AssertTrue('size update after field raised', Raised);
  finally
    Codec.Free;
  end;
end;

procedure THpackTest.TestDynamicTableSizeUpdateExceedsSettingRaises;
var
  Codec: THpackCodec;
  Raised: Boolean;
begin
  Codec := THpackCodec.Create;
  try
    Codec.ApplySettings(256);
    Raised := False;
    // size update to 4096 (default) exceeds the 256 cap -> COMPRESSION_ERROR
    try
      Codec.Decode(HexToBytes('3f e1 1f'));
    except
      on E: EHttpProtocolError do
      begin
        Raised := True;
        AssertEquals('code', Ord(ecCompressionError), Ord(E.ErrorCode));
      end;
    end;
    AssertTrue('oversize update raised', Raised);
  finally
    Codec.Free;
  end;
end;

{ ---------- 03.2 dynamic table ---------- }

procedure THpackTest.TestOversizedEntryClearsTable;
var
  Codec: THpackCodec;
  Data, Raw: TBytes;
  Block: THeaderBlock;
  i: Integer;
begin
  Codec := THpackCodec.Create;
  try
    Codec.Huffman := False;
    Codec.ApplySettings(64);
    // a small entry fits and populates the table
    Codec.Decode(HexToBytes('40016103616161')); // name 'a', value 'aaa' (36 bytes)
    AssertEquals('small entry present', 36, Codec.DecoderTableSize);
    // raw incremental-indexed entry larger than the 64-byte cap: 0x40, name
    // len 4 'huge', value len 200 (0x7f 0x49), then 200 'x'
    Raw := HexToBytes('400468756765' + '7f49');
    SetLength(Raw, Length(Raw) + 200);
    for i := 0 to 199 do
      Raw[Length(Raw) - 200 + i] := $78;
    Block := Codec.Decode(Raw);
    AssertEquals('table cleared', 0, Codec.DecoderTableSize);
    AssertEquals('field decoded', 1, Length(Block));
    AssertEquals('name', 'huge', Block[0].Name);
    AssertEquals('value length', 200, Length(Block[0].Value));
  finally
    Codec.Free;
  end;
end;

procedure THpackTest.TestDynamicTableEviction;
var
  Codec: THpackCodec;
begin
  Codec := THpackCodec.Create;
  try
    Codec.Huffman := False;
    // cap 64: two 41-byte entries cannot coexist; the first is evicted
    Codec.ApplySettings(64);
    Codec.Decode(HexToBytes('40016103616161')); // name 'a', value 'aaa'
    AssertTrue('first inserted', Codec.DecoderTableSize > 0);
    Codec.Decode(HexToBytes('40016203616161')); // name 'b', value 'aaa'
    // only the newest survives within a 64-byte cap
    AssertEquals('one survives', 32 + 1 + 3, Codec.DecoderTableSize);
  finally
    Codec.Free;
  end;
end;

{ ---------- 03.7 per-instance state ---------- }

procedure THpackTest.TestTwoCodecsHaveIndependentTables;
var
  A, B: THpackCodec;
  Block: THeaderBlock;
  Data: TBytes;
  Raised: Boolean;
begin
  A := THpackCodec.Create;
  B := THpackCodec.Create;
  try
    A.Huffman := False;
    B.Huffman := False;
    Block := [Field('custom-key', 'custom-value')];
    A.Decode(A.Encode(Block));
    AssertTrue('A has entries', A.DecoderTableSize > 0);
    AssertEquals('B untouched', 0, B.DecoderTableSize);
    // a block referencing a dynamic index (>= 62) fails on a fresh codec
    Data := HexToBytes('be'); // indexed 62
    Raised := False;
    try
      B.Decode(Data);
    except
      on E: EHttpProtocolError do
        Raised := True;
    end;
    AssertTrue('fresh codec rejects dynamic index', Raised);
  finally
    A.Free;
    B.Free;
  end;
end;

{ ---------- 03.8 errors ---------- }

procedure THpackTest.TestMalformedIndexRaises;
var
  Codec: THpackCodec;
  Raised: Boolean;
begin
  Codec := THpackCodec.Create;
  try
    Raised := False;
    try
      Codec.Decode(HexToBytes('be')); // indexed 62, no dynamic entries
    except
      on E: EHttpProtocolError do
      begin
        Raised := True;
        AssertEquals('code', Ord(ecCompressionError), Ord(E.ErrorCode));
      end;
    end;
    AssertTrue('malformed index raised', Raised);
  finally
    Codec.Free;
  end;
end;

procedure THpackTest.TestMalformedZeroIndexRaises;
var
  Codec: THpackCodec;
  Raised: Boolean;
begin
  Codec := THpackCodec.Create;
  try
    Raised := False;
    try
      Codec.Decode(HexToBytes('80')); // indexed field, index 0 is illegal
    except
      on E: EHttpProtocolError do
      begin
        Raised := True;
        AssertEquals('code', Ord(ecCompressionError), Ord(E.ErrorCode));
      end;
    end;
    AssertTrue('zero index raised', Raised);
  finally
    Codec.Free;
  end;
end;

{ ---------- Appendix C ---------- }

procedure THpackTest.TestAppendixC2LiteralRepresentations;
var
  Codec: THpackCodec;
begin
  // C.2.1 literal with incremental indexing
  Codec := THpackCodec.Create;
  try
    Codec.Huffman := False;
    AssertHexEquals('400a637573746f6d2d6b65790d637573746f6d2d686561646572',
      EncodeToHex(Codec, [Field('custom-key', 'custom-header')]), 'C.2.1 bytes');
  finally
    Codec.Free;
  end;
  // C.2.2 literal without indexing (decode only; representation is a choice)
  Codec := THpackCodec.Create;
  try
    AssertBlockEquals([Field(':path', '/sample/path')],
      Codec.Decode(HexToBytes('040c2f73616d706c652f70617468')), 'C.2.2 decode');
  finally
    Codec.Free;
  end;
  // C.2.3 literal never indexed
  Codec := THpackCodec.Create;
  try
    Codec.Huffman := False;
    AssertHexEquals('100870617373776f726406736563726574',
      EncodeToHex(Codec, [Field('password', 'secret', True)]), 'C.2.3 bytes');
  finally
    Codec.Free;
  end;
  // C.2.4 indexed header field
  Codec := THpackCodec.Create;
  try
    AssertEquals('C.2.4 bytes', '82', EncodeToHex(Codec, [Field(':method', 'GET')]));
  finally
    Codec.Free;
  end;
end;

procedure THpackTest.TestAppendixC3RequestsNoHuffman;
var
  Codec: THpackCodec;
  R1, R2, R3: THeaderBlock;
begin
  Codec := THpackCodec.Create;
  try
    Codec.Huffman := False;
    R1 := [Field(':method', 'GET'), Field(':scheme', 'http'),
      Field(':path', '/'), Field(':authority', 'www.example.com')];
    AssertHexEquals(
      '828684410f7777772e6578616d706c652e636f6d',
      EncodeToHex(Codec, R1), 'C.3.1 bytes');
    R2 := [Field(':method', 'GET'), Field(':scheme', 'http'),
      Field(':path', '/'), Field(':authority', 'www.example.com'),
      Field('cache-control', 'no-cache')];
    AssertHexEquals(
      '828684be58086e6f2d6361636865',
      EncodeToHex(Codec, R2), 'C.3.2 bytes');
    R3 := [Field(':method', 'GET'), Field(':scheme', 'https'),
      Field(':path', '/index.html'), Field(':authority', 'www.example.com'),
      Field('custom-key', 'custom-value')];
    AssertHexEquals(
      '828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565',
      EncodeToHex(Codec, R3), 'C.3.3 bytes');
  finally
    Codec.Free;
  end;
  // decode the full C.3 sequence on one codec
  Codec := THpackCodec.Create;
  try
    AssertBlockEquals([Field(':method', 'GET'), Field(':scheme', 'http'),
      Field(':path', '/'), Field(':authority', 'www.example.com')],
      Codec.Decode(HexToBytes('828684410f7777772e6578616d706c652e636f6d')), 'C.3.1 decode');
    AssertBlockEquals([Field(':method', 'GET'), Field(':scheme', 'http'),
      Field(':path', '/'), Field(':authority', 'www.example.com'),
      Field('cache-control', 'no-cache')],
      Codec.Decode(HexToBytes('828684be58086e6f2d6361636865')), 'C.3.2 decode');
    AssertBlockEquals([Field(':method', 'GET'), Field(':scheme', 'https'),
      Field(':path', '/index.html'), Field(':authority', 'www.example.com'),
      Field('custom-key', 'custom-value')],
      Codec.Decode(HexToBytes(
        '828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565')), 'C.3.3 decode');
  finally
    Codec.Free;
  end;
end;

procedure THpackTest.TestAppendixC4RequestsHuffman;
var
  Codec: THpackCodec;
  R1, R2, R3: THeaderBlock;
begin
  Codec := THpackCodec.Create;
  try
    Codec.Huffman := True;
    R1 := [Field(':method', 'GET'), Field(':scheme', 'http'),
      Field(':path', '/'), Field(':authority', 'www.example.com')];
    AssertHexEquals(
      '828684418cf1e3c2e5f23a6ba0ab90f4ff',
      EncodeToHex(Codec, R1), 'C.4.1 bytes');
    R2 := [Field(':method', 'GET'), Field(':scheme', 'http'),
      Field(':path', '/'), Field(':authority', 'www.example.com'),
      Field('cache-control', 'no-cache')];
    AssertHexEquals(
      '828684be5886a8eb10649cbf',
      EncodeToHex(Codec, R2), 'C.4.2 bytes');
    R3 := [Field(':method', 'GET'), Field(':scheme', 'https'),
      Field(':path', '/index.html'), Field(':authority', 'www.example.com'),
      Field('custom-key', 'custom-value')];
    AssertHexEquals(
      '828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf',
      EncodeToHex(Codec, R3), 'C.4.3 bytes');
  finally
    Codec.Free;
  end;
  // decode the standalone :authority literal on a fresh codec
  Codec := THpackCodec.Create;
  try
    AssertBlockEquals([Field(':authority', 'www.example.com')],
      Codec.Decode(HexToBytes('418cf1e3c2e5f23a6ba0ab90f4ff')),
      'C.4.1 authority literal decode');
  finally
    Codec.Free;
  end;
  // C.4.3 references dynamic indices and requires C.4.1/C.4.2 first
  Codec := THpackCodec.Create;
  try
    Codec.Decode(HexToBytes('828684418cf1e3c2e5f23a6ba0ab90f4ff'));
    Codec.Decode(HexToBytes('828684be5886a8eb10649cbf'));
    AssertBlockEquals(
      [Field(':method', 'GET'), Field(':scheme', 'https'),
       Field(':path', '/index.html'), Field(':authority', 'www.example.com'),
       Field('custom-key', 'custom-value')],
      Codec.Decode(HexToBytes(
        '828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf')), 'C.4.3 decode');
  finally
    Codec.Free;
  end;
end;

procedure THpackTest.TestAppendixC5ResponsesNoHuffman;
var
  Codec: THpackCodec;
  Res1, Res2, Res3: THeaderBlock;
begin
  Codec := THpackCodec.Create;
  try
    Codec.Huffman := False;
    Codec.ApplySettings(256);
    Res1 := [Field(':status', '302'), Field('cache-control', 'private'),
      Field('date', 'Mon, 21 Oct 2013 20:13:21 GMT'),
      Field('location', 'https://www.example.com')];
    AssertHexEquals(
      '4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d',
      EncodeToHex(Codec, Res1), 'C.5.1 bytes');
    AssertEquals('C.5.1 table size', 222, Codec.EncoderTableSize);
    Res2 := [Field(':status', '307'), Field('cache-control', 'private'),
      Field('date', 'Mon, 21 Oct 2013 20:13:21 GMT'),
      Field('location', 'https://www.example.com')];
    AssertHexEquals('4803333037c1c0bf',
      EncodeToHex(Codec, Res2), 'C.5.2 bytes');
    Res3 := [Field(':status', '200'), Field('cache-control', 'private'),
      Field('date', 'Mon, 21 Oct 2013 20:13:22 GMT'),
      Field('location', 'https://www.example.com'),
      Field('content-encoding', 'gzip'),
      Field('set-cookie',
        'foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1')];
    AssertHexEquals(
      '88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31',
      EncodeToHex(Codec, Res3), 'C.5.3 bytes');
  finally
    Codec.Free;
  end;
  // decode C.5.1
  Codec := THpackCodec.Create;
  try
    Codec.ApplySettings(256);
    AssertBlockEquals(
      [Field(':status', '302'), Field('cache-control', 'private'),
       Field('date', 'Mon, 21 Oct 2013 20:13:21 GMT'),
       Field('location', 'https://www.example.com')],
      Codec.Decode(HexToBytes(
        '4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d')),
      'C.5.1 decode');
  finally
    Codec.Free;
  end;
end;

procedure THpackTest.TestAppendixC6ResponsesHuffman;
var
  Codec: THpackCodec;
begin
  Codec := THpackCodec.Create;
  try
    Codec.ApplySettings(256);
    AssertHexEquals(
      '488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3',
      BytesToHex(Codec.Encode(
        [Field(':status', '302'), Field('cache-control', 'private'),
         Field('date', 'Mon, 21 Oct 2013 20:13:21 GMT'),
         Field('location', 'https://www.example.com')])),
      'C.6.1 bytes');
    AssertHexEquals('4883640effc1c0bf',
      BytesToHex(Codec.Encode(
        [Field(':status', '307'), Field('cache-control', 'private'),
         Field('date', 'Mon, 21 Oct 2013 20:13:21 GMT'),
         Field('location', 'https://www.example.com')])),
      'C.6.2 bytes');
    AssertHexEquals(
      '88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007',
      BytesToHex(Codec.Encode(
        [Field(':status', '200'), Field('cache-control', 'private'),
         Field('date', 'Mon, 21 Oct 2013 20:13:22 GMT'),
         Field('location', 'https://www.example.com'),
         Field('content-encoding', 'gzip'),
         Field('set-cookie',
           'foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1')])),
      'C.6.3 bytes');
  finally
    Codec.Free;
  end;
end;

initialization
  RegisterTest(THpackTest);

end.
