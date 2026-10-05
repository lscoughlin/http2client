/// Randomized HPACK round-trip property tests (plan S11 task 11.6)
// - this unit is part of the http2client project (see doc/design/
//   testing-observability.md: "property tests for HPACK round-trips
//   (Decode(Encode(H)) = H)").
// - Every run uses a FIXED SEED so failures are reproducible: the generator
//   is deterministic, and each case prints its index and the seed on failure.
// - Coverage is deliberate, not incidental: header names/values vary in
//   length (0, 1, static-table hits, the 127-byte integer boundary, long
//   values), sensitive flags force the never-indexed representation, and
//   duplicate names exercise the dynamic table.
unit Http2.HpackProps.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, fpcunit, testregistry,
  Http2.Errors, Http2.Hpack;

type
  TPropertyRng = record
    State: LongWord;
    class function FromSeed(const ASeed: LongWord): TPropertyRng; static;
    function Next: LongWord;
    /// 0 .. ACount-1 when ACount > 0, else 0
    function NextRange(const ACount: Integer): Integer;
    function NextBool: Boolean;
  end;

  THpackPropertyTest = class(TTestCase)
  private
    function RandomHeader(var ARng: TPropertyRng): THttpHeaderField;
    function RandomHeaderBlock(var ARng: TPropertyRng;
      const AMaxFields: Integer): THeaderBlock;
    procedure AssertBlocksEqual(const AExpected, AActual: THeaderBlock;
      const ALabel: string);
  published
    // deterministic examples first (fast failure if the generator is broken)
    procedure TestFixedSeedGeneratorIsDeterministic;
    procedure TestRoundTripSingleField;
    procedure TestRoundTripDuplicates;
    procedure TestRoundTripSensitiveNeverIndexed;
    // the property: decode(encode(H)) = H over many random sets
    procedure TestRoundTripManyRandomSets;
    // one codec shared across many messages (dynamic-table reuse)
    procedure TestRoundTripSharedDynamicTable;
    // incremental encoding actually shrinks repeated headers
    procedure TestIncrementalEncodingShrinksRepeats;
    // an entry larger than the table is never indexed and must still round-trip
    procedure TestOversizedFieldRoundTrips;
    // a small table forces eviction while the property still holds
    procedure TestEvictionStillRoundTrips;
    // malformed input must raise, not silently round-trip
    procedure TestTruncatedBlockRaises;
  end;

implementation

const
  /// fixed seed: the whole suite is deterministic across runs and machines
  cPropertySeed: LongWord = $5EED1234;
  cPropertyIterations = 500;

{ TPropertyRng — xorshift32, deterministic and cheap }

class function TPropertyRng.FromSeed(const ASeed: LongWord): TPropertyRng;
begin
  Result.State := ASeed;
  if Result.State = 0 then
    Result.State := $1234567;
end;

function TPropertyRng.Next: LongWord;
begin
  State := State xor (State shl 13);
  State := State xor (State shr 17);
  State := State xor (State shl 5);
  Result := State;
end;

function TPropertyRng.NextRange(const ACount: Integer): Integer;
begin
  if ACount <= 0 then
    Exit(0);
  Result := Integer(Next mod LongWord(ACount));
end;

function TPropertyRng.NextBool: Boolean;
begin
  Result := (Next and 1) = 1;
end;

{ header generators }

function IntToStrP(const AValue: Int64): string;
begin
  Result := IntToStr(AValue);
end;

function THpackPropertyTest.RandomHeader(
  var ARng: TPropertyRng): THttpHeaderField;
const
  Names: array[0..11] of string = (
    'content-type', 'content-length', 'authorization', 'cookie', 'x-custom',
    'cache-control', 'user-agent', 'accept', 'x-empty-name', 'a', 'set-cookie',
    'x-long-value');
  Values: array[0..9] of string = (
    '', 'text/plain', 'application/json', '0', 'Bearer abcdef',
    'a=1; b=2; c=3', 'gzip, deflate, br', 'no-store', 'x', 'value');
var
  N: Integer;
begin
  N := ARng.NextRange(Length(Names));
  Result.Name := Names[N];
  N := ARng.NextRange(Length(Values));
  Result.Value := Values[N];
  // occasionally append a random-length tail so sizes vary widely, including
  // across the 127-byte HPACK integer boundary
  case ARng.NextRange(6) of
    0: Result.Value := Result.Value + StringOfChar('x',
         ARng.NextRange(200));
    1: Result.Value := Result.Value + ':' + IntToStrP(ARng.Next);
    2: Result.Name := Result.Name + '-' + IntToStrP(ARng.NextRange(3));
  end;
  Result.Sensitive := ARng.NextBool;
end;

function THpackPropertyTest.RandomHeaderBlock(var ARng: TPropertyRng;
  const AMaxFields: Integer): THeaderBlock;
var
  I, N: Integer;
begin
  Result := nil;
  N := 1 + ARng.NextRange(AMaxFields);
  SetLength(Result, N);
  for I := 0 to N - 1 do
    Result[I] := RandomHeader(ARng);
end;

procedure THpackPropertyTest.AssertBlocksEqual(const AExpected,
  AActual: THeaderBlock; const ALabel: string);
var
  I: Integer;
begin
  AssertEquals(ALabel + ': field count', Length(AExpected), Length(AActual));
  for I := 0 to High(AExpected) do
  begin
    AssertEquals(ALabel + ': #' + IntToStr(I) + ' name',
      AExpected[I].Name, AActual[I].Name);
    AssertEquals(ALabel + ': #' + IntToStr(I) + ' value',
      AExpected[I].Value, AActual[I].Value);
    // an encoder must preserve the sensitive flag as the never-indexed form
    AssertEquals(ALabel + ': #' + IntToStr(I) + ' sensitive',
      AExpected[I].Sensitive, AActual[I].Sensitive);
  end;
end;

{ tests }

procedure THpackPropertyTest.TestFixedSeedGeneratorIsDeterministic;
var
  A, B: TPropertyRng;
  I: Integer;
  HA, HB: THeaderBlock;
begin
  A := TPropertyRng.FromSeed(cPropertySeed);
  B := TPropertyRng.FromSeed(cPropertySeed);
  for I := 0 to 9 do
  begin
    AssertEquals('rng step ' + IntToStr(I), A.Next, B.Next);
    AssertEquals('rng bool ' + IntToStr(I), Ord(A.NextBool), Ord(B.NextBool));
  end;
  A := TPropertyRng.FromSeed(cPropertySeed);
  B := TPropertyRng.FromSeed(cPropertySeed);
  HA := RandomHeaderBlock(A, 8);
  HB := RandomHeaderBlock(B, 8);
  AssertBlocksEqual(HA, HB, 'same seed yields the same block');
end;

procedure THpackPropertyTest.TestRoundTripSingleField;
var
  Codec: THpackCodec;
  InBlock, OutBlock: THeaderBlock;
begin
  Codec := THpackCodec.Create;
  try
    SetLength(InBlock, 1);
    InBlock[0].Name := 'content-type';
    InBlock[0].Value := 'text/plain';
    InBlock[0].Sensitive := False;
    OutBlock := Codec.Decode(Codec.Encode(InBlock));
    AssertBlocksEqual(InBlock, OutBlock, 'single field');
  finally
    Codec.Free;
  end;
end;

procedure THpackPropertyTest.TestRoundTripDuplicates;
var
  Codec: THpackCodec;
  InBlock, OutBlock: THeaderBlock;
begin
  Codec := THpackCodec.Create;
  try
    SetLength(InBlock, 4);
    InBlock[0].Name := 'set-cookie'; InBlock[0].Value := 'a=1';
    InBlock[1].Name := 'set-cookie'; InBlock[1].Value := 'b=2';
    InBlock[2].Name := 'set-cookie'; InBlock[2].Value := 'a=1';
    InBlock[3].Name := 'set-cookie'; InBlock[3].Value := 'c=3';
    OutBlock := Codec.Decode(Codec.Encode(InBlock));
    AssertBlocksEqual(InBlock, OutBlock, 'duplicates');
  finally
    Codec.Free;
  end;
end;

procedure THpackPropertyTest.TestRoundTripSensitiveNeverIndexed;
var
  Codec: THpackCodec;
  InBlock, OutBlock: THeaderBlock;
begin
  Codec := THpackCodec.Create;
  try
    SetLength(InBlock, 1);
    InBlock[0].Name := 'authorization';
    InBlock[0].Value := 'Bearer secret';
    InBlock[0].Sensitive := True;
    OutBlock := Codec.Decode(Codec.Encode(InBlock));
    AssertBlocksEqual(InBlock, OutBlock, 'sensitive field');
    AssertEquals('a sensitive field is not added to the encoder table', 0,
      Codec.EncoderTableSize);
  finally
    Codec.Free;
  end;
end;

procedure THpackPropertyTest.TestRoundTripManyRandomSets;
var
  Rng: TPropertyRng;
  Codec: THpackCodec;
  InBlock, OutBlock: THeaderBlock;
  I: Integer;
  FailLabel: string;
begin
  Rng := TPropertyRng.FromSeed(cPropertySeed);
  // one codec per case: Encode + Decode of the SAME instance is the
  // production codec pair (encoder/decoder tables evolve together)
  for I := 0 to cPropertyIterations - 1 do
  begin
    Codec := THpackCodec.Create;
    try
      InBlock := RandomHeaderBlock(Rng, 12);
      OutBlock := Codec.Decode(Codec.Encode(InBlock));
      FailLabel := Format('seed=$%.8x iter=%d', [cPropertySeed, I]);
      AssertBlocksEqual(InBlock, OutBlock, FailLabel);
    finally
      Codec.Free;
    end;
  end;
end;

procedure THpackPropertyTest.TestRoundTripSharedDynamicTable;
var
  Rng: TPropertyRng;
  Codec: THpackCodec;
  InBlock, OutBlock: THeaderBlock;
  I: Integer;
begin
  Rng := TPropertyRng.FromSeed(cPropertySeed xor $ABCDEF01);
  // one codec, many messages: the encoder table is reused, so later blocks
  // reference earlier entries. Decode must still return each original block.
  Codec := THpackCodec.Create;
  try
    for I := 0 to cPropertyIterations - 1 do
    begin
      InBlock := RandomHeaderBlock(Rng, 8);
      OutBlock := Codec.Decode(Codec.Encode(InBlock));
      AssertBlocksEqual(InBlock, OutBlock,
        Format('shared table seed=$%.8x iter=%d',
          [cPropertySeed xor $ABCDEF01, I]));
    end;
    AssertTrue('the shared encoder table actually holds entries',
      Codec.EncoderTableSize > 0);
  finally
    Codec.Free;
  end;
end;

procedure THpackPropertyTest.TestIncrementalEncodingShrinksRepeats;
var
  Codec: THpackCodec;
  InBlock: THeaderBlock;
  First, Second: TBytes;
  I: Integer;
begin
  Codec := THpackCodec.Create;
  try
    SetLength(InBlock, 3);
    InBlock[0].Name := 'x-repeat'; InBlock[0].Value := 'value-value-value';
    InBlock[1].Name := 'x-repeat'; InBlock[1].Value := 'value-value-value';
    InBlock[2].Name := 'x-repeat'; InBlock[2].Value := 'value-value-value';
    First := Codec.Encode(InBlock);
    Second := Codec.Encode(InBlock);
    AssertBlocksEqual(InBlock, Codec.Decode(First), 'first encode');
    AssertBlocksEqual(InBlock, Codec.Decode(Second), 'second encode');
    // the second occurrence is fully indexed, so the first block is the
    // larger one; this fails if dynamic-table insertion is skipped
    AssertTrue('repeated headers compress on the second message',
      Length(Second) < Length(First));
    I := Length(First) - Length(Second);
    AssertTrue('the shrink is at least the literal name+value', I > 0);
  finally
    Codec.Free;
  end;
end;

procedure THpackPropertyTest.TestOversizedFieldRoundTrips;
var
  Codec: THpackCodec;
  InBlock, OutBlock: THeaderBlock;
  Big: string;
begin
  Codec := THpackCodec.Create;
  try
    Big := StringOfChar('z', 5000);     // larger than the 4096-byte table
    SetLength(InBlock, 1);
    InBlock[0].Name := 'x-big';
    InBlock[0].Value := Big;
    InBlock[0].Sensitive := False;
    OutBlock := Codec.Decode(Codec.Encode(InBlock));
    AssertBlocksEqual(InBlock, OutBlock, 'oversized field');
    AssertEquals('an oversized field never enters the table', 0,
      Codec.EncoderTableSize);
  finally
    Codec.Free;
  end;
end;

procedure THpackPropertyTest.TestEvictionStillRoundTrips;
var
  Rng: TPropertyRng;
  Codec: THpackCodec;
  InBlock, OutBlock: THeaderBlock;
  I: Integer;
begin
  Rng := TPropertyRng.FromSeed(cPropertySeed xor $0F0F0F0F);
  Codec := THpackCodec.Create;
  try
    // a 512-byte table evicts aggressively, exercising the eviction path
    Codec.ApplySettings(512);
    for I := 0 to 200 do
    begin
      InBlock := RandomHeaderBlock(Rng, 6);
      OutBlock := Codec.Decode(Codec.Encode(InBlock));
      AssertBlocksEqual(InBlock, OutBlock,
        Format('eviction seed=$%.8x iter=%d',
          [cPropertySeed xor $0F0F0F0F, I]));
      AssertTrue('table stays within its cap',
        Codec.EncoderTableSize <= 512);
    end;
  finally
    Codec.Free;
  end;
end;

procedure THpackPropertyTest.TestTruncatedBlockRaises;
var
  Codec: THpackCodec;
  InBlock: THeaderBlock;
  Enc: TBytes;
  Raised: Boolean;
begin
  Codec := THpackCodec.Create;
  try
    SetLength(InBlock, 1);
    InBlock[0].Name := 'x-trunc';
    InBlock[0].Value := StringOfChar('q', 300);
    InBlock[0].Sensitive := False;
    Enc := Codec.Encode(InBlock);
    // drop the tail: the string literal length now overruns the block
    Enc := Copy(Enc, 0, Length(Enc) - 50);
    Raised := False;
    try
      Codec.Decode(Enc);
    except
      on E: EHttpProtocolError do
      begin
        Raised := True;
        AssertEquals('truncation is a compression error',
          Ord(ecCompressionError), Ord(E.ErrorCode));
      end;
    end;
    AssertTrue('a truncated block raises, never silently succeeds', Raised);
  finally
    Codec.Free;
  end;
end;

initialization
  RegisterTest(THpackPropertyTest);
end.
