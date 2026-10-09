/// Unit tests for Http2.Encoding (content coding)
// - covers the gzip and deflate codecs, the accept-encoding chooser, the
//   tolerant deflate container detection, and the transparent decode wrapper
unit Http2.Encoding.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$interfaces com}

interface

uses
  SysUtils, Classes, fpcunit, testregistry,
  Http2.Encoding, Http2.Headers, Http2.Messages, Http2.Stream;

type
  TEncodingTest = class(TTestCase)
  private
    function BytesOf(const AText: string): TBytes;
    function TextOf(const AData: TBytes): string;
    function Compressible: TBytes;
    function Drain(const ABody: IHttpBodyStream): TBytes;
  published
    // the codecs
    procedure TestGzipRoundTrip;
    procedure TestGzipEmptyInput;
    procedure TestGzipHeaderIsTheGzipContainer;
    procedure TestDeflateRoundTrip;
    procedure TestDeflateHeaderIsZlib;
    procedure TestRawDeflateRoundTrip;
    procedure TestDeflateDecompressAcceptsRawDeflate;
    procedure TestDeflateDecompressAcceptsZlib;
    procedure TestGzipOutputIsSmallerForRepetitiveInput;
    // the container detection
    procedure TestLooksZlibThroughDeflateDecompress;
    // ParseContentEncoding
    procedure TestParseGzip;
    procedure TestParseDeflate;
    procedure TestParseIdentityForAbsentAndUnknown;
    procedure TestParseXGzip;
    procedure TestParseChainTakesTheFirstKnown;
    // NegotiateEncoding
    procedure TestNegotiateAbsentIsIdentity;
    procedure TestNegotiateEmptyIsIdentity;
    procedure TestNegotiateGzipAndDeflatePrefersGzip;
    procedure TestNegotiateGzipOnly;
    procedure TestNegotiateDeflateOnly;
    procedure TestNegotiateUnknownIsIdentity;
    procedure TestNegotiateGzipRefusedFallsToDeflate;
    procedure TestNegotiateWildcardSelectsGzip;
    procedure TestNegotiateWildcardRefusedIsIdentity;
    procedure TestNegotiateQualityZeroOnBothIsIdentity;
    procedure TestNegotiateHigherQualityDeflateWins;
    // the wrapper
    procedure TestWrapDecodingRemovesTheCodingHeader;
    procedure TestWrapDecodingLeavesIdentityAlone;
    procedure TestDecodingBodyStreamInflatesGzip;
    procedure TestDecodingBodyStreamInflatesDeflate;
  end;

  /// a body stream over a fixed byte array, so a wrapper has an inner stream
  TMemoryBodyStream = class(TInterfacedObject, IHttpBodyStream)
  private
    FData: TBytes;
    FPos: Integer;
  public
    constructor Create(const AData: TBytes);
    function Read(var ABuffer; const ACount: LongInt): LongInt;
    function Eof: Boolean;
  end;

  /// the least response an IHttpResponse can be
  TStubResponse = class(TInterfacedObject, IHttpResponse)
  private
    FHeaders: IHttpHeaders;
    FBody: IHttpBodyStream;
  public
    constructor Create(const ABody: IHttpBodyStream);
    function GetStatusCode: LongInt;
    function GetHeaders: IHttpHeaders;
    function GetBody: IHttpBodyStream;
  end;

procedure RegisterTests;

implementation

{ TMemoryBodyStream }

constructor TMemoryBodyStream.Create(const AData: TBytes);
begin
  inherited Create;
  FData := Copy(AData, 0, Length(AData));
  FPos := 0;
end;

function TMemoryBodyStream.Read(var ABuffer; const ACount: LongInt): LongInt;
var
  P: PByte;
  Left, Take: Integer;
begin
  P := @ABuffer;
  Left := Length(FData) - FPos;
  if Left <= 0 then
    Exit(0);
  Take := ACount;
  if Take > Left then
    Take := Left;
  Move(FData[FPos], P[0], Take);
  Inc(FPos, Take);
  Result := Take;
end;

function TMemoryBodyStream.Eof: Boolean;
begin
  Result := FPos >= Length(FData);
end;

{ TStubResponse }

constructor TStubResponse.Create(const ABody: IHttpBodyStream);
begin
  inherited Create;
  FHeaders := NewHttpHeaders;
  FBody := ABody;
end;

function TStubResponse.GetStatusCode: LongInt;
begin
  Result := 200;
end;

function TStubResponse.GetHeaders: IHttpHeaders;
begin
  Result := FHeaders;
end;

function TStubResponse.GetBody: IHttpBodyStream;
begin
  Result := FBody;
end;

{ TEncodingTest }

function TEncodingTest.BytesOf(const AText: string): TBytes;
begin
  Result := TEncoding.ANSI.GetBytes(AText);
end;

function TEncodingTest.TextOf(const AData: TBytes): string;
begin
  Result := TEncoding.ANSI.GetString(AData);
end;

function TEncodingTest.Compressible: TBytes;
var
  I: Integer;
  S: string;
begin
  S := '';
  for I := 1 to 400 do
    S := S + 'the quick brown fox jumps over the lazy dog. ';
  Result := BytesOf(S);
end;

function TEncodingTest.Drain(const ABody: IHttpBodyStream): TBytes;
var
  Buf: array[0..4095] of Byte;
  N: LongInt;
begin
  SetLength(Result, 0);
  repeat
    N := ABody.Read(Buf[0], SizeOf(Buf));
    if N > 0 then
    begin
      SetLength(Result, Length(Result) + N);
      Move(Buf[0], Result[Length(Result) - N], N);
    end;
  until N <= 0;
end;

procedure TEncodingTest.TestGzipRoundTrip;
var
  Data, Blob: TBytes;
begin
  Data := Compressible;
  Blob := GzipCompress(Data);
  AssertEquals('the round trip returns the input size', Length(Data),
    Length(GzipDecompress(Blob)));
  AssertEquals('the round trip returns the input text', TextOf(Data),
    TextOf(GzipDecompress(Blob)));
end;

procedure TEncodingTest.TestGzipEmptyInput;
var
  Blob: TBytes;
begin
  Blob := GzipCompress(nil);
  // an empty gzip stream is still a valid container (header + footer)
  AssertTrue('an empty input still produces a gzip container',
    Length(Blob) >= 18);
  AssertEquals('an empty gzip stream decodes to nothing', 0,
    Length(GzipDecompress(Blob)));
end;

procedure TEncodingTest.TestGzipHeaderIsTheGzipContainer;
var
  Blob: TBytes;
begin
  Blob := GzipCompress(BytesOf('hello'));
  AssertEquals('the gzip signature byte 1', $1F, Blob[0]);
  AssertEquals('the gzip signature byte 2', $8B, Blob[1]);
  AssertEquals('the gzip compression method byte', 8, Blob[2]);
end;

procedure TEncodingTest.TestDeflateRoundTrip;
var
  Data, Blob: TBytes;
begin
  Data := Compressible;
  Blob := DeflateCompress(Data);
  AssertEquals('the round trip returns the input text', TextOf(Data),
    TextOf(DeflateDecompress(Blob)));
end;

procedure TEncodingTest.TestDeflateHeaderIsZlib;
var
  Blob: TBytes;
begin
  Blob := DeflateCompress(BytesOf('hello'));
  // RFC 1950 section 2.2: the low nibble of the first byte is 8, and the two
  // header bytes are a multiple of 31
  AssertEquals('the zlib method nibble', 8, Blob[0] and $0F);
  AssertEquals('the zlib header check bits', 0,
    (((Blob[0] shl 8) + Blob[1]) mod 31));
end;

procedure TEncodingTest.TestRawDeflateRoundTrip;
var
  Data, Blob: TBytes;
begin
  Data := Compressible;
  Blob := RawDeflateCompress(Data);
  // a bare deflate stream carries no zlib header
  AssertTrue('a bare deflate stream has no zlib header',
    not (((Blob[0] and $0F) = 8) and
      ((((Blob[0] shl 8) + Blob[1]) mod 31) = 0)));
  AssertEquals('the round trip returns the input text', TextOf(Data),
    TextOf(DeflateDecompress(Blob)));
end;

procedure TEncodingTest.TestDeflateDecompressAcceptsRawDeflate;
var
  Data, Raw: TBytes;
begin
  Data := BytesOf('deflate without a zlib wrapper');
  Raw := RawDeflateCompress(Data);
  AssertEquals('a bare deflate stream is decoded', 'deflate without a zlib wrapper',
    TextOf(DeflateDecompress(Raw)));
end;

procedure TEncodingTest.TestDeflateDecompressAcceptsZlib;
var
  Data, Z32: TBytes;
begin
  Data := BytesOf('deflate with a zlib wrapper');
  Z32 := DeflateCompress(Data);
  AssertEquals('a zlib stream is decoded', 'deflate with a zlib wrapper',
    TextOf(DeflateDecompress(Z32)));
end;

procedure TEncodingTest.TestGzipOutputIsSmallerForRepetitiveInput;
var
  Data, Blob: TBytes;
begin
  Data := Compressible;
  Blob := GzipCompress(Data);
  AssertTrue('repetitive input compresses', Length(Blob) < Length(Data) div 2);
end;

procedure TEncodingTest.TestLooksZlibThroughDeflateDecompress;
var
  Data: TBytes;
begin
  // a one-byte body cannot carry a zlib header; the decoder must not trust
  // a short prefix to be one
  Data := BytesOf('x');
  AssertEquals('a short body still decodes', 'x',
    TextOf(DeflateDecompress(DeflateCompress(Data))));
end;

procedure TEncodingTest.TestParseGzip;
begin
  AssertEquals('gzip parses', Ord(ceGzip), Ord(ParseContentEncoding('gzip')));
  AssertEquals('the case does not matter', Ord(ceGzip),
    Ord(ParseContentEncoding('GZIP')));
  AssertEquals('surrounding space does not matter', Ord(ceGzip),
    Ord(ParseContentEncoding(' gzip ')));
end;

procedure TEncodingTest.TestParseDeflate;
begin
  AssertEquals('deflate parses', Ord(ceDeflate),
    Ord(ParseContentEncoding('deflate')));
end;

procedure TEncodingTest.TestParseIdentityForAbsentAndUnknown;
begin
  AssertEquals('an empty value is identity', Ord(ceIdentity),
    Ord(ParseContentEncoding('')));
  AssertEquals('an unknown coding is identity', Ord(ceIdentity),
    Ord(ParseContentEncoding('br')));
  AssertEquals('identity parses as identity', Ord(ceIdentity),
    Ord(ParseContentEncoding('identity')));
end;

procedure TEncodingTest.TestParseXGzip;
begin
  // x-gzip is the historic alias of gzip
  AssertEquals('x-gzip parses as gzip', Ord(ceGzip),
    Ord(ParseContentEncoding('x-gzip')));
end;

procedure TEncodingTest.TestParseChainTakesTheFirstKnown;
begin
  AssertEquals('a chain takes its first known coding', Ord(ceGzip),
    Ord(ParseContentEncoding('br, gzip')));
  AssertEquals('a chain of unknown codings is identity', Ord(ceIdentity),
    Ord(ParseContentEncoding('br, zstd')));
end;

procedure TEncodingTest.TestNegotiateAbsentIsIdentity;
begin
  AssertEquals('an absent header is identity', Ord(ceIdentity),
    Ord(NegotiateEncoding('')));
end;

procedure TEncodingTest.TestNegotiateEmptyIsIdentity;
begin
  AssertEquals('a blank header is identity', Ord(ceIdentity),
    Ord(NegotiateEncoding('   ')));
end;

procedure TEncodingTest.TestNegotiateGzipAndDeflatePrefersGzip;
begin
  AssertEquals('gzip wins over deflate at equal quality', Ord(ceGzip),
    Ord(NegotiateEncoding('gzip, deflate')));
end;

procedure TEncodingTest.TestNegotiateGzipOnly;
begin
  AssertEquals('gzip alone is chosen', Ord(ceGzip),
    Ord(NegotiateEncoding('gzip')));
end;

procedure TEncodingTest.TestNegotiateDeflateOnly;
begin
  AssertEquals('deflate alone is chosen', Ord(ceDeflate),
    Ord(NegotiateEncoding('deflate')));
end;

procedure TEncodingTest.TestNegotiateUnknownIsIdentity;
begin
  AssertEquals('an unknown coding is never chosen', Ord(ceIdentity),
    Ord(NegotiateEncoding('br')));
end;

procedure TEncodingTest.TestNegotiateGzipRefusedFallsToDeflate;
begin
  // q=0 means "not acceptable"
  AssertEquals('a refused gzip falls to deflate', Ord(ceDeflate),
    Ord(NegotiateEncoding('gzip;q=0, deflate')));
end;

procedure TEncodingTest.TestNegotiateWildcardSelectsGzip;
begin
  AssertEquals('a wildcard selects gzip', Ord(ceGzip),
    Ord(NegotiateEncoding('*')));
end;

procedure TEncodingTest.TestNegotiateWildcardRefusedIsIdentity;
begin
  AssertEquals('a refused wildcard is identity', Ord(ceIdentity),
    Ord(NegotiateEncoding('*;q=0')));
end;

procedure TEncodingTest.TestNegotiateQualityZeroOnBothIsIdentity;
begin
  AssertEquals('both codings refused is identity', Ord(ceIdentity),
    Ord(NegotiateEncoding('gzip;q=0, deflate;q=0')));
end;

procedure TEncodingTest.TestNegotiateHigherQualityDeflateWins;
begin
  AssertEquals('a higher-quality deflate wins', Ord(ceDeflate),
    Ord(NegotiateEncoding('gzip;q=0.5, deflate;q=0.9')));
  AssertEquals('a higher-quality gzip wins', Ord(ceGzip),
    Ord(NegotiateEncoding('gzip;q=0.9, deflate;q=0.5')));
end;

procedure TEncodingTest.TestWrapDecodingRemovesTheCodingHeader;
var
  Inner: IHttpResponse;
  Wrapped: IHttpResponse;
begin
  Inner := TStubResponse.Create(
    TMemoryBodyStream.Create(GzipCompress(BytesOf('a coded body'))));
  Inner.Headers.Add(HeaderContentEncoding, 'gzip');
  Inner.Headers.Add(HeaderContentLength, '999');
  Wrapped := WrapDecodingResponse(Inner);
  AssertTrue('the wrapper is a different response', Wrapped <> Inner);
  AssertEquals('the coding header is gone', '',
    Wrapped.Headers.GetFirst(HeaderContentEncoding));
  AssertEquals('the length header is gone', '',
    Wrapped.Headers.GetFirst(HeaderContentLength));
  AssertEquals('the body decodes', 'a coded body',
    TextOf(Drain(Wrapped.Body)));
end;

procedure TEncodingTest.TestWrapDecodingLeavesIdentityAlone;
var
  Inner: IHttpResponse;
begin
  Inner := TStubResponse.Create(TMemoryBodyStream.Create(BytesOf('plain')));
  AssertTrue('an uncoded response is returned unchanged',
    WrapDecodingResponse(Inner) = Inner);
end;

procedure TEncodingTest.TestDecodingBodyStreamInflatesGzip;
var
  Stream: IHttpBodyStream;
  Buf: array[0..7] of Byte;
  N: LongInt;
  Got: TBytes;
begin
  Stream := TDecodingBodyStream.Create(
    TMemoryBodyStream.Create(GzipCompress(BytesOf('gzipped'))), ceGzip);
  SetLength(Got, 0);
  repeat
    N := Stream.Read(Buf[0], SizeOf(Buf));
    if N > 0 then
    begin
      SetLength(Got, Length(Got) + N);
      Move(Buf[0], Got[Length(Got) - N], N);
    end;
  until N <= 0;
  AssertEquals('the gzip body decodes', 'gzipped', TextOf(Got));
end;

procedure TEncodingTest.TestDecodingBodyStreamInflatesDeflate;
var
  Stream: IHttpBodyStream;
  Buf: array[0..7] of Byte;
  N: LongInt;
  Got: TBytes;
begin
  Stream := TDecodingBodyStream.Create(
    TMemoryBodyStream.Create(DeflateCompress(BytesOf('deflated'))), ceDeflate);
  SetLength(Got, 0);
  repeat
    N := Stream.Read(Buf[0], SizeOf(Buf));
    if N > 0 then
    begin
      SetLength(Got, Length(Got) + N);
      Move(Buf[0], Got[Length(Got) - N], N);
    end;
  until N <= 0;
  AssertEquals('the deflate body decodes', 'deflated', TextOf(Got));
end;

procedure RegisterTests;
begin
  RegisterTest(TEncodingTest);
end;

initialization
  RegisterTests;

end.
