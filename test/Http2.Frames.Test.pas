/// Unit tests for Http2.Frames (plan story S01, tasks 01.2 - 01.6)
// - covers bit-packing, round-trips, settings, padding/priority and I/O
unit Http2.Frames.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, fpcunit, testregistry, Http2.Errors, Http2.Frames;

type
  TFramesTest = class(TTestCase)
  private
    function RoundTrip(const AFrame: TFrame): TFrame;
    procedure AssertBytesEqual(const AExpected, AActual: TBytes;
      const AContext: string);
  published
    // 01.2 enums and wire flag values
    procedure TestFrameTypeValues;
    procedure TestKnownFrameTypes;
    procedure TestFlagWireBits;
    procedure TestFlagRoundTrip;
    // 01.3 header bit-packing
    procedure TestHeaderRoundTrip;
    procedure TestHeaderMasksReservedBit;
    procedure TestHeaderLengthIs24Bit;
    // 01.4 payload records / builders
    procedure TestDataFrameRoundTrip;
    procedure TestHeadersFrameRoundTrip;
    procedure TestContinuationFrameRoundTrip;
    procedure TestPriorityFrameRoundTrip;
    procedure TestRstStreamFrameRoundTrip;
    procedure TestPingFrameRoundTrip;
    procedure TestGoAwayFrameRoundTrip;
    procedure TestWindowUpdateFrameRoundTrip;
    procedure TestAllFrameTypesRoundTrip;
    // padding and the PRIORITY flag on HEADERS
    procedure TestPaddedDataExtraction;
    procedure TestPaddedHeadersExtraction;
    procedure TestHeadersPriorityBlockExtraction;
    procedure TestHeadersWithoutPriorityFlagKeepsBlock;
    procedure TestBadPaddingRaises;
    // 01.5 read/write and size enforcement
    procedure TestReadWriteStreamRoundTrip;
    procedure TestOversizedInboundFrameRaises;
    procedure TestShortHeaderRaisesConnectionClosed;
    procedure TestValidateRejectsZeroStreamId;
    procedure TestValidateRejectsBadSettingsPayload;
    procedure TestValidateIgnoresUnknownFrameType;
    // 01.6 settings
    procedure TestSettingsRoundTrip;
    procedure TestSettingsUnknownIdIgnored;
    procedure TestSettingsEnablePushValidation;
    procedure TestSettingsMaxFrameSizeValidation;
    // a client implements no pushed-stream state, so its default SETTINGS
    // must advertise ENABLE_PUSH = 0 (RFC 9113 section 6.6); advertising 1
    // while ignoring PUSH_PROMISE is the harness case 8.2/1 bug
    procedure TestDefaultsDisablePush;
  end;

implementation

{ helpers }

function TFramesTest.RoundTrip(const AFrame: TFrame): TFrame;
var
  S: TMemoryStream;
begin
  S := TMemoryStream.Create;
  try
    WriteFrame(S, AFrame);
    S.Position := 0;
    Result := ReadFrame(S);
  finally
    S.Free;
  end;
end;

procedure TFramesTest.AssertBytesEqual(const AExpected, AActual: TBytes;
  const AContext: string);
var
  I: Integer;
begin
  AssertEquals(AContext + ': length', Length(AExpected), Length(AActual));
  for I := 0 to High(AExpected) do
    AssertEquals(AContext + ': byte ' + IntToStr(I),
      AExpected[I], AActual[I]);
end;

function BytesOf(const AValues: array of Byte): TBytes;
var
  I: Integer;
begin
  Result := nil;
  SetLength(Result, Length(AValues));
  for I := 0 to High(AValues) do
    Result[I] := AValues[I];
end;

/// build a frame type from a runtime integer so tests can probe
/// values outside the declared enum without constant-range warnings
function FrameTypeOf(const AValue: Integer): TFrameType;
begin
  Result := TFrameType(AValue);
end;

{ 01.2 }

procedure TFramesTest.TestFrameTypeValues;
begin
  AssertEquals('DATA', $0, Ord(ftData));
  AssertEquals('HEADERS', $1, Ord(ftHeaders));
  AssertEquals('PRIORITY', $2, Ord(ftPriority));
  AssertEquals('RST_STREAM', $3, Ord(ftRstStream));
  AssertEquals('SETTINGS', $4, Ord(ftSettings));
  AssertEquals('PUSH_PROMISE', $5, Ord(ftPushPromise));
  AssertEquals('PING', $6, Ord(ftPing));
  AssertEquals('GOAWAY', $7, Ord(ftGoAway));
  AssertEquals('WINDOW_UPDATE', $8, Ord(ftWindowUpdate));
  AssertEquals('CONTINUATION', $9, Ord(ftContinuation));
end;

procedure TFramesTest.TestKnownFrameTypes;
begin
  AssertTrue('DATA known', IsKnownFrameType(ftData));
  AssertTrue('CONTINUATION known', IsKnownFrameType(ftContinuation));
  AssertFalse('$a unknown', IsKnownFrameType(FrameTypeOf($a)));
  AssertFalse('$ff unknown', IsKnownFrameType(FrameTypeOf($ff)));
  AssertEquals('name of $a', 'UNKNOWN(10)', FrameTypeName(FrameTypeOf($a)));
end;

procedure TFramesTest.TestFlagWireBits;
begin
  AssertEquals('END_STREAM', $1, FrameFlagsToByte([ffEndStream]));
  AssertEquals('END_HEADERS', $4, FrameFlagsToByte([ffEndHeaders]));
  AssertEquals('ACK', $1, FrameFlagsToByte([ffAck]));
  AssertEquals('PADDED', $8, FrameFlagsToByte([ffPadded]));
  AssertEquals('PRIORITY', $20, FrameFlagsToByte([ffPriority]));
  // END_STREAM and ACK share a wire bit; encoding them together stays $1
  AssertEquals('END_STREAM+ACK', $1,
    FrameFlagsToByte([ffEndStream, ffAck]));
end;

procedure TFramesTest.TestFlagRoundTrip;
var
  Hdr: TFrameHeader;
  Buf: TBytes;
  Once, Twice: TFrameHeader;
begin
  SetLength(Buf, FrameHeaderSize);
  Hdr.Clear;
  Hdr.FrameType := ftHeaders;
  Hdr.Flags := [ffEndStream, ffEndHeaders, ffPadded, ffPriority];
  Hdr.StreamId := 1;
  Hdr.WriteTo(Buf);
  Once := TFrameHeader.ReadFrom(Buf);
  AssertTrue('END_STREAM', ffEndStream in Once.Flags);
  AssertTrue('END_HEADERS', ffEndHeaders in Once.Flags);
  AssertTrue('PADDED', ffPadded in Once.Flags);
  AssertTrue('PRIORITY', ffPriority in Once.Flags);
  // END_STREAM and ACK are the same wire bit, so decoding sets both;
  // consumers disambiguate by frame type. Encoding stays stable.
  Once.WriteTo(Buf);
  Twice := TFrameHeader.ReadFrom(Buf);
  AssertEquals('stable flags', Ord(Byte(Once.Flags)), Ord(Byte(Twice.Flags)));
end;

{ 01.3 }

procedure TFramesTest.TestHeaderRoundTrip;
var
  Hdr: TFrameHeader;
  Buf: TBytes;
  Got: TFrameHeader;
begin
  SetLength(Buf, FrameHeaderSize);
  Hdr.Clear;
  Hdr.Length := 1234;
  Hdr.FrameType := ftWindowUpdate;
  Hdr.Flags := [ffAck];
  Hdr.StreamId := 7;
  Hdr.WriteTo(Buf);
  Got := TFrameHeader.ReadFrom(Buf);
  AssertEquals('length', 1234, Got.Length);
  AssertEquals('type', Ord(ftWindowUpdate), Ord(Got.FrameType));
  AssertTrue('ack', ffAck in Got.Flags);
  AssertEquals('stream', 7, Got.StreamId);
end;

procedure TFramesTest.TestHeaderMasksReservedBit;
var
  Hdr: TFrameHeader;
  Buf: TBytes;
  Got: TFrameHeader;
begin
  SetLength(Buf, FrameHeaderSize);
  Hdr.Clear;
  // the reserved high bit must be stripped on write and never come back
  Hdr.StreamId := $80000001;
  Hdr.WriteTo(Buf);
  AssertEquals('R bit cleared on wire', $00, Buf[5]);
  AssertEquals('stream low byte', $01, Buf[8]);
  Got := TFrameHeader.ReadFrom(Buf);
  AssertEquals('31-bit stream id', $00000001, Got.StreamId);
end;

procedure TFramesTest.TestHeaderLengthIs24Bit;
var
  Hdr: TFrameHeader;
  Buf: TBytes;
  Got: TFrameHeader;
begin
  SetLength(Buf, FrameHeaderSize);
  Hdr.Clear;
  Hdr.Length := $FFFFFF; // max 24-bit value
  Hdr.WriteTo(Buf);
  Got := TFrameHeader.ReadFrom(Buf);
  AssertEquals('24-bit length round-trip', $FFFFFF, Got.Length);
end;

{ 01.4 }

procedure TFramesTest.TestDataFrameRoundTrip;
var
  F, G: TFrame;
begin
  F := BuildDataFrame(1, BytesOf([1, 2, 3]), True);
  G := RoundTrip(F);
  AssertEquals('type', Ord(ftData), Ord(G.Header.FrameType));
  AssertEquals('stream', 1, G.Header.StreamId);
  AssertTrue('end stream', G.IsEndStream);
  AssertEquals('length from payload', 3, G.Header.Length);
  AssertBytesEqual(BytesOf([1, 2, 3]), G.Payload, 'data');
end;

procedure TFramesTest.TestHeadersFrameRoundTrip;
var
  F, G: TFrame;
  Block: TBytes;
begin
  Block := BytesOf([$82, $86, $84]);
  F := BuildHeadersFrame(1, Block, True, True);
  G := RoundTrip(F);
  AssertTrue('end headers', G.IsEndHeaders);
  AssertTrue('end stream', G.IsEndStream);
  AssertBytesEqual(Block, ExtractHeaderBlock(G), 'no padding/priority');
end;

procedure TFramesTest.TestContinuationFrameRoundTrip;
var
  F, G: TFrame;
begin
  F := BuildContinuationFrame(5, BytesOf([$aa, $bb]), True);
  G := RoundTrip(F);
  AssertEquals('type', Ord(ftContinuation), Ord(G.Header.FrameType));
  AssertTrue('end headers', G.IsEndHeaders);
  AssertEquals('stream', 5, G.Header.StreamId);
end;

procedure TFramesTest.TestPriorityFrameRoundTrip;
var
  F, G: TFrame;
  Dep, Weight: LongWord;
  Excl: Boolean;
begin
  F := BuildPriorityFrame(3, 1, 200, True);
  AssertEquals('payload size', 5, Length(F.Payload));
  G := RoundTrip(F);
  ParsePriority(G, Dep, Weight, Excl);
  AssertEquals('depends on', 1, Dep);
  AssertEquals('weight', 200, Weight);
  AssertTrue('exclusive', Excl);
end;

procedure TFramesTest.TestRstStreamFrameRoundTrip;
var
  F, G: TFrame;
  Code: THttp2ErrorCode;
begin
  F := BuildRstStreamFrame(9, ecCancel);
  G := RoundTrip(F);
  ParseRstStream(G, Code);
  AssertEquals('error code', Ord(ecCancel), Ord(Code));
end;

procedure TFramesTest.TestPingFrameRoundTrip;
var
  F, G: TFrame;
  Data: TBytes;
begin
  F := BuildPingFrame(BytesOf([1, 2, 3, 4, 5, 6, 7, 8]), False);
  G := RoundTrip(F);
  Data := ParsePing(G);
  AssertEquals('ping payload', 8, Length(Data));
  AssertEquals('first', 1, Data[0]);
  AssertFalse('not ack', G.IsAck);
  // a short seed must be zero-padded, never over-read
  F := BuildPingFrame(BytesOf([9]), False);
  AssertEquals('always 8 bytes', 8, Length(F.Payload));
  AssertEquals('seeded', 9, F.Payload[0]);
  AssertEquals('padded', 0, F.Payload[1]);
end;

procedure TFramesTest.TestGoAwayFrameRoundTrip;
var
  F, G: TFrame;
  Last: LongWord;
  Code: THttp2ErrorCode;
  Debug: TBytes;
begin
  F := BuildGoAwayFrame(31, ecEnhanceYourCalm, BytesOf([$41, $42]));
  G := RoundTrip(F);
  ParseGoAway(G, Last, Code, Debug);
  AssertEquals('last stream id', 31, Last);
  AssertEquals('error code', Ord(ecEnhanceYourCalm), Ord(Code));
  AssertBytesEqual(BytesOf([$41, $42]), Debug, 'debug data');
end;

procedure TFramesTest.TestWindowUpdateFrameRoundTrip;
var
  F, G: TFrame;
begin
  F := BuildWindowUpdateFrame(1, 65535);
  G := RoundTrip(F);
  AssertEquals('increment', 65535, ParseWindowUpdate(G));
end;

procedure TFramesTest.TestAllFrameTypesRoundTrip;
var
  F, G: TFrame;
begin
  // DATA
  F := BuildDataFrame(1, BytesOf([$01]), False);
  G := RoundTrip(F);
  AssertEquals('DATA type', Ord(ftData), Ord(G.Header.FrameType));
  // HEADERS
  F := BuildHeadersFrame(1, BytesOf([$82]), True, False);
  G := RoundTrip(F);
  AssertEquals('HEADERS type', Ord(ftHeaders), Ord(G.Header.FrameType));
  // PRIORITY
  F := BuildPriorityFrame(1, 0, 16, False);
  G := RoundTrip(F);
  AssertEquals('PRIORITY type', Ord(ftPriority), Ord(G.Header.FrameType));
  // RST_STREAM
  F := BuildRstStreamFrame(1, ecNoError);
  G := RoundTrip(F);
  AssertEquals('RST_STREAM type', Ord(ftRstStream), Ord(G.Header.FrameType));
  // SETTINGS
  F := BuildSettingsFrame(TConnectionSettings.Defaults);
  G := RoundTrip(F);
  AssertEquals('SETTINGS type', Ord(ftSettings), Ord(G.Header.FrameType));
  // SETTINGS ACK
  F := BuildSettingsAck;
  G := RoundTrip(F);
  AssertEquals('SETTINGS ACK payload empty', 0, Length(G.Payload));
  AssertTrue('ACK flag', G.IsAck);
  // PING
  F := BuildPingFrame(BytesOf([0, 0, 0, 0, 0, 0, 0, 1]), True);
  G := RoundTrip(F);
  AssertEquals('PING type', Ord(ftPing), Ord(G.Header.FrameType));
  AssertTrue('PING ack', G.IsAck);
  // GOAWAY
  F := BuildGoAwayFrame(0, ecNoError, nil);
  G := RoundTrip(F);
  AssertEquals('GOAWAY type', Ord(ftGoAway), Ord(G.Header.FrameType));
  // WINDOW_UPDATE
  F := BuildWindowUpdateFrame(0, 100);
  G := RoundTrip(F);
  AssertEquals('WINDOW_UPDATE type', Ord(ftWindowUpdate),
    Ord(G.Header.FrameType));
  // CONTINUATION
  F := BuildContinuationFrame(1, BytesOf([$00]), True);
  G := RoundTrip(F);
  AssertEquals('CONTINUATION type', Ord(ftContinuation),
    Ord(G.Header.FrameType));
end;

procedure TFramesTest.TestPaddedDataExtraction;
var
  F, G: TFrame;
  Payload: TBytes;
begin
  // PADDED DATA: 1 pad-length byte, 3 data bytes, 2 pad bytes
  SetLength(Payload, 6);
  Payload[0] := 2;          // pad length
  Payload[1] := $aa;
  Payload[2] := $bb;
  Payload[3] := $cc;
  Payload[4] := 0;
  Payload[5] := 0;
  F := TFrame.Create(ftData, [ffPadded], 1, Payload);
  G := RoundTrip(F);
  AssertBytesEqual(BytesOf([$aa, $bb, $cc]), ExtractDataPayload(G), 'data');
end;

procedure TFramesTest.TestPaddedHeadersExtraction;
var
  F, G: TFrame;
  Payload: TBytes;
begin
  // PADDED HEADERS without PRIORITY: pad length, 2 header bytes, 1 pad byte
  SetLength(Payload, 4);
  Payload[0] := 1;
  Payload[1] := $82;
  Payload[2] := $86;
  Payload[3] := 0;
  F := TFrame.Create(ftHeaders, [ffPadded, ffEndHeaders], 1, Payload);
  G := RoundTrip(F);
  AssertBytesEqual(BytesOf([$82, $86]), ExtractHeaderBlock(G), 'block');
end;

procedure TFramesTest.TestHeadersPriorityBlockExtraction;
var
  F, G: TFrame;
  Payload: TBytes;
begin
  // HEADERS with PRIORITY flag: 5-byte priority block then header bytes
  SetLength(Payload, 7);
  Payload[0] := 0; Payload[1] := 0; Payload[2] := 0; Payload[3] := 3;
  Payload[4] := 16;         // weight
  Payload[5] := $82;
  Payload[6] := $84;
  F := TFrame.Create(ftHeaders, [ffPriority, ffEndHeaders], 1, Payload);
  G := RoundTrip(F);
  AssertBytesEqual(BytesOf([$82, $84]), ExtractHeaderBlock(G), 'block');
end;

procedure TFramesTest.TestHeadersWithoutPriorityFlagKeepsBlock;
var
  F, G: TFrame;
  Payload: TBytes;
begin
  // without the PRIORITY flag the first 5 bytes are part of the header block
  SetLength(Payload, 5);
  Payload[0] := $01; Payload[1] := $02; Payload[2] := $03;
  Payload[3] := $04; Payload[4] := $05;
  F := TFrame.Create(ftHeaders, [ffEndHeaders], 1, Payload);
  G := RoundTrip(F);
  AssertBytesEqual(Payload, ExtractHeaderBlock(G), 'whole block preserved');
end;

procedure TFramesTest.TestBadPaddingRaises;
begin
  // pad length claims more bytes than the payload holds
  try
    ExtractDataPayload(TFrame.Create(ftData, [ffPadded], 1, BytesOf([$09, $00])));
    Fail('expected EHttpProtocolError for over-long padding');
  except
    on E: EHttpProtocolError do
      ; // expected
  end;
  // PADDED with an empty payload has nowhere to store the pad length
  try
    ExtractDataPayload(TFrame.Create(ftData, [ffPadded], 1, nil));
    Fail('expected EHttpProtocolError for missing pad length');
  except
    on E: EHttpProtocolError do
      ; // expected
  end;
end;

{ 01.5 }

procedure TFramesTest.TestReadWriteStreamRoundTrip;
var
  S: TMemoryStream;
  F, G: TFrame;
begin
  S := TMemoryStream.Create;
  try
    F := BuildDataFrame(1, BytesOf([$de, $ad, $be, $ef]), True);
    WriteFrame(S, F);
    // 9 byte header + 4 byte payload
    AssertEquals('wire size', FrameHeaderSize + 4, S.Size);
    S.Position := 0;
    G := ReadFrame(S);
    AssertBytesEqual(F.Payload, G.Payload, 'payload');
    AssertEquals('length', 4, G.Header.Length);
    AssertEquals('stream', 1, G.Header.StreamId);
  finally
    S.Free;
  end;
end;

procedure TFramesTest.TestOversizedInboundFrameRaises;
var
  S: TMemoryStream;
  Hdr: TBytes;
begin
  S := TMemoryStream.Create;
  try
    SetLength(Hdr, FrameHeaderSize);
    // header advertising 20000 bytes while the limit is the 16384 default
    Hdr[0] := 0; Hdr[1] := $4e; Hdr[2] := $20;   // 20000
    Hdr[3] := Ord(ftData);
    Hdr[4] := 0;
    Hdr[5] := 0; Hdr[6] := 0; Hdr[7] := 0; Hdr[8] := 1;
    S.WriteBuffer(Hdr[0], FrameHeaderSize);
    S.Position := 0;
    try
      ReadFrame(S);
      Fail('expected EHttpProtocolError for oversized frame');
    except
      on E: EHttpProtocolError do
        AssertEquals('FRAME_SIZE_ERROR', Ord(ecFrameSizeError),
          Ord(E.ErrorCode));
    end;
  finally
    S.Free;
  end;
end;

procedure TFramesTest.TestShortHeaderRaisesConnectionClosed;
var
  S: TMemoryStream;
  Partial: TBytes;
begin
  S := TMemoryStream.Create;
  try
    Partial := BytesOf([0, 0, 1]);
    S.WriteBuffer(Partial[0], Length(Partial));
    S.Position := 0;
    try
      ReadFrame(S);
      Fail('expected EHttpConnectionClosed for a truncated header');
    except
      on E: EHttpConnectionClosed do
        ; // expected
    end;
  finally
    S.Free;
  end;
end;

procedure TFramesTest.TestValidateRejectsZeroStreamId;
begin
  try
    ValidateFrame(TFrame.Create(ftData, [], 0, BytesOf([1])));
    Fail('expected EHttpProtocolError for DATA on stream 0');
  except
    on E: EHttpProtocolError do
      ; // expected
  end;
  try
    ValidateFrame(TFrame.Create(ftPing, [], 4, BytesOf([0, 0, 0, 0, 0, 0, 0, 1])));
    Fail('expected EHttpProtocolError for PING on a non-zero stream');
  except
    on E: EHttpProtocolError do
      ; // expected
  end;
end;

procedure TFramesTest.TestValidateRejectsBadSettingsPayload;
begin
  // SETTINGS ACK must have an empty payload
  try
    ValidateFrame(TFrame.Create(ftSettings, [ffAck], 0, BytesOf([0, 0, 0, 0, 0, 0])));
    Fail('expected EHttpProtocolError for non-empty SETTINGS ACK');
  except
    on E: EHttpProtocolError do
      ; // expected
  end;
  // a non-ACK payload length must be a multiple of 6
  try
    ValidateFrame(TFrame.Create(ftSettings, [], 0, BytesOf([0, 1, 2])));
    Fail('expected EHttpProtocolError for misaligned SETTINGS payload');
  except
    on E: EHttpProtocolError do
      ; // expected
  end;
end;

procedure TFramesTest.TestValidateIgnoresUnknownFrameType;
begin
  // unknown frame types must be tolerated, never rejected
  ValidateFrame(TFrame.Create(FrameTypeOf($fe), [], 0, BytesOf([1, 2, 3])));
  ValidateFrame(TFrame.Create(FrameTypeOf($a), [ffAck], 7, nil));
end;

{ 01.6 }

procedure TFramesTest.TestSettingsRoundTrip;
var
  S, Got: TConnectionSettings;
begin
  S := TConnectionSettings.Defaults;
  S.HeaderTableSize := 8192;
  S.EnablePush := False;
  S.MaxConcurrentStreams := 42;
  S.InitialWindowSize := 100000;
  S.MaxFrameSize := 32768;
  S.MaxHeaderListSize := 65536;
  Got := TConnectionSettings.Decode(S.Encode);
  AssertEquals('header table', 8192, Got.HeaderTableSize);
  AssertFalse('enable push', Got.EnablePush);
  AssertEquals('max concurrent', 42, Got.MaxConcurrentStreams);
  AssertEquals('initial window', 100000, Got.InitialWindowSize);
  AssertEquals('max frame size', 32768, Got.MaxFrameSize);
  AssertEquals('max header list', 65536, Got.MaxHeaderListSize);
end;

procedure TFramesTest.TestSettingsUnknownIdIgnored;
var
  Payload: TBytes;
  Got: TConnectionSettings;
begin
  // id 99 (unknown) plus a valid id 3 (MAX_CONCURRENT_STREAMS = 5)
  SetLength(Payload, 12);
  Payload[0] := 0; Payload[1] := 99; Payload[2] := 0; Payload[3] := 0;
  Payload[4] := 0;  Payload[5] := 0;
  Payload[6] := 0; Payload[7] := 3; Payload[8] := 0; Payload[9] := 0;
  Payload[10] := 0; Payload[11] := 5;
  Got := TConnectionSettings.Decode(Payload);
  AssertEquals('unknown ignored, known applied', 5, Got.MaxConcurrentStreams);
end;

procedure TFramesTest.TestSettingsEnablePushValidation;
var
  Payload: TBytes;
begin
  // ENABLE_PUSH = 2 is illegal
  SetLength(Payload, 6);
  Payload[0] := 0; Payload[1] := 2; Payload[2] := 0; Payload[3] := 0;
  Payload[4] := 0; Payload[5] := 2;
  try
    TConnectionSettings.Decode(Payload);
    Fail('expected EHttpProtocolError for ENABLE_PUSH > 1');
  except
    on E: EHttpProtocolError do
      ; // expected
  end;
end;

procedure TFramesTest.TestDefaultsDisablePush;
var
  S: TConnectionSettings;
  Encoded: TBytes;
begin
  S := TConnectionSettings.Defaults;
  AssertFalse('default advertises ENABLE_PUSH = 0', S.EnablePush);
  // and the value really reaches the wire: entry 1 (id 2) must be zero
  Encoded := S.Encode;
  AssertEquals('ENABLE_PUSH id high', 0, Encoded[6]);
  AssertEquals('ENABLE_PUSH id low', SettingEnablePush, Encoded[7]);
  AssertEquals('ENABLE_PUSH value 0', 0, Encoded[11]);
end;

procedure TFramesTest.TestSettingsMaxFrameSizeValidation;
var
  Payload: TBytes;
begin
  // MAX_FRAME_SIZE below 16384 is illegal
  SetLength(Payload, 6);
  Payload[0] := 0; Payload[1] := 5; Payload[2] := 0; Payload[3] := 0;
  Payload[4] := $40; Payload[5] := $00;  // 16384 = lower bound, valid
  try
    TConnectionSettings.Decode(Payload);
  except
    on E: Exception do
      Fail('16384 is the valid lower bound, got ' + E.Message);
  end;
  // 16000 is below the lower bound
  Payload[4] := $3e; Payload[5] := $80;
  try
    TConnectionSettings.Decode(Payload);
    Fail('expected EHttpProtocolError for MAX_FRAME_SIZE too small');
  except
    on E: EHttpProtocolError do
      ; // expected
  end;
end;

initialization
  RegisterTest(TFramesTest);
end.
