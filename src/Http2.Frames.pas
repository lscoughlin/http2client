/// HTTP/2 frame types, header and payload records (plan story S01)
// - this unit is part of the http2client project (see doc/design/protocol.md)
// - freezes the wire format used by every other unit
unit Http2.Frames;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, Http2.Errors;

const
  /// every frame starts with a 9-byte header
  FrameHeaderSize = 9;
  /// SETTINGS_* payload entries are 6 bytes (2-byte id + 4-byte value)
  SettingsEntrySize = 6;
  /// RFC 7540 default SETTINGS_MAX_FRAME_SIZE
  DefaultMaxFrameSize = 16384;
  /// SETTINGS_MAX_FRAME_SIZE lower bound
  MinAllowedFrameSize = 16384;
  /// SETTINGS_MAX_FRAME_SIZE upper bound (24-bit)
  MaxAllowedFrameSize = 16777215;
  /// 31-bit stream-id mask (reserved bit cleared)
  MaxStreamId = $7FFFFFFF;

type
  TFrameType = (
    ftData           = $0,
    ftHeaders        = $1,
    ftPriority       = $2,
    ftRstStream      = $3,
    ftSettings       = $4,
    ftPushPromise    = $5,
    ftPing           = $6,
    ftGoAway         = $7,
    ftWindowUpdate   = $8,
    ftContinuation   = $9);

  /// bit flags. The ordinal order here is NOT the wire bit value: the wire
  /// values collide across frame types by design (PADDED=$8, PRIORITY=$20,
  /// END_STREAM=ACK=$1, END_HEADERS=$4). See FlagBit for the mapping.
  TFrameFlag = (ffEndStream, ffEndHeaders, ffAck, ffPadded, ffPriority);
  TFrameFlags = set of TFrameFlag;

  TFrameHeader = record
    Length: LongWord;        // 24 bits on the wire
    FrameType: TFrameType;
    Flags: TFrameFlags;
    StreamId: LongWord;      // reserved bit masked off
    procedure Clear;
    /// serialize into the first 9 bytes of ABuffer
    procedure WriteTo(const ABuffer: TBytes);
    /// parse the first 9 bytes of ABuffer
    class function ReadFrom(const ABuffer: TBytes): TFrameHeader; static;
  end;

  TFrame = record
    Header: TFrameHeader;
    Payload: TBytes;
    /// build a frame, filling Header.Length from Payload
    class function Create(const AFrameType: TFrameType; const AFlags: TFrameFlags;
      const AStreamId: LongWord; const APayload: TBytes): TFrame; static;
    function DataLength: LongWord;
    function IsEndStream: Boolean;
    function IsEndHeaders: Boolean;
    function IsAck: Boolean;
    function IsPadded: Boolean;
    /// HEADERS-only: the PRIORITY flag ($20), which adds a 5-byte block
    function IsPriority: Boolean;
  end;

  TConnectionSettings = record
    HeaderTableSize: LongWord;       // SETTINGS_HEADER_TABLE_SIZE (id 1)
    EnablePush: Boolean;             // SETTINGS_ENABLE_PUSH (id 2)
    MaxConcurrentStreams: LongWord;  // SETTINGS_MAX_CONCURRENT_STREAMS (id 3)
    InitialWindowSize: LongWord;     // SETTINGS_INITIAL_WINDOW_SIZE (id 4)
    MaxFrameSize: LongWord;          // SETTINGS_MAX_FRAME_SIZE (id 5)
    MaxHeaderListSize: LongWord;     // SETTINGS_MAX_HEADER_LIST_SIZE (id 6)
    class function Defaults: TConnectionSettings; static;
    /// serialize the six settings as SETTINGS payload entries
    function Encode: TBytes;
    /// parse SETTINGS payload entries (unknown ids are ignored)
    class function Decode(const APayload: TBytes): TConnectionSettings; static;
  end;

const
  SettingHeaderTableSize      = 1;
  SettingEnablePush           = 2;
  SettingMaxConcurrentStreams = 3;
  SettingInitialWindowSize    = 4;
  SettingMaxFrameSize         = 5;
  SettingMaxHeaderListSize    = 6;

/// wire byte for a flag set (public so tests can pin the mapping)
function FrameFlagsToByte(const AFlags: TFrameFlags): Byte;
/// stable name for a frame type (observability / error messages)
function FrameTypeName(const AFrameType: TFrameType): string;
/// is this a frame type defined in RFC 7540?
function IsKnownFrameType(const AFrameType: TFrameType): Boolean;

{ ---- payload builders ---- }

function BuildDataFrame(const AStreamId: LongWord; const AData: TBytes;
  const AEndStream: Boolean): TFrame;
function BuildHeadersFrame(const AStreamId: LongWord; const AHeaderBlock: TBytes;
  const AEndHeaders, AEndStream: Boolean): TFrame;
function BuildContinuationFrame(const AStreamId: LongWord;
  const AHeaderBlock: TBytes; const AEndHeaders: Boolean): TFrame;
function BuildPriorityFrame(const AStreamId, ADependsOn, AWeight: LongWord;
  const AExclusive: Boolean): TFrame;
function BuildRstStreamFrame(const AStreamId: LongWord;
  const AErrorCode: THttp2ErrorCode): TFrame;
function BuildSettingsFrame(const ASettings: TConnectionSettings): TFrame;
function BuildSettingsAck: TFrame;
function BuildPingFrame(const AData: TBytes; const AAck: Boolean): TFrame;
function BuildGoAwayFrame(const ALastStreamId: LongWord;
  const AErrorCode: THttp2ErrorCode; const ADebug: TBytes): TFrame;
function BuildWindowUpdateFrame(const AStreamId, AIncrement: LongWord): TFrame;

{ ---- payload parsers (raise EHttpProtocolError on malformed input) ---- }

procedure ParseRstStream(const AFrame: TFrame; out AErrorCode: THttp2ErrorCode);
procedure ParseGoAway(const AFrame: TFrame; out ALastStreamId: LongWord;
  out AErrorCode: THttp2ErrorCode; out ADebug: TBytes);
function ParseWindowUpdate(const AFrame: TFrame): LongWord;
function ParsePing(const AFrame: TFrame): TBytes;
procedure ParsePriority(const AFrame: TFrame; out ADependsOn, AWeight: LongWord;
  out AExclusive: Boolean);
/// the header block of a HEADERS/CONTINUATION frame with padding and the
/// optional priority fields removed
function ExtractHeaderBlock(const AFrame: TFrame): TBytes;
/// the DATA payload with padding removed
function ExtractDataPayload(const AFrame: TFrame): TBytes;
/// how many header-list octets a HEADERS frame may carry (block minus padding)
function HeaderBlockOffset(const AFrame: TFrame): Integer;

{ ---- stream I/O ---- }

/// read one frame; raises EHttpConnectionClosed on a short header/payload
function ReadFrame(const AStream: TStream;
  const AMaxFrameSize: LongWord = DefaultMaxFrameSize): TFrame;
/// write one frame; Header.Length is set from Payload before writing
procedure WriteFrame(const AStream: TStream; const AFrame: TFrame);
/// structural validation (stream-id rules, frame size, payload sizes)
procedure ValidateFrame(const AFrame: TFrame;
  const AMaxFrameSize: LongWord = DefaultMaxFrameSize);

implementation

{ big-endian helpers }

function ReadUInt24BE(const ABuffer: TBytes; const AOffset: Integer): LongWord;
begin
  Result := (LongWord(ABuffer[AOffset]) shl 16) or
            (LongWord(ABuffer[AOffset + 1]) shl 8) or
             LongWord(ABuffer[AOffset + 2]);
end;

procedure WriteUInt24BE(const ABuffer: TBytes; const AOffset: Integer;
  const AValue: LongWord);
begin
  ABuffer[AOffset]     := (AValue shr 16) and $FF;
  ABuffer[AOffset + 1] := (AValue shr 8) and $FF;
  ABuffer[AOffset + 2] := AValue and $FF;
end;

function ReadUInt32BE(const ABuffer: TBytes; const AOffset: Integer): LongWord;
begin
  Result := (LongWord(ABuffer[AOffset]) shl 24) or
            (LongWord(ABuffer[AOffset + 1]) shl 16) or
            (LongWord(ABuffer[AOffset + 2]) shl 8) or
             LongWord(ABuffer[AOffset + 3]);
end;

procedure WriteUInt32BE(const ABuffer: TBytes; const AOffset: Integer;
  const AValue: LongWord);
begin
  ABuffer[AOffset]     := (AValue shr 24) and $FF;
  ABuffer[AOffset + 1] := (AValue shr 16) and $FF;
  ABuffer[AOffset + 2] := (AValue shr 8) and $FF;
  ABuffer[AOffset + 3] := AValue and $FF;
end;

function FlagBit(const AFlag: TFrameFlag): Byte;
begin
  // explicit wire values; ffEndStream and ffAck intentionally share $1
  case AFlag of
    ffEndStream:  Result := $1;
    ffEndHeaders: Result := $4;
    ffAck:        Result := $1;
    ffPadded:     Result := $8;
    ffPriority:   Result := $20;
  else
    Result := 0;
  end;
end;

function FlagSet(const AFlags: TFrameFlags; const AFlag: TFrameFlag): Boolean;
begin
  // semantic membership; the wire encoding is handled by FlagBit
  Result := AFlag in AFlags;
end;

function FlagsFromByte(const AValue: Byte): TFrameFlags;
var
  F: TFrameFlag;
begin
  Result := [];
  for F := Low(TFrameFlag) to High(TFrameFlag) do
    if AValue and FlagBit(F) <> 0 then
      Include(Result, F);
end;

function FlagsToByte(const AFlags: TFrameFlags): Byte;
var
  F: TFrameFlag;
begin
  Result := 0;
  for F := Low(TFrameFlag) to High(TFrameFlag) do
    if F in AFlags then
      Result := Result or FlagBit(F);
end;

{ TFrameHeader }

procedure TFrameHeader.Clear;
begin
  Length := 0;
  FrameType := ftData;
  Flags := [];
  StreamId := 0;
end;

procedure TFrameHeader.WriteTo(const ABuffer: TBytes);
begin
  WriteUInt24BE(ABuffer, 0, Length and $FFFFFF);
  ABuffer[3] := Ord(FrameType);
  ABuffer[4] := FlagsToByte(Flags);
  WriteUInt32BE(ABuffer, 5, StreamId and MaxStreamId);
end;

class function TFrameHeader.ReadFrom(const ABuffer: TBytes): TFrameHeader;
begin
  Result.Length := ReadUInt24BE(ABuffer, 0);
  Result.FrameType := TFrameType(ABuffer[3]);
  Result.Flags := FlagsFromByte(ABuffer[4]);
  Result.StreamId := ReadUInt32BE(ABuffer, 5) and MaxStreamId;
end;

{ TFrame }

class function TFrame.Create(const AFrameType: TFrameType;
  const AFlags: TFrameFlags; const AStreamId: LongWord;
  const APayload: TBytes): TFrame;
begin
  Result.Header.Clear;
  Result.Header.FrameType := AFrameType;
  Result.Header.Flags := AFlags;
  Result.Header.StreamId := AStreamId and MaxStreamId;
  Result.Payload := APayload;
  Result.Header.Length := Length(APayload);
end;

function TFrame.DataLength: LongWord;
begin
  Result := Length(Payload);
end;

function TFrame.IsEndStream: Boolean;
begin
  Result := FlagSet(Header.Flags, ffEndStream);
end;

function TFrame.IsEndHeaders: Boolean;
begin
  Result := FlagSet(Header.Flags, ffEndHeaders);
end;

function TFrame.IsAck: Boolean;
begin
  Result := FlagSet(Header.Flags, ffAck);
end;

function TFrame.IsPadded: Boolean;
begin
  Result := FlagSet(Header.Flags, ffPadded);
end;

function TFrame.IsPriority: Boolean;
begin
  Result := FlagSet(Header.Flags, ffPriority);
end;

{ TConnectionSettings }

class function TConnectionSettings.Defaults: TConnectionSettings;
begin
  Result.HeaderTableSize := 4096;
  Result.EnablePush := True;
  Result.MaxConcurrentStreams := 100;   // matches MaxStreamsPerConnection
  Result.InitialWindowSize := 65535;
  Result.MaxFrameSize := DefaultMaxFrameSize;
  Result.MaxHeaderListSize := MaxStreamId;  // effectively unlimited
end;

function TConnectionSettings.Encode: TBytes;
var
  Count, I: Integer;
  Ids: array[0..5] of Word;
  Vals: array[0..5] of LongWord;
begin
  Result := nil;
  Ids[0] := SettingHeaderTableSize;      Vals[0] := HeaderTableSize;
  Ids[1] := SettingEnablePush;           Vals[1] := Ord(EnablePush);
  Ids[2] := SettingMaxConcurrentStreams; Vals[2] := MaxConcurrentStreams;
  Ids[3] := SettingInitialWindowSize;    Vals[3] := InitialWindowSize;
  Ids[4] := SettingMaxFrameSize;         Vals[4] := MaxFrameSize;
  Ids[5] := SettingMaxHeaderListSize;    Vals[5] := MaxHeaderListSize;
  Count := Length(Ids);
  SetLength(Result, Count * SettingsEntrySize);
  for I := 0 to Count - 1 do
  begin
    Result[I * SettingsEntrySize]     := (Ids[I] shr 8) and $FF;
    Result[I * SettingsEntrySize + 1] := Ids[I] and $FF;
    WriteUInt32BE(Result, I * SettingsEntrySize + 2, Vals[I]);
  end;
end;

class function TConnectionSettings.Decode(const APayload: TBytes): TConnectionSettings;
var
  Ofs, Id: Integer;
  Value: LongWord;
begin
  Result := TConnectionSettings.Defaults;
  if Length(APayload) mod SettingsEntrySize <> 0 then
    raise EHttpProtocolError.Create(
      'SETTINGS payload length is not a multiple of 6', ecFrameSizeError);
  Ofs := 0;
  while Ofs + SettingsEntrySize <= Length(APayload) do
  begin
    Id := (Integer(APayload[Ofs]) shl 8) or APayload[Ofs + 1];
    Value := ReadUInt32BE(APayload, Ofs + 2);
    case Id of
      SettingHeaderTableSize:
        Result.HeaderTableSize := Value;
      SettingEnablePush:
        begin
          if Value > 1 then
            raise EHttpProtocolError.Create(
              'SETTINGS_ENABLE_PUSH must be 0 or 1', ecProtocolError);
          Result.EnablePush := Value = 1;
        end;
      SettingMaxConcurrentStreams:
        Result.MaxConcurrentStreams := Value;
      SettingInitialWindowSize:
        begin
          if Value > MaxStreamId then
            raise EHttpProtocolError.Create(
              'SETTINGS_INITIAL_WINDOW_SIZE exceeds 2^31-1', ecFlowControlError);
          Result.InitialWindowSize := Value;
        end;
      SettingMaxFrameSize:
        begin
          if (Value < MinAllowedFrameSize) or (Value > MaxAllowedFrameSize) then
            raise EHttpProtocolError.Create(
              'SETTINGS_MAX_FRAME_SIZE out of range', ecProtocolError);
          Result.MaxFrameSize := Value;
        end;
      SettingMaxHeaderListSize:
        Result.MaxHeaderListSize := Value;
    else
      ; // unknown settings must be ignored (RFC 7540 section 6.5.2)
    end;
    Inc(Ofs, SettingsEntrySize);
  end;
end;

function FrameFlagsToByte(const AFlags: TFrameFlags): Byte;
begin
  Result := FlagsToByte(AFlags);
end;

{ names }

function FrameTypeName(const AFrameType: TFrameType): string;
begin
  case AFrameType of
    ftData:         Result := 'DATA';
    ftHeaders:      Result := 'HEADERS';
    ftPriority:     Result := 'PRIORITY';
    ftRstStream:    Result := 'RST_STREAM';
    ftSettings:     Result := 'SETTINGS';
    ftPushPromise:  Result := 'PUSH_PROMISE';
    ftPing:         Result := 'PING';
    ftGoAway:       Result := 'GOAWAY';
    ftWindowUpdate: Result := 'WINDOW_UPDATE';
    ftContinuation: Result := 'CONTINUATION';
  else
    Result := 'UNKNOWN(' + IntToStr(Ord(AFrameType)) + ')';
  end;
end;

function IsKnownFrameType(const AFrameType: TFrameType): Boolean;
begin
  Result := Ord(AFrameType) <= Ord(ftContinuation);
end;

{ payload builders }

function BuildDataFrame(const AStreamId: LongWord; const AData: TBytes;
  const AEndStream: Boolean): TFrame;
var
  Flags: TFrameFlags;
begin
  Flags := [];
  if AEndStream then
    Include(Flags, ffEndStream);
  Result := TFrame.Create(ftData, Flags, AStreamId, AData);
end;

function BuildHeadersFrame(const AStreamId: LongWord; const AHeaderBlock: TBytes;
  const AEndHeaders, AEndStream: Boolean): TFrame;
var
  Flags: TFrameFlags;
begin
  Flags := [];
  if AEndHeaders then
    Include(Flags, ffEndHeaders);
  if AEndStream then
    Include(Flags, ffEndStream);
  Result := TFrame.Create(ftHeaders, Flags, AStreamId, AHeaderBlock);
end;

function BuildContinuationFrame(const AStreamId: LongWord;
  const AHeaderBlock: TBytes; const AEndHeaders: Boolean): TFrame;
var
  Flags: TFrameFlags;
begin
  Flags := [];
  if AEndHeaders then
    Include(Flags, ffEndHeaders);
  Result := TFrame.Create(ftContinuation, Flags, AStreamId, AHeaderBlock);
end;

function BuildPriorityFrame(const AStreamId, ADependsOn, AWeight: LongWord;
  const AExclusive: Boolean): TFrame;
var
  Payload: TBytes;
  Dep: LongWord;
begin
  SetLength(Payload, 5);
  Dep := ADependsOn and MaxStreamId;
  if AExclusive then
    Dep := Dep or $80000000;
  WriteUInt32BE(Payload, 0, Dep);
  Payload[4] := AWeight and $FF;
  Result := TFrame.Create(ftPriority, [], AStreamId, Payload);
end;

function BuildRstStreamFrame(const AStreamId: LongWord;
  const AErrorCode: THttp2ErrorCode): TFrame;
var
  Payload: TBytes;
begin
  SetLength(Payload, 4);
  WriteUInt32BE(Payload, 0, LongWord(Ord(AErrorCode)));
  Result := TFrame.Create(ftRstStream, [], AStreamId, Payload);
end;

function BuildSettingsFrame(const ASettings: TConnectionSettings): TFrame;
begin
  Result := TFrame.Create(ftSettings, [], 0, ASettings.Encode);
end;

function BuildSettingsAck: TFrame;
begin
  Result := TFrame.Create(ftSettings, [ffAck], 0, nil);
end;

function BuildPingFrame(const AData: TBytes; const AAck: Boolean): TFrame;
var
  Payload: TBytes;
  Flags: TFrameFlags;
  N: Integer;
begin
  SetLength(Payload, 8);
  N := Length(AData);
  if N > 8 then
    N := 8;
  if N > 0 then
    Move(AData[0], Payload[0], N);
  Flags := [];
  if AAck then
    Include(Flags, ffAck);
  Result := TFrame.Create(ftPing, Flags, 0, Payload);
end;

function BuildGoAwayFrame(const ALastStreamId: LongWord;
  const AErrorCode: THttp2ErrorCode; const ADebug: TBytes): TFrame;
var
  Payload: TBytes;
begin
  SetLength(Payload, 8 + Length(ADebug));
  WriteUInt32BE(Payload, 0, ALastStreamId and MaxStreamId);
  WriteUInt32BE(Payload, 4, LongWord(Ord(AErrorCode)));
  if Length(ADebug) > 0 then
    Move(ADebug[0], Payload[8], Length(ADebug));
  Result := TFrame.Create(ftGoAway, [], 0, Payload);
end;

function BuildWindowUpdateFrame(const AStreamId, AIncrement: LongWord): TFrame;
var
  Payload: TBytes;
begin
  SetLength(Payload, 4);
  WriteUInt32BE(Payload, 0, AIncrement and MaxStreamId);
  Result := TFrame.Create(ftWindowUpdate, [], AStreamId, Payload);
end;

{ payload parsers }

procedure ParseRstStream(const AFrame: TFrame; out AErrorCode: THttp2ErrorCode);
begin
  if Length(AFrame.Payload) <> 4 then
    raise EHttpProtocolError.Create('RST_STREAM payload must be 4 bytes',
      ecFrameSizeError);
  AErrorCode := THttp2ErrorCode(ReadUInt32BE(AFrame.Payload, 0));
end;

procedure ParseGoAway(const AFrame: TFrame; out ALastStreamId: LongWord;
  out AErrorCode: THttp2ErrorCode; out ADebug: TBytes);
begin
  if Length(AFrame.Payload) < 8 then
    raise EHttpProtocolError.Create('GOAWAY payload must be at least 8 bytes',
      ecFrameSizeError);
  ALastStreamId := ReadUInt32BE(AFrame.Payload, 0) and MaxStreamId;
  AErrorCode := THttp2ErrorCode(ReadUInt32BE(AFrame.Payload, 4));
  SetLength(ADebug, Length(AFrame.Payload) - 8);
  if Length(ADebug) > 0 then
    Move(AFrame.Payload[8], ADebug[0], Length(ADebug));
end;

function ParseWindowUpdate(const AFrame: TFrame): LongWord;
begin
  if Length(AFrame.Payload) <> 4 then
    raise EHttpProtocolError.Create('WINDOW_UPDATE payload must be 4 bytes',
      ecFrameSizeError);
  Result := ReadUInt32BE(AFrame.Payload, 0) and MaxStreamId;
  if Result = 0 then
    raise EHttpProtocolError.Create('WINDOW_UPDATE increment must be non-zero',
      ecProtocolError);
end;

function ParsePing(const AFrame: TFrame): TBytes;
begin
  if Length(AFrame.Payload) <> 8 then
    raise EHttpProtocolError.Create('PING payload must be 8 bytes',
      ecFrameSizeError);
  Result := AFrame.Payload;
end;

procedure ParsePriority(const AFrame: TFrame; out ADependsOn, AWeight: LongWord;
  out AExclusive: Boolean);
var
  Raw: LongWord;
begin
  if Length(AFrame.Payload) <> 5 then
    raise EHttpProtocolError.Create('PRIORITY payload must be 5 bytes',
      ecFrameSizeError);
  Raw := ReadUInt32BE(AFrame.Payload, 0);
  AExclusive := Raw and $80000000 <> 0;
  ADependsOn := Raw and MaxStreamId;
  AWeight := AFrame.Payload[4];
end;

function HeaderBlockOffset(const AFrame: TFrame): Integer;
var
  PadLen: Integer;
begin
  Result := 0;
  if AFrame.IsPadded then
  begin
    if Length(AFrame.Payload) < 1 then
      raise EHttpProtocolError.Create('padded frame has no pad length',
        ecProtocolError);
    PadLen := AFrame.Payload[0];
    Inc(Result);
    if Length(AFrame.Payload) < Result + PadLen then
      raise EHttpProtocolError.Create('padding exceeds frame payload size',
        ecProtocolError);
  end;
  // HEADERS may carry a 5-byte priority block before the header block,
  // present only when the PRIORITY ($20) flag is set
  if (AFrame.Header.FrameType = ftHeaders) and AFrame.IsPriority then
    Inc(Result, 5);
  if Result > Length(AFrame.Payload) then
    raise EHttpProtocolError.Create('frame payload too short for its fields',
      ecProtocolError);
end;

function StripPadding(const AFrame: TFrame; const AOffset: Integer): TBytes;
var
  PadLen, EndOfs: Integer;
begin
  Result := nil;
  EndOfs := Length(AFrame.Payload);
  if AFrame.IsPadded then
  begin
    if EndOfs < 1 then
      raise EHttpProtocolError.Create('padded frame has no pad length',
        ecProtocolError);
    PadLen := AFrame.Payload[0];
    Dec(EndOfs, PadLen);
  end;
  if EndOfs < AOffset then
    raise EHttpProtocolError.Create('frame payload shorter than its padding',
      ecProtocolError);
  SetLength(Result, EndOfs - AOffset);
  if Length(Result) > 0 then
    Move(AFrame.Payload[AOffset], Result[0], Length(Result));
end;

function ExtractHeaderBlock(const AFrame: TFrame): TBytes;
var
  Ofs: Integer;
  PadLen: Integer;
begin
  Ofs := 0;
  if AFrame.IsPadded then
  begin
    if Length(AFrame.Payload) < 1 then
      raise EHttpProtocolError.Create('padded frame has no pad length',
        ecProtocolError);
    PadLen := AFrame.Payload[0];
    Inc(Ofs);
    if Length(AFrame.Payload) < Ofs + PadLen then
      raise EHttpProtocolError.Create('padding exceeds frame payload size',
        ecProtocolError);
  end;
  if (AFrame.Header.FrameType = ftHeaders) and AFrame.IsPriority then
  begin
    if Length(AFrame.Payload) < Ofs + 5 then
      raise EHttpProtocolError.Create('HEADERS priority block truncated',
        ecProtocolError);
    Inc(Ofs, 5);
  end;
  Result := StripPadding(AFrame, Ofs);
end;

function ExtractDataPayload(const AFrame: TFrame): TBytes;
var
  Ofs: Integer;
begin
  Ofs := 0;
  if AFrame.IsPadded then
    Ofs := 1;
  Result := StripPadding(AFrame, Ofs);
end;

{ stream I/O }

procedure ReadExact(const AStream: TStream; var ABuffer; const ACount: Integer;
  const AWhat: string);
var
  Got, N: Integer;
  P: PByte;
begin
  P := @ABuffer;
  Got := 0;
  while Got < ACount do
  begin
    N := AStream.Read(P[Got], ACount - Got);
    if N <= 0 then
      raise EHttpConnectionClosed.Create('connection closed while reading ' +
        AWhat);
    Inc(Got, N);
  end;
end;

function ReadFrame(const AStream: TStream; const AMaxFrameSize: LongWord): TFrame;
var
  Hdr: TBytes;
begin
  SetLength(Hdr, FrameHeaderSize);
  ReadExact(AStream, Hdr[0], FrameHeaderSize, 'frame header');
  Result.Header := TFrameHeader.ReadFrom(Hdr);
  if Result.Header.Length > AMaxFrameSize then
    raise EHttpProtocolError.Create(Format(
      'frame length %d exceeds SETTINGS_MAX_FRAME_SIZE %d',
      [Result.Header.Length, AMaxFrameSize]), ecFrameSizeError);
  SetLength(Result.Payload, Result.Header.Length);
  if Result.Header.Length > 0 then
    ReadExact(AStream, Result.Payload[0], Result.Header.Length, 'frame payload');
end;

procedure WriteFrame(const AStream: TStream; const AFrame: TFrame);
var
  Hdr: TBytes;
  H: TFrameHeader;
begin
  H := AFrame.Header;
  H.Length := Length(AFrame.Payload);
  SetLength(Hdr, FrameHeaderSize);
  H.WriteTo(Hdr);
  AStream.WriteBuffer(Hdr[0], FrameHeaderSize);
  if Length(AFrame.Payload) > 0 then
    AStream.WriteBuffer(AFrame.Payload[0], Length(AFrame.Payload));
end;

procedure ValidateFrame(const AFrame: TFrame; const AMaxFrameSize: LongWord);
var
  Len: Integer;
  FT: TFrameType;
begin
  Len := Length(AFrame.Payload);
  FT := AFrame.Header.FrameType;
  if LongWord(Len) > AMaxFrameSize then
    raise EHttpProtocolError.Create(Format('frame payload %d exceeds max %d',
      [Len, AMaxFrameSize]), ecFrameSizeError);
  case FT of
    ftData, ftHeaders:
      if AFrame.Header.StreamId = 0 then
        raise EHttpProtocolError.Create(
          FrameTypeName(FT) + ' must not use stream 0', ecProtocolError);
    ftRstStream, ftPriority:
      begin
        if AFrame.Header.StreamId = 0 then
          raise EHttpProtocolError.Create(
            FrameTypeName(FT) + ' must not use stream 0', ecProtocolError);
        if (FT = ftRstStream) and (Len <> 4) then
          raise EHttpProtocolError.Create('RST_STREAM payload must be 4 bytes',
            ecFrameSizeError);
        if (FT = ftPriority) and (Len <> 5) then
          raise EHttpProtocolError.Create('PRIORITY payload must be 5 bytes',
            ecFrameSizeError);
      end;
    ftSettings:
      begin
        if AFrame.Header.StreamId <> 0 then
          raise EHttpProtocolError.Create('SETTINGS must use stream 0',
            ecProtocolError);
        if AFrame.IsAck and (Len <> 0) then
          raise EHttpProtocolError.Create('SETTINGS ACK must have empty payload',
            ecFrameSizeError);
        if not AFrame.IsAck and (Len mod SettingsEntrySize <> 0) then
          raise EHttpProtocolError.Create(
            'SETTINGS payload length is not a multiple of 6', ecFrameSizeError);
      end;
    ftPing:
      begin
        if AFrame.Header.StreamId <> 0 then
          raise EHttpProtocolError.Create('PING must use stream 0',
            ecProtocolError);
        if Len <> 8 then
          raise EHttpProtocolError.Create('PING payload must be 8 bytes',
            ecFrameSizeError);
      end;
    ftGoAway:
      begin
        if AFrame.Header.StreamId <> 0 then
          raise EHttpProtocolError.Create('GOAWAY must use stream 0',
            ecProtocolError);
        if Len < 8 then
          raise EHttpProtocolError.Create('GOAWAY payload must be at least 8 bytes',
            ecFrameSizeError);
      end;
    ftWindowUpdate:
      begin
        if Len <> 4 then
          raise EHttpProtocolError.Create('WINDOW_UPDATE payload must be 4 bytes',
            ecFrameSizeError);
        if ParseWindowUpdate(AFrame) = 0 then
          ; // ParseWindowUpdate already raises on a zero increment
      end;
    ftContinuation:
      if AFrame.Header.StreamId = 0 then
        raise EHttpProtocolError.Create('CONTINUATION must not use stream 0',
          ecProtocolError);
    ftPushPromise:
      if AFrame.Header.StreamId = 0 then
        raise EHttpProtocolError.Create('PUSH_PROMISE must not use stream 0',
          ecProtocolError);
  else
    ; // unknown frame types must be ignored, not rejected
  end;
end;

end.
