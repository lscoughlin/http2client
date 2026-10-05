/// HPACK codec - static/dynamic tables, Huffman (plan S03)
// - this unit is part of the http2client project (see doc/design/)
// - RFC 7541: 5.1 integers, 5.2 string literals, 6.x representations,
//   Appendix A static table, Appendix B Huffman code
unit Http2.Hpack;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Http2.Errors;

type
  /// one header field as it appears in a decoded/encoded header block
  THttpHeaderField = record
    Name: string;
    Value: string;
    /// true for "literal never indexed" fields (must not be indexed by an
    /// intermediary); set by the decoder for 6.2.3 and honoured by the encoder
    Sensitive: Boolean;
  end;

  /// a whole header list (the payload of a HEADERS frame after HPACK)
  THeaderBlock = TArray<THttpHeaderField>;

  /// per-side dynamic table state (RFC 7541 section 2.3.2)
  THpackTableState = record
    Entries: TArray<THttpHeaderField>;  // Entries[0] is the newest
    Size: LongWord;                     // sum of entry sizes (32 + name + value)
    MaxSize: LongWord;                  // current SETTINGS_HEADER_TABLE_SIZE cap
  end;

  /// stateful, connection-scoped HPACK codec. One encoder table and one
  /// decoder table live inside each instance; nothing is shared globally.
  THpackCodec = class
  private
    FEncoder: THpackTableState;
    FDecoder: THpackTableState;
    FMaxTableSize: LongWord;
    FHuffman: Boolean;
    function GetEncoderTableSize: LongWord;
    function GetDecoderTableSize: LongWord;
    function GetEncoderMaxSize: LongWord;
    function GetDecoderMaxSize: LongWord;
  public
    constructor Create;
    /// encode a header list into an HPACK block
    function Encode(const AHeaders: THeaderBlock): TBytes;
    /// decode an HPACK block into a header list; malformed input raises
    /// EHttpProtocolError(ecCompressionError)
    function Decode(const AData: TBytes): THeaderBlock;
    /// apply SETTINGS_HEADER_TABLE_SIZE: caps the encoder table and bounds
    /// the size updates a decoder will accept from the peer
    procedure ApplySettings(aMaxTableSize: LongWord);
    /// current bytes used by the encoder's dynamic table
    property EncoderTableSize: LongWord read GetEncoderTableSize;
    /// current bytes used by the decoder's dynamic table
    property DecoderTableSize: LongWord read GetDecoderTableSize;
    /// current cap on the encoder's dynamic table
    property EncoderMaxSize: LongWord read GetEncoderMaxSize;
    /// current cap on the decoder's dynamic table (updated by size updates)
    property DecoderMaxSize: LongWord read GetDecoderMaxSize;
    /// when true (default) string literals are Huffman-encoded
    property Huffman: Boolean read FHuffman write FHuffman;
  end;

implementation

const
  /// per-entry overhead fixed by RFC 7541 section 4.1
  HpackEntryOverhead = 32;
  /// default SETTINGS_HEADER_TABLE_SIZE (RFC 7540 section 6.5.2)
  HpackDefaultTableSize = 4096;
  /// largest value an HPACK integer may represent (RFC 7541 section 5.1)
  HpackMaxInteger = LongWord($FFFFFFFF);

type
  THpackStaticEntry = record
    Name: string;
    Value: string;
  end;

const
  /// RFC 7541 Appendix A static table (61 entries, 1-based)
  HpackStaticTable: array[0..60] of THpackStaticEntry = (
    (Name: ':authority';                 Value: ''),
    (Name: ':method';                    Value: 'GET'),
    (Name: ':method';                    Value: 'POST'),
    (Name: ':path';                      Value: '/'),
    (Name: ':path';                      Value: '/index.html'),
    (Name: ':scheme';                    Value: 'http'),
    (Name: ':scheme';                    Value: 'https'),
    (Name: ':status';                    Value: '200'),
    (Name: ':status';                    Value: '204'),
    (Name: ':status';                    Value: '206'),
    (Name: ':status';                    Value: '304'),
    (Name: ':status';                    Value: '400'),
    (Name: ':status';                    Value: '404'),
    (Name: ':status';                    Value: '500'),
    (Name: 'accept-charset';             Value: ''),
    (Name: 'accept-encoding';            Value: 'gzip, deflate'),
    (Name: 'accept-language';            Value: ''),
    (Name: 'accept-ranges';              Value: ''),
    (Name: 'accept';                     Value: ''),
    (Name: 'access-control-allow-origin'; Value: ''),
    (Name: 'age';                        Value: ''),
    (Name: 'allow';                      Value: ''),
    (Name: 'authorization';              Value: ''),
    (Name: 'cache-control';              Value: ''),
    (Name: 'content-disposition';        Value: ''),
    (Name: 'content-encoding';           Value: ''),
    (Name: 'content-language';           Value: ''),
    (Name: 'content-length';             Value: ''),
    (Name: 'content-location';           Value: ''),
    (Name: 'content-range';              Value: ''),
    (Name: 'content-type';               Value: ''),
    (Name: 'cookie';                     Value: ''),
    (Name: 'date';                       Value: ''),
    (Name: 'etag';                       Value: ''),
    (Name: 'expect';                     Value: ''),
    (Name: 'expires';                    Value: ''),
    (Name: 'from';                       Value: ''),
    (Name: 'host';                       Value: ''),
    (Name: 'if-match';                   Value: ''),
    (Name: 'if-modified-since';          Value: ''),
    (Name: 'if-none-match';              Value: ''),
    (Name: 'if-range';                   Value: ''),
    (Name: 'if-unmodified-since';        Value: ''),
    (Name: 'last-modified';              Value: ''),
    (Name: 'link';                       Value: ''),
    (Name: 'location';                   Value: ''),
    (Name: 'max-forwards';               Value: ''),
    (Name: 'proxy-authenticate';         Value: ''),
    (Name: 'proxy-authorization';        Value: ''),
    (Name: 'range';                      Value: ''),
    (Name: 'referer';                    Value: ''),
    (Name: 'refresh';                    Value: ''),
    (Name: 'retry-after';                Value: ''),
    (Name: 'server';                     Value: ''),
    (Name: 'set-cookie';                 Value: ''),
    (Name: 'strict-transport-security';  Value: ''),
    (Name: 'transfer-encoding';          Value: ''),
    (Name: 'user-agent';                 Value: ''),
    (Name: 'vary';                       Value: ''),
    (Name: 'via';                        Value: ''),
    (Name: 'www-authenticate';           Value: ''));

  /// RFC 7541 Appendix B Huffman codes, LSB-aligned; index 256 is EOS
  HpackHuffCodes: array[0..256] of LongWord = (
        8184,    8388568,  268435426,  268435427,  268435428,  268435429,  268435430,  268435431,
   268435432,   16777194, 1073741820,  268435433,  268435434, 1073741821,  268435435,  268435436,
   268435437,  268435438,  268435439,  268435440,  268435441,  268435442, 1073741822,  268435443,
   268435444,  268435445,  268435446,  268435447,  268435448,  268435449,  268435450,  268435451,
          20,       1016,       1017,       4090,       8185,         21,        248,       2042,
        1018,       1019,        249,       2043,        250,         22,         23,         24,
           0,          1,          2,         25,         26,         27,         28,         29,
          30,         31,         92,        251,      32764,         32,       4091,       1020,
        8186,         33,         93,         94,         95,         96,         97,         98,
          99,        100,        101,        102,        103,        104,        105,        106,
         107,        108,        109,        110,        111,        112,        113,        114,
         252,        115,        253,       8187,     524272,       8188,      16380,         34,
       32765,          3,         35,          4,         36,          5,         37,         38,
          39,          6,        116,        117,         40,         41,         42,          7,
          43,        118,         44,          8,          9,         45,        119,        120,
         121,        122,        123,      32766,       2044,      16381,       8189,  268435452,
     1048550,    4194258,    1048551,    1048552,    4194259,    4194260,    4194261,    8388569,
     4194262,    8388570,    8388571,    8388572,    8388573,    8388574,   16777195,    8388575,
    16777196,   16777197,    4194263,    8388576,   16777198,    8388577,    8388578,    8388579,
     8388580,    2097116,    4194264,    8388581,    4194265,    8388582,    8388583,   16777199,
     4194266,    2097117,    1048553,    4194267,    4194268,    8388584,    8388585,    2097118,
     8388586,    4194269,    4194270,   16777200,    2097119,    4194271,    8388587,    8388588,
     2097120,    2097121,    4194272,    2097122,    8388589,    4194273,    8388590,    8388591,
     1048554,    4194274,    4194275,    4194276,    8388592,    4194277,    4194278,    8388593,
    67108832,   67108833,    1048555,     524273,    4194279,    8388594,    4194280,   33554412,
    67108834,   67108835,   67108836,  134217694,  134217695,   67108837,   16777201,   33554413,
      524274,    2097123,   67108838,  134217696,  134217697,   67108839,  134217698,   16777202,
     2097124,    2097125,   67108840,   67108841,  268435453,  134217699,  134217700,  134217701,
     1048556,   16777203,    1048557,    2097126,    4194281,    2097127,    2097128,    8388595,
     4194282,    4194283,   33554414,   33554415,   16777204,   16777205,   67108842,    8388596,
    67108843,  134217702,   67108844,   67108845,  134217703,  134217704,  134217705,  134217706,
   134217707,  268435454,  134217708,  134217709,  134217710,  134217711,  134217712,   67108846,
  1073741823);

  /// RFC 7541 Appendix B Huffman code lengths, in bits
  HpackHuffLens: array[0..256] of Byte = (
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
     6, 10, 10, 12, 13,  6,  8, 11, 10, 10,  8, 11,  8,  6,  6,  6,
     5,  5,  5,  6,  6,  6,  6,  6,  6,  6,  7,  8, 15,  6, 12, 10,
    13,  6,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
     7,  7,  7,  7,  7,  7,  7,  7,  8,  7,  8, 13, 19, 13, 14,  6,
    15,  5,  6,  5,  6,  5,  6,  6,  6,  5,  7,  7,  6,  6,  6,  5,
     6,  7,  6,  5,  5,  6,  7,  7,  7,  7,  7, 15, 11, 14, 13, 28,
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
    30);

  /// EOS symbol index within the Huffman tables
  HpackHuffEos = 256;

type
  /// one node of the Huffman decoding trie
  THuffNode = record
    Child: array[0..1] of Integer;  // -1 = absent
    Symbol: Integer;                // -1 = internal, else decoded byte / EOS
  end;

var
  GHuffTrie: array of THuffNode;

procedure BuildHuffmanTrie;
var
  Sym, Bit, Len, Node, Next: Integer;
  Code: LongWord;
begin
  SetLength(GHuffTrie, 1);
  GHuffTrie[0].Child[0] := -1;
  GHuffTrie[0].Child[1] := -1;
  GHuffTrie[0].Symbol := -1;
  for Sym := 0 to 256 do
  begin
    Node := 0;
    Code := HpackHuffCodes[Sym];
    Len := HpackHuffLens[Sym];
    for Bit := Len - 1 downto 0 do
    begin
      if ((Code shr Bit) and 1) = 1 then
      begin
        if GHuffTrie[Node].Child[1] < 0 then
        begin
          Next := Length(GHuffTrie);
          SetLength(GHuffTrie, Next + 1);
          GHuffTrie[Next].Child[0] := -1;
          GHuffTrie[Next].Child[1] := -1;
          GHuffTrie[Next].Symbol := -1;
          GHuffTrie[Node].Child[1] := Next;
        end;
        Node := GHuffTrie[Node].Child[1];
      end
      else
      begin
        if GHuffTrie[Node].Child[0] < 0 then
        begin
          Next := Length(GHuffTrie);
          SetLength(GHuffTrie, Next + 1);
          GHuffTrie[Next].Child[0] := -1;
          GHuffTrie[Next].Child[1] := -1;
          GHuffTrie[Next].Symbol := -1;
          GHuffTrie[Node].Child[0] := Next;
        end;
        Node := GHuffTrie[Node].Child[0];
      end;
    end;
    GHuffTrie[Node].Symbol := Sym;
  end;
end;

procedure CompressionError(const AMessage: string);
begin
  raise EHttpProtocolError.Create(AMessage, ecCompressionError);
end;

{ ---------- byte/string helpers ---------- }

procedure AddByte(var B: TBytes; var N: Integer; const V: Byte);
begin
  if N = Length(B) then
    SetLength(B, N * 2 + 16);
  B[N] := V;
  Inc(N);
end;

function StringToBytes(const S: string): TBytes;
begin
  Result := nil;
  SetLength(Result, Length(S));
  if Length(S) > 0 then
    Move(S[1], Result[0], Length(S));
end;

function BytesToString(const B: TBytes): string;
begin
  SetLength(Result, Length(B));
  if Length(B) > 0 then
    Move(B[0], Result[1], Length(B));
end;

procedure EncodeInt(var B: TBytes; var N: Integer; APrefixBits: Byte;
  APrefixValue: LongWord; AValue: LongWord);
var
  Mask, V: LongWord;
begin
  Mask := (LongWord(1) shl APrefixBits) - 1;
  if AValue < Mask then
  begin
    AddByte(B, N, Byte(APrefixValue or AValue));
    Exit;
  end;
  AddByte(B, N, Byte(APrefixValue or Mask));
  V := AValue - Mask;
  while V >= 128 do
  begin
    AddByte(B, N, Byte((V and $7f) or $80));
    V := V shr 7;
  end;
  AddByte(B, N, Byte(V));
end;

function DecodeInt(const Data: TBytes; var Pos: Integer; APrefixBits: Byte): LongWord;
var
  Mask: LongWord;
  B: Byte;
  V: UInt64;
  Shift: Integer;
begin
  Mask := (LongWord(1) shl APrefixBits) - 1;
  if Pos >= Length(Data) then
    CompressionError('HPACK: truncated integer');
  B := Data[Pos];
  Inc(Pos);
  Result := B and Mask;
  if Result < Mask then
    Exit;
  V := Result;
  Shift := 0;
  repeat
    if Pos >= Length(Data) then
      CompressionError('HPACK: truncated integer continuation');
    B := Data[Pos];
    Inc(Pos);
    V := V + (UInt64(B and $7f) shl Shift);
    if V > HpackMaxInteger then
      CompressionError('HPACK: integer overflow');
    Shift := Shift + 7;
  until (B and $80) = 0;
  Result := LongWord(V);
end;

{ ---------- Huffman ---------- }

function HuffmanEncode(const S: string): TBytes;
var
  i: Integer;
  Acc: UInt64;
  Bits, Sym, Len: Integer;
  Pad: Integer;
begin
  Result := nil;
  SetLength(Result, 0);
  Acc := 0;
  Bits := 0;
  for i := 1 to Length(S) do
  begin
    Sym := Ord(S[i]);
    Len := HpackHuffLens[Sym];
    Acc := (Acc shl Len) or HpackHuffCodes[Sym];
    Bits := Bits + Len;
    while Bits >= 8 do
    begin
      SetLength(Result, Length(Result) + 1);
      Result[High(Result)] := Byte((Acc shr (Bits - 8)) and $ff);
      Bits := Bits - 8;
    end;
  end;
  if Bits > 0 then
  begin
    Pad := 8 - Bits;
    SetLength(Result, Length(Result) + 1);
    Result[High(Result)] := Byte(((Acc shl Pad) or ((UInt64(1) shl Pad) - 1)) and $ff);
  end;
end;

function HuffmanDecode(const Data: TBytes): string;
var
  i, Bit, Node, Pending: Integer;
  AllOnes: Boolean;
  B: Byte;
begin
  Result := '';
  Node := 0;
  Pending := 0;
  AllOnes := True;
  for i := 0 to High(Data) do
  begin
    B := Data[i];
    for Bit := 7 downto 0 do
    begin
      Node := GHuffTrie[Node].Child[(B shr Bit) and 1];
      if Node < 0 then
        CompressionError('HPACK: invalid Huffman code');
      Inc(Pending);
      if ((B shr Bit) and 1) = 0 then
        AllOnes := False;
      if GHuffTrie[Node].Symbol >= 0 then
      begin
        if GHuffTrie[Node].Symbol = HpackHuffEos then
          CompressionError('HPACK: EOS symbol in Huffman literal');
        Result := Result + Chr(GHuffTrie[Node].Symbol);
        Node := 0;
        Pending := 0;
        AllOnes := True;
      end;
    end;
  end;
  if Pending > 0 then
  begin
    if (Pending > 7) or (not AllOnes) then
      CompressionError('HPACK: invalid Huffman padding');
  end;
end;

{ ---------- dynamic table ---------- }

function EntrySize(const F: THttpHeaderField): LongWord;
begin
  Result := HpackEntryOverhead + Length(F.Name) + Length(F.Value);
end;

procedure TableEvictOldest(var T: THpackTableState);
begin
  if Length(T.Entries) = 0 then
    Exit;
  Dec(T.Size, EntrySize(T.Entries[High(T.Entries)]));
  Delete(T.Entries, High(T.Entries), 1);
end;

procedure TableInsert(var T: THpackTableState; const F: THttpHeaderField);
var
  Sz: LongWord;
begin
  Sz := EntrySize(F);
  while (Length(T.Entries) > 0) and (T.Size + Sz > T.MaxSize) do
    TableEvictOldest(T);
  if Sz > T.MaxSize then
  begin
    // RFC 7541 4.4: an entry larger than the table clears it and is not added
    SetLength(T.Entries, 0);
    T.Size := 0;
    Exit;
  end;
  Insert(F, T.Entries, 0);
  Inc(T.Size, Sz);
end;

procedure TableSetMaxSize(var T: THpackTableState; const ANewMax: LongWord);
begin
  T.MaxSize := ANewMax;
  while T.Size > T.MaxSize do
    TableEvictOldest(T);
end;

function TableEntryAt(var T: THpackTableState; const Idx: LongWord): THttpHeaderField;
begin
  if (Idx >= 1) and (Idx <= 61) then
  begin
    Result.Name := HpackStaticTable[Idx - 1].Name;
    Result.Value := HpackStaticTable[Idx - 1].Value;
    Result.Sensitive := False;
    Exit;
  end;
  if (Idx >= 62) and (Idx < 62 + LongWord(Length(T.Entries))) then
  begin
    Result := T.Entries[Idx - 62];
    Exit;
  end;
  CompressionError(Format('HPACK: index %d out of range', [Idx]));
end;

function TableFindExact(var T: THpackTableState; const AName, AValue: string;
  out AIndex: LongWord): Boolean;
var
  i: Integer;
begin
  for i := 0 to High(HpackStaticTable) do
    if (HpackStaticTable[i].Name = AName) and (HpackStaticTable[i].Value = AValue) then
    begin
      AIndex := LongWord(i + 1);
      Exit(True);
    end;
  for i := 0 to High(T.Entries) do
    if (T.Entries[i].Name = AName) and (T.Entries[i].Value = AValue) then
    begin
      AIndex := 62 + LongWord(i);
      Exit(True);
    end;
  Result := False;
end;

function TableFindName(var T: THpackTableState; const AName: string;
  out AIndex: LongWord): Boolean;
var
  i: Integer;
begin
  for i := 0 to High(HpackStaticTable) do
    if HpackStaticTable[i].Name = AName then
    begin
      AIndex := LongWord(i + 1);
      Exit(True);
    end;
  for i := 0 to High(T.Entries) do
    if T.Entries[i].Name = AName then
    begin
      AIndex := 62 + LongWord(i);
      Exit(True);
    end;
  Result := False;
end;

{ ---------- string literals ---------- }

procedure EncodeString(var B: TBytes; var N: Integer; const S: string;
  const AHuffman: Boolean);
var
  Raw: TBytes;
  i: Integer;
  Prefix: LongWord;
begin
  if AHuffman then
  begin
    Raw := HuffmanEncode(S);
    Prefix := $80;
  end
  else
  begin
    Raw := StringToBytes(S);
    Prefix := 0;
  end;
  EncodeInt(B, N, 7, Prefix, Length(Raw));
  for i := 0 to High(Raw) do
    AddByte(B, N, Raw[i]);
end;

function DecodeString(const Data: TBytes; var Pos: Integer): string;
var
  B: Byte;
  Huff: Boolean;
  Len: LongWord;
  Raw: TBytes;
begin
  if Pos >= Length(Data) then
    CompressionError('HPACK: truncated string literal');
  B := Data[Pos];
  Huff := (B and $80) <> 0;
  Len := DecodeInt(Data, Pos, 7);
  if UInt64(Pos) + UInt64(Len) > UInt64(Length(Data)) then
    CompressionError('HPACK: string literal length overruns block');
  SetLength(Raw, Len);
  if Len > 0 then
    Move(Data[Pos], Raw[0], Len);
  Inc(Pos, Len);
  if Huff then
    Result := HuffmanDecode(Raw)
  else
    Result := BytesToString(Raw);
end;

{ ---------- header field representations ---------- }

procedure EncodeField(var Enc: THpackTableState; var B: TBytes; var N: Integer;
  const F: THttpHeaderField; const AHuffman: Boolean);
var
  Idx: LongWord;
begin
  if F.Sensitive then
  begin
    // 6.2.3 literal never indexed (4-bit name index)
    if TableFindName(Enc, F.Name, Idx) then
      EncodeInt(B, N, 4, $10, Idx)
    else
    begin
      EncodeInt(B, N, 4, $10, 0);
      EncodeString(B, N, F.Name, AHuffman);
    end;
    EncodeString(B, N, F.Value, AHuffman);
    Exit;
  end;

  if TableFindExact(Enc, F.Name, F.Value, Idx) then
  begin
    // 6.1 indexed header field
    EncodeInt(B, N, 7, $80, Idx);
    Exit;
  end;

  if EntrySize(F) > Enc.MaxSize then
  begin
    // 6.2.2 literal without indexing - never add an oversized entry
    if TableFindName(Enc, F.Name, Idx) then
      EncodeInt(B, N, 4, $00, Idx)
    else
    begin
      EncodeInt(B, N, 4, $00, 0);
      EncodeString(B, N, F.Name, AHuffman);
    end;
    EncodeString(B, N, F.Value, AHuffman);
    Exit;
  end;

  // 6.2.1 literal with incremental indexing (6-bit name index)
  if TableFindName(Enc, F.Name, Idx) then
    EncodeInt(B, N, 6, $40, Idx)
  else
  begin
    EncodeInt(B, N, 6, $40, 0);
    EncodeString(B, N, F.Name, AHuffman);
  end;
  EncodeString(B, N, F.Value, AHuffman);
  TableInsert(Enc, F);
end;

function DecodeFieldName(const Data: TBytes; var Pos: Integer; var Dec: THpackTableState;
  const Idx: LongWord): string;
var
  F: THttpHeaderField;
begin
  if Idx = 0 then
    Result := DecodeString(Data, Pos)
  else
  begin
    F := TableEntryAt(Dec, Idx);
    Result := F.Name;
  end;
end;

{ ---------- THpackCodec ---------- }

constructor THpackCodec.Create;
begin
  inherited Create;
  FHuffman := True;
  FMaxTableSize := HpackDefaultTableSize;
  FEncoder.MaxSize := HpackDefaultTableSize;
  FEncoder.Size := 0;
  SetLength(FEncoder.Entries, 0);
  FDecoder.MaxSize := HpackDefaultTableSize;
  FDecoder.Size := 0;
  SetLength(FDecoder.Entries, 0);
end;

function THpackCodec.GetEncoderTableSize: LongWord;
begin
  Result := FEncoder.Size;
end;

function THpackCodec.GetDecoderTableSize: LongWord;
begin
  Result := FDecoder.Size;
end;

function THpackCodec.GetEncoderMaxSize: LongWord;
begin
  Result := FEncoder.MaxSize;
end;

function THpackCodec.GetDecoderMaxSize: LongWord;
begin
  Result := FDecoder.MaxSize;
end;

procedure THpackCodec.ApplySettings(aMaxTableSize: LongWord);
begin
  FMaxTableSize := aMaxTableSize;
  TableSetMaxSize(FEncoder, aMaxTableSize);
  TableSetMaxSize(FDecoder, aMaxTableSize);
end;

function THpackCodec.Encode(const AHeaders: THeaderBlock): TBytes;
var
  i, N: Integer;
begin
  Result := nil;
  SetLength(Result, 0);
  N := 0;
  for i := 0 to High(AHeaders) do
    EncodeField(FEncoder, Result, N, AHeaders[i], FHuffman);
  SetLength(Result, N);
end;

function THpackCodec.Decode(const AData: TBytes): THeaderBlock;
var
  Pos: Integer;
  B: Byte;
  Idx: LongWord;
  Name: string;
  F: THttpHeaderField;
  SizeUpdateAllowed: Boolean;

  procedure Add(const AName: string);
  begin
    F.Name := AName;
    F.Value := DecodeString(AData, Pos);
  end;

begin
  Result := nil;
  SetLength(Result, 0);
  Pos := 0;
  SizeUpdateAllowed := True;
  while Pos < Length(AData) do
  begin
    B := AData[Pos];
    if (B and $80) <> 0 then
    begin
      // 6.1 indexed header field
      Idx := DecodeInt(AData, Pos, 7);
      if Idx = 0 then
        CompressionError('HPACK: indexed field with index 0');
      F := TableEntryAt(FDecoder, Idx);
      SetLength(Result, Length(Result) + 1);
      Result[High(Result)] := F;
      SizeUpdateAllowed := False;
    end
    else if (B and $C0) = $40 then
    begin
      // 6.2.1 literal with incremental indexing
      Idx := DecodeInt(AData, Pos, 6);
      Name := DecodeFieldName(AData, Pos, FDecoder, Idx);
      Add(Name);
      F.Sensitive := False;
      TableInsert(FDecoder, F);
      SetLength(Result, Length(Result) + 1);
      Result[High(Result)] := F;
      SizeUpdateAllowed := False;
    end
    else if (B and $E0) = $20 then
    begin
      // 6.3 dynamic table size update
      if not SizeUpdateAllowed then
        CompressionError('HPACK: dynamic table size update after a header field');
      Idx := DecodeInt(AData, Pos, 5);
      if Idx > FMaxTableSize then
        CompressionError('HPACK: dynamic table size update exceeds SETTINGS_HEADER_TABLE_SIZE');
      TableSetMaxSize(FDecoder, Idx);
    end
    else if (B and $F0) = $10 then
    begin
      // 6.2.3 literal never indexed
      Idx := DecodeInt(AData, Pos, 4);
      Name := DecodeFieldName(AData, Pos, FDecoder, Idx);
      Add(Name);
      F.Sensitive := True;
      SetLength(Result, Length(Result) + 1);
      Result[High(Result)] := F;
      SizeUpdateAllowed := False;
    end
    else
    begin
      // 6.2.2 literal without indexing
      Idx := DecodeInt(AData, Pos, 4);
      Name := DecodeFieldName(AData, Pos, FDecoder, Idx);
      Add(Name);
      F.Sensitive := False;
      SetLength(Result, Length(Result) + 1);
      Result[High(Result)] := F;
      SizeUpdateAllowed := False;
    end;
  end;
end;

initialization
  BuildHuffmanTrie;

end.
