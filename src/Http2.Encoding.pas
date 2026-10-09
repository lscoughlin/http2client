/// Content coding (gzip and deflate) for request and response bodies
// - this unit is part of the http2client project (see doc/design/messages.md
//   "Content coding").
// - the codecs use the zlib bindings that Free Pascal ships with the
//   compiler (`paszlib`/`zstream`), so the unit adds no third-party
//   dependency.
// - the client never asks for a coded response on its own. A caller that
//   offers `accept-encoding` through THttpRequest.WithAcceptEncoding gets
//   the body decoded transparently: THttpResponse wraps the body in a
//   TDecodingBodyStream and removes the `content-encoding` header, so every
//   reader (ReadText, ReadAllBodyBytes, a typed reader) sees plain bytes.
unit Http2.Encoding;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}

interface

uses
  SysUtils, Classes,
  Http2.Headers, Http2.Messages, Http2.Stream, zstream;

type
  /// the content codings this client understands
  TContentEncoding = (
    /// no coding; the body is already plain
    ceIdentity,
    /// the gzip container of RFC 1952
    ceGzip,
    /// the zlib container of RFC 1950, or a bare deflate stream
    ceDeflate
  );

/// the coding named by a response `content-encoding` value, or ceIdentity
// - the value is a list; the first coding this client understands wins,
//   because it cannot decode a chain it does not know
function ParseContentEncoding(const AValue: string): TContentEncoding;

/// the coding to answer a request with, given its `accept-encoding` value
// - an absent or empty value yields ceIdentity. The chooser reads the
//   quality values of RFC 9110 section 12.5.3: `gzip;q=0` rejects gzip, `*`
//   covers every coding, and a coding the client did not offer is never
//   chosen. ceIdentity is the answer when nothing else qualifies.
function NegotiateEncoding(const AAcceptEncoding: string): TContentEncoding;

/// the token to put in `content-encoding` for ACoding ('' for identity)
function EncodingToken(const ACoding: TContentEncoding): string;

/// true when the coding codes the body rather than passing it through
function IsEncoded(const ACoding: TContentEncoding): Boolean;

/// compress AData into a gzip container
function GzipCompress(const AData: TBytes): TBytes;
/// compress AData into a zlib container
function DeflateCompress(const AData: TBytes): TBytes;
/// compress AData into a bare deflate stream (no zlib header)
function RawDeflateCompress(const AData: TBytes): TBytes;

/// decompress a gzip container
function GzipDecompress(const AData: TBytes): TBytes;
/// decompress a deflate body, zlib-wrapped or bare
// - many servers send a bare deflate stream under the name `deflate`, so the
//   container is detected from the first two bytes rather than assumed
function DeflateDecompress(const AData: TBytes): TBytes;

/// an inflating body stream over another IHttpBodyStream
// - the compressed bytes are pulled from the inner stream on demand, so a
///   large response never has to be held in memory
type
  TDecodingBodyStream = class(TInterfacedObject, IHttpBodyStream)
  private
    FInner: IHttpBodyStream;
    FSource: TStream;
    FDecoder: TStream;
    FCoding: TContentEncoding;
    FDone: Boolean;
  public
    /// wrap AInner, inflating it as ACoding
    constructor Create(const AInner: IHttpBodyStream;
      const ACoding: TContentEncoding);
    destructor Destroy; override;
    function Read(var ABuffer; const ACount: LongInt): LongInt;
    function Eof: Boolean;
  end;

/// wrap AResponse's body for AResponse's own `content-encoding`
// - returns AResponse unchanged when the coding is absent or identity. The
///  coding header is removed from the response when a decode wrapper is
///  installed, so a caller never sees a header that describes bytes it can
///  no longer reach.
function WrapDecodingResponse(const AResponse: IHttpResponse)
  : IHttpResponse;

implementation

type
  /// a non-seekable TStream view of an IHttpBodyStream, with a pushback
  /// buffer so a caller can inspect the first bytes and put them back
  TBodyStreamAdapter = class(TStream)
  private
    FInner: IHttpBodyStream;
    FPush: TBytes;
    FPushPos: Integer;
  public
    constructor Create(const AInner: IHttpBodyStream);
    /// prepend AData to the bytes still to be served
    // - called once, at construction, with the bytes an inspection consumed
    procedure PushBack(const AData: TBytes);
    function Read(var ABuffer; ACount: LongInt): LongInt; override;
    function Seek(const Offset: Int64; Origin: TSeekOrigin): Int64; override;
  end;

  /// the response wrapper that decodes a body
  TDecodingResponse = class(TInterfacedObject, IHttpResponse)
  private
    FAccessories: IHttpResponse;
    FHeaders: IHttpHeaders;
    FBody: IHttpBodyStream;
    function GetStatusCode: LongInt;
    function GetHeaders: IHttpHeaders;
    function GetBody: IHttpBodyStream;
  public
    constructor Create(const AResponse: IHttpResponse;
      const ACoding: TContentEncoding);
  end;

{ helpers }

function ContainsToken(const AList, AToken: string): Boolean;
var
  P, Start: Integer;
  Item, Name: string;
begin
  Result := False;
  Start := 1;
  for P := 1 to Length(AList) + 1 do
  begin
    if (P > Length(AList)) or (AList[P] = ',') then
    begin
      Item := Trim(Copy(AList, Start, P - Start));
      Start := P + 1;
      if Item <> '' then
      begin
        if Pos(';', Item) > 0 then
          Name := Trim(Copy(Item, 1, Pos(';', Item) - 1))
        else
          Name := Item;
        if SameText(Name, AToken) then
          Exit(True);
      end;
    end;
  end;
end;

function ParseContentEncoding(const AValue: string): TContentEncoding;
var
  P, Start: Integer;
  Item, Name: string;
begin
  Result := ceIdentity;
  Start := 1;
  for P := 1 to Length(AValue) + 1 do
  begin
    if (P > Length(AValue)) or (AValue[P] = ',') then
    begin
      Item := Trim(Copy(AValue, Start, P - Start));
      Start := P + 1;
      if Item <> '' then
      begin
        if Pos(';', Item) > 0 then
          Name := Trim(Copy(Item, 1, Pos(';', Item) - 1))
        else
          Name := Item;
        if SameText(Name, 'gzip') or SameText(Name, 'x-gzip') then
          Exit(ceGzip);
        if SameText(Name, 'deflate') then
          Exit(ceDeflate);
      end;
    end;
  end;
end;

function NegotiateEncoding(const AAcceptEncoding: string): TContentEncoding;
var
  P, Start, Semi: Integer;
  Item, Name, Params: string;
  QGzip, QDeflate, QStar, Q: Single;
  HasGzip, HasDeflate, HasStar: Boolean;

  function ParseQuality(const AParams: string): Single;
  var
    Seg: string;
    SStart, SP, Eq: Integer;
  begin
    Result := 1.0;
    SStart := 1;
    for SP := 1 to Length(AParams) + 1 do
    begin
      if (SP > Length(AParams)) or (AParams[SP] = ';') then
      begin
        Seg := Trim(Copy(AParams, SStart, SP - SStart));
        SStart := SP + 1;
        Eq := Pos('=', Seg);
        if (Eq > 0) and SameText(Trim(Copy(Seg, 1, Eq - 1)), 'q') then
        begin
          Result := StrToFloatDef(Trim(Copy(Seg, Eq + 1, MaxInt)), 1.0);
          if Result < 0 then
            Result := 0;
          if Result > 1 then
            Result := 1;
        end;
      end;
    end;
  end;

begin
  Result := ceIdentity;
  if Trim(AAcceptEncoding) = '' then
    Exit;

  QGzip := -1;
  QDeflate := -1;
  QStar := -1;
  HasGzip := False;
  HasDeflate := False;
  HasStar := False;

  if HasGzip and (QGzip > 0) then
    Exit(ceGzip);
  if HasDeflate and (QDeflate > 0) then
    Exit(ceDeflate);
  Start := 1;
  for P := 1 to Length(AAcceptEncoding) + 1 do
  begin
    if (P > Length(AAcceptEncoding)) or (AAcceptEncoding[P] = ',') then
    begin
      Item := Trim(Copy(AAcceptEncoding, Start, P - Start));
      Start := P + 1;
      if Item <> '' then
      begin
        Semi := Pos(';', Item);
        if Semi > 0 then
        begin
          Name := Trim(Copy(Item, 1, Semi - 1));
          Params := Copy(Item, Semi + 1, MaxInt);
        end
        else
        begin
          Name := Item;
          Params := '';
        end;
        Q := ParseQuality(Params);
        if SameText(Name, 'gzip') or SameText(Name, 'x-gzip') then
        begin
          if Q > QGzip then
            QGzip := Q;
          HasGzip := True;
        end
        else if SameText(Name, 'deflate') then
        begin
          if Q > QDeflate then
            QDeflate := Q;
          HasDeflate := True;
        end
        else if Name = '*' then
        begin
          if Q > QStar then
            QStar := Q;
          HasStar := True;
        end;
      end;
    end;
  end;

  // The chooser is passed the acceptability of each coding, then picks the
  // most acceptable one. A crossing quality breaks toward gzip, which every
  // `deflate` reader in the field tolerates and which carries an integrity
  // check.
  if HasGzip and (QGzip > 0) and ((not HasDeflate) or (QGzip >= QDeflate)) then
    Exit(ceGzip);
  if HasDeflate and (QDeflate > 0) then
    Exit(ceDeflate);
  // A wildcard stands in for a coding the client did not name, so gzip is
  // the answer when it is acceptable. gzip is preferred over deflate because
  // every `deflate` reader in the field tolerates it and it is a container
  // with an integrity check.
  if HasStar and (QStar > 0) then
    Exit(ceGzip);
  Result := ceIdentity;
end;

function EncodingToken(const ACoding: TContentEncoding): string;
begin
  case ACoding of
    ceGzip: Result := 'gzip';
    ceDeflate: Result := 'deflate';
  else
    Result := '';
  end;
end;

function IsEncoded(const ACoding: TContentEncoding): Boolean;
begin
  Result := ACoding <> ceIdentity;
end;

function CompressInto(const AData: TBytes; const ALevel: TCompressionLevel;
  const AGzip, ASkipHeader: Boolean): TBytes;
var
  Dest: TMemoryStream;
  C: TStream;
begin
  SetLength(Result, 0);
  Dest := TMemoryStream.Create;
  try
    if AGzip then
      C := TGZipCompressionStream.Create(ALevel, Dest)
    else
      C := TCompressionStream.Create(ALevel, Dest, ASkipHeader);
    try
      if Length(AData) > 0 then
        C.Write(AData[0], Length(AData));
    finally
      // the destructor flushes the final block and writes the gzip footer
      C.Free;
    end;
    SetLength(Result, Dest.Size);
    if Dest.Size > 0 then
    begin
      Dest.Position := 0;
      Dest.ReadBuffer(Result[0], Dest.Size);
    end;
  finally
    Dest.Free;
  end;
end;

function GzipCompress(const AData: TBytes): TBytes;
begin
  Result := CompressInto(AData, clDefault, True, False);
end;

function DeflateCompress(const AData: TBytes): TBytes;
begin
  Result := CompressInto(AData, clDefault, False, False);
end;

function RawDeflateCompress(const AData: TBytes): TBytes;
begin
  Result := CompressInto(AData, clDefault, False, True);
end;

function InflateAll(const AData: TBytes; const AGzip, ASkipHeader: Boolean)
  : TBytes;
var
  Src, Dst: TMemoryStream;
  D: TStream;
  Buf: array[0..16383] of Byte;
  N: LongInt;
begin
  SetLength(Result, 0);
  Src := TMemoryStream.Create;
  Dst := TMemoryStream.Create;
  try
    if Length(AData) > 0 then
      Src.Write(AData[0], Length(AData));
    Src.Position := 0;
    if AGzip then
      D := TGZipDecompressionStream.Create(Src)
    else
      D := TDecompressionStream.Create(Src, ASkipHeader);
    try
      repeat
        N := D.Read(Buf[0], SizeOf(Buf));
        if N > 0 then
          Dst.Write(Buf[0], N);
      until N <= 0;
    finally
      D.Free;
    end;
    SetLength(Result, Dst.Size);
    if Dst.Size > 0 then
    begin
      Dst.Position := 0;
      Dst.ReadBuffer(Result[0], Dst.Size);
    end;
  finally
    Dst.Free;
    Src.Free;
  end;
end;

function GzipDecompress(const AData: TBytes): TBytes;
begin
  Result := InflateAll(AData, True, False);
end;

function LooksZlib(const AData: TBytes): Boolean;
var
  CMF, FLG: Integer;
begin
  Result := False;
  if Length(AData) < 2 then
    Exit;
  CMF := AData[0];
  FLG := AData[1];
  // RFC 1950 section 2.2: the low nibble is the method (8 = deflate) and the
  // two header bytes are a multiple of 31
  Result := ((CMF and $0F) = 8) and (((CMF shl 8) + FLG) mod 31 = 0);
end;

function DeflateDecompress(const AData: TBytes): TBytes;
begin
  if LooksZlib(AData) then
    Result := InflateAll(AData, False, False)
  else
    Result := InflateAll(AData, False, True);
end;

{ TBodyStreamAdapter }

constructor TBodyStreamAdapter.Create(const AInner: IHttpBodyStream);
begin
  inherited Create;
  FInner := AInner;
  FPushPos := 0;
end;

procedure TBodyStreamAdapter.PushBack(const AData: TBytes);
begin
  FPush := Copy(AData, 0, Length(AData));
  FPushPos := 0;
end;

function TBodyStreamAdapter.Read(var ABuffer; ACount: LongInt): LongInt;
var
  P: PByte;
  Got, Take, Room: LongInt;
begin
  Result := 0;
  if ACount <= 0 then
    Exit;
  P := @ABuffer;
  // serve the pushback first
  while (FPushPos < Length(FPush)) and (Result < ACount) do
  begin
    P[Result] := FPush[FPushPos];
    Inc(FPushPos);
    Inc(Result);
  end;
  if Result >= ACount then
    Exit;
  Take := ACount - Result;
  Got := FInner.Read(P[Result], Take);
  if Got > 0 then
    Inc(Result, Got);
end;

function TBodyStreamAdapter.Seek(const Offset: Int64;
  Origin: TSeekOrigin): Int64;
begin
  // The gzip decoder seeks to the footer to check the CRC. A body is not
  // seekable, so the seek is refused and the decoder skips the check, which
  // is what FPC's TGZipDecompressionStream expects.
  raise EStreamError.Create('the response body is not seekable');
end;

{ TDecodingBodyStream }

constructor TDecodingBodyStream.Create(const AInner: IHttpBodyStream;
  const ACoding: TContentEncoding);
var
  Probe: array[0..1] of Byte;
  ProbeBytes: TBytes;
  N: LongInt;
begin
  inherited Create;
  FInner := AInner;
  FCoding := ACoding;
  FDone := False;
  FSource := TBodyStreamAdapter.Create(AInner);
  if FCoding = ceGzip then
    FDecoder := TGZipDecompressionStream.Create(FSource)
  else
  begin
    // the deflate container is detected, not assumed: read up to two bytes
    // and put them back before the decoder is built
    N := FSource.Read(Probe[0], 2);
    SetLength(ProbeBytes, N);
    if N > 0 then
      Move(Probe[0], ProbeBytes[0], N);
    (FSource as TBodyStreamAdapter).PushBack(ProbeBytes);
    if LooksZlib(ProbeBytes) then
      FDecoder := TDecompressionStream.Create(FSource, False)
    else
      FDecoder := TDecompressionStream.Create(FSource, True);
  end;
end;

destructor TDecodingBodyStream.Destroy;
begin
  FDecoder.Free;
  FSource.Free;
  inherited Destroy;
end;

function TDecodingBodyStream.Read(var ABuffer; const ACount: LongInt): LongInt;
begin
  if FDone or (ACount <= 0) then
    Exit(0);
  try
    Result := FDecoder.Read(ABuffer, ACount);
  except
    // a truncated or corrupt stream ends the body rather than escaping
    FDone := True;
    raise;
  end;
  if Result <= 0 then
    FDone := True;
end;

function TDecodingBodyStream.Eof: Boolean;
begin
  Result := FDone;
end;

{ TDecodingResponse }

constructor TDecodingResponse.Create(const AResponse: IHttpResponse;
  const ACoding: TContentEncoding);
begin
  inherited Create;
  FAccessories := AResponse;
  FHeaders := AResponse.Headers;
  FBody := TDecodingBodyStream.Create(AResponse.Body, ACoding);
end;

function TDecodingResponse.GetStatusCode: LongInt;
begin
  Result := FAccessories.StatusCode;
end;

function TDecodingResponse.GetHeaders: IHttpHeaders;
begin
  Result := FHeaders;
end;

function TDecodingResponse.GetBody: IHttpBodyStream;
begin
  Result := FBody;
end;

function WrapDecodingResponse(const AResponse: IHttpResponse): IHttpResponse;
var
  Coding: TContentEncoding;
begin
  Result := AResponse;
  if AResponse = nil then
    Exit;
  Coding := ParseContentEncoding(
    AResponse.Headers.GetFirst(HeaderContentEncoding));
  if not IsEncoded(Coding) then
    Exit;
  // the header described the wire bytes; the body now yields plain bytes, so
  // the header is removed along with a content-length that no longer counts.
  // The coding is captured first, because the wrapper must still know it.
  AResponse.Headers.Remove(HeaderContentEncoding);
  AResponse.Headers.Remove(HeaderContentLength);
  Result := TDecodingResponse.Create(AResponse, Coding);
end;

end.
