/// HTTP/1.1 codec (plan S13 task 13.4; doc/design/fallback.md
/// "HTTP/1.1 codec" and "Errors").
// - this unit is deliberately small.  It is not a general HTTP/1.1 client: it
//   builds one request, writes it over an IHttp2Socket, and parses exactly one
//   response, including its body framing.  One connection carries one request
//   at a time (HTTP/1.1 has no multiplexing) and a response body must be
//   drained before the socket is reused.
// - the public surface mirrors the transport-neutral interfaces: the returned
//   IHttpResponse (Http2.Messages) is the same object the HTTP/2 codec hands
//   back, so redirects/timeouts/observers work unchanged once the pool wires
//   this codec in (task 13.6 does that; this unit only compiles and is tested).
// - request bodies are TStreamRequest bodies: a fixed THttpBody becomes
//   Content-Length, an IBodyWriter is drained and sent chunked because its
//   length is not known in advance.
unit Http2.Http1;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, Generics.Collections,
  Http2.Errors, Http2.Headers, Http2.Tls, Http2.Stream, Http2.Messages;

const
  /// ceiling for the whole response head (status line + all header fields),
  /// in bytes, before the empty line.  doc/design/fallback.md "Open items"
  /// leaves the value open; 64 KiB is generous for a small client that does
  /// not need to accept hostile peers and keeps the buffer bounded.
  cHttp1MaxHeaderBytes = 64 * 1024;
  /// one transport read fills at most this many bytes
  cHttp1ReadBufferSize = 16 * 1024;

type
  /// one parsed HTTP/1.1 header field.  Name keeps the first-seen spelling;
  /// repeated fields are joined (see ParseHeaders).
  THttp1HeaderField = record
    Name: string;
    Value: string;
  end;

  /// a buffered line/byte reader over an IHttp2Socket.  It is the single owner
  /// of the read position, so a response head and its body can be parsed from
  /// the same stream without losing bytes at the boundary.
  TBufferedReader = class
  private
    FSocket: IHttp2Socket;
    FBuf: TBytes;
    FPos: Integer;
    FEnd: Integer;
    /// pull another transport buffer into FBuf; False at end of stream
    function Fill: Boolean;
  public
    constructor Create(const ASocket: IHttp2Socket);
    /// read up to ACount bytes; 0 only at end of stream
    function ReadBytes(var ABuffer; const ACount: Integer): Integer;
    /// read exactly ACount bytes; shorter only when the peer closed early
    function ReadExact(var ABuffer; const ACount: Integer): Integer;
    /// read one CRLF- or LF-terminated line, stripping the terminator.  False
    /// only when the stream ends before any byte of the line arrives.
    function ReadLine(out ALine: string): Boolean;
    /// read one CRLF- or LF-terminated line WITHOUT reading past it.  Used at
    /// the HTTP/1.1 -> HTTP/2 upgrade boundary, where a buffered read would
    /// swallow the first HTTP/2 bytes that follow the status line.
    function ReadLineNoReadAhead(out ALine: string): Boolean;
    /// true when no buffered byte remains (may still pull more later)
    function Buffered: Integer;
  end;

  /// how a response body is delimited
  TBodyFraming = (bfNone, bfContentLength, bfChunked, bfUntilClose);

  /// an IHttpBodyStream over a response body.  Chunked decoding is pull-based
  /// (a chunk is decoded as the caller reads it), so a large body is not
  /// buffered whole.
  THttp1BodyStream = class(TInterfacedObject, IHttpBodyStream)
  private
    FReader: TBufferedReader;
    FFraming: TBodyFraming;
    FRemaining: Int64;          // content-length bytes still to read
    FChunkRemaining: Int64;     // bytes left in the current chunk
    FAtChunkEnd: Boolean;       // the CRLF after the current chunk is pending
    FDone: Boolean;
    FObservedEof: Boolean;
    FTrailers: IHttpHeaders;    // filled when the chunked terminator is parsed
    procedure ReadTrailers;
    function ReadContentLength(var ABuffer; const ACount: LongInt): LongInt;
    function ReadChunked(var ABuffer; const ACount: LongInt): LongInt;
    function ReadUntilClose(var ABuffer; const ACount: LongInt): LongInt;
  public
    constructor Create(const AReader: TBufferedReader;
      const AFraming: TBodyFraming; const AContentLength: Int64;
      const ATrailers: IHttpHeaders);
    function Read(var ABuffer; const ACount: LongInt): LongInt;
    function Eof: Boolean;
    property Trailers: IHttpHeaders read FTrailers;
  end;

  /// an HTTP/1.1 response (implements the transport-neutral IHttpResponse).
  /// Pseudo-headers do not exist in HTTP/1.1, so Headers carries every regular
  /// field except the connection-specific ones (Connection, Transfer-Encoding,
  /// Keep-Alive, Upgrade, Proxy-Connection), which are transport metadata.
  THttp1Response = class(TInterfacedObject, IHttpResponse)
  private
    FVersion: string;
    FReason: string;
    FStatusCode: LongInt;
    FHeaders: IHttpHeaders;
    FBody: IHttpBodyStream;
  public
    constructor Create(const AVersion: string; const AStatusCode: LongInt;
      const AReason: string; const AHeaders: IHttpHeaders;
      const ABody: IHttpBodyStream);
    function GetStatusCode: LongInt;
    function GetHeaders: IHttpHeaders;
    function GetBody: IHttpBodyStream;
    property Version: string read FVersion;
    property Reason: string read FReason;
  end;

  /// drives exactly one HTTP/1.1 connection.  Send builds a request, writes it
  /// in full, parses the response head, and returns a response whose body is
  /// framed by content-length, chunked coding, or connection close.
  THttp1Connection = class
  private
    FSocket: IHttp2Socket;
    FReader: TBufferedReader;
    FTimeoutMs: Integer;
    FReusable: Boolean;
    FLastBody: IHttpBodyStream;
    FLastTrailers: IHttpHeaders;
    FRequestCount: Integer;
    // response head, split so an h2c upgrade can inspect the status line
    // before the socket switches protocol
    FBeginDone: Boolean;
    FStatusCode: LongInt;
    FReason: string;
    FVersion: string;
    FFields: TArray<THttp1HeaderField>;
    FHeaders: IHttpHeaders;
    FSendRequest: TStreamRequest;
    procedure WriteAll(const ABytes: TBytes);
    function GetReaderBuffered: Integer;
  public
    constructor Create(const ASocket: IHttp2Socket;
      const ATimeoutMs: Integer = cDefaultSocketTimeoutMs);
    destructor Destroy; override;
    /// send ARequest and parse one response.  Raises EHttpProtocolError when
    /// the previous response body was not drained first.
    function Send(const ARequest: TStreamRequest): IHttpResponse;
    /// write ARequest, then read ONLY the response status line, byte by byte,
    /// without reading past it.  After True the socket sits exactly at the
    /// start of the header fields; inspect StatusCode to decide whether the
    /// peer accepted an Upgrade.  Used by the h2c upgrade path.
    function BeginResponse(const ARequest: TStreamRequest): Boolean;
    /// parse the header fields and body framing that follow the status line
    /// already read by BeginResponse, and return the response
    function FinishResponse: IHttpResponse;
    /// hand the raw socket back to the caller without closing it, so it can
    /// be reused for another protocol.  PendingBytes must be 0 first.
    function Detach: IHttp2Socket;
    /// the status line read by BeginResponse
    property StatusCode: LongInt read FStatusCode;
    property Reason: string read FReason;
    /// bytes already buffered from the socket (>0 only after a read-ahead)
    property PendingBytes: Integer read GetReaderBuffered;
    /// true when the last response permits reusing this socket (HTTP/1.1
    /// default keep-alive and no "Connection: close"; read-to-close framing
    /// always forbids reuse)
    function Reusable: Boolean;
    procedure Close;
    /// trailers of the last chunked response, filled once its body is drained
    property LastTrailers: IHttpHeaders read FLastTrailers;
    property RequestCount: Integer read FRequestCount;
  end;

/// build the wire bytes of ARequest: request line, exactly one Host header,
/// the regular headers, a body framing header (content-length or chunked), and
/// the body itself.
function BuildHttp1Request(const ARequest: TStreamRequest): TBytes;

/// parse "HTTP/1.1 200 OK" into version, 3-digit status code and reason (the
/// reason may be empty).  A malformed status line raises EHttpProtocolError.
procedure ParseStatusLine(const ALine: string; out AVersion: string;
  out AStatusCode: Integer; out AReason: string);

/// parse "Name: value" field lines.  Repeated names are joined with ", " into
/// a single field, except set-cookie which stays as separate fields (RFC 9110
/// section 5.2).  A malformed field raises EHttpProtocolError.
function ParseHeaders(const ALines: TArray<string>): TArray<THttp1HeaderField>;

/// the first value for AName (case-insensitive), or '' when absent
function HeaderFieldValue(const AFields: TArray<THttp1HeaderField>;
  const AName: string): string;

/// convert parsed fields to the shared header map, dropping connection-specific
/// fields that the map forbids on the HTTP/2 wire
function FieldsToHttpHeaders(
  const AFields: TArray<THttp1HeaderField>): IHttpHeaders;

/// parse one chunk-size line: hexadecimal, with an optional ";extension" that
/// is ignored.  A bad size raises EHttpProtocolError.
function ParseChunkSize(const ALine: string): Int64;

/// decode a whole chunked body from AReader, returning the decoded bytes and
/// any trailer fields.  Used for tests and eager callers; the streaming path
/// uses THttp1BodyStream.
function DecodeChunked(const AReader: TBufferedReader;
  out ATrailers: IHttpHeaders): TBytes;

implementation

const
  cCrLf = #13#10;
  cHexDigits = '0123456789abcdefABCDEF';
  cTokenChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' +
                '0123456789!#$%&''*+-.^_`|~';
  /// HTTP/1.1 connection-specific fields the shared header map rejects; they
  /// describe framing, not the application payload
  ForbiddenFields: array[0..4] of string = (
    'connection', 'keep-alive', 'transfer-encoding', 'upgrade',
    'proxy-connection');

function BytesOf(const S: string): TBytes;
begin
  Result := nil;
  SetLength(Result, Length(S));
  if Length(S) > 0 then
    Move(S[1], Result[0], Length(S));
end;

function ConcatBytes(const A, B: TBytes): TBytes;
var
  N: Integer;
begin
  Result := nil;
  N := Length(A);
  SetLength(Result, N + Length(B));
  if N > 0 then
    Move(A[0], Result[0], N);
  if Length(B) > 0 then
    Move(B[0], Result[N], Length(B));
end;

function IsHexDigit(const ACh: Char): Boolean;
begin
  Result := Pos(ACh, cHexDigits) > 0;
end;

function HexValue(const ACh: Char): Integer;
begin
  if (ACh >= '0') and (ACh <= '9') then
    Result := Ord(ACh) - Ord('0')
  else if (ACh >= 'a') and (ACh <= 'f') then
    Result := Ord(ACh) - Ord('a') + 10
  else
    Result := Ord(ACh) - Ord('A') + 10;
end;

function IsForbiddenField(const ALowerName: string): Boolean;
var
  I: Integer;
begin
  for I := Low(ForbiddenFields) to High(ForbiddenFields) do
    if ALowerName = ForbiddenFields[I] then
      Exit(True);
  Result := False;
end;

{ TBufferedReader }

constructor TBufferedReader.Create(const ASocket: IHttp2Socket);
begin
  inherited Create;
  FSocket := ASocket;
  FBuf := nil;
  FPos := 0;
  FEnd := 0;
end;

function TBufferedReader.Fill: Boolean;
var
  N: Integer;
  Tmp: TBytes;
begin
  // compact the consumed prefix so the buffer does not grow without bound
  if FPos > 0 then
  begin
    if FEnd > FPos then
      Move(FBuf[FPos], FBuf[0], FEnd - FPos);
    Dec(FEnd, FPos);
    FPos := 0;
  end;
  SetLength(Tmp, cHttp1ReadBufferSize);
  N := FSocket.Read(Tmp[0], cHttp1ReadBufferSize);
  if N <= 0 then
    Exit(False);
  if FEnd + N > Length(FBuf) then
    SetLength(FBuf, FEnd + N);
  Move(Tmp[0], FBuf[FEnd], N);
  Inc(FEnd, N);
  Result := True;
end;

function TBufferedReader.Buffered: Integer;
begin
  Result := FEnd - FPos;
end;

function TBufferedReader.ReadBytes(var ABuffer; const ACount: Integer): Integer;
var
  N: Integer;
  P: PByte;
begin
  Result := 0;
  if ACount <= 0 then
    Exit;
  if FPos >= FEnd then
    if not Fill then
      Exit;
  N := FEnd - FPos;
  if N > ACount then
    N := ACount;
  P := @ABuffer;
  Move(FBuf[FPos], P^, N);
  Inc(FPos, N);
  Result := N;
end;

function TBufferedReader.ReadExact(var ABuffer; const ACount: Integer): Integer;
var
  P: PByte;
  N: Integer;
begin
  Result := 0;
  P := @ABuffer;
  while Result < ACount do
  begin
    N := ReadBytes(P[Result], ACount - Result);
    if N = 0 then
      Break;
    Inc(Result, N);
  end;
end;

function TBufferedReader.ReadLineNoReadAhead(out ALine: string): Boolean;
var
  One: array[0..0] of Byte;
  Bytes: TBytes;
  N: Integer;
begin
  // This variant never reads past the terminating LF: it pulls one byte at a
  // time straight from the socket.  It is used at the h2c upgrade boundary,
  // where the bytes after the status line are HTTP/2 frames that must stay
  // in the socket for the HTTP/2 connection to read.
  ALine := '';
  SetLength(Bytes, 0);
  while True do
  begin
    if FPos < FEnd then
    begin
      SetLength(Bytes, Length(Bytes) + 1);
      Bytes[High(Bytes)] := FBuf[FPos];
      Inc(FPos);
    end
    else
    begin
      N := FSocket.Read(One[0], 1);
      if N <= 0 then
        Break;
      SetLength(Bytes, Length(Bytes) + 1);
      Bytes[High(Bytes)] := One[0];
    end;
    if Bytes[High(Bytes)] = 10 then
      Break;
    if Length(Bytes) > cHttp1MaxHeaderBytes then
      raise EHttpProtocolError.Create(
        'HTTP/1.1 header line exceeds the ' +
        IntToStr(cHttp1MaxHeaderBytes) + '-byte limit', ecProtocolError);
  end;
  if Length(Bytes) = 0 then
    Exit(False);
  if Bytes[High(Bytes)] = 10 then
    SetLength(Bytes, Length(Bytes) - 1);
  if (Length(Bytes) > 0) and (Bytes[High(Bytes)] = 13) then
    SetLength(Bytes, Length(Bytes) - 1);
  SetLength(ALine, Length(Bytes));
  if Length(Bytes) > 0 then
    Move(Bytes[0], ALine[1], Length(Bytes));
  Result := True;
end;

function TBufferedReader.ReadLine(out ALine: string): Boolean;
var
  I, Start, Len: Integer;
begin
  ALine := '';
  while True do
  begin
    for I := FPos to FEnd - 1 do
      if FBuf[I] = 10 then
      begin
        Start := FPos;
        Len := I - FPos;
        SetLength(ALine, Len);
        if Len > 0 then
          Move(FBuf[Start], ALine[1], Len);
        FPos := I + 1;
        if (Length(ALine) > 0) and (ALine[Length(ALine)] = #13) then
          SetLength(ALine, Length(ALine) - 1);
        Exit(True);
      end;
    // a single unterminated line is bounded by the header ceiling as well
    if (FEnd - FPos) > cHttp1MaxHeaderBytes then
      raise EHttpProtocolError.Create(
        'HTTP/1.1 header line exceeds the ' +
        IntToStr(cHttp1MaxHeaderBytes) + '-byte limit',
        ecProtocolError);
    if not Fill then
    begin
      if FEnd > FPos then
      begin
        Len := FEnd - FPos;
        SetLength(ALine, Len);
        Move(FBuf[FPos], ALine[1], Len);
        FPos := FEnd;
        Exit(True);
      end;
      Exit(False);
    end;
  end;
end;

{ THttp1BodyStream }

constructor THttp1BodyStream.Create(const AReader: TBufferedReader;
  const AFraming: TBodyFraming; const AContentLength: Int64;
  const ATrailers: IHttpHeaders);
begin
  inherited Create;
  FReader := AReader;
  FFraming := AFraming;
  FRemaining := AContentLength;
  FTrailers := ATrailers;
  FChunkRemaining := 0;
  // a bodyless response and an empty content-length body are complete already
  FDone := (AFraming = bfNone) or
           ((AFraming = bfContentLength) and (AContentLength = 0));
end;

procedure THttp1BodyStream.ReadTrailers;
var
  Line: string;
  Lines: TArray<string>;
  N, I: Integer;
  Fields: TArray<THttp1HeaderField>;
begin
  SetLength(Lines, 0);
  N := 0;
  while True do
  begin
    if not FReader.ReadLine(Line) then
      raise EHttpProtocolError.Create('truncated chunked trailer block',
        ecStreamClosed);
    if Line = '' then
      Break;
    SetLength(Lines, N + 1);
    Lines[N] := Line;
    Inc(N);
  end;
  if (N > 0) and (FTrailers <> nil) then
  begin
    Fields := ParseHeaders(Lines);
    for I := 0 to High(Fields) do
      if not IsForbiddenField(LowerCase(Fields[I].Name)) then
        FTrailers.Add(Fields[I].Name, Fields[I].Value);
  end;
end;

function THttp1BodyStream.ReadContentLength(var ABuffer;
  const ACount: LongInt): LongInt;
var
  N: Integer;
begin
  N := ACount;
  if Int64(N) > FRemaining then
    N := Integer(FRemaining);
  Result := FReader.ReadExact(PByte(@ABuffer)^, N);
  if Result <= 0 then
    raise EHttpProtocolError.Create('truncated response body',
      ecStreamClosed);
  Dec(FRemaining, Result);
  if FRemaining = 0 then
    FDone := True;   // the next Read observes EOF and returns 0
end;

function THttp1BodyStream.ReadChunked(var ABuffer;
  const ACount: LongInt): LongInt;
var
  Line, Term: string;
  Size: Int64;
  N: Integer;
begin
  while True do
  begin
    if FChunkRemaining > 0 then
    begin
      N := ACount;
      if Int64(N) > FChunkRemaining then
        N := Integer(FChunkRemaining);
      Result := FReader.ReadExact(PByte(@ABuffer)^, N);
      if Result <= 0 then
        raise EHttpProtocolError.Create('truncated chunked body',
          ecStreamClosed);
      Dec(FChunkRemaining, Result);
      if FChunkRemaining = 0 then
        FAtChunkEnd := True;
      Exit;
    end;
    if FAtChunkEnd then
    begin
      if not FReader.ReadLine(Term) then
        raise EHttpProtocolError.Create('truncated chunked body',
          ecStreamClosed);
      if Term <> '' then
        raise EHttpProtocolError.Create('malformed chunk terminator: ' + Term,
          ecProtocolError);
      FAtChunkEnd := False;
    end;
    if not FReader.ReadLine(Line) then
      raise EHttpProtocolError.Create('truncated chunk-size line',
        ecStreamClosed);
    Size := ParseChunkSize(Line);
    if Size = 0 then
    begin
      ReadTrailers;
      FDone := True;
      FObservedEof := True;   // this Read observes EOF and returns 0
      Exit(0);
    end;
    FChunkRemaining := Size;
  end;
end;

function THttp1BodyStream.ReadUntilClose(var ABuffer;
  const ACount: LongInt): LongInt;
begin
  Result := FReader.ReadBytes(PByte(@ABuffer)^, ACount);
  if Result = 0 then
  begin
    FDone := True;
    FObservedEof := True;   // this Read observes EOF and returns 0
  end;
end;

function THttp1BodyStream.Read(var ABuffer; const ACount: LongInt): LongInt;
begin
  Result := 0;
  if ACount <= 0 then
    Exit;
  if FDone then
  begin
    if FObservedEof then
      raise EHttpStreamError.Create('read after end of stream', 0,
        ecStreamClosed);
    FObservedEof := True;
    Exit(0);
  end;
  case FFraming of
    bfContentLength: Result := ReadContentLength(ABuffer, ACount);
    bfChunked:       Result := ReadChunked(ABuffer, ACount);
    bfUntilClose:    Result := ReadUntilClose(ABuffer, ACount);
  else
    // bfNone is FDone at construction; unreachable here
    FDone := True;
    FObservedEof := True;
    Result := 0;
  end;
end;

function THttp1BodyStream.Eof: Boolean;
begin
  // the body is complete once FDone is set; bytes still buffered in the
  // reader belong to the NEXT response, not to this body
  Result := FDone;
end;

{ THttp1Response }

constructor THttp1Response.Create(const AVersion: string;
  const AStatusCode: LongInt; const AReason: string;
  const AHeaders: IHttpHeaders; const ABody: IHttpBodyStream);
begin
  inherited Create;
  FVersion := AVersion;
  FStatusCode := AStatusCode;
  FReason := AReason;
  FHeaders := AHeaders;
  FBody := ABody;
end;

function THttp1Response.GetStatusCode: LongInt;
begin
  Result := FStatusCode;
end;

function THttp1Response.GetHeaders: IHttpHeaders;
begin
  Result := FHeaders;
end;

function THttp1Response.GetBody: IHttpBodyStream;
begin
  Result := FBody;
end;

{ request build / response parse }

function BuildHttp1Request(const ARequest: TStreamRequest): TBytes;
var
  Head: string;
  Names, Vals: TArray<string>;
  BodyBytes: TBytes;
  GenerateLength, GenerateChunked: Boolean;
  Host, Value, Chunk: string;
  Writer: IBodyWriter;
  Ch, All: TBytes;
  I, J: Integer;
begin
  Head := ARequest.Method;
  if Head = '' then
    Head := 'GET';
  if ARequest.Path = '' then
    Head := Head + ' / HTTP/1.1' + cCrLf
  else
    Head := Head + ' ' + ARequest.Path + ' HTTP/1.1' + cCrLf;

  // exactly one Host header: a caller-supplied value wins, else the authority
  Host := '';
  if ARequest.Headers <> nil then
    Host := ARequest.Headers.GetFirst(HeaderHost);
  if Host = '' then
    Host := ARequest.Authority;
  if Host = '' then
    raise EHttpProtocolError.Create('HTTP/1.1 request has no Host',
      ecProtocolError);
  Head := Head + 'Host: ' + Host + cCrLf;

  GenerateLength := ARequest.Body.IsSet;
  GenerateChunked := (not GenerateLength) and (ARequest.BodyWriter <> nil);

  if ARequest.Headers <> nil then
  begin
    Names := ARequest.Headers.Names;
    for I := 0 to High(Names) do
    begin
      if SameText(Names[I], HeaderHost) then
        Continue;
      if GenerateLength and SameText(Names[I], HeaderContentLength) then
        Continue;
      Vals := ARequest.Headers.GetValues(Names[I]);
      for J := 0 to High(Vals) do
      begin
        Value := Vals[J];
        Head := Head + Names[I] + ': ' + Value + cCrLf;
      end;
    end;
  end;

  All := nil;
  if GenerateLength then
  begin
    BodyBytes := ARequest.Body.Data;
    Head := Head + 'Content-Length: ' + IntToStr(Length(BodyBytes)) + cCrLf;
    Head := Head + cCrLf;
    All := ConcatBytes(BytesOf(Head), BodyBytes);
  end
  else if GenerateChunked then
  begin
    Head := Head + 'Transfer-Encoding: chunked' + cCrLf;
    Head := Head + cCrLf;
    All := BytesOf(Head);
    Writer := ARequest.BodyWriter;
    while Writer.NextChunk(Ch) do
    begin
      if Length(Ch) = 0 then
        Continue;   // a zero-length chunk would look like the terminator
      Chunk := IntToHex(Integer(Length(Ch)), 1) + cCrLf;
      All := ConcatBytes(All, BytesOf(Chunk));
      All := ConcatBytes(All, Ch);
      All := ConcatBytes(All, BytesOf(cCrLf));
    end;
    All := ConcatBytes(All, BytesOf('0' + cCrLf + cCrLf));
  end
  else
  begin
    Head := Head + cCrLf;
    All := BytesOf(Head);
  end;
  Result := All;
end;

procedure ParseStatusLine(const ALine: string; out AVersion: string;
  out AStatusCode: Integer; out AReason: string);
var
  P1, P2, I: Integer;
  CodeStr: string;
begin
  AVersion := '';
  AStatusCode := 0;
  AReason := '';
  P1 := Pos(' ', ALine);
  if P1 <= 1 then
    raise EHttpProtocolError.Create('malformed status line: ' + ALine,
      ecProtocolError);
  AVersion := Copy(ALine, 1, P1 - 1);
  // must be HTTP/<digit>.<digit>
  if (Copy(AVersion, 1, 5) <> 'HTTP/') or (Length(AVersion) <> 8) or
     ((AVersion[6] < '0') or (AVersion[6] > '9')) or (AVersion[7] <> '.') or
     ((AVersion[8] < '0') or (AVersion[8] > '9')) then
    raise EHttpProtocolError.Create('unsupported HTTP version: ' + AVersion,
      ecProtocolError);
  P2 := Pos(' ', ALine, P1 + 1);
  if P2 = 0 then
    CodeStr := Copy(ALine, P1 + 1, Length(ALine))
  else
  begin
    CodeStr := Copy(ALine, P1 + 1, P2 - P1 - 1);
    AReason := Copy(ALine, P2 + 1, Length(ALine));
  end;
  if Length(CodeStr) <> 3 then
    raise EHttpProtocolError.Create('status code is not 3 digits: ' + CodeStr,
      ecProtocolError);
  for I := 1 to 3 do
    if (CodeStr[I] < '0') or (CodeStr[I] > '9') then
      raise EHttpProtocolError.Create('status code is not numeric: ' + CodeStr,
        ecProtocolError);
  AStatusCode := StrToInt(CodeStr);
end;

function ParseHeaders(const ALines: TArray<string>): TArray<THttp1HeaderField>;
var
  I, J, P: Integer;
  Line, Name, Value: string;
  Ch: Char;
  Found: Boolean;
  Count: Integer;
begin
  Result := nil;
  Count := 0;
  for I := 0 to High(ALines) do
  begin
    Line := ALines[I];
    P := Pos(':', Line);
    if P <= 1 then
      raise EHttpProtocolError.Create('malformed header field: ' + Line,
        ecProtocolError);
    Name := Trim(Copy(Line, 1, P - 1));
    Value := Trim(Copy(Line, P + 1, Length(Line)));
    if Name = '' then
      raise EHttpProtocolError.Create('empty header field name',
        ecProtocolError);
    for J := 1 to Length(Name) do
    begin
      Ch := Name[J];
      if Pos(Ch, cTokenChars) = 0 then
        raise EHttpProtocolError.Create('invalid header field name: ' + Name,
          ecProtocolError);
    end;
    // join repeats (RFC 9110 section 5.2) except set-cookie
    Found := False;
    if not SameText(Name, HeaderSetCookie) then
      for J := 0 to Count - 1 do
        if SameText(Result[J].Name, Name) then
        begin
          Result[J].Value := Result[J].Value + ', ' + Value;
          Found := True;
          Break;
        end;
    if not Found then
    begin
      SetLength(Result, Count + 1);
      Result[Count].Name := Name;
      Result[Count].Value := Value;
      Inc(Count);
    end;
  end;
end;

function HeaderFieldValue(const AFields: TArray<THttp1HeaderField>;
  const AName: string): string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to High(AFields) do
    if SameText(AFields[I].Name, AName) then
      Exit(AFields[I].Value);
end;

function FieldsToHttpHeaders(
  const AFields: TArray<THttp1HeaderField>): IHttpHeaders;
var
  I: Integer;
begin
  Result := NewHttpHeaders;
  for I := 0 to High(AFields) do
    if not IsForbiddenField(LowerCase(AFields[I].Name)) then
      Result.Add(AFields[I].Name, AFields[I].Value);
end;

function ParseChunkSize(const ALine: string): Int64;
var
  S: string;
  P, I: Integer;
  Size: Int64;
begin
  S := ALine;
  P := Pos(';', S);
  if P > 0 then
    S := Copy(S, 1, P - 1);
  S := Trim(S);
  if S = '' then
    raise EHttpProtocolError.Create('empty chunk size', ecProtocolError);
  Size := 0;
  for I := 1 to Length(S) do
  begin
    if not IsHexDigit(S[I]) then
      raise EHttpProtocolError.Create('bad chunk size: ' + ALine,
        ecProtocolError);
    Size := Size * 16 + HexValue(S[I]);
    if Size > MaxInt then
      raise EHttpProtocolError.Create('chunk size too large: ' + ALine,
        ecProtocolError);
  end;
  Result := Size;
end;

function DecodeChunked(const AReader: TBufferedReader;
  out ATrailers: IHttpHeaders): TBytes;
var
  Line, Term: string;
  Size: Int64;
  Chunk: TBytes;
  Got: Integer;
  Lines: TArray<string>;
  N: Integer;
begin
  Result := nil;
  while True do
  begin
    if not AReader.ReadLine(Line) then
      raise EHttpProtocolError.Create('truncated chunk-size line',
        ecStreamClosed);
    Size := ParseChunkSize(Line);
    if Size = 0 then
      Break;
    SetLength(Chunk, Integer(Size));
    if Size > 0 then
    begin
      Got := AReader.ReadExact(Chunk[0], Integer(Size));
      if Got <> Integer(Size) then
        raise EHttpProtocolError.Create('truncated chunked body',
          ecStreamClosed);
    end;
    Result := ConcatBytes(Result, Chunk);
    if not AReader.ReadLine(Term) then
      raise EHttpProtocolError.Create('truncated chunked body',
        ecStreamClosed);
    if Term <> '' then
      raise EHttpProtocolError.Create('malformed chunk terminator: ' + Term,
        ecProtocolError);
  end;
  SetLength(Lines, 0);
  N := 0;
  while True do
  begin
    if not AReader.ReadLine(Line) then
      raise EHttpProtocolError.Create('truncated chunked trailer block',
        ecStreamClosed);
    if Line = '' then
      Break;
    SetLength(Lines, N + 1);
    Lines[N] := Line;
    Inc(N);
  end;
  if N > 0 then
    ATrailers := FieldsToHttpHeaders(ParseHeaders(Lines))
  else
    ATrailers := NewHttpHeaders;
end;

{ THttp1Connection }

constructor THttp1Connection.Create(const ASocket: IHttp2Socket;
  const ATimeoutMs: Integer);
begin
  inherited Create;
  if ASocket = nil then
    raise EHttpError.Create('THttp1Connection requires a socket',
      ecInternalError);
  FSocket := ASocket;
  FSocket.ReadTimeoutMs := ATimeoutMs;
  FSocket.WriteTimeoutMs := ATimeoutMs;
  FReader := TBufferedReader.Create(ASocket);
  FTimeoutMs := ATimeoutMs;
  FReusable := True;
  FLastTrailers := NewHttpHeaders;
end;

destructor THttp1Connection.Destroy;
begin
  FReader.Free;
  Close;
  inherited Destroy;
end;

procedure THttp1Connection.WriteAll(const ABytes: TBytes);
var
  Ofs, N: Integer;
begin
  Ofs := 0;
  while Ofs < Length(ABytes) do
  begin
    N := FSocket.Write(ABytes[Ofs], Length(ABytes) - Ofs);
    if N <= 0 then
      raise EHttpConnectionClosed.Create('HTTP/1.1 request write failed');
    Inc(Ofs, N);
  end;
end;

function THttp1Connection.BeginResponse(const ARequest: TStreamRequest): Boolean;
var
  Line: string;
begin
  // one request in flight at a time: the previous body must be drained
  if (FLastBody <> nil) and (not FLastBody.Eof) then
    raise EHttpProtocolError.Create(
      'previous HTTP/1.1 response body was not drained', ecProtocolError);
  if not FReusable then
    raise EHttpProtocolError.Create(
      'HTTP/1.1 connection cannot be reused (Connection: close or EOF body)',
      ecProtocolError);

  WriteAll(BuildHttp1Request(ARequest));
  Inc(FRequestCount);
  FSendRequest := ARequest;
  FBeginDone := False;

  // Read ONLY the status line, with no read-ahead: an h2c upgrade must leave
  // the bytes after the 101 in the socket for the HTTP/2 connection.
  if not FReader.ReadLineNoReadAhead(Line) then
    Exit(False);
  ParseStatusLine(Line, FVersion, FStatusCode, FReason);
  FBeginDone := True;
  Result := True;
end;

function THttp1Connection.FinishResponse: IHttpResponse;
var
  Head: TArray<string>;
  Line: string;
  Total, I: Integer;
  Fields: TArray<THttp1HeaderField>;
  Headers: IHttpHeaders;
  Framing: TBodyFraming;
  ContentLength: Int64;
  CL, TE, Connection: string;
  Bodyless: Boolean;
  Body: THttp1BodyStream;
  Trailers: IHttpHeaders;
begin
  if not FBeginDone then
    raise EHttpProtocolError.Create(
      'FinishResponse called before BeginResponse', ecInternalError);
  FBeginDone := False;   // consume: one status line per response

  // read the remaining header field lines, bounded
  Total := 0;
  SetLength(Head, 0);
  while True do
  begin
    if not FReader.ReadLine(Line) then
      raise EHttpProtocolError.Create('unexpected EOF in response head',
        ecStreamClosed);
    Inc(Total, Length(Line) + 2);
    if Total > cHttp1MaxHeaderBytes then
      raise EHttpProtocolError.Create(
        'HTTP/1.1 response header block exceeds the ' +
        IntToStr(cHttp1MaxHeaderBytes) + '-byte limit', ecProtocolError);
    if Line = '' then
      Break;
    SetLength(Head, Length(Head) + 1);
    Head[High(Head)] := Line;
  end;

  SetLength(Fields, 0);
  if Length(Head) > 0 then
    Fields := ParseHeaders(Head);
  FFields := Fields;
  Headers := FieldsToHttpHeaders(Fields);
  FHeaders := Headers;

  // bodyless responses: HEAD, 204 and 304 never carry a body even when a
  // content-length is present (RFC 9110 section 6.4.1)
  Bodyless := SameText(FSendRequest.Method, 'HEAD') or (FStatusCode = 204) or
    (FStatusCode = 304);

  CL := HeaderFieldValue(Fields, HeaderContentLength);
  TE := HeaderFieldValue(Fields, 'transfer-encoding');
  Connection := HeaderFieldValue(Fields, 'connection');
  ContentLength := 0;
  if Bodyless then
    Framing := bfNone
  else if (TE <> '') and (Pos('chunked', LowerCase(TE)) > 0) then
    Framing := bfChunked
  else if CL <> '' then
  begin
    if not TryStrToInt64(CL, ContentLength) or (ContentLength < 0) then
      raise EHttpProtocolError.Create('invalid content-length: ' + CL,
        ecProtocolError);
    Framing := bfContentLength;
  end
  else
    Framing := bfUntilClose;

  Trailers := NewHttpHeaders;
  Body := THttp1BodyStream.Create(FReader, Framing, ContentLength, Trailers);
  FLastBody := Body;
  FLastTrailers := Trailers;

  // keep-alive: HTTP/1.1 default unless "Connection: close"; read-to-close
  // framing always forbids reuse (the body ends only at EOF)
  FReusable := (Pos('close', LowerCase(Connection)) = 0) and
    (Framing <> bfUntilClose) and
    ((FVersion = 'HTTP/1.1') or
     (Pos('keep-alive', LowerCase(Connection)) > 0));

  Result := THttp1Response.Create(FVersion, FStatusCode, FReason, Headers,
    Body);
end;

function THttp1Connection.Send(const ARequest: TStreamRequest): IHttpResponse;
begin
  if not BeginResponse(ARequest) then
    raise EHttpProtocolError.Create('unexpected EOF in response head',
      ecStreamClosed);
  Result := FinishResponse;
end;

function THttp1Connection.GetReaderBuffered: Integer;
begin
  Result := FReader.Buffered;
end;

function THttp1Connection.Detach: IHttp2Socket;
begin
  if FReader.Buffered <> 0 then
    raise EHttpProtocolError.Create(
      'cannot detach: bytes were read past the status line', ecInternalError);
  Result := FSocket;
  FSocket := nil;        // ownership transfers; Close must not touch it
  FReusable := False;
end;

function THttp1Connection.Reusable: Boolean;
begin
  Result := FReusable;
end;

procedure THttp1Connection.Close;
begin
  FReusable := False;
  if FSocket <> nil then
    FSocket.Close;
end;

end.
