/// HTTP/1.1 codec tests (plan S13 task 13.4)
// - NOTHING here opens a real socket or touches the network: TSocketScript is
//   an in-memory IHttp2Socket that hands out scripted response bytes and
//   records every byte the codec wrote.
// - non-vacuous by construction: request bytes, the parsed status/headers, the
//   decoded chunked body with trailers, and keep-alive reuse are all asserted
//   from the exact wire bytes, so a broken request line, a dropped Host header
//   or a keep-alive regression fails a test.
unit Http2.Http1.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, fpcunit, testregistry,
  Http2.Errors, Http2.Headers, Http2.Tls, Http2.Stream, Http2.Messages,
  Http2.Http1;

type
  /// an in-memory byte script: Read serves FData from FPos and returns 0 at
  /// the end of the script (EOF); Write appends to FWritten.
  TSocketScript = class(TInterfacedObject, IHttp2Socket)
  private
    FData: TBytes;
    FPos: Integer;
    FWritten: TBytes;
    FClosed: Boolean;
  public
    constructor Create;
    /// append scripted server bytes
    procedure Feed(const AText: string);
    /// every byte the codec wrote, as text
    function WrittenText: string;
    // IHttp2Socket
    function Read(var ABuffer; ACount: Integer): Integer;
    function Write(const ABuffer; ACount: Integer): Integer;
    procedure Close;
    function GetConnected: Boolean;
    function GetConnectTimeoutMs: Integer;
    procedure SetConnectTimeoutMs(const AValue: Integer);
    function GetReadTimeoutMs: Integer;
    procedure SetReadTimeoutMs(const AValue: Integer);
    function GetWriteTimeoutMs: Integer;
    procedure SetWriteTimeoutMs(const AValue: Integer);
  end;

  /// a fixed IBodyWriter that yields a scripted list of chunks
  TScriptedBodyWriter = class(TInterfacedObject, IBodyWriter)
  private
    FChunks: TArray<TBytes>;
    FIndex: Integer;
  public
    constructor Create(const AChunks: array of string);
    function NextChunk(out ABuffer: TBytes): Boolean;
  end;

  THttp1Test = class(TTestCase)
  published
    procedure TestBuildGetRequest;
    procedure TestBuildPostRequestWithContentLength;
    procedure TestBuildRequestBodyWriterBecomesChunked;
    procedure TestBuildRequestRequiresHost;
    procedure TestParseStatusLine;
    procedure TestParseStatusLineRejectsGarbage;
    procedure TestParseHeadersJoinsRepeats;
    procedure TestParseHeadersRejectsMalformed;
    procedure TestParseChunkSizeIgnoresExtension;
    procedure TestParseChunkSizeRejectsBadSize;
    procedure TestResponseWithContentLengthBody;
    procedure TestChunkedResponseDecodeWithTrailers;
    procedure TestChunkedBodyStreamDecodesIncrementally;
    procedure TestKeepAliveReusesOneSocketForTwoRequests;
    procedure TestReadToCloseFramingForbidsReuse;
    procedure TestHeadResponseIsBodyless;
    procedure TestNoContentResponseIsBodyless;
    procedure TestBadStatusLineRaises;
    procedure TestBadChunkSizeRaises;
    procedure TestHeaderBlockLimitRaises;
    procedure TestBeginResponseReadsOnlyTheStatusLine;
    procedure TestDetachRefusesBufferedBytes;
    procedure TestDetachTransfersSocketOwnership;
  end;

implementation

function TextBytes(const S: string): TBytes;
begin
  Result := nil;
  SetLength(Result, Length(S));
  if Length(S) > 0 then
    Move(S[1], Result[0], Length(S));
end;

function BytesText(const B: TBytes): string;
begin
  Result := '';
  if Length(B) > 0 then
  begin
    SetLength(Result, Length(B));
    Move(B[0], Result[1], Length(B));
  end;
end;

{ TSocketScript }

constructor TSocketScript.Create;
begin
  inherited Create;
  FData := nil;
  FPos := 0;
  FWritten := nil;
  FClosed := False;
end;

procedure TSocketScript.Feed(const AText: string);
var
  B: TBytes;
begin
  B := TextBytes(AText);
  FData := FData + B;
end;

function TSocketScript.WrittenText: string;
begin
  Result := BytesText(FWritten);
end;

function TSocketScript.Read(var ABuffer; ACount: Integer): Integer;
var
  Avail, N: Integer;
begin
  if FClosed then
    Exit(0);
  Avail := Length(FData) - FPos;
  if Avail <= 0 then
    Exit(0);   // script exhausted: EOF
  N := ACount;
  if N > Avail then
    N := Avail;
  Move(FData[FPos], PByte(@ABuffer)^, N);
  Inc(FPos, N);
  Result := N;
end;

function TSocketScript.Write(const ABuffer; ACount: Integer): Integer;
var
  B: TBytes;
begin
  if FClosed then
    raise EHttpConnectionClosed.Create('scripted socket closed');
  SetLength(B, ACount);
  if ACount > 0 then
    Move(PByte(@ABuffer)^, B[0], ACount);
  FWritten := FWritten + B;
  Result := ACount;
end;

procedure TSocketScript.Close;
begin
  FClosed := True;
end;

function TSocketScript.GetConnected: Boolean;
begin
  Result := not FClosed;
end;

function TSocketScript.GetConnectTimeoutMs: Integer;
begin
  Result := 30000;
end;

procedure TSocketScript.SetConnectTimeoutMs(const AValue: Integer);
begin
end;

function TSocketScript.GetReadTimeoutMs: Integer;
begin
  Result := 30000;
end;

procedure TSocketScript.SetReadTimeoutMs(const AValue: Integer);
begin
end;

function TSocketScript.GetWriteTimeoutMs: Integer;
begin
  Result := 30000;
end;

procedure TSocketScript.SetWriteTimeoutMs(const AValue: Integer);
begin
end;

{ TScriptedBodyWriter }

constructor TScriptedBodyWriter.Create(const AChunks: array of string);
var
  I: Integer;
begin
  inherited Create;
  SetLength(FChunks, Length(AChunks));
  for I := 0 to High(AChunks) do
    FChunks[I] := TextBytes(AChunks[I]);
  FIndex := 0;
end;

function TScriptedBodyWriter.NextChunk(out ABuffer: TBytes): Boolean;
begin
  if FIndex >= Length(FChunks) then
  begin
    ABuffer := nil;
    Exit(False);
  end;
  ABuffer := FChunks[FIndex];
  Inc(FIndex);
  Result := True;
end;

{ helpers }

function NewGetRequest(const APath: string): TStreamRequest;
begin
  Result := TStreamRequest.Create('GET', 'example.com').WithPath(APath);
end;

/// read a whole body stream into a string
function DrainBody(const ABody: IHttpBodyStream): string;
var
  Buf: TBytes;
  N, Have: Integer;
begin
  SetLength(Buf, 256);
  Have := 0;
  while True do
  begin
    N := ABody.Read(Buf[Have], Length(Buf) - Have);
    if N = 0 then
      Break;
    Inc(Have, N);
    if Have = Length(Buf) then
      SetLength(Buf, Length(Buf) * 2);
  end;
  SetLength(Buf, Have);
  Result := BytesText(Buf);
end;

{ tests }

procedure THttp1Test.TestBuildGetRequest;
var
  Req: TStreamRequest;
  Wire: string;
begin
  Req := NewGetRequest('/hello');
  Wire := BytesText(BuildHttp1Request(Req));
  AssertTrue('request line',
    Pos('GET /hello HTTP/1.1'#13#10, Wire) = 1);
  AssertTrue('Host header present',
    Pos('Host: example.com'#13#10, Wire) > 0);
  AssertTrue('head ends with a blank line', Pos(#13#10#13#10, Wire) > 0);
end;

procedure THttp1Test.TestBuildPostRequestWithContentLength;
var
  Req: TStreamRequest;
  Wire: string;
begin
  Req := TStreamRequest.Create('POST', 'example.com').WithPath('/submit')
    .WithBody(THttpBody.FromString('abcde'));
  Wire := BytesText(BuildHttp1Request(Req));
  AssertTrue('request line',
    Pos('POST /submit HTTP/1.1'#13#10, Wire) = 1);
  AssertTrue('content-length reflects 5 body bytes',
    Pos('Content-Length: 5'#13#10, Wire) > 0);
  AssertTrue('body bytes follow the blank line',
    Pos(#13#10#13#10 + 'abcde', Wire) > 0);
end;

procedure THttp1Test.TestBuildRequestBodyWriterBecomesChunked;
var
  Req: TStreamRequest;
  Wire: string;
begin
  Req := TStreamRequest.Create('POST', 'example.com').WithPath('/stream')
    .WithBodyWriter(TScriptedBodyWriter.Create(['hello', ' world']));
  Wire := BytesText(BuildHttp1Request(Req));
  AssertTrue('chunked transfer-encoding',
    Pos('Transfer-Encoding: chunked'#13#10, Wire) > 0);
  AssertTrue('first chunk size + data',
    Pos('5'#13#10'hello'#13#10, Wire) > 0);
  AssertTrue('second chunk size + data',
    Pos('6'#13#10' world'#13#10, Wire) > 0);
  AssertTrue('terminating zero chunk',
    Pos('0'#13#10#13#10, Wire) > 0);
end;

procedure THttp1Test.TestBuildRequestRequiresHost;
var
  Req: TStreamRequest;
  Raised: Boolean;
begin
  Req := TStreamRequest.Create('GET', '');   // no authority
  Raised := False;
  try
    BuildHttp1Request(Req);
  except
    on E: EHttpProtocolError do
      Raised := True;
  end;
  AssertTrue('a missing Host raises', Raised);
end;

procedure THttp1Test.TestParseStatusLine;
var
  V, R: string;
  C: Integer;
begin
  ParseStatusLine('HTTP/1.1 200 OK', V, C, R);
  AssertEquals('version', 'HTTP/1.1', V);
  AssertEquals('status', 200, C);
  AssertEquals('reason', 'OK', R);
  // an empty reason phrase is legal
  ParseStatusLine('HTTP/1.0 204', V, C, R);
  AssertEquals('status without reason', 204, C);
  AssertEquals('empty reason', '', R);
end;

procedure THttp1Test.TestParseStatusLineRejectsGarbage;
var
  V, R: string;
  C: Integer;
  Raised: Boolean;
begin
  Raised := False;
  try
    ParseStatusLine('NOTHTTP 200 OK', V, C, R);
  except
    on E: EHttpProtocolError do
      Raised := True;
  end;
  AssertTrue('a non-HTTP version raises', Raised);

  Raised := False;
  try
    ParseStatusLine('HTTP/1.1 20 OK', V, C, R);
  except
    on E: EHttpProtocolError do
      Raised := True;
  end;
  AssertTrue('a two-digit status raises', Raised);
end;

procedure THttp1Test.TestParseHeadersJoinsRepeats;
var
  Fields: TArray<THttp1HeaderField>;
begin
  Fields := ParseHeaders(['Content-Type: text/plain',
    'X-Multi: a', 'X-Multi: b']);
  AssertEquals('two distinct names (repeats joined)', 2, Length(Fields));
  AssertEquals('content-type value', 'text/plain',
    HeaderFieldValue(Fields, 'content-type'));
  AssertEquals('repeats joined with comma', 'a, b',
    HeaderFieldValue(Fields, 'x-multi'));
end;

procedure THttp1Test.TestParseHeadersRejectsMalformed;
var
  Fields: TArray<THttp1HeaderField>;
  Raised: Boolean;
begin
  Raised := False;
  try
    Fields := ParseHeaders(['NoColonHere']);
  except
    on E: EHttpProtocolError do
      Raised := True;
  end;
  AssertTrue('a field without a colon raises', Raised);
end;

procedure THttp1Test.TestParseChunkSizeIgnoresExtension;
begin
  AssertEquals('plain hex', 255, ParseChunkSize('ff'));
  AssertEquals('extension ignored', 16, ParseChunkSize('10;foo=bar'));
end;

procedure THttp1Test.TestParseChunkSizeRejectsBadSize;
var
  Raised: Boolean;
begin
  Raised := False;
  try
    ParseChunkSize('xyz');
  except
    on E: EHttpProtocolError do
      Raised := True;
  end;
  AssertTrue('a non-hex chunk size raises', Raised);
end;

procedure THttp1Test.TestResponseWithContentLengthBody;
var
  Sock: TSocketScript;
  Conn: THttp1Connection;
  Resp: IHttpResponse;
  BodyText: string;
begin
  Sock := TSocketScript.Create;
  Sock.Feed('HTTP/1.1 200 OK'#13#10'Content-Type: text/plain'#13#10 +
    'Content-Length: 5'#13#10#13#10'hello');
  Conn := THttp1Connection.Create(Sock);
  try
    Resp := Conn.Send(NewGetRequest('/x'));
    AssertEquals('status', 200, Resp.StatusCode);
    AssertEquals('content-type',
      'text/plain', Resp.Headers.GetFirst('content-type'));
    AssertTrue('socket reusable', Conn.Reusable);
    BodyText := DrainBody(Resp.Body);
    AssertEquals('body', 'hello', BodyText);
    AssertTrue('body EOF after drain', Resp.Body.Eof);
  finally
    Conn.Free;
  end;
end;

procedure THttp1Test.TestChunkedResponseDecodeWithTrailers;
var
  Sock: TSocketScript;
  Conn: THttp1Connection;
  Resp: IHttpResponse;
  BodyText: string;
begin
  Sock := TSocketScript.Create;
  Sock.Feed('HTTP/1.1 200 OK'#13#10'Transfer-Encoding: chunked'#13#10#13#10 +
    '5'#13#10'hello'#13#10'6;ext=1'#13#10' world'#13#10 +
    '0'#13#10'X-Trailer: yes'#13#10#13#10);
  Conn := THttp1Connection.Create(Sock);
  try
    Resp := Conn.Send(NewGetRequest('/chunked'));
    AssertEquals('status', 200, Resp.StatusCode);
    BodyText := DrainBody(Resp.Body);
    AssertEquals('decoded body', 'hello world', BodyText);
    AssertEquals('trailer surfaced', 'yes',
      Conn.LastTrailers.GetFirst('x-trailer'));
    AssertTrue('socket reusable after chunked', Conn.Reusable);
  finally
    Conn.Free;
  end;
end;

procedure THttp1Test.TestChunkedBodyStreamDecodesIncrementally;
var
  Sock: TSocketScript;
  Conn: THttp1Connection;
  Resp: IHttpResponse;
  Buf: array[0..2] of Byte;
  N, Total: Integer;
begin
  Sock := TSocketScript.Create;
  Sock.Feed('HTTP/1.1 200 OK'#13#10'Transfer-Encoding: chunked'#13#10#13#10 +
    '3'#13#10'abc'#13#10'3'#13#10'def'#13#10'0'#13#10#13#10);
  Conn := THttp1Connection.Create(Sock);
  try
    Resp := Conn.Send(NewGetRequest('/small'));
    // read in 3-byte slices: the stream must hand back one chunk at a time
    Total := 0;
    while True do
    begin
      N := Resp.Body.Read(Buf[0], 3);
      if N = 0 then
        Break;
      Inc(Total, N);
    end;
    AssertEquals('total decoded bytes', 6, Total);
  finally
    Conn.Free;
  end;
end;

procedure THttp1Test.TestKeepAliveReusesOneSocketForTwoRequests;
var
  Sock: TSocketScript;
  Conn: THttp1Connection;
  R1, R2: IHttpResponse;
  Written: string;
begin
  Sock := TSocketScript.Create;
  Sock.Feed('HTTP/1.1 200 OK'#13#10'Content-Length: 2'#13#10#13#10'aa' +
    'HTTP/1.1 200 OK'#13#10'Content-Length: 2'#13#10#13#10'bb');
  Conn := THttp1Connection.Create(Sock);
  try
    R1 := Conn.Send(NewGetRequest('/a'));
    AssertEquals('first body', 'aa', DrainBody(R1.Body));
    AssertTrue('still reusable', Conn.Reusable);
    R2 := Conn.Send(NewGetRequest('/b'));
    AssertEquals('second status', 200, R2.StatusCode);
    AssertEquals('second body', 'bb', DrainBody(R2.Body));
    AssertEquals('two requests on one connection', 2, Conn.RequestCount);
    Written := Sock.WrittenText;
    AssertTrue('first request line written',
      Pos('GET /a HTTP/1.1'#13#10, Written) > 0);
    AssertTrue('second request line written on the same socket',
      Pos('GET /b HTTP/1.1'#13#10, Written) > 0);
  finally
    Conn.Free;
  end;
end;

procedure THttp1Test.TestReadToCloseFramingForbidsReuse;
var
  Sock: TSocketScript;
  Conn: THttp1Connection;
  Resp: IHttpResponse;
  Raised: Boolean;
begin
  Sock := TSocketScript.Create;
  // no content-length, not chunked: the body ends when the peer closes
  Sock.Feed('HTTP/1.1 200 OK'#13#10'Content-Type: text/plain'#13#10#13#10 +
    'until eof');
  Conn := THttp1Connection.Create(Sock);
  try
    Resp := Conn.Send(NewGetRequest('/close'));
    AssertEquals('body read to close', 'until eof', DrainBody(Resp.Body));
    AssertEquals('not reusable after read-to-close', False, Conn.Reusable);
    Raised := False;
    try
      Conn.Send(NewGetRequest('/again'));
    except
      on E: EHttpProtocolError do
        Raised := True;
    end;
    AssertTrue('a second request on a closed-framed connection raises',
      Raised);
  finally
    Conn.Free;
  end;
end;

procedure THttp1Test.TestHeadResponseIsBodyless;
var
  Sock: TSocketScript;
  Conn: THttp1Connection;
  Req: TStreamRequest;
  Resp: IHttpResponse;
begin
  Sock := TSocketScript.Create;
  // a HEAD reply advertises the length a GET would return, but sends no body
  Sock.Feed('HTTP/1.1 200 OK'#13#10'Content-Length: 100'#13#10#13#10);
  Conn := THttp1Connection.Create(Sock);
  try
    Req := TStreamRequest.Create('HEAD', 'example.com').WithPath('/h');
    Resp := Conn.Send(Req);
    AssertEquals('status', 200, Resp.StatusCode);
    AssertTrue('bodyless HEAD is EOF immediately', Resp.Body.Eof);
    AssertEquals('no body bytes', '', DrainBody(Resp.Body));
    AssertTrue('HEAD connection stays reusable', Conn.Reusable);
  finally
    Conn.Free;
  end;
end;

procedure THttp1Test.TestNoContentResponseIsBodyless;
var
  Sock: TSocketScript;
  Conn: THttp1Connection;
  Resp: IHttpResponse;
begin
  Sock := TSocketScript.Create;
  Sock.Feed('HTTP/1.1 204 No Content'#13#10'Content-Length: 7'#13#10#13#10);
  Conn := THttp1Connection.Create(Sock);
  try
    Resp := Conn.Send(NewGetRequest('/empty'));
    AssertEquals('status', 204, Resp.StatusCode);
    AssertTrue('204 bodyless', Resp.Body.Eof);
    AssertEquals('no body', '', DrainBody(Resp.Body));
  finally
    Conn.Free;
  end;
end;

procedure THttp1Test.TestBadStatusLineRaises;
var
  Sock: TSocketScript;
  Conn: THttp1Connection;
  Raised: Boolean;
begin
  Sock := TSocketScript.Create;
  Sock.Feed('GARBAGE RESPONSE'#13#10#13#10);
  Conn := THttp1Connection.Create(Sock);
  try
    Raised := False;
    try
      Conn.Send(NewGetRequest('/bad'));
    except
      on E: EHttpProtocolError do
        Raised := True;
    end;
    AssertTrue('a malformed status line raises', Raised);
  finally
    Conn.Free;
  end;
end;

procedure THttp1Test.TestBadChunkSizeRaises;
var
  Sock: TSocketScript;
  Conn: THttp1Connection;
  Resp: IHttpResponse;
  Raised: Boolean;
begin
  Sock := TSocketScript.Create;
  Sock.Feed('HTTP/1.1 200 OK'#13#10'Transfer-Encoding: chunked'#13#10#13#10 +
    'zz'#13#10'nope'#13#10);
  Conn := THttp1Connection.Create(Sock);
  try
    Resp := Conn.Send(NewGetRequest('/badchunk'));
    Raised := False;
    try
      DrainBody(Resp.Body);
    except
      on E: EHttpProtocolError do
        Raised := True;
    end;
    AssertTrue('a bad chunk size raises while reading', Raised);
  finally
    Conn.Free;
  end;
end;

procedure THttp1Test.TestHeaderBlockLimitRaises;
var
  Sock: TSocketScript;
  Conn: THttp1Connection;
  Big: string;
  Raised: Boolean;
begin
  Sock := TSocketScript.Create;
  // a header field far larger than the documented 64 KiB ceiling
  Big := 'HTTP/1.1 200 OK'#13#10'X-Big: ' + StringOfChar('a', cHttp1MaxHeaderBytes + 16)
    + #13#10#13#10;
  Sock.Feed(Big);
  Conn := THttp1Connection.Create(Sock);
  try
    Raised := False;
    try
      Conn.Send(NewGetRequest('/big'));
    except
      on E: EHttpProtocolError do
        Raised := True;
    end;
    AssertTrue('an oversized header block raises', Raised);
  finally
    Conn.Free;
  end;
end;

procedure THttp1Test.TestBeginResponseReadsOnlyTheStatusLine;
var
  Sock: TSocketScript;
  Conn: THttp1Connection;
  Resp: IHttpResponse;
begin
  // an h2c upgrade: after "101" the bytes that follow are HTTP/2 frames that
  // must stay in the socket.  BeginResponse must not read past the status
  // line, so idle 101 followed by a SETTINGS frame keeps PendingBytes at 0.
  Sock := TSocketScript.Create;
  Sock.Feed('HTTP/1.1 101 Switching Protocols'#13#10);
  Sock.Feed('X: y'#13#10#13#10);
  Conn := THttp1Connection.Create(Sock);
  try
    AssertTrue('status line read', Conn.BeginResponse(NewGetRequest('/')));
    AssertEquals('status', 101, Conn.StatusCode);
    AssertEquals('no read-ahead past the status line', 0, Conn.PendingBytes);
    Resp := Conn.FinishResponse;
    AssertEquals('finish keeps status', 101, Resp.StatusCode);
    AssertEquals('finish parsed the field', 'y',
      Resp.Headers.GetFirst('x'));
  finally
    Conn.Free;
  end;
end;

procedure THttp1Test.TestDetachRefusesBufferedBytes;
var
  Sock: TSocketScript;
  Conn: THttp1Connection;
  Raised: Boolean;
begin
  // a normal Send reads the head with read-ahead, so a buffered byte can be
  // left over.  Detach must refuse rather than silently discard it.
  Sock := TSocketScript.Create;
  Sock.Feed('HTTP/1.1 200 OK'#13#10'Content-Length: 5'#13#10#13#10'hello');
  Conn := THttp1Connection.Create(Sock);
  try
    Conn.Send(NewGetRequest('/x'));
    Raised := False;
    try
      Conn.Detach;
    except
      on E: EHttpError do
        Raised := True;
    end;
    AssertTrue('detach with buffered bytes raises', Raised);
  finally
    Conn.Free;
  end;
end;

procedure THttp1Test.TestDetachTransfersSocketOwnership;
var
  Sock: TSocketScript;
  Conn: THttp1Connection;
  Detached: IHttp2Socket;
begin
  // after a status-only BeginResponse, Detach must hand the socket back and
  // must NOT close it when the connection is freed
  Sock := TSocketScript.Create;
  Sock.Feed('HTTP/1.1 101 Switching Protocols'#13#10#13#10);
  Conn := THttp1Connection.Create(Sock);
  Conn.BeginResponse(NewGetRequest('/'));
  Detached := Conn.Detach;
  Conn.Free;                       // must not close the detached socket
  AssertTrue('socket survives Detach', Detached.GetConnected);
end;

initialization
  RegisterTest(THttp1Test);
end.
