/// Public-API client tests (plan story S09: factory, pool, Send, Close,
/// response types, generic reader).
// - the pool tests use an injected IHttp2SocketFactory that returns an
//   in-memory scripted server socket, so NO real sockets are opened.
// - non-vacuous by construction: the cap test asserts the observed dial count
//   and connection count equal MaxConnections (mutating the pool to ignore the
//   cap fails it); pseudo-header/port-omission is asserted from the DECODED
//   wire block in Http2.Request.Test.pas.
unit Http2.Client.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, SyncObjs, Generics.Collections, fpcunit, testregistry,
  Http2.Errors, Http2.Frames, Http2.Headers, Http2.Hpack,
  Http2.Tls, Http2.Connection, Http2.Stream, Http2.Client, Http2.Observer;

type
  /// a scripted in-memory HTTP/2 server: parses every frame the client writes
  /// and answers each request HEADERS with a configured response.
  TFakeServerSocket = class(TInterfacedObject, IHttp2Socket)
  private
    FLock: TCriticalSection;
    FAcc: TBytes;                 // all bytes the client has written
    FParsePos: Integer;
    FPrefaceDone: Boolean;
    FIn: TBytes;                  // bytes the client may read
    FReadPos: Integer;
    FStatus: string;
    FBody: TBytes;
    FEndStream: Boolean;
    FCodec: THpackCodec;
    FConnected: Boolean;
    FConnectTimeoutMs, FReadTimeoutMs, FWriteTimeoutMs: Integer;
    procedure AppendWritten(const ABuffer; const ACount: Integer);
    procedure ParseAvailable;
    procedure EmitResponse(const AStreamId: LongWord);
    function FrameBytes(const AF: TFrame): TBytes;
  public
    constructor Create;
    destructor Destroy; override;
    procedure SetResponse(const AStatus: string; const ABody: TBytes;
      const AEndStream: Boolean);
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

  /// counts dials and hands out fresh fake server sockets. ResponseEndStream=
  /// False makes the fake answer with HEADERS only (no END_STREAM, no DATA),
  /// so a lease stays registered and the pool cap binds.
  TFakeSocketFactory = class(TInterfacedObject, IHttp2SocketFactory)
  private
    FLock: TCriticalSection;
    FDials: Integer;
    FResponseBody: TBytes;
    FResponseEndStream: Boolean;
    FResponseStatus: string;
  public
    constructor Create;
    destructor Destroy; override;
    function Dial(const AHost: string; const APort: Word;
      const ATimeoutMs: Integer): IHttp2Socket;
    function Dials: Integer;
    procedure SetResponse(const AStatus: string; const ABody: TBytes;
      const AEndStream: Boolean);
  end;

  /// a fake IConnectionStream used only to raise a connection's stream count
  TFakeConnStream = class(TInterfacedObject, IConnectionStream)
  public
    procedure OnConnectionFailed(const AMessage: string;
      const ACode: THttp2ErrorCode);
    procedure OnConnectionGoAway(const ALastStreamId: LongWord);
    procedure OnStreamFrame(const AFrame: TFrame);
  end;

  /// a fake pooled connection for least-loaded pool tests (no sockets)
  TFakePooledConnection = class(TInterfacedObject, IPooledConnection)
  private
    FLoad: Integer;
    FEligible: Boolean;
    FOrigin: string;
    FConn: TConnection;
    FLock: TCriticalSection;
  public
    constructor Create(const AOrigin: string; const ALoad: Integer;
      const AEligible: Boolean);
    destructor Destroy; override;
    function ActiveStreams: Integer;
    function Eligible: Boolean;
    function Acquire(const ARequest: TStreamRequest; const ATimeoutMs: Integer;
      out AAcquired: Boolean): IHttpResponse;
    procedure Drain;
    procedure ReleaseIfIdle;
    function GetConn: TConnection;
    function GetOrigin: string;
    function GetLock: TCriticalSection;
  end;

  /// a fake response + body stream for TResponseReader<T> tests
  TFakeBody = class(TInterfacedObject, IHttpBodyStream)
  private
    FData: TBytes;
    FPos: Integer;
  public
    constructor Create(const AData: TBytes);
    function Read(var ABuffer; const ACount: LongInt): LongInt;
    function Eof: Boolean;
  end;

  TFakeResponse = class(TInterfacedObject, IHttpResponse)
  private
    FStatus: LongInt;
    FHeaders: IHttpHeaders;
    FBody: IHttpBodyStream;
  public
    constructor Create(const AStatus: LongInt; const ABody: IHttpBodyStream);
    function GetStatusCode: LongInt;
    function GetHeaders: IHttpHeaders;
    function GetBody: IHttpBodyStream;
  end;

  /// one thread performing a single Send against a shared client
  TSendWorker = class(TThread)
  private
    FClient: IHttpClient;
    FUrl: string;
    FDone: PRTLEvent;
    FDoneFlag: Boolean;
    FStatus: LongInt;
    FError: string;
    FRaised: Boolean;
    FResponse: IHttpResponse;   // retained so the stream stays registered
  protected
    procedure Execute; override;
  public
    constructor Create(const AClient: IHttpClient; const AUrl: string);
    destructor Destroy; override;
    function WaitDone(const ATimeoutMs: Integer): Boolean;
    property Status: LongInt read FStatus;
    property Raised: Boolean read FRaised;
    property Error: string read FError;
  end;

  TClientTest = class(TTestCase)
  published
    // 09.1
    procedure TestFactoryDefaults;
    procedure TestFactoryIsImmutable;
    procedure TestDocumentedFluentChainBuilds;
    // 09.2
    procedure TestSendReturnsStatusHeadersAndBody;
    // 09.3
    procedure TestResponseReaderDecodesBytes;
    procedure TestResponseReaderDecodesString;
    procedure TestResponseReaderDecodesRecord;
    // 09.5
    procedure TestPoolNeverExceedsMaxConnections;
    procedure TestConcurrentSendAcrossOneConnection;
    // 09.6
    procedure TestLeastLoadedSelection;
    procedure TestPerConnectionStreamCap;
    // 09.8
    procedure TestCloseRejectsNewSends;
    procedure TestCloseKeepsOutstandingBodyReadable;
    // 09.10 / integration (opt-in: set HTTP2_LIVE_ITEST=1 and run nghttpd)
    procedure TestLiveGetAgainstNghttpd;
    procedure TestLivePostEchoAgainstNghttpd;
    // S11 wiring: the factory-level observer reaches real connections
    procedure TestFactoryObserverReceivesConnectionAndFrameEvents;
  end;

implementation

{ TFakeServerSocket }

constructor TFakeServerSocket.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FCodec := THpackCodec.Create;
  FStatus := '200';
  FBody := nil;
  FEndStream := True;
  FConnected := True;
  FConnectTimeoutMs := 1000;
  FReadTimeoutMs := 1000;
  FWriteTimeoutMs := 1000;
end;

destructor TFakeServerSocket.Destroy;
begin
  FCodec.Free;
  FLock.Free;
  inherited Destroy;
end;

procedure TFakeServerSocket.SetResponse(const AStatus: string;
  const ABody: TBytes; const AEndStream: Boolean);
begin
  FLock.Acquire;
  try
    FStatus := AStatus;
    FBody := ABody;
    FEndStream := AEndStream;
  finally
    FLock.Release;
  end;
end;

function TFakeServerSocket.FrameBytes(const AF: TFrame): TBytes;
var
  MS: TMemoryStream;
begin
  Result := nil;
  MS := TMemoryStream.Create;
  try
    WriteFrame(MS, AF);
    SetLength(Result, MS.Size);
    if MS.Size > 0 then
      Move(MS.Memory^, Result[0], MS.Size);
  finally
    MS.Free;
  end;
end;

procedure TFakeServerSocket.EmitResponse(const AStreamId: LongWord);
var
  Block: THeaderBlock;
  Enc: TBytes;
  F: TFrame;
begin
  SetLength(Block, 1);
  Block[0].Name := ':status';
  Block[0].Value := FStatus;
  Block[0].Sensitive := False;
  Enc := FCodec.Encode(Block);
  if Length(FBody) = 0 then
  begin
    F := BuildHeadersFrame(AStreamId, Enc, True, FEndStream);
    FIn := FIn + FrameBytes(F);
  end
  else
  begin
    F := BuildHeadersFrame(AStreamId, Enc, True, False);
    FIn := FIn + FrameBytes(F);
    F := BuildDataFrame(AStreamId, FBody, FEndStream);
    FIn := FIn + FrameBytes(F);
  end;
end;

procedure TFakeServerSocket.AppendWritten(const ABuffer;
  const ACount: Integer);
var
  P: PByte;
  N: Integer;
begin
  if ACount <= 0 then
    Exit;
  P := @ABuffer;
  N := Length(FAcc);
  SetLength(FAcc, N + ACount);
  Move(P^, FAcc[N], ACount);
end;

procedure TFakeServerSocket.ParseAvailable;
var
  Len, Typ: Integer;
  StreamId: LongWord;
  Total: Integer;
begin
  if not FPrefaceDone then
  begin
    if Length(FAcc) < 24 then
      Exit;
    FParsePos := 24;
    FPrefaceDone := True;
  end;
  while Length(FAcc) - FParsePos >= FrameHeaderSize do
  begin
    Len := (FAcc[FParsePos] shl 16) or (FAcc[FParsePos + 1] shl 8) or
      FAcc[FParsePos + 2];
    Typ := FAcc[FParsePos + 3];
    StreamId := (LongWord(FAcc[FParsePos + 5]) shl 24) or
      (LongWord(FAcc[FParsePos + 6]) shl 16) or
      (LongWord(FAcc[FParsePos + 7]) shl 8) or LongWord(FAcc[FParsePos + 8]);
    if Length(FAcc) - FParsePos < FrameHeaderSize + Len then
      Exit;
    Total := FrameHeaderSize + Len;
    Inc(FParsePos, Total);
    if (Typ = Ord(ftHeaders)) and (StreamId <> 0) then
      EmitResponse(StreamId);
  end;
end;

function TFakeServerSocket.Write(const ABuffer; ACount: Integer): Integer;
begin
  FLock.Acquire;
  try
    if not FConnected then
      raise EHttpConnectionClosed.Create('fake socket closed');
    AppendWritten(ABuffer, ACount);
    ParseAvailable;
  finally
    FLock.Release;
  end;
  Result := ACount;
end;

function TFakeServerSocket.Read(var ABuffer; ACount: Integer): Integer;
var
  Avail, N: Integer;
  P: PByte;
begin
  FLock.Acquire;
  try
    if not FConnected then
      Exit(0);
    Avail := Length(FIn) - FReadPos;
    if Avail <= 0 then
      raise EHttpTimeout.Create('fake read idle');
    N := ACount;
    if N > Avail then
      N := Avail;
    P := @ABuffer;
    Move(FIn[FReadPos], P^, N);
    Inc(FReadPos, N);
    Result := N;
  finally
    FLock.Release;
  end;
end;

procedure TFakeServerSocket.Close;
begin
  FConnected := False;
end;

function TFakeServerSocket.GetConnected: Boolean;
begin
  Result := FConnected;
end;

function TFakeServerSocket.GetConnectTimeoutMs: Integer;
begin
  Result := FConnectTimeoutMs;
end;

procedure TFakeServerSocket.SetConnectTimeoutMs(const AValue: Integer);
begin
  FConnectTimeoutMs := AValue;
end;

function TFakeServerSocket.GetReadTimeoutMs: Integer;
begin
  Result := FReadTimeoutMs;
end;

procedure TFakeServerSocket.SetReadTimeoutMs(const AValue: Integer);
begin
  FReadTimeoutMs := AValue;
end;

function TFakeServerSocket.GetWriteTimeoutMs: Integer;
begin
  Result := FWriteTimeoutMs;
end;

procedure TFakeServerSocket.SetWriteTimeoutMs(const AValue: Integer);
begin
  FWriteTimeoutMs := AValue;
end;

{ TFakeSocketFactory }

constructor TFakeSocketFactory.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FResponseStatus := '200';
  FResponseBody := nil;
  FResponseEndStream := True;
end;

destructor TFakeSocketFactory.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

procedure TFakeSocketFactory.SetResponse(const AStatus: string;
  const ABody: TBytes; const AEndStream: Boolean);
begin
  FLock.Acquire;
  try
    FResponseStatus := AStatus;
    FResponseBody := ABody;
    FResponseEndStream := AEndStream;
  finally
    FLock.Release;
  end;
end;

function TFakeSocketFactory.Dial(const AHost: string; const APort: Word;
  const ATimeoutMs: Integer): IHttp2Socket;
var
  S: TFakeServerSocket;
begin
  S := TFakeServerSocket.Create;
  FLock.Acquire;
  try
    Inc(FDials);
    S.SetResponse(FResponseStatus, FResponseBody, FResponseEndStream);
  finally
    FLock.Release;
  end;
  Result := S;
end;

function TFakeSocketFactory.Dials: Integer;
begin
  FLock.Acquire;
  try
    Result := FDials;
  finally
    FLock.Release;
  end;
end;

{ TFakeConnStream }

procedure TFakeConnStream.OnConnectionFailed(const AMessage: string;
  const ACode: THttp2ErrorCode);
begin
end;

procedure TFakeConnStream.OnConnectionGoAway(const ALastStreamId: LongWord);
begin
end;

procedure TFakeConnStream.OnStreamFrame(const AFrame: TFrame);
begin
end;

{ TFakePooledConnection }

constructor TFakePooledConnection.Create(const AOrigin: string;
  const ALoad: Integer; const AEligible: Boolean);
begin
  inherited Create;
  FOrigin := AOrigin;
  FLoad := ALoad;
  FEligible := AEligible;
  FLock := TCriticalSection.Create;
  FConn := TConnection.Create(TFakeServerSocket.Create);
end;

destructor TFakePooledConnection.Destroy;
begin
  FConn.Free;
  FLock.Free;
  inherited Destroy;
end;

function TFakePooledConnection.ActiveStreams: Integer;
begin
  Result := FLoad;
end;

function TFakePooledConnection.Eligible: Boolean;
begin
  Result := FEligible;
end;

function TFakePooledConnection.Acquire(const ARequest: TStreamRequest;
  const ATimeoutMs: Integer; out AAcquired: Boolean): IHttpResponse;
begin
  AAcquired := False;
  Result := nil;
end;

procedure TFakePooledConnection.Drain;
begin
  FEligible := False;
end;

procedure TFakePooledConnection.ReleaseIfIdle;
begin
end;

function TFakePooledConnection.GetConn: TConnection;
begin
  Result := FConn;
end;

function TFakePooledConnection.GetOrigin: string;
begin
  Result := FOrigin;
end;

function TFakePooledConnection.GetLock: TCriticalSection;
begin
  Result := FLock;
end;

{ TFakeBody }

constructor TFakeBody.Create(const AData: TBytes);
begin
  inherited Create;
  FData := AData;
  FPos := 0;
end;

function TFakeBody.Read(var ABuffer; const ACount: LongInt): LongInt;
var
  Avail, N: Integer;
  P: PByte;
begin
  Avail := Length(FData) - FPos;
  if Avail <= 0 then
    Exit(0);
  N := ACount;
  if N > Avail then
    N := Avail;
  P := @ABuffer;
  Move(FData[FPos], P^, N);
  Inc(FPos, N);
  Result := N;
end;

function TFakeBody.Eof: Boolean;
begin
  Result := FPos >= Length(FData);
end;

{ TFakeResponse }

constructor TFakeResponse.Create(const AStatus: LongInt;
  const ABody: IHttpBodyStream);
begin
  inherited Create;
  FStatus := AStatus;
  FBody := ABody;
  FHeaders := NewHttpHeaders;
end;

function TFakeResponse.GetStatusCode: LongInt;
begin
  Result := FStatus;
end;

function TFakeResponse.GetHeaders: IHttpHeaders;
begin
  Result := FHeaders;
end;

function TFakeResponse.GetBody: IHttpBodyStream;
begin
  Result := FBody;
end;

{ TSendWorker }

constructor TSendWorker.Create(const AClient: IHttpClient; const AUrl: string);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FClient := AClient;
  FUrl := AUrl;
  FDone := RTLEventCreate;
end;

destructor TSendWorker.Destroy;
begin
  RTLEventDestroy(FDone);
  inherited Destroy;
end;

procedure TSendWorker.Execute;
var
  R: IHttpResponse;
begin
  try
    R := FClient.Send(THttpRequest.Create(hmGet, FUrl));
    FResponse := R;
    FStatus := R.StatusCode;
  except
    on E: Exception do
    begin
      FRaised := True;
      FError := E.ClassName + ': ' + E.Message;
      if E is EHttpError then
        FStatus := -1;
    end;
  end;
  FDoneFlag := True;
  RTLEventSetEvent(FDone);
end;

function TSendWorker.WaitDone(const ATimeoutMs: Integer): Boolean;
var
  Deadline: QWord;
  Remaining: Integer;
begin
  Deadline := GetTickCount64 + QWord(ATimeoutMs);
  while not FDoneFlag do
  begin
    if GetTickCount64 >= Deadline then
      Exit(False);
    Remaining := Integer(Deadline - GetTickCount64);
    RTLEventWaitFor(FDone, Remaining);
  end;
  Result := True;
end;

{ helpers }

function BytesOf(const A: string): TBytes;
var
  I: Integer;
begin
  Result := nil;
  SetLength(Result, Length(A));
  for I := 1 to Length(A) do
    Result[I - 1] := Ord(A[I]);
end;

function StrOf(const A: TBytes): string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to High(A) do
    Result := Result + Chr(A[I]);
end;

function ReadWholeBody(const ABody: IHttpBodyStream): string;
var
  Buf: array[0..255] of Byte;
  N: LongInt;
  B: TBytes;
begin
  Result := '';
  while True do
  begin
    N := ABody.Read(Buf, SizeOf(Buf));
    if N <= 0 then
      Break;
    SetLength(B, N);
    Move(Buf[0], B[0], N);
    Result := Result + StrOf(B);
  end;
end;

{ TClientTest }

procedure TClientTest.TestFactoryDefaults;
var
  F: THttpClientFactory;
begin
  F := THttpClientFactory.Create;
  AssertEquals('MaxConnections default', 4, F.MaxConnections);
  AssertEquals('MaxStreamsPerConnection default', 100,
    F.MaxStreamsPerConnection);
  AssertTrue('FollowRedirects default', F.FollowRedirects);
  AssertEquals('MaxRedirects default', 10, F.MaxRedirects);
  AssertEquals('ConnectTimeoutMs default', 10000, F.ConnectTimeoutMs);
  AssertEquals('HeaderTimeoutMs default', 30000, F.HeaderTimeoutMs);
  AssertEquals('IdleTimeoutMs default', 60000, F.IdleTimeoutMs);
  AssertEquals('ProxyHost default', '', F.ProxyHost);
  AssertEquals('ProxyPort default', 0, Ord(F.ProxyPort));
end;

procedure TClientTest.TestFactoryIsImmutable;
var
  Base, Forked: THttpClientFactory;
begin
  Base := THttpClientFactory.Create;
  Forked := Base.WithMaxConnections(8).WithFollowRedirects(False);
  AssertEquals('fork changed MaxConnections', 8, Forked.MaxConnections);
  AssertFalse('fork changed FollowRedirects', Forked.FollowRedirects);
  // the original is untouched
  AssertEquals('base MaxConnections unchanged', 4, Base.MaxConnections);
  AssertTrue('base FollowRedirects unchanged', Base.FollowRedirects);
  // chaining twice from one base yields independent records
  AssertEquals('base MaxStreams unchanged', 100, Base.MaxStreamsPerConnection);
  AssertEquals('fork MaxStreams unchanged', 100, Forked.MaxStreamsPerConnection);
end;

procedure TClientTest.TestDocumentedFluentChainBuilds;
var
  Client: IHttpClient;
begin
  Client := THttpClientFactory.Create
    .WithMaxConnections(8)
    .WithMaxStreamsPerConnection(50)
    .WithFollowRedirects(False)
    .Build;
  AssertTrue('the documented chain builds a client', Client <> nil);
  Client.Close;
end;

procedure TClientTest.TestSendReturnsStatusHeadersAndBody;
var
  Factory: TFakeSocketFactory;
  Client: IHttpClient;
  R: IHttpResponse;
begin
  Factory := TFakeSocketFactory.Create;
  Client := THttpClientFactory.Create
    .WithSocketFactory(Factory)
    .Build;
  R := Client.Send(THttpRequest.Create(hmGet, 'https://api.example/thing'));
  AssertEquals('status decoded from the wire', 200, R.StatusCode);
  AssertEquals('body streamed', '', ReadWholeBody(R.Body));
  AssertEquals('exactly one connection dialled', 1, Factory.Dials);
  Client.Close;
end;

procedure TClientTest.TestResponseReaderDecodesBytes;
var
  Resp: IHttpResponse;
  V: TBytes;
begin
  Resp := TFakeResponse.Create(200, TFakeBody.Create(BytesOf('abcd')));
  TResponseReader<TBytes>.Read(Resp, V);
  AssertEquals('byte count', 4, Length(V));
  AssertEquals('byte content', 'abcd', StrOf(V));
end;

procedure TClientTest.TestResponseReaderDecodesString;
var
  Resp: IHttpResponse;
  V: AnsiString;
begin
  Resp := TFakeResponse.Create(200, TFakeBody.Create(BytesOf('hello')));
  TResponseReader<AnsiString>.Read(Resp, V);
  AssertEquals('string content', 'hello', string(V));
end;

type
  TSmallDto = record
    A, B: LongWord;
  end;

procedure TClientTest.TestResponseReaderDecodesRecord;
var
  Resp: IHttpResponse;
  V: TSmallDto;
  Raw: TBytes;
begin
  SetLength(Raw, SizeOf(TSmallDto));
  LongWord(Pointer(@Raw[0])^) := $11223344;
  LongWord(Pointer(@Raw[4])^) := $55667788;
  Resp := TFakeResponse.Create(200, TFakeBody.Create(Raw));
  TResponseReader<TSmallDto>.Read(Resp, V);
  AssertEquals('first field', LongWord($11223344), V.A);
  AssertEquals('second field', LongWord($55667788), V.B);
end;

procedure TClientTest.TestPoolNeverExceedsMaxConnections;
var
  Factory: TFakeSocketFactory;
  Client: IHttpClient;
  Pool: TConnectionPool;
  Workers: array[0..5] of TSendWorker;
  I, Succeeded, TimedOut, Timeouts: Integer;
begin
  Factory := TFakeSocketFactory.Create;
  // answer with HEADERS only (no END_STREAM): each acquired lease keeps its
  // slot, so the pool can never wave more than MaxConnections*cap through
  Factory.SetResponse('200', nil, False);
  Client := THttpClientFactory.Create
    .WithSocketFactory(Factory)
    .WithMaxConnections(2)
    .WithMaxStreamsPerConnection(1)
    .WithHeaderTimeout(600)
    .Build;
  Pool := (Client as THttpClient).Pool;
  for I := 0 to High(Workers) do
  begin
    Workers[I] := TSendWorker.Create(Client, 'https://api.example/x');
    Workers[I].Start;
  end;
  Succeeded := 0;
  TimedOut := 0;
  Timeouts := 0;
  // wait for every worker BEFORE releasing any response, so the two holders
  // keep their slots occupied for the whole deadline and the rest time out
  for I := 0 to High(Workers) do
    AssertTrue('worker finished', Workers[I].WaitDone(5000));
  for I := 0 to High(Workers) do
  begin
    if (not Workers[I].Raised) and (Workers[I].Status = 200) then
      Inc(Succeeded)
    else
    begin
      if Pos('timed out', Workers[I].Error) > 0 then
        Inc(Timeouts);
      Inc(TimedOut);
    end;
  end;
  AssertEquals('exactly MaxConnections connections dialled', 2,
    Factory.Dials);
  AssertEquals('pool reports MaxConnections connections', 2,
    Pool.ConnectionCount);
  AssertEquals('two streams fit the two slots', 2, Succeeded);
  AssertEquals('the rest wait and time out at the slot deadline', 4, TimedOut);
  AssertEquals('the waits time out with EHttpTimeout', 4, Timeouts);
  for I := 0 to High(Workers) do
    Workers[I].Free;
  Client.Close;
end;

procedure TClientTest.TestConcurrentSendAcrossOneConnection;
const
  N = 8;
var
  Factory: TFakeSocketFactory;
  Client: IHttpClient;
  Pool: TConnectionPool;
  Workers: array[0..N - 1] of TSendWorker;
  I, Ok: Integer;
begin
  Factory := TFakeSocketFactory.Create;
  Client := THttpClientFactory.Create
    .WithSocketFactory(Factory)
    .WithMaxConnections(1)
    .WithMaxStreamsPerConnection(100)
    .Build;
  Pool := (Client as THttpClient).Pool;
  for I := 0 to N - 1 do
  begin
    Workers[I] := TSendWorker.Create(Client, 'https://api.example/x');
    Workers[I].Start;
  end;
  Ok := 0;
  for I := 0 to N - 1 do
  begin
    AssertTrue('worker finished', Workers[I].WaitDone(10000));
    AssertFalse('no error under concurrency: ' + Workers[I].Error,
      Workers[I].Raised);
    if Workers[I].Status = 200 then
      Inc(Ok);
    Workers[I].Free;
  end;
  AssertEquals('all concurrent sends succeed', N, Ok);
  AssertEquals('all streams share one connection', 1, Factory.Dials);
  AssertEquals('pool still reports one connection', 1, Pool.ConnectionCount);
  Client.Close;
end;

procedure TClientTest.TestLeastLoadedSelection;
var
  Factory: TFakeSocketFactory;
  Client: IHttpClient;
  Pool: TConnectionPool;
  Origin: string;
  Picked: IPooledConnection;
begin
  Factory := TFakeSocketFactory.Create;
  Client := THttpClientFactory.Create
    .WithSocketFactory(Factory)
    .Build;
  Pool := (Client as THttpClient).Pool;
  Origin := 'api.example';
  Pool.AddForTest(Origin, TFakePooledConnection.Create(Origin, 3, True));
  Pool.AddForTest(Origin, TFakePooledConnection.Create(Origin, 1, True));
  Pool.AddForTest(Origin, TFakePooledConnection.Create(Origin, 0, False));
  Picked := Pool.PickForTest(Origin);
  AssertTrue('a connection was picked', Picked <> nil);
  AssertEquals('least-loaded eligible connection chosen', 1,
    Picked.ActiveStreams);
  Client.Close;
end;

procedure TClientTest.TestPerConnectionStreamCap;
var
  Sock: IHttp2Socket;
  Conn: TConnection;
  Pooled: THttpConnection;
  Settings: TConnectionSettings;
begin
  Sock := TFakeServerSocket.Create;
  Conn := TConnection.Create(Sock);
  Pooled := THttpConnection.Create(Conn, 'api.example', 1);
  try
    AssertTrue('idle connection is eligible', Pooled.Eligible);
    Conn.RegisterStream(1, TFakeConnStream.Create);
    AssertFalse('local cap reached -> ineligible', Pooled.Eligible);
    Conn.UnregisterStream(1);
    AssertTrue('slot freed -> eligible again', Pooled.Eligible);
    // peer SETTINGS_MAX_CONCURRENT_STREAMS also caps eligibility
    Settings := TConnectionSettings.Defaults;
    Settings.MaxConcurrentStreams := 1;
    Conn.ApplyPeerSettingsValue(Settings);
    AssertTrue('peer cap 1, no streams -> eligible', Pooled.Eligible);
    Conn.RegisterStream(3, TFakeConnStream.Create);
    AssertFalse('peer cap 1 reached -> ineligible', Pooled.Eligible);
    Conn.UnregisterStream(3);
  finally
    // Pooled owns the TConnection and frees it in its destructor
    Pooled.Free;
  end;
end;

procedure TClientTest.TestCloseRejectsNewSends;
var
  Factory: TFakeSocketFactory;
  Client: IHttpClient;
  Raised: Boolean;
begin
  Factory := TFakeSocketFactory.Create;
  Client := THttpClientFactory.Create
    .WithSocketFactory(Factory)
    .Build;
  Client.Close;
  Raised := False;
  try
    Client.Send(THttpRequest.Create(hmGet, 'https://api.example/x'));
  except
    on E: EHttpConnectionClosed do Raised := True;
  end;
  AssertTrue('Send after Close raises EHttpConnectionClosed', Raised);
end;

procedure TClientTest.TestCloseKeepsOutstandingBodyReadable;
var
  Factory: TFakeSocketFactory;
  Client: IHttpClient;
  R: IHttpResponse;
  First: array[0..0] of Byte;
  Rest: array[0..15] of Byte;
  N: LongInt;
  Total: Integer;
begin
  Factory := TFakeSocketFactory.Create;
  // answer with a body that does not end the stream, so the response body
  // stays readable after Close
  Factory.SetResponse('200', BytesOf('hello-world'), False);
  Client := THttpClientFactory.Create
    .WithSocketFactory(Factory)
    .Build;
  R := Client.Send(THttpRequest.Create(hmGet, 'https://api.example/x'));
  AssertEquals('response headers', 200, R.StatusCode);

  N := R.Body.Read(First[0], 1);
  AssertEquals('one buffered byte before Close', 1, N);
  Client.Close;
  Total := N;
  while Total < 11 do
  begin
    N := R.Body.Read(Rest[0], SizeOf(Rest));
    AssertTrue('buffered body readable after Close', N > 0);
    Inc(Total, N);
  end;
  AssertEquals('the whole buffered body stayed readable after Close', 11,
    Total);
end;

procedure TClientTest.TestLiveGetAgainstNghttpd;
var
  Client: IHttpClient;
  R: IHttpResponse;
  Url: string;
begin
  // opt-in: requires nghttpd on 127.0.0.1:8080 and the matching TLS cert; the
  // default suite stays hermetic with this test skipped
  if GetEnvironmentVariable('HTTP2_LIVE_ITEST') <> '1' then
    Exit;
  Url := GetEnvironmentVariable('HTTP2_LIVE_ITEST_URL');
  if Url = '' then
    Url := 'https://127.0.0.1:8080/';
  Client := THttpClientFactory.Create
    .WithCACertFile(GetEnvironmentVariable('HTTP2_LIVE_ITEST_CA'))
    .Build;
  try
    R := Client.Send(THttpRequest.Create(hmGet, Url));
    AssertEquals('live GET returns 200', 200, R.StatusCode);
  finally
    Client.Close;
  end;
end;

procedure TClientTest.TestLivePostEchoAgainstNghttpd;
var
  Client: IHttpClient;
  R: IHttpResponse;
  Url, Echoed, Sent: string;
begin
  // nghttpd must be started with --echo-upload so a POST is echoed back
  if GetEnvironmentVariable('HTTP2_LIVE_ITEST') <> '1' then
    Exit;
  Url := GetEnvironmentVariable('HTTP2_LIVE_ITEST_URL');
  if Url = '' then
    Url := 'https://127.0.0.1:8080/';
  Sent := 'http2client-echo-body';
  Client := THttpClientFactory.Create
    .WithCACertFile(GetEnvironmentVariable('HTTP2_LIVE_ITEST_CA'))
    .Build;
  try
    R := Client.Send(THttpRequest.Create(hmPost, Url)
      .WithHeader('content-type', 'text/plain')
      .WithBody(THttpBody.FromString(Sent)));
    AssertEquals('live POST returns 200', 200, R.StatusCode);
    Echoed := string(AnsiString(PAnsiChar(ReadAllBodyBytes(R.Body))));
    AssertEquals('nghttpd echoed the uploaded POST body', Sent, Echoed);
  finally
    Client.Close;
  end;
end;

procedure TClientTest.TestFactoryObserverReceivesConnectionAndFrameEvents;
var
  Fact: TFakeSocketFactory;
  Obs: TRecordingObserver;
  Client: IHttpClient;
  R: IHttpResponse;
begin
  Fact := TFakeSocketFactory.Create;
  Obs := TRecordingObserver.Create;
  Client := THttpClientFactory.Create
    .WithSocketFactory(Fact)
    .WithObserver(Obs)
    .Build;
  R := Client.Send(THttpRequest.Create(hmGet, 'https://api.example/thing'));
  AssertEquals('status decoded', 200, R.StatusCode);
  AssertTrue('connection open was observed',
    Obs.WaitForCount(oekConnectionOpen, 1, 3000));
  AssertTrue('the request HEADERS frame was observed outbound',
    Obs.WaitForCount(oekFrameOut, 1, 3000));
  AssertTrue('the server SETTINGS frame was observed inbound',
    Obs.WaitForCount(oekFrameIn, 1, 3000));
  AssertTrue('the stream lease was observed open',
    Obs.WaitForCount(oekStreamOpen, 1, 3000));
  // non-vacuous: a factory that dropped the observer would record nothing
  AssertTrue('events were actually delivered', Obs.Count > 0);
  Client.Close;
  AssertTrue('connection close was observed',
    Obs.WaitForCount(oekConnectionClose, 1, 3000));
end;

initialization
  RegisterTest(TClientTest);
end.
