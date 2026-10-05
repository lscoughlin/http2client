/// Stream-lease state machine tests (plan story S08)
// - covers stream-id allocation under concurrency, HEADERS encode/decode
//   round-trip, request streaming, bodyless responses, RST_STREAM mapped from
//   the body Read, illegal transitions, exactly-once cleanup, a full mocked
//   exchange, and a live TConnection + mock socket integration.
// - non-vacuous by construction: every "did X happen" assertion observes a
//   positive counter (ids collected, unregister count, fail count) rather
//   than the absence of an error.
// - ownership: a lease is registered with the connection as an interface, so
//   the test keeps an IConnectionStream reference (as production's response
//   object would) and releases it via ReleaseLease + the interface going nil,
//   never a raw Free.
unit Http2.Stream.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, SyncObjs, Generics.Collections, fpcunit, testregistry,
  Http2.Errors, Http2.Frames, Http2.Headers, Http2.Hpack,
  Http2.Connection, Http2.Stream, Http2.ConnectionThread.Test;

type
  /// pulls a fixed list of chunks then returns False (single-use writer)
  TChunkWriter = class(TInterfacedObject, IBodyWriter)
  private
    FChunks: array of TBytes;
    FIndex: Integer;
  public
    constructor Create(const AChunks: array of TBytes);
    function NextChunk(out ABuffer: TBytes): Boolean;
  end;

  /// one thread that repeatedly calls Next on a shared allocator
  TAllocWorker = class(TThread)
  private
    FAlloc: TStreamIdAllocator;
    FCount: Integer;
    FIds: TArray<LongWord>;
    FDone: PRTLEvent;
    FDoneFlag: Boolean;
  protected
    procedure Execute; override;
  public
    constructor Create(const AAlloc: TStreamIdAllocator; const ACount: Integer);
    destructor Destroy; override;
    function WaitDone(const ATimeoutMs: Integer): Boolean;
    property Ids: TArray<LongWord> read FIds;
  end;

  TStreamLeaseTest = class(TTestCase)
  private
    /// allocate a lease that the connection owns and the caller also holds;
    /// IL keeps the interface alive like the production response object does
    function MakeLease(const AConn: TConnection;
      const ARequest: TStreamRequest; out AAlloc: TStreamIdAllocator;
      out ALease: TStreamLease; out AIL: IConnectionStream): Boolean;
  published
    // 08.1
    procedure TestAllocatorYieldsOddMonotonicIds;
    procedure TestAllocatorConcurrencyHasNoDuplicates;
    // 08.3
    procedure TestHeadersEmitAndDecodeRoundTrip;
    procedure TestLargeHeaderBlockUsesContinuation;
    // 08.4
    procedure TestBodyIsStreamedInDataFrames;
    procedure TestBodyWriterIsPulledUntilFalse;
    // 08.5
    procedure TestResponseAssemblyStatusHeadersBody;
    // 08.6
    procedure TestBodylessResponseIsImmediatelyEof;
    procedure TestReadAfterEofRaises;
    // RFC 9110 8.6 / RFC 7540 8.1.2.6: a HEAD response carries the
    // content-length a GET would return, but sends no body; it must be accepted.
    procedure TestHeadContentLengthIsNotComparedAgainstBody;
    // restores the mismatch check guarded by the HEAD exemption above
    procedure TestContentLengthMismatchRaises;
    // 08.7
    procedure TestRstMidBodySurfacesFromRead;
    // 08.8
    procedure TestInvalidTransitionsRaise;
    // 08.9
    procedure TestCleanupHappensExactlyOnce;
    procedure TestConnectionFailureReachesLeaseExactlyOnce;
    procedure TestGoAwayMarksHigherStreamRetryable;
    // end to end + integration
    procedure TestEndToEndSingleLeaseOverMockedConnection;
    procedure TestDispatchAndFailOverRealConnection;
  end;

implementation

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

function JoinBytes(const A, B: TBytes): TBytes;
var
  N, I: Integer;
begin
  Result := nil;
  N := Length(A);
  SetLength(Result, N + Length(B));
  for I := 0 to N - 1 do
    Result[I] := A[I];
  for I := 0 to High(B) do
    Result[N + I] := B[I];
end;

/// encode a response header list with a fresh codec and wrap it in a HEADERS
/// frame (used to drive the lease's decoder from the peer side)
function ResponseHeadersFrame(const ACodec: THpackCodec;
  const AStatus: string; const AExtra: array of THttpHeaderField;
  const AStreamId: LongWord; const AEndStream: Boolean): TFrame;
var
  Block: THeaderBlock;
  I, N: Integer;
begin
  N := 1 + Length(AExtra);
  SetLength(Block, N);
  Block[0].Name := ':status';
  Block[0].Value := AStatus;
  Block[0].Sensitive := False;
  for I := 0 to High(AExtra) do
    Block[I + 1] := AExtra[I];
  Result := BuildHeadersFrame(AStreamId, ACodec.Encode(Block), True,
    AEndStream);
end;

function ReadAllBody(const ABody: IHttpBodyStream): string;
var
  Buf: array[0..63] of Byte;
  Chunk: TBytes;
  N, I: LongInt;
begin
  Result := '';
  while True do
  begin
    N := ABody.Read(Buf, SizeOf(Buf));
    if N = 0 then
      Break;
    SetLength(Chunk, N);
    for I := 0 to N - 1 do
      Chunk[I] := Buf[I];
    Result := Result + StrOf(Chunk);
  end;
end;

{ TChunkWriter }

constructor TChunkWriter.Create(const AChunks: array of TBytes);
var
  I: Integer;
begin
  inherited Create;
  SetLength(FChunks, Length(AChunks));
  for I := 0 to High(AChunks) do
    FChunks[I] := AChunks[I];
  FIndex := 0;
end;

function TChunkWriter.NextChunk(out ABuffer: TBytes): Boolean;
begin
  Result := FIndex <= High(FChunks);
  if Result then
  begin
    ABuffer := FChunks[FIndex];
    Inc(FIndex);
  end
  else
    ABuffer := nil;
end;

{ TAllocWorker }

constructor TAllocWorker.Create(const AAlloc: TStreamIdAllocator;
  const ACount: Integer);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FAlloc := AAlloc;
  FCount := ACount;
  FDone := RTLEventCreate;
end;

destructor TAllocWorker.Destroy;
begin
  RTLEventDestroy(FDone);
  inherited Destroy;
end;

procedure TAllocWorker.Execute;
var
  I: Integer;
begin
  SetLength(FIds, FCount);
  for I := 0 to FCount - 1 do
    FIds[I] := FAlloc.Next;
  FDoneFlag := True;
  RTLEventSetEvent(FDone);
end;

function TAllocWorker.WaitDone(const ATimeoutMs: Integer): Boolean;
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

{ TStreamLeaseTest }

function TStreamLeaseTest.MakeLease(const AConn: TConnection;
  const ARequest: TStreamRequest; out AAlloc: TStreamIdAllocator;
  out ALease: TStreamLease; out AIL: IConnectionStream): Boolean;
begin
  AAlloc := TStreamIdAllocator.Create;
  ALease := TStreamLease.Create(AConn, AAlloc, ARequest);
  AIL := ALease;                       // caller-held reference keeps it alive
  Result := True;
end;

procedure TStreamLeaseTest.TestAllocatorYieldsOddMonotonicIds;
var
  A: TStreamIdAllocator;
  I: Integer;
  Prev, Cur: LongWord;
  AllOdd: Boolean;
begin
  A := TStreamIdAllocator.Create;
  try
    AssertEquals('first id is 1', LongWord(1), A.Next);
    AllOdd := True;
    Prev := 1;
    for I := 0 to 9 do
    begin
      Cur := A.Next;
      if (Cur = 0) or (Cur and 1 = 0) or (Cur <= Prev) then
        AllOdd := False;
      Prev := Cur;
    end;
    AssertTrue('every allocated id is odd, non-zero and increasing', AllOdd);
    AssertEquals('Peek matches the next id', A.Next, A.Peek);
  finally
    A.Free;
  end;
end;

procedure TStreamLeaseTest.TestAllocatorConcurrencyHasNoDuplicates;
const
  Threads = 8;
  PerThread = 2000;
var
  A: TStreamIdAllocator;
  Workers: array[0..Threads - 1] of TAllocWorker;
  Seen: TDictionary<LongWord, Integer>;
  I, J: Integer;
  Id: LongWord;
  Duplicates, Completed, NonOdd: Integer;
  Dup: Integer;
begin
  A := TStreamIdAllocator.Create;
  Seen := TDictionary<LongWord, Integer>.Create;
  try
    for I := 0 to Threads - 1 do
      Workers[I] := TAllocWorker.Create(A, PerThread);
    for I := 0 to Threads - 1 do
      Workers[I].Start;
    Completed := 0;
    for I := 0 to Threads - 1 do
      if Workers[I].WaitDone(10000) then
        Inc(Completed);
    AssertEquals('every worker thread completed', Threads, Completed);

    Duplicates := 0;
    NonOdd := 0;
    for I := 0 to Threads - 1 do
      for J := 0 to PerThread - 1 do
      begin
        Id := Workers[I].Ids[J];
        if (Id = 0) or (Id and 1 = 0) then
          Inc(NonOdd);
        if Seen.TryGetValue(Id, Dup) then
          Inc(Duplicates)
        else
          Seen.Add(Id, 1);
      end;
    AssertEquals('no even or zero ids', 0, NonOdd);
    AssertEquals('no duplicate ids across threads', 0, Duplicates);
    AssertEquals('every id observed once', Threads * PerThread, Seen.Count);
  finally
    for I := 0 to Threads - 1 do
      Workers[I].Free;
    Seen.Free;
    A.Free;
  end;
end;

procedure TStreamLeaseTest.TestHeadersEmitAndDecodeRoundTrip;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Lease: TStreamLease;
  IL: IConnectionStream;
  Alloc: TStreamIdAllocator;
  Req: TStreamRequest;
  Frame, Extra0: TFrame;
  Dec: THpackCodec;
  Fields: THeaderBlock;
  I: Integer;
  SMethod, SScheme, SPath, SAuth, SAccept: string;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Req := TStreamRequest.WithMethod(hmGet, 'api.example:443')
      .WithPath('/v1/things?q=1')
      .WithHeader('accept', 'application/json');
    MakeLease(Conn, Req, Alloc, Lease, IL);
    try
      Lease.Start;
      AssertTrue('HEADERS frame emitted', Conn.Outbound.Pop(Frame));
      Extra0 := Frame;
      AssertFalse('only one frame for a bodyless GET',
        Conn.Outbound.TryPop(Extra0));
      AssertEquals('frame is HEADERS', Ord(ftHeaders), Ord(Frame.Header.FrameType));
      AssertEquals('stream id is 1', LongWord(1), Frame.Header.StreamId);
      AssertTrue('HEADERS carries END_HEADERS', Frame.IsEndHeaders);
      AssertTrue('a bodyless GET sets END_STREAM', Frame.IsEndStream);

      Dec := THpackCodec.Create;
      try
        Fields := Dec.Decode(ExtractHeaderBlock(Frame));
      finally
        Dec.Free;
      end;
      SMethod := ''; SScheme := ''; SPath := ''; SAuth := ''; SAccept := '';
      for I := 0 to High(Fields) do
      begin
        if Fields[I].Name = ':method' then SMethod := Fields[I].Value
        else if Fields[I].Name = ':scheme' then SScheme := Fields[I].Value
        else if Fields[I].Name = ':path' then SPath := Fields[I].Value
        else if Fields[I].Name = ':authority' then SAuth := Fields[I].Value
        else if Fields[I].Name = 'accept' then SAccept := Fields[I].Value;
      end;
      AssertEquals('method pseudo-header', 'GET', SMethod);
      AssertEquals('scheme pseudo-header', 'https', SScheme);
      AssertEquals('path pseudo-header', '/v1/things?q=1', SPath);
      AssertEquals('authority pseudo-header', 'api.example:443', SAuth);
      AssertEquals('regular header preserved', 'application/json', SAccept);
    finally
      Lease.ReleaseLease;
      IL := nil;
      Alloc.Free;
    end;
  finally
    Conn.Free;
  end;
end;

procedure TStreamLeaseTest.TestLargeHeaderBlockUsesContinuation;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Lease: TStreamLease;
  IL: IConnectionStream;
  Alloc: TStreamIdAllocator;
  Req: TStreamRequest;
  Peer: TConnectionSettings;
  F1, F2, Fx: TFrame;
  Block: TBytes;
  Dec: THpackCodec;
  Fields: THeaderBlock;
  I: Integer;
  Found: Boolean;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    // force a tiny peer max frame size so the header block must be split
    Peer := TConnectionSettings.Defaults;
    Peer.MaxFrameSize := 16;
    Conn.ApplyPeerSettingsValue(Peer);
    Req := TStreamRequest.WithMethod(hmGet, 'api.example:443')
      .WithPath('/a/long/path/that/will/not/fit')
      .WithHeader('x-a', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
      .WithHeader('x-b', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
    MakeLease(Conn, Req, Alloc, Lease, IL);
    try
      Lease.Start;
      AssertTrue('HEADERS frame emitted', Conn.Outbound.Pop(F1));
      AssertEquals('first frame is HEADERS', Ord(ftHeaders),
        Ord(F1.Header.FrameType));
      Block := ExtractHeaderBlock(F1);
      AssertFalse('HEADERS does not end the header block', F1.IsEndHeaders);
      // pull every CONTINUATION and concatenate the raw block bytes
      while not F1.IsEndHeaders do
      begin
        AssertTrue('a CONTINUATION follows', Conn.Outbound.Pop(F2));
        AssertEquals('next frame is CONTINUATION', Ord(ftContinuation),
          Ord(F2.Header.FrameType));
        Block := JoinBytes(Block, ExtractHeaderBlock(F2));
        F1 := F2;
      end;
      AssertFalse('the whole request is consumed', Conn.Outbound.TryPop(Fx));
      Dec := THpackCodec.Create;
      try
        Fields := Dec.Decode(Block);
      finally
        Dec.Free;
      end;
      Found := False;
      for I := 0 to High(Fields) do
        if (Fields[I].Name = ':path') and
           (Fields[I].Value = '/a/long/path/that/will/not/fit') then
          Found := True;
      AssertTrue('header block reassembles across CONTINUATION', Found);
    finally
      Lease.ReleaseLease;
      IL := nil;
      Alloc.Free;
    end;
  finally
    Conn.Free;
  end;
end;

procedure TStreamLeaseTest.TestBodyIsStreamedInDataFrames;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Lease: TStreamLease;
  IL: IConnectionStream;
  Alloc: TStreamIdAllocator;
  Req: TStreamRequest;
  H, D, Dx: TFrame;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Req := TStreamRequest.WithMethod(hmPost, 'api.example')
      .WithBody(THttpBody.FromString('hello world'));
    MakeLease(Conn, Req, Alloc, Lease, IL);
    try
      Lease.Start;
      AssertTrue(Conn.Outbound.Pop(H));
      AssertTrue(Conn.Outbound.Pop(D));
      AssertFalse('no third frame for a fixed body', Conn.Outbound.TryPop(Dx));
      AssertFalse('body present so HEADERS has no END_STREAM', H.IsEndStream);
      AssertEquals('DATA frame', Ord(ftData), Ord(D.Header.FrameType));
      AssertTrue('last DATA carries END_STREAM', D.IsEndStream);
      AssertEquals('body bytes transported', 'hello world',
        StrOf(ExtractDataPayload(D)));
      AssertEquals('local side is half-closed',
        Ord(lsLocalHalfClosed), Ord(Lease.LocalState));
    finally
      Lease.ReleaseLease;
      IL := nil;
      Alloc.Free;
    end;
  finally
    Conn.Free;
  end;
end;

procedure TStreamLeaseTest.TestBodyWriterIsPulledUntilFalse;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Lease: TStreamLease;
  IL: IConnectionStream;
  Alloc: TStreamIdAllocator;
  Req: TStreamRequest;
  H, D1, D2, D3, Dx: TFrame;
  Writer: IBodyWriter;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Writer := TChunkWriter.Create([BytesOf('abc'), BytesOf('de'), BytesOf('f')]);
    Req := TStreamRequest.WithMethod(hmPost, 'api.example')
      .WithBodyWriter(Writer);
    MakeLease(Conn, Req, Alloc, Lease, IL);
    try
      Lease.Start;
      AssertTrue(Conn.Outbound.Pop(H));
      AssertTrue(Conn.Outbound.Pop(D1));
      AssertTrue(Conn.Outbound.Pop(D2));
      AssertTrue(Conn.Outbound.Pop(D3));
      AssertFalse('no fourth frame', Conn.Outbound.TryPop(Dx));
      AssertFalse('writer body -> HEADERS has no END_STREAM', H.IsEndStream);
      AssertFalse('first chunk not end-stream', D1.IsEndStream);
      AssertFalse('second chunk not end-stream', D2.IsEndStream);
      AssertTrue('final pulled chunk carries END_STREAM', D3.IsEndStream);
      AssertEquals('chunk 1', 'abc', StrOf(ExtractDataPayload(D1)));
      AssertEquals('chunk 2', 'de', StrOf(ExtractDataPayload(D2)));
      AssertEquals('chunk 3', 'f', StrOf(ExtractDataPayload(D3)));
    finally
      Lease.ReleaseLease;
      IL := nil;
      Alloc.Free;
    end;
  finally
    Conn.Free;
  end;
end;

procedure TStreamLeaseTest.TestResponseAssemblyStatusHeadersBody;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Lease: TStreamLease;
  IL: IConnectionStream;
  Alloc: TStreamIdAllocator;
  Req: TStreamRequest;
  Enc: THpackCodec;
  Extra: array[0..0] of THttpHeaderField;
  S1: string;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Req := TStreamRequest.WithMethod(hmGet, 'api.example');
    MakeLease(Conn, Req, Alloc, Lease, IL);
    try
      Lease.Start;
      Enc := THpackCodec.Create;
      try
        Extra[0].Name := 'content-type';
        Extra[0].Value := 'text/plain';
        Extra[0].Sensitive := False;
        Conn.DispatchStreamFrame(ResponseHeadersFrame(Enc, '200', Extra,
          Lease.StreamId, False));
      finally
        Enc.Free;
      end;
      AssertTrue('response header wait succeeded',
        Lease.WaitForResponseHeader(1000));
      AssertEquals('status decoded', 200, Lease.StatusCode);
      AssertEquals('header decoded', 'text/plain',
        Lease.ResponseHeaders.GetFirst('content-type'));
      AssertFalse('body not yet complete', Lease.Body.Eof);

      Conn.DispatchStreamFrame(BuildDataFrame(Lease.StreamId, BytesOf('x'),
        False));
      Conn.DispatchStreamFrame(BuildDataFrame(Lease.StreamId, BytesOf('y'),
        True));
      S1 := ReadAllBody(Lease.Body);
      AssertEquals('assembled body', 'xy', S1);
      AssertTrue('body complete', Lease.Body.Eof);
    finally
      Lease.ReleaseLease;
      IL := nil;
      Alloc.Free;
    end;
  finally
    Conn.Free;
  end;
end;

procedure TStreamLeaseTest.TestBodylessResponseIsImmediatelyEof;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Lease: TStreamLease;
  IL: IConnectionStream;
  Alloc: TStreamIdAllocator;
  Req: TStreamRequest;
  Enc: THpackCodec;
  Empty: THeaderBlock;
  Buf: array[0..7] of Byte;
  N: LongInt;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Req := TStreamRequest.WithMethod(hmGet, 'api.example');
    MakeLease(Conn, Req, Alloc, Lease, IL);
    try
      Lease.Start;
      Enc := THpackCodec.Create;
      try
        Empty := nil;
        Conn.DispatchStreamFrame(ResponseHeadersFrame(Enc, '204', Empty,
          Lease.StreamId, False));
      finally
        Enc.Free;
      end;
      AssertTrue('header wait', Lease.WaitForResponseHeader(1000));
      AssertEquals('status 204', 204, Lease.StatusCode);
      AssertTrue('204 is immediately Eof', Lease.Body.Eof);
      N := Lease.ReadBody(Buf, SizeOf(Buf));
      AssertEquals('read on a bodyless response returns 0', LongInt(0), N);
    finally
      Lease.ReleaseLease;
      IL := nil;
      Alloc.Free;
    end;
  finally
    Conn.Free;
  end;
end;

procedure TStreamLeaseTest.TestReadAfterEofRaises;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Lease: TStreamLease;
  IL: IConnectionStream;
  Alloc: TStreamIdAllocator;
  Req: TStreamRequest;
  Enc: THpackCodec;
  Extra: array[0..0] of THttpHeaderField;
  Buf: array[0..7] of Byte;
  N: LongInt;
  Raised: Boolean;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Req := TStreamRequest.WithMethod(hmGet, 'api.example');
    MakeLease(Conn, Req, Alloc, Lease, IL);
    try
      Lease.Start;
      Enc := THpackCodec.Create;
      try
        Extra[0].Name := 'content-length';
        Extra[0].Value := '0';
        Extra[0].Sensitive := False;
        Conn.DispatchStreamFrame(ResponseHeadersFrame(Enc, '200', Extra,
          Lease.StreamId, True));   // END_STREAM on HEADERS
      finally
        Enc.Free;
      end;
      AssertTrue('header wait', Lease.WaitForResponseHeader(1000));
      N := Lease.ReadBody(Buf, SizeOf(Buf));
      AssertEquals('first read after END_STREAM returns 0', LongInt(0), N);
      Raised := False;
      try
        Lease.ReadBody(Buf, SizeOf(Buf));
      except
        on E: EHttpStreamError do Raised := True;
      end;
      AssertTrue('a second read after EOF raises deterministically', Raised);
    finally
      Lease.ReleaseLease;
      IL := nil;
      Alloc.Free;
    end;
  finally
    Conn.Free;
  end;
end;

procedure TStreamLeaseTest.TestHeadContentLengthIsNotComparedAgainstBody;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Lease: TStreamLease;
  IL: IConnectionStream;
  Alloc: TStreamIdAllocator;
  Req: TStreamRequest;
  Enc: THpackCodec;
  Extra: array[0..0] of THttpHeaderField;
  Buf: array[0..7] of Byte;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Req := TStreamRequest.WithMethod(hmHead, 'api.example');
    MakeLease(Conn, Req, Alloc, Lease, IL);
    try
      Lease.Start;
      Enc := THpackCodec.Create;
      try
        Extra[0].Name := 'content-length';
        Extra[0].Value := '10';
        Extra[0].Sensitive := False;
        // a HEAD response: describes 10 bytes but END_STREAM with no DATA
        Conn.DispatchStreamFrame(ResponseHeadersFrame(Enc, '200', Extra,
          Lease.StreamId, True));
      finally
        Enc.Free;
      end;
      AssertTrue('HEAD response headers are accepted',
        Lease.WaitForResponseHeader(1000));
      AssertEquals('no body bytes for HEAD', LongInt(0),
        Lease.ReadBody(Buf, SizeOf(Buf)));
      AssertEquals('status preserved', 200, Lease.StatusCode);
    finally
      Lease.ReleaseLease;
      IL := nil;
      Alloc.Free;
    end;
  finally
    Conn.Free;
  end;
end;

procedure TStreamLeaseTest.TestContentLengthMismatchRaises;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Lease: TStreamLease;
  IL: IConnectionStream;
  Alloc: TStreamIdAllocator;
  Req: TStreamRequest;
  Enc: THpackCodec;
  Extra: array[0..0] of THttpHeaderField;
  Buf: array[0..63] of Byte;
  Raised: Boolean;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Req := TStreamRequest.WithMethod(hmGet, 'api.example');
    MakeLease(Conn, Req, Alloc, Lease, IL);
    try
      Lease.Start;
      Enc := THpackCodec.Create;
      try
        Extra[0].Name := 'content-length';
        Extra[0].Value := '10';
        Extra[0].Sensitive := False;
        Conn.DispatchStreamFrame(ResponseHeadersFrame(Enc, '200', Extra,
          Lease.StreamId, False));
        // only 3 bytes of DATA, but END_STREAM -> malformed response
        Conn.DispatchStreamFrame(
          BuildDataFrame(Lease.StreamId, BytesOf('abc'), True));
      finally
        Enc.Free;
      end;
      AssertTrue('headers accepted', Lease.WaitForResponseHeader(1000));
      Raised := False;
      try
        Lease.ReadBody(Buf, SizeOf(Buf));
      except
        on E: EHttpStreamError do Raised := True;
      end;
      AssertTrue(
        'a content-length that disagrees with the DATA length is a stream error',
        Raised);
    finally
      Lease.ReleaseLease;
      IL := nil;
      Alloc.Free;
    end;
  finally
    Conn.Free;
  end;
end;

procedure TStreamLeaseTest.TestRstMidBodySurfacesFromRead;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Lease: TStreamLease;
  IL: IConnectionStream;
  Alloc: TStreamIdAllocator;
  Req: TStreamRequest;
  Enc: THpackCodec;
  Empty: THeaderBlock;
  Got: EHttpStreamError;
  Raised: Boolean;
  GotStreamId: LongWord;
  GotCode: THttp2ErrorCode;
  Buf: array[0..7] of Byte;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Req := TStreamRequest.WithMethod(hmGet, 'api.example');
    MakeLease(Conn, Req, Alloc, Lease, IL);
    try
      Lease.Start;
      Enc := THpackCodec.Create;
      try
        Empty := nil;
        Conn.DispatchStreamFrame(ResponseHeadersFrame(Enc, '200', Empty,
          Lease.StreamId, False));
      finally
        Enc.Free;
      end;
      AssertTrue('headers received as a normal value',
        Lease.WaitForResponseHeader(1000));

      Conn.DispatchStreamFrame(BuildRstStreamFrame(Lease.StreamId, ecCancel));
      Raised := False;
      Got := nil;
      GotStreamId := 0;
      GotCode := ecNoError;
      try
        Lease.ReadBody(Buf, SizeOf(Buf));
      except
        on E: EHttpStreamError do
        begin
          Raised := True;
          Got := E;
          GotStreamId := E.StreamId;
          GotCode := E.ErrorCode;
        end;
      end;
      AssertTrue('RST surfaces from Read, not from Send', Raised);
      AssertEquals('stream id attached to the error', Lease.StreamId,
        GotStreamId);
      AssertEquals('wire code mapped', Ord(ecCancel), Ord(GotCode));
      AssertTrue('lease records the reset', Lease.RstReceived);
      AssertEquals('raw wire code recorded', Ord(ecCancel),
        Ord(Lease.RstCode));
    finally
      Lease.ReleaseLease;
      IL := nil;
      Alloc.Free;
    end;
  finally
    Conn.Free;
  end;
end;

procedure TStreamLeaseTest.TestInvalidTransitionsRaise;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Lease: TStreamLease;
  IL: IConnectionStream;
  Alloc: TStreamIdAllocator;
  Req: TStreamRequest;
  Raised: Boolean;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Req := TStreamRequest.WithMethod(hmGet, 'api.example');
    MakeLease(Conn, Req, Alloc, Lease, IL);
    try
      // DATA before HEADERS
      Raised := False;
      try
        Lease.SendData(BytesOf('x'), True);
      except
        on E: EHttpProtocolError do Raised := True;
      end;
      AssertTrue('DATA before HEADERS raises', Raised);

      Lease.Start;   // GET -> immediate half-close
      // a second HEADERS emission
      Raised := False;
      try
        Lease.SendHeaders;
      except
        on E: EHttpProtocolError do Raised := True;
      end;
      AssertTrue('second HEADERS raises', Raised);

      // DATA on the already half-closed local side
      Raised := False;
      try
        Lease.SendData(BytesOf('x'), True);
      except
        on E: EHttpProtocolError do Raised := True;
      end;
      AssertTrue('DATA after half-close raises', Raised);

      // RequestIsBodyless is observable through the local state
      AssertEquals('GET ends in local half-close',
        Ord(lsLocalHalfClosed), Ord(Lease.LocalState));
    finally
      Lease.ReleaseLease;
      IL := nil;
      Alloc.Free;
    end;
  finally
    Conn.Free;
  end;
end;

procedure TStreamLeaseTest.TestCleanupHappensExactlyOnce;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Lease: TStreamLease;
  IL: IConnectionStream;
  Alloc: TStreamIdAllocator;
  Req: TStreamRequest;
  Enc: THpackCodec;
  Empty: THeaderBlock;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Req := TStreamRequest.WithMethod(hmGet, 'api.example');
    MakeLease(Conn, Req, Alloc, Lease, IL);
    try
      Lease.Start;
      AssertEquals('registered on start', 1, Conn.StreamCount);
      Enc := THpackCodec.Create;
      try
        Empty := nil;
        Conn.DispatchStreamFrame(ResponseHeadersFrame(Enc, '200', Empty,
          Lease.StreamId, True));   // END_STREAM on HEADERS
      finally
        Enc.Free;
      end;
      AssertTrue(Lease.WaitForResponseHeader(1000));
      AssertEquals('completed stream unregistered', 0, Conn.StreamCount);
      AssertEquals('exactly one unregister', 1, Lease.UnregisterCount);
      AssertEquals('exactly one release', 1, Lease.ReleaseCount);
      AssertEquals('both sides closed -> fully closed',
        Ord(lsClosed), Ord(Lease.LocalState));

      // a duplicate release must not unregister again
      Lease.ReleaseLease;
      Lease.ReleaseLease;
      AssertEquals('unregister still exactly once', 1, Lease.UnregisterCount);
      AssertEquals('release still exactly once', 1, Lease.ReleaseCount);
      AssertEquals('no leak', 0, Conn.StreamCount);
    finally
      Lease.ReleaseLease;
      IL := nil;
      Alloc.Free;
    end;
  finally
    Conn.Free;
  end;
end;

procedure TStreamLeaseTest.TestConnectionFailureReachesLeaseExactlyOnce;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Lease: TStreamLease;
  IL: IConnectionStream;
  Alloc: TStreamIdAllocator;
  Req: TStreamRequest;
  Buf: array[0..7] of Byte;
  Raised: Boolean;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Req := TStreamRequest.WithMethod(hmGet, 'api.example');
    MakeLease(Conn, Req, Alloc, Lease, IL);
    try
      Lease.Start;
      Conn.FailWith('socket reset', ecConnectError);
      AssertEquals('failure delivered to the lease exactly once', 1,
        Lease.FailCount);
      // the lease unregistered during the callback, so a second failure
      // fan-out must not reach it again
      Conn.FailWith('socket reset again', ecConnectError);
      AssertEquals('second fan-out does not re-enter the lease', 1,
        Lease.FailCount);

      Raised := False;
      try
        Lease.ReadBody(Buf, SizeOf(Buf));
      except
        on E: EHttpConnectionError do Raised := True;
      end;
      AssertTrue('body read observes the connection failure', Raised);
    finally
      Lease.ReleaseLease;
      IL := nil;
      Alloc.Free;
    end;
  finally
    Conn.Free;
  end;
end;

procedure TStreamLeaseTest.TestGoAwayMarksHigherStreamRetryable;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Upper, Lower: TStreamLease;
  IUp, ILow: IConnectionStream;
  Alloc: TStreamIdAllocator;
  Req: TStreamRequest;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  Alloc := TStreamIdAllocator.Create;
  try
    Req := TStreamRequest.WithMethod(hmGet, 'api.example');
    Lower := TStreamLease.Create(Conn, Alloc, Req);
    ILow := Lower;
    Upper := TStreamLease.Create(Conn, Alloc, Req);
    IUp := Upper;
    try
      Lower.Start;   // stream id 1
      Upper.Start;   // stream id 3
      AssertEquals('both streams registered', 2, Conn.StreamCount);
      Conn.MarkGoAway(1);
      AssertTrue('stream above last-id is retryable', Upper.Retryable);
      AssertFalse('stream at last-id is not retryable', Lower.Retryable);
      AssertEquals('unprocessed upper stream released', 1,
        Upper.ReleaseCount);
      AssertEquals('processed lower stream stays registered', 1,
        Conn.StreamCount);
      AssertEquals('processed lower stream not released by GOAWAY', 0,
        Lower.ReleaseCount);
    finally
      Lower.ReleaseLease;
      Upper.ReleaseLease;
      ILow := nil;
      IUp := nil;
    end;
  finally
    Alloc.Free;
    Conn.Free;
  end;
end;

procedure TStreamLeaseTest.TestEndToEndSingleLeaseOverMockedConnection;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Lease: TStreamLease;
  IL: IConnectionStream;
  Alloc: TStreamIdAllocator;
  Req: TStreamRequest;
  Enc: THpackCodec;
  Extra: array[0..0] of THttpHeaderField;
  H, Hx: TFrame;
  Body: string;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Req := TStreamRequest.WithMethod(hmPost, 'api.example:443')
      .WithPath('/submit')
      .WithBody(THttpBody.FromString('payload'));
    MakeLease(Conn, Req, Alloc, Lease, IL);
    try
      Lease.Start;
      // request: HEADERS + DATA
      AssertTrue(Conn.Outbound.Pop(H));
      AssertEquals('request HEADERS', Ord(ftHeaders), Ord(H.Header.FrameType));
      AssertTrue(Conn.Outbound.Pop(H));
      AssertTrue('request body ends the local side', H.IsEndStream);
      AssertFalse('no extra request frames', Conn.Outbound.TryPop(Hx));

      Enc := THpackCodec.Create;
      try
        Extra[0].Name := 'content-length';
        Extra[0].Value := '2';
        Extra[0].Sensitive := False;
        Conn.DispatchStreamFrame(ResponseHeadersFrame(Enc, '200', Extra,
          Lease.StreamId, False));
      finally
        Enc.Free;
      end;
      AssertTrue(Lease.WaitForResponseHeader(1000));
      AssertEquals('200 OK', 200, Lease.StatusCode);
      Conn.DispatchStreamFrame(BuildDataFrame(Lease.StreamId, BytesOf('ok'),
        True));
      Body := ReadAllBody(Lease.Body);
      AssertEquals('full response body', 'ok', Body);
      AssertTrue('stream complete', Lease.Body.Eof);
      AssertEquals('cleanly unregistered once', 1, Lease.UnregisterCount);
      AssertEquals('no stream leak', 0, Conn.StreamCount);
    finally
      Lease.ReleaseLease;
      IL := nil;
      Alloc.Free;
    end;
  finally
    Conn.Free;
  end;
end;

procedure TStreamLeaseTest.TestDispatchAndFailOverRealConnection;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Lease: TStreamLease;
  IL: IConnectionStream;
  Alloc: TStreamIdAllocator;
  Req: TStreamRequest;
  Enc: THpackCodec;
  Empty: THeaderBlock;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Conn.Start;
    AssertTrue('connection opened', Conn.WaitForState(csOpen, 2000));
    Req := TStreamRequest.WithMethod(hmGet, 'api.example');
    MakeLease(Conn, Req, Alloc, Lease, IL);
    try
      Lease.Start;
      // the peer answers on the wire; the connection thread routes HEADERS to
      // the lease through DispatchStreamFrame
      Enc := THpackCodec.Create;
      try
        Empty := nil;
        Sock.FeedFrame(ResponseHeadersFrame(Enc, '200', Empty, Lease.StreamId,
          False));
      finally
        Enc.Free;
      end;
      AssertTrue('lease received its frame via DispatchStreamFrame',
        Lease.WaitForResponseHeader(2000));
      AssertEquals('status decoded from the routed frame', 200,
        Lease.StatusCode);

      Conn.FailWith('boom', ecConnectError);
      AssertEquals('FailWith reached the lease exactly once', 1,
        Lease.FailCount);
      Conn.FailWith('boom again', ecConnectError);
      AssertEquals('second FailWith does not re-reach the lease', 1,
        Lease.FailCount);
    finally
      Lease.ReleaseLease;
      IL := nil;
      Alloc.Free;
    end;
  finally
    Conn.Free;
  end;
end;

initialization
  RegisterTest(TStreamLeaseTest);
end.
