/// Stream lease and request/response state machine (plan S08)
// - this unit is part of the http2client project (see doc/design/messages.md
//   "Request and response streaming" and doc/design/client-api.md
//   "Lease acquisition").
// - a TStreamLease owns exactly ONE request/response exchange: stream-id
//   allocation, request frame emission (HEADERS + DATA), response assembly
//   (status + headers + body) and the RFC 7540 section 5.1 half-closed
//   transitions. It pushes outbound frames onto the connection's queue (the
//   connection thread is the sole socket writer) and receives inbound frames
//   through the IConnectionStream callback.
// - frame assembly is driven by the CALLER thread (WaitForResponseHeader /
//   Body.Read pop an internal inbound queue); the connection thread only
//   enqueues. This keeps HPACK decode single-threaded.
unit Http2.Stream;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, SyncObjs, Generics.Collections,
  Http2.Errors, Http2.Frames, Http2.Headers, Http2.Hpack, Http2.Connection;

type
  /// the HTTP methods this client sends. The token is uppercased on the
  /// wire; THttpMethodToken exposes the token for a pseudo-header.
  THttpMethod = (hmGet, hmHead, hmPost, hmPut, hmDelete, hmConnect,
    hmOptions, hmTrace, hmPatch);

  /// a pulled request body: NextChunk is called until it returns False, at
  /// which point the last emitted DATA frame carries END_STREAM
  /// (doc/design/messages.md "Request and response streaming").
  IBodyWriter = interface
    function NextChunk(out ABuffer: TBytes): Boolean;
  end;

  /// an in-memory request body; IsSet distinguishes an empty body from none
  THttpBody = record
  private
    FData: TBytes;
    FIsSet: Boolean;
  public
    class function FromBytes(const AData: TBytes): THttpBody; static;
    class function FromString(const AData: string): THttpBody; static;
    function IsSet: Boolean;
    function Data: TBytes;
  end;

  /// the wire method token plus the parsed request fields one lease emits.
  /// Pseudo-header mapping happens at encode time; Method is stored uppercase.
  TStreamRequest = record
    Method: string;         // ':method' (uppercase token)
    Scheme: string;         // ':scheme'
    Authority: string;      // ':authority' (host[:port])
    Path: string;           // ':path' (defaults to '/')
    Headers: IHttpHeaders;  // regular headers
    Body: THttpBody;        // fixed body; IsSet=False when absent
    BodyWriter: IBodyWriter;
    /// build a request with default scheme 'https', path '/', empty headers
    class function Create(const AMethod, AAuthority: string): TStreamRequest; static;
    class function WithMethod(const AMethod: THttpMethod;
      const AAuthority: string): TStreamRequest; static;
    function WithScheme(const AScheme: string): TStreamRequest;
    function WithPath(const APath: string): TStreamRequest;
    function WithHeader(const AName, AValue: string): TStreamRequest;
    function WithBody(const ABody: THttpBody): TStreamRequest;
    function WithBodyWriter(const AWriter: IBodyWriter): TStreamRequest;
  end;

  /// a response body stream (matches doc/design/messages.md IHttpBodyStream)
  IHttpBodyStream = interface
    /// block until bytes are available or END_STREAM is seen. The first Read
    /// that observes EOF returns 0; a Read after EOF raises EHttpStreamError.
    function Read(var ABuffer; const ACount: LongInt): LongInt;
    /// true once END_STREAM (or a bodyless response) is observed and buffered
    /// bytes are exhausted
    function Eof: Boolean;
  end;

  /// monotonic allocation of client-initiated (odd) stream ids for ONE
  /// connection. Guarded by its own TCriticalSection so many caller threads
  /// can allocate concurrently without duplicates.
  TStreamIdAllocator = class
  private
    FLock: TCriticalSection;
    FNext: LongWord;
  public
    constructor Create;
    destructor Destroy; override;
    /// the next odd id (1, 3, 5 ...); 0 once the id space is exhausted
    function Next: LongWord;
    /// the id that Next would return, without consuming it (test seam)
    function Peek: LongWord;
  end;

  /// the local (send) side of the RFC 7540 section 5.1 state machine
  TLeaseLocalState = (lsIdle, lsHeadersSent, lsLocalHalfClosed, lsClosed);

  /// the response (receive) side assembly state
  TResponseState = (rsIdle, rsBodyOpen, rsBodyComplete, rsFailed);

  TStreamLease = class;

  /// IHttpBodyStream view of a lease's response body
  TIStreamBody = class(TInterfacedObject, IHttpBodyStream)
  private
    FLease: TStreamLease;   // weak reference: the lease owns this object
  public
    constructor Create(const ALease: TStreamLease);
    function Read(var ABuffer; const ACount: LongInt): LongInt;
    function Eof: Boolean;
  end;

  /// one request/response exchange. Implements IConnectionStream so the
  /// connection can route stream-scoped frames to it and fan out failures.
  TStreamLease = class(TInterfacedObject, IConnectionStream)
  private
    FConnection: TConnection;
    FAllocator: TStreamIdAllocator;
    FRequest: TStreamRequest;
    FStreamId: LongWord;
    FOutbound: IBlockingQueue<TFrame>;
    FInbound: TBlockingQueue<TFrame>;
    FEncoder: THpackCodec;
    FDecoder: THpackCodec;
    FOwnsEncoder: Boolean;
    FOwnsDecoder: Boolean;
    FBodyStream: IHttpBodyStream;

    FStarted: Boolean;
    FRegistered: Boolean;
    FUnregistered: Boolean;
    FLocalState: TLeaseLocalState;
    FResponseState: TResponseState;

    FStatusCode: LongInt;
    FResponseHeaders: IHttpHeaders;
    FHeadersDecoded: Boolean;

    // in-progress header block (HEADERS + CONTINUATION reassembly)
    FInHeaderBlock: Boolean;
    FPendingBlock: TBytes;
    FPendingEndStream: Boolean;

    // body assembly
    FBodyPending: TBytes;
    FBodyPendingOfs: Integer;
    FBodyEof: Boolean;
    FBodyEofObserved: Boolean;
    /// total DATA bytes received on this stream, compared against a declared
    /// `content-length` at END_STREAM (RFC 7540 section 8.1.2.6)
    FBodyReceived: Int64;
    /// declared content-length, or -1 when the response did not send one
    FExpectedLength: Int64;

    // failure / teardown
    FFailed: Boolean;
    FErrorMessage: string;
    FErrorCode: THttp2ErrorCode;
    /// True when the failure came from the CONNECTION (FailWith / a
    /// connection-level protocol violation), False when the stream alone
    /// failed (RST_STREAM, GOAWAY above the stream id). Callers rely on the
    /// distinction: a stream error leaves the connection usable, a
    /// connection error does not, and the conformance harness scores them as
    /// different outcomes.
    FConnectionError: Boolean;
    FRstReceived: Boolean;
    FRstCode: THttp2ErrorCode;
    FFailCount: Integer;
    FReleaseCount: Integer;
    FUnregisterCount: Integer;
    FGoAwayLastStreamId: LongWord;
    FRetryable: Boolean;

    FTimeoutMs: Integer;

    function MaxFrameSize: LongWord;
    /// reserve up to AWant bytes of the peer's SEND window for this stream,
    /// blocking until credit arrives or the lease deadline expires. Raises
    /// EHttpTimeout on expiry so a stalled send fails instead of hanging.
    function AcquireCredit(const AWant: LongWord): LongWord;
    function MakeStreamError: EHttpError;
    procedure BuildRequestHeaderBlock(out ABlock: THeaderBlock);
    procedure EmitHeaderBlock(const ABlock: TBytes; const AEndStream: Boolean);
    procedure EmitData(const AData: TBytes; const AEndStream: Boolean);
    function PopInbound(out AFrame: TFrame; const ATimeoutMs: Integer): Boolean;
    procedure HandleInboundFrame(const AFrame: TFrame);
    procedure HandleHeaderFrame(const AFrame: TFrame);
    procedure HandleDataFrame(const AFrame: TFrame);
    procedure DecodeBlock(const ABlock: TBytes; const AEndStream: Boolean);
    procedure MarkResponseComplete;
    function RequestIsBodyless: Boolean;
  public
    constructor Create(const AConnection: TConnection;
      const AAllocator: TStreamIdAllocator; const ARequest: TStreamRequest);
      overload;
    /// inject connection-scoped HPACK codecs (production); when omitted the
    /// lease creates its own (unit-test only: a wire codec table is shared
    /// per connection, not per stream)
    constructor Create(const AConnection: TConnection;
      const AAllocator: TStreamIdAllocator; const ARequest: TStreamRequest;
      const AEncoder, ADecoder: THpackCodec); overload;
    destructor Destroy; override;

    /// allocate the stream id, register with the connection, emit the request
    procedure Start;
    /// RFC 7540 section 3.2 (h2c upgrade): the peer already received this
    /// request as stream 1 during the HTTP/1.1 Upgrade, so adopt stream 1 and
    /// wait for its response WITHOUT emitting any request frame.  The request
    /// body (if any) was carried by the HTTP/1.1 message, never by DATA.
    procedure AdoptUpgradedStream;
    /// emit the request HEADERS block (END_STREAM when there is no body)
    procedure SendHeaders;
    /// emit one DATA frame; AEndStream half-closes the local side
    procedure SendData(const AData: TBytes; const AEndStream: Boolean);
    /// emit the request body (THttpBody or IBodyWriter pull), half-closing
    procedure SendBody;
    /// half-close the local side with an empty END_STREAM DATA frame
    procedure EndSend;

    /// block until response HEADERS are decoded. Returns False on timeout;
    /// raises EHttpProtocolError on framing/HPACK errors and EHttpStreamError
    /// when the peer RESETs the stream before the headers arrived.
    function WaitForResponseHeader(const ATimeoutMs: Integer): Boolean;
    /// release the lease (idempotent; unregisters from the connection once)
    procedure ReleaseLease;
    /// true once the response body is complete and no bytes are buffered
    function BodyEof: Boolean;
    /// blocking body read; a read after EOF raises deterministically
    function ReadBody(var ABuffer; const ACount: LongInt): LongInt;

    // IConnectionStream
    procedure OnConnectionFailed(const AMessage: string;
      const ACode: THttp2ErrorCode);
    procedure OnConnectionGoAway(const ALastStreamId: LongWord);
    procedure OnStreamFrame(const AFrame: TFrame);

    property StreamId: LongWord read FStreamId;
    property LocalState: TLeaseLocalState read FLocalState;
    property ResponseState: TResponseState read FResponseState;
    property StatusCode: LongInt read FStatusCode;
    property ResponseHeaders: IHttpHeaders read FResponseHeaders;
    property Body: IHttpBodyStream read FBodyStream;
    property RequestMethod: string read FRequest.Method;
    /// response/body read deadline (ms); default 30000
    property TimeoutMs: Integer read FTimeoutMs write FTimeoutMs;
    // test seams
    property ReleaseCount: Integer read FReleaseCount;
    property UnregisterCount: Integer read FUnregisterCount;
    property FailCount: Integer read FFailCount;
    property RstReceived: Boolean read FRstReceived;
    property RstCode: THttp2ErrorCode read FRstCode;
    property GoAwayLastStreamId: LongWord read FGoAwayLastStreamId;
    property Retryable: Boolean read FRetryable;
  end;

implementation

function ConcatBytes(const A, B: TBytes): TBytes;
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

function HttpMethodToken(const AMethod: THttpMethod): string;
begin
  case AMethod of
    hmGet:     Result := 'GET';
    hmHead:    Result := 'HEAD';
    hmPost:    Result := 'POST';
    hmPut:     Result := 'PUT';
    hmDelete:  Result := 'DELETE';
    hmConnect: Result := 'CONNECT';
    hmOptions: Result := 'OPTIONS';
    hmTrace:   Result := 'TRACE';
    hmPatch:   Result := 'PATCH';
  else
    Result := 'GET';
  end;
end;

{ THttpBody }

class function THttpBody.FromBytes(const AData: TBytes): THttpBody;
begin
  Result.FData := AData;
  Result.FIsSet := True;
end;

class function THttpBody.FromString(const AData: string): THttpBody;
var
  B: TBytes;
begin
  B := nil;
  SetLength(B, Length(AData));
  if Length(B) > 0 then
    Move(AData[1], B[0], Length(B));
  Result.FData := B;
  Result.FIsSet := True;
end;

function THttpBody.IsSet: Boolean;
begin
  Result := FIsSet;
end;

function THttpBody.Data: TBytes;
begin
  Result := FData;
end;

{ TStreamRequest }

class function TStreamRequest.WithMethod(const AMethod: THttpMethod;
  const AAuthority: string): TStreamRequest;
begin
  Result := TStreamRequest.Create(HttpMethodToken(AMethod), AAuthority);
end;

class function TStreamRequest.Create(const AMethod,
  AAuthority: string): TStreamRequest;
begin
  Result.Method := UpperCase(AMethod);
  Result.Scheme := 'https';
  Result.Authority := AAuthority;
  Result.Path := '/';
  Result.Headers := NewHttpHeaders;
  Result.Body.FIsSet := False;
  Result.Body.FData := nil;
  Result.BodyWriter := nil;
end;

function TStreamRequest.WithScheme(const AScheme: string): TStreamRequest;
begin
  Result := Self;
  Result.Scheme := AScheme;
end;

function TStreamRequest.WithPath(const APath: string): TStreamRequest;
begin
  Result := Self;
  if APath = '' then
    Result.Path := '/'
  else
    Result.Path := APath;
end;

function TStreamRequest.WithHeader(const AName, AValue: string): TStreamRequest;
begin
  Result := Self;
  if not Assigned(Result.Headers) then
    Result.Headers := NewHttpHeaders;
  Result.Headers.Add(AName, AValue);
end;

function TStreamRequest.WithBody(const ABody: THttpBody): TStreamRequest;
begin
  Result := Self;
  Result.Body := ABody;
  Result.BodyWriter := nil;
end;

function TStreamRequest.WithBodyWriter(
  const AWriter: IBodyWriter): TStreamRequest;
begin
  Result := Self;
  Result.BodyWriter := AWriter;
  Result.Body.FIsSet := False;
  Result.Body.FData := nil;
end;

{ TIStreamBody }

constructor TIStreamBody.Create(const ALease: TStreamLease);
begin
  inherited Create;
  FLease := ALease;
end;

function TIStreamBody.Read(var ABuffer; const ACount: LongInt): LongInt;
begin
  Result := FLease.ReadBody(ABuffer, ACount);
end;

function TIStreamBody.Eof: Boolean;
begin
  Result := FLease.BodyEof;
end;

{ TStreamIdAllocator }

constructor TStreamIdAllocator.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FNext := 1;
end;

destructor TStreamIdAllocator.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

function TStreamIdAllocator.Next: LongWord;
begin
  FLock.Acquire;
  try
    Result := FNext;
    if FNext = 0 then
      Exit;                          // exhausted
    if FNext >= MaxStreamId then
      FNext := 0                     // this was the last odd id
    else
      FNext := FNext + 2;
  finally
    FLock.Release;
  end;
end;

function TStreamIdAllocator.Peek: LongWord;
begin
  FLock.Acquire;
  try
    Result := FNext;
  finally
    FLock.Release;
  end;
end;

{ TStreamLease }

constructor TStreamLease.Create(const AConnection: TConnection;
  const AAllocator: TStreamIdAllocator; const ARequest: TStreamRequest);
begin
  Create(AConnection, AAllocator, ARequest, nil, nil);
end;

constructor TStreamLease.Create(const AConnection: TConnection;
  const AAllocator: TStreamIdAllocator; const ARequest: TStreamRequest;
  const AEncoder, ADecoder: THpackCodec);
begin
  inherited Create;
  if AConnection = nil then
    raise EHttpError.Create('TStreamLease requires a connection',
      ecInternalError);
  if AAllocator = nil then
    raise EHttpError.Create('TStreamLease requires a stream-id allocator',
      ecInternalError);
  FConnection := AConnection;
  FAllocator := AAllocator;
  FRequest := ARequest;
  FOutbound := FConnection.Outbound;
  FInbound := TBlockingQueue<TFrame>.Create(cDefaultQueueCapacity);
  FOwnsEncoder := AEncoder = nil;
  FOwnsDecoder := ADecoder = nil;
  if AEncoder <> nil then FEncoder := AEncoder else FEncoder := THpackCodec.Create;
  if ADecoder <> nil then FDecoder := ADecoder else FDecoder := THpackCodec.Create;
  FResponseHeaders := NewHttpHeaders;
  FBodyStream := TIStreamBody.Create(Self);
  FLocalState := lsIdle;
  FResponseState := rsIdle;
  FStatusCode := -1;
  FBodyReceived := 0;
  FExpectedLength := -1;
  FTimeoutMs := 30000;
  FGoAwayLastStreamId := MaxStreamId;
end;

destructor TStreamLease.Destroy;
begin
  ReleaseLease;
  if FOwnsEncoder then FEncoder.Free;
  if FOwnsDecoder then FDecoder.Free;
  FInbound.Free;
  inherited Destroy;
end;

function TStreamLease.MaxFrameSize: LongWord;
begin
  Result := FConnection.PeerSettings.MaxFrameSize;
  if Result = 0 then
    Result := DefaultMaxFrameSize;
end;

function TStreamLease.AcquireCredit(const AWant: LongWord): LongWord;
begin
  Result := FConnection.AcquireSendCredit(FStreamId, AWant, FTimeoutMs);
  if Result = 0 then
    raise EHttpTimeout.CreateFmt(
      'timed out after %d ms waiting for flow-control credit on stream %d',
      [FTimeoutMs, FStreamId]);
end;

function TStreamLease.MakeStreamError: EHttpError;
var
  Msg: string;
begin
  Msg := FErrorMessage;
  if Msg = '' then
    Msg := 'stream failed';
  if FConnectionError then
    Result := EHttpConnectionError.Create(Msg, FErrorCode)
  else
    Result := EHttpStreamError.Create(Msg, FStreamId, FErrorCode);
end;

function TStreamLease.RequestIsBodyless: Boolean;
begin
  Result := SameText(FRequest.Method, 'HEAD');
end;

procedure TStreamLease.BuildRequestHeaderBlock(out ABlock: THeaderBlock);
var
  Fields: TList<THttpHeaderField>;
  Names: TArray<string>;
  Vals: TArray<string>;
  Name, V: string;
  I, J: Integer;
  F: THttpHeaderField;
begin
  ABlock := nil;
  Fields := TList<THttpHeaderField>.Create;
  try
    F.Name := HeaderMethod; F.Value := FRequest.Method; F.Sensitive := False;
    Fields.Add(F);
    F.Name := HeaderScheme; F.Value := FRequest.Scheme; F.Sensitive := False;
    Fields.Add(F);
    F.Name := HeaderPath;
    if FRequest.Path = '' then F.Value := '/' else F.Value := FRequest.Path;
    F.Sensitive := False;
    Fields.Add(F);
    F.Name := HeaderAuthority; F.Value := FRequest.Authority;
    F.Sensitive := False;
    Fields.Add(F);

    if FRequest.Headers <> nil then
    begin
      Names := FRequest.Headers.Names;
      for I := 0 to High(Names) do
      begin
        Name := Names[I];
        Vals := FRequest.Headers.GetValues(Name);
        for J := 0 to High(Vals) do
        begin
          V := Vals[J];
          F.Name := Name;
          F.Value := V;
          F.Sensitive := (Name = 'authorization') or (Name = 'cookie');
          Fields.Add(F);
        end;
      end;
    end;

    SetLength(ABlock, Fields.Count);
    for I := 0 to Fields.Count - 1 do
      ABlock[I] := Fields[I];
  finally
    Fields.Free;
  end;
end;

procedure TStreamLease.EmitHeaderBlock(const ABlock: TBytes;
  const AEndStream: Boolean);
var
  Max, Ofs, N: Integer;
  Chunk: TBytes;
begin
  Max := Integer(MaxFrameSize);
  if Length(ABlock) <= Max then
  begin
    FOutbound.Push(BuildHeadersFrame(FStreamId, ABlock, True, AEndStream));
    Exit;
  end;
  Chunk := Copy(ABlock, 0, Max);
  FOutbound.Push(BuildHeadersFrame(FStreamId, Chunk, False, AEndStream));
  Ofs := Max;
  while Ofs < Length(ABlock) do
  begin
    N := Length(ABlock) - Ofs;
    if N > Max then
      N := Max;
    Chunk := Copy(ABlock, Ofs, N);
    Inc(Ofs, N);
    FOutbound.Push(BuildContinuationFrame(FStreamId, Chunk,
      Ofs >= Length(ABlock)));
  end;
end;

procedure TStreamLease.EmitData(const AData: TBytes;
  const AEndStream: Boolean);
var
  Ofs, N: Integer;
  Want: LongWord;
  Chunk: TBytes;
begin
  if Length(AData) = 0 then
  begin
    // a zero-length DATA frame carries no flow-controlled bytes, so it must
    // NOT consume credit: this is how EndSend half-closes a stream whose
    // window the peer has pinned at zero
    FOutbound.Push(BuildDataFrame(FStreamId, nil, AEndStream));
    Exit;
  end;
  Ofs := 0;
  while Ofs < Length(AData) do
  begin
    // RFC 9113 section 6.9: never send more than the peer's window permits.
    // Split on whichever is smaller, the frame size or the credit now
    // available, and block here until the peer grants more.
    Want := MaxFrameSize;
    N := Length(AData) - Ofs;
    if LongWord(N) < Want then
      Want := LongWord(N);
    N := Integer(AcquireCredit(Want));
    Chunk := Copy(AData, Ofs, N);
    Inc(Ofs, N);
    FOutbound.Push(BuildDataFrame(FStreamId, Chunk,
      AEndStream and (Ofs >= Length(AData))));
  end;
end;

procedure TStreamLease.Start;
begin
  if FStarted then
    raise EHttpProtocolError.Create('stream lease already started',
      ecProtocolError);
  FStarted := True;
  FStreamId := FAllocator.Next;
  if FStreamId = 0 then
    raise EHttpError.Create('client stream-id space is exhausted',
      ecInternalError);
  FConnection.RegisterStream(FStreamId, Self);
  FRegistered := True;
  try
    SendHeaders;
    if FLocalState = lsHeadersSent then
      SendBody;
  except
    ReleaseLease;
    raise;
  end;
end;

procedure TStreamLease.AdoptUpgradedStream;
begin
  if FStarted then
    raise EHttpProtocolError.Create('stream lease already started',
      ecProtocolError);
  FStarted := True;
  // RFC 7540 section 3.2: "requests that contain a payload body MUST be sent
  // in their entirety before the client can send HTTP/2 frames", and the
  // upgrade request becomes stream 1
  FStreamId := FAllocator.Next;
  if FStreamId <> 1 then
    raise EHttpProtocolError.Create('an h2c upgrade must use stream 1',
      ecProtocolError);
  if not FConnection.AdoptStreamOne(Self) then
    raise EHttpProtocolError.Create('stream 1 is already in use',
      ecProtocolError);
  FRegistered := True;
  // the request was already sent as the HTTP/1.1 upgrade request, so nothing
  // more is emitted: the local side is half-closed (and the response's
  // END_STREAM drives it to closed via MarkResponseComplete)
  FLocalState := lsLocalHalfClosed;
end;

procedure TStreamLease.SendHeaders;
var
  Block: THeaderBlock;
  Encoded: TBytes;
  Bodyless: Boolean;
begin
  if FLocalState <> lsIdle then
    raise EHttpProtocolError.Create(
      'HEADERS already sent or stream closed', ecProtocolError);
  BuildRequestHeaderBlock(Block);
  Encoded := FEncoder.Encode(Block);
  Bodyless := (not FRequest.Body.IsSet) and (FRequest.BodyWriter = nil);
  EmitHeaderBlock(Encoded, Bodyless);
  if Bodyless then
    FLocalState := lsLocalHalfClosed
  else
    FLocalState := lsHeadersSent;
end;

procedure TStreamLease.SendData(const AData: TBytes;
  const AEndStream: Boolean);
begin
  if FLocalState = lsIdle then
    raise EHttpProtocolError.Create('cannot send DATA before HEADERS',
      ecProtocolError);
  if FLocalState <> lsHeadersSent then
    raise EHttpProtocolError.Create(
      'cannot send DATA on a half-closed or closed stream', ecStreamClosed);
  EmitData(AData, AEndStream);
  if AEndStream then
    FLocalState := lsLocalHalfClosed;
end;

procedure TStreamLease.SendBody;
var
  Chunk, Pending: TBytes;
  PendingSet: Boolean;
begin
  Pending := nil;
  if FLocalState = lsIdle then
    raise EHttpProtocolError.Create('cannot send a body before HEADERS',
      ecProtocolError);
  if FLocalState <> lsHeadersSent then
    raise EHttpProtocolError.Create(
      'cannot send a body on a half-closed or closed stream', ecStreamClosed);

  if FRequest.Body.IsSet then
  begin
    EmitData(FRequest.Body.Data, True);
  end
  else if FRequest.BodyWriter <> nil then
  begin
    PendingSet := False;
    while FRequest.BodyWriter.NextChunk(Chunk) do
    begin
      if PendingSet then
        EmitData(Pending, False);
      Pending := Chunk;
      PendingSet := True;
    end;
    if PendingSet then
      EmitData(Pending, True)
    else
      EmitData(nil, True);
  end
  else
    raise EHttpProtocolError.Create('SendBody called with no body',
      ecInternalError);

  FLocalState := lsLocalHalfClosed;
end;

procedure TStreamLease.EndSend;
begin
  if FLocalState = lsIdle then
    raise EHttpProtocolError.Create('cannot end before HEADERS',
      ecProtocolError);
  if FLocalState = lsLocalHalfClosed then
    raise EHttpProtocolError.Create('local side already half-closed',
      ecStreamClosed);
  EmitData(nil, True);
  FLocalState := lsLocalHalfClosed;
end;

function TStreamLease.PopInbound(out AFrame: TFrame;
  const ATimeoutMs: Integer): Boolean;
var
  Deadline: QWord;
  Remaining: Integer;
begin
  if FInbound.TryPop(AFrame) then
    Exit(True);
  Deadline := GetTickCount64 + QWord(ATimeoutMs);
  while True do
  begin
    if FInbound.IsShutdown then
      Exit(False);
    if GetTickCount64 >= Deadline then
      Exit(False);
    Remaining := Integer(Deadline - GetTickCount64);
    FInbound.WaitForItem(Remaining);
    if FInbound.TryPop(AFrame) then
      Exit(True);
  end;
end;

procedure TStreamLease.HandleInboundFrame(const AFrame: TFrame);
var
  Code: THttp2ErrorCode;
begin
  case AFrame.Header.FrameType of
    ftHeaders, ftContinuation:
      HandleHeaderFrame(AFrame);
    ftData:
      HandleDataFrame(AFrame);
    ftRstStream:
      begin
        ParseRstStream(AFrame, Code);
        FRstReceived := True;
        FRstCode := Code;
        if not FFailed then
        begin
          FFailed := True;
          FErrorCode := Code;
          FErrorMessage := 'peer reset stream ' + IntToStr(FStreamId) + ': ' +
            Http2ErrorCodeName(Code);
        end;
        FBodyEof := True;
        FResponseState := rsFailed;
        FLocalState := lsClosed;
        ReleaseLease;
      end;
    ftWindowUpdate:
      ; // flow-control replenishment is integrated by the connection layer
  else
    ; // frames not addressed to a single stream are ignored here
  end;
end;

procedure TStreamLease.HandleHeaderFrame(const AFrame: TFrame);
begin
  if not FInHeaderBlock then
  begin
    if AFrame.Header.FrameType <> ftHeaders then
      raise EHttpProtocolError.Create('CONTINUATION without HEADERS',
        ecProtocolError);
    FInHeaderBlock := True;
    FPendingBlock := ExtractHeaderBlock(AFrame);
    FPendingEndStream := AFrame.IsEndStream;
  end
  else
  begin
    if AFrame.Header.FrameType <> ftContinuation then
      raise EHttpProtocolError.Create('expected CONTINUATION',
        ecProtocolError);
    // append the continuation block
    if Length(ExtractHeaderBlock(AFrame)) > 0 then
    begin
      FPendingBlock := ConcatBytes(FPendingBlock, ExtractHeaderBlock(AFrame));
    end;
    if AFrame.IsEndStream then
      FPendingEndStream := True;
  end;
  if AFrame.IsEndHeaders then
  begin
    FInHeaderBlock := False;
    DecodeBlock(FPendingBlock, FPendingEndStream);
  end;
end;

procedure TStreamLease.DecodeBlock(const ABlock: TBytes;
  const AEndStream: Boolean);
var
  Fields: THeaderBlock;
  F: THttpHeaderField;
  I, St: Integer;
  SawRegular: Boolean;
begin
  Fields := FDecoder.Decode(ABlock);
  if not FHeadersDecoded then
  begin
    FStatusCode := -1;
    FExpectedLength := -1;
    SawRegular := False;
    for I := 0 to High(Fields) do
    begin
      F := Fields[I];
      if F.Name = ':status' then
      begin
        // RFC 7540 section 8.1.2.1: pseudo-header fields MUST appear before
        // regular fields; a :status arriving after a regular field is a
        // malformed response -> STREAM PROTOCOL_ERROR (harness 8.1.2.1/4).
        if SawRegular then
          raise EHttpStreamError.Create(
            ':status pseudo-header after a regular header field', FStreamId,
            ecProtocolError);
        St := StrToIntDef(F.Value, -1);
        if (St < 100) or (St > 599) then
          // RFC 7540 section 8.1.2.6: a malformed response is a STREAM error
          // (the connection survives); the peer is told with RST_STREAM.
          raise EHttpStreamError.Create('invalid :status value ' + F.Value,
            FStreamId, ecProtocolError);
        FStatusCode := St;
      end
      else if (F.Name <> '') and (F.Name[1] = ':') then
        raise EHttpStreamError.Create(
          'unexpected pseudo-header in response: ' + F.Name, FStreamId,
          ecProtocolError)
      else
      begin
        SawRegular := True;
        // RFC 7540 section 8.1.2: header field names MUST be lowercase; a
        // response with an uppercase name is malformed -> STREAM
        // PROTOCOL_ERROR (harness 8.1.2/1).
        if F.Name <> LowerCase(F.Name) then
          raise EHttpStreamError.Create(
            'header field name is not lowercase: ' + F.Name, FStreamId,
            ecProtocolError);
        if SameText(F.Name, 'content-length') then
          FExpectedLength := StrToInt64Def(F.Value, -1);
        // RFC 9113 section 8.2.2: 'te' is the one connection-specific field
        // allowed in HTTP/2, and a *response* may carry it only with the
        // value 'trailers'. Any other value is malformed -> STREAM
        // PROTOCOL_ERROR (harness 8.1.2.2/2).
        if SameText(F.Name, 'te') and (not SameText(Trim(F.Value), 'trailers')) then
          raise EHttpStreamError.Create(
            'response te header must be "trailers": ' + F.Value, FStreamId,
            ecProtocolError);
        FResponseHeaders.Add(F.Name, F.Value);
      end;
    end;
    if FStatusCode < 0 then
      raise EHttpStreamError.Create('response has no :status', FStreamId,
        ecProtocolError);
    FHeadersDecoded := True;
    // bodyless responses: 1xx, 204, 304 and every HEAD request.
    //  * HEAD and 1xx: a declared content-length describes the entity a GET
    //    *would* return (RFC 9110 section 8.6), so exempt it from the length
    //    check entirely.
    //  * 204/304: no body is sent, but a non-zero declared content-length is
    //    still malformed (RFC 7540 section 8.1.2.6); keep the value so
    //    MarkResponseComplete can compare it against the zero bytes received.
    if RequestIsBodyless or ((FStatusCode >= 100) and (FStatusCode < 200)) then
    begin
      FExpectedLength := -1;
      MarkResponseComplete;
    end
    else if (FStatusCode = 204) or (FStatusCode = 304) then
      MarkResponseComplete
    else
      FResponseState := rsBodyOpen;
  end  else
  begin
    // trailers: regular headers only, never a second :status, and the frame
    // must END the stream. RFC 7540 section 8.1.2.6: a HEADERS frame (and its
    // CONTINUATIONs) can only appear at the end of a stream, so one arriving
    // without END_STREAM is a malformed response -> STREAM PROTOCOL_ERROR
    // (the connection survives; harness case 8.1/1).
    if not AEndStream then
      raise EHttpStreamError.Create(
        'trailing HEADERS without END_STREAM', FStreamId, ecProtocolError);
    for I := 0 to High(Fields) do
    begin
      F := Fields[I];
      if F.Name = ':status' then
        raise EHttpStreamError.Create(
          'trailing HEADERS must not carry :status', FStreamId,
          ecProtocolError);
      FResponseHeaders.Add(F.Name, F.Value);
    end;
  end;

  if AEndStream then
    MarkResponseComplete;
  if FBodyEof then
    ReleaseLease;
end;

procedure TStreamLease.MarkResponseComplete;
begin
  FBodyEof := True;
  FResponseState := rsBodyComplete;
  // RFC 7540 section 8.1.2.6: if the response declared a content-length, the
  // DATA it actually sent must match. A mismatch is a malformed response ->
  // STREAM PROTOCOL_ERROR (the connection survives; harness 8.1.2.6/1,2).
  if (FExpectedLength >= 0) and (FBodyReceived <> FExpectedLength) then
    raise EHttpStreamError.Create(
      Format('content-length %d does not match %d received DATA bytes',
        [FExpectedLength, FBodyReceived]), FStreamId, ecProtocolError);
  // RFC 7540 section 5.1: local half-closed + remote END_STREAM = closed
  if FLocalState = lsLocalHalfClosed then
    FLocalState := lsClosed;
end;

procedure TStreamLease.HandleDataFrame(const AFrame: TFrame);
begin
  if FResponseState = rsIdle then
    raise EHttpProtocolError.Create('DATA before response HEADERS',
      ecProtocolError);
  // DATA on a stream that already saw END_STREAM is a STREAM error, not a
  // connection error: only this stream is broken (RFC 7540 section 5.1,
  // "closed (remote)" / "half-closed (remote)"), and the peer is told with
  // RST_STREAM. Raising a connection error here aborted the whole connection
  // and the harness scored it as a level mismatch (8.1.2.6/2).
  if (FResponseState = rsBodyComplete) or FBodyEof then
    raise EHttpStreamError.Create('DATA after END_STREAM', FStreamId,
      ecStreamClosed);
  FBodyPending := ExtractDataPayload(AFrame);
  FBodyPendingOfs := 0;
  Inc(FBodyReceived, Length(FBodyPending));
  FResponseState := rsBodyOpen;
  if AFrame.IsEndStream then
  begin
    MarkResponseComplete;
    ReleaseLease;
  end;
end;

function TStreamLease.WaitForResponseHeader(
  const ATimeoutMs: Integer): Boolean;
var
  Frame: TFrame;
  Deadline: QWord;
  Remaining: Integer;
begin
  Result := False;
  Deadline := GetTickCount64 + QWord(ATimeoutMs);
  while True do
  begin
    if FFailed then
      raise MakeStreamError;
    if FHeadersDecoded then
      Break;
    if GetTickCount64 >= Deadline then
      Exit(False);
    Remaining := Integer(Deadline - GetTickCount64);
    if not PopInbound(Frame, Remaining) then
    begin
      // the queue can shut down because the stream failed (RST_STREAM,
      // GOAWAY, connection loss) rather than because the deadline expired;
      // surface that cause instead of masking it as a timeout, else the
      // caller's transparent-retry path never sees the stream error
      if FFailed then
        raise MakeStreamError;
      Exit(False);
    end;
    HandleInboundFrame(Frame);
  end;
  if FFailed then
    raise MakeStreamError;
  Result := True;
end;

function TStreamLease.BodyEof: Boolean;
begin
  Result := FBodyEof and (FBodyPendingOfs >= Length(FBodyPending));
end;

function TStreamLease.ReadBody(var ABuffer; const ACount: LongInt): LongInt;
var
  P: PByte;
  Avail, N: Integer;
  Frame: TFrame;
begin
  Result := 0;
  if ACount <= 0 then
    Exit;
  P := @ABuffer;
  while True do
  begin
    Avail := Length(FBodyPending) - FBodyPendingOfs;
    if Avail > 0 then
    begin
      N := ACount;
      if N > Avail then
        N := Avail;
      Move(FBodyPending[FBodyPendingOfs], P^, N);
      Inc(FBodyPendingOfs, N);
      Exit(N);
    end;
    if FFailed then
      raise MakeStreamError;
    if FBodyEof then
    begin
      if FBodyEofObserved then
        raise EHttpStreamError.Create('read after end of stream', FStreamId,
          ecStreamClosed);
      FBodyEofObserved := True;
      Exit(0);
    end;
    if not PopInbound(Frame, FTimeoutMs) then
    begin
      // the queue can shut down because the stream failed (RST_STREAM,
      // GOAWAY, connection loss) rather than because the deadline expired;
      // surface that cause instead of masking it as a timeout, else a caller
      // cannot distinguish a dead connection from a slow peer (mirrors
      // WaitForResponseHeader)
      if FFailed then
        raise MakeStreamError;
      raise EHttpTimeout.Create('timed out reading response body');
    end;
    HandleInboundFrame(Frame);
  end;
end;

procedure TStreamLease.ReleaseLease;
begin
  if FUnregistered then
    Exit;
  FUnregistered := True;
  Inc(FReleaseCount);
  if FRegistered then
  begin
    Inc(FUnregisterCount);
    FConnection.UnregisterStream(FStreamId);
  end;
end;

procedure TStreamLease.OnConnectionFailed(const AMessage: string;
  const ACode: THttp2ErrorCode);
begin
  Inc(FFailCount);
  if not FFailed then
  begin
    FFailed := True;
    FConnectionError := True;   // connection-scoped: the connection is gone
    FErrorMessage := AMessage;
    FErrorCode := ACode;
    FBodyEof := True;
    if FResponseState = rsIdle then
      FResponseState := rsFailed;
    FLocalState := lsClosed;
  end;
  FInbound.Shutdown;
  ReleaseLease;
end;

procedure TStreamLease.OnConnectionGoAway(const ALastStreamId: LongWord);
begin
  FGoAwayLastStreamId := ALastStreamId;
  FRetryable := FStreamId > ALastStreamId;
  // RFC 7540 section 6.8: a stream whose id is above last-stream-id was never
  // processed and is safe to retry; a stream at or below it still completes
  // and must NOT be failed by the GOAWAY itself.
  if FRetryable and (not FBodyEof) then
  begin
    FFailed := True;
    FErrorMessage := 'peer sent GOAWAY before this stream was processed';
    FErrorCode := ecRefusedStream;
    FBodyEof := True;
    FResponseState := rsFailed;
    FInbound.Shutdown;
    ReleaseLease;
  end;
end;

procedure TStreamLease.OnStreamFrame(const AFrame: TFrame);
begin
  if FUnregistered then
    Exit;
  FInbound.Push(AFrame);
end;

end.
