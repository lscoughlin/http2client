/// cleartext h2c and HTTP/1.1 fallback tests (plan S13)
// - Covers the factory surface (13.1), prior knowledge (13.2), the h2c upgrade
//   handshake (13.3), ALPN codec selection (13.5) and the pool keys/limit
//   (13.6).  The two scripted fake transports below are the test doubles of
//   this unit: one speaks the HTTP/2 frame wire format (reused from the h2c
//   prior-knowledge path) and one answers an HTTP/1.1 byte script.
// - non-vacuous by construction: the prior-knowledge test asserts the DECODED
//   :scheme/:path the client actually put on the wire; the upgrade test
//   asserts the raw `Upgrade: h2c` / `HTTP2-Settings` / `Connection` bytes the
//   client wrote AND that the 101 socket then carried HTTP/2; the HTTP/1.1
//   test asserts the 200 came from the text codec; the pool test asserts two
//   separate origins and a stream limit of 1.
unit Http2.ClearText.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, SyncObjs, Generics.Collections, fpcunit, testregistry,
  Http2.Errors, Http2.Frames, Http2.Headers, Http2.Hpack,
  Http2.Tls, Http2.Connection, Http2.Stream, Http2.Messages, Http2.Client,
  Http2.Http1;

type
  /// a factory that must never be dialled: the strict default rejects the
  /// request before the transport is reached
  TNeverDialFactory = class(TInterfacedObject, IHttp2SocketFactory)
  public
    function Dial(const AHost: string; const APort: Word;
      const ATimeoutMs: Integer): IHttp2Socket;
  end;

  /// a scripted IHttp2Socket for one byte-exchange.  FScript is handed out to
  /// the reader; FWritten accumulates every byte the client wrote so a test
  /// can assert the exact request the codec/upgrade put on the wire.
  TScriptSocket = class(TInterfacedObject, IHttp2Socket)
  private
    FLock: TCriticalSection;
    FScript: TBytes;
    FReadPos: Integer;
    FWritten: TBytes;
    FConnected: Boolean;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Feed(const AText: string);
    procedure FeedBytes(const ABytes: TBytes);
    function WrittenText: string;
    function WrittenBytes: TBytes;
    /// bounded wait until the written bytes contain ANeedle (the connection
    /// thread flushes asynchronously, so a byte assertion must wait)
    function WaitForText(const ANeedle: string;
      const ATimeoutMs: Integer): Boolean;
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

  /// a factory implementing BOTH transport contracts.  Each DialProtocol call
  /// records the policy arguments and returns the socket handed to Create, so a
  /// path that needs a second connection (the h2c upgrade rerouted to HTTP/1.1)
  /// can hand out a fresh socket by constructing a second factory.
  /// a factory implementing BOTH transport contracts.  Every dial returns a
  /// FRESH TScriptSocket fed with the same script text, so a path that needs a
  /// second connection (the h2c upgrade rerouted to a fallen-back HTTP/1.1) is
  /// testable.  It records every DialProtocol call so policy plumbing is
  /// asserted.
  TScriptProtocolFactory = class(TInterfacedObject, IHttp2SocketFactory,
    ICleartextSocketFactory)
  private
    FProtocol: TNegotiatedProtocol;
    FScript: TBytes;
    /// holds a strong interface reference so each handed-out socket stays
    /// alive for SocketAt after the pool releases it
    FSockets: TList<IHttp2Socket>;
    FLock: TCriticalSection;
    FDials: Integer;
    FLastScheme: string;
    FLastFallback: Boolean;
    FLastPolicy: TClearTextPolicy;
    FLastHost: string;
    FLastPort: Word;
    function NewSocket: IHttp2Socket;
  public
    constructor Create(const AProtocol: TNegotiatedProtocol;
      const AScriptText: string);
    destructor Destroy; override;
    function Dial(const AHost: string; const APort: Word;
      const ATimeoutMs: Integer): IHttp2Socket;
    function DialProtocol(const AHost: string; const APort: Word;
      const AScheme: string; const AHttp1Fallback: Boolean;
      const APolicy: TClearTextPolicy; const ATimeoutMs: Integer;
      out AProtocol: TNegotiatedProtocol): IHttp2Socket;
    function Dials: Integer;
    /// the socket handed out on dial AIndex (0-based), or nil when out of range
    function SocketAt(const AIndex: Integer): TScriptSocket;
    function LastScheme: string;
    function LastFallback: Boolean;
    function LastPolicy: TClearTextPolicy;
    function LastHost: string;
    function LastPort: Word;
  end;

  /// an in-memory frame-level HTTP/2 peer (HTTP/2 side of a prior-knowledge or
  /// adopted upgrade connection).  It decodes the client's request HEADERS and
  /// answers one scripted response so a full Send can run end to end.
  TFramePeer = class(TInterfacedObject, IHttp2Socket)
  private
    FLock: TCriticalSection;
    FDataEvent: PRTLEvent;
    FAcc: TBytes;
    FParsePos: Integer;
    FPrefaceDone: Boolean;
    FIn: TBytes;
    FReadPos: Integer;
    FConnected: Boolean;
    FStatus: string;
    FBody: TBytes;
    FEndStream: Boolean;
    FCodec: THpackCodec;
    FRespCodec: THpackCodec;
    FReqMethod: string;
    FReqPath: string;
    FReqScheme: string;
    FReqAuthority: string;
    FReqCount: Integer;
    procedure AppendInLocked(const ABytes: TBytes);
    procedure AppendWritten(const ABuffer; const ACount: Integer);
    procedure ParseAvailable;
    procedure EmitResponse(const AStreamId: LongWord);
    function FrameBytes(const AF: TFrame): TBytes;
  public
    constructor Create(const AStatus: string; const ABody: TBytes);
    destructor Destroy; override;
    property ReqMethod: string read FReqMethod;
    property ReqPath: string read FReqPath;
    property ReqScheme: string read FReqScheme;
    property ReqAuthority: string read FReqAuthority;
    property ReqCount: Integer read FReqCount;
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

  /// hands out a fresh frame peer per dial (prior knowledge over cleartext).
  /// It implements the extended contract so the pool's DialProtocol path is
  /// exercised for BOTH schemes; the returned codec is always the HTTP/2
  /// cleartext one, which is enough to prove the pool keys by origin.
  TFramePeerPlainFactory = class(TInterfacedObject, IHttp2SocketFactory,
    ICleartextSocketFactory)
  private
    FStatus: string;
    FBody: TBytes;
    FPeers: TList<TFramePeer>;
  public
    constructor Create(const AStatus: string; const ABody: TBytes);
    destructor Destroy; override;
    function Dial(const AHost: string; const APort: Word;
      const ATimeoutMs: Integer): IHttp2Socket;
    function DialProtocol(const AHost: string; const APort: Word;
      const AScheme: string; const AHttp1Fallback: Boolean;
      const APolicy: TClearTextPolicy; const ATimeoutMs: Integer;
      out AProtocol: TNegotiatedProtocol): IHttp2Socket;
    function SocketAt(const AIndex: Integer): TFramePeer;
  end;

  TClearTextTest = class(TTestCase)
  published
    // 13.1 factory surface
    procedure TestDefaultsAreStrict;
    procedure TestWithClearTextChangesThePolicy;
    procedure TestWithHttp1FallbackIsOffByDefault;
    procedure TestFluentChainStaysCopyOnWrite;
    procedure TestStrictModeRejectsCleartextUrl;
    procedure TestHttpsUrlIsNotAffectedByThePolicy;
    // 13.5 DialProtocol selection is honoured
    procedure TestDialProtocolPriorKnowledgeSelectsCleartextH2;
    procedure TestDialProtocolUpgradeSelectsCleartextH1;
    procedure TestDialProtocolHttp1TlsSelectsTheTextCodec;
    // 13.2 prior knowledge end to end
    procedure TestPriorKnowledgeGetReachesHttp2OnTheSameSocket;
    // 13.3 h2c upgrade handshake
    procedure TestUpgradeSendsH2cHeadersAndSettings;
    // 13.3 non-101 falls back to HTTP/1.1
    procedure TestUpgradeNon101ReturnsTheHttp1Response;
    // 13.6 pool keys and the HTTP/1.1 stream limit
    procedure TestPoolKeepsHttpAndHttpsOriginsApart;
    procedure TestHttp1PooledConnectionReportsStreamLimitOne;
    // upgrade must not double-send a body
    procedure TestUpgradeWithBodyUsesPlainHttp1;
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

{ TNeverDialFactory }

function TNeverDialFactory.Dial(const AHost: string; const APort: Word;
  const ATimeoutMs: Integer): IHttp2Socket;
begin
  raise Exception.Create('the transport must not be dialled');
end;

{ TScriptSocket }

constructor TScriptSocket.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FConnected := True;
end;

destructor TScriptSocket.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

procedure TScriptSocket.Feed(const AText: string);
begin
  FeedBytes(TextBytes(AText));
end;

procedure TScriptSocket.FeedBytes(const ABytes: TBytes);
begin
  FLock.Acquire;
  try
    FScript := ConcatBytes(FScript, ABytes);
  finally
    FLock.Release;
  end;
end;

function TScriptSocket.WrittenText: string;
begin
  Result := BytesText(WrittenBytes);
end;

function TScriptSocket.WrittenBytes: TBytes;
begin
  FLock.Acquire;
  try
    Result := FWritten;
  finally
    FLock.Release;
  end;
end;

function TScriptSocket.WaitForText(const ANeedle: string;
  const ATimeoutMs: Integer): Boolean;
var
  Deadline: QWord;
begin
  Deadline := GetTickCount64 + QWord(ATimeoutMs);
  repeat
    if Pos(ANeedle, WrittenText) > 0 then
      Exit(True);
    if GetTickCount64 >= Deadline then
      Exit(False);
    Sleep(2);
  until False;
end;

function TScriptSocket.Read(var ABuffer; ACount: Integer): Integer;
var
  Avail, N: Integer;
begin
  FLock.Acquire;
  try
    if not FConnected then
      Exit(0);
    Avail := Length(FScript) - FReadPos;
    if Avail <= 0 then
      Exit(0);   // script exhausted: EOF
    N := ACount;
    if N > Avail then
      N := Avail;
    Move(FScript[FReadPos], PByte(@ABuffer)^, N);
    Inc(FReadPos, N);
    Result := N;
  finally
    FLock.Release;
  end;
end;

function TScriptSocket.Write(const ABuffer; ACount: Integer): Integer;
var
  B: TBytes;
begin
  FLock.Acquire;
  try
    if not FConnected then
      raise EHttpConnectionClosed.Create('scripted socket closed');
    SetLength(B, ACount);
    if ACount > 0 then
      Move(PByte(@ABuffer)^, B[0], ACount);
    FWritten := ConcatBytes(FWritten, B);
    Result := ACount;
  finally
    FLock.Release;
  end;
end;

procedure TScriptSocket.Close;
begin
  FLock.Acquire;
  try
    FConnected := False;
  finally
    FLock.Release;
  end;
end;

function TScriptSocket.GetConnected: Boolean;
begin
  Result := FConnected;
end;

function TScriptSocket.GetConnectTimeoutMs: Integer;
begin
  Result := 30000;
end;

procedure TScriptSocket.SetConnectTimeoutMs(const AValue: Integer);
begin
end;

function TScriptSocket.GetReadTimeoutMs: Integer;
begin
  Result := 30000;
end;

procedure TScriptSocket.SetReadTimeoutMs(const AValue: Integer);
begin
end;

function TScriptSocket.GetWriteTimeoutMs: Integer;
begin
  Result := 30000;
end;

procedure TScriptSocket.SetWriteTimeoutMs(const AValue: Integer);
begin
end;

{ TScriptProtocolFactory }

constructor TScriptProtocolFactory.Create(const AProtocol: TNegotiatedProtocol;
  const AScriptText: string);
begin
  inherited Create;
  FProtocol := AProtocol;
  FScript := TextBytes(AScriptText);
  FSockets := TList<IHttp2Socket>.Create;
  FLock := TCriticalSection.Create;
end;

destructor TScriptProtocolFactory.Destroy;
begin
  FSockets.Free;
  FLock.Free;
  inherited Destroy;
end;

function TScriptProtocolFactory.NewSocket: IHttp2Socket;
var
  S: TScriptSocket;
begin
  S := TScriptSocket.Create;
  S.FeedBytes(FScript);
  Result := S;
  FSockets.Add(Result);
end;

function TScriptProtocolFactory.SocketAt(const AIndex: Integer): TScriptSocket;
var
  O: TObject;
begin
  Result := nil;
  if (AIndex < 0) or (AIndex >= FSockets.Count) then
    Exit;
  // downcast via Supports, never a hard class cast on an interface
  if Supports(FSockets[AIndex], TScriptSocket, O) then
    Result := TScriptSocket(O);
end;

function TScriptProtocolFactory.Dial(const AHost: string; const APort: Word;
  const ATimeoutMs: Integer): IHttp2Socket;
begin
  Result := NewSocket;
end;

function TScriptProtocolFactory.DialProtocol(const AHost: string;
  const APort: Word; const AScheme: string; const AHttp1Fallback: Boolean;
  const APolicy: TClearTextPolicy; const ATimeoutMs: Integer;
  out AProtocol: TNegotiatedProtocol): IHttp2Socket;
begin
  FLock.Acquire;
  try
    Inc(FDials);
    FLastScheme := AScheme;
    FLastFallback := AHttp1Fallback;
    FLastPolicy := APolicy;
    FLastHost := AHost;
    FLastPort := APort;
  finally
    FLock.Release;
  end;
  AProtocol := FProtocol;
  Result := NewSocket;
end;

function TScriptProtocolFactory.Dials: Integer;
begin
  FLock.Acquire;
  try
    Result := FDials;
  finally
    FLock.Release;
  end;
end;

function TScriptProtocolFactory.LastScheme: string;
begin
  FLock.Acquire;
  try
    Result := FLastScheme;
  finally
    FLock.Release;
  end;
end;

function TScriptProtocolFactory.LastFallback: Boolean;
begin
  FLock.Acquire;
  try
    Result := FLastFallback;
  finally
    FLock.Release;
  end;
end;

function TScriptProtocolFactory.LastPolicy: TClearTextPolicy;
begin
  FLock.Acquire;
  try
    Result := FLastPolicy;
  finally
    FLock.Release;
  end;
end;

function TScriptProtocolFactory.LastHost: string;
begin
  FLock.Acquire;
  try
    Result := FLastHost;
  finally
    FLock.Release;
  end;
end;

function TScriptProtocolFactory.LastPort: Word;
begin
  FLock.Acquire;
  try
    Result := FLastPort;
  finally
    FLock.Release;
  end;
end;

{ TFramePeer }

constructor TFramePeer.Create(const AStatus: string; const ABody: TBytes);
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FDataEvent := RTLEventCreate;
  FCodec := THpackCodec.Create;
  FRespCodec := THpackCodec.Create;
  FConnected := True;
  FStatus := AStatus;
  FBody := ABody;
  FEndStream := True;
end;

destructor TFramePeer.Destroy;
begin
  FCodec.Free;
  FRespCodec.Free;
  RTLEventDestroy(FDataEvent);
  FLock.Free;
  inherited Destroy;
end;

function TFramePeer.FrameBytes(const AF: TFrame): TBytes;
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

procedure TFramePeer.AppendInLocked(const ABytes: TBytes);
begin
  FIn := ConcatBytes(FIn, ABytes);
end;

procedure TFramePeer.AppendWritten(const ABuffer; const ACount: Integer);
var
  N: Integer;
begin
  if ACount <= 0 then
    Exit;
  N := Length(FAcc);
  SetLength(FAcc, N + ACount);
  Move(PByte(@ABuffer)^, FAcc[N], ACount);
end;

procedure TFramePeer.EmitResponse(const AStreamId: LongWord);
var
  Block: THeaderBlock;
  Enc: TBytes;
begin
  SetLength(Block, 1);
  Block[0].Name := ':status';
  Block[0].Value := FStatus;
  Block[0].Sensitive := False;
  Enc := FRespCodec.Encode(Block);
  if Length(FBody) = 0 then
    AppendInLocked(FrameBytes(BuildHeadersFrame(AStreamId, Enc, True,
      FEndStream)))
  else
  begin
    AppendInLocked(FrameBytes(BuildHeadersFrame(AStreamId, Enc, True, False)));
    AppendInLocked(FrameBytes(BuildDataFrame(AStreamId, FBody, True)));
  end;
end;

procedure TFramePeer.ParseAvailable;
var
  Len, Typ, Total, Flags: Integer;
  StreamId: LongWord;
  Payload: TBytes;
  Fields: THeaderBlock;
  F: THttpHeaderField;
  I: Integer;
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
    Flags := FAcc[FParsePos + 4];
    StreamId := (LongWord(FAcc[FParsePos + 5]) shl 24) or
      (LongWord(FAcc[FParsePos + 6]) shl 16) or
      (LongWord(FAcc[FParsePos + 7]) shl 8) or LongWord(FAcc[FParsePos + 8]);
    if Length(FAcc) - FParsePos < FrameHeaderSize + Len then
      Exit;
    Total := FrameHeaderSize + Len;
    Payload := Copy(FAcc, FParsePos + FrameHeaderSize, Len);
    Inc(FParsePos, Total);
    if (Typ = Ord(ftHeaders)) and (StreamId <> 0) and
       ((Flags and $04) <> 0) then
    begin
      Inc(FReqCount);
      Fields := FCodec.Decode(Payload);
      for I := 0 to High(Fields) do
      begin
        F := Fields[I];
        if F.Name = ':method' then FReqMethod := F.Value
        else if F.Name = ':path' then FReqPath := F.Value
        else if F.Name = ':scheme' then FReqScheme := F.Value
        else if F.Name = ':authority' then FReqAuthority := F.Value;
      end;
      EmitResponse(StreamId);
    end
    else if (Typ = Ord(ftPing)) and ((Flags and $01) = 0) then
      AppendInLocked(FrameBytes(BuildPingFrame(Payload, True)))
    else if (Typ = Ord(ftSettings)) and ((Flags and $01) <> 0) then
      ; // SETTINGS ACK: ignore
  end;
end;

function TFramePeer.Read(var ABuffer; ACount: Integer): Integer;
var
  Avail, N: Integer;
begin
  FLock.Acquire;
  try
    if not FConnected then
      raise EHttpConnectionClosed.Create('frame peer closed');
    Avail := Length(FIn) - FReadPos;
    if Avail <= 0 then
      raise EHttpTimeout.Create('frame peer read idle');
    N := ACount;
    if N > Avail then
      N := Avail;
    Move(FIn[FReadPos], PByte(@ABuffer)^, N);
    Inc(FReadPos, N);
    Result := N;
  finally
    FLock.Release;
  end;
end;

function TFramePeer.Write(const ABuffer; ACount: Integer): Integer;
begin
  FLock.Acquire;
  try
    if not FConnected then
      raise EHttpConnectionClosed.Create('frame peer closed');
    AppendWritten(ABuffer, ACount);
    ParseAvailable;
  finally
    FLock.Release;
  end;
  RTLEventSetEvent(FDataEvent);
  Result := ACount;
end;

procedure TFramePeer.Close;
begin
  FLock.Acquire;
  try
    FConnected := False;
  finally
    FLock.Release;
  end;
  RTLEventSetEvent(FDataEvent);
end;

function TFramePeer.GetConnected: Boolean;
begin
  Result := FConnected;
end;

function TFramePeer.GetConnectTimeoutMs: Integer;
begin
  Result := 30000;
end;

procedure TFramePeer.SetConnectTimeoutMs(const AValue: Integer);
begin
end;

function TFramePeer.GetReadTimeoutMs: Integer;
begin
  Result := 30000;
end;

procedure TFramePeer.SetReadTimeoutMs(const AValue: Integer);
begin
end;

function TFramePeer.GetWriteTimeoutMs: Integer;
begin
  Result := 30000;
end;

procedure TFramePeer.SetWriteTimeoutMs(const AValue: Integer);
begin
end;

{ TFramePeerPlainFactory }

constructor TFramePeerPlainFactory.Create(const AStatus: string;
  const ABody: TBytes);
begin
  inherited Create;
  FStatus := AStatus;
  FBody := ABody;
  FPeers := TList<TFramePeer>.Create;
end;

destructor TFramePeerPlainFactory.Destroy;
begin
  FPeers.Free;
  inherited Destroy;
end;

function TFramePeerPlainFactory.Dial(const AHost: string; const APort: Word;
  const ATimeoutMs: Integer): IHttp2Socket;
var
  P: TFramePeer;
begin
  P := TFramePeer.Create(FStatus, FBody);
  FPeers.Add(P);
  Result := P;
end;

function TFramePeerPlainFactory.DialProtocol(const AHost: string;
  const APort: Word; const AScheme: string; const AHttp1Fallback: Boolean;
  const APolicy: TClearTextPolicy; const ATimeoutMs: Integer;
  out AProtocol: TNegotiatedProtocol): IHttp2Socket;
begin
  AProtocol := npHttp2Cleartext;
  Result := Dial(AHost, APort, ATimeoutMs);
end;

function TFramePeerPlainFactory.SocketAt(const AIndex: Integer): TFramePeer;
begin
  Result := FPeers[AIndex];
end;

{ TClearTextTest }

procedure TClearTextTest.TestDefaultsAreStrict;
var
  F: THttpClientFactory;
begin
  F := THttpClientFactory.Create;
  AssertEquals('Http1Fallback defaults off', False, F.Http1Fallback);
  AssertTrue('ClearTextPolicy defaults to ctReject',
    F.ClearTextPolicy = ctReject);
end;

procedure TClearTextTest.TestWithClearTextChangesThePolicy;
var
  F: THttpClientFactory;
begin
  F := THttpClientFactory.Create.WithClearText(ctPriorKnowledge);
  AssertTrue('policy is ctPriorKnowledge', F.ClearTextPolicy = ctPriorKnowledge);
  F := THttpClientFactory.Create.WithClearText(ctUpgrade);
  AssertTrue('policy is ctUpgrade', F.ClearTextPolicy = ctUpgrade);
end;

procedure TClearTextTest.TestWithHttp1FallbackIsOffByDefault;
var
  F: THttpClientFactory;
begin
  F := THttpClientFactory.Create.WithHttp1Fallback;
  AssertEquals('WithHttp1Fallback turns it on', True, F.Http1Fallback);
  F := THttpClientFactory.Create.WithHttp1Fallback(False);
  AssertEquals('explicit False keeps it off', False, F.Http1Fallback);
end;

procedure TClearTextTest.TestFluentChainStaysCopyOnWrite;
var
  A, B: THttpClientFactory;
begin
  A := THttpClientFactory.Create;
  B := A.WithClearText(ctUpgrade).WithMaxConnections(9);
  // the original factory must be untouched: WithX returns a new record
  AssertTrue('the original policy is still strict', A.ClearTextPolicy = ctReject);
  AssertEquals('the original MaxConnections is unchanged', 4, A.MaxConnections);
  AssertTrue('the fork carries the new policy', B.ClearTextPolicy = ctUpgrade);
  AssertEquals('the fork carries the new cap', 9, B.MaxConnections);
end;

procedure TClearTextTest.TestStrictModeRejectsCleartextUrl;
var
  Client: IHttpClient;
  Raised: Boolean;
  Code: Integer;
begin
  Client := THttpClientFactory.Create
    .WithSocketFactory(TNeverDialFactory.Create)
    .Build;
  Raised := False;
  Code := -1;
  try
    Client.Send(THttpRequest.Create(hmGet, 'http://plain.example/x'));
  except
    on E: EHttpError do
    begin
      Raised := True;
      Code := Ord(E.ErrorCode);
    end;
  end;
  AssertTrue('a cleartext request raises by default', Raised);
  AssertEquals('the error code is PROTOCOL_ERROR', Ord(ecProtocolError), Code);
  Client.Close;
end;

procedure TClearTextTest.TestHttpsUrlIsNotAffectedByThePolicy;
var
  Client: IHttpClient;
  Raised: Boolean;
  Msg: string;
begin
  // an https origin must pass the cleartext guard and reach the transport,
  // which proves the guard keys on the scheme and not on the policy alone
  Client := THttpClientFactory.Create
    .WithSocketFactory(TNeverDialFactory.Create)
    .Build;
  Raised := False;
  Msg := '';
  try
    Client.Send(THttpRequest.Create(hmGet, 'https://secure.example/x'));
  except
    on E: Exception do
    begin
      Raised := True;
      Msg := E.Message;
    end;
  end;
  AssertTrue('the transport was reached', Raised);
  AssertTrue('and it was the dial stub, not the cleartext guard',
    Pos('transport must not be dialled', Msg) > 0);
  Client.Close;
end;

procedure TClearTextTest.TestDialProtocolPriorKnowledgeSelectsCleartextH2;
var
  Factory: TScriptProtocolFactory;
  Client: IHttpClient;
begin
  // the factory reports npHttp2Cleartext, so the pool must hand the socket to
  // TConnection (which writes the preface) and never touch HTTP/1.1.  The
  // script is empty, so the only observable outcome is the exact call.
  Factory := TScriptProtocolFactory.Create(npHttp2Cleartext, '');
  Client := THttpClientFactory.Create
    .WithSocketFactory(Factory)
    .WithClearText(ctPriorKnowledge)
    .WithConnectTimeout(200).WithHeaderTimeout(200)
    .Build;
  try
    Client.Send(THttpRequest.Create(hmGet, 'http://plain.example/x'));
  except
    on E: Exception do ;   // no response scripted
  end;
  AssertEquals('the scheme reached DialProtocol', 'http', Factory.LastScheme);
  AssertEquals('the port reached DialProtocol', 80, Factory.LastPort);
  AssertTrue('prior knowledge was passed through',
    Factory.LastPolicy = ctPriorKnowledge);
  // a prior-knowledge connection writes the 24-byte preface first (the
  // connection thread flushes asynchronously, so wait before asserting)
  AssertTrue('the connection thread wrote the preface',
    Factory.SocketAt(0).WaitForText('PRI * HTTP/2.0', 2000));
  Client.Close;
end;

procedure TClearTextTest.TestDialProtocolUpgradeSelectsCleartextH1;
var
  Factory: TScriptProtocolFactory;
  Client: IHttpClient;
begin
  // npHttp1Cleartext with an empty script: the upgrade request is written,
  // then the status read hits EOF and the pool falls back; assert the request
  // bytes rather than the outcome
  Factory := TScriptProtocolFactory.Create(npHttp1Cleartext, '');
  Client := THttpClientFactory.Create
    .WithSocketFactory(Factory)
    .WithClearText(ctUpgrade)
    .WithConnectTimeout(200).WithHeaderTimeout(200)
    .Build;
  try
    Client.Send(THttpRequest.Create(hmGet, 'http://plain.example/x'));
  except
    on E: Exception do ;
  end;
  AssertTrue('the h2c upgrade request was written',
    Pos('Upgrade: h2c', Factory.SocketAt(0).WrittenText) > 0);
  Client.Close;
end;

procedure TClearTextTest.TestDialProtocolHttp1TlsSelectsTheTextCodec;
var
  Factory: TScriptProtocolFactory;
  Client: IHttpClient;
  R: IHttpResponse;
  Written: string;
begin
  // npHttp1Tls: an https origin whose ALPN resolved to http/1.1 must be served
  // by the TEXT codec, so the frame format would be meaningless here
  Factory := TScriptProtocolFactory.Create(npHttp1Tls,
    'HTTP/1.1 200 OK'#13#10'Content-Length: 5'#13#10#13#10'hello');
  Client := THttpClientFactory.Create
    .WithSocketFactory(Factory)
    .WithHttp1Fallback
    .WithConnectTimeout(200).WithHeaderTimeout(200)
    .Build;
  R := Client.Send(THttpRequest.Create(hmGet, 'https://secure.example/x'));
  AssertEquals('the HTTP/1.1 codec returned the status', 200, R.StatusCode);
  Written := Factory.SocketAt(0).WrittenText;
  AssertTrue('the plain-text request line was written',
    Pos('GET /x HTTP/1.1', Written) > 0);
  AssertTrue('no HTTP/2 preface was written',
    Pos('PRI * HTTP/2.0', Written) = 0);
  Client.Close;
end;

procedure TClearTextTest.TestPriorKnowledgeGetReachesHttp2OnTheSameSocket;
var
  Factory: TFramePeerPlainFactory;
  Client: IHttpClient;
  R: IHttpResponse;
  Body: array[0..63] of Byte;
  N: LongInt;
  Total: Integer;
begin
  Factory := TFramePeerPlainFactory.Create('200', TextBytes('0123456789'));
  Client := THttpClientFactory.Create
    .WithSocketFactory(Factory)
    .WithClearText(ctPriorKnowledge)
    .WithConnectTimeout(2000).WithHeaderTimeout(2000)
    .Build;
  R := Client.Send(THttpRequest.Create(hmGet, 'http://127.0.0.1:28080/small.txt'));
  AssertEquals('http2 response status', 200, R.StatusCode);
  Total := 0;
  repeat
    N := R.Body.Read(Body, SizeOf(Body));
    Inc(Total, N);
  until N <= 0;
  AssertEquals('http2 response body', 10, Total);
  AssertEquals('the :method reached the peer', 'GET', Factory.SocketAt(0).ReqMethod);
  AssertEquals('the :path reached the peer', '/small.txt',
    Factory.SocketAt(0).ReqPath);
  AssertEquals('the :scheme is http', 'http', Factory.SocketAt(0).ReqScheme);
  Client.Close;
end;

procedure TClearTextTest.TestUpgradeSendsH2cHeadersAndSettings;
var
  Factory: TScriptProtocolFactory;
  Client: IHttpClient;
  Req: string;
begin
  // a 101 head followed by no frames: the client must switch the SAME socket
  // to HTTP/2 and write the preface
  Factory := TScriptProtocolFactory.Create(npHttp1Cleartext,
    'HTTP/1.1 101 Switching Protocols'#13#10'Upgrade: h2c'#13#10 +
    'Connection: Upgrade'#13#10#13#10);
  Client := THttpClientFactory.Create
    .WithSocketFactory(Factory)
    .WithClearText(ctUpgrade)
    .WithConnectTimeout(200).WithHeaderTimeout(200)
    .Build;
  try
    Client.Send(THttpRequest.Create(hmGet, 'http://127.0.0.1:28081/x'));
  except
    on E: Exception do ;   // no response frames scripted: only the request matters
  end;
  Req := Factory.SocketAt(0).WrittenText;
  AssertTrue('the upgrade request line', Pos('GET /x HTTP/1.1', Req) > 0);
  AssertTrue('Upgrade: h2c', Pos('Upgrade: h2c', Req) > 0);
  AssertTrue('Connection: Upgrade, HTTP2-Settings',
    Pos('Connection: Upgrade, HTTP2-Settings', Req) > 0);
  AssertTrue('HTTP2-Settings carries base64url',
    Pos('HTTP2-Settings: ', Req) > 0);
  AssertTrue('HTTP2-Settings has no padding', Pos('=', Req) = 0);
  // the preface is written by the connection thread after the 101 is consumed,
  // and it flushes asynchronously, so wait rather than assume
  AssertTrue('the preface was written after the 101',
    Factory.SocketAt(0).WaitForText('PRI * HTTP/2.0', 2000));
  Client.Close;
end;

procedure TClearTextTest.TestUpgradeNon101ReturnsTheHttp1Response;
var
  Factory: TScriptProtocolFactory;
  Client: IHttpClient;
  R: IHttpResponse;
  Body: array[0..63] of Byte;
  N: LongInt;
  Total: Integer;
begin
  // the peer declines the upgrade: it answers 200 over HTTP/1.1.  The pool
  // discards the half-read socket and dials a fresh one (same factory), so
  // the second script must carry the 200 response
  Factory := TScriptProtocolFactory.Create(npHttp1Cleartext,
    'HTTP/1.1 200 OK'#13#10'Content-Length: 5'#13#10#13#10'hello');
  Client := THttpClientFactory.Create
    .WithSocketFactory(Factory)
    .WithClearText(ctUpgrade)
    .WithConnectTimeout(200).WithHeaderTimeout(200)
    .Build;
  R := Client.Send(THttpRequest.Create(hmGet, 'http://127.0.0.1:28082/x'));
  AssertEquals('the HTTP/1.1 response status is returned', 200, R.StatusCode);
  Total := 0;
  repeat
    N := R.Body.Read(Body, SizeOf(Body));
    Inc(Total, N);
  until N <= 0;
  AssertEquals('the HTTP/1.1 body is returned', 5, Total);
  // two dials: the upgrade probe, then the fresh HTTP/1.1 connection the
  // declined exchange is re-issued on (the half-read socket is unusable)
  AssertEquals('the upgrade was attempted and then re-dialled', 2,
    Factory.Dials);
  Client.Close;
end;

procedure TClearTextTest.TestPoolKeepsHttpAndHttpsOriginsApart;
var
  Factory: TFramePeerPlainFactory;
  Client: IHttpClient;
  Pool: TConnectionPool;
begin
  // both origins are dialled as HTTP/2 cleartext so both Sends succeed; the
  // pool must still keep the two origin keys apart
  Factory := TFramePeerPlainFactory.Create('200', TextBytes('ok'));
  Client := THttpClientFactory.Create
    .WithSocketFactory(Factory)
    .WithClearText(ctPriorKnowledge)
    .WithConnectTimeout(2000).WithHeaderTimeout(2000)
    .Build;
  Pool := (Client as THttpClient).Pool;
  Client.Send(THttpRequest.Create(hmGet, 'http://a.example/x'));
  Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  // OriginOfUrl prefixes only non-https schemes, so the two keys are
  // 'http://a.example' and 'a.example': an http origin can never reuse a
  // pooled https connection (doc/design/fallback.md "Pool keys")
  AssertEquals('the http origin has its own connection', 1,
    Pool.ConnectionCountForOrigin('http://a.example'));
  AssertEquals('the https origin has its own connection', 1,
    Pool.ConnectionCountForOrigin('a.example'));
  AssertEquals('the pool holds two connections', 2, Pool.ConnectionCount);
  Client.Close;
end;

procedure TClearTextTest.TestHttp1PooledConnectionReportsStreamLimitOne;
var
  Sock: TScriptSocket;
  H1: THttp1Connection;
  Wire: IPooledConnection;
  Req: TStreamRequest;
  R: IHttpResponse;
  Acquired: Boolean;
begin
  Sock := TScriptSocket.Create;
  Sock.Feed('HTTP/1.1 200 OK'#13#10'Content-Length: 2'#13#10#13#10'hi');
  H1 := THttp1Connection.Create(Sock, 500);
  // held as the interface so ARC owns it (the wrapper owns H1, H1 owns Sock)
  Wire := THttp1PooledConnection.Create(H1, 'http://a.example');
  AssertEquals('an idle HTTP/1.1 connection carries no stream', 0,
    Wire.ActiveStreams);
  AssertTrue('and is eligible', Wire.Eligible);
  AssertTrue('and is not closed', not Wire.Closed);
  AssertTrue('it has no TConnection', Wire.Conn = nil);
  // drive one request whose body is NOT drained: HTTP/1.1 has no
  // multiplexing, so the wrapper must now report the limit-1 state and stop
  // being eligible, which is how the pool opens a second connection instead
  Req := TStreamRequest.Create('GET', 'a.example');
  Req := Req.WithScheme('http').WithPath('/x');
  R := Wire.Acquire(Req, 500, Acquired);
  AssertTrue('the request was acquired', Acquired);
  AssertEquals('a request in flight reports the limit-1 state',
    cHttp1StreamLimit, Wire.ActiveStreams);
  AssertFalse('a connection with a request in flight is not eligible',
    Wire.Eligible);
  R := nil;
  Wire := nil;
end;

procedure TClearTextTest.TestUpgradeWithBodyUsesPlainHttp1;
var
  Factory: TScriptProtocolFactory;
  Client: IHttpClient;
  R: IHttpResponse;
  Written: string;
begin
  // a request WITH a body must not be probed with Upgrade (the body would be
  // transmitted twice); it goes over plain HTTP/1.1 on the dialled socket
  Factory := TScriptProtocolFactory.Create(npHttp1Cleartext,
    'HTTP/1.1 200 OK'#13#10'Content-Length: 2'#13#10#13#10'ok');
  Client := THttpClientFactory.Create
    .WithSocketFactory(Factory)
    .WithClearText(ctUpgrade)
    .WithConnectTimeout(200).WithHeaderTimeout(200)
    .Build;
  R := Client.Send(THttpRequest.Create(hmPost, 'http://127.0.0.1:28082/x')
    .WithBody(THttpBody.FromString('payload')));
  AssertEquals('the plain HTTP/1.1 response is returned', 200, R.StatusCode);
  Written := Factory.SocketAt(0).WrittenText;
  AssertTrue('the body was sent as Content-Length',
    Pos('Content-Length: 7', Written) > 0);
  AssertTrue('no Upgrade header was sent for a body request',
    Pos('Upgrade: h2c', Written) = 0);
  Client.Close;
end;

initialization
  RegisterTest(TClearTextTest);
end.
