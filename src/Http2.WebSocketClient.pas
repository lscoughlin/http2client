/// The WebSocket connection: opening handshake over an HTTP/1.1-only dial, a
/// reader thread that delivers listener callbacks under demand, serialised
/// sends and the closing handshake (doc/design/websocket.md).
unit Http2.WebSocketClient;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$interfaces com}

interface

uses
  SysUtils, Classes, SyncObjs, Http2.Errors, Http2.Proxy, Http2.Tls,
  Http2.Http1, Http2.WebSocket;

const
  /// the reader wakes this often to notice Abort, timers and demand; on a
  /// socket whose reads and writes share one TLS state it is shorter so a
  /// waiting send is never held up for long
  cWsPollMsPlain = 100;
  cWsPollMsTls   = 25;
  cWsWriteTimeoutMs = 30000;
  cWsMaxHandshakeLines = 100;
  cWsMaxHandshakeBody = 4096;

type
  TWebSocketConnection = class;

  TWsReaderThread = class(TThread)
  private
    FConn: TWebSocketConnection;
  protected
    procedure Execute; override;
  public
    constructor Create(const AConn: TWebSocketConnection);
  end;

  /// an open WebSocket.  One reader thread owns every read and runs every
  /// listener callback; sends from any thread are written whole under a lock.
  // - the reader thread holds a reference to the connection until it ends, so
  //   a connection whose last outside reference is dropped stays alive (and
  //   keeps delivering) until it is closed, aborted or fails
  // - a connection that the caller does not Abort ends with exactly one of
  //   OnClose or OnError; Abort ends delivery without a further callback
  TWebSocketConnection = class(TInterfacedObject, IWebSocket)
  private
    FSock: IHttp2Socket;
    FReader: TBufferedReader;
    FParser: TWebSocketFrameParser;
    FAssembler: TWebSocketMessageAssembler;
    FRequest: IWebSocketRequest;
    FListener: IWebSocketListener;
    FSubprotocol: string;
    FUrl: string;
    FMask: TMaskKeySource;
    FLocked: Boolean;           // reads and writes share one TLS state
    FPollMs: Integer;
    FIo: TCriticalSection;      // guards the socket when FLocked
    FWriters: Integer;          // senders waiting for FIo
    FSendLock: TCriticalSection;
    FStateLock: TCriticalSection;
    FDemandEvent: TEvent;
    FDemand: Int64;
    FInputClosed: Boolean;
    FOutputClosed: Boolean;
    FAborted: Boolean;
    FSockClosed: Boolean;
    FTerminal: Boolean;
    FSendKind: Integer;         // 0 none, 1 text open, 2 binary open
    FCloseSentTick: QWord;
    FLastRx: QWord;
    FLastPing: QWord;
    FSelfRef: IWebSocket;
    FThread: TWsReaderThread;
    procedure WriteFrame(const AOpcode: Byte; const AFin: Boolean;
      const APayload: TBytes);
    function PollRead(var ABuffer; const ACount: Integer): Integer;
    function WaitDemand: Boolean;
    procedure AddDemand(const AN: Int64);
    procedure Terminal(const AError: Exception; const AOwned: Boolean);
    procedure CallbackFailed(const AError: Exception);
    function NotifyText(const AData: TBytes; const ALast: Boolean): Boolean;
    function NotifyBytes(const AData: TBytes; const ALast: Boolean): Boolean;
    function NotifyPing(const AData: TBytes): Boolean;
    function NotifyPong(const AData: TBytes): Boolean;
    function HandleFrame(const AFrame: TWsFrame): Boolean;
    function HandleClose(const AFrame: TWsFrame): Boolean;
    procedure FailProtocol(const AError: EHttpWebSocketProtocolError);
    procedure SendCloseQuiet(const ACode: Integer);
    procedure DrainUntilEof;
    function TimersOk: Boolean;
    procedure CloseTransport;
    procedure Teardown;
    procedure ReleaseResources;
    procedure SendData(const AKind: Integer; const APayload: TBytes;
      const ALast: Boolean);
  public
    constructor Create(const ASock: IHttp2Socket; const AReader: TBufferedReader;
      const ARequest: IWebSocketRequest; const ASubprotocol: string;
      const AMask: TMaskKeySource; const ALocked: Boolean);
    destructor Destroy; override;
    /// start the reader thread (OnOpen is its first callback)
    procedure Start;
    procedure ReaderMain;
    procedure ReleaseSelf;
    procedure Abort;
    procedure Request(const AN: Integer);
    procedure SendPing(const AData: TBytes);
    procedure SendPong(const AData: TBytes);
    procedure SendBinary(const AData: TBytes; const ALast: Boolean = True);
    procedure SendText(const AText: string; const ALast: Boolean = True);
    procedure Close(const AStatusCode: Integer = cWsCloseNormal;
      const AReason: string = '');
    function GetInputClosed: Boolean;
    function GetOutputClosed: Boolean;
    function GetSubprotocol: string;
    function GetUrl: string;
  end;

/// dial AProxy-routed (nil = direct), run the opening handshake for ARequest
/// and return the open WebSocket.  ADefaultConnectTimeoutMs applies when the
/// request sets none.  AMask nil selects the secure random source.
function OpenWebSocket(const AFactory: IHttp1SocketFactory;
  const ARequest: IWebSocketRequest; const AProxy: IProxy;
  const ADefaultConnectTimeoutMs: Integer;
  const AMask: TMaskKeySource = nil): IWebSocket;

implementation

function NowMs: QWord;
begin
  Result := GetTickCount64;
end;

{ TWsReaderThread }

constructor TWsReaderThread.Create(const AConn: TWebSocketConnection);
begin
  FConn := AConn;
  FreeOnTerminate := True;
  inherited Create(False);
end;

procedure TWsReaderThread.Execute;
var
  Conn: TWebSocketConnection;
begin
  Conn := FConn;
  FConn := nil;
  try
    Conn.ReaderMain;
  finally
    // the last act: this may release the final reference and free Conn
    Conn.ReleaseSelf;
  end;
end;

{ TWebSocketConnection }

constructor TWebSocketConnection.Create(const ASock: IHttp2Socket;
  const AReader: TBufferedReader; const ARequest: IWebSocketRequest;
  const ASubprotocol: string; const AMask: TMaskKeySource;
  const ALocked: Boolean);
begin
  inherited Create;
  FSock := ASock;
  FReader := AReader;
  FRequest := ARequest;
  FListener := ARequest.Listener;
  FSubprotocol := ASubprotocol;
  FUrl := ARequest.Url;
  FMask := AMask;
  FLocked := ALocked;
  if ALocked then
    FPollMs := cWsPollMsTls
  else
    FPollMs := cWsPollMsPlain;
  FIo := TCriticalSection.Create;
  FSendLock := TCriticalSection.Create;
  FStateLock := TCriticalSection.Create;
  FDemandEvent := TEvent.Create(nil, False, False, '');
  FParser := TWebSocketFrameParser.Create;
  FAssembler := TWebSocketMessageAssembler.Create(ARequest.MaxMessageBytes);
  FSock.ReadTimeoutMs := FPollMs;
  FSock.WriteTimeoutMs := cWsWriteTimeoutMs;
  if ARequest.AutoRequest then
    FDemand := 1;
  FLastRx := NowMs;
  FLastPing := FLastRx;
end;

destructor TWebSocketConnection.Destroy;
begin
  if not FSockClosed then
    try
      FSock.Close;
    except
    end;
  FSock := nil;
  FParser.Free;
  FAssembler.Free;
  FReader.Free;
  FDemandEvent.Free;
  FStateLock.Free;
  FSendLock.Free;
  FIo.Free;
  inherited Destroy;
end;

procedure TWebSocketConnection.Start;
begin
  FSelfRef := Self;
  FThread := TWsReaderThread.Create(Self);
end;

procedure TWebSocketConnection.ReleaseSelf;
begin
  FSelfRef := nil;
end;

{ sending }

procedure TWebSocketConnection.WriteFrame(const AOpcode: Byte;
  const AFin: Boolean; const APayload: TBytes);
var
  Wire: TBytes;
  Sent, N: Integer;
begin
  // the caller holds FSendLock
  if FSockClosed or FAborted then
    raise EHttpWebSocketClosedError.Create('the WebSocket is closed');
  Wire := WsEncodeFrame(AOpcode, AFin, APayload, True,
    WsMaskKeyFromCardinal(FMask()));
  try
    if FLocked then
    begin
      InterlockedIncrement(FWriters);
      FIo.Enter;
      InterlockedDecrement(FWriters);
    end;
    try
      Sent := 0;
      while Sent < Length(Wire) do
      begin
        N := FSock.Write(Wire[Sent], Length(Wire) - Sent);
        if N <= 0 then
          raise EHttpConnectionError.Create('WebSocket write failed');
        Inc(Sent, N);
      end;
    finally
      if FLocked then
        FIo.Leave;
    end;
  except
    // a failed or partial write leaves the stream unusable
    FAborted := True;
    FDemandEvent.SetEvent;
    raise;
  end;
end;

procedure TWebSocketConnection.SendData(const AKind: Integer;
  const APayload: TBytes; const ALast: Boolean);
var
  Op: Byte;
begin
  FSendLock.Enter;
  try
    if FOutputClosed then
      raise EHttpWebSocketClosedError.Create('the output side is closed');
    if (FSendKind <> 0) and (FSendKind <> AKind) then
      raise EHttpWebSocketError.Create(
        'a message of the other kind is still being sent');
    if FSendKind = 0 then
    begin
      if AKind = 1 then Op := cWsOpText else Op := cWsOpBinary;
    end
    else
      Op := cWsOpContinuation;
    WriteFrame(Op, ALast, APayload);
    if ALast then
      FSendKind := 0
    else
      FSendKind := AKind;
  finally
    FSendLock.Leave;
  end;
end;

procedure TWebSocketConnection.SendText(const AText: string;
  const ALast: Boolean);
var
  B: TBytes;
  Safe: Integer;
begin
  SetLength(B, Length(AText));
  if AText <> '' then
  begin
    Move(AText[1], B[0], Length(AText));
    if (not WsUtf8Check(@B[0], Length(B), Safe)) or (Safe <> Length(B)) then
      raise EHttpWebSocketError.Create('text to send is not valid UTF-8');
  end;
  SendData(1, B, ALast);
end;

procedure TWebSocketConnection.SendBinary(const AData: TBytes;
  const ALast: Boolean);
begin
  SendData(2, AData, ALast);
end;

procedure TWebSocketConnection.SendPing(const AData: TBytes);
begin
  if Length(AData) > cWsMaxControlPayload then
    raise EHttpWebSocketError.Create('a ping carries at most 125 octets');
  FSendLock.Enter;
  try
    if FOutputClosed then
      raise EHttpWebSocketClosedError.Create('the output side is closed');
    WriteFrame(cWsOpPing, True, AData);
  finally
    FSendLock.Leave;
  end;
end;

procedure TWebSocketConnection.SendPong(const AData: TBytes);
begin
  if Length(AData) > cWsMaxControlPayload then
    raise EHttpWebSocketError.Create('a pong carries at most 125 octets');
  FSendLock.Enter;
  try
    if FOutputClosed then
      raise EHttpWebSocketClosedError.Create('the output side is closed');
    WriteFrame(cWsOpPong, True, AData);
  finally
    FSendLock.Leave;
  end;
end;

procedure TWebSocketConnection.Close(const AStatusCode: Integer;
  const AReason: string);
begin
  if not WsIsWireCloseCode(AStatusCode) then
    raise EHttpWebSocketError.CreateFmt(
      'status code %d cannot be sent in a close frame', [AStatusCode]);
  if Length(AReason) > cWsMaxControlPayload - 2 then
    raise EHttpWebSocketError.Create('a close reason carries at most 123 octets');
  FSendLock.Enter;
  try
    if FOutputClosed then
      Exit;
    WriteFrame(cWsOpClose, True, WsBuildClosePayload(AStatusCode, AReason));
    FStateLock.Enter;
    try
      FOutputClosed := True;
      FCloseSentTick := NowMs;
    finally
      FStateLock.Leave;
    end;
  finally
    FSendLock.Leave;
  end;
end;

procedure TWebSocketConnection.Abort;
begin
  FStateLock.Enter;
  try
    FAborted := True;
    FInputClosed := True;
    FOutputClosed := True;
  finally
    FStateLock.Leave;
  end;
  FDemandEvent.SetEvent;
end;

procedure TWebSocketConnection.Request(const AN: Integer);
begin
  if AN <= 0 then
    raise EHttpWebSocketError.Create('Request needs a positive count');
  AddDemand(AN);
end;

procedure TWebSocketConnection.AddDemand(const AN: Int64);
begin
  FStateLock.Enter;
  try
    if FDemand < High(Int64) div 4 then
      Inc(FDemand, AN);
  finally
    FStateLock.Leave;
  end;
  FDemandEvent.SetEvent;
end;

function TWebSocketConnection.GetInputClosed: Boolean;
begin
  FStateLock.Enter;
  try
    Result := FInputClosed;
  finally
    FStateLock.Leave;
  end;
end;

function TWebSocketConnection.GetOutputClosed: Boolean;
begin
  FStateLock.Enter;
  try
    Result := FOutputClosed;
  finally
    FStateLock.Leave;
  end;
end;

function TWebSocketConnection.GetSubprotocol: string;
begin
  Result := FSubprotocol;
end;

function TWebSocketConnection.GetUrl: string;
begin
  Result := FUrl;
end;

{ reading }

function TWebSocketConnection.PollRead(var ABuffer;
  const ACount: Integer): Integer;
begin
  try
    if FLocked then
    begin
      // senders go first: they announce themselves before taking the lock
      while FWriters > 0 do
        Sleep(1);
      FIo.Enter;
      try
        Result := FReader.ReadBytes(ABuffer, ACount);
      finally
        FIo.Leave;
      end;
    end
    else
      Result := FReader.ReadBytes(ABuffer, ACount);
  except
    on EHttpTimeout do
      Result := -1;
  end;
end;

function TWebSocketConnection.WaitDemand: Boolean;
begin
  while True do
  begin
    FStateLock.Enter;
    try
      if FAborted then
        Exit(False);
      if FDemand > 0 then
      begin
        Dec(FDemand);
        Exit(True);
      end;
    finally
      FStateLock.Leave;
    end;
    FDemandEvent.WaitFor(100);
  end;
end;

procedure TWebSocketConnection.Terminal(const AError: Exception;
  const AOwned: Boolean);
begin
  if not FTerminal then
  begin
    FTerminal := True;
    try
      FListener.OnError(FSelfRef, AError);
    except
      // a failing OnError has nowhere left to go
    end;
  end;
  if AOwned then
    AError.Free;
end;

procedure TWebSocketConnection.CallbackFailed(const AError: Exception);
begin
  Abort;
  Terminal(AError, False);
end;

function TWebSocketConnection.NotifyText(const AData: TBytes;
  const ALast: Boolean): Boolean;
var
  S: string;
begin
  Result := WaitDemand;
  if not Result then
    Exit;
  SetLength(S, Length(AData));
  if Length(AData) > 0 then
    Move(AData[0], S[1], Length(AData));
  try
    FListener.OnText(FSelfRef, S, ALast);
  except
    on E: Exception do
    begin
      CallbackFailed(E);
      Result := False;
    end;
  end;
  if Result and FRequest.AutoRequest then
    AddDemand(1);
end;

function TWebSocketConnection.NotifyBytes(const AData: TBytes;
  const ALast: Boolean): Boolean;
begin
  Result := WaitDemand;
  if not Result then
    Exit;
  try
    FListener.OnBytes(FSelfRef, AData, ALast);
  except
    on E: Exception do
    begin
      CallbackFailed(E);
      Result := False;
    end;
  end;
  if Result and FRequest.AutoRequest then
    AddDemand(1);
end;

function TWebSocketConnection.NotifyPing(const AData: TBytes): Boolean;
begin
  Result := WaitDemand;
  if not Result then
    Exit;
  try
    FListener.OnPing(FSelfRef, AData);
  except
    on E: Exception do
    begin
      CallbackFailed(E);
      Result := False;
    end;
  end;
  if Result and FRequest.AutoRequest then
    AddDemand(1);
end;

function TWebSocketConnection.NotifyPong(const AData: TBytes): Boolean;
begin
  Result := WaitDemand;
  if not Result then
    Exit;
  try
    FListener.OnPong(FSelfRef, AData);
  except
    on E: Exception do
    begin
      CallbackFailed(E);
      Result := False;
    end;
  end;
  if Result and FRequest.AutoRequest then
    AddDemand(1);
end;

function TWebSocketConnection.HandleClose(const AFrame: TWsFrame): Boolean;
var
  Code: Integer;
  Reason: string;
  Echo: TBytes;
begin
  WsParseClosePayload(AFrame.Payload, Code, Reason);
  FStateLock.Enter;
  try
    FInputClosed := True;
  finally
    FStateLock.Leave;
  end;
  // answer at once; delivery to the listener waits for demand
  FSendLock.Enter;
  try
    if not FOutputClosed then
    begin
      if Code = cWsCloseNoStatus then
        SetLength(Echo, 0)
      else
        Echo := WsBuildClosePayload(Code, '');
      try
        WriteFrame(cWsOpClose, True, Echo);
      except
        // the peer may already be gone; the close is still reported
      end;
      FStateLock.Enter;
      try
        FOutputClosed := True;
      finally
        FStateLock.Leave;
      end;
    end;
  finally
    FSendLock.Leave;
  end;
  Result := False;                    // the connection ends here
  // let the server finish and close TCP, then release the socket now: the
  // report below waits for demand, which may never come
  DrainUntilEof;
  CloseTransport;
  if WaitDemand then
  begin
    FTerminal := True;
    try
      FListener.OnClose(FSelfRef, Code, Reason);
    except
      on E: Exception do
      begin
        FTerminal := False;           // report the failure instead
        CallbackFailed(E);
      end;
    end;
  end;
end;

function TWebSocketConnection.HandleFrame(const AFrame: TWsFrame): Boolean;
var
  Kind: TWsDataKind;
  Data: TBytes;
  Last: Boolean;
begin
  Result := True;
  case AFrame.Opcode of
    cWsOpPing:
      begin
        // the pong goes out before the callback so a slow listener cannot
        // delay it
        FSendLock.Enter;
        try
          if not FOutputClosed then
            WriteFrame(cWsOpPong, True, AFrame.Payload);
        finally
          FSendLock.Leave;
        end;
        Result := NotifyPing(AFrame.Payload);
      end;
    cWsOpPong:
      Result := NotifyPong(AFrame.Payload);
    cWsOpClose:
      Result := HandleClose(AFrame);
  else
    if FAssembler.Accept(AFrame, Kind, Data, Last) then
    begin
      if Kind = wkText then
        Result := NotifyText(Data, Last)
      else
        Result := NotifyBytes(Data, Last);
    end;
  end;
end;

procedure TWebSocketConnection.SendCloseQuiet(const ACode: Integer);
begin
  FSendLock.Enter;
  try
    if not FOutputClosed then
    begin
      try
        WriteFrame(cWsOpClose, True, WsBuildClosePayload(ACode, ''));
      except
      end;
      FStateLock.Enter;
      try
        FOutputClosed := True;
        FCloseSentTick := NowMs;
      finally
        FStateLock.Leave;
      end;
    end;
  finally
    FSendLock.Leave;
  end;
end;

procedure TWebSocketConnection.FailProtocol(
  const AError: EHttpWebSocketProtocolError);
begin
  SendCloseQuiet(AError.CloseCode);
  FStateLock.Enter;
  try
    FInputClosed := True;
  finally
    FStateLock.Leave;
  end;
  Terminal(AError, False);
  DrainUntilEof;
end;

procedure TWebSocketConnection.DrainUntilEof;
var
  Deadline: QWord;
  Buf: array[0..4095] of Byte;
  N: Integer;
begin
  Deadline := NowMs + QWord(FRequest.CloseTimeoutMs);
  while (not FAborted) and (NowMs < Deadline) do
  begin
    try
      N := PollRead(Buf, SizeOf(Buf));
    except
      Exit;
    end;
    if N = 0 then
      Exit;
  end;
end;

function TWebSocketConnection.TimersOk: Boolean;
var
  Now_: QWord;
  Interval: QWord;
begin
  Result := True;
  if FAborted then
    Exit(False);
  Now_ := NowMs;
  if (FCloseSentTick <> 0) and (not FInputClosed) and
     (Now_ - FCloseSentTick > QWord(FRequest.CloseTimeoutMs)) then
  begin
    Terminal(EHttpTimeout.Create('the server did not answer the close frame'),
      True);
    Exit(False);
  end;
  if FRequest.PingIntervalMs > 0 then
  begin
    Interval := QWord(FRequest.PingIntervalMs);
    if Now_ - FLastRx >= 2 * Interval then
    begin
      Terminal(EHttpTimeout.Create('no frame from the server for two ping intervals'),
        True);
      Exit(False);
    end;
    if (Now_ - FLastRx >= Interval) and (Now_ - FLastPing >= Interval) then
    begin
      FLastPing := Now_;
      try
        SendPing(nil);
      except
        // reported when the next read or write fails
      end;
    end;
  end;
end;

procedure TWebSocketConnection.CloseTransport;
begin
  // waits out a send in flight, then closes; later sends see FSockClosed
  FSendLock.Enter;
  try
    if not FSockClosed then
    begin
      FSockClosed := True;
      try
        FSock.Close;
      except
      end;
    end;
  finally
    FSendLock.Leave;
  end;
end;

procedure TWebSocketConnection.Teardown;
begin
  FStateLock.Enter;
  try
    FInputClosed := True;
    FOutputClosed := True;
    FAborted := True;
  finally
    FStateLock.Leave;
  end;
  CloseTransport;
end;

procedure TWebSocketConnection.ReleaseResources;
begin
  // a listener that keeps the socket (the usual JDK pattern) would otherwise
  // form a cycle through the request; the reader is the only user of these
  FListener := nil;
  FRequest := nil;
  FreeAndNil(FParser);
  FreeAndNil(FAssembler);
  FreeAndNil(FReader);
end;

procedure TWebSocketConnection.ReaderMain;
var
  Frame: TWsFrame;
  Buf: array[0..16383] of Byte;
  N: Integer;
  Go: Boolean;
begin
  try
    try
      try
        FListener.OnOpen(FSelfRef);
      except
        on E: Exception do
        begin
          CallbackFailed(E);
          Exit;
        end;
      end;
      Go := True;
      while Go and (not FAborted) do
      begin
        while Go and FParser.Next(Frame) do
          Go := HandleFrame(Frame);
        if not Go then
          Break;
        // timers run on every pass: a server that keeps sending must not
        // keep a close timeout or a ping interval from being noticed
        if not TimersOk then
          Break;
        N := PollRead(Buf, SizeOf(Buf));
        if N > 0 then
        begin
          FLastRx := NowMs;
          FParser.Feed(Buf, N);
        end
        else if N = 0 then
        begin
          if not FTerminal then
            Terminal(EHttpConnectionError.Create(
              'the connection closed without a WebSocket close frame'), True);
          Break;
        end;
      end;
    except
      on E: EHttpWebSocketProtocolError do
        FailProtocol(E);
      on E: Exception do
        if not FTerminal then
          Terminal(E, False);
    end;
  finally
    Teardown;
    ReleaseResources;
  end;
end;

{ opening handshake }

function OpenWebSocket(const AFactory: IHttp1SocketFactory;
  const ARequest: IWebSocketRequest; const AProxy: IProxy;
  const ADefaultConnectTimeoutMs: Integer;
  const AMask: TMaskKeySource): IWebSocket;
var
  Secure: Boolean;
  Host, Target, Authority, Key, Chosen, Why, Line, Version, Reason: string;
  Port: Word;
  Timeout, Status, I, N, Sent: Integer;
  Mask: TMaskKeySource;
  Sock: IHttp2Socket;
  Reader: TBufferedReader;
  Req, BodyBuf: TBytes;
  Raw: TArray<string>;
  Parsed: TArray<THttp1HeaderField>;
  Fields: TArray<TWsHeaderField>;
  HeaderLines, Body: string;
  TlsObj: TObject;
  Conn: TWebSocketConnection;
  Want: Integer;
begin
  Mask := AMask;
  if not Assigned(Mask) then
    Mask := SecureRandomCardinal;
  WsParseUrl(ARequest.Url, Secure, Host, Port, Target, Authority);
  Timeout := ARequest.ConnectTimeoutMs;
  if Timeout <= 0 then
    Timeout := ADefaultConnectTimeoutMs;
  Key := WsNewKey(Mask);
  Req := WsBuildHandshake(Target, Authority, Key, ARequest.Subprotocols,
    ARequest.Headers);
  if Secure then
    Sock := AFactory.DialHttp1(Host, Port, 'https', Timeout, AProxy)
  else
    Sock := AFactory.DialHttp1(Host, Port, 'http', Timeout, AProxy);
  Reader := nil;
  try
    Sock.ReadTimeoutMs := Timeout;
    Sock.WriteTimeoutMs := Timeout;
    Sent := 0;
    while Sent < Length(Req) do
    begin
      N := Sock.Write(Req[Sent], Length(Req) - Sent);
      if N <= 0 then
        raise EHttpConnectionError.Create('WebSocket handshake write failed');
      Inc(Sent, N);
    end;
    Reader := TBufferedReader.Create(Sock);
    if not Reader.ReadLine(Line) then
      raise EHttpConnectionError.Create(
        'the connection closed during the WebSocket handshake');
    ParseStatusLine(Line, Version, Status, Reason);
    SetLength(Raw, 0);
    while True do
    begin
      if not Reader.ReadLine(Line) then
        raise EHttpConnectionError.Create(
          'the connection closed during the WebSocket handshake');
      if Line = '' then
        Break;
      if Length(Raw) >= cWsMaxHandshakeLines then
        raise EHttpProtocolError.Create(
          'too many handshake response headers', ecProtocolError);
      SetLength(Raw, Length(Raw) + 1);
      Raw[High(Raw)] := Line;
    end;
    Parsed := ParseHeaders(Raw);
    SetLength(Fields, Length(Parsed));
    HeaderLines := '';
    for I := 0 to High(Parsed) do
    begin
      Fields[I].Name := Parsed[I].Name;
      Fields[I].Value := Parsed[I].Value;
      HeaderLines := HeaderLines + Parsed[I].Name + ': ' + Parsed[I].Value + #10;
    end;
    Why := WsCheckResponse(Status, Fields, Key, ARequest.Subprotocols, Chosen);
    if Why <> '' then
    begin
      Body := '';
      Want := StrToIntDef(HeaderFieldValue(Parsed, 'Content-Length'), 0);
      if Want > cWsMaxHandshakeBody then
        Want := cWsMaxHandshakeBody;
      if Want > 0 then
        try
          SetLength(BodyBuf, Want);
          N := Reader.ReadExact(BodyBuf[0], Want);
          if N > 0 then
            SetString(Body, PAnsiChar(@BodyBuf[0]), N);
        except
          // the status and headers are what matter
        end;
      raise EHttpWebSocketHandshakeError.Create(
        'WebSocket handshake failed: ' + Why, Status, HeaderLines, Body);
    end;
    Conn := TWebSocketConnection.Create(Sock, Reader, ARequest, Chosen, Mask,
      Supports(Sock, TTlsSocket, TlsObj));
    Reader := nil;                    // owned by the connection now
  except
    Sock.Close;
    Reader.Free;
    raise;
  end;
  Result := Conn;
  Conn.Start;
end;

end.
