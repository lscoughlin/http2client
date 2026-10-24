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
  Http2.Http1, Http2.WebSocket, Http2.Clock, Http2.Headers, Http2.Messages,
  Http2.RequestObserver;

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

  /// how a WebSocket session ended, as the connection saw it
  // - ClosedBy and CloseCode follow doc/design/request-observability.md:
  //   CloseCode and CloseReason are the peer's close frame when one arrived,
  //   else the code this side closed a failed session with, else 1006
  TWsSessionEnd = record
    ClosedBy: TCloseInitiator;
    CloseCode: Integer;
    CloseReason: string;
    /// borrowed for the call; nil unless the session failed
    Error: Exception;
    /// the connection was released with no end of any kind recorded
    Abandoned: Boolean;
    /// payload bytes of the data messages received and sent
    BytesIn, BytesOut: Int64;
  end;

  /// what the connection reports to the request observer's attempt for one
  /// WebSocket session; the attempt object also answers IAttemptProgress
  // - the handshake calls run on the caller's thread before the reader thread
  //   starts, so OnResponseHeaders always precedes the first message and the
  //   end
  IWebSocketAttempt = interface
    ['{7D1E5A02-3B94-4C6F-8E21-5A0C9B3D6F20}']
    /// the handshake headers after the observers injected theirs
    function HandshakeHeaders: TArray<TWsHeaderField>;
    /// the handshake request has been written
    procedure HandshakeWritten;
    /// the server answered 101; ASubprotocol is the one it chose ('' if none)
    procedure HandshakeAccepted(const AStatus: Integer;
      const AFields: TArray<TWsHeaderField>; const ASubprotocol: string);
    /// the session is over; the connection calls it at most once
    procedure SessionEnded(const AEnd: TWsSessionEnd);
  end;

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
    // observation: FAttempt is nil and FProgress ignores every call when no
    // request observer is installed
    FAttempt: IWebSocketAttempt;
    FProgress: IAttemptProgress;
    FEnded: LongInt;            // the end latch
    FBytesIn: Int64;            // atomic: the reader and the senders both count
    FBytesOut: Int64;
    FStampUs: Int64;            // reader thread: the read that fed the parser
    FInMsgBytes: Int64;         // reader thread: payload of the open message
    FOutMsgBytes: Int64;        // under FSendLock: payload of the open message
    FLocalClose: Boolean;       // Close sent a close frame; FStateLock
    FPeerCode: Integer;
    FPeerReason: string;
    FFailText: string;          // a failed write, for the fallback end
    procedure WriteFrame(const AOpcode: Byte; const AFin: Boolean;
      const APayload: TBytes);
    function PollRead(var ABuffer; const ACount: Integer): Integer;
    function WaitDemand: Boolean;
    procedure AddDemand(const AN: Int64);
    procedure Terminal(const AError: Exception; const AOwned: Boolean);
    procedure CallbackFailed(const AError: Exception);
    procedure MarkAborted;
    procedure EndSession(const AClosedBy: TCloseInitiator; const ACode: Integer;
      const AReason: string; const AError: Exception;
      const AAbandoned: Boolean);
    procedure ReportIn(const AKind: TMessageKind; const ASize: Integer);
    procedure ReportOut(const AKind: TMessageKind; const AStampUs: Int64;
      const ASize: Integer);
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
      const AMask: TMaskKeySource; const ALocked: Boolean;
      const AAttempt: IWebSocketAttempt = nil);
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
/// request sets none.  AMask nil selects the secure random source.  AAttempt,
/// when given, supplies the handshake headers (the request's plus what the
/// observers injected) and hears of the handshake and of the session.
function OpenWebSocket(const AFactory: IHttp1SocketFactory;
  const ARequest: IWebSocketRequest; const AProxy: IProxy;
  const ADefaultConnectTimeoutMs: Integer;
  const AMask: TMaskKeySource = nil;
  const AAttempt: IWebSocketAttempt = nil): IWebSocket;

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
  const ALocked: Boolean; const AAttempt: IWebSocketAttempt);
begin
  inherited Create;
  FAttempt := AAttempt;
  if (AAttempt = nil) or (not Supports(AAttempt, IAttemptProgress, FProgress)) then
    FProgress := NullAttemptProgress;
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
  // a connection released with no end recorded (never started, or the reader
  // could not run) ends its attempt as abandoned; one that ended is a no-op
  EndSession(ciNone, 0, '', nil, True);
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

{ observation }

procedure TWebSocketConnection.EndSession(const AClosedBy: TCloseInitiator;
  const ACode: Integer; const AReason: string; const AError: Exception;
  const AAbandoned: Boolean);
var
  E: TWsSessionEnd;
begin
  // the latch is taken here, so the reader, a caller's Abort and the release
  // race for it and exactly one reports.  No library lock is held: every
  // caller leaves its own locks before calling.
  if InterlockedCompareExchange(FEnded, 1, 0) <> 0 then
    Exit;
  if FAttempt = nil then
    Exit;
  E.ClosedBy := AClosedBy;
  E.CloseCode := ACode;
  E.CloseReason := AReason;
  E.Error := AError;
  E.Abandoned := AAbandoned;
  E.BytesIn := InterlockedExchangeAdd64(FBytesIn, 0);
  E.BytesOut := InterlockedExchangeAdd64(FBytesOut, 0);
  try
    FAttempt.SessionEnded(E);
  except
    // the attempt guards its observers; this is the last line of defence
  end;
end;

procedure TWebSocketConnection.ReportIn(const AKind: TMessageKind;
  const ASize: Integer);
begin
  FProgress.ReportMessage(AKind, mdIn, FStampUs, ASize, nil);
end;

procedure TWebSocketConnection.ReportOut(const AKind: TMessageKind;
  const AStampUs: Int64; const ASize: Integer);
begin
  FProgress.ReportMessage(AKind, mdOut, AStampUs, ASize, nil);
end;

procedure TWebSocketConnection.MarkAborted;
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
    // a failed or partial write leaves the stream unusable; the reader ends
    // the attempt when it notices (it holds no lock of the sender's)
    on E: Exception do
    begin
      FFailText := E.Message;
      FAborted := True;
      FDemandEvent.SetEvent;
      raise;
    end;
  end;
end;

procedure TWebSocketConnection.SendData(const AKind: Integer;
  const APayload: TBytes; const ALast: Boolean);
var
  Op: Byte;
  Stamp: Int64;
  Total: Int64;
begin
  Total := -1;
  Stamp := 0;
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
    Stamp := NowUs;
    InterlockedExchangeAdd64(FBytesOut, Length(APayload));
    Inc(FOutMsgBytes, Length(APayload));
    if ALast then
    begin
      FSendKind := 0;
      Total := FOutMsgBytes;
      FOutMsgBytes := 0;
    end
    else
      FSendKind := AKind;
  finally
    FSendLock.Leave;
  end;
  // a message is reported when its last fragment is written, outside the lock
  if Total >= 0 then
    if AKind = 1 then
      ReportOut(mkWsText, Stamp, Integer(Total))
    else
      ReportOut(mkWsBinary, Stamp, Integer(Total));
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
var
  Stamp: Int64;
begin
  if Length(AData) > cWsMaxControlPayload then
    raise EHttpWebSocketError.Create('a ping carries at most 125 octets');
  FSendLock.Enter;
  try
    if FOutputClosed then
      raise EHttpWebSocketClosedError.Create('the output side is closed');
    WriteFrame(cWsOpPing, True, AData);
    Stamp := NowUs;
  finally
    FSendLock.Leave;
  end;
  ReportOut(mkWsPing, Stamp, Length(AData));
end;

procedure TWebSocketConnection.SendPong(const AData: TBytes);
var
  Stamp: Int64;
begin
  if Length(AData) > cWsMaxControlPayload then
    raise EHttpWebSocketError.Create('a pong carries at most 125 octets');
  FSendLock.Enter;
  try
    if FOutputClosed then
      raise EHttpWebSocketClosedError.Create('the output side is closed');
    WriteFrame(cWsOpPong, True, AData);
    Stamp := NowUs;
  finally
    FSendLock.Leave;
  end;
  ReportOut(mkWsPong, Stamp, Length(AData));
end;

procedure TWebSocketConnection.Close(const AStatusCode: Integer;
  const AReason: string);
var
  Stamp: Int64;
  Sent: Boolean;
begin
  Sent := False;
  Stamp := 0;
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
    Stamp := NowUs;
    FStateLock.Enter;
    try
      FOutputClosed := True;
      FLocalClose := True;
      FCloseSentTick := NowMs;
    finally
      FStateLock.Leave;
    end;
    Sent := True;
  finally
    FSendLock.Leave;
  end;
  if Sent then
    ReportOut(mkWsClose, Stamp, 2 + Length(AReason));
end;

procedure TWebSocketConnection.Abort;
begin
  MarkAborted;
  // a deliberate end, reported here rather than by the reader so a reader
  // parked in a listener callback cannot delay it
  EndSession(ciAbort, cWsCloseAbnormal, '', nil, False);
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
  // the error is borrowed until here: the attempt sees it, then it is freed
  if AError is EHttpWebSocketProtocolError then
    EndSession(ciError, EHttpWebSocketProtocolError(AError).CloseCode, '',
      AError, False)
  else
    EndSession(ciError, cWsCloseAbnormal, '', AError, False);
  if AOwned then
    AError.Free;
end;

procedure TWebSocketConnection.CallbackFailed(const AError: Exception);
begin
  MarkAborted;
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
  Stamp: Int64;
  Echoed, Local: Boolean;
  By: TCloseInitiator;
begin
  WsParseClosePayload(AFrame.Payload, Code, Reason);
  ReportIn(mkWsClose, Length(AFrame.Payload));
  FPeerCode := Code;
  FPeerReason := Reason;
  FStateLock.Enter;
  try
    FInputClosed := True;
    Local := FLocalClose;
  finally
    FStateLock.Leave;
  end;
  Echoed := False;
  Stamp := 0;
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
        Stamp := NowUs;
        Echoed := True;
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
  if Echoed then
    ReportOut(mkWsClose, Stamp, Length(Echo));
  Result := False;                    // the connection ends here
  // let the server finish and close TCP, then release the socket now: the
  // report below waits for demand, which may never come
  DrainUntilEof;
  CloseTransport;
  // the close handshake is complete: the attempt ends here, not when the
  // listener has asked for the notification, which may never come
  if Local then
    By := ciLocal
  else
    By := ciRemote;
  EndSession(By, Code, Reason, nil, False);
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
  Last, Ponged, Accepted: Boolean;
  Stamp: Int64;
begin
  Result := True;
  case AFrame.Opcode of
    cWsOpPing:
      begin
        ReportIn(mkWsPing, Length(AFrame.Payload));
        // the pong goes out before the callback so a slow listener cannot
        // delay it
        Ponged := False;
        Stamp := 0;
        FSendLock.Enter;
        try
          if not FOutputClosed then
          begin
            WriteFrame(cWsOpPong, True, AFrame.Payload);
            Stamp := NowUs;
            Ponged := True;
          end;
        finally
          FSendLock.Leave;
        end;
        if Ponged then
          ReportOut(mkWsPong, Stamp, Length(AFrame.Payload));
        Result := NotifyPing(AFrame.Payload);
      end;
    cWsOpPong:
      begin
        ReportIn(mkWsPong, Length(AFrame.Payload));
        Result := NotifyPong(AFrame.Payload);
      end;
    cWsOpClose:
      Result := HandleClose(AFrame);
  else
    Accepted := FAssembler.Accept(AFrame, Kind, Data, Last);
    // a message is reported once, when its last frame arrives, with the
    // stamp of the read that completed it and before the listener has asked
    // for it, so the attempt sees it at the wire
    InterlockedExchangeAdd64(FBytesIn, Length(AFrame.Payload));
    Inc(FInMsgBytes, Length(AFrame.Payload));
    if AFrame.Fin then
    begin
      if Kind = wkText then
        ReportIn(mkWsText, Integer(FInMsgBytes))
      else
        ReportIn(mkWsBinary, Integer(FInMsgBytes));
      FInMsgBytes := 0;
    end;
    if Accepted then
    begin
      if Kind = wkText then
        Result := NotifyText(Data, Last)
      else
        Result := NotifyBytes(Data, Last);
    end;
  end;
end;

procedure TWebSocketConnection.SendCloseQuiet(const ACode: Integer);
var
  Stamp: Int64;
  Sent: Boolean;
begin
  Sent := False;
  Stamp := 0;
  FSendLock.Enter;
  try
    if not FOutputClosed then
    begin
      try
        WriteFrame(cWsOpClose, True, WsBuildClosePayload(ACode, ''));
        Stamp := NowUs;
        Sent := True;
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
  if Sent then
    ReportOut(mkWsClose, Stamp, 2);
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
  Failure: Exception;
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
          // every frame this feed completes was completed by this read
          FStampUs := FReader.LastReadUs;
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
    // a session that ended without any path above reporting it (a write that
    // failed on a caller's thread) ends here with that failure
    if InterlockedCompareExchange(FEnded, 0, 0) = 0 then
    begin
      Failure := nil;
      try
        if FFailText <> '' then
          Failure := EHttpConnectionError.Create(FFailText)
        else
          Failure := EHttpConnectionError.Create(
            'the WebSocket ended without a close');
        EndSession(ciError, cWsCloseAbnormal, '', Failure, False);
      finally
        Failure.Free;
      end;
    end;
    ReleaseResources;
  end;
end;

{ opening handshake }

function OpenWebSocket(const AFactory: IHttp1SocketFactory;
  const ARequest: IWebSocketRequest; const AProxy: IProxy;
  const ADefaultConnectTimeoutMs: Integer;
  const AMask: TMaskKeySource; const AAttempt: IWebSocketAttempt): IWebSocket;
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
  if AAttempt <> nil then
    Req := WsBuildHandshake(Target, Authority, Key, ARequest.Subprotocols,
      AAttempt.HandshakeHeaders)
  else
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
    if AAttempt <> nil then
      AAttempt.HandshakeWritten;
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
      Supports(Sock, TTlsSocket, TlsObj), AAttempt);
    Reader := nil;                    // owned by the connection now
  except
    Sock.Close;
    Reader.Free;
    raise;
  end;
  Result := Conn;
  // the headers are reported before the reader thread exists, so no message
  // or end can precede them
  if AAttempt <> nil then
    AAttempt.HandshakeAccepted(Status, Fields, Chosen);
  Conn.Start;
end;

end.
