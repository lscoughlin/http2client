/// WebSocket (RFC 6455) protocol pieces with no I/O: the frame codec, message
/// assembly with incremental UTF-8 validation, the opening handshake, and the
/// public interfaces (doc/design/websocket.md).
// - depends on the RTL and Http2.Errors only, like Http2.Proxy
unit Http2.WebSocket;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$interfaces com}

interface

uses
  SysUtils, sha1, base64, Http2.Errors, Http2.IdentityHandle;

const
  /// frame opcodes (RFC 6455 section 5.2)
  cWsOpContinuation = $0;
  cWsOpText         = $1;
  cWsOpBinary       = $2;
  cWsOpClose        = $8;
  cWsOpPing         = $9;
  cWsOpPong         = $A;

  /// close status codes the client sends or reports
  cWsCloseNormal        = 1000;
  cWsCloseGoingAway     = 1001;
  cWsCloseProtocolError = 1002;
  cWsCloseUnsupported   = 1003;
  cWsCloseNoStatus      = 1005;   // never on the wire
  cWsCloseAbnormal      = 1006;   // never on the wire
  cWsCloseBadData       = 1007;
  cWsCloseTooBig        = 1009;

  cWsGuid = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
  cWsMaxControlPayload = 125;
  /// a frame header declaring more than this is refused before allocation
  cWsMaxFrameBytes = 64 * 1024 * 1024;
  cWsDefaultMaxMessageBytes = 16 * 1024 * 1024;
  cWsDefaultCloseTimeoutMs = 5000;

type
  TWsMaskKey = array[0..3] of Byte;

  /// source of the 32-bit masking key for one client frame; production uses a
  /// cryptographically secure source (RFC 6455 section 10.3)
  TMaskKeySource = function: Cardinal;

  TWsFrame = record
    Fin: Boolean;
    Opcode: Byte;
    Payload: TBytes;
  end;

  TWsHeaderField = record
    Name: string;
    Value: string;
  end;

  TWsDataKind = (wkText, wkBinary);

{ masking }

/// XOR ABuffer[0..ACount-1] with the key, starting at key index APhase mod 4;
/// the same call masks and unmasks
procedure WsApplyMask(const AKey: TWsMaskKey; var ABuffer; const ACount: Integer;
  const APhase: Integer = 0);

function WsMaskKeyFromCardinal(const AValue: Cardinal): TWsMaskKey;

{ frames }

/// encode one frame; a masked frame carries AKey and a masked payload copy
function WsEncodeFrame(const AOpcode: Byte; const AFin: Boolean;
  const APayload: TBytes; const AMasked: Boolean;
  const AKey: TWsMaskKey): TBytes;

type
  /// incremental frame parser.  Feed any chunking; Next yields whole frames.
  // - client side (RequireMasked False): a server frame with the MASK bit
  //   set is a protocol error
  // - server side (RequireMasked True): the client frame must be masked and
  //   the payload is returned unmasked (used by test servers)
  // - every violation raises EHttpWebSocketProtocolError carrying the close
  //   code the peer should be answered with (1002, or 1009 for a frame
  //   declaring more than MaxFrameBytes)
  TWebSocketFrameParser = class
  private
    FBuf: TBytes;
    FPos: Integer;
    FEnd: Integer;
    FMaxFrameBytes: Int64;
    FRequireMasked: Boolean;
  public
    constructor Create;
    procedure Feed(const AData; const ACount: Integer);
    /// False until a whole frame is buffered
    function Next(out AFrame: TWsFrame): Boolean;
    function Buffered: Integer;
    property MaxFrameBytes: Int64 read FMaxFrameBytes write FMaxFrameBytes;
    property RequireMasked: Boolean read FRequireMasked write FRequireMasked;
  end;

{ UTF-8 and close payloads }

/// validate UTF-8 (RFC 3629: no overlongs, no surrogates, nothing above
/// U+10FFFF).  False when the bytes can never be valid.  When the buffer ends
/// inside a sequence that is still valid so far, True is returned and ASafeLen
/// is the length of the complete prefix; otherwise ASafeLen = ACount.
function WsUtf8Check(const ABuffer: PByte; const ACount: Integer;
  out ASafeLen: Integer): Boolean;

/// True for a status code a peer may send on the wire
function WsIsWireCloseCode(const ACode: Integer): Boolean;

/// split a close payload into code and reason.  An empty payload is code 1005.
/// Raises EHttpWebSocketProtocolError (1002 for a one-octet payload or a bad
/// code, 1007 for a reason that is not UTF-8).
procedure WsParseClosePayload(const APayload: TBytes; out ACode: Integer;
  out AReason: string);

function WsBuildClosePayload(const ACode: Integer;
  const AReason: string): TBytes;

type
  /// turns data frames into per-fragment deliveries; enforces fragmentation
  /// order, the message size limit and UTF-8 validity of text
  TWebSocketMessageAssembler = class
  private
    FInMessage: Boolean;
    FKind: TWsDataKind;
    FTotal: Int64;
    FMax: Int64;
    FCarry: TBytes;
  public
    constructor Create(const AMaxMessageBytes: Int64);
    /// False when the frame yields nothing to deliver yet (a text fragment
    /// that ends inside a character and is not the last)
    function Accept(const AFrame: TWsFrame; out AKind: TWsDataKind;
      out AData: TBytes; out ALast: Boolean): Boolean;
  end;

{ handshake }

/// split a ws/wss (or http/https) URL.  ATarget is path and query ('/' when
/// empty); AAuthority is the Host header value.  Raises EHttpWebSocketError.
procedure WsParseUrl(const AUrl: string; out ASecure: Boolean;
  out AHost: string; out APort: Word; out ATarget, AAuthority: string);

function WsIsHttpToken(const AValue: string): Boolean;
function WsIsRestrictedHeader(const AName: string): Boolean;

function WsComputeAccept(const AKey: string): string;
/// base64 of 16 random octets
function WsNewKey(const ASource: TMaskKeySource): string;

function WsBuildHandshake(const ATarget, AAuthority, AKey: string;
  const ASubprotocols: TArray<string>;
  const AHeaders: TArray<TWsHeaderField>): TBytes;

/// check a handshake response.  Returns '' when it is acceptable (AChosen is
/// the selected subprotocol or ''), else the reason it is not.
function WsCheckResponse(const AStatus: Integer;
  const AFields: TArray<TWsHeaderField>; const AKey: string;
  const AOffered: TArray<string>; out AChosen: string): string;

{ public interfaces }

type
  IWebSocket = interface;

  /// receives what the server sends.  Every callback runs on the WebSocket's
  /// reader thread, one at a time, in wire order.
  IWebSocketListener = interface
    ['{5E0A7C11-3B2D-4F6A-9C41-8D7E1B2A0001}']
    procedure OnOpen(const ASocket: IWebSocket);
    /// a text fragment (the whole message when ALast and it is the first)
    procedure OnText(const ASocket: IWebSocket; const AText: string;
      const ALast: Boolean);
    procedure OnBytes(const ASocket: IWebSocket; const AData: TBytes;
      const ALast: Boolean);
    procedure OnPing(const ASocket: IWebSocket; const AData: TBytes);
    procedure OnPong(const ASocket: IWebSocket; const AData: TBytes);
    /// the server's close frame arrived (once)
    procedure OnClose(const ASocket: IWebSocket; const AStatusCode: Integer;
      const AReason: string);
    /// the connection failed after the handshake; AError is freed on return
    procedure OnError(const ASocket: IWebSocket; const AError: Exception);
  end;

  IWebSocket = interface
    ['{5E0A7C11-3B2D-4F6A-9C41-8D7E1B2A0002}']
    /// close the connection at once, without a close frame
    procedure Abort;
    /// allow AN more notifications to be delivered
    procedure Request(const AN: Integer);
    procedure SendPing(const AData: TBytes);
    procedure SendPong(const AData: TBytes);
    procedure SendBinary(const AData: TBytes; const ALast: Boolean = True);
    procedure SendText(const AText: string; const ALast: Boolean = True);
    /// begin the closing handshake
    procedure Close(const AStatusCode: Integer = cWsCloseNormal;
      const AReason: string = '');
    function GetInputClosed: Boolean;
    function GetOutputClosed: Boolean;
    function GetSubprotocol: string;
    function GetUrl: string;
    property InputClosed: Boolean read GetInputClosed;
    property OutputClosed: Boolean read GetOutputClosed;
    property Subprotocol: string read GetSubprotocol;
    property Url: string read GetUrl;
  end;

  /// an immutable request to open a WebSocket; every WithX returns a new one
  IWebSocketRequest = interface
    ['{5E0A7C11-3B2D-4F6A-9C41-8D7E1B2A0003}']
    function WithConnectTimeoutMs(const AMs: Integer): IWebSocketRequest;
    /// raises EHttpWebSocketError for a header the handshake owns
    function WithHeader(const AName, AValue: string): IWebSocketRequest;
    function WithSubprotocol(const AName: string): IWebSocketRequest;
    function WithSubprotocols(const ANames: TArray<string>): IWebSocketRequest;
    function WithCloseTimeoutMs(const AMs: Integer): IWebSocketRequest;
    function WithMaxMessageBytes(const ABytes: Int64): IWebSocketRequest;
    function WithPingIntervalMs(const AMs: Integer): IWebSocketRequest;
    /// request one more notification after each delivery
    function WithAutoRequest(const AEnable: Boolean = True): IWebSocketRequest;
    /// attach an opaque object that the request observer receives as
    /// THttpAttempt.Context (a parent span, a tenant); nil clears it
    function WithContext(const AContext: IInterface): IWebSocketRequest;
    /// present AIdentity to the origin on the wss connection, ahead of the
    /// client's selector and fixed identity (doc/design/mtls.md "Per-request
    /// identity"); never to a proxy.  Send raises EHttpTlsConfigError before
    /// dialling when it has expired.  nil clears it; ws ignores it
    function WithClientIdentity(const AIdentity: IClientIdentityHandle): IWebSocketRequest;
    function GetClientIdentity: IClientIdentityHandle;
    function GetUrl: string;
    function GetListener: IWebSocketListener;
    function GetHeaders: TArray<TWsHeaderField>;
    function GetSubprotocols: TArray<string>;
    function GetConnectTimeoutMs: Integer;
    function GetCloseTimeoutMs: Integer;
    function GetMaxMessageBytes: Int64;
    function GetPingIntervalMs: Integer;
    function GetAutoRequest: Boolean;
    function GetContext: IInterface;
    property ClientIdentity: IClientIdentityHandle read GetClientIdentity;
    property Url: string read GetUrl;
    property Listener: IWebSocketListener read GetListener;
    property Headers: TArray<TWsHeaderField> read GetHeaders;
    property Subprotocols: TArray<string> read GetSubprotocols;
    property ConnectTimeoutMs: Integer read GetConnectTimeoutMs;
    property CloseTimeoutMs: Integer read GetCloseTimeoutMs;
    property MaxMessageBytes: Int64 read GetMaxMessageBytes;
    property PingIntervalMs: Integer read GetPingIntervalMs;
    property AutoRequest: Boolean read GetAutoRequest;
    property Context: IInterface read GetContext;
  end;

  /// base class with empty callbacks; descend and override what is needed
  TWebSocketListener = class(TInterfacedObject, IWebSocketListener)
  public
    procedure OnOpen(const ASocket: IWebSocket); virtual;
    procedure OnText(const ASocket: IWebSocket; const AText: string;
      const ALast: Boolean); virtual;
    procedure OnBytes(const ASocket: IWebSocket; const AData: TBytes;
      const ALast: Boolean); virtual;
    procedure OnPing(const ASocket: IWebSocket; const AData: TBytes); virtual;
    procedure OnPong(const ASocket: IWebSocket; const AData: TBytes); virtual;
    procedure OnClose(const ASocket: IWebSocket; const AStatusCode: Integer;
      const AReason: string); virtual;
    procedure OnError(const ASocket: IWebSocket;
      const AError: Exception); virtual;
  end;

  TWebSocketRequest = class(TInterfacedObject, IWebSocketRequest)
  private
    FUrl: string;
    FListener: IWebSocketListener;
    FHeaders: TArray<TWsHeaderField>;
    FSubprotocols: TArray<string>;
    FConnectTimeoutMs: Integer;
    FCloseTimeoutMs: Integer;
    FMaxMessageBytes: Int64;
    FPingIntervalMs: Integer;
    FAutoRequest: Boolean;
    FContext: IInterface;
    FIdentity: IClientIdentityHandle;
    function Clone: TWebSocketRequest;
  public
    /// AUrl is ws, wss, http or https; AListener is required
    constructor Create(const AUrl: string; const AListener: IWebSocketListener);
    function WithConnectTimeoutMs(const AMs: Integer): IWebSocketRequest;
    function WithHeader(const AName, AValue: string): IWebSocketRequest;
    function WithSubprotocol(const AName: string): IWebSocketRequest;
    function WithSubprotocols(const ANames: TArray<string>): IWebSocketRequest;
    function WithCloseTimeoutMs(const AMs: Integer): IWebSocketRequest;
    function WithMaxMessageBytes(const ABytes: Int64): IWebSocketRequest;
    function WithPingIntervalMs(const AMs: Integer): IWebSocketRequest;
    function WithAutoRequest(const AEnable: Boolean = True): IWebSocketRequest;
    function WithContext(const AContext: IInterface): IWebSocketRequest;
    /// present AIdentity to the origin on the wss connection, ahead of the
    /// client's selector and fixed identity (doc/design/mtls.md "Per-request
    /// identity"); never to a proxy.  Send raises EHttpTlsConfigError before
    /// dialling when it has expired.  nil clears it; ws ignores it
    function WithClientIdentity(const AIdentity: IClientIdentityHandle): IWebSocketRequest;
    function GetClientIdentity: IClientIdentityHandle;
    function GetUrl: string;
    function GetListener: IWebSocketListener;
    function GetHeaders: TArray<TWsHeaderField>;
    function GetSubprotocols: TArray<string>;
    function GetConnectTimeoutMs: Integer;
    function GetCloseTimeoutMs: Integer;
    function GetMaxMessageBytes: Int64;
    function GetPingIntervalMs: Integer;
    function GetAutoRequest: Boolean;
    function GetContext: IInterface;
  end;

implementation

{ masking }

function WsMaskKeyFromCardinal(const AValue: Cardinal): TWsMaskKey;
begin
  Result[0] := Byte(AValue shr 24);
  Result[1] := Byte(AValue shr 16);
  Result[2] := Byte(AValue shr 8);
  Result[3] := Byte(AValue);
end;

procedure WsApplyMask(const AKey: TWsMaskKey; var ABuffer; const ACount: Integer;
  const APhase: Integer);
var
  P: PByte;
  K: TWsMaskKey;
  Word32, Mask32: Cardinal;
  I, Ph: Integer;
begin
  if ACount <= 0 then
    Exit;
  Ph := APhase and 3;
  // rotate the key so that K[0] lines up with the first byte of the buffer
  for I := 0 to 3 do
    K[I] := AKey[(I + Ph) and 3];
  Move(K[0], Mask32, 4);
  P := @ABuffer;
  I := 0;
  while I + 4 <= ACount do
  begin
    Move(P^, Word32, 4);
    Word32 := Word32 xor Mask32;
    Move(Word32, P^, 4);
    Inc(P, 4);
    Inc(I, 4);
  end;
  Ph := 0;
  while I < ACount do
  begin
    P^ := P^ xor K[Ph];
    Inc(P);
    Inc(I);
    Inc(Ph);
  end;
end;

{ frames }

function WsEncodeFrame(const AOpcode: Byte; const AFin: Boolean;
  const APayload: TBytes; const AMasked: Boolean;
  const AKey: TWsMaskKey): TBytes;
var
  Len, HeadLen, P: Integer;
  B1: Byte;
begin
  Len := Length(APayload);
  HeadLen := 2;
  if Len > 65535 then
    Inc(HeadLen, 8)
  else if Len > 125 then
    Inc(HeadLen, 2);
  if AMasked then
    Inc(HeadLen, 4);
  SetLength(Result, HeadLen + Len);
  Result[0] := AOpcode and $0F;
  if AFin then
    Result[0] := Result[0] or $80;
  if AMasked then
    B1 := $80
  else
    B1 := 0;
  P := 2;
  if Len <= 125 then
    Result[1] := B1 or Byte(Len)
  else if Len <= 65535 then
  begin
    Result[1] := B1 or 126;
    Result[2] := Byte(Len shr 8);
    Result[3] := Byte(Len);
    P := 4;
  end
  else
  begin
    Result[1] := B1 or 127;
    Result[2] := 0; Result[3] := 0; Result[4] := 0; Result[5] := 0;
    Result[6] := Byte(Len shr 24);
    Result[7] := Byte(Len shr 16);
    Result[8] := Byte(Len shr 8);
    Result[9] := Byte(Len);
    P := 10;
  end;
  if AMasked then
  begin
    Move(AKey[0], Result[P], 4);
    Inc(P, 4);
  end;
  if Len > 0 then
  begin
    Move(APayload[0], Result[P], Len);
    if AMasked then
      WsApplyMask(AKey, Result[P], Len, 0);
  end;
end;

{ TWebSocketFrameParser }

constructor TWebSocketFrameParser.Create;
begin
  inherited Create;
  FMaxFrameBytes := cWsMaxFrameBytes;
end;

procedure TWebSocketFrameParser.Feed(const AData; const ACount: Integer);
begin
  if ACount <= 0 then
    Exit;
  if FPos > 0 then
  begin
    if FEnd > FPos then
      Move(FBuf[FPos], FBuf[0], FEnd - FPos);
    Dec(FEnd, FPos);
    FPos := 0;
  end;
  if FEnd + ACount > Length(FBuf) then
    SetLength(FBuf, (FEnd + ACount) * 2);
  Move(AData, FBuf[FEnd], ACount);
  Inc(FEnd, ACount);
end;

function TWebSocketFrameParser.Buffered: Integer;
begin
  Result := FEnd - FPos;
end;

function TWebSocketFrameParser.Next(out AFrame: TWsFrame): Boolean;
var
  Avail, HeadLen, Idx: Integer;
  B0, B1: Byte;
  Len7: Integer;
  PayLen: Int64;
  Masked, IsControl: Boolean;
  Key: TWsMaskKey;
  I: Integer;
begin
  Result := False;
  Avail := FEnd - FPos;
  if Avail < 2 then
    Exit;
  B0 := FBuf[FPos];
  B1 := FBuf[FPos + 1];
  if (B0 and $70) <> 0 then
    raise EHttpWebSocketProtocolError.Create(
      'reserved bits set with no extension negotiated', cWsCloseProtocolError);
  IsControl := (B0 and $08) <> 0;
  case B0 and $0F of
    cWsOpContinuation, cWsOpText, cWsOpBinary, cWsOpClose, cWsOpPing, cWsOpPong: ;
  else
    raise EHttpWebSocketProtocolError.CreateFmt(
      'reserved opcode %d', [B0 and $0F], cWsCloseProtocolError);
  end;
  Masked := (B1 and $80) <> 0;
  if Masked and (not FRequireMasked) then
    raise EHttpWebSocketProtocolError.Create(
      'server frame is masked', cWsCloseProtocolError);
  if (not Masked) and FRequireMasked then
    raise EHttpWebSocketProtocolError.Create(
      'client frame is not masked', cWsCloseProtocolError);
  Len7 := B1 and $7F;
  Idx := 2;
  if Len7 <= 125 then
    PayLen := Len7
  else if Len7 = 126 then
  begin
    if Avail < 4 then
      Exit;
    PayLen := (Int64(FBuf[FPos + 2]) shl 8) or FBuf[FPos + 3];
    if PayLen < 126 then
      raise EHttpWebSocketProtocolError.Create(
        'payload length not in its shortest form', cWsCloseProtocolError);
    Idx := 4;
  end
  else
  begin
    if Avail < 10 then
      Exit;
    if (FBuf[FPos + 2] and $80) <> 0 then
      raise EHttpWebSocketProtocolError.Create(
        'payload length has its top bit set', cWsCloseProtocolError);
    PayLen := 0;
    for I := 2 to 9 do
      PayLen := (PayLen shl 8) or FBuf[FPos + I];
    if PayLen < 65536 then
      raise EHttpWebSocketProtocolError.Create(
        'payload length not in its shortest form', cWsCloseProtocolError);
    Idx := 10;
  end;
  if IsControl then
  begin
    if (B0 and $80) = 0 then
      raise EHttpWebSocketProtocolError.Create(
        'fragmented control frame', cWsCloseProtocolError);
    if PayLen > cWsMaxControlPayload then
      raise EHttpWebSocketProtocolError.Create(
        'control frame payload over 125 octets', cWsCloseProtocolError);
  end;
  if PayLen > FMaxFrameBytes then
    raise EHttpWebSocketProtocolError.CreateFmt(
      'frame of %d octets exceeds the limit', [PayLen], cWsCloseTooBig);
  HeadLen := Idx;
  if Masked then
    Inc(HeadLen, 4);
  if Avail < HeadLen + PayLen then
    Exit;
  AFrame.Fin := (B0 and $80) <> 0;
  AFrame.Opcode := B0 and $0F;
  SetLength(AFrame.Payload, Integer(PayLen));
  if PayLen > 0 then
    Move(FBuf[FPos + HeadLen], AFrame.Payload[0], Integer(PayLen));
  if Masked then
  begin
    Move(FBuf[FPos + Idx], Key[0], 4);
    if PayLen > 0 then
      WsApplyMask(Key, AFrame.Payload[0], Integer(PayLen), 0);
  end;
  Inc(FPos, HeadLen + Integer(PayLen));
  Result := True;
end;

{ UTF-8 }

function WsUtf8Check(const ABuffer: PByte; const ACount: Integer;
  out ASafeLen: Integer): Boolean;
var
  I, K, Need: Integer;
  B, Lo, Hi, C: Byte;
begin
  ASafeLen := ACount;
  I := 0;
  while I < ACount do
  begin
    B := ABuffer[I];
    if B < $80 then
    begin
      Inc(I);
      Continue;
    end;
    Lo := $80;
    Hi := $BF;
    if (B >= $C2) and (B <= $DF) then
      Need := 1
    else if (B >= $E0) and (B <= $EF) then
    begin
      Need := 2;
      if B = $E0 then Lo := $A0;
      if B = $ED then Hi := $9F;
    end
    else if (B >= $F0) and (B <= $F4) then
    begin
      Need := 3;
      if B = $F0 then Lo := $90;
      if B = $F4 then Hi := $8F;
    end
    else
      Exit(False);
    for K := 1 to Need do
    begin
      if I + K >= ACount then
      begin
        ASafeLen := I;          // valid so far, the sequence is unfinished
        Exit(True);
      end;
      C := ABuffer[I + K];
      if (C < Lo) or (C > Hi) then
        Exit(False);
      Lo := $80;                // only the first continuation byte is special
      Hi := $BF;
    end;
    Inc(I, Need + 1);
  end;
  Result := True;
end;

function WsIsWireCloseCode(const ACode: Integer): Boolean;
begin
  Result := ((ACode >= 1000) and (ACode <= 1003)) or
    ((ACode >= 1007) and (ACode <= 1011)) or
    ((ACode >= 3000) and (ACode <= 4999));
end;

procedure WsParseClosePayload(const APayload: TBytes; out ACode: Integer;
  out AReason: string);
var
  Safe: Integer;
begin
  AReason := '';
  if Length(APayload) = 0 then
  begin
    ACode := cWsCloseNoStatus;
    Exit;
  end;
  if Length(APayload) = 1 then
    raise EHttpWebSocketProtocolError.Create(
      'close payload of one octet', cWsCloseProtocolError);
  ACode := (Integer(APayload[0]) shl 8) or APayload[1];
  if not WsIsWireCloseCode(ACode) then
    raise EHttpWebSocketProtocolError.CreateFmt(
      'invalid close code %d', [ACode], cWsCloseProtocolError);
  if Length(APayload) > 2 then
  begin
    if (not WsUtf8Check(@APayload[2], Length(APayload) - 2, Safe)) or
       (Safe <> Length(APayload) - 2) then
      raise EHttpWebSocketProtocolError.Create(
        'close reason is not UTF-8', cWsCloseBadData);
    SetLength(AReason, Length(APayload) - 2);
    Move(APayload[2], AReason[1], Length(APayload) - 2);
  end;
end;

function WsBuildClosePayload(const ACode: Integer;
  const AReason: string): TBytes;
begin
  SetLength(Result, 2 + Length(AReason));
  Result[0] := Byte(ACode shr 8);
  Result[1] := Byte(ACode);
  if AReason <> '' then
    Move(AReason[1], Result[2], Length(AReason));
end;

{ TWebSocketMessageAssembler }

constructor TWebSocketMessageAssembler.Create(const AMaxMessageBytes: Int64);
begin
  inherited Create;
  FMax := AMaxMessageBytes;
end;

function TWebSocketMessageAssembler.Accept(const AFrame: TWsFrame;
  out AKind: TWsDataKind; out AData: TBytes; out ALast: Boolean): Boolean;
var
  Buf: TBytes;
  Safe, N: Integer;
begin
  if AFrame.Opcode = cWsOpContinuation then
  begin
    if not FInMessage then
      raise EHttpWebSocketProtocolError.Create(
        'continuation frame with no message open', cWsCloseProtocolError);
  end
  else
  begin
    if FInMessage then
      raise EHttpWebSocketProtocolError.Create(
        'new data frame inside an open message', cWsCloseProtocolError);
    FInMessage := True;
    FTotal := 0;
    SetLength(FCarry, 0);
    if AFrame.Opcode = cWsOpText then
      FKind := wkText
    else
      FKind := wkBinary;
  end;
  AKind := FKind;
  ALast := AFrame.Fin;
  Inc(FTotal, Length(AFrame.Payload));
  if (FMax > 0) and (FTotal > FMax) then
    raise EHttpWebSocketProtocolError.CreateFmt(
      'message exceeds the limit of %d octets', [FMax], cWsCloseTooBig);
  if FKind = wkBinary then
  begin
    AData := AFrame.Payload;
    if AFrame.Fin then
      FInMessage := False;
    Exit(True);
  end;
  // text: validate carry + payload; hold back an unfinished character
  N := Length(FCarry) + Length(AFrame.Payload);
  SetLength(Buf, N);
  if Length(FCarry) > 0 then
    Move(FCarry[0], Buf[0], Length(FCarry));
  if Length(AFrame.Payload) > 0 then
    Move(AFrame.Payload[0], Buf[Length(FCarry)], Length(AFrame.Payload));
  if N = 0 then
    Safe := 0
  else if not WsUtf8Check(@Buf[0], N, Safe) then
    raise EHttpWebSocketProtocolError.Create(
      'text message is not valid UTF-8', cWsCloseBadData);
  if AFrame.Fin then
  begin
    if Safe <> N then
      raise EHttpWebSocketProtocolError.Create(
        'text message ends inside a character', cWsCloseBadData);
    FInMessage := False;
  end;
  SetLength(FCarry, N - Safe);
  if N - Safe > 0 then
    Move(Buf[Safe], FCarry[0], N - Safe);
  SetLength(AData, Safe);
  if Safe > 0 then
    Move(Buf[0], AData[0], Safe);
  Result := (Safe > 0) or AFrame.Fin;
end;

{ handshake }

function WsIsHttpToken(const AValue: string): Boolean;
const
  Separators = '()<>@,;:\"/[]?={} ' + #9;
var
  I: Integer;
begin
  Result := AValue <> '';
  for I := 1 to Length(AValue) do
    if (Ord(AValue[I]) <= 32) or (Ord(AValue[I]) >= 127) or
       (Pos(AValue[I], Separators) > 0) then
      Exit(False);
end;

function WsIsRestrictedHeader(const AName: string): Boolean;
var
  L: string;
begin
  L := LowerCase(Trim(AName));
  Result := (L = 'host') or (L = 'upgrade') or (L = 'connection') or
    (L = 'content-length') or (L = 'transfer-encoding') or (L = 'expect') or
    (Copy(L, 1, 14) = 'sec-websocket-');
end;

procedure WsParseUrl(const AUrl: string; out ASecure: Boolean;
  out AHost: string; out APort: Word; out ATarget, AAuthority: string);
var
  Scheme, Rest, Auth, HostPart, PortPart: string;
  P, Q, PortNum: Integer;
begin
  P := Pos('://', AUrl);
  if P < 2 then
    raise EHttpWebSocketError.CreateFmt('not an absolute URL: %s', [AUrl]);
  Scheme := LowerCase(Copy(AUrl, 1, P - 1));
  if (Scheme = 'ws') or (Scheme = 'http') then
    ASecure := False
  else if (Scheme = 'wss') or (Scheme = 'https') then
    ASecure := True
  else
    raise EHttpWebSocketError.CreateFmt(
      'unsupported scheme "%s" (ws, wss, http or https expected)', [Scheme]);
  Rest := Copy(AUrl, P + 3, MaxInt);
  if Pos('#', Rest) > 0 then
    raise EHttpWebSocketError.Create('a WebSocket URL has no fragment');
  Q := 0;
  for P := 1 to Length(Rest) do
    if Rest[P] in ['/', '?'] then
    begin
      Q := P;
      Break;
    end;
  if Q = 0 then
  begin
    Auth := Rest;
    ATarget := '/';
  end
  else
  begin
    Auth := Copy(Rest, 1, Q - 1);
    ATarget := Copy(Rest, Q, MaxInt);
    if ATarget[1] = '?' then
      ATarget := '/' + ATarget;
  end;
  P := Pos('@', Auth);
  if P > 0 then
    Auth := Copy(Auth, P + 1, MaxInt);       // userinfo is not sent
  PortPart := '';
  if (Auth <> '') and (Auth[1] = '[') then
  begin
    Q := Pos(']', Auth);
    if Q = 0 then
      raise EHttpWebSocketError.CreateFmt('bad IPv6 literal in %s', [AUrl]);
    HostPart := Copy(Auth, 2, Q - 2);
    if Copy(Auth, Q + 1, 1) = ':' then
      PortPart := Copy(Auth, Q + 2, MaxInt)
    else if Q < Length(Auth) then
      raise EHttpWebSocketError.CreateFmt('bad authority in %s', [AUrl]);
  end
  else
  begin
    Q := Pos(':', Auth);
    if Q > 0 then
    begin
      HostPart := Copy(Auth, 1, Q - 1);
      PortPart := Copy(Auth, Q + 1, MaxInt);
    end
    else
      HostPart := Auth;
  end;
  if HostPart = '' then
    raise EHttpWebSocketError.CreateFmt('no host in %s', [AUrl]);
  if PortPart = '' then
  begin
    if ASecure then PortNum := 443 else PortNum := 80;
  end
  else
  begin
    PortNum := StrToIntDef(PortPart, -1);
    if (PortNum < 1) or (PortNum > 65535) then
      raise EHttpWebSocketError.CreateFmt('bad port in %s', [AUrl]);
  end;
  AHost := HostPart;
  APort := Word(PortNum);
  if Pos(':', HostPart) > 0 then
    AAuthority := '[' + HostPart + ']'
  else
    AAuthority := HostPart;
  if (PortPart <> '') and not ((ASecure and (PortNum = 443)) or
     ((not ASecure) and (PortNum = 80))) then
    AAuthority := AAuthority + ':' + IntToStr(PortNum);
end;

function WsComputeAccept(const AKey: string): string;
var
  D: TSHA1Digest;
  S: string;
begin
  D := SHA1String(AKey + cWsGuid);
  SetLength(S, SizeOf(D));
  Move(D[0], S[1], SizeOf(D));
  Result := EncodeStringBase64(S);
end;

function WsNewKey(const ASource: TMaskKeySource): string;
var
  Raw: string;
  V: Cardinal;
  I: Integer;
begin
  SetLength(Raw, 16);
  for I := 0 to 3 do
  begin
    V := ASource();
    Move(V, Raw[1 + I * 4], 4);
  end;
  Result := EncodeStringBase64(Raw);
end;

function WsBuildHandshake(const ATarget, AAuthority, AKey: string;
  const ASubprotocols: TArray<string>;
  const AHeaders: TArray<TWsHeaderField>): TBytes;
var
  S: string;
  I: Integer;
begin
  S := 'GET ' + ATarget + ' HTTP/1.1'#13#10 +
    'Host: ' + AAuthority + #13#10 +
    'Upgrade: websocket'#13#10 +
    'Connection: Upgrade'#13#10 +
    'Sec-WebSocket-Key: ' + AKey + #13#10 +
    'Sec-WebSocket-Version: 13'#13#10;
  if Length(ASubprotocols) > 0 then
  begin
    S := S + 'Sec-WebSocket-Protocol: ';
    for I := 0 to High(ASubprotocols) do
    begin
      if I > 0 then
        S := S + ', ';
      S := S + ASubprotocols[I];
    end;
    S := S + #13#10;
  end;
  for I := 0 to High(AHeaders) do
    S := S + AHeaders[I].Name + ': ' + AHeaders[I].Value + #13#10;
  S := S + #13#10;
  SetLength(Result, Length(S));
  if S <> '' then
    Move(S[1], Result[0], Length(S));
end;

function FieldValues(const AFields: TArray<TWsHeaderField>;
  const AName: string): TArray<string>;
var
  I, N: Integer;
begin
  N := 0;
  SetLength(Result, Length(AFields));
  for I := 0 to High(AFields) do
    if SameText(AFields[I].Name, AName) then
    begin
      Result[N] := AFields[I].Value;
      Inc(N);
    end;
  SetLength(Result, N);
end;

function HasToken(const AValues: TArray<string>; const AToken: string): Boolean;
var
  I, P: Integer;
  V, Item: string;
begin
  Result := False;
  for I := 0 to High(AValues) do
  begin
    V := AValues[I];
    while V <> '' do
    begin
      P := Pos(',', V);
      if P = 0 then
      begin
        Item := V;
        V := '';
      end
      else
      begin
        Item := Copy(V, 1, P - 1);
        V := Copy(V, P + 1, MaxInt);
      end;
      if SameText(Trim(Item), AToken) then
        Exit(True);
    end;
  end;
end;

function WsCheckResponse(const AStatus: Integer;
  const AFields: TArray<TWsHeaderField>; const AKey: string;
  const AOffered: TArray<string>; out AChosen: string): string;
var
  Accept, Protos: TArray<string>;
  Items: TArray<string>;
  V, Item: string;
  P, I, N: Integer;
  Found: Boolean;
begin
  AChosen := '';
  if AStatus <> 101 then
    Exit(Format('server answered %d instead of 101', [AStatus]));
  if not HasToken(FieldValues(AFields, 'Upgrade'), 'websocket') then
    Exit('response has no "Upgrade: websocket"');
  if not HasToken(FieldValues(AFields, 'Connection'), 'upgrade') then
    Exit('response has no "Connection: Upgrade"');
  Accept := FieldValues(AFields, 'Sec-WebSocket-Accept');
  if (Length(Accept) <> 1) or (Trim(Accept[0]) <> WsComputeAccept(AKey)) then
    Exit('Sec-WebSocket-Accept does not match the key');
  if Length(FieldValues(AFields, 'Sec-WebSocket-Extensions')) > 0 then
    Exit('server selected an extension that was not offered');
  Protos := FieldValues(AFields, 'Sec-WebSocket-Protocol');
  if Length(Protos) = 0 then
    Exit('');
  // every value of every header line is one list item
  SetLength(Items, 0);
  for I := 0 to High(Protos) do
  begin
    V := Protos[I];
    while True do
    begin
      P := Pos(',', V);
      if P = 0 then
        Item := V
      else
        Item := Copy(V, 1, P - 1);
      N := Length(Items);
      SetLength(Items, N + 1);
      Items[N] := Trim(Item);
      if P = 0 then
        Break;
      V := Copy(V, P + 1, MaxInt);
    end;
  end;
  if Length(Items) <> 1 then
    Exit('server selected more than one subprotocol');
  Found := False;
  for I := 0 to High(AOffered) do
    if AOffered[I] = Items[0] then
      Found := True;
  if not Found then
    Exit(Format('server selected subprotocol "%s" that was not offered',
      [Items[0]]));
  AChosen := Items[0];
  Result := '';
end;

{ TWebSocketListener }

procedure TWebSocketListener.OnOpen(const ASocket: IWebSocket);
begin
end;

procedure TWebSocketListener.OnText(const ASocket: IWebSocket;
  const AText: string; const ALast: Boolean);
begin
end;

procedure TWebSocketListener.OnBytes(const ASocket: IWebSocket;
  const AData: TBytes; const ALast: Boolean);
begin
end;

procedure TWebSocketListener.OnPing(const ASocket: IWebSocket;
  const AData: TBytes);
begin
end;

procedure TWebSocketListener.OnPong(const ASocket: IWebSocket;
  const AData: TBytes);
begin
end;

procedure TWebSocketListener.OnClose(const ASocket: IWebSocket;
  const AStatusCode: Integer; const AReason: string);
begin
end;

procedure TWebSocketListener.OnError(const ASocket: IWebSocket;
  const AError: Exception);
begin
end;

{ TWebSocketRequest }

constructor TWebSocketRequest.Create(const AUrl: string;
  const AListener: IWebSocketListener);
var
  Secure: Boolean;
  Host, Target, Auth: string;
  Port: Word;
begin
  inherited Create;
  if AListener = nil then
    raise EHttpWebSocketError.Create('a WebSocket request needs a listener');
  WsParseUrl(AUrl, Secure, Host, Port, Target, Auth);   // validates
  FUrl := AUrl;
  FListener := AListener;
  FCloseTimeoutMs := cWsDefaultCloseTimeoutMs;
  FMaxMessageBytes := cWsDefaultMaxMessageBytes;
end;

function TWebSocketRequest.Clone: TWebSocketRequest;
begin
  Result := TWebSocketRequest.Create(FUrl, FListener);
  Result.FHeaders := Copy(FHeaders);
  Result.FSubprotocols := Copy(FSubprotocols);
  Result.FConnectTimeoutMs := FConnectTimeoutMs;
  Result.FCloseTimeoutMs := FCloseTimeoutMs;
  Result.FMaxMessageBytes := FMaxMessageBytes;
  Result.FPingIntervalMs := FPingIntervalMs;
  Result.FAutoRequest := FAutoRequest;
  Result.FContext := FContext;
  Result.FIdentity := FIdentity;
end;

function TWebSocketRequest.WithConnectTimeoutMs(
  const AMs: Integer): IWebSocketRequest;
var
  R: TWebSocketRequest;
begin
  if AMs < 0 then
    raise EHttpWebSocketError.Create('connect timeout cannot be negative');
  R := Clone;
  R.FConnectTimeoutMs := AMs;
  Result := R;
end;

function TWebSocketRequest.WithHeader(const AName,
  AValue: string): IWebSocketRequest;
var
  R: TWebSocketRequest;
  N: Integer;
begin
  if not WsIsHttpToken(AName) then
    raise EHttpWebSocketError.CreateFmt('"%s" is not a header name', [AName]);
  if WsIsRestrictedHeader(AName) then
    raise EHttpWebSocketError.CreateFmt(
      'header "%s" is set by the handshake and cannot be supplied', [AName]);
  if (Pos(#13, AValue) > 0) or (Pos(#10, AValue) > 0) then
    raise EHttpWebSocketError.Create('a header value cannot contain a line break');
  R := Clone;
  N := Length(R.FHeaders);
  SetLength(R.FHeaders, N + 1);
  R.FHeaders[N].Name := AName;
  R.FHeaders[N].Value := AValue;
  Result := R;
end;

function TWebSocketRequest.WithSubprotocol(
  const AName: string): IWebSocketRequest;
var
  R: TWebSocketRequest;
  N: Integer;
begin
  if not WsIsHttpToken(AName) then
    raise EHttpWebSocketError.CreateFmt(
      '"%s" is not a valid subprotocol name', [AName]);
  R := Clone;
  N := Length(R.FSubprotocols);
  SetLength(R.FSubprotocols, N + 1);
  R.FSubprotocols[N] := AName;
  Result := R;
end;

function TWebSocketRequest.WithSubprotocols(
  const ANames: TArray<string>): IWebSocketRequest;
var
  I: Integer;
begin
  Result := Self;
  for I := 0 to High(ANames) do
    Result := Result.WithSubprotocol(ANames[I]);
end;

function TWebSocketRequest.WithCloseTimeoutMs(
  const AMs: Integer): IWebSocketRequest;
var
  R: TWebSocketRequest;
begin
  if AMs < 0 then
    raise EHttpWebSocketError.Create('close timeout cannot be negative');
  R := Clone;
  R.FCloseTimeoutMs := AMs;
  Result := R;
end;

function TWebSocketRequest.WithMaxMessageBytes(
  const ABytes: Int64): IWebSocketRequest;
var
  R: TWebSocketRequest;
begin
  if ABytes < 0 then
    raise EHttpWebSocketError.Create('message limit cannot be negative');
  R := Clone;
  R.FMaxMessageBytes := ABytes;
  Result := R;
end;

function TWebSocketRequest.WithPingIntervalMs(
  const AMs: Integer): IWebSocketRequest;
var
  R: TWebSocketRequest;
begin
  if AMs < 0 then
    raise EHttpWebSocketError.Create('ping interval cannot be negative');
  R := Clone;
  R.FPingIntervalMs := AMs;
  Result := R;
end;

function TWebSocketRequest.WithAutoRequest(
  const AEnable: Boolean): IWebSocketRequest;
var
  R: TWebSocketRequest;
begin
  R := Clone;
  R.FAutoRequest := AEnable;
  Result := R;
end;

function TWebSocketRequest.WithContext(
  const AContext: IInterface): IWebSocketRequest;
var
  R: TWebSocketRequest;
begin
  R := Clone;
  R.FContext := AContext;
  Result := R;
end;

function TWebSocketRequest.WithClientIdentity(
  const AIdentity: IClientIdentityHandle): IWebSocketRequest;
var
  R: TWebSocketRequest;
begin
  R := Clone;
  R.FIdentity := AIdentity;
  Result := R;
end;

function TWebSocketRequest.GetClientIdentity: IClientIdentityHandle;
begin
  Result := FIdentity;
end;

function TWebSocketRequest.GetUrl: string;
begin
  Result := FUrl;
end;

function TWebSocketRequest.GetListener: IWebSocketListener;
begin
  Result := FListener;
end;

function TWebSocketRequest.GetHeaders: TArray<TWsHeaderField>;
begin
  Result := Copy(FHeaders);
end;

function TWebSocketRequest.GetSubprotocols: TArray<string>;
begin
  Result := Copy(FSubprotocols);
end;

function TWebSocketRequest.GetConnectTimeoutMs: Integer;
begin
  Result := FConnectTimeoutMs;
end;

function TWebSocketRequest.GetCloseTimeoutMs: Integer;
begin
  Result := FCloseTimeoutMs;
end;

function TWebSocketRequest.GetMaxMessageBytes: Int64;
begin
  Result := FMaxMessageBytes;
end;

function TWebSocketRequest.GetPingIntervalMs: Integer;
begin
  Result := FPingIntervalMs;
end;

function TWebSocketRequest.GetAutoRequest: Boolean;
begin
  Result := FAutoRequest;
end;

function TWebSocketRequest.GetContext: IInterface;
begin
  Result := FContext;
end;

end.
