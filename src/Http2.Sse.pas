/// Server-Sent Events: event-stream parser, source and reconnect loop
// - this unit is part of the http2client project (see doc/design/
//   server-sent-events.md).
// - SSE is a READER layer, not a transport mode: it consumes
//   IHttpResponse.Body and therefore works over HTTP/2 and over the HTTP/1.1
//   fallback without the transport knowing about it.
// - the parser is pure and incremental: bytes in, completed TSseEvent values
//   out. That is what makes it testable by slicing an input at every byte
//   boundary (doc/design/server-sent-events.md "Testing").
// - an SSE stream is idle BETWEEN events by design, so the body read must not
//   use the request header timeout. SseRequest attaches an explicit
//   body-read deadline of 0 ("wait indefinitely") through
//   THttpRequest.WithSseReadTimeout, and TSseSource rejects a response that
//   is not a 200 `text/event-stream`.
unit Http2.Sse;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, Generics.Collections,
  Http2.Errors, Http2.Headers, Http2.Stream, Http2.Messages, Http2.Client;

const
  /// the media type of an event stream (WHATWG / RFC 9110)
  cSseContentType = 'text/event-stream';
  /// the event type a dispatch uses when the stream sent no `event:` field
  cSseDefaultEventType = 'message';
  /// the reconnect delay used until a server sends `retry:` (ms). WHATWG
  /// leaves the value implementation-defined; this library uses 3000 ms.
  cSseDefaultRetryMs = 3000;
  /// reconnect attempts before EHttpTooManySseRetries (0 = retry forever)
  cSseDefaultMaxRetries = 10;
  /// the read chunk size a TSseSource pulls from the body stream
  cSseReadChunkSize = 8192;

type
  /// one dispatched event (WHATWG "Dispatch the event")
  TSseEvent = record
    /// the event type; 'message' when the stream sent no `event:` field
    EventType: string;
    /// the data payload, with the single trailing newline removed
    Data: string;
    /// the last-event-ID in force at dispatch time ('' when never set)
    Id: string;
    /// the `retry:` value in force at dispatch time, in ms (0 = none seen)
    RetryMs: Integer;
  end;

  /// parses a text/event-stream byte stream into TSseEvent values
  // - pure and incremental: Feed may be called with any chunking, including
  //   a chunk that splits a CRLF, a field name, a value, or a multi-byte
  //   UTF-8 sequence. State that survives across events is the last-event-ID
  //   and the retry delay; the data and event-type buffers are reset at each
  //   dispatch.
  TSseEventParser = class
  private
    FData: string;          // the data buffer (one '\n' appended per data: line)
    FEventType: string;     // the event-type buffer
    FLastEventId: string;   // survives dispatch (WHATWG "last event ID string")
    FRetryMs: Integer;
    FLine: string;          // the line being assembled (terminator not seen)
    FAtStart: Boolean;      // the BOM has not been inspected yet
    FSkipLf: Boolean;       // the last chunk ended on a CR that may pair with LF
    FPending: TBytes;       // held-back bytes (incomplete UTF-8 / partial BOM)
    procedure FeedText(const AText: string; const AEvents: TList<TSseEvent>);
    procedure HandleLine(const ALine: string;
      const AEvents: TList<TSseEvent>);
    procedure DispatchEvent(const AEvents: TList<TSseEvent>);
  public
    constructor Create;
    /// feed one chunk of raw bytes; AEvents receives completed events
    procedure Feed(const AChunk: TBytes;
      const AEvents: TList<TSseEvent>); overload;
    /// feed text (convenience; the caller is responsible for UTF-8 validity)
    procedure Feed(const AText: string;
      const AEvents: TList<TSseEvent>); overload;
    /// the last-event-ID in force after the last fed byte (survives dispatch)
    function LastEventId: string;
    /// the reconnection delay in force, in ms (0 = never set)
    function RetryMs: Integer;
    /// drop any partial line and buffered data (a stream boundary)
    procedure Reset;
  end;

  /// a source of events over one response body
  IHttpSseSource = interface
    ['{8B1C2D3E-4F50-4A61-9C72-00000000E001}']
    /// block until the next event is parsed, or the stream ends.
    /// True = AEvent is set; False = the stream ended cleanly.
    function ReadEvent(out AEvent: TSseEvent): Boolean;
    /// the last-event-ID in force ('' when none)
    function LastEventId: string;
    /// the server's last `retry:` value in ms (0 = none)
    function RetryMs: Integer;
    /// stop the source and release the lease (idempotent)
    procedure Close;
  end;

  /// reads an event stream from one already-acquired response
  // - validates the response (status 200, `text/event-stream`, a UTF-8 or
  //   absent charset, an identity or absent content coding) before yielding
  //   any event. The caller keeps ownership of the response.
  // - the BODY READ DEADLINE is not set here: it belongs to the lease and is
  //   chosen when the request is sent (THttpRequest.WithSseReadTimeout, which
  //   SseRequest sets to 0 = wait indefinitely). A constructor parameter
  //   could not change it, because the lease already owns the body stream.
  TSseSource = class(TInterfacedObject, IHttpSseSource)
  private
    FResponse: IHttpResponse;    // keeps the response (and lease) alive
    FBody: IHttpBodyStream;
    FParser: TSseEventParser;
    FQueue: TQueue<TSseEvent>;
    FBuf: TBytes;
    FEof: Boolean;
    FClosed: Boolean;
    /// pull one chunk, feed the parser and enqueue whatever it completed.
    /// False when the stream reached EOF.
    function Fill: Boolean;
    function Dequeue(out AEvent: TSseEvent): Boolean;
  public
    /// a response that passed ValidateResponse (raises otherwise)
    constructor Create(const AResponse: IHttpResponse);
    destructor Destroy; override;
    function ReadEvent(out AEvent: TSseEvent): Boolean;
    function LastEventId: string;
    function RetryMs: Integer;
    procedure Close;
    /// true when AValue is `text/event-stream` (case-insensitive, parameters
    /// allowed); a declared non-utf-8 charset makes it false
    class function IsEventStreamContentType(const AValue: string): Boolean;
      static;
    /// raise unless AResponse is a valid event stream; True when valid
    class function ValidateResponse(const AResponse: IHttpResponse): Boolean;
      static;
  end;

  /// reconnect + resume wrapper over IHttpClient
  // - reconnects when a source ends, echoes the last observed id as
  //   `last-event-id`, honours a server `retry:` delay, and raises
  //   EHttpTooManySseRetries once AMaxRetries RECONNECTS were made
  //   (AMaxRetries = 0 retries forever). The first connection is not a retry.
  // - a transient transport failure reconnects; a protocol error (bad status
  //   or content-type) is terminal and propagates, because reconnecting
  //   cannot fix a server that answered the wrong way.
  // - it deliberately does NOT take an IHttp2Observer: SSE is a message-level
  //   concept and IHttp2Observer is frame/stream-level, so per-event
  //   observation would be high-cardinality noise
  //   (doc/design/open-questions.md "SSE observer cardinality").
  TSseReconnectLoop = class
  private
    FClient: IHttpClient;
    FRequest: THttpRequest;
    FMaxRetries: Integer;
    FSource: IHttpSseSource;
    FRetryMs: Integer;
    FReconnects: Integer;
    FStarted: Boolean;
    FClosed: Boolean;
    FLastEventId: string;
    FLastDispatchedId: string;   // replay guard
    procedure OpenSource;
  public
    constructor Create(const AClient: IHttpClient;
      const ARequest: THttpRequest;
      const AMaxRetries: Integer = cSseDefaultMaxRetries);
    destructor Destroy; override;
    /// the next event across reconnects; False when the loop is closed
    function Next(out AEvent: TSseEvent): Boolean;
    procedure Close;
    /// the reconnect delay currently in force, in ms
    function RetryMs: Integer;
    /// reconnects performed so far (the first connection is not counted)
    function Reconnects: Integer;
  end;

/// build an SSE GET request: accept, cache-control and identity encoding
// - also attaches a body-read deadline of 0 (wait indefinitely), which is the
//   whole point of the SSE transport change: an event stream is quiet between
//   events and must not be aborted by the request header timeout.
function SseRequest(const AUrl: string): THttpRequest;

implementation

/// strict UTF-8 validation of a byte string: every sequence complete and
/// well-formed, no overlong form, no surrogate, no code point above U+10FFFF
function IsValidUtf8(const AText: string): Boolean;
var
  I, N, Need, J: Integer;
  B: Byte;
  CP: LongWord;
begin
  Result := True;
  I := 1;
  N := Length(AText);
  while I <= N do
  begin
    B := Ord(AText[I]);
    if B < $80 then
    begin
      Inc(I);
      Continue;
    end;
    if B < $C2 then
      Exit(False);                     // continuation byte or overlong lead
    if B < $E0 then
      Need := 1
    else if B < $F0 then
      Need := 2
    else if B < $F5 then
      Need := 3
    else
      Exit(False);
    if I + Need > N then
      Exit(False);
    CP := B and ($7F shr Need);
    for J := 1 to Need do
    begin
      if (Ord(AText[I + J]) and $C0) <> $80 then
        Exit(False);
      CP := (CP shl 6) or LongWord(Ord(AText[I + J]) and $3F);
    end;
    if ((Need = 1) and (CP < $80)) or ((Need = 2) and (CP < $800)) or
       ((Need = 3) and (CP < $10000)) or (CP > $10FFFF) or
       ((CP >= $D800) and (CP <= $DFFF)) then
      Exit(False);
    Inc(I, Need + 1);
  end;
end;

/// split AData into the part that is complete UTF-8 and a trailing partial
/// multi-byte sequence (nil when none). The caller holds the tail back for
/// the next chunk, so a code point split across a chunk boundary is never
/// mangled and never reported as invalid.
procedure SplitTrailingUtf8(const AData: TBytes;
  out AComplete, ATail: TBytes);
var
  I, Need: Integer;
begin
  AComplete := AData;
  ATail := nil;
  if Length(AData) = 0 then
    Exit;
  // walk back over the trailing continuation bytes to the last lead byte
  I := Length(AData) - 1;
  while (I >= 0) and ((AData[I] and $C0) = $80) do
    Dec(I);
  if I < 0 then
    Exit;                              // no lead byte: all continuation
  Need := 0;
  if AData[I] >= $C2 then
  begin
    if AData[I] < $E0 then
      Need := 1
    else if AData[I] < $F0 then
      Need := 2
    else if AData[I] < $F5 then
      Need := 3;
  end;
  // the sequence starting at I is incomplete when I + Need is past the end
  if I + Need >= Length(AData) then
  begin
    SetLength(ATail, Length(AData) - I);
    Move(AData[I], ATail[0], Length(ATail));
    SetLength(AComplete, I);
    if I > 0 then
      Move(AData[0], AComplete[0], I);
  end;
end;

/// join two byte arrays
function ConcatBytes(const A, B: TBytes): TBytes;
begin
  Result := nil;
  SetLength(Result, Length(A) + Length(B));
  if Length(A) > 0 then
    Move(A[0], Result[0], Length(A));
  if Length(B) > 0 then
    Move(B[0], Result[Length(A)], Length(B));
end;

{ TSseEventParser }

constructor TSseEventParser.Create;
begin
  inherited Create;
  FRetryMs := 0;
  FAtStart := True;
  FSkipLf := False;
end;

procedure TSseEventParser.Feed(const AChunk: TBytes;
  const AEvents: TList<TSseEvent>);
var
  Data, Complete, Tail: TBytes;
  Text: string;
  I, N: Integer;
  B: Byte;
begin
  if Length(AChunk) = 0 then
    Exit;
  Data := ConcatBytes(FPending, AChunk);
  FPending := nil;

  // one leading U+FEFF at stream start is stripped; a later BOM is data.
  // Hold bytes until the three-byte BOM can be decided.
  if FAtStart then
  begin
    if Length(Data) < 3 then
    begin
      if Data[0] = $EF then
      begin
        FPending := Data;
        Exit;
      end;
      FAtStart := False;
    end
    else if (Data[0] = $EF) and (Data[1] = $BB) and (Data[2] = $BF) then
    begin
      SetLength(Data, Length(Data) - 3);
      Move(Data[3], Data[0], Length(Data));
      FAtStart := False;
    end
    else
      FAtStart := False;
  end;

  // a CR that ended the previous chunk may have been the CR of a CRLF
  if FSkipLf and (Length(Data) > 0) and (Data[0] = $0A) then
  begin
    SetLength(Data, Length(Data) - 1);
    Move(Data[1], Data[0], Length(Data));
  end;
  FSkipLf := False;

  SplitTrailingUtf8(Data, Complete, Tail);
  FPending := Tail;
  if Length(Complete) = 0 then
    Exit;

  SetLength(Text, Length(Complete));
  if Length(Complete) > 0 then
    Move(Complete[0], Text[1], Length(Complete));
  if not IsValidUtf8(Text) then
    raise EHttpProtocolError.Create(
      'event stream is not valid UTF-8', ecProtocolError);

  FeedText(Text, AEvents);
end;

procedure TSseEventParser.Feed(const AText: string;
  const AEvents: TList<TSseEvent>);
var
  B: TBytes;
begin
  B := nil;
  if AText <> '' then
  begin
    SetLength(B, Length(AText));
    Move(AText[1], B[0], Length(AText));
  end;
  Feed(B, AEvents);
end;

procedure TSseEventParser.FeedText(const AText: string;
  const AEvents: TList<TSseEvent>);
var
  I, N: Integer;
  C: Char;
begin
  N := Length(AText);
  I := 1;
  while I <= N do
  begin
    C := AText[I];
    if C = #13 then
    begin
      HandleLine(FLine, AEvents);
      FLine := '';
      if I = N then
        FSkipLf := True               // a lone CR may be the CR of a CRLF
      else if AText[I + 1] = #10 then
        Inc(I);                       // consume the LF of this CRLF
      Inc(I);
      Continue;
    end;
    if C = #10 then
    begin
      HandleLine(FLine, AEvents);
      FLine := '';
      Inc(I);
      Continue;
    end;
    FLine := FLine + C;
    Inc(I);
  end;
end;

procedure TSseEventParser.HandleLine(const ALine: string;
  const AEvents: TList<TSseEvent>);
var
  Colon, I: Integer;
  Field, Value: string;
  IsDigits: Boolean;
begin
  if ALine = '' then
  begin
    DispatchEvent(AEvents);
    Exit;
  end;
  if ALine[1] = ':' then
    Exit;                                  // comment (a valid keep-alive)
  Colon := Pos(':', ALine);
  if Colon = 0 then
  begin
    Field := ALine;
    Value := '';
  end
  else
  begin
    Field := Copy(ALine, 1, Colon - 1);
    Value := Copy(ALine, Colon + 1, Length(ALine));
    // exactly one leading space is stripped from the value
    if (Value <> '') and (Value[1] = ' ') then
      Value := Copy(Value, 2, Length(Value));
  end;
  if Field = 'data' then
    FData := FData + Value + #10
  else if Field = 'event' then
    FEventType := Value
  else if Field = 'id' then
  begin
    // a value containing a NUL is ignored, leaving the id in force
    if Pos(#0, Value) = 0 then
      FLastEventId := Value;
  end
  else if Field = 'retry' then
  begin
    IsDigits := Value <> '';
    for I := 1 to Length(Value) do
      if (Value[I] < '0') or (Value[I] > '9') then
      begin
        IsDigits := False;
        Break;
      end;
    if IsDigits then
    begin
      try
        FRetryMs := StrToInt(Value);
      except
        FRetryMs := 0;
      end;
    end;
  end;
  // any other field name is ignored
end;

procedure TSseEventParser.DispatchEvent(const AEvents: TList<TSseEvent>);
var
  E: TSseEvent;
begin
  if FData = '' then
  begin
    // id/retry/event lines update state but must not fire on their own; an
    // event-type buffer set without data is discarded with the blank line
    FEventType := '';
    Exit;
  end;
  // strip exactly one trailing '\n'
  SetLength(FData, Length(FData) - 1);
  if AEvents <> nil then
  begin
    E.EventType := FEventType;
    if E.EventType = '' then
      E.EventType := cSseDefaultEventType;
    E.Data := FData;
    E.Id := FLastEventId;
    E.RetryMs := FRetryMs;
    AEvents.Add(E);
  end;
  FData := '';
  FEventType := '';
end;

function TSseEventParser.LastEventId: string;
begin
  Result := FLastEventId;
end;

function TSseEventParser.RetryMs: Integer;
begin
  Result := FRetryMs;
end;

procedure TSseEventParser.Reset;
begin
  FData := '';
  FEventType := '';
  FLine := '';
  FLastEventId := '';
  FRetryMs := 0;
  FAtStart := True;
  FSkipLf := False;
  FPending := nil;
end;

{ TSseSource }

class function TSseSource.IsEventStreamContentType(
  const AValue: string): Boolean;
var
  I: Integer;
  Media, Param: string;
  Parts: TArray<string>;
begin
  Result := False;
  if Trim(AValue) = '' then
    Exit;
  Media := Trim(AValue);
  I := Pos(';', Media);
  if I > 0 then
    Media := Trim(Copy(Media, 1, I - 1));
  if not SameText(Media, cSseContentType) then
    Exit;
  // a declared charset must be utf-8: the event stream is UTF-8 by definition
  Parts := AValue.Split([';']);
  for I := 1 to High(Parts) do
  begin
    Param := Trim(Parts[I]);
    if (Length(Param) >= 8) and SameText(Copy(Param, 1, 8), 'charset=') then
    begin
      Param := Trim(Copy(Param, 9, Length(Param)));
      if (Length(Param) >= 2) and (Param[1] = '"') and
         (Param[Length(Param)] = '"') then
        Param := Copy(Param, 2, Length(Param) - 2);
      if not SameText(Param, 'utf-8') then
        Exit;
    end;
  end;
  Result := True;
end;

class function TSseSource.ValidateResponse(
  const AResponse: IHttpResponse): Boolean;
var
  Coding: string;
begin
  Result := False;
  if AResponse = nil then
    Exit;
  if AResponse.StatusCode <> 200 then
    raise EHttpProtocolError.Create(Format(
      'event stream requires status 200, got %d',
      [AResponse.StatusCode]), ecProtocolError);
  if not IsEventStreamContentType(
    AResponse.Headers.GetFirst(HeaderContentType)) then
    raise EHttpProtocolError.Create(
      'response content-type is not text/event-stream', ecProtocolError);
  // transparent decoding buffers to the coding footer, which destroys
  // incremental delivery: an event stream is identity-coded only
  Coding := Trim(LowerCase(AResponse.Headers.GetFirst(HeaderContentEncoding)));
  if (Coding <> '') and (Coding <> 'identity') then
    raise EHttpProtocolError.Create(
      'event stream must not carry a content coding: ' + Coding,
      ecProtocolError);
  Result := True;
end;

constructor TSseSource.Create(const AResponse: IHttpResponse);
begin
  inherited Create;
  if AResponse = nil then
    raise EHttpError.Create('TSseSource requires a response', ecInternalError);
  ValidateResponse(AResponse);
  FResponse := AResponse;
  FBody := AResponse.Body;
  FParser := TSseEventParser.Create;
  FQueue := TQueue<TSseEvent>.Create;
  SetLength(FBuf, cSseReadChunkSize);
end;

destructor TSseSource.Destroy;
begin
  FParser.Free;
  FQueue.Free;
  inherited Destroy;
end;

function TSseSource.Fill: Boolean;
var
  N: Integer;
  Chunk: TBytes;
  Events: TList<TSseEvent>;
begin
  Result := False;
  if FEof then
    Exit;
  N := FBody.Read(FBuf[0], Length(FBuf));
  if N > 0 then
  begin
    SetLength(Chunk, N);
    Move(FBuf[0], Chunk[0], N);
    Events := TList<TSseEvent>.Create;
    try
      FParser.Feed(Chunk, Events);
      while Events.Count > 0 do
      begin
        FQueue.Enqueue(Events[0]);
        Events.Delete(0);
      end;
    finally
      Events.Free;
    end;
    Result := True;
  end
  else
    FEof := True;
end;

function TSseSource.Dequeue(out AEvent: TSseEvent): Boolean;
begin
  Result := FQueue.Count > 0;
  if Result then
    AEvent := FQueue.Dequeue;
end;

function TSseSource.ReadEvent(out AEvent: TSseEvent): Boolean;
begin
  Result := False;
  while not FClosed do
  begin
    if Dequeue(AEvent) then
      Exit(True);
    if FEof then
      Exit(False);
    // Fill returns True when it read bytes; the queue can still be empty
    // when the chunk held only a partial event, so loop and read again
    Fill;
  end;
end;

function TSseSource.LastEventId: string;
begin
  if FParser = nil then
    Result := ''
  else
    Result := FParser.LastEventId;
end;

function TSseSource.RetryMs: Integer;
begin
  if FParser = nil then
    Result := 0
  else
    Result := FParser.RetryMs;
end;

procedure TSseSource.Close;
begin
  FClosed := True;
end;

{ TSseReconnectLoop }

constructor TSseReconnectLoop.Create(const AClient: IHttpClient;
  const ARequest: THttpRequest; const AMaxRetries: Integer);
begin
  inherited Create;
  if AClient = nil then
    raise EHttpError.Create('TSseReconnectLoop requires a client',
      ecInternalError);
  FClient := AClient;
  FRequest := ARequest;
  FMaxRetries := AMaxRetries;
  FRetryMs := cSseDefaultRetryMs;
  FReconnects := 0;
  FStarted := False;
  FClosed := False;
  FLastEventId := '';
  FLastDispatchedId := '';
end;

destructor TSseReconnectLoop.Destroy;
begin
  if FSource <> nil then
  begin
    FSource.Close;
    FSource := nil;
  end;
  inherited Destroy;
end;

procedure TSseReconnectLoop.OpenSource;
var
  Req: THttpRequest;
  Resp: IHttpResponse;
begin
  // clone: THttpRequest.Headers is a shared interface, so adding the resume
  // header to a plain copy would mutate the caller's request too
  Req := FRequest.Clone;
  if FLastEventId <> '' then
    Req := Req.WithHeader(HeaderLastEventId, FLastEventId);
  Resp := FClient.Send(Req);
  FSource := TSseSource.Create(Resp);
end;

function TSseReconnectLoop.Next(out AEvent: TSseEvent): Boolean;
var
  Delay: Integer;
begin
  Result := False;
  while not FClosed do
  begin
    if FSource = nil then
    begin
      if FStarted then
      begin
        // a reconnect: count it against the bound and wait first
        if (FMaxRetries > 0) and (FReconnects >= FMaxRetries) then
          raise EHttpTooManySseRetries.Create(Format(
            'SSE reconnect limit of %d reached', [FMaxRetries]));
        Inc(FReconnects);
        Delay := FRetryMs;
        if (Delay > 0) and not FClosed then
          Sleep(Delay);
        if FClosed then
          Exit(False);
      end;
      try
        OpenSource;
        FStarted := True;
      except
        // a transient transport failure is what reconnecting is for; a
        // protocol error is terminal (the design note's rule)
        on E: EHttpProtocolError do
          raise;
        on E: EHttpError do
          if not FStarted then
            raise          // the very first connection failing is reported
          else
            Continue;      // loop: the bound and the delay are applied above
      end;
    end;
    if FSource.ReadEvent(AEvent) then
    begin
      // replay guard: an event whose id was already dispatched is dropped, so
      // a server that resumes inclusive of `last-event-id` cannot duplicate it
      if (AEvent.Id <> '') and (AEvent.Id = FLastDispatchedId) then
        Continue;
      if AEvent.Id <> '' then
        FLastDispatchedId := AEvent.Id;
      FLastEventId := FSource.LastEventId;
      if FSource.RetryMs > 0 then
        FRetryMs := FSource.RetryMs;
      Exit(True);
    end;
    // the stream ended: remember where it got to, then reconnect after the
    // delay the server last asked for (or the default)
    FLastEventId := FSource.LastEventId;
    if FSource.RetryMs > 0 then
      FRetryMs := FSource.RetryMs;
    FSource := nil;
  end;
end;

procedure TSseReconnectLoop.Close;
begin
  FClosed := True;
  if FSource <> nil then
  begin
    FSource.Close;
    FSource := nil;
  end;
end;

function TSseReconnectLoop.RetryMs: Integer;
begin
  Result := FRetryMs;
end;

function TSseReconnectLoop.Reconnects: Integer;
begin
  Result := FReconnects;
end;

{ SseRequest }

function SseRequest(const AUrl: string): THttpRequest;
begin
  Result := THttpRequest.Create(hmGet, AUrl)
    .WithHeader(HeaderAccept, cSseContentType)
    .WithHeader(HeaderCacheControl, 'no-store')
    .WithAcceptEncoding('identity')
    // an event stream is idle between events: wait indefinitely rather than
    // inherit the request header timeout (doc/design/server-sent-events.md)
    .WithSseReadTimeout(0);
end;

end.
