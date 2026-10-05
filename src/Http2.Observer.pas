/// Observability interface and test seams (plan S11, 11.1)
// - this unit is part of the http2client project (see doc/design/
//   testing-observability.md): "an IHttp2Observer interface set on the
//   factory receives connection open/close, stream open/close, frames
//   in/out, window updates, retries, and discarded frames".
// - the interface is deliberately plain and side-effect free: a no-op
//   TBaseObserver is the cheap opt-in default, and TRecordingObserver keeps
//   the events in a list for assertions. Every callback is invoked OUTSIDE
//   any connection lock, and the connection guards each call with try/except
//   so a raising observer can never corrupt the connection loop.
unit Http2.Observer;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, SyncObjs, Generics.Collections,
  Http2.Errors, Http2.Frames;

type
  /// the kind of a recorded observer event
  TObserverEventKind = (
    oekConnectionOpen,
    oekConnectionClose,
    oekGoAway,
    oekStreamOpen,
    oekStreamClose,
    oekFrameIn,
    oekFrameOut,
    oekWindowUpdate,
    oekRetry,
    oekDiscarded);

  /// the production observability seam. Implementations must be fast and must
  /// never raise (the connection still guards the call).
  IHttp2Observer = interface
    /// the client preface + initial SETTINGS have been written
    procedure OnConnectionOpen;
    /// the connection is closing or has failed (empty message = clean close)
    procedure OnConnectionClose(const AMessage: string;
      const ACode: THttp2ErrorCode);
    /// the peer sent GOAWAY
    procedure OnGoAway(const ALastStreamId: LongWord;
      const ACode: THttp2ErrorCode);
    /// a stream lease registered (a client-initiated stream exists)
    procedure OnStreamOpen(const AStreamId: LongWord);
    /// a stream lease unregistered (the stream is finished/closed)
    procedure OnStreamClose(const AStreamId: LongWord);
    /// a frame arrived from the peer
    procedure OnFrameIn(const AFrame: TFrame);
    /// a frame was written to the socket
    procedure OnFrameOut(const AFrame: TFrame);
    /// a flow-control WINDOW_UPDATE arrived from the peer
    procedure OnWindowUpdate(const AStreamId: LongWord;
      const AIncrement: LongWord);
    /// a stream above the peer's GOAWAY last-stream-id may be retried
    procedure OnRetry(const AStreamId: LongWord);
    /// a frame the connection loop ignored (unknown type / unroutable)
    procedure OnDiscarded(const AFrame: TFrame; const AReason: string);
  end;

  /// a no-op observer with empty virtual methods, so a caller can subclass
  /// and override only the events it cares about
  TBaseObserver = class(TInterfacedObject, IHttp2Observer)
  public
    procedure OnConnectionOpen; virtual;
    procedure OnConnectionClose(const AMessage: string;
      const ACode: THttp2ErrorCode); virtual;
    procedure OnGoAway(const ALastStreamId: LongWord;
      const ACode: THttp2ErrorCode); virtual;
    procedure OnStreamOpen(const AStreamId: LongWord); virtual;
    procedure OnStreamClose(const AStreamId: LongWord); virtual;
    procedure OnFrameIn(const AFrame: TFrame); virtual;
    procedure OnFrameOut(const AFrame: TFrame); virtual;
    procedure OnWindowUpdate(const AStreamId: LongWord;
      const AIncrement: LongWord); virtual;
    procedure OnRetry(const AStreamId: LongWord); virtual;
    procedure OnDiscarded(const AFrame: TFrame;
      const AReason: string); virtual;
  end;

  /// the canonical no-op observer; use when a connection must run unobserved
  TNullObserver = class(TBaseObserver)
  end;

  /// one captured event, with the fields relevant to its kind
  TObserverEvent = record
    Kind: TObserverEventKind;
    StreamId: LongWord;
    Increment: LongWord;
    ErrorCode: THttp2ErrorCode;
    Message: string;
    FrameType: TFrameType;
    Flags: TFrameFlags;
    Payload: TBytes;
    /// for oekDiscarded: why the frame was ignored
    Reason: string;
  end;

  /// records every callback for use in assertions. Thread-safe: the connection
  /// thread and caller threads can both deliver events.
  TRecordingObserver = class(TInterfacedObject, IHttp2Observer)
  private
    FLock: TCriticalSection;
    FEvents: TList<TObserverEvent>;
    FChanged: PRTLEvent;
    FRaiseOnEvent: Boolean;
    procedure Capture(const AEvent: TObserverEvent);
  protected
    // TRecordEvent is exposed so a subclass (or a test) can inject failures
    procedure Add(const AEvent: TObserverEvent); virtual;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Clear;
    /// number of recorded events
    function Count: Integer;
    /// a copy of the event at AIndex (0-based)
    function Event(const AIndex: Integer): TObserverEvent;
    /// a copy of every recorded event, in order
    function Snapshot: TArray<TObserverEvent>;
    /// how many events of this kind were recorded
    function CountOf(const AKind: TObserverEventKind): Integer;
    function HasEvent(const AKind: TObserverEventKind): Boolean;
    /// index of the first event of this kind, or -1
    function IndexOf(const AKind: TObserverEventKind): Integer;
    /// bounded, event-driven wait until at least ACount events of AKind are
    /// recorded; never sleeps (wakes on the observer's change event)
    function WaitForCount(const AKind: TObserverEventKind; const ACount,
      ATimeoutMs: Integer): Boolean;
    /// when True every callback raises EHttpError; the connection must survive
    property RaiseOnEvent: Boolean read FRaiseOnEvent write FRaiseOnEvent;

    // IHttp2Observer
    procedure OnConnectionOpen;
    procedure OnConnectionClose(const AMessage: string;
      const ACode: THttp2ErrorCode);
    procedure OnGoAway(const ALastStreamId: LongWord;
      const ACode: THttp2ErrorCode);
    procedure OnStreamOpen(const AStreamId: LongWord);
    procedure OnStreamClose(const AStreamId: LongWord);
    procedure OnFrameIn(const AFrame: TFrame);
    procedure OnFrameOut(const AFrame: TFrame);
    procedure OnWindowUpdate(const AStreamId: LongWord;
      const AIncrement: LongWord);
    procedure OnRetry(const AStreamId: LongWord);
    procedure OnDiscarded(const AFrame: TFrame; const AReason: string);
  end;

/// stable, human-readable event kind name (assertions / diagnostics)
function ObserverEventKindName(const AKind: TObserverEventKind): string;

implementation

function ObserverEventKindName(const AKind: TObserverEventKind): string;
begin
  case AKind of
    oekConnectionOpen:  Result := 'connection-open';
    oekConnectionClose: Result := 'connection-close';
    oekGoAway:          Result := 'goaway';
    oekStreamOpen:      Result := 'stream-open';
    oekStreamClose:     Result := 'stream-close';
    oekFrameIn:         Result := 'frame-in';
    oekFrameOut:        Result := 'frame-out';
    oekWindowUpdate:    Result := 'window-update';
    oekRetry:           Result := 'retry';
    oekDiscarded:       Result := 'discarded';
  else
    Result := 'unknown';
  end;
end;

{ TBaseObserver }

procedure TBaseObserver.OnConnectionOpen;
begin
end;

procedure TBaseObserver.OnConnectionClose(const AMessage: string;
  const ACode: THttp2ErrorCode);
begin
end;

procedure TBaseObserver.OnGoAway(const ALastStreamId: LongWord;
  const ACode: THttp2ErrorCode);
begin
end;

procedure TBaseObserver.OnStreamOpen(const AStreamId: LongWord);
begin
end;

procedure TBaseObserver.OnStreamClose(const AStreamId: LongWord);
begin
end;

procedure TBaseObserver.OnFrameIn(const AFrame: TFrame);
begin
end;

procedure TBaseObserver.OnFrameOut(const AFrame: TFrame);
begin
end;

procedure TBaseObserver.OnWindowUpdate(const AStreamId: LongWord;
  const AIncrement: LongWord);
begin
end;

procedure TBaseObserver.OnRetry(const AStreamId: LongWord);
begin
end;

procedure TBaseObserver.OnDiscarded(const AFrame: TFrame;
  const AReason: string);
begin
end;

{ TRecordingObserver }

constructor TRecordingObserver.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FEvents := TList<TObserverEvent>.Create;
  FChanged := RTLEventCreate;
  FRaiseOnEvent := False;
end;

destructor TRecordingObserver.Destroy;
begin
  FEvents.Free;
  RTLEventDestroy(FChanged);
  FLock.Free;
  inherited Destroy;
end;

procedure TRecordingObserver.Add(const AEvent: TObserverEvent);
begin
  FLock.Acquire;
  try
    FEvents.Add(AEvent);
  finally
    FLock.Release;
  end;
  // wake a blocked WaitForCount outside the lock
  RTLEventSetEvent(FChanged);
end;

procedure TRecordingObserver.Capture(const AEvent: TObserverEvent);
begin
  if FRaiseOnEvent then
    raise EHttpError.Create('observer failure injected', ecInternalError);
  Add(AEvent);
end;

procedure TRecordingObserver.Clear;
begin
  FLock.Acquire;
  try
    FEvents.Clear;
  finally
    FLock.Release;
  end;
end;

function TRecordingObserver.Count: Integer;
begin
  FLock.Acquire;
  try
    Result := FEvents.Count;
  finally
    FLock.Release;
  end;
end;

function TRecordingObserver.Event(const AIndex: Integer): TObserverEvent;
begin
  FLock.Acquire;
  try
    Result := FEvents[AIndex];
  finally
    FLock.Release;
  end;
end;

function TRecordingObserver.Snapshot: TArray<TObserverEvent>;
begin
  FLock.Acquire;
  try
    Result := FEvents.ToArray;
  finally
    FLock.Release;
  end;
end;

function TRecordingObserver.CountOf(const AKind: TObserverEventKind): Integer;
var
  E: TObserverEvent;
begin
  Result := 0;
  FLock.Acquire;
  try
    for E in FEvents do
      if E.Kind = AKind then
        Inc(Result);
  finally
    FLock.Release;
  end;
end;

function TRecordingObserver.HasEvent(const AKind: TObserverEventKind): Boolean;
begin
  Result := CountOf(AKind) > 0;
end;

function TRecordingObserver.IndexOf(const AKind: TObserverEventKind): Integer;
var
  I: Integer;
begin
  Result := -1;
  FLock.Acquire;
  try
    for I := 0 to FEvents.Count - 1 do
      if FEvents[I].Kind = AKind then
        Exit(I);
  finally
    FLock.Release;
  end;
end;

function TRecordingObserver.WaitForCount(const AKind: TObserverEventKind;
  const ACount, ATimeoutMs: Integer): Boolean;
var
  Deadline: QWord;
  Remaining: Integer;
begin
  Deadline := GetTickCount64 + QWord(ATimeoutMs);
  while True do
  begin
    if CountOf(AKind) >= ACount then
      Exit(True);
    if GetTickCount64 >= Deadline then
      Exit(False);
    Remaining := Integer(Deadline - GetTickCount64);
    RTLEventWaitFor(FChanged, Remaining);
  end;
end;

procedure TRecordingObserver.OnConnectionOpen;
var
  E: TObserverEvent;
begin
  E.Kind := oekConnectionOpen;
  Capture(E);
end;

procedure TRecordingObserver.OnConnectionClose(const AMessage: string;
  const ACode: THttp2ErrorCode);
var
  E: TObserverEvent;
begin
  E.Kind := oekConnectionClose;
  E.Message := AMessage;
  E.ErrorCode := ACode;
  Capture(E);
end;

procedure TRecordingObserver.OnGoAway(const ALastStreamId: LongWord;
  const ACode: THttp2ErrorCode);
var
  E: TObserverEvent;
begin
  E.Kind := oekGoAway;
  E.StreamId := ALastStreamId;
  E.ErrorCode := ACode;
  Capture(E);
end;

procedure TRecordingObserver.OnStreamOpen(const AStreamId: LongWord);
var
  E: TObserverEvent;
begin
  E.Kind := oekStreamOpen;
  E.StreamId := AStreamId;
  Capture(E);
end;

procedure TRecordingObserver.OnStreamClose(const AStreamId: LongWord);
var
  E: TObserverEvent;
begin
  E.Kind := oekStreamClose;
  E.StreamId := AStreamId;
  Capture(E);
end;

procedure TRecordingObserver.OnFrameIn(const AFrame: TFrame);
var
  E: TObserverEvent;
begin
  E.Kind := oekFrameIn;
  E.StreamId := AFrame.Header.StreamId;
  E.FrameType := AFrame.Header.FrameType;
  E.Flags := AFrame.Header.Flags;
  E.Payload := AFrame.Payload;
  Capture(E);
end;

procedure TRecordingObserver.OnFrameOut(const AFrame: TFrame);
var
  E: TObserverEvent;
begin
  E.Kind := oekFrameOut;
  E.StreamId := AFrame.Header.StreamId;
  E.FrameType := AFrame.Header.FrameType;
  E.Flags := AFrame.Header.Flags;
  E.Payload := AFrame.Payload;
  Capture(E);
end;

procedure TRecordingObserver.OnWindowUpdate(const AStreamId: LongWord;
  const AIncrement: LongWord);
var
  E: TObserverEvent;
begin
  E.Kind := oekWindowUpdate;
  E.StreamId := AStreamId;
  E.Increment := AIncrement;
  Capture(E);
end;

procedure TRecordingObserver.OnRetry(const AStreamId: LongWord);
var
  E: TObserverEvent;
begin
  E.Kind := oekRetry;
  E.StreamId := AStreamId;
  Capture(E);
end;

procedure TRecordingObserver.OnDiscarded(const AFrame: TFrame;
  const AReason: string);
var
  E: TObserverEvent;
begin
  E.Kind := oekDiscarded;
  E.StreamId := AFrame.Header.StreamId;
  E.FrameType := AFrame.Header.FrameType;
  E.Flags := AFrame.Header.Flags;
  E.Payload := AFrame.Payload;
  E.Reason := AReason;
  Capture(E);
end;

end.
