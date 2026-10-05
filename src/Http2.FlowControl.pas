/// Connection and stream flow-control accounting (plan S04)
// - this unit is part of the http2client project (see doc/design/protocol.md)
// - pure accounting: no sockets, no threads, no dependency on Http2.Connection
unit Http2.FlowControl;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Generics.Collections, Http2.Errors;

const
  /// largest legal flow-control window (RFC 7540: 2^31-1)
  MaxWindowSize = $7FFFFFFF;

type
  /// A single flow-control window counter.
  ///
  /// A window is signed: the send window can go negative when the peer lowers
  /// SETTINGS_INITIAL_WINDOW_SIZE after bytes are already in flight, and the
  /// receiver's window shrinks as DATA arrives until it is replenished by
  /// WINDOW_UPDATE. `FConsumed` tracks bytes received since the last emitted
  /// WINDOW_UPDATE, which drives batching.
  TWindow = record
  private
    FSize: Int64;      // signed current window
    FConsumed: Int64;  // receive credit accrued since the last WINDOW_UPDATE
  public
    /// a fresh window opened at AInitial bytes
    class function Defaults(const AInitial: LongInt): TWindow; static;
    /// current window (may be negative on the send side)
    function Size: Int64;
    /// bytes received since the last WINDOW_UPDATE was emitted
    function Consumed: Int64;
    /// is there any send credit at all?
    function CanSend: Boolean;
    /// is there at least AN bytes of send credit?
    function CanSendN(const AN: LongWord): Boolean;

    /// true when AN bytes of send credit are available; on success the
    /// window is decremented. On failure the window is left untouched.
    function TryConsume(const AN: LongWord): Boolean;

    /// apply an inbound WINDOW_UPDATE increment. A zero increment is a
    /// PROTOCOL_ERROR; an increment that overflows past 2^31-1 is a
    /// FLOW_CONTROL_ERROR.
    procedure ApplyUpdate(const AIncrement: LongWord);

    /// account for AN DATA bytes sent (caller has already checked CanSendN)
    procedure ApplyDataSent(const AN: LongWord);
    /// account for AN DATA bytes received; accrues WINDOW_UPDATE credit
    procedure ApplyDataReceived(const AN: LongWord);

    /// apply a SETTINGS_INITIAL_WINDOW_SIZE delta to this (stream) window.
    /// ADelta is signed; it may push the window negative. A positive delta
    /// that overflows past 2^31-1 is a FLOW_CONTROL_ERROR.
    procedure ApplyInitialWindowDelta(const ADelta: Int64);

    /// batching decision: has AThreshold worth of credit accrued?
    function NeedsUpdate(const AThreshold: LongInt): Boolean;
    /// the WINDOW_UPDATE increment to emit and reset the accrued credit
    function UpdateIncrement: LongWord;
  end;

/// Pure batching predicate. A WINDOW_UPDATE should be emitted once the
/// consumed amount reaches at least half the configured window, or whenever
/// the stream ends (so the peer is not left waiting).
function ShouldEmitWindowUpdate(const AConsumed: LongWord;
  const AWindowSize: LongWord; const AStreamEnded: Boolean): Boolean;

type
  /// Connection-level aggregate: the shared connection window plus one window
/// per open stream. Used to prove per-stream isolation.
TFlowControl = class
private
  FConnection: TWindow;
  FStreams: TDictionary<LongWord, TWindow>;
  FInitialStreamWindow: LongInt;
public
  constructor Create(const AConnectionWindow, AInitialStreamWindow: LongInt);
  destructor Destroy; override;

  /// register a new stream, opening its window at the initial window size
  procedure OpenStream(const AStreamId: LongWord);
  /// forget a closed stream
  procedure CloseStream(const AStreamId: LongWord);
  /// true and the current window when AStreamId is open
  function TryGetStream(const AStreamId: LongWord; out AWindow: TWindow): Boolean;

  /// decrement both the connection and the stream window for AN DATA bytes.
  /// Returns False (leaving both untouched) when either lacks credit, so a
  /// blocked stream does not consume the shared connection window.
  function TryConsume(const AStreamId: LongWord; const AN: LongWord): Boolean;

  /// apply a connection-level WINDOW_UPDATE
  procedure ApplyConnectionUpdate(const AIncrement: LongWord);
  /// apply a stream-level WINDOW_UPDATE
  procedure ApplyStreamUpdate(const AStreamId: LongWord;
    const AIncrement: LongWord);
  /// apply a SETTINGS_INITIAL_WINDOW_SIZE delta to every open stream and
  /// remember the new initial size for streams opened later
  procedure ApplyInitialWindowDelta(const ADelta: Int64);

  /// the shared connection window
  property Connection: TWindow read FConnection;
  /// the initial size for streams opened from now on
  property InitialStreamWindow: LongInt read FInitialStreamWindow;
end;

implementation

class function TWindow.Defaults(const AInitial: LongInt): TWindow;
begin
  Result.FSize := AInitial;
  Result.FConsumed := 0;
end;

function TWindow.Size: Int64;
begin
  Result := FSize;
end;

function TWindow.Consumed: Int64;
begin
  Result := FConsumed;
end;

function TWindow.CanSend: Boolean;
begin
  Result := FSize > 0;
end;

function TWindow.CanSendN(const AN: LongWord): Boolean;
begin
  Result := FSize >= Int64(AN);
end;

function TWindow.TryConsume(const AN: LongWord): Boolean;
begin
  Result := CanSendN(AN);
  if Result then
    FSize := FSize - Int64(AN);
end;

procedure TWindow.ApplyUpdate(const AIncrement: LongWord);
begin
  if AIncrement = 0 then
    raise EHttpProtocolError.Create(
      'WINDOW_UPDATE increment must be non-zero', ecProtocolError);
  FSize := FSize + Int64(AIncrement);
  if FSize > MaxWindowSize then
    raise EHttpProtocolError.Create(
      'WINDOW_UPDATE overflows the flow-control window', ecFlowControlError);
end;

procedure TWindow.ApplyDataSent(const AN: LongWord);
begin
  FSize := FSize - Int64(AN);
end;

procedure TWindow.ApplyDataReceived(const AN: LongWord);
begin
  FSize := FSize - Int64(AN);
  FConsumed := FConsumed + Int64(AN);
end;

procedure TWindow.ApplyInitialWindowDelta(const ADelta: Int64);
begin
  FSize := FSize + ADelta;
  if FSize > MaxWindowSize then
    raise EHttpProtocolError.Create(
      'SETTINGS_INITIAL_WINDOW_SIZE overflows a flow-control window',
      ecFlowControlError);
end;

function TWindow.NeedsUpdate(const AThreshold: LongInt): Boolean;
begin
  Result := FConsumed >= AThreshold;
end;

function TWindow.UpdateIncrement: LongWord;
begin
  Result := LongWord(FConsumed);
  FConsumed := 0;
end;

function ShouldEmitWindowUpdate(const AConsumed: LongWord;
  const AWindowSize: LongWord; const AStreamEnded: Boolean): Boolean;
begin
  Result := AStreamEnded or (AConsumed >= AWindowSize div 2);
end;

constructor TFlowControl.Create(const AConnectionWindow,
  AInitialStreamWindow: LongInt);
begin
  inherited Create;
  FConnection := TWindow.Defaults(AConnectionWindow);
  FStreams := TDictionary<LongWord, TWindow>.Create;
  FInitialStreamWindow := AInitialStreamWindow;
end;

destructor TFlowControl.Destroy;
begin
  FStreams.Free;
  inherited Destroy;
end;

procedure TFlowControl.OpenStream(const AStreamId: LongWord);
begin
  FStreams.AddOrSetValue(AStreamId, TWindow.Defaults(FInitialStreamWindow));
end;

procedure TFlowControl.CloseStream(const AStreamId: LongWord);
begin
  FStreams.Remove(AStreamId);
end;

function TFlowControl.TryGetStream(const AStreamId: LongWord;
  out AWindow: TWindow): Boolean;
begin
  Result := FStreams.TryGetValue(AStreamId, AWindow);
end;

function TFlowControl.TryConsume(const AStreamId: LongWord;
  const AN: LongWord): Boolean;
var
  W: TWindow;
begin
  Result := False;
  if not FConnection.CanSendN(AN) then
    Exit;
  if not FStreams.TryGetValue(AStreamId, W) then
    Exit;
  if not W.CanSendN(AN) then
    Exit;
  FConnection.TryConsume(AN);
  W.TryConsume(AN);
  FStreams[AStreamId] := W;
  Result := True;
end;

procedure TFlowControl.ApplyConnectionUpdate(const AIncrement: LongWord);
begin
  FConnection.ApplyUpdate(AIncrement);
end;

procedure TFlowControl.ApplyStreamUpdate(const AStreamId: LongWord;
  const AIncrement: LongWord);
var
  W: TWindow;
begin
  if not FStreams.TryGetValue(AStreamId, W) then
    Exit;
  W.ApplyUpdate(AIncrement);
  FStreams[AStreamId] := W;
end;

procedure TFlowControl.ApplyInitialWindowDelta(const ADelta: Int64);
var
  Key: LongWord;
  W: TWindow;
begin
  for Key in FStreams.Keys do
  begin
    W := FStreams[Key];
    W.ApplyInitialWindowDelta(ADelta);
    FStreams[Key] := W;
  end;
  FInitialStreamWindow := FInitialStreamWindow + LongInt(ADelta);
end;

end.
