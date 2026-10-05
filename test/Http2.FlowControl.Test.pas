/// Unit tests for Http2.FlowControl (plan story S04, tasks 04.1-04.6)
// - run with `make test`
unit Http2.FlowControl.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, fpcunit, testregistry, Http2.Errors, Http2.FlowControl;

type
  TFlowControlTest = class(TTestCase)
  published
    // 04.1 window arithmetic
    procedure TestDefaultsAndSize;
    procedure TestCanSendReflectsCredit;
    procedure TestCanSendNExactBoundary;
    procedure TestTryConsumeExactLeavesZero;
    procedure TestTryConsumeBeyondRefusedLeavesUntouched;
    // 04.2 DATA consumption
    procedure TestApplyDataSentDecrementsWindow;
    procedure TestApplyDataReceivedAccruesConsumedCredit;
    // 04.3 WINDOW_UPDATE handling
    procedure TestApplyUpdateAppliesDelta;
    procedure TestZeroIncrementUpdateRaisesProtocolError;
    procedure TestUpdateOverflowRaisesFlowControlError;
    // 04.4 batching
    procedure TestNeedsUpdateBelowThresholdIsFalse;
    procedure TestNeedsUpdateAtThresholdIsTrue;
    procedure TestUpdateIncrementResetsConsumed;
    procedure TestShouldEmitBelowHalfIsFalse;
    procedure TestShouldEmitAtHalfIsTrue;
    procedure TestShouldEmitOnStreamEnd;
    // 04.6 SETTINGS interaction
    procedure TestInitialWindowDeltaCanDriveNegative;
    procedure TestInitialWindowDeltaOverflowRaisesFlowControlError;
    procedure TestInitialWindowDeltaAdjustsEveryOpenStream;
    procedure TestNewStreamUsesUpdatedInitialWindow;
    // 04.5 per-stream isolation
    procedure TestZeroWindowBlocksOnlyThatStream;
    procedure TestBlockedStreamDoesNotConsumeConnectionWindow;
  end;

implementation

procedure TFlowControlTest.TestDefaultsAndSize;
var
  W: TWindow;
begin
  W := TWindow.Defaults(65535);
  AssertEquals('fresh window size', Int64(65535), W.Size);
  AssertEquals('fresh consumed', Int64(0), W.Consumed);
end;

procedure TFlowControlTest.TestCanSendReflectsCredit;
var
  W: TWindow;
begin
  W := TWindow.Defaults(100);
  AssertTrue('100 is sendable', W.CanSend);
  W.ApplyDataSent(100);
  AssertFalse('0 is not sendable', W.CanSend);
  W.ApplyInitialWindowDelta(-10);
  AssertFalse('negative is not sendable', W.CanSend);
end;

procedure TFlowControlTest.TestCanSendNExactBoundary;
var
  W: TWindow;
begin
  W := TWindow.Defaults(100);
  AssertTrue('exactly 100', W.CanSendN(100));
  AssertFalse('101 exceeds', W.CanSendN(101));
end;

procedure TFlowControlTest.TestTryConsumeExactLeavesZero;
var
  W: TWindow;
begin
  W := TWindow.Defaults(100);
  AssertTrue('consume all 100 succeeds', W.TryConsume(100));
  AssertEquals('window drained to zero', Int64(0), W.Size);
  AssertFalse('nothing left to send', W.CanSend);
end;

procedure TFlowControlTest.TestTryConsumeBeyondRefusedLeavesUntouched;
var
  W: TWindow;
begin
  W := TWindow.Defaults(100);
  AssertFalse('consuming beyond the window is refused', W.TryConsume(101));
  AssertEquals('window untouched on refusal', Int64(100), W.Size);
  AssertTrue('still sendable', W.CanSend);
end;

procedure TFlowControlTest.TestApplyDataSentDecrementsWindow;
var
  W: TWindow;
begin
  W := TWindow.Defaults(1000);
  W.ApplyDataSent(400);
  AssertEquals('send decrement', Int64(600), W.Size);
  AssertEquals('sending is not receive credit', Int64(0), W.Consumed);
end;

procedure TFlowControlTest.TestApplyDataReceivedAccruesConsumedCredit;
var
  W: TWindow;
begin
  W := TWindow.Defaults(1000);
  W.ApplyDataReceived(300);
  AssertEquals('recv decrement', Int64(700), W.Size);
  AssertEquals('recv accrues credit', Int64(300), W.Consumed);
end;

procedure TFlowControlTest.TestApplyUpdateAppliesDelta;
var
  W: TWindow;
begin
  W := TWindow.Defaults(100);
  W.ApplyDataSent(80);
  W.ApplyUpdate(50);
  AssertEquals('update applied', Int64(70), W.Size);
end;

procedure TFlowControlTest.TestZeroIncrementUpdateRaisesProtocolError;
var
  W: TWindow;
begin
  W := TWindow.Defaults(100);
  try
    W.ApplyUpdate(0);
    Fail('expected EHttpProtocolError for a zero WINDOW_UPDATE increment');
  except
    on E: EHttpProtocolError do
      AssertEquals('zero increment is PROTOCOL_ERROR',
        Ord(ecProtocolError), Ord(E.ErrorCode));
  end;
end;

procedure TFlowControlTest.TestUpdateOverflowRaisesFlowControlError;
var
  W: TWindow;
begin
  W := TWindow.Defaults(MaxWindowSize);
  try
    W.ApplyUpdate(1);
    Fail('expected EHttpProtocolError for a window overflow');
  except
    on E: EHttpProtocolError do
      AssertEquals('overflow is FLOW_CONTROL_ERROR',
        Ord(ecFlowControlError), Ord(E.ErrorCode));
  end;
end;

procedure TFlowControlTest.TestNeedsUpdateBelowThresholdIsFalse;
var
  W: TWindow;
begin
  W := TWindow.Defaults(65535);
  W.ApplyDataReceived(100);
  AssertFalse('100 below a half-window threshold',
    W.NeedsUpdate(65535 div 2));
end;

procedure TFlowControlTest.TestNeedsUpdateAtThresholdIsTrue;
var
  W: TWindow;
begin
  W := TWindow.Defaults(65535);
  W.ApplyDataReceived(65535 div 2);
  AssertTrue('at the half-window threshold', W.NeedsUpdate(65535 div 2));
end;

procedure TFlowControlTest.TestUpdateIncrementResetsConsumed;
var
  W: TWindow;
begin
  W := TWindow.Defaults(1000);
  W.ApplyDataReceived(250);
  AssertEquals('increment equals accrued credit', LongWord(250),
    W.UpdateIncrement);
  AssertEquals('credit reset after emit', Int64(0), W.Consumed);
  AssertEquals('second emit has no credit', LongWord(0), W.UpdateIncrement);
end;

procedure TFlowControlTest.TestShouldEmitBelowHalfIsFalse;
begin
  AssertFalse('nothing emitted below half the window',
    ShouldEmitWindowUpdate(100, 65535, False));
  AssertFalse('just below half is still silent',
    ShouldEmitWindowUpdate(65534 div 2 - 1, 65534, False));
end;

procedure TFlowControlTest.TestShouldEmitAtHalfIsTrue;
begin
  AssertTrue('emitted at exactly half the window',
    ShouldEmitWindowUpdate(65535 div 2, 65535, False));
  AssertTrue('emitted above half the window',
    ShouldEmitWindowUpdate(40000, 65535, False));
end;

procedure TFlowControlTest.TestShouldEmitOnStreamEnd;
begin
  AssertTrue('stream end flushes whatever accrued',
    ShouldEmitWindowUpdate(1, 65535, True));
  AssertTrue('stream end with nothing accrued',
    ShouldEmitWindowUpdate(0, 65535, True));
end;

procedure TFlowControlTest.TestInitialWindowDeltaCanDriveNegative;
var
  W: TWindow;
begin
  W := TWindow.Defaults(100);
  W.ApplyDataSent(90);
  W.ApplyInitialWindowDelta(-50);
  AssertEquals('delta can drive the send window negative', Int64(-40), W.Size);
  AssertFalse('negative window cannot send', W.CanSend);
end;

procedure TFlowControlTest.TestInitialWindowDeltaOverflowRaisesFlowControlError;
var
  W: TWindow;
begin
  W := TWindow.Defaults(MaxWindowSize);
  try
    W.ApplyInitialWindowDelta(1);
    Fail('expected EHttpProtocolError for an initial-window overflow');
  except
    on E: EHttpProtocolError do
      AssertEquals('initial-window overflow is FLOW_CONTROL_ERROR',
        Ord(ecFlowControlError), Ord(E.ErrorCode));
  end;
end;

procedure TFlowControlTest.TestInitialWindowDeltaAdjustsEveryOpenStream;
var
  FC: TFlowControl;
  W1, W2, W3: TWindow;
begin
  FC := TFlowControl.Create(65535, 65535);
  try
    FC.OpenStream(1);
    FC.OpenStream(3);
    FC.OpenStream(5);
    FC.ApplyInitialWindowDelta(-1000);
    AssertTrue('stream 1 present', FC.TryGetStream(1, W1));
    AssertTrue('stream 3 present', FC.TryGetStream(3, W2));
    AssertTrue('stream 5 present', FC.TryGetStream(5, W3));
    AssertEquals('stream 1 adjusted', Int64(64535), W1.Size);
    AssertEquals('stream 3 adjusted', Int64(64535), W2.Size);
    AssertEquals('stream 5 adjusted', Int64(64535), W3.Size);
    AssertEquals('connection window is untouched by settings',
      Int64(65535), FC.Connection.Size);
  finally
    FC.Free;
  end;
end;

procedure TFlowControlTest.TestNewStreamUsesUpdatedInitialWindow;
var
  FC: TFlowControl;
  W: TWindow;
begin
  FC := TFlowControl.Create(65535, 65535);
  try
    FC.ApplyInitialWindowDelta(5000);
    FC.OpenStream(1);
    AssertTrue('new stream opened', FC.TryGetStream(1, W));
    AssertEquals('new stream uses the updated initial size',
      Int64(70535), W.Size);
  finally
    FC.Free;
  end;
end;

procedure TFlowControlTest.TestZeroWindowBlocksOnlyThatStream;
var
  FC: TFlowControl;
  W: TWindow;
begin
  FC := TFlowControl.Create(65535, 100);
  try
    FC.OpenStream(1);
    FC.OpenStream(3);
    // drain stream 1 completely
    AssertTrue('stream 1 can send its full window',
      FC.TryConsume(1, 100));
    AssertFalse('stream 1 is now blocked', FC.TryConsume(1, 1));
    AssertTrue('stream 3 is unaffected', FC.TryConsume(3, 50));
    AssertTrue('stream 3 still has credit', FC.TryGetStream(3, W));
    AssertEquals('stream 3 window', Int64(50), W.Size);
    AssertEquals('connection window shared decrement',
      Int64(65535 - 150), FC.Connection.Size);
  finally
    FC.Free;
  end;
end;

procedure TFlowControlTest.TestBlockedStreamDoesNotConsumeConnectionWindow;
var
  FC: TFlowControl;
begin
  FC := TFlowControl.Create(65535, 100);
  try
    FC.OpenStream(1);
    FC.TryConsume(1, 100);
    AssertFalse('blocked stream cannot consume more',
      FC.TryConsume(1, 10));
    AssertEquals('connection window untouched by the refused DATA',
      Int64(65535 - 100), FC.Connection.Size);
  finally
    FC.Free;
  end;
end;

initialization
  RegisterTest(TFlowControlTest);
end.
