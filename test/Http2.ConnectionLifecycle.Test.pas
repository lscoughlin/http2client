/// Connection-lifecycle fan-out tests (plan story S07, task 07.6)
// - proves that a dying connection terminates every in-flight stream exactly
//   once, and that GOAWAY reports the peer's last-stream-id to each lease.
// - uses a recording fake lease (IConnectionStream); no sockets are needed.
unit Http2.ConnectionLifecycle.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, fpcunit, testregistry,
  Http2.Errors, Http2.Frames, Http2.Connection, Http2.ConnectionThread.Test;

type
  /// records every callback a connection issues to one stream lease
  TRecordingLease = class(TInterfacedObject, IConnectionStream)
  private
    FFailCount: Integer;
    FGoAwayCount: Integer;
    FLastMessage: string;
    FLastCode: THttp2ErrorCode;
    FLastGoAwayId: LongWord;
    FFrameCount: Integer;
    FLastFrameType: TFrameType;
    FLastFrameStreamId: LongWord;
  public
    procedure OnConnectionFailed(const AMessage: string;
      const ACode: THttp2ErrorCode);
    procedure OnConnectionGoAway(const ALastStreamId: LongWord);
    procedure OnStreamFrame(const AFrame: TFrame);
    property FailCount: Integer read FFailCount;
    property GoAwayCount: Integer read FGoAwayCount;
    property LastMessage: string read FLastMessage;
    property LastCode: THttp2ErrorCode read FLastCode;
    property LastGoAwayId: LongWord read FLastGoAwayId;
    property FrameCount: Integer read FFrameCount;
    property LastFrameType: TFrameType read FLastFrameType;
    property LastFrameStreamId: LongWord read FLastFrameStreamId;
  end;

  TConnectionLifecycleTest = class(TTestCase)
  published
    /// 07.6 every in-flight stream terminated exactly once on failure
    procedure TestFailWithFansOutToEveryStreamOnce;
    /// 07.6 a deregistered stream is not notified
    procedure TestUnregisteredStreamIsNotNotified;
    /// 07.4 GOAWAY reports last-stream-id to every in-flight lease
    procedure TestGoAwayNotifiesEveryStream;
    /// 07.7 state exposure drives pool eligibility
    procedure TestStateTransitionsExposed;
  end;

implementation

{ TRecordingLease }

procedure TRecordingLease.OnConnectionFailed(const AMessage: string;
  const ACode: THttp2ErrorCode);
begin
  Inc(FFailCount);
  FLastMessage := AMessage;
  FLastCode := ACode;
end;

procedure TRecordingLease.OnConnectionGoAway(const ALastStreamId: LongWord);
begin
  Inc(FGoAwayCount);
  FLastGoAwayId := ALastStreamId;
end;

procedure TRecordingLease.OnStreamFrame(const AFrame: TFrame);
begin
  Inc(FFrameCount);
  FLastFrameType := AFrame.Header.FrameType;
  FLastFrameStreamId := AFrame.Header.StreamId;
end;

{ TConnectionLifecycleTest }

procedure TConnectionLifecycleTest.TestFailWithFansOutToEveryStreamOnce;
var
  Sock: TMockSocket;
  Conn: TConnection;
  L1, L2, L3: TRecordingLease;
  I1, I2, I3: IConnectionStream;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Conn.Start;
    AssertTrue('connection opened', Conn.WaitForState(csOpen, 2000));
    L1 := TRecordingLease.Create; I1 := L1;
    L2 := TRecordingLease.Create; I2 := L2;
    L3 := TRecordingLease.Create; I3 := L3;
    Conn.RegisterStream(1, I1);
    Conn.RegisterStream(3, I2);
    Conn.RegisterStream(5, I3);
    AssertEquals('three streams registered', 3, Conn.StreamCount);

    Conn.FailWith('socket reset', ecConnectError);

    AssertEquals('stream 1 failed exactly once', 1, L1.FailCount);
    AssertEquals('stream 3 failed exactly once', 1, L2.FailCount);
    AssertEquals('stream 5 failed exactly once', 1, L3.FailCount);
    AssertEquals('failure message propagated', 'socket reset', L1.LastMessage);
    AssertEquals('failure code propagated', Ord(ecConnectError),
      Ord(L1.LastCode));
    AssertEquals('state is closed', Ord(csClosed), Ord(Conn.State));
  finally
    Conn.Free;
  end;
end;

procedure TConnectionLifecycleTest.TestUnregisteredStreamIsNotNotified;
var
  Sock: TMockSocket;
  Conn: TConnection;
  L1, L2: TRecordingLease;
  I1, I2: IConnectionStream;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Conn.Start;
    AssertTrue('connection opened', Conn.WaitForState(csOpen, 2000));
    L1 := TRecordingLease.Create; I1 := L1;
    L2 := TRecordingLease.Create; I2 := L2;
    Conn.RegisterStream(1, I1);
    Conn.RegisterStream(3, I2);
    // stream 1 completed successfully and cleaned up
    Conn.UnregisterStream(1);
    // unregister is idempotent
    Conn.UnregisterStream(1);
    AssertEquals('one stream left', 1, Conn.StreamCount);

    Conn.FailWith('later failure', ecConnectError);

    AssertEquals('completed stream is not failed', 0, L1.FailCount);
    AssertEquals('in-flight stream is failed', 1, L2.FailCount);
  finally
    Conn.Free;
  end;
end;

procedure TConnectionLifecycleTest.TestGoAwayNotifiesEveryStream;
var
  Sock: TMockSocket;
  Conn: TConnection;
  L1, L2: TRecordingLease;
  I1, I2: IConnectionStream;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    Conn.Start;
    AssertTrue('connection opened', Conn.WaitForState(csOpen, 2000));
    L1 := TRecordingLease.Create; I1 := L1;
    L2 := TRecordingLease.Create; I2 := L2;
    Conn.RegisterStream(1, I1);
    Conn.RegisterStream(5, I2);

    Conn.MarkGoAway(3);

    AssertEquals('stream 1 notified', 1, L1.GoAwayCount);
    AssertEquals('stream 5 notified', 1, L2.GoAwayCount);
    AssertEquals('last-stream-id reported', 3, L1.LastGoAwayId);
    AssertEquals('state is goaway', Ord(csGoAway), Ord(Conn.State));
    // RFC 7540 section 6.8 "may retry": only ids strictly above the peer's
    // last-stream-id are guaranteed unprocessed
    AssertTrue('stream 5 may be retried', Conn.IsStreamRetryable(5));
    AssertFalse('stream 1 was processed, not retryable',
      Conn.IsStreamRetryable(1));
    AssertFalse('no new streams after GOAWAY', Conn.CanOpenStream);
  finally
    Conn.Free;
  end;
end;

procedure TConnectionLifecycleTest.TestStateTransitionsExposed;
var
  Sock: TMockSocket;
  Conn: TConnection;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  try
    AssertEquals('starts opening', Ord(csOpening), Ord(Conn.State));
    AssertFalse('cannot open a stream before Start', Conn.CanOpenStream);
    Conn.Start;
    AssertTrue('reaches open', Conn.WaitForState(csOpen, 2000));
    AssertTrue('can open a stream when open', Conn.CanOpenStream);
    Conn.Close;
    AssertEquals('closed after Close', Ord(csClosed), Ord(Conn.State));
    AssertFalse('cannot open after Close', Conn.CanOpenStream);
  finally
    Conn.Free;
  end;
end;

initialization
  RegisterTest(TConnectionLifecycleTest);

end.
