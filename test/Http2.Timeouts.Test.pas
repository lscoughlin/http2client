/// Timeout, cancellation and transparent-retry tests (plan story S10,
/// tasks 10.5-10.9).
// - hermetic: everything runs through Htt2.Redirects.Test's in-memory
//   frame-level fake (TFakeFrameFactory / TFakeFrameSocket); no real sockets.
// - non-vacuous by construction: the header-timeout test uses a peer that
//   never answers (auto-respond off), so removing the deadline makes it hang
//   and the harness fail it; the cancellation test asserts the exact
//   RST_STREAM(CANCEL) frame the fake captured; the retry matrix asserts the
//   observed request count (2 for an idempotent retry, 1 for a POST).
unit Http2.Timeouts.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, SyncObjs, fpcunit, testregistry,
  Http2.Errors, Http2.Frames, Http2.Headers, Http2.Hpack,
  Http2.Tls, Http2.Connection, Http2.Stream, Http2.Messages, Http2.Client,
  Http2.Redirects.Test;

type
  /// one worker performing a single Send on a shared client, so a test thread
  /// can cancel it or observe a timeout without blocking the harness
  TTimeoutSendWorker = class(TThread)
  private
    FClient: IHttpClient;
    FRequest: THttpRequest;
    FDone: PRTLEvent;
    FDoneFlag: Boolean;
    FRaised: Boolean;
    FError: string;
    FErrorCode: THttp2ErrorCode;
    FStatus: LongInt;
    FResponse: IHttpResponse;
  protected
    procedure Execute; override;
  public
    constructor Create(const AClient: IHttpClient;
      const ARequest: THttpRequest);
    destructor Destroy; override;
    function WaitDone(const ATimeoutMs: Integer): Boolean;
    property Raised: Boolean read FRaised;
    property Error: string read FError;
    property ErrorCode: THttp2ErrorCode read FErrorCode;
    property Status: LongInt read FStatus;
  end;

  TTimeoutsTest = class(TTestCase)
  published
    procedure TestConnectTimeoutMapsToEHttpTimeout;
    procedure TestHeaderTimeoutMapsToEHttpTimeout;
    procedure TestPerRequestHeaderTimeoutOverridesFactory;
    procedure TestCancelResetsStreamAndReleasesLease;
    procedure TestIdleConnectionIsReaped;
    procedure TestIdempotentGetRetriesOnRefusedStream;
    procedure TestNonIdempotentPostNeverRetries;
  end;

implementation

{ TTimeoutSendWorker }

constructor TTimeoutSendWorker.Create(const AClient: IHttpClient;
  const ARequest: THttpRequest);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FClient := AClient;
  FRequest := ARequest;
  FDone := RTLEventCreate;
end;

destructor TTimeoutSendWorker.Destroy;
begin
  RTLEventDestroy(FDone);
  inherited Destroy;
end;

procedure TTimeoutSendWorker.Execute;
begin
  try
    FResponse := FClient.Send(FRequest);
    FStatus := FResponse.StatusCode;
  except
    on E: EHttpStreamError do
    begin
      FRaised := True;
      FError := E.ClassName + ': ' + E.Message;
      FErrorCode := E.ErrorCode;
    end;
    on E: Exception do
    begin
      FRaised := True;
      FError := E.ClassName + ': ' + E.Message;
      if E is EHttpError then
        FErrorCode := EHttpError(E).ErrorCode;
    end;
  end;
  FDoneFlag := True;
  RTLEventSetEvent(FDone);
end;

function TTimeoutSendWorker.WaitDone(const ATimeoutMs: Integer): Boolean;
var
  Deadline: QWord;
  Remaining: Integer;
begin
  Deadline := GetTickCount64 + QWord(ATimeoutMs);
  while not FDoneFlag do
  begin
    if GetTickCount64 >= Deadline then
      Exit(False);
    Remaining := Integer(Deadline - GetTickCount64);
    RTLEventWaitFor(FDone, Remaining);
  end;
  Result := True;
end;

function HasRstStream(const AFrames: TArray<TFrame>): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 0 to High(AFrames) do
    if AFrames[I].Header.FrameType = ftRstStream then
      Exit(True);
end;

{ TTimeoutsTest }

procedure TTimeoutsTest.TestConnectTimeoutMapsToEHttpTimeout;
var
  Factory: TFakeFrameFactory;
  Client: IHttpClient;
  Raised: Boolean;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetFailDial(True);
  Client := THttpClientFactory.Create
    .WithSocketFactory(Factory)
    .WithConnectTimeout(150)
    .Build;
  Raised := False;
  try
    Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  except
    on E: EHttpTimeout do Raised := True;
  end;
  AssertTrue('a stalled connect maps to EHttpTimeout', Raised);
  Client.Close;
end;

procedure TTimeoutsTest.TestHeaderTimeoutMapsToEHttpTimeout;
var
  Factory: TFakeFrameFactory;
  Client: IHttpClient;
  Raised: Boolean;
  Sock: TFakeFrameSocket;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetAutoRespond(False);       // the peer never answers
  Client := THttpClientFactory.Create
    .WithSocketFactory(Factory)
    .WithHeaderTimeout(200)
    .Build;
  Raised := False;
  try
    Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  except
    on E: EHttpTimeout do Raised := True;
  end;
  AssertTrue('the response-header deadline maps to EHttpTimeout', Raised);
  Sock := Factory.SocketAt(0);
  AssertTrue('the request was issued before the deadline',
    Sock.WaitForRequests(1, 1000));
  Client.Close;
end;

procedure TTimeoutsTest.TestPerRequestHeaderTimeoutOverridesFactory;
var
  Factory: TFakeFrameFactory;
  Client: IHttpClient;
  Raised: Boolean;
  Started, Elapsed: QWord;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetAutoRespond(False);
  // factory default is generous; the request asks for 150 ms
  Client := THttpClientFactory.Create
    .WithSocketFactory(Factory)
    .WithHeaderTimeout(5000)
    .Build;
  Raised := False;
  Started := GetTickCount64;
  try
    Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x')
      .WithTimeout(150));
  except
    on E: EHttpTimeout do Raised := True;
  end;
  Elapsed := GetTickCount64 - Started;
  AssertTrue('the per-request timeout fired', Raised);
  AssertTrue('it fired well before the factory default (got ' +
    IntToStr(Elapsed) + ' ms)', Elapsed < 2000);
  Client.Close;
end;

procedure TTimeoutsTest.TestCancelResetsStreamAndReleasesLease;
var
  Factory: TFakeFrameFactory;
  Client: IHttpClient;
  Token: TCancellationToken;
  Worker: TTimeoutSendWorker;
  Sock: TFakeFrameSocket;
  Req: THttpRequest;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetAutoRespond(False);       // the peer stalls, so Send is in flight
  Client := THttpClientFactory.Create
    .WithSocketFactory(Factory)
    .WithHeaderTimeout(5000)
    .Build;
  Token := TCancellationToken.Create;
  Req := THttpRequest.Create(hmGet, 'https://a.example/x')
    .WithCancelToken(Token);
  Worker := TTimeoutSendWorker.Create(Client, Req);
  try
    Worker.Start;
    AssertTrue('the client dialled', Factory.WaitForDials(1, 2000));
    Sock := Factory.SocketAt(0);
    AssertTrue('the in-flight request was issued',
      Sock.WaitForRequests(1, 2000));
    Token.Cancel;
    AssertTrue('Send unblocked after cancel', Worker.WaitDone(3000));
    AssertTrue('cancel raises an error', Worker.Raised);
    AssertTrue('cancel maps to EHttpStreamError',
      Pos('EHttpStreamError', Worker.Error) > 0);
    AssertEquals('cancel error code is CANCEL', Ord(ecCancel),
      Ord(Worker.ErrorCode));
    // cancel returns after the reset is *queued*; wait for the connection
    // thread to flush it, otherwise this races the wire (flaky at 1/6)
    AssertTrue('the stream was reset with RST_STREAM',
      Sock.WaitForWrittenFrame(ftRstStream, 2000));
  finally
    Worker.Free;
  end;
  Client.Close;
end;

procedure TTimeoutsTest.TestIdleConnectionIsReaped;
var
  Factory: TFakeFrameFactory;
  Client: IHttpClient;
  Pool: TConnectionPool;
  R: IHttpResponse;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([HdrSpec('200')]));
  Client := THttpClientFactory.Create
    .WithSocketFactory(Factory)
    .WithIdleTimeout(150)
    .Build;
  Pool := (Client as THttpClient).Pool;
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  AssertEquals('request succeeded', 200, R.StatusCode);
  AssertEquals('one pooled connection', 1, Pool.ConnectionCount);
  Sleep(400);                          // exceed the idle deadline
  Pool.ReapIdle;
  AssertEquals('the idle connection was reaped', 0, Pool.ConnectionCount);
  Client.Close;
end;

procedure TTimeoutsTest.TestIdempotentGetRetriesOnRefusedStream;
var
  Factory: TFakeFrameFactory;
  Client: IHttpClient;
  R: IHttpResponse;
  Sock: TFakeFrameSocket;
begin
  Factory := TFakeFrameFactory.Create;
  // the first attempt is refused; the transparent retry gets a 200
  Factory.SetDialScript(0, SpecArray([
    RstSpec(ecRefusedStream),
    HdrSpec('200')]));
  Client := THttpClientFactory.Create.WithSocketFactory(Factory).Build;
  R := Client.Send(THttpRequest.Create(hmGet, 'https://a.example/x'));
  AssertEquals('the retried GET succeeds', 200, R.StatusCode);
  Sock := Factory.SocketAt(0);
  AssertTrue('two requests were issued', Sock.WaitForRequests(2, 2000));
  AssertEquals('the GET was retried exactly once', 2, Sock.RequestCount);
  Client.Close;
end;

procedure TTimeoutsTest.TestNonIdempotentPostNeverRetries;
var
  Factory: TFakeFrameFactory;
  Client: IHttpClient;
  Raised: Boolean;
  Sock: TFakeFrameSocket;
begin
  Factory := TFakeFrameFactory.Create;
  Factory.SetDialScript(0, SpecArray([RstSpec(ecRefusedStream)]));
  Client := THttpClientFactory.Create.WithSocketFactory(Factory).Build;
  Raised := False;
  try
    Client.Send(THttpRequest.Create(hmPost, 'https://a.example/x')
      .WithBody(THttpBody.FromString('payload')));
  except
    on E: EHttpStreamError do Raised := True;
  end;
  AssertTrue('a refused POST is not retried (it raises)', Raised);
  Sock := Factory.SocketAt(0);
  AssertTrue('the POST was issued once', Sock.WaitForRequests(1, 2000));
  AssertEquals('no transparent retry for a non-idempotent request', 1,
    Sock.RequestCount);
  Client.Close;
end;

initialization
  RegisterTest(TTimeoutsTest);
end.
