/// Tests that writes to a closed peer never raise SIGPIPE in the host process
// - the library never changes a signal disposition: plain sends use
//   MSG_NOSIGNAL, and every OpenSSL call that can write is bracketed by a
//   per-thread SIGPIPE shield (Http2.SigPipe).  Each test writes repeatedly to
//   a peer that has closed and then checks that the process is alive, the
//   SIGPIPE disposition is still the default, and the thread's signal mask and
//   pending set are what they were before.
unit Http2.SigPipe.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$interfaces com}

interface

uses
  SysUtils, Classes, Sockets, BaseUnix, fpcunit, testregistry,
  mormot.lib.openssl11, Http2.Errors, Http2.SigPipe, Http2.Tls,
  Http2.Tls.Test;

type
  /// room for the platform's sigset_t (128 bytes on glibc, 4 on Darwin)
  TRawSigSet = array[0..127] of Byte;

  TSigPipeTest = class(TTestCase)
  private
    FMask: TRawSigSet;
    FPending: TRawSigSet;
    procedure Snapshot;
    procedure AssertUnchanged;
  published
    procedure TestDispositionIsDefaultAtStart;
    procedure TestPlainWritesToClosedPeer;
    procedure TestTlsWritesToClosedPeer;
    procedure TestShieldConsumesRaisedSigPipe;
  end;

implementation

function c_pthread_sigmask(How: Integer; NewSet, OldSet: Pointer): Integer;
  cdecl; external 'c' name 'pthread_sigmask';
function c_sigpending(SigSet: Pointer): Integer; cdecl;
  external 'c' name 'sigpending';
{$IFDEF LINUX}
function c_raise(Sig: Integer): Integer; cdecl; external 'c' name 'raise';
{$ENDIF}

procedure TSigPipeTest.Snapshot;
begin
  FillChar(FMask, SizeOf(FMask), 0);
  FillChar(FPending, SizeOf(FPending), 0);
  c_pthread_sigmask(SIG_BLOCK, nil, @FMask);
  c_sigpending(@FPending);
end;

procedure TSigPipeTest.AssertUnchanged;
var
  Mask, Pending: TRawSigSet;
  Old: SigActionRec;
  Handler: Pointer;
begin
  FillChar(Mask, SizeOf(Mask), 0);
  FillChar(Pending, SizeOf(Pending), 0);
  c_pthread_sigmask(SIG_BLOCK, nil, @Mask);
  c_sigpending(@Pending);
  AssertTrue('thread signal mask is unchanged', CompareMem(@Mask, @FMask,
    SizeOf(Mask)));
  AssertTrue('pending signals are unchanged', CompareMem(@Pending, @FPending,
    SizeOf(Pending)));
  FillChar(Old, SizeOf(Old), 0);
  AssertEquals('sigaction query', 0, fpSigAction(SIGPIPE, nil, @Old));
  Handler := nil;
  Move(Old.sa_handler, Handler, SizeOf(Handler));
  AssertTrue('SIGPIPE disposition is still SIG_DFL', Handler = nil);
end;

procedure TSigPipeTest.TestDispositionIsDefaultAtStart;
begin
  // the test runner starts with the default action; loading the library must
  // not have changed it
  Snapshot;
  AssertUnchanged;
end;

procedure TSigPipeTest.TestPlainWritesToClosedPeer;
var
  Fds: array[0..1] of cint;
  Buf: array[0..1023] of Byte;
  I, Failures: Integer;
{$IFDEF DARWIN}
  One: LongInt;
{$ENDIF}
begin
  AssertEquals('socketpair', 0, fpsocketpair(AF_UNIX, SOCK_STREAM, 0, @Fds[0]));
{$IFDEF DARWIN}
  One := 1;
  fpSetSockOpt(Fds[0], SOL_SOCKET, SO_NOSIGPIPE, @One, SizeOf(One));
{$ENDIF}
  FillChar(Buf, SizeOf(Buf), 1);
  Snapshot;
  fpClose(Fds[1]);
  Failures := 0;
  for I := 1 to 200 do
    try
      SocketWriteFully(Fds[0], SizeOf(Buf), 1000, Buf);
    except
      on EHttpConnectionClosed do
        Inc(Failures);
    end;
  fpClose(Fds[0]);
  AssertEquals('every write to the closed peer failed', 200, Failures);
  AssertUnchanged;
end;

procedure TSigPipeTest.TestTlsWritesToClosedPeer;
var
  ListenFd: Integer;
  Addr: TSockAddr;
  Len: LongInt;
  Port: Word;
  Server: TLoopbackTlsServer;
  Sock: IHttp2Socket;
  Buf: array[0..4095] of Byte;
  I, Failures: Integer;
  Cert, Key: string;
begin
  if not OpenSslIsAvailable then
    Exit;
  Cert := ExtractFilePath(ParamStr(0)) + '../../test/certs/localhost.crt';
  Key := ExtractFilePath(ParamStr(0)) + '../../test/certs/localhost.key';
  if not FileExists(Cert) then
  begin
    Cert := 'test/certs/localhost.crt';
    Key := 'test/certs/localhost.key';
  end;
  if not FileExists(Cert) then
    Exit;
  ListenFd := fpsocket(AF_INET, SOCK_STREAM, 0);
  FillChar(Addr, SizeOf(Addr), 0);
  Addr.sin_family := AF_INET;
  Addr.sin_port := htons(0);
  Addr.sin_addr.s_addr := htonl($7F000001);
  fpbind(ListenFd, @Addr, SizeOf(Addr));
  fplisten(ListenFd, 1);
  Len := SizeOf(Addr);
  fpgetsockname(ListenFd, @Addr, @Len);
  Port := ntohs(Addr.sin_port);
  Server := TLoopbackTlsServer.Create(ListenFd, Cert, Key);
  Server.Start;
  FillChar(Buf, SizeOf(Buf), 2);
  Failures := 0;
  try
    Snapshot;
    // the fixture server handshakes, waits 100 ms and closes
    Sock := TTlsSocket.DialWithAlpn('localhost', Port, AlpnOfferFor(True),
      True, 2000);
    Server.WaitFor;
    Sleep(50);
    for I := 1 to 200 do
      try
        Sock.Write(Buf[0], SizeOf(Buf));
      except
        on EHttpError do
          Inc(Failures);
      end;
    Sock.Close;                // SSL_shutdown writes close_notify to the dead peer
    Sock := nil;
  finally
    Server.Free;
    fpClose(ListenFd);
  end;
  AssertTrue('writes to the closed peer failed', Failures > 0);
  AssertUnchanged;
end;

procedure TSigPipeTest.TestShieldConsumesRaisedSigPipe;
{$IFDEF LINUX}
var
  Shield: TSigPipeShield;
begin
  Snapshot;
  SigPipeShieldEnter(Shield);
  try
    // the same thread-directed signal a write() to a closed peer generates
    AssertEquals('raise', 0, c_raise(SIGPIPE));
  finally
    SigPipeShieldLeave(Shield);
  end;
  AssertUnchanged;
end;
{$ELSE}
begin
end;
{$ENDIF}

initialization
  RegisterTest(TSigPipeTest);
end.
