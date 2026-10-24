/// scoped SIGPIPE suppression for writes the library does not make itself
// - Linux has no SO_NOSIGPIPE, and OpenSSL writes a socket descriptor with
//   write(), so a write to a peer that has closed raises SIGPIPE, whose default
//   action kills the process.  A library must not change the host program's
//   signal disposition, so the library never installs a handler or SIG_IGN.
//   Instead each OpenSSL call that can write is bracketed by a shield:
//   SIGPIPE is blocked in the calling thread only, the signal the call may
//   have generated is consumed with a zero-timeout sigtimedwait, and the
//   thread's previous mask is restored, so nothing is delivered later.
//   (A SIGPIPE raised by write() is directed at the writing thread.)
// - plain sends do not need this: they use send() with MSG_NOSIGNAL
//   (cMsgNoSignal below).
// - on every other platform the shield is a no-op: macOS sets SO_NOSIGPIPE
//   per socket.
unit Http2.SigPipe;

{$mode delphi}{$H+}

interface

const
  /// send() flag that suppresses SIGPIPE for that call (Linux value); 0
  /// elsewhere, where SO_NOSIGPIPE covers the socket instead
{$IFDEF LINUX}
  cMsgNoSignal = $4000;
{$ELSE}
  cMsgNoSignal = 0;
{$ENDIF}

type
  /// the state one shield saves between Enter and Leave
  TSigPipeShield = record
{$IFDEF LINUX}
    OldMask: array[0..127] of Byte;   // glibc sigset_t is 128 bytes
    WasBlocked: Boolean;              // SIGPIPE was already blocked on entry
    WasPending: Boolean;              // ... and already pending, so not ours
    Active: Boolean;
{$ENDIF}
  end;

/// block SIGPIPE in the calling thread; pair with SigPipeShieldLeave in a
// try/finally
procedure SigPipeShieldEnter(out AShield: TSigPipeShield);

/// consume any SIGPIPE raised since Enter and restore the thread's mask
procedure SigPipeShieldLeave(var AShield: TSigPipeShield);

implementation

{$IFDEF LINUX}
uses
  BaseUnix;

const
  cSigBlock = 0;
  cSigSetMask = 2;

type
  TLibcSigSet = array[0..127] of Byte;

function pthread_sigmask(how: Integer; const newset: Pointer;
  oldset: Pointer): Integer; cdecl; external 'c' name 'pthread_sigmask';
function sigemptyset(var ASet: TLibcSigSet): Integer; cdecl;
  external 'c' name 'sigemptyset';
function sigaddset(var ASet: TLibcSigSet; signo: Integer): Integer; cdecl;
  external 'c' name 'sigaddset';
function sigismember(const ASet: TLibcSigSet; signo: Integer): Integer; cdecl;
  external 'c' name 'sigismember';
function sigpending(var ASet: TLibcSigSet): Integer; cdecl;
  external 'c' name 'sigpending';
function sigtimedwait(const ASet: TLibcSigSet; info: Pointer;
  const timeout: TTimeSpec): Integer; cdecl; external 'c' name 'sigtimedwait';

procedure PipeSet(out ASet: TLibcSigSet);
begin
  sigemptyset(ASet);
  sigaddset(ASet, SIGPIPE);
end;

procedure SigPipeShieldEnter(out AShield: TSigPipeShield);
var
  S, Pend: TLibcSigSet;
begin
  FillChar(AShield, SizeOf(AShield), 0);
  PipeSet(S);
  if pthread_sigmask(cSigBlock, @S, @AShield.OldMask) <> 0 then
    Exit;
  AShield.Active := True;
  AShield.WasBlocked :=
    sigismember(TLibcSigSet(AShield.OldMask), SIGPIPE) = 1;
  if AShield.WasBlocked then
  begin
    // the caller already blocks SIGPIPE: one pending now is theirs to keep
    FillChar(Pend, SizeOf(Pend), 0);
    sigpending(Pend);
    AShield.WasPending := sigismember(Pend, SIGPIPE) = 1;
  end;
end;

procedure SigPipeShieldLeave(var AShield: TSigPipeShield);
var
  S: TLibcSigSet;
  Zero: TTimeSpec;
  R: Integer;
begin
  if not AShield.Active then
    Exit;
  AShield.Active := False;
  if not AShield.WasPending then
  begin
    PipeSet(S);
    Zero.tv_sec := 0;
    Zero.tv_nsec := 0;
    repeat
      R := sigtimedwait(S, nil, Zero);   // consumes at most one pending SIGPIPE
    until (R >= 0) or (fpGetErrno <> ESysEINTR);
  end;
  if not AShield.WasBlocked then
    pthread_sigmask(cSigSetMask, @AShield.OldMask, nil);
end;

{$ELSE}

procedure SigPipeShieldEnter(out AShield: TSigPipeShield);
begin
end;

procedure SigPipeShieldLeave(var AShield: TSigPipeShield);
begin
end;

{$ENDIF}

end.
