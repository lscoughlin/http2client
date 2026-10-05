REPO: /Users/liamcoughlin/Source/lscoughlin/http2client
STORY: plan/stories/08-stream-lease.md  (read it first, in full)
SPEC: doc/design/client-api.md (Lease acquisition), doc/design/messages.md
      (Request and response streaming), doc/design/protocol.md (flow control)

## CRITICAL ENVIRONMENT FACTS (do not re-derive, do not compile in the repo)
- FPC 3.2.4. You MUST compile in your OWN private directory:
    mkdir -p /tmp/h2agents/s08
    fpc -O2 -Mdelphi -Fu./src -Fu./test \
        -Fu/usr/local/lib/fpc/3.2.4/units/aarch64-darwin/fcl-fpcunit \
        -Futhird_party/mORMot2/src/core -Futhird_party/mORMot2/src/lib \
        -Futhird_party/mORMot2/src/net -Futhird_party/mORMot2/src/crypt \
        -FU/tmp/h2agents/s08 -FE/tmp/h2agents/s08 test/Http2.RunTests.pas
  then run /tmp/h2agents/s08/Http2.RunTests --all --format=plain --sparse
  NEVER put .o/.ppu in src/ or test/ (they will break other lanes).
- DO NOT run `make`. DO NOT `git commit`. DO NOT `git add`. I (the parent) do that.
- DO NOT edit any file other than src/Http2.Stream.pas, src/Http2.Connection.pas
  (only if strictly required), test/Http2.Stream.Test.pas, and appending the
  unit name to test/Http2.TestRunner.pas uses clause.
- NEEDS `OPENSSL_LIBPATH=/opt/homebrew/opt/openssl@3/lib` exported when running
  tests that touch TLS (your tests should not need TLS).
- This is a MULTI-WRITER repo: another lane may touch other units concurrently.
  Only touch the files listed above.
- NO network access needed. NO `find /`. NO searching the filesystem.

## WHAT ALREADY EXISTS (read these before writing anything)
- src/Http2.Errors.pas : EHttpError / EHttpProtocolError / EHttpStreamError
  (has FStreamId and Create(AMessage, AStreamId, AErrorCode)) / EHttpTimeout /
  EHttpConnectionClosed; THttp2ErrorCode enum (ecNoError, ecProtocolError,
  ecInternalError, ecFlowControlError, ecSettingsTimeout, ecStreamClosed,
  ecFrameSizeError, ecRefusedStream, ecCancel, ecCompressionError,
  ecConnectError, ecEnhanceYourCalm, ecInadequateSecurity, ecHttp11Required).
  NOTE: there is NO `ecConnectionError`. Use ecInternalError / ecConnectError.
- src/Http2.Frames.pas : TFrameType, TFrameHeader, TFrame (Create/DataLength/
  IsEndStream/IsEndHeaders/IsAck/IsPadded/IsPriority), TConnectionSettings,
  builders Build*Frame, parsers ExtractHeaderBlock / ExtractDataPayload /
  ParseRstStream / ParseGoAway / ParseWindowUpdate, ReadFrame/WriteFrame.
- src/Http2.Headers.pas : IHttpHeaders (Add/SetValue/GetValues/GetFirst/
  Contains/Remove/Names/AddPseudo/GetPseudo) + NewHttpHeaders.
- src/Http2.Hpack.pas : THpackCodec (Encode/Decode/ApplySettings/Huffman),
  THttpHeaderField{Name,Value,Sensitive}, THeaderBlock = TArray<THttpHeaderField>.
- src/Http2.FlowControl.pas : TWindow, TFlowControl (connection + per-stream
  windows; TryConsume for the SEND window; ApplyDataReceived for receive credit).
- src/Http2.Connection.pas :
    * IBlockingQueue<T> / TBlockingQueue<T> (Push/Pop/TryPop/Shutdown/Count/
      WaitersParked/WaitForItem/IsShutdown)
    * TConnectionState = (csOpening, csOpen, csGoAway, csClosed)
    * IConnectionStream = interface
        procedure OnConnectionFailed(const AMessage: string; const ACode: THttp2ErrorCode);
        procedure OnConnectionGoAway(const ALastStreamId: LongWord);
        procedure OnStreamFrame(const AFrame: TFrame);
      TConnection: RegisterStream(AStreamId, AStream) / UnregisterStream(AStreamId)
        / StreamCount / DispatchStreamFrame(AFrame): Boolean / PostFrame(AFrame)
        / CanOpenStream / IsStreamRetryable / MarkGoAway / FailWith / Close /
        Start / WaitForState / PeerSettings / State / Outbound / Inbound /
        HighestStreamId (read/write) / GoAwayLastStreamId / Socket
    * TConnectionThread routes stream-scoped frames to the owning lease via
      DispatchStreamFrame; unclaimed frames land on TConnection.Inbound.
    * TConnectionThread ALSO needs to be taught nothing new for HEADERS/DATA
      because DispatchStreamFrame handles it — but CHECK RouteInbound: it
      currently intercepts ftSettings/ftPing/ftGoAway and pushes the rest.
      If you need WINDOW_UPDATE / CONTINUATION special handling, say so in
      your report rather than editing broadly.

## YOUR DELIVERABLE — src/Http2.Stream.pas (implement all of S08)
Implement a `TStreamLease` (implements IConnectionStream) that owns ONE
request/response exchange:

08.1 stream-id allocation: odd ids, monotonic per connection, guarded by a
     TCriticalSection on the connection. Provide e.g.
       TStreamIdAllocator = class  ...  function Next: LongWord;
     Ids start at 1, step 2, never 0, never even, and must not exceed
     MaxStreamId ($7FFFFFFF). A concurrency test must show NO duplicate ids
     across N threads.
08.2 TStreamLease: fields FStreamId, FOutbound: IBlockingQueue<TFrame>,
     FInbound: IBlockingQueue<TFrame>, response state. Register with the
     connection on start, unregister exactly once on completion/reset/failure.
08.3 HEADERS emission: build pseudo-headers (:method, :scheme, :path,
     :authority) + regular headers, encode with THpackCodec, emit
     BuildHeadersFrame (with END_HEADERS; END_STREAM when there is no body).
     CONTINUATION frames when the block exceeds the peer max frame size.
08.4 request body: THttpBody bytes -> DATA frames; also support an
     IBodyWriter-style pull (see doc/design/messages.md) — an interface whose
     NextChunk(out ABuffer: TBytes): Boolean is called until it returns False.
08.5 response assembly: HEADERS -> status + headers become available; DATA ->
     appended to the body stream; END_STREAM closes the body.
08.6 Eof semantics: bodyless responses (204, 304, HEAD requests, 1xx) are
     immediately Eof; reading after EOF raises deterministically.
08.7 RST_STREAM: a mid-body reset surfaces from the body Read (NOT from Send);
     map the wire code to EHttpStreamError with FStreamId set.
08.8 half-closed states: the client may finish sending while still receiving;
     an invalid transition must raise (state machine, not silent).
08.9 cleanup: lease released on completion/reset/connection failure EXACTLY
     ONCE (use a guard flag); no queue or response-state leaks.

## TESTS — test/Http2.Stream.Test.pas
Cover: id allocation under concurrency (no duplicates), HEADERS encode/decode
round-trip (decode with a fresh THpackCodec), streaming upload, bodyless
responses, RST mapping from Read, invalid transition rejection, exactly-once
cleanup, and an end-to-end single lease over a mocked connection.
Also add ONE test using the real TConnection + a mock socket proving a
registered lease receives its frames via DispatchStreamFrame and that
FailWith reaches it exactly once.

IMPORTANT — make the tests NON-VACUOUS. A test that passes when the behaviour
is removed is worthless. After your tests are green, deliberately break ONE
key behaviour (e.g. make the allocator return even ids) and confirm a test
FAILS; then restore. Report which test caught it. Note: an earlier lane wrote
a concurrency test whose "not yet done" assertion was also satisfied by a
thread that had not started — avoid that class of mistake (assert on a
positive observable state, e.g. a parked-waiter count or a completed count).

## FPC QUIRKS ALREADY KNOWN (do not rediscover)
- {$mode objfpc} cannot parse generic methods: this project uses {$mode delphi}.
- Exception.CreateFmt takes only 2 params: use Create(Format(...), ACode).
- A procedure cannot assign to a `const` record parameter: copy it first.
- Managed TBytes results warn uninitialized: set `Result := nil;` first.
- TStringList has no Remove: use IndexOf + Delete.
- Use TCriticalSection (no TMonitor) and RTLEvent (no TEvent/TSimpleEvent).
- RTLEventSetEvent wakes exactly ONE waiter (verified): re-signal the same
  event to chain-wake a set of waiters.
- {$IFDEF UNIX}cthreads,{$ENDIF} must be first in any program that uses threads.

## REPORT BACK (concise)
1. Files written + exact public API of src/Http2.Stream.pas (type signatures).
2. Test names + count; the mutation you ran and the test that caught it.
3. Exact command to reproduce; the final test totals (N/E/F).
4. Any change needed in src/Http2.Connection.pas or RouteInbound, and why.
5. Deviations from plan/stories/08-stream-lease.md and the reason.
6. Anything you could NOT do.
