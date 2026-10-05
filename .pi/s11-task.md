REPO: /Users/liamcoughlin/Source/lscoughlin/http2client
STORY: plan/stories/11-observability.md   (read it first, in full)
SPEC: doc/design/testing-observability.md,
      doc/design/transport.md (connection lifecycle, threading)

## FILE OWNERSHIP — THIS IS A PARALLEL LANE, RESPECT IT EXACTLY
YOU OWN: src/Http2.Observer.pas (currently an EMPTY shell),
         src/Http2.Connection.pas, src/Http2.Stream.pas,
         test/Http2.MockSocket.pas (new),
         test/Http2.Hpack.Property.Test.pas (new),
         test/Http2.Concurrency.Test.pas (new),
         and appending those three unit names to test/Http2.TestRunner.pas.
ANOTHER AGENT IS EDITING src/Http2.Client.pas, test/Http2.Redirects.Test.pas
and test/Http2.Timeouts.Test.pas CONCURRENTLY.
=> Do NOT edit src/Http2.Client.pas, test/Http2.Redirects.Test.pas,
   test/Http2.Timeouts.Test.pas, test/Http2.Client.Test.pas, or
   test/Http2.Request.Test.pas. I (the parent) wire the observer into the
   factory afterwards.
Your edits to Connection.pas / Stream.pas MUST be purely ADDITIVE: do not
change any existing signature, field, or behaviour, so the other lane keeps
compiling. If you think an existing signature must change, REPORT it instead.

## CRITICAL ENVIRONMENT FACTS (do not re-derive, do not compile in the repo)
- Compile in your OWN private directory, NEVER in the repo:
    mkdir -p /tmp/h2agents/s11
    fpc -O2 -Mdelphi -Fu./src -Fu./test \
        -Fu/usr/local/lib/fpc/3.2.4/units/aarch64-darwin/fcl-fpcunit \
        -Futhird_party/mORMot2/src/core -Futhird_party/mORMot2/src/lib \
        -Futhird_party/mORMot2/src/net -Futhird_party/mORMot2/src/crypt \
        -FU/tmp/h2agents/s11 -FE/tmp/h2agents/s11 test/Http2.RunTests.pas
    OPENSSL_LIBPATH=/opt/homebrew/opt/openssl@3/lib \
      /tmp/h2agents/s11/Http2.RunTests --all --format=plain --sparse
  Use a FRESH output dir (rm -rf) for EVERY build: fpc -FU only recompiles
  when it sees a MISSING .ppu, so a reused dir silently links a STALE binary
  and makes mutations look like passes.
- DO NOT run `make`. DO NOT `git add`/`git commit`. I (the parent) do that.
- NO network. NO `find /`. NO filesystem searching. NO real sockets.
- Baseline suite is 186 tests, 0 errors, 0 failures — it must stay green.

## WHAT ALREADY EXISTS (READ THESE BEFORE WRITING)
- src/Http2.Connection.pas — TConnectionState = (csOpening, csOpen, csGoAway,
  csClosed); TConnectionThread (sole socket writer, weak `FConn: Pointer`)
  with DoPreface/ApplyPeerSettings/RouteInbound/DrainOutbound/
  CheckPingKeepAlive/HandlePingAck/Fail; TConnection with Start/Close/
  PostFrame/CanOpenStream/IsStreamRetryable/WaitForState/MarkGoAway/FailWith/
  RegisterStream/UnregisterStream/StreamCount/DispatchStreamFrame/
  ApplyPeerSettingsValue/MarkSettingsAcked/TouchActivity/SetState and
  IConnectionStream (OnConnectionFailed/OnConnectionGoAway/OnStreamFrame).
  `cClientPreface` is the client connection preface constant.
- src/Http2.Stream.pas — TStreamLease with WaitForResponseHeader, ReadBody,
  BodyEof, ReleaseLease, LocalState/ResponseState.
- src/Http2.Frames.pas — ReadFrame/WriteFrame/Build*/Parse*; TFrame.
- src/Http2.Tls.pas — IHttp2Socket (Read/Write/Close/Connected + timeouts).
- test/Http2.Client.Test.pas has a TFakeServerSocket implementing the SERVER
  side of IHttp2Socket inline — read it as a starting point, but do NOT edit
  that file; your mock goes in your own new unit.

## YOUR DELIVERABLE — implement all of S11
11.1 `IHttp2Observer` in src/Http2.Observer.pas. Per
     doc/design/testing-observability.md it must receive: connection
     open/close/GOAWAY, stream open/close, frames IN and OUT, window updates,
     retries, and DISCARDED frames. Make it a plain interface with a
     no-op/NULL default (e.g. a TNullObserver or a
     TBaseObserver with empty virtual methods) so callers opt in cheaply.
     Also provide a recording observer useful for assertions.
     Wire the emission points ADDITIVELY: TConnectionThread.DoPreface/open
     (connection open), Close/FailWith (connection close), RouteInbound
     (frame in), DrainOutbound (frame out), MarkGoAway, RegisterStream/
     UnregisterStream (stream open/close), flow-control WINDOW_UPDATE,
     IsStreamRetryable/retry path, and any frame the loop discards
     (unknown types are ignored per spec — report those).
     The observer must be injectable on TConnection (e.g. an added
     `Observer` property) WITHOUT changing existing constructor signatures
     used by other units; if you must add an overload, keep the old one.
11.2 `test/Http2.MockSocket.pas` — an IHttp2Socket implementation that feeds
     CANNED INBOUND BYTES and CAPTURES OUTBOUND BYTES, in memory, with no
     network. Include helpers to enqueue a server frame sequence
     (SETTINGS, HEADERS, DATA, RST_STREAM, GOAWAY, PING, WINDOW_UPDATE) and
     to drain the captured client output. It must support a STALLED mode
     (reads never return) so timeouts can be tested.
11.3 Frame-level assertion helpers: assert the EXACT outbound frame sequence
     (types, flags, stream ids, payloads) rather than just "something was
     written".
11.4 Reusable scripted scenarios: normal GET, multiplex, GOAWAY, RST_STREAM,
     zero-window (flow control stall), malformed frame. These must be usable
     by the S12 port of http2/http2-test intents.
11.5 fpcunit wiring: register every new unit in test/Http2.RunTests.pas
     (or Http2.TestRunner.pas — check which one the Makefile compiles:
     `${FPC} ... test/Http2.RunTests.pas`). Do NOT break the existing list.
     Integration tests must stay gated behind an env var.
11.6 `test/Http2.Hpack.Property.Test.pas` — randomized round-trip property
     tests: decode(encode(headers)) == headers over many random header sets
     (varied names/values/sizes/sensitive flags/duplicates), plus
     incremental-encoding against a shared table. Use a FIXED SEED so runs
     are deterministic.
11.7 `test/Http2.Concurrency.Test.pas` — N concurrent operations over one
     mock connection with NO data races: e.g. many stream leases driving one
     TConnectionThread, plus the blocking-queue multi-waiter behaviour.
     Deterministic, no sleeps-as-synchronization where avoidable.
11.8 Oracle hook: a documented procedure (and, if cheap, a helper) to dump
     our outbound frame sequence and compare it with `nghttp -nv` output.
     A written procedure + the dump helper is enough; you cannot run nghttp.

## CRITICAL CONCURRENCY REQUIREMENT (learned the hard way in this repo)
`RTLEventSetEvent` wakes exactly ONE waiter (NOT level-triggered). Any
shutdown/broadcast path must re-signal the SAME event to chain-wake every
waiter. TBlockingQueue already does this correctly — do not regress it.
Never invoke an observer callback while holding a lock (it may re-enter or
block); snapshot under the lock, call outside it. Same rule as the existing
stream-callback fan-out in FailWith/MarkGoAway.

## NON-VACUOUS TESTS ARE MANDATORY
Run at least THREE mutations, confirm a test FAILS for each, then restore:
(a) remove an observer emission (e.g. frame-in) and show the observer test
    catches it; (b) make the mock socket ignore canned input (or return
    nothing) and show the scripted scenario fails; (c) break the HPACK
    property (e.g. skip dynamic-table eviction, or break the fixed seed's
    coverage) and show the property test fails. If a mutation cannot be
    caught, say so explicitly rather than claiming success. Report the exact
    test that caught each mutation.

## FPC QUIRKS (do not rediscover)
- {$mode objfpc} cannot parse generic methods — this project uses {$mode delphi}.
- Exception.CreateFmt takes only 2 params: use Create(Format(...), ACode).
- Cannot assign to a `const` record param: copy it first.
- Managed TBytes results warn uninitialized: set `Result := nil;` first.
- TStringList has no Remove: IndexOf + Delete.
- TCriticalSection (no TMonitor); RTLEvent (no TEvent/TSimpleEvent).
- {$IFDEF UNIX}cthreads,{$ENDIF} must be first in any program using threads.
- Observer callbacks must be exception-safe: a raising observer must not
  corrupt the connection loop (guard with try/except).

## REPORT BACK (concise)
1. Exact `IHttp2Observer` declaration + the recording observer's API.
2. Where each emission point is wired (file:line) and what event it emits.
3. Public API of test/Http2.MockSocket.pas.
4. Test names + counts; the THREE mutations and which test caught each.
5. Reproduce command + final totals (N/E/F); confirm the S10 lane's files
   still compiled (the shared build must be green).
6. Deviations from plan/stories/11-observability.md and why.
7. What you could NOT do.
