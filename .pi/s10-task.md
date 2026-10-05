REPO: /Users/liamcoughlin/Source/lscoughlin/http2client
STORY: plan/stories/10-redirects-timeouts.md   (read it first, in full)
SPEC: doc/design/errors-redirects.md (all of it), doc/design/client-api.md

## FILE OWNERSHIP — THIS IS A PARALLEL LANE, RESPECT IT EXACTLY
YOU OWN: src/Http2.Client.pas, test/Http2.Redirects.Test.pas (new),
         test/Http2.Timeouts.Test.pas (new), and appending those two unit
         names to test/Http2.TestRunner.pas's uses clause.
ANOTHER AGENT IS EDITING src/Http2.Connection.pas, src/Http2.Stream.pas,
src/Http2.Observer.pas and test/Http2.MockSocket.pas CONCURRENTLY.
=> Do NOT edit src/Http2.Connection.pas, src/Http2.Stream.pas,
   src/Http2.Observer.pas, src/Http2.MockSocket.pas, or their tests.
   Do NOT edit any other src/ unit. If you need a seam there, REPORT it.

## CRITICAL ENVIRONMENT FACTS (do not re-derive, do not compile in the repo)
- Compile in your OWN private directory, NEVER in the repo:
    mkdir -p /tmp/h2agents/s10
    fpc -O2 -Mdelphi -Fu./src -Fu./test \
        -Fu/usr/local/lib/fpc/3.2.4/units/aarch64-darwin/fcl-fpcunit \
        -Futhird_party/mORMot2/src/core -Futhird_party/mORMot2/src/lib \
        -Futhird_party/mORMot2/src/net -Futhird_party/mORMot2/src/crypt \
        -FU/tmp/h2agents/s10 -FE/tmp/h2agents/s10 test/Http2.RunTests.pas
    OPENSSL_LIBPATH=/opt/homebrew/opt/openssl@3/lib \
      /tmp/h2agents/s10/Http2.RunTests --all --format=plain --sparse
  Use a FRESH output dir (rm -rf) for every build: fpc -FU only recompiles
  when it sees a MISSING .ppu, so a reused dir silently links a STALE binary.
- DO NOT run `make`. DO NOT `git add`/`git commit`. I (the parent) do that.
- NO network. NO `find /`. NO filesystem searching. NO real sockets.
- Baseline suite is 186 tests, 0 errors, 0 failures — it must stay green.

## WHAT ALREADY EXISTS (READ THESE BEFORE WRITING)
- src/Http2.Client.pas — THttpClientFactory (pure value record) with
  MaxConnections/MaxStreamsPerConnection/FollowRedirects/MaxRedirects/
  ConnectTimeoutMs/HeaderTimeoutMs/IdleTimeoutMs/ProxyHost/ProxyPort/
  CACertFile/SocketFactory; IHttpClient.Send/Close; THttpRequest;
  IHttpResponse; TConnectionPool; IHttp2SocketFactory (inject a fake to run
  with NO real sockets). NOTE: FollowRedirects/MaxRedirects are currently
  STORED BUT NOT HONOURED — that is exactly what you implement.
- src/Http2.Stream.pas — TStreamLease (Start/SendHeaders/SendData/SendBody/
  EndSend/WaitForResponseHeader/BodyEof/ReadBody/ReleaseLease;
  StatusCode/ResponseHeaders/Body/RequestMethod); TStreamRequest record;
  TStreamIdAllocator.
- src/Http2.Errors.pas — EHttpTimeout, EHttpTooManyRedirects,
  EHttpNotReplayable, EHttpConnectionClosed, EHttpStreamError, plus
  THttp2ErrorCode (NO ecConnectionError).
- src/Http2.Frames.pas — TFrame, frame types/flags.
- Http2.Headers — IHttpHeaders (GetFirst/GetValues/Names/...); 'location'.
- THttpBody has FromBytes/FromString/IsSet/Data; IBodyWriter.NextChunk.

## YOUR DELIVERABLE — implement all of S10
10.1 REDIRECT LOOP. When FollowRedirects is on and the response is 301/302/
     303/307/308 with a `location` header: resolve the target (absolute, or
     relative to the current URL), re-issue the request, and repeat up to
     MaxRedirects. Status handling MUST match the spec table exactly:
       - 303 -> method becomes GET, body dropped
       - 307/308 -> method AND body preserved
       - 301/302 -> preserve the method for GET/HEAD; for other methods the
         spec's table is what counts — read it and follow it, and state in
         your report which rule you implemented.
     Preserve headers across the hop (except any you must not).
10.2 NON-REPLAYABLE GUARD. 307/308 with an IBodyWriter body cannot be
     replayed -> raise EHttpNotReplayable. A replayable THttpBody may be
     re-sent. (A body already consumed by a THttpBody must still be
     replayable — verify.)
10.3 LIMIT. Exceeding MaxRedirects raises EHttpTooManyRedirects.
10.4 CROSS-ORIGIN. A Location with a different scheme/host/port must use a
     NEW authority (separate pool entry/connection), not the old lease.
10.5/10.6/10.7 TIMEOUTS. ConnectTimeoutMs / HeaderTimeoutMs / IdleTimeoutMs
     enforced and mapped to EHttpTimeout. HeaderTimeout covers the wait for
     status+headers. Idle connections are reaped and the pool stays within
     MaxConnections. A timeout must CANCEL the stream, not orphan it.
     The per-request timeout must be overridable if the design says so.
10.8 CANCELLATION. A caller can cancel an in-flight Send: the stream is
     reset (RST_STREAM/CANCEL) and the lease released. Expose a cancellation
     seam (e.g. an ICancellationToken parameter or a THttpRequest field) and
     document it.
10.9 IDEMPOTENT RETRY. Transparently retry ONLY idempotent methods
     (GET/HEAD/PUT/DELETE/OPTIONS/TRACE) and ONLY when the connection says it
     is safe: GOAWAY (stream id above last-stream-id -> `may` retry) or a
     refused stream. NEVER transparently retry a non-idempotent request, and
     never retry a request that carried a body it cannot replay.
     TConnection already exposes IsStreamRetryable.

## TESTS — non-negotiable
Hermetic: drive everything through an injected IHttp2SocketFactory fake (see
TFakeServerSocket in test/Http2.Client.Test.pas and test/Http2.MockSocket.pas
as examples). No real sockets.
- test/Http2.Redirects.Test.pas: each of 301/302/303/307/308; body
  preservation matrix; 303 -> GET; the non-replayable guard; the MaxRedirects
  limit; cross-origin uses a different authority; no-Location 3xx is returned
  as-is; FollowRedirects=False returns the 3xx untouched.
- test/Http2.Timeouts.Test.pas: connect/handle/header timeout each ->
  EHttpTimeout (use a stalled peer: a fake socket that never replies);
  idle reap; cancellation resets + releases; idempotent retry happens,
  non-idempotent retry does NOT.

## NON-VACUOUS TESTS ARE MANDATORY
Run at least THREE mutations, confirm a test FAILS for each, then restore:
(a) ignore FollowRedirects and return the 3xx; (b) let 307 replay an
IBodyWriter body (drop the guard) or let 303 keep the POST body;
(c) retry a non-idempotent request (e.g. POST) transparently, or drop the
HeaderTimeout. Report the exact test that caught each mutation. A test that
still passes with the behaviour removed is worthless and I will reject it.

## FPC QUIRKS (do not rediscover)
- {$mode objfpc} cannot parse generic methods — this project uses {$mode delphi}.
- Exception.CreateFmt takes only 2 params: use Create(Format(...), ACode).
- Cannot assign to a `const` record param: copy it first.
- Managed TBytes results warn uninitialized: set `Result := nil;` first.
- TStringList has no Remove: IndexOf + Delete.
- TCriticalSection (no TMonitor); RTLEvent (no TEvent/TSimpleEvent).
- RTLEventSetEvent wakes exactly ONE waiter: re-signal the same event to
  chain-wake a set of waiters.
- {$IFDEF UNIX}cthreads,{$ENDIF} must be first in any program using threads.

## REPORT BACK (concise)
1. Exact public additions to src/Http2.Client.pas (signatures).
2. The redirect status/method/body rule you implemented for 301/302, with the
   spec line you followed.
3. Test names + counts; the THREE mutations and which test caught each.
4. Reproduce command + final totals (N/E/F), and confirm the baseline suite
   stayed green.
5. Any seam you need in Connection/Stream (do NOT add it yourself).
6. Deviations from plan/stories/10-redirects-timeouts.md and why.
7. What you could NOT do.
