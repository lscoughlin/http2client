REPO: /Users/liamcoughlin/Source/lscoughlin/http2client
STORY: plan/stories/12-validation.md AND plan/validation.md   (read both, in full)
This is the FINAL story: prove the client against real external HTTP/2 peers.

## FILE OWNERSHIP
YOU OWN: test/h2probe.pas (new), tools/validate/ (new scripts),
         plan/validation.md (append the RESULTS sections),
         and appending h2probe-related unit names to test/Http2.TestRunner.pas.
You may READ everything. Do NOT edit src/*.pas or the other test units —
if you need a source change, REPORT it (I, the parent, make it).

## CRITICAL ENVIRONMENT FACTS (established, do not re-derive)
- Compile privately, NEVER in the repo:
    mkdir -p /tmp/h2agents/s12
    fpc -O2 -Mdelphi -Fu./src -Fu./test \
        -Fu/usr/local/lib/fpc/3.2.4/units/aarch64-darwin/fcl-fpcunit \
        -Futhird_party/mORMot2/src/core -Futhird_party/mORMot2/src/lib \
        -Futhird_party/mORMot2/src/net -Futhird_party/mORMot2/src/crypt \
        -FU/tmp/h2agents/s12 -FE/tmp/h2agents/s12 test/Http2.RunTests.pas
    # probe (a PROGRAM, not the unit runner):
    fpc -O2 -Mdelphi -Fu./src -Fu/tmp/h2agents/s12 \
        -Futhird_party/mORMot2/src/core -Futhird_party/mORMot2/src/lib \
        -Futhird_party/mORMot2/src/net -Futhird_party/mORMot2/src/crypt \
        -FU/tmp/h2agents/s12 -FE/tmp/h2agents/s12 test/h2probe.pas
  Always `export OPENSSL_LIBPATH=/opt/homebrew/opt/openssl@3/lib` to RUN.
  Use a FRESH output dir (rm -rf) per build — fpc -FU silently reuses a stale
  .ppu when one exists.
- DO NOT run `make`. DO NOT `git add`/`git commit`.
- docker is at /Users/liamcoughlin/.rd/bin/docker (add to PATH).
- Baseline suite: 186 tests, 0 errors, 0 failures.

## WHAT IS ALREADY TRUE (verified by the parent — do not redo)
- `nghttpd` 1.70.0 installed at /opt/homebrew/bin. TLS on 8080 already proven:
    nghttpd 8080 test/certs/localhost.key test/certs/localhost.crt \
        --echo-upload -d /tmp/nghttpd-root
  test/certs/localhost.{crt,key} exist (CN=localhost, SAN DNS:localhost,IP:127.0.0.1).
  A live GET and POST (echo) both PASS today.
- Docker image `h2-test-harness` is ALREADY BUILT locally (source in
  third_party/h2-client-test-harness). `docker run --rm h2-test-harness --list`
  prints the case ids.
- HARNESS WIRE FACTS (read from its source — trust these):
  * Server listens TLS on 127.0.0.1:8080, ALPN "h2".
  * It generates cert.pem IN THE CONTAINER with
      openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem \
        -days 365 -subj /CN=localhost
    => CN only, NO subjectAltName. TLS hostname verification WILL fail for
    both `localhost` and `127.0.0.1`. The probe MUST run with peer
    verification OFF. TTlsSocket has an `AInsecure` dial flag but the public
    factory has no way to set it yet — see "REPORTED SEAM" below.
  * Protocol: read client preface, read client's initial SETTINGS, write
    server SETTINGS, then run the case (sending crafted frames), then exit
    after ONE connection. Any number of frames may be sent; the client must
    keep reading until the case is decided.
  * Verifier semantics (what "pass" means), from verifier/verifier.go:
      ExpectSuccessfulRequest  -> client GETs https://127.0.0.1:8080, gets a
                                  200 response, and keeps the connection open.
      ExpectConnectionError(s) -> client's request FAILS (any error), and the
                                  error text contains one of the expected
                                  tokens.
      ExpectStreamError(code)  -> client's request fails with a STREAM error
                                  of the given HTTP/2 code.
    So a case is PASSED when OUR client exhibits the same OUTCOME CLASS.
  * Invocation (one case at a time), from test-runner.sh:
      docker run --rm -p 8080:8080 h2-test-harness --harness-only --test=<id>
    Note --harness-only requires the test id as the following argv element.
    The container is long-running (server), so start it detached, run the
    probe, then kill it.

## DELIVERABLE 1 — test/h2probe.pas (single-shot conformance probe CLI)
A small program that:
- takes a URL and a few options, e.g.
    h2probe --url=https://127.0.0.1:8080/ [--insecure] [--method=GET]
            [--body=...] [--timeout-ms=N] [--keep-open-ms=N]
- builds a client, performs ONE request, and maps the OUTCOME to an exit code
  that distinguishes the three verifier classes:
    0 = success (HTTP 200)          (ExpectSuccessfulRequest)
    2 = connection-level error      (ExpectConnectionError)
    3 = stream-level error          (ExpectStreamError; print the error code)
    1 = anything else / usage error
  Print a machine-readable single line to stdout, e.g.
    `RESULT=success status=200` or
    `RESULT=conn-error class=EHttpProtocolError code=PROTOCOL_ERROR msg=...` or
    `RESULT=stream-error code=CANCEL msg=...`
  This line is what the runner parses. Use EHttpError.ErrorCode /
  Http2ErrorCodeName / the exception CLASS to classify. EHttpStreamError
  carries StreamId; a RST_STREAM case should surface as a stream error.
- `--keep-open-ms` lets the probe linger after the response so the harness can
  finish writing (some cases send frames only after the request).
- MUST NOT hang: enforce the timeout and exit.

## DELIVERABLE 2 — tools/validate/ runner scripts
- `tools/validate/interop.sh` — plan/validation.md §A:
  start nghttpd (TLS) on 8443 with test/certs, run the A.1..A.9 cases, print a
  PASS/FAIL table, exit 0 only when all mandatory cases pass. Include the
  live GET/POST/HEAD/large-response/concurrency/GOAWAY/ALPN cases. Where a
  case needs client features that do not exist yet, mark it SKIP with a
  one-line reason and do NOT silently pass it.
- `tools/validate/harness.sh` — plan/validation.md §B:
  for each id from `docker run --rm h2-test-harness --list`:
    start the container detached with that id, wait for the port, run
    `h2probe --insecure`, classify, record id->outcome, stop the container.
  Print a summary table and write the full results to
  `plan/validation-results.md` (one row per id: id, outcome, error, note).
  A case is PASS when the probe's outcome class matches the case's
  expectation. You do NOT have the expectation per id in machine form, so:
  derive it by reading third_party/h2-client-test-harness/harness/harness.go
  (registry) + harness/cases/*.go + verifier/cases/*.go, and encode an
  expectations table in the script. Where the expectation is genuinely
  ambiguous, mark the case UNKNOWN and list it separately — do not guess PASS.
- Make both scripts re-runnable and independent of the repo's build state
  (they may invoke fpc in a temp dir).

## DELIVERABLE 3 — plan/validation.md results
APPEND (do not rewrite) a "## Results" set of sections under A/B/C/E:
- exact commands run, the pinned revisions (harness git rev, nghttpd version),
- the interop table with real outcomes,
- the harness results table: total ids, passed, failed (list every failed id
  with the raw probe output), skipped/unknown with justification,
- §C ported intents: map each upstream client intent to the unit test that
  now covers it (S11 scripts + existing tests); list any intent NOT covered,
- §E oracle: run `nghttp -nv https://localhost:8443/` and record the frame
  dump notes; state what our frame sequence matched and what was not compared,
- a candid "what is NOT validated" section.

## MANDATORY: HONESTY ABOUT THE RESULT
Do NOT claim a green ladder if it is not green. If many of the 146 cases fail,
that IS the result — report it precisely, with the failing ids and reasons,
and say what client capability each failure needs. A truthful partial result
is worth far more than a fabricated pass. Explicitly state which cases you
could not run and why.

## NON-VACUITY / SANITY CHECKS (required)
1. Prove the harness actually exercises our client: run a case that should
   FAIL (e.g. temporarily point h2probe at the wrong port, or run a case the
   client genuinely mishandles) and show it is reported as a failure — i.e.
   the runner is not reporting PASS unconditionally.
2. Prove the classification works: fabricate a connection-level failure
   (unreachable port) and a stream-level failure if you can (RST_STREAM case)
   and show the probe returns exit 2 vs 3 respectively.
3. `--list` count must match the number of rows in your results table.
Report the exact evidence for each.

## REPORT BACK
1. Exact command lines and the pinned revisions.
2. The interop table (real outcomes) and the harness summary counts.
3. The full list of failing/unknown case ids with one-line reasons.
4. The sanity-check evidence from the three checks above.
5. Any source seam you need (see below) and any client capability gap the
   validation exposed, ranked.
6. What you could NOT run.

## INSECURE-TLS SEAM — NOW AVAILABLE (I just added it)
The factory-level toggle you need now exists:
    THttpClientFactory.Create.WithInsecureTls(True).Build
`WithInsecureTls(const AInsecure: Boolean = True)` disables peer certificate
verification (it composes with `WithCACertFile`). Use it for the harness
probe; the harness cert has no SAN so verification must be off.
`WithSocketFactory` + `TTlsSocket.Dial(host, port, True, timeout)` also still
works if you prefer to construct the socket yourself. Do NOT edit
src/Http2.Client.pas — if you need another source change, report it.
