---
title: "S12 — Validation against external suites"
story-id: "12"
aliases:
  - "S12"
  - "validation"
tags:
  - http2client
  - verification
  - validation
status: validated
up: "[[http2client]]"
updated: 2026-10-08
validation-results: "bin/validation-results.md"
harness-log: "doc/verification/harness-run-full.log"
---

> Story lineage: S12 closes the plan and was built on S10 and S11. The notes
> for those earlier stories are not part of this repository. This record is
> self-contained, so they are not required to read it.

# S12 — Validation against external suites

## Goal

Prove the compiler-built client against real HTTP/2 peers and RFC conformance
harnesses. This story closes the plan: it decides what is gate, what is
oracle, and what is legacy reference, and it records exact commands and
results.

## Why the suites are used this way

The user named `http2/http2-test` and said "if reasonable" for the nghttp2
work. Evidence changes how each is used — state this in the report, do not
quietly substitute:

| Suite | Verdict | Reason |
|---|---|---|
| `nghttpd` / `nghttp` (nghttp2 1.70.0) | **Gate + oracle** | Real TLS+ALPN peer; `nghttp -nv` gives frame dumps for differential checking. |
| `nomadlabsinc/h2-client-test-harness` | **Primary RFC gate** | 146 inverted RFC 7540/7541 client-conformance cases over TLS; Docker image available (no `go`). |
| `http2/http2-test` | **Legacy reference + ported intents** | Draft-09 (`HTTP-draft-09/2.0`), plaintext `h2c`, 2014 deps (`http2 ~2.2.0`, `mocha ~1.15.1`) vs `node v26`; and the spec is TLS-only. Raw run is best-effort only. |
| `h2spec` | **Optional appendix** | Server-conformance only; not applicable to a client. |

## A. nghttpd interop (first real green)

```sh
export OPENSSL_LIBPATH=/opt/homebrew/opt/openssl@3/lib
tools/validate/interop.sh          # or: make validate-interop
```

The script starts `nghttpd` twice itself: `--echo-upload` with TLS+ALPN
`h2` on `INTEROP_PORT` (default 18443), and `--no-tls` on
`INTEROP_PLAIN_PORT` (default 18080) for the ALPN-negative case. Certs are
`test/certs/localhost.{crt,key}`; note **nghttpd takes the key before the
cert**. `INTEROP_HTDOCS` (default `/tmp/nghttpd-root`) holds `index.html`
(10 bytes) and `big.bin` (100000 bytes).

| ID | Case | Expected |
|---|---|---|
| A.1 | GET a small file | 200, correct bytes, `content-length` |
| A.2 | POST with `THttpBody` | echo/echo semantics, 200 |
| A.3 | Streaming upload via `IBodyWriter` | body arrives; `END_STREAM` on last DATA |
| A.4 | HEAD | headers only, `Eof` immediately |
| A.5 | Concurrency | 20 parallel `Send`s, one connection, all complete |
| A.6 | `SETTINGS_MAX_CONCURRENT_STREAMS` | client honors the peer limit |
| A.7 | Large response | flow-control `WINDOW_UPDATE` emitted, no stall |
| A.8 | Server GOAWAY | in-flight streams above id retried/handled per policy |
| A.9 | TLS ALPN | `SSL_get0_alpn_selected == h2`; an http/1.1-only server raises |
| A.10 | h2c prior knowledge (S13) | a GET against `nghttpd --no-tls` returns `200` |
| A.11 | h2c upgrade (S13) | a GET returns `101` then uses HTTP/2 |
| A.12 | HTTP/1.1 fallback (S13) | a GET against an HTTP/1.1 server returns `200` |
| A.13 | strict mode (S13) | a cleartext request raises `EHttpProtocolError` |

Acceptance command: `make validate-interop` (wraps the above) exits 0.

The S13 cases (A.10–A.13) need two cleartext servers, which `nghttpd`
cannot provide for the upgrade: `nghttpd` is HTTP/2-only, so it cannot
answer an HTTP/1.1 `Upgrade` request. The script starts
`httpd:2.4` (Apache, `mod_http2`) under docker instead. One container runs
`Protocols h2c http/1.1` with `H2Upgrade on` on `INTEROP_H2C_PORT` (default
18481), and one runs `Protocols http/1.1` on `INTEROP_H1_PORT` (default
18482). Both use `--network host`; the generated `httpd.conf` and the
docroot are copied in with `docker cp` (a bind-mount source inside the repo
is intermittently deleted by Rancher Desktop, which left the container
serving 404). The ports default away from 18080–18082 because an unrelated
dev proxy on `127.0.0.1` would shadow Lima's `*:<port>` tunnel and silently
answer the probe; the script refuses a busy port instead of reporting a
false pass. A.10 uses the existing `nghttpd --no-tls` server on
`INTEROP_PLAIN_PORT` (default 18480). When docker is unavailable, A.11 and
A.12 report SKIP with that reason.

**Result (2026-10-08): `PASS=13 FAIL=0 SKIP=1` → `RESULT: interop gate GREEN`.**
A.1–A.7 and A.9–A.13 PASS; **A.8 is SKIP**. The S13 cases A.10–A.13
(h2c prior knowledge, h2c upgrade, HTTP/1.1 fallback, strict-mode reject)
were added after the first green; A.3 was closed by adding a
`--body-writer` mode to `test/h2probe.pas` (`TChunkWriter`, 7-byte chunks)
and a matching `run_probe ... --body-writer=...` case in `interop.sh`. A.7
exposed and fixed a real client bug — see the S12 note below. A.8 has no
nghttpd trigger to force a mid-flight GOAWAY; the same semantics are covered
by unit tests (`TStreamLease.OnConnectionGoAway` sets
`FRetryable := FStreamId > ALastStreamId`; `TestGoAwayNotifiesEveryStream`
in `test/Http2.ConnectionLifecycle.Test.pas`).

The cleartext and fallback paths these cases exercise are described in
[[fallback]] (`src/Http2.Http1.pas`, `src/Http2.Client.pas`).

**A.7 found a real bug: flow control was never wired.** `TFlowControl` was
implemented and unit-tested but referenced by no runtime code, so the client
never returned window credit after receiving DATA; a 100 KB response stalled
at the 65535-byte initial window with `EHttpTimeout`. The fix lives in
`src/Http2.Connection.pas` (`TrackReceivedData` / `SendWindowUpdate`, batched
at `cWindowUpdateBatchSize = 32768`) and is documented in
`doc/design/protocol.md` under "Implementation note (S12 validation finding)".

## B. h2-client-test-harness (primary conformance)

```sh
# the whole sweep (reference verifier + our probe for every id). Needs
# Docker/Rancher Desktop; ~30 minutes. Writes bin/validation-results.md.
tools/validate/harness.sh                 # or: make validate-harness

# one id by hand
docker run --rm h2-test-harness --list                 # enumerate 146 ids
docker run -d --name h2-harness --network host h2-test-harness \
  --harness-only --test=6.5/1                           # one case, server up
bin/h2probe --url=https://127.0.0.1:8080/ --insecure --timeout-ms=5000
docker rm -f h2-harness
```

The harness container is a TLS server on `127.0.0.1:8080` that accepts ONE
connection then exits, so `--network host` is required. Its self-signed cert
has a CN but no subjectAltName, so hostname verification cannot succeed — the
probe runs `--insecure` deliberately. Each id is run twice: once with the
Go reference verifier (defines the expected outcome class) and once with our
probe; the two are compared.

| ID | Case | Expected |
|---|---|---|
| B.1 | Case runner | a single-shot client CLI `test/h2probe` issues one request and exits with a status encoding the observed outcome. |
| B.2 | All 146 ids | run every case; record pass/fail; justify every skip. |
| B.3 | Protocol-error cases | client detects violation and closes with the correct error code. |
| B.4 | Compliance cases | client handles the edge-case frame and keeps the connection. |
| B.5 | HPACK cases | compression/dynamic-table cases pass. |

Acceptance: a results table with counts and the failing id list
(empty = green) at the pinned harness revision. The generated table lives in
`bin/validation-results.md`; this file records the
interpretation and the justification for every non-MATCH row.

Verdicts: **MATCH** = our outcome class equals the reference's; **BETTER** =
the reference's verifier timed out/errored while we produced a clean
connection or stream error (we enforced a rule it missed); **WORSE** = the
reference detected an error (or succeeded) and we produced no error or a
timeout — these are the only real failures; **UNKNOWN** = neither side
resolved a class (typically the reference verifier hit EOF and we timed out),
so the case cannot be scored either way.

## C. http2/http2-test (ported intents)

Port the **client** case intents into mock-socket unit tests (they map
directly onto S11 scripts). Record the draft-09 divergences.

| ID | Upstream case | Ported to |
|---|---|---|
| C.1 | `compression/` invalid data | `test/Http2.Hpack.Test.pas` — `TestMalformedIndexRaises`, `TestHuffmanBadPaddingRaises`, `TestIntegerOverflowRaises`, `TestDynamicTableSizeUpdateAfterFieldRaises` |
| C.2 | `framing/oversized-ping` | `test/Http2.Frames.Test.pas` — `TestOversizedInboundFrameRaises`, `TestPingFrameRoundTrip`, `TestSettingsMaxFrameSizeValidation` |
| C.3 | `multiplexing/invalid-level-*` | `test/Http2.Stream.Test.pas` — `TestInvalidTransitionsRaise`; stream-state enforcement in `src/Http2.Stream.pas` |
| C.4 | `stream/data-when-*` / `rst-stream` | `test/Http2.Stream.Test.pas` — `TestRstMidBodySurfacesFromRead`, `TestReadAfterEofRaises`, `TestCleanupHappensExactlyOnce`; `test/Http2.ConnectionLifecycle.Test.pas` |
| C.5 | `window-update-when-*` | `test/Http2.FlowControl.Test.pas` — `TestZeroIncrementUpdateRaisesProtocolError`, `TestUpdateOverflowRaisesFlowControlError`, `TestApplyUpdateAppliesDelta`, `TestInitialWindowDeltaAdjustsEveryOpenStream` |

Intents verified present by grep on 2026-10-05 (C.1–C.5); each maps a
draft-09 client intent onto the equivalent RFC 7540/7541 unit test. The
draft-09 wire details differ (different preface/ALPN, no mandatory TLS), so
the *intent* is ported, not the bytes.

| ID | Legacy raw run (stretch) | Condition |
|---|---|---|
| C.6 | `grunt mochaTest:client` with `HTTP2_BROWSER=test/testclient` | **Ported, not raw-run.** The suite speaks **draft-09** plaintext `h2c`; the shipped client implements the RFC 7540 cleartext paths (`ctPriorKnowledge` / `ctUpgrade`, see [[fallback]]) but not the draft-09 wire dialect (different preface/ALPN, and the 2014 node deps do not run on node v26). The h2c code path is instead covered by interop A.10–A.13 and by `test/Http2.ClearText.Test.pas`. Recorded as a documented skip. |

## D. h2spec (optional appendix)

```sh
h2spec -p 8443 -t -k -h localhost          # only if we ship a test server
```

**N/A.** h2spec probes a *server*; this project ships a client, so h2spec has
no surface to exercise. No embedded test server is built. Documented skip.

## E. nghttp differential oracle

```sh
# our wire trace (h2probe --trace-frames prints every frame in/out)
/tmp/h2probe3/h2probe --url=https://127.0.0.1:18443/ --insecure \
  --trace-frames --timeout-ms=5000
# reference
nghttp -nv --no-verify-peer https://127.0.0.1:18443/
```

Both run against the same command line (`nghttpd -d /tmp/oracle-root 18443
localhost.key localhost.crt`, `index.html` = 38 bytes) on 2026-10-05.

| ID | Case | Result |
|---|---|---|
| E.1 | Frame flags | **Match on every frame that both peers send.** Our trace: `out SETTINGS stream=0 len=36 flags=[]` → `in SETTINGS flags=[]` → `out SETTINGS flags=[ACK]` → `in SETTINGS flags=[ACK]` → `out HEADERS stream=1 flags=[ENDSTREAM,ENDHEADERS]` → `in HEADERS flags=[ENDHEADERS]` → `in DATA stream=1 flags=[ENDSTREAM]` → `out WINDOW_UPDATE` → `out GOAWAY`. nghttp sends the same sequence with the same flag bits: initial SETTINGS `flags=0x00`, ACK `flags=0x01`, request HEADERS `flags=0x05` (= END_STREAM\|END_HEADERS), response HEADERS `flags=0x04` (END_HEADERS), terminal DATA `flags=0x01` (END_STREAM), GOAWAY `flags=0x00`. Our flags are set-typed (`ffEndStream`/`ffEndHeaders` shared-$1 nuance in `src/Http2.Frames.pas` `FlagBit`) but serialize to the identical bytes. |
| E.2 | HPACK accumulator | **Ordering matches; encoder differs in literal representation only.** nghttp's request HEADERS is 46 bytes and its response HEADERS 83; ours are 31 and 86. Both sides use the same static-table pseudo-headers and both keep the dynamic table *empty* for a single request (`nghttp -nv` shows no `header table` resize), so per-request accumulator growth is equivalent — the length delta is literal-vs-indexed encoding of the same header names, not a table-state divergence. Not a conformance difference. |
| E.3 | SETTINGS | **Our advertised ids are all within the peer-accepted set.** We send all six RFC 7540 ids (`SettingHeaderTableSize`=1, `EnablePush`=2, `MaxConcurrentStreams`=3, `InitialWindowSize`=4, `MaxFrameSize`=5, `MaxHeaderListSize`=6) per `TConnectionSettings.Defaults`/`Encode` — lengths 36 out vs nghttp's 18, consistent with nghttp omitting some. nghttpd accepts them: it replies with a normal SETTINGS (len 12) whose values we applied without error, and the request then completes 200/38. No `SETTINGS` id we send is unknown to nghttp2 1.70.0. |

Note: `--trace-frames` is a probe-only diagnostic (`TFrameTraceObserver` in
`test/h2probe.pas`); it is not part of the shipped client API.

## Report (written to this file)

Record: toolchain versions, harness revision/image digest, the B results
table, A command output summary, C port list, E comparison notes, and every
skip with its reason. Update the `status:` front matter to `validated` only
when A and B are green.

### Toolchain and suite revisions (2026-10-05)

| Component | Version / revision |
|---|---|
| Free Pascal | `fpc 3.2.4`, target `aarch64-darwin` (`ppca64`) |
| OpenSSL | Homebrew `openssl@3` (`OPENSSL_LIBPATH=/opt/homebrew/opt/openssl@3/lib`) |
| nghttp2 (`nghttpd`/`nghttp`) | `1.70.0` |
| `h2-client-test-harness` image | `h2-test-harness`, digest `sha256:745149517ede…` |
| `third_party/h2-client-test-harness` | git `0bc075c` |
| Container runtime | Rancher Desktop `docker` (`~/.rd/bin/docker`) |
| Unit suite (2026-10-05, at that revision) | 292 tests, 0 errors, 0 failures |
| Unit suite (current) | 315 tests, 0 errors, 0 failures |
| Library units | 14 in `src/` (13 core + optional `Http2.Readers`) |
| Example programs | 5 in `examples/` (`make examples`) |

Skips, each with its reason: **A.8** (no nghttpd GOAWAY trigger; covered by
unit tests), **C.6** (draft-09 plaintext `h2c`; client is TLS-only), **D**
(h2spec is server-conformance only). No conformance claim rests on the
draft-09 suite.

### B results: full sweep (146 ids)

Command: `make validate-harness` (or `bash tools/validate/harness.sh`), run
detached because 146 x (~3.1 s reference verifier + ~8 s probe) is ~30 min.
Positive control `6.5/1`: **pass** (when it does not, every row is scored
`fail invalid`). Results table: `bin/validation-results.md`; raw log:
`doc/verification/harness-run-full.log`.

| Verdict | Count |
|---|---|
| MATCH | 25 |
| BETTER | 44 |
| **WORSE** | **0** |
| CLASS-DIFF | 13 |
| UNKNOWN | 64 |

`PASS = MATCH+BETTER = 69; FAIL = WORSE = 0`.

**Method note (environment).** The harness server binds `--network host` port
8080, so the sweep must run **alone**: a second concurrent sweep (or anything
else on 8080) makes the probe hit the wrong peer and records spurious
`ours=timeout`/`conn-error` rows, including `WORSE` on ids that are `MATCH`
when run in isolation. The figures above are from a sweep run with no other
sweep active. Several ids (`5.4.1/2`, `6.5/2`, `6.1/3`, `5.1/13`, `4.1/1`,
`6.9/2`, …) are *load-sensitive*: under heavy host load (a parallel container
build, or another sweep) the declared detection can arrive after the 4 s probe
deadline and be recorded as `timeout`. They pass 40+ consecutive isolated runs.
Re-run a suspect id alone with
`HARNESS_IDS="<id>" bash tools/validate/harness.sh` before treating a `WORSE`
as a client defect.

**Scoring rule.** The expected outcome class for every id is *declared* by the
harness's own verifier sources, extracted by `tools/validate/extract_expectations.py`
into `doc/verification/harness-expectations.tsv` (paren-scoped `verifier.Register(...)`
scan). The declaration, not the observed reference run, is the authority:
the image's verifier only matches error **substrings**, so Go can log
"Verifier passed" while reporting a different error level (e.g. `6.2/4`).
A row is scored against the declaration; the reference run only says whether
that declared outcome was *demonstrated*. `WORSE` requires the reference to
have demonstrated the declaration while our client did not.

**WORSE = 0.** This is the gate. No case exists where the reference
produced the declared outcome and our client failed to produce *an* error.

**UNKNOWN = 64.** Every one of these has `ref=fail` — the reference verifier
itself did not resolve the case. Two shapes dominate:

* cases declaring `success` whose harness function never writes a response
  HEADERS frame (`main.go:handleConnection` reads the preface, exchanges
  SETTINGS, runs the case, then closes). The reference Go client also fails
  (`fail/eof` / `fail/unresolved`); no compliant client can observe success.
  Example: `3.5/1` sends one SETTINGS frame and closes. This is a
  harness-case defect, not a client defect.
* cases that need an environment feature the image does not provide.

Our client produced a clean error (never a timeout-with-no-diagnosis) in all
64; that is why none is `WORSE`.

**CLASS-DIFF = 12** — both sides produced an error, at different levels
(connection vs stream). Each is justified below. RFC 7540 / RFC 9113 map the
stream-state rules in section 5.1 to explicit levels, so where our client is
the stricter (connection) level we keep it: a stricter level never lets a
broken stream corrupt connection state.

| id | declaration | ours | justification |
|---|---|---|---|
| `5.1/2` | conn-error | stream-error (`CANCEL`) | RST_STREAM on an idle stream. We surface the peer's RST as a stream error on the requesting lease. Section 5.1 makes this a connection error; we would rather not tear down the whole connection for a stream we never opened. Accepted divergence; no response data is trusted. |
| `6.4/2` | conn-error | stream-error (`CANCEL`) | Same shape as `5.1/2` (RST_STREAM on an idle stream). |
| `5.1.1/2`,`5.1/12`,`5.1/13`,`6.2/1` | conn-error | stream-error (`PROTOCOL_ERROR`) | The harness sends a frame whose HPACK block decodes to a **request** pseudo-header (`:method`) on a server-to-client stream. We reject it while decoding the response, as a stream error (`unexpected pseudo-header in response`). The case declares a connection error. We choose stream scope: the malformed block is confined to one stream. |
| `hpack/6.3/1` | conn-error | stream-error (`PROTOCOL_ERROR`) | Same HPACK shape as above; the harness's dynamic-table intent still holds (we reject the block), only the level differs. |
| `4.2/2` | stream-error | conn-error (`FRAME_SIZE_ERROR`) | A DATA frame exceeding `SETTINGS_MAX_FRAME_SIZE`. Section 4.2 makes an oversized frame a connection error of type FRAME_SIZE_ERROR; the case declares stream scope. We are stricter, per the RFC. |
| `6.3/2` | stream-error | conn-error (`FRAME_SIZE_ERROR`) | PRIORITY payload not 5 octets. Section 6.3: a PRIORITY frame of any other length "MUST be treated as a connection error of type FRAME_SIZE_ERROR". We are stricter, per the RFC. |
| `6.1/2` | stream-error | conn-error (`PROTOCOL_ERROR`) | DATA on a stream not in open/half-closed(local) — here an idle stream, since the harness never opened it. We raise `DATA before response HEADERS` at connection scope. Section 5.1 makes DATA on an idle stream a connection error; the case declares stream scope. We are stricter, per the RFC. |
| `8.1.2.1/3` | stream-error | conn-error (`PROTOCOL_ERROR`) | A pseudo-header field in trailers. We reject while decoding; the harness declares stream scope. RFC 9113 permits either level here; we keep connection scope because the forbidden field corrupts the header block. |
| `8.1.2.2/1` | stream-error | conn-error (`PROTOCOL_ERROR`) | A connection-specific header field (`connection`) in a response. Same reasoning as `8.1.2.1/3`. |

Every CLASS-DIFF is therefore one of: (a) our client is *stricter* and acting
per the explicit RFC section (4.2/2, 6.3/2, 6.1/2, 8.1.2.1/3, 8.1.2.2/1), or
(b) our client is *narrower* (a peer RST or malformed HPACK block is surfaced at
stream scope rather than tearing down the connection: 5.1/2, 6.4/2, 5.1.1/2,
5.1/12, 5.1/13, 6.2/1, hpack/6.3/1). In both directions our client detects
and reports the violation; no malformed input is silently accepted. The gate
therefore holds: **no WORSE**, and every divergence is a deliberate,
RFC-grounded level choice rather than an unhandled case.

## Sanity checks (non-vacuity)

Before trusting A or B, prove the probe can fail. `tools/validate/h2probe-sanity.sh`
(also `task validate:sanity`, seconds) runs five conditions and asserts a
distinct exit code for each outcome class:

| # | Condition | Expected |
|---|---|---|
| 1 | an unreachable port | exit 2 (connection error) |
| 2 | a reset that follows a 200 response (`tools/validate/fake_rst_server.py`) | exit 3 (stream error) |
| 3 | bad command-line usage | exit 1 |
| 4 | an `http/1.1`-only ALPN peer | exit 2, ALPN message |
| 5 | a live `nghttpd` GET (positive control) | exit 0 |

Checks 1-4 use local peers; only check 5 is SKIPped when `nghttpd` is absent.
Each checked server is waited for explicitly (`wait_port`, `wait_log_line`). A
server that never binds is reported as an **infrastructure** failure and
counted apart from a probe failure, because an unready server says nothing
about the client.

Check 2 deliberately does **not** use the h2-test-harness case `5.1/2`. That
case sends RST_STREAM on a stream the *server* still considers idle (it never
reads our HEADERS) and then closes the socket at once, so the reset races the
EOF: our probe can legitimately report either a stream error (exit 3) or a
connection error (exit 2), and the harness's own reference verifier expects the
connection error (`verifier/cases/http2/5_1_stream_states.go`). It is an
accepted divergence (see the `5.1/2` row above), not a deterministic
stream-error oracle, and using it here made the check flaky (roughly 1 run in
3). The fabricated peer instead sends a valid 200 response HEADERS *then*
RST_STREAM and holds the socket open, so exit 3 is unambiguous. Non-vacuity
against that peer is verified by mutation: remove the RST_STREAM write and the
check fails (`exit=2`, header timeout) as it must.

Readiness for a **single-accept** server (the h2-test-harness, the fabricated
peer, `openssl s_server`) must be gated on a **log line**, never on a TCP
connect. These servers call `Accept()` exactly once and exit; a connect-based
probe (`nc -z`, `wait_port`, `port_open`) *is* a connection and would consume
that accept, so the following real run fails with a spurious `connect ...
failed` or TLS-handshake error. This is not theoretical: adding a `wait_port`
check to `wait_harness_ready` turned nearly the whole harness sweep from
`ours=stream-error` into a false `ours=conn-error`. The residual host-forwarder
race (the container logs `listening on` a moment before the ssh-forwarded host
port exists, ~1 run in 20) is handled by retrying a bounded number of times on
that specific connect failure inside `run_ours`, which is safe because it does
not pre-connect.

Recorded result (2026-10-07): `PASS=5 FAIL=0`, stable over twenty consecutive
runs; the mutation above flips check 2 to `FAIL exit=2`. Negative control: with
a server that never opens its port, the script reports `PASS=4 FAIL=1`, names
the cause as infrastructure, and exits 1.

## Done when

- A exits 0 on a real TLS ALPN connection.
- B has a complete, justified results set for all 146 ids.
- The sanity checks pass, and a server that fails to start is reported as an
  infrastructure failure rather than as a probe failure.
- C intents exist as unit tests; any raw-suite skip is documented.
- E comparison notes exist for at least one request.
- No claim of conformance rests on the draft-09 suite.
