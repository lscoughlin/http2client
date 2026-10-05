---
title: "S12 — Validation against external suites"
story-id: "12"
aliases:
  - "S12"
  - "validation"
tags:
  - http2client
  - plan
  - validation
status: ready
up: "[[http2client]]"
depends-on:
  - "10-redirects-timeouts"
  - "11-observability"
parallel-with: []
updated: 2026-10-05
---

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

Acceptance command: `make validate-interop` (wraps the above) exits 0.

**Result (2026-10-05): `PASS=8 FAIL=0 SKIP=1` → `RESULT: interop gate GREEN`.**
A.1–A.7 and A.9 PASS; **A.8 is SKIP**. A.3 was closed by adding a
`--body-writer` mode to `test/h2probe.pas` (`TChunkWriter`, 7-byte chunks)
and a matching `run_probe ... --body-writer=...` case in `interop.sh`. A.7
exposed and fixed a real client bug — see the S12 note below. A.8 has no
nghttpd trigger to force a mid-flight GOAWAY; the same semantics are covered
by unit tests (`TStreamLease.OnConnectionGoAway` sets
`FRetryable := FStreamId > ALastStreamId`; `TestGoAwayNotifiesEveryStream`
in `test/Http2.ConnectionLifecycle.Test.pas`).

**A.7 found a real bug: flow control was never wired.** `TFlowControl` was
implemented and unit-tested but referenced by no runtime code, so the client
never returned window credit after receiving DATA; a 100 KB response stalled
at the 65535-byte initial window with `EHttpTimeout`. The fix lives in
`src/Http2.Connection.pas` (`TrackReceivedData` / `SendWindowUpdate`, batched
at `cWindowUpdateBatchSize = 32768`) and is documented in
`doc/design/flow-control.md` under "Validation finding (S12)".

## B. h2-client-test-harness (primary conformance)

```sh
docker run --rm h2-test-harness --list                  # enumerate 146 ids
docker run --rm -p 8080:8080 h2-test-harness \
  --harness-only --test=6.5/1                            # one case, server up
test/h2probe --insecure https://localhost:8080/          # our single-shot client
```

| ID | Case | Expected |
|---|---|---|
| B.1 | Case runner | a single-shot client CLI `test/h2probe` issues one request and exits with a status encoding the observed outcome. |
| B.2 | All 146 ids | run every case; record pass/fail; justify every skip. |
| B.3 | Protocol-error cases | client detects violation and closes with the correct error code. |
| B.4 | Compliance cases | client handles the edge-case frame and keeps the connection. |
| B.5 | HPACK cases | compression/dynamic-table cases pass. |

Acceptance: a results table in this file with counts and the failing id list
(empty = green) at the pinned harness revision.

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

Intents verified present by grep on 2026-10-05; each maps a draft-09 client
intent onto the equivalent RFC 7540/7541 unit test. The draft-09 wire details
differ (different preface/ALPN, no mandatory TLS), so the *intent* is ported,
not the bytes.

| ID | Legacy raw run (stretch) | Condition |
|---|---|---|
| C.6 | `grunt mochaTest:client` with `HTTP2_BROWSER=test/testclient` | **Not run.** The suite speaks draft-09 plaintext `h2c`, and the shipped client is TLS-only: there is no `h2c`/prior-knowledge upgrade path in `src/` (`grep` finds only the TLS preface `cClientPreface` in `src/Http2.Connection.pas`). Running it therefore cannot exercise our code, and a green result would not be evidence of RFC 7540 conformance. Recorded as a documented skip. |

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
| Unit suite | 247 tests, 0 errors, 0 failures |

Skips, each with its reason: **A.8** (no nghttpd GOAWAY trigger; covered by
unit tests), **C.6** (draft-09 plaintext `h2c`; client is TLS-only), **D**
(h2spec is server-conformance only). No conformance claim rests on the
draft-09 suite.

## Done when

- A exits 0 on a real TLS ALPN connection.
- B has a complete, justified results set for all 146 ids.
- C intents exist as unit tests; any raw-suite skip is documented.
- E comparison notes exist for at least one request.
- No claim of conformance rests on the draft-09 suite.
