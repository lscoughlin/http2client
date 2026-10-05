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
nghttpd -d /tmp/h2root --no-tls 8080            # sanity only
nghttpd -d /tmp/h2root -n test/certs 8443       # TLS + ALPN h2 (gate)
test/testclient https://localhost:8443/         # uses insecure test mode
```

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
| C.1 | `compression/` invalid data | `test/Http2.Hpack.Test.pas` malformed-input cases |
| C.2 | `framing/oversized-ping` | `test/Http2.Frames.Test.pas` size enforcement |
| C.3 | `multiplexing/invalid-level-*` | stream-state transition tests (S08) |
| C.4 | `stream/data-when-*` / `rst-stream` | stream lifecycle tests (S08) |
| C.5 | `window-update-when-*` | flow-control tests (S04) |

| ID | Legacy raw run (stretch) | Condition |
|---|---|---|
| C.6 | `grunt mochaTest:client` with `HTTP2_BROWSER=test/testclient` | Only if the draft-09 plaintext path is exercised via an explicit `h2c` opt-in; otherwise document as not run and why. |

## D. h2spec (optional appendix)

```sh
h2spec -p 8443 -t -k -h localhost          # only if we ship a test server
```

Not a client gate. Record as N/A unless an embedded test server is built.

## E. nghttp differential oracle

```sh
nghttp -nv https://localhost:8443/ > /tmp/nghttp.frames
```

| ID | Case | Expected |
|---|---|---|
| E.1 | Frame flags | our outbound HEADERS/DATA flags match nghttp's for the same request. |
| E.2 | HPACK accumulator | encoded size growth/table updates match after a header sequence. |
| E.3 | SETTINGS | our SETTINGS ids/values are within the peer-accepted set. |

## Report (written to this file)

Record: toolchain versions, harness revision/image digest, the B results
table, A command output summary, C port list, E comparison notes, and every
skip with its reason. Update the `status:` front matter to `validated` only
when A and B are green.

## Done when

- A exits 0 on a real TLS ALPN connection.
- B has a complete, justified results set for all 146 ids.
- C intents exist as unit tests; any raw-suite skip is documented.
- E comparison notes exist for at least one request.
- No claim of conformance rests on the draft-09 suite.
