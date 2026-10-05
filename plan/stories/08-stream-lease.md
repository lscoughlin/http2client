---
title: "S08 — Stream lease state machine"
story-id: "08"
aliases:
  - "S08"
  - "stream-lease"
tags:
  - http2client
  - plan
  - story
status: done
up: "[[http2client]]"
depends-on:
  - "07-connection-lifecycle"
  - "02-headers"
  - "03-hpack"
  - "04-flow-control"
  - "05-tls-alpn-socket"
parallel-with: []
updated: 2026-10-05
---

# S08 — Stream lease state machine

## Goal

Implement one request/response exchange: stream-id allocation, request frame
emission, response framing, and stream state transitions. Spec:
[`../../doc/design/client-api.md`](../../doc/design/client-api.md) §Lease
acquisition and
[`../../doc/design/messages.md`](../../doc/design/messages.md) §Request and
response streaming.

## Tasks

| ID | Description | Files touched | Deliverable | Acceptance | Depends on |
|---|---|---|---|---|---|
| 08.1 | Stream-id allocation | `src/Http2.Stream.pas` | odd client ids, monotonic, guarded by connection `TCriticalSection` | concurrency test: no duplicates | 07.7 |
| 08.2 | `TStreamLease` | idem | `FStreamId`, `FOutbound`/`FInbound` queues, `FResponseState` | created/cleaned per request | 08.1 |
| 08.3 | HEADERS emission | idem | pseudo-headers + regular headers via HPACK; `END_HEADERS`/`END_STREAM` | encode/decode round-trip | 08.2, 03.7 |
| 08.4 | Request body | idem | `THttpBody` → DATA frames; `IBodyWriter` pulled by the connection thread until `False` | streaming test | 08.3, 04.2 |
| 08.5 | Response assembly | idem | HEADERS → status+headers available; DATA → body stream; `END_STREAM` closes body | test | 08.3 |
| 08.6 | `Eof` semantics | idem | bodyless/`204`/`304`/`HEAD` → immediate `Eof`; read-after-EOF raises deterministically | test | 08.5 |
| 08.7 | RST_STREAM | idem | mid-body reset surfaces from `Read`, not from `Send`; maps code to `EHttpStreamError` | test | 08.5 |
| 08.8 | Half-closed states | idem | client can finish sending while still receiving; state machine rejects invalid transitions | transition matrix test | 08.5 |
| 08.9 | Cleanup | idem | lease released on response completion/reset/connection failure exactly once | leak test | 08.6, 07.6 |

## Unit tests

- `test/Http2.Stream.Test.pas` — id allocation under concurrency, HEADERS
  round-trip, streaming upload, bodyless responses, RST mapping, invalid
  transition rejection, exactly-once cleanup.

## Done when

- A single lease completes end-to-end over a mocked connection.
- Stream state transitions match RFC 7540 §5.1 and invalid ones raise.
- No stream leaks its queue or response state.
