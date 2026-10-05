---
title: "S11 — Observability and test seams"
story-id: "11"
aliases:
  - "S11"
  - "observability"
tags:
  - http2client
  - plan
  - story
status: ready
up: "[[http2client]]"
depends-on:
  - "09-public-api"
  - "01-errors-frames"
parallel-with:
  - "10-redirects-timeouts"
updated: 2026-10-05
---

# S11 — Observability and test seams

## Goal

Add the interfaces that make the stack testable without a network and
observable in production: `IHttp2Observer`, a recording/mock `IHttp2Socket`,
frame-level assertions, and `fpcunit` integration. Spec:
[`../../doc/design/testing-observability.md`](../../doc/design/testing-observability.md).

## Tasks

| ID | Description | Files touched | Deliverable | Acceptance | Depends on |
|---|---|---|---|---|---|
| 11.1 | `IHttp2Observer` | `src/Http2.Observer.pas` | events: connection open/close/goaway, stream open/close, frame sent/received, HPACK table update, window update, error | test observer receives events | 01.1 |
| 11.2 | Recording socket | `test/Http2.MockSocket.pas` | `IHttp2Socket` impl that feeds canned inbound bytes and captures outbound bytes | test | 05.1 |
| 11.3 | Frame-level assertions | idem | helpers to assert the exact outbound frame sequence | test | 11.2, 01.5 |
| 11.4 | Scripted scenarios | idem | reusable scripts: normal GET, multiplex, GOAWAY, RST, zero-window, malformed | test | 11.3 |
| 11.5 | `fpcunit` wiring | `test/Http2.TestRunner.pas` | all tests registered; opt-in integration tests gated by an env var | `make test` green | 00.8 |
| 11.6 | HPACK property tests | `test/Http2.Hpack.Property.pas` | randomized header sets round-trip | green | 03.7 |
| 11.7 | Concurrency tests | `test/Http2.Concurrency.Test.pas` | N concurrent `Send`s over one mock connection, no data races | green | 09.7 |
| 11.8 | Oracle hook | `test/Http2.NghttpOracle.pas` | optional: dump our frame sequence and compare to `nghttp -nv` output | documented procedure | 11.3 |

## Unit tests

- Everything above is itself the test seam; ensure the mock socket can
  reproduce every scenario S12.C ports from `http2/http2-test`.

## Done when

- No protocol test needs a real socket.
- Concurrency tests are deterministic and race-free.
- The mock socket can drive the full `Send` path to completion.
