---
title: "Testing & Observability"
aliases:
  - "testing-observability"
tags:
  - http2client
  - design
  - testing
status: draft
up: "[[http2client]]"
related:
  - "[[architecture]]"
  - "[[protocol]]"
  - "[[transport]]"
updated: 2026-10-05
---

# Testing & Observability

- **Seams:** `THpackCodec` and `TWindow` are pure enough to unit-test in
  isolation. `IHttp2Socket` has a mock implementation (an in-memory duplex
  of `TFrame`s) so the whole connection loop runs without a socket.
- **FPC test framework:** either `fpcunit` or the repo's existing
  `TTestCase` harness; property tests for HPACK round-trips
  (`Decode(Encode(H)) = H`), window arithmetic, and frame serialization.
- **Observability hooks:** an `IHttp2Observer` interface set on the factory
  receives connection open/close, stream open/close, frames in/out, window
  updates, retries, and discarded frames.
- **Concurrency tests:** many threads calling `Send` against a slow
  streaming server to prove `MaxConnections`/stream-cap accounting and that
  backpressure throttles instead of buffering.
