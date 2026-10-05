---
title: "S04 — Flow control"
story-id: "04"
aliases:
  - "S04"
  - "flow-control"
tags:
  - http2client
  - plan
  - story
status: ready
up: "[[http2client]]"
depends-on:
  - "01-errors-frames"
parallel-with:
  - "02-headers"
  - "03-hpack"
  - "05-tls-alpn-socket"
updated: 2026-10-05
---

# S04 — Flow control

## Goal

Implement connection- and stream-level flow-control accounting and batched
`WINDOW_UPDATE` emission. Spec:
[`../../doc/design/protocol.md`](../../doc/design/protocol.md) §Flow control.

## Tasks

| ID | Description | Files touched | Deliverable | Acceptance | Depends on |
|---|---|---|---|---|---|
| 04.1 | `TWindow` record | `src/Http2.FlowControl.pas` | send/recv window counters per connection and per stream | arithmetic tests | 01.1 |
| 04.2 | DATA consumption | idem | sending DATA decrements the send window; receiving DATA decrements the recv window | test | 04.1 |
| 04.3 | `WINDOW_UPDATE` handling | idem | apply delta; detect overflow past 2^31−1 → `FLOW_CONTROL_ERROR` | overflow test | 04.2 |
| 04.4 | Batching threshold | idem | emit `WINDOW_UPDATE` only once consumed ≥ half the window (or on stream end) | test asserts no update below threshold | 04.2 |
| 04.5 | Zero-window blocking | idem | a stream with a zero send window blocks its DATA, not the connection | test | 04.3 |
| 04.6 | Settings interaction | idem | peer `SETTINGS_INITIAL_WINDOW_SIZE` change adjusts all open streams by the delta | test | 04.3 |

## Unit tests

- `test/Http2.FlowControl.Test.pas` — window arithmetic, overflow,
  initial-window change deltas, batching, per-stream vs connection isolation.

## Done when

- Stream blocking does not stall other streams on the same connection.
- Overflow and invalid `WINDOW_UPDATE` deltas raise the correct error.
