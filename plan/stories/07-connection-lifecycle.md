---
title: "S07 — Connection lifecycle"
story-id: "07"
aliases:
  - "S07"
  - "connection-lifecycle"
tags:
  - http2client
  - plan
  - story
status: ready
up: "[[http2client]]"
depends-on:
  - "06-queue-connection-thread"
parallel-with: []
updated: 2026-10-05
---

# S07 — Connection lifecycle

## Goal

Implement the connection state machine: preface + SETTINGS exchange, PING
keep-alive, GOAWAY draining, and graceful/abrupt shutdown. Spec:
[`../../doc/design/transport.md`](../../doc/design/transport.md) §Connection
lifecycle.

## Tasks

| ID | Description | Files touched | Deliverable | Acceptance | Depends on |
|---|---|---|---|---|---|
| 07.1 | Client preface | `src/Http2.Connection.pas` | send `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` then SETTINGS | bytes asserted against spec | 06.5 |
| 07.2 | SETTINGS exchange | idem | apply peer settings, ack peer SETTINGS, enforce peer max streams/frame size | test exchange | 07.1, 04.6 |
| 07.3 | PING keep-alive | idem | periodic PING, ack incoming PING, detect missing ack → `EHttpConnectionClosed` | test | 07.2 |
| 07.4 | GOAWAY handling | idem | mark streams above `last-stream-id` as retryable (they **may** be retried); initiate close for this connection | test | 07.2 |
| 07.5 | Graceful shutdown | idem | `Close` sends GOAWAY (last stream = highest processed), drains, then closes socket | test | 07.4 |
| 07.6 | Abrupt failure | idem | socket EOF/reset → fail all in-flight streams with `EHttpConnectionClosed` | test | 07.2 |
| 07.7 | State exposure | idem | lifecycle state (`opening/open/goaway/closed`) readable for pool eligibility | test | 07.1 |

## Unit tests

- `test/Http2.ConnectionLifecycle.Test.pas` — preface bytes, SETTINGS
  ack, GOAWAY may-retry set, shutdown ordering, abrupt-failure fan-out.
- Uses the recording/mock socket from S11 where available; otherwise a local
  fake.

## Done when

- Preface and SETTINGS exchange are byte-exact.
- GOAWAY correctly distinguishes retryable (above id) from non-retryable
  streams, using the "may retry" wording from the spec.
- Every in-flight stream is terminated exactly once on connection failure.
