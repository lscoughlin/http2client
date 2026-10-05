---
title: "S06 — Blocking queue and connection thread"
story-id: "06"
aliases:
  - "S06"
  - "queue-connection-thread"
tags:
  - http2client
  - plan
  - story
status: ready
up: "[[http2client]]"
depends-on:
  - "01-errors-frames"
parallel-with: []
updated: 2026-10-05
---

# S06 — Blocking queue and connection thread

## Goal

Build the producer/consumer primitives the connection is built from:
`TBlockingQueue<T>` (since FPC 3.2.4 has no `TThreadedQueue<T>`) and the
connection thread skeleton with its two frame queues. Spec:
[`../../doc/design/transport.md`](../../doc/design/transport.md) §Threading
and queues.

## Tasks

| ID | Description | Files touched | Deliverable | Acceptance | Depends on |
|---|---|---|---|---|---|
| 06.1 | `TBlockingQueue<T>` | `src/Http2.Connection.pas` | `TQueue<T>` + `TCriticalSection` + two `RTLEvent`s (`Push`, `Pop`, `TryPop`, `Shutdown`) | consumer test drains 100 items, sum 5050 | 01.1 |
| 06.2 | Shutdown semantics | idem | `Shutdown` wakes all blocked waiters; later `Pop` returns false | blocked consumer released | 06.1 |
| 06.3 | Bounded option | idem | optional capacity for backpressure (producer waits when full) | test | 06.1 |
| 06.4 | `IBlockingQueue<T>` | idem | interface form (ARC-safe) | test | 06.1 |
| 06.5 | Thread skeleton | idem | `TConnectionThread` with weak `FConn: Pointer`, `FOutbound`/`FInbound` queues, `Terminate`/`WaitFor` | thread starts/stops cleanly | 06.2 |
| 06.6 | Sole-writer invariant | idem | only the thread calls `socket.Write`; callers only enqueue | test injects a recording socket and asserts single writer | 06.5 |
| 06.7 | Error propagation | idem | an exception on the thread moves the connection to failed state and unblocks waiters | test | 06.5 |

## Unit tests

- `test/Http2.BlockingQueue.Test.pas` — ordering, blocking, shutdown,
  backpressure, concurrent producers.
- `test/Http2.ConnectionThread.Test.pas` — single-writer assertion, clean
  stop, error propagation.

## Done when

- Queue primitives are free of `TThreadedQueue`/`TMonitor`/`TEvent`.
- The thread holds only a weak connection reference (no ARC cycle).
- Concurrency tests are deterministic (bounded waits, no sleeps as
  synchronisation).
