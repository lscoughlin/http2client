---
title: "Observer overhead"
aliases:
  - "observer-overhead"
tags:
  - http2client
  - verification
  - observability
status: pending
up: "[http2client](../http2client.md)"
related:
  - "[request-observability](../design/request-observability.md)"
updated: 2026-10-24
---

# Observer overhead

What the request observers cost on a loopback request. The program and the
method are in place; the results table below is **empty until the measurement
has been run and recorded**. No figure in this note has been measured yet.

## Method

`examples/observer_overhead.pas` starts a small HTTP/1.1 server on a loopback
port of its own (cleartext, keep-alive, one connection at a time) and sends
requests to it through a real `THttpClient`, one at a time, timing each
request from `Send` to the end of the body with the library's monotonic clock.

Two workloads:

- **plain GET.** `GET /plain` answers a five-byte body with a content length.
  The body is read to its end.
- **SSE, 20 events.** `GET /sse` (a request built by `SseRequest`) answers a
  chunked event stream of 20 events written at once; the stream is read to its
  end with `TSseSource`.

Three configurations:

| Configuration | Observers installed |
|---|---|
| no observer | none: `WithRequestObserver` is not called |
| tracing + metrics + logging | `TTracingObserver`, `TMetricsObserver` (per-event gate off) and `TLoggingObserver`, in that order. The tracer and the metric registry are the in-memory stand-ins of the examples; the logger counts lines and keeps none |
| all three, per-event gate on | the same, with `TMetricsObserver.PerEvent` on, so every SSE event reaches `OnMessage` and feeds the inter-event histogram. Run for the SSE workload only, because a plain response has no per-message callbacks |

Each configuration gets a fresh client, a warm-up of 200 requests that is
dropped, then the timed requests. The configurations run in turn inside a
round and the rounds repeat (default 3 rounds of 3000 requests), so a machine
whose load drifts affects every configuration alike. The samples of the rounds
are pooled for each configuration. The program prints the mean, the median
(p50) and the 99th percentile per request, and the mean overhead against "no
observer" in microseconds and in percent.

The measurement is wall time on a loopback socket and includes the server's
thread and the kernel, so the absolute figures belong to the machine they were
taken on; what carries over is the difference between configurations. Run it on
an otherwise idle machine.

## Command

```sh
make measure-observer MORMOT=third_party/mORMot2/src
# or: task measure-observer
# or, with the program already built:
bin/observer_overhead [requests-per-round [rounds]]
```

It is not part of `make test` and needs no fixture and no network beyond
loopback. The traffic is cleartext HTTP/1.1, so there is no TLS handshake in
the timings; `make` passes `OPENSSL_LIBPATH` as for every other target, and a
direct run of the program should export it too.

## Results

**Filled in by the lead after the run. The cells are empty on purpose.**

Machine, FPC version and date of the run:

| Machine | FPC | Date | Requests per round | Rounds |
|---|---|---|---|---|
| | | | | |

| Workload | Configuration | Requests | Mean (us) | p50 (us) | p99 (us) | Mean overhead (us) | Mean overhead (%) |
|---|---|---|---|---|---|---|---|
| plain GET | no observer | | | | | - | - |
| plain GET | tracing + metrics + logging | | | | | | |
| SSE, 20 events | no observer | | | | | - | - |
| SSE, 20 events | tracing + metrics + logging | | | | | | |
| SSE, 20 events | all three, per-event gate on | | | | | | |

## Bound

The bound on what an observer may cost per request is **not yet stated**. It is
set when the table above is filled in, and then recorded here and in
[open-questions](../design/open-questions.md).

| Statement | Value |
|---|---|
| bound on the mean overhead of the three adapters, plain GET | |
| bound on the mean overhead of the three adapters, SSE, gate off | |
| bound on the additional mean overhead of the per-event gate, 20 events | |
