---
title: "Errors, Timeouts & Redirects"
aliases:
  - "errors-redirects"
tags:
  - http2client
  - design
  - errors
status: draft
up: "[[http2client]]"
related:
  - "[[messages]]"
  - "[[transport]]"
  - "[[fallback]]"
  - "[[open-questions]]"
updated: 2026-10-08
---

# Errors, Timeouts & Redirects

## Redirects

When `WithFollowRedirects` is on and a `3xx` carries a `Location`:

- A cross-origin redirect requires a different connection/lease; do not
  reuse the current one.
- Method/body rewriting follows the standard rules (`303` → GET, no body;
  `307`/`308` preserve method and body only if the body is a replayable
  `THttpBody`; an `IBodyWriter` body cannot be replayed and the redirect
  fails with `EHttpNotReplayable`).
- Redirect count is bounded by `MaxRedirects`; exceeding it raises
  `EHttpTooManyRedirects`.

```mermaid
flowchart TB
  R["response received"] --> S{"3xx and FollowRedirects?"}
  S -->|"no"| DONE["return response"]
  S -->|"yes"| COUNT{"redirects so far &lt; MaxRedirects?"}
  COUNT -->|"no"| E1["raise EHttpTooManyRedirects"]
  COUNT -->|"yes"| M{"status code?"}
  M -->|"303"| G["method = GET · body dropped"]
  M -->|"307 / 308"| B{"body replayable?"}
  M -->|"301 / 302"| G
  B -->|"no · IBodyWriter"| E2["raise EHttpNotReplayable"]
  B -->|"yes"| K["keep method + body"]
  G --> X{"same origin?"}
  K --> X
  X -->|"yes"| REUSE["reuse the current connection"]
  X -->|"no"| NEW["acquire a lease on a new origin"]
  REUSE --> LOOP["re-send (bounded by MaxRedirects)"]
  NEW --> LOOP
  LOOP --> R
```

## Error handling and timeouts

Exception hierarchy (all derive from `EHttpError`):

```pascal
type
  EHttpError            = class(Exception);
  EHttpConnectionError  = class(EHttpError);   // fails all leases on the conn
  EHttpProtocolError    = class(EHttpError);
  EHttpStreamError      = class(EHttpError);   // RST_STREAM; conn survives
  EHttpTimeout          = class(EHttpError);
  EHttpConnectionClosed = class(EHttpError);
  EHttpTooManyRedirects = class(EHttpError);
  EHttpNotReplayable    = class(EHttpError);
```

- **Connection errors** (transport failure, protocol error, `GOAWAY`,
  `COMPRESSION_ERROR`, settings error) fail all in-flight leases.
- **Stream errors** (`ftRstStream` or stream-level protocol error) fail only
  that lease.
- **Cancellation:** abandoning a `Send`/`Read` sends `RST_STREAM` with
  `CANCEL` and releases the lease. A request may carry an
  `ICancellationToken` (`THttpRequest.WithCancelToken`); cancelling it resets
  the stream in flight.
- **Timeouts:** the factory sets three defaults — `WithConnectTimeout`,
  `WithHeaderTimeout`, `WithIdleTimeout` (milliseconds). Only the header
  timeout is overridable per request, through `THttpRequest.WithTimeout(ms)`
  (`0` means "use the factory default"). A timeout cancels the stream — it
  does not orphan it.
- **Uniform reporting:** errors are raised as the exception types above;
  partial records are never left half-owned because ownership is by
  interface (refcount cleans up on unwind).

### Where each error is raised

```mermaid
flowchart TB
  OP["Send / read"] --> E{"failure kind"}
  E -->|"TCP, TLS, proxy CONNECT refused"| C["EHttpConnectionError<br/>all leases on the connection fail"]
  E -->|"bad frame, HPACK, settings, GOAWAY"| P["EHttpProtocolError<br/>all leases on the connection fail"]
  E -->|"RST_STREAM or stream-level error"| S["EHttpStreamError<br/>only that lease fails"]
  E -->|"connect / header / idle deadline"| T["EHttpTimeout<br/>stream is reset, not orphaned"]
  E -->|"queue shutdown, Close called"| X["EHttpConnectionClosed<br/>waiters are released"]
  E -->|"redirect bound exceeded"| R["EHttpTooManyRedirects"]
  E -->|"IBodyWriter cannot replay"| N["EHttpNotReplayable"]
```

A connection-level failure **takes precedence over** a queued stream error:
if the transport dies while a retryable stream error is pending, the caller
sees `EHttpConnectionError` so the request is not silently masked as
non-retryable. See [[protocol]].
