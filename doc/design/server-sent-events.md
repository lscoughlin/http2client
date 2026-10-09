---
title: "Server-Sent Events"
aliases:
  - "server-sent-events"
  - "sse"
  - "event-stream"
tags:
  - http2client
  - design
  - api
  - protocol
status: done
up: "[[http2client]]"
related:
  - "[[messages]]"
  - "[[client-api]]"
  - "[[errors-redirects]]"
  - "[[transport]]"
  - "[[fallback]]"
  - "[[testing-observability]]"
  - "[[open-questions]]"
updated: 2026-10-09
---

# Server-Sent Events

This note brings **Server-Sent Events** (SSE) into scope. SSE is a
one-way, long-lived HTTP response: the server holds the response body open
and pushes `text/event-stream` events until the client disconnects or the
server closes the stream.

The client already speaks the transport SSE needs. What is missing is a
**parser**, a **source/loop layer above `IHttpBodyStream`**, and — this is
the load-bearing part — an **inactivity timeout** distinct from the existing
per-request header timeout, because the shipped body read raises
`EHttpTimeout` after `FTimeoutMs` of silence (`src/Http2.Stream.pas:1068`,
default `30000` at `src/Http2.Stream.pas:476`). A live SSE stream is quiet
between events, so under the current code every stream idle for more than the
header timeout fails.

## Scope

SSE is a **reader layer**, not a transport mode:

| Layer | Unit | Role in SSE |
| --- | --- | --- |
| Socket / TLS | `Http2.Tls` | unchanged |
| Connection + thread | `Http2.Connection` | unchanged; supplies DATA frames and keeps the receive window open |
| Stream lease / body | `Http2.Stream` | **extended**: body-read inactivity timeout + cancellation polling |
| Response | `Http2.Messages` (`IHttpResponse`, `IHttpBodyStream`) | the seam SSE reads from |
| Codec | `Http2.Client` (HTTP/2), `Http2.Http1` (fallback) | HTTP/2 fully supported; HTTP/1.1 best-effort (see below) |
| **SSE (new)** | `Http2.Sse` | parser, source, reconnect loop |

SSE is codec-agnostic on purpose: it consumes `IHttpResponse.Body` and
therefore inherits HTTP/2 multiplexing (an SSE stream is one HTTP/2 stream
among others on a shared connection) and the HTTP/1.1 fallback (where the
stream occupies the connection for its lifetime — see "Connection
lifetime").

**Supported scope (as implemented).** The parser, source and reconnect loop
are codec-agnostic and run over either codec. The *transport guarantees*
differ, and the difference is stated rather than papered over:

- **HTTP/2 — full support.** A blocked body read honours the per-request
  body deadline (including "wait indefinitely"), polls the request's
  `ICancellationToken` on a 20 ms slice, and resets the stream with
  `RST_STREAM(CANCEL)` on a caller cancel. Receive window credit is returned
  on frame arrival, so an idle stream is never reaped and never stalls the
  connection.
- **HTTP/1.1 fallback — best-effort.** `THttp1Connection.Create` sets
  `FSocket.ReadTimeoutMs := ATimeoutMs` from the *header* timeout
  (`src/Http2.Http1.pas:906`), and `THttp1BodyStream.Read` has no token and
  no cancel path. So over the fallback an idle SSE stream is bounded by the
  socket read timeout and cannot be cancelled mid-read; the parser, event
  delivery and reconnect/resume still work. The fallback is off by default
  and is a single-connection codec, so an event stream monopolizes it for
  its lifetime.

An SSE request is an ordinary GET. It is **not** special-cased in the
transport; the caller builds it with `accept: text/event-stream` and (when
resuming) `last-event-id`.

## Request

An SSE request is `GET` with:

| Header | Value | Required |
| --- | --- | --- |
| `accept` | `text/event-stream` | yes |
| `cache-control` | `no-store` | recommended; stops an intermediary caching the stream |
| `last-event-id` | the last observed id | only on resume (see "Reconnection") |
| `accept-encoding` | `identity` | **yes — see "Content coding"** |

`Http2.Headers` already carries `HeaderAccept`, `HeaderCacheControl`,
`HeaderAcceptEncoding`. The one missing constant is
`HeaderLastEventId = 'last-event-id'`; it is added by the story.

## Response validation

A response is a valid event stream only when the status is `200` and the
`content-type` is `text/event-stream` (case-insensitive media type, optional
parameters allowed). The rules mirror the other readers:

- A non-`200` status raises; the body is the error payload, so the source
  drains at most a bounded prefix for the message and never treats it as
  events.
- A missing or non-`text/event-stream` content-type raises
  `EHttpProtocolError` with `ecProtocolError`.
- A declared `charset` parameter other than `utf-8` raises. The event stream
  is UTF-8 by definition; a declared non-UTF-8 charset is a protocol error,
  not something to transcode.
- A `text/event-stream` body is never buffered whole: the source reads
  incrementally and yields each event as its terminating blank line arrives.

## Wire format and parser

The format is the WHATWG event-stream grammar (HTML Living Standard,
"Interpreting an event stream"). The parser is a **pure, incremental,
byte-in/event-out class** — `TSseEventParser` — with no socket or lease
dependency, so it can be tested by slicing an input at every byte boundary
(see "Testing"). It is the SSE analogue of `THpackCodec` in
[[protocol]]: a pure layer the rest of the stack composes.

Grammar, exactly:

| Rule | Behaviour |
| --- | --- |
| Line terminators | CRLF, bare CR, **and** bare LF all end a line. |
| BOM | One leading U+FEFF at stream start is stripped; a later BOM is data. |
| Field line | `field: value` — the field ends at the **first** `:`. |
| Leading space | One single space after the `:` is stripped from the value. |
| No colon | A line with no `:` is a field name with an empty value. |
| Comment | A line whose first character is `:` is ignored (valid keep-alive). |
| `data` | Append the value plus a single `\n` to the data buffer. |
| `event` | Set the event-type buffer to the value. |
| `id` | If the value contains no NUL, set the last-event-ID buffer to it; else ignore. |
| `retry` | If the value is **ASCII digits only**, set the reconnection time; else ignore. |
| Other fields | Ignored. |
| End of stream | A partial (unterminated) event is **discarded**, never dispatched: the event fires only on its blank line. A stream that is cut mid-event therefore delivers no half event. |
| Blank line | **Dispatch**: if the data buffer is empty, reset and fire nothing. Otherwise strip one trailing `\n`, use the event-type buffer or `message` when empty, fire with `lastEventId`, then reset the data and event-type buffers. |

The dispatch condition is the subtle one: `id:`, `retry:`, and `event:`
lines **update state** but must not, by themselves, fire a message event.
Only a blank line with a non-empty data buffer dispatches. `lastEventId`
survives cluster boundaries; the data and event-type buffers do not.

`retry` sets a reconnection **delay**, not a timeout: it is the client's
wait before reconnecting after the stream ends.

The parser's public shape:

```pascal
// src/Http2.Sse.pas
type
  TSseEvent = record
    /// event type; 'message' when the stream sent no event: field
    EventType: string;
    /// the data payload with the single trailing newline removed
    Data: string;
    /// the id in force at dispatch time ('' when none was ever set)
    Id: string;
    /// the retry: value in force, in ms (0 = none seen)
    RetryMs: Integer;
  end;

  TSseEventParser = class
  public
    /// feed one chunk; AEvents receives zero or more completed events
    procedure Feed(const AChunk: TBytes; const AEvents: TList<TSseEvent>); overload;
    procedure Feed(const AText: string; const AEvents: TList<TSseEvent>); overload;
    /// the id in force after the last fed byte (survives dispatch)
    function LastEventId: string;
    /// the retry delay in force, in ms (0 = never set)
    function RetryMs: Integer;
    /// abandon any partial line and buffered data (stream boundary)
    procedure Reset;
  end;
```

The parser is UTF-8: a `TSseEvent.Data` is a UTF-8 string. It performs no
transcoding, matching `ReadText`'s byte-verbatim rule in [[messages]]. A
multi-byte sequence split across two `Feed` calls is held until complete.

## Timeouts and liveness

**This is the reason SSE needs a transport change.** The shipped body read
blocks on an internal frame queue with a deadline:

```pascal
// src/Http2.Stream.pas:1068 (ReadBody)
if not PopInbound(Frame, FTimeoutMs) then ... raise EHttpTimeout
```

`FTimeoutMs` is set from the **header** timeout in
`THttpConnection.AcquireCancellable` (`src/Http2.Client.pas:1600`,
`Lease.TimeoutMs := ATimeoutMs`) and defaults to `30000`
(`src/Http2.Stream.pas:476`). For a normal request that is correct — the
whole body is expected promptly. For SSE it is wrong: between events the
stream is idle by design, so the 30 s header deadline would abort a perfectly
healthy stream.

SSE therefore needs a **body read timeout separate from the header
timeout**:

| Setting | Applies to | Default | `0` means |
| --- | --- | --- | --- |
| `HeaderTimeoutMs` | until response HEADERS/status line | `30000` | `0` = default |
| `IdleTimeoutMs` | reaping an unused pooled connection | `60000` | `0` = never reap |
| **`BodyReadTimeoutMs`** (new) | each blocked body read on an SSE source | unset = fall back to `HeaderTimeoutMs`; SSE sets it to `0` | **`0` = wait indefinitely** |

The default for an SSE source is **wait indefinitely** (`0`): an abrupt
"no event for N seconds" abort is a client policy the caller should opt into,
not a library default that silently truncates streams. A caller who wants a
liveness bound sets `WithSseReadTimeout(ms)` on the request; a `0` value is
explicit and documented.

Independent liveness signals still work and are preferred:

- A **comment line** (`: keep-alive`) is a valid server heartbeat. It
  completes no event but it **does** deliver bytes, so it resets the
  inactivity clock. A server that emits `:` every 15 s keeps the stream alive
  with no client-side timeout at all.
- A server may also send `retry:`; that is the reconnect delay, not a
  liveness bound.

The story therefore adds a **body read timeout** to `TStreamLease`, set from
`THttpRequest.WithSseReadTimeout` and threaded to the lease through
`TStreamRequest.WithBodyReadTimeout`. A separate named field (not a reuse of
`FTimeoutMs`) is required so header waiting and body waiting can differ, and
`TStreamRequest.BodyReadTimeoutSet` distinguishes "no opinion, keep the
historic header-timeout deadline" from "explicitly wait indefinitely".

## Cancellation

Read-side cancellation did not exist in the shipped code.
`ICancellationToken` was polled only in the header-wait loop
(`THttpConnection.AcquireCancellable`, `cCancelPollSliceMs = 20`); `ReadBody`
had no token and no poll, so an SSE reader blocked on its inbound queue could
not be interrupted by `Cancel`.

This is now implemented (it was a required story task, not a follow-up):

- `ICancellationToken`/`TCancellationToken` moved from `Http2.Client` into
  `src/Http2.Stream.pas`, so the lease's body read can poll the token without
  a second, twin interface. `Http2.Client` re-exports them (its `uses` clause
  already included `Http2.Stream`), so no caller broke.
- `TStreamLease.ReadBody` no longer calls the generic
  `PopInbound(Frame, FTimeoutMs)`; it calls `WaitForBodyFrame`, which honours
  the request's body-read deadline and, when a token is present, polls it on
  the `cReadCancelPollSliceMs = 20` slice.
- On a cancel the lease posts `RST_STREAM(CANCEL)`, releases the lease, and
  raises `EHttpStreamError('body read cancelled', StreamId, ecCancel)`. The
  stream is reset rather than orphaned, the same rule [[errors-redirects]]
  applies to a cancelled `Send`.
- The header-wait and body-read paths now share one token type and one slice
  constant, so "cancelled" means the same thing at both points of an
  exchange.

A caller's `Cancel` therefore unblocks a parked SSE read and half-closes the
stream; `TSseReconnectLoop` stops when the source is closed or cancelled.

## Flow control on a long-lived stream

A slow or paused SSE reader must not starve the connection. The receive
window is replenished by the connection, not by the application read:
`TConnection.TrackReceivedData` (`src/Http2.Connection.pas:1094`) credits
the connection window and the per-stream window as each DATA frame arrives,
and emits `WINDOW_UPDATE` in `cWindowUpdateBatchSize = 32768`-byte batches
(`src/Http2.Connection.pas:28`). Because the credit is issued on frame
arrival rather than on consumption, a draining SSE reader keeps the window
open and the stream does not stall.

The bound to state and test: the peer may have at most one batch of
unacknowledged bytes in flight per window before a `WINDOW_UPDATE` is due,
and the lease's `FBodyPending` holds at most the frames the parser has not
consumed yet. A **slow-consumer test** must assert the cadence: feed a large
SSE body while reading slowly and confirm `WINDOW_UPDATE` still flows and the
stream never deadlocks.

## Connection lifetime and pool interaction

- An open SSE lease counts as **one active stream**. The pool's idle reaper
  skips a connection with `ActiveStreams > 0`
  (`src/Http2.Client.pas:2075`), so an SSE stream is never reaped while it
  is open — correct, but it also means the stream **occupies one slot of
  `MaxStreamsPerConnection` for its whole life**, which can be hours.
- Over **HTTP/2** that is one stream among many; the connection is shared.
- Over the **HTTP/1.1 fallback** the stream limit is 1 by design (see
  [[fallback]]), so a single SSE stream monopolizes the entire connection
  until it ends. Document this; it is a property of HTTP/1.1, not a defect.
- Calling `IHttpClient.Close` while an SSE source is open stops new leases
  and gracefully closes connections (GOAWAY); the SSE read then fails with
  `EHttpConnectionClosed`. The source surfaces that as a terminal error
  (or, when the reconnect loop is enabled and the failure is transient, as a
  reconnect trigger — see the open item).

## Content coding

SSE is incompatible with transparent content decoding as implemented.

`WithAcceptEncoding` (see [[messages]]) sets `accept-encoding`; a response
that answers with gzip or deflate is wrapped by `WrapDecodingResponse`
(`src/Http2.Client.pas:1640`) so `Body` yields plain bytes. That wrapper
**buffers to the coding's footer** before it can emit anything, which
destroys the defining property of SSE — each event becomes readable only at
stream end, at which point events are no longer "server-sent" in real time.

Rule: **an SSE request sends `accept-encoding: identity` and the source
rejects a `content-encoding` other than `identity` (or absent) with
`EHttpProtocolError`.** No decompression wrapper is applied on the SSE path.
This is a correctness rule, not an optimisation: the whole point of SSE is
incremental delivery.

## Reconnection and resume

SSE's reconnect contract is client-driven: when the stream ends (server
close, transient failure, or a bounded retry), the client reconnects to the
same URL, sends `last-event-id: <last id>`, and the server resumes after that
id.

`TSseReconnectLoop` wraps a source with:

- a **reconnect delay** starting at the implementation default (the WHATWG
  recommendation is implementation-defined; this library uses **3000 ms**),
  overridden by any `retry:` the server sent, and optionally backed off;
- an **echoed `last-event-id`** taken from the parser's `LastEventId`
  ('' means send nothing);
- a **bounded retry count** mirroring the redirect idiom: `MaxRetries`
  (default `10`, `0` = reconnect forever), exceeding which raises a new
  `EHttpTooManySseRetries` (mirroring `EHttpTooManyRedirects` in
  [[errors-redirects]]);
- a **replay guard**: events are dispatched at most once per observed id, so
  a server that resumes inclusive of `last-event-id` does not duplicate the
  last event.

Reconnect is deliberately a **wrapper, not a transport feature**: keeping it
above the client means a caller can use the `IHttpSseSource` directly and own
its own reconnect policy, while `TSseReconnectLoop` is the batteries-included
default.

## Public API

```pascal
// src/Http2.Sse.pas
type
  IHttpSseSource = interface
    ['{8B1C2D3E-4F50-4A61-9C72-00000000E001}']
    /// block until the next event is parsed, or the stream ends.
    /// True = AEvent is set; False = the stream ended cleanly.
    function ReadEvent(out AEvent: TSseEvent): Boolean;
    /// the last-event-id in force ('' when none)
    function LastEventId: string;
    /// the server's last retry: value in ms (0 = none)
    function RetryMs: Integer;
    /// stop the source and release the lease (idempotent)
    procedure Close;
  end;

  /// a source over one IHttpResponse body
  TSseSource = class(TInterfacedObject, IHttpSseSource)
  public
    /// the read deadline is NOT a constructor argument: the lease already
    /// owns the body stream and its deadline was chosen when the request was
    /// built (SseRequest sets it to 0 = wait indefinitely). To bound a read,
    /// use THttpRequest.WithSseReadTimeout before sending.
    constructor Create(const AResponse: IHttpResponse);
    /// True when the media type is text/event-stream (params allowed, a
    /// declared charset must be utf-8)
    class function IsEventStreamContentType(const AValue: string): Boolean;
    /// raises EHttpProtocolError unless AResponse is a 200 event-stream with
    /// no content coding
    class function ValidateResponse(const AResponse: IHttpResponse): Boolean;
    ...
  end;

  /// reconnect + resume wrapper
  TSseReconnectLoop = class
  public
    /// NO observer argument: IHttp2Observer is frame/stream level, so one
    /// event per message would be high-cardinality (open item 2)
    constructor Create(const AClient: IHttpClient;
      const ARequest: THttpRequest;
      const AMaxRetries: Integer = cSseDefaultMaxRetries);
    function Next(out AEvent: TSseEvent): Boolean;
    procedure Close;
    /// the reconnect delay in force (server retry: or the 3000 ms default)
    function RetryMs: Integer;
    /// reconnects performed so far; the FIRST connection is not counted
    function Reconnects: Integer;
  end;

/// build an SSE GET request (accept + cache-control + identity encoding)
function SseRequest(const AUrl: string): THttpRequest;
```

Two consumption styles, matching the two the library already has:

- **Pull** — `ReadEvent` blocks until an event or the stream end; the
  caller's thread loops. This is the primitive.
- **Push** — not shipped. The design left open whether the source should
  emit an observer event per parsed event; the implementation does not, so
  "push" means a caller-owned thread that wraps `ReadEvent` (for a UI or a
  queue). A callback channel is a possible later addition, not a second
  parser.

`TSseSource` reads `IHttpResponse.Body` in chunks, feeds
`TSseEventParser`, and buffers completed events in a bounded queue so a
single `Read` call can produce several events. `Body.Eof` (`END_STREAM`)
ends the source cleanly; `EHttpStreamError` mid-body surfaces from
`ReadEvent`, not from the `Send` that returned the response.

## Error model

SSE reuses the existing hierarchy ([[errors-redirects]]); no new exception
types except the retry bound:

| Condition | Error |
| --- | --- |
| Non-`200`, or wrong/missing content-type, or non-utf-8 charset | `EHttpProtocolError` (`ecProtocolError`) |
| `content-encoding` not `identity` | `EHttpProtocolError` (`ecProtocolError`) |
| Idle body read past `BodyReadTimeoutMs` | `EHttpTimeout` |
| Peer `RST_STREAM` / connection loss | `EHttpStreamError` / `EHttpConnectionError` |
| Caller `Cancel` during a blocked read | `EHttpStreamError` (`ecCancel`) |
| `MaxRetries` exceeded | `EHttpTooManySseRetries` (new) |

## Unit layout

| Unit | Status | Content |
| --- | --- | --- |
| `src/Http2.Sse.pas` | **new** | `TSseEvent`, `TSseEventParser`, `IHttpSseSource`, `TSseSource`, `TSseReconnectLoop`, `SseRequest` |
| `src/Http2.Stream.pas` | extended | body read timeout + read-side cancellation |
| `src/Http2.Client.pas` | extended | `WithSseReadTimeout` request setter; thread the token and the body deadline to the lease's body read |
| `src/Http2.Headers.pas` | extended | `HeaderLastEventId` constant |
| `src/Http2.pas` | extended | re-export `Http2.Sse` |
| `test/Http2.Sse.Test.pas` | **new** | parser, validation, source, reconnect |
| `examples/sse_stream.pas` | **new** | runnable demo against the test server |
| `tools/validate/sse_server.py` | **new** | a minimal live SSE server for interop (see "Testing") |

`Http2.Sse` joins the umbrella because, unlike `Http2.Readers`, it needs no
`fcl-json`/`fcl-xml` dependency.

## Testing

- **Parser unit tests** are the heart of this. Feed the WHATWG example byte
  stream, then re-feed it **sliced at every offset** (all chunk boundaries,
  including splits inside a CRLF, inside a field name, inside a value, and
  across a multi-byte UTF-8 sequence) and assert an identical event
  sequence. This is the same "prove the assertion can fail" standard
  [[testing-observability]] uses.
- **Pure parser cases:** comment-only keep-alive fires nothing but resets
  liveness; `id`/`retry`/`event` with no `data` fires nothing but updates
  state; blank-line dispatch removes exactly one trailing `\n`; `retry:`
  non-numeric ignored; `id` with NUL ignored; BOM stripped once.
- **Response validation cases:** non-200, missing content-type, wrong
  content-type, non-utf-8 charset, `content-encoding: gzip` rejected.
- **Timeout/cancellation cases:** with `BodyReadTimeoutMs` set, an idle
  stream raises `EHttpTimeout`; with `0`, an indefinitely quiet stream blocks
  (asserted with a short `Cancel` from another thread, not a long sleep); a
  `Cancel` during a blocked read raises `ecCancel` within one poll slice.
- **Flow-control case:** slow reader over a mock socket still sees
  `WINDOW_UPDATE` and never deadlocks.
- **Live case (opt-in, `SSE_TEST_URL`):** `pytest`-free: `tools/validate/sse_server.py`
  serves `text/event-stream` and emits a scripted sequence (comment
  keep-alive, multi-line data, `event:`, `id:`, `retry:`), then closes; the
  example and one integration test consume it. This mirrors the opt-in
  integration gate in [[testing-observability]].

## Resolved items

These were open when the note was written and are settled in the shipped
code (also indexed in [[open-questions]]).

1. **Reconnect after a transient GOAWAY.** Settled: the reconnect policy
   lives in `TSseReconnectLoop`, not in the transport. It reconnects after
   any clean end of stream or transient failure unless the caller closes it;
   a protocol error (non-200, wrong content-type, non-identity coding) is
   terminal and propagates. `EHttpTooManySseRetries` bounds the reconnects
   (`AMaxRetries = 0` retries forever).
2. **Observer cardinality for events.** Settled: SSE emits no per-event
   observer event. `IHttp2Observer` stays frame/stream-level; per-message
   observability belongs to the caller's own callback, because a chatty
   stream would be high-cardinality noise.
3. **SSE over the HTTP/1.1 fallback.** Settled: supported but best-effort,
   not rejected. Liveness is bounded by the socket read timeout
   (`THttp1Connection.Create` sets `FSocket.ReadTimeoutMs := ATimeoutMs`,
   `src/Http2.Http1.pas:906`) and `THttp1BodyStream.Read` has no cancel path,
   so an idle fallback stream cannot wait indefinitely and a blocked read
   cannot be cancelled. HTTP/2 has no such limit.
