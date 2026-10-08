---
title: "Open Questions"
aliases:
  - "open-questions"
tags:
  - http2client
  - design
  - open-questions
status: open
up: "[[http2client]]"
related:
  - "[[client-api]]"
  - "[[messages]]"
  - "[[protocol]]"
  - "[[transport]]"
  - "[[fallback]]"
  - "[[errors-redirects]]"
updated: 2026-10-08
---

# Open Questions

Single source of truth for unresolved decisions. Other notes link here
rather than restating an item. Items that the shipped code has since
settled are marked **resolved** with the file or unit that answers them.

1. `MaxStreamsPerConnection` default and behavior when the peer advertises
   `SETTINGS_MAX_CONCURRENT_STREAMS` of 0 or "unlimited" — **resolved:**
   default is `cDefaultMaxStreamsPerConnection = 100`. A peer value of `0`
   is treated as "no advertised limit" (the client cap stands) and the
   effective cap is `min(client cap, peer value when > 0)`. See
   `src/Http2.Client.pas` (`THttpConnection.HasCapacity`) and [[client-api]].
2. Proxy semantics: `CONNECT` tunnel only, or also forwarding? What do
   `:authority`/`:scheme` become behind a proxy? — **resolved 2026-10-07:**
   `CONNECT` tunnel only (no forwarding mode); `:authority`/`:scheme` are
   unchanged because the tunnel is transparent to HTTP/2 — see [[transport]]
   and [[client-api]].
3. HTTP/1.1 fallback: fail on non-`h2` ALPN, or implement a fallback
   codec? — **resolved 2026-10-06:** implement the fallback, off by default;
   `WithHttp1Fallback` turns it on. See [[fallback]].
4. Transparent retry: idempotent-only, or opt-in per request? —
   **resolved:** transparent retry is allowed only for an idempotent method
   with no body writer, and only on `EHttpStreamError` with
   `ecRefusedStream` (the peer refused the stream) or a `GOAWAY` that puts
   the stream above the last-stream-id. Bounded by
   `cMaxTransparentRetries`. There is no per-request opt-in. See
   `src/Http2.Client.pas` (`THttpClient.Send`) and [[transport]].
5. `ftPriority` support: send it, or ignore received priority? —
   **resolved:** the frame layer encodes and parses PRIORITY
   (`BuildPriorityFrame`/`ParsePriority`, `TFrame.IsPriority` in
   `src/Http2.Frames.pas`), but the client **never sends** a PRIORITY
   frame; received priority is parsed, not scheduled on. See [[protocol]].
6. Generic reader shape: FPC `TResponseReader<T>` class with a
   `{$mode delphi}` generic method, vs. a specialized generic class only;
   which FPC release is the floor (currently 3.2.4) — **resolved:** a
   generic **class** `TResponseReader<T>` with both an instance `Read` and a
   static `Read`, under `{$mode delphi}`; FPC 3.2.4 is the floor. See
   [[messages]] and [[fpc-runtime]].
7. Should `THttpRequest.Headers` be shared or copy-on-write when a request
   record is copied? — **resolved (as shared):** `FHeaders` is an interface,
   so copying a `THttpRequest` shares the header map; callers that mutate a
   shared map see the change in every copy. This is documented behaviour,
   not a hidden copy. See [[messages]].
8. `THttpBody` vs. `IBodyWriter` precedence and replayability on redirect —
   **resolved:** the two are mutually exclusive and setting both raises;
   `IBodyWriter` wins for sending. On a redirect an `IBodyWriter` body is
   non-replayable and raises `EHttpNotReplayable`; a `THttpBody` is
   replayed. See [[messages]] and [[errors-redirects]].

Still open:

9. The observer has no cleartext-warning event, so the security rule "log
   one warning per cleartext origin" is not implemented. See [[fallback]]
   and [[testing-observability]].
10. Whether one HTTP/1.1 connection may later be upgraded to `h2`. The
    current design says no. See [[fallback]].
