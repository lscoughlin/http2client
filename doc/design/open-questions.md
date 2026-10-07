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
updated: 2026-10-06
---

# Open Questions

Single source of truth for unresolved decisions. Other notes link here
rather than restating an item.

1. `MaxStreamsPerConnection` default and behavior when the peer advertises
   `SETTINGS_MAX_CONCURRENT_STREAMS` of 0 or "unlimited" — see
   [[client-api]].
2. Proxy semantics: `CONNECT` tunnel only, or also forwarding? What do
   `:authority`/`:scheme` become behind a proxy? — **resolved 2026-10-07:**
   `CONNECT` tunnel only (no forwarding mode); `:authority`/`:scheme` are
   unchanged because the tunnel is transparent to HTTP/2 — see [[transport]]
   and [[client-api]].
3. HTTP/1.1 fallback: fail on non-`h2` ALPN, or implement a fallback
   codec? — **resolved 2026-10-06:** implement the fallback, off by default;
   `WithHttp1Fallback` turns it on. See [[fallback]].
4. Transparent retry: idempotent-only, or opt-in per request? — see
   [[transport]].
5. `ftPriority` support: send it, or ignore received priority? — see
   [[protocol]].
6. Generic reader shape: FPC `TResponseReader<T>` class with a
   `{$mode delphi}` generic method, vs. a specialized generic class only;
   which FPC release is the floor (currently 3.2.4) — see [[messages]] and
   [[fpc-runtime]].
7. Should `THttpRequest.Headers` be shared or copy-on-write when a request
   record is copied? — see [[messages]].
8. `THttpBody` vs. `IBodyWriter` precedence and replayability on redirect —
   see [[messages]] and [[errors-redirects]].
