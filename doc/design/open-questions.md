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
  - "[[proxy]]"
  - "[[errors-redirects]]"
updated: 2026-10-13
---

# Open Questions

Single source of truth for **unresolved** decisions. A settled decision lives
in the note that owns the area (see "Settled decisions" for where each one
is recorded) and is not restated here.

## Open

1. The observer has no cleartext-warning event, so the security rule "log
   one warning per cleartext origin" is not implemented, so a cleartext
   request is silent. See [[fallback]] and
   [[testing-observability]].

## Settled decisions

Recorded in the owning note; listed here only as a lookup index.

| Decision | Owning note |
| --- | --- |
| `MaxStreamsPerConnection` default and peer `SETTINGS_MAX_CONCURRENT_STREAMS` of `0` | [[client-api]] |
| Proxy: `CONNECT` tunnel only, no forwarding; `:authority`/`:scheme` unchanged | [[transport]], [[proxy]] |
| Proxy: no forwarding mode; `socks5` / `socks5h` (RFC 1928, 1929) and `https://` proxies are supported, SOCKS4 is not | [[proxy]] |
| Proxy route is chosen per request; selector > `WithProxy` > `WithAllProxy` > environment (`http_proxy`/`https_proxy`, then `all_proxy`); loopback always connects directly | [[proxy]] |
| HTTP/1.1 fallback is off by default (`WithHttp1Fallback`) | [[fallback]] |
| Transparent retry: idempotent (no body writer) + `ecRefusedStream`/GOAWAY only | [[transport]] |
| `ftPriority` is parsed but never sent | [[protocol]] |
| Reader is a generic class `TResponseReader<T>` on FPC 3.2.4 | [[messages]], [[fpc-runtime]] |
| `THttpRequest.Headers` is shared (an interface), not copy-on-write | [[messages]] |
| `THttpRequest.Clone` deep-copies the header map; `WithHeader` on a fork mutates the original | [[messages]], [[server-sent-events]] |
| `THttpBody` vs `IBodyWriter` precedence and redirect replayability | [[messages]], [[errors-redirects]] |
| An HTTP/1.1 connection is **not** later upgraded to `h2` | [[fallback]] |
| The client does not remember that an origin declined the h2c upgrade; each new connection sends the probe again, and the request is still sent once. `ctHttp1` avoids the probe | [[fallback]] |
| SSE reconnect: wrapper, not transport; clean end or transient failure reconnects, a protocol error is terminal | [[server-sent-events]] |
| WebSocket: RFC 6455 over HTTP/1.1 only (RFC 8441 and `permessage-deflate` are not implemented); demand-driven delivery; a dedicated unpooled connection per socket; the observer sees nothing of it | [[websocket]] |
| SSE emits no observer event per message (frame/stream-level observer only); push support is caller-owned | [[server-sent-events]] |
| SSE over the HTTP/1.1 fallback is best-effort: liveness bounded by the socket read timeout, no cancel path | [[server-sent-events]], [[fallback]] |
| SSE sends `accept-encoding: identity` and rejects any other `content-encoding` | [[server-sent-events]] |
