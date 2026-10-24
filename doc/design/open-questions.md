---
title: "Open Questions"
aliases:
  - "open-questions"
tags:
  - http2client
  - design
  - open-questions
status: open
up: "[http2client](../http2client.md)"
related:
  - "[client-api](client-api.md)"
  - "[messages](messages.md)"
  - "[protocol](protocol.md)"
  - "[transport](transport.md)"
  - "[fallback](fallback.md)"
  - "[proxy](proxy.md)"
  - "[errors-redirects](errors-redirects.md)"
updated: 2026-10-13
---

# Open Questions

Single source of truth for **unresolved** decisions. A settled decision lives
in the note that owns the area (see "Settled decisions" for where each one
is recorded) and is not restated here.

## Open

1. The observer has no cleartext-warning event, so the security rule "log
   one warning per cleartext origin" is not implemented, so a cleartext
   request is silent. See [fallback](fallback.md) and
   [testing-observability](testing-observability.md).

## Settled decisions

Recorded in the owning note; listed here only as a lookup index.

| Decision | Owning note |
| --- | --- |
| `MaxStreamsPerConnection` default and peer `SETTINGS_MAX_CONCURRENT_STREAMS` of `0` | [client-api](client-api.md) |
| Proxy: `CONNECT` tunnel only, no forwarding; `:authority`/`:scheme` unchanged | [transport](transport.md), [proxy](proxy.md) |
| Proxy: no forwarding mode; `socks5` / `socks5h` (RFC 1928, 1929) and `https://` proxies are supported, SOCKS4 is not | [proxy](proxy.md) |
| Proxy route is chosen per request; selector > `WithProxy` > `WithAllProxy` > environment (`http_proxy`/`https_proxy`, then `all_proxy`); loopback always connects directly | [proxy](proxy.md) |
| HTTP/1.1 fallback is off by default (`WithHttp1Fallback`) | [fallback](fallback.md) |
| Transparent retry: idempotent (no body writer) + `ecRefusedStream`/GOAWAY only | [transport](transport.md) |
| `ftPriority` is parsed but never sent | [protocol](protocol.md) |
| Reader is a generic class `TResponseReader<T>` on FPC 3.2.4 | [messages](messages.md), [fpc-runtime](fpc-runtime.md) |
| `THttpRequest.Headers` is shared (an interface), not copy-on-write | [messages](messages.md) |
| `THttpRequest.Clone` deep-copies the header map; `WithHeader` on a fork mutates the original | [messages](messages.md), [server-sent-events](server-sent-events.md) |
| `THttpBody` vs `IBodyWriter` precedence and redirect replayability | [messages](messages.md), [errors-redirects](errors-redirects.md) |
| An HTTP/1.1 connection is **not** later upgraded to `h2` | [fallback](fallback.md) |
| The client does not remember that an origin declined the h2c upgrade; each new connection sends the probe again, and the request is still sent once. `ctHttp1` avoids the probe | [fallback](fallback.md) |
| SSE reconnect: wrapper, not transport; clean end or transient failure reconnects, a protocol error is terminal | [server-sent-events](server-sent-events.md) |
| WebSocket: RFC 6455 over HTTP/1.1 only (RFC 8441 and `permessage-deflate` are not implemented); demand-driven delivery; a dedicated unpooled connection per socket; the observer sees nothing of it | [websocket](websocket.md) |
| The transport observer (`IHttp2Observer`) sees no SSE message, and SSE push support is caller-owned. The request observer can opt in to one callback per event through `IHttpMessageObserver`; without the opt-in an SSE stream costs it only the aggregates | [server-sent-events](server-sent-events.md), [request-observability](request-observability.md) |
| SSE over the HTTP/1.1 fallback is best-effort: liveness bounded by the socket read timeout, no cancel path | [server-sent-events](server-sent-events.md), [fallback](fallback.md) |
| SSE sends `accept-encoding: identity` and rejects any other `content-encoding` | [server-sent-events](server-sent-events.md) |
