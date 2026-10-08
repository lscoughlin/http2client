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

Single source of truth for **unresolved** decisions. An item leaves this file
when the shipped code settles it; the decision then lives in the note that
owns the area (see "Settled decisions" for where each one went). Do not
restate a settled decision here.

## Open

1. The observer has no cleartext-warning event, so the security rule "log
   one warning per cleartext origin" is not implemented — a cleartext
   request is currently silent. See [[fallback]] and
   [[testing-observability]].

## Settled decisions

Recorded in the owning note; listed here only as a lookup index.

| Decision | Owning note |
| --- | --- |
| `MaxStreamsPerConnection` default and peer `SETTINGS_MAX_CONCURRENT_STREAMS` of `0` | [[client-api]] |
| Proxy: `CONNECT` tunnel only, no forwarding; `:authority`/`:scheme` unchanged | [[transport]] |
| HTTP/1.1 fallback implemented, off by default (`WithHttp1Fallback`) | [[fallback]] |
| Transparent retry: idempotent (no body writer) + `ecRefusedStream`/GOAWAY only | [[transport]] |
| `ftPriority` is parsed but never sent | [[protocol]] |
| Reader is a generic class `TResponseReader<T>` on FPC 3.2.4 | [[messages]], [[fpc-runtime]] |
| `THttpRequest.Headers` is shared (an interface), not copy-on-write | [[messages]] |
| `THttpBody` vs `IBodyWriter` precedence and redirect replayability | [[messages]], [[errors-redirects]] |
| An HTTP/1.1 connection is **not** later upgraded to `h2` | [[fallback]] |
