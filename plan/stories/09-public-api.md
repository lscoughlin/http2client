---
title: "S09 — Public API, pool, request/response"
story-id: "09"
aliases:
  - "S09"
  - "public-api"
tags:
  - http2client
  - plan
  - story
status: done
up: "[[http2client]]"
depends-on:
  - "08-stream-lease"
parallel-with: []
updated: 2026-10-05
---

# S09 — Public API, pool, request/response

## Goal

Expose the designed public surface: `THttpClientFactory`, `IHttpClient`,
`THttpRequest`, `IHttpResponse`, `TResponseReader<T>`, and the connection
pool. Spec:
[`../../doc/design/client-api.md`](../../doc/design/client-api.md) and
[`../../doc/design/messages.md`](../../doc/design/messages.md).

## Tasks

| ID | Description | Files touched | Deliverable | Acceptance | Depends on |
|---|---|---|---|---|---|
| 09.1 | Factory record | `src/Http2.Client.pas` | `THttpClientFactory` with `WithMaxConnections`, `WithMaxStreamsPerConnection`, `WithFollowRedirects`, `WithMaxRedirects`, `WithProxy`, `Build: IHttpClient`; pure value semantics; documented defaults | `testclient` fluent chain compiles | 00.4 |
| 09.2 | Response types | idem | `IHttpResponse{StatusCode,Headers,Body}`, `IHttpBodyStream{Eof,Read}` | test | 08.5 |
| 09.3 | Generic reader | idem | `IResponseReader<T>` + `TResponseReader<T>` under `{$mode delphi}` | DTO decode test | 09.2 |
| 09.4 | Request record | idem | `THttpRequest` with `WithMethod`, `WithMethodToken` (uppercase), `WithHeader`, `WithBody`, `WithBodyWriter`; body/bodywriter mutually exclusive | test both-set raises | 09.2 |
| 09.5 | Connection pool | idem | `TDictionary<string,TConnectionList>` under `TCriticalSection`; global `MaxConnections`; per-host reuse | cap test | 08.9 |
| 09.6 | Lease acquisition | idem | compute Origin; least-loaded eligible conn; open/wait; allocate stream; enqueue frames | test all branches | 09.5, 08.1 |
| 09.7 | `Send` | idem | blocks until status+headers, returns response; thread-safe; concurrent send test | concurrency test | 09.6 |
| 09.8 | `Close` | idem | stop new leases, GOAWAY open connections, release pool; outstanding bodies still readable | test | 09.5, 07.5 |
| 09.9 | Pseudo-header mapping | idem | `:method/:scheme=https/:path/:authority` with default-port omission | encode assertion | 09.4 |
| 09.10 | Sample CLI | `test/testclient.pas` | builds a client, GETs a URL | runs against `nghttpd` | 09.7 |

## Unit tests

- `test/Http2.Client.Test.pas` — factory immutability, defaults, pool caps,
  least-loaded selection, concurrent `Send`, `Close` semantics.
- `test/Http2.Request.Test.pas` — method token uppercase, body precedence,
  pseudo-header mapping.

## Done when

- The documented fluent example compiles and runs.
- A live GET and POST succeed against `nghttpd` (integration, opt-in).
- Pool never exceeds `MaxConnections`; streams never exceed per-connection
  caps.
