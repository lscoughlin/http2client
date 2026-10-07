---
title: "Architecture"
aliases:
  - "architecture"
tags:
  - http2client
  - design
  - architecture
status: draft
up: "[[http2client]]"
related:
  - "[[client-api]]"
  - "[[transport]]"
  - "[[fpc-runtime]]"
updated: 2026-10-05
---

# Architecture

## Resolved multiplexing model

The original sketch contained three statements that cannot all hold at once:
the pool is capped by total connections, "when 4 leases go out it creates a
new connection", *and* leases queue frames on the connection they are
attached to. This design resolves them as follows and the rest of the design
depends on it:

- **A lease is one HTTP/2 stream, not one TCP connection.** A single
  connection multiplexes many concurrent leases/streams.
- **Two connection caps bound TCP connections**: `MaxConnectionsPerHost`
  caps concurrent connections to one `host:port`, and `MaxTotalConnections`
  caps them across all hosts combined. Neither is a cap on in-flight
  requests.
- **Concurrency of requests is bounded separately** by
  `MaxStreamsPerConnection` (and by the peer's advertised
  `SETTINGS_MAX_CONCURRENT_STREAMS`).
- When a new lease is requested, the client reuses the least-loaded open
  connection for that `host:port` if it has a free stream slot; otherwise it
  opens a new connection (until `MaxConnectionsPerHost` /`MaxTotalConnections`);
  otherwise the lease waits.

```
THttpClient
 ├─ FPool["api.example:443"] -> [Conn1, Conn2]
 │     Conn1 (1 read thread, 1 TLS socket, HPACK state)
 │       ├─ Stream 1 <- Lease A  (GET /a)
 │       ├─ Stream 3 <- Lease B  (POST /b)
 │       └─ Stream 5 <- Lease C  (GET /c)
 │     Conn2
 │       └─ Stream 1 <- Lease D
 └─ caps: MaxConnectionsPerHost (TCP per host), MaxTotalConnections (TCP pool),
          MaxStreamsPerConnection (streams)
```

## Component diagram

```
THttpClientFactory (record, immutable)
        │ Build: IHttpClient
        ▼
IHttpClient ───────── owns ──────────► TConnectionPool
   │  Send(const ARequest: THttpRequest): IHttpResponse   TDictionary<string, TConnectionList>
   │  lease acquisition                                   (bounded by FMaxTotalConnections)
   ▼                                                           │
TStreamLease (one stream) ─ attached to ─► IConnection ───────┘
   FStreamId                                     │ owns
   FOutbound: IBlockingQueue<TFrame>             ├─ TSSLSocket (ALPN "h2")
   FInbound:  IBlockingQueue<TFrame>             ├─ TConnectionThread (1 per connection)
   FResponseState                                └─ THpackCodec (encoder + decoder, stateful)
```

Layering, top down:

1. **`THttpClientFactory`** — immutable builder record; produces a configured
   `IHttpClient`. See [[client-api]].
2. **`IHttpClient` / `THttpClient`** — public entry point, thread-safe,
   owns the pool, hands out leases. `Send` may be called concurrently.
3. **`TConnectionPool`** — `TDictionary<string, TConnectionList>` guarded by
   a `TCriticalSection`. Enforces the per-host `MaxConnectionsPerHost` budget
   and the global `MaxTotalConnections` budget.
4. **`IConnection` / `TConnection`** — owns one socket, one background
   thread, and all connection-scoped HTTP/2 state (HPACK, settings, windows,
   stream-id counter). See [[transport]].
5. **`TStreamLease` / stream state** — one request/response exchange.

## Unit layout and naming

```pascal
unit Http2.Client;          // factory, IHttpClient, THttpRequest/Response
unit Http2.Headers;         // IHttpHeaders, THttpHeaders, THttpHeaderNames
unit Http2.Frames;          // TFrameType, TFrame, TFrameHeader, TSettings
unit Http2.Connection;      // IConnection, TConnection, TConnectionPool
unit Http2.Stream;          // TStreamLease, stream state machine
unit Http2.Hpack;           // THpackCodec (static + dynamic tables)
unit Http2.FlowControl;     // TWindow, connection/stream window accounting
unit Http2.Tls;             // ALPN, TLS context, cert validation
unit Http2.Errors;          // exception types / result records
```

Conventions:

- **Unit names**: `Http2.<Area>`, dotted, one class per unit where practical.
- **Types**: `T` prefix for classes/records, `I` prefix for interfaces,
  `E` prefix for exceptions, `F` prefix for fields.
- **Parameters**: `A` prefix (`ARequest`, `AValue`), `const` for managed
  types (avoids an implicit copy + refcount churn).
- **Header-name constants** are lowercase (`HeaderContentType` = `'content-type'`)
  because HTTP/2 requires lowercase on the wire. See [[messages]].
