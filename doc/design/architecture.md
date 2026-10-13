---
title: "Architecture"
aliases:
  - "architecture"
tags:
  - http2client
  - design
  - architecture
status: done
up: "[http2client](../http2client.md)"
related:
  - "[client-api](client-api.md)"
  - "[transport](transport.md)"
  - "[fpc-runtime](fpc-runtime.md)"
updated: 2026-10-13
---

# Architecture

## Resolved multiplexing model

The pool is capped by total connections and leases queue frames on the
connection they are attached to. The model that reconciles the two, and on
which the rest of the design depends, is:

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

```mermaid
flowchart TB
  C["THttpClient · FPool"]
  C --> K1["api.example:443"]
  C --> K2["other.example:443"]
  K1 --> A["Conn 1 · 1 read thread · 1 TLS socket · HPACK"]
  K1 --> B["Conn 2"]
  A --> A1["Stream 1 · Lease A · GET /a"]
  A --> A2["Stream 3 · Lease B · POST /b"]
  A --> A3["Stream 5 · Lease C · GET /c"]
  B --> B1["Stream 1 · Lease D"]
  K2 --> D["Conn 1"]
  C -.-> CAP["caps: MaxConnectionsPerHost · MaxTotalConnections · MaxStreamsPerConnection"]
```

## Component diagram

```mermaid
flowchart TB
  F["THttpClientFactory · pure value record"]
  F -->|"Build: IHttpClient"| C["IHttpClient · THttpClient"]
  C -->|"owns"| P["TConnectionPool · TDictionary origin → TConnectionList"]
  C -.->|"lease acquisition"| L["TStreamLease · one stream"]
  L -->|"attached to"| N["IConnection · TConnection"]
  P --> N
  N -->|"owns"| S["IHttp2Socket · TSSLSocket · ALPN h2"]
  N -->|"owns"| T["TConnectionThread · 1 per connection"]
  N -->|"owns"| H["THpackCodec · encoder + decoder, stateful"]
```

Layering, top down:

1. **`THttpClientFactory`** — immutable builder record; produces a configured
   `IHttpClient`. See [client-api](client-api.md).
2. **`IHttpClient` / `THttpClient`** — public entry point, thread-safe,
   owns the pool, hands out leases. `Send` may be called concurrently.
3. **`TConnectionPool`** — `TDictionary<string, TConnectionList>` guarded by
   a `TCriticalSection`. Enforces the per-host `MaxConnectionsPerHost` budget
   and the global `MaxTotalConnections` budget.
4. **`IConnection` / `TConnection`** — owns one socket, one background
   thread, and all connection-scoped HTTP/2 state (HPACK, settings, windows,
   stream-id counter). See [transport](transport.md).
5. **`TStreamLease` / stream state** — one request/response exchange.

## Unit layout and naming

Twenty units in `src/`, listed roughly in dependency order (`Http2.Client`
depends on the units after it that it re-exports, such as `Http2.Proxy` and
`Http2.WebSocket`):

```pascal
unit Http2.Errors;      // EHttpError hierarchy, THttp2ErrorCode
unit Http2.Frames;      // TFrameType, TFrame, TFrameHeader, TConnectionSettings
unit Http2.Headers;     // IHttpHeaders, THttpHeaders, header-name constants
unit Http2.Hpack;       // THpackCodec (static + dynamic tables)
unit Http2.FlowControl; // TWindow, connection/stream window accounting
unit Http2.Tls;         // IHttp2Socket, ALPN, TLS context, cert validation,
                        // TClearTextPolicy, TNegotiatedProtocol
unit Http2.Messages;    // IHttpResponse, IResponseReader<T> (re-exports TLS enums)
unit Http2.Http1;       // THttp1Connection, HTTP/1.1 codec + h2c upgrade
unit Http2.Connection;  // TConnection, TConnectionThread, IConnectionStream,
                        // IBlockingQueue<T>, TBlockingQueue<T>
unit Http2.Stream;      // TStreamLease, THttpMethod, THttpBody, IBodyWriter,
                        // IHttpBodyStream, TStreamIdAllocator
unit Http2.Observer;    // IHttp2Observer
unit Http2.Client;      // THttpClientFactory, IHttpClient, THttpRequest,
                        // TConnectionPool, IPooledConnection,
                        // THttpConnection, THttp1PooledConnection,
                        // IHttp2SocketFactory, TResponseReader<T>,
                        // WithTextBody / ReadText
unit Http2.Readers;     // optional: JSON/XML readers + send helpers (fcl-json/fcl-xml)
unit Http2.Sse;         // TSseEventParser, TSseSource, TSseReconnectLoop, SseRequest
unit Http2.Encoding;    // content codings (gzip, deflate)
unit Http2.Proxy;       // IProxy, IProxySelector, proxy URLs, no-proxy list,
                        // environment snapshot (RTL + Http2.Errors only)
unit Http2.Socks;       // SOCKS5 client messages and tunnel (RFC 1928, 1929)
unit Http2.WebSocket;   // frame codec, message assembly, handshake rules,
                        // IWebSocket / IWebSocketListener / IWebSocketRequest
                        // (RTL + Http2.Errors only)
unit Http2.WebSocketClient; // TWebSocketConnection, OpenWebSocket
unit Http2;             // umbrella: re-exports every unit above EXCEPT Http2.Readers
```

`Http2.Readers` is deliberately **outside** the umbrella and the core: it is the only unit that depends on `fcl-json`/`fcl-xml`, so a caller
links it only by naming it in their own `uses` clause. See [messages](messages.md).

**Dependency direction.** `Http2.Client` and `Http2.Connection` are the
concurrency owners; the layers below them are pure and independently
testable. `Http2.Messages` re-exports `TClearTextPolicy` and
`TNegotiatedProtocol` from `Http2.Tls`, so a caller that only needs the
public message types does not pull in the socket layer's details.

Conventions:

- **Unit names**: `Http2.<Area>`, dotted, one class per unit where practical.
- **Types**: `T` prefix for classes/records, `I` prefix for interfaces,
  `E` prefix for exceptions, `F` prefix for fields.
- **Parameters**: `A` prefix (`ARequest`, `AValue`), `const` for managed
  types (avoids an implicit copy + refcount churn).
- **Header-name constants** are lowercase (`HeaderContentType` = `'content-type'`)
  because HTTP/2 requires lowercase on the wire. See [messages](messages.md).
