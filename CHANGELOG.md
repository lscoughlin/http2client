# Changelog

The notable changes of the library. Each entry names the release that
holds it. Dates follow the release commits and tags.

Releases 0.14.0 to 0.21.0 have tags (`v0.14.0` to `v0.21.0`). Release 0.13.0
has none: it is the commit `558787c`. The package version in
`http2client.lpk` is 0.22.0, which has no tag yet, so its changes sit under
Unreleased.

## [Unreleased]

Changes after the 0.22.0 version bump (`d7a422f`).

### Changed

- The mORMot2 checkout is pinned to `b2b195da1e0580058672a88620ef71bb47283eb1`
  (2026-10-08), the revision `http2server` uses. It was `2ccea1a0`. The unit
  suite, the interop gate and the mutual TLS gate give the same results on
  both revisions. The harness sweep was not run on the new revision.
- A header block is decoded in wire order, by the connection reader thread,
  before its frames go to the streams. A `HEADERS` frame must be followed by
  its `CONTINUATION` frames, with no other frame between them.
- A stream that waits for input releases the connection lock while it waits,
  so other streams on the same connection make progress.

### Fixed

- A `text/event-stream` response keeps its `content-encoding` header and its
  body as sent, so the event-stream reader sees and rejects a coding other
  than identity. Before, the decoding wrapper could hide the coding.

## [0.21.0] - 2026-10-25

### Added

- Mutual TLS: a client identity from PEM files, PEM in memory or PKCS#12,
  presented on every TLS connection to the origin (HTTP/2, the HTTP/1.1
  fallback, event streams and `wss`, direct or through a tunnel).
- `IClientIdentitySelector` picks an identity per origin. It is asked once per
  new TLS connection, outside the pool lock, and the pool key carries the
  identity.
- `WithClientIdentity` on a request or a WebSocket request sets an identity
  for that request. It wins over the selector and the fixed identity.
- `WithProxyClientIdentity` sets the identity for the TLS leg of an `https`
  proxy. The origin identity never reaches the proxy.
- `EHttpTlsConfigError` for a bad or expired identity, raised at `Build` or
  before the dial, and `EHttpTlsClientAuthError` for a server that refuses the
  identity under TLS 1.2 or TLS 1.3. Neither is retried and neither falls back.
- The opt-in gates `task validate:mtls` (a Python server and `nghttpd`),
  `task validate:mtls-real` (nginx, Apache httpd and Caddy) and
  `task validate:proxy:real` (Apache httpd and Squid in containers), with a
  remote container runner and a mutual TLS example.
- The design note `doc/design/mtls.md`.

### Changed

- The client runs and builds on Linux. The monotonic clock, the SIGPIPE
  handling and the macOS-only socket option are platform-specific, and the
  Linux results are recorded.
- Sends use `MSG_NOSIGNAL` and OpenSSL calls run under a per-thread SIGPIPE
  shield. The library no longer ignores SIGPIPE for the whole process.
- The connection cap counts connections across identities.
- A stream registered on an already failed connection fails at once.

### Fixed

- A read deadline on a blocking TLS socket surfaced as a closed connection on
  Linux. OpenSSL's want-read and want-write now count as a timeout.
- An upload that waits for flow-control credit stops once the peer has
  answered or reset the stream. The response already queued is read. Before,
  `Send` waited out the header timeout and lost it (nginx answers a missing
  client certificate this way).

## [0.20.0] - 2026-10-24

### Added

- The request observer. `WithRequestObserver`, `WithContext`, the header
  sink and `WithLogger` report the start of an attempt, its headers, a
  redirect, a retry and its end from `Send`, with a monotonic clock
  (`Http2.Clock`) behind the stamps.
- Arrival stamping: the reader thread stamps each inbound frame, and each
  `Read` reports one stamp on HTTP/2 and on HTTP/1.1. The aggregates travel
  with the end of the attempt.
- Observation of Server-Sent Events (stream identity, per-event stamps and the
  message observer) and of WebSocket sessions (handshake sink, one attempt per
  session, close details, counters, stamps and per-message reports).
- The connection pool statistics snapshot, on the pool and on the client.
- The examples `observer_tracing`, `observer_metrics`, `observer_logging` and
  `observer_all`, the overhead measurement (`task measure-observer`) and the
  documentation in `doc/design/request-observability.md`.
- A live cadence check for event streams in the SSE gate, and observed-session
  cases in the WebSocket gate.

### Changed

- The h2c probe write is stamped as the request-sent time.

### Fixed

- Two timing-sensitive tests, the pool statistics load test and a racy
  WebSocket test no longer depend on timing.

## [0.19.0] - 2026-10-12

### Added

- WebSocket over HTTP/1.1 (RFC 6455). `IHttpClient.Send(IWebSocketRequest)`
  opens `ws` and `wss` connections, directly or through any proxy kind, and
  returns an `IWebSocket` with `Request(n)` demand, the close handshake and a
  reader thread per socket. The units are `Http2.WebSocket` and
  `Http2.WebSocketClient`.
- The live gate `task validate:websocket` and an Autobahn client driver
  (`task validate:websocket:autobahn`).
- `ctHttp1`, a cleartext policy that speaks HTTP/1.1 with no probe, and the
  live gate `task validate:cleartext`.

### Fixed

- A server that declines the h2c `Upgrade` saw the request twice: the client
  closed the socket, redialled and sent it again. The client now keeps the
  socket, finishes the response on it and pools the connection.

## [0.18.0] - 2026-10-12

### Added

- Per-request proxy routing: `WithProxyEnvironmentVars` (`http_proxy`,
  `https_proxy`, `all_proxy`, `no_proxy`), `WithNoProxy`, `WithAllProxy` and
  `WithProxySelector` (`IProxySelector`). `WithProxy` stays.
- Proxies of the kinds `http://` (CONNECT), `https://` (TLS to the proxy, and
  TLS inside TLS over memory BIOs) and `socks5://` or `socks5h://`
  (RFC 1928 and RFC 1929). Loopback is always direct, and pooled connections
  are keyed by route.
- The units `Http2.Proxy` and `Http2.Socks`, the live gate
  `task validate:proxy`, the `proxy_env` example and `doc/design/proxy.md`.

### Fixed

- HTTP/1.1 over TLS stalled against servers that keep the connection open.
  Reads now use partial reads (`IPartialReader`).
- Bracketed IPv6 URLs parse.

## [0.17.0] - 2026-10-09

### Added

- Server-Sent Events: an event-stream reader, an event source and a
  reconnect loop with `Last-Event-ID`, the `sse_stream` example, the live
  gate `task validate:sse` with a reference event-stream server, and
  `doc/design/server-sent-events.md`.
- `WithSseReadTimeout` and `WithBodyReadTimeout`. A body read has its own
  deadline (0 waits indefinitely). A cancelled body read resets the stream
  with `RST_STREAM(CANCEL)` and raises `EHttpStreamError`.

### Changed

- `ICancellationToken` and `TCancellationToken` moved from `Http2.Client` to
  `Http2.Stream`. `Http2.Client` still reaches them, so callers keep working.
- The request forwards its cancel token and body deadline to the stream
  lease. Before, it dropped them.

## [0.16.0] - 2026-10-09

### Added

- Response decoding for `gzip` and `deflate` bodies, in the new unit
  `Http2.Encoding`. `WithAcceptEncoding` offers a coding. Nothing is offered
  by default, so an existing caller sees the same bytes. `ReadText`,
  `ReadAllBodyBytes` and the typed readers decode, and the headers
  `content-encoding` and `content-length` are removed because they no longer
  describe the body.
- A bare `deflate` stream is accepted, as servers send it under that name.

## [0.15.0] - 2026-10-08

### Added

- The example programs in `examples/` (GET, text POST, JSON, XML and a
  multi-threaded GET), built by `task examples`.
- `WithTextBody` and `ReadText` in `Http2.Client`.
- The optional unit `Http2.Readers`, the only unit that depends on fcl-json
  and fcl-xml: `TJsonObjectReader`, `TJsonReader<T>`, `TXmlDocumentReader`,
  `WithJsonBody`, `WithJsonText` and `WithXmlBody`. Parse failures surface as
  `EHttpProtocolError`.

### Fixed

- A caller blocked in a body read saw a timeout when the stream had failed
  (`RST_STREAM`, `GOAWAY` or a lost connection). It now sees
  `EHttpConnectionError`, and the transparent retry can act.
- A response `te` header that is not `trailers` is a stream protocol error
  (RFC 9113 section 8.2.2).
- The sanity and interop checks are deterministic: single-accept servers are
  gated on a log line, not on a TCP connect.

### Changed

- The design notes follow the shipped code, with diagrams, and the validation
  counts are regenerated.

## [0.14.0] - 2026-10-07

### Added

- HTTP CONNECT proxies through `WithProxy(host, port)`. The tunnel is made
  before TLS, so SNI, certificate checks and ALPN still address the origin,
  and the h2c and cleartext HTTP/1.1 paths tunnel the same way. A reply other
  than 2xx raises `EHttpConnectionError`, with no direct fallback.
- `MaxConnectionsPerHost` (default 4) and `MaxTotalConnections` (default 32).
  `WithMaxConnections(n)` sets both to n, and `MaxConnections` is an alias of
  the per-host cap.
- The README, the `Taskfile.yaml` and the Apache-2.0 licence.

### Fixed

- A 200 KB upload to a peer with a small window stalled for good. A stream
  `WINDOW_UPDATE` filled the lease queue and blocked the connection reader,
  the only thread that can apply further credit.
- Large uploads were flaky against a peer that lowers
  `SETTINGS_INITIAL_WINDOW_SIZE`. `DATA` could go out before the peer's
  `SETTINGS` was applied and drew `GOAWAY(FLOW_CONTROL_ERROR)`. `DATA` now
  waits for the settings; `HEADERS` does not.
- The sanity gate fails loudly instead of blaming the probe.

## [0.13.0] - 2026-10-06

The first recorded release. It holds the work from the first commit
(2026-10-05) to the package bump `558787c`.

### Added

- The HTTP/2 client in Free Pascal: the error hierarchy and the frame codec,
  headers, HPACK, flow control, the blocking queue and connection thread, the
  connection lifecycle, the stream lease, and the public API with the
  connection pool, requests and responses.
- TLS with ALPN `h2` on mORMot2's OpenSSL binding. FPC's bundled
  `opensslsockets` has no ALPN.
- Redirects (301, 302, 303, 307 and 308, bounded by `MaxRedirects`), timeouts,
  cancellation with `WithCancelToken`, the transparent retry of an idempotent
  request on a refused stream, and the observability and test seams (a mock
  socket drives the full `Send` path).
- `WithCACertFile` and `WithInsecureTls` for private and self-signed origins.
- Cleartext HTTP/2 and the HTTP/1.1 fallback: h2c with prior knowledge,
  h2c upgrade, the ALPN fallback and `Http2.Messages`, with the origin scheme in
  the pool key. HTTP/1.1 connections allow one stream.
- A Lazarus package (`http2client.lpk`).
- The validation ladder: unit tests, the `h2probe` conformance probe, the
  `nghttpd` interop gate (`task validate:interop`) and the 146-id
  h2-client-test-harness sweep (`task validate:harness`) with its recorded
  results.
- The design notes in `doc/design/` and the implementation plan.

### Fixed

- Received `DATA` returns `WINDOW_UPDATE` credit on the connection and the
  stream. Before, a response above the 64 KiB initial window stalled and
  surfaced as a timeout.
- A stream killed by `RST_STREAM`, `GOAWAY` or a lost connection raises
  `EHttpStreamError` and no longer shows as a timeout, so the transparent
  retry can act.
- `SETTINGS_INITIAL_WINDOW_SIZE` changes apply to open streams.
- Frame validation runs on every inbound frame. Malformed server frames used
  to queue silently and stall the request until the timeout.
- Response validation follows the RFCs: server push is disabled, errors are
  split into stream and connection errors, trailer `HEADERS`, `content-length`
  and the `HEAD` exemption are handled, and uppercase header names, pseudo-header
  order and `DATA` after `END_STREAM` are rejected.
- The ALPN result is read back through an interface reference.
