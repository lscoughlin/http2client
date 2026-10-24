---
title: "Mutual TLS (client certificates)"
aliases:
  - "mtls"
  - "client-certificates"
tags:
  - http2client
  - design
  - tls
  - api
status: done
up: "[http2client](../http2client.md)"
related:
  - "[client-api](client-api.md)"
  - "[transport](transport.md)"
  - "[proxy](proxy.md)"
  - "[errors-redirects](errors-redirects.md)"
  - "[request-observability](request-observability.md)"
  - "[open-questions](open-questions.md)"
updated: 2026-10-24
---

# Mutual TLS (client certificates)

A client can present a certificate during the TLS handshake, so a server that
asks for one can authenticate the caller. This note describes how a consumer
supplies that identity, where it is used, and how a rejection is reported.
The library verifies the server with `WithCACertFile` and `WithInsecureTls`;
a client identity is what answers the server's certificate request, and
without one the client answers none.

## Goals

- A consumer configures one client identity (certificate chain and private
  key) and every TLS connection the client opens presents it: HTTP/2,
  HTTP/1.1 fallback, Server-Sent Events and `wss`.
- The identity can come from PEM files, PEM held in memory, or a PKCS#12
  bundle, with an optional passphrase.
- A consumer that needs a different identity per origin, or that rotates the
  certificate while the process runs, supplies a selector that is asked at
  each dial (see "Selector and proxy identity").
- A caller that knows which service needs which certificate attaches the
  identity to the request itself (see "Per-request identity").
- An `https://` proxy can require its own client identity, kept apart from the
  origin identity: the two identities are separate and each goes to exactly one
  kind of peer.
- A bad configuration fails when the client is built, not on the first
  request.
- A server that rejects the identity produces a distinct error, even though
  TLS 1.3 reports the rejection after the handshake has "succeeded".
- Key material is never logged, never copied into an observer record and is
  not kept as a Pascal string longer than loading needs.

## Non-goals

- No hardware tokens, keychains or PKCS#11. The key must be loadable by
  OpenSSL from the formats above.
- No certificate generation, signing or renewal.
- No client certificate on cleartext (`http`, `ws`) connections; there is no
  handshake. Configuring one is not an error and has no effect there.
- No TLS renegotiation or post-handshake client authentication.
- No server-side mutual TLS.
- No file watching or automatic reload; rotation is a selector that returns a
  fresh identity.
- No identity from the proxy environment variables; `WithProxyClientIdentity`
  is explicit.
- No selector and no per-request choice for the proxy identity: it is one
  fixed identity per client.
- No identity on the `http://` or `socks5://` proxy leg: they have no TLS, so
  the proxy identity is unused there.
- No eviction of a busy connection: a connection of a replaced identity is
  closed only while idle, and only to make room under a connection cap.

## Vocabulary

| Term | Meaning |
|---|---|
| Identity | a leaf certificate, its chain, and the matching private key |
| Selector | an object that returns the identity for a dial, or none |
| Origin identity | the identity presented to an origin: the request's, else the selector's, else the client's fixed one |
| Request identity | an origin identity attached to one request |
| Proxy identity | the identity presented to an `https://` proxy, never to an origin |
| Rejection | the server closed the connection with a client-certificate alert |

## Public surface

Unit `Http2.ClientCert` (no dependency on the client, so a consumer can
load an identity to test it).

```pascal
type
  /// a loaded identity; immutable once built, safe to share between threads
  IClientIdentity = interface
    function GetSubject: string;        // leaf subject, for diagnostics only
    function GetFingerprint: string;    // lowercase hex SHA-256 of the leaf DER
    function GetNotAfter: TDateTime;    // UTC expiry of the leaf
    // the OpenSSL objects, borrowed by the TLS layer while the identity lives
    function GetCertificate: PX509;
    function GetPrivateKey: PEVP_PKEY;
    function GetChainCount: Integer;
    function GetChainCertificate(const AIndex: Integer): PX509;
    property Subject: string read GetSubject;
    property Fingerprint: string read GetFingerprint;
    property NotAfter: TDateTime read GetNotAfter;
  end;

  TClientIdentity = class
  public
    /// PEM chain file (leaf first) and PEM key file
    class function FromPemFiles(const ACertFile, AKeyFile: string;
      const APassphrase: string = ''): IClientIdentity; static;
    /// the same from memory
    class function FromPem(const ACertPem, AKeyPem: TBytes;
      const APassphrase: string = ''): IClientIdentity; static;
    /// a PKCS#12 file or bundle
    class function FromPkcs12File(const AFile: string;
      const APassphrase: string = ''): IClientIdentity; static;
    class function FromPkcs12(const AData: TBytes;
      const APassphrase: string = ''): IClientIdentity; static;
  end;

  /// chooses the identity of a TLS dial to an origin
  IClientIdentitySelector = interface
    function Select(const AHost: string; const APort: Word): IClientIdentity;
  end;

/// a selector that answers one identity (possibly nil) for every origin
function FixedIdentitySelector(
  const AIdentity: IClientIdentity): IClientIdentitySelector;
```

Factory methods:

| Method | Meaning |
|---|---|
| `WithClientIdentity(identity)` | the origin identity: present it on every TLS connection to an origin; `nil` removes it |
| `WithClientCertificateFiles(cert, key, passphrase)` | sugar: load PEM files, then `WithClientIdentity` |
| `WithClientIdentitySelector(selector)` | ask the selector for the origin identity at each dial, in place of a fixed identity; `nil` removes it |
| `WithProxyClientIdentity(identity)` | present this identity on the TLS leg to an `https://` proxy only; `nil` removes it. Also the `ProxyClientIdentity` property |

Request methods (on `THttpRequest` and `IWebSocketRequest`; an SSE request is a
`THttpRequest`):

| Method | Meaning |
|---|---|
| `WithClientIdentity(identity)` | the origin identity for this request; `nil` clears it. `ClientIdentity` reads it back |

`IWebSocketRequest` carries the identity as `IClientIdentityHandle`, the
TLS-free base interface of `IClientIdentity` in `Http2.IdentityHandle`, so the
WebSocket unit stays free of OpenSSL types; a caller passes an
`IClientIdentity` unchanged.

`WithClientIdentity`, `WithClientCertificateFiles` and
`WithClientIdentitySelector` replace one another: the last one called wins.
`WithProxyClientIdentity` is independent of them, and a request identity wins
over all three (see "Per-request identity").

A client with neither configured behaves as before. `Build` raises
`EHttpTlsConfigError` for a fixed or proxy identity whose leaf has expired, and for files
given to `WithClientCertificateFiles` that could not be loaded: the factory is
a value builder, so the load failure is held and raised at `Build`, and the
passphrase is not kept past the call.

An injected socket factory (`WithSocketFactory`) is a test seam and can present
an identity only when it implements `IIdentitySocketFactory`. `Build` raises
`EHttpTlsConfigError` when a fixed identity, a proxy identity or a selector is
configured with an injected factory that does not, and `Send` raises it before
dialling when an `https` or `wss` request carries an identity and the factory
cannot present it. Nothing is dropped silently.

Loaders raise `EHttpTlsConfigError` (derives from `EHttpError`, as
`EHttpProxyConfigError` does) for an unreadable file, malformed PEM or
PKCS#12, a wrong passphrase, or a key that does not match the leaf. An
expired leaf still loads, so `NotAfter` can be inspected; `Build` refuses it.
The message names the file and the OpenSSL reason, never the passphrase or
key bytes. An encrypted key with no passphrase raises instead of prompting on
the terminal.

## Loading and use

- A loader parses the certificate chain and key once, into OpenSSL
  `X509` and `EVP_PKEY` objects, checks them with
  `SSL_CTX_check_private_key` against a scratch context, then wipes any
  passphrase buffer it created. `IClientIdentity` owns the OpenSSL objects
  and frees them when the last reference goes.
- Each dial builds its `SSL_CTX` (as it does today), then installs the
  identity with `SSL_CTX_use_certificate`, the chain with
  `SSL_CTX_add_extra_chain_cert` (reference-counted, so the identity keeps its
  copy) and `SSL_CTX_use_PrivateKey`. No file is read on the dial path.
- The identity is installed whether or not the server has asked yet; OpenSSL
  sends it only if the server sends a `CertificateRequest`.
- `WithInsecureTls` and `WithCACertFile` are independent: they govern how the
  client verifies the server, the identity governs how the server verifies
  the client.
- Only `TTlsSocket.Establish` changes on the dial path. Every dial helper
  (direct, through a proxy tunnel, HTTP/1.1-only for WebSocket) reaches
  it, so one hook covers them; a test enumerates the helpers to make that
  claim checkable.

## Where it applies

The origin identity and the proxy identity are separate, and each goes to one
kind of peer.

| Connection | Identity presented |
|---|---|
| TLS to an origin, direct | the origin identity |
| TLS to an origin inside an HTTP CONNECT, SOCKS5 or `https://` proxy tunnel | the origin identity; the tunnel is transparent to the origin |
| TLS to an `https://` proxy | the proxy identity, or none; never the origin identity |
| `http://` or `socks5://` proxy leg | none: there is no TLS leg |
| `http` and `ws` to an origin | none: there is no handshake |
| `http` and `ws` to an origin through an `https://` proxy | the proxy identity on the proxy leg only |

The origin identity is, in order, the request's identity, the selector's
answer, the client's fixed identity, or none. It reaches only the TLS
handshake with the origin, on every route. The proxy identity reaches only the
handshake with an `https://` proxy and never the origin. Only the `TTlsSocket`
built for the proxy leg in `DialRoutedTransport` takes the proxy identity, and
the socket for the origin takes the origin identity whether or not a tunnel
carries it. The selector is asked with the origin's host and port on every
route, never the proxy's. WebSocket (`wss`) follows the same rules as a
request.

## Pooling

The pool keys connections by origin and route. With a fixed identity and no
request identity the key is unchanged, because the client has one origin
identity and one proxy identity. The proxy identity is fixed per client, so it
never varies the key, including for a cleartext origin behind an `https://`
proxy, which has no origin identity part at all.

The key carries the origin identity fingerprint
(`origin id=<fingerprint>`) in two cases:

- a request carries its own identity: the key carries that identity's
  fingerprint, so two identities to one origin never share a connection, and a
  request with none keeps the plain key (or the selector's key);
- a selector is installed: a TLS request's key carries the fingerprint of the
  selector's answer (an empty fingerprint for a `nil` answer), so two
  identities, or an identity and a `nil` answer, never share a connection.

Cleartext requests keep the plain key, since no origin identity is presented
to them. A request identity is never passed to the selector, and a connection
found by fingerprint is reused without calling it. `PoolStats` lists the keys with their `id=` suffix.

The caps do not follow the key. `MaxConnectionsPerHost` counts connections to
one origin and route across all identities, and `MaxTotalConnections` counts
the whole pool, so an origin never holds more than the cap however many
identities it is reached with. When a cap is reached and the origin holds an
idle connection of a different identity, the pool closes the oldest such idle
connection and dials for the new identity in its place; this is how a replaced
certificate gives up its connections. A connection with a request in flight is
never evicted: the new request waits for a slot, or fails with the usual
timeout, as the caps already define.

## Selector and proxy identity

`IClientIdentitySelector.Select(host, port)` returns the identity for a dial,
or `nil` to present no certificate. `WithClientIdentitySelector` installs it in
place of a fixed identity.

- It is called for each new TLS connection: on the dialling thread (the thread
  that called `Send`, for a WebSocket the thread that opens it), outside the
  pool lock, with the origin's host and port on every route, direct or through
  a tunnel. A request that reuses a pooled connection does not call it, a
  request that carries its own identity does not call it, and a cleartext
  request never does. It may be
  called from several threads at once (for different origins) and the dial
  waits for it, so it should not block for long. The lock is released while it
  runs. While one request is asking for an origin and route, a concurrent
  request that also needs a dial for it waits for that dial to publish its
  connection or fail instead of asking again, so two concurrent requests to a
  cold origin ask once and share the new connection (HTTP/2). The waiting
  request asks itself if the dial did not leave it a usable connection (the
  connection is busy, as an HTTP/1.1 one is, or the dial failed), so the
  guarantee is at most one call per request that needs a dial, and one call
  per dial when the new connection can serve the waiting request. The wait is
  bounded by the header timeout.
- An exception from the selector fails that dial with `EHttpTlsConfigError`
  carrying its message; nothing is dialled, and the next request asks again.
- An answer whose leaf has expired fails that dial with `EHttpTlsConfigError`
  naming the expiry date (never key material), before anything is dialled; a
  `wss` dial likewise. `Build` cannot check an identity the selector has not
  returned yet, so this check runs on each dial.
- How the pool asks without holding its lock: a request first looks for a
  connection under the fingerprint the last dial to that origin presented
  (remembered per origin). Only when none is eligible and a new connection may
  be opened does it release the lock, ask the selector, and key the new
  connection by the answer.
- Rotation needs no special code. A selector that returns a fresh identity
  (for example `TClientIdentity.FromPemFiles` on each call, or a cached
  identity that a background task replaces) is presented by the next new
  connection. Connections authenticated with the replaced certificate stay in
  the pool, finish the requests already on them and are used until they close
  or idle out, or until a cap needs their slot while they are idle. A pooled HTTP/2 connection takes every
  later request while it lives, so a new certificate is presented once that
  connection closes, idles out, or the pool opens another (for example because
  it is full: an idle connection of the replaced identity is then evicted, see
  "Pooling"). The selector is not asked in between.
- Per origin: the selector decides by host and port.

```pascal
type
  TByOrigin = class(TInterfacedObject, IClientIdentitySelector)
    function Select(const AHost: string; const APort: Word): IClientIdentity;
  end;

function TByOrigin.Select(const AHost: string; const APort: Word): IClientIdentity;
begin
  if (AHost = 'billing.example') and (APort = 443) then
    Result := TClientIdentity.FromPemFiles('billing.pem', 'billing.key')
  else
    Result := nil;
end;

Client := THttpClientFactory.Create
  .WithClientIdentitySelector(TByOrigin.Create)
  .Build;
```

`WithProxyClientIdentity(identity)` presents an identity on the TLS leg to an
`https://` proxy, so a proxy that requires a client certificate accepts the
client, and to nothing else. It is fixed per client (no selector), and is
checked at `Build` like a fixed identity: an expired leaf raises
`EHttpTlsConfigError`. An origin identity does not satisfy a proxy that asks
for one: the proxy refuses the handshake and the request fails before the
origin is dialled. An `http://` or `socks5://` proxy has no TLS leg, so the
proxy identity is unused there.

## Per-request identity

A caller that knows which service needs which certificate attaches the origin
identity to the request:

```pascal
Resp := Client.Send(THttpRequest.Create(hmGet, 'https://billing.example/')
  .WithClientIdentity(BillingIdentity));
```

- Precedence for the origin identity at dial time: the request's identity,
  else the selector's answer, else the client's fixed identity, else none.
- It works through every route (direct, HTTP CONNECT, SOCKS5, `https://`
  proxy) and goes to the origin only; the proxy leg still uses only
  `WithProxyClientIdentity`. A cleartext request ignores it.
- The pool key carries its fingerprint, so requests with different identities
  never share a connection, and a request with none keeps today's key. A
  second request with the same identity reuses the connection, and the
  selector is not asked for either.
- Requests stay immutable: `Clone`, `WithUrl`, `DropBody`, `WithMethodToken`
  and the other `With` methods carry it.
- Send raises `EHttpTlsConfigError` before dialling when the identity has
  expired (a `wss` request likewise), and when the injected socket factory
  cannot present it.
- Redirects: the identity follows a redirect to the same origin (scheme, host
  and port) and is dropped on a redirect to another origin, which falls back to
  the selector's answer or the client's fixed identity. It behaves like a
  credential header: it must not be handed to a third party the redirect names.
- An SSE reconnect is the same origin and keeps it.
- `IWebSocketRequest.WithClientIdentity` does the same for `wss`; a `ws`
  request ignores it.

## Rejection

A server that requires a certificate and does not accept ours closes the
connection with an alert. When this is seen depends on the version:

- TLS 1.2: `SSL_connect` fails, so the handshake raises.
- TLS 1.3: the client finishes its handshake before the server validates the
  certificate, so `SSL_connect` returns success and the alert arrives on the
  first read.

Both are reported as `EHttpTlsClientAuthError` (new, derives from
`EHttpConnectionError`), carrying the alert name (`certificate required`,
`bad certificate`, `unknown ca`, `certificate expired`, `certificate
revoked`, `access denied`, `unsupported certificate`, `unknown certificate`)
derived from the OpenSSL reason code (`SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED`,
`SSL_R_SSLV3_ALERT_BAD_CERTIFICATE`, `SSL_R_TLSV1_ALERT_UNKNOWN_CA` and the
matching `SSL_R_*` values in `openssl/sslerr.h`). A TLS 1.2 server that gets no
certificate answers `handshake failure`; that is reported as a rejection only
after the server sent a `CertificateRequest`, so an unrelated handshake failure
stays a generic connection error. The TLS socket recognises the reason on the
handshake or on the first failing read of a connection; the connection layer
carries the alert to the request that was waiting, instead of a generic
closed-connection error. A connection that fails before a stream registers
fails that stream at once rather than leaving it to the header timeout.

Consequences:

- It is not retried. A transparent retry of a request that failed this way
  would only repeat the rejection; the retry rule treats it as a final error.
- It is not a redirect trigger and never falls back to HTTP/1.1.
- A request observer sees it as the attempt's `Error`; no new outcome field is
  added in this version.
- A connection that reads some bytes before the alert (an alert after real
  application data) is not classified this way; only an alert on the first
  read is.

## Logging and secrets

- The library logs the identity's `Subject` and `Fingerprint` at debug level
  when a dial installs it; never the PEM, the path of the key file, or the
  passphrase.
- `Subject` can be personal data; it is logged only through the logger the
  consumer installed.
- Error messages quote file names the consumer supplied and OpenSSL reasons
  only.

## Testing

- Unit: each loader against fixtures (valid, passphrase right and wrong,
  mismatched key, truncated PEM, empty chain, expired leaf, PKCS#12 with and
  without a chain), and that no loader error contains the passphrase.
- Loopback: an in-process OpenSSL server that requires a client certificate
  against a mock-free client dial: accepted identity, none configured, wrong
  CA and expired, for TLS 1.2 and TLS 1.3 separately, over HTTP/2, HTTP/1.1,
  SSE and `wss`, and through a CONNECT, a SOCKS5 and an `https` proxy. A
  source scan checks that every `TTlsSocket` for an origin is built with the
  identity. The selector cases count its calls (once per dial, not per
  request, never for cleartext), check the thread and that another thread can
  take the pool lock meanwhile, choose a different identity per origin, answer
  `nil`, throw, rotate between two dials (the old connection still delivers
  its response and the pool holds two keys), refuse an expired answer before
  dialling (HTTP/2 and `wss`), ask once for two concurrent cold requests and
  cover `wss`. The cap cases check that rotation at `MaxConnectionsPerHost` and
  at `MaxTotalConnections` evicts the idle connection of the old identity, that
  a busy one is never evicted, and that two identities share the host cap. An
  injected factory without `IIdentitySocketFactory` is refused at `Build` for a
  fixed identity, a proxy identity and a selector, and at `Send` for a request
  identity (`https` and `wss`). The proxy cases
  use a loopback `https` proxy that requires a client certificate: through
  CONNECT, SOCKS5 and the `https` proxy (TLS 1.2 and 1.3) the origin sees the
  origin identity, the `https` proxy sees only the proxy identity, the origin
  never sees the proxy identity, the proxy identity alone is refused by an
  origin that asks for a certificate, the origin identity alone is refused by
  a proxy that asks for one, the selector is asked with the origin's host and
  port on every route, and a cleartext origin behind the proxy gets the proxy
  identity on the proxy leg and no identity part in its key. The request
  identity cases cover every route, two identities on one origin never
  sharing a connection, precedence over the selector and the fixed identity,
  the plain key for a request with none, redirects (same origin keeps it,
  another origin drops it), `wss`, SSE and an expired identity raised before
  anything is dialled.
- Live: a Python `ssl` server with `CERT_REQUIRED` (TLS 1.2 and 1.3, HTTP/1.1,
  SSE and `wss`) and `nghttpd --verify-client` for HTTP/2 (it requests a
  certificate but does not verify it); two Python origins that each serve one
  identity only, reached by one client with a selector; and a Python `https`
  proxy that requires a client certificate in front of an origin that requires
  another, and an HTTP CONNECT proxy, with the logs of both showing which
  identity each saw, and a per-request identity case;
  `make validate-mtls`.

Fixtures (a private CA, a server certificate, two accepted clients, an expired
client, a client from another CA) are generated by a script and checked in
beside the existing `test/certs`, with validity long enough that the suite
does not rot.

## Open questions

| Question | Recommendation |
|---|---|
| Passphrase as a callback so it is never in a long-lived string | Accept a string now, wipe it after loading; add a callback later if asked |
| Pin the server's certificate or key | Out of scope here; it is a server-verification feature, not a client-identity one |
| Expose the negotiated client identity on the outcome (`THttpOutcome`) | Not in this version; the selector's caller already knows what it returned |
