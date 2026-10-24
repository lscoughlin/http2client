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
  certificate while the process runs, will supply a selector that is asked at
  each dial. That extension is described below under "Selector and proxy
  identity" and is not built yet.
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

## Vocabulary

| Term | Meaning |
|---|---|
| Identity | a leaf certificate, its chain, and the matching private key |
| Selector | a callback that returns the identity for a dial, or none |
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

```

Factory methods:

| Method | Meaning |
|---|---|
| `WithClientIdentity(identity)` | present this identity on every TLS dial; `nil` removes it |
| `WithClientCertificateFiles(cert, key, passphrase)` | sugar: load PEM files, then `WithClientIdentity` |

A client with neither configured behaves as before. `Build` raises
`EHttpTlsConfigError` for an identity whose leaf has expired, and for files
given to `WithClientCertificateFiles` that could not be loaded: the factory is
a value builder, so the load failure is held and raised at `Build`, and the
passphrase is not kept past the call. An injected socket factory
(`WithSocketFactory`) is a test seam and receives no identity.

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

| Connection | Identity |
|---|---|
| TLS to an origin, direct | the client identity, or the selector's answer |
| TLS to an origin inside a proxy tunnel | the same; the tunnel is transparent to the origin |
| TLS to an `https://` proxy | none; the origin identity is never handed to the proxy |
| `http` and `ws` | none |

The proxy rule keeps an origin identity from being handed to a third party
that happens to relay the connection.

## Pooling

The pool keys connections by origin and route. A client has one identity, so
the key is unchanged.

## Selector and proxy identity

Not built yet; the shape is fixed so the pieces added later fit:

- `IClientIdentitySelector.Select(host, port)` returns the identity for a dial,
  or `nil`, and `WithClientIdentitySelector` installs it in place of a fixed
  identity. A selector that returns a fresh `FromPemFiles` per dial gives
  rotation.
- When a selector is installed the pool key gains the identity fingerprint, so
  two identities to one origin never share a connection, and connections that
  were authenticated with a rotated-out certificate stay pooled until they
  close or idle out.
- `WithProxyClientIdentity(identity)` presents an identity to an `https://`
  proxy only.

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
  identity.
- Live: a Python `ssl` server with `CERT_REQUIRED` (TLS 1.2 and 1.3, HTTP/1.1,
  SSE and `wss`) and `nghttpd --verify-client` for HTTP/2 (it requests a
  certificate but does not verify it); `make validate-mtls`.

Fixtures (a private CA, a server certificate, an accepted client, an expired
client, a client from another CA) are generated by a script and checked in
beside the existing `test/certs`, with validity long enough that the suite
does not rot.

## Open questions

| Question | Recommendation |
|---|---|
| Passphrase as a callback so it is never in a long-lived string | Accept a string now, wipe it after loading; add a callback later if asked |
| Reload of files when they change on disk | Not built in; a selector that returns a fresh `FromPemFiles` per dial gives rotation |
| An identity on a proxy leg through the environment variables | No; explicit `WithProxyClientIdentity` only |
| Pin the server's certificate or key | Out of scope here; it is a server-verification feature, not a client-identity one |
| Expose the negotiated client identity on the outcome (`THttpOutcome`) | Not in this version; the selector's caller already knows what it returned |
