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
status: draft
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
The library today verifies the server only (`WithCACertFile`,
`WithInsecureTls`); it never answers a server's certificate request.

## Goals

- A consumer configures one client identity (certificate chain and private
  key) and every TLS connection the client opens presents it: HTTP/2,
  HTTP/1.1 fallback, Server-Sent Events and `wss`.
- The identity can come from PEM files, PEM held in memory, or a PKCS#12
  bundle, with an optional passphrase.
- A consumer that needs a different identity per origin, or that rotates the
  certificate while the process runs, supplies a selector that is asked at
  each dial.
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

New unit `Http2.ClientCert` (no dependency on the client, so a consumer can
load an identity to test it). Declarations are indicative; the story fixes
the final names.

```pascal
type
  /// a loaded identity; immutable once built, safe to share between threads
  IClientIdentity = interface
    function GetSubject: string;        // leaf subject, for diagnostics only
    function GetFingerprint: string;    // lowercase hex SHA-256 of the leaf DER
    function GetNotAfter: TDateTime;    // UTC expiry of the leaf
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

  /// asked once per dial; return nil to present no certificate
  IClientIdentitySelector = interface
    function Select(const AHost: string; const APort: Word): IClientIdentity;
  end;
```

Factory additions:

| Method | Meaning |
|---|---|
| `WithClientIdentity(identity)` | present this identity on every TLS dial |
| `WithClientCertificateFiles(cert, key, passphrase)` | sugar: load PEM files, then `WithClientIdentity` |
| `WithClientIdentitySelector(selector)` | ask the selector at each dial; replaces a fixed identity |
| `WithProxyClientIdentity(identity)` | present this identity to an `https://` proxy only |

A client with none of these configured behaves as before.

Loaders raise `EHttpTlsConfigError` (new, derives from `EHttpError`, as
`EHttpProxyConfigError` does) for an unreadable file, malformed PEM or
PKCS#12, a wrong passphrase, a key that does not match the leaf, or an
expired leaf. The message names the file and the OpenSSL reason, never the
passphrase or key bytes.

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
| TLS to an `https://` proxy | `WithProxyClientIdentity` only, never the origin identity |
| `http` and `ws` | none |

The proxy rule keeps an origin identity from being handed to a third party
that happens to relay the connection.

## Pooling

The pool keys connections by origin and route. A connection authenticated as
one identity must not serve a request that expects another, so when a
selector is installed the key gains the identity fingerprint. With a fixed
identity, or none, the key is unchanged. A rotated certificate therefore
opens new connections; connections that were authenticated with the old one
stay pooled until they close or idle out, and the pool statistics show
nothing special about them.

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
derived from the OpenSSL reason code. The connection layer recognises the
reason on the first failing read of a connection and raises this error to the
request that was waiting, instead of a generic closed-connection error.

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
  CA, expired, and selector answers, for TLS 1.2 and TLS 1.3 separately.
- Pool: two identities to one origin never share a connection.
- Live: a Python `ssl` server with `CERT_REQUIRED` and `nghttpd
  --verify-client`, with HTTP/2, HTTP/1.1, SSE and `wss` over it, directly
  and through each proxy kind.

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
