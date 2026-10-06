---
title: "S05 — TLS, ALPN, and socket abstraction"
story-id: "05"
aliases:
  - "S05"
  - "tls-alpn-socket"
tags:
  - http2client
  - plan
  - story
status: done
up: "[[http2client]]"
depends-on:
  - "01-errors-frames"
parallel-with:
  - "02-headers"
  - "03-hpack"
  - "04-flow-control"
updated: 2026-10-05
---

# S05 — TLS, ALPN, and socket abstraction

## Goal

Provide a blocking byte-stream socket that performs the TLS handshake, offers
ALPN `h2`, and **fails loudly** if the server does not select `h2`. This is
the highest-risk story: FPC 3.2.4's bundled SSL units have no ALPN (see
[`../toolchain.md`](../toolchain.md)), so the implementation sits on
`mormot.lib.openssl11.pas`.

Spec: [`../../doc/design/transport.md`](../../doc/design/transport.md) §TLS
and ALPN, and §Memory model (`TInterfacedObject`, ARC).

**Scope change (2026-10-06):** cleartext `h2c` and HTTP/1.1 fallback are now
in scope. They are off by default and land in story S13; see
[`../../doc/design/fallback.md`](../../doc/design/fallback.md) and
[`13-cleartext-fallback.md`](13-cleartext-fallback.md). S05 keeps the TLS
and ALPN work.

## Tasks

| ID | Description | Files touched | Deliverable | Acceptance | Depends on |
|---|---|---|---|---|---|
| 05.1 | `IHttp2Socket` | `src/Http2.Tls.pas` | interface: `Read`, `Write`, `Close`, `Connected: Boolean`, timeouts | mock satisfies it | 00.3, 01.1 |
| 05.2 | Plain TCP socket | idem | `TSocketBase` using `ssockets` (`TInetSocket`) | connects to a local listener | 05.1 |
| 05.3 | OpenSSL context | idem | `SSL_CTX_new`, TLS method, `SSL_CTX_set_alpn_protos` with wire bytes `#2'h2'` | handshake to `nghttpd` succeeds | 00.3, 05.2 |
| 05.4 | ALPN verification | idem | after handshake, `SSL_get0_alpn_selected` must equal `h2`; otherwise raise `EHttpProtocolError` | test against an `http/1.1` server fails | 05.3 |
| 05.5 | Cert validation | idem | verify peer; allow a test-only "insecure" mode gated behind an explicit factory flag | self-signed `nghttpd` accepted only in insecure mode | 05.3 |
| 05.6 | SNI | idem | set `SSL_set_tlsext_host_name` from the origin host | test | 05.3 |
| 05.7 | Timeouts | idem | connect/read/write deadlines via non-blocking socket or `SO_RCVTIMEO`; map expiry to `EHttpTimeout` | test with a stalled peer | 05.2 |
| 05.8 | Dynamic loading | idem | resolve `libssl`/`libcrypto` via the mormot loader; document OpenSSL 3.6.5; LibreSSL noted as same surface | `openssl version`-compatible run | 00.3 |
| 05.9 | Vendoring guard | `third_party/mormot/` | minimal include set needed by `mormot.lib.openssl11.pas` builds standalone | compile with only vendored files | 00.3 |

## Unit tests

- `test/Http2.Tls.Test.pas` — ALPN wire bytes, "no h2 → raise", SNI set,
  insecure-mode toggle, timeout mapping, short-read loop.
- Integration (opt-in, needs `nghttpd`): handshake + selected protocol.

## Done when

- A real TLS connection to `nghttpd` negotiates `h2` and the selected
  protocol is asserted in a test.
- A server offering only `http/1.1` makes the client raise rather than
  silently continue.
- The vendored mormot revision is pinned and compiles with only the vendored
  files.
