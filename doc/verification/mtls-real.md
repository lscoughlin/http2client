---
title: "Mutual TLS against real servers"
aliases:
  - "mtls-real"
tags:
  - http2client
  - verification
  - tls
status: validated
up: "[http2client](../http2client.md)"
related:
  - "[mtls](../design/mtls.md)"
  - "[validation](validation.md)"
updated: 2026-10-24
---

# Mutual TLS against real servers

`make validate-mtls-real` (`tools/validate/mtls-real.sh`) drives the client,
through `examples/mtls_get.pas`, against three server stacks that require a
client certificate. It complements `make validate-mtls`, whose servers are a
Python `ssl` script and `nghttpd`.

## Method

The script runs on a Docker host (`MTLS_REAL_HOST`, default
`lscoughlin@liam-rzbox.local`; `local` uses this machine). It copies the tree
with `tools/container/remote-run.sh`, compiles the example in the dev image,
and starts the servers as sibling containers from their stock images with
`--network host` on ports from `MTLS_REAL_BASE` (default 9440). The client runs
in a container on the same network. Every client run is under a 20 second
timeout.

| Server | Configuration |
|---|---|
| nginx 1.28 | `ssl_verify_client on`, `http2 on`, `ssl_client_certificate` the fixture CA, `ssl_verify_depth 3` |
| Apache httpd 2.4 | mod_ssl `SSLVerifyClient require`, `Protocols h2 http/1.1`, `SSLCACertificateFile` the fixture CA |
| Caddy 2 | `client_auth { mode require_and_verify  trust_pool file ... }` |

Each server has three listeners, all with the fixture server certificate for
`localhost`: HTTP/2 with TLS 1.2, HTTP/2 with TLS 1.3, and HTTP/1.1 with TLS 1.3
(no `h2` in ALPN, so the client's HTTP/1.1 fallback carries the request). Each
echoes the client subject, the protocol and the TLS version in the response
body, which the example prints with `MTLS_PRINT_BODY=1`.

## Scenarios

| Scenario | Identity | Expected |
|---|---|---|
| accepted | fixed identity (`WithClientCertificateFiles`) | 200; echoed subject is `mtls client`; expected protocol and TLS version |
| request | none fixed, one attached to the request | 200; echoed subject is `mtls client two` |
| none | none | a rejection |
| wrong CA | an identity issued by another CA | a rejection |

A rejection is `EHttpTlsClientAuthError` with a plausible alert name. A server
that completes the handshake and answers an HTTP 4xx status (nginx does) has
sent no alert, so the row records `HTTP <status>` and passes. A generic
connection error, a hang, an implausible alert or a mixed result across repeats
fails the gate, unless the case is listed in `KNOWN` in the script (empty
today). Rejections are repeated `MTLS_REPEAT` times (default 5), because a
server that resets the connection with unread client data could turn the alert
into a generic error only some of the time.

## Results

Ubuntu 24.04 x86_64, nginx 1.28.3, Apache 2.4.69, Caddy 2.11.7. All 36 rows
pass; the rejection rows were also run with 20 repeats, with one distinct
outcome per row.

| Server | Listener | accepted | request | none | wrong CA |
|---|---|---|---|---|---|
| nginx | h2 / TLS 1.2 | pass | pass | HTTP 400 | HTTP 400 |
| nginx | h2 / TLS 1.3 | pass | pass | HTTP 400 | HTTP 400 |
| nginx | h1 / TLS 1.3 | pass | pass | HTTP 400 | HTTP 400 |
| httpd | h2 / TLS 1.2 | pass | pass | alert `handshake failure` | alert `unknown ca` |
| httpd | h2 / TLS 1.3 | pass | pass | alert `certificate required` | alert `unknown ca` |
| httpd | h1 / TLS 1.3 | pass | pass | alert `certificate required` | alert `unknown ca` |
| Caddy | h2 / TLS 1.2 | pass | pass | alert `handshake failure` | alert `unknown ca` |
| Caddy | h2 / TLS 1.3 | pass | pass | alert `certificate required` | alert `unknown ca` |
| Caddy | h1 / TLS 1.3 | pass | pass | alert `certificate required` | alert `unknown ca` |

nginx rejects at the HTTP layer: with `ssl_verify_client on` it finishes the
handshake and answers `400` (its internal 495/496), so no TLS alert exists for
the client to report. The script prints the full table with the exact error on
every run.

## Not covered

- Only GET requests: the rejection race with a large unread request body is not
  exercised.
- TLS 1.2 is not run with HTTP/1.1 only, and the client has no option to pin
  its own TLS version; versions are pinned on the server.
- Certificate revocation, an expired server certificate and `ssl_verify_client
  optional` are not run.
