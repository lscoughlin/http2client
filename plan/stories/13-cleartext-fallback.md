---
title: "S13 — Cleartext h2c and HTTP/1.1 fallback"
story-id: "13"
aliases:
  - "S13"
  - "cleartext-fallback"
tags:
  - http2client
  - plan
  - story
status: todo
up: "[[http2client]]"
depends-on:
  - "05-tls-alpn-socket"
  - "09-public-api"
parallel-with:
  - "10-redirects-timeouts"
  - "11-observability"
spec:
  - "[[fallback]]"
updated: 2026-10-06
---

# S13 — Cleartext h2c and HTTP/1.1 fallback

## Goal

Add cleartext HTTP/2 (`h2c`) and HTTP/1.1 fallback to the client. Both are
off by default. The caller turns them on. Spec:
[`../../doc/design/fallback.md`](../../doc/design/fallback.md).

This story was added on 2026-10-06. It replaces the earlier decision in
[[transport]] that both are out of scope. Story S05 keeps the TLS and ALPN
work.

## Tasks

| ID | Description | Files touched | Deliverable | Acceptance | Depends on |
|---|---|---|---|---|---|
| 13.1 | Factory surface | `src/Http2.Client.pas` | `TClearTextPolicy` (`ctReject`, `ctPriorKnowledge`, `ctUpgrade`) and the methods `WithHttp1Fallback`, `WithClearText` | the fluent chain compiles; the defaults stay strict | 09.2 |
| 13.2 | h2c prior knowledge | `src/Http2.Connection.pas`, `src/Http2.Tls.pas` | a cleartext socket that writes the HTTP/2 preface at once | a GET against `nghttpd --no-tls` returns `200` | 13.1, 05.1, 06.1 |
| 13.3 | h2c upgrade | `src/Http2.Client.pas` | send `Upgrade: h2c` and `HTTP2-Settings`; handle `101`; write the preface after the `101` | a GET returns `101` and then uses HTTP/2 | 13.2 |
| 13.4 | HTTP/1.1 codec | new `src/Http2.Http1.pas` | request line, `Host`, body framing, status line, header parse, body framing, keep-alive | a GET and a POST against a plain HTTP/1.1 server succeed | 13.1, 09.4 |
| 13.5 | ALPN fallback | `src/Http2.Tls.pas`, `src/Http2.Client.pas` | offer `h2` and `http/1.1` when fallback is on; select the codec from the ALPN result; an empty result means HTTP/1.1 | an `http/1.1`-only TLS server returns a response when fallback is on | 13.1, 13.4 |
| 13.6 | Pool keys and limits | `src/Http2.Client.pas` | keep origins with different schemes apart; set the stream limit to 1 for HTTP/1.1 | the pool test passes | 13.4 |
| 13.7 | Interop cases | `test/h2probe.pas`, `tools/validate/interop.sh` | A.10-A.13 | `make validate-interop` stays green | 13.2, 13.3, 13.4, 13.5 |

## Unit tests

- `test/Http2.Http1.Test.pas` — request build, response parse, body framing
  (content-length and chunked), keep-alive, a malformed response.
- `test/Http2.ClearText.Test.pas` — policy selection, strict-mode rejection,
  the upgrade handshake, the pool key, the stream limit.

## Done when

- A cleartext prior-knowledge GET against `nghttpd --no-tls` returns `200`.
- An h2c upgrade returns `101` and then uses HTTP/2 on the same connection.
- A GET and a POST against a plain HTTP/1.1 server succeed.
- An `http/1.1`-only TLS server returns a response when fallback is on.
- The default still rejects a cleartext request with `EHttpProtocolError`.
- `make validate-interop` exits 0 with cases A.10-A.13 passing.
