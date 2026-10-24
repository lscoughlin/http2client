---
title: "Real-proxy gate"
tags:
  - http2client
  - verification
  - proxy
status: done
up: "[validation](validation.md)"
related:
  - "[proxy](../design/proxy.md)"
  - "[mtls](../design/mtls.md)"
updated: 2026-10-24
---

# Real-proxy gate

`make validate-proxy-real` (`task validate:proxy:real`) drives the client
through two real proxy servers, Apache httpd 2.4 (`mod_proxy`,
`mod_proxy_connect`) and Squid 6.13 (the `ubuntu/squid` image), and reads
their access logs to prove what each request did. The older gate
(`make validate-proxy`, [validation](validation.md)) uses Python stand-ins
for the proxies; this one uses the software deployments run.

## How it runs

`tools/validate/proxy-real.sh` copies the tree to a Docker host through
`tools/container/remote-run.sh` (`PROXY_REAL_HOST`, default
`lscoughlin@liam-rzbox.local`; `PROXY_REAL_LOCAL=1` uses the local Docker) and
runs itself there. Everything is a sibling container from a stock image with
`--network host` on loopback ports `PR_BASE` (18400) and up; no image is
built:

| Container | Image | Role |
| --- | --- | --- |
| proxy | `httpd:2.4` | three listeners: open, Basic auth, TLS requiring a client certificate; config bind-mounted |
| proxy | `ubuntu/squid` | the same three listeners; config bind-mounted |
| tools | `http2client-dev` | compiles and runs `tools/validate/proxy_real_client.pas`; hosts the origins |

Origins: nghttpd (HTTP/2, plain and `--verify-client`), `proxy_servers.py`
(HTTP/1.1 TLS and plain), `ws_servers.py` (ws, wss), `sse_server.py`, and
`mtls_server.py` (requires a certificate from the fixture CA; logs the subject
it accepted). Origins are reached as `other.example`, which every container
maps to 127.0.0.1, because the client never proxies loopback names. The
proxies allow `CONNECT` to the origin ports only.

Each scenario runs the client once, records the exact client error class and
message, and checks the proxy's own log: the `CONNECT` line and status, the
user name on authenticated requests, the client-certificate subject where the
proxy can log one (Apache), and that no password or Basic token appears in any
log. Exit status is non-zero only for a failed assertion; a scenario a proxy
cannot do is `SKIP` with the reason.

## Results

Last run: 65 pass, 0 fail, 3 skip. Both proxies give the same result unless
noted.

| Scenario | Result (both proxies) |
| --- | --- |
| https GET through `CONNECT`, origin HTTP/2 | ok, `pool proto=h2`, one `CONNECT host:port 200` |
| https GET through `CONNECT`, origin HTTP/1.1 | ok, `http/1.1+tls`, origin saw `Host: other.example` |
| `http://` origin | ok, but as `CONNECT other.example:port`, not absolute-URI form (documented limit: no forwarding mode) |
| keep-alive, 2 requests (h2, HTTP/1.1, and through the https proxy) | one pooled connection, one `CONNECT` line |
| auth, no credentials | `EHttpConnectionError: proxy CONNECT failed: HTTP/1.1 407 Proxy Authentication Required`, 0.1 s |
| auth, wrong password | the same 407; the log names user `bob` |
| auth, right credentials | ok, log `bob "CONNECT ..." 200`; ws also ok |
| no secret in logs | no password or Basic token in the proxy log, container log or origin logs |
| ACL denial (port not allowed) | `EHttpConnectionError: proxy CONNECT failed: HTTP/1.1 403` (Apache: `403 Proxy Error`, Squid: `403 Forbidden`), 0.1 s, no hang |
| allowed port, nothing listening | `proxy CONNECT failed: HTTP/1.1 503 Service Unavailable`, 0.1 s |
| ws:// and wss:// echo | ok, `CONNECT` logged, origin logged the handshake |
| SSE over `http://` | 3 events, `CONNECT` logged |
| `https_proxy`, `http_proxy` (lookup supplied by the program) | routed through the proxy |
| `no_proxy`, `WithNoProxy` | direct: no proxy log line, origin reached |
| uppercase `HTTP_PROXY` | ignored (direct) |
| mTLS origin through the tunnel, h1 | ok; origin logged `commonName=mtls client`; proxy log has no certificate |
| mTLS origin without a certificate (h1, h2) | `EHttpTlsClientAuthError: ... certificate required` |
| mTLS origin through the tunnel, h2 | ok, `h2` |
| mTLS SSE and wss through the tunnel | ok |
| https proxy, origin h2 | ok, `h2` over TLS in TLS |
| https proxy plus origin mTLS (two identities) | ok; origin saw `mtls client` only, never `client two` |
| https proxy keep-alive, ACL denial, wss | one `CONNECT` for two requests; 403; ok |

Rows that differ by proxy:

| Scenario | Apache | Squid |
| --- | --- | --- |
| https proxy saw the proxy identity (log) | PASS: log `cert=CN=mtls client two` | SKIP: the Ubuntu build uses GnuTLS and has no `%ssl::>cert_subject` |
| https proxy, no client certificate | PASS: `EHttpTlsClientAuthError: certificate required` | SKIP: Squid cannot require one here; `tls-clientca=` aborts startup with `Unable to read client CAs` on the GnuTLS build, and the connection is accepted (observed ok) |
| https proxy, certificate from the wrong CA | PASS: `EHttpTlsClientAuthError: unknown ca` | SKIP: accepted, as above |

## Library findings

No client bug was found. The behaviours above match
[proxy](../design/proxy.md) and [mtls](../design/mtls.md), including the
documented limit that `http://` origins are tunnelled with `CONNECT`.

## Not covered

- The client's proxy identity reaching Squid cannot be shown in Squid's log
  (see the table). Squid's behaviour with a required client certificate would
  need an OpenSSL build of Squid.
- Absolute-URI forwarding is not exercised: the client does not use it.
- The mTLS h2 origin (nghttpd `--verify-client`) does not verify the
  certificate and does not log a subject, so only success and failure are
  asserted for it; the h1 origin logs the subject.
