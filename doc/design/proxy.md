---
title: "Proxy Selection"
aliases:
  - "proxy"
  - "proxy-selection"
  - "proxy-environment"
tags:
  - http2client
  - design
  - api
  - transport
status: done
up: "[[http2client]]"
related:
  - "[[client-api]]"
  - "[[transport]]"
  - "[[fallback]]"
  - "[[errors-redirects]]"
  - "[[open-questions]]"
  - "[[toolchain]]"
updated: 2026-10-12
---

# Proxy Selection

A client reaches an origin either directly or through an HTTP proxy. This
note describes how the route for each request is chosen: a fixed proxy, the
`http_proxy` / `https_proxy` / `no_proxy` environment variables, a manual
bypass list, or a caller-supplied selector. The tunnel mechanics themselves
(`CONNECT`, the SOCKS5 handshake, TLS and ALPN inside the tunnel) are
described in [[transport]]. SOCKS5 follows RFC 1928, with username/password
authentication from RFC 1929; the proxy URL conventions follow Go's
`net/http` and `golang.org/x/net/proxy`.

## Route model

Every request resolves to one of two routes:

- **direct**: the TCP connection goes to the origin;
- **proxied**: the TCP connection goes to a proxy and a tunnel to the origin
  is negotiated before TLS, h2c or HTTP/1.1 begins. An `http://` or
  `https://` proxy is given an HTTP `CONNECT`; a `socks5://` proxy is given a
  SOCKS5 `CONNECT` command. The leg to the proxy is plain TCP for `http://`
  and `socks5://` and TLS for `https://`.

The route is chosen **per request**, not per client, so one client can reach
some origins directly and others through a proxy. A redirect is a new
request, so its target is routed again from scratch: a redirect from an
origin that bypasses the proxy to one that does not (or the reverse) changes
the route.

## Types

The proxy types live in a unit that depends on the RTL and `Http2.Errors`
only, `Http2.Proxy`, re-exported by
`Http2.Client` and the `Http2` umbrella unit.

```pascal
type
  /// pkHttp: HTTP CONNECT over TCP; pkHttps: HTTP CONNECT over TLS;
  /// pkSocks5: SOCKS5 CONNECT over TCP
  TProxyKind = (pkHttp, pkHttps, pkSocks5);

  /// one proxy endpoint. Credentials are optional.
  IProxy = interface
    function GetHost: string;
    function GetPort: Word;
    function GetKind: TProxyKind;
    function GetUserName: string;
    function GetPassword: string;
    property Host: string read GetHost;
    property Port: Word read GetPort;
    /// how the proxy is spoken to; also decides whether the leg to it is TLS
    property Kind: TProxyKind read GetKind;
    property UserName: string read GetUserName;
    property Password: string read GetPassword;
  end;

  /// chooses the route for one request URI
  IProxySelector = interface
    /// the proxy to use for AUri, or nil for a direct connection
    function SelectProxy(const AUri: string): IProxy;
  end;
```

`TProxy.Create(host, port)` and `TProxy.Create(host, port, user, password)`
build an `http` proxy; the overloads taking a leading `TProxyKind` build the
other kinds. A `nil` result from `SelectProxy` means "connect directly".
`AUri` is the absolute URL of the request about to be sent, in the same string
form `THttpRequest.Url` uses.

## Builder surface

```pascal
function WithProxy(const AHost: string; const APort: Word): THttpClientFactory;
function WithProxySelector(const ASelector: IProxySelector): THttpClientFactory;
function WithAllProxy(const AUrl: string): THttpClientFactory;
function WithProxyEnvironmentVars(const AEnable: Boolean = True): THttpClientFactory;
function WithNoProxy(const AList: string): THttpClientFactory;
```

| Method | Effect |
| --- | --- |
| `WithProxy(host, port)` | one fixed proxy for every request that the no-proxy list does not exempt |
| `WithAllProxy(url)` | one proxy URL for every scheme that has no more specific proxy; accepts the full URL grammar below (scheme, credentials, SOCKS5); an empty string clears it |
| `WithProxySelector(selector)` | the selector decides every request; nothing else is consulted |
| `WithProxyEnvironmentVars(enable)` | reads `http_proxy`, `https_proxy`, `all_proxy` and `no_proxy` from the process environment; off by default |
| `WithNoProxy(list)` | adds hosts that always connect directly (grammar below) |

The factory stays an immutable value record: each method returns a new record,
and the proxy fields are resolved into a single `IProxySelector` when
`Build` runs. Read-only accessors `ProxyHost`, `ProxyPort`,
`ProxyEnvironmentVars`, `NoProxy` and `ProxySelector` report the configured
values.

A test seam, `WithProxyEnvironmentLookup(lookup)`, replaces the process
environment with a caller-supplied `function(const AName: string): string`, so
tests of the environment rules never depend on the variables of the machine
running them. `nil` restores the process environment.

### Precedence

The sources are ranked, highest first:

1. a selector installed with `WithProxySelector`;
2. a fixed proxy installed with `WithProxy`;
3. a proxy URL installed with `WithAllProxy`;
4. the scheme-specific environment variables (`http_proxy` for `http`,
   `https_proxy` for `https`), when `WithProxyEnvironmentVars` is on;
5. the environment variable `all_proxy`, when `WithProxyEnvironmentVars` is on.

Explicit builder configuration therefore outranks the ambient environment, and
within the environment a scheme-specific variable outranks `all_proxy`.

The ranking is fixed at `Build`, so the order in which the `WithX` methods are
called has no effect. A custom selector is the sole authority: the no-proxy
list and the environment are not consulted for it, and a selector that wants
`no_proxy` behaviour implements it.

The built-in selectors are all subject to the loopback rule and the no-proxy
list: a host that matches either goes direct whether the proxy came from `WithProxy` or from the
environment.

With nothing configured the route is direct for every request, which is the
behaviour of a client that never mentions a proxy. The environment is never
read unless `WithProxyEnvironmentVars` is on.

### `WithNoProxy`

`WithNoProxy` takes the same comma-separated grammar as the `no_proxy`
variable and works with or without the environment switch.

- Repeated calls **append**: `WithNoProxy('a.example').WithNoProxy('b.example')`
  exempts both.
- When the environment switch is on, the list is the **union** of the
  `WithNoProxy` entries and the `no_proxy` variable.
- It applies to `WithProxy` and to environment proxies, and has no effect on a
  custom selector.
- An empty string adds nothing.

## Environment variables

`WithProxyEnvironmentVars` reads a **snapshot** of the environment when
`Build` runs. Later changes to the process environment do not affect an
existing client, which keeps routing deterministic and free of per-request
environment reads on a multithreaded client.

| Variable | Applies to |
| --- | --- |
| `http_proxy` | requests whose scheme is `http` |
| `https_proxy` | requests whose scheme is `https` |
| `all_proxy` | requests whose scheme has no `http_proxy` / `https_proxy` of its own |
| `no_proxy` | the bypass list, for both schemes |

Name resolution rules:

- The lowercase name wins over its uppercase form (`https_proxy` over
  `HTTPS_PROXY`, `all_proxy` over `ALL_PROXY`, `no_proxy` over `NO_PROXY`).
- Uppercase `HTTP_PROXY` is **ignored**. In a CGI-style process the `Proxy:`
  request header is exposed as `HTTP_PROXY`, so honouring it lets a remote
  client choose the proxy of a server-side program (the "httpoxy" attack).
  `http_proxy` in lowercase carries no such risk.
- An empty value counts as unset.
- `all_proxy` is the usual home of a `socks5://` value. Uppercase `ALL_PROXY`
  is honoured: only `HTTP_PROXY` carries the CGI risk.

### Proxy URL values

A proxy value is parsed as `[scheme://][user[:password]@]host[:port]`.

| Input | Result |
| --- | --- |
| `proxy.corp:3128` | `http` proxy, host `proxy.corp`, port `3128` |
| `http://proxy.corp:3128/` | the same; a trailing path is ignored |
| `http://proxy.corp` | port defaults to `80` |
| `https://proxy.corp:3129` | `https` proxy: TLS to the proxy, host `proxy.corp`, port `3129` |
| `https://proxy.corp` | port defaults to `443` |
| `http://user:p%40ss@proxy.corp:3128` | credentials `user` / `p@ss` (percent-decoded) |
| `socks5://proxy.corp` | SOCKS5 proxy, port defaults to `1080` |
| `socks5h://user:pw@proxy.corp:1080` | the same as `socks5`, with credentials |
| `socks4://proxy.corp` | rejected: `EHttpProxyConfigError` |

A value without a scheme is treated as `http`. The default port follows the
proxy's own scheme: `80` for `http`, `443` for `https` and `1080` for
`socks5`, matching Go. The schemes `http`, `https`, `socks5` and `socks5h` are
accepted; `socks4`, `socks4a`, a bare `socks` and any other scheme are
rejected rather than silently downgraded. The error is
raised by `Build` for environment values, so a bad value fails before any
request is sent.

## The no-proxy list

The list is comma-separated. Whitespace around entries is trimmed, empty
entries are skipped and matching is case-insensitive. Matching is lexical:
the client never resolves a name to compare addresses.

| Entry | Matches |
| --- | --- |
| `*` | every host |
| `example.com` | `example.com` and every subdomain (`a.example.com`) |
| `.example.com` | the same as `example.com` |
| `*.example.com` | the same as `example.com` |
| `example.com:8443` | `example.com` and its subdomains on port `8443` only |
| `10.1.2.3` | that IPv4 literal |
| `10.0.0.0/8` | every IPv4 literal inside the CIDR range |
| `[::1]` or `::1` | that IPv6 literal |
| `fd00::/8` | every IPv6 literal inside the CIDR range |

A suffix entry matches on a label boundary, so `example.com` does not match
`notexample.com`. An entry with a port constrains the request's effective
port (the explicit port, or `80` / `443` from the scheme). CIDR ranges
are matched bitwise for IPv4 and IPv6 literals; a hostname never matches a
CIDR entry.

`localhost` and loopback addresses are **always** connected directly, as in
Go's proxy resolution: the host `localhost`, any address in `127.0.0.0/8`,
and `::1`, with or without a port. This applies to the built-in selectors
whatever the environment or the no-proxy list contains, and does not apply to
a custom selector.

## Connection pooling

The pool key for a direct route is the plain origin, exactly as before.
A proxied route appends the proxy identity, `origin via [user@]host:port`
(`origin via tls:[user@]host:port` for an `https://` proxy and
`origin via socks5:[user@]host:port` for a SOCKS5 proxy), so:

- a direct connection and a tunnel to the same origin are never shared;
- a tunnel over a plain proxy connection and one over a TLS proxy connection
  are never shared;
- two different proxies never share a connection;
- the password is not part of the key; the user name is.

Because each route is a separate pool bucket, `MaxConnectionsPerHost` counts
connections **per origin and route**. `MaxTotalConnections` still bounds the
whole pool.

## TLS to the proxy

An `https://` proxy value makes the client run a TLS handshake with the proxy
before sending `CONNECT`. The origin's own TLS (or h2c, or HTTP/1.1) then runs
inside the tunnel, so a proxied `https` request carries two TLS layers.

- The proxy certificate is verified against the **proxy's host name**, never
  the origin's, using the trust settings of the client (`WithCACertFile`,
  `WithInsecureTls`).
- No ALPN is offered to the proxy; the `CONNECT` exchange is HTTP/1.1.
- `Proxy-Authorization` travels inside the encrypted leg, so credentials are
  not exposed to the network between client and proxy.
- A handshake failure with the proxy raises `EHttpConnectionError` and names
  the proxy host and port, not the origin.
- Timeouts apply per leg: the connect timeout covers the proxy TCP connect,
  the proxy handshake and the `CONNECT` exchange.

## Proxy authentication

When the proxy carries credentials, the `CONNECT` request includes a
`Proxy-Authorization: Basic` header built from the percent-decoded user name
and password. A proxy that answers `407` or any other non-2xx status surfaces
as `EHttpConnectionError` (`proxy CONNECT failed: <status line>`), the same as
any refused `CONNECT`. Passwords are never copied into an exception message,
an observer event or a pool key; the user name appears in the pool key only.

## SOCKS5

A `socks5://` (or `socks5h://`) proxy is spoken to with the SOCKS5 protocol of
RFC 1928. Only the `CONNECT` command is used; `BIND` and `UDP ASSOCIATE` are
not part of an HTTP client's needs. The exchange on the proxy connection is:

1. **Method selection.** The client sends `VER=5`, `NMETHODS` and the method
   list. Without credentials the list is `0x00` (no authentication). With
   credentials it is `0x00` and `0x02` (username/password). The server answers
   with its choice; `0xFF` ("no acceptable methods") is a failure. GSSAPI
   (`0x01`) is not offered.
2. **Authentication (only when the server chose `0x02`).** RFC 1929: the
   client sends `VER=1`, `ULEN`, the user name, `PLEN`, the password. A reply
   status other than `0x00` is a failure and the connection is closed.
3. **Request.** `VER=5`, `CMD=1` (`CONNECT`), `RSV=0`, `ATYP`, the target
   address and the target port in network byte order. The target host is sent
   as a domain name (`ATYP=3`, one length octet, at most 255 octets, no NUL)
   unless it is an IPv4 literal (`ATYP=1`, 4 octets) or an IPv6 literal
   (`ATYP=4`, 16 octets).
4. **Reply.** `VER`, `REP`, `RSV`, `ATYP` and a variable-length `BND.ADDR` plus
   `BND.PORT`. `REP=0` is success; the bound address is read in full and then
   ignored. After success the socket is a transparent byte stream to the
   origin, and TLS, h2c or HTTP/1.1 start on it as they do after `CONNECT`.

Behaviour that follows from this:

- **The proxy resolves names.** `socks5` and `socks5h` are the same: the
  client never resolves the origin's host name, so DNS for proxied requests
  happens at the proxy, as Go does for both spellings. No local lookup means
  no DNS leak around the proxy.
- **Credentials are not hidden.** RFC 1929 carries the user name and password
  in clear text over the connection to the proxy. There is no `socks5` over
  TLS.
- **User name and password lengths** are limited to 255 octets each by the
  protocol; longer values raise `EHttpProxyConfigError` at `Build`. An empty
  user name means "no credentials".
- **Failures** raise `EHttpConnectionError` with the reply meaning, not a
  number alone: `general SOCKS server failure` (1), `connection not allowed by
  ruleset` (2), `network unreachable` (3), `host unreachable` (4), `connection
  refused` (5), `TTL expired` (6), `command not supported` (7), `address type
  not supported` (8), and `unassigned reply code` for 9 to 255. A `VER` other
  than 5 in any reply, a method the client did not offer, or a short read is
  also `EHttpConnectionError`. Messages name the proxy host and port and never
  contain the credentials.
- SOCKS5 tunnels any scheme, so `http://` origins reach the proxy through the
  same `CONNECT` command as `https://` ones and are not subject to the HTTP
  proxy's restriction on `CONNECT` ports.

## Selector execution

`SelectProxy` runs on the **calling thread** of `Send`, once per hop, outside
any pool lock. A client shared between threads calls it from several threads at
once, so an implementation is invoked concurrently. An exception raised by the selector
propagates unchanged out of `Send`. A returned `IProxy` with an empty host or
a zero port raises `EHttpProxyConfigError`.

A WebSocket ([[websocket]]) is routed by the same selector. It is called once
with the URL's `http` or `https` form (`ws` maps to `http`, `wss` to `https`),
so `http_proxy`, `https_proxy`, `all_proxy` and `no_proxy` apply as for the
equivalent HTTP request, and the tunnel is a `CONNECT` or SOCKS5 connection
for `ws` as well.

## Interaction with the transport

- The tunnel (HTTP `CONNECT` or SOCKS5) is negotiated on the proxy
  connection before TLS, so SNI,
  certificate verification and ALPN target the origin, not the proxy
  ([[transport]]).
- Cleartext origins (`http://`, h2c and HTTP/1.1) tunnel the same way, which
  keeps one mechanism for every scheme.
- A declined h2c upgrade keeps the connection that carried it, so it opens no
  second route. Any redial the client makes (a refused stream sent again, a
  redirect) reuses the route of the request that triggered it. A cleartext
  origin behind a proxy follows the same cleartext policy, and a request is
  sent once.
- A TLS layer carried over another byte stream (an `https` origin behind an
  `https://` proxy) runs OpenSSL on a pair of memory BIOs; the bytes are moved
  between OpenSSL and the lower stream by the TLS socket itself. A socket
  that can return what is available instead of insisting on a full read says so
  through `IPartialReader`; the HTTP/1.1 codec reads through it, so a
  keep-alive connection is not held until the server closes it.
- A socket factory injected with `WithSocketFactory` for tests predates
  per-request routing and dials without a proxy, as it always has; the
  selector is still consulted, so pool keys reflect the route, but the
  injected factory ignores the proxy.

## mORMot2 as a reference

> [!info] mORMot2 is the reference implementation for most of the pieces
> The library already depends on mORMot2 for TLS and ALPN
> (`mormot.lib.openssl11`). The pinned checkout also contains small, careful
> implementations of nearly every parser and matcher that proxy routing needs.
> `Http2.Proxy` and `Http2.Socks` take **no** dependency on it: they are
> self-contained units that mirror these designs, with mORMot2's behaviour
> and edge cases as the guide. Names below are from the checkout recorded in
> [[toolchain]].

| mORMot2 piece | What it shows | Mirrored here by |
| --- | --- | --- |
| `TUri` and `TUri.From` (`mormot.net.sock`) | an RFC 3986 parser that splits scheme, userinfo, host, port and path, and keeps bracketed IPv6 literals such as `https://[::1]:123/` intact | the proxy URL parser and the request-URL parser |
| `TUri.UserPasswordBase64` | `Basic` credentials built as base64 of `user:password`, documented for `Proxy-Authorization` | the `CONNECT` authentication header |
| `TIp4SubNet` (`From('10.0.0.0/8')`, `Match`) | CIDR entries stored as a masked address plus a mask and matched with one AND and one compare | IPv4 entries of the no-proxy list |
| `NetIsIP4`, `NetIsIP6` | telling an address literal from a host name and decoding it to bytes | literal detection and IPv6 CIDR matching in the no-proxy list |
| `IsLocalHost` (`mormot.core.os`) | the loopback test (`127.x.x.x`, `::1`) | the always-direct loopback rule |
| `GetSystemEnv` (`mormot.core.os`) | one cross-platform path to environment variables | the environment snapshot |
| `TCrtSocket.DoOpenTunnel` (`mormot.net.sock`) | the `CONNECT` exchange: `Proxy-Authorization: Basic`, success on a `2xx` status line, headers read to the blank line | `CONNECT` tunnel establishment |
| `BIO_s_mem`, `BIO_read`, `BIO_write`, `BIO_ctrl`, `SSL_set_bio` (`mormot.lib.openssl11`) | the memory-BIO functions already bound for the TLS layer | TLS carried over another byte stream (`Http2.Tls`, which already uses this unit) |

Behaviour of the reference code that shapes the design:

- `IsLocalHost` tests the first bytes of the text for `127.` or `::1`. A name
  such as `127.example.com` also matches, so the loopback rule here applies
  the test only to a confirmed address literal. The host name `localhost` is a
  separate comparison.
- `GetSystemEnv` fills a process-wide cache on first use and serves later
  reads from it, so changes made to the process environment after that read do
  not show up through it. The snapshot taken here reads the environment
  directly.
- `GetProxyForUri` in `mormot.net.client` reads `HTTP_PROXY` and `HTTPS_PROXY`
  in uppercase only. This client reads the lowercase names first and ignores
  uppercase `HTTP_PROXY` (see "Environment variables").
- `TIp4SubNet` covers IPv4 only. IPv6 CIDR ranges are matched here.
- `TCrtSocket.DoOpenTunnel` accepts an `https://` proxy only when the
  destination itself is not TLS; it raises `unsupported dual TLS layers`
  otherwise. TLS inside TLS, as needed for an `https` origin behind an
  `https://` proxy, therefore has no mORMot2 counterpart and is built here
  on the memory-BIO functions.
- mORMot2 has no SOCKS client; SOCKS5 is implemented from RFC 1928 and
  RFC 1929.

## Known limits

- **`CONNECT` only.** An `http_proxy` for an `http://` origin conventionally
  means "forward the request in absolute form". This client tunnels instead,
  and many proxies refuse `CONNECT` to ports other than 443, answering `403`
  or `405`. Such a request fails with `EHttpConnectionError`; the client never
  falls back to a direct connection.
- SOCKS4, SOCKS4a, GSSAPI authentication and the `BIND` / `UDP ASSOCIATE`
  commands are not implemented.
- Forwarding mode is not provided; see above.
- Proxy auto-config (PAC) is not implemented.

## Errors

| Situation | Exception | Raised by |
| --- | --- | --- |
| unsupported proxy scheme (`socks4`, `socks4a` and others), credential longer than 255 octets for SOCKS5, malformed proxy value, empty host or zero port | `EHttpProxyConfigError` | `Build`, or `Send` for a selector result |
| proxy unreachable, proxy TLS handshake fails, `CONNECT` refused, `407`, SOCKS5 method or reply failure | `EHttpConnectionError` | `Send` |
| selector raises | the selector's own exception | `Send` |

`EHttpProxyConfigError` derives from `EHttpError`.

## Examples

Reading the environment, with local names exempted:

```pascal
Client := THttpClientFactory.Create
  .WithProxyEnvironmentVars
  .WithNoProxy('.internal.example')
  .Build;
```

One proxy for everything, including a SOCKS5 endpoint with credentials:

```pascal
Client := THttpClientFactory.Create
  .WithAllProxy('socks5://user:secret@127.0.0.1:1080')
  .Build;
```

A fixed proxy with an exemption:

```pascal
Client := THttpClientFactory.Create
  .WithProxy('proxy.corp', 3128)
  .WithNoProxy('.corp,10.0.0.0/8')
  .Build;
```

A custom selector that proxies only one host:

```pascal
type
  TOnlyApiSelector = class(TInterfacedObject, IProxySelector)
  public
    function SelectProxy(const AUri: string): IProxy;
  end;

function TOnlyApiSelector.SelectProxy(const AUri: string): IProxy;
begin
  if Pos('://api.example.com/', AUri) > 0 then
    Result := TProxy.Create('proxy.corp', 3128)
  else
    Result := nil;
end;

Client := THttpClientFactory.Create
  .WithProxySelector(TOnlyApiSelector.Create)
  .Build;
```
