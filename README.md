# http2client

An HTTP/2 client library for Free Pascal.

The client speaks HTTP/2 (RFC 7540 and RFC 9113) and HPACK (RFC 7541).
The library is written in Object Pascal. It uses OpenSSL for TLS, and it has
no other C dependency.

The client multiplexes many streams on one TCP connection.
One request uses one stream. The pool keeps many TCP connections.

## What the client does

- Uses TLS with ALPN. The peer must select `h2`.
- Sends and receives the HTTP/2 frames. It handles HPACK and flow control.
- Runs one request at a time on each stream. Many streams share one connection.
- Follows redirects. It has a redirect limit.
- Applies connect, header, and idle timeouts. A caller can cancel a request.
- Reports errors through an exception hierarchy. It reports events through an
  observer interface.
- Speaks cleartext `h2c` when the caller enables it. Cleartext has three modes:
  prior knowledge, upgrade, and HTTP/1.1 with no probe. A server that declines
  the upgrade answers the request on the same connection, so the client sends
  the request once.
- Falls back to HTTP/1.1 when the peer does not offer `h2`. The caller must
  enable the fallback.
- Reads Server-Sent Events (`text/event-stream`) incrementally, with a
  per-request body read timeout, read-side cancellation, and an optional
  reconnect-and-resume loop. See
  [`doc/design/server-sent-events.md`](doc/design/server-sent-events.md).
- Opens WebSocket connections (`ws://`, `wss://`; RFC 6455) with a listener,
  demand-driven delivery, fragment-aware sends and the closing handshake,
  directly or through any of the proxy kinds. See
  [`doc/design/websocket.md`](doc/design/websocket.md).

The default is strict. The client uses `h2` over TLS only.

## Requirements

| Item | Value |
|---|---|
| Free Pascal | 3.2.4 or later. Use `{$mode delphi}`. |
| OpenSSL | Version 3. Set `OPENSSL_LIBPATH` to the library directory. |
| mORMot2 | A pinned checkout in `third_party/mORMot2`. |
| Task | Version 3.54 or later. This tool runs the build tasks. |
| Docker | Only for the conformance harness. The image is not on a registry. |
| nghttpd | Only for the interop gate. Install it with `brew install nghttp2`. |

macOS example for the OpenSSL path:

```sh
export OPENSSL_LIBPATH=/opt/homebrew/opt/openssl@3/lib
```

## Set up the environment

Do these steps one time after you clone the repository:

```sh
task setup
```

The `setup` task does three things:

1. Clones the pinned `third_party` checkouts.
2. Installs `nghttp2` when `nghttpd` is absent.
3. Builds the local Docker image `h2-test-harness`.

Each step is safe to repeat. A second run does no work.

The validate tasks run the setup steps when they need them. You can therefore
start with `task validate`.

`make` also works. The Makefile runs the build and the unit suite.

## Build

```sh
task build
```

The `build` task compiles every library unit into `bin/`. The output is the
`.ppu` and `.o` files for each unit. The task does not create a linked binary,
because the library has no program of its own. To use the units in your own
program, add `-Fu` for the `src` and `bin` directories. See the `FPCFLAGS`
value in `Taskfile.yaml`.

The umbrella unit `Http2` re-exports the core library. `Http2.Readers.pas`
is not part of it and is optional: it adds JSON and XML helpers and is the only unit that depends on
`fcl-json` or `fcl-xml`. Name it in your `uses` clause only when you need it.
See [Examples](#examples).

## Test

```sh
task test
```

The `test` task compiles the library and the unit suite. Then it runs the
suite. The suite has 648 tests (the SSE live case skips unless
`SSE_TEST_URL` is set; run it with `task validate:sse`).

The suite uses `fpcunit` and a mock socket. It needs no network and no server.

Every test must pass. The task returns a non-zero exit code when a test fails.

## Validate

The validation suite has four levels, plus two opt-in live gates. Each level
has its own task.

| Task | What it checks | Time |
|---|---|---|
| `task test` | The unit suite. | Under 1 minute |
| `task validate:sanity` | The probe classifies outcomes correctly. | Seconds |
| `task validate:interop` | A real TLS peer, `nghttpd`. Cases A.1 to A.13. | About 1 minute |
| `task validate:harness` | The RFC conformance harness. 146 case ids. | About 30 minutes |
| `task validate:sse` | The opt-in live SSE case against `tools/validate/sse_server.py`. | Seconds |
| `task validate:websocket` | The opt-in live WebSocket case: `ws` and `wss`, directly and through an HTTP `CONNECT`, https and SOCKS5 proxy, against `tools/validate/ws_servers.py`, plus a check of the servers' logs (mask bit on every client frame, close codes, route). `task validate:websocket:autobahn` runs the Autobahn|Testsuite client cases (Docker). | Seconds |
| `task validate:cleartext` | The opt-in live cleartext case: a bodyless `GET`, `POST`, `DELETE` and `HEAD` under `ctUpgrade` and `ctHttp1` against `tools/validate/h1_counter_server.py`, an HTTP/1.1-only server that logs each request; every request arrives once. | Seconds |
| `task validate:proxy` | The opt-in live proxy case: HTTP `CONNECT`, https and SOCKS5 proxies from `tools/validate/proxy_servers.py`, with and without credentials, HTTP/2 through each proxy kind when `nghttpd` is installed, plus a check of the proxy logs. | Seconds |

Run the full suite with one command:

```sh
task validate
```

`task validate` runs the setup, then the four levels in order. It stops at the
first level that fails.

Run the fast subset with this command:

```sh
task validate:fast
```

`task validate:fast` runs the setup and every level except the harness sweep.
Use it during development.

### Sanity checks

The sanity script proves that the probe does not report success always.
It checks five conditions, run by `task validate:sanity` (or
`tools/validate/h2probe-sanity.sh`):

1. An unreachable port gives exit code 2 (connection error).
2. A reset that follows a 200 response gives exit code 3 (stream error).
   The peer is a local fabricated server (`tools/validate/fake_rst_server.py`)
   that sends `HEADERS(200)` then `RST_STREAM(CANCEL)` and holds the socket
   open, so classification is deterministic with no container or host-port
   race.
3. Bad command-line usage gives exit code 1.
4. A peer that does not offer `h2` over ALPN gives exit code 2.
5. A live `nghttpd` GET gives exit code 0. This check is a SKIP when
   `nghttpd` is absent.

The script waits for each server to open its port. If a server does not
start, the script reports an infrastructure failure. It does not report a
probe failure. A probe failure always means that the probe is wrong.

### Interop gate

The interop script starts `nghttpd` with the test certificates. Then it runs
the cases A.1 to A.13. It prints a table and exits 0 when no mandatory case
fails.

Case A.8 is a SKIP. No `nghttpd` trigger can force a GOAWAY in the middle of
a request. The unit suite covers the same behavior.

Cases A.11 and A.12 are SKIPs when Docker is absent. A.10–A.13 cover the
cleartext and fallback paths (h2c prior knowledge, h2c upgrade, HTTP/1.1
fallback, strict-mode reject).

### Conformance harness

The harness script runs the image `h2-test-harness`. For each case id it does
two runs:

1. It runs the harness reference client. This run declares an outcome.
2. It runs our probe. This run gives our outcome.

Then the script compares the two outcomes. The verdicts are:

- MATCH. The two outcomes are equal.
- BETTER. We found an error. The reference did not.
- WORSE. The reference found an error. We did not. **This is a failure.**
- CLASS-DIFF. Both sides found an error. The levels are different.
- UNKNOWN. Neither side resolved the case.

The gate passes when there are zero WORSE rows.

The last full sweep (2026-10-08) gave this result:

| Verdict | Count |
|---|---|
| MATCH | 29 |
| BETTER | 41 |
| WORSE | 0 |
| CLASS-DIFF | 13 |
| UNKNOWN | 63 |

`PASS = MATCH + BETTER = 70; FAIL = WORSE = 0`.

This is a **representative snapshot**, not a reproducible constant: individual
rows move between runs within a few load-sensitive families, and the client's
own fixes moved some of them (e.g. `8.1.2.2/2` went from `success` to
`stream-error` once response `te` validation landed). What is stable is the
strictness level — **WORSE = 0** whenever the sweep runs alone.

The script writes the table to `bin/validation-results.md`; the raw per-id
log is `doc/verification/harness-run-full.log`.

The harness server binds host port 8080, so **the sweep must run alone**. A
second concurrent sweep, or any other heavy work, makes the probe hit the
wrong peer and records spurious `timeout`/`WORSE` rows. Re-check a suspect id
in isolation:

```sh
HARNESS_IDS="5.4.1/2" bash tools/validate/harness.sh
```

## Use the client

This example builds a client and sends one GET request:

```pascal
uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils, Classes, Http2.Client;

var
  Client: IHttpClient;
  Response: IHttpResponse;
begin
  Client := THttpClientFactory.Create
    .WithMaxConnectionsPerHost(2)
    .WithMaxTotalConnections(8)
    .WithMaxStreamsPerConnection(50)
    .WithFollowRedirects(False)
    .Build;
  Response := Client.Send(
    THttpRequest.Create(hmGet, 'https://api.example/things'));
  // Response.StatusCode and Response.Headers are ready here.
  // Read Response.Body until Eof to get the body.
end;
```

A caller can change the protocol behavior:

```pascal
uses Http2.Client, Http2.Tls;   // Http2.Tls gives the TClearTextPolicy values

// Accept cleartext h2c as prior knowledge.
Client := THttpClientFactory.Create
  .WithClearText(ctPriorKnowledge)
  .Build;

// Speak plain HTTP/1.1 to a cleartext server, with no Upgrade request.
Client := THttpClientFactory.Create
  .WithClearText(ctHttp1)
  .Build;

// Accept an HTTP/1.1 peer when the peer does not offer h2.
Client := THttpClientFactory.Create
  .WithHttp1Fallback(True)
  .Build;
```

`TClearTextPolicy` lives in `Http2.Tls`. You must name that unit in your
`uses` clause to write the value `ctPriorKnowledge`, `ctUpgrade` or `ctHttp1`.

A client reaches each origin directly or through an HTTP proxy, chosen per
request:

```pascal
// Read http_proxy, https_proxy and no_proxy when the client is built.
Client := THttpClientFactory.Create
  .WithProxyEnvironmentVars
  .WithNoProxy('.internal.example')
  .Build;

// One proxy URL for every scheme (the manual form of all_proxy).
Client := THttpClientFactory.Create
  .WithAllProxy('socks5://user:pw@127.0.0.1:1080')
  .Build;

// A fixed proxy.
Client := THttpClientFactory.Create
  .WithProxy('proxy.corp', 3128)
  .Build;

// A SOCKS5 proxy; the proxy resolves host names.
Client := THttpClientFactory.Create
  .WithProxyEnvironmentVars   // e.g. https_proxy=socks5://user:pw@127.0.0.1:1080
  .Build;

// A selector returns a proxy per URI, or nil for a direct connection.
Client := THttpClientFactory.Create
  .WithProxySelector(MySelector)   // MySelector implements IProxySelector
  .Build;
```

A selector overrides `WithProxy`, which overrides `WithAllProxy`, which overrides the environment. The
environment is read only when `WithProxyEnvironmentVars` is on. Proxies are
reached with a `CONNECT` tunnel, over TLS for an `https://` proxy value, or a SOCKS5 `CONNECT` for `socks5://`; see `doc/design/proxy.md`.

For a test against a private certificate, use `WithCACertFile`.
For a self-signed certificate, use `WithInsecureTls`.

### Text, JSON, and XML helpers

`WithTextBody` and `ReadText` live in `Http2.Client`:

```pascal
uses Http2.Client;

Response := Client.Send(
  WithTextBody(THttpRequest.Create(hmPost, Url), 'hello'));
WriteLn(ReadText(Response));
```

JSON and XML live in the optional `Http2.Readers` unit. The read helpers
parse the whole body and return an object **you own** (free it):

```pascal
uses fpjson, Http2.Client, Http2.Readers;

Sent := TJSONObject.Create;
Sent.Add('name', 'widget');
Response := Client.Send(WithJsonBody(THttpRequest.Create(hmPost, Url), Sent));

Got := ReadJsonObject(Response);   // TJSONObject, caller-owned
try
  WriteLn(Got.AsJSON);
finally
  Got.Free;
end;
```

The same shape works for XML: `WithXmlBody` / `ReadXmlDocument`.
`ReadJsonData` and the `TJsonReader<T>` class decode any `TJSONData`
descendant (arrays, numbers, strings). A body that does not parse raises
`EHttpProtocolError`, so a malformed response never leaks `EJSONParser` or
`EXMLReadError`. The XML reader also accepts documents that declare
`encoding="us-ascii"`, which `fcl-xml` rejects on its own.

## Examples

The `examples/` directory has seven small programs. Build them all with:

```sh
make examples      # or: task examples
```

They compile into `bin/` and are not run by the build. Run one with the
OpenSSL path set (`OPENSSL_LIBPATH` is required at runtime):

```sh
export OPENSSL_LIBPATH=/opt/homebrew/opt/openssl@3/lib
bin/basic_get      https://nghttp2.org/
bin/post_text      https://nghttp2.org/httpbin/post
bin/json_request   https://nghttp2.org/httpbin/post
bin/xml_request    https://nghttp2.org/httpbin/xml
bin/threaded_get   https://nghttp2.org/ 8 25
bin/sse_stream     http://127.0.0.1:8091/events   # tools/validate/sse_server.py
https_proxy=http://proxy.corp:3128 bin/proxy_env https://nghttp2.org/
bin/websocket_echo ws://127.0.0.1:8601/echo hello   # tools/validate/ws_servers.py
```

| Program | Shows |
|---|---|
| `basic_get.pas` | The factory, one GET, status/headers, `ReadText`. |
| `post_text.pas` | `WithTextBody` streaming a plain text request body. |
| `json_request.pas` | `WithJsonBody` + `ReadJsonObject` (`TJSONObject`). |
| `xml_request.pas` | `WithXmlBody` + `ReadXmlDocument` (`TXMLDocument`). |
| `threaded_get.pas` | Many threads sharing one client and its pool. |
| `sse_stream.pas` | `SseRequest` + `TSseReconnectLoop` over an event stream. |
| `proxy_env.pas` | A GET routed by the proxy environment variables. |
| `websocket_echo.pas` | Open a WebSocket, send a message, print the echo, close. |

## Project layout

| Path | Content |
|---|---|
| `src/` | The library units. |
| `examples/` | Seven small, runnable programs. See [Examples](#examples). |
| `test/` | The unit suite, the mock socket, and the `h2probe` CLI. |
| `tools/validate/` | The interop, sanity, and harness scripts. |
| `bin/` | The build output. |
| `third_party/` | The pinned mORMot2 and harness checkouts. |
| `doc/` | The design notes and the validation record. Read them first. |
| `LICENSE` | The Apache License, Version 2.0. |
| `NOTICE` | The copyright and the third-party components. |

### WebSocket

```pascal
type
  TChat = class(TWebSocketListener)
  public
    procedure OnOpen(const ASocket: IWebSocket); override;
    procedure OnText(const ASocket: IWebSocket; const AText: string;
      const ALast: Boolean); override;
  end;

procedure TChat.OnOpen(const ASocket: IWebSocket);
begin
  ASocket.Request(1);          // nothing is delivered until requested
end;

procedure TChat.OnText(const ASocket: IWebSocket; const AText: string;
  const ALast: Boolean);
begin
  WriteLn(AText);
  ASocket.Request(1);
end;

var
  Socket: IWebSocket;
begin
  Socket := Client.Send(
    TWebSocketRequest.Create('wss://example.com/chat', TChat.Create)
      .WithSubprotocol('chat'));
  Socket.SendText('hello');
  Socket.Close(1000, 'bye');
end;
```

The connection speaks HTTP/1.1 (RFC 6455); a WebSocket is not pooled. See
`doc/design/websocket.md`.

## Where to read more

- `doc/http2client.md` gives the document map.
- `doc/design/client-api.md` gives the full factory surface.
- `doc/design/proxy.md` gives the proxy routing: environment variables,
  the no-proxy list, and `IProxySelector`.
- `doc/design/websocket.md` gives the WebSocket client: handshake, framing,
  delivery and demand, closing, and the reference implementations.
- `doc/design/messages.md` gives the request and response types.
- `doc/design/server-sent-events.md` gives the SSE parser, source, and
  reconnect/resume loop.
- `doc/design/errors-redirects.md` gives the exceptions and the timeouts.
- `doc/verification/validation.md` gives the validation results and the reasons.
- `doc/verification/toolchain.md` gives the exact tool versions and revisions.

The validation record refers to the generated table at `[[validation-results]]`
and to the raw sweep log at `[[harness-log]]`.

## Known limits

- The harness image is not on a registry. You must build it from the source.
- Case A.8 of the interop gate is a SKIP. See the section above.
- The `http2/http2-test` suite uses draft-09 and cleartext. No conformance
  claim depends on it.
- `h2spec` is a server test tool. It does not apply to this client.
- The cleartext warning is not wired to the observer: `IHttp2Observer` has
  no cleartext event, so a cleartext request is currently silent. Tracked in
  `doc/design/open-questions.md` and `doc/design/fallback.md`.
- Server-Sent Events are full-featured over HTTP/2. Over the HTTP/1.1
  fallback they are best-effort: an idle stream is bounded by the socket
  read timeout and a blocked read cannot be cancelled. See
  `doc/design/server-sent-events.md`.

- WebSockets are RFC 6455 over HTTP/1.1 only: no RFC 8441, no
  `permessage-deflate`, no automatic reconnection. See
  `doc/design/websocket.md`.

- Proxies are reached by `CONNECT` tunnel only. An `http_proxy` for an
  `http://` origin tunnels instead of forwarding, and many proxies refuse
  `CONNECT` to ports other than 443; a `socks5://` proxy has no such
  restriction. SOCKS4 and SOCKS5 `BIND` / `UDP ASSOCIATE` are not
  implemented. See `doc/design/proxy.md`.

## License

This product is licensed under the Apache License, Version 2.0.
See the `LICENSE` file for the full text.

Copyright 2026 Liam Seamus Coughlin.

The library uses mORMot2 for TLS and ALPN. The proxy-routing code is
self-contained but follows mORMot2's designs for URL parsing (`TUri`), CIDR
matching (`TIp4SubNet`), loopback detection and the `CONNECT` exchange; see
`doc/design/proxy.md`, section "mORMot2 as a reference". mORMot2 keeps its own
license.
See the `NOTICE` file for the full list of third-party components.
