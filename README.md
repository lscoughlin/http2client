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
- Speaks cleartext `h2c` when the caller enables it. Cleartext has two modes:
  prior knowledge and upgrade.
- Falls back to HTTP/1.1 when the peer does not offer `h2`. The caller must
  enable the fallback.

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

The `build` task compiles all 13 library units into `bin/`. The output is the
`.ppu` and `.o` files for each unit. The task does not create a linked binary,
because the library has no program of its own. To use the units in your own
program, add `-Fu` for the `src` and `bin` directories. See the `FPCFLAGS`
value in `Taskfile.yaml`.

## Test

```sh
task test
```

The `test` task compiles the library and the unit suite. Then it runs the
suite. The suite has 292 tests.

The suite uses `fpcunit` and a mock socket. It needs no network and no server.

Every test must pass. The task returns a non-zero exit code when a test fails.

## Validate

The validation suite has four levels. Each level has its own task.

| Task | What it checks | Time |
|---|---|---|
| `task test` | The unit suite. | Under 1 minute |
| `task validate:sanity` | The probe classifies outcomes correctly. | Seconds |
| `task validate:interop` | A real TLS peer, `nghttpd`. Cases A.1 to A.13. | About 1 minute |
| `task validate:harness` | The RFC conformance harness. 146 case ids. | About 30 minutes |

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
It checks five conditions:

1. An unreachable port gives exit code 2.
2. A harness stream error gives exit code 3. This check is a SKIP when the
   harness image is absent.
3. Bad command-line usage gives exit code 1.
4. A peer without `h2` ALPN gives exit code 2.
5. A live `nghttpd` GET gives exit code 0. This check is a SKIP when
   `nghttpd` is absent.

### Interop gate

The interop script starts `nghttpd` with the test certificates. Then it runs
the cases A.1 to A.13. It prints a table and exits 0 when no mandatory case
fails.

Case A.8 is a SKIP. No `nghttpd` trigger can force a GOAWAY in the middle of
a request. The unit suite covers the same behavior.

Cases A.11 and A.12 are SKIPs when Docker is absent.

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

The last full sweep gave this result:

| Verdict | Count |
|---|---|
| MATCH | 28 |
| BETTER | 42 |
| WORSE | 0 |
| CLASS-DIFF | 12 |
| UNKNOWN | 64 |

The script writes the table to `bin/validation-results.md`.

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
    .WithMaxConnections(8)
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

// Accept an HTTP/1.1 peer when the peer does not offer h2.
Client := THttpClientFactory.Create
  .WithHttp1Fallback(True)
  .Build;
```

`TClearTextPolicy` lives in `Http2.Tls`. You must name that unit in your
`uses` clause to write the value `ctPriorKnowledge` or `ctUpgrade`.

For a test against a private certificate, use `WithCACertFile`.
For a self-signed certificate, use `WithInsecureTls`.

## Project layout

| Path | Content |
|---|---|
| `src/` | The library units. |
| `test/` | The unit suite, the mock socket, and the `h2probe` CLI. |
| `tools/validate/` | The interop, sanity, and harness scripts. |
| `bin/` | The build output. |
| `third_party/` | The pinned mORMot2 and harness checkouts. |
| `doc/` | The design notes and the validation record. Read them first. |
| `LICENSE` | The Apache License, Version 2.0. |
| `NOTICE` | The copyright and the third-party components. |

## Where to read more

- `doc/http2client.md` gives the document map.
- `doc/design/client-api.md` gives the full factory surface.
- `doc/design/messages.md` gives the request and response types.
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

## License

This product is licensed under the Apache License, Version 2.0.
See the `LICENSE` file for the full text.

Copyright 2026 Liam Seamus Coughlin.

The library uses mORMot2 for TLS and ALPN. mORMot2 keeps its own license.
See the `NOTICE` file for the full list of third-party components.
