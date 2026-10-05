---
title: "Toolchain and environment"
aliases:
  - "toolchain"
tags:
  - http2client
  - plan
status: ready
up: "[[http2client]]"
updated: 2026-10-05
---

# Toolchain and environment

Locked, externally verified facts. Agents must not silently substitute
tools; if something here is wrong, correct this file in the same change and
note it.

## Compiler and platform

| Fact | Value | Evidence |
|---|---|---|
| Compiler | `fpc 3.2.4` (`ppca64`), macOS aarch64 | `fpc -iV` |
| Unit search root | `/usr/local/lib/fpc/3.2.4/units/aarch64-darwin/` | `/etc/fpc.cfg` `-Fu` entries |
| Mode | `{$mode delphi}{$H+}`, `{$modeswitch advancedrecords}`, `{$modeswitch typehelpers}`, `{$interfaces com}` | `doc/design/fpc-runtime.md` |
| Thread manager | `{$IFDEF UNIX}cthreads,{$ENDIF}` **before** threaded units | probe12; else `Runtime error 232` |
| Queue primitive | `TBlockingQueue<T>` — `TThreadedQueue<T>` does **not** exist | `doc/reference/fpc-verified/README.md` |
| Lock | `TCriticalSection` — `TMonitor` absent | idem |
| Signal | `RTLEvent` — `TEvent`/`TSimpleEvent` raise `ESyncObjectException` on macOS | idem |
| List delete | `TStringList.IndexOf` + `Delete` — no `.Remove` | idem |

See `doc/reference/fpc-verified/` for the probe programs and exact
reproduce commands.

## TLS / ALPN (decisive)

| Fact | Value |
|---|---|
| FPC 3.2.4 bundled `openssl` / `opensslsockets` | **No ALPN symbols** (grep of `opensslsockets.ppu` empty) → cannot negotiate `h2`. |
| mormot2 `src/lib/mormot.lib.openssl11.pas` | **Exports ALPN**: `SSL_CTX_set_alpn_protos` (line 2164), `SSL_get0_alpn_selected` (line 2192); dynamically loads OpenSSL 1.1/3.x. |
| Backend library | OpenSSL `3.6.5` — `/opt/homebrew/opt/openssl@3` (kegs 3.4/3.5/3.6 also present). |
| LibreSSL | API-compatible (`libssl` OpenSSL-1.1 symbol surface). **No separate backend**; document only. |

**Decision:** `Http2.Tls` implements `IHttp2Socket` and ALPN on top of
`mormot.lib.openssl11.pas`. Do not attempt ALPN through FPC's bundled
`opensslsockets`. Vendor the mormot unit (or pin a checkout + revision) in
S00 and record the exact revision used.

## External tools

| Tool | Status | Use |
|---|---|---|
| `brew` | present | install `nghttp2` CLI in S00. |
| `libnghttp2` 1.70.0 | present (brew keg) | linked library; **the `nghttpd`/`nghttp` CLIs are not installed**. |
| `nghttpd`, `nghttp` | **absent** → `brew install nghttp2` | interop server (`nghttpd`) and differential oracle (`nghttp -nv`). |
| `docker` | present (Rancher Desktop, `/Users/liamcoughlin/.rd/bin/docker`) | run `h2-client-test-harness` image. |
| `go` | **absent** | do not rely on `go run` for the harness — use Docker. |
| `node` v26.10.0, `npm` | present | legacy `http2/http2-test` only (best-effort). |
| `make` | present (`/usr/bin/make`) | build. **No `cmake`** (absent). |
| `openssl` CLI | present (3.6.5) | generate test certs. |
| `h2spec` | absent | server-conformance only; optional appendix in S12. |

## Bootstrap commands (S00 executes these)

```sh
# 1. Build toolchain check
fpc -iV                      # expect 3.2.4

# 2. Interop + oracle binaries
brew install nghttp2
nghttpd --version            # expect 1.70.0

# 3. TLS unit dependency (no mormot checkout exists yet)
#    Vendor mormot.lib.openssl11.pas (and its include deps) under third_party/,
#    OR clone synopse/mORMot2 at a pinned revision and record it here.
#    Record the resolved commit/URL in this file before S05 starts.

# 4. Compliance harness (Docker)
docker pull h2-test-harness 2>/dev/null || true
docker run --rm h2-test-harness --list   # lists the 146 case ids

# 5. Legacy reference (already cloned, do not gate on it)
#    http2/http2-test is draft-09 + plaintext + 2014 deps vs node v26.
```

## Constraints

- **No Pascal source in plan files** and **no `cmake`**; use a Makefile with
  `fpc` invocations.
- Every build must `-Fu` the units dir and the vendored mormot dir.
- Generated test certificates live in `test/certs/` and are not committed to
  a vault (repo is not git anyway); regenerate with the openssl CLI.
- Cite versions exactly as in the table when a story's acceptance depends on
  them.
