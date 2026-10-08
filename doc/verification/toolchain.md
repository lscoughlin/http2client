---
title: "Toolchain and environment"
aliases:
  - "toolchain"
tags:
  - http2client
  - verification
status: done
up: "[[http2client]]"
updated: 2026-10-08
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
| mormot checkout | `third_party/mORMot2` @ `2ccea1a0e5d7be85bd3cf68e1fd70e9e603d09cc` (2026-10-05, "net: minor hardening of TTunnelLocal.SendFrame"). Unit dirs: `core`, `lib`, `net`, `crypt`. |
| `OPENSSL_LIBPATH` | **Required on this machine.** Without it `OpenSslIsAvailable=FALSE` and `OpenSslVersionText=''`. With `OPENSSL_LIBPATH=/opt/homebrew/opt/openssl@3/lib`: `OpenSslIsAvailable=TRUE`, `OpenSslVersionText='OpenSSL 3.6.5 29 Sep 2026'`. Probed from `/tmp/mormotprobe/probe_tls.pas`. |
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
| `nghttpd`, `nghttp` | **installed** — nghttp2/1.70.0 at `/opt/homebrew/bin` | interop server (`nghttpd`) and differential oracle (`nghttp -nv`). |
| `docker` | present (Rancher Desktop, `/Users/liamcoughlin/.rd/bin/docker`) | run the locally-built harness image. |
| h2 harness image | **not published on any registry** (`docker pull nomadlabsinc/h2-client-test-harness` → `pull access denied … repository does not exist`). Source cloned to `third_party/h2-client-test-harness` (module `github.com/nomadlabsinc/h2-client-test-harness`, `go 1.24.4`); image is built locally with `docker build -t h2-test-harness .` (Dockerfile = `golang:1.24-alpine`, builds `/h2-client-test-harness` + `/h2-verifier`, entrypoint `/test-runner.sh`). |
| `go` | **absent** | do not rely on `go run` for the harness — use Docker. |
| `node` v26.10.0, `npm` | present | legacy `http2/http2-test` only (best-effort). |
| `make` | present (`/usr/bin/make`) | build. **No `cmake`** (absent). |
| `task` (go-task) | present `3.54.0` (`/opt/homebrew/bin/task`) | the primary build/test entry point (`task build`, `task test`, `task examples`, `task validate:*`); `Makefile` remains a thin mirror. Note go-task's embedded shell (mvdan/sh) does **not** support `ulimit`. |
| `openssl` CLI | present (3.6.5) | generate test certs. |
| `h2spec` | absent | server-conformance only; optional appendix in S12. |

## Bootstrap commands (S00 executes these)

```sh
# 1. Build toolchain check
fpc -iV                      # expect 3.2.4

# 2. Interop + oracle binaries
brew install nghttp2
nghttpd --version            # expect 1.70.0

# 3. TLS unit dependency — DONE: pinned checkout
git clone --depth 1 https://github.com/synopse/mORMot2.git third_party/mORMot2
# revision 2ccea1a0e5d7be85bd3cf68e1fd70e9e603d09cc (recorded above).
# Http2.Tls uses these unit dirs: third_party/mORMot2/src/{core,lib,net,crypt}
# Runtime needs OPENSSL_LIBPATH=/opt/homebrew/opt/openssl@3/lib (see the table).

# 4. Compliance harness (Docker) — the image is NOT published; build it locally
docker build -t h2-test-harness third_party/h2-client-test-harness
docker run --rm h2-test-harness --list   # lists the case ids

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

## Lazarus package

The repo ships `http2client.lpk` so the library is usable from the Lazarus
IDE as a design-time package.

| Fact | Value |
|---|---|
| Package name / type | `http2client`, `RunAndDesignTime`, `Version 0.14.0` |
| Units | all 14 in `src/`, `Http2.pas` (umbrella) first; `Http2.Readers.pas` is the optional JSON/XML unit |
| Test suite | 315 tests, 0 errors, 0 failures (registration list: `test/Http2.TestRunner.pas`); see [[testing-observability]] |
| `OtherUnitFiles` | `src` + the four vendored mormot dirs (`core`, `lib`, `net`, `crypt`) |
| `RequiredPkgs` | `FCL` **only** — deliberately **not** the IDE `mormot2` package (see below) |
| Unit output | `lib/$(TargetCPU)-$(TargetOS)` (gitignored) |
| Syntax mode | Delphi (`{$mode delphi}` is set per-unit anyway) |
| Generated file | `http2client.pas` (auto-created registration unit) — **derived from the `.lpk`, gitignored** |

Build:

```sh
lazbuild http2client.lpk
```

**Why the IDE `mormot2` package is not a dependency.** Declaring
`<PackageName Value="mormot2"/>` makes `lazbuild` fail with
`TLazPackageGraph.AddPackage failed to open: Package: http2client 0.0 uses
mormot2` until the IDE has the `mormot2` package linked/installed, and
mormot's own `.lpk` forces defines (`FPCMM_REPORTMEMORYLEAKS`,
`FPCMM_SERVER`, …) that our Makefile build does not use. Putting the four
mormot source dirs on `OtherUnitFiles` instead makes the package compile
self-contained from within the repo, with no IDE package state.

**Environment quirk (this machine).** The checked-out Lazarus 4.2
(`/Users/liamcoughlin/Downloads/lazarus`) was built against a different FPC
than the system `fpc 3.2.4`, so its prebuilt
`packager/units/aarch64-darwin/lazaruspackageintf.ppu` trips
`(10028) Recompiling LazarusPackageIntf, checksum changed for system.ppu`
and then `(10022) Can't find unit LazarusPackageIntf`. Workaround: compile
that unit from source against 3.2.4 into a scratch dir and pass it to
`lazbuild`:

```sh
L=/Users/liamcoughlin/Downloads/lazarus
F=/usr/local/lib/fpc/3.2.4/units/aarch64-darwin
mkdir -p /tmp/lpkintf
fpc -Mobjfpc -Fu$L/packager/registration -Fu$L/components/buildintf \
    -Fu$L/designer -Fu$L/ideintf \
    -Fu$F/rtl -Fu$F/fcl-base -Fu$F/fcl-net -Fu$F/rtl-generics \
    -Fu$F/fcl-process -Fu$F/paszlib -Fu$F/hash \
    -FU/tmp/lpkintf -FE/tmp/lpkintf \
    $L/packager/registration/lazaruspackageintf.pas
lazbuild --opt=-Fu/tmp/lpkintf \
         --opt=-Fu$L/packager/registration http2client.lpk
```

Verified: `83049 lines compiled`, all 13 units produced `.ppu`/`.o` in
`lib/aarch64-darwin/`. A stock Lazarus matched to its FPC would not need the
`--opt` workaround. (`Http2.Readers.pas` was added after that build, so the
current count is 14 and a fresh `lazbuild` compiles one more unit than the
`83049 lines` figure above.)

## Example programs

`examples/` holds five programs (`basic_get`, `post_text`, `json_request`,
`xml_request`, `threaded_get`) — see `examples/README.md`. Build and run:

```sh
make examples          # or: task examples  ->  bin/<source-stem>
OPENSSL_LIBPATH=/opt/homebrew/opt/openssl@3/lib bin/basic_get
```

FPC names the output binary after the **source file stem** (`basic_get.pas` →
`bin/basic_get`), not after any unit. Every example needs `OPENSSL_LIBPATH`
exported at runtime (the library loads OpenSSL dynamically); a threaded
example additionally needs `{$IFDEF UNIX}cthreads,{$ENDIF}` first in its
`uses` clause.

## Prerequisites for a fresh clone (expanded)

The pinned checkouts under `third_party/` are **not** committed (see
`.gitignore`) — they are external, revision-pinned dependencies. To rebuild
the environment from a fresh clone:

```sh
git clone --depth 1 https://github.com/synopse/mORMot2.git third_party/mORMot2
git clone --depth 1 https://github.com/nomadlabsinc/h2-client-test-harness.git \
    third_party/h2-client-test-harness
brew install nghttp2
docker build -t h2-test-harness third_party/h2-client-test-harness
make && make test
```

`OPENSSL_LIBPATH` must be exported for any binary that loads TLS (the
Makefile does this). Verified on this machine: `docker run --rm
h2-test-harness --list` lists **146** case ids, matching the harness README.
