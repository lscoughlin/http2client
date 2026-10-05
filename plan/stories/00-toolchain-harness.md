---
title: "S00 — Toolchain, build, and harness bootstrap"
story-id: "00"
aliases:
  - "S00"
  - "toolchain-harness"
tags:
  - http2client
  - plan
  - story
status: ready
up: "[[http2client]]"
depends-on: []
parallel-with: []
updated: 2026-10-05
---

# S00 — Toolchain, build, and harness bootstrap

## Goal

Make the repository buildable and the external harnesses runnable before any
protocol code exists. Freeze the toolchain facts and the ALPN dependency so
S05 is not blocked. See [`../toolchain.md`](../toolchain.md) for the verified
environment table.

## Tasks

| ID | Description | Files touched | Deliverable | Acceptance | Depends on |
|---|---|---|---|---|---|
| 00.1 | Record verified environment | `plan/toolchain.md` | Already written; confirm on this machine | `fpc -iV` prints `3.2.4` | — |
| 00.2 | Install interop tools | (host) | `nghttpd` v1.70.0 available | `nghttpd --version` succeeds | 00.1 |
| 00.3 | Vendor mormot OpenSSL unit | `third_party/mormot/` | `mormot.lib.openssl11.pas` + includes present at a pinned revision; URL/revision recorded in `toolchain.md` | `grep -c alpn` ≥ 2 in the vendored unit | 00.1 |
| 00.4 | Create unit skeletons | `src/Http2.{Errors,Frames,Headers,Hpack,FlowControl,Tls,Connection,Stream,Client,Observer}.pas`, `src/Http2.pas` | Each unit compiles empty (`{$mode delphi}` header) | build command below succeeds | 00.1 |
| 00.5 | Makefile | `Makefile` | `make` builds `src/`, `make test` runs `test/`; `-Fu` includes units dir + `third_party/mormot`; `-Fl` links `libssl` | both targets exit 0 | 00.3, 00.4 |
| 00.6 | Test certs | `test/certs/` | localhost cert+key via openssl CLI | files exist, `openssl x509` parses | 00.2 |
| 00.7 | Harness smoke | `plan/toolchain.md` | `docker run --rm h2-test-harness --list` prints 146 ids; `nghttpd` starts | both commands shown to work | 00.2 |
| 00.8 | Test scaffolding | `test/Http2.TestRunner.pas` | `fpcunit` console runner that auto-discovers test units | runner builds and prints 0 failures | 00.5 |

Build acceptance command:

```sh
make clean && make          # compiles all unit skeletons
make test                    # fpcunit runner, 0 tests, 0 failures
```

## Unit tests

- `test/Http2.Skeleton.Test.pas` — trivial assertion per unit that the unit
  can be `uses`-d.

## Done when

- `make` and `make test` both exit 0 on a clean tree.
- `nghttpd --version`, `docker run --rm h2-test-harness --list`, and a
  locally generated cert are all demonstrated in `toolchain.md`.
- The vendored mormot revision is recorded, unblocking S05.
