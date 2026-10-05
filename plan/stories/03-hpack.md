---
title: "S03 — HPACK codec"
story-id: "03"
aliases:
  - "S03"
  - "hpack"
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
  - "04-flow-control"
  - "05-tls-alpn-socket"
updated: 2026-10-05
---

# S03 — HPACK codec

## Goal

Implement a stateful, connection-scoped HPACK (RFC 7541) encoder/decoder:
static table, dynamic table with eviction, Huffman, integer/string literals.
Spec: [`../../doc/design/protocol.md`](../../doc/design/protocol.md) §HPACK.

## Tasks

| ID | Description | Files touched | Deliverable | Acceptance | Depends on |
|---|---|---|---|---|---|
| 03.1 | Static table | `src/Http2.Hpack.pas` | RFC 7541 Appendix A, 61 entries | lookup + index tests | 01.1 |
| 03.2 | Dynamic table | idem | insert/evict by size, `SETTINGS_HEADER_TABLE_SIZE` cap, per-entry 32-byte overhead | eviction/size-update tests | 03.1 |
| 03.3 | Integer coding | idem | RFC 7541 §5.1 prefix-coded integers | boundary tests (127/128, max) | 03.1 |
| 03.4 | String literal coding | idem | §5.2, raw + Huffman (H bit) | round-trip both modes | 03.3 |
| 03.5 | Huffman codec | idem | RFC 7541 Appendix B tables + encoder/decoder | round-trip, padding rules, EOS error | 03.4 |
| 03.6 | Header field coding | idem | §6.1 indexed, §6.2.1 incremental, §6.2.2 without indexing, §6.2.3 never-indexed, §6.3 table-size update | all forms decode correctly | 03.1, 03.2 |
| 03.7 | `THpackCodec` | idem | `Encode(headers):TBytes`, `Decode(bytes):IHttpHeaders`; mutable dynamic table | encode→decode→compare | 03.5, 03.6 |
| 03.8 | Error mapping | idem | malformed input raises `EHttpProtocolError` marked connection-fatal (`COMPRESSION_ERROR`) | test asserts exception class | 03.7 |

## Unit tests

- `test/Http2.Hpack.Test.pas` — Huffman round-trip on random ASCII, dynamic
  table eviction, table-size update mid-stream, never-indexed fields,
  oversized entry clears table, malformed index raises.
- Reproduce the RFC 7541 Appendix C vectors (C.1–C.6) exactly.

## Done when

- RFC 7541 Appendix C vectors pass byte-for-byte.
- Dynamic table state is demonstrably per-codec-instance (not global).
- A malformed input is connection-fatal, not a silent skip.
