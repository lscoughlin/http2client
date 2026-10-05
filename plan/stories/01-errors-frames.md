---
title: "S01 — Error model and frame codec"
story-id: "01"
aliases:
  - "S01"
  - "errors-frames"
tags:
  - http2client
  - plan
  - story
status: ready
up: "[[http2client]]"
depends-on:
  - "00-toolchain-harness"
parallel-with: []
updated: 2026-10-05
---

# S01 — Error model and frame codec

## Goal

Freeze the two surfaces every other story consumes: `Http2.Errors` and
`Http2.Frames`. Nothing else may edit these once merged without a versioned
change. Spec: [`../../doc/design/protocol.md`](../../doc/design/protocol.md)
(frames) and
[`../../doc/design/errors-redirects.md`](../../doc/design/errors-redirects.md)
(exceptions).

## Tasks

| ID | Description | Files touched | Deliverable | Acceptance | Depends on |
|---|---|---|---|---|---|
| 01.1 | Exception hierarchy | `src/Http2.Errors.pas` | `EHttpError` base + `EHttpConnectionError`, `EHttpProtocolError`, `EHttpStreamError`, `EHttpTimeout`, `EHttpConnectionClosed`, `EHttpTooManyRedirects`, `EHttpNotReplayable`; error codes enum | unit test raises/`is`-checks each | 00.4 |
| 01.2 | Frame type + flag enums | `src/Http2.Frames.pas` | `TFrameType` = `ftData=$0..ftContinuation=$9`; `TFrameFlags` = set of `ffEndStream, ffEndHeaders, ffAck, ffPadded` | values asserted in test | 01.1 |
| 01.3 | `TFrameHeader` | idem | `Length: 24-bit`, `FrameType`, `Flags`, `StreamId` (31-bit, `R` bit masked) | encode/decode round-trip | 01.2 |
| 01.4 | Frame payload records | idem | DATA, HEADERS (+priority/padding), PRIORITY, RST_STREAM, SETTINGS (+ACK), PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION | round-trip per type | 01.3 |
| 01.5 | Frame read/write | idem | `ReadFrame(stream): TFrame`, `WriteFrame(stream, frame)`; enforce max frame size from `SETTINGS_MAX_FRAME_SIZE` | oversized inbound raises `EHttpProtocolError` | 01.4 |
| 01.6 | `TConnectionSettings` | idem | typed record for the six RFC 7540 settings + defaults | encode/decode each setting id | 01.4 |

## Unit tests

- `test/Http2.Frames.Test.pas` — header bit-packing (R bit, 31-bit ids,
  24-bit length), max-frame-size enforcement, settings round-trip,
  unknown-frame skip, padded/priority HEADERS flags.
- Property-style loop: encode→decode→compare for every frame type.

## Done when

- Every frame type round-trips byte-for-byte.
- The exception hierarchy matches the spec doc exactly.
- `make test` green; neither file is modified by later stories except by
  documented change.
