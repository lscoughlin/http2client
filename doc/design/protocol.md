---
title: "Protocol Layer"
aliases:
  - "protocol"
tags:
  - http2client
  - design
  - protocol
status: draft
up: "[[http2client]]"
related:
  - "[[transport]]"
  - "[[messages]]"
  - "[[open-questions]]"
updated: 2026-10-05
---

# Protocol Layer

## Frame layer

```pascal
type
  TFrameType = (
    ftData           = $0,
    ftHeaders        = $1,
    ftPriority       = $2,
    ftRstStream      = $3,
    ftSettings       = $4,
    ftPushPromise    = $5,
    ftPing           = $6,
    ftGoAway         = $7,
    ftWindowUpdate   = $8,
    ftContinuation   = $9);

  // wire bit values collide across frame types: PADDED=$8, PRIORITY=$20,
  // END_STREAM=ACK=$1, END_HEADERS=$4
  TFrameFlags = set of (ffEndStream, ffEndHeaders, ffAck, ffPadded, ffPriority);

  TFrameHeader = record
    Length: LongWord;      // 24 bits on the wire
    FrameType: TFrameType;
    Flags: TFrameFlags;
    StreamId: LongWord;    // reserved bit masked off
  end;

  TFrame = record
    Header: TFrameHeader;
    Payload: TBytes;
  end;

  TConnectionSettings = record
    HeaderTableSize: LongWord;
    EnablePush: Boolean;
    MaxConcurrentStreams: LongWord;   // $7FFFFFFF = "unlimited"
    InitialWindowSize: LongWord;
    MaxFrameSize: LongWord;
    MaxHeaderListSize: LongWord;
  end;
```

Which frames the client sends vs. receives, and how they map to the public
API:

| Frame | Client sends | Client receives | Maps to |
| --- | --- | --- | --- |
| `ftSettings` | yes (preface, acks) | yes | connection setup/limits |
| `ftHeaders` | yes | yes | request headers / response `:status` |
| `ftContinuation` | yes | yes | continuation of a header block |
| `ftData` | yes | yes | request body / response body |
| `ftWindowUpdate` | yes | yes | flow control |
| `ftRstStream` | yes | yes | cancellation / stream error |
| `ftGoAway` | yes (shutdown) | yes | connection drain |
| `ftPing` | yes | yes | keep-alive / RTT |
| `ftPriority` | optional | yes | prioritization (may be ignored) |

`Send` returning "status + headers" is exactly `ftHeaders` with
`ffEndHeaders` decoded and `:status` present. See [[messages]].

## HPACK

Header compression is **connection-scoped and stateful**, which is why the
codec lives on `TConnection` (see [[transport]]):

```pascal
type
  THpackCodec = class
  private
    FEncoder: THpackEncoder;   // dynamic table, write side
    FDecoder: THpackDecoder;   // dynamic table, read side
    FMaxTableSize: LongWord;
  public
    function Encode(const AHeaders: THeaderBlock): TBytes;
    function Decode(const AData: TBytes): THeaderBlock;
    procedure ApplySettings(const ASettings: TConnectionSettings);
  end;
```

- **Static table** — fixed, known to both peers.
- **Dynamic table** — grows/shrinks as fields are sent/received; encoder and
  decoder must apply identical eviction rules and honor
  `SETTINGS_HEADER_TABLE_SIZE`.
- Correctness requires exact ordering: the decoder processes header blocks
  in the order the connection thread read them; the encoder emits blocks in
  the order streams were written. A missed/reordered block desynchronizes
  every subsequent decode on that connection.
- Errors (`COMPRESSION_ERROR`) are **connection-fatal** and force `GOAWAY`,
  not a single-stream failure.

## Flow control

```pascal
type
  TWindow = record
  private
    FSize: LongInt;       // can go negative for the send window
    FConsumed: LongInt;   // bytes consumed since last WINDOW_UPDATE
  public
    procedure Consume(const ACount: LongInt);
    procedure ApplyUpdate(const AIncrement: LongWord);
    function NeedsUpdate(const AThreshold: LongInt): Boolean;
    function UpdateIncrement: LongWord;
  end;
```

Two nested windows, both counting **only** DATA bytes:

- **Connection-level window** — shared by all streams.
- **Stream-level window** — per stream, initialized from
  `SETTINGS_INITIAL_WINDOW_SIZE`.

Rules:

- Sending DATA decrements both windows; the sender must not exceed either and
  waits for `WINDOW_UPDATE`. This turns a slow reader into backpressure on
  `IBodyWriter` rather than unbounded buffering.
- Receiving DATA consumes local windows; the client sends `WINDOW_UPDATE`
  (connection and stream) as `Read` consumes bytes, so a slow consumer
  throttles the peer.
- `WINDOW_UPDATE` is batched: credit is returned once
  `TWindow.NeedsUpdate(Threshold)` is true, so small reads do not emit one
  frame per call.

### Implementation note (S12 validation finding)

`TFlowControl` was implemented and unit-tested but initially wired into
**nothing**: `TConnection` received DATA without ever returning window
credit, so a body larger than the advertised 65535-byte window stalled once
the peer's window hit zero — nghttpd simply stopped sending and the read
raised `EHttpTimeout` (`timed out reading response body`). Interop case A.7
(a 100 000-byte response) reproduces it.

The connection layer now drives `TFlowControl`: `TrackReceivedData` accrues
receive credit on every inbound DATA frame, and `SendWindowUpdate` posts a
WINDOW_UPDATE — connection level on stream 0, stream level on the lease's
stream — once `cWindowUpdateBatchSize` (32768) bytes have accrued;
`UnregisterStream` flushes the remainder. `ApplyPeerSettingsValue` adjusts
every open stream by the `SETTINGS_INITIAL_WINDOW_SIZE` delta.
