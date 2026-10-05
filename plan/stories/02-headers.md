---
title: "S02 — Headers and header names"
story-id: "02"
aliases:
  - "S02"
  - "headers"
tags:
  - http2client
  - plan
  - story
status: ready
up: "[[http2client]]"
depends-on:
  - "01-errors-frames"
parallel-with:
  - "03-hpack"
  - "04-flow-control"
  - "05-tls-alpn-socket"
updated: 2026-10-05
---

# S02 — Headers and header names

## Goal

Implement `IHttpHeaders` (case-insensitive, multi-valued) and the header-name
constants. Spec:
[`../../doc/design/messages.md`](../../doc/design/messages.md) §Headers and
header names.

## Tasks

| ID | Description | Files touched | Deliverable | Acceptance | Depends on |
|---|---|---|---|---|---|
| 02.1 | `IHttpHeaders` + impl | `src/Http2.Headers.pas` | `Add`, `SetValue`, `GetValues`, `GetFirst`, `Contains`, `Remove`, `Names`; backed by `TDictionary<string,TStringList>` in a `TInterfacedObject` | unit test | 01.1 |
| 02.2 | Lowercase normalisation | idem | names lowercased on `Add`/`SetValue`; values preserved verbatim | mixed-case add then lookup succeeds | 02.1 |
| 02.3 | Header-name constants | idem | pseudo-headers `:method/:path/:scheme/:authority/:status`; lowercase regular names per spec | constant values asserted | 02.1 |
| 02.4 | Forbidden-header guard | idem | reject `connection`, `keep-alive`, `transfer-encoding`, `upgrade` (connection-specific) | adding any raises `EHttpProtocolError` | 02.3 |
| 02.5 | Pseudo vs regular split | idem | pseudo-headers excluded from the regular map / `Names` | test asserts absence | 02.4 |

## Unit tests

- `test/Http2.Headers.Test.pas` — multi-value `set-cookie`, `GetFirst`,
  case-insensitivity, forbidden-header rejection, ordering preservation of
  values, `Remove` using `IndexOf`+`Delete`.

## Done when

- Spec's header API is complete and tested; constants match the wire form.
- No ALPN/HPACK dependency leaks into this unit (it stays a plain map).
