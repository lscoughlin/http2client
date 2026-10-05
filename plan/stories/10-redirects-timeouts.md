---
title: "S10 — Redirects, timeouts, cancellation"
story-id: "10"
aliases:
  - "S10"
  - "redirects-timeouts"
tags:
  - http2client
  - plan
  - story
status: ready
up: "[[http2client]]"
depends-on:
  - "09-public-api"
parallel-with:
  - "11-observability"
updated: 2026-10-05
---

# S10 — Redirects, timeouts, cancellation

## Goal

Implement redirect following, the configured timeouts, cancellation, and
idempotent-only transparent retry. Spec:
[`../../doc/design/errors-redirects.md`](../../doc/design/errors-redirects.md).

## Tasks

| ID | Description | Files touched | Deliverable | Acceptance | Depends on |
|---|---|---|---|---|---|
| 10.1 | Redirect loop | `src/Http2.Client.pas` | follow `301/302/303/307/308` up to `MaxRedirects`; `303` → GET; `307`/`308` preserve body only if replayable | test matrix | 09.7 |
| 10.2 | Non-replayable guard | idem | writer body on `307`/`308` raises `EHttpNotReplayable` | test | 10.1 |
| 10.3 | Limit | idem | exceeding `MaxRedirects` raises `EHttpTooManyRedirects` | test | 10.1 |
| 10.4 | Cross-origin redirect | idem | new authority → separate pool entry / connection | test | 10.1, 09.5 |
| 10.5 | `ConnectTimeoutMs` | idem | TCP+TLS handshake deadline → `EHttpTimeout` | test with stalled peer | 05.7 |
| 10.6 | `HeaderTimeoutMs` | idem | response-header deadline → `EHttpTimeout` | test | 10.5 |
| 10.7 | `IdleTimeoutMs` | idem | idle connections reaped; pool stays within budget | test | 09.5 |
| 10.8 | Cancellation | idem | caller cancels an in-flight `Send`; stream RST and lease released | test | 08.7 |
| 10.9 | Idempotent retry | idem | retry `GET/HEAD/PUT/DELETE/OPTIONS/TRACE` on GOAWAY "may retry" or refused stream; never retry non-idempotent with a body | test | 07.4 |

## Unit tests

- `test/Http2.Redirects.Test.pas` — each status, body-preservation rules,
  limit, cross-origin.
- `test/Http2.Timeouts.Test.pas` — each timeout, cancellation, retry policy.

## Done when

- Redirect status handling matches the spec table exactly.
- Every timeout is enforced and mapped to `EHttpTimeout`.
- No non-idempotent request is ever transparently retried.
