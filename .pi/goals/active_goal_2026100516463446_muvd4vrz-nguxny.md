{
  "version": 3,
  "id": "muvd4vrz-nguxny",
  "objective": "Implement the HTTP/2 client specified in doc/design/ and planned in plan/README.md in Object Pascal for Free Pascal 3.2.4, using a team of parallel agents, until all 12 plan stories (S00–S12) are complete and the external validation ladder is green.",
  "status": "active",
  "autoContinue": true,
  "usage": {
    "tokensUsed": 80353,
    "activeSeconds": 1
  },
  "sisyphus": false,
  "createdAt": "2026-10-05T14:46:34.463Z",
  "updatedAt": "2026-10-05T14:46:36.308Z",
  "activePath": ".pi/goals/active_goal_2026100516463446_muvd4vrz-nguxny.md",
  "revision": 7,
  "scheduler": {
    "version": 1,
    "owner": "01a10c49-6455-75dd-a27f-500acef91d00",
    "generation": "abe4c506-6f97-45b3-91cf-2ee69dc6bb96",
    "used": 1,
    "phase": "running",
    "repairUsed": false,
    "decision": {
      "kind": "ready",
      "purpose": "ready"
    },
    "dispatch": {
      "id": "94b571f5-9c7b-41e2-b8cb-06f04a1cf23c",
      "kind": "ready",
      "claimedAt": 1791211594484
    }
  },
  "taskList": {
    "tasks": [
      {
        "id": "task-s00",
        "title": "S00 — Toolchain, build, and harness bootstrap",
        "status": "pending",
        "verificationContract": "make and make test both exit 0; nghttpd --version and docker run --rm h2-test-harness --list demonstrated; vendored mormot revision recorded in plan/toolchain.md."
      },
      {
        "id": "task-s01",
        "title": "S01 — Error model and frame codec (Http2.Errors, Http2.Frames)",
        "status": "pending",
        "verificationContract": "Every frame type byte-round-trips; exception hierarchy matches doc/design/errors-redirects.md; make test green."
      },
      {
        "id": "task-s02",
        "title": "S02 — Headers and header names (Http2.Headers)",
        "status": "pending",
        "verificationContract": "Header API complete; case-insensitivity and forbidden-header rejection tested; make test green."
      },
      {
        "id": "task-s03",
        "title": "S03 — HPACK codec (Http2.Hpack)",
        "status": "pending",
        "verificationContract": "RFC 7541 Appendix C vectors pass byte-for-byte; malformed input is connection-fatal; make test green."
      },
      {
        "id": "task-s04",
        "title": "S04 — Flow control (Http2.FlowControl)",
        "status": "pending",
        "verificationContract": "Window arithmetic, overflow, initial-window deltas, batching, and per-stream isolation tested; make test green."
      },
      {
        "id": "task-s05",
        "title": "S05 — TLS, ALPN, and socket abstraction (Http2.Tls)",
        "status": "pending",
        "verificationContract": "Real TLS connection to nghttpd negotiates h2 and asserts SSL_get0_alpn_selected; an http/1.1-only server raises; vendored mormot compiles standalone."
      },
      {
        "id": "task-s06",
        "title": "S06 — Blocking queue and connection thread",
        "status": "pending",
        "verificationContract": "No TThreadedQueue/TMonitor/TEvent; weak connection reference (no ARC cycle); deterministic concurrency tests green."
      },
      {
        "id": "task-s07",
        "title": "S07 — Connection lifecycle",
        "status": "pending",
        "verificationContract": "Preface and SETTINGS byte-exact; GOAWAY may-retry set correct; every in-flight stream terminated exactly once on failure."
      },
      {
        "id": "task-s08",
        "title": "S08 — Stream lease state machine (Http2.Stream)",
        "status": "pending",
        "verificationContract": "Single lease completes end-to-end over a mock connection; stream transitions match RFC 7540 §5.1; no queue/response-state leaks."
      },
      {
        "id": "task-s09",
        "title": "S09 — Public API, pool, request/response (Http2.Client)",
        "status": "pending",
        "verificationContract": "Documented fluent example compiles and runs; live GET and POST succeed against nghttpd; pool never exceeds MaxConnections or per-connection stream caps."
      },
      {
        "id": "task-s10",
        "title": "S10 — Redirects, timeouts, cancellation",
        "status": "pending",
        "verificationContract": "Redirect status table matches spec; every timeout enforced as EHttpTimeout; no non-idempotent request transparently retried."
      },
      {
        "id": "task-s11",
        "title": "S11 — Observability and test seams",
        "status": "pending",
        "verificationContract": "No protocol test needs a real socket; deterministic race-free concurrency tests; mock socket drives full Send path."
      },
      {
        "id": "task-s12",
        "title": "S12 — Validation against external suites",
        "status": "pending",
        "verificationContract": "nghttpd TLS/ALPN interop (validation.md §A) exits 0; h2-client-test-harness all 146 ids run with results table recorded (failures empty or justified); http2/http2-test intents ported; nghttp oracle notes recorded."
      }
    ],
    "blockCompletion": true,
    "proposedAt": "2026-10-05T14:46:31.581Z"
  }
}

# Goal Prompt

Implement the HTTP/2 client specified in doc/design/ and planned in plan/README.md in Object Pascal for Free Pascal 3.2.4, using a team of parallel agents, until all 12 plan stories (S00–S12) are complete and the external validation ladder is green.

## Progress

- Status: running
- Auto-continue: on
- Sisyphus mode: no
- Time spent: 1s
- Tokens used: 80K (80,353) tokens
## Tasks

<!-- blockCompletion: true -->
- [ ] task-s00: S00 — Toolchain, build, and harness bootstrap — contract: make and make test both exit 0; nghttpd --version and docker run --rm h2-test-harness --list demonstrated; vendored mormot revision recorded in plan/toolchain.md.
- [ ] task-s01: S01 — Error model and frame codec (Http2.Errors, Http2.Frames) — contract: Every frame type byte-round-trips; exception hierarchy matches doc/design/errors-redirects.md; make test green.
- [ ] task-s02: S02 — Headers and header names (Http2.Headers) — contract: Header API complete; case-insensitivity and forbidden-header rejection tested; make test green.
- [ ] task-s03: S03 — HPACK codec (Http2.Hpack) — contract: RFC 7541 Appendix C vectors pass byte-for-byte; malformed input is connection-fatal; make test green.
- [ ] task-s04: S04 — Flow control (Http2.FlowControl) — contract: Window arithmetic, overflow, initial-window deltas, batching, and per-stream isolation tested; make test green.
- [ ] task-s05: S05 — TLS, ALPN, and socket abstraction (Http2.Tls) — contract: Real TLS connection to nghttpd negotiates h2 and asserts SSL_get0_alpn_selected; an http/1.1-only server raises; vendored mormot compiles standalone.
- [ ] task-s06: S06 — Blocking queue and connection thread — contract: No TThreadedQueue/TMonitor/TEvent; weak connection reference (no ARC cycle); deterministic concurrency tests green.
- [ ] task-s07: S07 — Connection lifecycle — contract: Preface and SETTINGS byte-exact; GOAWAY may-retry set correct; every in-flight stream terminated exactly once on failure.
- [ ] task-s08: S08 — Stream lease state machine (Http2.Stream) — contract: Single lease completes end-to-end over a mock connection; stream transitions match RFC 7540 §5.1; no queue/response-state leaks.
- [ ] task-s09: S09 — Public API, pool, request/response (Http2.Client) — contract: Documented fluent example compiles and runs; live GET and POST succeed against nghttpd; pool never exceeds MaxConnections or per-connection stream caps.
- [ ] task-s10: S10 — Redirects, timeouts, cancellation — contract: Redirect status table matches spec; every timeout enforced as EHttpTimeout; no non-idempotent request transparently retried.
- [ ] task-s11: S11 — Observability and test seams — contract: No protocol test needs a real socket; deterministic race-free concurrency tests; mock socket drives full Send path.
- [ ] task-s12: S12 — Validation against external suites — contract: nghttpd TLS/ALPN interop (validation.md §A) exits 0; h2-client-test-harness all 146 ids run with results table recorded (failures empty or justified); http2/http2-test intents ported; nghttp oracle notes recorded.

