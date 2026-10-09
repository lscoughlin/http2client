#!/usr/bin/env bash
# S14 live SSE gate: run the opt-in TSseLiveTest case against the reference
# event-stream server in this directory.
#
# The default unit suite skips the live case (SSE_TEST_URL unset), so this is
# the only runner that executes it. It starts tools/validate/sse_server.py on a
# private port, points SSE_TEST_URL at it, runs just the TSseLiveTest suite,
# then always stops the server again.
#
#   bash tools/validate/sse-live.sh          # or: make validate-sse
#
# Env overrides: SSE_PORT (default 8399), SSE_HOST (default 127.0.0.1),
# BIN (default bin), and the usual FPC/OPENSSL_LIBPATH.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BIN="${BIN:-$ROOT/bin}"
SSE_HOST="${SSE_HOST:-127.0.0.1}"
SSE_PORT="${SSE_PORT:-8399}"
RUNNER="$BIN/Http2.RunTests"

if [ ! -x "$RUNNER" ]; then
  echo "sse-live: $RUNNER is missing; run 'make test' first" >&2
  exit 2
fi

SRV_PID=""
cleanup() {
  if [ -n "$SRV_PID" ]; then
    kill "$SRV_PID" 2>/dev/null
    wait "$SRV_PID" 2>/dev/null
  fi
}
trap cleanup EXIT INT TERM

python3 "$HERE/sse_server.py" --host "$SSE_HOST" --port "$SSE_PORT" \
  >/dev/null 2>&1 &
SRV_PID=$!

# wait for the listener rather than sleeping a fixed second. The probe runs
# in a subshell whose stderr is dropped, because bash reports a refused
# /dev/tcp connection before later redirections on the same line take effect.
for _ in $(seq 1 50); do
  if (exec 3<"/dev/tcp/$SSE_HOST/$SSE_PORT") 2>/dev/null; then
    break
  fi
  sleep 0.1
done

echo "sse-live: server on http://$SSE_HOST:$SSE_PORT/events (pid $SRV_PID)"
SSE_TEST_URL="http://$SSE_HOST:$SSE_PORT/events" \
  "$RUNNER" --all --format=plain --sparse --suite=TSseLiveTest
RC=$?
echo "sse-live: exit $RC"
exit $RC
