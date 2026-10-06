#!/usr/bin/env bash
# tools/validate/h2probe-sanity.sh — non-vacuity / classification proof for
# the S12 probe (doc/verification/validation.md "sanity checks").
#
# It proves the probe is not reporting PASS unconditionally, and that the
# three verifier outcome classes map to distinct exit codes:
#   check 1: an unreachable port              -> exit 2 (connection error)
#   check 2: the harness RST_STREAM case 5.1/2 -> exit 3 (stream error)
#   check 3: bad usage                        -> exit 1
#   check 4: an http/1.1-only ALPN peer       -> exit 2 with an ALPN message
#   check 5: a live nghttpd GET               -> exit 0 (positive control)
#
# Check 2 uses the real h2-test-harness (case 5.1/2 sends RST_STREAM on an idle
# stream); our client surfaces it as EHttpStreamError, which is verifier class
# ExpectStreamError. This also cross-checks the runner: if the probe had
# reported exit 0 for 5.1/2, the runner would be vacuous.
set -u

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

BUILD="$(mktemp -d /tmp/h2sanity-build.XXXXXX)"
PROBE="$BUILD/h2probe"
FPC="${FPC:-fpc}"
MORMOT="third_party/mORMot2/src"
export OPENSSL_LIBPATH="${OPENSSL_LIBPATH:-/opt/homebrew/opt/openssl@3/lib}"
export PATH="/Users/liamcoughlin/.rd/bin:$PATH"

PASS=0; FAIL=0
cleanup() {
  [ -n "${SSERVER_PID:-}" ] && kill "$SSERVER_PID" 2>/dev/null
  [ -n "${NGHTTPD_PID:-}" ] && kill "$NGHTTPD_PID" 2>/dev/null
  [ -n "${CONTAINER:-}" ] && docker rm -f "$CONTAINER" >/dev/null 2>&1
  rm -rf "$BUILD" 2>/dev/null
}
trap cleanup EXIT

check() { # name expected_exit actual_exit detail
  if [ "$2" = "$3" ]; then
    printf 'PASS  %-46s exit=%s %s\n' "$1" "$3" "$4"
    PASS=$((PASS+1))
  else
    printf 'FAIL  %-46s exit=%s (want %s) %s\n' "$1" "$3" "$2" "$4"
    FAIL=$((FAIL+1))
  fi
}

"$FPC" -O2 -Mdelphi -Fu./src -Fu"$BUILD" \
  -Fu"$MORMOT/core" -Fu"$MORMOT/lib" -Fu"$MORMOT/net" -Fu"$MORMOT/crypt" \
  -FU"$BUILD" -FE"$BUILD" test/h2probe.pas >"$BUILD/build.log" 2>&1 || {
    echo "ERROR: h2probe failed to compile" >&2; tail -20 "$BUILD/build.log" >&2
    exit 1; }

echo "== h2probe sanity checks =="

# 1. unreachable port -> connection error -> exit 2
out="$("$PROBE" --url=https://127.0.0.1:1/ --insecure --timeout-ms=1500 2>&1)"; rc=$?
check "unreachable port -> conn-error" 2 "$rc" "$out"

# 2. real harness RST_STREAM case 5.1/2 -> stream error -> exit 3
if command -v docker >/dev/null 2>&1 && docker image inspect h2-test-harness >/dev/null 2>&1; then
  CONTAINER="h2sanity-$$"
  docker rm -f "$CONTAINER" >/dev/null 2>&1
  docker run -d --name "$CONTAINER" --network host h2-test-harness \
    --harness-only --test=5.1/2 >/dev/null 2>&1
  for i in $(seq 1 100); do
    docker logs "$CONTAINER" 2>&1 | grep -q "listening on" && break; sleep 0.1
  done
  out="$("$PROBE" --url=https://127.0.0.1:8080/ --insecure --timeout-ms=3000 \
    --keep-open-ms=200 2>&1)"; rc=$?
  docker rm -f "$CONTAINER" >/dev/null 2>&1; CONTAINER=""
  check "harness 5.1/2 RST_STREAM -> stream-error" 3 "$rc" "$out"
else
  echo "SKIP  harness 5.1/2 stream-error (image not built)"
fi

# 3. bad usage -> exit 1
out="$("$PROBE" --nonsense 2>&1)"; rc=$?
check "bad usage -> usage error" 1 "$rc" "$out"

# 4. http/1.1-only (or no-ALPN) peer -> connection error (ALPN) -> exit 2
openssl s_server -quiet -accept 18446 \
  -cert test/certs/localhost.crt -key test/certs/localhost.key -alpn http/1.1 -www \
  >"$BUILD/sserver.log" 2>&1 &
SSERVER_PID=$!
sleep 1
out="$("$PROBE" --url=https://127.0.0.1:18446/ --insecure --timeout-ms=3000 2>&1)"; rc=$?
check "no-h2 ALPN peer -> conn-error (ALPN)" 2 "$rc" "$out"
kill "$SSERVER_PID" 2>/dev/null; SSERVER_PID=""

# 5. positive control: a live nghttpd GET -> exit 0
if command -v nghttpd >/dev/null 2>&1; then
  ROOT="$BUILD/www"; mkdir -p "$ROOT"; printf 'ok' > "$ROOT/f.txt"
  nghttpd -d "$ROOT" 18447 test/certs/localhost.key test/certs/localhost.crt \
    >"$BUILD/ng.log" 2>&1 &
  NGHTTPD_PID=$!
  for i in $(seq 1 50); do nc -z 127.0.0.1 18447 2>/dev/null && break; sleep 0.1; done
  out="$("$PROBE" --url=https://localhost:18447/f.txt --insecure --timeout-ms=4000 2>&1)"; rc=$?
  check "live nghttpd GET -> success" 0 "$rc" "$out"
  kill "$NGHTTPD_PID" 2>/dev/null; NGHTTPD_PID=""
else
  echo "SKIP  live nghttpd GET (nghttpd not installed)"
fi

echo
echo "sanity: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
