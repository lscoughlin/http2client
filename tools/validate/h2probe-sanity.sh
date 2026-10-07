#!/usr/bin/env bash
# tools/validate/h2probe-sanity.sh — non-vacuity / classification proof for
# the S12 probe (doc/verification/validation.md "sanity checks").
#
# It proves the probe is not reporting PASS unconditionally, and that the
# three verifier outcome classes map to distinct exit codes:
#   check 1: an unreachable port              -> exit 2 (connection error)
#   check 2: a reset after a 200 response     -> exit 3 (stream error)
#   check 3: bad usage                        -> exit 1
#   check 4: an http/1.1-only ALPN peer       -> exit 2 with an ALPN message
#   check 5: a live nghttpd GET               -> exit 0 (positive control)
#
# Check 2 uses a local fabricated peer (tools/validate/fake_rst_server.py),
# not the h2-test-harness. The harness's case 5.1/2 sends RST_STREAM on a
# stream it considers idle (it never reads our HEADERS) and then closes the
# socket at once, so the reset races the EOF: the probe legitimately reports
# either a stream error (exit 3) or a connection error (exit 2), and the
# harness's own reference verifier expects the connection error. That case
# therefore cannot serve as a deterministic stream-error oracle. The
# fabricated peer answers the request with a 200 response and only then sends
# RST_STREAM, holding the socket open, so exit 3 is unambiguous. This still
# cross-checks the runner: a vacuous probe that reported exit 0 would fail.
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
  [ -n "${RSTSERVER_PID:-}" ] && kill "$RSTSERVER_PID" 2>/dev/null
  [ -n "${NGHTTPD_PID:-}" ] && kill "$NGHTTPD_PID" 2>/dev/null
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

# Infrastructure failures are counted apart from client failures: a server that
# never bound its port says nothing about the probe, and must not be reported as
# a probe defect (nor silently ignored).
INFRA=0
infra_fail() { # name detail
  printf 'FAIL  %-46s %s\n' "$1" "$2"
  FAIL=$((FAIL+1)); INFRA=$((INFRA+1))
}

# Is a host TCP port accepting connections? Uses nc when present, else bash's
# /dev/tcp. Returns 1 when neither mechanism is available, so the caller treats
# an unverifiable port as not-ready rather than assuming success.
port_open() { # host port
  if command -v nc >/dev/null 2>&1; then
    nc -z "$1" "$2" 2>/dev/null
  else
    (exec 3<>"/dev/tcp/$1/$2") 2>/dev/null
  fi
}

wait_port() { # host port [tenths]  -> 0 when open, 1 when never opened
  local host="$1" port="$2" tries="${3:-100}" i
  for i in $(seq 1 "$tries"); do
    port_open "$host" "$port" && return 0
    sleep 0.1
  done
  return 1
}

# Wait for a line to appear in a file. Use this (NOT port_open/wait_port) to
# gate a server that accepts a SINGLE connection: a TCP-connect readiness probe
# is itself a connection and would consume that one accept, so the real probe
# afterwards would hit a consumed/half-open socket.
wait_log_line() { # file pattern [tenths]
  local file="$1" pattern="$2" tries="${3:-100}" i
  for i in $(seq 1 "$tries"); do
    grep -q "$pattern" "$file" 2>/dev/null && return 0
    sleep 0.1
  done
  return 1
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

# 2. reset after a 200 response -> stream error -> exit 3
# A local fabricated peer sends HEADERS(200) then RST_STREAM(CANCEL) and holds
# the socket open, so the classification is deterministic (see the header
# note). No container and no host-port race are involved.
RST_PORT=18445
python3 tools/validate/fake_rst_server.py \
  "$RST_PORT" test/certs/localhost.crt test/certs/localhost.key 2.0 \
  >"$BUILD/rstserver.log" 2>&1 &
RSTSERVER_PID=$!
if wait_log_line "$BUILD/rstserver.log" "listening on"; then
  out="$("$PROBE" --url=https://127.0.0.1:$RST_PORT/ --insecure \
    --timeout-ms=3000 --keep-open-ms=200 2>&1)"; rc=$?
  check "reset after response -> stream-error" 3 "$rc" "$out"
else
  infra_fail "reset after response -> stream-error" \
    "fabricated rst server never opened port $RST_PORT; see $BUILD/rstserver.log"
fi
kill "$RSTSERVER_PID" 2>/dev/null; RSTSERVER_PID=""

# 3. bad usage -> exit 1
out="$("$PROBE" --nonsense 2>&1)"; rc=$?
check "bad usage -> usage error" 1 "$rc" "$out"

# 4. http/1.1-only (or no-ALPN) peer -> connection error (ALPN) -> exit 2
# Ports 18446/18447 are chosen to avoid the fabricated rst server's 18445.
openssl s_server -quiet -accept 18446 \
  -cert test/certs/localhost.crt -key test/certs/localhost.key -alpn http/1.1 -www \
  >"$BUILD/sserver.log" 2>&1 &
SSERVER_PID=$!
if wait_port 127.0.0.1 18446; then
  out="$("$PROBE" --url=https://127.0.0.1:18446/ --insecure --timeout-ms=3000 2>&1)"; rc=$?
  check "no-h2 ALPN peer -> conn-error (ALPN)" 2 "$rc" "$out"
else
  infra_fail "no-h2 ALPN peer -> conn-error (ALPN)" \
    "openssl s_server never opened port 18446"
fi
kill "$SSERVER_PID" 2>/dev/null; SSERVER_PID=""

# 5. positive control: a live nghttpd GET -> exit 0
if command -v nghttpd >/dev/null 2>&1; then
  ROOT="$BUILD/www"; mkdir -p "$ROOT"; printf 'ok' > "$ROOT/f.txt"
  nghttpd -d "$ROOT" 18447 test/certs/localhost.key test/certs/localhost.crt \
    >"$BUILD/ng.log" 2>&1 &
  NGHTTPD_PID=$!
  if wait_port 127.0.0.1 18447; then
    out="$("$PROBE" --url=https://localhost:18447/f.txt --insecure --timeout-ms=4000 2>&1)"; rc=$?
    check "live nghttpd GET -> success" 0 "$rc" "$out"
  else
    infra_fail "live nghttpd GET -> success" \
      "nghttpd never opened port 18447; see $BUILD/ng.log"
  fi
  kill "$NGHTTPD_PID" 2>/dev/null; NGHTTPD_PID=""
else
  echo "SKIP  live nghttpd GET (nghttpd not installed)"
fi

echo
echo "sanity: PASS=$PASS FAIL=$FAIL"
if [ "$INFRA" -gt 0 ]; then
  echo "        ($INFRA of the failures are infrastructure: a server did not start)"
fi
[ "$FAIL" -eq 0 ]
