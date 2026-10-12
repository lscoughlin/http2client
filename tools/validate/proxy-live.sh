#!/usr/bin/env bash
# Opt-in live proxy gate (doc/design/proxy.md): drive the real client through a
# real HTTP CONNECT proxy, an https (TLS) proxy and a SOCKS5 proxy, with and
# without credentials, then read the servers' logs to prove WHICH route each
# request took.
#
# The default unit suite skips TProxyLiveTest (PROXY_LIVE_PORTS unset), so this
# script is the only runner that executes it.  It starts
# tools/validate/proxy_servers.py twice on loopback (open proxies on base port
# PROXY_BASE, proxies requiring bob:pw on PROXY_BASE+10), runs just the live
# suite, checks the logs, and always stops the servers again.
#
#   bash tools/validate/proxy-live.sh          # or: make validate-proxy
#
# Env overrides: PROXY_BASE (default 8481), BIN (default bin), and the usual
# OPENSSL_LIBPATH.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BIN="${BIN:-$ROOT/bin}"
BASE="${PROXY_BASE:-8481}"
AUTH_BASE=$((BASE + 10))
RUNNER="$BIN/Http2.RunTests"
WORK="$(mktemp -d)"
LOG_OPEN="$WORK/open.log"
LOG_AUTH="$WORK/auth.log"

if [ ! -x "$RUNNER" ]; then
  echo "proxy-live: $RUNNER is missing; run 'make test' first" >&2
  exit 2
fi

PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do
    [ -n "$p" ] && kill "$p" 2>/dev/null && wait "$p" 2>/dev/null
  done
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# one trust file that covers both certificates: the origin (other.example) and
# the https proxy (localhost)
cat "$ROOT/test/certs/other.crt" "$ROOT/test/certs/localhost.crt" > "$WORK/ca.pem"

start() { # base-port log extra-args...
  local base="$1" log="$2"; shift 2
  python3 "$HERE/proxy_servers.py" --log "$log" --certs "$ROOT/test/certs" \
    --origin-tls-port "$base" --origin-plain-port $((base + 1)) \
    --http-proxy-port $((base + 2)) --https-proxy-port $((base + 3)) \
    --socks-port $((base + 4)) "$@" >"$WORK/ready.$base" 2>"$WORK/err.$base" &
  PIDS+=($!)
  for _ in $(seq 1 50); do
    grep -q ready "$WORK/ready.$base" 2>/dev/null && return 0
    sleep 0.1
  done
  echo "proxy-live: servers on $base did not start" >&2
  cat "$WORK/err.$base" >&2
  return 1
}

start "$BASE" "$LOG_OPEN" || exit 2
start "$AUTH_BASE" "$LOG_AUTH" --user bob --password pw || exit 2

# HTTP/2 through each proxy kind needs a real h2 origin: nghttpd presents the
# other.example certificate, and a third proxy instance maps other.example:443
# to it.  The case is skipped when nghttpd is not installed.
H2_BASE=$((BASE + 30))
H2_PORT=$((BASE + 20))
LOG_H2="$WORK/h2.log"
H2_ENV=""
NGHTTPD="$(command -v nghttpd || true)"
if [ -n "$NGHTTPD" ]; then
  mkdir -p "$WORK/htdocs"
  head -c 100000 /dev/urandom > "$WORK/htdocs/big.bin"
  "$NGHTTPD" -d "$WORK/htdocs" "$H2_PORT" \
    "$ROOT/test/certs/other.key" "$ROOT/test/certs/other.crt" \
    >"$WORK/nghttpd.log" 2>&1 &
  PIDS+=($!)
  start "$H2_BASE" "$LOG_H2" --origin-tls-port "$H2_PORT" --external-tls-origin \
    || exit 2
  H2_ENV="$H2_BASE"
else
  echo "proxy-live: nghttpd not found; HTTP/2-through-proxy cases skipped"
fi

echo "proxy-live: open servers at $BASE.., auth servers at $AUTH_BASE.."
PROXY_LIVE_PORTS="$BASE,$AUTH_BASE" PROXY_LIVE_CA="$WORK/ca.pem" \
  PROXY_LIVE_H2_BASE="$H2_ENV" \
  "$RUNNER" --all --format=plain --sparse --suite=TProxyLiveTest
RC=$?

# the logs prove the route taken, not just that a response arrived
FAIL=0
expect() { # file pattern description
  if ! grep -qE "$2" "$1"; then
    echo "proxy-live: MISSING in $(basename "$1"): $3  /$2/"
    FAIL=1
  fi
}
reject() { # file pattern description
  if grep -qE "$2" "$1"; then
    echo "proxy-live: UNEXPECTED in $(basename "$1"): $3  /$2/"
    FAIL=1
  fi
}
expect "$LOG_OPEN" '^http-connect other\.example:443 auth=none' "CONNECT tunnel for https"
expect "$LOG_OPEN" '^http-connect other\.example:80 auth=none'  "CONNECT tunnel for http"
expect "$LOG_OPEN" '^https-connect other\.example:443 auth=none' "CONNECT inside TLS to the proxy"
expect "$LOG_OPEN" '^socks5 atyp=3 other\.example:443 auth=none' "SOCKS5 sends the name unresolved (https)"
expect "$LOG_OPEN" '^socks5 atyp=3 other\.example:80 auth=none'  "SOCKS5 sends the name unresolved (http)"
expect "$LOG_OPEN" '^origin tls host=other\.example'  "origin saw the tunnelled request"
expect "$LOG_OPEN" '^origin tls host=localhost:'      "loopback request reached the origin directly"
reject "$LOG_OPEN" 'localhost.* auth=|refused'        "loopback or unknown target went through a proxy"
expect "$LOG_AUTH" '^http-connect other\.example:443 auth=ok'  "Basic credentials accepted"
expect "$LOG_AUTH" '^http-connect other\.example:443 auth=bad' "wrong Basic password rejected"
expect "$LOG_AUTH" '^socks5 atyp=3 other\.example:443 auth=ok' "SOCKS5 credentials accepted"
expect "$LOG_AUTH" '^socks5 auth=bad'                          "wrong SOCKS5 password rejected"

if [ -n "$H2_ENV" ]; then
  expect "$LOG_H2" '^http-connect other\.example:443 auth=none'  "h2 over an HTTP CONNECT tunnel"
  expect "$LOG_H2" '^https-connect other\.example:443 auth=none' "h2 over TLS inside TLS (https proxy)"
  expect "$LOG_H2" '^socks5 atyp=3 other\.example:443 auth=none' "h2 over a SOCKS5 tunnel"
  reject "$LOG_H2" 'refused'                                      "an h2 tunnel was refused"
fi

if [ "$RC" -ne 0 ] || [ "$FAIL" -ne 0 ]; then
  echo "proxy-live: FAILED (tests rc=$RC, log checks=$FAIL)"
  echo "--- open log"; cat "$LOG_OPEN"; echo "--- auth log"; cat "$LOG_AUTH"
  [ -f "$LOG_H2" ] && { echo "--- h2 log"; cat "$LOG_H2"; }
  exit 1
fi
echo "proxy-live: PASS"
