#!/usr/bin/env bash
# Opt-in live WebSocket gate (doc/design/websocket.md): drive the real client
# against a reference RFC 6455 server over ws and wss, directly and through an
# HTTP CONNECT proxy, an https (TLS) proxy and a SOCKS5 proxy, then read the
# servers' logs to prove what each connection did on the wire: the mask bit of
# every client frame, the close codes, the subprotocol, the route.  The
# observed-session cases attach a request observer and assert one start, one
# end, the close code and the message gaps of a /chatter session.
#
#   bash tools/validate/websocket-live.sh              # or: make validate-websocket
#   bash tools/validate/websocket-live.sh autobahn     # or: make validate-websocket-autobahn
#
# The default unit suite skips TWebSocketLiveTest (WS_LIVE_PORTS unset), so
# this script is the only runner that executes it.  The autobahn mode runs the
# Autobahn|Testsuite fuzzing server (Docker) against the client and reads its
# report.
#
# Env overrides: WS_BASE (default 8601), BIN (default bin), OPENSSL_LIBPATH.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BIN="${BIN:-$ROOT/bin}"
BASE="${WS_BASE:-8601}"
PBASE=$((BASE + 10))
MODE="${1:-live}"
WORK="$(mktemp -d)"
LOG_A="$WORK/a.log"; LOG_B="$WORK/b.log"; LOG_P="$WORK/proxy.log"

PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do
    [ -n "$p" ] && kill "$p" 2>/dev/null && wait "$p" 2>/dev/null
  done
  docker rm -f ws-autobahn >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

wait_ready() { # file name
  for _ in $(seq 1 60); do
    grep -q ready "$1" 2>/dev/null && return 0
    sleep 0.1
  done
  echo "websocket-live: $2 did not start" >&2
  return 1
}

live() {
  local RUNNER="$BIN/Http2.RunTests"
  if [ ! -x "$RUNNER" ]; then
    echo "websocket-live: $RUNNER is missing; run 'make test' first" >&2
    exit 2
  fi
  cat "$ROOT/test/certs/other.crt" "$ROOT/test/certs/localhost.crt" > "$WORK/ca.pem"

  # A: ws on BASE, wss (certificate for 127.0.0.1) on BASE+1
  python3 "$HERE/ws_servers.py" --log "$LOG_A" --plain-port "$BASE" \
    --tls-port $((BASE + 1)) --cert "$ROOT/test/certs/localhost.crt" \
    --key "$ROOT/test/certs/localhost.key" >"$WORK/ra" 2>"$WORK/ea" &
  PIDS+=($!)
  # B: wss (certificate for other.example) on BASE+2, ws on BASE+3: the
  # origins the proxies map other.example to
  python3 "$HERE/ws_servers.py" --log "$LOG_B" --plain-port $((BASE + 3)) \
    --tls-port $((BASE + 2)) --cert "$ROOT/test/certs/other.crt" \
    --key "$ROOT/test/certs/other.key" --no-alpn >"$WORK/rb" 2>"$WORK/eb" &
  PIDS+=($!)
  python3 "$HERE/proxy_servers.py" --log "$LOG_P" --certs "$ROOT/test/certs" \
    --origin-tls-port $((BASE + 2)) --external-tls-origin \
    --origin-plain-port $((BASE + 3)) --external-plain-origin \
    --http-proxy-port $((PBASE + 2)) --https-proxy-port $((PBASE + 3)) \
    --socks-port $((PBASE + 4)) >"$WORK/rp" 2>"$WORK/ep" &
  PIDS+=($!)
  wait_ready "$WORK/ra" "server A" || { cat "$WORK/ea" >&2; exit 2; }
  wait_ready "$WORK/rb" "server B" || { cat "$WORK/eb" >&2; exit 2; }
  wait_ready "$WORK/rp" "proxies"  || { cat "$WORK/ep" >&2; exit 2; }

  WS_LIVE_PORTS="$BASE,$PBASE" WS_LIVE_CA="$WORK/ca.pem" \
    "$RUNNER" --all --format=plain --sparse --suite=TWebSocketLiveTest
  RC=$?

  FAIL=0
  expect() { # file pattern description
    if ! grep -qE "$2" "$1"; then
      echo "websocket-live: MISSING in $(basename "$1"): $3  /$2/"; FAIL=1
    fi
  }
  reject() {
    if grep -qE "$2" "$1"; then
      echo "websocket-live: UNEXPECTED in $(basename "$1"): $3  /$2/"; FAIL=1
    fi
  }
  for f in "$LOG_A" "$LOG_B"; do
    expect "$f" '^handshake .* version=13 keylen=16 upgrade=websocket connection=Upgrade' "RFC 6455 handshake headers"
    expect "$f" '^conn-summary .* frames=[1-9]'  "frames were exchanged"
    reject "$f" 'unmasked=[1-9]'                  "a client frame was sent unmasked"
  done
  expect "$LOG_A" '^handshake path=/echo host=127\.0\.0\.1:'"$BASE"      "Host header carries the port"
  expect "$LOG_A" '^handshake path=/protocol .* protocols=chat,superchat' "subprotocols offered as a list"
  expect "$LOG_A" '^handshake path=/chatter host=127\.0\.0\.1:'"$BASE"  "an observed session over ws"
  expect "$LOG_A" '^handshake path=/chatter host=127\.0\.0\.1:'$((BASE + 1))  "an observed session over wss"
  expect "$LOG_B" '^handshake path=/chatter host=other\.example'         "an observed session through a proxy"
  expect "$LOG_A" '^pong len=3 data=srv'          "the pong answered the server ping"
  expect "$LOG_A" '^ping-answered len=0'          "the client ping was answered"
  expect "$LOG_A" '^close code=1000 reason=done'  "client close carries its code and reason"
  expect "$LOG_A" '^close-echo code=1001'         "the server close was echoed with its code"
  expect "$LOG_A" '^close code=1007'              "invalid UTF-8 was answered with 1007"
  expect "$LOG_A" '^handshake path=/echo host=127\.0\.0\.1:'$((BASE + 1))  "wss over TLS reached the server"
  expect "$LOG_B" '^handshake path=/echo host=other\.example'              "tunnelled request named the origin"
  expect "$LOG_A" '^handshake path=/echo host=127\.0\.0\.1:'$((BASE + 1))' alpn=http/1.1' "wss offered and got http/1.1 alone"
  expect "$LOG_B" 'host=other\.example:?[0-9]* alpn=None'                     "a server without ALPN is accepted"
  expect "$LOG_P" '^http-connect other\.example:80 auth=none'              "ws through CONNECT"
  expect "$LOG_P" '^http-connect other\.example:443 auth=none'             "wss through CONNECT"
  expect "$LOG_P" '^https-connect other\.example:80 auth=none'             "ws through TLS to the proxy"
  expect "$LOG_P" '^https-connect other\.example:443 auth=none'            "wss is TLS inside TLS"
  expect "$LOG_P" '^socks5 atyp=3 other\.example:80 auth=none'             "ws through SOCKS5, name unresolved"
  expect "$LOG_P" '^socks5 atyp=3 other\.example:443 auth=none'            "wss through SOCKS5, name unresolved"
  reject "$LOG_P" '127\.0\.0\.1|refused'                                   "loopback or unknown target went through a proxy"

  if [ "$RC" -ne 0 ] || [ "$FAIL" -ne 0 ]; then
    echo "websocket-live: FAILED (tests rc=$RC, log checks=$FAIL)"
    for f in "$LOG_A" "$LOG_B" "$LOG_P"; do echo "--- $(basename "$f")"; cat "$f"; done
    exit 1
  fi
  echo "websocket-live: PASS"
}

autobahn() {
  if ! docker info >/dev/null 2>&1; then
    echo "websocket-live: SKIP autobahn (the Docker daemon is not running)"
    exit 0
  fi
  local PORT="${AUTOBAHN_PORT:-9001}"
  mkdir -p "$WORK/config" "$WORK/reports"
  cat > "$WORK/config/fuzzingserver.json" <<JSON
{
  "url": "ws://127.0.0.1:9001",
  "outdir": "/reports/clients",
  "cases": ["*"],
  "exclude-cases": ["12.*", "13.*"],
  "exclude-agent-cases": {}
}
JSON
  chmod -R a+rwx "$WORK/reports"
  docker run -d --rm --name ws-autobahn -p "$PORT:9001" \
    -v "$WORK/config:/config" -v "$WORK/reports:/reports" \
    crossbario/autobahn-testsuite wstest -m fuzzingserver -s /config/fuzzingserver.json \
    >/dev/null || { echo "websocket-live: could not start the Autobahn container" >&2; exit 2; }
  for _ in $(seq 1 100); do
    (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null && break
    sleep 0.3
  done
  local M="$ROOT/third_party/mORMot2/src"
  fpc -O2 -vw -Mdelphi -Fu"$ROOT/src" -Fu"$M/core" -Fu"$M/lib" -Fu"$M/net" -Fu"$M/crypt" \
    -FE"$WORK" -FU"$WORK" "$HERE/autobahn_client.pas" >"$WORK/fpc.log" 2>&1 \
    || { cat "$WORK/fpc.log"; echo "websocket-live: could not build the Autobahn client" >&2; exit 2; }
  "$WORK/autobahn_client" "127.0.0.1:$PORT"
  RC=$?
  python3 "$HERE/autobahn_report.py" "$WORK/reports/clients/index.json" "http2client" \
    "$HERE/autobahn-expected.txt"
  RC2=$?
  mkdir -p "$ROOT/bin/autobahn" && cp -R "$WORK/reports/clients" "$ROOT/bin/autobahn/" 2>/dev/null
  if [ "$RC" -ne 0 ] || [ "$RC2" -ne 0 ]; then
    echo "websocket-live: autobahn FAILED (client rc=$RC, report rc=$RC2)"
    exit 1
  fi
  echo "websocket-live: autobahn PASS"
}

case "$MODE" in
  live) live ;;
  autobahn) autobahn ;;
  *) echo "usage: $0 [live|autobahn]" >&2; exit 2 ;;
esac
