#!/usr/bin/env bash
# Opt-in live mutual TLS gate (doc/design/mtls.md): drive the real client,
# through examples/mtls_get.pas, against servers that require a client
# certificate:
#
#   tools/validate/mtls_server.py   Python `ssl`, CERT_REQUIRED; HTTP/1.1, an
#                                   event stream and a WebSocket route, once
#                                   pinned to TLS 1.2 and once to TLS 1.3
#   nghttpd --verify-client         HTTP/2 (it requires a certificate but does
#                                   not verify it, so the wrong-CA case is
#                                   left to the Python servers)
#
# Cases per server: an accepted identity, no identity, an identity from
# another CA, and an expired identity (refused by the client at Build, before
# any connection).  The Python servers also serve /events and wss, and their
# logs prove what each connection did on the server side.
#
#   bash tools/validate/mtls-live.sh          # or: make validate-mtls
#
# Fixtures come from tools/validate/make-mtls-certs.sh (test/certs/mtls).
# Env overrides: MTLS_BASE (default 8661), OPENSSL_LIBPATH.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BASE="${MTLS_BASE:-8661}"
CERTS="$ROOT/test/certs/mtls"
WORK="$(mktemp -d)"
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do
    [ -n "$p" ] && kill "$p" 2>/dev/null && wait "$p" 2>/dev/null
  done
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

M="$ROOT/third_party/mORMot2/src"
fpc -O2 -vw -Mdelphi -Fu"$ROOT/src" -Fu"$M/core" -Fu"$M/lib" -Fu"$M/net" -Fu"$M/crypt" \
  -FE"$WORK" -FU"$WORK" "$ROOT/examples/mtls_get.pas" >"$WORK/fpc.log" 2>&1 \
  || { cat "$WORK/fpc.log"; echo "mtls-live: could not build examples/mtls_get.pas" >&2; exit 2; }
GET="$WORK/mtls_get"

FAIL=0
check() { # description expected actual
  if [ "$2" = "$3" ]; then
    echo "mtls-live: ok   $1"
  else
    echo "mtls-live: FAIL $1 (expected '$2', saw '$3')"; FAIL=1
  fi
}
contains() { # description needle haystack
  case "$3" in
    *"$2"*) echo "mtls-live: ok   $1" ;;
    *) echo "mtls-live: FAIL $1 (expected to contain '$2', saw '$3')"; FAIL=1 ;;
  esac
}

wait_ready() { # file name
  for _ in $(seq 1 60); do
    grep -q ready "$1" 2>/dev/null && return 0
    sleep 0.1
  done
  echo "mtls-live: $2 did not start" >&2
  exit 2
}

# run_get url cert key  -> sets OUT (stdout+stderr) and RC
run_get() {
  OUT="$("$GET" "$1" "$2" "$3" "$CERTS/ca.crt" 2>&1)"
  RC=$?
}

GOOD_CERT="$CERTS/client-chain.pem"; GOOD_KEY="$CERTS/client.key"

# the cases every server must pass; $1 label, $2 port
common_cases() {
  local label="$1" port="$2"
  run_get "https://localhost:$port/" "$GOOD_CERT" "$GOOD_KEY"
  check "$label accepted: exit" 0 "$RC"
  contains "$label accepted: status" "status: 200" "$OUT"

  run_get "https://localhost:$port/" "-" "-"
  check "$label no identity: exit" 3 "$RC"
  contains "$label no identity: alert named" "server rejected the client certificate" "$OUT"

  if [ "$label" != "nghttpd http/2" ]; then
    # nghttpd --verify-client only asks for a certificate, it does not verify it
    run_get "https://localhost:$port/" "$CERTS/other-client.crt" "$CERTS/other-client.key"
    check "$label wrong CA: exit" 3 "$RC"
    contains "$label wrong CA: alert" "unknown ca" "$OUT"
  fi

  run_get "https://localhost:$port/" "$CERTS/expired.crt" "$CERTS/expired.key"
  check "$label expired: exit" 1 "$RC"
  contains "$label expired: refused at Build" "expired" "$OUT"
}

# the Python servers: also /events and wss, and the server-side logs
python_cases() {
  local label="$1" port="$2" log="$3"
  common_cases "$label" "$port"
  run_get "https://localhost:$port/events" "$GOOD_CERT" "$GOOD_KEY"
  check "$label event stream: exit" 0 "$RC"
  run_get "wss://localhost:$port/ws" "$GOOD_CERT" "$GOOD_KEY"
  check "$label wss: exit" 0 "$RC"
  contains "$label wss: message" "message: hello" "$OUT"
  sleep 0.3
  check "$label accepted connections (/, /events, wss)" 3 "$(grep -c '^accept ' "$log")"
  contains "$label server saw the client subject" "commonName=mtls client" "$(cat "$log")"
  # no identity and the wrong CA were both refused; the expired one never connected
  check "$label refused handshakes" 2 "$(grep -c '^reject ' "$log")"
}

start_python() { # port tls log
  python3 "$HERE/mtls_server.py" --port "$1" --tls "$2" --log "$3" \
    --cert "$CERTS/server.crt" --key "$CERTS/server.key" --ca "$CERTS/ca.crt" \
    >"$WORK/ready-$1" 2>"$WORK/err-$1" &
  PIDS+=($!)
  wait_ready "$WORK/ready-$1" "mtls_server.py (TLS $2)"
}

start_python "$BASE" 1.2 "$WORK/tls12.log"
python_cases "tls1.2 http/1.1" "$BASE" "$WORK/tls12.log"

start_python $((BASE + 1)) 1.3 "$WORK/tls13.log"
python_cases "tls1.3 http/1.1" $((BASE + 1)) "$WORK/tls13.log"

NGHTTPD="$(command -v nghttpd || true)"
if [ -z "$NGHTTPD" ]; then
  echo "mtls-live: SKIP nghttpd not found; HTTP/2 cases not run"
  FAIL=1
else
  mkdir -p "$WORK/docroot"
  echo ok > "$WORK/docroot/index.html"
  "$NGHTTPD" --verify-client \
    -d "$WORK/docroot" $((BASE + 2)) "$CERTS/server.key" "$CERTS/server.crt" \
    >"$WORK/nghttpd.log" 2>&1 &
  PIDS+=($!)
  sleep 1
  common_cases "nghttpd http/2" $((BASE + 2))
fi

if [ "$FAIL" -ne 0 ]; then
  echo "mtls-live: FAILED"; exit 1
fi
echo "mtls-live: PASS"
