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
# Then the selector, proxy and per-request cases (doc/design/mtls.md "Where it
# applies", "Per-request identity"): two origins that each serve one identity
# only, reached by one client whose selector picks the identity per origin; an
# https proxy (mtls_server.py --proxy) that requires its own client
# certificate while the origin behind it sees the origin identity (the proxy
# sees the proxy identity only); an HTTP CONNECT proxy
# (mtls_server.py --plain-proxy) through which the origin still sees
# the origin identity; and an identity attached to the request, directly and
# through the https proxy, where the origin sees that identity and the proxy
# the proxy identity.
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

start_python() { # port tls log [extra mtls_server.py args...]
  python3 "$HERE/mtls_server.py" --port "$1" --tls "$2" --log "$3" "${@:4}" \
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

# the selector: each origin serves one identity only, so a client that offered
# the wrong one would be answered 403; one client, one selector, two origins
ORIGIN_A=$((BASE + 3)); ORIGIN_B=$((BASE + 4))
start_python "$ORIGIN_A" 1.3 "$WORK/origin-a.log" --only-subject "mtls client"
start_python "$ORIGIN_B" 1.3 "$WORK/origin-b.log" --only-subject "mtls client two"
SELECT="$ORIGIN_A:$GOOD_CERT:$GOOD_KEY;$ORIGIN_B:$CERTS/client2-chain.pem:$CERTS/client2.key"
OUT="$(MTLS_SELECT="$SELECT" "$GET" \
  "https://localhost:$ORIGIN_A/,https://localhost:$ORIGIN_B/,https://localhost:$ORIGIN_A/" \
  - - "$CERTS/ca.crt" 2>&1)"
RC=$?
check "selector two origins: exit" 0 "$RC"
check "selector two origins: three 200s" 3 "$(printf '%s\n' "$OUT" | grep -c 'status: 200')"
# the server closes after each response, so each of A's two requests dials
check "selector origin A: two connections" 2 "$(grep -c '^accept ' "$WORK/origin-a.log")"
check "selector origin A: its identity each time" 2 "$(grep -c 'commonName=mtls client$' "$WORK/origin-a.log")"
check "selector origin B: one connection" 1 "$(grep -c '^accept ' "$WORK/origin-b.log")"
check "selector origin B: its identity" 1 "$(grep -c 'commonName=mtls client two$' "$WORK/origin-b.log")"
check "selector: neither origin refused an identity" 0 \
  "$(cat "$WORK/origin-a.log" "$WORK/origin-b.log" | grep -c '^forbid ')"
# the origins do enforce it: the one fixed identity is forbidden at B
run_get "https://localhost:$ORIGIN_B/" "$GOOD_CERT" "$GOOD_KEY"
contains "fixed identity at the other origin: forbidden" "status: 403" "$OUT"
contains "fixed identity at the other origin: logged" "forbid " "$(cat "$WORK/origin-b.log")"

# the proxy identity: an https proxy that requires a client certificate in front
# of an origin that requires another; each must see its own identity only
PROXY_ORIGIN=$((BASE + 5)); PROXY_PORT=$((BASE + 6))
start_python "$PROXY_ORIGIN" 1.3 "$WORK/proxy-origin.log"
start_python "$PROXY_PORT" 1.3 "$WORK/proxy.log" --proxy
OUT="$(MTLS_PROXY="$PROXY_PORT" MTLS_PROXY_CERT="$CERTS/client2-chain.pem" \
  MTLS_PROXY_KEY="$CERTS/client2.key" "$GET" "https://localhost:$PROXY_ORIGIN/" \
  "$GOOD_CERT" "$GOOD_KEY" "$CERTS/ca.crt" 2>&1)"
RC=$?
check "proxy identity: exit" 0 "$RC"
contains "proxy identity: status" "status: 200" "$OUT"
check "proxy accepted the proxy identity" 1 "$(grep -c 'commonName=mtls client two$' "$WORK/proxy.log")"
contains "proxy tunnelled to the origin" "tunnel localhost:$PROXY_ORIGIN" "$(cat "$WORK/proxy.log")"
check "origin accepted the origin identity" 1 "$(grep -c 'commonName=mtls client$' "$WORK/proxy-origin.log")"
check "origin never saw the proxy identity" 0 "$(grep -c 'client two' "$WORK/proxy-origin.log")"
check "proxy never saw the origin identity" 0 "$(grep -c 'commonName=mtls client$' "$WORK/proxy.log")"
# the origin identity does not satisfy the proxy
OUT="$(MTLS_PROXY="$PROXY_PORT" "$GET" "https://localhost:$PROXY_ORIGIN/" \
  "$GOOD_CERT" "$GOOD_KEY" "$CERTS/ca.crt" 2>&1)"
RC=$?
check "proxy without its identity: refused" 1 "$([ "$RC" -ne 0 ] && echo 1 || echo 0)"
check "proxy without its identity: no second tunnel" 1 \
  "$(grep -c '^tunnel ' "$WORK/proxy.log")"

# HTTP CONNECT proxy: no TLS leg, so there is no proxy identity, and the origin
# identity still reaches the origin through the tunnel
CONNECT_PORT=$((BASE + 7))
start_python "$CONNECT_PORT" 1.3 "$WORK/connect.log" --plain-proxy
OUT="$(MTLS_PROXY="$CONNECT_PORT" MTLS_PROXY_KIND=http "$GET" \
  "https://localhost:$PROXY_ORIGIN/" "$GOOD_CERT" "$GOOD_KEY" "$CERTS/ca.crt" 2>&1)"
RC=$?
check "connect proxy: exit" 0 "$RC"
contains "connect proxy: status" "status: 200" "$OUT"
contains "connect proxy tunnelled to the origin" "tunnel localhost:$PROXY_ORIGIN" "$(cat "$WORK/connect.log")"
check "connect proxy: the origin saw the origin identity again" 2 \
  "$(grep -c 'commonName=mtls client$' "$WORK/proxy-origin.log")"
check "connect proxy: no certificate reached the proxy" 0 "$(grep -c '^accept ' "$WORK/connect.log")"

# the selector through the https proxy is asked for the origin (its port picks
# the identity), and the proxy identity still goes to the proxy only
ORIGIN_C=$((BASE + 8))
start_python "$ORIGIN_C" 1.3 "$WORK/origin-c.log" --only-subject "mtls client two"
PROXY2=$((BASE + 9))
start_python "$PROXY2" 1.3 "$WORK/proxy2.log" --proxy
OUT="$(MTLS_PROXY="$PROXY2" MTLS_PROXY_CERT="$GOOD_CERT" MTLS_PROXY_KEY="$GOOD_KEY" \
  MTLS_SELECT="$ORIGIN_C:$CERTS/client2-chain.pem:$CERTS/client2.key" "$GET" \
  "https://localhost:$ORIGIN_C/" - - "$CERTS/ca.crt" 2>&1)"
RC=$?
check "selector through the https proxy: exit" 0 "$RC"
contains "selector through the https proxy: status" "status: 200" "$OUT"
check "selector through the https proxy: origin saw the selected identity" 1 \
  "$(grep -c 'commonName=mtls client two$' "$WORK/origin-c.log")"
check "selector through the https proxy: proxy saw the proxy identity only" 1 \
  "$(grep -c 'commonName=mtls client$' "$WORK/proxy2.log")"
check "selector through the https proxy: proxy never saw the selected identity" 0 \
  "$(grep -c 'client two' "$WORK/proxy2.log")"

# a per-request identity: no client identity is configured, the request names
# one.  Origin C serves "mtls client two" only
OUT="$(MTLS_REQUEST_CERT="$CERTS/client2-chain.pem" MTLS_REQUEST_KEY="$CERTS/client2.key" \
  "$GET" "https://localhost:$ORIGIN_C/" - - "$CERTS/ca.crt" 2>&1)"
RC=$?
check "request identity direct: exit" 0 "$RC"
contains "request identity direct: status" "status: 200" "$OUT"
check "request identity direct: origin saw the request identity" 2 \
  "$(grep -c 'commonName=mtls client two$' "$WORK/origin-c.log")"
# through the https proxy: the request identity reaches the origin, the proxy
# identity the proxy, neither the other
: > "$WORK/proxy2.log"
OUT="$(MTLS_REQUEST_CERT="$CERTS/client2-chain.pem" MTLS_REQUEST_KEY="$CERTS/client2.key" \
  MTLS_PROXY="$PROXY2" MTLS_PROXY_CERT="$GOOD_CERT" MTLS_PROXY_KEY="$GOOD_KEY" \
  "$GET" "https://localhost:$ORIGIN_C/" - - "$CERTS/ca.crt" 2>&1)"
RC=$?
check "request identity through the https proxy: exit" 0 "$RC"
contains "request identity through the https proxy: status" "status: 200" "$OUT"
check "request identity through the https proxy: origin saw it" 3 \
  "$(grep -c 'commonName=mtls client two$' "$WORK/origin-c.log")"
check "request identity through the https proxy: proxy saw the proxy identity only" 1 \
  "$(grep -c 'commonName=mtls client$' "$WORK/proxy2.log")"
check "request identity through the https proxy: proxy never saw the request identity" 0 \
  "$(grep -c 'client two' "$WORK/proxy2.log")"
# an expired request identity is refused before any connection
before="$(grep -c '^accept ' "$WORK/origin-c.log")"
OUT="$(MTLS_REQUEST_CERT="$CERTS/expired.crt" MTLS_REQUEST_KEY="$CERTS/expired.key" \
  "$GET" "https://localhost:$ORIGIN_C/" - - "$CERTS/ca.crt" 2>&1)"
RC=$?
check "expired request identity: exit" 1 "$RC"
contains "expired request identity: refused" "expired" "$OUT"
check "expired request identity: nothing dialled" "$before" "$(grep -c '^accept ' "$WORK/origin-c.log")"

if [ "$FAIL" -ne 0 ]; then
  echo "mtls-live: FAILED"; exit 1
fi
echo "mtls-live: PASS"
