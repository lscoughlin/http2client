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
# Then the selector case (doc/design/mtls.md "Selector"): two origins that each
# serve one identity only, reached by one client whose selector picks the
# identity per origin.  Then the proxy cases (doc/design/mtls.md "Where it
# applies"): an https proxy (mtls_server.py --proxy) that requires a client
# certificate receives the identity and the origin behind it sees none, with a
# fixed identity and with a selector; an http proxy (--plain-proxy) receives
# it nowhere, so an origin that requires a certificate is unreachable through it.
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

# proxies: the identity goes to the TLS leg of an https proxy and to nothing
# else.  The origin asks for a certificate without requiring one
# (--optional-cert), so it completes the handshake and its log shows whether
# the client offered any: through every proxy it must log "accept nocert".
PROXY_ORIGIN=$((BASE + 5)); HTTPS_PROXY_PORT=$((BASE + 6))
HTTP_PROXY_PORT=$((BASE + 7)); STRICT_ORIGIN=$((BASE + 8))
start_python "$PROXY_ORIGIN" 1.3 "$WORK/proxy-origin.log" --optional-cert
start_python "$HTTPS_PROXY_PORT" 1.3 "$WORK/https-proxy.log" --proxy
start_python "$HTTP_PROXY_PORT" 1.3 "$WORK/http-proxy.log" --plain-proxy
start_python "$STRICT_ORIGIN" 1.3 "$WORK/strict-origin.log"

# https proxy, fixed identity: the proxy sees it, the origin sees none
OUT="$(MTLS_PROXY="https:$HTTPS_PROXY_PORT" "$GET" "https://localhost:$PROXY_ORIGIN/" \
  "$GOOD_CERT" "$GOOD_KEY" "$CERTS/ca.crt" 2>&1)"
RC=$?
check "https proxy: exit" 0 "$RC"
contains "https proxy: status" "status: 200" "$OUT"
check "https proxy accepted the identity" 1 "$(grep -c 'commonName=mtls client$' "$WORK/https-proxy.log")"
contains "https proxy tunnelled to the origin" "tunnel localhost:$PROXY_ORIGIN" "$(cat "$WORK/https-proxy.log")"
check "origin behind the https proxy saw no certificate" 1 "$(grep -c '^accept nocert' "$WORK/proxy-origin.log")"
check "origin behind the https proxy saw no subject" 0 "$(grep -c 'subject=' "$WORK/proxy-origin.log")"

# https proxy, selector: asked for the proxy's port; the entry for the origin's
# port would present an identity there, and must not be used
: > "$WORK/https-proxy.log"
SELECT="$HTTPS_PROXY_PORT:$CERTS/client2-chain.pem:$CERTS/client2.key;$PROXY_ORIGIN:$GOOD_CERT:$GOOD_KEY"
OUT="$(MTLS_SELECT="$SELECT" MTLS_PROXY="https:$HTTPS_PROXY_PORT" "$GET" \
  "https://localhost:$PROXY_ORIGIN/" - - "$CERTS/ca.crt" 2>&1)"
RC=$?
check "https proxy selector: exit" 0 "$RC"
check "https proxy selector: the proxy's identity" 1 "$(grep -c 'commonName=mtls client two$' "$WORK/https-proxy.log")"
check "https proxy selector: origin saw no certificate (two connections, both nocert)" 2 \
  "$(grep -c '^accept nocert' "$WORK/proxy-origin.log")"
check "https proxy selector: origin never saw a subject" 0 "$(grep -c 'subject=' "$WORK/proxy-origin.log")"

# https proxy, no identity: it asks for one and refuses; no tunnel is opened
OUT="$(MTLS_PROXY="https:$HTTPS_PROXY_PORT" "$GET" "https://localhost:$PROXY_ORIGIN/" \
  - - "$CERTS/ca.crt" 2>&1)"
RC=$?
check "https proxy without an identity: refused" 1 "$([ "$RC" -ne 0 ] && echo 1 || echo 0)"
check "https proxy without an identity: no new tunnel" 1 \
  "$(grep -c '^tunnel ' "$WORK/https-proxy.log")"

# http:// proxy: no TLS to it, so the identity is presented nowhere
OUT="$(MTLS_PROXY="http:$HTTP_PROXY_PORT" "$GET" "https://localhost:$PROXY_ORIGIN/" \
  "$GOOD_CERT" "$GOOD_KEY" "$CERTS/ca.crt" 2>&1)"
RC=$?
check "http proxy: exit" 0 "$RC"
contains "http proxy: status" "status: 200" "$OUT"
contains "http proxy tunnelled to the origin" "tunnel localhost:$PROXY_ORIGIN" "$(cat "$WORK/http-proxy.log")"
check "origin behind the http proxy saw no certificate" 3 "$(grep -c '^accept nocert' "$WORK/proxy-origin.log")"
check "origin behind the http proxy saw no subject" 0 "$(grep -c 'subject=' "$WORK/proxy-origin.log")"
# the consequence: an origin that requires a client certificate cannot be
# reached through an http proxy, whatever identity the client holds
OUT="$(MTLS_PROXY="http:$HTTP_PROXY_PORT" "$GET" "https://localhost:$STRICT_ORIGIN/" \
  "$GOOD_CERT" "$GOOD_KEY" "$CERTS/ca.crt" 2>&1)"
RC=$?
check "http proxy to a strict origin: refused" 1 "$([ "$RC" -ne 0 ] && echo 1 || echo 0)"
check "strict origin refused the handshake" 1 "$(grep -c '^reject ' "$WORK/strict-origin.log")"
check "strict origin accepted nothing" 0 "$(grep -c '^accept ' "$WORK/strict-origin.log")"

if [ "$FAIL" -ne 0 ]; then
  echo "mtls-live: FAILED"; exit 1
fi
echo "mtls-live: PASS"
