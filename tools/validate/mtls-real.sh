#!/usr/bin/env bash
# Opt-in mutual TLS gate against real server stacks (doc/verification/mtls-real.md):
# drive the real client, through examples/mtls_get.pas, against nginx, Apache
# httpd (mod_ssl) and Caddy (Go crypto/tls), each requiring a client certificate
# issued under the fixture CA.  The servers run as sibling containers from their
# stock images (--network host, high ports); the client is compiled and run in
# the dev image.  Each server echoes the client certificate subject, the
# protocol and the TLS version in the response body, so the identity the server
# saw is observable.
#
# Per server, three listeners: HTTP/2 + TLS 1.2, HTTP/2 + TLS 1.3 and
# HTTP/1.1 + TLS 1.3 (the server offers no h2, so the client's HTTP/1.1
# fallback carries the request).  Per listener:
#
#   accepted   the fixed identity (WithClientCertificateFiles): 200 and the
#              echoed subject is "mtls client", over the expected protocol and
#              TLS version
#   request    no fixed identity, the identity attached to the request: the
#              echoed subject is "mtls client two"
#   none       no identity: a rejection
#   wrong CA   an identity from another CA: a rejection
#
# A rejection is expected to surface as EHttpTlsClientAuthError with a plausible
# alert name.  A server that answers an HTTP error status instead of a TLS alert
# (nginx does for a missing certificate) is recorded as "HTTP <status>" and
# passes: the library has no alert to report.  Anything else (a generic
# connection error, a hang, a mixed result across repeats) fails unless the
# server/scenario is a documented known limit (KNOWN below).  The rejections are
# repeated (MTLS_REPEAT, default 5) because a server that resets the connection
# with unread client data can turn the alert into a generic error only some of
# the time.  Every client run is under a timeout.
#
# Needs Docker.  From a machine without it, set MTLS_REAL_HOST (default
# lscoughlin@liam-rzbox.local): the tree is copied there with
# tools/container/remote-run.sh and this script runs on that host.
# MTLS_REAL_HOST=local runs it on this machine.
#
#   bash tools/validate/mtls-real.sh          # or: make validate-mtls-real
#
# Env: MTLS_REAL_BASE (default 9440; each server uses 10 ports from its slot),
# MTLS_REPEAT, HTTP2_IMAGE (dev image), NGINX_IMAGE, HTTPD_IMAGE, CADDY_IMAGE.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
HOST="${MTLS_REAL_HOST:-lscoughlin@liam-rzbox.local}"

if [ "${MTLS_REAL_LOCAL:-0}" != 1 ] && [ "$HOST" != local ]; then
  DIR="${HTTP2_REMOTE_DIR:-http2client-ci}"
  # copies the tree (and builds the dev image if the host has none)
  "$ROOT/tools/container/remote-run.sh" "$HOST" true || exit 2
  exec ssh "$HOST" "cd $DIR/src && MTLS_REAL_LOCAL=1 MTLS_REAL_BASE=${MTLS_REAL_BASE:-9440} \
    MTLS_REPEAT=${MTLS_REPEAT:-5} bash tools/validate/mtls-real.sh"
fi

BASE="${MTLS_REAL_BASE:-9440}"
REPEAT="${MTLS_REPEAT:-5}"
IMAGE="${HTTP2_IMAGE:-http2client-dev}"
NGINX_IMAGE="${NGINX_IMAGE:-nginx:1.28-alpine}"
HTTPD_IMAGE="${HTTPD_IMAGE:-httpd:2.4}"
CADDY_IMAGE="${CADDY_IMAGE:-caddy:2}"
CERTS="$ROOT/test/certs/mtls"
WORK="$(mktemp -d)"
TAG="mtls-real-$$"
RUN_TIMEOUT=20
ID="$(id -u):$(id -g)"

# Documented known limits: "server|listener|scenario" a reason.  A listed case
# may end in a generic connection error without failing the gate; it is still
# printed as KNOWN with the exact error.
KNOWN=()

cleanup() {
  docker rm -f "$TAG-client" "$TAG-nginx" "$TAG-httpd" "$TAG-caddy" >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

command -v docker >/dev/null || { echo "mtls-real: docker not found" >&2; exit 2; }

# the client, built with the dev image's Free Pascal
M=/src/third_party/mORMot2/src
mkdir -p "$ROOT/bin/mtls-real"
docker run --rm --user "$ID" -e HOME=/tmp -v "$ROOT:/src" -w /src "$IMAGE" \
  fpc -O2 -vw -Mdelphi -Fu/src/src -Fu$M/core -Fu$M/lib -Fu$M/net -Fu$M/crypt \
  -FE/src/bin/mtls-real -FU/tmp examples/mtls_get.pas >"$WORK/fpc.log" 2>&1 \
  || { cat "$WORK/fpc.log"; echo "mtls-real: could not build examples/mtls_get.pas" >&2; exit 2; }
docker run -d --rm --name "$TAG-client" --network host --user "$ID" -e HOME=/tmp \
  -v "$ROOT:/src:ro" "$IMAGE" sleep 3600 >/dev/null || exit 2

# servers: nginx, httpd, caddy; ports BASE+slot*10 + {0: h2/1.2, 1: h2/1.3, 2: h1/1.3}
SERVERS="nginx httpd caddy"
slot_of() { case "$1" in nginx) echo 0;; httpd) echo 1;; caddy) echo 2;; esac; }
port_of() { echo $((BASE + $(slot_of "$1") * 10 + $2)); }

for s in $SERVERS; do
  mkdir -p "$WORK/$s"
  conf=nginx.conf; [ "$s" = httpd ] && conf=httpd.conf; [ "$s" = caddy ] && conf=Caddyfile
  sed -e "s/@P12@/$(port_of $s 0)/g" -e "s/@P13@/$(port_of $s 1)/g" \
    -e "s/@P1H@/$(port_of $s 2)/g" "$HERE/mtls-real/$conf" >"$WORK/$s/$conf"
done
cp -R "$HERE/mtls-real/htdocs" "$WORK/httpd/htdocs"
chmod -R a+rX "$WORK"

docker run -d --rm --name "$TAG-nginx" --network host -v "$CERTS:/certs:ro" \
  -v "$WORK/nginx:/conf:ro" "$NGINX_IMAGE" nginx -c /conf/nginx.conf >/dev/null || exit 2
docker run -d --rm --name "$TAG-httpd" --network host -v "$CERTS:/certs:ro" \
  -v "$WORK/httpd:/conf:ro" "$HTTPD_IMAGE" httpd -f /conf/httpd.conf -DFOREGROUND >/dev/null || exit 2
docker run -d --rm --name "$TAG-caddy" --network host -v "$CERTS:/certs:ro" \
  -v "$WORK/caddy:/conf:ro" "$CADDY_IMAGE" caddy run --config /conf/Caddyfile --adapter caddyfile >/dev/null || exit 2

for s in $SERVERS; do
  for i in 0 1 2; do
    up=0
    for _ in $(seq 1 100); do
      if (exec 3<>"/dev/tcp/127.0.0.1/$(port_of $s $i)") 2>/dev/null; then up=1; break; fi
      sleep 0.2
    done
    if [ "$up" != 1 ]; then
      echo "mtls-real: $s did not listen on $(port_of $s $i)" >&2
      docker logs "$TAG-$s" 2>&1 | tail -20 >&2
      exit 2
    fi
  done
done

FAIL=0
SKIPPED=0
ROWS="$WORK/rows"
: >"$ROWS"
row() { printf '%s\t%s\t%s\t%s\t%s\n' "$@" >>"$ROWS"; } # server listener scenario result detail

# run_get url cert key [ENV=...]  -> OUT, RC (stdout+stderr, in the client container)
run_get() {
  local url="$1" cert="$2" key="$3"
  shift 3
  OUT="$(timeout $((RUN_TIMEOUT + 15)) docker exec -e MTLS_PRINT_BODY=1 "$@" "$TAG-client" \
    timeout "$RUN_TIMEOUT" /src/bin/mtls-real/mtls_get "$url" "$cert" "$key" /src/test/certs/mtls/ca.crt 2>&1)"
  RC=$?
}

# the sorted RDNs of a subject, so RFC 2253 order and spacing do not matter
norm_dn() { printf '%s' "$1" | tr ',' '\n' | sed 's/^ *//; s/ *$//' | sort | paste -sd, -; }

known_reason() { # key
  local k
  for k in ${KNOWN[@]+"${KNOWN[@]}"}; do
    case "$k" in "$1 "*) echo "${k#"$1 "}"; return 0;; esac
  done
  return 1
}

PLAUSIBLE='certificate required|handshake failure|bad certificate|unknown ca|unknown certificate|access denied|unsupported certificate|certificate expired|certificate revoked'

# an accepting scenario: $1 server $2 listener-label $3 scenario $4 want-dn $5 want-proto $6 want-tls $7... run_get args
accept_case() {
  local server="$1" lis="$2" scen="$3" want_dn="$4" want_proto="$5" want_tls="$6"
  shift 6
  run_get "$@"
  local body dn proto tls status
  status="$(printf '%s\n' "$OUT" | sed -n 's/^status: //p')"
  body="$(printf '%s\n' "$OUT" | sed -n 's/^body: //p')"
  dn="$(printf '%s' "$body" | sed 's/^dn=//; s/ \(verify\|proto\)=.*//')"
  proto="$(printf '%s' "$body" | sed -n 's/.* proto=\([^ ]*\).*/\1/p' | tr 'A-Z' 'a-z')"
  tls="$(printf '%s' "$body" | sed -n 's/.* tls=\([^ ]*\).*/\1/p' | tr -cd '0-9')"
  case "$proto" in http/2*) proto=h2;; http/1.1) proto=h1;; esac
  local problems=""
  [ "$RC" = 0 ] || problems="exit $RC: $(printf '%s' "$OUT" | tail -1)"
  [ "$RC" != 0 ] || [ "$status" = 200 ] || problems="status $status"
  if [ -z "$problems" ]; then
    [ "$(norm_dn "$dn")" = "$(norm_dn "$want_dn")" ] || problems="subject '$dn', expected '$want_dn'"
    [ -n "$problems" ] || [ "$proto" = "$want_proto" ] || problems="protocol '$proto', expected '$want_proto'"
    [ -n "$problems" ] || [ "$tls" = "$want_tls" ] || problems="TLS '$tls', expected '$want_tls'"
  fi
  if [ -n "$problems" ]; then
    FAIL=1; row "$server" "$lis" "$scen" FAIL "$problems"
  else
    row "$server" "$lis" "$scen" PASS "200, subject '$dn', $proto, TLS $tls"
  fi
}

# a rejecting scenario, repeated: $1 server $2 listener-label $3 scenario $4... run_get args
reject_case() {
  local server="$1" lis="$2" scen="$3"
  shift 3
  local sigs="$WORK/sigs" i line bad=0 key reason
  : >"$sigs"
  for i in $(seq 1 "$REPEAT"); do
    run_get "$@"
    case "$RC" in
      3)
        line="$(printf '%s\n' "$OUT" | grep 'server rejected' | head -1)"
        alert="${line#*client certificate: }"; alert="${alert%% (*}"
        if printf '%s' "$alert" | grep -Eq "^($PLAUSIBLE)\$"; then
          echo "EHttpTlsClientAuthError alert '$alert'" >>"$sigs"
        else
          echo "EHttpTlsClientAuthError implausible alert '$alert'" >>"$sigs"; bad=1
        fi ;;
      0) echo "HTTP $(printf '%s\n' "$OUT" | sed -n 's/^status: //p')" >>"$sigs"
         printf '%s\n' "$OUT" | grep -q '^status: 4' || bad=1 ;;
      124) echo "HANG (timeout ${RUN_TIMEOUT}s)" >>"$sigs"; bad=1 ;;
      *) echo "$(printf '%s\n' "$OUT" | tail -1)" >>"$sigs"; bad=1 ;;
    esac
  done
  local summary distinct
  summary="$(sort "$sigs" | uniq -c | sed 's/^ *//; s/^\([0-9]*\) /\1x /' | paste -sd';' - | sed 's/;/; /g')"
  distinct="$(sort -u "$sigs" | wc -l | tr -d ' ')"
  [ "$distinct" -le 1 ] || bad=1   # a mixed result is the race the gate looks for
  key="$server|$lis|$scen"
  if [ "$bad" = 0 ]; then
    row "$server" "$lis" "$scen" PASS "$summary"
  elif reason="$(known_reason "$key")"; then
    row "$server" "$lis" "$scen" KNOWN "$summary [$reason]"
  else
    FAIL=1; row "$server" "$lis" "$scen" FAIL "$summary"
  fi
}

C1="CN=mtls client,O=http2client mtls test"
C2="CN=mtls client two,O=http2client mtls test"
CD=/src/test/certs/mtls

for s in $SERVERS; do
  for i in 0 1 2; do
    port="$(port_of $s $i)"
    case $i in
      0) lis="h2/tls1.2"; proto=h2; tls=12 ;;
      1) lis="h2/tls1.3"; proto=h2; tls=13 ;;
      2) lis="h1/tls1.3"; proto=h1; tls=13 ;;
    esac
    url="https://localhost:$port/"
    accept_case "$s" "$lis" accepted "$C1" "$proto" "$tls" "$url" "$CD/client-chain.pem" "$CD/client.key"
    accept_case "$s" "$lis" request "$C2" "$proto" "$tls" "$url" - - \
      -e "MTLS_REQUEST_CERT=$CD/client2-chain.pem" -e "MTLS_REQUEST_KEY=$CD/client2.key"
    reject_case "$s" "$lis" none "$url" - -
    reject_case "$s" "$lis" "wrong CA" "$url" "$CD/other-client.crt" "$CD/other-client.key"
  done
done

# the results table
echo
echo "mtls-real: results (rejections repeated ${REPEAT}x)"
{
  printf 'SERVER\tLISTENER\tSCENARIO\tRESULT\tOBSERVED\n'
  cat "$ROWS"
} | column -t -s "$(printf '\t')"
echo
echo "mtls-real: images $(docker run --rm --entrypoint "" "$NGINX_IMAGE" nginx -v 2>&1 | head -1)," \
  "$(docker run --rm --entrypoint "" "$HTTPD_IMAGE" httpd -v 2>&1 | head -1 | sed 's/^Server version: //')," \
  "$(docker run --rm "$CADDY_IMAGE" caddy version 2>&1 | head -1)"

if [ "$FAIL" -ne 0 ]; then
  echo "mtls-real: FAILED"; exit 1
fi
echo "mtls-real: PASS"
