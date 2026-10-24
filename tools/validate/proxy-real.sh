#!/usr/bin/env bash
# Opt-in real-proxy gate (doc/verification/proxy-real.md): drive the real
# client through REAL proxy servers, Apache httpd (mod_proxy, mod_proxy_connect)
# and Squid, as an HTTP CONNECT proxy and as an https:// proxy, and read the
# proxies' own access logs to prove what each request did.  The existing
# proxy-live.sh gate uses Python stand-ins; this one uses the software
# deployments run.
#
#   bash tools/validate/proxy-real.sh            # or: make validate-proxy-real
#
# It runs on a Docker host.  With no argument the script copies the tree to
# the host named by PROXY_REAL_HOST (default lscoughlin@liam-rzbox.local; set
# PROXY_REAL_LOCAL=1 to use this machine's Docker instead) through
# tools/container/remote-run.sh and runs itself there with --on-host.  On the
# host everything is a container started from stock images, all with
# --network host on loopback ports PR_BASE.. (default 18400):
#
#   httpd:2.4            the Apache proxies (config bind-mounted)
#   ubuntu/squid         the Squid proxies (config bind-mounted)
#   http2client-dev      the dev image: it compiles and runs the client driver
#                        tools/validate/proxy_real_client.pas and hosts the
#                        origins (tools/validate/*.py, nghttpd)
#
# The origins are reached by the name other.example (every container maps it
# to 127.0.0.1), because the client always connects loopback names directly
# and never through a proxy.
#
# Exit status: 0 when every assertion passed or is a documented known limit,
# 1 when an assertion failed.  A scenario a proxy cannot do is SKIP with the
# reason; documented limits (doc/design/proxy.md "Known limits") are KNOWN.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
HOST="${PROXY_REAL_HOST:-lscoughlin@liam-rzbox.local}"
# the remote tree remote-run.sh uses for this checkout (same derivation)
RDIR="${HTTP2_REMOTE_DIR:-http2client-ci/run-$(printf '%s' "$ROOT" | cksum | cut -d' ' -f1)}"
export HTTP2_REMOTE_DIR="$RDIR"
IMG="${HTTP2_IMAGE:-http2client-dev}"
HTTPD_IMG="${PR_HTTPD_IMAGE:-httpd:2.4}"
SQUID_IMG="${PR_SQUID_IMAGE:-ubuntu/squid:latest}"

# ---------------------------------------------------------------- driver mode
if [ "${1:-}" != "--on-host" ] && [ "${1:-}" != "--build" ]; then
  if [ "${PROXY_REAL_LOCAL:-0}" = 1 ]; then
    exec bash "$HERE/proxy-real.sh" --on-host
  fi
  # remote-run.sh copies the tree to the host as a side effect of running a
  # command in the dev container; the gate itself then runs on the host
  "$ROOT/tools/container/remote-run.sh" "$HOST" true || exit 2
  exec ssh -o BatchMode=yes "$HOST" "cd $RDIR/src && bash tools/validate/proxy-real.sh --on-host"
fi

# ----------------------------------------------------- build (in the dev image)
if [ "$1" = "--build" ]; then
  M="$ROOT/third_party/mORMot2/src"
  mkdir -p "$ROOT/bin/proxy-real"
  exec fpc -O2 -vewn -Mdelphi -Fu"$ROOT/src" -Fu"$M/core" -Fu"$M/lib" -Fu"$M/net" \
    -Fu"$M/crypt" -FE"$ROOT/bin/proxy-real" -FU"$ROOT/bin/proxy-real" \
    "$ROOT/tools/validate/proxy_real_client.pas"
fi

# ------------------------------------------------------------------ on the host
cd "$ROOT" || exit 2
BASE="${PR_BASE:-18400}"
WORK="$ROOT/bin/proxy-real-work"
CERTS="$ROOT/test/certs"
MT="$CERTS/mtls"
CA_C=/src/bin/proxy-real-work/ca.pem   # the same files as the client container sees them
MTC=/src/test/certs/mtls
export LC_ALL=C
rm -rf "$WORK"; mkdir -p "$WORK/apache" "$WORK/squid"

# origins
O_H2=$((BASE + 1)); O_H1=$((BASE + 2)); O_PL=$((BASE + 3)); O_WS=$((BASE + 4))
O_WSS=$((BASE + 5)); O_SSE=$((BASE + 6)); O_MT=$((BASE + 7)); O_MT2=$((BASE + 8))
O_DENY=$((BASE + 9)); O_DOWN=$((BASE + 10))
# unused companions of proxy_servers.py (its own proxies)
O_JUNK=$((BASE + 11))
# proxies: apache open/auth/tls, squid open/auth/tls
A_OPEN=$((BASE + 20)); A_AUTH=$((BASE + 21)); A_TLS=$((BASE + 22))
S_OPEN=$((BASE + 30)); S_AUTH=$((BASE + 31)); S_TLS=$((BASE + 32))
ALLOWED="$O_H2 $O_H1 $O_PL $O_WS $O_WSS $O_SSE $O_MT $O_MT2 $O_DOWN"   # O_DENY is not

TOOLS=pr-tools; APACHE=pr-apache; SQUID=pr-squid
RESULTS="$WORK/results.tsv"; : > "$RESULTS"
FAILS=0

cleanup() {
  docker rm -f $TOOLS $APACHE $SQUID >/dev/null 2>&1
}
trap cleanup EXIT INT TERM
cleanup

command -v docker >/dev/null || { echo "proxy-real: docker not found" >&2; exit 2; }
docker image inspect "$IMG" >/dev/null 2>&1 || { echo "proxy-real: image $IMG missing (tools/container/remote-run.sh builds it)" >&2; exit 2; }
for i in "$HTTPD_IMG" "$SQUID_IMG"; do
  docker image inspect "$i" >/dev/null 2>&1 || docker pull -q "$i" >/dev/null || { echo "proxy-real: cannot pull $i" >&2; exit 2; }
done

HOSTS="--add-host other.example:127.0.0.1"
ME="$(id -u):$(id -g)"
docker run -d --rm --name $TOOLS --network host $HOSTS --user "$ME" -e HOME=/tmp \
  -v "$ROOT:/src" -w /src "$IMG" sleep 3600 >/dev/null || exit 2
tx() { docker exec -w /src $TOOLS "$@"; }

echo "proxy-real: building the client driver"
tx bash tools/validate/proxy-real.sh --build >"$WORK/build.log" 2>&1 \
  || { tail -20 "$WORK/build.log"; echo "proxy-real: build failed" >&2; exit 2; }
CLIENT=bin/proxy-real/proxy_real_client

# ----------------------------------------------------------------- the origins
CA_BUNDLE="$WORK/ca.pem"     # trusts the origin (other.example) and the https proxies (localhost)
cat "$CERTS/other.crt" "$CERTS/localhost.crt" > "$CA_BUNDLE"
mkdir -p "$WORK/htdocs"; echo origin-h2 > "$WORK/htdocs/index.html"
WORKC=/src/bin/proxy-real-work

bg() { # name command...   (a background process in the tools container)
  local n="$1"; shift
  docker exec -d -w /src $TOOLS sh -c "$* >$WORKC/$n.out 2>$WORKC/$n.err"
}
waitport() { # port label
  for _ in $(seq 1 100); do
    (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null && return 0
    sleep 0.1
  done
  echo "proxy-real: $2 did not listen on $1" >&2
  return 1
}

bg h2 nghttpd -d $WORKC/htdocs $O_H2 test/certs/other.key test/certs/other.crt
bg mt2 nghttpd --verify-client -d $WORKC/htdocs $O_MT2 test/certs/other.key test/certs/other.crt
bg h1 python3 tools/validate/proxy_servers.py --log $WORKC/origin-h1pl.log --certs test/certs \
  --origin-tls-port $O_H1 --origin-plain-port $O_PL --http-proxy-port $((O_JUNK)) \
  --https-proxy-port $((O_JUNK + 1)) --socks-port $((O_JUNK + 2))
bg ws python3 tools/validate/ws_servers.py --log $WORKC/origin-ws.log --plain-port $O_WS \
  --tls-port $O_WSS --cert test/certs/other.crt --key test/certs/other.key
bg sse python3 tools/validate/sse_server.py --port $O_SSE
bg mt python3 -u tools/validate/mtls_server.py --port $O_MT --tls 1.3 --log $WORKC/origin-mt.log \
  --cert test/certs/other.crt --key test/certs/other.key --ca test/certs/mtls/ca.crt
for p in $O_H2 $O_MT2 $O_H1 $O_PL $O_WS $O_WSS $O_SSE $O_MT; do waitport $p origin || exit 2; done

# --------------------------------------------------------------- proxy configs
USERPASS="$(tx openssl passwd -apr1 pw)"
printf 'bob:%s\n' "$USERPASS" > "$WORK/htpasswd"
chmod 644 "$WORK/htpasswd"
ALLOW_LIST="$ALLOWED"

# Apache: three listeners (open, Basic auth, TLS with a required client
# certificate); CONNECT is allowed to the origin ports only
{
  cat <<EOF
ServerRoot "/usr/local/apache2"
ServerName localhost
PidFile /tmp/httpd.pid
User daemon
Group daemon
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule authn_file_module modules/mod_authn_file.so
LoadModule authn_core_module modules/mod_authn_core.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule authz_user_module modules/mod_authz_user.so
LoadModule auth_basic_module modules/mod_auth_basic.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_connect_module modules/mod_proxy_connect.so
LoadModule ssl_module modules/mod_ssl.so
LoadModule socache_shmcb_module modules/mod_socache_shmcb.so
ErrorLog logs/error.log
LogLevel info
LogFormat "%u \"%r\" %>s cert=%{SSL_CLIENT_S_DN}x" pr
CustomLog logs/access.log pr
SSLSessionCache shmcb:/tmp/ssl_scache(512000)
ProxyRequests On
ProxyVia Off
Listen 127.0.0.1:$A_OPEN
Listen 127.0.0.1:$A_AUTH
Listen 127.0.0.1:$A_TLS
<VirtualHost 127.0.0.1:$A_OPEN>
  AllowCONNECT $ALLOW_LIST
</VirtualHost>
<VirtualHost 127.0.0.1:$A_AUTH>
  AllowCONNECT $ALLOW_LIST
  <Proxy "*">
    AuthType Basic
    AuthName "proxy"
    AuthBasicProvider file
    AuthUserFile /conf/htpasswd
    Require valid-user
  </Proxy>
</VirtualHost>
<VirtualHost 127.0.0.1:$A_TLS>
  AllowCONNECT $ALLOW_LIST
  SSLEngine on
  SSLCertificateFile /certs/localhost.crt
  SSLCertificateKeyFile /certs/localhost.key
  SSLCACertificateFile /certs/mtls/ca.crt
  SSLVerifyClient require
  SSLVerifyDepth 3
</VirtualHost>
EOF
} > "$WORK/apache/httpd.conf"

# Squid: the same three listeners.  Basic auth is by port; CONNECT only to the
# origin ports; the https_port verifies client certificates against the
# fixture CA.  The Ubuntu build uses GnuTLS, where tls-clientca= (the option that
# makes Squid request and verify a client certificate) fails at startup with
# 'Unable to read client CAs', so the https_port accepts any client
{
  cat <<EOF
http_port 127.0.0.1:$S_OPEN
http_port 127.0.0.1:$S_AUTH
https_port 127.0.0.1:$S_TLS tls-cert=/certs/localhost.crt tls-key=/certs/localhost.key tls-cafile=/certs/mtls/ca.crt
auth_param basic program /usr/lib/squid/basic_ncsa_auth /conf/htpasswd
auth_param basic realm proxy
acl authed proxy_auth REQUIRED
acl authport localport $S_AUTH
acl connect_ok port $ALLOW_LIST
acl CONNECT method CONNECT
http_access deny CONNECT !connect_ok
http_access allow authport authed
http_access deny authport
http_access allow localhost
http_access deny all
logformat pr %un "%rm %ru HTTP/%rv" %>Hs
access_log stdio:/var/log/squid/access.log pr
cache deny all
pid_filename /tmp/squid.pid
forwarded_for delete
via off
EOF
} > "$WORK/squid/squid.conf"

MOUNTS=(-v "$WORK/htpasswd:/conf/htpasswd:ro" -v "$CERTS:/certs:ro")
docker run -d --name $APACHE --network host $HOSTS "${MOUNTS[@]}" \
  -v "$WORK/apache/httpd.conf:/usr/local/apache2/conf/httpd.conf:ro" "$HTTPD_IMG" >/dev/null || exit 2
docker run -d --name $SQUID --network host $HOSTS "${MOUNTS[@]}" \
  -v "$WORK/squid/squid.conf:/etc/squid/squid.conf:ro" "$SQUID_IMG" >/dev/null || exit 2
for p in $A_OPEN $A_AUTH $A_TLS $S_OPEN $S_AUTH $S_TLS; do
  waitport $p proxy || { docker logs $APACHE 2>&1 | tail -20; docker logs $SQUID 2>&1 | tail -20; exit 2; }
done
echo "proxy-real: $(docker exec $APACHE httpd -v | head -1 | sed 's/Server version: //'), $(docker exec $SQUID squid -v 2>/dev/null | head -1)"
docker exec $SQUID sh -c 'squid -v 2>/dev/null | grep -o "with-gnutls\|with-openssl" | sort -u | tr "\n" " "' | sed 's/^/proxy-real: squid TLS library: /'; echo

# ------------------------------------------------------------------- helpers
plogfile() { # proxy -> the access log, in its container
  if [ "$1" = apache ]; then echo "$APACHE /usr/local/apache2/logs/access.log"
  else echo "$SQUID /var/log/squid/access.log"; fi
}
plog_all() { local c f; read -r c f <<<"$(plogfile "$1")"; docker exec "$c" cat "$f" 2>/dev/null; }
mark() { plog_all "$1" | wc -l | tr -d ' '; }                 # lines so far
since() { plog_all "$1" | tail -n +$(($2 + 1)); }               # lines after a mark
omark() { wc -l < "$WORK/$1" 2>/dev/null | tr -d ' ' || echo 0; }
osince() { tail -n +$(($2 + 1)) "$WORK/$1" 2>/dev/null; }

OUT=""; RC=0; SECS=0
cl() { # client args...  -> OUT (stdout+stderr), RC, SECS
  local t0=$(date +%s.%N)
  OUT="$(tx timeout 45 $CLIENT "$@" 2>&1)"; RC=$?
  SECS="$(awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN{printf "%.1f", b-a}')"
}
last() { printf '%s\n' "$OUT" | grep '^RESULT' | tail -1; }
brief() { # the one-line summary recorded in the table
  local r; r="$(last)"
  [ -z "$r" ] && r="rc=$RC no RESULT: $(printf '%s' "$OUT" | tail -1)"
  printf '%s' "$r" | cut -c1-150
}

# row proxy scenario STATUS detail ; STATUS: PASS FAIL SKIP KNOWN INFO
row() {
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$RESULTS"
  [ "$3" = FAIL ] && FAILS=$((FAILS + 1))
  printf 'proxy-real: %-6s %-5s %-34s %s\n' "$3" "$1" "$2" "$4"
}
# verdict proxy scenario condition(0=true) detail-on-pass detail-on-fail
verdict() {
  if [ "$3" = 0 ]; then row "$1" "$2" PASS "$4"; else row "$1" "$2" FAIL "$5"; fi
}
has() { printf '%s\n' "$1" | grep -qE -- "$2"; }      # has TEXT REGEX
ok() { has "$OUT" '^RESULT ok'; }
errmatch() { has "$OUT" "^RESULT error .*$1"; }
proto() { printf '%s\n' "$OUT" | sed -n 's/^pool .*proto=//p' | tail -1; }
conns() { printf '%s\n' "$OUT" | sed -n 's/^pool conns=\([0-9]*\).*/\1/p' | tail -1; }
count() { printf '%s\n' "$1" | grep -cE -- "$2"; }      # count TEXT REGEX

# ------------------------------------------------------------------ scenarios
run_proxy() {
  local P="$1" OPEN="$2" AUTH="$3" TLS="$4"
  local PX="http://localhost:$OPEN" m om

  # 1. https GET through the CONNECT tunnel: HTTP/2 (ALPN h2), then HTTP/1.1
  m=$(mark $P); cl get "https://other.example:$O_H2/" proxy=$PX ca=$CA_C
  L="$(since $P $m)"
  verdict $P "CONNECT https, origin h2" "$({ ok && [ "$(proto)" = h2 ] && has "$L" "CONNECT other.example:$O_H2 "; } && echo 0 || echo 1)" \
    "$(last); proto=$(proto); log: $(printf '%s' "$L" | head -1)" "$(brief); proto=$(proto); log: $(printf '%s' "$L" | head -1)"
  m=$(mark $P); om=$(omark origin-h1pl.log)
  cl get "https://other.example:$O_H1/" proxy=$PX ca=$CA_C
  L="$(since $P $m)"
  verdict $P "CONNECT https, origin http/1.1" "$({ ok && [ "$(proto)" = "http/1.1+tls" ] && has "$L" "CONNECT other.example:$O_H1 " && osince origin-h1pl.log $om | grep -q 'origin tls host=other.example'; } && echo 0 || echo 1)" \
    "$(last); proto=$(proto); origin saw host=other.example" "$(brief); proto=$(proto); log: $(printf '%s' "$L" | head -1)"

  # 2. plain http:// origin.  The client tunnels (CONNECT), it does not forward
  #    in absolute-URI form (doc/design/proxy.md "Known limits")
  m=$(mark $P); cl get "http://other.example:$O_PL/" proxy=$PX
  L="$(since $P $m)"
  verdict $P "http:// via CONNECT (no abs-URI)" "$({ ok && has "$L" "CONNECT other.example:$O_PL "; } && echo 0 || echo 1)" \
    "$(last); proxy saw: $(printf '%s' "$L" | head -1) (KNOWN: CONNECT only, no forwarding mode)" "$(brief); log: $(printf '%s' "$L" | head -1)"

  # 3. keep-alive: two requests, one tunnel
  m=$(mark $P); cl get "https://other.example:$O_H2/" proxy=$PX ca=$CA_C repeat=2
  L="$(since $P $m)"
  verdict $P "keep-alive h2: 2 requests" "$({ ok && [ "$(conns)" = 1 ] && [ "$(count "$L" "CONNECT other.example:$O_H2 ")" = 1 ]; } && echo 0 || echo 1)" \
    "pool conns=$(conns), CONNECT lines=$(count "$L" "CONNECT other.example:$O_H2 ")" "$(brief); pool conns=$(conns), CONNECT lines=$(count "$L" "CONNECT other.example:$O_H2 ")"
  m=$(mark $P); cl get "https://other.example:$O_H1/" proxy=$PX ca=$CA_C repeat=2
  L="$(since $P $m)"
  verdict $P "keep-alive http/1.1: 2 requests" "$({ ok && [ "$(conns)" = 1 ] && [ "$(count "$L" "CONNECT other.example:$O_H1 ")" = 1 ]; } && echo 0 || echo 1)" \
    "pool conns=$(conns), CONNECT lines=$(count "$L" "CONNECT other.example:$O_H1 ")" "$(brief); pool conns=$(conns), CONNECT lines=$(count "$L" "CONNECT other.example:$O_H1 ")"

  # 4. proxy Basic auth
  local AX="localhost:$AUTH"
  m=$(mark $P); cl get "https://other.example:$O_H2/" proxy=http://$AX ca=$CA_C
  L="$(since $P $m)"
  verdict $P "auth: no credentials" "$({ ! ok && errmatch 'EHttpConnectionError.*407' && has "$L" ' 407'; } && echo 0 || echo 1)" \
    "$(brief) (${SECS}s); proxy log: $(printf '%s' "$L" | head -1)" "$(brief); log: $(printf '%s' "$L" | head -1)"
  m=$(mark $P); cl get "https://other.example:$O_H2/" proxy=http://bob:wrongpw@$AX ca=$CA_C
  L="$(since $P $m)"
  verdict $P "auth: wrong credentials" "$({ ! ok && errmatch 'EHttpConnectionError.*407' && has "$L" ' 407'; } && echo 0 || echo 1)" \
    "$(brief) (${SECS}s); proxy log: $(printf '%s' "$L" | head -1)" "$(brief); log: $(printf '%s' "$L" | head -1)"
  m=$(mark $P); cl get "https://other.example:$O_H2/" proxy=http://bob:pw@$AX ca=$CA_C
  L="$(since $P $m)"
  verdict $P "auth: right credentials" "$({ ok && has "$L" "^bob \"CONNECT other.example:$O_H2 .* 200"; } && echo 0 || echo 1)" \
    "$(last); proxy log: $(printf '%s' "$L" | head -1)" "$(brief); log: $(printf '%s' "$L" | head -1)"
  m=$(mark $P); cl ws "ws://other.example:$O_WS/echo" proxy=http://bob:pw@$AX
  verdict $P "auth: ws with credentials" "$({ ok; } && echo 0 || echo 1)" "$(last); $(printf '%s' "$OUT" | grep '^ws ')" "$(brief)"
  # no credential in any cleartext log: neither the password nor the base64 of bob:pw / bob:wrongpw
  local ALL; ALL="$(plog_all $P; docker logs $P 2>&1 | head -200; cat "$WORK"/origin-*.log)"
  verdict $P "auth: no secret in logs" "$({ ! has "$ALL" 'wrongpw|Ym9iOnB3|Ym9iOndyb25ncHc' ; } && echo 0 || echo 1)" \
    "no password or Basic token in the proxy log, container log or origin logs" "a credential appears in a log"

  # 5. ACL denial: CONNECT to a port the proxy does not allow
  m=$(mark $P); cl get "https://other.example:$O_DENY/" proxy=$PX ca=$CA_C
  L="$(since $P $m)"
  verdict $P "ACL denial: CONNECT to refused port" "$({ ! ok && errmatch 'EHttpConnectionError.*403' && [ "${SECS%.*}" -lt 5 ]; } && echo 0 || echo 1)" \
    "$(brief) (${SECS}s); proxy log: $(printf '%s' "$L" | head -1)" "$(brief) (${SECS}s); log: $(printf '%s' "$L" | head -1)"
  # allowed port, nothing listening
  m=$(mark $P); cl get "https://other.example:$O_DOWN/" proxy=$PX ca=$CA_C
  L="$(since $P $m)"
  verdict $P "origin down behind the tunnel" "$({ ! ok && [ "${SECS%.*}" -lt 10 ]; } && echo 0 || echo 1)" \
    "$(brief) (${SECS}s); proxy log: $(printf '%s' "$L" | head -1)" "$(brief) (${SECS}s)"

  # 6. WebSocket and SSE through the tunnel
  m=$(mark $P); om=$(omark origin-ws.log); cl ws "ws://other.example:$O_WS/echo" proxy=$PX
  L="$(since $P $m)"
  verdict $P "WebSocket ws://" "$({ ok && has "$OUT" 'ws text=hello-through-proxy' && has "$L" "CONNECT other.example:$O_WS " && osince origin-ws.log $om | grep -q 'handshake path=/echo'; } && echo 0 || echo 1)" \
    "echo received; CONNECT other.example:$O_WS; origin logged the handshake" "$(brief); log: $(printf '%s' "$L" | head -1)"
  m=$(mark $P); cl ws "wss://other.example:$O_WSS/echo" proxy=$PX ca=$CA_C
  L="$(since $P $m)"
  verdict $P "WebSocket wss://" "$({ ok && has "$OUT" 'ws text=hello-through-proxy' && has "$L" "CONNECT other.example:$O_WSS "; } && echo 0 || echo 1)" \
    "echo received over TLS in the tunnel; CONNECT other.example:$O_WSS" "$(brief); log: $(printf '%s' "$L" | head -1)"
  m=$(mark $P); cl sse "http://other.example:$O_SSE/events" proxy=$PX events=3
  L="$(since $P $m)"
  verdict $P "SSE http://" "$({ ok && [ "$(count "$OUT" '^sse ')" -ge 3 ] && has "$L" "CONNECT other.example:$O_SSE "; } && echo 0 || echo 1)" \
    "$(count "$OUT" '^sse ') events; CONNECT other.example:$O_SSE" "$(brief); events=$(count "$OUT" '^sse '); log: $(printf '%s' "$L" | head -1)"

  # 7. proxy selection from the environment (lookup supplied by the program)
  m=$(mark $P); cl get "https://other.example:$O_H2/" env=https_proxy=$PX ca=$CA_C
  L="$(since $P $m)"
  verdict $P "env https_proxy" "$({ ok && has "$L" "CONNECT other.example:$O_H2 "; } && echo 0 || echo 1)" \
    "tunnel through the proxy named by https_proxy" "$(brief); log: $(printf '%s' "$L" | head -1)"
  m=$(mark $P); cl get "http://other.example:$O_PL/" env=http_proxy=$PX
  L="$(since $P $m)"
  verdict $P "env http_proxy" "$({ ok && has "$L" "CONNECT other.example:$O_PL "; } && echo 0 || echo 1)" \
    "tunnel through the proxy named by http_proxy" "$(brief); log: $(printf '%s' "$L" | head -1)"
  m=$(mark $P); om=$(omark origin-h1pl.log)
  cl get "http://other.example:$O_PL/" env=http_proxy=$PX env=no_proxy=other.example
  L="$(since $P $m)"
  verdict $P "env no_proxy bypass" "$({ ok && [ -z "$L" ] && osince origin-h1pl.log $om | grep -q 'origin plain'; } && echo 0 || echo 1)" \
    "direct: no proxy log line, origin reached" "$(brief); proxy log: $(printf '%s' "$L" | head -1)"
  m=$(mark $P)
  cl get "http://other.example:$O_PL/" env=HTTP_PROXY=$PX
  L="$(since $P $m)"
  verdict $P "env HTTP_PROXY (upper) ignored" "$({ ok && [ -z "$L" ]; } && echo 0 || echo 1)" \
    "direct: uppercase HTTP_PROXY is not honoured (httpoxy)" "$(brief); proxy log: $(printf '%s' "$L" | head -1)"
  m=$(mark $P)
  cl get "https://other.example:$O_H2/" proxy=$PX noproxy=.example ca=$CA_C
  L="$(since $P $m)"
  verdict $P "WithNoProxy bypass" "$({ ok && [ -z "$L" ]; } && echo 0 || echo 1)" \
    "direct: no proxy log line" "$(brief); proxy log: $(printf '%s' "$L" | head -1)"

  # 8. mutual TLS to the origin through the tunnel (HTTP CONNECT proxy: no
  #    certificate can reach the proxy)
  local ID="cert=$MTC/client-chain.pem key=$MTC/client.key"
  m=$(mark $P); om=$(omark origin-mt.log)
  cl get "https://other.example:$O_MT/" proxy=$PX ca=$CA_C $ID
  L="$(since $P $m)"; OL="$(osince origin-mt.log $om)"
  verdict $P "mTLS origin via tunnel (h1)" "$({ ok && has "$OL" '^accept .*commonName=mtls client$' && has "$L" "CONNECT other.example:$O_MT " && ! has "$L" 'mtls client'; } && echo 0 || echo 1)" \
    "origin accepted subject 'mtls client'; proxy log has no certificate" "$(brief); origin: $(printf '%s' "$OL" | head -2 | tr '\n' ' ')"
  m=$(mark $P); om=$(omark origin-mt.log)
  cl get "https://other.example:$O_MT/" proxy=$PX ca=$CA_C
  OL="$(osince origin-mt.log $om)"
  verdict $P "mTLS origin via tunnel, no cert" "$({ ! ok && has "$OL" '^reject|accept nocert|alert'; } && echo 0 || echo 1)" \
    "$(brief); origin: $(printf '%s' "$OL" | head -1)" "$(brief); origin: $(printf '%s' "$OL" | head -1)"
  cl get "https://other.example:$O_MT2/" proxy=$PX ca=$CA_C $ID
  verdict $P "mTLS origin via tunnel (h2)" "$({ ok && [ "$(proto)" = h2 ]; } && echo 0 || echo 1)" \
    "$(last); proto=$(proto) (nghttpd --verify-client)" "$(brief); proto=$(proto)"
  cl get "https://other.example:$O_MT2/" proxy=$PX ca=$CA_C
  verdict $P "mTLS origin h2, no cert" "$({ ! ok; } && echo 0 || echo 1)" "$(brief)" "unexpectedly succeeded: $(brief)"
  om=$(omark origin-mt.log)
  cl sse "https://other.example:$O_MT/events" proxy=$PX ca=$CA_C $ID events=1
  verdict $P "mTLS SSE via tunnel" "$({ ok && has "$OUT" '^sse '; } && echo 0 || echo 1)" "$(last); $(printf '%s' "$OUT" | grep -m1 '^sse ')" "$(brief)"
  cl ws "wss://other.example:$O_MT/ws" proxy=$PX ca=$CA_C $ID
  verdict $P "mTLS wss via tunnel" "$({ ok && has "$OUT" '^ws text=hello'; } && echo 0 || echo 1)" "$(last); $(printf '%s' "$OUT" | grep -m1 '^ws ')" "$(brief)"

  # 9. https:// proxy (TLS to the proxy), requiring a client certificate
  local PTLS="https://localhost:$TLS" PID="pcert=$MTC/client2-chain.pem pkey=$MTC/client2.key"
  m=$(mark $P)
  cl get "https://other.example:$O_H2/" proxy=$PTLS ca=$CA_C $PID
  L="$(since $P $m)"
  verdict $P "https proxy: h2 origin" "$({ ok && [ "$(proto)" = h2 ] && has "$L" "CONNECT other.example:$O_H2 "; } && echo 0 || echo 1)" \
    "$(last); proto=$(proto); log: $(printf '%s' "$L" | head -1)" "$(brief); log: $(printf '%s' "$L" | head -1)"
  m=$(mark $P); om=$(omark origin-mt.log)
  cl get "https://other.example:$O_MT/" proxy=$PTLS ca=$CA_C $PID $ID
  L="$(since $P $m)"; OL="$(osince origin-mt.log $om)"
  verdict $P "https proxy + origin mTLS (two ids)" "$({ ok && has "$OL" '^accept .*commonName=mtls client$' && ! has "$OL" 'client two' && ! has "$L" 'commonName=mtls client$'; } && echo 0 || echo 1)" \
    "origin saw 'mtls client' only; proxy log: $(printf '%s' "$L" | head -1 | cut -c1-110)" "$(brief); origin: $(printf '%s' "$OL" | head -1); proxy log: $(printf '%s' "$L" | head -1)"
  if [ $P = squid ]; then
    row $P "https proxy saw the proxy identity" SKIP "the Ubuntu Squid build uses GnuTLS and has no %ssl::>cert_subject log code; acceptance is shown by the wrong-CA and no-cert rows"
  else
    verdict $P "https proxy saw the proxy identity" "$({ has "$L" 'client two'; } && echo 0 || echo 1)" \
      "proxy log subject: $(printf '%s' "$L" | head -1 | grep -o 'cert=.*')" "proxy log has no 'client two' subject: $(printf '%s' "$L" | head -1)"
  fi
  m=$(mark $P)
  cl get "https://other.example:$O_H2/" proxy=$PTLS ca=$CA_C
  L="$(since $P $m)"
  if ok; then
    if [ $P = squid ]; then row $P "https proxy: no client cert" SKIP "Squid cannot require one here (GnuTLS build: tls-clientca= aborts startup with 'Unable to read client CAs'); observed: $(last)"
    else row $P "https proxy: no client cert" FAIL "proxy accepted a client with no certificate: $(last)"; fi
  else
    row $P "https proxy: no client cert" PASS "$(brief) (${SECS}s)"
  fi
  cl get "https://other.example:$O_H2/" proxy=$PTLS ca=$CA_C pcert=$MTC/other-client.crt pkey=$MTC/other-client.key
  if [ $P = squid ]; then
    row $P "https proxy: cert from wrong CA" SKIP "Squid cannot verify client certificates here (see above); observed: $(last)"
  else
    verdict $P "https proxy: cert from wrong CA" "$({ ! ok; } && echo 0 || echo 1)" "$(brief) (${SECS}s)" "accepted: $(brief)"
  fi
  m=$(mark $P)
  cl get "https://other.example:$O_H2/" proxy=$PTLS ca=$CA_C pcert=$MTC/client2-chain.pem pkey=$MTC/client2.key repeat=2
  L="$(since $P $m)"
  verdict $P "https proxy keep-alive: 2 requests" "$({ ok && [ "$(count "$L" "CONNECT other.example:$O_H2 ")" = 1 ]; } && echo 0 || echo 1)" \
    "pool conns=$(conns); CONNECT lines=$(count "$L" "CONNECT other.example:$O_H2 ")" "$(brief); CONNECT lines=$(count "$L" "CONNECT other.example:$O_H2 ")"
  cl get "https://other.example:$O_DENY/" proxy=$PTLS ca=$CA_C $PID
  verdict $P "https proxy: ACL denial" "$({ ! ok && errmatch '403' && [ "${SECS%.*}" -lt 5 ]; } && echo 0 || echo 1)" \
    "$(brief) (${SECS}s)" "$(brief) (${SECS}s)"
  cl ws "wss://other.example:$O_WSS/echo" proxy=$PTLS ca=$CA_C $PID
  verdict $P "https proxy: wss" "$({ ok && has "$OUT" 'ws text=hello-through-proxy'; } && echo 0 || echo 1)" "$(last)" "$(brief)"
}

run_proxy apache $A_OPEN $A_AUTH $A_TLS
run_proxy squid  $S_OPEN $S_AUTH $S_TLS

# ----------------------------------------------------------------- the table
echo
echo "proxy-real: results"
printf '%-7s %-40s %-6s %s\n' PROXY SCENARIO RESULT DETAIL
while IFS=$'\t' read -r p s st d; do
  printf '%-7s %-40s %-6s %s\n' "$p" "$s" "$st" "$d"
done < "$RESULTS"
echo
echo "proxy-real: $(grep -c "	PASS	" "$RESULTS") pass, $FAILS fail, $(grep -c "	KNOWN	" "$RESULTS") known, $(grep -c "	SKIP	" "$RESULTS") skip"
if [ "$FAILS" -ne 0 ]; then
  echo "proxy-real: FAILED"
  exit 1
fi
echo "proxy-real: PASS"
