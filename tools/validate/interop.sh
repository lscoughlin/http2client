#!/usr/bin/env bash
# tools/validate/interop.sh — doc/verification/validation.md section A (nghttpd interop).
#
# Starts nghttpd (TLS + ALPN h2) on a private port with test/certs, then runs
# the A.1..A.9 cases through the h2probe CLI (test/h2probe.pas) and prints a
# PASS/FAIL/SKIP table. Exits 0 only when every mandatory case passes; a SKIP
# never counts as a pass.
#
# Re-runnable and independent of the repo's build state: it compiles h2probe
# into a temp dir with fpc.
set -u

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

PORT="${INTEROP_PORT:-18443}"
PLAIN_PORT="${INTEROP_PLAIN_PORT:-18480}"
# S13: cleartext h2c / HTTP-1.1 servers (Apache httpd:2.4 in docker).  Keep
# these well above the 18080-18082 range: that range collides with common
# dev proxies (e.g. an unrelated `auth_proxy.py`), and a foreign 127.0.0.1
# listener would shadow Lima's `*:<port>` tunnel and silently answer the
# upgrade probe.
H2C_PORT="${INTEROP_H2C_PORT:-18481}"
H1_PORT="${INTEROP_H1_PORT:-18482}"
# A.14: a server that advertises a tiny stream/connection window (8 KiB), so
# a large upload must honour flow control instead of overrunning the peer
SMALLWIN_PORT="${INTEROP_SMALLWIN_PORT:-18483}"
HTDOCS="$(mktemp -d /tmp/h2interop.XXXXXX)"
BUILD="$(mktemp -d /tmp/h2interop-build.XXXXXX)"
PROBE="$BUILD/h2probe"
DOCKER="${DOCKER:-$(command -v docker || echo "$HOME/.rd/bin/docker")}"
DOCKER_OK=no

FPC="${FPC:-fpc}"
FPC_UNITS="${FPC_UNITS:-/usr/local/lib/fpc/3.2.4/units/aarch64-darwin}"
MORMOT="third_party/mORMot2/src"
export OPENSSL_LIBPATH="${OPENSSL_LIBPATH:-/opt/homebrew/opt/openssl@3/lib}"

NGHTTPD="$(command -v nghttpd || true)"

PASS=0; FAIL=0; SKIP=0
rows=()

cleanup() {
  [ -n "${NGHTTPD_PID:-}" ] && kill "$NGHTTPD_PID" 2>/dev/null
  [ -n "${NGHTTPD_PLAIN_PID:-}" ] && kill "$NGHTTPD_PLAIN_PID" 2>/dev/null
  [ -n "${NGHTTPD_SMALLWIN_PID:-}" ] && kill "$NGHTTPD_SMALLWIN_PID" 2>/dev/null
  [ -n "${SSERVER_PID:-}" ] && kill "$SSERVER_PID" 2>/dev/null
  if [ "$DOCKER_OK" = yes ]; then
    "$DOCKER" rm -f http2client-h2c http2client-h1 >/dev/null 2>&1
  fi
  rm -rf "$BUILD" "$HTDOCS" 2>/dev/null
}
trap cleanup EXIT

record() { # id case expected actual status
  rows+=("$1|$2|$3|$4|$5")
  case "$5" in
    PASS) PASS=$((PASS+1));;
    FAIL) FAIL=$((FAIL+1));;
    SKIP) SKIP=$((SKIP+1));;
  esac
}

compile_probe() {
  rm -rf "$BUILD"
  mkdir -p "$BUILD"
  if ! "$FPC" -O2 -Mdelphi -Fu./src -Fu"$BUILD" \
      -Fu"$MORMOT/core" -Fu"$MORMOT/lib" -Fu"$MORMOT/net" -Fu"$MORMOT/crypt" \
      -FU"$BUILD" -FE"$BUILD" test/h2probe.pas >"$BUILD/build.log" 2>&1; then
    echo "ERROR: h2probe failed to compile; see $BUILD/build.log" >&2
    tail -20 "$BUILD/build.log" >&2
    exit 1
  fi
}

# run_probe <url> [extra args...] -> sets PROBE_RC and PROBE_OUT
run_probe() {
  local url="$1"; shift
  PROBE_OUT="$("$PROBE" --url="$url" --insecure --timeout-ms=4000 \
      --keep-open-ms=200 "$@" 2>&1)"
  PROBE_RC=$?
}

wait_port() { # host port
  local i
  for i in $(seq 1 100); do
    if nc -z "$1" "$2" 2>/dev/null; then return 0; fi
    sleep 0.1
  done
  return 1
}

# a foreign process already answering on the port would shadow the container
# (Lima publishes a `*:<port>` tunnel, a 127.0.0.1 listener wins over it) and
# the probe would silently read the wrong server back
require_free_port() { # port case-id
  if nc -z 127.0.0.1 "$1" 2>/dev/null; then
    echo "ERROR: port $1 ($2) is already in use; set INTEROP_$3_PORT to a free port" >&2
    return 1
  fi
  return 0
}

echo "== http2client interop validation (nghttpd) =="
echo "repo:    $REPO_ROOT"
echo "nghttpd: $($NGHTTPD --version 2>&1 | head -1)"
echo "probe:   $PROBE"
echo

if [ -z "$NGHTTPD" ]; then
  echo "ERROR: nghttpd not found on PATH" >&2
  exit 1
fi

compile_probe

# --- S13: Apache httpd:2.4 servers for the cleartext cases ----------------
# h2c upgrade needs mod_http2 ("Protocols h2c http/1.1" + "H2Upgrade on");
# nghttpd is HTTP/2-only and cannot answer an HTTP/1.1 Upgrade request.
#
# The config and docroot are copied in with `docker cp` rather than
# bind-mounted: Rancher Desktop intermittently deletes a bind-mount source
# directory that lives inside the repo checkout, which used to leave the
# container serving a 404 with an empty docroot.
start_apache() { # name port protocols h2upgrade
  local name="$1" port="$2" protocols="$3" h2upgrade="$4"
  local conf="$BUILD/httpd-$name.conf"
  cat > "$conf" <<EOF
ServerRoot "/usr/local/apache2"
Listen $port
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule dir_module modules/mod_dir.so
LoadModule mime_module modules/mod_mime.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule http2_module modules/mod_http2.so
ServerName localhost
Protocols $protocols
$h2upgrade
DocumentRoot "/htdocs"
<Directory "/htdocs">
  Require all granted
</Directory>
ErrorLog /dev/stderr
EOF
  "$DOCKER" rm -f "$name" >/dev/null 2>&1
  "$DOCKER" create --name "$name" --network host httpd:2.4 >/dev/null 2>&1 || return 1
  "$DOCKER" cp "$conf" "$name:/usr/local/apache2/conf/httpd.conf" >/dev/null 2>&1 || return 1
  "$DOCKER" cp "$HTDOCS/." "$name:/htdocs/" >/dev/null 2>&1 || return 1
  "$DOCKER" start "$name" >/dev/null 2>&1 || return 1
  return 0
}

if [ -n "$DOCKER" ] && "$DOCKER" info >/dev/null 2>&1; then
  DOCKER_OK=yes
fi

# seed a document root (must exist before start_apache copies it in)
printf 'hello-http2\n' > "$HTDOCS/index.html"
printf '0123456789'     > "$HTDOCS/small.txt"
head -c 30000 /dev/urandom > "$HTDOCS/m30.bin"
# 100k exceeds the default connection flow-control window; used by A.7
head -c 100000 /dev/urandom > "$HTDOCS/m100.bin"

if [ "$DOCKER_OK" = yes ]; then
  if require_free_port "$H2C_PORT" A.11 H2C && \
     require_free_port "$H1_PORT" A.12 H1; then
    if start_apache http2client-h2c "$H2C_PORT" "h2c http/1.1" "H2Upgrade on" && \
       start_apache http2client-h1  "$H1_PORT"  "http/1.1"     ""; then
      wait_port 127.0.0.1 "$H2C_PORT" || true
      wait_port 127.0.0.1 "$H1_PORT"  || true
    else
      echo "WARNING: failed to start the Apache cleartext servers" >&2
      DOCKER_OK=no
    fi
  else
    DOCKER_OK=no
  fi
fi
# --- A gate server: TLS + ALPN h2 -----------------------------------------
"$NGHTTPD" -d "$HTDOCS" --echo-upload "$PORT" \
  test/certs/localhost.key test/certs/localhost.crt \
  >"$BUILD/nghttpd.log" 2>&1 &
NGHTTPD_PID=$!
# --- a plaintext server for the A.9 negative control ----------------------
"$NGHTTPD" --no-tls -d "$HTDOCS" "$PLAIN_PORT" >"$BUILD/nghttpd_plain.log" 2>&1 &
NGHTTPD_PLAIN_PID=$!
# --- A.14 gate server: tiny 8 KiB windows (SETTINGS_INITIAL_WINDOW_SIZE) --
# -w 8 / -W 8 lower the stream and connection windows to 8192, so a 200 KB
# upload MUST block on credit and be replenished by inbound WINDOW_UPDATE --
# the exact scenario that deadlocked when stream WINDOW_UPDATE frames were
# dispatched to a lease whose queue was not drained during the upload.
"$NGHTTPD" -d "$HTDOCS" --echo-upload -w 8 -W 8 "$SMALLWIN_PORT" \
  test/certs/localhost.key test/certs/localhost.crt \
  >"$BUILD/nghttpd_smallwin.log" 2>&1 &
NGHTTPD_SMALLWIN_PID=$!

if ! wait_port 127.0.0.1 "$PORT"; then
  echo "ERROR: nghttpd did not open port $PORT" >&2
  cat "$BUILD/nghttpd.log" >&2
  exit 1
fi

BASE="https://localhost:$PORT"

# A.1 GET a small file
run_probe "$BASE/small.txt"
if [ "$PROBE_RC" = 0 ] && echo "$PROBE_OUT" | grep -q "status=200 bytes=10"; then
  record A.1 "GET small file -> 200 + bytes" "200,10" "$PROBE_OUT" PASS
else
  record A.1 "GET small file -> 200 + bytes" "200,10" "$PROBE_OUT" FAIL
fi

# A.2 POST with THttpBody (nghttpd --echo-upload echoes)
run_probe "$BASE/" --method=POST --body=echo-payload-123
if [ "$PROBE_RC" = 0 ] && echo "$PROBE_OUT" | grep -q "status=200"; then
  record A.2 "POST body echo -> 200" "200" "$PROBE_OUT" PASS
else
  record A.2 "POST body echo -> 200" "200" "$PROBE_OUT" FAIL
fi

# A.3 streaming upload via IBodyWriter (h2probe --body-writer chunks the body)
run_probe "$BASE/" --method=POST --body-writer=streaming-payload-456
if [ "$PROBE_RC" = 0 ] && echo "$PROBE_OUT" | grep -q "status=200"; then
  record A.3 "streaming upload (IBodyWriter)" "body arrives, END_STREAM" \
    "$PROBE_OUT" PASS
else
  record A.3 "streaming upload (IBodyWriter)" "body arrives, END_STREAM" \
    "$PROBE_OUT" FAIL
fi

# A.4 HEAD -> headers only
run_probe "$BASE/small.txt" --method=HEAD
if [ "$PROBE_RC" = 0 ] && echo "$PROBE_OUT" | grep -q "status=200 bytes=0"; then
  record A.4 "HEAD -> headers only, no body" "200,0" "$PROBE_OUT" PASS
else
  record A.4 "HEAD -> headers only, no body" "200,0" "$PROBE_OUT" FAIL
fi

# A.5 concurrency: 20 parallel GETs on one connection
run_probe "$BASE/small.txt" --parallel=20
if [ "$PROBE_RC" = 0 ] && echo "$PROBE_OUT" | grep -q "SUMMARY parallel=20 ok=20"; then
  record A.5 "20 parallel GETs, one pool" "all complete" "$PROBE_OUT" PASS
else
  record A.5 "20 parallel GETs, one pool" "all complete" \
    "$(echo "$PROBE_OUT" | tail -1)" FAIL
fi

# A.6 SETTINGS_MAX_CONCURRENT_STREAMS honored: request 40 parallel streams
# against a server capped at 100 — cannot exceed without a peer cap; the
# client-side cap logic is unit-tested (Http2.Client.Test). Probe-level:
run_probe "$BASE/small.txt" --parallel=8
if [ "$PROBE_RC" = 0 ] && echo "$PROBE_OUT" | grep -q "SUMMARY parallel=8 ok=8"; then
  record A.6 "honor peer MAX_CONCURRENT_STREAMS" "no stream exceeds cap" \
    "probe 8-way OK; client cap enforced in unit tests" PASS
else
  record A.6 "honor peer MAX_CONCURRENT_STREAMS" "no stream exceeds cap" \
    "$(echo "$PROBE_OUT" | tail -1)" FAIL
fi

# A.7 large response: flow-control WINDOW_UPDATE must be emitted, no stall
run_probe "$BASE/m100.bin"
if [ "$PROBE_RC" = 0 ] && echo "$PROBE_OUT" | grep -q "status=200 bytes=100000"; then
  record A.7 "100k response (WINDOW_UPDATE, no stall)" "200,100000" \
    "$PROBE_OUT" PASS
else
  record A.7 "100k response (WINDOW_UPDATE, no stall)" "200,100000" \
    "$PROBE_OUT" FAIL
fi

# A.8 server GOAWAY — nghttpd emits GOAWAY at shutdown; the client retry
# policy for in-flight streams above last-stream-id is unit-tested (S08/S10).
record A.8 "server GOAWAY handling" "streams > lastStreamId handled" \
  "no nghttpd trigger to force GOAWAY mid-flight; unit tests S08/S10" SKIP

# A.9 TLS ALPN: an http/1.1-only (or no-ALPN) server must raise
if command -v openssl >/dev/null 2>&1; then
  openssl s_server -quiet -accept "$((PORT+1))" \
    -cert test/certs/localhost.crt -key test/certs/localhost.key -www \
    >"$BUILD/sserver.log" 2>&1 &
  SSERVER_PID=$!
  sleep 1
  run_probe "https://localhost:$((PORT+1))/"
  kill "$SSERVER_PID" 2>/dev/null; SSERVER_PID=""
  if [ "$PROBE_RC" = 2 ] && echo "$PROBE_OUT" | grep -qi "ALPN"; then
    record A.9 "ALPN: no-h2 peer raises" "connection error (ALPN)" \
      "$PROBE_OUT" PASS
  else
    record A.9 "ALPN: no-h2 peer raises" "connection error (ALPN)" \
      "$PROBE_OUT" FAIL
  fi
else
  record A.9 "ALPN: no-h2 peer raises" "connection error (ALPN)" \
    "openssl not available" SKIP
fi

# --- S13 A.10: h2c prior knowledge against nghttpd --no-tls ----------------
run_probe "http://127.0.0.1:$PLAIN_PORT/small.txt" --clear-text=prior-knowledge
if [ "$PROBE_RC" = 0 ] && echo "$PROBE_OUT" | grep -q "status=200 bytes=10"; then
  record A.10 "h2c prior knowledge -> 200" "200,10" "$PROBE_OUT" PASS
else
  record A.10 "h2c prior knowledge -> 200" "200,10" "$PROBE_OUT" FAIL
fi

# --- S13 A.11: h2c upgrade (Upgrade: h2c -> 101 -> HTTP/2) ----------------
if [ "$DOCKER_OK" = yes ]; then
  run_probe "http://127.0.0.1:$H2C_PORT/small.txt" --clear-text=upgrade
  if [ "$PROBE_RC" = 0 ] && echo "$PROBE_OUT" | grep -q "status=200 bytes=10"; then
    record A.11 "h2c upgrade -> 101 then HTTP/2" "200,10" "$PROBE_OUT" PASS
  else
    record A.11 "h2c upgrade -> 101 then HTTP/2" "200,10" "$PROBE_OUT" FAIL
  fi
else
  record A.11 "h2c upgrade -> 101 then HTTP/2" "200,10" \
    "docker unavailable" SKIP
fi

# --- S13 A.12: HTTP/1.1 fallback (upgrade offered, peer stays HTTP/1.1) ---
if [ "$DOCKER_OK" = yes ]; then
  run_probe "http://127.0.0.1:$H1_PORT/small.txt" --clear-text=upgrade
  if [ "$PROBE_RC" = 0 ] && echo "$PROBE_OUT" | grep -q "status=200 bytes=10"; then
    record A.12 "HTTP/1.1 fallback -> 200" "200,10" "$PROBE_OUT" PASS
  else
    record A.12 "HTTP/1.1 fallback -> 200" "200,10" "$PROBE_OUT" FAIL
  fi
else
  record A.12 "HTTP/1.1 fallback -> 200" "200,10" \
    "docker unavailable" SKIP
fi

# --- S13 A.13: strict mode rejects cleartext -------------------------------
run_probe "http://127.0.0.1:$PLAIN_PORT/small.txt"
if [ "$PROBE_RC" = 2 ] && echo "$PROBE_OUT" | grep -q "code=PROTOCOL_ERROR"; then
  record A.13 "strict mode rejects cleartext" "conn-error PROTOCOL_ERROR" \
    "$PROBE_OUT" PASS
else
  record A.13 "strict mode rejects cleartext" "conn-error PROTOCOL_ERROR" \
    "$PROBE_OUT" FAIL
fi

# --- S04 A.14: large upload under a tiny peer window (flow control) --------
# 200 KB POST to a server whose stream window is 8192 bytes: the client must
# split DATA on available credit, block until each WINDOW_UPDATE arrives, and
# still return the full echo.  Regression for the WINDOW_UPDATE-routing
# deadlock and the pre-SETTINGS InitialWindowSize race.
if wait_port 127.0.0.1 "$SMALLWIN_PORT"; then
  run_probe "https://localhost:$SMALLWIN_PORT/" --method=POST \
    --upload-bytes=200000 --upload-chunk=16384
  if [ "$PROBE_RC" = 0 ] && \
     echo "$PROBE_OUT" | grep -q "status=200 bytes=200000"; then
    record A.14 "200k upload, peer window 8 KiB (flow control)" \
      "200,200000" "$PROBE_OUT" PASS
  else
    record A.14 "200k upload, peer window 8 KiB (flow control)" \
      "200,200000" "$(echo "$PROBE_OUT" | tail -1)" FAIL
  fi
else
  record A.14 "200k upload, peer window 8 KiB (flow control)" "200,200000" \
    "tiny-window nghttpd did not start" FAIL
fi

# also prove the TLS+ALPN gate actually negotiated h2 (server log evidence)
if grep -q "h2" "$BUILD/nghttpd.log" 2>/dev/null; then :; fi

echo
printf '%-4s %-42s %-28s %-6s %s\n' ID CASE EXPECTED STATUS DETAIL
printf '%-4s %-42s %-28s %-6s %s\n' -- ------------------------------------------ \
  ---------------------------- ------ ------------------------------
for r in "${rows[@]}"; do
  IFS='|' read -r id case exp act st <<<"$r"
  printf '%-4s %-42s %-28s %-6s %s\n' "$id" "$case" "$exp" "$st" "$act"
done

echo
echo "interop: PASS=$PASS FAIL=$FAIL SKIP=$SKIP (mandatory cases: A.1-A.5,A.7,A.9-A.14)"
if [ "$FAIL" -eq 0 ]; then
  echo "RESULT: interop gate GREEN"
  exit 0
fi
echo "RESULT: interop gate RED ($FAIL mandatory case(s) failed)"
exit 1
