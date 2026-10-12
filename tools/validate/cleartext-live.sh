#!/usr/bin/env bash
# Opt-in live cleartext gate (doc/design/fallback.md): drive the real client
# against an HTTP/1.1-only server that logs every request it receives, and
# prove from the server's side that a request is sent ONCE under both
# cleartext HTTP/1.1-capable policies:
#
#   ctUpgrade  the h2c probe is declined; the probe's response answers the
#              request and the request is not written again
#   ctHttp1    no Upgrade header at all
#
#   bash tools/validate/cleartext-live.sh     # or: make validate-cleartext
#
# Env overrides: CT_PORT (default 8651), OPENSSL_LIBPATH.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PORT="${CT_PORT:-8651}"
WORK="$(mktemp -d)"
LOG="$WORK/server.log"
SERVER_PID=""
cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

M="$ROOT/third_party/mORMot2/src"
fpc -O2 -vw -Mdelphi -Fu"$ROOT/src" -Fu"$M/core" -Fu"$M/lib" -Fu"$M/net" -Fu"$M/crypt" \
  -FE"$WORK" -FU"$WORK" "$HERE/cleartext_probe.pas" >"$WORK/fpc.log" 2>&1 \
  || { cat "$WORK/fpc.log"; echo "cleartext-live: could not build the probe" >&2; exit 2; }

python3 "$HERE/h1_counter_server.py" --log "$LOG" --port "$PORT" >"$WORK/ready" 2>"$WORK/err" &
SERVER_PID=$!
for _ in $(seq 1 60); do
  grep -q ready "$WORK/ready" 2>/dev/null && break
  sleep 0.1
done
grep -q ready "$WORK/ready" || { echo "cleartext-live: server did not start" >&2; exit 2; }

FAIL=0
check() { # description expected actual
  if [ "$2" = "$3" ]; then
    echo "cleartext-live: ok   $1"
  else
    echo "cleartext-live: FAIL $1 (expected $2, saw $3)"; FAIL=1
  fi
}

for POLICY in upgrade http1; do
  for METHOD in GET POST DELETE HEAD; do
    : > "$LOG"
    OUT="$("$WORK/cleartext_probe" "$PORT" "$POLICY" "$METHOD" 2>&1)"
    EXPECT_BODY=2; [ "$METHOD" = HEAD ] && EXPECT_BODY=0
    check "$POLICY $METHOD response" "status=200 body=$EXPECT_BODY" "$OUT"
    check "$POLICY $METHOD copies received" 1 "$(grep -c "^request $METHOD /probe " "$LOG")"
    if [ "$POLICY" = http1 ]; then
      check "$POLICY $METHOD sent no Upgrade" 1 "$(grep -c 'upgrade=-' "$LOG")"
    else
      check "$POLICY $METHOD carried the probe once" 1 "$(grep -c 'upgrade=h2c' "$LOG")"
    fi
  done
done

if [ "$FAIL" -ne 0 ]; then
  echo "cleartext-live: FAILED"; exit 1
fi
echo "cleartext-live: PASS"
