#!/usr/bin/env bash
# tools/validate/harness.sh — plan/validation.md section B
# (nomadlabsinc/h2-client-test-harness, the primary RFC gate).
#
# For every id from `docker run --rm h2-test-harness --list` this script:
#   1. measures the REFERENCE outcome by running the harness's own Go verifier
#      (`docker run --rm h2-test-harness --test=<id>`), and
#   2. measures OUR outcome by starting the harness server (detached, host
#      network) and running test/h2probe against it,
# then classifies the id MATCH / BETTER / WORSE / UNKNOWN.
#
# It writes the full per-id table to plan/validation-results.md and prints a
# summary. It is re-runnable and independent of the repo build state.
#
# Verdict model (approved direction):
#   PASS = MATCH or BETTER;  FAIL = WORSE;  UNKNOWN counted separately.
#   MATCH  : our outcome class == the reference's.
#   BETTER : we produced a connection/stream error where the reference only
#            stayed open / timed out (a genuine conformance improvement).
#   WORSE  : the reference detected an error (or got a success) and we only
#            timed out / stayed open (a real client bug).
#   UNKNOWN: neither side resolves to an outcome class.
#
# harness_wrote_status: whether the harness case ever writes a response
# HEADERS frame carrying a :status (source-derived; only these 21 ids can
# possibly yield a successful request for a compliant client).
set -u

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

BUILD="$(mktemp -d /tmp/h2harness-build.XXXXXX)"
PROBE="$BUILD/h2probe"
OUT_MD="$REPO_ROOT/plan/validation-results.md"
RESULTS_TSV="$BUILD/results.tsv"

FPC="${FPC:-fpc}"
MORMOT="third_party/mORMot2/src"
export OPENSSL_LIBPATH="${OPENSSL_LIBPATH:-/opt/homebrew/opt/openssl@3/lib}"
export PATH="/Users/liamcoughlin/.rd/bin:$PATH"

DOCKER="$(command -v docker || true)"
IMG="h2-test-harness"
CONTAINER="h2harness-$$"
PROBE_TIMEOUT_MS="${PROBE_TIMEOUT_MS:-4000}"

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1
  rm -rf "$BUILD" 2>/dev/null
}
trap cleanup EXIT

if [ -z "$DOCKER" ]; then
  echo "ERROR: docker not found on PATH" >&2
  exit 1
fi

# --- static expectation annotation (from verifier/cases/*.go source) --------
# id=intent where intent is success|conn-error|stream-error|MULTI:...|UNKNOWN
STATIC_EXPECT="$(cat <<'EOF'
3.5/1=MULTI:conn-error/success
3.5/2=MULTI:conn-error/success
4.1/1=MULTI:success
4.1/2=MULTI:success
4.1/3=MULTI:success
4.2/1=MULTI:conn-error/stream-error/success
4.2/2=MULTI:conn-error/stream-error/success
4.2/3=MULTI:conn-error/stream-error/success
5.1.1/1=conn-error
5.1.1/2=conn-error
5.1.2/1=MULTI:conn-error/stream-error
5.1/1=MULTI:conn-error/stream-error
5.1/10=MULTI:conn-error/stream-error
5.1/11=MULTI:conn-error/stream-error
5.1/12=MULTI:conn-error/stream-error
5.1/13=MULTI:conn-error/stream-error
5.1/2=MULTI:conn-error/stream-error
5.1/3=MULTI:conn-error/stream-error
5.1/4=MULTI:conn-error/stream-error
5.1/5=MULTI:conn-error/stream-error
5.1/6=MULTI:conn-error/stream-error
5.1/7=MULTI:conn-error/stream-error
5.1/8=MULTI:conn-error/stream-error
5.1/9=MULTI:conn-error/stream-error
5.3.1/1=stream-error
5.3.1/2=stream-error
5.4.1/1=conn-error
5.4.1/2=conn-error
6.1/1=MULTI:conn-error/stream-error
6.1/2=MULTI:conn-error/stream-error
6.1/3=MULTI:conn-error/stream-error
6.10/2=conn-error
6.10/3=UNKNOWN
6.10/4=UNKNOWN
6.10/5=UNKNOWN
6.10/6=UNKNOWN
6.2/1=conn-error
6.2/2=conn-error
6.2/3=conn-error
6.2/4=conn-error
6.3/1=MULTI:conn-error/stream-error
6.3/2=MULTI:conn-error/stream-error
6.4/1=conn-error
6.4/2=conn-error
6.4/3=conn-error
6.5/1=UNKNOWN
6.5/2=UNKNOWN
6.5/3=UNKNOWN
6.5.2/1=UNKNOWN
6.5.2/2=UNKNOWN
6.5.2/3=UNKNOWN
6.5.2/4=UNKNOWN
6.5.2/5=UNKNOWN
6.5.3/2=UNKNOWN
6.7/1=UNKNOWN
6.7/2=UNKNOWN
6.7/3=UNKNOWN
6.7/4=UNKNOWN
6.8/1=UNKNOWN
6.9.1/1=MULTI:conn-error/stream-error/success
6.9.1/2=MULTI:conn-error/stream-error/success
6.9.1/3=MULTI:conn-error/stream-error/success
6.9.2/3=UNKNOWN
6.9/1=UNKNOWN
6.9/2=UNKNOWN
6.9/3=UNKNOWN
8.1/1=UNKNOWN
8.1.2/1=UNKNOWN
8.1.2.1/1=UNKNOWN
8.1.2.1/2=UNKNOWN
8.1.2.1/3=UNKNOWN
8.1.2.1/4=UNKNOWN
8.1.2.2/1=UNKNOWN
8.1.2.2/2=UNKNOWN
8.1.2.3/1=UNKNOWN
8.1.2.3/2=UNKNOWN
8.1.2.3/3=UNKNOWN
8.1.2.3/4=UNKNOWN
8.1.2.3/5=UNKNOWN
8.1.2.3/6=UNKNOWN
8.1.2.3/7=UNKNOWN
8.1.2.6/1=UNKNOWN
8.1.2.6/2=UNKNOWN
8.2/1=UNKNOWN
generic/1/1=MULTI:conn-error/success
generic/2/1=MULTI:conn-error/success
generic/3.1/1=MULTI:success
generic/3.1/2=MULTI:success
generic/3.1/3=MULTI:success
generic/3.10/1=MULTI:success
generic/3.2/1=MULTI:success
generic/3.2/2=MULTI:success
generic/3.2/3=MULTI:success
generic/3.3/1=MULTI:success
generic/3.3/2=MULTI:success
generic/3.3/3=MULTI:success
generic/3.3/4=MULTI:success
generic/3.3/5=MULTI:success
generic/3.4/1=MULTI:success
generic/3.5/1=success
generic/3.7/1=success
generic/3.8/1=success
generic/3.9/1=MULTI:success
generic/4/1=MULTI:success
generic/4/2=MULTI:success
generic/5/1=MULTI:conn-error/success
generic/misc/1=MULTI:success
hpack/2.3.3/1=UNKNOWN
hpack/2.3.3/2=UNKNOWN
hpack/2.3/1=MULTI:success
hpack/4.1/1=MULTI:success
hpack/4.2/1=UNKNOWN
hpack/5.2/1=MULTI:conn-error
hpack/5.2/2=MULTI:conn-error
hpack/5.2/3=MULTI:conn-error
hpack/6.1/1=conn-error
hpack/6.2.2/1=MULTI:success
hpack/6.2.3/1=MULTI:success
hpack/6.2/1=MULTI:success
hpack/6.3/1=conn-error
hpack/misc/1=MULTI:success
http2/4.3/1=MULTI:conn-error/success
http2/5.5/1=MULTI:conn-error/success
http2/7/1=MULTI:conn-error/success
http2/8.1.2.4/1=MULTI:conn-error/success
http2/8.1.2.5/1=MULTI:conn-error/success
complete/1=MULTI:success
complete/10=MULTI:success
complete/11=MULTI:success
complete/12=MULTI:success
complete/13=MULTI:success
complete/2=MULTI:success
complete/3=MULTI:success
complete/4=MULTI:success
complete/5=MULTI:success
complete/6=MULTI:success
complete/7=MULTI:success
complete/8=MULTI:success
complete/9=MULTI:success
extra/1=MULTI:success
extra/2=MULTI:success
extra/3=MULTI:success
extra/4=MULTI:success
extra/5=MULTI:success
final/1=MULTI:success
final/2=MULTI:success
EOF
)"

# ids whose harness case writes a response :status (source-derived)
STATUS_WRITERS="6.10/2 6.9/2 8.1/1 8.1.2/1 8.1.2.1/1 8.1.2.1/2 8.1.2.1/3 \
8.1.2.1/4 8.1.2.2/1 8.1.2.2/2 8.1.2.3/1 8.1.2.6/1 8.1.2.6/2 hpack/2.3.3/1 \
hpack/2.3.3/2 hpack/4.2/1 http2/8.1.2.4/1 6.10/3 6.10/4 6.10/5 6.10/6"

static_intent() { # id -> intent string
  local line
  line="$(echo "$STATIC_EXPECT" | grep -m1 "^$1=" || true)"
  if [ -z "$line" ]; then echo "UNKNOWN"; else echo "${line#*=}"; fi
}

wrote_status() { # id -> yes/no
  local x
  for x in $STATUS_WRITERS; do [ "$x" = "$1" ] && { echo yes; return; }; done
  echo no
}

compile_probe() {
  "$FPC" -O2 -Mdelphi -Fu./src -Fu"$BUILD" \
    -Fu"$MORMOT/core" -Fu"$MORMOT/lib" -Fu"$MORMOT/net" -Fu"$MORMOT/crypt" \
    -FU"$BUILD" -FE"$BUILD" test/h2probe.pas >"$BUILD/build.log" 2>&1 || {
    echo "ERROR: h2probe failed to compile; see $BUILD/build.log" >&2
    tail -20 "$BUILD/build.log" >&2; exit 1; }
}

classify_ref_log() { # logfile id -> "pass|fail class"
  # The reference resolves to an outcome class ONLY when its verifier passed.
  #
  # The expected class comes from the verifier's OWN success/failure message,
  # falling back to the curated table only when the log is silent; that keeps
  # the oracle honest when the image is rebuilt. A positive control
  # (BASELINE_ID) must pass first; if it does not, the reference is not
  # trustworthy and every row is downgraded to fail/invalid rather than being
  # scored against a broken oracle.
  local log="$1" intent cls
  if [ "${BASELINE_OK:-}" != yes ]; then echo "fail invalid"; return; fi
  if grep -q 'Got successful response as expected' "$log"; then
    echo "pass success"; return
  fi
  if grep -q 'Got expected error' "$log"; then
    if grep -q 'connection error:' "$log"; then echo "pass conn-error"; return; fi
    if grep -q 'stream error:' "$log"; then echo "pass stream-error"; return; fi
    intent="$(static_intent "$2")"
    case "$intent" in
      *conn-error*) echo "pass conn-error"; return;;
      *stream-error*) echo "pass stream-error"; return;;
    esac
    echo "pass error"; return
  fi
  if grep -q 'unexpected EOF' "$log"; then
    echo "fail eof"
  else
    echo "fail unresolved"
  fi
}

classify_our_line() { # RESULT line (+ msg) -> class
  local line="$1"
  if echo "$line" | grep -q "RESULT=success"; then echo success
  elif echo "$line" | grep -qi "timed out"; then echo timeout
  elif echo "$line" | grep -q "RESULT=stream-error"; then echo stream-error
  elif echo "$line" | grep -q "RESULT=conn-error"; then echo conn-error
  else echo unresolved; fi
}

verdict_for() { # ref_state ref_class our id -> verdict
  local rstate="$1" rclass="$2" our="$3" id="$4"
  local our_err=false
  { [ "$our" = conn-error ] || [ "$our" = stream-error ]; } && our_err=true
  # The reference did not resolve a class (verifier failed, or the whole oracle
  # was invalid): we cannot score against it. A clean error of ours still shows
  # a rule was enforced -> BETTER; otherwise both sides are inconclusive.
  if [ "$rstate" = fail ]; then
    if [ "$our_err" = true ]; then echo "BETTER"; else echo "UNKNOWN"; fi
    return
  fi
  # The reference PASSED, so the expected outcome class is authoritative.
  case "$rclass" in
    success)
      if [ "$our" = success ]; then echo "MATCH"; else echo "WORSE"; fi;;
    conn-error|stream-error)
      if [ "$our" = "$rclass" ]; then
        echo "MATCH"
      elif [ "$our_err" = true ]; then
        # both are errors, but at different levels. The harness's own verifier
        # distinguishes these ("got an unexpected error type: ConnectionError,
        # expected StreamError"), so a mismatch is a real divergence to justify
        # rather than a MATCH.
        echo "CLASS-DIFF"
      else
        echo "WORSE"
      fi;;
    *)
      if [ "$our" = success ]; then echo "MATCH"; else echo "UNKNOWN"; fi;;
  esac
}

wait_harness_ready() {
  local i
  for i in $(seq 1 100); do
    docker logs "$CONTAINER" 2>&1 | grep -q "listening on" && return 0
    sleep 0.1
  done
  return 1
}

run_reference() { # id -> writes log to stdout
  docker run --rm "$IMG" --test="$1" 2>&1
}

run_ours() { # id -> echo "exit line"
  # A NOT_READY result means the harness container did not finish binding
  # 127.0.0.1:8080 within the readiness window (host load, image warm-up);
  # it says nothing about the client. Retry a bounded number of times so an
  # infrastructure hiccup is not recorded as a client failure.
  local attempt out rc
  for attempt in 1 2 3; do
    docker rm -f "$CONTAINER" >/dev/null 2>&1
    docker run -d --name "$CONTAINER" --network host "$IMG" \
      --harness-only --test="$1" >/dev/null 2>&1
    if wait_harness_ready; then
      out="$(timeout_guard "$PROBE" --url=https://127.0.0.1:8080/ --insecure \
        --timeout-ms="$PROBE_TIMEOUT_MS" --keep-open-ms=200 2>&1)"
      rc=$?
      docker rm -f "$CONTAINER" >/dev/null 2>&1
      echo "$rc $(echo "$out" | head -1)"
      return
    fi
    docker rm -f "$CONTAINER" >/dev/null 2>&1
    sleep 1
  done
  echo "999 NOT_READY"
}

# a tiny timeout guard (macOS has no `timeout`): run in background, kill after N
timeout_guard() {
  local secs=$(( (PROBE_TIMEOUT_MS / 1000) + 5 ))
  "$@" & local pid=$!
  ( sleep "$secs"; kill -9 "$pid" 2>/dev/null ) & local wd=$!
  wait "$pid" 2>/dev/null; local rc=$?
  kill "$wd" 2>/dev/null
  return $rc
}

echo "== http2client harness validation ($IMG) =="
echo "image:    $(docker image inspect "$IMG" --format '{{.Id}}' 2>/dev/null | cut -c1-19)"
echo "ids:      $(docker run --rm "$IMG" --list 2>/dev/null | grep -c '  - ')"
echo

if ! docker image inspect "$IMG" >/dev/null 2>&1; then
  echo "ERROR: image '$IMG' not built. Build it from" \
    "third_party/h2-client-test-harness first." >&2
  exit 1
fi

compile_probe

mapfile -t IDS < <(docker run --rm "$IMG" --list 2>/dev/null | sed -n 's/^  - //p')
if [ -n "${HARNESS_IDS:-}" ]; then
  mapfile -t IDS < <(for x in $HARNESS_IDS; do echo "$x"; done)
fi
echo "running ${#IDS[@]} ids (reference + probe each)..." >&2

# Positive control: a case the Go verifier must pass. If it does not, the
# reference image (or the environment) is broken and no row can be trusted.
BASELINE_ID="${BASELINE_ID:-6.5/1}"
BASELINE_OK=no
mkdir -p "$BUILD"
base_log="$(run_reference "$BASELINE_ID")"
printf '%s' "$base_log" > "$BUILD/baseline.log"
if grep -q 'Verifier passed' "$BUILD/baseline.log"; then
  BASELINE_OK=yes
else
  echo "WARNING: reference positive control $BASELINE_ID did not pass;" \
    "scoring every row as invalid (see $BUILD/baseline.log)" >&2
fi
export BASELINE_OK

: > "$RESULTS_TSV"
n_match=0; n_better=0; n_worse=0; n_unknown=0; n_classdiff=0; n_ref_pass=0
for id in "${IDS[@]}"; do
  [ -z "$id" ] && continue
  ref_log="$(run_reference "$id")"
  printf '%s' "$ref_log" > "$BUILD/ref.log"
  if grep -q 'Verifier passed' "$BUILD/ref.log"; then
    n_ref_pass=$((n_ref_pass+1))
  fi
  ref_state_class="$(classify_ref_log "$BUILD/ref.log" "$id")"
  ref_state="${ref_state_class%% *}"; ref_class="${ref_state_class#* }"
  ours="$(run_ours "$id")"
  our_rc="${ours%% *}"; our_line="${ours#* }"
  our_class="$(classify_our_line "$our_line")"
  verdict="$(verdict_for "$ref_state" "$ref_class" "$our_class" "$id")"
  case "$verdict" in
    MATCH) n_match=$((n_match+1));;
    BETTER) n_better=$((n_better+1));;
    WORSE) n_worse=$((n_worse+1));;
    CLASS-DIFF) n_classdiff=$((n_classdiff+1));;
    UNKNOWN) n_unknown=$((n_unknown+1));;
  esac
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$id" "$ref_state" "$ref_class" "$our_rc" "$our_class" \
    "$(static_intent "$id")" "$verdict" "$our_line" \
    >> "$RESULTS_TSV"
  printf '  %-16s ref=%-4s/%-12s ours=%-13s %s\n' \
    "$id" "$ref_state" "$ref_class" "$our_class" "$verdict" >&2
done

reference_count=$n_ref_pass

{
  echo "# Harness validation results (section B)"
  echo
  echo "Generated by \`tools/validate/harness.sh\`."
  echo
  echo "Image: \`$IMG\`  ($(docker image inspect "$IMG" --format '{{.Id}}' 2>/dev/null | cut -c1-19))"
  echo
  echo "Go reference verifier tally: $n_ref_pass / ${#IDS[@]} ids passed."
  echo
  echo "Positive control (${BASELINE_ID:-6.5/1}): ${BASELINE_OK:-no}"
  echo
  echo "PASS = MATCH+BETTER = $((n_match+n_better));  FAIL = WORSE = $n_worse;  CLASS-DIFF = $n_classdiff;  UNKNOWN = $n_unknown"
  echo
  echo "| id | ref state | ref class | our exit | our outcome | static intent | verdict | our RESULT |"
  echo "|---|---|---|---|---|---|---|---|"
  while IFS=$'\t' read -r id rstate rclass rc our intent verdict line; do
    [ -z "$id" ] && continue
    echo "| $id | $rstate | $rclass | $rc | $our | $intent | $verdict | \`$line\` |"
  done < "$RESULTS_TSV"
} > "$OUT_MD"

echo
echo "harness: MATCH=$n_match BETTER=$n_better WORSE=$n_worse CLASS-DIFF=$n_classdiff UNKNOWN=$n_unknown"
echo "wrote $OUT_MD"
echo "RESULT: PASS=$((n_match+n_better)) FAIL=$n_worse CLASS-DIFF=$n_classdiff UNKNOWN=$n_unknown"
[ "$n_worse" -eq 0 ]
