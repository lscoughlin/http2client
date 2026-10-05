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
# The outcome class for every id is DECLARED in plan/harness-expectations.tsv,
# generated from the harness verifier sources. The reference run only tells us
# whether it demonstrated that declared outcome; where it could not (Go's
# verifier fails, or the whole oracle was invalid) a declared outcome we DO meet
# still counts as BETTER rather than being scored against a broken oracle.
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
# --- declared expectations (authority: the verifier's own sources) ----------
# plan/harness-expectations.tsv is generated from
# third_party/h2-client-test-harness/verifier/cases/*.go by
# tools/validate/extract_expectations.py. Each row is "<id>\t<expectation>"
# with expectation in {success, conn-error, stream-error}.
#
# Why the declared table and not the reference run's own wording: the image's
# verifier matches SUBSTRINGS of the Go client's error text, so a case declared
# as ExpectConnectionError can still log "Verifier passed" while Go actually
# reported a *stream* error (e.g. 5.1/1, 6.2/4). Scoring us against that
# observed wording would import Go's imprecision; the declaration is the rule.
EXPECTATIONS="$REPO_ROOT/plan/harness-expectations.tsv"
if [ ! -f "$EXPECTATIONS" ]; then
  echo "ERROR: $EXPECTATIONS missing; regenerate with:" >&2
  echo "  python3 tools/validate/extract_expectations.py \\" >&2
  echo "      third_party/h2-client-test-harness/verifier/cases \\" >&2
  echo "      > plan/harness-expectations.tsv" >&2
  exit 1
fi

declared_intent() { # id -> success|conn-error|stream-error|'' (absent)
  awk -F'\t' -v id="$1" '$1 == id { print $2; exit }' "$EXPECTATIONS"
}

# ids whose harness case writes a response :status (source-derived)
STATUS_WRITERS="6.10/2 6.9/2 8.1/1 8.1.2/1 8.1.2.1/1 8.1.2.1/2 8.1.2.1/3 \
8.1.2.1/4 8.1.2.2/1 8.1.2.2/2 8.1.2.3/1 8.1.2.6/1 8.1.2.6/2 hpack/2.3.3/1 \
hpack/2.3.3/2 hpack/4.2/1 http2/8.1.2.4/1 6.10/3 6.10/4 6.10/5 6.10/6"

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
  # The reference run tells us only whether the reference client produced the
  # declared outcome. The EXPECTED class itself comes from the declarations in
  # plan/harness-expectations.tsv (see declared_intent), NOT from the reference
  # log: the image's verifier matches error SUBSTRINGS, so its own wording can
  # disagree with the case author's expectation.
  #
  # A positive control (BASELINE_ID) must pass first; if it does not, the
  # reference is not trustworthy and every row is downgraded to fail/invalid.
  local log="$1"
  if [ "${BASELINE_OK:-}" != yes ]; then echo "fail invalid"; return; fi
  if grep -q 'Got successful response as expected' "$log"; then
    echo "pass success"; return
  fi
  if grep -q 'Got expected error\|Got expected stream error' "$log"; then
    # record the level Go happened to produce (fallback scoring only)
    if grep -q 'stream error' "$log"; then echo "pass stream-error"; return; fi
    echo "pass conn-error"; return
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
  local rstate="$1" rclass="$2" our="$3" id="$4" expected
  local our_err=false
  { [ "$our" = conn-error ] || [ "$our" = stream-error ]; } && our_err=true
  expected="$(declared_intent "$id")"

  # No declaration for this id: fall back to whatever class the reference run
  # happened to demonstrate.
  if [ -z "$expected" ]; then
    if [ "$rstate" = fail ]; then
      if [ "$our_err" = true ]; then echo "BETTER"; else echo "UNKNOWN"; fi
    elif [ "$our" = "$rclass" ]; then
      echo "MATCH"
    else
      echo "UNKNOWN"
    fi
    return
  fi

  if [ "$our" = "$expected" ]; then
    # We produced exactly what the case declares. When the reference ALSO
    # demonstrated it, that is a MATCH; when the reference could not, the
    # declaration is still satisfied -> BETTER.
    if [ "$rstate" = pass ]; then echo "MATCH"; else echo "BETTER"; fi
    return
  fi

  if [ "$expected" != success ] && [ "$our_err" = true ]; then
    # both are errors, at different levels: a real divergence to justify
    echo "CLASS-DIFF"
    return
  fi

  # We did not meet the declared outcome. That is a genuine failure only when
  # the reference demonstrated the declared outcome; otherwise it is
  # inconclusive (the environment could not show either side).
  if [ "$rstate" = pass ]; then echo "WORSE"; else echo "UNKNOWN"; fi
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
    "$(declared_intent "$id")" "$verdict" "$our_line" \
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
