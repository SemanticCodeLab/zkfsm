#!/usr/bin/env bash
# S3 conformance: runs client suites against zkfsm on a single drive and on 6 drives with EC:4+2.
#   SUITES="boto3 s3cli mc rclone s5cmd"  which client suites to run; add s3tests for ceph/s3-tests
#   LAYOUTS="single ec"                     which server layouts to run against
# Prints PASS/FAIL/XFAIL per check and `conformance: P/T passed (X xfail)`; exits 1 on unexpected failures.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SUITES="${SUITES:-boto3 s3cli mc rclone s5cmd}"
LAYOUTS="${LAYOUTS:-single ec}"
PY="${PYTHON:-python3}"
TOP="$(mktemp -d)"
RESULTS="$TOP/results"
: >"$RESULTS"
PID=""
cleanup() { [[ -n "$PID" ]] && kill "$PID" 2>/dev/null || true; rm -rf "$TOP"; }
trap cleanup EXIT

export AK="conformanceadmin" SK="conformance/secret+key0123456789"
export RESULTS
source "$HERE/lib.sh"

(cd "$ROOT" && zig build)
BIN="$ROOT/zig-out/bin/zkfsm"

venv() {
  local v="$HERE/.venv"
  if [[ ! -x "$v/bin/python" ]]; then "$PY" -m venv "$v"; fi
  if ! cmp -s "$HERE/requirements.txt" "$v/.requirements"; then
    "$v/bin/pip" install -q --disable-pip-version-check -r "$HERE/requirements.txt"
    cp "$HERE/requirements.txt" "$v/.requirements"
  fi
}

start_server() { # layout
  local data=()
  case "$1" in
    single) mkdir -p "$TOP/$1/d0"; data=("$TOP/$1/d0") ;;
    ec) for i in 1 2 3 4 5 6; do mkdir -p "$TOP/$1/d$i"; data+=("$TOP/$1/d$i"); done
        data+=(--protection EC:4+2) ;;
    *) echo "unknown layout $1"; exit 2 ;;
  esac
  PORT="$("$PY" -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')"
  export EP="http://127.0.0.1:$PORT"
  ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$BIN" --data "${data[@]}" --listen "127.0.0.1:$PORT" \
    --scan-interval 0 2>"$TOP/$1.server.log" &
  PID=$!
  for _ in $(seq 100); do curl -s -o /dev/null "$EP/health/live" && return 0; sleep 0.1; done
  echo "server did not start:"; cat "$TOP/$1.server.log"; exit 1
}

run_pytest() { # suite dir extra-args...
  local suite="$1" dir="$2"; shift 2
  venv
  S3_ENDPOINT="$EP" S3_ACCESS_KEY="$AK" S3_SECRET_KEY="$SK" \
    "$HERE/.venv/bin/python" -m pytest -q -p no:cacheprovider --junitxml="$WORK/$suite.xml" "$dir" "$@" \
    >"$WORK/$suite.log" 2>&1 || true
  if [[ -f "$WORK/$suite.xml" ]]; then
    "$HERE/.venv/bin/python" "$HERE/junit_results.py" "$WORK/$suite.xml" "$SUITE" "$RESULTS"
  else
    record FAIL "pytest" "no junit output"; tail -20 "$WORK/$suite.log"
  fi
  grep -E '^(FAILED|ERROR) ' "$WORK/$suite.log" | head -50 || true
}

for layout in $LAYOUTS; do
  start_server "$layout"
  echo "== layout $layout on $EP"
  for suite in $SUITES; do
    export WORK="$TOP/$layout-$suite" SUITE="$layout/$suite"
    export LOG="$WORK/client.log"
    mkdir -p "$WORK"
    case "$suite" in
      boto3) run_pytest boto3 "$HERE/boto3" ;;
      s3tests) source "$HERE/s3tests.sh" ;;
      *) source "$HERE/clients/$suite.sh" ;;
    esac
    if [[ -n "${KEEP_LOGS:-}" ]]; then mkdir -p "$KEEP_LOGS"; cp -r "$WORK" "$KEEP_LOGS/"; fi
  done
  if [[ -n "${KEEP_LOGS:-}" ]]; then cp "$TOP/$layout.server.log" "$KEEP_LOGS/"; fi
  SUITE="$layout/server"
  if kill "$PID" 2>/dev/null; then record PASS "stayed up"; else record FAIL "stayed up" "server exited early"; tail -30 "$TOP/$layout.server.log"; fi
  wait "$PID" 2>/dev/null || true; PID=""
done

echo
echo "== summary"
awk -F'\t' '{split($2, a, "::"); s[a[1]" "$1]++; k[a[1]]=1}
  END {for (x in k) printf "%-18s pass %d  fail %d  xfail %d  xpass %d  skip %d\n", x, s[x" PASS"], s[x" FAIL"], s[x" XFAIL"], s[x" XPASS"], s[x" SKIP"]}' \
  "$RESULTS" | sort
P=$(grep -c $'^\(PASS\|XPASS\)\t' "$RESULTS" || true)
F=$(grep -c $'^FAIL\t' "$RESULTS" || true)
X=$(grep -c $'^XFAIL\t' "$RESULTS" || true)
T=$((P + F + X))
echo "conformance: $P/$T passed ($X xfail)"
if [[ -f "$TOP/s3tests.results" ]]; then
  for layout in $LAYOUTS; do
    SP=$(grep -c $'^PASS\t'"$layout/" "$TOP/s3tests.results" || true)
    ST=$(grep -c $'^\(PASS\|FAIL\)\t'"$layout/" "$TOP/s3tests.results" || true)
    echo "s3-tests ($layout): $SP/$ST passed (reported separately, not gating)"
  done
fi
[[ $F -eq 0 ]]
