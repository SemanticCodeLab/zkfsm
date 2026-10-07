#!/usr/bin/env bash
# S3 Select end to end: every case in tests/select/cases.zig runs through the
# server over Parquet (four encodings), gzip CSV, JSON lines and an SSE-S3
# encrypted Parquet object, and must match the DuckDB-derived expected output.
# With DuckDB importable (DUCKDB_PYTHON=/path/to/python, default python3) the
# Parquet results are also compared against live DuckDB queries. Also: event
# stream errors, mc sql, and the small CSV/JSON cases from the original suite.
set -euo pipefail
S3CLI_BIN="${S3CLI_BIN:-aws}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')"
EP="http://127.0.0.1:$PORT"
WORK="$(mktemp -d)"
PID=""
cleanup() { [[ -n "$PID" ]] && kill "$PID" 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

AK="zkfsmselaccess"
SK="zkfsm-select-secret-1"
export ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK"
export AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_DEFAULT_REGION=us-east-1
export AWS_CONFIG_FILE="$WORK/aws.conf" AWS_SHARED_CREDENTIALS_FILE="$WORK/aws.creds" AWS_PAGER="" AWS_EC2_METADATA_DISABLED=true
printf '[default]\ns3 =\n  addressing_style = path\n' >"$AWS_CONFIG_FILE"
export MC_CONFIG_DIR="$WORK/mc"
MC="${MC:-$(command -v mc || true)}"
DUCKDB_PYTHON="${DUCKDB_PYTHON:-python3}"
FIX="$ROOT/tests/select/fixtures"

fail() { echo "FAIL: $*" >&2; tail -20 "$WORK/server.log" >&2 || true; exit 1; }
ok() { echo "ok   $*"; }
s3api() { "$S3CLI_BIN" --endpoint-url "$EP" s3api "$@"; }

(cd "$ROOT" && zig build)
"$ROOT/zig-out/bin/zkfsm" --data "$WORK/data" --listen "127.0.0.1:$PORT" --scan-interval 0 \
  --kms-backend local --kms-dir "$WORK/kms" >"$WORK/server.log" 2>&1 &
PID=$!
for _ in $(seq 100); do curl -s -o /dev/null "$EP/" && break; sleep 0.1; done

s3api create-bucket --bucket sel >/dev/null || fail "create bucket"
for f in plain_none.parquet dict_snappy.parquet gzip_v2.parquet zstd_plain_v2.parquet rows.csv.gz rows.jsonl; do
  s3api put-object --bucket sel --key "$f" --body "$FIX/$f" >/dev/null || fail "put $f"
done
s3api put-object --bucket sel --key enc.parquet --body "$FIX/dict_snappy.parquet" --server-side-encryption AES256 >/dev/null || fail "put encrypted"

# Small hand-written cases.
printf 'name,age,city\nann,34,paris\nbob,19,oslo\ncid,52,rome\n' >"$WORK/people.csv"
printf '{"name":"ann","age":34}\n{"name":"bob","age":19}\n{"name":"cid","age":52}\n' >"$WORK/people.json"
s3api put-object --bucket sel --key people.csv --body "$WORK/people.csv" >/dev/null
s3api put-object --bucket sel --key people.json --body "$WORK/people.json" >/dev/null
s3api select-object-content --bucket sel --key people.csv \
  --expression "SELECT s.name, s.city FROM S3Object s WHERE CAST(s.age AS INT) > 30" --expression-type SQL \
  --input-serialization '{"CSV":{"FileHeaderInfo":"USE"}}' --output-serialization '{"CSV":{}}' "$WORK/sel.csv" || fail "select csv"
[[ "$(cat "$WORK/sel.csv")" == $'ann,paris\ncid,rome' ]] || fail "select csv output: $(cat "$WORK/sel.csv")"
s3api select-object-content --bucket sel --key people.json \
  --expression "SELECT s.name FROM S3Object s WHERE s.age < 30" --expression-type SQL \
  --input-serialization '{"JSON":{"Type":"LINES"}}' --output-serialization '{"JSON":{}}' "$WORK/sel.json" || fail "select json"
grep -q '{"name":"bob"}' "$WORK/sel.json" || fail "select json output: $(cat "$WORK/sel.json")"
if s3api select-object-content --bucket sel --key people.csv --expression "SELEC nonsense" --expression-type SQL \
  --input-serialization '{"CSV":{}}' --output-serialization '{"CSV":{}}' "$WORK/bad.out" 2>"$WORK/bad.err"; then
  fail "bad SQL accepted"
fi
grep -q "400\|Parse\|Syntax" "$WORK/bad.err" || fail "bad SQL error: $(cat "$WORK/bad.err")"
if s3api select-object-content --bucket sel --key missing.csv --expression "SELECT * FROM S3Object" --expression-type SQL \
  --input-serialization '{"CSV":{}}' --output-serialization '{"CSV":{}}' "$WORK/bad.out" 2>"$WORK/miss.err"; then
  fail "select on a missing key accepted"
fi
grep -q "NoSuchKey" "$WORK/miss.err" || fail "missing key error: $(cat "$WORK/miss.err")"
ok "CSV/JSON select, parse error, missing key"

# Generated cases against every input format.
python3 - "$ROOT/tests/select/cases.zig" "$S3CLI_BIN" "$EP" "$WORK" <<'PY' || fail "fixture cases"
import json, re, subprocess, sys
cases_path, cli, ep, work = sys.argv[1:5]
cases = []
for line in open(cases_path):
    m = re.match(r'\s*\.\{ \.name = ("(?:[^"\\]|\\.)*"), \.sql = ("(?:[^"\\]|\\.)*"), \.text_ok = (true|false), \.expected = ("(?:[^"\\]|\\.)*") \},', line)
    if m:
        cases.append((json.loads(m[1]), json.loads(m[2]), m[3] == "true", json.loads(m[4])))
assert len(cases) >= 10, len(cases)
inputs = [(k, '{"Parquet":{}}', False) for k in ("plain_none.parquet", "dict_snappy.parquet", "gzip_v2.parquet", "zstd_plain_v2.parquet", "enc.parquet")]
inputs += [("rows.csv.gz", '{"CSV":{"FileHeaderInfo":"USE"},"CompressionType":"GZIP"}', True),
           ("rows.jsonl", '{"JSON":{"Type":"LINES"}}', True)]
bad = 0
runs = 0
for key, ser, text in inputs:
    for name, sql, text_ok, expected in cases:
        if text and not text_ok:
            continue
        out = f"{work}/case.out"
        r = subprocess.run([cli, "--endpoint-url", ep, "s3api", "select-object-content", "--bucket", "sel", "--key", key,
                            "--expression", sql, "--expression-type", "SQL", "--input-serialization", ser,
                            "--output-serialization", '{"CSV":{}}', out], capture_output=True, text=True)
        runs += 1
        got = open(out).read() if r.returncode == 0 else f"<error {r.stderr.strip()}>"
        if got != expected:
            bad += 1
            print(f"mismatch {key} / {name}\n--- expected\n{expected[:400]}--- got\n{got[:400]}")
print(f"{runs} select runs, {bad} mismatches")
sys.exit(1 if bad else 0)
PY
ok "fixture cases over Parquet x4, encrypted Parquet, gzip CSV, JSON lines"

if "$DUCKDB_PYTHON" -c 'import duckdb, pyarrow' 2>/dev/null; then
  "$DUCKDB_PYTHON" - "$ROOT/tests/select" "$S3CLI_BIN" "$EP" "$WORK" <<'PY' || fail "live duckdb comparison"
import subprocess, sys
here, cli, ep, work = sys.argv[1:5]
sys.path.insert(0, here)
import duckdb
import gen_fixtures as g
con = duckdb.connect()
con.execute("SET threads = 1")
bad = 0
for f in g.PARQUET_VARIANTS:
    con.execute(f"CREATE OR REPLACE VIEW t AS SELECT * FROM read_parquet('{here}/fixtures/{f}')")
    for name, s3sql, duck, _ in g.CASES:
        want = g.csv_rows(con.execute(duck).fetchall())
        out = f"{work}/duck.out"
        subprocess.run([cli, "--endpoint-url", ep, "s3api", "select-object-content", "--bucket", "sel", "--key", f,
                        "--expression", s3sql, "--expression-type", "SQL", "--input-serialization", '{"Parquet":{}}',
                        "--output-serialization", '{"CSV":{}}', out], check=True, capture_output=True)
        got = open(out).read()
        if got != want:
            bad += 1
            print(f"duckdb mismatch {f} / {name}\n--- duckdb\n{want[:400]}--- zkfsm\n{got[:400]}")
print(f"duckdb {duckdb.__version__}: {bad} mismatches")
sys.exit(1 if bad else 0)
PY
  ok "results match live DuckDB"
else
  echo "skip live DuckDB comparison (set DUCKDB_PYTHON to a python with duckdb and pyarrow)"
fi

if [[ -n "$MC" ]]; then
  "$MC" alias set z "$EP" "$AK" "$SK" >/dev/null
  got=$("$MC" sql --csv-input "fh=USE" --query "SELECT COUNT(*) FROM S3Object" z/sel/people.csv) || fail "mc sql"
  [[ "$(tr -d '\n' <<<"$got")" == 3 ]] || fail "mc sql output: $got"
  got=$("$MC" sql --query "SELECT COUNT(*) FROM S3Object" z/sel/plain_none.parquet) || fail "mc sql parquet"
  [[ "$(tr -d '\n' <<<"$got")" == 1000 ]] || fail "mc sql parquet output: $got"
  ok "mc sql"
fi

echo "select: PASS"
