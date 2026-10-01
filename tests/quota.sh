#!/usr/bin/env bash
# Bucket quotas: mc quota set/info/clear, hard limits on PUT, multipart complete, and
# copy (QuotaExceeded), usage from the key index through overwrites, deletes,
# versioning, and restarts, and the same limit seen through every node of a cluster.
set -euo pipefail
S3CLI_BIN="${S3CLI_BIN:-aws}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
freeport() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
PORT="$(freeport)"
EP="http://127.0.0.1:$PORT"
DATA="$(mktemp -d)"
WORK="$(mktemp -d)"
PID=""
CPIDS=()
cleanup() {
  [[ -n "$PID" ]] && kill "$PID" 2>/dev/null || true
  for p in "${CPIDS[@]}"; do kill -9 "$p" 2>/dev/null || true; done
  rm -rf "$DATA" "$WORK"
}
trap cleanup EXIT

AK="zkfsmadmin"
SK="zkfsm-admin-secret-0123"
export AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_DEFAULT_REGION=us-east-1 AWS_PAGER=""
export AWS_CONFIG_FILE="$WORK/cli.conf" AWS_SHARED_CREDENTIALS_FILE="$WORK/cli.creds"
printf '[default]\ns3 =\n  addressing_style = path\n  multipart_threshold = 6MB\n  multipart_chunksize = 5MB\n' >"$AWS_CONFIG_FILE"
export MC_CONFIG_DIR="$WORK/mc"
MC="${MC:-$(command -v mc || true)}"
if [[ -z "$MC" ]] || ! "$MC" --version 2>/dev/null | grep -q RELEASE; then echo "quota.sh needs the MinIO client (set MC)"; exit 1; fi

pass=0
fail=0
check() { # name expected actual
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); echo "ok   $1"
  else fail=$((fail + 1)); echo "FAIL $1: expected [$2] got [$3]"; fi
}
ok() { if "$@" >/dev/null 2>&1; then echo 0; else echo 1; fi; }
jfield() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }
s3() { "$S3CLI_BIN" --endpoint-url "$EP" "$@"; }
code() { "$@" 2>&1 | grep -o 'QuotaExceeded' | head -1 || true; }
# Raw signed PUT: prints the HTTP status, keeps the body.
rawput() { curl -s -o "$WORK/put.out" -w '%{http_code}' --aws-sigv4 aws:amz:us-east-1:s3 --user "$AK:$SK" -T "$2" "$1"; }
usage_of() { # bucket -> bytes per the admin API
  curl -s --aws-sigv4 aws:amz:us-east-1:s3 --user "$AK:$SK" "$EP/minio/admin/v3/get-bucket-quota?bucket=$1" | jfield '["usage"]'
}

(cd "$ROOT" && zig build)
BIN="$ROOT/zig-out/bin/zkfsm"
start() {
  ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$BIN" --data "$DATA" --listen "127.0.0.1:$PORT" "$@" 2>>"$WORK/server.log" &
  PID=$!
  for _ in $(seq 50); do curl -s -o /dev/null "$EP/" && break; sleep 0.1; done
}
stop() { kill "$PID"; wait "$PID" 2>/dev/null || true; PID=""; }

head -c 400000 /dev/urandom >"$WORK/400k"
head -c 700000 /dev/urandom >"$WORK/700k"
head -c 12000000 /dev/urandom >"$WORK/12m"
start
"$MC" alias set z "$EP" "$AK" "$SK" >/dev/null
"$MC" mb z/qbk z/free >/dev/null

check "info without quota fails" 1 "$(ok "$MC" quota info z/qbk)"
check "quota set" 0 "$(ok "$MC" quota set z/qbk --size 1MiB)"
check "quota info size" 1048576 "$("$MC" quota info z/qbk --json | jfield '["quota"]')"
check "quota info type" hard "$("$MC" quota info z/qbk --json | jfield '["type"]' 2>/dev/null || "$MC" quota info z/qbk --json | jfield '["quotaType"]')"
check "quota on missing bucket" 1 "$(ok "$MC" quota set z/nope --size 1MiB)"

# PUT within, then past the limit.
check "put under quota" 200 "$(rawput "$EP/qbk/a" "$WORK/400k")"
check "second put under quota" 200 "$(rawput "$EP/qbk/b" "$WORK/400k")"
check "put over quota rejected" 400 "$(rawput "$EP/qbk/c" "$WORK/400k")"
check "error code QuotaExceeded" 1 "$(grep -c '<Code>QuotaExceeded</Code>' "$WORK/put.out")"
check "rejected object absent" 1 "$(ok s3 s3api head-object --bucket qbk --key c)"
check "usage counts stored bytes" 800000 "$(usage_of qbk)"
check "S3 CLI sees QuotaExceeded" QuotaExceeded "$(code s3 s3 cp "$WORK/400k" s3://qbk/d)"
check "mc put rejected" 1 "$(ok "$MC" cp "$WORK/400k" z/qbk/e)"
check "other buckets unaffected" 200 "$(rawput "$EP/free/x" "$WORK/700k")"

# Overwrite in an unversioned bucket replaces bytes; delete frees them.
check "overwrite within quota" 200 "$(rawput "$EP/qbk/a" "$WORK/400k")"
check "delete frees space" 0 "$(ok s3 s3api delete-object --bucket qbk --key b)"
check "usage after delete" 400000 "$(usage_of qbk)"
check "put fits after delete" 200 "$(rawput "$EP/qbk/b" "$WORK/400k")"

# Copy into the bucket is limited too.
check "copy over quota rejected" QuotaExceeded "$(code s3 s3api copy-object --bucket qbk --key copied --copy-source free/x)"

# Multipart: parts are checked as they arrive, complete re-checks the total.
"$MC" quota set z/qbk --size 20MiB >/dev/null
check "multipart under quota" 0 "$(ok s3 s3 cp "$WORK/12m" s3://qbk/mp1)"
check "multipart over quota" QuotaExceeded "$(code s3 s3 cp "$WORK/12m" s3://qbk/mp2)"
UP="$(s3 s3api create-multipart-upload --bucket qbk --key mp3 --query UploadId --output text)"
check "upload part over quota" QuotaExceeded "$(code s3 s3api upload-part --bucket qbk --key mp3 --upload-id "$UP" --part-number 1 --body "$WORK/12m")"
s3 s3api abort-multipart-upload --bucket qbk --key mp3 --upload-id "$UP" >/dev/null

# Versioned buckets count every version.
"$MC" mb z/vqb >/dev/null
"$MC" version enable z/vqb >/dev/null
"$MC" quota set z/vqb --size 1MiB >/dev/null
rawput "$EP/vqb/k" "$WORK/400k" >/dev/null
rawput "$EP/vqb/k" "$WORK/400k" >/dev/null
check "noncurrent versions count" 800000 "$(usage_of vqb)"
check "versioned overwrite past quota" 400 "$(rawput "$EP/vqb/k" "$WORK/400k")"
check "delete marker frees nothing" 0 "$(ok s3 s3api delete-object --bucket vqb --key k)"
check "usage after delete marker" 800000 "$(usage_of vqb)"

# Clear, admin authorization, persistence.
check "quota clear" 0 "$(ok "$MC" quota clear z/vqb)"
check "cleared quota allows writes" 200 "$(rawput "$EP/vqb/k" "$WORK/400k")"
check "cleared quota info fails" 1 "$(ok "$MC" quota info z/vqb)"
"$MC" admin user add z quser quser-secret1 >/dev/null
"$MC" admin policy attach z readwrite --user quser >/dev/null
check "non-admin cannot set quota" 403 "$(curl -s -o /dev/null -w '%{http_code}' -X PUT --aws-sigv4 aws:amz:us-east-1:s3 --user quser:quser-secret1 -d '{"size":1}' "$EP/minio/admin/v3/set-bucket-quota?bucket=qbk")"
"$MC" quota set z/qbk --size 1MiB >/dev/null
stop
start
check "quota persists across restart" 1048576 "$("$MC" quota info z/qbk --json | jfield '["quota"]')"
check "usage rebuilt after restart" 400 "$(rawput "$EP/qbk/z" "$WORK/400k")"
stop

# ---------------------------------------------------------------- cluster
P1="$(freeport)"
P2="$(freeport)"
POOL=("http://127.0.0.1:$P1$WORK/c1/d{1...3}" "http://127.0.0.1:$P2$WORK/c2/d{1...3}")
for p in "$P1" "$P2"; do
  ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$BIN" --data "${POOL[@]}" --listen "127.0.0.1:$p" \
    --node-address "127.0.0.1:$p" --protection EC:4+2 --cluster-refresh 2 >>"$WORK/cluster.log" 2>&1 &
  CPIDS+=($!)
done
for p in "$P1" "$P2"; do
  for _ in $(seq 600); do [[ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/health/ready")" == 200 ]] && break; sleep 0.1; done
done
"$MC" alias set c1 "http://127.0.0.1:$P1" "$AK" "$SK" >/dev/null
"$MC" alias set c2 "http://127.0.0.1:$P2" "$AK" "$SK" >/dev/null
"$MC" mb c1/cqb >/dev/null
check "cluster quota set on node 1" 0 "$(ok "$MC" quota set c1/cqb --size 1MiB)"
check "cluster quota visible on node 2" 1048576 "$("$MC" quota info c2/cqb --json | jfield '["quota"]')"
check "cluster put on node 1" 200 "$(rawput "http://127.0.0.1:$P1/cqb/a" "$WORK/700k")"
sleep 0.5
check "cluster put on node 2 sees node 1 usage" 400 "$(rawput "http://127.0.0.1:$P2/cqb/b" "$WORK/700k")"
check "cluster delete on node 2" 0 "$(ok "$MC" rm c2/cqb/a)"
sleep 0.5
check "cluster put on node 1 after delete" 200 "$(rawput "http://127.0.0.1:$P1/cqb/b" "$WORK/700k")"

echo "quota: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
