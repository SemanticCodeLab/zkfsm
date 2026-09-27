#!/usr/bin/env bash
# SigV4 end-to-end: an S3 CLI and mc against a zkfsm started with root credentials.
set -euo pipefail
S3CLI_BIN="${S3CLI_BIN:-aws}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')"
EP="http://127.0.0.1:$PORT"
DATA="$(mktemp -d)"
WORK="$(mktemp -d)"
PID=""
cleanup() { [[ -n "$PID" ]] && kill "$PID" 2>/dev/null || true; rm -rf "$DATA" "$WORK"; }
trap cleanup EXIT

AK="zkfsmtestaccess"
SK="zkfsm/test+secret0123456789"
export AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_DEFAULT_REGION=us-east-1
export AWS_CONFIG_FILE="$WORK/aws.conf" AWS_SHARED_CREDENTIALS_FILE="$WORK/aws.creds" AWS_PAGER=""
printf '[default]\ns3 =\n  addressing_style = path\n' >"$AWS_CONFIG_FILE"
export MC_CONFIG_DIR="$WORK/mc"
# MinIO client; some distros ship Midnight Commander as `mc`, so MC can point elsewhere.
MC="${MC:-$(command -v mc || true)}"

pass=0
fail=0
check() { # name expected actual
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); echo "ok   $1"
  else fail=$((fail + 1)); echo "FAIL $1: expected [$2] got [$3]"; fi
}
s3cli() { "$S3CLI_BIN" --endpoint-url "$EP" "$@"; }
code() { curl -s "$@" | sed -n 's|.*<Code>\([^<]*\)</Code>.*|\1|p'; }

(cd "$ROOT" && zig build)
BIN="$ROOT/zig-out/bin/zkfsm"

# Startup policy: no credentials refuses to start unless --anonymous.
set +e
env -u ZKFSM_ACCESS_KEY -u ZKFSM_SECRET_KEY -u MINIO_ROOT_USER -u MINIO_ROOT_PASSWORD \
  "$BIN" --data "$DATA" --listen "127.0.0.1:$PORT" 2>/dev/null
check "refuses to start without credentials" 2 "$?"
set -e

# IAM store seeded with a readonly user and a service account under it.
mkdir -p "$DATA/.zkfsm"
cat >"$DATA/.zkfsm/iam.json" <<'JSON'
{"format":1,"users":[{"name":"reader","secret":"readersecret","policies":["readonly"]}],
 "service_accounts":[{"access_key":"svcreader","secret":"svcsecret1","parent":"reader"}]}
JSON
ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$BIN" --data "$DATA" --listen "127.0.0.1:$PORT" 2>"$WORK/server.log" &
PID=$!
for _ in $(seq 50); do curl -s -o /dev/null "$EP/" && break; sleep 0.1; done

check "anonymous request denied" AccessDenied "$(code "$EP/")"
check "anonymous status 403" 403 "$(curl -s -o /dev/null -w '%{http_code}' "$EP/")"
check "curl sigv4 list" 200 "$(curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 aws:amz:us-east-1:s3 --user "$AK:$SK" "$EP/")"
check "wrong secret" SignatureDoesNotMatch "$(code --aws-sigv4 aws:amz:us-east-1:s3 --user "$AK:nope" "$EP/")"
check "unknown access key" InvalidAccessKeyId "$(code --aws-sigv4 aws:amz:us-east-1:s3 --user "someone:$SK" "$EP/")"

head -c 5000000 /dev/urandom >"$WORK/big.bin"
echo "hello zkfsm" >"$WORK/small.txt"
MD5=$(md5sum "$WORK/big.bin" | cut -d' ' -f1)

# S3 CLI
check "cli mb" 0 "$(s3cli s3 mb s3://clib >/dev/null; echo $?)"
check "cli cp small" 0 "$(s3cli s3 cp "$WORK/small.txt" s3://clib/small.txt >/dev/null; echo $?)"
check "cli put-object" 0 "$(s3cli s3api put-object --bucket clib --key dir/big.bin --body "$WORK/big.bin" >/dev/null; echo $?)"
check "cli ls" 1 "$(s3cli s3 ls s3://clib/ | grep -c 'small.txt')"
check "cli ls recursive" 2 "$(s3cli s3 ls --recursive s3://clib/ | wc -l)"
s3cli s3api get-object --bucket clib --key dir/big.bin "$WORK/got.bin" >/dev/null
check "cli get-object md5" "$MD5" "$(md5sum "$WORK/got.bin" | cut -d' ' -f1)"
check "cli cp download" "hello zkfsm" "$(s3cli s3 cp s3://clib/small.txt -)"

# User metadata: put, head, copy with REPLACE, multipart via s3 cp.
s3cli s3api put-object --bucket clib --key meta.txt --body "$WORK/small.txt" --metadata k=v,Other=x --cache-control no-cache >/dev/null
check "cli head metadata" "v" "$(s3cli s3api head-object --bucket clib --key meta.txt --query Metadata.k --output text)"
check "cli head cache-control" "no-cache" "$(s3cli s3api head-object --bucket clib --key meta.txt --query CacheControl --output text)"
s3cli s3api copy-object --bucket clib --key meta.txt --copy-source clib/meta.txt --metadata-directive REPLACE --metadata k=w >/dev/null
check "cli copy replace metadata" "w" "$(s3cli s3api head-object --bucket clib --key meta.txt --query Metadata.k --output text)"
check "cli copy replace drops old" "None" "$(s3cli s3api head-object --bucket clib --key meta.txt --query Metadata.other --output text)"
head -c 12000000 /dev/urandom >"$WORK/mp.bin" # over the CLI's 8 MB multipart threshold
s3cli s3 cp "$WORK/mp.bin" s3://clib/mp.bin --metadata mk=mv >/dev/null
check "cli multipart etag" 1 "$(s3cli s3api head-object --bucket clib --key mp.bin --query ETag --output text | grep -c -- '-')"
check "cli multipart metadata" "mv" "$(s3cli s3api head-object --bucket clib --key mp.bin --query Metadata.mk --output text)"
s3cli s3 rm s3://clib/meta.txt >/dev/null
s3cli s3 rm s3://clib/mp.bin >/dev/null

URL=$(s3cli s3 presign s3://clib/small.txt --expires-in 300)
check "presigned curl" "hello zkfsm" "$(curl -s "$URL")"
check "presigned tampered" SignatureDoesNotMatch "$(code "${URL/small.txt/other.txt}")"
check "presigned wrong method" 403 "$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$URL")"

# Service account inherits the readonly policy: GET allowed, PUT denied.
SA=(--aws-sigv4 aws:amz:us-east-1:s3 --user svcreader:svcsecret1)
check "service account GET" "hello zkfsm" "$(curl -s "${SA[@]}" "$EP/clib/small.txt")"
check "service account PUT denied" AccessDenied "$(code "${SA[@]}" -X PUT --data-binary x "$EP/clib/sa.txt")"
check "service account aws cp denied" 1 "$(AWS_ACCESS_KEY_ID=svcreader AWS_SECRET_ACCESS_KEY=svcsecret1 s3cli s3 cp "$WORK/small.txt" s3://clib/sa.txt >/dev/null 2>&1; echo $?)"
check "service account DELETE denied" 403 "$(curl -s -o /dev/null -w '%{http_code}' "${SA[@]}" -X DELETE "$EP/clib/small.txt")"
check "health unauthenticated" 200 "$(curl -s -o /dev/null -w '%{http_code}' "$EP/health/live")"
check "metrics unauthenticated" 200 "$(curl -s -o /dev/null -w '%{http_code}' "$EP/metrics")"

check "cli rm" 0 "$(s3cli s3 rm s3://clib/small.txt >/dev/null; echo $?)"
check "cli get removed" 404 "$(curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 aws:amz:us-east-1:s3 --user "$AK:$SK" "$EP/clib/small.txt")"

# Payload hash mismatch: signed header claims one body, a different one is sent.
check "sha256 mismatch" XAmzContentSHA256Mismatch "$(code --aws-sigv4 aws:amz:us-east-1:s3 --user "$AK:$SK" \
  -H "x-amz-content-sha256: $(echo -n expected | sha256sum | cut -d' ' -f1)" -X PUT --data-binary actual "$EP/clib/mm")"

# mc (uses chunked signed streaming for uploads)
if [[ -n "$MC" ]] && "$MC" --version 2>/dev/null | grep -q RELEASE; then
mc() { "$MC" "$@"; }
mc alias set zk "$EP" "$AK" "$SK" --api S3v4 --path on >/dev/null
check "mc mb" 0 "$(mc mb zk/mcb >/dev/null; echo $?)"
check "mc cp" 0 "$(mc cp "$WORK/big.bin" zk/mcb/big.bin >/dev/null; echo $?)"
check "mc cp small" 0 "$(mc cp "$WORK/small.txt" zk/mcb/small.txt >/dev/null; echo $?)"
check "mc cat md5" "$MD5" "$(mc cat zk/mcb/big.bin | md5sum | cut -d' ' -f1)"
check "mc cat small" "hello zkfsm" "$(mc cat zk/mcb/small.txt)"
check "mc ls" 2 "$(mc ls zk/mcb | wc -l)"
# mc rm sends DeleteObjects (POST ?delete), which zkfsm does not serve yet.
s3cli s3 rm s3://mcb/big.bin >/dev/null
check "mc ls after rm" 1 "$(mc ls zk/mcb | wc -l)"
URL=$(mc share download --expire 5m --json zk/clib/dir/big.bin | sed -n 's/.*"share":"\([^"]*\)".*/\1/p')
check "mc presigned curl" "$MD5" "$(curl -s "$URL" | md5sum | cut -d' ' -f1)"
else
  fail=$((fail + 1)); echo "FAIL mc: MinIO client not found (set MC=/path/to/mc)"
fi

# MINIO_ROOT_* aliases.
kill "$PID"; wait "$PID" 2>/dev/null || true
MINIO_ROOT_USER="$AK" MINIO_ROOT_PASSWORD="$SK" "$BIN" --data "$DATA" --listen "127.0.0.1:$PORT" 2>>"$WORK/server.log" &
PID=$!
for _ in $(seq 50); do curl -s -o /dev/null "$EP/" && break; sleep 0.1; done
check "minio alias credentials" 0 "$(s3cli s3 ls s3://clib/ >/dev/null; echo $?)"

echo "s3cli: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
