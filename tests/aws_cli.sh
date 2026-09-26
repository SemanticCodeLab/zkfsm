#!/usr/bin/env bash
# SigV4 end-to-end: aws CLI and mc against a zkfsm started with root credentials.
set -euo pipefail
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
aws_() { aws --endpoint-url "$EP" "$@"; }
code() { curl -s "$@" | sed -n 's|.*<Code>\([^<]*\)</Code>.*|\1|p'; }

(cd "$ROOT" && zig build)
BIN="$ROOT/zig-out/bin/zkfsm"

# Startup policy: no credentials refuses to start unless --anonymous.
set +e
env -u ZKFSM_ACCESS_KEY -u ZKFSM_SECRET_KEY -u MINIO_ROOT_USER -u MINIO_ROOT_PASSWORD \
  "$BIN" --data "$DATA" --listen "127.0.0.1:$PORT" 2>/dev/null
check "refuses to start without credentials" 2 "$?"
set -e

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

# aws CLI
check "aws mb" 0 "$(aws_ s3 mb s3://awsb >/dev/null; echo $?)"
check "aws cp small" 0 "$(aws_ s3 cp "$WORK/small.txt" s3://awsb/small.txt >/dev/null; echo $?)"
check "aws put-object" 0 "$(aws_ s3api put-object --bucket awsb --key dir/big.bin --body "$WORK/big.bin" >/dev/null; echo $?)"
check "aws ls" 1 "$(aws_ s3 ls s3://awsb/ | grep -c 'small.txt')"
check "aws ls recursive" 2 "$(aws_ s3 ls --recursive s3://awsb/ | wc -l)"
aws_ s3api get-object --bucket awsb --key dir/big.bin "$WORK/got.bin" >/dev/null
check "aws get-object md5" "$MD5" "$(md5sum "$WORK/got.bin" | cut -d' ' -f1)"
check "aws cp download" "hello zkfsm" "$(aws_ s3 cp s3://awsb/small.txt -)"

URL=$(aws_ s3 presign s3://awsb/small.txt --expires-in 300)
check "presigned curl" "hello zkfsm" "$(curl -s "$URL")"
check "presigned tampered" SignatureDoesNotMatch "$(code "${URL/small.txt/other.txt}")"
check "presigned wrong method" 403 "$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$URL")"

check "aws rm" 0 "$(aws_ s3 rm s3://awsb/small.txt >/dev/null; echo $?)"
check "aws get removed" 404 "$(curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 aws:amz:us-east-1:s3 --user "$AK:$SK" "$EP/awsb/small.txt")"

# Payload hash mismatch: signed header claims one body, a different one is sent.
check "sha256 mismatch" XAmzContentSHA256Mismatch "$(code --aws-sigv4 aws:amz:us-east-1:s3 --user "$AK:$SK" \
  -H "x-amz-content-sha256: $(echo -n expected | sha256sum | cut -d' ' -f1)" -X PUT --data-binary actual "$EP/awsb/mm")"

# mc (uses aws-chunked signed streaming for uploads)
if [[ -n "$MC" ]] && "$MC" --version 2>/dev/null | grep -q RELEASE; then
mc() { "$MC" "$@"; }
mc alias set zk "$EP" "$AK" "$SK" --api S3v4 --path on >/dev/null
check "mc mb" 0 "$(mc mb zk/mcb >/dev/null; echo $?)"
check "mc cp" 0 "$(mc cp "$WORK/big.bin" zk/mcb/big.bin >/dev/null; echo $?)"
check "mc pipe" 0 "$(mc pipe zk/mcb/piped.txt <"$WORK/small.txt" >/dev/null; echo $?)"
check "mc cat md5" "$MD5" "$(mc cat zk/mcb/big.bin | md5sum | cut -d' ' -f1)"
check "mc cat piped" "hello zkfsm" "$(mc cat zk/mcb/piped.txt)"
check "mc ls" 2 "$(mc ls zk/mcb | wc -l)"
check "mc rm" 0 "$(mc rm zk/mcb/big.bin zk/mcb/piped.txt >/dev/null; echo $?)"
check "mc ls empty" 0 "$(mc ls zk/mcb | wc -l)"
URL=$(mc share download --expire 5m --json zk/awsb/dir/big.bin | sed -n 's/.*"share":"\([^"]*\)".*/\1/p')
check "mc presigned curl" "$MD5" "$(curl -s "$URL" | md5sum | cut -d' ' -f1)"
else
  fail=$((fail + 1)); echo "FAIL mc: MinIO client not found (set MC=/path/to/mc)"
fi

# MINIO_ROOT_* aliases.
kill "$PID"; wait "$PID" 2>/dev/null || true
MINIO_ROOT_USER="$AK" MINIO_ROOT_PASSWORD="$SK" "$BIN" --data "$DATA" --listen "127.0.0.1:$PORT" 2>>"$WORK/server.log" &
PID=$!
for _ in $(seq 50); do curl -s -o /dev/null "$EP/" && break; sleep 0.1; done
check "minio alias credentials" 0 "$(aws_ s3 ls s3://awsb/ >/dev/null; echo $?)"

echo "aws_cli: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
