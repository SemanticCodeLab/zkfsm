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
{"format":1,"users":[{"name":"reader","secret":"readersecret","policies":["readonly"]},
  {"name":"writer","secret":"writersecret","policies":["readwrite"]}],
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

# Bucket policies: public read for unsigned requests; a bucket deny beats an identity allow.
ROOTC=(--aws-sigv4 aws:amz:us-east-1:s3 --user "$AK:$SK")
WR=(--aws-sigv4 aws:amz:us-east-1:s3 --user writer:writersecret)
s3cli s3 mb s3://pubb >/dev/null
echo "public body" >"$WORK/pub.txt"
s3cli s3 cp "$WORK/pub.txt" s3://pubb/pub.txt >/dev/null
s3cli s3 cp "$WORK/pub.txt" s3://pubb/keep/x >/dev/null
s3cli s3 cp "$WORK/pub.txt" s3://pubb/tmp/x >/dev/null
check "unsigned get before policy" 403 "$(curl -s -o /dev/null -w '%{http_code}' "$EP/pubb/pub.txt")"
POLICY='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::pubb/*"},{"Effect":"Deny","Principal":{"AWS":"*"},"Action":"s3:DeleteObject","Resource":"arn:aws:s3:::pubb/keep/*"}]}'
check "cli put-bucket-policy" 0 "$(s3cli s3api put-bucket-policy --bucket pubb --policy "$POLICY" >/dev/null; echo $?)"
check "cli get-bucket-policy" 1 "$(s3cli s3api get-bucket-policy --bucket pubb --query Policy --output text | grep -c 'pubb/keep')"
check "cli policy status" "True" "$(s3cli s3api get-bucket-policy-status --bucket pubb --query PolicyStatus.IsPublic --output text)"
check "unsigned get public-read" "public body" "$(curl -s "$EP/pubb/pub.txt")"
check "unsigned head public-read" 200 "$(curl -s -o /dev/null -w '%{http_code}' -I "$EP/pubb/pub.txt")"
check "unsigned put denied" AccessDenied "$(code -X PUT --data-binary x "$EP/pubb/new.txt")"
check "unsigned list denied" 403 "$(curl -s -o /dev/null -w '%{http_code}' "$EP/pubb?list-type=2")"
check "unsigned get other bucket" 403 "$(curl -s -o /dev/null -w '%{http_code}' "$EP/clib/dir/big.bin")"
check "bad signature still rejected" SignatureDoesNotMatch "$(code --aws-sigv4 aws:amz:us-east-1:s3 --user "$AK:nope" "$EP/pubb/pub.txt")"
check "bucket deny beats identity allow" AccessDenied "$(code "${WR[@]}" -X DELETE "$EP/pubb/keep/x")"
check "identity allow outside deny" 204 "$(curl -s -o /dev/null -w '%{http_code}' "${WR[@]}" -X DELETE "$EP/pubb/tmp/x")"
check "root not bound by bucket deny" 204 "$(curl -s -o /dev/null -w '%{http_code}' "${ROOTC[@]}" -X DELETE "$EP/pubb/keep/x")"
check "malformed policy" 1 "$(s3cli s3api put-bucket-policy --bucket pubb --policy '{"Statement":[]}' 2>&1 | grep -c MalformedPolicy)"
check "cli delete-bucket-policy" 0 "$(s3cli s3api delete-bucket-policy --bucket pubb >/dev/null; echo $?)"
check "unsigned get after delete" 403 "$(curl -s -o /dev/null -w '%{http_code}' "$EP/pubb/pub.txt")"
check "no policy" 1 "$(s3cli s3api get-bucket-policy --bucket pubb 2>&1 | grep -c NoSuchBucketPolicy)"

# Lifecycle configuration through the CLI.
LCJ='{"Rules":[{"ID":"logs","Filter":{"And":{"Prefix":"logs/","Tags":[{"Key":"t","Value":"1"}],"ObjectSizeGreaterThan":10}},"Status":"Enabled","Expiration":{"Days":30},"NoncurrentVersionExpiration":{"NoncurrentDays":7,"NewerNoncurrentVersions":3}},{"ID":"mpu","Filter":{"Prefix":""},"Status":"Enabled","AbortIncompleteMultipartUpload":{"DaysAfterInitiation":2}},{"ID":"dm","Filter":{},"Status":"Disabled","Expiration":{"ExpiredObjectDeleteMarker":true}}]}'
check "cli put lifecycle" 0 "$(s3cli s3api put-bucket-lifecycle-configuration --bucket pubb --lifecycle-configuration "$LCJ" >/dev/null; echo $?)"
check "cli get lifecycle ids" "logs mpu dm" "$(s3cli s3api get-bucket-lifecycle-configuration --bucket pubb --query 'Rules[].ID' --output text | xargs)"
check "cli get lifecycle filter" 10 "$(s3cli s3api get-bucket-lifecycle-configuration --bucket pubb --query 'Rules[0].Filter.And.ObjectSizeGreaterThan' --output text)"
check "cli get lifecycle newer noncurrent" 3 "$(s3cli s3api get-bucket-lifecycle-configuration --bucket pubb --query 'Rules[0].NoncurrentVersionExpiration.NewerNoncurrentVersions' --output text)"
TRJ='{"Rules":[{"ID":"t","Filter":{"Prefix":""},"Status":"Enabled","Transitions":[{"Days":30,"StorageClass":"STANDARD_IA"}]}]}'
check "cli lifecycle transition rejected" 1 "$(s3cli s3api put-bucket-lifecycle-configuration --bucket pubb --lifecycle-configuration "$TRJ" 2>&1 | grep -c NotImplemented)"
check "cli delete lifecycle" 0 "$(s3cli s3api delete-bucket-lifecycle --bucket pubb >/dev/null; echo $?)"
check "cli lifecycle gone" 1 "$(s3cli s3api get-bucket-lifecycle-configuration --bucket pubb 2>&1 | grep -c NoSuchLifecycleConfiguration)"

# ACLs, ListObjects v1, and part reads through the CLI.
check "cli get-bucket-acl" "zkfsm" "$(s3cli s3api get-bucket-acl --bucket pubb --query Owner.ID --output text)"
check "cli get-object-acl" "FULL_CONTROL" "$(s3cli s3api get-object-acl --bucket pubb --key pub.txt --query 'Grants[0].Permission' --output text)"
check "cli put-object-acl private" 0 "$(s3cli s3api put-object-acl --bucket pubb --key pub.txt --acl private >/dev/null; echo $?)"
check "cli put-bucket-acl public rejected" 1 "$(s3cli s3api put-bucket-acl --bucket pubb --acl public-read 2>&1 | grep -c NotImplemented)"
for k in a b c d e; do s3cli s3api put-object --bucket pubb --key "v1/$k" --body "$WORK/pub.txt" >/dev/null; done
check "cli list-objects v1 paginated" 5 "$(s3cli s3api list-objects --bucket pubb --prefix v1/ --page-size 2 --query 'Contents[].Key' --output text | wc -w)"
check "cli list-objects v1 delimiter" "v1/" "$(s3cli s3api list-objects --bucket pubb --delimiter / --query 'CommonPrefixes[0].Prefix' --output text)"
head -c 12000000 /dev/urandom >"$WORK/parts.bin"
s3cli s3 cp "$WORK/parts.bin" s3://pubb/parts.bin >/dev/null
check "cli head part count" 2 "$(s3cli s3api head-object --bucket pubb --key parts.bin --part-number 1 --query PartsCount --output text)"
s3cli s3api get-object --bucket pubb --key parts.bin --part-number 2 "$WORK/part2.bin" >/dev/null
check "cli get part 2" "$(tail -c +8388609 "$WORK/parts.bin" | md5sum)" "$(md5sum <"$WORK/part2.bin")"
rm -f "$WORK/parts.bin" "$WORK/part2.bin"

# MINIO_ROOT_* aliases.
kill "$PID"; wait "$PID" 2>/dev/null || true
MINIO_ROOT_USER="$AK" MINIO_ROOT_PASSWORD="$SK" "$BIN" --data "$DATA" --listen "127.0.0.1:$PORT" 2>>"$WORK/server.log" &
PID=$!
for _ in $(seq 50); do curl -s -o /dev/null "$EP/" && break; sleep 0.1; done
check "minio alias credentials" 0 "$(s3cli s3 ls s3://clib/ >/dev/null; echo $?)"

# Base path, virtual hosts, and custom operational paths.
kill "$PID"; wait "$PID" 2>/dev/null || true
ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" ZKFSM_PATH_PREFIX=/s3 "$BIN" --data "$DATA" --listen "127.0.0.1:$PORT" \
  --domain s3.local --health-prefix /ops/health --metrics-path /ops/metrics --no-minio-compat 2>>"$WORK/server.log" &
PID=$!
for _ in $(seq 50); do curl -s -o /dev/null "$EP/ops/health/live" && break; sleep 0.1; done
check "custom health live" 200 "$(curl -s -o /dev/null -w '%{http_code}' "$EP/ops/health/live")"
check "custom health ready" 200 "$(curl -s -o /dev/null -w '%{http_code}' "$EP/ops/health/ready")"
check "custom metrics" 1 "$(curl -s "$EP/ops/metrics" | grep -c '^zkfsm_requests_total{code="2xx"}')"
check "default health moved" 404 "$(curl -s -o /dev/null -w '%{http_code}' "$EP/health/live")"
check "minio health disabled" 404 "$(curl -s -o /dev/null -w '%{http_code}' "$EP/minio/health/live")"
check "outside prefix" NoSuchBucket "$(code "${ROOTC[@]}" "$EP/clib/dir/big.bin")"
PEP="$EP/s3"
check "prefix cli ls" 1 "$(s3cli --endpoint-url "$PEP" s3 ls s3://clib/ | grep -c 'dir/')"
check "prefix cli cp" 0 "$(s3cli --endpoint-url "$PEP" s3 cp "$WORK/small.txt" s3://clib/prefixed.txt >/dev/null; echo $?)"
check "prefix cli get" "hello zkfsm" "$(s3cli --endpoint-url "$PEP" s3 cp s3://clib/prefixed.txt -)"
check "prefix curl sigv4" "hello zkfsm" "$(curl -s "${ROOTC[@]}" "$PEP/clib/prefixed.txt")"
URL=$(s3cli --endpoint-url "$PEP" s3 presign s3://clib/prefixed.txt --expires-in 300)
check "prefix presigned" "hello zkfsm" "$(curl -s "$URL")"
check "prefix presigned tampered" SignatureDoesNotMatch "$(code "${URL/prefixed.txt/other.txt}")"
# Virtual-host style without DNS: the CLI sends absolute-form requests through the server as its proxy.
VCONF="$WORK/virtual.conf"
printf '[default]\ns3 =\n  addressing_style = virtual\n' >"$VCONF"
vcli() { AWS_CONFIG_FILE="$VCONF" HTTP_PROXY="$EP" http_proxy="$EP" NO_PROXY= no_proxy= "$S3CLI_BIN" --endpoint-url "http://s3.local:$PORT/s3" "$@"; }
check "vhost cli cp" 0 "$(vcli s3 cp "$WORK/small.txt" s3://clib/vhost.txt >/dev/null; echo $?)"
check "vhost cli get" "hello zkfsm" "$(vcli s3 cp s3://clib/vhost.txt -)"
check "vhost cli ls" 1 "$(vcli s3 ls s3://clib/ | grep -c vhost.txt)"
check "vhost curl resolve" "hello zkfsm" "$(curl -s "${ROOTC[@]}" --resolve "clib.s3.local:$PORT:127.0.0.1" "http://clib.s3.local:$PORT/s3/vhost.txt")"
check "vhost curl host header" "hello zkfsm" "$(curl -s "${ROOTC[@]}" -H "Host: clib.s3.local:$PORT" "$PEP/vhost.txt")"
# mc refuses endpoint URLs with a path, so it cannot use a base path; it is checked
# with virtual-host addressing (through the server as proxy) on a root-path server.
kill "$PID"; wait "$PID" 2>/dev/null || true
ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$BIN" --data "$DATA" --listen "127.0.0.1:$PORT" --domain s3.local 2>>"$WORK/server.log" &
PID=$!
for _ in $(seq 50); do curl -s -o /dev/null "$EP/health/live" && break; sleep 0.1; done
check "mc rejects base path" 1 "$("$MC" alias set zkp "$PEP" "$AK" "$SK" --api S3v4 2>&1 | grep -c 'without resource component')"
if [[ -n "$MC" ]] && "$MC" --version 2>/dev/null | grep -q RELEASE; then
  vmc() { HTTP_PROXY="$EP" http_proxy="$EP" NO_PROXY= no_proxy= "$MC" "$@"; }
  check "vhost mc alias" 0 "$(vmc alias set zkv "http://s3.local:$PORT" "$AK" "$SK" --api S3v4 --path off >/dev/null 2>"$WORK/mc.err"; echo $?)"
  check "vhost mc cat" "hello zkfsm" "$(vmc cat zkv/clib/prefixed.txt 2>>"$WORK/mc.err")"
  check "vhost mc cp" 0 "$(vmc cp "$WORK/small.txt" zkv/clib/mc-vhost.txt >/dev/null 2>>"$WORK/mc.err"; echo $?)"
  check "vhost mc ls" 1 "$(vmc ls zkv/clib 2>>"$WORK/mc.err" | grep -c mc-vhost.txt)"
  URL=$(vmc share download --expire 5m --json zkv/clib/prefixed.txt 2>>"$WORK/mc.err" | sed -n 's/.*"share":"\([^"]*\)".*/\1/p')
  check "vhost mc presigned" "hello zkfsm" "$(curl -s --proxy "$EP" "$URL")"
  [[ -s "$WORK/mc.err" ]] && cat "$WORK/mc.err"
fi

echo "s3cli: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
