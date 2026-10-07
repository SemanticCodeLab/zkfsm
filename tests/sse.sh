#!/usr/bin/env bash
# Server-side encryption end to end: SSE-S3, SSE-KMS, SSE-C on single and
# multipart objects, CopyObject/UploadPartCopy, bucket default encryption,
# plaintext size/ETag reporting, ciphertext on disk, mc encrypt, and the
# no-KMS behaviour (SSE-C works, SSE-S3/SSE-KMS refused, nothing stored).
set -euo pipefail
S3CLI_BIN="${S3CLI_BIN:-aws}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')"
EP="http://127.0.0.1:$PORT"
WORK="$(mktemp -d)"
PID=""
stop() { if [[ -n "$PID" ]] && kill -0 "$PID" 2>/dev/null; then kill "$PID"; wait "$PID" 2>/dev/null || true; fi; PID=""; }
cleanup() { stop; rm -rf "$WORK"; }
trap cleanup EXIT

AK="zkfsmsseaccess"
SK="zkfsm-sse-secret-123"
export ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK"
export AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_DEFAULT_REGION=us-east-1
export AWS_CONFIG_FILE="$WORK/aws.conf" AWS_SHARED_CREDENTIALS_FILE="$WORK/aws.creds" AWS_PAGER="" AWS_EC2_METADATA_DISABLED=true
printf '[default]\ns3 =\n  addressing_style = path\n' >"$AWS_CONFIG_FILE"
export MC_CONFIG_DIR="$WORK/mc"
MC="${MC:-$(command -v mc || true)}"

fail() { echo "FAIL: $*" >&2; [[ -f "$WORK/server.log" ]] && tail -20 "$WORK/server.log" >&2; exit 1; }
ok() { echo "ok   $*"; }
s3api() { "$S3CLI_BIN" --endpoint-url "$EP" s3api "$@"; }
s3cp() { "$S3CLI_BIN" --endpoint-url "$EP" s3 "$@"; }
sigcurl() { curl -s --aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" "$@"; }

(cd "$ROOT" && zig build)
BIN="$ROOT/zig-out/bin/zkfsm"
start() { # log, extra flags...
  local log=$1; shift
  "$BIN" --data "$WORK/data" --listen "127.0.0.1:$PORT" --scan-interval 0 "$@" >"$WORK/$log" 2>&1 &
  PID=$!
  for _ in $(seq 100); do curl -s -o /dev/null "$EP/" && return 0; sleep 0.1; done
  fail "server did not start"
}

start server.log --kms-backend local --kms-dir "$WORK/kms"
grep -q "kms backend local" "$WORK/server.log" || fail "kms backend log line"

s3api create-bucket --bucket sse >/dev/null || fail "create bucket"
echo "hello plain" >"$WORK/obj"
s3api put-object --bucket sse --key k1 --body "$WORK/obj" >/dev/null || fail "put plain"
s3api get-object --bucket sse --key k1 "$WORK/obj.out" >"$WORK/plain.head" || fail "get plain"
cmp -s "$WORK/obj" "$WORK/obj.out" || fail "plain object mismatch"
if grep -q ServerSideEncryption "$WORK/plain.head"; then fail "plain object reports SSE"; fi
ok "plain objects untouched"

MARKER="ZKFSM-SSE-PLAINTEXT-MARKER-7f3a"
python3 -c "
import sys
blk = b'$MARKER ' + bytes(range(256)) * 40
sys.stdout.buffer.write(blk * 30)" >"$WORK/secret.bin"
ondisk() { grep -rqa "$MARKER" "$WORK/data"; }
check_sse() { # key expected-algo extra-get-args...
  local key=$1 algo=$2; shift 2
  s3api get-object --bucket sse --key "$key" "$@" "$WORK/$key.out" >"$WORK/$key.head" || fail "get $key"
  cmp -s "$WORK/secret.bin" "$WORK/$key.out" || fail "$key round trip mismatch"
  grep -q "\"$algo\"" "$WORK/$key.head" || fail "$key missing $algo: $(cat "$WORK/$key.head")"
  s3api get-object --bucket sse --key "$key" --range bytes=70000-140000 "$@" "$WORK/$key.rng" >/dev/null || fail "range $key"
  cmp -s <(tail -c +70001 "$WORK/secret.bin" | head -c 70001) "$WORK/$key.rng" || fail "$key range mismatch"
}

s3api put-object --bucket sse --key sse-s3 --body "$WORK/secret.bin" --server-side-encryption AES256 >"$WORK/put.json" || fail "put sse-s3"
grep -q '"ServerSideEncryption": "AES256"' "$WORK/put.json" || fail "put sse-s3 response"
check_sse sse-s3 AES256
s3api head-object --bucket sse --key sse-s3 | grep -q "\"ContentLength\": $(stat -c %s "$WORK/secret.bin")" || fail "head size"
ok "SSE-S3 put/get/range/head"

s3api put-object --bucket sse --key sse-kms --body "$WORK/secret.bin" --server-side-encryption aws:kms >/dev/null || fail "put sse-kms"
check_sse sse-kms aws:kms
s3api head-object --bucket sse --key sse-kms | grep -q '"SSEKMSKeyId": "zkfsm-sse-s3"' || fail "sse-kms key id"
if s3api put-object --bucket sse --key sse-kms-missing --body "$WORK/obj" --server-side-encryption aws:kms \
  --ssekms-key-id no-such-key >/dev/null 2>"$WORK/nokey.err"; then fail "unknown kms key accepted"; fi
grep -q "NotFound" "$WORK/nokey.err" || fail "unknown kms key error: $(cat "$WORK/nokey.err")"
ok "SSE-KMS put/get, unknown key refused"

head -c 32 /dev/urandom >"$WORK/ck.bin"
CK=(--sse-customer-algorithm AES256 --sse-customer-key "fileb://$WORK/ck.bin")
s3api put-object --bucket sse --key sse-c --body "$WORK/secret.bin" "${CK[@]}" >/dev/null || fail "put sse-c"
check_sse sse-c AES256 "${CK[@]}"
if s3api get-object --bucket sse --key sse-c "$WORK/x.out" >/dev/null 2>&1; then fail "sse-c read without key"; fi
head -c 32 /dev/urandom >"$WORK/ck2.bin"
if s3api get-object --bucket sse --key sse-c --sse-customer-algorithm AES256 --sse-customer-key "fileb://$WORK/ck2.bin" \
  "$WORK/x.out" >/dev/null 2>&1; then fail "sse-c read with wrong key"; fi
ok "SSE-C put/get, missing or wrong key refused"

s3api create-bucket --bucket sse-enc >/dev/null
s3api put-bucket-encryption --bucket sse-enc --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' || fail "put bucket encryption"
s3api get-bucket-encryption --bucket sse-enc | grep -q AES256 || fail "get bucket encryption"
s3api put-object --bucket sse-enc --key dflt --body "$WORK/secret.bin" >/dev/null || fail "put default-encrypted"
s3api head-object --bucket sse-enc --key dflt | grep -q '"ServerSideEncryption": "AES256"' || fail "default encryption not applied"
s3api get-object --bucket sse-enc --key dflt "$WORK/dflt.out" >/dev/null && cmp -s "$WORK/secret.bin" "$WORK/dflt.out" || fail "default round trip"
ok "bucket default encryption"

# Plaintext size/ETag reported, content type and user metadata kept, internals hidden.
PMD5=$(md5sum "$WORK/secret.bin" | cut -d' ' -f1)
PSIZE=$(stat -c %s "$WORK/secret.bin")
s3api put-object --bucket sse --key sse-meta --body "$WORK/secret.bin" --server-side-encryption AES256 \
  --content-type text/csv --metadata owner=e2e --cache-control no-cache >/dev/null || fail "put sse-meta"
s3api head-object --bucket sse --key sse-meta >"$WORK/meta.head" || fail "head sse-meta"
grep -q '"ContentType": "text/csv"' "$WORK/meta.head" || fail "content type: $(cat "$WORK/meta.head")"
grep -q '"owner": "e2e"' "$WORK/meta.head" || fail "user metadata"
grep -q '"CacheControl": "no-cache"' "$WORK/meta.head" || fail "system header"
grep -q "\"ETag\": \"\\\\\"$PMD5\\\\\"\"" "$WORK/meta.head" || fail "sse-s3 etag is not the plaintext md5"
if grep -qi "zkfsm-internal\|x-zkfsm" "$WORK/meta.head"; then fail "internal headers exposed"; fi
if sigcurl -I "$EP/sse/sse-meta" | grep -qi "zkfsm"; then fail "internal header on the wire"; fi
s3api list-objects-v2 --bucket sse >"$WORK/list.json" || fail "list"
python3 - "$WORK/list.json" "$PSIZE" "$PMD5" <<'PY' || fail "listing sizes/etags: $(cat "$WORK/list.json")"
import json, sys
objs = {o["Key"]: o for o in json.load(open(sys.argv[1]))["Contents"]}
size, md5 = int(sys.argv[2]), sys.argv[3]
for k in ("sse-s3", "sse-kms", "sse-c", "sse-meta"):
    assert objs[k]["Size"] == size, (k, objs[k])
for k in ("sse-s3", "sse-meta"):
    assert objs[k]["ETag"] == '"%s"' % md5, (k, objs[k])
for k in ("sse-kms", "sse-c"):
    assert objs[k]["ETag"] != '"%s"' % md5, (k, objs[k])
PY
ok "plaintext size/ETag in HEAD and listings, metadata kept"

# Multipart: 50 MB copy into a default-encrypted bucket.
python3 -c "
import sys
blk = b'$MARKER ' + bytes(range(256)) * 4000
out = sys.stdout.buffer
n = 0
while n < 50 * 1024 * 1024:
    b = blk[: 50 * 1024 * 1024 - n]
    out.write(b); n += len(b)" >"$WORK/big.bin"
BSIZE=$(stat -c %s "$WORK/big.bin")
s3cp cp "$WORK/big.bin" s3://sse-enc/big >/dev/null || fail "multipart up"
s3cp cp s3://sse-enc/big "$WORK/big.out" >/dev/null || fail "multipart down"
cmp -s "$WORK/big.bin" "$WORK/big.out" || fail "multipart round trip"
s3api head-object --bucket sse-enc --key big >"$WORK/big.head"
grep -q '"ServerSideEncryption": "AES256"' "$WORK/big.head" || fail "multipart not encrypted"
grep -q "\"ContentLength\": $BSIZE" "$WORK/big.head" || fail "multipart size: $(cat "$WORK/big.head")"
grep -q -- '-[0-9]*\\"",' "$WORK/big.head" || fail "multipart etag: $(cat "$WORK/big.head")"
s3cp ls s3://sse-enc/big | grep -q " $BSIZE big" || fail "ls multipart size"
for r in 0-99 8388000-8389000 8388608-8388608 16000000-26000000 52428700-52428799; do
  s3api get-object --bucket sse-enc --key big --range "bytes=$r" "$WORK/big.rng" >/dev/null || fail "multipart range $r"
  a=${r%-*} b=${r#*-}
  cmp -s <(tail -c +$((a + 1)) "$WORK/big.bin" | head -c $((b - a + 1))) "$WORK/big.rng" || fail "multipart range $r mismatch"
done
ok "SSE multipart upload, size, ETag, ranges across parts"

s3cp cp "$WORK/big.bin" s3://sse/big-kms --sse aws:kms >/dev/null || fail "kms multipart up"
s3api head-object --bucket sse --key big-kms | grep -q '"ServerSideEncryption": "aws:kms"' || fail "kms multipart header"
s3cp cp s3://sse/big-kms s3://sse/big-copy --sse AES256 >/dev/null || fail "multipart copy"
s3cp cp s3://sse/big-copy "$WORK/big-copy.out" >/dev/null || fail "multipart copy down"
cmp -s "$WORK/big.bin" "$WORK/big-copy.out" || fail "multipart copy mismatch"
s3api head-object --bucket sse --key big-copy >"$WORK/bc.head"
grep -q '"ServerSideEncryption": "AES256"' "$WORK/bc.head" || fail "multipart copy header"
grep -q -- '-[0-9]*\\"",' "$WORK/bc.head" || fail "copy did not use UploadPartCopy"
ok "SSE-KMS multipart, UploadPartCopy re-encrypted"

head -c 131072 "$WORK/big.bin" >"$WORK/exact.bin"
s3api put-object --bucket sse --key exact --body "$WORK/exact.bin" --server-side-encryption AES256 >/dev/null || fail "put exact"
s3api get-object --bucket sse --key exact "$WORK/exact.out" >"$WORK/exact.head" || fail "get exact"
cmp -s "$WORK/exact.bin" "$WORK/exact.out" || fail "exact round trip"
grep -q "$(md5sum "$WORK/exact.bin" | cut -d' ' -f1)" "$WORK/exact.head" || fail "exact etag"
touch "$WORK/empty.bin"
s3api put-object --bucket sse --key empty --body "$WORK/empty.bin" --server-side-encryption AES256 >/dev/null || fail "put empty"
s3api get-object --bucket sse --key empty "$WORK/empty.out" >/dev/null || fail "get empty"
[[ ! -s "$WORK/empty.out" ]] || fail "empty object not empty"
ok "package-size multiples and empty objects"

head -c $((5 * 1024 * 1024 + 11)) "$WORK/big.bin" >"$WORK/p1.bin"
printf 'tail-part' >"$WORK/p2.bin"
uid=$(s3api create-multipart-upload --bucket sse --key mp-c "${CK[@]}" --query UploadId --output text) || fail "create sse-c upload"
if s3api upload-part --bucket sse --key mp-c --upload-id "$uid" --part-number 1 --body "$WORK/p1.bin" >/dev/null 2>&1; then
  fail "sse-c part accepted without key"
fi
e1=$(s3api upload-part --bucket sse --key mp-c --upload-id "$uid" --part-number 1 --body "$WORK/p1.bin" "${CK[@]}" --query ETag --output text) || fail "part 1"
e2=$(s3api upload-part --bucket sse --key mp-c --upload-id "$uid" --part-number 2 --body "$WORK/p2.bin" "${CK[@]}" --query ETag --output text) || fail "part 2"
s3api complete-multipart-upload --bucket sse --key mp-c --upload-id "$uid" \
  --multipart-upload "{\"Parts\":[{\"PartNumber\":1,\"ETag\":$e1},{\"PartNumber\":2,\"ETag\":$e2}]}" >/dev/null || fail "sse-c complete"
cat "$WORK/p1.bin" "$WORK/p2.bin" >"$WORK/mpc.bin"
s3api get-object --bucket sse --key mp-c "${CK[@]}" "$WORK/mpc.out" >/dev/null || fail "get sse-c multipart"
cmp -s "$WORK/mpc.bin" "$WORK/mpc.out" || fail "sse-c multipart mismatch"
s3api get-object --bucket sse --key mp-c "${CK[@]}" --range bytes=5242870-5242900 "$WORK/mpc.rng" >/dev/null || fail "sse-c mp range"
cmp -s <(tail -c +5242871 "$WORK/mpc.bin" | head -c 31) "$WORK/mpc.rng" || fail "sse-c multipart range mismatch"
if s3api get-object --bucket sse --key mp-c "$WORK/x.out" >/dev/null 2>&1; then fail "sse-c multipart read without key"; fi
ok "SSE-C multipart, key required per part"

CCK=(--copy-source-sse-customer-algorithm AES256 --copy-source-sse-customer-key "fileb://$WORK/ck.bin")
s3api copy-object --bucket sse --key c-to-s3 --copy-source sse/sse-c "${CCK[@]}" --server-side-encryption AES256 >"$WORK/copy1.json" || fail "copy sse-c -> sse-s3"
grep -q "\"ETag\": \"\\\\\"$PMD5\\\\\"\"" "$WORK/copy1.json" || fail "copy etag: $(cat "$WORK/copy1.json")"
check_sse c-to-s3 AES256
if s3api copy-object --bucket sse --key c-nokey --copy-source sse/sse-c --server-side-encryption AES256 >/dev/null 2>&1; then
  fail "sse-c source copied without its key"
fi
s3api copy-object --bucket sse --key s3-to-c --copy-source sse/sse-s3 "${CK[@]}" >/dev/null || fail "copy sse-s3 -> sse-c"
check_sse s3-to-c AES256 "${CK[@]}"
s3api copy-object --bucket sse --key sse-s3 --copy-source sse/sse-s3 --server-side-encryption aws:kms >/dev/null || fail "same-key re-encrypt"
check_sse sse-s3 aws:kms
s3api copy-object --bucket sse-enc --key from-plain --copy-source sse/k1 >/dev/null || fail "copy into default-encrypted bucket"
s3api head-object --bucket sse-enc --key from-plain | grep -q '"ServerSideEncryption": "AES256"' || fail "copy default encryption"
s3api put-object --bucket sse --key people-enc.csv --body "$WORK/obj" --server-side-encryption AES256 >/dev/null
s3api copy-object --bucket sse --key dec-copy --copy-source sse/people-enc.csv >/dev/null || fail "copy encrypted -> plain"
s3api get-object --bucket sse --key dec-copy "$WORK/dec.out" >"$WORK/dec.head" || fail "get decrypted copy"
cmp -s "$WORK/obj" "$WORK/dec.out" || fail "decrypted copy mismatch"
if grep -q ServerSideEncryption "$WORK/dec.head"; then fail "plain copy reports SSE"; fi
s3api copy-object --bucket sse --key meta-copy --copy-source sse/sse-meta --server-side-encryption AES256 >/dev/null || fail "copy keeps meta"
s3api head-object --bucket sse --key meta-copy >"$WORK/mc.head"
grep -q '"owner": "e2e"' "$WORK/mc.head" && grep -q '"ContentType": "text/csv"' "$WORK/mc.head" || fail "copy metadata"
ok "CopyObject across SSE-C/SSE-S3/SSE-KMS/plain"

if [[ -n "$MC" ]]; then
  "$MC" alias set z "$EP" "$AK" "$SK" >/dev/null
  "$MC" mb -q z/mcenc >/dev/null
  "$MC" encrypt set sse-s3 z/mcenc >/dev/null || fail "mc encrypt set sse-s3"
  "$MC" encrypt info z/mcenc | grep -qi "sse-s3\|AES256" || fail "mc encrypt info: $("$MC" encrypt info z/mcenc)"
  "$MC" cp -q "$WORK/secret.bin" z/mcenc/a >/dev/null || fail "mc cp into encrypted bucket"
  "$MC" stat z/mcenc/a | grep -qi "SSE-S3\|AES256\|Encrypted" || fail "mc stat encryption: $("$MC" stat z/mcenc/a)"
  "$MC" encrypt set sse-kms zkfsm-sse-s3 z/mcenc >/dev/null || fail "mc encrypt set sse-kms"
  "$MC" encrypt info z/mcenc | grep -q "zkfsm-sse-s3" || fail "mc encrypt info kms"
  "$MC" encrypt clear z/mcenc >/dev/null || fail "mc encrypt clear"
  if "$MC" encrypt info z/mcenc 2>&1 | grep -qi "sse-s3\|sse-kms"; then fail "encryption not cleared"; fi
  HEXKEY=$(od -An -tx1 "$WORK/ck.bin" | tr -d ' \n')
  "$MC" cp -q --enc-c "z/mcenc/c=$HEXKEY" "$WORK/secret.bin" z/mcenc/c >/dev/null || fail "mc cp --enc-c"
  "$MC" cat --enc-c "z/mcenc/c=$HEXKEY" z/mcenc/c | cmp -s - "$WORK/secret.bin" || fail "mc cat --enc-c"
  "$MC" cp -q --enc-s3 z/mcenc/s3obj "$WORK/secret.bin" z/mcenc/s3obj >/dev/null || fail "mc cp --enc-s3"
  "$MC" cat z/mcenc/s3obj | cmp -s - "$WORK/secret.bin" || fail "mc cat sse-s3"
  ok "mc encrypt set/info/clear, mc cp --enc-c/--enc-s3"
else
  echo "skip mc checks (no mc)"
fi

if ondisk; then fail "plaintext marker found on disk"; fi
s3api put-object --bucket sse --key plain-marker --body "$WORK/secret.bin" >/dev/null
ondisk || fail "marker grep is not effective"
s3api delete-object --bucket sse --key plain-marker >/dev/null
ok "ciphertext on disk"

stop

# Without a KMS: SSE-C still works; SSE-S3/SSE-KMS refused, never stored as plaintext.
start nokms.log
if s3api put-object --bucket sse --key nokms --body "$WORK/secret.bin" --server-side-encryption AES256 \
  >/dev/null 2>"$WORK/nokms.err"; then fail "SSE-S3 put accepted without KMS"; fi
grep -q NotImplemented "$WORK/nokms.err" || fail "no-KMS error: $(cat "$WORK/nokms.err")"
if s3api head-object --bucket sse --key nokms >/dev/null 2>&1; then fail "no-KMS SSE object was stored"; fi
if s3api put-object --bucket sse-enc --key nokms --body "$WORK/secret.bin" >/dev/null 2>"$WORK/nokms2.err"; then
  fail "put into default-encrypted bucket accepted without KMS"
fi
grep -q NotImplemented "$WORK/nokms2.err" || fail "no-KMS default-encryption error"
if s3api get-object --bucket sse --key sse-kms "$WORK/x.out" >/dev/null 2>"$WORK/nokms3.err"; then fail "SSE-KMS read without KMS"; fi
grep -q NotImplemented "$WORK/nokms3.err" || fail "no-KMS read error"
s3api get-object --bucket sse --key sse-c "${CK[@]}" "$WORK/c2.out" >/dev/null || fail "SSE-C read without KMS"
cmp -s "$WORK/secret.bin" "$WORK/c2.out" || fail "SSE-C round trip without KMS"
s3api put-object --bucket sse --key sse-c2 --body "$WORK/secret.bin" "${CK[@]}" >/dev/null || fail "SSE-C put without KMS"
if ondisk; then fail "plaintext marker on disk after no-KMS run"; fi
ok "no KMS: SSE-C works, SSE-S3/SSE-KMS refused"
stop

# Restart with the same key directory: everything stays readable.
start restart.log --kms-backend local --kms-dir "$WORK/kms"
check_sse sse-kms aws:kms
s3api get-object --bucket sse-enc --key big "$WORK/big2.out" >/dev/null && cmp -s "$WORK/big.bin" "$WORK/big2.out" || fail "multipart after restart"
ok "objects readable after restart"
stop

echo "sse: PASS"
