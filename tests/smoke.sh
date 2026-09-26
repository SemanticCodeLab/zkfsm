#!/usr/bin/env bash
# End-to-end smoke test: builds zkfsm, starts it on a temp dir, drives it with curl.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${ZKFSM_SMOKE_PORT:-$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')}"
EP="http://127.0.0.1:$PORT"
DATA="$(mktemp -d)"
WORK="$(mktemp -d)"
PID=""
cleanup() { [[ -n "$PID" ]] && kill "$PID" 2>/dev/null || true; rm -rf "$DATA" "$WORK"; }
trap cleanup EXIT

pass=0
fail=0
check() { # name expected actual
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); echo "ok   $1"
  else fail=$((fail + 1)); echo "FAIL $1: expected [$2] got [$3]"; fi
}
status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
header() { # name, curl args...
  local h="$1"; shift
  curl -s -D - -o /dev/null "$@" | tr -d '\r' | awk -v h="$h" 'BEGIN{IGNORECASE=1} index(tolower($0), tolower(h)":")==1 {sub(/^[^:]*: */,""); print}'
}

wait_up() {
  for _ in $(seq 50); do curl -s -o /dev/null "$EP/" && return 0; sleep 0.1; done
  echo "server did not start:"; cat "$WORK/server.log"; exit 1
}

(cd "$ROOT" && zig build)
"$ROOT/zig-out/bin/zkfsm" --data "$DATA" --listen "127.0.0.1:$PORT" 2>"$WORK/server.log" &
PID=$!
wait_up

head -c 3000000 /dev/urandom > "$WORK/obj.bin"
SIZE=$(stat -c %s "$WORK/obj.bin")
MD5=$(md5sum "$WORK/obj.bin" | cut -d' ' -f1)

check "create bucket" 200 "$(status -X PUT "$EP/smoke")"
check "create dup bucket" 409 "$(status -X PUT "$EP/smoke")"
check "head bucket" 200 "$(status -I "$EP/smoke")"
check "head missing bucket" 404 "$(status -I "$EP/nope-bucket")"
check "list buckets" 1 "$(curl -s "$EP/" | grep -c '<Name>smoke</Name>')"

check "put etag" "\"$MD5\"" "$(header etag -T "$WORK/obj.bin" "$EP/smoke/dir/obj.bin")"
check "head content-length" "$SIZE" "$(header content-length -I "$EP/smoke/dir/obj.bin")"
check "head etag" "\"$MD5\"" "$(header etag -I "$EP/smoke/dir/obj.bin")"
curl -s -o "$WORK/got.bin" "$EP/smoke/dir/obj.bin"
check "get body md5" "$MD5" "$(md5sum "$WORK/got.bin" | cut -d' ' -f1)"
check "get content-length" "$SIZE" "$(header content-length "$EP/smoke/dir/obj.bin")"

check "range status" 206 "$(status -r 10-19 "$EP/smoke/dir/obj.bin")"
check "range bytes" "$(head -c 20 "$WORK/obj.bin" | tail -c 10 | md5sum)" "$(curl -s -r 10-19 "$EP/smoke/dir/obj.bin" | md5sum)"
check "range content-range" "bytes 10-19/$SIZE" "$(header content-range -r 10-19 "$EP/smoke/dir/obj.bin")"
check "suffix range" "$(tail -c 5 "$WORK/obj.bin" | md5sum)" "$(curl -s -H 'Range: bytes=-5' "$EP/smoke/dir/obj.bin" | md5sum)"
check "invalid range" 416 "$(status -r "$SIZE-" "$EP/smoke/dir/obj.bin")"
check "invalid range code" 1 "$(curl -s -r "$SIZE-" "$EP/smoke/dir/obj.bin" | grep -c '<Code>InvalidRange</Code>')"

echo -n "hi" | curl -s -o /dev/null -T - -H 'Content-Type: text/plain' "$EP/smoke/top.txt"
echo -n "" > "$WORK/empty"; curl -s -o /dev/null -T "$WORK/empty" "$EP/smoke/empty"
check "content-type kept" "text/plain" "$(header content-type -I "$EP/smoke/top.txt")"
check "empty object length" 0 "$(header content-length -I "$EP/smoke/empty")"
check "empty object etag" '"d41d8cd98f00b204e9800998ecf8427e"' "$(header etag -I "$EP/smoke/empty")"

LIST=$(curl -s "$EP/smoke?list-type=2&delimiter=/")
check "list common prefix" 1 "$(grep -c '<CommonPrefixes><Prefix>dir/</Prefix></CommonPrefixes>' <<<"$LIST")"
check "list key count" 1 "$(grep -c '<KeyCount>3</KeyCount>' <<<"$LIST")"
check "list prefix" 1 "$(curl -s "$EP/smoke?list-type=2&prefix=dir/" | grep -c '<Key>dir/obj.bin</Key>')"
PAGE=$(curl -s "$EP/smoke?list-type=2&max-keys=1")
check "list truncated" 1 "$(grep -c '<IsTruncated>true</IsTruncated>' <<<"$PAGE")"
TOKEN=$(sed -n 's/.*<NextContinuationToken>\([^<]*\)<.*/\1/p' <<<"$PAGE")
check "list continuation" 1 "$(curl -s "$EP/smoke?list-type=2&max-keys=1&continuation-token=$TOKEN" | grep -c '<Key>empty</Key>')"

check "delete non-empty bucket" 409 "$(status -X DELETE "$EP/smoke")"
check "bucket not empty code" 1 "$(curl -s -X DELETE "$EP/smoke" | grep -c '<Code>BucketNotEmpty</Code>')"
check "delete object" 204 "$(status -X DELETE "$EP/smoke/dir/obj.bin")"
check "get deleted" 404 "$(status "$EP/smoke/dir/obj.bin")"
check "no such key code" 1 "$(curl -s "$EP/smoke/dir/obj.bin" | grep -c '<Code>NoSuchKey</Code>')"
check "no such bucket code" 1 "$(curl -s "$EP/nope-bucket?list-type=2" | grep -c '<Code>NoSuchBucket</Code>')"
check "method not allowed" 405 "$(status -X POST "$EP/")"
curl -s -o /dev/null -X DELETE "$EP/smoke/top.txt"
curl -s -o /dev/null -X DELETE "$EP/smoke/empty"
check "delete bucket" 204 "$(status -X DELETE "$EP/smoke")"

# Multipart uploads.
xmlval() { sed -n "s/.*<$1>\([^<]*\)<\/$1>.*/\1/p"; }
check "mp bucket" 200 "$(status -X PUT "$EP/mpb")"
head -c 6000000 /dev/urandom > "$WORK/p1"
head -c 1234 /dev/urandom > "$WORK/p2"
cat "$WORK/p1" "$WORK/p2" > "$WORK/whole"
UPID=$(curl -s -X POST -H 'Content-Type: application/x-mp' "$EP/mpb/big?uploads" | xmlval UploadId)
check "mp create" 32 "${#UPID}"
E1=$(header etag -T "$WORK/p1" "$EP/mpb/big?partNumber=1&uploadId=$UPID")
E2=$(header etag -T "$WORK/p2" "$EP/mpb/big?partNumber=2&uploadId=$UPID")
check "mp part etag" "\"$(md5sum "$WORK/p2" | cut -d' ' -f1)\"" "$E2"
check "mp list parts" 2 "$(curl -s "$EP/mpb/big?uploadId=$UPID" | grep -o '<Part>' | wc -l)"
check "mp list parts max" 1 "$(curl -s "$EP/mpb/big?uploadId=$UPID&max-parts=1" | grep -c '<IsTruncated>true</IsTruncated>')"
check "mp list uploads" 1 "$(curl -s "$EP/mpb?uploads" | grep -c "<UploadId>$UPID</UploadId>")"
cbody() { printf '<CompleteMultipartUpload>'; while [[ $# -gt 0 ]]; do printf '<Part><PartNumber>%s</PartNumber><ETag>%s</ETag></Part>' "$1" "$2"; shift 2; done; printf '</CompleteMultipartUpload>'; }
complete() { curl -s -X POST --data-binary @- "$EP/mpb/big?uploadId=$UPID"; }
check "mp bad order" 1 "$(cbody 2 "$E2" 1 "$E1" | complete | grep -c '<Code>InvalidPartOrder</Code>')"
check "mp bad etag" 1 "$(cbody 1 "$E2" 2 "$E2" | complete | grep -c '<Code>InvalidPart</Code>')"
check "mp missing part" 1 "$(cbody 1 "$E1" 3 "$E2" | complete | grep -c '<Code>InvalidPart</Code>')"
check "mp malformed" 1 "$(echo 'junk' | complete | grep -c '<Code>MalformedXML</Code>')"
WANT_ETAG="\"$(echo -n "${E1//\"/}${E2//\"/}" | xxd -r -p | md5sum | cut -d' ' -f1)-2\""
check "mp complete etag" "$WANT_ETAG" "$(cbody 1 "$E1" 2 "$E2" | complete | xmlval ETag | sed 's/&quot;/"/g')"
check "mp head etag" "$WANT_ETAG" "$(header etag -I "$EP/mpb/big")"
check "mp content-type" "application/x-mp" "$(header content-type -I "$EP/mpb/big")"
check "mp body" "$(md5sum < "$WORK/whole")" "$(curl -s "$EP/mpb/big" | md5sum)"
check "mp range across parts" "$(tail -c +5999991 "$WORK/whole" | head -c 20 | md5sum)" "$(curl -s -r 5999990-6000009 "$EP/mpb/big" | md5sum)"
check "mp upload gone" 404 "$(status "$EP/mpb/big?uploadId=$UPID")"
check "mp no uploads left" 0 "$(curl -s "$EP/mpb?uploads" | grep -c '<Upload>')"

UP2=$(curl -s -X POST "$EP/mpb/small?uploads" | xmlval UploadId)
S1=$(echo -n "tiny" | curl -s -D - -o /dev/null -T - "$EP/mpb/small?partNumber=1&uploadId=$UP2" | tr -d '\r' | awk 'tolower($1)=="etag:"{print $2}')
S2=$(echo -n "tail" | curl -s -D - -o /dev/null -T - "$EP/mpb/small?partNumber=2&uploadId=$UP2" | tr -d '\r' | awk 'tolower($1)=="etag:"{print $2}')
check "mp entity too small" 1 "$(cbody 1 "$S1" 2 "$S2" | curl -s -X POST --data-binary @- "$EP/mpb/small?uploadId=$UP2" | grep -c '<Code>EntityTooSmall</Code>')"
check "mp bad part number" 400 "$(echo -n x | status -T - "$EP/mpb/small?partNumber=0&uploadId=$UP2")"
check "mp upload part copy" 1 "$(curl -s -X PUT -H 'x-amz-copy-source: /mpb/big' -H 'x-amz-copy-source-range: bytes=10-19' "$EP/mpb/small?partNumber=3&uploadId=$UP2" | grep -c "<ETag>&quot;$(head -c 20 "$WORK/whole" | tail -c 10 | md5sum | cut -d' ' -f1)&quot;</ETag>")"
check "mp copy bad range" 416 "$(status -X PUT -H 'x-amz-copy-source: mpb/big' -H 'x-amz-copy-source-range: bytes=10-99999999' "$EP/mpb/small?partNumber=4&uploadId=$UP2")"
check "mp abort" 204 "$(status -X DELETE "$EP/mpb/small?uploadId=$UP2")"
check "mp abort again" 1 "$(curl -s -X DELETE "$EP/mpb/small?uploadId=$UP2" | grep -c '<Code>NoSuchUpload</Code>')"
check "mp bad upload id" 404 "$(status "$EP/mpb/small?uploadId=nothex")"

# CopyObject.
check "copy object" 1 "$(curl -s -X PUT -H 'x-amz-copy-source: /mpb/big' "$EP/mpb/copy%20of%20big" | grep -c '<CopyObjectResult')"
check "copy body" "$(md5sum < "$WORK/whole")" "$(curl -s "$EP/mpb/copy%20of%20big" | md5sum)"
check "copy keeps type" "application/x-mp" "$(header content-type -I "$EP/mpb/copy%20of%20big")"
check "copy replace type" 200 "$(status -X PUT -H 'x-amz-copy-source: mpb/big' -H 'x-amz-metadata-directive: REPLACE' -H 'Content-Type: text/x-new' "$EP/mpb/big")"
check "copy replaced type" "text/x-new" "$(header content-type -I "$EP/mpb/big")"
check "copy self without replace" 400 "$(status -X PUT -H 'x-amz-copy-source: mpb/big' "$EP/mpb/big")"
check "copy missing source" 404 "$(status -X PUT -H 'x-amz-copy-source: mpb/nope' "$EP/mpb/x")"

# DeleteObjects.
echo -n a | curl -s -o /dev/null -T - "$EP/mpb/a&b"
DEL='<Delete><Object><Key>big</Key></Object><Object><Key>copy of big</Key></Object><Object><Key>a&amp;b</Key></Object><Object><Key>never</Key></Object></Delete>'
check "delete objects" 4 "$(curl -s -X POST --data-binary "$DEL" "$EP/mpb?delete" | grep -o '<Deleted>' | wc -l)"
check "delete objects quiet" 0 "$(curl -s -X POST --data-binary '<Delete><Quiet>true</Quiet><Object><Key>x</Key></Object></Delete>' "$EP/mpb?delete" | grep -c '<Deleted>')"
check "delete objects empty bucket" 204 "$(status -X DELETE "$EP/mpb")"

# aws cli (optional): a 50 MB `s3 cp` goes through multipart.
if command -v aws >/dev/null && [[ -z "${ZKFSM_SMOKE_NO_AWS:-}" ]]; then
  export AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=x AWS_DEFAULT_REGION=us-east-1 AWS_EC2_METADATA_DISABLED=true
  export AWS_REQUEST_CHECKSUM_CALCULATION=when_required AWS_RESPONSE_CHECKSUM_VALIDATION=when_required
  awss3() { aws --no-sign-request --endpoint-url "$EP" "$@"; }
  head -c 50000000 /dev/urandom > "$WORK/fifty"
  awss3 s3 mb s3://awsmp >/dev/null
  check "aws cp 50MB" 0 "$(awss3 s3 cp --quiet "$WORK/fifty" s3://awsmp/fifty >/dev/null 2>"$WORK/aws.err"; echo $?)"
  check "aws multipart etag" 1 "$(header etag -I "$EP/awsmp/fifty" | grep -c -- '-[0-9]*"$')"
  awss3 s3 cp --quiet s3://awsmp/fifty "$WORK/fifty.back" 2>>"$WORK/aws.err" || true
  check "aws roundtrip" "$(md5sum < "$WORK/fifty")" "$(md5sum < "$WORK/fifty.back" 2>/dev/null)"
  # --copy-props none: object tagging (GetObjectTagging) is not implemented.
  check "aws server copy" 0 "$(awss3 s3 cp --quiet --copy-props none s3://awsmp/fifty s3://awsmp/fifty2 2>>"$WORK/aws.err"; echo $?)"
  check "aws server copy body" "$(md5sum < "$WORK/fifty")" "$(curl -s "$EP/awsmp/fifty2" | md5sum)"
  check "aws rm recursive" 0 "$(awss3 s3 rm --quiet --recursive s3://awsmp 2>>"$WORK/aws.err"; echo $?)"
  check "aws rb" 0 "$(awss3 s3 rb s3://awsmp >/dev/null 2>>"$WORK/aws.err"; echo $?)"
  [[ -s "$WORK/aws.err" ]] && cat "$WORK/aws.err"
fi

# Keep-alive: two requests on one connection.
check "keep-alive" "200 200" "$(curl -s -o /dev/null -o /dev/null -w '%{http_code} ' "$EP/" "$EP/" | xargs)"

# Persistence across restart.
curl -s -o /dev/null -X PUT "$EP/persist"
echo -n "durable" | curl -s -o /dev/null -T - "$EP/persist/k"
kill "$PID"; wait "$PID" 2>/dev/null || true
"$ROOT/zig-out/bin/zkfsm" --data "$DATA" --listen "127.0.0.1:$PORT" 2>>"$WORK/server.log" &
PID=$!
wait_up
check "survives restart" "durable" "$(curl -s "$EP/persist/k")"

echo "smoke: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
