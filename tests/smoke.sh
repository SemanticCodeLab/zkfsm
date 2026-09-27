#!/usr/bin/env bash
# End-to-end smoke test: builds zkfsm, starts it on a temp dir, drives it with curl.
set -euo pipefail
S3CLI_BIN="${S3CLI_BIN:-aws}"
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
"$ROOT/zig-out/bin/zkfsm" --anonymous --domain s3.local --data "$DATA" --listen "127.0.0.1:$PORT" 2>"$WORK/server.log" &
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

# User metadata and system headers.
check "meta bucket" 200 "$(status -X PUT "$EP/metab")"
check "meta put" 200 "$(echo -n m | status -T - -H 'x-amz-meta-Color: red' -H 'x-amz-meta-x-zkfsm-internal-k: sneaky' -H 'x-zkfsm-internal-j: sneaky' \
  -H 'Cache-Control: max-age=60' -H 'Content-Disposition: attachment; filename="a.txt"' -H 'Content-Language: en' "$EP/metab/m")"
check "meta head" "red" "$(header x-amz-meta-color -I "$EP/metab/m")"
check "meta cache-control" "max-age=60" "$(header cache-control "$EP/metab/m")"
check "meta content-language" "en" "$(header content-language -I "$EP/metab/m")"
check "meta internal stripped" 0 "$(curl -s -D - -o /dev/null -I "$EP/metab/m" | grep -ci 'zkfsm-internal')"
check "response override" "text/x-over" "$(header content-type "$EP/metab/m?response-content-type=text/x-over")"
check "response override disposition" "inline" "$(header content-disposition "$EP/metab/m?response-content-disposition=inline")"
check "meta too large" 400 "$(echo -n m | status -T - -H "x-amz-meta-big: $(head -c 2100 /dev/zero | tr '\0' a)" "$EP/metab/big")"
check "meta copy keeps" "red" "$(curl -s -o /dev/null -X PUT -H 'x-amz-copy-source: metab/m' "$EP/metab/c1"; header x-amz-meta-color -I "$EP/metab/c1")"
curl -s -o /dev/null -X PUT -H 'x-amz-copy-source: metab/m' -H 'x-amz-metadata-directive: REPLACE' -H 'x-amz-meta-color: blue' "$EP/metab/c2"
check "meta copy replace" "blue" "$(header x-amz-meta-color -I "$EP/metab/c2")"
check "meta copy replace drops system" "" "$(header cache-control -I "$EP/metab/c2")"
for k in m c1 c2; do curl -s -o /dev/null -X DELETE "$EP/metab/$k"; done
check "meta bucket delete" 204 "$(status -X DELETE "$EP/metab")"

# Multipart uploads.
xmlval() { sed -n "s/.*<$1>\([^<]*\)<\/$1>.*/\1/p"; }
check "mp bucket" 200 "$(status -X PUT "$EP/mpb")"
head -c 6000000 /dev/urandom > "$WORK/p1"
head -c 1234 /dev/urandom > "$WORK/p2"
cat "$WORK/p1" "$WORK/p2" > "$WORK/whole"
UPID=$(curl -s -X POST -H 'Content-Type: application/x-mp' -H 'x-amz-meta-mp: yes' "$EP/mpb/big?uploads" | xmlval UploadId)
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
check "mp metadata" "yes" "$(header x-amz-meta-mp -I "$EP/mpb/big")"
check "mp body" "$(md5sum < "$WORK/whole")" "$(curl -s "$EP/mpb/big" | md5sum)"
check "mp range across parts" "$(tail -c +5999991 "$WORK/whole" | head -c 20 | md5sum)" "$(curl -s -r 5999990-6000009 "$EP/mpb/big" | md5sum)"
check "part 2 status" 206 "$(status "$EP/mpb/big?partNumber=2")"
check "part 2 body" "$(md5sum < "$WORK/p2")" "$(curl -s "$EP/mpb/big?partNumber=2" | md5sum)"
check "part 1 body" "$(md5sum < "$WORK/p1")" "$(curl -s "$EP/mpb/big?partNumber=1" | md5sum)"
check "part content-range" "bytes 6000000-6001233/6001234" "$(header content-range "$EP/mpb/big?partNumber=2")"
check "part parts count" 2 "$(header x-amz-mp-parts-count -I "$EP/mpb/big?partNumber=1")"
check "part head length" 1234 "$(header content-length -I "$EP/mpb/big?partNumber=2")"
check "part out of range" 416 "$(status "$EP/mpb/big?partNumber=3")"
check "part out of range code" 1 "$(curl -s "$EP/mpb/big?partNumber=3" | grep -c '<Code>InvalidPartNumber</Code>')"
check "part with range" 400 "$(status -r 0-1 "$EP/mpb/big?partNumber=1")"
check "part zero" 400 "$(status "$EP/mpb/big?partNumber=0")"
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

# Multipart, copy, and multi-delete through versioning and object lock.
MV="$EP/mpver"
curl -s -o /dev/null -X PUT -H 'x-amz-bucket-object-lock-enabled: true' "$MV"
curl -s -o /dev/null -X PUT --data-binary '<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>1</Days></DefaultRetention></Rule></ObjectLockConfiguration>' "$MV?object-lock"
VUP=$(curl -s -X POST -H 'x-amz-tagging: t=1' "$MV/obj?uploads" | xmlval UploadId)
VE1=$(echo -n "only" | curl -s -D - -o /dev/null -T - "$MV/obj?partNumber=1&uploadId=$VUP" | tr -d '\r' | awk 'tolower($1)=="etag:"{print $2}')
VVER=$(printf '<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part></CompleteMultipartUpload>' "$VE1" | curl -s -D - -o /dev/null -X POST --data-binary @- "$MV/obj?uploadId=$VUP" | tr -d '\r' | awk 'tolower($1)=="x-amz-version-id:"{print $2}')
check "mp complete version id" 32 "${#VVER}"
check "mp complete lock default" "GOVERNANCE" "$(header x-amz-object-lock-mode -I "$MV/obj")"
check "mp complete tags" "1" "$(header x-amz-tagging-count -I "$MV/obj")"
CVER=$(curl -s -D - -o /dev/null -X PUT -H "x-amz-copy-source: /mpver/obj?versionId=$VVER" "$MV/copy" | tr -d '\r' | awk 'tolower($1)=="x-amz-version-id:"{print $2}')
check "copy version id" 32 "${#CVER}"
check "copy keeps tags" "1" "$(header x-amz-tagging-count -I "$MV/copy")"
check "copy lock default" "GOVERNANCE" "$(header x-amz-object-lock-mode -I "$MV/copy")"
DV=$(curl -s -X POST --data-binary "<Delete><Object><Key>obj</Key><VersionId>$VVER</VersionId></Object><Object><Key>copy</Key></Object></Delete>" "$MV?delete")
check "multi-delete locked version" 1 "$(grep -c "<Error><Key>obj</Key><VersionId>$VVER</VersionId><Code>AccessDenied</Code>" <<<"$DV")"
check "multi-delete marker" 1 "$(grep -c '<Deleted><Key>copy</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>' <<<"$DV")"
DV2=$(curl -s -X POST -H 'x-amz-bypass-governance-retention: true' --data-binary "<Delete><Object><Key>obj</Key><VersionId>$VVER</VersionId></Object></Delete>" "$MV?delete")
check "multi-delete bypass governance" 1 "$(grep -c "<Deleted><Key>obj</Key><VersionId>$VVER</VersionId></Deleted>" <<<"$DV2")"
check "deleted version gone" 404 "$(status -I "$MV/obj?versionId=$VVER")"

# S3 CLI (optional): a 50 MB `s3 cp` goes through multipart.
if command -v "$S3CLI_BIN" >/dev/null && [[ -z "${ZKFSM_SMOKE_NO_CLI:-}" ]]; then
  export AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=x AWS_DEFAULT_REGION=us-east-1 AWS_EC2_METADATA_DISABLED=true
  export AWS_REQUEST_CHECKSUM_CALCULATION=when_required AWS_RESPONSE_CHECKSUM_VALIDATION=when_required
  s3cli() { "$S3CLI_BIN" --no-sign-request --endpoint-url "$EP" "$@"; }
  head -c 50000000 /dev/urandom > "$WORK/fifty"
  s3cli s3 mb s3://climp >/dev/null
  check "cli cp 50MB" 0 "$(s3cli s3 cp --quiet "$WORK/fifty" s3://climp/fifty >/dev/null 2>"$WORK/cli.err"; echo $?)"
  check "cli multipart etag" 1 "$(header etag -I "$EP/climp/fifty" | grep -c -- '-[0-9]*"$')"
  s3cli s3 cp --quiet s3://climp/fifty "$WORK/fifty.back" 2>>"$WORK/cli.err" || true
  check "cli roundtrip" "$(md5sum < "$WORK/fifty")" "$(md5sum < "$WORK/fifty.back" 2>/dev/null)"
  # --copy-props none: object tagging (GetObjectTagging) is not implemented.
  check "cli server copy" 0 "$(s3cli s3 cp --quiet --copy-props none s3://climp/fifty s3://climp/fifty2 2>>"$WORK/cli.err"; echo $?)"
  check "cli server copy body" "$(md5sum < "$WORK/fifty")" "$(curl -s "$EP/climp/fifty2" | md5sum)"
  check "cli rm recursive" 0 "$(s3cli s3 rm --quiet --recursive s3://climp 2>>"$WORK/cli.err"; echo $?)"
  check "cli rb" 0 "$(s3cli s3 rb s3://climp >/dev/null 2>>"$WORK/cli.err"; echo $?)"
  [[ -s "$WORK/cli.err" ]] && cat "$WORK/cli.err"
fi

# Keep-alive: two requests on one connection.
check "keep-alive" "200 200" "$(curl -s -o /dev/null -o /dev/null -w '%{http_code} ' "$EP/" "$EP/" | xargs)"

# Conditional requests.
curl -s -o /dev/null -X PUT "$EP/cond"
echo -n "v1" | curl -s -o /dev/null -T - "$EP/cond/k"
ET=$(header etag -I "$EP/cond/k")
LM=$(header last-modified -I "$EP/cond/k")
check "if-none-match create conflict" 412 "$(echo -n x | status -T - -H 'If-None-Match: *' "$EP/cond/k")"
check "if-none-match create new" 200 "$(echo -n x | status -T - -H 'If-None-Match: *' "$EP/cond/new")"
check "put if-match mismatch" 412 "$(echo -n x | status -T - -H 'If-Match: "nope"' "$EP/cond/k")"
check "get if-match ok" 200 "$(status -H "If-Match: $ET" "$EP/cond/k")"
check "get if-match fail" 412 "$(status -H 'If-Match: "nope"' "$EP/cond/k")"
check "get if-none-match 304" 304 "$(status -H "If-None-Match: $ET" "$EP/cond/k")"
check "head if-none-match 304" 304 "$(status -I -H "If-None-Match: $ET" "$EP/cond/k")"
check "get if-modified-since 304" 304 "$(status -H "If-Modified-Since: $LM" "$EP/cond/k")"
check "get if-modified-since old" 200 "$(status -H 'If-Modified-Since: Sun, 06 Nov 1994 08:49:37 GMT' "$EP/cond/k")"
check "get if-unmodified-since 412" 412 "$(status -H 'If-Unmodified-Since: Sun, 06 Nov 1994 08:49:37 GMT' "$EP/cond/k")"

# Tagging.
TAGS='<Tagging><TagSet><Tag><Key>env</Key><Value>prod</Value></Tag></TagSet></Tagging>'
echo -n "t" | curl -s -o /dev/null -T - -H 'x-amz-tagging: a=1&b=2' "$EP/cond/tagged"
check "put x-amz-tagging count" 2 "$(header x-amz-tagging-count -I "$EP/cond/tagged")"
check "put object tagging" 200 "$(status -X PUT --data-binary "$TAGS" "$EP/cond/tagged?tagging")"
check "get object tagging" 1 "$(curl -s "$EP/cond/tagged?tagging" | grep -c '<Key>env</Key><Value>prod</Value>')"
check "delete object tagging" 204 "$(status -X DELETE "$EP/cond/tagged?tagging")"
check "tagging emptied" 0 "$(curl -s "$EP/cond/tagged?tagging" | grep -c '<Tag>')"
check "no bucket tagging" 404 "$(status "$EP/cond?tagging")"
check "put bucket tagging" 204 "$(status -X PUT --data-binary "$TAGS" "$EP/cond?tagging")"
check "get bucket tagging" 1 "$(curl -s "$EP/cond?tagging" | grep -c '<Key>env</Key>')"
check "delete bucket tagging" 204 "$(status -X DELETE "$EP/cond?tagging")"

# Versioning.
V=$EP/ver
curl -s -o /dev/null -X PUT "$V"
check "versioning unset" 0 "$(curl -s "$V?versioning" | grep -c '<Status>')"
echo -n "null-body" | curl -s -o /dev/null -T - "$V/k"
check "enable versioning" 200 "$(status -X PUT --data-binary '<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>' "$V?versioning")"
check "versioning enabled" 1 "$(curl -s "$V?versioning" | grep -c '<Status>Enabled</Status>')"
V1=$(echo -n "one" | curl -s -D - -o /dev/null -T - "$V/k" | tr -d '\r' | awk 'tolower($1)=="x-amz-version-id:"{print $2}')
V2=$(echo -n "two" | curl -s -D - -o /dev/null -T - "$V/k" | tr -d '\r' | awk 'tolower($1)=="x-amz-version-id:"{print $2}')
check "version ids differ" 1 "$([[ -n "$V1" && "$V1" != "$V2" ]] && echo 1 || echo 0)"
check "get latest" "two" "$(curl -s "$V/k")"
check "get by version" "one" "$(curl -s "$V/k?versionId=$V1")"
check "get null version" "null-body" "$(curl -s "$V/k?versionId=null")"
check "head version header" "$V1" "$(header x-amz-version-id -I "$V/k?versionId=$V1")"
check "bad version id" 400 "$(status "$V/k?versionId=zzz")"
check "missing version" 404 "$(status "$V/k?versionId=0123456789abcdef0123456789abcdef")"
check "delete makes marker" "true" "$(header x-amz-delete-marker -X DELETE "$V/k")"
check "get after marker" 404 "$(status "$V/k")"
check "marker header on get" "true" "$(header x-amz-delete-marker "$V/k")"
check "list hides marked key" 0 "$(curl -s "$V?list-type=2" | grep -c '<Key>k</Key>')"
VERS=$(curl -s "$V?versions")
check "list versions count" 3 "$(grep -o '<Version>' <<<"$VERS" | wc -l)"
check "list delete markers" 1 "$(grep -o '<DeleteMarker>' <<<"$VERS" | wc -l)"
MARKER=$(sed -n 's/.*<DeleteMarker><Key>k<\/Key><VersionId>\([^<]*\)<.*/\1/p' <<<"$VERS")
PAGE=$(curl -s "$V?versions&max-keys=2")
check "versions truncated" 1 "$(grep -c '<IsTruncated>true</IsTruncated>' <<<"$PAGE")"
NKM=$(sed -n 's/.*<NextKeyMarker>\([^<]*\)<.*/\1/p' <<<"$PAGE")
NVM=$(sed -n 's/.*<NextVersionIdMarker>\([^<]*\)<.*/\1/p' <<<"$PAGE")
PAGE2=$(curl -s "$V?versions&key-marker=$NKM&version-id-marker=$NVM")
check "versions page 2" 2 "$(grep -o '<VersionId>' <<<"$PAGE2" | wc -l)"
check "versions page 2 has null" 1 "$(grep -c '<VersionId>null</VersionId>' <<<"$PAGE2")"
check "delete marker by id" 204 "$(status -X DELETE "$V/k?versionId=$MARKER")"
check "latest restored" "two" "$(curl -s "$V/k")"
check "delete version" "$V2" "$(header x-amz-version-id -X DELETE "$V/k?versionId=$V2")"
check "previous promoted" "one" "$(curl -s "$V/k")"
check "suspend versioning" 200 "$(status -X PUT --data-binary '<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>' "$V?versioning")"
echo -n "susp" | curl -s -o /dev/null -T - "$V/k"
check "suspended replaces null" "susp" "$(curl -s "$V/k?versionId=null")"
check "suspended versions" 2 "$(curl -s "$V?versions" | grep -o '<Version>' | wc -l)"
check "versioned bucket not empty" 409 "$(status -X DELETE "$V")"
curl -s -o /dev/null -X DELETE "$V/k?versionId=null"
curl -s -o /dev/null -X DELETE "$V/k?versionId=$V1"
check "delete emptied versioned bucket" 204 "$(status -X DELETE "$V")"

# Object lock.
L=$EP/locked
FUT=$(date -u -d '+1 day' +%Y-%m-%dT%H:%M:%SZ)
check "create lock bucket" 200 "$(status -X PUT -H 'x-amz-bucket-object-lock-enabled: true' "$L")"
check "lock bucket versioned" 1 "$(curl -s "$L?versioning" | grep -c '<Status>Enabled</Status>')"
check "cannot suspend lock bucket" 409 "$(status -X PUT --data-binary '<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>' "$L?versioning")"
check "no lock config on plain bucket" 404 "$(status "$EP/cond?object-lock")"
check "put lock config" 200 "$(status -X PUT --data-binary '<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>1</Days></DefaultRetention></Rule></ObjectLockConfiguration>' "$L?object-lock")"
check "get lock config" 1 "$(curl -s "$L?object-lock" | grep -c '<Mode>GOVERNANCE</Mode><Days>1</Days>')"
GV=$(echo -n "g" | curl -s -D - -o /dev/null -T - "$L/g" | tr -d '\r' | awk 'tolower($1)=="x-amz-version-id:"{print $2}')
check "default retention applied" "GOVERNANCE" "$(header x-amz-object-lock-mode -I "$L/g")"
check "governance delete denied" 403 "$(status -X DELETE "$L/g?versionId=$GV")"
check "access denied code" 1 "$(curl -s -X DELETE "$L/g?versionId=$GV" | grep -c '<Code>AccessDenied</Code>')"
check "marker delete allowed" 204 "$(status -X DELETE "$L/g")"
check "governance shorten denied" 403 "$(status -X PUT --data-binary '<Retention></Retention>' "$L/g?retention&versionId=$GV")"
check "governance bypass delete" 204 "$(status -X DELETE -H 'x-amz-bypass-governance-retention: true' "$L/g?versionId=$GV")"
CV=$(echo -n "c" | curl -s -D - -o /dev/null -T - -H 'x-amz-object-lock-mode: COMPLIANCE' -H "x-amz-object-lock-retain-until-date: $FUT" "$L/c" | tr -d '\r' | awk 'tolower($1)=="x-amz-version-id:"{print $2}')
check "get retention" 1 "$(curl -s "$L/c?retention" | grep -c '<Mode>COMPLIANCE</Mode>')"
check "compliance bypass denied" 403 "$(status -X DELETE -H 'x-amz-bypass-governance-retention: true' "$L/c?versionId=$CV")"
check "compliance downgrade denied" 403 "$(status -X PUT -H 'x-amz-bypass-governance-retention: true' --data-binary "<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>$FUT</RetainUntilDate></Retention>" "$L/c?retention")"
HV=$(echo -n "h" | curl -s -D - -o /dev/null -T - "$L/h" | tr -d '\r' | awk 'tolower($1)=="x-amz-version-id:"{print $2}')
check "put legal hold" 200 "$(status -X PUT --data-binary '<LegalHold><Status>ON</Status></LegalHold>' "$L/h?legal-hold")"
check "get legal hold" 1 "$(curl -s "$L/h?legal-hold" | grep -c '<Status>ON</Status>')"
check "legal hold blocks delete" 403 "$(status -X DELETE -H 'x-amz-bypass-governance-retention: true' "$L/h?versionId=$HV")"
check "retention on plain bucket" 400 "$(status -X PUT --data-binary "<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>$FUT</RetainUntilDate></Retention>" "$EP/cond/k?retention")"

# ACLs: canned private only.
curl -s -o /dev/null -X PUT "$EP/aclb"
echo -n a | curl -s -o /dev/null -T - "$EP/aclb/k"
check "get bucket acl" 1 "$(curl -s "$EP/aclb?acl" | grep -c '<Permission>FULL_CONTROL</Permission>')"
check "get object acl" 1 "$(curl -s "$EP/aclb/k?acl" | grep -c '<Owner><ID>zkfsm</ID>')"
check "get acl missing object" 404 "$(status "$EP/aclb/nope?acl")"
check "put bucket acl private" 200 "$(status -X PUT -H 'x-amz-acl: private' "$EP/aclb?acl")"
check "put object acl private" 200 "$(status -X PUT -H 'x-amz-acl: private' "$EP/aclb/k?acl")"
check "put object acl public" 501 "$(status -X PUT -H 'x-amz-acl: public-read' "$EP/aclb/k?acl")"
check "put acl grant header" 501 "$(status -X PUT -H 'x-amz-grant-read: id=x' "$EP/aclb?acl")"
check "put acl owner body" 200 "$(curl -s "$EP/aclb?acl" | status -X PUT --data-binary @- "$EP/aclb/k?acl")"
check "single part partNumber=1" 200 "$(status "$EP/aclb/k?partNumber=1")"
check "single part partNumber=2" 416 "$(status "$EP/aclb/k?partNumber=2")"

# ListObjects v1 (marker pagination).
for k in a b c/d c/e; do echo -n x | curl -s -o /dev/null -T - "$EP/aclb/v1-$k"; done
V1=$(curl -s "$EP/aclb?prefix=v1-&max-keys=2")
check "v1 list keys" 2 "$(grep -o '<Key>' <<<"$V1" | wc -l)"
check "v1 no key count" 0 "$(grep -c '<KeyCount>' <<<"$V1")"
check "v1 truncated" 1 "$(grep -c '<IsTruncated>true</IsTruncated>' <<<"$V1")"
check "v1 next marker" "v1-b" "$(sed -n 's/.*<NextMarker>\([^<]*\)<.*/\1/p' <<<"$V1")"
V1B=$(curl -s "$EP/aclb?prefix=v1-&marker=v1-b&delimiter=/")
check "v1 marker page" 1 "$(grep -c '<Marker>v1-b</Marker>' <<<"$V1B")"
check "v1 common prefix" 1 "$(grep -c '<CommonPrefixes><Prefix>v1-c/</Prefix></CommonPrefixes>' <<<"$V1B")"
check "v1 owner" 1 "$(curl -s "$EP/aclb?prefix=v1-a" | grep -c '<Owner><ID>zkfsm</ID>')"
check "v1 url encoding" 1 "$(curl -s "$EP/aclb?prefix=v1-c/&encoding-type=url" | grep -c '<Key>v1-c/d</Key>')"

# Virtual-host-style addressing (--domain s3.local).
VH=(-H "Host: aclb.s3.local:$PORT")
check "vhost get" "a" "$(curl -s "${VH[@]}" "$EP/k")"
check "vhost list" 1 "$(curl -s "${VH[@]}" "$EP/?list-type=2&prefix=k" | grep -c '<Key>k</Key>')"
check "vhost put" 200 "$(echo -n vh | status -T - "${VH[@]}" "$EP/dir/vh.txt")"
check "vhost path-style read" "vh" "$(curl -s "$EP/aclb/dir/vh.txt")"
check "vhost resolve" "vh" "$(curl -s --resolve "aclb.s3.local:$PORT:127.0.0.1" "http://aclb.s3.local:$PORT/dir/vh.txt")"
check "bare domain is path style" 1 "$(curl -s -H "Host: s3.local:$PORT" "$EP/aclb?list-type=2&prefix=k" | grep -c '<Key>k</Key>')"
check "absolute-form target" "vh" "$(curl -s --proxy "$EP" "http://aclb.s3.local:$PORT/dir/vh.txt")"

# Bucket policy and lifecycle configuration (anonymous mode stores them; see s3cli.sh for enforcement).
POL='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::aclb/*"}]}'
check "no bucket policy" 1 "$(curl -s "$EP/aclb?policy" | grep -c '<Code>NoSuchBucketPolicy</Code>')"
check "put bucket policy" 204 "$(status -X PUT --data-binary "$POL" "$EP/aclb?policy")"
check "get bucket policy" "$POL" "$(curl -s "$EP/aclb?policy")"
check "policy status" 1 "$(curl -s "$EP/aclb?policyStatus" | grep -c '<IsPublic>true</IsPublic>')"
check "malformed policy" 1 "$(curl -s -X PUT --data-binary '{"nope":1}' "$EP/aclb?policy" | grep -c '<Code>MalformedPolicy</Code>')"
check "policy other bucket" 400 "$(status -X PUT --data-binary "${POL/aclb/other}" "$EP/aclb?policy")"
check "delete bucket policy" 204 "$(status -X DELETE "$EP/aclb?policy")"
check "policy gone" 404 "$(status "$EP/aclb?policy")"
LC='<LifecycleConfiguration><Rule><ID>tmp</ID><Filter><And><Prefix>tmp/</Prefix><Tag><Key>t</Key><Value>1</Value></Tag></And></Filter><Status>Enabled</Status><Expiration><Days>3</Days></Expiration></Rule><Rule><ID>mpu</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status><AbortIncompleteMultipartUpload><DaysAfterInitiation>7</DaysAfterInitiation></AbortIncompleteMultipartUpload><NoncurrentVersionExpiration><NoncurrentDays>30</NoncurrentDays><NewerNoncurrentVersions>2</NewerNoncurrentVersions></NoncurrentVersionExpiration></Rule></LifecycleConfiguration>'
check "no lifecycle" 1 "$(curl -s "$EP/aclb?lifecycle" | grep -c '<Code>NoSuchLifecycleConfiguration</Code>')"
check "put lifecycle" 200 "$(status -X PUT --data-binary "$LC" "$EP/aclb?lifecycle")"
GLC=$(curl -s "$EP/aclb?lifecycle")
check "get lifecycle rules" 2 "$(grep -o '<Rule>' <<<"$GLC" | wc -l)"
check "get lifecycle and filter" 1 "$(grep -c '<Filter><And><Prefix>tmp/</Prefix><Tag><Key>t</Key><Value>1</Value></Tag></And></Filter>' <<<"$GLC")"
check "get lifecycle noncurrent" 1 "$(grep -c '<NoncurrentDays>30</NoncurrentDays><NewerNoncurrentVersions>2</NewerNoncurrentVersions>' <<<"$GLC")"
check "lifecycle transition" 501 "$(status -X PUT --data-binary '<LifecycleConfiguration><Rule><Status>Enabled</Status><Transition><Days>1</Days><StorageClass>COLD</StorageClass></Transition></Rule></LifecycleConfiguration>' "$EP/aclb?lifecycle")"
check "lifecycle bad days" 400 "$(status -X PUT --data-binary '<LifecycleConfiguration><Rule><Status>Enabled</Status><Expiration><Days>0</Days></Expiration></Rule></LifecycleConfiguration>' "$EP/aclb?lifecycle")"
check "lifecycle malformed" 1 "$(curl -s -X PUT --data-binary 'junk' "$EP/aclb?lifecycle" | grep -c '<Code>MalformedXML</Code>')"
check "lifecycle kept after bad put" 2 "$(curl -s "$EP/aclb?lifecycle" | grep -o '<Rule>' | wc -l)"
check "delete lifecycle" 204 "$(status -X DELETE "$EP/aclb?lifecycle")"
check "lifecycle gone" 404 "$(status "$EP/aclb?lifecycle")"

# Persistence across restart.
curl -s -o /dev/null -X PUT "$EP/persist"
echo -n "durable" | curl -s -o /dev/null -T - "$EP/persist/k"
curl -s -o /dev/null -X PUT --data-binary "$LC" "$EP/persist?lifecycle"
kill "$PID"; wait "$PID" 2>/dev/null || true
"$ROOT/zig-out/bin/zkfsm" --anonymous --domain s3.local --data "$DATA" --listen "127.0.0.1:$PORT" 2>>"$WORK/server.log" &
PID=$!
wait_up
check "survives restart" "durable" "$(curl -s "$EP/persist/k")"
check "versions survive restart" "$CV" "$(header x-amz-version-id -I "$EP/locked/c")"
check "lifecycle survives restart" 2 "$(curl -s "$EP/persist?lifecycle" | grep -o '<Rule>' | wc -l)"
check "lock survives restart" 403 "$(status -X DELETE "$EP/locked/c?versionId=$CV")"

echo "smoke: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
