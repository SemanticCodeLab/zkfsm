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
"$ROOT/zig-out/bin/zkfsm" --anonymous --data "$DATA" --listen "127.0.0.1:$PORT" 2>"$WORK/server.log" &
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
check "multipart not implemented" 501 "$(status -X POST "$EP/smoke/k?uploads")"
curl -s -o /dev/null -X DELETE "$EP/smoke/top.txt"
curl -s -o /dev/null -X DELETE "$EP/smoke/empty"
check "delete bucket" 204 "$(status -X DELETE "$EP/smoke")"

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

# Persistence across restart.
curl -s -o /dev/null -X PUT "$EP/persist"
echo -n "durable" | curl -s -o /dev/null -T - "$EP/persist/k"
kill "$PID"; wait "$PID" 2>/dev/null || true
"$ROOT/zig-out/bin/zkfsm" --anonymous --data "$DATA" --listen "127.0.0.1:$PORT" 2>>"$WORK/server.log" &
PID=$!
wait_up
check "survives restart" "durable" "$(curl -s "$EP/persist/k")"
check "versions survive restart" "$CV" "$(header x-amz-version-id -I "$EP/locked/c")"
check "lock survives restart" 403 "$(status -X DELETE "$EP/locked/c?versionId=$CV")"

echo "smoke: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
