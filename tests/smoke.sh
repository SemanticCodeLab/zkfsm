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

# Persistence across restart.
curl -s -o /dev/null -X PUT "$EP/persist"
echo -n "durable" | curl -s -o /dev/null -T - "$EP/persist/k"
kill "$PID"; wait "$PID" 2>/dev/null || true
"$ROOT/zig-out/bin/zkfsm" --anonymous --data "$DATA" --listen "127.0.0.1:$PORT" 2>>"$WORK/server.log" &
PID=$!
wait_up
check "survives restart" "durable" "$(curl -s "$EP/persist/k")"

echo "smoke: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
