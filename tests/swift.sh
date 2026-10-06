#!/usr/bin/env bash
# Swift gateway end to end: python-swiftclient against tempauth and a Keystone v3
# mock, curl for formats, errors, temp URLs, and S3 visibility of the same objects.
# Needs: swift (python-swiftclient + keystoneclient), mc, curl, python3.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SWIFT="${SWIFT:-$(command -v swift || true)}"
MC="${MC:-$(command -v mc || true)}"
if [[ -z "$SWIFT" ]] || ! "$SWIFT" --version >/dev/null 2>&1; then echo "swift.sh needs python-swiftclient (set SWIFT)"; exit 1; fi
if [[ -z "$MC" ]] || ! "$MC" --version 2>/dev/null | grep -q 'mc version'; then echo "swift.sh needs the MinIO client (set MC)"; exit 1; fi
freeport() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
S3PORT=$(freeport); SWPORT=$(freeport); KSPORT=$(freeport)
EP="http://127.0.0.1:$S3PORT"
SW="http://127.0.0.1:$SWPORT"
KSURL="http://127.0.0.1:$KSPORT"
AK=swiftadmin; SK=swiftadminsecret
DATA="$(mktemp -d)"; WORK="$(mktemp -d)"
PID=""; MPID=""
export MC_CONFIG_DIR="$WORK/mc"
cleanup() {
  [[ -n "$PID" ]] && kill "$PID" 2>/dev/null || true
  [[ -n "$MPID" ]] && kill "$MPID" 2>/dev/null || true
  rm -rf "$DATA" "$WORK"
}
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
ok() { if "$@" >/dev/null 2>&1; then echo 0; else echo 1; fi; }
md5() { md5sum "$1" | cut -d' ' -f1; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

(cd "$ROOT" && zig build)
BIN="$ROOT/zig-out/bin/zkfsm"
python3 "$ROOT/tests/swift_keystone_mock.py" "$KSPORT" "$SW" 2>"$WORK/mock.log" &
MPID=$!
KSFLAGS=(--swift-keystone "$KSURL/v3" --swift-keystone-user svc --swift-keystone-password svcpass
  --swift-keystone-project service --swift-keystone-map aaaa1111="$AK" --swift-keystone-map beta=rouser)
start() {
  ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$BIN" --data "$DATA" --listen "127.0.0.1:$S3PORT" \
    --swift "127.0.0.1:$SWPORT" "$@" 2>>"$WORK/server.log" &
  PID=$!
  for _ in $(seq 50); do curl -s -o /dev/null "$SW/info" && return 0; sleep 0.1; done
  echo "server did not start:"; cat "$WORK/server.log"; exit 1
}
stop() { kill "$PID"; wait "$PID" 2>/dev/null || true; PID=""; }
start "${KSFLAGS[@]}"

# ---- info and tempauth ----
INFO=$(curl -s "$SW/info")
check "info slo segments" 1000 "$(jget 'd["slo"]["max_manifest_segments"]' <<<"$INFO")"
check "info tempurl digests" "sha1 sha256 sha512" "$(jget '" ".join(d["tempurl"]["allowed_digests"])' <<<"$INFO")"
check "auth bad key" 401 "$(status -H "X-Auth-User: test:$AK" -H 'X-Auth-Key: wrong' "$SW/auth/v1.0")"
check "auth missing user" 401 "$(status "$SW/auth/v1.0")"
check "auth unknown user" 401 "$(status -H 'X-Auth-User: test:nobody' -H "X-Auth-Key: $SK" "$SW/auth/v1.0")"
check "auth bad account label" 401 "$(status -H "X-Auth-User: a/b:$AK" -H "X-Auth-Key: $SK" "$SW/auth/v1.0")"
check "auth ok" 200 "$(status -H "X-Auth-User: test:$AK" -H "X-Auth-Key: $SK" "$SW/auth/v1.0")"
TOKEN=$(header x-auth-token -H "X-Auth-User: test:$AK" -H "X-Auth-Key: $SK" "$SW/auth/v1.0")
SURL=$(header x-storage-url -H "X-Auth-User: test:$AK" -H "X-Auth-Key: $SK" "$SW/auth/v1.0")
check "token prefix" AUTH_tk "${TOKEN:0:7}"
check "storage url" "$SW/v1/AUTH_test" "$SURL"
check "bare user account" "$SW/v1/AUTH_$AK" "$(header x-storage-url -H "X-Auth-User: $AK" -H "X-Auth-Key: $SK" "$SW/auth/v1.0")"
T=(-H "X-Auth-Token: $TOKEN")
check "no token" 401 "$(status "$SURL")"
check "forged token" 401 "$(status -H "X-Auth-Token: ${TOKEN%?}0" "$SURL")"
check "garbage token" 401 "$(status -H 'X-Auth-Token: AUTH_tkzz' "$SURL")"
check "other account" 403 "$(status "${T[@]}" "$SW/v1/AUTH_other")"
check "unknown path" 404 "$(status "${T[@]}" "$SW/nope")"

export ST_AUTH="$SW/auth/v1.0" ST_USER="test:$AK" ST_KEY="$SK"
check "swift stat" 0 "$(ok "$SWIFT" stat)"
check "stat containers 0" 0 "$("$SWIFT" stat | awk '/Containers:/{print $2}')"

# ---- containers ----
check "post creates container" 0 "$(ok "$SWIFT" post photos)"
check "container put again" 202 "$(status -X PUT "${T[@]}" "$SURL/photos")"
check "container put bad name" 400 "$(status -X PUT "${T[@]}" "$SURL/Bad%20Name")"
check "post container meta" 0 "$(ok "$SWIFT" post -m color:red -m size:big photos)"
check "container meta color" red "$(header x-container-meta-color -I "${T[@]}" "$SURL/photos")"
check "remove container meta" 204 "$(status -X POST "${T[@]}" -H 'X-Remove-Container-Meta-Size: x' "$SURL/photos")"
check "container meta removed" "" "$(header x-container-meta-size -I "${T[@]}" "$SURL/photos")"
check "head missing container" 404 "$(status -I "${T[@]}" "$SURL/missing")"
check "post account meta" 0 "$(ok "$SWIFT" post -m owner:qa)"
check "account meta" qa "$(header x-account-meta-owner -I "${T[@]}" "$SURL")"
check "account bad meta name" 400 "$(status -X POST "${T[@]}" -H 'X-Account-Meta-a@b: x' "$SURL")"

# ---- objects ----
head -c 3000000 /dev/urandom >"$WORK/f.bin"
echo hello >"$WORK/a.txt"
cd "$WORK"
check "upload" 0 "$(ok "$SWIFT" upload photos f.bin --object-name dir/f.bin)"
check "upload small" 0 "$(ok "$SWIFT" upload photos a.txt --object-name dir/sub/a.txt)"
check "upload top" 0 "$(ok "$SWIFT" upload photos a.txt --object-name top.txt -H 'Content-Type: text/plain')"
check "download" 0 "$(ok "$SWIFT" download photos dir/f.bin -o "$WORK/g.bin")"
check "download md5" "$(md5 f.bin)" "$(md5 g.bin)"
check "list" "dir/f.bin dir/sub/a.txt top.txt" "$("$SWIFT" list photos | xargs)"
check "list prefix" "dir/f.bin dir/sub/a.txt" "$("$SWIFT" list photos --prefix dir/ | xargs)"
check "list delimiter" "dir/ top.txt" "$("$SWIFT" list photos --delimiter / | xargs)"
check "list prefix+delimiter" "dir/f.bin dir/sub/" "$("$SWIFT" list photos --prefix dir/ --delimiter / | xargs)"
check "object etag" "$(md5 f.bin)" "$(header etag -I "${T[@]}" "$SURL/photos/dir/f.bin")"
check "object length" 3000000 "$(header content-length -I "${T[@]}" "$SURL/photos/dir/f.bin")"
check "content type" text/plain "$(header content-type -I "${T[@]}" "$SURL/photos/top.txt")"
check "missing object" 404 "$(status "${T[@]}" "$SURL/photos/nope")"
check "delete missing object" 404 "$(status -X DELETE "${T[@]}" "$SURL/photos/nope")"

# metadata round trip; POST replaces the whole set
check "upload with meta" 0 "$(ok "$SWIFT" upload photos a.txt --object-name m.txt -m Color:blue -m Shape:round)"
check "meta color" blue "$(header x-object-meta-color -I "${T[@]}" "$SURL/photos/m.txt")"
check "meta shape" round "$(header x-object-meta-shape -I "${T[@]}" "$SURL/photos/m.txt")"
check "post object meta" 202 "$(status -X POST "${T[@]}" -H 'X-Object-Meta-Color: green' "$SURL/photos/m.txt")"
check "post replaced meta" green "$(header x-object-meta-color -I "${T[@]}" "$SURL/photos/m.txt")"
check "post dropped meta" "" "$(header x-object-meta-shape -I "${T[@]}" "$SURL/photos/m.txt")"
check "post kept content" hello "$(curl -s "${T[@]}" "$SURL/photos/m.txt")"
check "swift stat meta" green "$("$SWIFT" stat photos m.txt | awk '/Meta Color:/{print $3}')"

# formats
J=$(curl -s "${T[@]}" "$SURL/photos?format=json")
check "json names" "dir/f.bin dir/sub/a.txt m.txt top.txt" "$(jget '" ".join(o["name"] for o in d)' <<<"$J")"
check "json bytes" 3000000 "$(jget 'd[0]["bytes"]' <<<"$J")"
check "json hash" "$(md5 f.bin)" "$(jget 'd[0]["hash"]' <<<"$J")"
check "json content type" text/plain "$(jget 'd[3]["content_type"]' <<<"$J")"
check "json subdir" "dir/" "$(curl -s "${T[@]}" "$SURL/photos?format=json&delimiter=/" | jget 'd[0]["subdir"]')"
check "accept json" application/json "$(header content-type -H 'Accept: application/json' "${T[@]}" "$SURL/photos" | cut -d';' -f1)"
X=$(curl -s "${T[@]}" "$SURL/photos?format=xml")
check "xml container" 1 "$(grep -c '<container name="photos">' <<<"$X")"
check "xml object" 1 "$(grep -c '<name>top.txt</name>' <<<"$X")"
check "plain limit" "dir/f.bin dir/sub/a.txt" "$(curl -s "${T[@]}" "$SURL/photos?limit=2" | xargs)"
check "marker" "m.txt top.txt" "$(curl -s "${T[@]}" "$SURL/photos?marker=dir/sub/a.txt" | xargs)"
check "end_marker" "dir/f.bin dir/sub/a.txt" "$(curl -s "${T[@]}" "$SURL/photos?end_marker=m.txt" | xargs)"
check "path" "dir/f.bin dir/sub/" "$(curl -s "${T[@]}" "$SURL/photos?path=dir" | xargs)"
check "limit too big" 412 "$(status "${T[@]}" "$SURL/photos?limit=10001")"
check "account json" photos "$(curl -s "${T[@]}" "$SURL?format=json" | jget 'd[0]["name"]')"
check "account json count" 4 "$(curl -s "${T[@]}" "$SURL?format=json" | jget 'd[0]["count"]')"
check "account xml" 1 "$(curl -s "${T[@]}" "$SURL?format=xml" | grep -c '<container><name>photos</name><count>4</count>')"
check "account prefix" "" "$(curl -s "${T[@]}" "$SURL?prefix=zz" | xargs)"
check "empty listing 204" 204 "$(status "${T[@]}" "$SURL/photos?prefix=zz")"
check "container object count" 4 "$(header x-container-object-count -I "${T[@]}" "$SURL/photos")"
check "container bytes" 3000018 "$(header x-container-bytes-used -I "${T[@]}" "$SURL/photos")"
check "account container count" 1 "$(header x-account-container-count -I "${T[@]}" "$SURL")"
check "account object count" 4 "$(header x-account-object-count -I "${T[@]}" "$SURL")"

# ranges and conditionals
ETAG=$(md5 f.bin)
check "range" 206 "$(status -r 10-19 "${T[@]}" "$SURL/photos/dir/f.bin")"
check "range bytes" "$(head -c 20 f.bin | tail -c 10 | md5sum)" "$(curl -s -r 10-19 "${T[@]}" "$SURL/photos/dir/f.bin" | md5sum)"
check "content-range" "bytes 10-19/3000000" "$(header content-range -r 10-19 "${T[@]}" "$SURL/photos/dir/f.bin")"
check "range unsatisfiable" 416 "$(status -r 3000000- "${T[@]}" "$SURL/photos/dir/f.bin")"
check "if-none-match" 304 "$(status -H "If-None-Match: $ETAG" "${T[@]}" "$SURL/photos/dir/f.bin")"
check "if-match fail" 412 "$(status -H 'If-Match: 0000' "${T[@]}" "$SURL/photos/dir/f.bin")"
check "if-modified-since" 304 "$(status -H 'If-Modified-Since: Fri, 01 Jan 2100 00:00:00 GMT' "${T[@]}" "$SURL/photos/dir/f.bin")"
check "put etag mismatch" 422 "$(status -X PUT -H 'Etag: 00000000000000000000000000000000' --data-binary @a.txt "${T[@]}" "$SURL/photos/bad.txt")"
check "put etag match" 201 "$(status -X PUT -H "Etag: $(md5 a.txt)" --data-binary @a.txt "${T[@]}" "$SURL/photos/good.txt")"
check "put no length" 411 "$(status -X PUT -H 'Content-Length:' "${T[@]}" "$SURL/photos/nolen.txt")"
check "put if-none-match exists" 412 "$(status -X PUT -H 'If-None-Match: *' --data-binary @a.txt "${T[@]}" "$SURL/photos/good.txt")"
check "put missing container" 404 "$(status -X PUT --data-binary @a.txt "${T[@]}" "$SURL/nocont/x")"
check "chunked put" 201 "$(status -X PUT -H 'Transfer-Encoding: chunked' --data-binary @f.bin "${T[@]}" "$SURL/photos/chunked.bin")"
check "chunked md5" "$(md5 f.bin)" "$(curl -s "${T[@]}" "$SURL/photos/chunked.bin" | md5sum | cut -d' ' -f1)"

# copy: swift copy, COPY verb, X-Copy-From
check "swift copy" 0 "$(ok "$SWIFT" copy photos dir/f.bin -d /photos/copy1.bin)"
check "copy md5" "$ETAG" "$(header etag -I "${T[@]}" "$SURL/photos/copy1.bin")"
check "COPY verb" 201 "$(status -X COPY -H 'Destination: photos/copy2.txt' -H 'X-Object-Meta-Note: copied' "${T[@]}" "$SURL/photos/m.txt")"
check "COPY merged meta" "green copied" "$(header x-object-meta-color -I "${T[@]}" "$SURL/photos/copy2.txt") $(header x-object-meta-note -I "${T[@]}" "$SURL/photos/copy2.txt")"
check "X-Copy-From" 201 "$(status -X PUT -H 'X-Copy-From: /photos/top.txt' -H 'Content-Length: 0' "${T[@]}" "$SURL/photos/copy3.txt")"
check "copied-from header" "photos/top.txt" "$(header x-copied-from -X PUT -H 'X-Copy-From: photos/top.txt' -H 'Content-Length: 0' "${T[@]}" "$SURL/photos/copy4.txt")"
check "copy content" hello "$(curl -s "${T[@]}" "$SURL/photos/copy3.txt")"
check "copy missing source" 404 "$(status -X COPY -H 'Destination: photos/x' "${T[@]}" "$SURL/photos/nope")"
check "copy bad destination" 412 "$(status -X COPY -H 'Destination: nodest' "${T[@]}" "$SURL/photos/top.txt")"

# ---- large objects (~50MB) ----
head -c 50000000 /dev/urandom >"$WORK/big.bin"
BIGMD5=$(md5 big.bin)
check "dlo upload" 0 "$(ok "$SWIFT" upload big big.bin --object-name dlo.bin --segment-size 10000000 --use-dlo)"
check "dlo manifest header" 1 "$(header x-object-manifest -I "${T[@]}" "$SURL/big/dlo.bin" | grep -c '^big_segments/dlo.bin/')"
check "dlo length" 50000000 "$(header content-length -I "${T[@]}" "$SURL/big/dlo.bin")"
check "dlo download" 0 "$(ok "$SWIFT" download big dlo.bin -o "$WORK/dlo.out")"
check "dlo md5" "$BIGMD5" "$(md5 dlo.out)"
check "dlo range" "$(dd if=big.bin bs=1 skip=9999990 count=20 2>/dev/null | md5sum)" "$(curl -s -r 9999990-10000009 "${T[@]}" "$SURL/big/dlo.bin" | md5sum)"
check "slo upload" 0 "$(ok "$SWIFT" upload big big.bin --object-name slo.bin --segment-size 10000000 --use-slo)"
check "slo header" True "$(header x-static-large-object -I "${T[@]}" "$SURL/big/slo.bin")"
check "slo length" 50000000 "$(header content-length -I "${T[@]}" "$SURL/big/slo.bin")"
SEGTAGS=$(curl -s "${T[@]}" "$SURL/big/slo.bin?multipart-manifest=get" | jget '"".join(s["hash"] for s in d)')
check "slo etag" "\"$(printf %s "$SEGTAGS" | md5sum | cut -d' ' -f1)\"" "$(header etag -I "${T[@]}" "$SURL/big/slo.bin")"
check "slo manifest get" 5 "$(curl -s "${T[@]}" "$SURL/big/slo.bin?multipart-manifest=get" | jget 'len(d)')"
check "slo manifest raw" 10000000 "$(curl -s "${T[@]}" "$SURL/big/slo.bin?multipart-manifest=get&format=raw" | jget 'd[0]["size_bytes"]')"
check "slo download" 0 "$(ok "$SWIFT" download big slo.bin -o "$WORK/slo.out")"
check "slo md5" "$BIGMD5" "$(md5 slo.out)"
check "slo range" "$(dd if=big.bin bs=1 skip=29999995 count=10 2>/dev/null | md5sum)" "$(curl -s -r 29999995-30000004 "${T[@]}" "$SURL/big/slo.bin" | md5sum)"
check "slo listing bytes" 50000000 "$(curl -s "${T[@]}" "$SURL/big?format=json&prefix=slo" | jget 'd[0]["bytes"]')"
check "slo copy materializes" 201 "$(status -X COPY -H 'Destination: big/flat.bin' "${T[@]}" "$SURL/big/slo.bin")"
check "slo copy md5" "$BIGMD5" "$(header etag -I "${T[@]}" "$SURL/big/flat.bin")"
SEG1=$(curl -s "${T[@]}" "$SURL/big/slo.bin?multipart-manifest=get" | jget 'd[0]["name"]')
SEG1TAG=$(curl -s "${T[@]}" "$SURL/big/slo.bin?multipart-manifest=get" | jget 'd[0]["hash"]')
mput() { status -X PUT "${T[@]}" --data-binary "$1" "$SURL/big/m.json?multipart-manifest=put"; }
check "slo ranged manifest" 201 "$(mput "[{\"path\":\"$SEG1\",\"etag\":\"$SEG1TAG\",\"size_bytes\":10000000,\"range\":\"5-9\"},{\"path\":\"$SEG1\",\"range\":\"0-4\"}]")"
check "slo ranged content" "$( (dd if=big.bin bs=1 skip=5 count=5; dd if=big.bin bs=1 count=5) 2>/dev/null | md5sum)" "$(curl -s "${T[@]}" "$SURL/big/m.json" | md5sum)"
check "slo missing segment" 400 "$(mput '[{"path":"/big_segments/nope","etag":null,"size_bytes":null}]')"
check "slo etag mismatch" 400 "$(mput "[{\"path\":\"$SEG1\",\"etag\":\"00000000000000000000000000000000\"}]")"
check "slo size mismatch" 400 "$(mput "[{\"path\":\"$SEG1\",\"size_bytes\":1}]")"
check "slo bad json" 400 "$(mput 'not json')"
check "slo unknown key" 400 "$(mput "[{\"path\":\"$SEG1\",\"bogus\":1}]")"
check "slo empty" 400 "$(mput '[]')"
python3 -c "import json; print(json.dumps([{'path': '$SEG1'}] * 1001))" >"$WORK/many.json"
check "slo too many segments" 400 "$(status -X PUT "${T[@]}" --data-binary @"$WORK/many.json" "$SURL/big/m2?multipart-manifest=put")"
check "segments before delete" 10 "$("$SWIFT" list big_segments | wc -l)"
check "delete slo with segments" 0 "$(ok "$SWIFT" delete big slo.bin)"
check "delete dlo with segments" 0 "$(ok "$SWIFT" delete big dlo.bin)"
check "segments after delete" 0 "$("$SWIFT" list big_segments | wc -l)"
check "ranged manifest broken" 409 "$(status "${T[@]}" "$SURL/big/m.json")"
check "manifest delete plain" 204 "$(status -X DELETE "${T[@]}" "$SURL/big/m.json")"

# ---- temp URLs ----
check "set account temp url key" 0 "$(ok "$SWIFT" post -m Temp-URL-Key:acctsecret)"
TU=$("$SWIFT" tempurl GET 600 /v1/AUTH_test/photos/dir/f.bin acctsecret)
check "tempurl get" "$ETAG" "$(curl -s "$SW$TU" | md5sum | cut -d' ' -f1)"
check "tempurl disposition" 'attachment; filename="f.bin"; filename*=UTF-8'"''"'f.bin' "$(header content-disposition "$SW$TU")"
check "tempurl inline" inline "$(header content-disposition "$SW$TU&inline")"
check "tempurl filename" 'attachment; filename="x.bin"; filename*=UTF-8'"''"'x.bin' "$(header content-disposition "$SW$TU&filename=x.bin")"
check "tempurl head" 200 "$(status -I "$SW$TU")"
check "tempurl wrong method" 401 "$(status -X PUT --data-binary @a.txt "$SW$TU")"
check "tempurl other object" 401 "$(status "$SW${TU/dir\/f.bin/top.txt}")"
TP=$("$SWIFT" tempurl PUT 600 /v1/AUTH_test/photos/up.txt acctsecret)
check "tempurl put" 201 "$(status -X PUT --data-binary @a.txt "$SW$TP")"
check "tempurl put content" hello "$(curl -s "${T[@]}" "$SURL/photos/up.txt")"
sig() { # digest key method expires path [b64]
  python3 - "$@" <<'EOF'
import hmac, hashlib, base64, sys
d, key, m, exp, path = sys.argv[1:6]
mac = hmac.new(key.encode(), f"{m}\n{exp}\n{path}".encode(), getattr(hashlib, d))
print(f"{d}:" + base64.urlsafe_b64encode(mac.digest()).decode().rstrip("=") if len(sys.argv) > 6 else mac.hexdigest())
EOF
}
NOW=$(date +%s)
P=/v1/AUTH_test/photos/top.txt
check "tempurl expired" 401 "$(status "$SW$P?temp_url_sig=$(sig sha1 acctsecret GET $((NOW - 10)) $P)&temp_url_expires=$((NOW - 10))")"
check "tempurl sha256" 200 "$(status "$SW$P?temp_url_sig=$(sig sha256 acctsecret GET $((NOW + 60)) $P)&temp_url_expires=$((NOW + 60))")"
check "tempurl sha512 b64" 200 "$(status "$SW$P?temp_url_sig=$(sig sha512 acctsecret GET $((NOW + 60)) $P b64)&temp_url_expires=$((NOW + 60))")"
check "tempurl bad key" 401 "$(status "$SW$P?temp_url_sig=$(sig sha256 nope GET $((NOW + 60)) $P)&temp_url_expires=$((NOW + 60))")"
ISO=$(date -u -d "@$((NOW + 60))" +%Y-%m-%dT%H:%M:%SZ)
check "tempurl iso expiry" 200 "$(status "$SW$P?temp_url_sig=$(sig sha256 acctsecret GET $((NOW + 60)) $P)&temp_url_expires=$ISO")"
check "container temp url key" 0 "$(ok "$SWIFT" post -m Temp-URL-Key:contsecret photos)"
check "tempurl container key" 200 "$(status "$SW$P?temp_url_sig=$(sig sha1 contsecret GET $((NOW + 60)) $P)&temp_url_expires=$((NOW + 60))")"
PP=/v1/AUTH_test/photos/dir/
check "tempurl prefix" 200 "$(status "$SW/v1/AUTH_test/photos/dir/sub/a.txt?temp_url_sig=$(sig sha256 acctsecret GET $((NOW + 60)) "prefix:$PP")&temp_url_expires=$((NOW + 60))&temp_url_prefix=dir/")"
check "tempurl prefix outside" 401 "$(status "$SW/v1/AUTH_test/photos/top.txt?temp_url_sig=$(sig sha256 acctsecret GET $((NOW + 60)) "prefix:$PP")&temp_url_expires=$((NOW + 60))&temp_url_prefix=dir/")"

# ---- deletes ----
check "delete non-empty container" 409 "$(status -X DELETE "${T[@]}" "$SURL/photos")"
check "delete object" 204 "$(status -X DELETE "${T[@]}" "$SURL/photos/top.txt")"
check "deleted object gone" 404 "$(status -I "${T[@]}" "$SURL/photos/top.txt")"
check "swift delete container" 0 "$(ok "$SWIFT" delete photos)"
check "container gone" 404 "$(status -I "${T[@]}" "$SURL/photos")"

# ---- S3 visibility ----
s3() { curl -s --aws-sigv4 aws:amz:us-east-1:s3 --user "$AK:$SK" "$@"; }
check "swift object via s3" "$BIGMD5" "$(s3 "$EP/big/flat.bin" | md5sum | cut -d' ' -f1)"
check "s3 list sees swift object" 1 "$(s3 "$EP/big?list-type=2" | grep -c '<Key>flat.bin</Key>')"
check "s3 meta from swift" 1 "$(s3 -I "$EP/big/flat.bin" | grep -ci 'x-amz-meta-mtime')"
s3 -X PUT --data-binary @a.txt "$EP/big/from-s3.txt" >/dev/null
check "s3 object via swift" hello "$(curl -s "${T[@]}" "$SURL/big/from-s3.txt")"

# ---- Keystone v3 ----
"$MC" alias set z "$EP" "$AK" "$SK" >/dev/null
check "mc user add" 0 "$(ok "$MC" admin user add z rouser rousersecret1)"
check "mc readonly policy" 0 "$(ok "$MC" admin policy attach z readonly --user rouser)"
KS=(--auth-version 3 --os-auth-url "$KSURL/v3" --os-user-domain-name Default --os-project-domain-name Default)
ALICE=(env -u ST_AUTH -u ST_USER -u ST_KEY "$SWIFT" "${KS[@]}" --os-username alice --os-password alicepass --os-project-name alpha)
check "keystone stat" AUTH_aaaa1111 "$("${ALICE[@]}" stat | awk '/Account:/{print $2}')"
check "keystone post" 0 "$(ok "${ALICE[@]}" post kscont)"
check "keystone upload" 0 "$(ok "${ALICE[@]}" upload kscont f.bin)"
check "keystone list" f.bin "$("${ALICE[@]}" list kscont)"
check "keystone download" 0 "$(ok "${ALICE[@]}" download kscont f.bin -o "$WORK/ks.out")"
check "keystone md5" "$ETAG" "$(md5 ks.out)"
check "keystone object via s3" "$ETAG" "$(s3 "$EP/kscont/f.bin" | md5sum | cut -d' ' -f1)"
kstoken() { # user password project
  curl -s -D - -o /dev/null -H 'Content-Type: application/json' -X POST "$KSURL/v3/auth/tokens" -d \
    "{\"auth\":{\"identity\":{\"methods\":[\"password\"],\"password\":{\"user\":{\"name\":\"$1\",\"domain\":{\"name\":\"Default\"},\"password\":\"$2\"}}},\"scope\":{\"project\":{\"name\":\"$3\",\"domain\":{\"name\":\"Default\"}}}}}" |
    tr -d '\r' | awk 'BEGIN{IGNORECASE=1} /^x-subject-token:/{print $2}'
}
AT=$(kstoken alice alicepass alpha)
BT=$(kstoken bob bobpass beta)
CT=$(kstoken carol carolpass gamma)
check "keystone curl" 200 "$(status -H "X-Auth-Token: $AT" "$SW/v1/AUTH_aaaa1111/kscont")"
check "keystone invalid token" 401 "$(status -H 'X-Auth-Token: gAAAAbogus' "$SW/v1/AUTH_aaaa1111")"
check "keystone unmapped project" 403 "$(status -H "X-Auth-Token: $CT" "$SW/v1/AUTH_cccc3333")"
check "keystone wrong account" 403 "$(status -H "X-Auth-Token: $AT" "$SW/v1/AUTH_bbbb2222")"
check "keystone readonly get" 200 "$(status -H "X-Auth-Token: $BT" "$SW/v1/AUTH_bbbb2222/kscont/f.bin")"
check "keystone readonly put" 403 "$(status -X PUT -H "X-Auth-Token: $BT" --data-binary @a.txt "$SW/v1/AUTH_bbbb2222/kscont/ro.txt")"
check "keystone readonly delete" 403 "$(status -X DELETE -H "X-Auth-Token: $BT" "$SW/v1/AUTH_bbbb2222/kscont/f.bin")"
check "keystone readonly list" 403 "$(status -H "X-Auth-Token: $BT" "$SW/v1/AUTH_bbbb2222/kscont")"
V0=$(curl -s "$KSURL/stats" | jget 'd["validations"]')
for _ in 1 2 3; do status -H "X-Auth-Token: $AT" "$SW/v1/AUTH_aaaa1111/kscont" >/dev/null; done
check "keystone cache" "$V0" "$(curl -s "$KSURL/stats" | jget 'd["validations"]')"
kill "$MPID"; wait "$MPID" 2>/dev/null || true; MPID=""
check "keystone down cached" 200 "$(status -H "X-Auth-Token: $AT" "$SW/v1/AUTH_aaaa1111/kscont")"
check "keystone down uncached" 503 "$(status -H 'X-Auth-Token: gAAAAother' "$SW/v1/AUTH_aaaa1111")"

# ---- restart: prefix, tempauth off, persisted token key and account meta ----
stop
start --swift-prefix /swift --swift-tempauth off
check "prefix info" 200 "$(status "$SW/swift/info")"
check "outside prefix" 404 "$(status "$SW/info")"
check "tempauth off" 404 "$(status -H "X-Auth-User: test:$AK" -H "X-Auth-Key: $SK" "$SW/swift/auth/v1.0")"
check "tempauth token rejected when off" 401 "$(status "${T[@]}" "$SW/swift/v1/AUTH_test")"
stop
start --swift-prefix /swift
check "token survives restart" 204 "$(status -I "${T[@]}" "$SW/swift/v1/AUTH_test")"
check "account meta persisted" qa "$(header x-account-meta-owner -I "${T[@]}" "$SW/swift/v1/AUTH_test")"
check "prefixed storage url" "$SW/swift/v1/AUTH_test" "$(header x-storage-url -H "X-Auth-User: test:$AK" -H "X-Auth-Key: $SK" "$SW/swift/auth/v1.0")"

echo "swift: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
