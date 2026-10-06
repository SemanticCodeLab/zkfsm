#!/usr/bin/env bash
# WebDAV gateway end to end: curl (methods, locks, auth), a python client, rclone,
# and S3 visibility of what WebDAV wrote. HTTPS with a per-run self-signed cert.
# Env: RCLONE=path, WEBDAV_PYTHON=python with webdavclient3, TMPDIR for scratch.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$WORK"; }
trap cleanup EXIT

freeport() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
pass=0
fail=0
check() { # name expected actual
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); echo "ok   $1"
  else fail=$((fail + 1)); echo "FAIL $1: expected [$2] got [$3]"; fi
}

AK="zkfsmdavaccess"
SK="zkfsm/dav+secret0123456789"
RCLONE="${RCLONE:-$(command -v rclone || true)}"
PY="${WEBDAV_PYTHON:-python3}"

(cd "$ROOT" && zig build)
BIN="$ROOT/zig-out/bin/zkfsm"

cd "$WORK"
# RSA: EC handshakes fail ~1% (non-minimal DER ECDSA signatures from std toDer).
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 2 \
  -subj /CN=localhost -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" 2>/dev/null

start() { # name, args...; waits for the webdav listener
  local name="$1"; shift
  env ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$BIN" "$@" 2>"$WORK/$name.log" &
  PIDS+=($!)
  for _ in $(seq 300); do grep -q "webdav.*listening" "$WORK/$name.log" 2>/dev/null && return 0; sleep 0.1; done
  echo "server did not start:"; cat "$WORK/$name.log"; exit 1
}

S3P="$(freeport)"
DP="$(freeport)"
start main --data "$WORK/data" --listen "127.0.0.1:$S3P" --webdav "127.0.0.1:$DP" --tls-cert cert.pem --tls-key key.pem
DAV="https://127.0.0.1:$DP"
S3="https://127.0.0.1:$S3P"
c=(-s -k -u "$AK:$SK")
code() { curl "${c[@]}" -o /dev/null -w '%{http_code}' "$@"; }
hdr() { # name, curl args...
  local h="$1"; shift
  curl "${c[@]}" -D - -o /dev/null "$@" | tr -d '\r' | awk -v h="$h" 'index(tolower($0), tolower(h)":")==1 {sub(/^[^:]*: */,""); print}'
}
s3() { curl -s -k --aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" "$@"; }

# ---- auth and OPTIONS ----
check "options dav header" "1, 2" "$(hdr dav -X OPTIONS "$DAV/")"
check "options allow has PROPFIND" 1 "$(hdr allow -X OPTIONS "$DAV/" | grep -c PROPFIND)"
check "unauthenticated 401" 401 "$(curl -s -k -o /dev/null -w '%{http_code}' -X PROPFIND -H 'Depth: 0' "$DAV/")"
check "www-authenticate" 1 "$(curl -s -k -D - -o /dev/null -X PROPFIND "$DAV/" | grep -ci '^www-authenticate: Basic')"
check "wrong password 401" 401 "$(curl -s -k -u "$AK:nope" -o /dev/null -w '%{http_code}' -X PROPFIND -H 'Depth: 0' "$DAV/")"

# ---- MKCOL ----
check "mkcol bucket" 201 "$(code -X MKCOL "$DAV/davb")"
check "mkcol exists 405" 405 "$(code -X MKCOL "$DAV/davb")"
check "mkcol dir" 201 "$(code -X MKCOL "$DAV/davb/dir")"
check "mkcol missing parent 409" 409 "$(code -X MKCOL "$DAV/davb/nope/sub")"
check "mkcol with body 415" 415 "$(code -X MKCOL --data x "$DAV/davb/withbody")"

# ---- PUT / GET / HEAD / Range ----
head -c 1000000 /dev/urandom >obj.bin
MD5="$(md5sum obj.bin | cut -d' ' -f1)"
check "put new 201" 201 "$(code -T obj.bin "$DAV/davb/dir/obj.bin")"
check "put replace 204" 204 "$(code -T obj.bin "$DAV/davb/dir/obj.bin")"
check "put chunked" 201 "$(curl "${c[@]}" -o /dev/null -w '%{http_code}' -H 'Transfer-Encoding: chunked' -T - "$DAV/davb/dir/chunked.bin" <obj.bin)"
check "chunked md5" "$MD5" "$(curl "${c[@]}" "$DAV/davb/dir/chunked.bin" | md5sum | cut -d' ' -f1)"
check "put missing parent 409" 409 "$(code -T obj.bin "$DAV/davb/none/x.bin")"
check "put on collection 405" 405 "$(code -T obj.bin "$DAV/davb/dir")"
check "get md5" "$MD5" "$(curl "${c[@]}" "$DAV/davb/dir/obj.bin" | md5sum | cut -d' ' -f1)"
check "get etag" "\"$MD5\"" "$(hdr etag "$DAV/davb/dir/obj.bin")"
check "head length" 1000000 "$(hdr content-length -I "$DAV/davb/dir/obj.bin")"
check "last-modified" 1 "$(hdr last-modified -I "$DAV/davb/dir/obj.bin" | grep -c 'GMT$')"
check "range 206" 206 "$(code -r 10-19 "$DAV/davb/dir/obj.bin")"
check "range bytes" "$(head -c 20 obj.bin | tail -c 10 | md5sum)" "$(curl "${c[@]}" -r 10-19 "$DAV/davb/dir/obj.bin" | md5sum)"
check "content-range" "bytes 10-19/1000000" "$(hdr content-range -r 10-19 "$DAV/davb/dir/obj.bin")"
check "range 416" 416 "$(code -r 2000000- "$DAV/davb/dir/obj.bin")"
check "if-none-match 304" 304 "$(code -H "If-None-Match: \"$MD5\"" "$DAV/davb/dir/obj.bin")"
check "get missing 404" 404 "$(code "$DAV/davb/dir/missing")"
printf 'hello' | curl "${c[@]}" -o /dev/null -T - -H 'Content-Type: text/x-test' "$DAV/davb/dir/a%20b%26c.txt"
check "content-type kept" "text/x-test" "$(hdr content-type "$DAV/davb/dir/a%20b%26c.txt")"
check "get collection html" 1 "$(curl "${c[@]}" "$DAV/davb/dir/" | grep -c 'obj.bin')"

# ---- PROPFIND ----
pf0="$(curl "${c[@]}" -X PROPFIND -H 'Depth: 0' "$DAV/davb/dir/obj.bin")"
check "propfind 0 status" 207 "$(code -X PROPFIND -H 'Depth: 0' "$DAV/davb/dir/obj.bin")"
check "propfind 0 length" 1 "$(grep -c '<D:getcontentlength>1000000</D:getcontentlength>' <<<"$pf0")"
check "propfind 0 etag" 1 "$(grep -c "<D:getetag>&quot;$MD5&quot;</D:getetag>" <<<"$pf0")"
check "propfind 0 supportedlock" 1 "$(grep -c '<D:supportedlock><D:lockentry>' <<<"$pf0")"
pf1="$(curl "${c[@]}" -X PROPFIND -H 'Depth: 1' "$DAV/davb/dir/")"
check "propfind 1 members" 4 "$(grep -o '<D:response>' <<<"$pf1" | wc -l)"
check "propfind 1 encoded href" 1 "$(grep -c '<D:href>/davb/dir/a%20b%26c.txt</D:href>' <<<"$pf1")"
check "propfind 1 collection" 1 "$(grep -c '<D:href>/davb/dir/</D:href><D:propstat><D:prop><D:resourcetype><D:collection/>' <<<"$pf1")"
check "propfind root lists bucket" 1 "$(curl "${c[@]}" -X PROPFIND -H 'Depth: 1' "$DAV/" | grep -c '<D:href>/davb/</D:href>')"
check "propfind infinity 403" 403 "$(code -X PROPFIND -H 'Depth: infinity' "$DAV/davb/")"
check "propfind no depth 403" 403 "$(code -X PROPFIND "$DAV/davb/")"
pfp="$(curl "${c[@]}" -X PROPFIND -H 'Depth: 0' --data '<?xml version="1.0"?><propfind xmlns="DAV:"><prop><getlastmodified/><foo xmlns="urn:x"/></prop></propfind>' "$DAV/davb/dir/obj.bin")"
check "propfind prop found" 1 "$(grep -c '<D:getlastmodified>.*GMT</D:getlastmodified>' <<<"$pfp")"
check "propfind prop 404" 1 "$(grep -c 'HTTP/1.1 404 Not Found' <<<"$pfp")"
check "propfind propname" 1 "$(curl "${c[@]}" -X PROPFIND -H 'Depth: 0' --data '<propfind xmlns="DAV:"><propname/></propfind>' "$DAV/davb/" | grep -c '<D:displayname/>')"
check "propfind bad xml 400" 400 "$(code -X PROPFIND -H 'Depth: 0' --data '<propfind' "$DAV/davb/")"
check "propfind entity 400" 400 "$(code -X PROPFIND -H 'Depth: 0' --data '<!DOCTYPE x [<!ENTITY a "b">]><propfind xmlns="DAV:"><allprop/></propfind>' "$DAV/davb/")"
check "propfind missing 404" 404 "$(code -X PROPFIND -H 'Depth: 0' "$DAV/davb/zzz")"
head -c 70000 /dev/zero | tr '\0' ' ' >big.xml
check "propfind body too large 413" 413 "$(code -X PROPFIND -H 'Depth: 0' --data-binary @big.xml "$DAV/davb/")"
check "proppatch 207/403" 1 "$(curl "${c[@]}" -X PROPPATCH --data '<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop><Z:x xmlns:Z="urn:z">1</Z:x></D:prop></D:set></D:propertyupdate>' "$DAV/davb/dir/obj.bin" | grep -c '403 Forbidden')"

# ---- COPY / MOVE ----
check "copy file 201" 201 "$(code -X COPY -H "Destination: $DAV/davb/copy.bin" "$DAV/davb/dir/obj.bin")"
check "copy overwrite F 412" 412 "$(code -X COPY -H 'Overwrite: F' -H "Destination: $DAV/davb/copy.bin" "$DAV/davb/dir/obj.bin")"
check "copy overwrite 204" 204 "$(code -X COPY -H "Destination: $DAV/davb/copy.bin" "$DAV/davb/dir/obj.bin")"
check "copy md5" "$MD5" "$(curl "${c[@]}" "$DAV/davb/copy.bin" | md5sum | cut -d' ' -f1)"
check "copy tree 201" 201 "$(code -X COPY -H "Destination: /davb/dir2" "$DAV/davb/dir")"
check "copied tree member" "$MD5" "$(curl "${c[@]}" "$DAV/davb/dir2/obj.bin" | md5sum | cut -d' ' -f1)"
check "copy into self 403" 403 "$(code -X COPY -H "Destination: /davb/dir/sub" "$DAV/davb/dir")"
check "copy missing parent 409" 409 "$(code -X COPY -H "Destination: /davb/no/where.bin" "$DAV/davb/copy.bin")"
check "copy no destination 400" 400 "$(code -X COPY "$DAV/davb/copy.bin")"
check "move file 201" 201 "$(code -X MOVE -H "Destination: $DAV/davb/moved.bin" "$DAV/davb/copy.bin")"
check "move source gone" 404 "$(code "$DAV/davb/copy.bin")"
check "move dir 201" 201 "$(code -X MOVE -H "Destination: /davb/dir3" "$DAV/davb/dir2")"
check "moved dir member" "$MD5" "$(curl "${c[@]}" "$DAV/davb/dir3/obj.bin" | md5sum | cut -d' ' -f1)"
check "moved dir source gone" 404 "$(code -X PROPFIND -H 'Depth: 0' "$DAV/davb/dir2")"
check "copy to bucket 201" 201 "$(code -X COPY -H "Destination: /davb2" "$DAV/davb/dir3")"
check "bucket copy member" "$MD5" "$(curl "${c[@]}" "$DAV/davb2/obj.bin" | md5sum | cut -d' ' -f1)"

# ---- LOCK / UNLOCK ----
LI='<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner><D:href>tester</D:href></D:owner></D:lockinfo>'
lockout="$(curl "${c[@]}" -D lock.h -X LOCK -H 'Timeout: Second-600' --data "$LI" "$DAV/davb/moved.bin")"
TOK="$(tr -d '\r' <lock.h | awk 'tolower($1)=="lock-token:" {print $2}')"
check "lock token header" 1 "$(grep -c '^<opaquelocktoken:[0-9a-f-]\{36\}>$' <<<"$TOK")"
check "lock body" 1 "$(grep -c '<D:owner><D:href>tester</D:href></D:owner>' <<<"$lockout")"
check "lock timeout" 1 "$(grep -c '<D:timeout>Second-600</D:timeout>' <<<"$lockout")"
check "conflicting lock 423" 423 "$(code -X LOCK --data "$LI" "$DAV/davb/moved.bin")"
check "put without token 423" 423 "$(code -T obj.bin "$DAV/davb/moved.bin")"
check "delete without token 423" 423 "$(code -X DELETE "$DAV/davb/moved.bin")"
check "move without token 423" 423 "$(code -X MOVE -H "Destination: /davb/m2.bin" "$DAV/davb/moved.bin")"
check "delete parent without token 423" 423 "$(code -X DELETE "$DAV/davb2/../davb")"
check "put with token 204" 204 "$(code -T obj.bin -H "If: ($TOK)" "$DAV/davb/moved.bin")"
check "put with bad token 412" 412 "$(code -T obj.bin -H "If: (<opaquelocktoken:00000000-0000-4000-8000-000000000000>)" "$DAV/davb/moved.bin")"
check "lock refresh" 1 "$(curl "${c[@]}" -X LOCK -H "If: ($TOK)" -H 'Timeout: Second-60' "$DAV/davb/moved.bin" | grep -c 'Second-60')"
check "propfind lockdiscovery" 1 "$(curl "${c[@]}" -X PROPFIND -H 'Depth: 0' "$DAV/davb/moved.bin" | grep -c "<D:locktoken><D:href>${TOK:1:-1}</D:href>")"
check "unlock wrong token 409" 409 "$(code -X UNLOCK -H 'Lock-Token: <opaquelocktoken:nope>' "$DAV/davb/moved.bin")"
check "unlock 204" 204 "$(code -X UNLOCK -H "Lock-Token: $TOK" "$DAV/davb/moved.bin")"
check "put after unlock 204" 204 "$(code -T obj.bin "$DAV/davb/moved.bin")"
check "lock new resource 201" 201 "$(code -X LOCK --data "$LI" "$DAV/davb/locknull.txt")"
check "lock-null resource exists" 0 "$(hdr content-length -I "$DAV/davb/locknull.txt")"
SLI="${LI/exclusive/shared}"
check "shared lock dir" 200 "$(code -X LOCK -H 'Depth: infinity' --data "$SLI" "$DAV/davb/dir3")"
check "second shared lock" 200 "$(code -X LOCK -H 'Depth: infinity' --data "$SLI" "$DAV/davb/dir3")"
check "exclusive over shared 423" 423 "$(code -X LOCK --data "$LI" "$DAV/davb/dir3/obj.bin")"
check "put in shared-locked dir 423" 423 "$(code -T obj.bin "$DAV/davb/dir3/new.bin")"

# ---- DELETE ----
check "delete file 204" 204 "$(code -X DELETE "$DAV/davb/moved.bin")"
check "delete missing 404" 404 "$(code -X DELETE "$DAV/davb/moved.bin")"
check "delete dir recursive 204" 204 "$(code -X DELETE "$DAV/davb/dir")"
check "deleted dir gone" 404 "$(code -X PROPFIND -H 'Depth: 0' "$DAV/davb/dir")"
check "delete bucket recursive" 204 "$(code -X DELETE "$DAV/davb2")"

# ---- python client ----
pyout="$("$PY" "$ROOT/tests/webdav_client.py" "$DAV" "$AK" "$SK" 2>&1 || true)"
sed 's/^/     py: /' <<<"$pyout" | grep -v ' py: ok$'
check "python client" "ok" "$(tail -1 <<<"$pyout")"

# ---- rclone ----
if [[ -n "$RCLONE" ]]; then
  export RCLONE_CONFIG="$WORK/rclone.conf" RCLONE_CONFIG_DAV_TYPE=webdav RCLONE_CONFIG_DAV_URL="$DAV" \
    RCLONE_CONFIG_DAV_VENDOR=other RCLONE_CONFIG_DAV_USER="$AK"
  : >"$RCLONE_CONFIG"
  RCLONE_CONFIG_DAV_PASS="$("$RCLONE" obscure "$SK")"
  export RCLONE_CONFIG_DAV_PASS
  rc() { "$RCLONE" --no-check-certificate -q "$@"; }
  mkdir -p tree/a/b tree/empty
  for i in 1 2 3; do head -c $((i * 70000)) /dev/urandom >"tree/f$i.bin"; head -c 1234 /dev/urandom >"tree/a/b/g$i.dat"; done
  echo "x y" >"tree/a/sp ace.txt"
  check "rclone mkdir" 0 "$(rc mkdir dav:rcb; echo $?)"
  check "rclone copy up" 0 "$(rc copy tree dav:rcb/tree --create-empty-src-dirs; echo $?)"
  check "rclone ls" 7 "$(rc ls dav:rcb/tree | wc -l)"
  check "rclone lsd" 2 "$(rc lsd dav:rcb/tree | wc -l)"
  check "rclone check" 0 "$(rc check tree dav:rcb/tree --size-only 2>/dev/null; echo $?)"
  check "rclone copy down" 0 "$(rc copy dav:rcb/tree down; echo $?)"
  check "rclone tree equal" 0 "$(diff -r tree/a down/a >/dev/null && cmp tree/f3.bin down/f3.bin; echo $?)"
  check "rclone moveto" 0 "$(rc moveto dav:rcb/tree/f1.bin dav:rcb/tree/a/f1-moved.bin; echo $?)"
  check "rclone moved" "1 0" "$(rc ls dav:rcb/tree/a | grep -c f1-moved.bin) $(rc ls dav:rcb/tree --max-depth 1 | grep -c ' f1.bin$' || true)"
  check "rclone delete" 0 "$(rc delete dav:rcb/tree/a/b; echo $?)"
  check "rclone deleted" 0 "$(rc ls dav:rcb/tree/a/b | wc -l)"
  head -c 100000000 /dev/urandom >big.bin
  BMD5="$(md5sum big.bin | cut -d' ' -f1)"
  check "rclone 100MB up" 0 "$(rc copyto big.bin dav:rcb/big.bin; echo $?)"
  rc copyto dav:rcb/big.bin big.down
  check "rclone 100MB md5" "$BMD5" "$(md5sum big.down | cut -d' ' -f1)"
  check "s3 sees 100MB etag" 1 "$(s3 -I "$S3/rcb/big.bin" | grep -ci "content-length: 100000000")"
  rm -f big.bin big.down
  check "rclone purge" 0 "$(rc purge dav:rcb/tree; echo $?)"
  check "rclone purged" 0 "$(rc lsf dav:rcb | grep -c tree || true)"
else
  echo "skip rclone (set RCLONE=)"
fi

# ---- visible over S3 ----
printf 's3-visible' | curl "${c[@]}" -o /dev/null -T - "$DAV/davb/s3check.txt"
check "s3 get dav object" "s3-visible" "$(s3 "$S3/davb/s3check.txt")"
check "s3 lists bucket" 1 "$(s3 "$S3/" | grep -c '<Name>davb</Name>')"
printf 'from-s3' | s3 -o /dev/null -T - "$S3/davb/froms3.txt"
check "dav get s3 object" "from-s3" "$(curl "${c[@]}" "$DAV/davb/froms3.txt")"

# ---- plain HTTP needs --webdav-insecure; prefix ----
P2="$(freeport)"; D2="$(freeport)"
check "plain http refused without insecure" 1 "$(set +e; timeout 20 env ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$BIN" --data "$WORK/d2" --listen "127.0.0.1:$P2" --webdav "127.0.0.1:$D2" >/dev/null 2>&1; [[ $? -ne 0 && $? -ne 124 ]] && echo 1 || echo 0)"
start plain --data "$WORK/d3" --listen "127.0.0.1:$P2" --webdav "127.0.0.1:$D2" --webdav-insecure on --webdav-prefix /dav
check "insecure prefix mkcol" 201 "$(code -X MKCOL "http://127.0.0.1:$D2/dav/pbkt")"
check "outside prefix 404" 404 "$(code -X PROPFIND -H 'Depth: 0' "http://127.0.0.1:$D2/pbkt")"
check "prefixed href" 1 "$(curl "${c[@]}" -X PROPFIND -H 'Depth: 1' "http://127.0.0.1:$D2/dav/" | grep -c '<D:href>/dav/pbkt/</D:href>')"
check "keep-alive reuse" 2 "$(curl "${c[@]}" -v -X PROPFIND -H 'Depth: 0' "http://127.0.0.1:$D2/dav/pbkt" "http://127.0.0.1:$D2/dav/pbkt" 2>&1 | grep -c '< HTTP/1.1 207')"
check "garbage request survives" 201 "$(printf 'BAD<> / HTTP/1.1\r\n\r\n' | timeout 5 python3 -c 'import socket,sys;s=socket.create_connection(("127.0.0.1",int(sys.argv[1])));s.sendall(sys.stdin.buffer.read());s.recv(100)' "$D2"; code -X MKCOL "http://127.0.0.1:$D2/dav/pbkt2")"
check "server alive" 0 "$(kill -0 "${PIDS[0]}"; echo $?)"

echo "passed $pass, failed $fail"
[[ $fail -eq 0 ]]
