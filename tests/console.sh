#!/usr/bin/env bash
# Web console: login/session API, signing proxy, admin decryption, share links,
# security headers, OpenID code login (mock provider), then the UI unit and
# Playwright suites when console/node_modules exists (CONSOLE_E2E=0 skips them).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
free_port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
PORT="$(free_port)"
CPORT="$(free_port)"
EP="http://127.0.0.1:$PORT"
CON="http://127.0.0.1:$CPORT"
API="$CON/api/v1"
DATA="$(mktemp -d)"
WORK="$(mktemp -d)"
PID=""
IDP_PID=""
cleanup() {
  [[ -n "$PID" ]] && kill "$PID" 2>/dev/null || true
  [[ -n "$IDP_PID" ]] && kill "$IDP_PID" 2>/dev/null || true
  rm -rf "$DATA" "$WORK"
}
trap cleanup EXIT

pass=0
fail=0
check() { # name expected actual
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); echo "ok   $1"
  else fail=$((fail + 1)); echo "FAIL $1: expected [$2] got [$3]"; fi
}
contains() { # name needle haystack
  if [[ "$3" == *"$2"* ]]; then pass=$((pass + 1)); echo "ok   $1"
  else fail=$((fail + 1)); echo "FAIL $1: [$2] not in [${3:0:300}]"; fi
}
status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
header() { # name, curl args...
  local h="$1"; shift
  curl -s -D - -o /dev/null "$@" | tr -d '\r' | awk -v h="$h" 'BEGIN{IGNORECASE=1} index(tolower($0), tolower(h)":")==1 {sub(/^[^:]*: */,""); print}'
}
JAR="$WORK/jar"
C=(-s -b "$JAR" -H "x-console-csrf: 1")

(cd "$ROOT" && zig build)
ZKFSM_ACCESS_KEY=admin ZKFSM_SECRET_KEY=adminsecret "$ROOT/zig-out/bin/zkfsm" --data "$DATA" --listen "127.0.0.1:$PORT" \
  --console-address "127.0.0.1:$CPORT" --console-session 3600 2>"$WORK/server.log" &
PID=$!
for _ in $(seq 50); do curl -s -o /dev/null "$CON/" && break; sleep 0.1; done

# --- static bundle and headers
check "index served" 200 "$(status "$CON/")"
contains "page CSP" "default-src 'self'" "$(header content-security-policy "$CON/")"
check "frame denied" "DENY" "$(header x-frame-options "$CON/")"
check "spa fallback" 200 "$(status "$CON/some/deep/link")"
check "app.js" 200 "$(status "$CON/app.js")"
contains "js type" "javascript" "$(header content-type "$CON/app.js")"

# --- login and session
check "no session" 401 "$(status "$API/session")"
check "proxy needs session" 401 "$(status "$API/s3/")"
check "login without csrf header" 403 "$(status -H 'content-type: application/json' -d '{"accessKey":"admin","secretKey":"adminsecret"}' "$API/login")"
check "cross-origin login" 403 "$(status -H 'x-console-csrf: 1' -H 'origin: http://evil.example' -d '{"accessKey":"admin","secretKey":"adminsecret"}' "$API/login")"
check "bad secret" 401 "$(status -H 'x-console-csrf: 1' -d '{"accessKey":"admin","secretKey":"wrongwrong"}' "$API/login")"
check "malformed login" 400 "$(status -H 'x-console-csrf: 1' -d 'nope' "$API/login")"
SETC="$(curl -s -D - -o "$WORK/login.json" -c "$JAR" -H 'x-console-csrf: 1' -d '{"accessKey":"admin","secretKey":"adminsecret"}' "$API/login" | tr -d '\r' | grep -i '^set-cookie:')"
contains "cookie httponly" "HttpOnly" "$SETC"
contains "cookie samesite" "SameSite=Strict" "$SETC"
contains "cookie lifetime" "Max-Age=3600" "$SETC"
contains "login user" '"user":"admin"' "$(cat "$WORK/login.json")"
if grep -q adminsecret "$WORK/login.json" "$JAR"; then check "secret not exposed" no yes; else check "secret not exposed" no no; fi
contains "temporary key" '"accessKey":"ASIA' "$(cat "$WORK/login.json")"
check "session" 200 "$(status -b "$JAR" "$API/session")"
contains "methods" '"password":true' "$(curl -s "$API/login/methods")"

# --- signing proxy
check "create bucket" 200 "$(status "${C[@]}" -X PUT "$API/s3/con")"
check "proxy put needs csrf" 403 "$(status -b "$JAR" -X PUT --data-binary x "$API/s3/con/x")"
printf 'hello console\n' >"$WORK/h.txt"
check "put object (key needs encoding)" 200 "$(status "${C[@]}" -X PUT -H 'content-type: text/plain' -H 'x-amz-meta-note: hi there' --data-binary @"$WORK/h.txt" "$API/s3/con/dir%20a/h%2B1.txt")"
contains "list via proxy" "<Key>dir a/h+1.txt</Key>" "$(curl "${C[@]}" "$API/s3/con?list-type=2&prefix=dir%20a%2F")"
check "get via proxy" "hello console" "$(curl "${C[@]}" "$API/s3/con/dir%20a/h%2B1.txt")"
check "metadata forwarded" "hi there" "$(header x-amz-meta-note "${C[@]}" -I "$API/s3/con/dir%20a/h%2B1.txt")"
check "head length" 14 "$(header content-length "${C[@]}" -I "$API/s3/con/dir%20a/h%2B1.txt")"
check "range" "hello" "$(curl "${C[@]}" -H 'range: bytes=0-4' "$API/s3/con/dir%20a/h%2B1.txt")"
contains "download disposition" "attachment; filename*=UTF-8''h%2B1.txt" "$(header content-disposition "${C[@]}" "$API/s3/con/dir%20a/h%2B1.txt?x-console-download=1")"
contains "user content sandboxed" "sandbox" "$(header content-security-policy "${C[@]}" "$API/s3/con/dir%20a/h%2B1.txt")"
check "nosniff" "nosniff" "$(header x-content-type-options "${C[@]}" "$API/s3/con/dir%20a/h%2B1.txt")"
check "s3 errors pass through" 404 "$(status "${C[@]}" "$API/s3/con/missing")"
contains "s3 error body" "<Code>NoSuchKey</Code>" "$(curl "${C[@]}" "$API/s3/con/missing")"
check "put error body (PUT response read)" 400 "$(status "${C[@]}" -X PUT --data-binary '<bad' "$API/s3/con?versioning")"
check "path traversal" 400 "$(status "${C[@]}" --path-as-is "$API/s3/con/../x")"
check "unknown api" 404 "$(status "${C[@]}" "$API/nope")"
head -c 3000000 /dev/urandom >"$WORK/big.bin"
check "3 MB put" 200 "$(status "${C[@]}" -X PUT --data-binary @"$WORK/big.bin" "$API/s3/con/big.bin")"
curl "${C[@]}" -o "$WORK/big.out" "$API/s3/con/big.bin"
check "3 MB streamed back" "$(md5sum <"$WORK/big.bin")" "$(md5sum <"$WORK/big.out")"
UP="$(curl "${C[@]}" -X POST "$API/s3/con/mp.bin?uploads" | sed -n 's:.*<UploadId>\(.*\)</UploadId>.*:\1:p')"
ET="$(header etag "${C[@]}" -X PUT --data-binary @"$WORK/big.bin" "$API/s3/con/mp.bin?partNumber=1&uploadId=$UP")"
check "multipart complete" 200 "$(status "${C[@]}" -X POST --data-binary "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>$ET</ETag></Part></CompleteMultipartUpload>" "$API/s3/con/mp.bin?uploadId=$UP")"

# --- admin API through the proxy (sio sealing done server-side)
check "add user (sealed body)" 200 "$(status "${C[@]}" -X PUT -H 'x-console-encrypt: 1' -d '{"secretKey":"bobsecret12","status":"enabled"}' "$API/s3/minio/admin/v3/add-user?accessKey=bob")"
check "list users decrypted" '{"bob":{"status":"enabled"}}' "$(curl "${C[@]}" "$API/s3/minio/admin/v3/list-users")"
check "canned policy" 200 "$(status "${C[@]}" -X PUT -d '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::con","arn:aws:s3:::con/*"]}]}' "$API/s3/minio/admin/v3/add-canned-policy?name=conread")"
check "attach policy" 200 "$(status "${C[@]}" -X PUT "$API/s3/minio/admin/v3/set-user-or-group-policy?policyName=conread&userOrGroup=bob&isGroup=false")"
contains "service account sealed response" '"secretKey"' "$(curl "${C[@]}" -X PUT -H 'x-console-encrypt: 1' -d '{"name":"ci"}' "$API/s3/minio/admin/v3/add-service-account")"

# --- dashboard, metrics, heal
CL="$(curl "${C[@]}" "$API/cluster")"
contains "cluster drives" '"drives":[{"path"' "$CL"
contains "cluster usage" '"buckets":1' "$CL"
contains "metrics" "zkfsm_requests_total" "$(curl "${C[@]}" "$API/metrics")"
check "heal trigger" 202 "$(status "${C[@]}" -X POST "$API/heal")"

# --- share links
URL="$(curl "${C[@]}" "$API/presign?bucket=con&key=dir%20a/h%2B1.txt&expires=600" | python3 -c 'import sys,json;print(json.load(sys.stdin)["url"])')"
check "presigned get" "hello console" "$(curl -s "$URL")"
EXP="$(curl "${C[@]}" "$API/presign?bucket=con&key=big.bin&expires=999999" | python3 -c 'import sys,json;print(json.load(sys.stdin)["expiresSeconds"])')"
if [[ "$EXP" -le 3600 ]]; then check "share link capped by session" ok ok; else check "share link capped by session" "<=3600" "$EXP"; fi

# --- a limited user sees only what its policy allows
BJ="$WORK/bob"
check "bob login" 200 "$(status -c "$BJ" -H 'x-console-csrf: 1' -d '{"accessKey":"bob","secretKey":"bobsecret12"}' "$API/login")"
check "bob reads" "hello console" "$(curl -s -b "$BJ" "$API/s3/con/dir%20a/h%2B1.txt")"
check "bob cannot write" 403 "$(status -b "$BJ" -H 'x-console-csrf: 1' -X PUT --data-binary x "$API/s3/con/nope")"
check "bob cannot admin" 403 "$(status -b "$BJ" "$API/s3/minio/admin/v3/list-users")"
check "bob has no dashboard" 403 "$(status -b "$BJ" "$API/cluster")"

# --- logout
check "logout" 200 "$(status "${C[@]}" -X POST "$API/logout")"
check "session gone" 401 "$(status -b "$JAR" "$API/session")"
check "proxy after logout" 401 "$(status -b "$JAR" "$API/s3/")"

# --- OpenID authorization-code login against the mock provider
python3 "$ROOT/tests/mock_idp.py" >"$WORK/idp.port" 2>"$WORK/idp.log" &
IDP_PID=$!
for _ in $(seq 100); do [[ -s "$WORK/idp.port" ]] && break; sleep 0.1; done
IDP="http://127.0.0.1:$(cat "$WORK/idp.port")"
curl -s -c "$JAR" -H 'x-console-csrf: 1' -d '{"accessKey":"admin","secretKey":"adminsecret"}' "$API/login" >/dev/null
check "add openid provider" 200 "$(status "${C[@]}" -X PUT -H 'x-console-encrypt: 1' --data-binary "config_url=$IDP/.well-known/openid-configuration client_id=zkfsm-console claim_name=policy display_name=Corp" "$API/s3/minio/admin/v3/idp-config/openid/corp")"
contains "login offers provider" '"label":"Corp"' "$(curl -s "$API/login/methods")"
LOC="$(header location "$API/oidc/start?provider=corp")"
contains "redirect to provider" "$IDP/auth?response_type=code&client_id=zkfsm-console" "$LOC"
contains "redirect has state" "&state=" "$LOC"
CB="$(header location "$LOC")"
contains "provider redirects back" "/api/v1/oidc/callback?code=" "$CB"
OJ="$WORK/oidc"
check "callback starts session" 303 "$(curl -s -o /dev/null -w '%{http_code}' -c "$OJ" "$CB")"
SESS="$(curl -s -b "$OJ" "$API/session")"
contains "sso user" '"user":"sso-user"' "$SESS"
contains "sso provider" '"provider":"openid:corp"' "$SESS"
check "sso user lists buckets" 200 "$(status -b "$OJ" "$API/s3/")"
check "replayed code rejected" "/?error=" "$(header location "$CB" | cut -c1-8)"
check "unknown provider" "/?error=" "$(header location "$API/oidc/start?provider=nope" | cut -c1-8)"

echo "api: $pass passed, $fail failed"
[[ $fail -eq 0 ]] || { echo "--- server log"; tail -50 "$WORK/server.log"; exit 1; }

# --- UI unit and end-to-end suites
if [[ "${CONSOLE_E2E:-1}" != "0" && -d "$ROOT/console/node_modules" ]]; then
  cd "$ROOT/console"
  npx vitest run
  CONSOLE_URL="$CON" SCREENSHOT_DIR="${SCREENSHOT_DIR:-$WORK/shots}" npx playwright test
else
  echo "skip UI suites (console/node_modules missing or CONSOLE_E2E=0)"
fi
echo "console: OK"
