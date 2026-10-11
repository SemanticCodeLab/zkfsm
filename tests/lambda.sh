#!/usr/bin/env bash
# Object Lambda end to end: webhook functions from the environment and from
# `mc admin config set lambda_webhook`, GET ?lambdaArn= transforms (uppercase,
# rot13, chunked, Range), x-amz-fwd-* mapping, error cases, permissions, and
# https webhooks that demand a client certificate (TLS 1.3 and 1.2-only).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
MC="${MC:-$(command -v mc || true)}"
if [[ -z "$MC" ]] || ! "$MC" --version >/dev/null 2>&1; then echo "lambda.sh needs the MinIO client (set MC)"; exit 1; fi
H="$ROOT/tests/lambda_helper.py"
declare -A PID=()
cleanup() {
  if [[ "${fail:-0}" -gt 0 ]]; then echo "--- server log tail"; tail -n 30 "$WORK/z.log" 2>/dev/null; fi
  for p in "${PID[@]}"; do kill -9 "$p" 2>/dev/null || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

pass=0
fail=0
check() { # name expected actual
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); echo "ok   $1"
  else fail=$((fail + 1)); echo "FAIL $1: expected [$2] got [$3]"; fi
}
freeport() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }

AK="lambdaadmin"
SK="lambda-secret-0123"
export MC_CONFIG_DIR="$WORK/mc"
(cd "$ROOT" && zig build -Doptimize=ReleaseSafe)
BIN="$ROOT/zig-out/bin/zkfsm"

P="$(freeport)"
WH="$(freeport)"
DOWN="$(freeport)"
ep="http://127.0.0.1:$P"
mkdir -p "$WORK/hook"
python3 "$H" "$WH" "$WORK/hook" &
PID[hook]=$!

# Test PKI: a CA, a rogue CA, server and client certificates (EC and RSA).
PKI="$WORK/pki"
mkdir -p "$PKI" "$WORK/hooks" "$WORK/hooks12"
printf '%s\n' '[srv]' 'basicConstraints=CA:FALSE' 'subjectAltName=DNS:localhost,IP:127.0.0.1' 'extendedKeyUsage=serverAuth' \
  '[cli]' 'basicConstraints=CA:FALSE' 'extendedKeyUsage=clientAuth' >"$PKI/ext.cnf"
mkca() { # name
  openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null | openssl pkcs8 -topk8 -nocrypt -out "$PKI/$1.key"
  openssl req -x509 -new -key "$PKI/$1.key" -subj "/CN=$1" -days 2 -out "$PKI/$1.pem" -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
}
mkcert() { # name cn ca ext [keytype]
  if [[ "${5:-ec}" == rsa ]]; then openssl genrsa -out "$PKI/$1.key" 2048 2>/dev/null
  else openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null | openssl pkcs8 -topk8 -nocrypt -out "$PKI/$1.key"; fi
  openssl req -new -key "$PKI/$1.key" -subj "/CN=$2" -out "$PKI/$1.csr" 2>/dev/null
  openssl x509 -req -in "$PKI/$1.csr" -CA "$PKI/$3.pem" -CAkey "$PKI/$3.key" -CAcreateserial -days 2 -extfile "$PKI/ext.cnf" -extensions "$4" -out "$PKI/$1.pem" 2>/dev/null
}
mkca ca
mkca rogue
mkcert server localhost ca srv
mkcert server-rsa localhost ca srv rsa
mkcert client zkfsm-client ca cli
mkcert client-rsa zkfsm-client-rsa ca cli rsa
mkcert rogue-client rogue-client rogue cli
CA="$PKI/ca.pem"
CC="$PKI/client.pem"
CK="$PKI/client.key"
WHS="$(freeport)"
WHS12="$(freeport)"
python3 "$H" "$WHS" "$WORK/hooks" "$PKI/server.pem" "$PKI/server.key" "$CA" &
PID[hooks]=$!
python3 "$H" "$WHS12" "$WORK/hooks12" "$PKI/server-rsa.pem" "$PKI/server-rsa.key" "$CA" tls1.2 &
PID[hooks12]=$!

env ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" \
  MINIO_LAMBDA_WEBHOOK_ENABLE_upper=on MINIO_LAMBDA_WEBHOOK_ENDPOINT_upper="http://127.0.0.1:$WH/upper" \
  MINIO_LAMBDA_WEBHOOK_AUTH_TOKEN_upper=tok123 \
  ZKFSM_LAMBDA_WEBHOOK_ENABLE_rot=on ZKFSM_LAMBDA_WEBHOOK_ENDPOINT_rot="http://127.0.0.1:$WH/rot13" \
  MINIO_LAMBDA_WEBHOOK_ENABLE_chunked=on MINIO_LAMBDA_WEBHOOK_ENDPOINT_chunked="http://127.0.0.1:$WH/chunked" \
  MINIO_LAMBDA_WEBHOOK_ENABLE_deny=on MINIO_LAMBDA_WEBHOOK_ENDPOINT_deny="http://127.0.0.1:$WH/deny" \
  MINIO_LAMBDA_WEBHOOK_ENABLE_fail=on MINIO_LAMBDA_WEBHOOK_ENDPOINT_fail="http://127.0.0.1:$WH/fail" \
  MINIO_LAMBDA_WEBHOOK_ENABLE_down=on MINIO_LAMBDA_WEBHOOK_ENDPOINT_down="http://127.0.0.1:$DOWN/x" \
  MINIO_LAMBDA_WEBHOOK_ENDPOINT_off="http://127.0.0.1:$WH/upper" \
  MINIO_LAMBDA_WEBHOOK_ENABLE_envm=on MINIO_LAMBDA_WEBHOOK_ENDPOINT_envm="https://localhost:$WHS/upper" \
  MINIO_LAMBDA_WEBHOOK_CLIENT_CERT_envm="$CC" MINIO_LAMBDA_WEBHOOK_CLIENT_KEY_envm="$CK" ZKFSM_LAMBDA_WEBHOOK_TLS_CA_FILE_envm="$CA" \
  "$BIN" --data "$WORK/d" --listen "127.0.0.1:$P" >>"$WORK/z.log" 2>&1 &
PID[z]=$!
for _ in $(seq 300); do [[ "$(curl -s -o /dev/null -w '%{http_code}' "$ep/health/ready")" == 200 ]] && break; sleep 0.1; done
for _ in $(seq 50); do curl -s -o /dev/null "http://127.0.0.1:$WH/" && break; sleep 0.1; done
for p in "$WHS" "$WHS12"; do
  for _ in $(seq 50); do curl -s -o /dev/null --cacert "$CA" --cert "$CC" --key "$CK" "https://localhost:$p/" && break; sleep 0.1; done
done
"$MC" alias set z "$ep" "$AK" "$SK" >/dev/null

arn() { echo "arn:minio:s3-object-lambda::$1:webhook"; }
# get USER:SECRET PATH [curl args...] -> body to $WORK/out, headers to $WORK/hdr; prints status
get() {
  local cred="$1" path="$2"; shift 2
  curl -s --aws-sigv4 "aws:amz:us-east-1:s3" --user "$cred" -D "$WORK/hdr" -o "$WORK/out" -w '%{http_code}' "$@" "$ep$path"
}
hdr() { grep -i "^$1:" "$WORK/hdr" | head -n1 | cut -d' ' -f2- | tr -d '\r'; }
xmlcode() { sed -n 's:.*<Code>\(.*\)</Code>.*:\1:p' "$WORK/out"; }
A="$AK:$SK"

"$MC" mb z/docs >/dev/null
printf 'hello lambda world\n' | "$MC" pipe z/docs/greet.txt >/dev/null
printf 'abcdefghijklmnopqrstuvwxyz' | "$MC" pipe "z/docs/dir/a b+c.txt" >/dev/null

echo "== transforms"
check "uppercase status" 200 "$(get "$A" "/docs/greet.txt?lambdaArn=$(arn upper)")"
check "uppercase body" "HELLO LAMBDA WORLD" "$(cat "$WORK/out")"
check "fwd header mapped" "text/plain" "$(hdr content-type)"
check "second fwd header" "upper" "$(hdr x-transformed)"
check "webhook-only headers not leaked" "" "$(hdr x-amz-request-route)"
check "auth token sent as bearer" "Bearer tok123" "$(cat "$WORK/hook/auth")"
check "event protocolVersion" "1.00" "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["protocolVersion"])' "$WORK/hook/last.json")"
check "event userIdentity" "$AK" "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["userIdentity"]["accessKeyId"])' "$WORK/hook/last.json")"
check "event configuration arn" "$(arn upper)" "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["configuration"]["accessPointArn"])' "$WORK/hook/last.json")"
check "event userRequest url" 1 "$(python3 -c 'import json,sys; e=json.load(open(sys.argv[1])); print(int(e["userRequest"]["url"].startswith("/docs/greet.txt?lambdaArn=")))' "$WORK/hook/last.json")"
check "caller signature not in event" 0 "$(grep -c 'Authorization' "$WORK/hook/last.json" || true)"
check "outputRoute and token present" 1 "$(python3 -c 'import json,sys; c=json.load(open(sys.argv[1]))["getObjectContext"]; print(int(len(c["outputRoute"])>0 and len(c["outputToken"])>0))' "$WORK/hook/last.json")"
check "inputS3Url is presigned" 1 "$(python3 -c 'import json,sys; u=json.load(open(sys.argv[1]))["getObjectContext"]["inputS3Url"]; print(int("X-Amz-Signature=" in u and "lambdaArn" not in u))' "$WORK/hook/last.json")"
check "rot13" 200 "$(get "$A" "/docs/greet.txt?lambdaArn=$(arn rot)")"
check "rot13 body" "uryyb ynzoqn jbeyq" "$(cat "$WORK/out")"
check "chunked webhook reply" 200 "$(get "$A" "/docs/dir/a%20b%2Bc.txt?lambdaArn=$(arn chunked)")"
check "chunked body, escaped key" "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "$(cat "$WORK/out")"
check "range forwarded" 206 "$(get "$A" "/docs/dir/a%20b%2Bc.txt?lambdaArn=$(arn upper)" -H 'Range: bytes=2-5')"
check "range body" "CDEF" "$(cat "$WORK/out")"
check "plain GET untouched" "hello lambda world" "$("$MC" cat z/docs/greet.txt)"

echo "== errors"
check "fwd-status 403" 403 "$(get "$A" "/docs/greet.txt?lambdaArn=$(arn deny)")"
check "fwd error code" AccessDenied "$(xmlcode)"
check "fwd error message" 1 "$(grep -c '<Message>blocked by lambda</Message>' "$WORK/out")"
check "fwd header on error" denied "$(hdr x-lambda)"
check "webhook 500" 500 "$(get "$A" "/docs/greet.txt?lambdaArn=$(arn fail)")"
check "webhook 500 code" LambdaFunctionError "$(xmlcode)"
check "webhook down" 500 "$(get "$A" "/docs/greet.txt?lambdaArn=$(arn down)")"
check "webhook down code" InternalError "$(xmlcode)"
check "unknown ARN" 404 "$(get "$A" "/docs/greet.txt?lambdaArn=$(arn nope)")"
check "unknown ARN code" LambdaARNNotFound "$(xmlcode)"
check "env target without ENABLE ignored" 404 "$(get "$A" "/docs/greet.txt?lambdaArn=$(arn off)")"
check "malformed ARN" 400 "$(get "$A" "/docs/greet.txt?lambdaArn=arn:minio:sqs::upper:webhook")"
check "malformed ARN code" LambdaARNInvalid "$(xmlcode)"
check "missing object surfaces through the function" 404 "$(get "$A" "/docs/missing.txt?lambdaArn=$(arn upper)")"
check "missing object code" FetchFailed "$(xmlcode)"

echo "== permissions"
"$MC" admin user add z reader reader-secret-1 >/dev/null
"$MC" admin user add z nobody nobody-secret-1 >/dev/null
"$MC" admin policy attach z readonly --user reader >/dev/null
check "reader allowed" 200 "$(get "reader:reader-secret-1" "/docs/greet.txt?lambdaArn=$(arn upper)")"
check "reader body (presigned with reader's key)" "HELLO LAMBDA WORLD" "$(cat "$WORK/out")"
check "presigned as the caller" 1 "$(python3 -c 'import json,sys; print(int("X-Amz-Credential=reader%2F" in json.load(open(sys.argv[1]))["getObjectContext"]["inputS3Url"]))' "$WORK/hook/last.json")"
before="$(stat -c %Y "$WORK/hook/last.json")"
sleep 1
check "caller without GetObject denied" 403 "$(get "nobody:nobody-secret-1" "/docs/greet.txt?lambdaArn=$(arn upper)")"
check "denied code" AccessDenied "$(xmlcode)"
check "webhook not called when denied" "$before" "$(stat -c %Y "$WORK/hook/last.json")"
check "anonymous denied" 403 "$(curl -s -o "$WORK/out" -w '%{http_code}' "$ep/docs/greet.txt?lambdaArn=$(arn upper)")"
check "bad signature denied" 403 "$(get "$AK:wrong-secret" "/docs/greet.txt?lambdaArn=$(arn upper)")"

echo "== admin config"
check "config set" "Successfully applied new settings." "$("$MC" admin config set z lambda_webhook:cfg endpoint="http://127.0.0.1:$WH/rot13" 2>&1 | tail -n1)"
check "config get shows endpoint" 1 "$("$MC" admin config get z lambda_webhook:cfg | grep -c "endpoint=http://127.0.0.1:$WH/rot13")"
check "configured target works" 200 "$(get "$A" "/docs/greet.txt?lambdaArn=$(arn cfg)")"
check "configured target body" "uryyb ynzoqn jbeyq" "$(cat "$WORK/out")"
check "unknown key rejected" 1 "$("$MC" admin config set z lambda_webhook:cfg nope=1 >/dev/null 2>&1 && echo 0 || echo 1)"
check "bad endpoint rejected" 1 "$("$MC" admin config set z lambda_webhook:x endpoint=ftp://h >/dev/null 2>&1 && echo 0 || echo 1)"
check "unreadable client cert rejected" 1 "$("$MC" admin config set z lambda_webhook:x endpoint="https://127.0.0.1:$WH/" client_cert=/c.pem client_key=/k.pem >/dev/null 2>&1 && echo 0 || echo 1)"
check "client cert without key rejected" 1 "$("$MC" admin config set z lambda_webhook:x endpoint="https://localhost:$WHS/" client_cert="$CC" >/dev/null 2>&1 && echo 0 || echo 1)"
check "mismatched cert and key rejected" 1 "$("$MC" admin config set z lambda_webhook:x endpoint="https://localhost:$WHS/" client_cert="$CC" client_key="$PKI/client-rsa.key" >/dev/null 2>&1 && echo 0 || echo 1)"
check "unreadable CA file rejected" 1 "$("$MC" admin config set z lambda_webhook:x endpoint="https://localhost:$WHS/" tls_ca_file=/nope.pem >/dev/null 2>&1 && echo 0 || echo 1)"
check "bad tls_min_version rejected" 1 "$("$MC" admin config set z lambda_webhook:x endpoint="https://localhost:$WHS/" tls_min_version=1.1 >/dev/null 2>&1 && echo 0 || echo 1)"
check "rejected target not stored" 404 "$(get "$A" "/docs/greet.txt?lambdaArn=$(arn x)")"

echo "== mutual TLS webhook"
applied="Successfully applied new settings."
set_l() { "$MC" admin config set z "$@" 2>&1 | tail -n1; }
peer() { cat "$1/peer" 2>/dev/null || true; rm -f "$1/peer"; }
check "env target with client cert" 200 "$(get "$A" "/docs/greet.txt?lambdaArn=$(arn envm)")"
check "env mTLS body" "HELLO LAMBDA WORLD" "$(cat "$WORK/out")"
check "env mTLS peer (client CN, TLS 1.3)" "zkfsm-client TLSv1.3" "$(peer "$WORK/hooks")"
check "mTLS target set" "$applied" "$(set_l lambda_webhook:mtls endpoint="https://localhost:$WHS/rot13" client_cert="$CC" client_key="$CK" tls_ca_file="$CA")"
check "mTLS target works" 200 "$(get "$A" "/docs/greet.txt?lambdaArn=$(arn mtls)")"
check "mTLS body" "uryyb ynzoqn jbeyq" "$(cat "$WORK/out")"
check "mTLS peer" "zkfsm-client TLSv1.3" "$(peer "$WORK/hooks")"
set_l lambda_webhook:mtls endpoint="https://localhost:$WHS/chunked" >/dev/null
check "mTLS chunked reply" 200 "$(get "$A" "/docs/dir/a%20b%2Bc.txt?lambdaArn=$(arn mtls)")"
check "mTLS chunked body" "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "$(cat "$WORK/out")"
check "RSA client cert set" "$applied" "$(set_l lambda_webhook:rsa endpoint="https://localhost:$WHS/upper" client_cert="$PKI/client-rsa.pem" client_key="$PKI/client-rsa.key" tls_ca_file="$CA")"
check "RSA client cert works" 200 "$(get "$A" "/docs/greet.txt?lambdaArn=$(arn rsa)")"
check "RSA peer" "zkfsm-client-rsa TLSv1.3" "$(peer "$WORK/hooks")"
check "TLS 1.2-only webhook set" "$applied" "$(set_l lambda_webhook:t12 endpoint="https://localhost:$WHS12/upper" client_cert="$CC" client_key="$CK" tls_ca_file="$CA")"
check "TLS 1.2-only webhook works" 200 "$(get "$A" "/docs/greet.txt?lambdaArn=$(arn t12)")"
check "TLS 1.2 body" "HELLO LAMBDA WORLD" "$(cat "$WORK/out")"
check "TLS 1.2 peer" "zkfsm-client TLSv1.2" "$(peer "$WORK/hooks12")"
check "tls_min_version=1.3 set" "$applied" "$(set_l lambda_webhook:t12 tls_min_version=1.3)"
check "min 1.3 refuses the 1.2-only webhook" 500 "$(get "$A" "/docs/greet.txt?lambdaArn=$(arn t12)")"
check "min 1.3 refusal code" InternalError "$(xmlcode)"
check "min 1.3 never reached the function" "" "$(peer "$WORK/hooks12")"
check "no client cert set" "$applied" "$(set_l lambda_webhook:nocert endpoint="https://localhost:$WHS/upper" tls_ca_file="$CA")"
check "webhook refuses a caller without a certificate" 500 "$(get "$A" "/docs/greet.txt?lambdaArn=$(arn nocert)")"
check "rogue client cert set" "$applied" "$(set_l lambda_webhook:rogue endpoint="https://localhost:$WHS/upper" client_cert="$PKI/rogue-client.pem" client_key="$PKI/rogue-client.key" tls_ca_file="$CA")"
check "webhook refuses a rogue client certificate" 500 "$(get "$A" "/docs/greet.txt?lambdaArn=$(arn rogue)")"
check "refused callers never reached the function" "" "$(peer "$WORK/hooks")"
check "wrong CA set" "$applied" "$(set_l lambda_webhook:badca endpoint="https://localhost:$WHS/upper" client_cert="$CC" client_key="$CK" tls_ca_file="$PKI/rogue.pem")"
check "server certificate from another CA refused" 500 "$(get "$A" "/docs/greet.txt?lambdaArn=$(arn badca)")"
check "untrusted server never got the event" "" "$(peer "$WORK/hooks")"
check "tls_skip_verify set" "$applied" "$(set_l lambda_webhook:badca tls_skip_verify=on)"
check "tls_skip_verify still presents the client cert" 200 "$(get "$A" "/docs/greet.txt?lambdaArn=$(arn badca)")"
check "skip-verify peer" "zkfsm-client TLSv1.3" "$(peer "$WORK/hooks")"
check "name mismatch set" "$applied" "$(set_l lambda_webhook:name endpoint="https://localhost:$WHS/upper" client_cert="$CC" client_key="$CK" tls_ca_file="$CA" tls_server_name=other.example)"
check "server name mismatch refused" 500 "$(get "$A" "/docs/greet.txt?lambdaArn=$(arn name)")"
check "tls_server_name=localhost set" "$applied" "$(set_l lambda_webhook:name tls_server_name=localhost endpoint="https://127.0.0.1:$WHS/upper")"
check "tls_server_name overrides the dialed host" 200 "$(get "$A" "/docs/greet.txt?lambdaArn=$(arn name)")"
check "config get lists TLS keys" 1 "$("$MC" admin config get z lambda_webhook:mtls | grep -c "client_cert=$CC")"
P2="$(freeport)"
set +e
timeout 20 env ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" MINIO_LAMBDA_WEBHOOK_ENABLE_m=on \
  MINIO_LAMBDA_WEBHOOK_ENDPOINT_m="https://127.0.0.1:$WH/" MINIO_LAMBDA_WEBHOOK_CLIENT_CERT_m=/c.pem MINIO_LAMBDA_WEBHOOK_CLIENT_KEY_m=/k.pem \
  "$BIN" --data "$WORK/d2" --listen "127.0.0.1:$P2" >"$WORK/z2.log" 2>&1
rc=$?
set -e
check "env unreadable client cert fails startup" 2 "$rc"
check "startup error names the target" 1 "$(grep -c 'lambda_webhook:m' "$WORK/z2.log")"
check "disable" "Successfully applied new settings." "$("$MC" admin config set z lambda_webhook:cfg enable=off 2>&1 | tail -n1)"
check "disabled target not found" 404 "$(get "$A" "/docs/greet.txt?lambdaArn=$(arn cfg)")"
"$MC" admin config set z lambda_webhook:cfg enable=on >/dev/null
check "re-enabled" 200 "$(get "$A" "/docs/greet.txt?lambdaArn=$(arn cfg)")"
check "config reset" 1 "$("$MC" admin config reset z lambda_webhook:cfg 2>&1 | grep -c 'successfully reset')"
check "reset target gone" 404 "$(get "$A" "/docs/greet.txt?lambdaArn=$(arn cfg)")"

echo "lambda.sh: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
