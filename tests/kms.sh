#!/usr/bin/env bash
# KMS backends end to end. Always: local and static backends, the /minio/kms/v1
# API (mc admin kms key create|list|status, rotate, status), access control,
# SSE-KMS across restarts. When available: a dev Vault (VAULT_BIN or docker)
# for the Transit/KV2/AppRole live tests plus a server on Vault Transit, and a
# kms-api emulator (LOCAL_KMS_BIN, i.e. nsmithuk/local-kms, or docker).
set -euo pipefail
S3CLI_BIN="${S3CLI_BIN:-aws}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
freeport() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
PORT="$(freeport)"
EP="http://127.0.0.1:$PORT"
WORK="$(mktemp -d)"
PID=""
AUX=()
CIDS=()
DOCKER="${DOCKER:-docker}"
stop() { if [[ -n "$PID" ]] && kill -0 "$PID" 2>/dev/null; then kill "$PID"; wait "$PID" 2>/dev/null || true; fi; PID=""; }
cleanup() {
  stop
  for p in "${AUX[@]}"; do kill "$p" 2>/dev/null || true; done
  for c in "${CIDS[@]}"; do "$DOCKER" rm -f "$c" >/dev/null 2>&1 || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

AK="zkfsmkmsaccess"
SK="zkfsm-kms-secret-123"
export ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK"
export AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_DEFAULT_REGION=us-east-1
export AWS_CONFIG_FILE="$WORK/aws.conf" AWS_SHARED_CREDENTIALS_FILE="$WORK/aws.creds" AWS_PAGER="" AWS_EC2_METADATA_DISABLED=true
printf '[default]\ns3 =\n  addressing_style = path\n' >"$AWS_CONFIG_FILE"
export MC_CONFIG_DIR="$WORK/mc"
MC="${MC:-$(command -v mc || true)}"

fail() { echo "FAIL: $*" >&2; for l in "$WORK"/*.log; do [[ -f "$l" ]] && { echo "== $l" >&2; tail -15 "$l" >&2; }; done; exit 1; }
ok() { echo "ok   $*"; }
skip() { echo "skip $*"; }
s3api() { "$S3CLI_BIN" --endpoint-url "$EP" s3api "$@"; }
kmsapi() { curl -s --aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" "$@"; }
waitport() { for _ in $(seq 150); do curl -s -o /dev/null "$1" && return 0; sleep 0.1; done; return 1; }

(cd "$ROOT" && zig build)
BIN="$ROOT/zig-out/bin/zkfsm"
start() { # log, data dir, extra flags... (environment passes through)
  local log=$1 data=$2; shift 2
  "$BIN" --data "$data" --listen "127.0.0.1:$PORT" --scan-interval 0 "$@" >"$WORK/$log" 2>&1 &
  PID=$!
  waitport "$EP/" || fail "server did not start ($log)"
}
head -c 200000 /dev/urandom >"$WORK/obj.bin"
roundtrip() { # bucket key extra put args...
  local b=$1 k=$2; shift 2
  s3api put-object --bucket "$b" --key "$k" --body "$WORK/obj.bin" "$@" >/dev/null || fail "put $b/$k"
  s3api get-object --bucket "$b" --key "$k" "$WORK/rt.out" >/dev/null || fail "get $b/$k"
  cmp -s "$WORK/obj.bin" "$WORK/rt.out" || fail "$b/$k mismatch"
}

if [[ -z "$MC" ]]; then fail "mc is required (set MC)"; fi

# ---------------------------------------------------------------- local backend
start local.log "$WORK/d-local" --kms-backend local --kms-dir "$WORK/kms"
"$MC" alias set z "$EP" "$AK" "$SK" >/dev/null
st=$(kmsapi "$EP/minio/kms/v1/status")
grep -q '"name":"local"' <<<"$st" && grep -q '"default-key-id":"zkfsm-sse-s3"' <<<"$st" || fail "kms status: $st"
"$MC" admin kms key create z tenant-a >/dev/null || fail "mc admin kms key create"
"$MC" admin kms key list z | grep -q tenant-a || fail "mc admin kms key list: $("$MC" admin kms key list z)"
"$MC" admin kms key list --json z | grep -q zkfsm-sse-s3 || fail "default key not listed"
"$MC" admin kms key status --json z tenant-a | grep -Eq '"keyId": ?"tenant-a"' || fail "key status"
if "$MC" admin kms key status --json z tenant-a | grep -q "Error"; then fail "key status reports an error"; fi
"$MC" admin kms key status --json z | grep -Eq '"keyId": ?"zkfsm-sse-s3"' || fail "default key status"
if "$MC" admin kms key status --json z no-such-key 2>&1 | grep -Eq '"encryptionError": ?""'; then fail "missing key reported healthy"; fi
"$MC" admin kms key status --json z no-such-key | grep -q 'encryptionError' || fail "missing key status has no error"
code=$(kmsapi -o /dev/null -w '%{http_code}' -X POST "$EP/minio/kms/v1/key/create?key-id=tenant-a")
[[ "$code" == 409 ]] || fail "duplicate key create got $code"
code=$(kmsapi -o /dev/null -w '%{http_code}' -X POST "$EP/minio/kms/v1/key/create?key-id=bad%20name")
[[ "$code" == 400 ]] || fail "bad key name got $code"
code=$(curl -s -o /dev/null -w '%{http_code}' "$EP/minio/kms/v1/status")
[[ "$code" == 403 ]] || fail "anonymous kms status got $code"
ok "local: status, key create/list/status, duplicate and bad names, anonymous refused"

s3api create-bucket --bucket kms-local >/dev/null
roundtrip kms-local k1 --server-side-encryption aws:kms --ssekms-key-id tenant-a
s3api head-object --bucket kms-local --key k1 | grep -q '"SSEKMSKeyId": "tenant-a"' || fail "key id on head"
kmsapi -f -X POST "$EP/minio/kms/v1/key/rotate?key-id=tenant-a" >/dev/null || fail "rotate"
s3api get-object --bucket kms-local --key k1 "$WORK/rot.out" >/dev/null && cmp -s "$WORK/obj.bin" "$WORK/rot.out" || fail "read after rotate"
roundtrip kms-local k2 --server-side-encryption aws:kms --ssekms-key-id tenant-a
ok "local: SSE-KMS with a created key, rotation keeps old objects readable"

"$MC" admin user add z kmsuser kmsuser-secret-1 >/dev/null
"$MC" admin policy attach z readwrite --user kmsuser >/dev/null
"$MC" alias set zu "$EP" kmsuser kmsuser-secret-1 >/dev/null
if "$MC" admin kms key create zu denied-key >/dev/null 2>&1; then fail "non-admin created a key"; fi
cat >"$WORK/kmspol.json" <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["kms:CreateKey","kms:ListKeys","kms:KeyStatus"],"Resource":["arn:aws:s3:::*"]}]}
JSON
"$MC" admin policy create z kmsadmin "$WORK/kmspol.json" >/dev/null
"$MC" admin policy attach z kmsadmin --user kmsuser >/dev/null
"$MC" admin kms key create zu allowed-key >/dev/null || fail "kms:CreateKey policy not honoured"
ok "kms:* actions gate the KMS API"
stop
start local2.log "$WORK/d-local" --kms-backend local --kms-dir "$WORK/kms"
s3api get-object --bucket kms-local --key k1 "$WORK/r.out" >/dev/null && cmp -s "$WORK/obj.bin" "$WORK/r.out" || fail "read after restart"
"$MC" admin kms key list z | grep -q allowed-key || fail "keys lost on restart"
ok "local: keys and objects survive restart"
BKEY="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
kmsapi -f -X POST -H "x-zkfsm-kms-backup-key: $BKEY" "$EP/minio/kms/v1/backup" >"$WORK/backup.json" || fail "kms backup"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); m=json.loads(d["manifest"]); assert d["bundle"] and {"tenant-a","allowed-key"} <= {k["id"] for k in m["keys"]}' "$WORK/backup.json" \
  || fail "backup document: $(head -c 300 "$WORK/backup.json")"
kmsapi -f -X POST "$EP/minio/kms/v1/backup" | grep -q '"bundle":null' || fail "metadata-only backup"
stop
# Restore into an empty key directory, then read the old objects.
start local3.log "$WORK/d-local" --kms-backend local --kms-dir "$WORK/kms-restored"
s3api get-object --bucket kms-local --key k1 "$WORK/r.out" >/dev/null 2>&1 && fail "read before restore"
code=$(kmsapi -o /dev/null -w '%{http_code}' -X POST --data-binary @"$WORK/backup.json" "$EP/minio/kms/v1/restore")
[[ "$code" == 400 ]] || fail "restore without backup key got $code"
kmsapi -f -X POST -H "x-zkfsm-kms-backup-key: $BKEY" --data-binary @"$WORK/backup.json" "$EP/minio/kms/v1/restore?dry-run=true" \
  | grep -q '"dry_run":true' || fail "restore dry run"
s3api get-object --bucket kms-local --key k1 "$WORK/r.out" >/dev/null 2>&1 && fail "dry run restored keys"
WRONG="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
code=$(kmsapi -o /dev/null -w '%{http_code}' -X POST -H "x-zkfsm-kms-backup-key: $WRONG" --data-binary @"$WORK/backup.json" "$EP/minio/kms/v1/restore")
[[ "$code" == 400 ]] || fail "restore with a wrong backup key got $code"
kmsapi -f -X POST -H "x-zkfsm-kms-backup-key: $BKEY" --data-binary @"$WORK/backup.json" "$EP/minio/kms/v1/restore" \
  | grep -q '"restored":' || fail "restore"
s3api get-object --bucket kms-local --key k1 "$WORK/r.out" >/dev/null && cmp -s "$WORK/obj.bin" "$WORK/r.out" || fail "read after restore"
ok "local: backup (sealed bundle), dry run, wrong key refused, restore"
stop

# ---------------------------------------------------------------- static key
KEY="static-key:$(head -c 32 /dev/urandom | base64 -w0)"
MINIO_KMS_SECRET_KEY="$KEY" start static.log "$WORK/d-static"
grep -q "kms backend static, default key static-key" "$WORK/static.log" || fail "static backend log"
s3api create-bucket --bucket kms-static >/dev/null
roundtrip kms-static s1 --server-side-encryption AES256
roundtrip kms-static s2 --server-side-encryption aws:kms
code=$(kmsapi -o /dev/null -w '%{http_code}' -X POST "$EP/minio/kms/v1/key/create?key-id=other")
[[ "$code" == 501 ]] || fail "static backend key create got $code"
"$MC" admin kms key list z | grep -q static-key || fail "static key not listed"
stop
ZKFSM_KMS_SECRET_KEY="$KEY" start static2.log "$WORK/d-static"
s3api get-object --bucket kms-static --key s1 "$WORK/s.out" >/dev/null && cmp -s "$WORK/obj.bin" "$WORK/s.out" || fail "static read after restart"
stop
ZKFSM_KMS_SECRET_KEY="static-key:$(head -c 32 /dev/urandom | base64 -w0)" start static3.log "$WORK/d-static"
if s3api get-object --bucket kms-static --key s1 "$WORK/s.out" >/dev/null 2>&1; then fail "read with a different static key"; fi
stop
if "$BIN" --data "$WORK/d-x" --listen "127.0.0.1:$PORT" --kms-secret-key "bad" >"$WORK/badkey.log" 2>&1; then fail "bad static key accepted"; fi
ok "static key (MINIO_KMS_SECRET_KEY format): SSE-S3/SSE-KMS, restart, wrong key, read-only keys"

# ---------------------------------------------------------------- Vault
VAULT_BIN="${VAULT_BIN:-$(command -v vault || true)}"
VPORT="$(freeport)"
VADDR="http://127.0.0.1:$VPORT"
VTOKEN="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
vault_up=""
if [[ -n "$VAULT_BIN" ]]; then
  "$VAULT_BIN" server -dev -dev-root-token-id="$VTOKEN" -dev-listen-address="127.0.0.1:$VPORT" >"$WORK/vault.log" 2>&1 &
  AUX+=($!)
  vault_up=1
elif "$DOCKER" image inspect hashicorp/vault >/dev/null 2>&1; then
  CIDS+=("$("$DOCKER" run -d --cap-add=IPC_LOCK -e VAULT_DEV_ROOT_TOKEN_ID="$VTOKEN" -p "127.0.0.1:$VPORT:8200" hashicorp/vault)")
  vault_up=1
fi
if [[ -n "$vault_up" ]]; then
  for _ in $(seq 100); do curl -sf "$VADDR/v1/sys/health" >/dev/null && break; sleep 0.2; done
  vapi() { curl -sf -H "X-Vault-Token: $VTOKEN" "$@"; }
  vapi -X POST -d '{"type":"transit"}' "$VADDR/v1/sys/mounts/transit" >/dev/null || fail "enable transit"
  vapi -X POST -d '{"type":"approle"}' "$VADDR/v1/sys/auth/approle" >/dev/null || fail "enable approle"
  vapi -X PUT -d '{"policy":"path \"transit/*\" { capabilities = [\"create\",\"read\",\"update\",\"list\"] }"}' "$VADDR/v1/sys/policies/acl/zkfsm" >/dev/null
  vapi -X POST -d '{"token_policies":"zkfsm"}' "$VADDR/v1/auth/approle/role/zkfsm" >/dev/null
  ROLE_ID=$(vapi "$VADDR/v1/auth/approle/role/zkfsm/role-id" | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["role_id"])')
  SECRET_ID=$(vapi -X POST "$VADDR/v1/auth/approle/role/zkfsm/secret-id" | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["secret_id"])')
  (cd "$ROOT" && ZKFSM_KMS_TEST_VAULT_ADDR="$VADDR" ZKFSM_KMS_TEST_VAULT_TOKEN="$VTOKEN" ZKFSM_KMS_TEST_VAULT_ROLE_ID="$ROLE_ID" \
    ZKFSM_KMS_TEST_VAULT_SECRET_ID="$SECRET_ID" zig test src/kms/root.zig --test-filter "vault live" >"$WORK/vault-unit.log" 2>&1) \
    || fail "vault live unit test"
  if grep -q "skipped" "$WORK/vault-unit.log"; then fail "vault live unit test skipped"; fi
  ok "vault live: Transit, KV2, AppRole"

  VAULT_ADDR="$VADDR" VAULT_ROLE_ID="$ROLE_ID" VAULT_SECRET_ID="$SECRET_ID" start vault-srv.log "$WORK/d-vault" --kms-backend vault
  s3api create-bucket --bucket kms-vault >/dev/null
  roundtrip kms-vault v1 --server-side-encryption AES256
  "$MC" admin kms key create z vault-tenant >/dev/null || fail "create key in vault"
  roundtrip kms-vault v2 --server-side-encryption aws:kms --ssekms-key-id vault-tenant
  vapi "$VADDR/v1/transit/keys/vault-tenant" >/dev/null || fail "key not in vault transit"
  "$MC" admin kms key status --json z vault-tenant | grep -Eq '"keyId": ?"vault-tenant"' || fail "vault key status"
  stop
  VAULT_ADDR="$VADDR" VAULT_TOKEN="$VTOKEN" ZKFSM_KMS_VAULT_ENGINE=kv2 start vault-kv.log "$WORK/d-vkv" --kms-backend vault
  s3api create-bucket --bucket kms-vkv >/dev/null
  roundtrip kms-vkv k1 --server-side-encryption AES256
  stop
  ok "server on Vault Transit (AppRole) and KV2 (token)"
else
  skip "Vault (set VAULT_BIN or pull hashicorp/vault)"
fi

# ---------------------------------------------------------------- kms-api emulator
LOCAL_KMS_BIN="${LOCAL_KMS_BIN:-$(command -v local-kms || true)}"
KPORT="$(freeport)"
KEP="http://127.0.0.1:$KPORT"
kms_up=""
if [[ -n "$LOCAL_KMS_BIN" ]]; then
  mkdir -p "$WORK/lkms"
  PORT="$KPORT" KMS_REGION=us-east-1 KMS_ACCOUNT_ID=111122223333 KMS_DATA_PATH="$WORK/lkms" "$LOCAL_KMS_BIN" >"$WORK/local-kms.log" 2>&1 &
  AUX+=($!)
  kms_up=1
elif "$DOCKER" image inspect nsmithuk/local-kms >/dev/null 2>&1; then
  CIDS+=("$("$DOCKER" run -d -e KMS_REGION=us-east-1 -e KMS_ACCOUNT_ID=111122223333 -p "127.0.0.1:$KPORT:8080" nsmithuk/local-kms)")
  kms_up=1
fi
if [[ -n "$kms_up" ]]; then
  for _ in $(seq 100); do curl -s -o /dev/null "$KEP/" && break; sleep 0.1; done
  (cd "$ROOT" && ZKFSM_KMS_API_TEST_ENDPOINT="$KEP" AWS_REGION=us-east-1 AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
    zig test src/kms/root.zig --test-filter "kms-api live" >"$WORK/kmsapi-unit.log" 2>&1) || fail "kms-api live unit test"
  if grep -q "skipped" "$WORK/kmsapi-unit.log"; then fail "kms-api live unit test skipped"; fi
  ok "kms-api live: create, data keys, context binding, rotation, list"

  srv_env=(env AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1 ZKFSM_KMS_API_ENDPOINT="$KEP")
  "${srv_env[@]}" "$BIN" --data "$WORK/d-kapi" --listen "127.0.0.1:$PORT" --scan-interval 0 --kms-backend kms-api >"$WORK/kapi.log" 2>&1 &
  PID=$!
  waitport "$EP/" || fail "server on kms-api did not start"
  s3api create-bucket --bucket kms-api >/dev/null
  roundtrip kms-api a1 --server-side-encryption AES256
  "$MC" admin kms key create z api-tenant >/dev/null || fail "create key via kms-api"
  roundtrip kms-api a2 --server-side-encryption aws:kms --ssekms-key-id api-tenant
  "$MC" admin kms key list z | grep -q api-tenant || fail "kms-api key list"
  stop
  ok "server on kms-api"
else
  skip "kms-api emulator (set LOCAL_KMS_BIN or pull nsmithuk/local-kms)"
fi

echo "kms: PASS"
