#!/usr/bin/env bash
# KMS key management end to end: mc admin kms key create|list|status, key
# enable/disable, tags, delete with usage checks, rekey of a prefix (paged,
# versioned), runtime backend reconfiguration (local, static, and Vault Transit
# when VAULT_BIN or the hashicorp/vault image is available), Prometheus and
# admin metrics, and kms:* policy gating.
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

AK="zkfsmkmsadmin"
SK="zkfsm-kms-admin-secret"
export ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK"
export AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_DEFAULT_REGION=us-east-1
export AWS_CONFIG_FILE="$WORK/aws.conf" AWS_SHARED_CREDENTIALS_FILE="$WORK/aws.creds" AWS_PAGER="" AWS_EC2_METADATA_DISABLED=true
printf '[default]\ns3 =\n  addressing_style = path\n' >"$AWS_CONFIG_FILE"
export MC_CONFIG_DIR="$WORK/mc"
MC="${MC:-$(command -v mc || true)}"
[[ -n "$MC" ]] || { echo "FAIL: mc is required (set MC)" >&2; exit 1; }

fail() { echo "FAIL: $*" >&2; for l in "$WORK"/*.log; do [[ -f "$l" ]] && { echo "== $l" >&2; tail -15 "$l" >&2; }; done; exit 1; }
ok() { echo "ok   $*"; }
skip() { echo "skip $*"; }
s3api() { "$S3CLI_BIN" --endpoint-url "$EP" s3api "$@"; }
kmsapi() { curl -s --aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" "$@"; }
code() { kmsapi -o "$WORK/last.json" -w '%{http_code}' "$@"; }
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2], {}, {"d": d}))' "$1" "$2"; }
waitport() { for _ in $(seq 150); do curl -s -o /dev/null "$1" && return 0; sleep 0.1; done; return 1; }
K="$EP/minio/kms/v1"

(cd "$ROOT" && zig build)
BIN="$ROOT/zig-out/bin/zkfsm"
"$BIN" --data "$WORK/data" --listen "127.0.0.1:$PORT" --scan-interval 0 --kms-backend local --kms-dir "$WORK/kms" >"$WORK/server.log" 2>&1 &
PID=$!
waitport "$EP/" || fail "server did not start"
"$MC" alias set z "$EP" "$AK" "$SK" >/dev/null
head -c 150000 /dev/urandom >"$WORK/obj.bin"
put() { s3api put-object --bucket "$1" --key "$2" --body "$WORK/obj.bin" "${@:3}" >/dev/null; }
check() { # bucket key [version]
  local extra=()
  [[ -n "${3:-}" ]] && extra=(--version-id "$3")
  s3api get-object --bucket "$1" --key "$2" "${extra[@]}" "$WORK/rt.out" >/dev/null || fail "get $1/$2 ${3:-}"
  cmp -s "$WORK/obj.bin" "$WORK/rt.out" || fail "$1/$2 content mismatch"
}
keyof() { s3api head-object --bucket "$1" --key "$2" --query SSEKMSKeyId --output text; }

# ---------------------------------------------------------------- mc + listing
"$MC" admin kms key create z key-a >/dev/null || fail "mc admin kms key create"
"$MC" admin kms key create z key-b >/dev/null
"$MC" admin kms key list --json z | grep -q key-b || fail "mc admin kms key list"
"$MC" admin kms key status --json z key-a | grep -Eq '"keyId": ?"key-a"' || fail "mc admin kms key status"
[[ $(code "$K/key/list") == 200 ]] || fail "key list"
python3 -c 'import json,sys; l=json.load(open(sys.argv[1])); m={k["name"]:k for k in l}; assert m["key-a"]["state"]=="enabled" and m["key-a"]["version"]==1' "$WORK/last.json" \
  || fail "key list lacks state: $(cat "$WORK/last.json")"
[[ $(code "$EP/minio/admin/v3/kms/status") == 200 ]] && grep -q '"name":"local"' "$WORK/last.json" || fail "admin v3 kms status"
[[ $(code "$EP/minio/admin/v3/kms/key/list") == 200 ]] && grep -q key-a "$WORK/last.json" || fail "admin v3 kms key list"
[[ $(code -X PATCH "$K/key/list") == 405 ]] || fail "wrong method not refused"
ok "mc admin kms key create/list/status; list with state; /minio/admin/v3/kms paths"

# ---------------------------------------------------------------- tags
[[ $(code -X PUT --data '{"tags":{"env":"prod","team":"storage"}}' "$K/key/tags?key-id=key-a") == 200 ]] || fail "put tags: $(cat "$WORK/last.json")"
[[ $(code "$K/key/tags?key-id=key-a") == 200 ]] || fail "get tags"
[[ $(jget "$WORK/last.json" 'd["tags"]["env"]+","+d["tags"]["team"]') == "prod,storage" ]] || fail "tags: $(cat "$WORK/last.json")"
[[ $(code -X PUT --data '{"tags":{"env":1}}' "$K/key/tags?key-id=key-a") == 400 ]] || fail "non-string tag accepted"
[[ $(code -X PUT --data '{"tags":{"x":"y"}}' "$K/key/tags?key-id=no-such") == 404 ]] || fail "tags on missing key"
[[ $(code -X DELETE "$K/key/tags?key-id=key-b") == 200 ]] || fail "clear tags"
[[ $(code "$K/key/tags?key-id=key-a") == 200 ]] && grep -q prod "$WORK/last.json" || fail "tags lost"
ok "key tags: set, get, replace validation, clear"

# ---------------------------------------------------------------- enable/disable
s3api create-bucket --bucket bkt-kb >/dev/null
put bkt-kb before --server-side-encryption aws:kms --ssekms-key-id key-a || fail "put before disable"
[[ $(code -X POST "$K/key/disable?key-id=key-a") == 200 ]] || fail "disable"
[[ $(code "$K/key/list?state=disabled") == 200 ]] && grep -q key-a "$WORK/last.json" || fail "disabled key not listed by state"
if put bkt-kb after --server-side-encryption aws:kms --ssekms-key-id key-a 2>"$WORK/put.err"; then fail "PUT with a disabled key succeeded"; fi
grep -q "DisabledException" "$WORK/put.err" || fail "disabled PUT error: $(cat "$WORK/put.err")"
check bkt-kb before
"$MC" admin kms key status --json z key-a | grep -q KeyDisabled || fail "status of disabled key"
[[ $(code -X POST "$K/key/enable?key-id=key-a") == 200 ]] || fail "enable"
put bkt-kb after --server-side-encryption aws:kms --ssekms-key-id key-a || fail "put after enable"
ok "disable blocks new SSE-KMS PUTs, keeps old objects readable; enable restores"

# ---------------------------------------------------------------- rekey
s3api create-bucket --bucket bkt-rk >/dev/null
for i in 1 2 3 4 5; do put bkt-rk "p/$i" --server-side-encryption aws:kms --ssekms-key-id key-a; done
put bkt-rk q/1 --server-side-encryption aws:kms --ssekms-key-id key-a
put bkt-rk p/s3 --server-side-encryption AES256
s3api put-bucket-versioning --bucket bkt-rk --versioning-configuration Status=Enabled
put bkt-rk p/v --server-side-encryption aws:kms --ssekms-key-id key-a
V1=$(s3api list-object-versions --bucket bkt-rk --prefix p/v --query 'Versions[0].VersionId' --output text)
put bkt-rk p/v --server-side-encryption aws:kms --ssekms-key-id key-a
marker="" total=0 pages=0
while :; do
  q="bucket=bkt-rk&prefix=p/&key-id=key-b&from-key-id=key-a&max-keys=2"
  [[ -n "$marker" ]] && q="$q&marker=$marker"
  [[ $(code -X POST "$K/key/rekey?$q") == 200 ]] || fail "rekey: $(cat "$WORK/last.json")"
  [[ $(jget "$WORK/last.json" 'd["failed"]') == 0 ]] || fail "rekey failures: $(cat "$WORK/last.json")"
  total=$((total + $(jget "$WORK/last.json" 'd["rekeyed"]')))
  pages=$((pages + 1))
  [[ $(jget "$WORK/last.json" 'd["truncated"]') == True ]] || break
  marker=$(jget "$WORK/last.json" 'd["next-marker"]')
  [[ $pages -lt 20 ]] || fail "rekey did not finish"
done
[[ $total == 7 && $pages -ge 3 ]] || fail "rekeyed $total objects in $pages pages (want 7 over >=3)"
for i in 1 2 3 4 5; do [[ $(keyof bkt-rk "p/$i") == key-b ]] || fail "p/$i not under key-b"; check bkt-rk "p/$i"; done
[[ $(keyof bkt-rk p/v) == key-b ]] || fail "latest version not rekeyed"
check bkt-rk p/v && check bkt-rk p/v "$V1"
[[ $(keyof bkt-rk q/1) == key-a ]] || fail "object outside the prefix was rekeyed"
check bkt-rk p/s3
[[ $(code -X POST "$K/key/rekey?bucket=bkt-rk&prefix=p/&key-id=key-b&from-key-id=key-a") == 200 && $(jget "$WORK/last.json" 'd["rekeyed"]') == 0 ]] \
  || fail "second rekey pass not idempotent: $(cat "$WORK/last.json")"
[[ $(code -X POST "$K/key/rekey?bucket=nope&key-id=key-b") == 404 ]] || fail "rekey of a missing bucket"
[[ $(code -X POST "$K/key/rekey?bucket=bkt-rk&key-id=no-such") == 404 ]] || fail "rekey to a missing key"
ok "rekey: prefix paged by marker, versions included, outside prefix untouched, data readable, idempotent"

# ---------------------------------------------------------------- delete
[[ $(code -X DELETE "$K/key/delete?key-id=key-a") == 409 ]] || fail "delete of a key in use: $(cat "$WORK/last.json")"
[[ $(jget "$WORK/last.json" 'd["objects"]') -ge 1 ]] || fail "usage count: $(cat "$WORK/last.json")"
for b in bkt-kb bkt-rk; do
  [[ $(code -X POST "$K/key/rekey?bucket=$b&key-id=key-b&from-key-id=key-a") == 200 ]] || fail "rekey $b"
done
[[ $(code -X DELETE "$K/key/delete?key-id=key-a") == 200 ]] || fail "delete after rekey: $(cat "$WORK/last.json")"
"$MC" admin kms key list --json z | grep -q '"key-a"' && fail "deleted key still listed"
check bkt-rk q/1 && check bkt-kb before && check bkt-kb after
[[ $(code -X DELETE "$K/key/delete?key-id=key-a") == 404 ]] || fail "second delete"
[[ $(code -X DELETE "$K/key/delete?key-id=zkfsm-sse-s3") == 409 ]] && grep -q '"default":true' "$WORK/last.json" || fail "default key delete not refused"
"$MC" admin kms key create z key-d >/dev/null
s3api create-bucket --bucket bkt-bd >/dev/null
"$MC" encrypt set sse-kms key-d z/bkt-bd >/dev/null || fail "mc encrypt set"
[[ $(code -X DELETE "$K/key/delete?key-id=key-d") == 409 ]] && grep -q '"bkt-bd"' "$WORK/last.json" || fail "bucket default key delete: $(cat "$WORK/last.json")"
[[ $(code -X DELETE "$K/key/delete?key-id=key-d&force=true") == 200 ]] || fail "forced delete"
"$MC" admin kms key create z key-e >/dev/null
[[ $(code -X POST "$K/key/delete?key-id=key-e") == 200 ]] || fail "delete unused key"
ok "delete: refused while objects, bucket defaults or the default key use it; works after rekey; force"

# ---------------------------------------------------------------- metrics
curl -s "$EP/metrics" >"$WORK/metrics.txt"
grep -Eq '^zkfsm_kms_requests_total\{op="generate_data_key"\} [1-9]' "$WORK/metrics.txt" || fail "kms request metric: $(grep zkfsm_kms "$WORK/metrics.txt" | head)"
grep -Eq '^zkfsm_kms_errors_total\{op="generate_data_key"\} [1-9]' "$WORK/metrics.txt" || fail "kms error metric"
grep -q '^zkfsm_kms_request_duration_seconds_count{op="decrypt_data_key"}' "$WORK/metrics.txt" || fail "kms latency metric"
grep -Eq '^zkfsm_kms_keys\{state="enabled"\} [1-9]' "$WORK/metrics.txt" || fail "kms key count metric"
grep -Eq '^zkfsm_kms_rekeyed_objects_total [1-9]' "$WORK/metrics.txt" || fail "rekey metric"
grep -q 'zkfsm_kms_backend_info{backend="local"} 1' "$WORK/metrics.txt" || fail "backend info metric"
curl -s "$EP/minio/v2/metrics/cluster" | grep -q zkfsm_kms_requests_total || fail "kms metrics on the minio path"
[[ $(code "$K/metrics") == 200 ]] || fail "admin kms metrics"
[[ $(jget "$WORK/last.json" 'd["kes_http_request_success"] > 0 and d["kes_http_request_error"] > 0 and d["operations"]["seal_data_key"]["requests"] > 0') == True ]] \
  || fail "admin metrics: $(cat "$WORK/last.json")"
ok "metrics: per-op requests/errors/latency, key counts, rekey count on /metrics and /minio/kms/v1/metrics"

# ---------------------------------------------------------------- runtime reconfig
[[ $(code "$K/config") == 200 && $(jget "$WORK/last.json" 'd["backend"]') == local ]] || fail "get config"
cfg() { code -X POST --data "$1" "$K/config"; }
[[ $(cfg '{"backend":"vault","vault":{"addr":"http://127.0.0.1:1"}}') == 400 ]] || fail "incomplete vault config accepted"
[[ $(cfg '{"backend":"bogus"}') == 400 ]] || fail "unknown backend accepted"
[[ $(cfg '{"backend":"local","dir":"/proc/no/such","unknown":1}') == 400 ]] || fail "unknown field accepted"
check bkt-rk p/1
[[ $(cfg "{\"backend\":\"local\",\"dir\":\"$WORK/kms2\",\"default_key\":\"second\"}") == 200 ]] || fail "reconfig local: $(cat "$WORK/last.json")"
[[ $(code "$K/status") == 200 ]] && grep -q '"default-key-id":"second"' "$WORK/last.json" || fail "status after reconfig"
s3api create-bucket --bucket bkt-rc >/dev/null
put bkt-rc s1 --server-side-encryption AES256 || fail "SSE-S3 PUT after reconfig"
check bkt-rc s1
if s3api get-object --bucket bkt-rk --key p/1 "$WORK/x" >/dev/null 2>&1; then fail "object readable with keys from another directory"; fi
KEY="static-one:$(head -c 32 /dev/urandom | base64 -w0)"
[[ $(cfg "{\"backend\":\"static\",\"secret_key\":\"$KEY\"}") == 200 ]] || fail "reconfig static: $(cat "$WORK/last.json")"
put bkt-rc st --server-side-encryption aws:kms || fail "PUT on static after reconfig"
check bkt-rc st
[[ $(cfg "{\"backend\":\"local\",\"dir\":\"$WORK/kms\"}") == 200 ]] || fail "reconfig back"
check bkt-rk p/1 && check bkt-rk q/1
# In-flight safety: swaps while SSE round trips run.
(for i in $(seq 25); do
  s3api put-object --bucket bkt-rk --key "live/$i" --body "$WORK/obj.bin" --server-side-encryption AES256 >/dev/null || exit 1
  s3api get-object --bucket bkt-rk --key "live/$i" "$WORK/live.out" >/dev/null || exit 1
  cmp -s "$WORK/obj.bin" "$WORK/live.out" || exit 1
done) &
LOOP=$!
for i in $(seq 15); do [[ $(cfg "{\"backend\":\"local\",\"dir\":\"$WORK/kms\"}") == 200 ]] || fail "swap $i"; done
wait "$LOOP" || fail "SSE round trips failed during backend swaps"
grep -Eq '^zkfsm_kms_reconfigurations_total (1[0-9]|[2-9][0-9])' <(curl -s "$EP/metrics") || fail "reconfiguration metric"
ok "runtime reconfig: validation, local->local(other dir)->static->local, swaps under load"

# ---------------------------------------------------------------- Vault via reconfig
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
  curl -sf -H "X-Vault-Token: $VTOKEN" -X POST -d '{"type":"transit"}' "$VADDR/v1/sys/mounts/transit" >/dev/null || fail "enable transit"
  [[ $(cfg "{\"backend\":\"vault\",\"vault\":{\"addr\":\"$VADDR\",\"token\":\"wrong-token\"}}") == 400 ]] || fail "vault with a bad token accepted"
  check bkt-rk p/1
  [[ $(cfg "{\"backend\":\"vault\",\"default_key\":\"vault-default\",\"vault\":{\"addr\":\"$VADDR\",\"token\":\"$VTOKEN\",\"engine\":\"transit\"}}") == 200 ]] \
    || fail "reconfig vault: $(cat "$WORK/last.json")"
  [[ $(code "$K/config") == 200 ]] && ! grep -q "$VTOKEN" "$WORK/last.json" && grep -q '"auth":"token"' "$WORK/last.json" || fail "config leaks the token or misses vault: $(cat "$WORK/last.json")"
  "$MC" admin kms key create z vault-k >/dev/null || fail "key create on vault"
  put bkt-rc vt --server-side-encryption aws:kms --ssekms-key-id vault-k || fail "PUT on vault"
  check bkt-rc vt
  curl -sf -H "X-Vault-Token: $VTOKEN" "$VADDR/v1/transit/keys/vault-k" >/dev/null || fail "key not in vault"
  [[ $(code -X POST "$K/key/disable?key-id=vault-k") == 501 ]] || fail "transit disable should be unsupported"
  [[ $(cfg "{\"backend\":\"local\",\"dir\":\"$WORK/kms\"}") == 200 ]] || fail "back to local"
  check bkt-rk p/1
  ok "runtime reconfig local -> vault transit -> local; bad token rejected; secrets not echoed"
else
  skip "Vault reconfig (set VAULT_BIN or pull hashicorp/vault)"
fi

# ---------------------------------------------------------------- access control
"$MC" admin user add z kmsop kmsop-secret-123 >/dev/null
"$MC" admin policy attach z readwrite --user kmsop >/dev/null
U="kmsop:kmsop-secret-123"
ucode() { curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 "aws:amz:us-east-1:s3" --user "$U" "$@"; }
[[ $(ucode -X DELETE "$K/key/delete?key-id=key-b") == 403 ]] || fail "non-admin delete"
[[ $(ucode -X POST --data '{"backend":"local"}' "$K/config") == 403 ]] || fail "non-admin reconfig"
cat >"$WORK/pol.json" <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["kms:TagKey","kms:KeyStatus","kms:Metrics"],"Resource":["arn:aws:s3:::*"]}]}
JSON
"$MC" admin policy create z kmstagger "$WORK/pol.json" >/dev/null
"$MC" admin policy attach z kmstagger --user kmsop >/dev/null
[[ $(ucode -X PUT --data '{"tags":{"a":"b"}}' "$K/key/tags?key-id=key-b") == 200 ]] || fail "kms:TagKey not honoured"
[[ $(ucode "$K/metrics") == 200 ]] || fail "kms:Metrics not honoured"
[[ $(ucode -X POST "$K/key/disable?key-id=key-b") == 403 ]] || fail "kms:DisableKey not required"
ok "kms:DeleteKey/Configure/TagKey/Metrics/DisableKey policy actions"

echo "kms_admin: PASS"
