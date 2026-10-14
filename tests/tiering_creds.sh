#!/usr/bin/env bash
# Remote-tier credentials and transitions beyond static keys: GCS service-account
# (OAuth2 JWT bearer grant), S3 roles (web identity against a zkfsm STS, and the
# instance-metadata endpoint), Azure service principal against Azurite (HTTPS +
# OAuth), storage class on remote writes, chained transitions, and asynchronous
# restore, and a role tier whose STS and store require a client certificate.
# Token endpoints and a bearer-checking store are mocked in Python
# (tests/tier_oauth_mock.py); Azurite parts are skipped without docker or the image.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
freeport() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
HOT_PORT="$(freeport)"
REM_PORT="$(freeport)"
HOT="http://127.0.0.1:$HOT_PORT"
REM="http://127.0.0.1:$REM_PORT"
WORK="$(mktemp -d)"
PIDS=()
CONTAINERS=()
HOT_PID=""
cleanup() {
  [[ -n "$HOT_PID" ]] && kill "$HOT_PID" 2>/dev/null || true
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  for c in "${CONTAINERS[@]}"; do docker rm -f -v "$c" >/dev/null 2>&1 || true; done
  if [[ -n "${KEEP_WORK:-}" ]]; then echo "work dir kept: $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

AK="tieradmin"
SK="tier-admin-secret-0123"
RAK="remoteadmin"
RSK="remote-admin-secret-01"
export AWS_DEFAULT_REGION=us-east-1 AWS_PAGER=""
export AWS_CONFIG_FILE="$WORK/cli.conf" AWS_SHARED_CREDENTIALS_FILE="$WORK/cli.creds"
printf '[default]\ns3 =\n  addressing_style = path\n' >"$AWS_CONFIG_FILE"
export MC_CONFIG_DIR="$WORK/mc"
MC="${MC:-$(command -v mc || true)}"
if [[ -z "$MC" ]] || ! "$MC" --version 2>/dev/null | grep -q RELEASE; then echo "tiering_creds.sh needs the MinIO client (set MC)"; exit 1; fi
S3CLI_BIN="${S3CLI_BIN:-aws}"
command -v "$S3CLI_BIN" >/dev/null || { echo "tiering_creds.sh needs an S3 CLI (set S3CLI_BIN)"; exit 1; }

pass=0
fail=0
check() {
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); echo "ok   $1"
  else fail=$((fail + 1)); echo "FAIL $1: expected [$2] got [$3]"; fi
}
ok() { if "$@" >/dev/null 2>&1; then echo 0; else echo 1; fi; }
hot() { AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" "$S3CLI_BIN" --endpoint-url "$HOT" "$@"; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
sclass() { hot s3api head-object --bucket "$1" --key "$2" 2>/dev/null | jget "d.get('StorageClass','')" || echo ERR; }
restore_hdr() { hot s3api head-object --bucket "$1" --key "$2" 2>/dev/null | jget "d.get('Restore','')" || echo ERR; }
wait_for() {
  local desc="$1" want="$2" got=""; shift 2
  for _ in $(seq 120); do got="$("$@" 2>/dev/null || true)"; [[ "$got" == "$want" ]] && break; sleep 0.25; done
  check "$desc" "$want" "$got"
}
stat_of() { curl -s "$MOCK/stats" | jget "d['$1']"; }
restore_req() { curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 aws:amz:us-east-1:s3 --user "$AK:$SK" -X POST --data "<RestoreRequest><Days>$3</Days></RestoreRequest>" "$HOT/$1/$2?restore"; }
# tier_add_raw JSON: PUT an encrypted tier config (fields the MinIO client cannot set).
tier_add_raw() {
  printf '%s' "$1" | python3 "$ROOT/tests/madmin_encrypt.py" "$SK" >"$WORK/tier.enc"
  curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 aws:amz:us-east-1:s3 --user "$AK:$SK" -X PUT --data-binary @"$WORK/tier.enc" "$HOT/minio/admin/v3/tier"
}
wait_up() { for _ in $(seq 100); do curl -s -o /dev/null "$1/" && return 0; sleep 0.1; done; return 1; }
# put_and_check BUCKET TIER: an object transitions to TIER and reads back intact.
put_and_check() {
  local b="$1" t="$2"
  "$MC" mb "hot/$b" >/dev/null
  "$MC" cp "$WORK/obj.bin" "hot/$b/obj" >/dev/null
  "$MC" ilm rule add "hot/$b" --transition-days 1 --transition-tier "$t" >/dev/null || true
  wait_for "$t transition" "$t" sclass "$b" obj
  check "$t read-through" "$(sha256sum <"$WORK/obj.bin")" "$("$MC" cat "hot/$b/obj" | sha256sum)"
}

(cd "$ROOT" && zig build)
BIN="$ROOT/zig-out/bin/zkfsm"
head -c 300000 /dev/urandom >"$WORK/obj.bin"

# ---- mocks: OAuth endpoints, metadata endpoint, bearer-checking store; OpenID IdP ----
python3 "$ROOT/tests/tier_oauth_mock.py" "$WORK" --ttl 4 --keys "$RAK:$RSK" >"$WORK/mock.port" 2>"$WORK/mock.log" &
PIDS+=($!)
python3 "$ROOT/tests/mock_idp.py" >"$WORK/idp.port" 2>"$WORK/idp.log" &
PIDS+=($!)
for _ in $(seq 100); do [[ -s "$WORK/mock.port" && -s "$WORK/idp.port" ]] && break; sleep 0.1; done
MOCK="http://127.0.0.1:$(cat "$WORK/mock.port")"
IDP="http://127.0.0.1:$(cat "$WORK/idp.port")"

# ---- Azurite over HTTPS with OAuth (optional) ----
AZ_IMAGE=mcr.microsoft.com/azure-storage/azurite
AZ=""
if command -v docker >/dev/null && docker info >/dev/null 2>&1 && docker image inspect "$AZ_IMAGE" >/dev/null 2>&1; then
  mkdir -p "$WORK/certs"
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/certs/key.pem" -out "$WORK/certs/cert.pem" -days 2 \
    -subj /CN=localhost -addext subjectAltName=DNS:localhost -addext basicConstraints=critical,CA:TRUE >/dev/null 2>&1
  chmod 755 "$WORK/certs"
  chmod 644 "$WORK/certs/"*.pem
  AZ_PORT="$(freeport)"
  cname="zkfsm-tiering-creds-azurite-$$"
  # Copy the certs in: bind mounts of the private work dir may be unreadable.
  CONTAINERS+=("$cname")
  if docker create --name "$cname" -p "127.0.0.1:$AZ_PORT:10000" "$AZ_IMAGE" \
      azurite-blob --blobHost 0.0.0.0 --blobPort 10000 --oauth basic --cert /tmp/cert.pem --key /tmp/key.pem \
      --loose --skipApiVersionCheck -l /tmp/az >/dev/null 2>&1 &&
    docker cp "$WORK/certs/cert.pem" "$cname:/tmp/cert.pem" >/dev/null 2>&1 &&
    docker cp "$WORK/certs/key.pem" "$cname:/tmp/key.pem" >/dev/null 2>&1 &&
    docker start "$cname" >/dev/null 2>&1; then
    AZ="https://localhost:$AZ_PORT/devstoreaccount1"
    for _ in $(seq 100); do curl -sk -o /dev/null "$AZ?comp=list" && break; sleep 0.2; done
    curl -sk -o /dev/null "$AZ?comp=list" || { echo "skip azurite: container did not start"; AZ=""; }
  fi
else
  echo "skip azurite: docker or $AZ_IMAGE not available"
fi

# ---- servers ----
ZKFSM_ACCESS_KEY="$RAK" ZKFSM_SECRET_KEY="$RSK" "$BIN" --data "$WORK/remote" --listen "127.0.0.1:$REM_PORT" 2>>"$WORK/remote.log" &
PIDS+=($!)
wait_up "$REM"
start_hot() {
  ZKFSM_ILM_DAY_SECONDS=1 ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" \
    ZKFSM_TIER_STS_ENDPOINT="$REM" ZKFSM_TIER_METADATA_ENDPOINT="$MOCK" ZKFSM_TIER_AZURE_AUTHORITY="$MOCK/az" ZKFSM_TIER_GCS_ENDPOINT="$MOCK/store" \
    ZKFSM_TIER_CA_FILE="$WORK/certs/cert.pem" \
    "$BIN" --data "$WORK/hot" --listen "127.0.0.1:$HOT_PORT" --lifecycle-interval 1 2>>"$WORK/hot.log" &
  HOT_PID=$!
  wait_up "$HOT"
}
start_hot
"$MC" alias set rem "$REM" "$RAK" "$RSK" >/dev/null
"$MC" alias set hot "$HOT" "$AK" "$SK" >/dev/null
"$MC" mb rem/rolebkt rem/imdsbkt rem/warm rem/cold >/dev/null

# ---- storage class on remote writes (S3 tier over the recording store) ----
check "s3 tier with storage class" 0 "$(ok "$MC" ilm tier add s3 hot SC --endpoint "$MOCK/store" --access-key k --secret-key secret-123 --bucket scb --storage-class STANDARD_IA)"
check "tier ls storage class" STANDARD_IA "$("$MC" ilm tier ls hot --json | jget '[t for t in d["tiers"] if t["Name"]=="SC"][0]["S3"]["StorageClass"]')"
put_and_check scdata SC
check "x-amz-storage-class sent" 1 "$(curl -s "$MOCK/stats" | jget "int('STANDARD_IA' in d['storage_classes'])")"

# ---- GCS service account (JWT bearer grant) ----
check "gcs tier with bad key file refused" 1 "$(ok "$MC" ilm tier add gcs hot BADG --credentials-file "$WORK/obj.bin" --bucket gcsb)"
check "gcs service-account tier add (mc)" 0 "$(ok "$MC" ilm tier add gcs hot GSAMC --credentials-file "$WORK/sa.json" --bucket gcsb --prefix mc/)"
# The MinIO client drops --storage-class for GCS, so this tier goes in through the admin route.
check "gcs service-account tier add" 204 "$(tier_add_raw "{\"Version\":\"v1\",\"Type\":\"gcs\",\"Name\":\"GSA\",\"GCS\":{\"Creds\":\"$(base64 -w0 "$WORK/sa.json")\",\"Bucket\":\"gcsb\",\"Prefix\":\"g/\",\"StorageClass\":\"NEARLINE\"}}")"
check "tier ls gcs storage class" NEARLINE "$("$MC" ilm tier ls hot --json | jget '[t for t in d["tiers"] if t["Name"]=="GSA"][0]["GCS"]["StorageClass"]')"
check "gcs token issued" 1 "$(( $(stat_of gcs_tokens) >= 1 ))"
check "gcs requests use bearer tokens" 1 "$(( $(stat_of bearer_requests) >= 1 ))"
check "tier ls redacts gcs creds" REDACTED "$("$MC" ilm tier ls hot --json | jget '[t for t in d["tiers"] if t["Name"]=="GSA"][0]["GCS"]["Creds"]')"
check "sealed at rest (private key)" 0 "$(grep -rq "BEGIN PRIVATE KEY" "$WORK/hot" && echo 1 || echo 0)"
put_and_check gdata GSA
check "x-goog-storage-class sent" 1 "$(curl -s "$MOCK/stats" | jget "int('NEARLINE' in d['storage_classes'])")"
before="$(stat_of gcs_tokens)"
sleep 5 # past the 4 s token lifetime
check "read-through after token expiry" "$(sha256sum <"$WORK/obj.bin")" "$("$MC" cat hot/gdata/obj | sha256sum)"
check "token refreshed" 1 "$(( $(stat_of gcs_tokens) > before ))"

# ---- asynchronous restore (slow remote) ----
curl -s -X POST "$MOCK/delay?s=2" >/dev/null
check "restore accepted" 202 "$(restore_req gdata obj 3)"
check "restore ongoing" 'ongoing-request="true"' "$(restore_hdr gdata obj)"
check "second restore while ongoing" 409 "$(restore_req gdata obj 3)"
restore_state() { restore_hdr "$@" | cut -d, -f1; }
wait_for "restore completes" 'ongoing-request="false"' restore_state gdata obj
check "restore has expiry-date" 1 "$(restore_hdr gdata obj | grep -c expiry-date)"
check "restore again extends" 200 "$(restore_req gdata obj 3)"
curl -s -X POST "$MOCK/delay?s=0" >/dev/null

# ---- S3 role: web identity token exchanged at the remote's STS ----
check "remote role provider" 0 "$(ok "$MC" idp openid add rem rw "config_url=$IDP/.well-known/openid-configuration" client_id=zkfsm role_policy=readwrite)"
curl -s "$IDP/token?sub=tier-node&ttl=7200" >"$WORK/wi.token"
check "role tier add (web identity)" 0 "$(ok "$MC" ilm tier add s3 hot ROLE --endpoint "$REM" --aws-role-arn arn:zkfsm:iam:::role/rw --aws-web-identity-file "$WORK/wi.token" --bucket rolebkt --prefix r/)"
check "tier ls shows role" arn:zkfsm:iam:::role/rw "$("$MC" ilm tier ls hot --json | jget '[t for t in d["tiers"] if t["Name"]=="ROLE"][0]["S3"].get("AWSRoleARN")')"
put_and_check roledata ROLE
check "role tier wrote to the remote" 1 "$("$MC" ls --recursive rem/rolebkt/r/ | wc -l | tr -d ' ')"
echo bogus >"$WORK/bad.token"
check "role tier with a bad token refused" 1 "$(ok "$MC" ilm tier add s3 hot BADROLE --endpoint "$REM" --aws-role-arn arn:zkfsm:iam:::role/rw --aws-web-identity-file "$WORK/bad.token" --bucket rolebkt --prefix bad/)"

# ---- S3 role: instance-metadata credential endpoint ----
check "role tier add (metadata endpoint)" 0 "$(ok "$MC" ilm tier add s3 hot IMDS --endpoint "$REM" --use-aws-role --bucket imdsbkt)"
check "metadata endpoint used" 1 "$(( $(stat_of imds) >= 1 ))"
put_and_check imdsdata IMDS

# ---- chained transitions in one rule ----
"$MC" ilm tier add minio hot WARM --endpoint "$REM" --access-key "$RAK" --secret-key "$RSK" --bucket warm >/dev/null
"$MC" ilm tier add minio hot COLD --endpoint "$REM" --access-key "$RAK" --secret-key "$RSK" --bucket cold >/dev/null
"$MC" mb hot/chain >/dev/null
"$MC" cp "$WORK/obj.bin" hot/chain/obj >/dev/null
cat >"$WORK/chain.json" <<'JSON'
{"Rules":[{"ID":"chain","Status":"Enabled","Filter":{"Prefix":""},
 "Transitions":[{"Days":6,"StorageClass":"COLD"},{"Days":1,"StorageClass":"WARM"}]}]}
JSON
check "rule with two transitions" 0 "$(ok hot s3api put-bucket-lifecycle-configuration --bucket chain --lifecycle-configuration "file://$WORK/chain.json")"
check "rule export lists both, ordered" "WARM COLD" "$(hot s3api get-bucket-lifecycle-configuration --bucket chain | jget "' '.join(t['StorageClass'] for t in d['Rules'][0]['Transitions'])")"
wait_for "first step" WARM sclass chain obj
wait_for "second step" COLD sclass chain obj
check "chained read-through" "$(sha256sum <"$WORK/obj.bin")" "$("$MC" cat hot/chain/obj | sha256sum)"
check "first tier cleaned" 0 "$("$MC" ls --recursive rem/warm | wc -l | tr -d ' ')"
check "second tier holds the data" 1 "$("$MC" ls --recursive rem/cold | wc -l | tr -d ' ')"
cat >"$WORK/bad.json" <<'JSON'
{"Rules":[{"ID":"bad","Status":"Enabled","Filter":{"Prefix":""},
 "Transitions":[{"Days":2,"StorageClass":"WARM"},{"Days":2,"StorageClass":"COLD"}]}]}
JSON
check "same-day transitions refused" 1 "$(ok hot s3api put-bucket-lifecycle-configuration --bucket chain --lifecycle-configuration "file://$WORK/bad.json")"

# ---- Azure: shared key and service principal against Azurite ----
if [[ -n "$AZ" ]]; then
  aztok="$(curl -s "$MOCK/az-token")"
  azc() { curl -sk -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer $aztok" -H "x-ms-version: 2021-08-06" "$AZ/$1?restype=container"; }
  check "azurite container (oauth)" 201 "$(azc azk)"
  azc azsp >/dev/null
  AZKEY="Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
  azc azmc >/dev/null
  check "azure shared-key tier (mc)" 0 "$(ok "$MC" ilm tier add azure hot AZMC --endpoint "$AZ" --account-name devstoreaccount1 --account-key "$AZKEY" --bucket azmc)"
  check "azure shared-key tier with access tier" 204 "$(tier_add_raw "{\"Version\":\"v1\",\"Type\":\"azure\",\"Name\":\"AZK\",\"Azure\":{\"Endpoint\":\"$AZ\",\"AccountName\":\"devstoreaccount1\",\"AccountKey\":\"$AZKEY\",\"Bucket\":\"azk\",\"StorageClass\":\"Cool\"}}")"
  put_and_check azkdata AZK
  check "x-ms-access-tier applied" Cool "$(curl -sk -H "Authorization: Bearer $aztok" -H "x-ms-version: 2021-08-06" "$AZ/azk?restype=container&comp=list" | python3 -c 'import re,sys; m=re.findall(r"<AccessTier>([^<]*)</AccessTier>", sys.stdin.read()); print(m[0] if m else "")')"
  check "azure service principal wrong secret refused" 1 "$(ok "$MC" ilm tier add azure hot AZBAD --endpoint "$AZ" --account-name devstoreaccount1 --az-sp-tenant-id test-tenant --az-sp-client-id zkfsm-client --az-sp-client-secret wrong --bucket azsp)"
  check "azure service principal tier add" 0 "$(ok "$MC" ilm tier add azure hot AZSP --endpoint "$AZ" --account-name devstoreaccount1 --az-sp-tenant-id test-tenant --az-sp-client-id zkfsm-client --az-sp-client-secret zkfsm-client-secret --bucket azsp --prefix sp/)"
  check "tier ls service principal" "test-tenant REDACTED" "$("$MC" ilm tier ls hot --json | jget '[t["Azure"]["SPAuth"]["TenantID"] + " " + t["Azure"]["SPAuth"]["ClientSecret"] for t in d["tiers"] if t["Name"]=="AZSP"][0]')"
  check "azure token issued" 1 "$(( $(stat_of az_tokens) >= 1 ))"
  put_and_check azspdata AZSP
  "$MC" rm hot/azspdata/obj >/dev/null
  azcount() { curl -sk -H "Authorization: Bearer $aztok" -H "x-ms-version: 2021-08-06" "$AZ/azsp?restype=container&comp=list&prefix=sp/" | grep -o '<Blob>' | wc -l | tr -d ' '; }
  wait_for "azure SP cleanup" 0 azcount
fi

# ---- role tier over mutual TLS: STS and store both demand a client certificate ----
source "$ROOT/tests/tls_remote.sh"
tls_pki
MT_PORT="$(freeport)"
tls_zkfsm mtlsrem "$MT_PORT" "$RAK" "$RSK" --identity-openid "config_url=$IDP/.well-known/openid-configuration client_id=zkfsm role_policy=readwrite"
PIDS+=("${TLS_PIDS[@]}")
check "mtls remote bucket" 200 "$(tls_s3 "$MT_PORT" "$RAK" "$RSK" PUT /mrole -o /dev/null -w '%{http_code}')"
H2_PORT="$(freeport)"
H2="http://127.0.0.1:$H2_PORT"
ZKFSM_ILM_DAY_SECONDS=1 ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" ZKFSM_TIER_STS_ENDPOINT="https://127.0.0.1:$MT_PORT" \
  "$BIN" --data "$WORK/hot2" --listen "127.0.0.1:$H2_PORT" --lifecycle-interval 1 2>>"$WORK/hot2.log" &
PIDS+=($!)
wait_up "$H2"
"$MC" alias set hot2 "$H2" "$AK" "$SK" >/dev/null
tier2() { # JSON -> status of the admin tier add on hot2
  printf '%s' "$1" | python3 "$ROOT/tests/madmin_encrypt.py" "$SK" >"$WORK/tier.enc"
  curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 aws:amz:us-east-1:s3 --user "$AK:$SK" -X PUT --data-binary @"$WORK/tier.enc" "$H2/minio/admin/v3/tier"
}
mrole() { # NAME EXTRA-JSON
  printf '{"Version":"v1","Type":"s3","Name":"%s","S3":{"Endpoint":"https://127.0.0.1:%s","AWSRoleARN":"arn:zkfsm:iam:::role/_","AWSRoleWebIdentityTokenFile":"%s","Bucket":"mrole","Prefix":"m/","CAFile":"%s"%s}}' \
    "$1" "$MT_PORT" "$WORK/wi.token" "$PKI/ca.pem" "$2"
}
check "mtls role tier without client cert refused" 400 "$(tier2 "$(mrole MNOCERT "")")"
check "mtls role tier add" 204 "$(tier2 "$(mrole MROLE ",\"ClientCert\":\"$PKI/client.pem\",\"ClientKey\":\"$PKI/client.key\"")")"
"$MC" mb hot2/mrdata >/dev/null
"$MC" cp "$WORK/obj.bin" hot2/mrdata/obj >/dev/null
"$MC" ilm rule add hot2/mrdata --transition-days 1 --transition-tier MROLE >/dev/null
h2class() { AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" "$S3CLI_BIN" --endpoint-url "$H2" s3api head-object --bucket mrdata --key obj 2>/dev/null | jget "d.get('$1','')"; }
wait_for "mtls role transition" MROLE h2class StorageClass
check "mtls role remote holds the data" 1 "$(tls_count "$MT_PORT" "$RAK" "$RSK" mrole m/)"
check "mtls role read-through" "$(sha256sum <"$WORK/obj.bin")" "$("$MC" cat hot2/mrdata/obj | sha256sum)"
AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" "$S3CLI_BIN" --endpoint-url "$H2" s3api get-object --bucket mrdata --key obj --range bytes=100-199 "$WORK/mr.out" >/dev/null
check "mtls role range" "$(tail -c +101 "$WORK/obj.bin" | head -c 100 | sha256sum)" "$(sha256sum <"$WORK/mr.out")"
check "mtls role restore accepted" 202 "$(curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 aws:amz:us-east-1:s3 --user "$AK:$SK" -X POST --data '<RestoreRequest><Days>1</Days></RestoreRequest>' "$H2/mrdata/obj?restore")"
h2restore() { h2class Restore | cut -d, -f1; }
wait_for "mtls role restore completes" 'ongoing-request="false"' h2restore
"$MC" rm hot2/mrdata/obj >/dev/null
wait_for "mtls role delete cleans the tier" 0 tls_count "$MT_PORT" "$RAK" "$RSK" mrole m/

# ---- persistence ----
kill "$HOT_PID"; wait "$HOT_PID" 2>/dev/null || true; HOT_PID=""
start_hot
check "credential tiers persist" 0 "$(ok "$MC" ilm tier verify hot GSA)"
check "role tier after restart" "$(sha256sum <"$WORK/obj.bin")" "$("$MC" cat hot/roledata/obj | sha256sum)"

echo "tiering_creds: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
