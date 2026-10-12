#!/usr/bin/env bash
# Replication extras across local deployments: synchronous targets, read proxying
# (and its opt-out), counters kept across restarts, recovery of versions left PENDING
# without a queue entry, an HTTPS target trusted through a custom CA, and site
# replication between sites with different root credentials: site edit, site
# resync, STS sessions valid on peers, website and ownership-controls sync.
set -euo pipefail
S3CLI_BIN="${S3CLI_BIN:-aws}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
MC="${MC:-$(command -v mc || true)}"
if [[ -z "$MC" ]] || ! "$MC" --version >/dev/null 2>&1; then echo "replication_ext.sh needs the MinIO client (set MC)"; exit 1; fi
command -v openssl >/dev/null || { echo "replication_ext.sh needs openssl"; exit 1; }
declare -A PID=()
cleanup() {
  for p in "${PID[@]}"; do kill -9 "$p" 2>/dev/null || true; done
  if [[ -n "${KEEP_WORK:-}" ]]; then echo "work dir kept: $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

pass=0
fail=0
check() { # name expected actual
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); echo "ok   $1"
  else fail=$((fail + 1)); echo "FAIL $1: expected [$2] got [$3]"; fi
}
eventually() { # name expected command...: retries for up to 60 s
  local name="$1" want="$2" got=""; shift 2
  for _ in $(seq 120); do got="$("$@" 2>/dev/null || true)"; [[ "$got" == "$want" ]] && break; sleep 0.5; done
  check "$name" "$want" "$got"
}
freeport() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
jfield() { python3 -c "import json,sys; d=json.load(sys.stdin); print(d$1)"; }

AK="repladmin"
SK="replication-secret-0123"
AK2="otheradmin"
SK2="other-secret-456789"
export AWS_DEFAULT_REGION=us-east-1 AWS_PAGER=""
export AWS_CONFIG_FILE="$WORK/s3cli.conf" AWS_SHARED_CREDENTIALS_FILE="$WORK/s3cli.creds"
printf '[default]\ns3 =\n  addressing_style = path\n' >"$AWS_CONFIG_FILE"
export MC_CONFIG_DIR="$WORK/mc"

(cd "$ROOT" && zig build -Doptimize=ReleaseSafe)
BIN="$ROOT/zig-out/bin/zkfsm"

# Test CA and a localhost certificate for the HTTPS target.
mkdir -p "$WORK/pki" "$MC_CONFIG_DIR/certs/CAs"
(cd "$WORK/pki"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.crt -days 2 -subj /CN=zkfsm-repl-ca \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign 2>/dev/null
  openssl ecparam -name prime256v1 -genkey -noout -out leaf.sec1 2>/dev/null
  openssl pkcs8 -topk8 -nocrypt -in leaf.sec1 -out leaf.key
  openssl req -new -key leaf.key -subj /CN=localhost -out leaf.csr 2>/dev/null
  openssl x509 -req -in leaf.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 \
    -extfile <(echo "subjectAltName=DNS:localhost,IP:127.0.0.1") -out leaf.crt 2>/dev/null)
cp "$WORK/pki/ca.crt" "$MC_CONFIG_DIR/certs/CAs/"

PA="$(freeport)"; PC="$(freeport)"; PD="$(freeport)"; PS1="$(freeport)"; PS2="$(freeport)"
run() { # name access secret args...
  local n="$1" ak="$2" sk="$3"; shift 3
  ZKFSM_ACCESS_KEY="$ak" ZKFSM_SECRET_KEY="$sk" ZKFSM_REPLICATION_CA_FILE="$WORK/pki/ca.crt" \
    ZKFSM_REPLICATION_RECOVERY_INTERVAL=2 "$BIN" "$@" >>"$WORK/$n.log" 2>&1 &
  PID[$n]=$!
}
startA() { run a "$AK" "$SK" --data "$WORK/a" --listen "127.0.0.1:$PA"; }
startC() { run c "$AK" "$SK" --data "$WORK/c" --listen "127.0.0.1:$PC"; }
ready() { # port [scheme]
  for _ in $(seq 600); do [[ "$(curl -sk -o /dev/null -w '%{http_code}' "${2:-http}://127.0.0.1:$1/health/ready")" == 200 ]] && return 0; sleep 0.1; done
  echo "server on $1 not ready"; tail -n 20 "$WORK"/*.log; exit 1
}
stop() { kill -9 "${PID[$1]}" 2>/dev/null || true; wait "${PID[$1]}" 2>/dev/null || true; unset "PID[$1]"; }

startA; startC
run d "$AK" "$SK" --data "$WORK/d" --listen "127.0.0.1:$PD" --tls-cert "$WORK/pki/leaf.crt" --tls-key "$WORK/pki/leaf.key"
run s1 "$AK" "$SK" --data "$WORK/s1" --listen "127.0.0.1:$PS1"
run s2 "$AK2" "$SK2" --data "$WORK/s2" --listen "127.0.0.1:$PS2"
ready "$PA"; ready "$PC"; ready "$PD" https; ready "$PS1"; ready "$PS2"
"$MC" alias set a "http://127.0.0.1:$PA" "$AK" "$SK" >/dev/null
"$MC" alias set c "http://127.0.0.1:$PC" "$AK" "$SK" >/dev/null
"$MC" alias set d "https://localhost:$PD" "$AK" "$SK" >/dev/null
"$MC" alias set s1 "http://127.0.0.1:$PS1" "$AK" "$SK" >/dev/null
"$MC" alias set s2 "http://127.0.0.1:$PS2" "$AK2" "$SK2" >/dev/null
cli() { # port access secret args...
  local p="$1"; AWS_ACCESS_KEY_ID="$2" AWS_SECRET_ACCESS_KEY="$3" "$S3CLI_BIN" --endpoint-url "http://127.0.0.1:$p" "${@:4}"; }
cliA() { cli "$PA" "$AK" "$SK" "$@"; }
cliC() { cli "$PC" "$AK" "$SK" "$@"; }
rstatus() { cliA s3api head-object --bucket "$1" --key "$2" 2>/dev/null | jfield '.get("ReplicationStatus","")'; }
pair() { # bucket [flags...]: versioned bucket on A and C, A replicates to C
  local b="$1"; shift
  "$MC" mb a/"$b" c/"$b" >/dev/null
  "$MC" version enable a/"$b" >/dev/null; "$MC" version enable c/"$b" >/dev/null
  "$MC" replicate add a/"$b" --remote-bucket "http://$AK:$SK@127.0.0.1:$PC/$b" --priority 1 "$@" >/dev/null
}
targets() { # port bucket
  curl -s --aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" "http://127.0.0.1:$1/minio/admin/v3/list-remote-targets?bucket=$2&type=replication"; }
metric() { # port access secret bucket field
  curl -s --aws-sigv4 "aws:amz:us-east-1:s3" --user "$2:$3" "http://127.0.0.1:$1/$4?replication-metrics" | jfield "[\"$5\"]"; }

echo "== synchronous target"
pair syn --sync
check "target is synchronous" True "$(targets "$PA" syn | jfield '[0]["replicationSync"]')"
for i in 1 2 3; do
  echo "sync $i" | "$MC" pipe a/syn/k$i >/dev/null
  # No waiting: the write returned only after delivery.
  check "sync put $i present on target at once" "sync $i" "$("$MC" cat c/syn/k$i 2>/dev/null)"
  check "sync put $i COMPLETED at once" COMPLETED "$(rstatus syn k$i)"
done

echo "== counters survive a restart"
eventually "replicated count before restart" 3 metric "$PA" "$AK" "$SK" syn replicationCount
sleep 2
stop a; startA; ready "$PA"
check "replicated count after restart" 3 "$(metric "$PA" "$AK" "$SK" syn replicationCount)"

echo "== proxying reads to the target"
pair prx
echo "only on c" | "$MC" pipe c/prx/remote.txt >/dev/null
check "GET proxied from target" "only on c" "$(cliA s3 cp s3://prx/remote.txt - 2>/dev/null)"
check "HEAD proxied from target" 10 "$(cliA s3api head-object --bucket prx --key remote.txt 2>/dev/null | jfield '["ContentLength"]')"
check "range GET proxied" "on" "$(cliA s3api get-object --bucket prx --key remote.txt --range bytes=5-6 "$WORK/rg" >/dev/null 2>&1; cat "$WORK/rg")"
check "missing everywhere is 404" 1 "$(cliA s3api head-object --bucket prx --key nowhere >/dev/null 2>&1 && echo 0 || echo 1)"
RULE="$("$MC" replicate ls a/prx --json | jfield '["rule"]["ID"]')"
"$MC" replicate update a/prx --id "$RULE" --remote-bucket "http://$AK:$SK@127.0.0.1:$PC/prx" --proxy disable >/dev/null
check "target proxy disabled" True "$(targets "$PA" prx | jfield '[0]["disableProxy"]')"
eventually "no proxy once disabled" 1 sh -c "AWS_ACCESS_KEY_ID=$AK AWS_SECRET_ACCESS_KEY=$SK '$S3CLI_BIN' --endpoint-url http://127.0.0.1:$PA s3api head-object --bucket prx --key remote.txt >/dev/null 2>&1 && echo 0 || echo 1"

echo "== recovery of versions left PENDING"
pair rcv
stop c
echo "lost entry" | "$MC" pipe a/rcv/lost.txt >/dev/null
sleep 1
stop a
# Drop the durable queue records: the version is PENDING/FAILED with nothing queued.
dropped="$(find "$WORK/a" -path '*system/5a5251*' -print -delete | wc -l | tr -d ' ')"
check "queue records dropped" 1 "$([[ "$dropped" -ge 1 ]] && echo 1 || echo 0)"
startC; startA; ready "$PC"; ready "$PA"
eventually "recovered version delivered" "lost entry" "$MC" cat c/rcv/lost.txt
eventually "recovered version COMPLETED" COMPLETED rstatus rcv lost.txt

echo "== HTTPS target trusted through a custom CA"
"$MC" mb a/tlsb d/tlsb >/dev/null
"$MC" version enable a/tlsb >/dev/null; "$MC" version enable d/tlsb >/dev/null
check "https target added" 0 "$("$MC" replicate add a/tlsb --remote-bucket "https://$AK:$SK@localhost:$PD/tlsb" --priority 1 >/dev/null && echo 0)"
echo "over tls" | "$MC" pipe a/tlsb/t.txt >/dev/null
eventually "object replicated over TLS" "over tls" "$MC" cat d/tlsb/t.txt
eventually "TLS replica COMPLETED" COMPLETED rstatus tlsb t.txt

echo "== site replication with different root credentials"
"$MC" mb s1/web >/dev/null
check "admin replicate add" 0 "$("$MC" admin replicate add s1 s2 >/dev/null && echo 0)"
eventually "bucket on s2" 1 sh -c "'$MC' ls s2 | grep -c ' web/'"
S2DEP="$("$MC" admin replicate info s1 --json | python3 -c 'import json,sys; d=json.load(sys.stdin); print([s["deploymentID"] for s in d["sites"] if s["endpoint"].endswith(":'"$PS2"'")][0])')"
cli "$PS1" "$AK" "$SK" s3api put-bucket-website --bucket web --website-configuration '{"IndexDocument":{"Suffix":"index.html"},"ErrorDocument":{"Key":"err.html"}}'
cli "$PS1" "$AK" "$SK" s3api put-bucket-ownership-controls --bucket web --ownership-controls '{"Rules":[{"ObjectOwnership":"BucketOwnerPreferred"}]}'
eventually "website config on peer" index.html sh -c "AWS_ACCESS_KEY_ID=$AK2 AWS_SECRET_ACCESS_KEY=$SK2 '$S3CLI_BIN' --endpoint-url http://127.0.0.1:$PS2 s3api get-bucket-website --bucket web | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"IndexDocument\"][\"Suffix\"])'"
eventually "ownership controls on peer" BucketOwnerPreferred sh -c "AWS_ACCESS_KEY_ID=$AK2 AWS_SECRET_ACCESS_KEY=$SK2 '$S3CLI_BIN' --endpoint-url http://127.0.0.1:$PS2 s3api get-bucket-ownership-controls --bucket web | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"OwnershipControls\"][\"Rules\"][0][\"ObjectOwnership\"])'"
cli "$PS1" "$AK" "$SK" s3api delete-bucket-website --bucket web
eventually "website delete on peer" 1 sh -c "AWS_ACCESS_KEY_ID=$AK2 AWS_SECRET_ACCESS_KEY=$SK2 '$S3CLI_BIN' --endpoint-url http://127.0.0.1:$PS2 s3api get-bucket-website --bucket web >/dev/null 2>&1 && echo 0 || echo 1"

echo "-- STS across sites"
"$MC" admin user add s1 stsuser stsuser-secret-1 >/dev/null
"$MC" admin policy attach s1 readwrite --user stsuser >/dev/null
eventually "user replicated" 1 sh -c "'$MC' admin user list s2 | grep -c stsuser"
echo "for sts" | "$MC" pipe s1/web/sts.txt >/dev/null
eventually "object on s2" "for sts" "$MC" cat s2/web/sts.txt
CREDS="$(AWS_ACCESS_KEY_ID=stsuser AWS_SECRET_ACCESS_KEY=stsuser-secret-1 "$S3CLI_BIN" --endpoint-url "http://127.0.0.1:$PS1" sts assume-role --role-arn arn:minio:iam:::role/x --role-session-name sess --output json)"
TAK="$(echo "$CREDS" | jfield '["Credentials"]["AccessKeyId"]')"
TSK="$(echo "$CREDS" | jfield '["Credentials"]["SecretAccessKey"]')"
TST="$(echo "$CREDS" | jfield '["Credentials"]["SessionToken"]')"
stsget() { AWS_ACCESS_KEY_ID="$TAK" AWS_SECRET_ACCESS_KEY="$TSK" AWS_SESSION_TOKEN="$TST" "$S3CLI_BIN" --endpoint-url "http://127.0.0.1:$1" s3 cp s3://web/sts.txt - 2>&1; }
check "STS session on issuing site" "for sts" "$(stsget "$PS1")"
check "STS session on peer site" "for sts" "$(stsget "$PS2")"

echo "-- site edit"
check "edit to sync mode" 0 "$("$MC" admin replicate update s1 --deployment-id "$S2DEP" --mode sync >/dev/null && echo 0)"
peerfield() { # alias field
  "$MC" admin replicate info "$1" --json | python3 -c 'import json,sys; d=json.load(sys.stdin); print([s["'"$2"'"] for s in d["sites"] if s["deploymentID"]=="'"$S2DEP"'"][0])'; }
check "s1 sees sync" enable "$(peerfield s1 sync)"
check "edit reached s2" enable "$(peerfield s2 sync)"
echo "sync site" | "$MC" pipe s1/web/sync.txt >/dev/null
check "sync site write present at once" "sync site" "$("$MC" cat s2/web/sync.txt 2>/dev/null)"
check "edit endpoint" 0 "$("$MC" admin replicate update s1 --deployment-id "$S2DEP" --endpoint "http://localhost:$PS2" >/dev/null && echo 0)"
check "new endpoint recorded" "http://localhost:$PS2" "$(peerfield s1 endpoint)"
check "endpoint of another deployment refused" 1 "$("$MC" admin replicate update s1 --deployment-id "$S2DEP" --endpoint "http://127.0.0.1:$PA" >/dev/null 2>&1 && echo 0 || echo 1)"
echo "after edit" | "$MC" pipe s1/web/after-edit.txt >/dev/null
eventually "replication after endpoint edit" "after edit" "$MC" cat s2/web/after-edit.txt

check "endpoint edited back" 0 "$("$MC" admin replicate update s1 --deployment-id "$S2DEP" --endpoint "http://127.0.0.1:$PS2" >/dev/null && echo 0)"
echo "-- site resync"
check "resync start" 0 "$("$MC" admin replicate resync start s1 s2 >/dev/null && echo 0)"
resync_status() { # madmin resync op "status" (mc renders it only on a TTY)
  curl -s --aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" -X PUT --data "{\"deploymentID\":\"$S2DEP\"}" \
    "http://127.0.0.1:$PS1/minio/admin/v3/site-replication/resync/op?operation=status" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(",".join(sorted(set(b["status"] for b in d.get("buckets") or []))))'; }
eventually "resync completes" Completed resync_status
check "resync cancel" 0 "$("$MC" admin replicate resync cancel s1 s2 >/dev/null && echo 0)"
check "status after cancel" Canceled "$(resync_status)"

echo "== $pass passed, $fail failed"
[[ $fail -eq 0 ]]
