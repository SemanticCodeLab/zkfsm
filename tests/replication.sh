#!/usr/bin/env bash
# Bucket and site replication across three local deployments: A (single node),
# B (4-node EC:4+2 cluster), C (single node). Covers one-way and two-way bucket
# replication, version ids, multipart, metadata, delete markers and version deletes,
# delivery after a target outage, resync, and `mc replicate` / `mc admin replicate`
# with bucket, IAM, and object propagation.
set -euo pipefail
S3CLI_BIN="${S3CLI_BIN:-aws}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
MC="${MC:-$(command -v mc || true)}"
if [[ -z "$MC" ]] || ! "$MC" --version >/dev/null 2>&1; then echo "replication.sh needs the MinIO client (set MC)"; exit 1; fi
declare -A PID=()
cleanup() {
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
# eventually NAME EXPECTED COMMAND... : retries for up to 60 s
eventually() {
  local name="$1" want="$2" got=""; shift 2
  for _ in $(seq 120); do got="$("$@" 2>/dev/null || true)"; [[ "$got" == "$want" ]] && break; sleep 0.5; done
  check "$name" "$want" "$got"
}
freeport() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }

AK="repladmin"
SK="replication-secret-0123"
export AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_DEFAULT_REGION=us-east-1 AWS_PAGER=""
export AWS_CONFIG_FILE="$WORK/s3cli.conf" AWS_SHARED_CREDENTIALS_FILE="$WORK/s3cli.creds"
printf '[default]\ns3 =\n  addressing_style = path\n' >"$AWS_CONFIG_FILE"
export MC_CONFIG_DIR="$WORK/mc"

(cd "$ROOT" && zig build -Doptimize=ReleaseSafe)
BIN="$ROOT/zig-out/bin/zkfsm"

PA="$(freeport)"
PC="$(freeport)"
PB=(0 "$(freeport)" "$(freeport)" "$(freeport)" "$(freeport)")
POOL=()
for i in 1 2 3 4; do POOL+=("http://127.0.0.1:${PB[$i]}$WORK/b$i/d{1...4}"); done

run() { # name args...
  local n="$1"; shift
  ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$BIN" "$@" >>"$WORK/$n.log" 2>&1 &
  PID[$n]=$!
}
startA() { run a --data "$WORK/a" --listen "127.0.0.1:$PA"; }
startC() { run c --data "$WORK/c" --listen "127.0.0.1:$PC"; }
startB() {
  for i in 1 2 3 4; do
    run "b$i" --data "${POOL[@]}" --listen "127.0.0.1:${PB[$i]}" --node-address "127.0.0.1:${PB[$i]}" --protection EC:4+2 --cluster-refresh 2
  done
}
ready() { # port
  for _ in $(seq 600); do [[ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$1/health/ready")" == 200 ]] && return 0; sleep 0.1; done
  echo "server on $1 not ready"; tail -n 20 "$WORK"/*.log; exit 1
}
stop() { kill -9 "${PID[$1]}" 2>/dev/null || true; wait "${PID[$1]}" 2>/dev/null || true; unset "PID[$1]"; }

startA; startC; startB
ready "$PA"; ready "$PC"; for i in 1 2 3 4; do ready "${PB[$i]}"; done
"$MC" alias set a "http://127.0.0.1:$PA" "$AK" "$SK" >/dev/null
"$MC" alias set c "http://127.0.0.1:$PC" "$AK" "$SK" >/dev/null
for i in 1 2 3 4; do "$MC" alias set "b$i" "http://127.0.0.1:${PB[$i]}" "$AK" "$SK" >/dev/null; done
cliA() { "$S3CLI_BIN" --endpoint-url "http://127.0.0.1:$PA" "$@"; }
cliB() { "$S3CLI_BIN" --endpoint-url "http://127.0.0.1:${PB[2]}" "$@"; }
jfield() { python3 -c "import json,sys; d=json.load(sys.stdin); print(d$1)"; }
vid() { # cli bucket key
  "$1" s3api head-object --bucket "$2" --key "$3" 2>/dev/null | jfield '["VersionId"]'
}
rstatus() { "$1" s3api head-object --bucket "$2" --key "$3" 2>/dev/null | jfield '.get("ReplicationStatus","")'; }
etag() { "$1" s3api head-object --bucket "$2" --key "$3" 2>/dev/null | jfield '["ETag"]'; }
nversions() { "$MC" ls --versions "$1" 2>/dev/null | wc -l | tr -d ' '; }
catobj() { "$MC" cat "$1" 2>/dev/null; }

echo "== bucket replication A -> B (cluster)"
"$MC" mb a/src b1/dst >/dev/null
"$MC" version enable a/src >/dev/null
check "rule needs versioning on the target" 1 "$("$MC" replicate add a/src --remote-bucket "http://$AK:$SK@127.0.0.1:${PB[1]}/dst" >/dev/null 2>&1 && echo 0 || echo 1)"
"$MC" version enable b1/dst >/dev/null
echo old | "$MC" pipe a/src/existing.txt >/dev/null
check "replicate add" 0 "$("$MC" replicate add a/src --remote-bucket "http://$AK:$SK@127.0.0.1:${PB[1]}/dst" --replicate "delete,delete-marker,existing-objects,metadata-sync" >/dev/null && echo 0)"
ARN="$("$MC" replicate ls a/src --json | python3 -c "import json,sys; print(json.loads(sys.stdin.readline())['rule']['Destination']['Bucket'])")"
admin() { curl -s "${@:2}" --aws-sigv4 aws:amz:us-east-1:s3 --user "$AK:$SK" "http://127.0.0.1:$PA/minio/admin/v3/$1"; }
check "rule names the remote target" 1 "$(admin "list-remote-targets?bucket=src&type=replication" | grep -c "$ARN")"
eventually "existing object replicated" old catobj b3/dst/existing.txt

echo hello >"$WORK/f.txt"
cliA s3 cp "$WORK/f.txt" s3://src/docs/f.txt --metadata color=blue --content-type text/plain >/dev/null
cliA s3api put-object-tagging --bucket src --key docs/f.txt --tagging 'TagSet=[{Key=team,Value=red}]' >/dev/null
V1="$(vid cliA src docs/f.txt)"
eventually "object replicated" hello catobj b2/dst/docs/f.txt
check "version id preserved" "$V1" "$(vid cliB dst docs/f.txt)"
eventually "source status COMPLETED" COMPLETED rstatus cliA src docs/f.txt
check "target status REPLICA" REPLICA "$(rstatus cliB dst docs/f.txt)"
check "user metadata replicated" blue "$(cliB s3api head-object --bucket dst --key docs/f.txt | jfield '["Metadata"]["color"]')"
check "content type replicated" text/plain "$(cliB s3api head-object --bucket dst --key docs/f.txt | jfield '["ContentType"]')"
eventually "tags replicated" red sh -c "'$S3CLI_BIN' --endpoint-url http://127.0.0.1:${PB[3]} s3api get-object-tagging --bucket dst --key docs/f.txt | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"TagSet\"][0][\"Value\"])'"

head -c 12000000 /dev/urandom >"$WORK/big.bin"
cliA s3 cp "$WORK/big.bin" s3://src/big.bin >/dev/null
eventually "multipart replicated with the same ETag" "$(etag cliA src big.bin)" etag cliB dst big.bin
check "multipart part count kept" 2 "$(cliB s3api head-object --bucket dst --key big.bin --part-number 1 | jfield '["PartsCount"]')"
cliB s3 cp s3://dst/big.bin "$WORK/big.out" >/dev/null
check "multipart content" "$(md5sum <"$WORK/big.bin")" "$(md5sum <"$WORK/big.out")"

"$MC" rm a/src/docs/f.txt >/dev/null
DM="$(cliA s3api list-object-versions --bucket src --prefix docs/f.txt | jfield '["DeleteMarkers"][0]["VersionId"]')"
eventually "delete marker replicated" "$DM" sh -c "'$S3CLI_BIN' --endpoint-url http://127.0.0.1:${PB[1]} s3api list-object-versions --bucket dst --prefix docs/f.txt | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"DeleteMarkers\"][0][\"VersionId\"])'"
cliA s3api delete-object --bucket src --key docs/f.txt --version-id "$V1" >/dev/null
eventually "version delete replicated" 1 nversions b1/dst/docs/f.txt

echo "== two-way (active-active)"
"$MC" replicate add b1/dst --remote-bucket "http://$AK:$SK@127.0.0.1:$PA/src" --replicate "delete-marker,metadata-sync" >/dev/null
echo fromb | "$MC" pipe b4/dst/fromb.txt >/dev/null
eventually "B write reaches A" fromb catobj a/src/fromb.txt
check "A copy is a replica" REPLICA "$(rstatus cliA src fromb.txt)"
echo froma | "$MC" pipe a/src/froma.txt >/dev/null
eventually "A write reaches B" froma catobj b1/dst/froma.txt
sleep 3
check "no replication loop (A)" 1 "$(nversions a/src/froma.txt)"
check "no replication loop (B)" 1 "$(nversions b2/dst/fromb.txt)"
cliA s3api put-object-tagging --bucket src --key fromb.txt --tagging 'TagSet=[{Key=edited,Value=on-a}]' >/dev/null
eventually "replica modification flows back" on-a sh -c "'$S3CLI_BIN' --endpoint-url http://127.0.0.1:${PB[1]} s3api get-object-tagging --bucket dst --key fromb.txt | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"TagSet\"][0][\"Value\"])'"

echo "== target outage"
for i in 1 2 3 4; do stop "b$i"; done
for i in 1 2 3; do echo "out$i" | "$MC" pipe "a/src/out/$i" >/dev/null; done
eventually "status FAILED while the target is down" FAILED rstatus cliA src out/1
check "metrics show the backlog" 1 "$(curl -s "http://127.0.0.1:$PA/metrics" | grep -c "zkfsm_replication_pending_operations{bucket=\"src\",target=\"$ARN\"} [1-9]")"
startB
for i in 1 2 3 4; do ready "${PB[$i]}"; done
eventually "backlog delivered after recovery" 3 sh -c "'$MC' ls b2/dst/out/ | wc -l | tr -d ' '"
eventually "status COMPLETED after recovery" COMPLETED rstatus cliA src out/3

echo "== resync"
"$MC" rm --recursive --force --versions b1/dst/out/ >/dev/null
check "target copies removed" 0 "$("$MC" ls b1/dst/out/ 2>/dev/null | wc -l | tr -d ' ')"
check "resync start" 0 "$("$MC" replicate resync start a/src --remote-bucket "$ARN" >/dev/null && echo 0)"
eventually "resync restores objects" 3 sh -c "'$MC' ls b3/dst/out/ | wc -l | tr -d ' '"
eventually "resync status Completed" Completed sh -c "'$MC' replicate resync status a/src --remote-bucket '$ARN' --json | python3 -c 'import json,sys; print(json.loads(sys.stdin.readline())[\"resyncInfo\"][\"target\"][0][\"resyncStatus\"])'"

echo "== status and metrics"
check "replicate status" 0 "$("$MC" replicate status a/src >/dev/null && echo 0)"
check "metrics: sent bytes" 1 "$(curl -s "http://127.0.0.1:$PA/metrics" | grep -c "^zkfsm_replication_sent_bytes_total{bucket=\"src\"")"
check "metrics: replicas received on B" 1 "$(curl -s "http://127.0.0.1:${PB[1]}/metrics" "http://127.0.0.1:${PB[2]}/metrics" "http://127.0.0.1:${PB[3]}/metrics" "http://127.0.0.1:${PB[4]}/metrics" | grep -c '^zkfsm_replication_received_objects_total [1-9]' | awk '{print ($1 > 0)}')"
check "target in use cannot be removed" 400 "$(admin "remove-remote-target?bucket=src&arn=$ARN" -o /dev/null -w '%{http_code}' -X DELETE)"
check "replicate rm" 0 "$("$MC" replicate rm --all --force a/src >/dev/null && echo 0)"
admin "remove-remote-target?bucket=src&arn=$ARN" -o /dev/null -X DELETE
check "remote target removed" 0 "$(admin "list-remote-targets?bucket=src&type=replication" | grep -c "$ARN" || true)"
echo after | "$MC" pipe a/src/after-rm.txt >/dev/null
sleep 3
check "nothing replicates after rule removal" 1 "$("$MC" stat b1/dst/after-rm.txt >/dev/null 2>&1 && echo 0 || echo 1)"

echo "== site replication A + B + C"
"$MC" mb c/cbucket >/dev/null
echo fromc | "$MC" pipe c/cbucket/pre.txt >/dev/null
"$MC" admin user add a alice alicesecret1 >/dev/null
check "admin replicate add" 0 "$("$MC" admin replicate add a b1 c >/dev/null && echo 0)"
check "info lists three sites" 3 "$("$MC" admin replicate info c --json | jfield '["sites"].__len__()')"
eventually "existing bucket reaches A" fromc catobj a/cbucket/pre.txt
eventually "existing bucket reaches B" fromc catobj b2/cbucket/pre.txt
eventually "existing user reaches C" enabled sh -c "'$MC' admin user info c alice --json | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"userStatus\"])'"
eventually "existing user reaches B" enabled sh -c "'$MC' admin user info b3 alice --json | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"userStatus\"])'"

"$MC" mb b1/newb >/dev/null
check "new bucket is versioned" Enabled "$("$MC" version info b1/newb --json | jfield '["versioning"]["status"]')"
echo site | "$MC" pipe b2/newb/k.txt >/dev/null
eventually "bucket created on B reaches C" site catobj c/newb/k.txt
eventually "bucket created on B reaches A" site catobj a/newb/k.txt
check "site replica keeps the version id" "$(vid cliB newb k.txt)" "$(vid cliA newb k.txt)"
"$MC" rm c/newb/k.txt >/dev/null
eventually "delete marker from C reaches B" 2 nversions b3/newb/k.txt

"$MC" admin user add b1 bob bobsecret12 >/dev/null
printf '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::newb","arn:aws:s3:::newb/*"]}]}' >"$WORK/pol.json"
"$MC" admin policy create c newbrw "$WORK/pol.json" >/dev/null
eventually "user created on B reaches A" enabled sh -c "'$MC' admin user info a bob --json | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"userStatus\"])'"
eventually "policy created on C reaches B" 1 sh -c "'$MC' admin policy list b4 | grep -cx newbrw"
"$MC" admin policy attach a newbrw --user bob >/dev/null
eventually "policy mapping reaches C" newbrw sh -c "'$MC' admin user info c bob --json | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"policyName\"])'"
"$MC" alias set bobc "http://127.0.0.1:$PC" bob bobsecret12 >/dev/null
check "replicated user can use C" 2 "$(nversions bobc/newb/k.txt)"
"$MC" admin user remove a alice >/dev/null
eventually "user removal reaches B" 1 sh -c "'$MC' admin user info b2 alice >/dev/null 2>&1 && echo 0 || echo 1"
"$MC" anonymous set download a/cbucket >/dev/null
eventually "bucket policy reaches B" download sh -c "'$MC' anonymous get b1/cbucket | awk '{print \$NF}' | tr -d '\`'"
eventually "status: buckets in sync" 0 sh -c "curl -s --aws-sigv4 aws:amz:us-east-1:s3 --user '$AK:$SK' 'http://127.0.0.1:$PA/minio/admin/v3/site-replication/status' | python3 -c 'import json,sys; print(len(json.load(sys.stdin)[\"BucketStats\"]))'"
check "mc admin replicate status" 0 "$("$MC" admin replicate status a >/dev/null && echo 0)"

check "admin replicate rm" 0 "$("$MC" admin replicate rm a c --force >/dev/null && echo 0)"
check "removed site is disabled" False "$("$MC" admin replicate info c --json | jfield '.get("enabled", False)')"
check "remaining sites list two" 2 "$("$MC" admin replicate info b1 --json | jfield '["sites"].__len__()')"
"$MC" mb a/after >/dev/null
eventually "bucket still syncs between A and B" 1 sh -c "'$MC' ls b1 | grep -c ' after/'"
sleep 2
check "removed site gets nothing" 0 "$("$MC" ls c | grep -c ' after/' || true)"

echo "replication: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
