#!/usr/bin/env bash
# ILM tiering end-to-end: a second zkfsm is the remote tier (plus RustFS / MinIO in
# docker when available). Covers mc ilm tier add/ls/info/verify/edit/rm, transition
# and noncurrent transition, read-through with ranges, RestoreObject and restore
# expiry, delete/overwrite cleanup, object lock, tier outages, stats and metrics,
# and a three-node cluster sharing the tier configuration.
# Lifecycle days are shortened to seconds with ZKFSM_ILM_DAY_SECONDS.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
freeport() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
HOT_PORT="$(freeport)"
REM_PORT="$(freeport)"
HOT="http://127.0.0.1:$HOT_PORT"
REM="http://127.0.0.1:$REM_PORT"
WORK="$(mktemp -d)"
HOT_PID=""
REM_PID=""
CONTAINERS=()
CPIDS=()
cleanup() {
  for p in "${CPIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  [[ -n "$HOT_PID" ]] && kill "$HOT_PID" 2>/dev/null || true
  [[ -n "$REM_PID" ]] && kill "$REM_PID" 2>/dev/null || true
  for c in "${CONTAINERS[@]}"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
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
if [[ -z "$MC" ]] || ! "$MC" --version 2>/dev/null | grep -q RELEASE; then echo "tiering.sh needs the MinIO client (set MC)"; exit 1; fi
command -v aws >/dev/null || { echo "tiering.sh needs the aws CLI"; exit 1; }

pass=0
fail=0
check() { # name expected actual
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); echo "ok   $1"
  else fail=$((fail + 1)); echo "FAIL $1: expected [$2] got [$3]"; fi
}
ok() { if "$@" >/dev/null 2>&1; then echo 0; else echo 1; fi; }
hot() { AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" aws --endpoint-url "$HOT" "$@"; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
# head_field KEY FIELD [extra args]: one field of HeadObject ("" when absent).
head_field() { local k="$1" f="$2"; shift 2; hot s3api head-object --bucket data --key "$k" "$@" 2>/dev/null | jget "d.get('$f','')" || echo ERR; }
sclass() { head_field "$1" StorageClass "${@:2}"; }
# wait_for DESC EXPECTED CMD...: polls CMD (up to ~20s) until it prints EXPECTED.
wait_for() {
  local desc="$1" want="$2" got=""; shift 2
  for _ in $(seq 80); do got="$("$@" 2>/dev/null || true)"; [[ "$got" == "$want" ]] && break; sleep 0.25; done
  check "$desc" "$want" "$got"
}
status_of() { curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 aws:amz:us-east-1:s3 --user "$AK:$SK" "$@"; }
remote_count() { "$MC" ls --recursive "rem/$1" 2>/dev/null | wc -l | tr -d ' '; }

(cd "$ROOT" && zig build)
BIN="$ROOT/zig-out/bin/zkfsm"
wait_up() { for _ in $(seq 100); do curl -s -o /dev/null "$1/" && return 0; sleep 0.1; done; return 1; }
start_remote() {
  ZKFSM_ACCESS_KEY="$RAK" ZKFSM_SECRET_KEY="$RSK" "$BIN" --data "$WORK/remote" --listen "127.0.0.1:$REM_PORT" 2>>"$WORK/remote.log" &
  REM_PID=$!
  wait_up "$REM"
}
stop_remote() { kill "$REM_PID"; wait "$REM_PID" 2>/dev/null || true; REM_PID=""; }
start_hot() {
  ZKFSM_ILM_DAY_SECONDS=1 ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$BIN" --data "$WORK/hot" --listen "127.0.0.1:$HOT_PORT" \
    --lifecycle-interval 1 "$@" 2>>"$WORK/hot.log" &
  HOT_PID=$!
  wait_up "$HOT"
}
stop_hot() { kill "$HOT_PID"; wait "$HOT_PID" 2>/dev/null || true; HOT_PID=""; }
local_blobs() { find "$WORK/hot/data" -type f 2>/dev/null | wc -l | tr -d ' '; }

mkdir -p "$WORK/remote" "$WORK/hot"
start_remote
start_hot
"$MC" alias set rem "$REM" "$RAK" "$RSK" >/dev/null
"$MC" alias set hot "$HOT" "$AK" "$SK" >/dev/null
"$MC" mb rem/warm rem/cold >/dev/null

# ---- tier management ----
check "tier add" 0 "$(ok "$MC" ilm tier add minio hot WARM --endpoint "$REM" --access-key "$RAK" --secret-key "$RSK" --bucket warm --prefix tiered/)"
check "tier add duplicate refused" 1 "$(ok "$MC" ilm tier add minio hot WARM --endpoint "$REM" --access-key "$RAK" --secret-key "$RSK" --bucket warm --prefix other/)"
check "tier add reserved name refused" 1 "$(ok "$MC" ilm tier add minio hot STANDARD --endpoint "$REM" --access-key "$RAK" --secret-key "$RSK" --bucket warm --prefix x/)"
check "tier add bad credentials refused" 1 "$(ok "$MC" ilm tier add minio hot BAD --endpoint "$REM" --access-key "$RAK" --secret-key wrong-secret-123 --bucket warm --prefix bad/)"
check "tier add unreachable refused" 1 "$(ok "$MC" ilm tier add s3 hot DOWN --endpoint http://127.0.0.1:1 --access-key a --secret-key bbbbbbbb --bucket warm)"
echo junk | "$MC" pipe rem/cold/used/junk >/dev/null 2>&1
check "tier add over non-empty prefix refused" 1 "$(ok "$MC" ilm tier add s3 hot COLD --endpoint "$REM" --access-key "$RAK" --secret-key "$RSK" --bucket cold --prefix used/)"
check "tier add s3 type" 0 "$(ok "$MC" ilm tier add s3 hot COLD --endpoint "$REM" --access-key "$RAK" --secret-key "$RSK" --bucket cold --prefix fresh --region us-east-1)"
check "tier ls" "COLD WARM" "$("$MC" ilm tier ls hot --json | jget '" ".join(sorted(t["Name"] for t in d["tiers"]))')"
check "tier ls redacts secret" "REDACTED" "$("$MC" ilm tier ls hot --json | jget '[t for t in d["tiers"] if t["Name"]=="WARM"][0]["MinIO"]["SecretKey"]')"
check "tier ls s3 fields" "cold fresh" "$("$MC" ilm tier ls hot --json | jget '" ".join([(t["S3"]["Bucket"]+" "+t["S3"]["Prefix"]) for t in d["tiers"] if t["Name"]=="COLD"])')"
check "tier verify" 0 "$(ok "$MC" ilm tier verify hot WARM)"
check "tier verify unknown" 1 "$(ok "$MC" ilm tier verify hot NOPE)"
check "tier edit" 0 "$(ok "$MC" ilm tier edit hot COLD --access-key "$RAK" --secret-key "$RSK")"
check "tier edit bad secret refused" 1 "$(ok "$MC" ilm tier edit hot COLD --access-key "$RAK" --secret-key not-the-secret-1)"
check "tier rm empty" 0 "$(ok "$MC" ilm tier rm hot COLD)"
check "tier gone" 1 "$(ok "$MC" ilm tier verify hot COLD)"
check "sealed at rest" 0 "$(grep -rq "$RSK" "$WORK/hot" && echo 1 || echo 0)"

# ---- transition and read-through ----
"$MC" mb hot/data >/dev/null
head -c 3000000 /dev/urandom >"$WORK/big.bin"
echo "small object" >"$WORK/small.txt"
"$MC" cp "$WORK/big.bin" hot/data/big.bin >/dev/null
"$MC" cp "$WORK/small.txt" hot/data/logs/small.txt >/dev/null
"$MC" cp "$WORK/small.txt" hot/data/keep/local.txt >/dev/null
blobs_before="$(local_blobs)"
check "rule naming unknown tier refused" 1 "$(ok "$MC" ilm rule add hot/data --transition-days 1 --transition-tier NOPE)"
check "transition rule add" 0 "$(ok "$MC" ilm rule add hot/data --prefix big --transition-days 1 --transition-tier WARM)"
check "transition rule add (prefix logs/)" 0 "$(ok "$MC" ilm rule add hot/data --prefix logs/ --transition-days 1 --transition-tier WARM)"
check "rule export shows transition" "WARM" "$("$MC" ilm rule export hot/data | jget "d['Rules'][0]['Transition']['StorageClass']")"
wait_for "big.bin transitioned" WARM sclass big.bin
wait_for "small transitioned" WARM sclass logs/small.txt
check "unmatched stays local" "" "$(sclass keep/local.txt)"
check "remote holds the data" 2 "$(remote_count warm/tiered/)"
check "local blobs released" "$((blobs_before - 2))" "$(local_blobs)"
hot s3 cp s3://data/big.bin "$WORK/big.out" >/dev/null
check "read-through content" "$(sha256sum <"$WORK/big.bin")" "$(sha256sum <"$WORK/big.out")"
hot s3api get-object --bucket data --key big.bin --range bytes=1000-1999999 "$WORK/range.out" >/dev/null
check "read-through range" "$(tail -c +1001 "$WORK/big.bin" | head -c 1999000 | sha256sum)" "$(sha256sum <"$WORK/range.out")"
check "head size" 3000000 "$(head_field big.bin ContentLength)"
check "list shows object" 1 "$("$MC" ls hot/data/big.bin | wc -l | tr -d ' ')"
check "ListObjectsV2 storage class" "WARM STANDARD" "$(hot s3api list-objects-v2 --bucket data --prefix '' | jget "' '.join(o['StorageClass'] for o in d['Contents'] if o['Key'] in ('big.bin','keep/local.txt'))")"
check "ListObjects v1 storage class" WARM "$(hot s3api list-objects --bucket data --prefix big.bin | jget "d['Contents'][0]['StorageClass']")"
check "mc stat storage class" WARM "$("$MC" stat --json hot/data/big.bin | jget "d['metadata'].get('X-Amz-Storage-Class','')")"
"$MC" cp hot/data/big.bin hot/data/copy.bin >/dev/null
check "server-side copy of tiered object" "$(sha256sum <"$WORK/big.bin")" "$("$MC" cat hot/data/copy.bin | sha256sum)"

# ---- tier outage ----
stop_remote
check "GET during outage is 503" 503 "$(status_of "$HOT/data/big.bin")"
check "HEAD during outage works" 200 "$(status_of -I "$HOT/data/big.bin")"
check "local objects unaffected" 0 "$(ok "$MC" cat hot/data/keep/local.txt)"
"$MC" cp "$WORK/small.txt" hot/data/big2 >/dev/null
"$MC" ilm rule add hot/data --prefix big2 --transition-days 1 --transition-tier WARM >/dev/null
sleep 3
check "transition waits for the tier" "" "$(sclass big2)"
start_remote
wait_for "transition retried after outage" WARM sclass big2
check "GET after outage" "$(sha256sum <"$WORK/big.bin")" "$("$MC" cat hot/data/big.bin | sha256sum)"

# ---- restore ----
check "restore of local object refused" 403 "$(curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 aws:amz:us-east-1:s3 --user "$AK:$SK" -X POST --data '<RestoreRequest><Days>1</Days></RestoreRequest>' "$HOT/data/keep/local.txt?restore")"
check "restore accepted" 202 "$(curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 aws:amz:us-east-1:s3 --user "$AK:$SK" -X POST --data '<RestoreRequest><Days>8</Days></RestoreRequest>' "$HOT/data/big.bin?restore")"
check "x-amz-restore header" 'ongoing-request="false"' "$(head_field big.bin Restore | cut -d, -f1)"
check "restore again extends" 200 "$(curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 aws:amz:us-east-1:s3 --user "$AK:$SK" -X POST --data '<RestoreRequest><Days>8</Days></RestoreRequest>' "$HOT/data/big.bin?restore")"
stop_remote
check "restored copy served while tier is down" "$(sha256sum <"$WORK/big.bin")" "$("$MC" cat hot/data/big.bin | sha256sum)"
start_remote
check "mc ilm restore" 0 "$(ok "$MC" ilm restore --days 30 hot/data/logs/small.txt)"
wait_for "restored copy expires" "" head_field big.bin Restore
check "storage class kept after expiry" WARM "$(sclass big.bin)"
check "read-through after expiry" "$(sha256sum <"$WORK/big.bin")" "$("$MC" cat hot/data/big.bin | sha256sum)"

# ---- cleanup on delete and overwrite ----
before="$(remote_count warm/tiered/)"
"$MC" rm hot/data/big2 >/dev/null
wait_for "delete removes remote data" "$((before - 1))" remote_count warm/tiered/
"$MC" cp "$WORK/small.txt" hot/data/logs/small.txt >/dev/null
wait_for "overwrite removes remote data" "$((before - 2))" remote_count warm/tiered/
check "overwritten object is local again" "" "$(sclass logs/small.txt)"
stop_remote
"$MC" rm hot/data/copy.bin >/dev/null 2>&1 || true
"$MC" cp "$WORK/small.txt" hot/data/del-me >/dev/null
"$MC" ilm rule add hot/data --prefix del-me --transition-days 1 --transition-tier WARM >/dev/null 2>&1 || true
start_remote
wait_for "del-me transitioned" WARM sclass del-me
n_before="$(remote_count warm/tiered/)"
stop_remote
"$MC" rm hot/data/del-me >/dev/null
sleep 2
check "pending cleanup in metrics" 1 "$(curl -s "$HOT/metrics" | awk '/^zkfsm_tier_cleanup_pending /{print ($2>=1)}')"
start_remote
wait_for "cleanup retried after outage" "$((n_before - 1))" remote_count warm/tiered/

# ---- versioning and noncurrent transition ----
"$MC" mb hot/ver >/dev/null
"$MC" version enable hot/ver >/dev/null
echo one | "$MC" pipe hot/ver/doc >/dev/null 2>&1
echo two | "$MC" pipe hot/ver/doc >/dev/null 2>&1
check "noncurrent transition rule" 0 "$(ok "$MC" ilm rule add hot/ver --noncurrent-transition-days 1 --noncurrent-transition-tier WARM)"
old_vid() { hot s3api list-object-versions --bucket ver --prefix doc | jget "[v['VersionId'] for v in d['Versions'] if not v['IsLatest']][0]"; }
OLD="$(old_vid)"
vclass() { hot s3api head-object --bucket ver --key doc ${1:+--version-id "$1"} | jget "d.get('StorageClass','')"; }
wait_for "noncurrent version transitioned" WARM vclass "$OLD"
check "current version stays local" "" "$(vclass)"
check "ListObjectVersions storage class" "STANDARD WARM" "$(hot s3api list-object-versions --bucket ver --prefix doc | jget "' '.join(v['StorageClass'] for v in d['Versions'])")"
check "noncurrent read-through" one "$(hot s3api get-object --bucket ver --key doc --version-id "$OLD" "$WORK/v.out" >/dev/null && cat "$WORK/v.out")"
before="$(remote_count warm/tiered/)"
hot s3api delete-object --bucket ver --key doc >/dev/null
# The marker makes "two" noncurrent, so it transitions too; nothing is deleted.
wait_for "delete marker keeps tiered versions" "$((before + 1))" remote_count warm/tiered/
before="$(remote_count warm/tiered/)"
hot s3api delete-object --bucket ver --key doc --version-id "$OLD" >/dev/null
wait_for "version delete removes remote data" "$((before - 1))" remote_count warm/tiered/

# ---- object lock ----
hot s3api create-bucket --bucket locked --object-lock-enabled-for-bucket >/dev/null
echo locked | "$MC" pipe hot/locked/l.txt >/dev/null 2>&1
LVID="$(hot s3api head-object --bucket locked --key l.txt | jget "d['VersionId']")"
hot s3api put-object-retention --bucket locked --key l.txt --version-id "$LVID" --retention "Mode=COMPLIANCE,RetainUntilDate=$(date -u -d '+1 day' +%Y-%m-%dT%H:%M:%SZ)" >/dev/null
"$MC" ilm rule add hot/locked --transition-days 1 --transition-tier WARM >/dev/null
lclass() { hot s3api head-object --bucket locked --key l.txt | jget "d.get('StorageClass','')"; }
wait_for "locked object transitions" WARM lclass
before="$(remote_count warm/tiered/)"
check "locked version delete refused" 1 "$(ok hot s3api delete-object --bucket locked --key l.txt --version-id "$LVID")"
sleep 2
check "locked version's remote data kept" "$before" "$(remote_count warm/tiered/)"
check "retention kept on tiered version" COMPLIANCE "$(hot s3api head-object --bucket locked --key l.txt | jget "d.get('ObjectLockMode','')")"

# ---- stats, metrics, persistence ----
sleep 2
tinfo() { "$MC" ilm tier info hot --json | jget "[t['Stats']['$1'] for t in d['tiers'] if t['Name']=='$2'][0]"; }
check "tier info counts WARM versions" 1 "$(( $(tinfo numVersions WARM) >= 4 ))"
check "tier info counts WARM bytes" 1 "$(( $(tinfo totalSize WARM) >= 3000000 ))"
check "tier info has STANDARD" 1 "$(( $(tinfo numObjects STANDARD) >= 1 ))"
check "tier info daily transitions" 1 "$("$MC" ilm tier info hot --json | jget "int(sum(b['numObjects'] for t in d['tiers'] if t['Name']=='WARM' for b in t['DailyStats']['Bins']) >= 4)")"
check "admin tier-stats has STANDARD" 1 "$(curl -s --aws-sigv4 aws:amz:us-east-1:s3 --user "$AK:$SK" "$HOT/minio/admin/v3/tier-stats" | jget "int(any(t['Name']=='STANDARD' for t in d))")"
check "metrics transitions" 1 "$(curl -s "$HOT/metrics" | awk '/^zkfsm_tier_transitions_total /{print ($2>=4)}')"
check "metrics per-tier bytes" 1 "$(curl -s "$HOT/metrics" | grep -c '^zkfsm_tier_bytes{tier="WARM"')"
check "tier rm in use refused" 1 "$(ok "$MC" ilm tier rm hot WARM)"
stop_hot
start_hot
check "tiers persist across restart" 0 "$(ok "$MC" ilm tier verify hot WARM)"
check "read-through after restart" "$(sha256sum <"$WORK/big.bin")" "$("$MC" cat hot/data/big.bin | sha256sum)"
stop_hot
mv "$WORK/hot.log" "$WORK/hot1.log"
ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="other-root-secret-999" "$BIN" --data "$WORK/hot" --listen "127.0.0.1:$HOT_PORT" 2>"$WORK/hot.log" &
HOT_PID=$!
wait_up "$HOT"
"$MC" alias set hot2 "$HOT" "$AK" "other-root-secret-999" >/dev/null
check "other root secret cannot open tiers" 1 "$(ok "$MC" ilm tier verify hot2 WARM)"
stop_hot
start_hot

# ---- cluster: tiers are cluster-wide; any node reads through ----
CPORT=(0 "$(freeport)" "$(freeport)" "$(freeport)")
CDATA=()
for i in 1 2 3; do CDATA+=("http://127.0.0.1:${CPORT[$i]}$WORK/c$i/d{1...2}"); done
for i in 1 2 3; do
  ZKFSM_ILM_DAY_SECONDS=1 ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$BIN" --data "${CDATA[@]}" --listen "127.0.0.1:${CPORT[$i]}" \
    --node-address "127.0.0.1:${CPORT[$i]}" --protection EC:4+2 --lifecycle-interval 1 >>"$WORK/c$i.log" 2>&1 &
  CPIDS+=($!)
done
cleanup_cluster() { for p in "${CPIDS[@]}"; do kill "$p" 2>/dev/null || true; done; for p in "${CPIDS[@]}"; do wait "$p" 2>/dev/null || true; done; }
for i in 1 2 3; do
  for _ in $(seq 600); do [[ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${CPORT[$i]}/health/ready")" == 200 ]] && break; sleep 0.1; done
done
for i in 1 2 3; do "$MC" alias set "c$i" "http://127.0.0.1:${CPORT[$i]}" "$AK" "$SK" >/dev/null; done
"$MC" mb rem/clu >/dev/null
check "cluster tier add (node 1)" 0 "$(ok "$MC" ilm tier add minio c1 CWARM --endpoint "$REM" --access-key "$RAK" --secret-key "$RSK" --bucket clu --prefix c/)"
wait_for "cluster tier visible on node 3" 0 ok "$MC" ilm tier verify c3 CWARM
"$MC" mb c2/cdata >/dev/null
"$MC" cp "$WORK/big.bin" c2/cdata/obj >/dev/null
check "cluster rule add (node 2)" 0 "$(ok "$MC" ilm rule add c2/cdata --transition-days 1 --transition-tier CWARM)"
cclass() { AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" aws --endpoint-url "http://127.0.0.1:${CPORT[$1]}" s3api head-object --bucket cdata --key obj | jget "d.get('StorageClass','')"; }
wait_for "cluster transition" CWARM cclass 3
check "cluster read-through (node 1)" "$(sha256sum <"$WORK/big.bin")" "$("$MC" cat c1/cdata/obj | sha256sum)"
check "cluster read-through (node 3)" "$(sha256sum <"$WORK/big.bin")" "$("$MC" cat c3/cdata/obj | sha256sum)"
check "cluster remote holds data" 1 "$(remote_count clu/c/)"
"$MC" rm c3/cdata/obj >/dev/null
wait_for "cluster delete cleans the tier" 0 remote_count clu/c/
cleanup_cluster
CPIDS=()

# ---- third-party S3 backends in docker (optional) ----
docker_tier() { # NAME IMAGE ENV... -- ARGS
  local name="$1" image="$2"; shift 2
  local port; port="$(freeport)"
  local envs=(); while [[ "$1" != "--" ]]; do envs+=(-e "$1"); shift; done; shift
  local cname="zkfsm-tiering-$name-$$"
  docker run -d --name "$cname" -p "127.0.0.1:$port:9000" "${envs[@]}" "$image" "$@" >/dev/null 2>&1 || return 1
  CONTAINERS+=("$cname")
  for _ in $(seq 100); do curl -s -o /dev/null "http://127.0.0.1:$port/" && break; sleep 0.2; done
  echo "$port"
}
if command -v docker >/dev/null && docker info >/dev/null 2>&1; then
  for spec in "RUSTFS|rustfs/rustfs:latest|RUSTFS_ACCESS_KEY=dockeradmin|RUSTFS_SECRET_KEY=docker-secret-123" \
              "MINIO|quay.io/minio/minio:latest|MINIO_ROOT_USER=dockeradmin|MINIO_ROOT_PASSWORD=docker-secret-123"; do
    IFS='|' read -r tname image e1 e2 <<<"$spec"
    docker image inspect "$image" >/dev/null 2>&1 || { echo "skip $tname: image $image not present"; continue; }
    if [[ "$tname" == MINIO ]]; then port="$(docker_tier minio "$image" "$e1" "$e2" -- server /data)" || continue
    else port="$(docker_tier rustfs "$image" "$e1" "$e2" -- )" || continue; fi
    "$MC" alias set "d$tname" "http://127.0.0.1:$port" dockeradmin docker-secret-123 >/dev/null 2>&1 || true
    for _ in $(seq 50); do "$MC" mb --ignore-existing "d$tname/tier" >/dev/null 2>&1 && break; sleep 0.3; done
    check "$tname tier add" 0 "$(ok "$MC" ilm tier add s3 hot "$tname" --endpoint "http://127.0.0.1:$port" --access-key dockeradmin --secret-key docker-secret-123 --bucket tier --prefix z/)"
    "$MC" mb "hot/d-$(echo "$tname" | tr A-Z a-z)" >/dev/null
    b="d-$(echo "$tname" | tr A-Z a-z)"
    "$MC" cp "$WORK/big.bin" "hot/$b/obj" >/dev/null
    "$MC" ilm rule add "hot/$b" --transition-days 1 --transition-tier "$tname" >/dev/null
    dclass() { hot s3api head-object --bucket "$b" --key obj | jget "d.get('StorageClass','')"; }
    wait_for "$tname transition" "$tname" dclass
    check "$tname read-through" "$(sha256sum <"$WORK/big.bin")" "$("$MC" cat "hot/$b/obj" | sha256sum)"
    hot s3api get-object --bucket "$b" --key obj --range bytes=5-104 "$WORK/r.out" >/dev/null
    check "$tname range" "$(tail -c +6 "$WORK/big.bin" | head -c 100 | sha256sum)" "$(sha256sum <"$WORK/r.out")"
    "$MC" rm "hot/$b/obj" >/dev/null
    wait_for "$tname cleanup" 0 bash -c "\"$MC\" ls --recursive d$tname/tier/z/ 2>/dev/null | wc -l | tr -d ' '"
  done
else
  echo "skip docker tiers: docker not available"
fi

echo "tiering: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
