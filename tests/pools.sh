#!/usr/bin/env bash
# Server pools on local 4-node clusters (EC:4+2):
#  1. two pools: decommission the first pool (it holds the system records) under
#     concurrent PUT/GET/DELETE traffic with versioned, locked, tagged, and multipart
#     data; kill -9 the moving node mid-way and resume; restart without the pool;
#     a pool that was not decommissioned cannot be dropped.
#  2. three pools: append an empty pool, rebalance (throttled; stop and restart it),
#     then decommission the middle pool and restart without it.
set -euo pipefail
S3CLI_BIN="${S3CLI_BIN:-aws}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
MC="${MC:-$(command -v mc || true)}"
[[ -n "$MC" ]] || { echo "pools.sh needs mc (set MC=)"; exit 1; }
PIDS=(0 0 0 0 0)
TPID=0
cleanup() {
  local rc=$?
  [[ "$TPID" != 0 ]] && kill "$TPID" 2>/dev/null || true
  if [[ $rc -ne 0 && -n "${POOLS_KEEP_LOGS:-}" ]]; then mkdir -p "$POOLS_KEEP_LOGS"; cp "$WORK"/n*.log "$POOLS_KEEP_LOGS/" 2>/dev/null || true; fi
  for p in "${PIDS[@]}"; do [[ "$p" != 0 ]] && kill -9 "$p" 2>/dev/null || true; done
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

AK="poolsadmin"
SK="pools-secret-key-0123"
export AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_DEFAULT_REGION=us-east-1 AWS_PAGER=""
export AWS_CONFIG_FILE="$WORK/s3cli.conf" AWS_SHARED_CREDENTIALS_FILE="$WORK/s3cli.creds"
printf '[default]\ns3 =\n  addressing_style = path\n' >"$AWS_CONFIG_FILE"
export MC_CONFIG_DIR="$WORK/mc"

(cd "$ROOT" && zig build -Doptimize=ReleaseSafe)
BIN="$ROOT/zig-out/bin/zkfsm"

PORT=(0 "$(freeport)" "$(freeport)" "$(freeport)" "$(freeport)")
pool() { # drive-dir-prefix -> endpoint args, one per node
  local out=() i
  for i in 1 2 3 4; do out+=("http://127.0.0.1:${PORT[$i]}$WORK/n$i/$1{1...4}"); done
  echo "${out[*]}"
}
read -r -a PA <<<"$(pool a)"
read -r -a PB <<<"$(pool b)"
POOLS=()
RATE=64

start() { # node
  local i="$1"
  ZKFSM_REBALANCE_MBPS="$RATE" ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$BIN" "${POOLS[@]}" --listen "127.0.0.1:${PORT[$i]}" \
    --node-address "127.0.0.1:${PORT[$i]}" --protection EC:4+2 --scan-interval 20 >>"$WORK/n$i.log" 2>&1 &
  PIDS[$i]=$!
}
ready() { curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT[$1]}/health/ready" || true; }
wait_ready() { # node [seconds]
  for _ in $(seq $((${2:-60} * 10))); do [[ "$(ready "$1")" == 200 ]] && return 0; sleep 0.1; done
  echo "node $1 not ready:"; tail -n 30 "$WORK/n$1.log"; exit 1
}
start_all() { for i in 1 2 3 4; do start "$i"; done; for i in 1 2 3 4; do wait_ready "$i" 120; done; }
stop_all() {
  for i in 1 2 3 4; do [[ "${PIDS[$i]}" != 0 ]] && kill "${PIDS[$i]}" 2>/dev/null || true; done
  for i in 1 2 3 4; do [[ "${PIDS[$i]}" != 0 ]] && { wait "${PIDS[$i]}" 2>/dev/null || true; }; PIDS[$i]=0; done
}
kill9() { kill -9 "${PIDS[$1]}" 2>/dev/null || true; wait "${PIDS[$1]}" 2>/dev/null || true; PIDS[$1]=0; }
ep() { echo "http://127.0.0.1:${PORT[$1]}"; }
cli() { local i="$1"; shift; "$S3CLI_BIN" --endpoint-url "$(ep "$i")" "$@"; }
sig=(--aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK")
md5() { md5sum "$1" | cut -d' ' -f1; }
aliases() { for i in 1 2 3 4; do "$MC" alias set "z$i" "$(ep "$i")" "$AK" "$SK" >/dev/null; done; }
# Blob shard files under a pool's drives (records leave delete tombstones for a while).
keyfiles() { find "$WORK"/n*/"$1"[0-9]* -path '*/data/*' -type f 2>/dev/null | wc -l; }
jget() { python3 -c 'import json,sys
d=json.load(sys.stdin)
for k in sys.argv[1].split("."):
    d=d[int(k)] if isinstance(d,list) else d.get(k)
print(str(d).lower() if isinstance(d,bool) else d)' "$1"; }
decom() { # node pool-cmdline field
  "$MC" admin decommission status --json "z$1" "$2" 2>/dev/null | jget "decommissionInfo.$3" || echo "?"
}
wait_decom() { # node pool-cmdline seconds -> complete|failed|canceled|timeout
  local s
  for _ in $(seq "$3"); do
    s=$("$MC" admin decommission status --json "z$1" "$2" 2>/dev/null || true)
    if [[ -n "$s" ]]; then
      [[ "$(echo "$s" | jget decommissionInfo.complete)" == true ]] && { echo complete; return; }
      [[ "$(echo "$s" | jget decommissionInfo.failed)" == true ]] && { echo failed; return; }
      [[ "$(echo "$s" | jget decommissionInfo.canceled)" == true ]] && { echo canceled; return; }
    fi
    sleep 1
  done
  echo timeout
}

# ---- everything an object can carry, captured for comparison ----
snapshot() { # node -> stdout
  local n="$1"
  cli "$n" s3api list-object-versions --bucket ver --output json |
    python3 -c 'import json,sys
d=json.load(sys.stdin)
for v in sorted(d.get("Versions",[]),key=lambda v:(v["Key"],v["VersionId"])): print("V",v["Key"],v["VersionId"],v["IsLatest"],v["Size"],v["ETag"])
for m in sorted(d.get("DeleteMarkers",[]),key=lambda v:(v["Key"],v["VersionId"])): print("D",m["Key"],m["VersionId"],m["IsLatest"])'
  cli "$n" s3api get-object-tagging --bucket ver --key tagged --output text | sort
  cli "$n" s3api get-object-retention --bucket locked --key held --output text
  cli "$n" s3api get-object-legal-hold --bucket locked --key legal --output text
  cli "$n" s3api get-bucket-versioning --bucket ver --output text
  cli "$n" s3api list-multipart-uploads --bucket plain --output json | python3 -c 'import json,sys
for u in json.load(sys.stdin).get("Uploads",[]): print("U",u["Key"],u["UploadId"])'
  cli "$n" s3api list-parts --bucket plain --key open-upload --upload-id "$(cat "$WORK/upload-id")" --output json |
    python3 -c 'import json,sys
for p in json.load(sys.stdin).get("Parts",[]): print("P",p["PartNumber"],p["Size"],p["ETag"])'
  local o
  for o in $(ls "$WORK/obj"); do
    if cli "$n" s3 cp --no-progress "s3://plain/$o" "$WORK/got" >/dev/null 2>&1; then echo "O $o $(md5 "$WORK/got")"; else echo "O $o missing"; fi
    rm -f "$WORK/got"
  done
}

load_data() { # node
  local n="$1" i
  mkdir -p "$WORK/obj"
  cli "$n" s3 mb s3://plain >/dev/null
  cli "$n" s3 mb s3://ver >/dev/null
  cli "$n" s3api put-bucket-versioning --bucket ver --versioning-configuration Status=Enabled >/dev/null
  cli "$n" s3api create-bucket --bucket locked --object-lock-enabled-for-bucket >/dev/null
  for i in $(seq 1 30); do
    head -c $((i * 3001 + 17)) /dev/urandom >"$WORK/obj/o$i"
    cli "$n" s3 cp --no-progress "$WORK/obj/o$i" "s3://plain/o$i" >/dev/null
  done
  head -c 9437191 /dev/urandom >"$WORK/obj/big"
  cli "$n" s3 cp --no-progress "$WORK/obj/big" s3://plain/big >/dev/null
  head -c 12000000 /dev/urandom >"$WORK/obj/multi"
  cli "$n" s3 cp --no-progress "$WORK/obj/multi" s3://plain/multi >/dev/null
  for i in 1 2 3; do echo "version $i" | cli "$n" s3 cp - s3://ver/doc >/dev/null; done
  echo gone | cli "$n" s3 cp - s3://ver/deleted >/dev/null
  cli "$n" s3 rm s3://ver/deleted >/dev/null
  echo tagged | cli "$n" s3 cp - s3://ver/tagged >/dev/null
  cli "$n" s3api put-object-tagging --bucket ver --key tagged --tagging 'TagSet=[{Key=team,Value=storage},{Key=tier,Value=hot}]' >/dev/null
  echo held | cli "$n" s3 cp - s3://locked/held >/dev/null
  cli "$n" s3api put-object-retention --bucket locked --key held --retention "Mode=GOVERNANCE,RetainUntilDate=$(date -u -d '+2 days' +%Y-%m-%dT%H:%M:%SZ)" >/dev/null
  echo legal | cli "$n" s3 cp - s3://locked/legal >/dev/null
  cli "$n" s3api put-object-legal-hold --bucket locked --key legal --legal-hold Status=ON >/dev/null
  cli "$n" s3api create-multipart-upload --bucket plain --key open-upload --query UploadId --output text >"$WORK/upload-id"
  head -c 5242880 /dev/urandom >"$WORK/part1"
  cli "$n" s3api upload-part --bucket plain --key open-upload --upload-id "$(cat "$WORK/upload-id")" --part-number 1 --body "$WORK/part1" >/dev/null
}

# ---- background traffic: PUT/GET/DELETE through one node, results checked later ----
traffic() { # node
  local n="$1" i=0 code k f
  mkdir -p "$WORK/tr"
  : >"$WORK/tr/put"; : >"$WORK/tr/del"; : >"$WORK/tr/err"
  while [[ ! -f "$WORK/tr/stop" ]]; do
    i=$((i + 1))
    f="$WORK/tr/o$i"
    head -c $((RANDOM * 4 + 1)) /dev/urandom >"$f"
    code=$(curl -s -o /dev/null -w '%{http_code}' "${sig[@]}" -T "$f" "$(ep "$n")/traffic/t$i" || true)
    if [[ "$code" == 200 ]]; then echo "t$i $(md5 "$f")" >>"$WORK/tr/put"; else echo "put t$i $code" >>"$WORK/tr/err"; fi
    code=$(curl -s -o /dev/null -w '%{http_code}' "${sig[@]}" -T "$f" "$(ep "$n")/tver/hot" || true)
    if [[ "$code" == 200 ]]; then md5 "$f" >"$WORK/tr/hot"; else echo "put hot $code" >>"$WORK/tr/err"; fi
    if ((i % 3 == 0)); then
      code=$(curl -s -o /dev/null -w '%{http_code}' "${sig[@]}" -X DELETE "$(ep "$n")/traffic/t$((i - 2))" || true)
      if [[ "$code" == 204 ]]; then echo "t$((i - 2))" >>"$WORK/tr/del"; else echo "del t$((i - 2)) $code" >>"$WORK/tr/err"; fi
    fi
    k="t$((RANDOM % i + 1))"
    if grep -q "^$k " "$WORK/tr/put" && ! grep -qx "$k" "$WORK/tr/del"; then
      code=$(curl -s -o "$WORK/tr/got" -w '%{http_code}' "${sig[@]}" "$(ep "$n")/traffic/$k" || true)
      if [[ "$code" != 200 || "$(md5 "$WORK/tr/got")" != "$(grep "^$k " "$WORK/tr/put" | cut -d' ' -f2)" ]]; then echo "get $k $code" >>"$WORK/tr/err"; fi
    fi
  done
}
verify_traffic() { # node -> number of mismatches
  local n="$1" bad=0 k sum code
  while read -r k sum; do
    if grep -qx "$k" "$WORK/tr/del"; then
      code=$(curl -s -o /dev/null -w '%{http_code}' "${sig[@]}" "$(ep "$n")/traffic/$k")
      [[ "$code" == 404 ]] || bad=$((bad + 1))
    else
      code=$(curl -s -o "$WORK/tr/got" -w '%{http_code}' "${sig[@]}" "$(ep "$n")/traffic/$k")
      [[ "$code" == 200 && "$(md5 "$WORK/tr/got")" == "$sum" ]] || bad=$((bad + 1))
    fi
  done <"$WORK/tr/put"
  curl -s -o "$WORK/tr/got" "${sig[@]}" "$(ep "$n")/tver/hot"
  [[ "$(md5 "$WORK/tr/got")" == "$(cat "$WORK/tr/hot")" ]] || bad=$((bad + 1))
  echo "$bad"
}

# ================= 1. two pools: decommission pool 1 =================
POOLS=(--data "${PA[@]}" --data "${PB[@]}")
start_all
aliases
load_data 1
snapshot 1 >"$WORK/before"
check "snapshot sees versions, markers, tags, lock, uploads" yes "$(grep -c '^[VDUP] ' "$WORK/before" | awk '{print ($1 >= 8) ? "yes" : "no"}')"
check "pool 1 holds data before" yes "$([[ $(keyfiles a) -gt 0 ]] && echo yes || echo no)"
CMD_A="${PA[*]}"
CMD_B="${PB[*]}"
list=$("$MC" admin decommission status --json z1)
check "status lists both pools" 2 "$(echo "$list" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)))' 2>/dev/null || true)"
check "pool 1 not scheduled" "0001-01-01T00:00:00Z" "$(decom 2 "$CMD_A" startTime)"
check "unknown pool refused" 1 "$("$MC" admin decommission start z1 "http://nowhere:9000/x" >/dev/null 2>&1 && echo 0 || echo 1)"

"$MC" admin decommission start z1 "$CMD_A" >/dev/null
check "decommission started" yes "$([[ "$(decom 3 "$CMD_A" startTime)" != 0001* ]] && echo yes || echo no)"
check "second start of another pool refused while draining" 1 "$("$MC" admin decommission start z1 "$CMD_B" >/dev/null 2>&1 && echo 0 || echo 1)"
check "rebalance refused while draining" 1 "$("$MC" admin rebalance start z1 >/dev/null 2>&1 && echo 0 || echo 1)"

# The node moving keys; traffic goes through another node.
W=0
for _ in $(seq 300); do
  for i in 1 2 3 4; do grep -q "pools: draining pool 1" "$WORK/n$i.log" && W=$i; done
  [[ "$W" != 0 ]] && break
  sleep 0.1
done
check "a node drains pool 1" yes "$([[ "$W" != 0 ]] && echo yes || echo no)"
T=$((W % 4 + 1))
cli 1 s3 mb s3://traffic >/dev/null
cli 1 s3 mb s3://tver >/dev/null
cli 1 s3api put-bucket-versioning --bucket tver --versioning-configuration Status=Enabled >/dev/null
traffic "$T" &
TPID=$!
sleep 3
# Cancel and restart once mid-way: canceled state is visible, then resumes.
"$MC" admin decommission cancel z2 "$CMD_A" >/dev/null
check "cancel shows canceled" true "$(decom 1 "$CMD_A" canceled)"
"$MC" admin decommission start z2 "$CMD_A" >/dev/null
check "restart after cancel" false "$(decom 1 "$CMD_A" canceled)"
for _ in $(seq 300); do
  [[ "$(decom "$T" "$CMD_A" objectsDecommissioned)" =~ ^[1-9] ]] && break
  sleep 0.2
done
check "progress persisted before the crash" yes "$([[ "$(decom "$T" "$CMD_A" objectsDecommissioned)" =~ ^[1-9] ]] && echo yes || echo no)"
W=0
for i in 1 2 3 4; do [[ $(grep -c "pools: draining pool 1" "$WORK/n$i.log") -gt 0 ]] && W=$i; done
[[ "$W" == "$T" || "$W" == 0 ]] && W=$((T % 4 + 1))
kill9 "$W"
sleep 2
start "$W"
wait_ready "$W" 120
r=$(wait_decom "$T" "$CMD_A" 400)
check "decommission completes after kill -9 of node $W" complete "$r"
touch "$WORK/tr/stop"
wait "$TPID" || true
TPID=0
check "traffic errors during decommission" 0 "$(wc -l <"$WORK/tr/err")"
[[ -s "$WORK/tr/err" ]] && head -n 5 "$WORK/tr/err"
check "traffic ran" yes "$([[ $(wc -l <"$WORK/tr/put") -gt 20 ]] && echo yes || echo no)"
check "objects moved reported" yes "$([[ "$(decom 1 "$CMD_A" objectsDecommissioned)" =~ ^[1-9] ]] && echo yes || echo no)"
check "bytes moved reported" yes "$([[ "$(decom 1 "$CMD_A" bytesDecommissioned)" =~ ^[1-9] ]] && echo yes || echo no)"
check "no failed objects" 0 "$(decom 1 "$CMD_A" objectsDecommissionedFailed)"
check "status table says complete" 1 "$("$MC" admin decommission status z1 | grep -c Complete || true)"
check "pool 1 drives hold no blobs" 0 "$(keyfiles a)"
check "resumed by a node after the crash" yes "$([[ $(cat "$WORK"/n*.log | grep -c 'pools: draining pool 1') -ge 2 ]] && echo yes || echo no)"
snapshot 2 >"$WORK/after"
check "all versions, markers, tags, lock, uploads, data intact" "" "$(diff "$WORK/before" "$WORK/after" || true)"
check "traffic data intact" 0 "$(verify_traffic 3)"
check "new writes avoid the retired pool" 200 "$(curl -s -o /dev/null -w '%{http_code}' "${sig[@]}" -T "$WORK/obj/o1" "$(ep 1)/plain/after-decom")"
check "pool 1 still empty" 0 "$(keyfiles a)"

# ---- restart without pool 1 ----
stop_all
POOLS=(--data "${PB[@]}")
start_all
check "cluster starts without the decommissioned pool" "200 200 200 200" "$(ready 1) $(ready 2) $(ready 3) $(ready 4)"
snapshot 4 >"$WORK/after2"
check "data intact after dropping pool 1" "" "$(diff "$WORK/before" "$WORK/after2" || true)"
check "traffic data intact after restart" 0 "$(verify_traffic 1)"
"$MC" admin user add z1 bob bob-secret-1234 >/dev/null
check "IAM (system records) moved and writable" 1 "$("$MC" admin user list --json z3 | grep -c '"accessKey":"bob"' || true)"
check "completing the open multipart upload" 0 "$(cli 2 s3api complete-multipart-upload --bucket plain --key open-upload --upload-id "$(cat "$WORK/upload-id")" \
  --multipart-upload "Parts=[{PartNumber=1,ETag=$(md5 "$WORK/part1")}]" >/dev/null 2>&1; echo $?)"
cli 3 s3 cp --no-progress s3://plain/open-upload "$WORK/got" >/dev/null
check "completed upload reads back" "$(md5 "$WORK/part1")" "$(md5 "$WORK/got")"
stop_all

# ---- a pool that was not decommissioned cannot be dropped ----
POOLS=(--data "${PA[@]}")
start 1
code=0
for _ in $(seq 300); do kill -0 "${PIDS[1]}" 2>/dev/null || break; sleep 0.1; done
wait "${PIDS[1]}" 2>/dev/null || code=$?
PIDS[1]=0
check "startup refuses a layout missing a live pool" yes "$([[ $code -ne 0 ]] && echo yes || echo no)"
check "and says why" 1 "$(grep -c 'missing from the endpoint list and was not decommissioned' "$WORK/n1.log" || true)"
rm -rf "$WORK"/n*/a* "$WORK"/n*/b* "$WORK/obj" "$WORK"/n*.log

# ================= 2. three pools: rebalance, then decommission the middle pool =================
read -r -a PC <<<"$(pool c)"
read -r -a PD <<<"$(pool d)"
read -r -a PE <<<"$(pool e)"
RATE=4
POOLS=(--data "${PC[@]}" --data "${PD[@]}")
start_all
aliases
load_data 2
snapshot 2 >"$WORK/before"
stop_all
POOLS=(--data "${PC[@]}" --data "${PD[@]}" --data "${PE[@]}")
start_all
check "appended pool starts empty" 0 "$(keyfiles e)"
check "rebalance status before any run" 1 "$("$MC" admin rebalance status z1 >/dev/null 2>&1 && echo 0 || echo 1)"
id=$("$MC" admin rebalance start --json z1 | jget id)
check "rebalance started with an id" yes "$([[ ${#id} -ge 32 ]] && echo yes || echo no)"
sleep 4
"$MC" admin rebalance stop z2 >/dev/null
st=$("$MC" admin rebalance status --json z3)
check "stopped rebalance reports Stopped" yes "$(echo "$st" | python3 -c 'import json,sys;d=json.load(sys.stdin);print("yes" if any(p["status"]=="Stopped" for p in d["pools"]) else "no")')"
check "throttled: partial progress only" yes "$([[ $(keyfiles e) -gt 0 ]] && echo yes || echo no)"
id2=$("$MC" admin rebalance start --json z4 | jget id)
check "rebalance restarts" yes "$([[ -n "$id2" && "$id2" != "$id" ]] && echo yes || echo no)"
done_=no
for _ in $(seq 300); do
  st=$("$MC" admin rebalance status --json z1 2>/dev/null || true)
  if echo "$st" | python3 -c 'import json,sys;d=json.load(sys.stdin);s=[p["status"] for p in d["pools"] if p["status"]];sys.exit(0 if s and all(x=="Completed" for x in s) else 1)' 2>/dev/null; then done_=yes; break; fi
  sleep 1
done
check "rebalance completes" yes "$done_"
echo "$st" | python3 -c 'import json,sys;[print("  pool",p["id"],"used %.6f"%p["used"],p["status"],p["progress"]["bytes"]) for p in json.load(sys.stdin)["pools"]]'
check "rebalance moved data into the new pool" yes "$([[ $(keyfiles e) -gt 10 ]] && echo yes || echo no)"
check "rebalance reports moved bytes" yes "$(echo "$st" | python3 -c 'import json,sys;print("yes" if sum(p["progress"]["bytes"] for p in json.load(sys.stdin)["pools"])>0 else "no")')"
check "pools within threshold" yes "$(echo "$st" | python3 -c 'import json,sys
u=[p["used"] for p in json.load(sys.stdin)["pools"]]
g=sum(u)/len(u)
print("yes" if max(u) <= g*1.6 and min(u) > 0 else "no")')"
snapshot 3 >"$WORK/after"
check "data intact after rebalance" "" "$(diff "$WORK/before" "$WORK/after" || true)"

CMD_D="${PD[*]}"
"$MC" admin decommission start z4 "$CMD_D" >/dev/null
check "middle pool decommission completes" complete "$(wait_decom 1 "$CMD_D" 300)"
check "middle pool drives hold no blobs" 0 "$(keyfiles d)"
info=$("$MC" admin decommission status z2)
check "status table: complete middle, active others" "Active Complete Active" "$(echo "$info" | grep -o 'Active\|Complete' | tr '\n' ' ' | sed 's/ $//')"
stop_all
POOLS=(--data "${PC[@]}" --data "${PE[@]}")
start_all
snapshot 1 >"$WORK/after2"
check "data intact without the middle pool" "" "$(diff "$WORK/before" "$WORK/after2" || true)"
head -c 77777 /dev/urandom >"$WORK/late"
check "writes after dropping the middle pool" 200 "$(curl -s -o /dev/null -w '%{http_code}' "${sig[@]}" -T "$WORK/late" "$(ep 2)/plain/late")"
curl -s -o "$WORK/got" "${sig[@]}" "$(ep 3)/plain/late"
check "and read back" "$(md5 "$WORK/late")" "$(md5 "$WORK/got")"
stop_all

echo "pools: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
