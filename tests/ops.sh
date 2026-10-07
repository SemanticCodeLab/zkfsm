#!/usr/bin/env bash
# Admin observability and control with mc: server info, background heal status,
# heal of a bucket after a shard is deleted, scanner metrics, top locks, and service
# restart/stop, on a 4-node cluster and on a single node.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
MC="${MC:-$(command -v mc || true)}"
if [[ -z "$MC" ]] || ! "$MC" --version 2>/dev/null | grep -q RELEASE; then echo "ops.sh needs the MinIO client (set MC)"; exit 1; fi
PIDS=(0 0 0 0 0)
SPID=0
cleanup() {
  for p in "${PIDS[@]}" "$SPID"; do [[ "$p" != 0 ]] && kill -9 "$p" 2>/dev/null || true; done
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
# py EXPR: evaluates EXPR with `docs` = every JSON document read from stdin.
py() {
  python3 -c '
import json, sys
def j(*x): return " ".join(str(v) for v in x)
src = sys.stdin.read(); dec = json.JSONDecoder(); docs = []; i = 0
while i < len(src):
    while i < len(src) and src[i].isspace(): i += 1
    if i >= len(src): break
    d, i = dec.raw_decode(src, i); docs.append(d)
*pre, last = sys.argv[1].split("; ")
exec("\n".join(pre))
print(eval(last))' "$1"
}

AK="opsadmin"
SK="ops-secret-key-0123"
export MC_CONFIG_DIR="$WORK/mc"
(cd "$ROOT" && zig build -Doptimize=ReleaseSafe)
BIN="$ROOT/zig-out/bin/zkfsm"
sig=(--aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK")

PORT=(0 "$(freeport)" "$(freeport)" "$(freeport)" "$(freeport)")
EPS=()
for i in 1 2 3 4; do EPS+=("http://127.0.0.1:${PORT[$i]}$WORK/n$i/d{1...4}"); done
start() { # node
  local i="$1"
  ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$BIN" --data "${EPS[@]}" --listen "127.0.0.1:${PORT[$i]}" \
    --node-address "127.0.0.1:${PORT[$i]}" --protection EC:4+2 --scan-interval 3 >>"$WORK/n$i.log" 2>&1 &
  PIDS[$i]=$!
}
ep() { echo "http://127.0.0.1:${PORT[$1]}"; }
ready() { curl -s -o /dev/null -w '%{http_code}' "$(ep "$1")/health/ready" || true; }
wait_ready() { # node [seconds]
  for _ in $(seq $((${2:-60} * 10))); do [[ "$(ready "$1")" == 200 ]] && return 0; sleep 0.1; done
  echo "node $1 not ready:"; tail -n 30 "$WORK/n$1.log"; exit 1
}
exited() { # pid seconds -> yes|no
  for _ in $(seq $(($2 * 10))); do kill -0 "$1" 2>/dev/null || { echo yes; return; }; sleep 0.1; done
  echo no
}

for i in 1 2 3 4; do start "$i"; done
for i in 1 2 3 4; do wait_ready "$i" 120; done
for i in 1 2 3 4; do "$MC" alias set "z$i" "$(ep "$i")" "$AK" "$SK" >/dev/null; done
"$MC" mb z1/ops >/dev/null
for k in 1 2 3 4 5 6; do head -c $((k * 30000 + 7)) /dev/urandom >"$WORK/o$k"; "$MC" cp -q "$WORK/o$k" "z$(((k % 4) + 1))/ops/dir/o$k" >/dev/null; done

# ---- mc admin info ----
info=$("$MC" admin info --json z2)
check "info status" success "$(py 'docs[0]["status"]' <<<"$info")"
check "info mode" online "$(py 'docs[0]["info"]["mode"]' <<<"$info")"
check "info four servers online" "4 4" "$(py 'j(len(docs[0]["info"]["servers"]), sum(s["state"]=="online" for s in docs[0]["info"]["servers"]))' <<<"$info")"
check "info drives online/offline" "16 0" "$(py 'j(docs[0]["info"]["backend"]["onlineDisks"], docs[0]["info"]["backend"]["offlineDisks"])' <<<"$info")"
check "info parity and sets" "2 [1] [16]" "$(py 'b=docs[0]["info"]["backend"]; j(b["standardSCParity"], b["totalSets"], b["totalDrivesPerSet"])' <<<"$info")"
check "info buckets and objects" "1 6" "$(py 'j(docs[0]["info"]["buckets"]["count"], docs[0]["info"]["objects"]["count"])' <<<"$info")"
check "info usage counts object bytes" yes "$(py '"yes" if docs[0]["info"]["usage"]["size"] >= 630042 else "no"' <<<"$info")"
dep=$(py 'docs[0]["info"]["deploymentID"]' <<<"$info")
check "deployment id is a uuid" 1 "$(grep -cE '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' <<<"$dep")"
check "same deployment id via node 4" "$dep" "$("$MC" admin info --json z4 | py 'docs[0]["info"]["deploymentID"]')"
check "every drive reports capacity and its slot" 16 "$(py 'sum(1 for s in docs[0]["info"]["servers"] for d in s["drives"] if d["state"]=="ok" and d.get("totalspace",0)>0 and d["pool_index"]==0 and d["set_index"]==0)' <<<"$info")"
check "four drives per server" "4 4 4 4" "$(py '" ".join(str(len(s["drives"])) for s in docs[0]["info"]["servers"])' <<<"$info")"
check "servers report uptime and version" yes "$(py '"yes" if all(s.get("uptime",0)>=1 and s["version"] for s in docs[0]["info"]["servers"]) else "no"' <<<"$info")"
check "pool erasure-set info" yes "$(py '"yes" if docs[0]["info"]["pools"]["0"]["0"]["rawCapacity"]>0 and docs[0]["info"]["pools"]["0"]["0"]["objectsCount"]>=6 else "no"' <<<"$info")"
raw=$(curl -s "${sig[@]}" "$(ep 1)/minio/admin/v3/info")
check "pool status exposed" active "$(py 'docs[0]["poolsStatus"][0]["status"]' <<<"$raw")"
text=$("$MC" admin info z1)
check "info text summary" 1 "$(grep -c '16 drives online, 0 drives offline, EC:2' <<<"$text")"

# ---- background heal status ----
bg=$("$MC" admin heal --json z1)
check "background heal status" success "$(py 'docs[0]["status"]' <<<"$bg")"
check "heal status lists the set with its drives" "1 16" "$(py 'j(len(docs[0]["HealInfo"]["sets"]), len(docs[0]["HealInfo"]["sets"][0]["disks"]))' <<<"$bg")"
check "heal status parity" 2 "$(py 'docs[0]["HealInfo"]["sc_parity"]["STANDARD"]' <<<"$bg")"
"$MC" admin heal z1 >/dev/null
check "background heal text view" 0 $?

# ---- heal -r repairs a deleted shard ----
victim=$(find "$WORK"/n2/d*/data -type f | head -n 1)
rm -f "$victim"
check "shard deleted" no "$([[ -f "$victim" ]] && echo yes || echo no)"
out=$("$MC" admin heal -r --json z3/ops)
check "heal reports the damaged object" 1 "$(py 'sum(1 for d in docs if d.get("type")=="object" and d["before"]["missing"]==1 and d["after"]["missing"]==0 and d["after"]["online"]==6)' <<<"$out")"
check "heal items colour without errors" 0 "$(py 'sum(1 for d in docs if d.get("error"))' <<<"$out")"
check "heal summary" "6 1" "$(py 's=[d for d in docs if d.get("type")=="summary"][0]; j(s["objects_scanned"], s["objects_healed"])' <<<"$out")"
check "shard restored on disk" yes "$([[ -f "$victim" ]] && echo yes || echo no)"
"$MC" cat z1/ops/dir/o3 >"$WORK/got"
check "object intact after heal" "$(md5sum <"$WORK/o3")" "$(md5sum <"$WORK/got")"
out=$("$MC" admin heal -r --dry-run --json z1/ops/dir/o1)
check "dry-run heal of a prefix" 1 "$(py 'sum(1 for d in docs if d.get("type")=="object")' <<<"$out")"

# ---- scanner status ----
sc=""
for _ in $(seq 30); do
  sc=$("$MC" admin scanner status --json -n 1 z1)
  [[ "$(py 'len(docs[0]["aggregated"]["scanner"]["cycle_complete_times"])' <<<"$sc")" -ge 1 ]] && break
  sleep 1
done
check "scanner reports completed cycles" yes "$(py '"yes" if docs[0]["aggregated"]["scanner"]["current_cycle"]>=1 and docs[0]["aggregated"]["scanner"]["cycle_complete_times"] else "no"' <<<"$sc")"
check "scanner counts scanned entries" yes "$(py '"yes" if docs[0]["aggregated"]["scanner"]["life_time_ops"]["ScanObject"]>0 else "no"' <<<"$sc")"
check "scanner hosts" 4 "$(py 'len(docs[0]["hosts"])' <<<"$sc")"
two=$("$MC" admin scanner status --json -n 2 --interval 1 z2)
check "scanner streams n samples" 2 "$(py 'len(docs)' <<<"$two")"

# ---- top locks ----
check "top locks needs registration without --dev" 1 "$("$MC" support top locks --json z1 >/dev/null 2>&1 && echo 0 || echo 1)"
check "top locks with --dev" 0 "$("$MC" support top locks --dev --json z1 >/dev/null 2>&1 && echo 0 || echo 1)"
(for r in $(seq 400); do head -c 100 /dev/zero | curl -s -o /dev/null "${sig[@]}" -T - "$(ep $(((r % 4) + 1)))/ops/hot" & [[ $((r % 8)) == 0 ]] && wait; done; wait) &
LOADER=$!
seen=no
for _ in $(seq 300); do
  l=$(curl -s "${sig[@]}" "$(ep 1)/minio/admin/v3/top/locks?count=10&stale=true")
  if [[ "$(py 'sum(1 for e in docs[0] if e["resource"].startswith("obj") and e["serverlist"] and e["owner"])' <<<"$l")" -ge 1 ]]; then seen=yes; break; fi
done
wait "$LOADER" 2>/dev/null || true
check "top locks shows a held object lock with owner" yes "$seen"

# ---- one node down ----
kill -9 "${PIDS[3]}"; wait "${PIDS[3]}" 2>/dev/null || true; PIDS[3]=0
sleep 3
info=$("$MC" admin info --json z1)
check "info shows the offline server" "3 1" "$(py 'j(sum(s["state"]=="online" for s in docs[0]["info"]["servers"]), sum(s["state"]=="offline" for s in docs[0]["info"]["servers"]))' <<<"$info")"
check "info shows its drives offline" "12 4" "$(py 'j(docs[0]["info"]["backend"]["onlineDisks"], docs[0]["info"]["backend"]["offlineDisks"])' <<<"$info")"
check "heal status lists the offline node" 1 "$("$MC" admin heal --json z1 | py 'len(docs[0]["HealInfo"]["offline_nodes"])')"
start 3
wait_ready 3 60

# ---- service restart: every node re-executes in place ----
up_before=$("$MC" admin info --json z1 | py 'min(s.get("uptime",0) for s in docs[0]["info"]["servers"])')
sleep 2
res=$("$MC" admin service restart --json z1)
check "restart answered for four nodes" "success 4 0" "$(py 'j(docs[0]["status"], len(docs[0]["result"]["results"]), sum(1 for r in docs[0]["result"]["results"] if r.get("err")))' <<<"$res")"
sleep 1
for i in 1 2 3 4; do wait_ready "$i" 60; done
alive=0
for i in 1 2 3 4; do kill -0 "${PIDS[$i]}" 2>/dev/null && alive=$((alive + 1)); done
check "same processes after restart" 4 "$alive"
info=$("$MC" admin info --json z1)
check "uptime reset by restart" yes "$(py '"yes" if max(s.get("uptime",0) for s in docs[0]["info"]["servers"]) < '"$((up_before + 2))"' else "no"' <<<"$info")"
check "restart logged on every node" 4 "$(grep -l 'restarting' "$WORK"/n*.log | wc -l)"
"$MC" cat z2/ops/dir/o5 >"$WORK/got"
check "data readable after restart" "$(md5sum <"$WORK/o5")" "$(md5sum <"$WORK/got")"
dry=""
for _ in 1 2 3; do dry=$("$MC" admin service restart --dry-run --json z1 2>&1 || true); grep -q dryRun <<<"$dry" && break; echo "     dry-run retry: $dry"; sleep 1; done
check "dry-run restart" "true" "$(py 'str(docs[0]["result"]["dryRun"]).lower()' <<<"$dry")"

# ---- service stop: every node exits ----
res=$("$MC" admin service stop --json z2)
check "stop answered" success "$(py 'docs[0]["status"]' <<<"$res")"
gone=0
for i in 1 2 3 4; do [[ "$(exited "${PIDS[$i]}" 30)" == yes ]] && { gone=$((gone + 1)); PIDS[$i]=0; }; done
check "every node stopped" 4 "$gone"

# ---- single node, one drive ----
SP="$(freeport)"
SEP="http://127.0.0.1:$SP"
mkdir -p "$WORK/single"
sstart() {
  ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$BIN" --data "$WORK/single" --listen "127.0.0.1:$SP" --scan-interval 2 >>"$WORK/single.log" 2>&1 &
  SPID=$!
  for _ in $(seq 100); do [[ "$(curl -s -o /dev/null -w '%{http_code}' "$SEP/health/ready")" == 200 ]] && return 0; sleep 0.1; done
  echo "single node not ready"; tail -n 20 "$WORK/single.log"; exit 1
}
sstart
"$MC" alias set s "$SEP" "$AK" "$SK" >/dev/null
"$MC" mb s/one >/dev/null
"$MC" cp -q "$WORK/o1" s/one/a >/dev/null
"$MC" cp -q "$WORK/o2" s/one/b >/dev/null
info=$("$MC" admin info --json s)
check "single info" "online 1 1 0" "$(py 'i=docs[0]["info"]; j(i["mode"], len(i["servers"]), i["backend"]["onlineDisks"], i["backend"]["standardSCParity"])' <<<"$info")"
check "single info objects" "1 2" "$(py 'j(docs[0]["info"]["buckets"]["count"], docs[0]["info"]["objects"]["count"])' <<<"$info")"
check "single info text" 0 "$("$MC" admin info s >/dev/null 2>&1 && echo 0 || echo 1)"
out=$("$MC" admin heal -r --json s/one)
check "single heal items are green" "2 0" "$(py 'j(sum(1 for d in docs if d.get("type")=="object" and d["after"]["color"]=="green"), sum(1 for d in docs if d.get("error")))' <<<"$out")"
check "single background heal" success "$("$MC" admin heal --json s | py 'docs[0]["status"]')"
sleep 3
check "single scanner cycles" yes "$("$MC" admin scanner status --json -n 1 s | py '"yes" if docs[0]["aggregated"]["scanner"]["current_cycle"]>=1 else "no"')"
check "single top locks empty" "[]" "$(curl -s "${sig[@]}" "$SEP/minio/admin/v3/top/locks")"
res=$("$MC" admin service restart --json s)
check "single restart" "success 1" "$(py 'j(docs[0]["status"], len(docs[0]["result"]["results"]))' <<<"$res")"
sleep 1
for _ in $(seq 100); do [[ "$(curl -s -o /dev/null -w '%{http_code}' "$SEP/health/ready")" == 200 ]] && break; sleep 0.1; done
check "single node back after restart" yes "$(kill -0 "$SPID" 2>/dev/null && "$MC" cat s/one/a | cmp -s - "$WORK/o1" && echo yes || echo no)"
"$MC" admin service stop --json s >/dev/null
check "single node stopped" yes "$(exited "$SPID" 30)"
SPID=0

echo "ops: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
