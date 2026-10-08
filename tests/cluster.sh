#!/usr/bin/env bash
# Multi-node cluster: 4 local nodes x 4 drives, EC:4+2 sets spanning nodes.
# Identical views through every node (S3 CLI and mc), IAM propagation, node loss with
# failover and healing, quorum loss, concurrent writers, pool expansion, and TLS.
set -euo pipefail
S3CLI_BIN="${S3CLI_BIN:-aws}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
MC="${MC:-$(command -v mc || true)}"
PIDS=(0 0 0 0 0)
cleanup() {
  for p in "${PIDS[@]}"; do [[ "$p" != 0 ]] && kill -9 "$p" 2>/dev/null || true; done
  [[ -n "${KEEP:-}" ]] || rm -rf "$WORK"
}
trap cleanup EXIT

pass=0
fail=0
check() { # name expected actual
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); echo "ok   $1"
  else fail=$((fail + 1)); echo "FAIL $1: expected [$2] got [$3]"; fi
}
freeport() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }

AK="clusteradmin"
SK="cluster-secret-key-0123"
export AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_DEFAULT_REGION=us-east-1 AWS_PAGER=""
export AWS_CONFIG_FILE="$WORK/s3cli.conf" AWS_SHARED_CREDENTIALS_FILE="$WORK/s3cli.creds"
printf '[default]\ns3 =\n  addressing_style = path\n' >"$AWS_CONFIG_FILE"
export MC_CONFIG_DIR="$WORK/mc"

(cd "$ROOT" && zig build -Doptimize=ReleaseSafe)
BIN="$ROOT/zig-out/bin/zkfsm"

PORT=(0 "$(freeport)" "$(freeport)" "$(freeport)" "$(freeport)")
POOL1=()
POOL2=()
for i in 1 2 3 4; do
  POOL1+=("http://127.0.0.1:${PORT[$i]}$WORK/n$i/d{1...4}")
  POOL2+=("http://127.0.0.1:${PORT[$i]}$WORK/n$i/p{1...4}")
done
POOLS=(--data "${POOL1[@]}")

start() { # node
  local i="$1"
  ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$BIN" "${POOLS[@]}" --listen "127.0.0.1:${PORT[$i]}" \
    --node-address "127.0.0.1:${PORT[$i]}" --protection EC:4+2 --scan-interval 20 >>"$WORK/n$i.log" 2>&1 &
  PIDS[$i]=$!
}
ready() { curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT[$1]}/health/ready"; }
wait_ready() { # node [seconds]
  for _ in $(seq $((${2:-60} * 10))); do [[ "$(ready "$1")" == 200 ]] && return 0; sleep 0.1; done
  echo "node $1 not ready:"; tail -n 30 "$WORK/n$1.log"; exit 1
}
ep() { echo "http://127.0.0.1:${PORT[$1]}"; }
cli() { local i="$1"; shift; "$S3CLI_BIN" --endpoint-url "$(ep "$i")" "$@"; }
sig=(--aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK")
cput() { curl -s -o /dev/null -w '%{http_code}' "${sig[@]}" -T "$3" "$(ep "$1")/clu/$2"; }
cget() { curl -s -o "$3" -w '%{http_code}' "${sig[@]}" "$(ep "$1")/clu/$2"; }
md5() { md5sum "$1" | cut -d' ' -f1; }
kill9() { kill -9 "${PIDS[$1]}" 2>/dev/null || true; wait "${PIDS[$1]}" 2>/dev/null || true; PIDS[$1]=0; }

# Every live data blob (k=4 or more shards) has all six shards. Fewer than four
# shards are leftovers of a delete a node missed; heal purges them after a grace.
redundant() { # expected blob count
  local counts
  counts=$(find "$WORK"/n*/[dp]* -path '*/data/*' -type f -printf '%f\n' | sort | uniq -c | awk '$1 >= 4 {print $1}' | sort | uniq -c | awk '{printf "%s:%s ", $2, $1}')
  [[ "$counts" == "6:$1 " ]]
}
wait_redundant() { # expected blob count, seconds
  for _ in $(seq "$2"); do redundant "$1" && return 0; sleep 1; done
  echo "     want 6:$1; shards per blob (count:blobs):" \
    "$(find "$WORK"/n*/[dp]* -path '*/data/*' -type f -printf '%f\n' | sort | uniq -c | awk '{print $1}' | sort | uniq -c | awk '{printf "%s:%s ", $2, $1}')"
  return 1
}

mkdir -p "$WORK/obj"
for i in 1 2 3 4; do start "$i"; done
for i in 1 2 3 4; do wait_ready "$i" 120; done
check "four nodes ready" "200 200 200 200" "$(ready 1) $(ready 2) $(ready 3) $(ready 4)"

# ---- identical views through every node ----
cli 1 s3 mb s3://clu >/dev/null
for n in 1 2 3 4; do head -c $((n * 70000 + 13)) /dev/urandom >"$WORK/obj/cli$n"; cli "$n" s3 cp --no-progress "$WORK/obj/cli$n" "s3://clu/cli$n" >/dev/null; done
head -c 12000000 /dev/urandom >"$WORK/obj/multi"
cli 2 s3 cp --no-progress "$WORK/obj/multi" s3://clu/multi >/dev/null
if [[ -n "$MC" ]]; then
  for i in 1 2 3 4; do "$MC" alias set "z$i" "$(ep "$i")" "$AK" "$SK" >/dev/null; done
  head -c 99999 /dev/urandom >"$WORK/obj/mc1"
  "$MC" cp -q "$WORK/obj/mc1" z3/clu/mc1 >/dev/null
fi
OBJS=$(ls "$WORK/obj")
listing() { cli "$1" s3 ls --recursive s3://clu/ | awk '{print $3, $4}' | sort; }
check "s3 cli listings identical" "$(listing 1)" "$(listing 2)"
check "s3 cli listings identical 3" "$(listing 1)" "$(listing 3)"
check "s3 cli listings identical 4" "$(listing 1)" "$(listing 4)"
if [[ -n "$MC" ]]; then
  mcl() { "$MC" ls --recursive "z$1/clu" | awk '{print $NF}' | sort; }
  check "mc listings identical" "$(mcl 1)" "$(mcl 4)"
fi
bad=0
for i in 1 2 3 4; do for o in $OBJS; do
  cli "$i" s3 cp --no-progress "s3://clu/$o" "$WORK/got" >/dev/null
  [[ "$(md5 "$WORK/got")" == "$(md5 "$WORK/obj/$o")" ]] || bad=$((bad + 1))
done; done
check "every object reads back through every node" 0 "$bad"

# ---- overwrite and delete during a slow cross-node GET: the read ends on its bytes ----
head -c 48000000 /dev/urandom >"$WORK/big1"
head -c 1000 /dev/urandom >"$WORK/big2"
check "put a large object" 200 "$(cput 1 big "$WORK/big1")"
curl -s -o "$WORK/bigread" -w '%{http_code}' --limit-rate 3M "${sig[@]}" "$(ep 3)/clu/big" >"$WORK/bigcode" &
gp=$!
sleep 2
check "overwrite during the read" 200 "$(cput 2 big "$WORK/big2")"
# Past the deferred-deletion grace: only the read leases keep the old shards readable.
sleep 12
check "delete during the read" 204 "$(curl -s -o /dev/null -w '%{http_code}' "${sig[@]}" -X DELETE "$(ep 4)/clu/big")"
wait "$gp" || true
check "slow cross-node GET completes" 200 "$(cat "$WORK/bigcode")"
check "with the bytes it started on" "$(md5 "$WORK/big1")" "$(md5 "$WORK/bigread")"
check "overwritten object is gone" 404 "$(cget 1 big "$WORK/got")"
rm -f "$WORK/big1" "$WORK/big2" "$WORK/bigread"

# ---- S3 load cannot starve internal RPC: node 1's S3 workers are all held ----
# 300 keep-alive clients pin node 1's 256 S3 workers; peers still reach it over RPC.
python3 - "${PORT[1]}" >"$WORK/hog.log" 2>&1 <<'EOF' &
import socket, sys, time
port = int(sys.argv[1])
socks = []
for _ in range(300):
    s = socket.create_connection(("127.0.0.1", port))
    s.sendall(b"GET /health/live HTTP/1.1\r\nhost: x\r\n\r\n")
    socks.append(s)
print("open", flush=True)
time.sleep(20)
EOF
hog=$!
for _ in $(seq 100); do grep -q open "$WORK/hog.log" && break; sleep 0.1; done
sleep 1
check "node 1 S3 workers saturated" 000 "$(curl -s -m 3 -o /dev/null -w '%{http_code}' "$(ep 1)/health/live" || true)"
off0=$(grep -c "127.0.0.1:${PORT[1]} is offline" "$WORK/n2.log" || true)
n1a=$(find "$WORK"/n1/d* -path '*/data/*' -type f | wc -l)
for k in 1 2 3 4 5 6; do
  head -c $((k * 1000 + 3)) /dev/urandom >"$WORK/obj/sat$k"
  [[ "$(cput 2 "sat$k" "$WORK/obj/sat$k")" == 200 ]] || echo "put sat$k failed"
done
n1b=$(find "$WORK"/n1/d* -path '*/data/*' -type f | wc -l)
check "node 1 took its shards of writes made meanwhile" yes "$([[ $((n1b - n1a)) -ge 6 ]] && echo yes || echo no)"
cget 2 sat3 "$WORK/got" >/dev/null
check "and reads through node 2 work" "$(md5 "$WORK/obj/sat3")" "$(md5 "$WORK/got")"
check "node 1 stayed online for its peers" "$off0" "$(grep -c "127.0.0.1:${PORT[1]} is offline" "$WORK/n2.log" || true)"
kill "$hog" 2>/dev/null || true
wait "$hog" 2>/dev/null || true
OBJS=$(ls "$WORK/obj")

# ---- IAM: a user added on node 1 authenticates on node 2 ----
if [[ -n "$MC" ]]; then
  "$MC" admin user add z1 alice alice-secret-123 >/dev/null
  "$MC" admin policy attach z1 readwrite --user alice >/dev/null
  "$MC" alias set a2 "$(ep 2)" alice alice-secret-123 >/dev/null
  t0=$(date +%s)
  ok=no
  for _ in $(seq 100); do "$MC" ls a2/clu >/dev/null 2>&1 && { ok=yes; break; }; sleep 0.1; done
  check "user added via node 1 works on node 2" yes "$ok"
  check "within bounded time (<= 10 s)" yes "$([[ $(($(date +%s) - t0)) -le 10 ]] && echo yes || echo no)"
  check "user listed on node 4" 1 "$("$MC" admin user list --json z4 | grep -c '"accessKey":"alice"')"
fi

# ---- one node down: service continues through the others ----
head -c 4242 /dev/urandom >"$WORK/gone"
check "write an object to delete later" 200 "$(cput 1 gone "$WORK/gone")"
kill9 3
sleep 2
check "ready while one node is down" "200 200 200" "$(ready 1) $(ready 2) $(ready 4)"
bad=0
for i in 1 2 4; do for o in $OBJS; do
  cli "$i" s3 cp --no-progress "s3://clu/$o" "$WORK/got" >/dev/null 2>&1 || true
  [[ -f "$WORK/got" && "$(md5 "$WORK/got")" == "$(md5 "$WORK/obj/$o")" ]] || bad=$((bad + 1))
  rm -f "$WORK/got"
done; done
check "reads with one node down" 0 "$bad"
for n in 1 2 4; do
  head -c $((n * 5000 + 7)) /dev/urandom >"$WORK/obj/down$n"
  check "write via node $n with a node down" 200 "$(cput "$n" "down$n" "$WORK/obj/down$n")"
done
check "delete with a node down" 204 "$(curl -s -o /dev/null -w '%{http_code}' "${sig[@]}" -X DELETE "$(ep 2)/clu/gone")"
OBJS=$(ls "$WORK/obj")
check "new objects listed via node 1" 3 "$(cli 1 s3 ls s3://clu/ | grep -c ' down')"

# ---- the node returns and healing restores full redundancy ----
start 3
wait_ready 3 60
NOBJ=$(echo "$OBJS" | wc -w)
if wait_redundant "$NOBJ" 90; then r=yes; else r=no; fi
check "heal restored all shards of $NOBJ objects" yes "$r"
# The key index comes back from node 3's snapshot plus the peers' journals; no node
# rebuilds it from the records.
check "returning node resumed its key index from snapshot and journals" 1 "$(grep -c 'key index loaded from snapshot' "$WORK/n3.log" || true)"
check "no peer rebuilt its key index" 0 "$(cat "$WORK"/n[124].log | grep -c 'rebuilding the key index' || true)"
check "returning node lists like the others" "$(listing 1)" "$(listing 3)"
cli 3 s3 cp --no-progress s3://clu/down2 "$WORK/got" >/dev/null
check "object written while node 3 was down reads via node 3" "$(md5 "$WORK/obj/down2")" "$(md5 "$WORK/got")"
check "object deleted while node 3 was down stays deleted" 404 "$(cget 3 gone "$WORK/got")"
check "and is not listed via node 3" 0 "$(cli 3 s3 ls s3://clu/gone | grep -c gone || true)"

# ---- two nodes down: quorum lost ----
for k in $(seq 1 40); do
  head -c $((k * 311 + 1)) /dev/urandom >"$WORK/obj/q$k"
  n=$(((k % 4) + 1))
  [[ "$(cput "$n" "q$k" "$WORK/obj/q$k")" == 200 ]] || echo "put q$k failed"
done
kill9 3
kill9 4
sleep 2
check "ready turns 503 without quorum" "503 503" "$(ready 1) $(ready 2)"
okr=0
wrong=0
unavail=0
for k in $(seq 1 40); do
  code=$(cget 1 "q$k" "$WORK/got")
  if [[ "$code" == 200 ]]; then
    if [[ "$(md5 "$WORK/got")" == "$(md5 "$WORK/obj/q$k")" ]]; then okr=$((okr + 1)); else wrong=$((wrong + 1)); fi
  elif [[ "$code" == 503 ]]; then unavail=$((unavail + 1)); else wrong=$((wrong + 1)); fi
done
echo "     two nodes down: $okr readable, $unavail unavailable (503)"
check "reads never return wrong data" 0 "$wrong"
check "reads still work where shards suffice" yes "$([[ $okr -gt 0 ]] && echo yes || echo no)"
head -c 1000 /dev/urandom >"$WORK/nq"
out=$(cli 1 s3 cp --no-progress "$WORK/nq" s3://clu/nq 2>&1 || true)
check "write fails with a clear quorum error" 1 "$(echo "$out" | grep -c 'WriteQuorumUnavailable')"
check "write refused with 503" 503 "$(cput 2 nq "$WORK/nq")"
start 3
start 4
for i in 1 2 3 4; do wait_ready "$i" 60; done
OBJS=$(ls "$WORK/obj")
NOBJ=$(echo "$OBJS" | wc -w)
if wait_redundant "$NOBJ" 120; then r=yes; else r=no; fi
check "heal after quorum returns" yes "$r"

# ---- concurrent writers to one key through different nodes ----
for k in $(seq 1 16); do head -c $((20000 + k * 100)) /dev/urandom >"$WORK/hot$k"; done
jobs_=()
for k in $(seq 1 16); do cput $(((k % 4) + 1)) hot "$WORK/hot$k" >/dev/null & jobs_+=($!); done
for k in $(seq 1 32); do echo "distinct $k" >"$WORK/par$k"; cput $(((k % 4) + 1)) "par$k" "$WORK/par$k" >/dev/null & jobs_+=($!); done
wait "${jobs_[@]}"
sums=$(for k in $(seq 1 16); do md5 "$WORK/hot$k"; done)
seen=""
for i in 1 2 3 4; do
  cget "$i" hot "$WORK/got" >/dev/null
  m=$(md5 "$WORK/got")
  check "hot key via node $i is one whole version" 1 "$(echo "$sums" | grep -c "$m")"
  seen="$seen$m"
done
check "all nodes agree on the hot key" "$(printf '%s' "${seen:0:32}" | sed 's/.*/&&&&/')" "$seen"
for i in 1 2 3 4; do
  check "hot key listed once via node $i" 1 "$(cli "$i" s3 ls s3://clu/hot | grep -c ' hot$')"
  check "32 parallel keys listed via node $i" 32 "$(cli "$i" s3 ls s3://clu/par | grep -c ' par')"
done

# ---- a replaced node: its drives come back empty and are rebuilt ----
kill9 2
rm -rf "$WORK"/n2/d*
start 2
wait_ready 2 60
if wait_redundant $((NOBJ + 33)) 120; then r=yes; else r=no; fi
check "replaced node's drives rebuilt" yes "$r"
cli 2 s3 cp --no-progress s3://clu/multi "$WORK/got" >/dev/null
check "replaced node serves reads" "$(md5 "$WORK/obj/multi")" "$(md5 "$WORK/got")"
check "replaced node lists the bucket" "$(listing 1)" "$(listing 2)"

# ---- restart with a second pool appended ----
for i in 1 2 3 4; do kill "${PIDS[$i]}"; done
for i in 1 2 3 4; do wait "${PIDS[$i]}" 2>/dev/null || true; PIDS[$i]=0; done
POOLS=(--data "${POOL1[@]}" --data "${POOL2[@]}")
for i in 1 2 3 4; do start "$i"; done
for i in 1 2 3 4; do wait_ready "$i" 120; done
before=$(find "$WORK"/n*/d* -path '*/data/*' -type f | wc -l)
for n in 1 2 3 4; do
  head -c $((n * 9000 + 5)) /dev/urandom >"$WORK/obj/pool$n"
  check "write after expansion via node $n" 200 "$(cput "$n" "pool$n" "$WORK/obj/pool$n")"
done
check "new writes land in the emptier pool" 24 "$(find "$WORK"/n*/p* -path '*/data/*' -type f | wc -l)"
check "first pool untouched by new writes" "$before" "$(find "$WORK"/n*/d* -path '*/data/*' -type f | wc -l)"
bad=0
for o in cli1 multi down2 q7; do
  cget 4 "$o" "$WORK/got" >/dev/null
  [[ "$(md5 "$WORK/got")" == "$(md5 "$WORK/obj/$o")" ]] || bad=$((bad + 1))
done
check "old objects readable after expansion" 0 "$bad"
cget 2 pool3 "$WORK/got" >/dev/null
check "new-pool object readable via another node" "$(md5 "$WORK/obj/pool3")" "$(md5 "$WORK/got")"
for i in 1 2 3 4; do kill9 "$i"; done

# ---- TLS: node-to-node RPC over the same HTTPS port ----
if command -v openssl >/dev/null; then
  T="$WORK/tls"
  mkdir -p "$T"
  (
    cd "$T"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.crt -days 2 -subj /CN=zkfsm-cluster-ca \
      -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
    openssl ecparam -name prime256v1 -genkey -noout -out leaf.key 2>/dev/null
    openssl req -new -key leaf.key -subj /CN=localhost -out leaf.csr 2>/dev/null
    openssl x509 -req -in leaf.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 \
      -extfile <(echo "subjectAltName=IP:127.0.0.1,DNS:localhost") -out leaf.crt 2>/dev/null
    cat leaf.crt ca.crt >chain.crt
  )
  TP=(0 "$(freeport)" "$(freeport)" "$(freeport)" "$(freeport)")
  TEPS=()
  for i in 1 2 3 4; do TEPS+=("https://localhost:${TP[$i]}$T/n$i/d{1...2}"); done
  for i in 1 2 3 4; do
    ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$BIN" --data "${TEPS[@]}" --listen "127.0.0.1:${TP[$i]}" --node-address "localhost:${TP[$i]}" \
      --tls-cert "$T/chain.crt" --tls-key "$T/leaf.key" --cluster-ca "$T/ca.crt" >>"$WORK/t$i.log" 2>&1 &
    PIDS[$i]=$!
  done
  tready() { curl -s --cacert "$T/ca.crt" -o /dev/null -w '%{http_code}' "https://localhost:${TP[$1]}/health/ready"; }
  for i in 1 2 3 4; do for _ in $(seq 600); do [[ "$(tready "$i")" == 200 ]] && break; sleep 0.1; done; done
  check "tls cluster ready" "200 200 200 200" "$(tready 1) $(tready 2) $(tready 3) $(tready 4)"
  export AWS_CA_BUNDLE="$T/ca.crt"
  "$S3CLI_BIN" --endpoint-url "https://localhost:${TP[1]}" s3 mb s3://tlsclu >/dev/null
  "$S3CLI_BIN" --endpoint-url "https://localhost:${TP[2]}" s3 cp --no-progress "$WORK/obj/multi" s3://tlsclu/multi >/dev/null
  "$S3CLI_BIN" --endpoint-url "https://localhost:${TP[4]}" s3 cp --no-progress s3://tlsclu/multi "$WORK/got" >/dev/null
  check "tls cluster roundtrip across nodes" "$(md5 "$WORK/obj/multi")" "$(md5 "$WORK/got")"
  unset AWS_CA_BUNDLE
fi

echo "cluster: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
