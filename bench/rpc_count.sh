#!/usr/bin/env bash
# Node-to-node calls per small PUT on a local 4-node x 4-drive EC:4+2 cluster.
# Sums zkfsm_cluster_rpc_sent_total over all nodes around N PUTs sent to node 1.
#   bench/rpc_count.sh [size_bytes] [count] [extra server args...]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SIZE="${1:-4096}"
N="${2:-200}"
shift $(($# < 2 ? $# : 2))
WORK="$(mktemp -d)"
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill -9 "$p" 2>/dev/null || true; done; rm -rf "$WORK"; }
trap cleanup EXIT
freeport() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
AK=rpcadmin
SK=rpc-secret-key-0123456
(cd "$ROOT" && zig build -Doptimize=ReleaseFast)
BIN="$ROOT/zig-out/bin/zkfsm"
PORT=(0 "$(freeport)" "$(freeport)" "$(freeport)" "$(freeport)")
POOL=()
for i in 1 2 3 4; do POOL+=("http://127.0.0.1:${PORT[$i]}$WORK/n$i/d{1...4}"); done
for i in 1 2 3 4; do
  ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$BIN" --data "${POOL[@]}" --listen "127.0.0.1:${PORT[$i]}" \
    --node-address "127.0.0.1:${PORT[$i]}" --protection EC:4+2 --scan-interval 0 "$@" >>"$WORK/n$i.log" 2>&1 &
  PIDS+=($!)
done
for i in 1 2 3 4; do
  for _ in $(seq 600); do [[ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT[$i]}/health/ready")" == 200 ]] && break; sleep 0.1; done
done
sig=(--aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK")
curl -sf "${sig[@]}" -X PUT "http://127.0.0.1:${PORT[1]}/rpcb" >/dev/null
head -c "$SIZE" /dev/urandom >"$WORK/obj"
put() { curl -sf "${sig[@]}" -T "$WORK/obj" "http://127.0.0.1:${PORT[1]}/rpcb/$1" >/dev/null; }
for k in $(seq 20); do put "warm$k"; done
sleep 1
snap() {
  for i in 1 2 3 4; do curl -s "http://127.0.0.1:${PORT[$i]}/metrics"; done |
    awk -F'[{}" ]+' '/^zkfsm_cluster_rpc_sent_total/ {s[$3]+=$4} END {for (o in s) print o, s[o]}' | sort
}
snap >"$WORK/a"
for k in $(seq "$N"); do put "k$k"; done
# Overwrites: the replaced version's data is garbage.
for k in $(seq "$N"); do put "k$k"; done
sleep 1
snap >"$WORK/b"
echo "calls per PUT (size $SIZE, $N new keys then $N overwrites, all through node 1):"
join "$WORK/a" "$WORK/b" | awk -v n=$((2 * N)) '{d=$3-$2; if (d > 0) {printf "  %-10s %6.2f\n", $1, d/n; t+=d}} END {printf "  %-10s %6.2f\n", "total", t/n}'
