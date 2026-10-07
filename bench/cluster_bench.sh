#!/usr/bin/env bash
# Cluster bench: 4 local nodes x 4 drives, EC:4+2, ReleaseFast. PUT then GET ops/s with
# p50/p99 at concurrency 16 and 64, connections spread over all four endpoints.
# env: BIN (server binary; default builds ReleaseFast), SIZE (bytes, default 4096),
#      OPS (requests per run, default 4000), CONCS (default "16 64").
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SIZE="${SIZE:-4096}"
OPS="${OPS:-4000}"
CONCS="${CONCS:-16 64}"
WORK="$(mktemp -d)"
PIDS=()
cleanup() {
  for p in "${PIDS[@]}"; do kill -9 "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

if [[ -z "${BIN:-}" ]]; then
  (cd "$ROOT" && zig build -Doptimize=ReleaseFast -p "$WORK/fast" >/dev/null)
  BIN="$WORK/fast/bin/zkfsm"
fi
(cd "$ROOT" && zig build s3load -Doptimize=ReleaseFast -p "$WORK/load" >/dev/null)
LOAD="$WORK/load/bin/s3load"

freeport() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
PORT=()
for _ in 1 2 3 4; do PORT+=("$(freeport)"); done
EPS=()
for i in 1 2 3 4; do EPS+=("http://127.0.0.1:${PORT[$((i - 1))]}$WORK/n$i/d{1...4}"); done
for i in 1 2 3 4; do
  "$BIN" --data "${EPS[@]}" --listen "127.0.0.1:${PORT[$((i - 1))]}" --node-address "127.0.0.1:${PORT[$((i - 1))]}" \
    --protection EC:4+2 --anonymous --cluster-secret bench-secret --scan-interval 0 >"$WORK/n$i.log" 2>&1 &
  PIDS+=($!)
done
for p in "${PORT[@]}"; do
  for _ in $(seq 600); do
    [[ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/health/ready")" == 200 ]] && break
    sleep 0.1
  done
done
ALL=$(IFS=,; echo "${PORT[*]}")
mk() { curl -sf -X PUT "http://127.0.0.1:${PORT[0]}/$1" >/dev/null; }

echo "== cluster 4 nodes x 4 drives, EC:4+2, ${SIZE} B objects, $OPS ops per run, all endpoints"
for c in $CONCS; do
  mk "bkt$c"
  sleep 1
  printf "PUT c=%-3s %s\n" "$c" "$("$LOAD" put 127.0.0.1 "$ALL" "bkt$c" "$c" "$OPS" "$SIZE")"
  printf "GET c=%-3s %s\n" "$c" "$("$LOAD" get 127.0.0.1 "$ALL" "bkt$c" "$c" "$OPS")"
done
