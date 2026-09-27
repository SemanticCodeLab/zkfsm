#!/usr/bin/env bash
# S3 throughput/latency bench: small-object PUT/GET ops/s at concurrency 1/16/64,
# and ListObjectsV2 first-page latency at 1k/10k/100k keys in one bucket.
# env: BIN (server binary, default zig-out/bin/zkfsm), SIZE (bytes, default 4096),
#      OPS (requests per PUT/GET run, default 5000), SIZES (key counts), DRIVES, PROTECTION.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${BIN:-$ROOT/zig-out/bin/zkfsm}"
SIZE="${SIZE:-4096}"
OPS="${OPS:-5000}"
SIZES="${SIZES:-1000 10000 100000}"
DRIVES="${DRIVES:-1}"
LOAD="$ROOT/zig-out/bin/s3load"
(cd "$ROOT" && zig build s3load >/dev/null)
PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')"
DATA="$(mktemp -d)"
PID=""
cleanup() { [[ -n "$PID" ]] && kill "$PID" 2>/dev/null; wait 2>/dev/null || true; rm -rf "$DATA"; }
trap cleanup EXIT

args=(--data "$DATA/d{1...$DRIVES}" --anonymous --scan-interval 0 --listen "127.0.0.1:$PORT")
[[ -n "${PROTECTION:-}" ]] && args+=(--protection "$PROTECTION")
"$BIN" "${args[@]}" 2>"$DATA.log" &
PID=$!
for _ in $(seq 100); do curl -s -o /dev/null "http://127.0.0.1:$PORT/" && break; sleep 0.1; done
mk() { curl -sf -X PUT "http://127.0.0.1:$PORT/$1" >/dev/null; }

echo "== small objects (${SIZE} B, $OPS ops per run)"
for c in 1 16 64; do
  mk "bkt$c"
  printf "PUT c=%-3s %s\n" "$c" "$("$LOAD" put 127.0.0.1 "$PORT" "bkt$c" "$c" "$OPS" "$SIZE")"
  printf "GET c=%-3s %s\n" "$c" "$("$LOAD" get 127.0.0.1 "$PORT" "bkt$c" "$c" "$OPS")"
done

echo "== ListObjectsV2 first page (max-keys 1000)"
have=0
mk list
for n in $SIZES; do
  "$LOAD" put 127.0.0.1 "$PORT" list 64 "$n" 16 >/dev/null
  have=$n
  reps=$((n >= 100000 ? 5 : 20))
  printf "keys=%-7s plain     %s\n" "$have" "$("$LOAD" list 127.0.0.1 "$PORT" list "$reps" "list-type=2")"
  printf "keys=%-7s delimiter %s\n" "$have" "$("$LOAD" list 127.0.0.1 "$PORT" list "$reps" "list-type=2&delimiter=0")"
done
