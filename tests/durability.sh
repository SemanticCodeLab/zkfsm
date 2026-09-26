#!/usr/bin/env bash
# Durability test: 4 drives, replica:2. Damages drives in three ways and checks
# that reads keep working and the background healer restores full redundancy.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/zig-out/bin/zkfsm"
PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')"
EP="http://127.0.0.1:$PORT"
DATA="$(mktemp -d)"
WORK="$(mktemp -d)"
PID=""
cleanup() { [[ -n "$PID" ]] && kill "$PID" 2>/dev/null || true; rm -rf "$DATA" "$WORK"; }
trap cleanup EXIT
[[ -n "${KEEP_LOG:-}" ]] && trap 'cp "$WORK/server.log" "$KEEP_LOG" 2>/dev/null; cleanup' EXIT

pass=0
fail=0
check() { # name expected actual
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); echo "ok   $1"
  else fail=$((fail + 1)); echo "FAIL $1: expected [$2] got [$3]"; fi
}

NDRIVES=4
PROFILE=replica:2
COPIES=2
start() {
  "$BIN" --data "$DATA/d{1...$NDRIVES}" --protection "$PROFILE" --scan-interval 1 --anonymous \
    --listen "127.0.0.1:$PORT" 2>>"$WORK/server.log" &
  PID=$!
  for _ in $(seq 50); do curl -s -o /dev/null "$EP/" && return 0; sleep 0.1; done
  echo "server did not start:"; cat "$WORK/server.log"; exit 1
}
stop() { kill "$PID"; wait "$PID" 2>/dev/null || true; PID=""; }

N=24
# Every object readable with the right content: prints the number of good reads.
reads_ok() {
  local good=0
  for i in $(seq $N); do
    if curl -sf -o "$WORK/got" "$EP/dur/obj$i" && [[ "$(md5sum <"$WORK/got")" == "$(md5sum <"$WORK/obj$i")" ]]; then
      good=$((good + 1))
    fi
  done
  echo "$good"
}

# Full redundancy: every data blob/shard and record on exactly COPIES drives
# (replicas byte-identical; EC shards differ), and the catalog on every drive.
redundancy() {
  python3 - "$DATA" "$N" "$COPIES" "$NDRIVES" "$PROFILE" <<'EOF'
import collections, hashlib, os, sys
root, n, want, ndrives, profile = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
copies = collections.defaultdict(list)
drives = sorted(os.listdir(root))
for d in drives:
    for sp in ("data", "record"):
        for dp, _, fs in os.walk(os.path.join(root, d, sp)):
            for f in fs:
                with open(os.path.join(dp, f), "rb") as fh:
                    copies[(sp, f)].append(hashlib.md5(fh.read()).hexdigest())
identical = lambda k: k[0] == "record" or profile.startswith("replica")
bad = [k for k, v in copies.items() if len(v) != want or (identical(k) and len(set(v)) != 1)]
data = sum(1 for k in copies if k[0] == "data")
cat = sum(os.path.exists(os.path.join(root, d, "system", "0" * 32 + ".meta")) for d in drives)
print("full" if not bad and data == n and cat == ndrives else f"degraded bad={len(bad)} data={data} catalog={cat}")
EOF
}

wait_full() {
  for _ in $(seq 100); do [[ "$(redundancy)" == full ]] && { echo full; return; }; sleep 0.2; done
  redundancy
}

(cd "$ROOT" && zig build)
start
curl -s -o /dev/null -X PUT "$EP/dur"
for i in $(seq $N); do
  head -c $((RANDOM * 8 + i)) /dev/urandom >"$WORK/obj$i"
  curl -s -o /dev/null -T "$WORK/obj$i" "$EP/dur/obj$i"
done
check "initial reads" $N "$(reads_ok)"
check "initial redundancy" full "$(redundancy)"
check "format files" 4 "$(ls "$DATA"/d*/format.zkfsm | wc -l)"

# (a) Wipe one drive's contents while running.
rm -rf "$DATA"/d2/*
check "(a) reads after wipe" $N "$(reads_ok)"
check "(a) heal restores redundancy" full "$(wait_full)"

# (b) Flip bytes inside a stored shard.
SHARD="$(find "$DATA/d3/data" -type f -size +1k | head -1)"
python3 - "$SHARD" <<'EOF'
import sys
with open(sys.argv[1], "r+b") as f:
    f.seek(100); b = f.read(1); f.seek(100); f.write(bytes([b[0] ^ 0xff]))
EOF
check "(b) corruption visible" degraded "$(redundancy | cut -d' ' -f1)"
check "(b) reads after bitrot" $N "$(reads_ok)"
check "(b) heal repairs shard" full "$(wait_full)"
check "(b) corruption logged" 1 "$(grep -c "corrupt.*$(basename "$SHARD")" "$WORK/server.log" | awk '{print ($1>0)}')"

# (c) Remove a drive entirely while running.
rm -rf "$DATA/d4"
check "(c) reads without drive" $N "$(reads_ok)"
check "(c) heal rebuilds drive" full "$(wait_full)"

# (c') Remove a drive while stopped; startup formats it as a replacement.
stop
rm -rf "$DATA/d1"
start
check "(c') reads after restart" $N "$(reads_ok)"
check "(c') heal rebuilds replacement" full "$(wait_full)"

# Leftover temp file from an interrupted write gets swept.
touch -d '2 hours ago' "$DATA/d1/tmp/deadbeef.tmp"
for _ in $(seq 50); do [[ -e "$DATA/d1/tmp/deadbeef.tmp" ]] || break; sleep 0.2; done
check "stale temp removed" no "$([[ -e "$DATA/d1/tmp/deadbeef.tmp" ]] && echo yes || echo no)"

# Writes and deletes still work, and the one-shot admin heal reports a clean set.
echo -n "after" | curl -s -o /dev/null -T - "$EP/dur/late"
check "write after heal" after "$(curl -s "$EP/dur/late")"
curl -s -o /dev/null -X DELETE "$EP/dur/late"
stop
set +e
"$BIN" heal --data "$DATA/d{1...4}" 2>"$WORK/heal.log"
rc=$?
set -e
check "one-shot heal clean" 0 "$rc"

# Foreign and reordered drives are refused.
mkdir -p "$WORK/other"
"$BIN" heal --data "$WORK/other/x" --protection single 2>/dev/null || true
set +e
"$BIN" heal --data "$DATA/d1" "$DATA/d2" "$DATA/d3" "$WORK/other/x" 2>"$WORK/foreign.log"
check "foreign drive refused" 1 "$?"
"$BIN" heal --data "$DATA/d2" "$DATA/d1" "$DATA/d3" "$DATA/d4" 2>/dev/null
check "reordered drives refused" 1 "$?"
set -e
check "foreign reason" 1 "$(grep -c ForeignDrive "$WORK/foreign.log")"

# EC:4+2 on 6 drives: lose any 2 and keep serving, then heal.
rm -rf "${DATA:?}"/*
NDRIVES=6
PROFILE=EC:4+2
COPIES=6
start
curl -s -o /dev/null -X PUT "$EP/dur"
for i in $(seq $N); do
  head -c $((RANDOM * 64 + i)) /dev/urandom >"$WORK/obj$i"
  curl -s -o /dev/null -T "$WORK/obj$i" "$EP/dur/obj$i"
done
check "EC initial reads" $N "$(reads_ok)"
check "EC initial redundancy" full "$(redundancy)"
rm -rf "${DATA:?}/d2" "${DATA:?}/d5"
check "EC reads with 2 drives gone" $N "$(reads_ok)"
check "EC heal rebuilds 2 drives" full "$(wait_full)"
SHARD="$(find "$DATA/d3/data" -type f -size +100k | head -1)"
ORIG="$(md5sum <"$SHARD")"
python3 - "$SHARD" <<'EOF'
import sys
with open(sys.argv[1], "r+b") as f:
    f.seek(5000); b = f.read(1); f.seek(5000); f.write(bytes([b[0] ^ 0xff]))
EOF
rm -rf "${DATA:?}/d6"
check "EC reads with bitrot and a drive gone" $N "$(reads_ok)"
check "EC heal after bitrot and loss" full "$(wait_full)"
for _ in $(seq 50); do [[ "$(md5sum <"$SHARD")" == "$ORIG" ]] && break; sleep 0.2; done
check "EC corrupt shard rebuilt byte-exact" "$ORIG" "$(md5sum <"$SHARD")"
stop
rm -rf "${DATA:?}/d1" "${DATA:?}/d4" "${DATA:?}/d6"
set +e
"$BIN" heal --data "$DATA/d{1...6}" 2>"$WORK/heal-ec.log"
check "EC loss of 3 drives reported as data loss" 3 "$?"
set -e

echo "durability: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
