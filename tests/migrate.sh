#!/usr/bin/env bash
# Migration from a MinIO-format deployment: a real server in docker on 4 erasure-coded
# drives gets versioned, locked, suspended, and plain buckets, multipart and inline
# objects, tags, metadata, policy, lifecycle, and IAM. Then:
#   1. online pull (--from-s3) while it runs, compared through mc;
#   2. offline import (--from-minio) of the stopped drives, compared through mc;
#   3. a rerun resumes from the checkpoint and copies nothing;
#   4. a degraded import (one drive missing, one shard corrupted) still verifies.
# Needs docker and mc ($MC). Image: $MINIO_IMAGE, else the first that pulls.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MC="${MC:-mc}"
export MC
WORK="$(mktemp -d)"
NAME="zkfsm-migrate-$$"
export MC_CONFIG_DIR="$WORK/mc"
free_port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
MPORT="$(free_port)"
ZPORT="$(free_port)"
ZPID=""
cleanup() {
  [[ -n "$ZPID" ]] && kill "$ZPID" 2>/dev/null || true
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "ok   $1"; }
bad() { fail=$((fail + 1)); echo "FAIL $1"; }
check() { if "$@" >"$WORK/check.log" 2>&1; then ok "$CHECK"; else bad "$CHECK"; cat "$WORK/check.log"; fi; }

(cd "$ROOT" && zig build)
ZK="$ROOT/zig-out/bin/zkfsm"

IMAGE="${MINIO_IMAGE:-}"
if [[ -z "$IMAGE" ]]; then
  for img in quay.io/minio/minio:latest minio/minio:latest pgsty/minio:latest; do
    if docker image inspect "$img" >/dev/null 2>&1 || docker pull -q "$img" >/dev/null 2>&1; then IMAGE="$img"; break; fi
  done
fi
[[ -n "$IMAGE" ]] || { echo "no MinIO image available"; exit 1; }
echo "image: $IMAGE"

export MINIO_ROOT_USER=minioadmin MINIO_ROOT_PASSWORD=minio-secret-1
mkdir -p "$WORK"/src/d{1,2,3,4}
docker run -d --name "$NAME" --user "$(id -u):$(id -g)" -p "127.0.0.1:$MPORT:9000" \
  -e MINIO_ROOT_USER -e MINIO_ROOT_PASSWORD -v "$WORK/src:/src:z" "$IMAGE" server '/src/d{1...4}' >/dev/null
for _ in $(seq 100); do curl -sf "http://127.0.0.1:$MPORT/minio/health/live" >/dev/null && break; sleep 0.2; done
"$MC" alias set src "http://127.0.0.1:$MPORT" "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null

# ---- populate ----
q() { "$MC" -q "$@" >/dev/null; }
echo "first" > "$WORK/f1"; echo "second version" > "$WORK/f2"; echo "third" > "$WORK/f3"
head -c 3000000 /dev/urandom > "$WORK/big.bin"
head -c 40000000 /dev/urandom > "$WORK/mp.bin"
q mb src/vbk; q version enable src/vbk
q cp "$WORK/f1" src/vbk/a.txt
q cp --attr "X-Amz-Meta-Color=blue;Cache-Control=max-age=60;Content-Type=text/x-test" --tags "k1=v1&k2=v 2" "$WORK/f2" src/vbk/a.txt
q rm src/vbk/a.txt
q cp "$WORK/f3" src/vbk/a.txt
q cp "$WORK/big.bin" src/vbk/dir/big.bin
q cp "$WORK/mp.bin" src/vbk/mp.bin
q cp "$WORK/f1" "src/vbk/sp ace & more.txt"
q cp "$WORK/f1" src/vbk/gone.txt; q rm src/vbk/gone.txt
q anonymous set download src/vbk
q tag set src/vbk "env=prod&team=storage"
q mb src/unv
q cp "$WORK/f1" src/unv/x.txt; q cp "$WORK/f2" src/unv/x.txt
q cp --attr "Content-Type=application/json;X-Amz-Meta-Owner=ops" "$WORK/f3" src/unv/cfg.json
q ilm rule add --expire-days 30 src/unv
q mb --with-lock src/lkb
q cp "$WORK/f1" src/lkb/l1.txt
q retention set governance 1d src/lkb/l1.txt
q legalhold set src/lkb/l1.txt
q retention set --default GOVERNANCE 2d src/lkb
q cp "$WORK/f2" src/lkb/l2.txt
q mb src/sus; q version enable src/sus
q cp "$WORK/f1" src/sus/s.txt
q version suspend src/sus
q cp "$WORK/f2" src/sus/s.txt
q cp "$WORK/f3" src/sus/n.txt
cat > "$WORK/pol1.json" <<'EOF'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::vbk/*"]}]}
EOF
q admin user add src alice alice-secret-1
q admin user add src bob bob-secret-12
q admin policy create src pol1 "$WORK/pol1.json"
q admin policy attach src readwrite --user alice
q admin group add src g1 bob
q admin policy attach src pol1 --group g1
ETAG=$("$MC" --json stat src/vbk/mp.bin | python3 -c 'import json,sys;print(json.load(sys.stdin)["etag"])')
CHECK="source has a multipart object ($ETAG)" check grep -q -- '-[2-9]' <<<"$ETAG"

python3 "$ROOT/tests/migrate_snapshot.py" take src "$WORK/src.json" --iam
echo "source: $(grep -c '"md5"' "$WORK/src.json") object version(s)"

start_zk() { # data dirs...
  ZKFSM_ACCESS_KEY=zkadmin ZKFSM_SECRET_KEY=zk-secret-1 "$ZK" --data "$@" --listen "127.0.0.1:$ZPORT" --scan-interval 0 --lifecycle-interval 0 2>"$WORK/zk.log" &
  ZPID=$!
  for _ in $(seq 100); do curl -s -o /dev/null "http://127.0.0.1:$ZPORT/" && break; sleep 0.1; done
  "$MC" alias set dst "http://127.0.0.1:$ZPORT" zkadmin zk-secret-1 >/dev/null
}
stop_zk() { kill "$ZPID"; wait "$ZPID" 2>/dev/null || true; ZPID=""; }

# ---- 1. online pull ----
mkdir -p "$WORK/online"
CHECK="online pull with verify" check env ZKFSM_MIGRATE_ACCESS_KEY="$MINIO_ROOT_USER" ZKFSM_MIGRATE_SECRET_KEY="$MINIO_ROOT_PASSWORD" \
  "$ZK" migrate --from-s3 "http://127.0.0.1:$MPORT" --to "$WORK/online" --verify
start_zk "$WORK/online"
python3 "$ROOT/tests/migrate_snapshot.py" take dst "$WORK/online.json"
CHECK="online: contents, versions, tags, metadata, configs match" check python3 "$ROOT/tests/migrate_snapshot.py" diff "$WORK/src.json" "$WORK/online.json" --no-iam
stop_zk

# ---- 2. offline import ----
docker stop "$NAME" >/dev/null
mkdir -p "$WORK"/dst/{1,2,3,4}
export ZKFSM_ACCESS_KEY=zkadmin ZKFSM_SECRET_KEY=zk-secret-1
CHECK="offline import with verify" check "$ZK" migrate --from-minio "$WORK/src/d{1...4}" --to "$WORK"/dst/{1,2,3,4} --verify
cp "$WORK/check.log" "$WORK/offline.log"
CHECK="offline: IAM imported" check grep -q "iam entities [1-9]" "$WORK/offline.log"
start_zk "$WORK"/dst/{1,2,3,4}
python3 "$ROOT/tests/migrate_snapshot.py" take dst "$WORK/offline.json" --iam
CHECK="offline: contents, versions, tags, metadata, configs, IAM match" check python3 "$ROOT/tests/migrate_snapshot.py" diff "$WORK/src.json" "$WORK/offline.json"
CHECK="offline: dashed source version ids still resolve" check "$MC" stat --vid "$(python3 -c 'import json;d=json.load(open("'"$WORK/src.json"'"));print(d["buckets"]["vbk"]["objects"]["a.txt"][0]["id"])' | sed -E 's/(.{8})(.{4})(.{4})(.{4})(.{12})/\1-\2-\3-\4-\5/')" dst/vbk/a.txt
stop_zk

# ---- 3. resume ----
CHECK="rerun resumes from the checkpoint" check "$ZK" migrate --from-minio "$WORK/src/d{1...4}" --to "$WORK"/dst/{1,2,3,4}
cp "$WORK/check.log" "$WORK/rerun.log"
CHECK="rerun copied nothing" check grep -q "versions 0 (0 bytes), delete markers 0" "$WORK/rerun.log"

# ---- 4. degraded source ----
mv "$WORK/src/d4" "$WORK/src-d4-offline"
part=$(find "$WORK/src/d1/vbk/mp.bin" -name 'part.1' | head -1)
printf 'XXXXXXXX' | dd of="$part" bs=1 seek=4096 conv=notrunc 2>/dev/null
mkdir -p "$WORK/degraded"
CHECK="degraded import (drive missing, shard corrupted) verifies" check "$ZK" migrate --from-minio "$WORK"/src/d{1,2,3} --to "$WORK/degraded" --verify --no-iam
cp "$WORK/check.log" "$WORK/degraded.log"
CHECK="degraded import reported the bitrot and rebuilt from parity" check grep -q "bitrot failure" "$WORK/degraded.log"

echo "migrate: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
