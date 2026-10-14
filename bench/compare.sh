#!/usr/bin/env bash
# warp PUT/GET/LIST/mixed/multipart against zkfsm, MinIO and RustFS in docker containers
# with identical CPU/memory/tmpfs limits and erasure coding on all three, single node
# (4 drives, 2+2) and 4 nodes x 4 drives (12+4). See bench/RESULTS.md for methodology.
# REPS rounds; each round runs every topology and workload, and every product back to back
# per workload (order rotated per round), so host noise spreads across products. Each run records the load average.
# Drives are tmpfs charged to the container: they must hold a whole PUT run, so large
# PUTs run for DUR_PUT_BIG only.
#
# env: PRODUCTS ("zkfsm minio rustfs"), TOPOS ("single cluster"), WORKLOADS (see below), REPS (3), ROUNDS (1..REPS; run a subset of rounds),
#      DUR (15s), DUR_PUT_BIG (6s, PUT of 1 MiB and larger), DUR_MP (10s, multipart), CONC (32),
#      SERVER_CPUS (0,1,2,3), CLIENT_CPUS (4-7), CLIENT_NCPU (4),
#      SINGLE_MEM (20g), SINGLE_DRIVE (4096m), NODE_MEM (3g), NODE_DRIVE (512m),
#      CACHE (build caches + binaries), OUT (raw logs + results.tsv),
#      ZKFSM_BIN / WARP_BIN (prebuilt binaries; built into CACHE when unset),
#      MINIO_IMAGE (pgsty/minio:latest), RUSTFS_IMAGE (rustfs/rustfs:latest), BASE_IMAGE (busybox:1.36-musl).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CACHE="${CACHE:-${TMPDIR:-/tmp}/zc-bench-cache}"
OUT="${OUT:-$CACHE/out-$(date +%Y%m%d-%H%M%S)}"
PRODUCTS="${PRODUCTS:-zkfsm minio rustfs}"
TOPOS="${TOPOS:-single cluster}"
WORKLOADS="${WORKLOADS:-put-4k put-64k put-1m put-16m get-4k get-64k get-1m get-16m list-4k mixed-4k mixed-1m mp-64m}"
REPS="${REPS:-3}"
ROUNDS="${ROUNDS:-$(seq -s" " 1 "$REPS")}"
DUR="${DUR:-15s}"
DUR_PUT_BIG="${DUR_PUT_BIG:-6s}"
DUR_MP="${DUR_MP:-10s}"
CONC="${CONC:-32}"
SERVER_CPUS="${SERVER_CPUS:-0,1,2,3}"
CLIENT_CPUS="${CLIENT_CPUS:-4-7}"
CLIENT_NCPU="${CLIENT_NCPU:-4}"
SINGLE_MEM="${SINGLE_MEM:-20g}"
SINGLE_DRIVE="${SINGLE_DRIVE:-4096m}"
NODE_MEM="${NODE_MEM:-3g}"
NODE_DRIVE="${NODE_DRIVE:-512m}"
MINIO_IMAGE="${MINIO_IMAGE:-pgsty/minio:latest}"
RUSTFS_IMAGE="${RUSTFS_IMAGE:-rustfs/rustfs:latest}"
BASE_IMAGE="${BASE_IMAGE:-busybox:1.36-musl}"
AK=zcbenchadmin
SK=zcbenchsecret123
BUCKET=zc-bench
IFS=, read -r -a CPUS <<<"$SERVER_CPUS"
NCPU=${#CPUS[@]}

mkdir -p "$CACHE" "$OUT"
log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$OUT/run.log" >&2; }

containers() { docker ps -aq --filter "name=^zc-bench-(node-|client)" 2>/dev/null || true; }
stop_all() {
  local ids
  ids="$(containers)"
  [[ -n "$ids" ]] && docker rm -f $ids >/dev/null 2>&1 || true
}
cleanup() { stop_all; docker network rm zc-bench-net >/dev/null 2>&1 || true; }
trap cleanup EXIT
trap 'exit 130' INT TERM

# --- binaries and images ---------------------------------------------------
prepare() {
  if [[ -z "${ZKFSM_BIN:-}" ]]; then
    (cd "$ROOT" && ZIG_LOCAL_CACHE_DIR="$CACHE/zig-local" ZIG_GLOBAL_CACHE_DIR="$CACHE/zig-global" \
      zig build -Dtarget=x86_64-linux-musl -Doptimize=ReleaseFast --prefix "$CACHE/zkfsm-out")
    ZKFSM_BIN="$CACHE/zkfsm-out/bin/zkfsm"
  fi
  if [[ -z "${WARP_BIN:-}" ]]; then
    GOPATH="$CACHE/go" GOMODCACHE="$CACHE/go/mod" GOCACHE="$CACHE/go/cache" GOFLAGS=-modcacherw \
      CGO_ENABLED=0 go install github.com/minio/warp@v1.8.2
    WARP_BIN="$CACHE/go/bin/warp"
  fi
  # Binaries are baked into images: bind mounts from tmp dirs fail exec under SELinux.
  local ctx="$CACHE/ctx"
  mkdir -p "$ctx"
  printf 'FROM %s\nARG BIN\nCOPY $BIN /usr/local/bin/$BIN\n' "$BASE_IMAGE" >"$ctx/Dockerfile"
  cp "$ZKFSM_BIN" "$ctx/zkfsm"
  cp "$WARP_BIN" "$ctx/warp"
  for b in zkfsm warp; do docker build -q --build-arg BIN=$b -t zc-bench-$b "$ctx" >/dev/null; done
  rm -f "$ctx/zkfsm" "$ctx/warp"
  for img in "$MINIO_IMAGE" "$RUSTFS_IMAGE"; do
    docker image inspect "$img" >/dev/null 2>&1 || docker pull "$img" >/dev/null
  done
}

# --- targets ---------------------------------------------------------------
# Own bridge network; the client is a container on it too (no docker-proxy/NAT).
NET=zc-bench-net
start_target() { # product topo
  local p=$1 t=$2 n mem drive cpus ncpu
  if [[ $t == single ]]; then n=1 mem=$SINGLE_MEM drive=$SINGLE_DRIVE ncpu=$NCPU; else n=4 mem=$NODE_MEM drive=$NODE_DRIVE ncpu=1; fi
  local eps="/data{1...4}" zkp=${ZKFSM_SINGLE_PROTECTION:-EC:2+2} parity=EC:2
  if [[ $t == cluster ]]; then
    eps="http://zc-bench-node-{1...4}:9000/data{1...4}"
    zkp=EC:12+4 parity=EC:4
  fi
  docker network inspect $NET >/dev/null 2>&1 || docker network create $NET >/dev/null
  HOSTS=""
  for i in $(seq 1 "$n"); do
    local name="zc-bench-node-$i"
    if [[ $t == single ]]; then cpus="$SERVER_CPUS"; else cpus="${CPUS[$((i - 1))]}"; fi
    local args=(-d --name "$name" --hostname "$name" --network $NET --cpuset-cpus "$cpus" --cpus "$ncpu"
      --memory "$mem" --memory-swap "$mem" --ulimit nofile=65536:65536 --tmpfs /tmp:size=256m)
    local uid=0
    [[ $p == rustfs ]] && uid=10001
    for d in 1 2 3 4; do args+=(--tmpfs "/data$d:size=$drive,uid=$uid,gid=$uid,mode=0750"); done
    case $p in
      zkfsm)
        local cmd=(zkfsm --data "$eps" --listen 0.0.0.0:9000 --protection "$zkp")
        [[ $t == cluster ]] && cmd+=(--node-address "$name:9000")
        docker run "${args[@]}" -e ZKFSM_ACCESS_KEY=$AK -e ZKFSM_SECRET_KEY=$SK zc-bench-zkfsm "${cmd[@]}" >/dev/null ;;
      minio)
        docker run "${args[@]}" -e MINIO_ROOT_USER=$AK -e MINIO_ROOT_PASSWORD=$SK \
          -e MINIO_STORAGE_CLASS_STANDARD=$parity "$MINIO_IMAGE" \
          server --address :9000 --console-address :9001 "$eps" >/dev/null ;;
      rustfs)
        docker run "${args[@]}" -e RUSTFS_ACCESS_KEY=$AK -e RUSTFS_SECRET_KEY=$SK \
          -e RUSTFS_ADDRESS=:9000 -e RUSTFS_VOLUMES="$eps" -e RUSTFS_CONSOLE_ENABLE=false \
          -e RUSTFS_STORAGE_CLASS_STANDARD=$parity -e RUSTFS_OBS_LOG_DIRECTORY=  "$RUSTFS_IMAGE" >/dev/null ;;
    esac
    HOSTS+="${HOSTS:+,}$name:9000"
  done
}

# Client in its own netns: wide port range + tw_reuse, since a server that closes
# connections per request would otherwise exhaust ephemeral ports.
warp() { # subcommand tag args...
  local sub=$1 tag=$2
  shift 2
  docker run --rm --name zc-bench-client --network $NET --cpuset-cpus "$CLIENT_CPUS" --cpus "$CLIENT_NCPU" \
    --sysctl net.ipv4.ip_local_port_range="1024 65535" --sysctl net.ipv4.tcp_tw_reuse=1 \
    --tmpfs /tmp:size=512m zc-bench-warp warp "$sub" --host "$HOSTS" --host-select roundrobin \
    --access-key $AK --secret-key $SK --bucket $BUCKET --concurrent "$CONC" \
    --benchdata "/tmp/$tag" "$@"
}

# A short PUT run doubles as readiness gate and warm-up.
wait_ready() { # tag
  for _ in $(seq 1 30); do
    if warp put "$1-warmup" --obj.size 4KiB --duration 3s >"$OUT/$1-warmup.log" 2>&1; then return 0; fi
    sleep 3
  done
  return 1
}

servers_alive() {
  local id st
  for id in $(containers); do
    st="$(docker inspect -f '{{.State.Running}} {{.State.OOMKilled}} {{.State.ExitCode}}' "$id")"
    [[ $st == "true false 0" ]] || { echo "$st"; return 1; }
  done
}

# Parses warp's text report into: op MiB/s obj/s p50 p99.
parse() {
  awk '
    /^Report: / { op=$2; sub(/\.$/, "", op); next }
    op != "" && /\* Average:/ {
      mib="-"; ops="-"
      if (match($0, /[0-9.]+ ?[KMG]iB\/s/)) { v=substr($0, RSTART, RLENGTH); sub(/ ?MiB\/s/, "", v); mib=v }
      if (match($0, /[0-9.]+ obj\/s/)) { v=substr($0, RSTART, RLENGTH); sub(/ obj\/s/, "", v); ops=v }
      next }
    op != "" && /\* Reqs:/ {
      p50="-"; p99="-"
      if (match($0, /50%: [0-9.]+[mµn]?s/)) p50=substr($0, RSTART+5, RLENGTH-5)
      if (match($0, /99%: [0-9.]+[mµn]?s/)) p99=substr($0, RSTART+5, RLENGTH-5)
      printf "%s\t%s\t%s\t%s\t%s\n", op, ops, mib, p50, p99; op=""; next }' "$1"
  # Total (mixed) has no Reqs line.
  awk '/^Report: Total/ { t=1; next } t && /\* Average:/ {
      mib=$0; sub(/.*Average: /, "", mib); sub(/ MiB\/s.*/, "", mib)
      ops=$0; sub(/.* MiB\/s, /, "", ops); sub(/ obj\/s.*/, "", ops)
      printf "Total\t%s\t%s\t-\t-\n", ops, mib; exit }' "$1"
}

run_workload() { # product topo workload rep
  local p=$1 t=$2 w=$3 r=$4 tag="$1-$2-$3-r$4" rc=0
  local kind=${w%-*} size
  case ${w#*-} in 4k) size=4KiB ;; 64k) size=64KiB ;; 1m) size=1MiB ;; 16m) size=16MiB ;; 64m) size=64MiB ;; esac
  local extra=(--obj.size "$size" --duration "$DUR")
  case $kind in
    put) extra+=(--disable-multipart)
      [[ $size == 4KiB || $size == 64KiB ]] || extra[3]="$DUR_PUT_BIG" ;;
    # 64 MiB objects through minio-go's default 16 MiB parts: 4 parts each.
    mp) kind=put extra[3]="$DUR_MP" ;;
    get | mixed) case $size in 4KiB | 64KiB) extra+=(--objects 2500) ;; 1MiB) extra+=(--objects 1000) ;; *) extra+=(--objects 100) ;; esac ;;
    list) extra+=(--objects 2500) ;;
  esac
  local load
  load="$(cut -d' ' -f1-3 /proc/loadavg)"
  log "run $tag (load $load)"
  warp "$kind" "$tag" "${extra[@]}" >"$OUT/$tag.log" 2>&1 || rc=$?
  local errs
  errs="$(grep -ciE 'error' "$OUT/$tag.log" || true)"
  local alive="ok"
  servers_alive >/dev/null || alive="server-down"
  if [[ $rc -ne 0 ]]; then
    log "FAIL $tag rc=$rc ($alive); tail: $(tail -n 2 "$OUT/$tag.log" | tr '\n' ' ')"
    printf '%s\t%s\t%s\t%s\tFAILED\t-\t-\t-\t-\t%s\trc=%s %s\n' "$p" "$t" "$w" "$r" "$load" "$rc" "$alive" >>"$OUT/results.tsv"
    return 1
  fi
  parse "$OUT/$tag.log" | while IFS=$'\t' read -r op ops mib p50 p99; do
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\terr_lines=%s %s\n' "$p" "$t" "$w" "$r" "$op" "$ops" "$mib" "$p50" "$p99" "$load" "$errs" "$alive"
  done >>"$OUT/results.tsv"
}

main() {
  log "out: $OUT"
  prepare
  printf 'product\ttopo\tworkload\trep\top\tobj/s\tMiB/s\tp50\tp99\tload\tnotes\n' >"$OUT/results.tsv"
  {
    echo "warp: $(go version -m "$WARP_BIN" 2>/dev/null | awk '$1=="mod"{print $3}')"
    echo "zkfsm: $(git -C "$ROOT" rev-parse --short HEAD) ReleaseFast x86_64-linux-musl"
    echo "minio: $(docker run --rm "$MINIO_IMAGE" --version 2>&1 | head -1) $(docker image inspect -f '{{index .RepoDigests 0}}' "$MINIO_IMAGE")"
    echo "rustfs: $(docker run --rm --entrypoint /usr/bin/rustfs "$RUSTFS_IMAGE" --version 2>&1 | head -1) $(docker image inspect -f '{{index .RepoDigests 0}}' "$RUSTFS_IMAGE")"
  } >"$OUT/versions.txt"
  local failed=0 prods
  read -r -a prods <<<"$PRODUCTS"
  for r in $ROUNDS; do
    # Rotate the product order each round.
    local k=$(((r - 1) % ${#prods[@]}))
    local order=("${prods[@]:k}" "${prods[@]:0:k}")
    for t in $TOPOS; do
      for w in $WORKLOADS; do
        for p in "${order[@]}"; do
          # A fresh target with empty drives per workload: RustFS keeps deleted objects
          # in .rustfs.sys/tmp/.trash, so earlier runs would fill the next run's drives.
          stop_all
          start_target "$p" "$t"
          if ! wait_ready "$p-$t-$w-r$r"; then
            log "FAIL $p $t $w r$r: not ready"
            printf '%s\t%s\t%s\t%s\tFAILED\t-\t-\t-\t-\t-\tnot ready\n' "$p" "$t" "$w" "$r" >>"$OUT/results.tsv"
            failed=1
          else
            run_workload "$p" "$t" "$w" "$r" || failed=1
          fi
          for id in $(containers); do
            docker logs "$id" >"$OUT/$p-$t-$w-r$r-server-$(docker inspect -f '{{.Name}}' "$id" | tr -d /).log" 2>&1 || true
          done
          stop_all
        done
      done
    done
  done
  column -t -s $'\t' "$OUT/results.tsv" >"$OUT/results.txt"
  log "done; failed=$failed"
  return "$failed"
}
main "$@"
