# Sourced by the gateway suites. ZKFSM_GW_CLUSTER=1 runs their main server as a
# 4-node cluster (4 drives per node, EC:4+2) with the gateway on every node.
# Needs: BIN, AK, SK, freeport. Sets GW_S3P[1..4] and GW_PIDS[1..4].
GW_CLUSTER="${ZKFSM_GW_CLUSTER:-0}"
GW_PIDS=()
GW_S3P=()

# Cluster mode uses a release build: debug-mode erasure coding and TLS RPC are too slow.
gw_build() { # out dir; sets BIN when in cluster mode
  [[ $GW_CLUSTER == 1 ]] || return 0
  (cd "$ROOT" && zig build -Doptimize=ReleaseSafe -p "$1")
  BIN="$1/bin/zkfsm"
}

# Private CA plus a leaf for 127.0.0.1/localhost: nodes verify each other with it.
gw_tls() { # dir; writes ca.crt chain.crt leaf.key
  local d="$1"
  mkdir -p "$d"
  (
    cd "$d"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.crt -days 2 -subj /CN=zkfsm-gw-ca \
      -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
    openssl ecparam -name prime256v1 -genkey -noout -out leaf.key 2>/dev/null
    openssl req -new -key leaf.key -subj /CN=localhost -out leaf.csr 2>/dev/null
    openssl x509 -req -in leaf.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 \
      -extfile <(echo "subjectAltName=IP:127.0.0.1,DNS:localhost") -out leaf.crt 2>/dev/null
    cat leaf.crt ca.crt >chain.crt
  )
}

# gw_cluster_start WORK READY_REGEX TLSDIR|"" NODE_ARGS_FN [common args...]
# NODE_ARGS_FN i prints node i's own flags (gateway listen ports).
gw_cluster_start() {
  local work="$1" ready="$2" tlsdir="$3" fn="$4"
  shift 4
  local scheme=http tlsargs=()
  if [[ -n "$tlsdir" ]]; then
    scheme=https
    tlsargs=(--tls-cert "$tlsdir/chain.crt" --tls-key "$tlsdir/leaf.key" --cluster-ca "$tlsdir/ca.crt")
  fi
  # Ports are kept across restarts of the same cluster.
  [[ ${#GW_S3P[@]} -eq 5 ]] || GW_S3P=(0 "$(freeport)" "$(freeport)" "$(freeport)" "$(freeport)")
  GW_PIDS=(0 0 0 0 0)
  local eps=() i
  for i in 1 2 3 4; do eps+=("$scheme://localhost:${GW_S3P[$i]}$work/n$i/d{1...4}"); done
  for i in 1 2 3 4; do
    # shellcheck disable=SC2046
    ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$BIN" --data "${eps[@]}" --listen "127.0.0.1:${GW_S3P[$i]}" \
      --node-address "localhost:${GW_S3P[$i]}" --protection EC:4+2 "${tlsargs[@]}" $("$fn" "$i") "$@" \
      >>"$work/node$i.log" 2>&1 &
    GW_PIDS[$i]=$!
  done
  for i in 1 2 3 4; do
    local ok=0
    for _ in $(seq 1200); do
      if [[ "$(curl -sk -o /dev/null -w '%{http_code}' "$scheme://127.0.0.1:${GW_S3P[$i]}/health/ready")" == 200 ]] &&
        grep -Eq "$ready" "$work/node$i.log"; then ok=1; break; fi
      sleep 0.1
    done
    if [[ $ok != 1 ]]; then echo "cluster node $i did not start:"; tail -30 "$work/node$i.log"; exit 1; fi
  done
}

gw_cluster_stop() {
  local p
  for p in "${GW_PIDS[@]}"; do [[ "$p" != 0 ]] && kill "$p" 2>/dev/null || true; done
  for p in "${GW_PIDS[@]}"; do [[ "$p" != 0 ]] && wait "$p" 2>/dev/null || true; done
  GW_PIDS=()
}
