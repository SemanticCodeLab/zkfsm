#!/usr/bin/env bash
# Large-object tier transport benchmark: two zkfsm binaries (OLD, NEW) each run as the
# hot node over the same kind of remote tier (zkfsm, plain HTTP and HTTPS), timing a
# lifecycle transition (tier write) and full plus ranged read-through (tier reads).
# HTTPS tiers use a host name: the old std client did not match IP-address SANs.
# usage: bench/tier_transport.sh OLD_BIN NEW_BIN [size_mb] [runs]
set -euo pipefail
OLD="$1" NEW="$2" MB="${3:-512}" RUNS="${4:-3}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$WORK"; }
trap cleanup EXIT
freeport() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
BIN="$NEW"
source "$ROOT/tests/tls_remote.sh"
tls_pki
AK=benchadmin SK=bench-admin-secret-0123
export AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_DEFAULT_REGION=us-east-1 AWS_PAGER=""
head -c "$((MB << 20))" /dev/urandom >"$WORK/obj"
now() { date +%s.%N; }
since() { python3 -c "import sys; print(f'{float(sys.argv[2])-float(sys.argv[1]):.2f}')" "$1" "$(now)"; }

start() { # name port [flags] -> pid in LAST
  local n="$1" p="$2"; shift 2
  ZKFSM_ILM_DAY_SECONDS=1 ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$@" --listen "127.0.0.1:$p" 2>>"$WORK/$n.log" &
  LAST=$!; PIDS+=("$LAST")
}
up() { for _ in $(seq 200); do curl -sk -o /dev/null "$1/" && return 0; sleep 0.1; done; return 1; }
sclass() { aws --endpoint-url "$1" s3api head-object --bucket data --key obj | python3 -c 'import json,sys; print(json.load(sys.stdin).get("StorageClass",""))'; }

one() { # label hot-bin scheme run
  local label="$1" hb="$2" scheme="$3" run="$4"
  local rp hp; rp="$(freeport)"; hp="$(freeport)"
  local rd="$WORK/r-$label-$scheme-$run" hd="$WORK/h-$label-$scheme-$run"
  mkdir -p "$rd" "$hd"
  if [[ "$scheme" == https ]]; then
    start rem "$rp" "$NEW" --data "$rd" --tls-cert "$PKI/server.pem" --tls-key "$PKI/server.key"; local rpid=$LAST
  else start rem "$rp" "$NEW" --data "$rd"; local rpid=$LAST; fi
  up "$scheme://127.0.0.1:$rp"
  curl -sk -o /dev/null --aws-sigv4 aws:amz:us-east-1:s3 --user "$AK:$SK" -X PUT "$scheme://127.0.0.1:$rp/tier"
  SSL_CERT_FILE="$PKI/ca.pem" ZKFSM_TIER_CA_FILE="$PKI/ca.pem" start hot "$hp" "$hb" --data "$hd" --lifecycle-interval 1; local hpid=$LAST
  local H="http://127.0.0.1:$hp"
  up "$H"
  printf '{"Version":"v1","Type":"minio","Name":"WARM","MinIO":{"Endpoint":"%s://localhost:%s","AccessKey":"%s","SecretKey":"%s","Bucket":"tier","Prefix":"b/"}}' "$scheme" "$rp" "$AK" "$SK" |
    python3 "$ROOT/tests/madmin_encrypt.py" "$SK" >"$WORK/t.enc"
  curl -s -o /dev/null --aws-sigv4 aws:amz:us-east-1:s3 --user "$AK:$SK" -X PUT --data-binary @"$WORK/t.enc" "$H/minio/admin/v3/tier"
  aws --endpoint-url "$H" s3 mb s3://data >/dev/null
  aws --endpoint-url "$H" s3 cp "$WORK/obj" s3://data/obj >/dev/null
  local t0; t0="$(now)"
  aws --endpoint-url "$H" s3api put-bucket-lifecycle-configuration --bucket data --lifecycle-configuration \
    '{"Rules":[{"ID":"t","Status":"Enabled","Filter":{"Prefix":""},"Transitions":[{"Days":1,"StorageClass":"WARM"}]}]}'
  until [[ "$(sclass "$H")" == WARM ]]; do sleep 0.05; done
  local tw; tw="$(since "$t0")"
  t0="$(now)"; curl -s --aws-sigv4 aws:amz:us-east-1:s3 --user "$AK:$SK" -o /dev/null "$H/data/obj"; local tr; tr="$(since "$t0")"
  t0="$(now)"
  for i in $(seq 0 63); do
    curl -s --aws-sigv4 aws:amz:us-east-1:s3 --user "$AK:$SK" -o /dev/null -H "Range: bytes=$((i * 1048576))-$((i * 1048576 + 65535))" "$H/data/obj"
  done
  local tg; tg="$(since "$t0")"
  echo "$label $scheme run=$run transition_s=$tw read_s=$tr read_MiBps=$(python3 -c "print(round($MB/$tr))") ranges64_s=$tg"
  kill "$hpid" "$rpid"; wait "$hpid" "$rpid" 2>/dev/null || true
}

for scheme in http https; do
  for run in $(seq "$RUNS"); do
    one old "$OLD" "$scheme" "$run"
    one new "$NEW" "$scheme" "$run"
  done
done
