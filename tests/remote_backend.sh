#!/usr/bin/env bash
# End-to-end test of the remote S3 backend against a throwaway MinIO container.
# Also runs the Azure Blob suite against Azurite when that image is available.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOCKER="${DOCKER:-docker}"
freeport() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
CIDS=()
cleanup() { for c in "${CIDS[@]}"; do "$DOCKER" rm -f "$c" >/dev/null 2>&1 || true; done; }
trap cleanup EXIT

wait_http() { # url
  for _ in $(seq 100); do curl -s -o /dev/null "$1" && return 0; sleep 0.2; done
  echo "service at $1 did not start"; return 1
}

S3_PORT="$(freeport)"
export ZKFSM_S3_ACCESS_KEY="${ZKFSM_S3_ACCESS_KEY:-zkfsmtest}"
export ZKFSM_S3_SECRET_KEY="${ZKFSM_S3_SECRET_KEY:-zkfsmtestsecret$RANDOM$RANDOM}"
CIDS+=("$("$DOCKER" run -d --rm -p "127.0.0.1:$S3_PORT:9000" \
  -e MINIO_ROOT_USER="$ZKFSM_S3_ACCESS_KEY" -e MINIO_ROOT_PASSWORD="$ZKFSM_S3_SECRET_KEY" \
  "${MINIO_IMAGE:-cgr.dev/chainguard/minio}" server /data)")
export ZKFSM_S3_ENDPOINT="http://127.0.0.1:$S3_PORT"
wait_http "$ZKFSM_S3_ENDPOINT/minio/health/live"

if [[ "${SKIP_AZURITE:-0}" != 1 ]] && "$DOCKER" image inspect "${AZURITE_IMAGE:-mcr.microsoft.com/azure-storage/azurite}" >/dev/null 2>&1; then
  AZ_PORT="$(freeport)"
  CIDS+=("$("$DOCKER" run -d --rm -p "127.0.0.1:$AZ_PORT:10000" \
    "${AZURITE_IMAGE:-mcr.microsoft.com/azure-storage/azurite}" azurite-blob --blobHost 0.0.0.0 --loose)")
  # Azurite's well-known development account (public, not a secret).
  export ZKFSM_AZURE_ENDPOINT="http://127.0.0.1:$AZ_PORT/devstoreaccount1"
  export ZKFSM_AZURE_ACCOUNT=devstoreaccount1
  export ZKFSM_AZURE_KEY="Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
  wait_http "$ZKFSM_AZURE_ENDPOINT"
else
  echo "azurite image not present; Azure live test will be skipped"
fi

cd "$ROOT"
zig build test-remote -Doptimize="${OPTIMIZE:-ReleaseSafe}" --summary all
