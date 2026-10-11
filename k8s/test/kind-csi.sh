#!/usr/bin/env bash
# zkfsm on csi.zkfsm.io volumes in kind. Kind nodes share the host's loop devices,
# so drives are directories (--drive-dir); mkfs/mount of block devices is unit-tested only.
# Expects the cluster, images and operator from kind-e2e.sh (KEEP=1); env: CLUSTER, KUBECONFIG.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CLUSTER="${CLUSTER:-zc-k8s}"
NS=csitest
for n in $(kind get nodes --name "$CLUSTER" | grep worker); do
  docker exec "$n" mkdir -p /var/lib/zkfsm-drives/d1 /var/lib/zkfsm-drives/d2 /var/lib/zkfsm-drives/d3 /var/lib/zkfsm-drives/d4
done
kind load docker-image --name "$CLUSTER" zc-k8s/zkfsm-csi:dev >/dev/null
helm upgrade --install zkcsi "$ROOT/helm/zkfsm-csi" -n zkfsm-csi --create-namespace \
  --set image.repository=zc-k8s/zkfsm-csi --set image.tag=dev --set driveDir=/var/lib/zkfsm-drives >/dev/null
kubectl -n zkfsm-csi rollout status ds --timeout=180s >/dev/null
kubectl delete ns "$NS" --ignore-not-found --wait=true >/dev/null
kubectl create ns "$NS" >/dev/null
kubectl -n "$NS" create secret generic root --from-literal=accessKey=admin --from-literal=secretKey=admin-secret-123 >/dev/null
kubectl apply -f - >/dev/null <<EOF
apiVersion: zkfsm.io/v1
kind: Cluster
metadata: {name: direct, namespace: $NS}
spec:
  image: zc-k8s/zkfsm:v1
  credsSecret: root
  pools: [{name: p0, servers: 4, drivesPerServer: 2, size: 2Gi, storageClassName: zkfsm-direct}]
  iam: {buckets: [{name: b}]}
EOF
for _ in $(seq 120); do [[ "$(kubectl -n "$NS" get zkc direct -o jsonpath='{.status.phase}')" == Ready ]] && break; sleep 3; done
phase=$(kubectl -n "$NS" get zkc direct -o jsonpath='{.status.phase}')
bound=$(kubectl -n "$NS" get pvc --no-headers | grep -c Bound || true)
drivers=$(kubectl get pv -o jsonpath='{range .items[*]}{.spec.csi.driver}{"\n"}{end}' | grep -c csi.zkfsm.io || true)
echo "phase=$phase bound_pvcs=$bound csi_pvs=$drivers"
[[ "$phase" == Ready && "$bound" == 8 && "$drivers" -ge 8 ]]
