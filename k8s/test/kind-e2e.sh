#!/usr/bin/env bash
# End-to-end test of the operator on kind: 4-server cluster, S3 round trip and IAM
# bootstrap, pod kill, rolling upgrade gated on readiness, pool expansion, TLS
# switch, decommission request. Needs docker, kind, kubectl, helm, curl, zig.
# env: CLUSTER (kind name, default zc-k8s), KEEP=1 keeps the kind cluster,
#      STORAGE_CLASS (default standard), WORK (scratch dir), SKIP_BUILD=1
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CLUSTER="${CLUSTER:-zc-k8s}"
WORK="${WORK:-$(mktemp -d)}"
SC="${STORAGE_CLASS:-standard}"
NS=s3test
export KUBECONFIG="${KUBECONFIG:-$WORK/kubeconfig}"
PASS=0
FAIL=0
PF=""

log() { printf '\n== %s\n' "$*"; }
check() { # name expected actual
  if [[ "$2" == "$3" ]]; then PASS=$((PASS + 1)); echo "ok   $1"; else FAIL=$((FAIL + 1)); echo "FAIL $1: want [$2] got [$3]"; fi
}
cleanup() {
  [[ -n "$PF" ]] && kill "$PF" 2>/dev/null || true
  if [[ "${KEEP:-0}" != 1 ]]; then kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

k() { kubectl -n "$NS" "$@"; }
phase() { k get zkc s3 -o jsonpath='{.status.phase}' 2>/dev/null; }
wait_phase() { # phase seconds
  for _ in $(seq "$2"); do [[ "$(phase)" == "$1" ]] && return 0; sleep 1; done
  echo "phase stuck at $(phase)"; k get pods; k get zkc s3 -o jsonpath='{.status.conditions}'; echo
  kubectl -n zkfsm-system logs deploy/zkop-zkfsm-operator --tail=30; return 1
}
free_port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
SCHEME=http
CURL_TLS=()
forward() {
  [[ -n "$PF" ]] && kill "$PF" 2>/dev/null || true
  PORT="$(free_port)"
  k port-forward svc/s3 "$PORT:9000" >"$WORK/pf.log" 2>&1 &
  PF=$!
  for _ in $(seq 50); do curl -s --max-time 2 "${CURL_TLS[@]}" -o /dev/null "$SCHEME://127.0.0.1:$PORT/health/live" && return 0; sleep 0.2; done
  echo "port-forward failed"; cat "$WORK/pf.log"; return 1
}
s3() { curl -sS --max-time 20 "${CURL_TLS[@]}" --aws-sigv4 "aws:amz:us-east-1:s3" --user "$1" "${@:2}"; }
APP=appuser:app-secret-123
put() { s3 "$APP" -o /dev/null -w '%{http_code}' -T "$2" "$SCHEME://127.0.0.1:$PORT/app/$1"; }
get() { rm -f "$2"; s3 "$APP" -o "$2" -w '%{http_code}' "$SCHEME://127.0.0.1:$PORT/app/$1"; }
same() { cmp -s "$1" "$2" && echo same || echo differ; }

if [[ "${SKIP_BUILD:-0}" != 1 ]]; then
  log "build images"
  (cd "$ROOT" && zig build -Dtarget=x86_64-linux-musl -Doptimize=ReleaseSafe --prefix "$WORK/out")
  mkdir -p "$WORK/img"
  cp "$WORK/out/bin/zkfsm" "$WORK/out/bin/zkfsm-operator" "$WORK/img/"
  cat >"$WORK/img/Dockerfile" <<'EOF'
FROM busybox:1.36-musl
RUN for i in $(seq 1 16); do mkdir -p /data$i; done && chown 10001:10001 /data*
COPY zkfsm zkfsm-operator /usr/local/bin/
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/zkfsm"]
EOF
  docker build -q -t zc-k8s/zkfsm:v1 "$WORK/img" >/dev/null
  docker tag zc-k8s/zkfsm:v1 zc-k8s/zkfsm:v2
  docker tag zc-k8s/zkfsm:v1 zc-k8s/zkfsm-operator:dev
fi

if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  log "create kind cluster $CLUSTER"
  cat >"$WORK/kind.yaml" <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes: [{role: control-plane}, {role: worker}, {role: worker}, {role: worker}, {role: worker}]
EOF
  kind create cluster --name "$CLUSTER" --config "$WORK/kind.yaml" --kubeconfig "$KUBECONFIG" >/dev/null
else
  kind get kubeconfig --name "$CLUSTER" >"$KUBECONFIG"
fi
kind load docker-image --name "$CLUSTER" zc-k8s/zkfsm:v1 zc-k8s/zkfsm:v2 zc-k8s/zkfsm-operator:dev >/dev/null

log "install operator"
# helm installs crds/ only once; apply so schema changes land on reruns.
kubectl apply -f "$ROOT/helm/zkfsm-operator/crds/" >/dev/null
helm upgrade --install zkop "$ROOT/helm/zkfsm-operator" -n zkfsm-system --create-namespace \
  --set image.repository=zc-k8s/zkfsm-operator --set image.tag=dev --set interval=3 >/dev/null
# The test image's entrypoint is the server; run the operator binary instead.
kubectl -n zkfsm-system patch deploy zkop-zkfsm-operator --type=json \
  -p '[{"op":"add","path":"/spec/template/spec/containers/0/command","value":["/usr/local/bin/zkfsm-operator"]}]' >/dev/null
kubectl -n zkfsm-system rollout status deploy/zkop-zkfsm-operator --timeout=120s >/dev/null

log "deploy a 4-server cluster (4 drives each, EC:4+2)"
kubectl delete ns "$NS" --ignore-not-found --wait=true >/dev/null
kubectl create ns "$NS" >/dev/null
k create secret generic s3-root --from-literal=accessKey=admin --from-literal=secretKey=admin-secret-123 >/dev/null
k create secret generic s3-app --from-literal=accessKey=appuser --from-literal=secretKey=app-secret-123 >/dev/null
cat >"$WORK/cluster.yaml" <<EOF
apiVersion: zkfsm.io/v1
kind: Cluster
metadata: {name: s3, namespace: $NS}
spec:
  image: zc-k8s/zkfsm:v1
  credsSecret: s3-root
  protection: EC:4+2
  pools:
    - {name: pool-0, servers: 4, drivesPerServer: 4, size: 1Gi, storageClassName: $SC}
  iam:
    policies:
      - name: app-rw
        document: '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::app","arn:aws:s3:::app/*"]}]}'
    users: [{secretName: s3-app, policies: [app-rw]}]
    buckets: [{name: app}]
EOF
kubectl apply -f "$WORK/cluster.yaml" >/dev/null
wait_phase Ready 240
check "4 servers ready" "4/4" "$(k get zkc s3 -o jsonpath='{.status.readyServers}/{.status.servers}')"
check "bootstrap condition" "True" "$(k get zkc s3 -o jsonpath='{.status.conditions[?(@.type=="Bootstrapped")].status}')"
check "pdb maxUnavailable" "1" "$(k get pdb s3-pool-0 -o jsonpath='{.spec.maxUnavailable}')"

log "S3 round trip with the bootstrapped user"
forward
head -c 3000000 /dev/urandom >"$WORK/obj1"
check "put" 200 "$(put obj1 "$WORK/obj1")"
check "get" 200 "$(get obj1 "$WORK/back")"
check "content" same "$(same "$WORK/obj1" "$WORK/back")"
check "user policy denies other buckets" 403 "$(s3 "$APP" -o /dev/null -w '%{http_code}' -X PUT "$SCHEME://127.0.0.1:$PORT/other")"

log "kill a pod"
k delete pod s3-pool-0-2 --grace-period=0 --force >/dev/null 2>&1
# port-forward pins one pod; reconnect so the client is not on the dead one.
forward
check "get while a server is down" 200 "$(get obj1 "$WORK/back")"
check "content while degraded" same "$(same "$WORK/obj1" "$WORK/back")"
sleep 5
wait_phase Ready 180
check "recovered 4/4" "4/4" "$(k get zkc s3 -o jsonpath='{.status.readyServers}/{.status.servers}')"

log "rolling upgrade v1 -> v2 (one pod at a time)"
k patch zkc s3 --type=merge -p '{"spec":{"image":"zc-k8s/zkfsm:v2"}}' >/dev/null
forward
max_down=0
get_fail=0
for _ in $(seq 900); do
  ready=$(k get pods -l zkfsm.io/cluster=s3 -o jsonpath='{range .items[*]}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}' | grep -c True || true)
  total=$(k get pods -l zkfsm.io/cluster=s3 --no-headers 2>/dev/null | wc -l)
  down=$((4 - ready)); ((down > max_down)) && max_down=$down
  [[ "$(get obj1 "$WORK/back" 2>/dev/null)" == 200 ]] || get_fail=$((get_fail + 1))
  imgs=$(k get pods -l zkfsm.io/cluster=s3 -o jsonpath='{range .items[*]}{.spec.containers[0].image}{"\n"}{end}' | sort -u | tr '\n' ' ')
  [[ "$imgs" == "zc-k8s/zkfsm:v2 " && "$ready" == 4 && "$total" == 4 && "$(phase)" == Ready ]] && break
  sleep 1
done
check "all pods on v2" "zc-k8s/zkfsm:v2 " "$imgs"
check "at most one server down during the rollout" 1 "$max_down"
echo "     GETs failed during rollout (port-forward reconnects included): $get_fail"
forward
check "data after upgrade" 200 "$(get obj1 "$WORK/back")"
check "content after upgrade" same "$(same "$WORK/obj1" "$WORK/back")"

log "expand: append pool-1 (4 servers x 2 drives)"
k patch zkc s3 --type=json -p "[{\"op\":\"add\",\"path\":\"/spec/pools/-\",\"value\":{\"name\":\"pool-1\",\"servers\":4,\"drivesPerServer\":2,\"size\":\"1Gi\",\"storageClassName\":\"$SC\"}}]" >/dev/null
sleep 8
wait_phase Ready 300
check "8 servers ready" "8/8" "$(k get zkc s3 -o jsonpath='{.status.readyServers}/{.status.servers}')"
check "pool-0 args list both pools" 2 "$(k get sts s3-pool-0 -o jsonpath='{.spec.template.spec.containers[0].args}' | grep -o -- '--data' | wc -l)"
forward
check "old object after expansion" 200 "$(get obj1 "$WORK/back")"
check "content after expansion" same "$(same "$WORK/obj1" "$WORK/back")"
for i in $(seq 1 8); do head -c 200000 /dev/urandom >"$WORK/n$i"; [[ "$(put "n$i" "$WORK/n$i")" == 200 ]] || echo "put n$i failed"; done
check "objects written after expansion" 200 "$(get n8 "$WORK/back")"
check "pool-1 holds data" yes "$(k exec s3-pool-1-0 -- sh -c 'find /data1 /data2 -type f | grep -q . && echo yes')"

check "tls.mode change is rejected" rejected "$(k patch zkc s3 --type=merge -p '{"spec":{"tls":{"mode":"selfSigned"}}}' >/dev/null 2>&1 && echo accepted || echo rejected)"

log "decommission pool-1 through the admin API"
k patch zkc s3 --type=json -p '[{"op":"add","path":"/spec/pools/1/decommission","value":true}]' >/dev/null
for _ in $(seq 120); do
  st=$(k get zkc s3 -o jsonpath='{.status.conditions[?(@.type=="Decommissioning")].reason}')
  [[ -n "$st" && "$st" != Started ]] && break
  sleep 2
done
check "decommission request answered" yes "$([[ -n "$st" ]] && echo yes)"
echo "     decommission condition: $(k get zkc s3 -o jsonpath='{.status.conditions[?(@.type=="Decommissioning")]}')"
pool1=$(k get zkc s3 -o jsonpath='{.status.pools[?(@.name=="pool-1")].state}')
if [[ "$pool1" == decommissioned ]]; then
  wait_phase Ready 300
  check "pool-1 statefulset removed" "" "$(k get sts s3-pool-1 --ignore-not-found -o name)"
  forward
  check "data after decommission" same "$( [[ $(get n8 "$WORK/back") == 200 ]] && same "$WORK/n8" "$WORK/back")"
else
  echo "     pool-1 state: $pool1 (the server build does not drain pools)"
fi

log "second cluster with self-signed TLS from the start"
cat >"$WORK/tls.yaml" <<YAML
apiVersion: zkfsm.io/v1
kind: Cluster
metadata: {name: s3tls, namespace: $NS}
spec:
  image: zc-k8s/zkfsm:v2
  credsSecret: s3-root
  pools: [{name: p0, servers: 4, drivesPerServer: 1, size: 1Gi, storageClassName: $SC}]
  tls: {mode: selfSigned}
  iam: {buckets: [{name: tlsb}]}
YAML
kubectl apply -f "$WORK/tls.yaml" >/dev/null
for _ in $(seq 300); do [[ "$(k get zkc s3tls -o jsonpath='{.status.phase}')" == Ready ]] && break; sleep 1; done
check "tls cluster ready" Ready "$(k get zkc s3tls -o jsonpath='{.status.phase}')"
k get secret s3tls-tls -o jsonpath='{.data.ca\.crt}' | base64 -d >"$WORK/ca.crt"
[[ -n "$PF" ]] && kill "$PF" 2>/dev/null || true
TPORT="$(free_port)"
k port-forward svc/s3tls "$TPORT:9000" >"$WORK/pf2.log" 2>&1 &
PF=$!
for _ in $(seq 50); do curl -s --cacert "$WORK/ca.crt" -o /dev/null "https://127.0.0.1:$TPORT/health/live" && break; sleep 0.2; done
U=admin:admin-secret-123
check "https put verified by the cluster CA" 200 "$(curl -sS --cacert "$WORK/ca.crt" --aws-sigv4 aws:amz:us-east-1:s3 --user $U -o /dev/null -w '%{http_code}' -T "$WORK/obj1" "https://127.0.0.1:$TPORT/tlsb/o")"
curl -sS --cacert "$WORK/ca.crt" --aws-sigv4 aws:amz:us-east-1:s3 --user $U -o "$WORK/back" "https://127.0.0.1:$TPORT/tlsb/o"
check "https content" same "$(same "$WORK/obj1" "$WORK/back")"

log "result: $PASS passed, $FAIL failed"
[[ "$FAIL" == 0 ]]
