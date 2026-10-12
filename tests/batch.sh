#!/usr/bin/env bash
# Batch jobs end to end with `mc batch`: generate templates, then real replicate
# (local to remote with versions and delete markers, remote to local, local to
# local), keyrotate (SSE-S3 to SSE-KMS, versions kept), and expire jobs; list,
# describe, status, cancel of a long job, and resume after a restart.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
MC="${MC:-$(command -v mc || true)}"
if [[ -z "$MC" ]] || ! "$MC" --version >/dev/null 2>&1; then echo "batch.sh needs the MinIO client (set MC)"; exit 1; fi
declare -A PID=()
cleanup() {
  for p in "${PID[@]}"; do kill -9 "$p" 2>/dev/null || true; done
  if [[ -n "${KEEP_WORK:-}" ]]; then echo "work dir kept: $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

pass=0
fail=0
check() { # name expected actual
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); echo "ok   $1"
  else fail=$((fail + 1)); echo "FAIL $1: expected [$2] got [$3]"; fi
}
freeport() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
jget() { python3 -c "import json,sys; d=json.loads(sys.stdin.read().strip().splitlines()[-1]); print(d$1)"; }

AK="batchadmin"
SK="batch-admin-secret-0123"
export MC_CONFIG_DIR="$WORK/mc"
(cd "$ROOT" && zig build)
BIN="$ROOT/zig-out/bin/zkfsm"
PA="$(freeport)"
PB="$(freeport)"
run() { # name args...
  local n="$1"; shift
  ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$BIN" "$@" >>"$WORK/$n.log" 2>&1 &
  PID[$n]=$!
}
ready() { # port
  for _ in $(seq 300); do [[ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$1/health/ready")" == 200 ]] && return 0; sleep 0.1; done
  echo "server on $1 not ready"; tail -n 20 "$WORK"/*.log; exit 1
}
startA() { run a --data "$WORK/a" --listen "127.0.0.1:$PA" --scan-interval 0 --kms-backend local --kms-dir "$WORK/kms"; ready "$PA"; }
stopA() { kill -9 "${PID[a]}" 2>/dev/null || true; wait "${PID[a]}" 2>/dev/null || true; unset "PID[a]"; }
startA
run b --data "$WORK/b" --listen "127.0.0.1:$PB" --scan-interval 0; ready "$PB"
"$MC" alias set a "http://127.0.0.1:$PA" "$AK" "$SK" >/dev/null
"$MC" alias set b "http://127.0.0.1:$PB" "$AK" "$SK" >/dev/null

# start FILE -> job id
start() { "$MC" --json batch start a "$1" | jget '["result"]["id"]'; }
state() { python3 -c "import json,sys; m=json.loads(sys.stdin.read().strip().splitlines()[-1])['metric']; print('complete' if m['complete'] else ('failed' if m['failed'] else 'running'))"; }
# wait_done ID -> complete|failed; `mc batch status` follows a running job to its end.
wait_done() {
  local st=""
  for _ in $(seq 60); do
    st="$(timeout 30 "$MC" --json batch status a "$1" 2>/dev/null | state 2>/dev/null || true)"
    [[ "$st" == complete || "$st" == failed ]] && break
    sleep 0.5
  done
  echo "$st"
}
metric() { # id python-path
  timeout 20 "$MC" --json batch status a "$1" | tail -n 1 | jget "['metric']$2"
}
versions() { # alias/bucket -> sorted "key version kind" lines
  "$MC" ls --versions --recursive --json "$1" | python3 -c "
import json,sys
rows=[]
for l in sys.stdin:
    d=json.loads(l)
    rows.append('%s %s %s' % (d['key'], d.get('versionId',''), 'DEL' if d.get('isDeleteMarker') else 'OBJ'))
print('\n'.join(sorted(rows)))"
}

# ---- generate ----
check "generate list" "replicate keyrotate expire" "$("$MC" batch generate a list | xargs)"
for t in replicate keyrotate expire; do
  check "generate $t" 1 "$("$MC" batch generate a "$t" | grep -c "^$t:")"
done
if "$MC" batch generate a catalog >/dev/null 2>&1; then check "generate unknown type refused" refused accepted; else check "generate unknown type refused" refused refused; fi

# ---- replicate: local -> remote, versions and delete markers preserved ----
"$MC" mb --with-versioning a/src >/dev/null
"$MC" mb --with-versioning b/dst >/dev/null
for i in 1 2 3; do
  echo "first $i" | "$MC" pipe a/src/docs/f$i.txt >/dev/null
  echo "second $i" | "$MC" pipe a/src/docs/f$i.txt >/dev/null
done
echo "tagged" | "$MC" pipe --tags "team=blue" a/src/docs/tagged.txt >/dev/null
echo "gone" | "$MC" pipe a/src/docs/gone.txt >/dev/null
"$MC" rm a/src/docs/gone.txt >/dev/null
echo "other" | "$MC" pipe a/src/other/x.txt >/dev/null
cat >"$WORK/rep.yaml" <<EOF
replicate:
  apiVersion: v1
  source:
    type: minio
    bucket: src
    prefix: docs/
  target:
    type: minio
    bucket: dst
    endpoint: "http://127.0.0.1:$PB"
    credentials:
      accessKey: $AK
      secretKey: $SK
  flags:
    retry:
      attempts: 2
      delay: "100ms"
EOF
ID="$(start "$WORK/rep.yaml")"
check "replicate job id" 22 "${#ID}"
check "replicate completes" complete "$(wait_done "$ID")"
check "replicated versions and markers" "$(versions a/src/docs/)" "$(versions b/dst/docs/)"
check "replicated object count" 8 "$(metric "$ID" '["replicate"]["objects"]')"
check "replicated delete markers" 1 "$(metric "$ID" '["replicate"]["deleteMarkers"]')"
check "replicated content" "second 2" "$("$MC" cat b/dst/docs/f2.txt)"
check "replicated tags" "blue" "$("$MC" tag list --json b/dst/docs/tagged.txt | jget '["tagset"]["team"]')"
check "prefix respected" 0 "$("$MC" ls --recursive b/dst | grep -c other/ || true)"
# A second run finds every version present and transfers nothing.
ID2="$(start "$WORK/rep.yaml")"
check "rerun completes" complete "$(wait_done "$ID2")"
check "rerun transfers no bytes" 0 "$(metric "$ID2" '["replicate"]["bytesTransferred"]')"

# ---- replicate: remote -> local, with a filter ----
"$MC" mb b/pull >/dev/null
echo "img" | "$MC" pipe --attr "Content-Type=image/png" b/pull/a.png >/dev/null
echo "txt" | "$MC" pipe --attr "Content-Type=text/plain" b/pull/b.txt >/dev/null
"$MC" mb a/pulled >/dev/null
cat >"$WORK/pull.yaml" <<EOF
replicate:
  apiVersion: v1
  source:
    type: minio
    bucket: pull
    endpoint: "http://127.0.0.1:$PB"
    credentials:
      accessKey: $AK
      secretKey: $SK
  target:
    type: minio
    bucket: pulled
    prefix: in
  flags:
    filter:
      metadata:
        - key: content-type
          value: "image/*"
EOF
ID="$(start "$WORK/pull.yaml")"
check "pull completes" complete "$(wait_done "$ID")"
check "pulled matching object" "img" "$("$MC" cat a/pulled/in/a.png)"
check "pull filter skipped text" 0 "$("$MC" ls --recursive a/pulled | grep -c b.txt || true)"

# ---- replicate: local -> local ----
"$MC" mb a/copy >/dev/null
printf 'replicate:\n  apiVersion: v1\n  source:\n    type: minio\n    bucket: src\n    prefix: other/\n  target:\n    type: minio\n    bucket: copy\n' >"$WORK/local.yaml"
ID="$(start "$WORK/local.yaml")"
check "local replicate completes" complete "$(wait_done "$ID")"
check "local replicate content" other "$("$MC" cat a/copy/other/x.txt)"

# ---- keyrotate: SSE-S3 -> SSE-KMS(newkey), versions kept ----
"$MC" admin kms key create a newkey >/dev/null
"$MC" mb --with-versioning a/krot >/dev/null
"$MC" encrypt set sse-s3 a/krot >/dev/null
echo "v1" | "$MC" pipe a/krot/k1 >/dev/null
echo "v2" | "$MC" pipe a/krot/k1 >/dev/null
echo "solo" | "$MC" pipe a/krot/k2 >/dev/null
echo "plain" | "$MC" pipe a/krot/plain/p >/dev/null || true
check "before rotation SSE-S3" 1 "$("$MC" stat a/krot/k2 | grep -c 'SSE-S3')"
BEFORE="$(versions a/krot)"
cat >"$WORK/rot.yaml" <<EOF
keyrotate:
  apiVersion: v1
  bucket: krot
  encryption:
    type: sse-kms
    key: newkey
EOF
ID="$(start "$WORK/rot.yaml")"
check "keyrotate completes" complete "$(wait_done "$ID")"
check "keyrotate objects" 4 "$(metric "$ID" '["rotation"]["objects"]')"
check "rotated key id" 1 "$("$MC" stat a/krot/k2 | grep -c 'SSE-KMS (newkey)')"
check "rotated content" solo "$("$MC" cat a/krot/k2)"
check "rotation keeps version ids" "$BEFORE" "$(versions a/krot)"
OLDV="$("$MC" ls --versions --json a/krot/k1 | python3 -c "import json,sys; print([d for d in map(json.loads, sys.stdin) if d['versionOrdinal'] == 1][0]['versionId'])")"
check "old version rotated" 1 "$("$MC" stat --version-id "$OLDV" a/krot/k1 | grep -c 'SSE-KMS (newkey)')"
check "old version content" v1 "$("$MC" cat --version-id "$OLDV" a/krot/k1)"

# ---- expire ----
"$MC" mb --with-versioning a/exp >/dev/null
for k in a.log b.log keep.txt; do
  echo "1" | "$MC" pipe a/exp/$k >/dev/null
  echo "2" | "$MC" pipe a/exp/$k >/dev/null
done
echo "x" | "$MC" pipe a/exp/dead.txt >/dev/null
"$MC" rm a/exp/dead.txt >/dev/null
cat >"$WORK/exp.yaml" <<EOF
expire:
  apiVersion: v1
  bucket: exp
  rules:
    - type: object
      name: "*.log"
      size:
        lessThan: 1KiB
    - type: deleted
      name: "dead*"
EOF
ID="$(start "$WORK/exp.yaml")"
check "expire completes" complete "$(wait_done "$ID")"
check "expired objects" 5 "$(metric "$ID" '["expired"]["objects"]')"
check "expired markers" 1 "$(metric "$ID" '["expired"]["deleteMarkers"]')"
check "expire leaves only keep.txt" "keep.txt keep.txt" "$(versions a/exp | awk '{print $1}' | xargs)"

# ---- list / describe / cancel a long job, resume after restart ----
cat >"$WORK/slow.yaml" <<EOF
replicate:
  apiVersion: v1
  source:
    type: minio
    bucket: src
  target:
    type: minio
    bucket: nowhere
    endpoint: "http://127.0.0.1:1"
    credentials:
      accessKey: x
      secretKey: y
  flags:
    retry:
      attempts: 100
      delay: "1s"
EOF
SLOW="$(start "$WORK/slow.yaml")"
check "list shows jobs" 1 "$("$MC" --json batch list a | jget '["jobs"]' | grep -c "$SLOW")"
check "list by type" 0 "$("$MC" --json batch list a --type expire | jget '["jobs"]' | grep -c "$SLOW" || true)"
check "describe active job" 1 "$("$MC" batch describe a "$SLOW" | grep -c 'endpoint: "http://127.0.0.1:1"')"
check "status streams a running job" running "$( (timeout 3 "$MC" --json batch status a "$SLOW" || true) | head -n 1 | state)"
stopA
startA
for _ in $(seq 50); do grep -q "resuming replicate job $SLOW" "$WORK/a.log" && break; sleep 0.1; done
check "job resumed after restart" 1 "$(grep -c "resuming replicate job $SLOW" "$WORK/a.log")"
check "resumed job describable" 1 "$("$MC" batch describe a "$SLOW" | grep -c '^replicate:')"
check "cancel" "success $SLOW" "$("$MC" --json batch cancel a "$SLOW" | jget '["status"] + " " + d["job-id"]')"
check "canceled job ends failed" failed "$(wait_done "$SLOW")"
if "$MC" batch describe a "$SLOW" >/dev/null 2>&1; then check "canceled job not describable" no yes; else check "canceled job not describable" no no; fi
if "$MC" batch cancel a "$SLOW" >/dev/null 2>&1; then check "second cancel refused" refused accepted; else check "second cancel refused" refused refused; fi
check "finished jobs survive restart" complete "$(timeout 20 "$MC" --json batch status a "$ID" | state)"

# ---- bad input ----
printf 'expire:\n  bucket: exp\n  rules: [\n' >"$WORK/bad.yaml"
if "$MC" batch start a "$WORK/bad.yaml" >/dev/null 2>&1; then check "malformed job refused" refused accepted; else check "malformed job refused" refused refused; fi
printf 'expire:\n  bucket: nosuch\n  rules:\n    - type: object\n' >"$WORK/nob.yaml"
if "$MC" batch start a "$WORK/nob.yaml" >/dev/null 2>&1; then check "missing bucket refused" refused accepted; else check "missing bucket refused" refused refused; fi
"$MC" admin user add a nobody nobody-secret-1 >/dev/null
"$MC" alias set n "http://127.0.0.1:$PA" nobody nobody-secret-1 >/dev/null
if "$MC" batch list n >/dev/null 2>&1; then check "unprivileged list denied" denied allowed; else check "unprivileged list denied" denied denied; fi

echo "batch.sh: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
