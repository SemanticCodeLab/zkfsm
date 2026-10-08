#!/usr/bin/env bash
# Observability end-to-end: OTLP/HTTP export of traces, logs, and metrics (an in-test
# receiver, then an OpenTelemetry Collector container), W3C traceparent and sampling,
# metrics v3 with mc admin prometheus, mc admin trace / logs, server access log
# delivery (format, permissions, crash safety), and a 3-node cluster: trace context
# over internal RPC, cluster-wide trace streams, and per-node log delivery.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
PIDS=()
CONTAINER=""
cleanup() {
  for p in "${PIDS[@]}"; do kill -9 "$p" 2>/dev/null || true; done
  [[ -n "$CONTAINER" ]] && docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$WORK" 2>/dev/null || docker run --rm -v "$WORK:/w" busybox:1.36-musl rm -rf /w/col >/dev/null 2>&1 || true
  rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

MC="${MC:-$(command -v mc || true)}"
if [[ -z "$MC" ]] || ! "$MC" --version 2>/dev/null | grep -q RELEASE; then echo "observe.sh needs the MinIO client (set MC)"; exit 1; fi
export MC_CONFIG_DIR="$WORK/mc"

pass=0
fail=0
check() { # name expected actual
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); echo "ok   $1"
  else fail=$((fail + 1)); echo "FAIL $1: expected [$2] got [$3]"; fi
}
freeport() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
# wait_for SECONDS CMD... : retries CMD until it succeeds.
wait_for() { local t="$1"; shift; for _ in $(seq $((t * 10))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.1; done; return 1; }
yes_no() { if "$@" >/dev/null 2>&1; then echo yes; else echo no; fi; }

AK="obsadmin"
SK="obs-admin-secret-0123"
sig=(--aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK")

(cd "$ROOT" && zig build)
BIN="$ROOT/zig-out/bin/zkfsm"

RPORT="$(freeport)"
python3 "$ROOT/tests/otlp_receiver.py" "$RPORT" "$WORK/otlp" &
PIDS+=($!)
wait_for 5 curl -s -o /dev/null "http://127.0.0.1:$RPORT/"
OTLP="$WORK/otlp"

PORT="$(freeport)"
FPORT="$(freeport)"
EP="http://127.0.0.1:$PORT"
SPID=""
start() { # extra args...
  ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" OTEL_EXPORTER_OTLP_ENDPOINT="${OTEL_EP:-http://127.0.0.1:$RPORT}" \
    OTEL_EXPORTER_OTLP_HEADERS="x-tenant=t1,x-token=a%20b" OTEL_BSP_SCHEDULE_DELAY=200 OTEL_METRIC_EXPORT_INTERVAL=1000 \
    OTEL_RESOURCE_ATTRIBUTES="deployment.environment=test" ZKFSM_ACCESS_LOG_INTERVAL="${ALI:-1}" \
    "$BIN" --data "$WORK/d1" --listen "127.0.0.1:$PORT" --node-address "127.0.0.1:$PORT" "$@" >>"$WORK/s1.log" 2>&1 &
  SPID=$!
  PIDS+=("$SPID")
  wait_for 10 curl -sf -o /dev/null "$EP/health/ready" || { echo "server did not start"; tail -20 "$WORK/s1.log"; exit 1; }
}
stop() { kill "$SPID" 2>/dev/null || true; wait "$SPID" 2>/dev/null || true; }
kill9() { kill -9 "$SPID" 2>/dev/null || true; wait "$SPID" 2>/dev/null || true; }

# spans "python predicate on s" -> count of matching spans received so far
spans() { python3 - "$OTLP/spans.jsonl" "$1" <<'PY'
import json, sys
n = 0
try:
    for line in open(sys.argv[1]):
        s = json.loads(line)
        if eval(sys.argv[2]):
            n += 1
except FileNotFoundError:
    pass
print(n)
PY
}
has_spans() { [[ "$(spans "$1")" -ge "${2:-1}" ]]; }

start --kms-backend local --kms-dir "$WORK/kms" --ftp "127.0.0.1:$FPORT"
"$MC" alias set z "$EP" "$AK" "$SK" >/dev/null
echo "hello observability" >"$WORK/f.txt"
"$MC" mb z/obs z/logs z/denied z/granted >/dev/null
"$MC" cp -q "$WORK/f.txt" z/obs/a.txt >/dev/null

echo "--- OTLP traces"
TID=4bf92f3577b34da6a3ce929d0e0e4736
PSID=00f067aa0ba902b7
check "GET with traceparent" 200 "$(curl -s -o /dev/null -w '%{http_code}' "${sig[@]}" -H "traceparent: 00-$TID-$PSID-01" "$EP/obs/a.txt")"
wait_for 5 has_spans "s['trace_id']=='$TID' and s['name']=='s3.GetObject'"
check "root span joins the client trace" 1 "$(spans "s['trace_id']=='$TID' and s['name']=='s3.GetObject' and s['parent']=='$PSID' and s['kind']==2")"
ROOT_SID="$(python3 -c "import json;print([s['span_id'] for s in map(json.loads,open('$OTLP/spans.jsonl')) if s['trace_id']=='$TID' and s['name']=='s3.GetObject'][0])")"
check "storage child spans under the request" yes "$(yes_no has_spans "s['trace_id']=='$TID' and s['name'].startswith('storage.') and s['parent']=='$ROOT_SID'")"
check "span attributes" 1 "$(spans "s['trace_id']=='$TID' and s['attrs'].get('http.request.method')=='GET' and s['attrs'].get('http.response.status_code')==200 and s['attrs'].get('aws.s3.bucket')=='obs' and s['attrs'].get('aws.s3.key')=='a.txt' and s['attrs'].get('http.response.body.size')==20")"
check "resource attributes" yes "$(yes_no has_spans "s['resource'].get('service.name')=='zkfsm' and s['resource'].get('deployment.environment')=='test' and s['resource'].get('service.instance.id')=='127.0.0.1:$PORT'")"
check "export headers" yes "$(yes_no has_spans "s['headers'].get('x-tenant')=='t1' and s['headers'].get('x-token')=='a b'")"
"$MC" cat z/obs/missing.txt >/dev/null 2>&1 || true
wait_for 5 has_spans "s['name']=='s3.HeadObject' and s['attrs'].get('http.response.status_code')==404"
check "4xx span carries the S3 error code" yes "$(yes_no has_spans "s['attrs'].get('aws.s3.error_code')=='NoSuchKey'")"
UTID=11111111111111111111111111111111
curl -s -o /dev/null "${sig[@]}" -H "traceparent: 00-$UTID-$PSID-00" "$EP/obs/a.txt"
curl -s -o /dev/null "${sig[@]}" -H "traceparent: 00-zzzz-bad-01" "$EP/obs/a.txt"
wait_for 3 has_spans "s['name']=='admin.info'" || true
sleep 0.5
check "unsampled parent is not exported" 0 "$(spans "s['trace_id']=='$UTID'")"
"$MC" admin info z >/dev/null 2>&1 || true
wait_for 5 has_spans "s['name']=='admin.info'"
check "admin calls are spans" yes "$(yes_no has_spans "s['name']=='admin.info'")"

KTID=22222222222222222222222222222222
check "SSE-KMS PUT with traceparent" 200 "$(curl -s -o /dev/null -w '%{http_code}' "${sig[@]}" -H "traceparent: 00-$KTID-$PSID-01" -H "x-amz-server-side-encryption: aws:kms" -T "$WORK/f.txt" "$EP/obs/enc.txt")"
wait_for 5 has_spans "s['trace_id']=='$KTID' and s['name']=='s3.PutObject'"
check "KMS span in the request trace" yes "$(yes_no has_spans "s['trace_id']=='$KTID' and s['name']=='kms.GenerateDataKey' and s['kind']==3 and s['attrs'].get('kms.backend')=='local'")"
python3 - "$FPORT" "$AK" "$SK" <<'PY'
import ftplib, sys
f = ftplib.FTP()
f.connect("127.0.0.1", int(sys.argv[1]), timeout=10)
f.login(sys.argv[2], sys.argv[3])
f.cwd("/obs")
f.nlst()
f.quit()
PY
wait_for 5 has_spans "s['name']=='ftp.NLST'"
check "FTP gateway commands are root spans" yes "$(yes_no has_spans "s['name']=='ftp.CWD' and s['parent']=='' and s['kind']==2 and s['attrs'].get('path')=='/obs'")"

echo "--- OTLP logs and metrics"
logs_has() { grep -q "$1" "$OTLP/logs.jsonl" 2>/dev/null; }
wait_for 5 logs_has "listening on"
check "log record exported" yes "$(yes_no logs_has '"severity_text": "INFO", "body": "zkfsm listening on')"
metric() { python3 - "$OTLP/metrics.jsonl" "$1" <<'PY'
import json, sys
best = None
try:
    for line in open(sys.argv[1]):
        m = json.loads(line)
        if m["name"] == sys.argv[2].split("|")[0]:
            best = m
except FileNotFoundError:
    pass
if best is None:
    print("none")
else:
    want = dict(kv.split("=") for kv in sys.argv[2].split("|")[1:])
    for p in best["points"]:
        if all(p["attrs"].get(k) == v for k, v in want.items()):
            print(best["kind"], int(p.get("value", p.get("count", 0))))
            break
    else:
        print(best["kind"], "nopoint")
PY
}
metric_ready() { [[ "$(metric "minio_api_requests_total|name=GetObject")" != none ]]; }
wait_for 5 metric_ready
check "OTLP counter (cumulative sum)" "sum" "$(metric "minio_api_requests_total|name=GetObject" | cut -d' ' -f1)"
check "OTLP histogram" "histogram" "$(metric "minio_api_requests_duration_seconds|name=GetObject" | cut -d' ' -f1)"
check "OTLP gauge" "gauge" "$(metric "minio_system_drive_total_bytes" | cut -d' ' -f1)"

echo "--- sampling ratio"
stop
start --otel-sample-ratio 0
: >"$OTLP/spans.jsonl"
for _ in 1 2 3; do curl -s -o /dev/null "${sig[@]}" "$EP/obs/a.txt"; done
curl -s -o /dev/null "${sig[@]}" -H "traceparent: 00-$TID-$PSID-01" "$EP/obs/a.txt"
wait_for 5 has_spans "s['trace_id']=='$TID'"
check "ratio 0 drops new traces" 0 "$(spans "s['trace_id']!='$TID'")"
check "sampled parent still exported" yes "$(yes_no has_spans "s['trace_id']=='$TID' and s['name']=='s3.GetObject'")"
stop
start --otel-sample-ratio 1
check "bad sample ratio refused" 2 "$("$BIN" --otel-sample-ratio 1.5 >/dev/null 2>&1; echo $?)"
check "bad endpoint refused" 2 "$(OTEL_EXPORTER_OTLP_ENDPOINT=nope ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$BIN" --data "$WORK/x" --listen 127.0.0.1:1 >/dev/null 2>&1; echo $?)"

echo "--- metrics v3"
"$MC" cat z/obs/a.txt >/dev/null
v3() { "$MC" admin prometheus metrics z "$@" --api-version v3 2>&1; }
check "v3 api group" yes "$(yes_no grep -q 'minio_api_requests_total{name="GetObject",type="s3"' <<<"$(v3 api)")"
check "v3 latency histogram" yes "$(yes_no grep -q 'minio_api_requests_duration_seconds_bucket{name="GetObject",type="s3",server="127.0.0.1:'"$PORT"'",le="+Inf"}' <<<"$(v3 api)")"
check "v3 ttfb distribution" yes "$(yes_no grep -q 'minio_api_requests_ttfb_seconds_distribution{name="GetObject",type="s3",le="0.05"' <<<"$(v3 api)")"
check "v3 per-bucket api" yes "$(yes_no grep -q 'minio_bucket_api_total{bucket="obs",name="GetObject"' <<<"$(v3 api --bucket obs)")"
check "v3 system drive" yes "$(yes_no grep -q "minio_system_drive_total_bytes{drive=\"$WORK/d1\"" <<<"$(v3 system)")"
check "v3 system memory/cpu/process" 3 "$(v3 system | grep -cE '^minio_system_(memory_total|cpu_load|process_resident_memory_bytes)\{')"
check "v3 cluster usage" yes "$(yes_no grep -q 'minio_cluster_usage_buckets_objects_count{bucket="obs"} 2' <<<"$(v3 cluster)")"
check "v3 cluster health" yes "$(yes_no grep -q '^minio_cluster_health_drives_online_count 1' <<<"$(v3 cluster)")"
for g in ilm replication notification scanner audit logger debug; do
  check "v3 group $g" 0 "$("$MC" admin prometheus metrics z "$g" --api-version v3 >/dev/null 2>&1; echo $?)"
done
check "v3 needs a token" 403 "$(curl -s -o /dev/null -w '%{http_code}' "$EP/minio/metrics/v3/api")"
GEN="$("$MC" admin prometheus generate z --api-version v3)"
TOKEN="$(sed -n 's/.*bearer_token: *//p' <<<"$GEN" | head -1)"
check "generate emits the v3 path" yes "$(yes_no grep -q 'metrics_path: /minio/metrics/v3' <<<"$GEN")"
check "generated token scrapes" 200 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$EP/minio/metrics/v3")"
check "v3 unknown group 404" 404 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$EP/minio/metrics/v3/nope")"
check "forged token refused" 403 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${TOKEN%?}x" "$EP/minio/metrics/v3")"
check "v2 cluster metrics still served" yes "$(yes_no grep -q zkfsm_requests_total <<<"$(curl -s "$EP/minio/v2/metrics/cluster")")"
check "/metrics still served" yes "$(yes_no grep -q zkfsm_request_duration_seconds_bucket <<<"$(curl -s "$EP/metrics")")"
"$MC" admin user add z prom promsecret123 >/dev/null
"$MC" alias set p "$EP" prom promsecret123 >/dev/null
check "token of a user without admin:Prometheus refused" 1 "$("$MC" admin prometheus metrics p api --api-version v3 >/dev/null 2>&1; echo $?)"

echo "--- mc admin trace"
"$MC" admin trace z --json >"$WORK/trace.json" 2>&1 &
TP=$!
"$MC" admin trace z --call storage --json >"$WORK/trace-storage.json" 2>&1 &
TSP=$!
"$MC" admin trace z --errors --json >"$WORK/trace-errors.json" 2>&1 &
TEP=$!
"$MC" admin trace z >"$WORK/trace.txt" 2>&1 &
TTP=$!
"$MC" admin trace z --response-duration 1h --json >"$WORK/trace-slow.json" 2>&1 &
TLP=$!
sleep 1
"$MC" cat z/obs/a.txt >/dev/null
"$MC" cat z/obs/nothere >/dev/null 2>&1 || true
sleep 1.5
kill "$TP" "$TSP" "$TEP" "$TTP" "$TLP" 2>/dev/null || true
wait "$TP" "$TSP" "$TEP" "$TTP" "$TLP" 2>/dev/null || true
tq() { python3 - "$1" "$2" <<'PY'
import json, sys
n = 0
for line in open(sys.argv[1]):
    line = line.strip()
    if not line.startswith("{"):
        continue
    t = json.loads(line)
    if eval(sys.argv[2]):
        n += 1
print(n)
PY
}
check "trace shows GetObject" yes "$([[ "$(tq "$WORK/trace.json" "t.get('api')=='s3.GetObject' and t.get('statusCode')==200 and t['path']=='/obs/a.txt'")" -ge 1 ]] && echo yes || echo no)"
check "trace output bytes" yes "$([[ "$(tq "$WORK/trace.json" "t.get('api')=='s3.GetObject' and t['callStats']['tx']==20")" -ge 1 ]] && echo yes || echo no)"
check "trace storage calls" yes "$([[ "$(tq "$WORK/trace-storage.json" "t.get('type')=='Storage' and t.get('api','').startswith('storage.')")" -ge 1 ]] && echo yes || echo no)"
check "storage-only stream has no S3 calls" 0 "$(tq "$WORK/trace-storage.json" "t.get('type')=='S3'")"
check "errors filter" 0 "$(tq "$WORK/trace-errors.json" "t.get('statusCode',0) < 400")"
check "errors filter keeps 404" yes "$([[ "$(tq "$WORK/trace-errors.json" "t.get('statusCode')==404")" -ge 1 ]] && echo yes || echo no)"
check "threshold filter" 0 "$(tq "$WORK/trace-slow.json" "t.get('type')=='S3'")"
check "text trace" yes "$(yes_no grep -q 's3.GetObject' "$WORK/trace.txt")"
check "trace needs admin:ServerTrace" 1 "$(timeout 3 "$MC" admin trace p >/dev/null 2>&1; echo $?)"

echo "--- mc admin logs"
LOGS="$(timeout 3 "$MC" admin logs z --last 50 2>&1 || true)"
check "logs replay recent entries" yes "$(yes_no grep -q "Message: zkfsm listening on" <<<"$LOGS")"
check "logs carry the deployment id" yes "$(yes_no grep -q "DeploymentID: [0-9a-f]\{32\}" <<<"$LOGS")"
"$MC" admin logs z >"$WORK/live-logs.txt" 2>&1 &
LP=$!
sleep 1

echo "--- access logs"
put_logging() { # bucket target prefix
  curl -s -o /dev/null -w '%{http_code}' "${sig[@]}" -X PUT --data-binary \
    "<BucketLoggingStatus xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><LoggingEnabled><TargetBucket>$2</TargetBucket><TargetPrefix>$3</TargetPrefix></LoggingEnabled></BucketLoggingStatus>" "$EP/$1?logging"
}
check "put bucket logging" 200 "$(put_logging obs logs access/)"
"$MC" cp -q "$WORK/f.txt" z/obs/b.txt >/dev/null
"$MC" cat z/obs/b.txt >/dev/null
curl -s -o /dev/null "$EP/obs/b.txt"
log_objects() { "$MC" ls -r --json "${2:-z}/$1" 2>/dev/null | python3 -c "import sys,json;[print(json.loads(l)['key']) for l in sys.stdin if l.strip()]"; }
delivered() { [[ -n "$(log_objects "$1")" ]]; }
wait_for 10 delivered logs
ALL="$(for k in $(log_objects logs); do "$MC" cat "z/logs/$k"; done)"
check "log object key format" yes "$(yes_no grep -qE '^access/[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9A-F]{16}$' <<<"$(log_objects logs | head -1)")"
check "PUT record" yes "$(yes_no grep -qE "^zkfsm obs \[[0-9]{2}/[A-Z][a-z]{2}/[0-9]{4}:[0-9:]{8} \+0000\] 127.0.0.1 $AK [0-9A-F]{16} REST.PUT.OBJECT b.txt \"PUT /obs/b.txt HTTP/1.1\" 200 - - 20 " <<<"$ALL")"
check "GET record bytes sent" yes "$(yes_no grep -qE 'REST.GET.OBJECT b.txt "GET /obs/b.txt HTTP/1.1" 200 - 20 20 ' <<<"$ALL")"
check "anonymous denied record" yes "$(yes_no grep -qE '127.0.0.1 - [0-9A-F]{16} REST.GET.OBJECT b.txt "GET /obs/b.txt HTTP/1.1" 403 AccessDenied ' <<<"$ALL")"
check "signature columns" yes "$(yes_no grep -qE 'SigV4 - AuthHeader 127.0.0.1:'"$PORT"' - - -$' <<<"$ALL")"
check "target bucket not logged into itself" 0 "$(grep -c ' logs \[' <<<"$ALL" || true)"

# Explicit Deny for the logging service on the target drops the records.
cat >"$WORK/deny.json" <<JSON
{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"Service":"logging.s3.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::denied/*"}]}
JSON
"$MC" anonymous set-json "$WORK/deny.json" z/denied >/dev/null
check "logging into a denying bucket" 200 "$(put_logging obs denied x/)"
"$MC" cat z/obs/a.txt >/dev/null
sleep 3
check "denying target gets nothing" "" "$(log_objects denied)"
denied_metric() { curl -s -H "Authorization: Bearer $TOKEN" "$EP/minio/metrics/v3" | grep -q '^zkfsm_access_log_denied_total [1-9]'; }
check "denied deliveries counted" yes "$(yes_no wait_for 5 denied_metric)"
check "denial logged as a warning" yes "$(yes_no grep -q 'access log: obs -> denied: target bucket does not grant log delivery' "$WORK/s1.log")"
kill "$LP" 2>/dev/null || true
wait "$LP" 2>/dev/null || true
check "live logs stream the warning" yes "$(yes_no grep -q 'does not grant log delivery' "$WORK/live-logs.txt")"

# A Service grant allows a target with another owner policy; partitioned keys.
cat >"$WORK/grant.json" <<JSON
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"logging.s3.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::granted/*"}]}
JSON
"$MC" anonymous set-json "$WORK/grant.json" z/granted >/dev/null
check "partitioned prefix config" 200 "$(curl -s -o /dev/null -w '%{http_code}' "${sig[@]}" -X PUT --data-binary '<BucketLoggingStatus xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LoggingEnabled><TargetBucket>granted</TargetBucket><TargetPrefix>p/</TargetPrefix><TargetObjectKeyFormat><PartitionedPrefix><PartitionDateSource>EventTime</PartitionDateSource></PartitionedPrefix></TargetObjectKeyFormat></LoggingEnabled></BucketLoggingStatus>' "$EP/obs?logging")"
"$MC" cat z/obs/a.txt >/dev/null
wait_for 10 delivered granted
check "partitioned key layout" yes "$(yes_no grep -qE '^p/zkfsm/us-east-1/obs/[0-9]{4}/[0-9]{2}/[0-9]{2}/[0-9]{4}(-[0-9]{2}){5}-[0-9A-F]{16}$' <<<"$(log_objects granted | head -1)")"

# Crash safety: records journaled before a kill -9 are delivered after restart.
stop
ALI=3600 start
check "logging back to logs" 200 "$(put_logging obs logs crash/)"
"$MC" cat z/obs/a.txt >/dev/null
curl -s -o /dev/null "${sig[@]}" "$EP/obs/crash-marker"
sleep 1.2
kill9
check "journal survives kill -9" yes "$(yes_no grep -q crash-marker "$WORK/d1/.zkfsm/accesslog/pending.log")"
ALI=1 start
crash_delivered() { [[ -n "$(log_objects logs | grep '^crash/')" ]]; }
wait_for 10 crash_delivered
CR="$(for k in $(log_objects logs | grep '^crash/'); do "$MC" cat "z/logs/$k"; done)"
check "crash records delivered once" 1 "$(grep -c 'GET /obs/crash-marker' <<<"$CR")"
check "journal drained" "" "$(ls "$WORK/d1/.zkfsm/accesslog/" | grep -v pending.log || true)"
check "logging disabled stops records" 200 "$(curl -s -o /dev/null -w '%{http_code}' "${sig[@]}" -X PUT --data-binary '<BucketLoggingStatus xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>' "$EP/obs?logging")"
BEFORE="$(log_objects logs | wc -l)"
curl -s -o /dev/null "${sig[@]}" "$EP/obs/after-disable"
sleep 2.5
AFTER_ALL="$(for k in $(log_objects logs); do "$MC" cat "z/logs/$k"; done)"
check "no records after disable" 0 "$(grep -c after-disable <<<"$AFTER_ALL" || true)"
stop

echo "--- OpenTelemetry Collector"
if docker image inspect otel/opentelemetry-collector-contrib:latest >/dev/null 2>&1 || timeout 300 docker pull -q otel/opentelemetry-collector-contrib:latest >/dev/null 2>&1; then
  CPORT="$(freeport)"
  mkdir -p "$WORK/col"
  chmod 777 "$WORK/col"
  cat >"$WORK/col/config.yaml" <<'YAML'
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
exporters:
  file/traces:
    path: /out/traces.json
    flush_interval: 100ms
  file/logs:
    path: /out/logs.json
    flush_interval: 100ms
  file/metrics:
    path: /out/metrics.json
    flush_interval: 100ms
service:
  pipelines:
    traces: {receivers: [otlp], exporters: [file/traces]}
    logs: {receivers: [otlp], exporters: [file/logs]}
    metrics: {receivers: [otlp], exporters: [file/metrics]}
YAML
  CONTAINER="zkfsm-observe-otelcol-$$"
  docker run -d --name "$CONTAINER" -p "127.0.0.1:$CPORT:4318" -v "$WORK/col:/out:Z" \
    otel/opentelemetry-collector-contrib:latest --config /out/config.yaml >/dev/null
  col_up() { curl -s -o /dev/null -X POST -H 'content-type: application/x-protobuf' "http://127.0.0.1:$CPORT/v1/traces"; }
  wait_for 30 col_up
  OTEL_EP="http://127.0.0.1:$CPORT" start
  curl -s -o /dev/null "${sig[@]}" -H "traceparent: 00-$TID-$PSID-01" "$EP/obs/a.txt"
  col_has() { grep -q "$1" "$WORK/col/$2" 2>/dev/null; }
  wait_for 10 col_has '"name":"s3.GetObject"' traces.json || true
  check "collector accepted spans" yes "$(yes_no col_has '"name":"s3.GetObject"' traces.json)"
  check "collector kept the trace id" yes "$(yes_no col_has "\"traceId\":\"$TID\"" traces.json)"
  check "collector kept the parent" yes "$(yes_no col_has "\"parentSpanId\":\"$PSID\"" traces.json)"
  wait_for 10 col_has '"name":"minio_api_requests_total"' metrics.json || true
  check "collector accepted metrics" yes "$(yes_no col_has '"name":"minio_api_requests_total"' metrics.json)"
  check "collector histogram" yes "$(yes_no col_has '"name":"minio_api_requests_duration_seconds"[^}]*"histogram"' metrics.json)"
  wait_for 10 col_has 'zkfsm listening on' logs.json || true
  check "collector accepted logs" yes "$(yes_no col_has 'zkfsm listening on' logs.json)"
  check "collector saw no decode errors" 0 "$(docker logs "$CONTAINER" 2>&1 | grep -ciE 'error.*(unmarshal|proto|decode)' || true)"
  stop
  docker rm -f "$CONTAINER" >/dev/null
  CONTAINER=""
  unset OTEL_EP
else
  echo "skip collector (otel/opentelemetry-collector-contrib not available)"
fi

echo "--- cluster: trace context over RPC, cluster-wide trace, per-node delivery"
: >"$OTLP/spans.jsonl"
CP=(0 "$(freeport)" "$(freeport)" "$(freeport)")
EPS=()
for i in 1 2 3; do EPS+=("http://127.0.0.1:${CP[$i]}$WORK/c$i/d{1...2}"); done
CPIDS=(0 0 0 0)
for i in 1 2 3; do
  ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" OTEL_EXPORTER_OTLP_ENDPOINT="http://127.0.0.1:$RPORT" OTEL_BSP_SCHEDULE_DELAY=200 \
    ZKFSM_ACCESS_LOG_INTERVAL=1 "$BIN" --data "${EPS[@]}" --listen "127.0.0.1:${CP[$i]}" --node-address "127.0.0.1:${CP[$i]}" \
    --protection EC:4+2 --cluster-refresh 1 >>"$WORK/c$i.log" 2>&1 &
  CPIDS[$i]=$!
  PIDS+=("${CPIDS[$i]}")
done
for i in 1 2 3; do
  wait_for 60 curl -sf -o /dev/null "http://127.0.0.1:${CP[$i]}/health/ready" || { echo "node $i not ready"; tail -20 "$WORK/c$i.log"; exit 1; }
done
"$MC" alias set c1 "http://127.0.0.1:${CP[1]}" "$AK" "$SK" >/dev/null
"$MC" alias set c2 "http://127.0.0.1:${CP[2]}" "$AK" "$SK" >/dev/null
"$MC" mb c1/cobs c1/clogs >/dev/null
"$MC" cp -q "$WORK/f.txt" c1/cobs/a.txt >/dev/null
CTID=aaaabbbbccccddddeeeeffff00001111
check "cluster GET with traceparent" 200 "$(curl -s -o /dev/null -w '%{http_code}' "${sig[@]}" -H "traceparent: 00-$CTID-$PSID-01" "http://127.0.0.1:${CP[1]}/cobs/a.txt")"
wait_for 10 has_spans "s['trace_id']=='$CTID' and s['name']=='internode.server'"
check "RPC client spans on the entry node" yes "$(yes_no has_spans "s['trace_id']=='$CTID' and s['name']=='internode' and s['kind']==3 and s['resource']['service.instance.id']=='127.0.0.1:${CP[1]}'")"
check "remote nodes continue the trace" yes "$(yes_no has_spans "s['trace_id']=='$CTID' and s['name']=='internode.server' and s['resource']['service.instance.id']!='127.0.0.1:${CP[1]}'")"
check "remote spans parent to the RPC client span" yes "$(python3 - "$OTLP/spans.jsonl" "$CTID" <<'PY'
import json, sys
spans = [json.loads(l) for l in open(sys.argv[1])]
t = [s for s in spans if s["trace_id"] == sys.argv[2]]
clients = {s["span_id"] for s in t if s["name"] == "internode"}
servers = [s for s in t if s["name"] == "internode.server"]
print("yes" if servers and all(s["parent"] in clients for s in servers) else "no")
PY
)"
"$MC" admin trace c1 --json >"$WORK/ctrace.json" 2>&1 &
CTP=$!
sleep 1.5
"$MC" cat c2/cobs/a.txt >/dev/null
sleep 2.5
kill "$CTP" 2>/dev/null || true
wait "$CTP" 2>/dev/null || true
check "trace on node 1 streams node 2 requests" yes "$([[ "$(tq "$WORK/ctrace.json" "t.get('api')=='s3.GetObject' and t.get('host')=='127.0.0.1:${CP[2]}'")" -ge 1 ]] && echo yes || echo no)"
check "cluster put bucket logging" 200 "$(curl -s -o /dev/null -w '%{http_code}' "${sig[@]}" -X PUT --data-binary '<BucketLoggingStatus xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LoggingEnabled><TargetBucket>clogs</TargetBucket><TargetPrefix>n/</TargetPrefix></LoggingEnabled></BucketLoggingStatus>' "http://127.0.0.1:${CP[1]}/cobs?logging")"
sleep 6 # other nodes pick the configuration up within the cache lifetime
for i in 1 2 3; do curl -s -o /dev/null "${sig[@]}" "http://127.0.0.1:${CP[$i]}/cobs/from-node-$i"; done
all_nodes() { local a; a="$(for k in $(log_objects clogs c1); do "$MC" cat "c1/clogs/$k"; done)"; for i in 1 2 3; do grep -q "from-node-$i" <<<"$a" || return 1; done; }
check "every node delivers its own records" yes "$(yes_no wait_for 15 all_nodes)"
check "one object per node batch" yes "$([[ "$(log_objects clogs c1 | wc -l)" -ge 3 ]] && echo yes || echo no)"
check "v3 cluster health sees 3 nodes" yes "$(yes_no grep -q '^minio_cluster_health_nodes_online_count 3' <<<"$("$MC" admin prometheus metrics c1 cluster --api-version v3)")"

echo
echo "observe: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
