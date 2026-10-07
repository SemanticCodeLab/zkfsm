#!/usr/bin/env bash
# Bucket event notifications and audit logging, end to end: target config through
# `mc admin config` and the environment, `mc event add/ls/rm`, filters, event names,
# a webhook receiver outage, crash/restart with queued events, `mc watch`, audit to
# file/webhook/kafka, metrics, a 4-node cluster, and real brokers in docker
# (redpanda, nats + jetstream, mosquitto, redis, postgres, rabbitmq; mysql when an
# image is available). EVENTS_BROKERS=0 skips the docker part.
set -euo pipefail
S3CLI_BIN="${S3CLI_BIN:-aws}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
MC="${MC:-$(command -v mc || true)}"
if [[ -z "$MC" ]] || ! "$MC" --version >/dev/null 2>&1; then echo "events.sh needs the MinIO client (set MC)"; exit 1; fi
BROKERS="${EVENTS_BROKERS:-1}"
H="$ROOT/tests/events_helper.py"
declare -A PID=()
CONTAINERS=()
cleanup() {
  for p in "${PID[@]}"; do kill -9 "$p" 2>/dev/null || true; done
  for c in "${CONTAINERS[@]}"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'echo "events.sh: command failed at line $LINENO: $BASH_COMMAND" >&2' ERR

pass=0
fail=0
check() { # name expected actual
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); echo "ok   $1"
  else fail=$((fail + 1)); echo "FAIL $1: expected [$2] got [$3]"; fi
}
eventually() { # name expected command... (retries for up to 60 s)
  local name="$1" want="$2" got=""; shift 2
  for _ in $(seq 120); do got="$("$@" 2>/dev/null || true)"; [[ "$got" == "$want" ]] && break; sleep 0.5; done
  check "$name" "$want" "$got"
}
freeport() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }

AK="evadmin"
SK="events-secret-0123"
export AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_DEFAULT_REGION=us-east-1 AWS_PAGER=""
export AWS_CONFIG_FILE="$WORK/s3cli.conf" AWS_SHARED_CREDENTIALS_FILE="$WORK/s3cli.creds"
printf '[default]\ns3 =\n  addressing_style = path\n  multipart_threshold = 5MB\n  multipart_chunksize = 5MB\n' >"$AWS_CONFIG_FILE"
export MC_CONFIG_DIR="$WORK/mc"

(cd "$ROOT" && zig build -Doptimize=ReleaseSafe)
BIN="$ROOT/zig-out/bin/zkfsm"

P="$(freeport)"
WH="$(freeport)"
HOOK="$WORK/hook"
ep="http://127.0.0.1:$P"

recv_start() { python3 "$H" recv "$WH" "$HOOK" & PID[recv]=$!; sleep 0.3; }
recv_stop() { kill -9 "${PID[recv]}" 2>/dev/null || true; wait "${PID[recv]}" 2>/dev/null || true; unset "PID[recv]"; }
start() { # extra env assignments...
  env ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" ZKFSM_AUDIT_FILE="$WORK/audit.log" \
    MINIO_NOTIFY_WEBHOOK_ENABLE_ENV=on MINIO_NOTIFY_WEBHOOK_ENDPOINT_ENV="http://127.0.0.1:$WH/env" \
    ZKFSM_ILM_DAY_SECONDS=2 "$@" "$BIN" --data "$WORK/d" --listen "127.0.0.1:$P" --lifecycle-interval 2 >>"$WORK/z.log" 2>&1 &
  PID[z]=$!
  for _ in $(seq 300); do [[ "$(curl -s -o /dev/null -w '%{http_code}' "$ep/health/ready")" == 200 ]] && return 0; sleep 0.1; done
  echo "server not ready"; tail -n 30 "$WORK/z.log"; exit 1
}
stop() { kill -9 "${PID[z]}" 2>/dev/null || true; wait "${PID[z]}" 2>/dev/null || true; unset "PID[z]"; }
cli() { "$S3CLI_BIN" --endpoint-url "$ep" "$@"; }
keys() { python3 "$H" keys "$@" | sort | tr '\n' ' ' | sed 's/ $//'; }
count() { python3 "$H" count "$1" "$2"; }
metric() { curl -s "$ep/metrics" | awk -v m="$1" 'index($0, m" ")==1 {print $2}'; }

recv_start
start
"$MC" alias set z "$ep" "$AK" "$SK" >/dev/null

echo "== target configuration"
check "config set applies live" "Successfully applied new settings." "$("$MC" admin config set z notify_webhook:1 endpoint="http://127.0.0.1:$WH/hook" auth_token=s3cr3t 2>&1 | tail -n1)"
check "config get shows the endpoint" 1 "$("$MC" admin config get z notify_webhook:1 | grep -c "endpoint=http://127.0.0.1:$WH/hook")"
check "unknown key rejected" 1 "$("$MC" admin config set z notify_webhook:2 nope=1 >/dev/null 2>&1 && echo 0 || echo 1)"
check "invalid endpoint rejected" 1 "$("$MC" admin config set z notify_webhook:2 endpoint=ftp://x >/dev/null 2>&1 && echo 0 || echo 1)"
"$MC" admin config set z notify_webhook:tmp endpoint="http://127.0.0.1:$WH/tmp" >/dev/null
check "config reset removes a target" "'notify_webhook:tmp' is successfully reset." "$("$MC" admin config reset z notify_webhook:tmp 2>&1 | tail -n1)"
check "reset target gone" 0 "$("$MC" admin config get z notify_webhook | grep -c 'notify_webhook:tmp' || true)"
check "help lists target keys" 1 "$("$MC" admin config set z notify_kafka 2>&1 | grep -c '^sasl_mechanism ')"
check "metrics list the target" 1 "$(metric 'zkfsm_notify_target_online{target_id="1",target_name="notify_webhook"}')"
check "env target is running" 1 "$(metric 'zkfsm_notify_target_online{target_id="ENV",target_name="notify_webhook"}')"

echo "== mc event add / ls / rm"
"$MC" mb z/photos z/other >/dev/null
check "event add" 0 "$("$MC" event add z/photos arn:minio:sqs::1:webhook --event put,delete --prefix img/ --suffix .jpg >/dev/null && echo 0)"
check "event add with unknown ARN fails" 1 "$("$MC" event add z/photos arn:minio:sqs::nope:webhook --event put >/dev/null 2>&1 && echo 0 || echo 1)"
check "overlapping rule rejected" 1 "$("$MC" event add z/photos arn:minio:sqs::1:webhook --event put --prefix img/ --suffix .jpg >/dev/null 2>&1 && echo 0 || echo 1)"
"$MC" event add z/photos arn:minio:sqs::1:webhook --event get --prefix read/ >/dev/null
"$MC" event add z/photos arn:minio:sqs::ENV:webhook --event put --prefix env/ >/dev/null
check "event ls lists three rules" 3 "$("$MC" event ls z/photos | grep -c arn:minio:sqs)"
check "event ls shows the filter" 1 "$("$MC" event ls z/photos arn:minio:sqs::1:webhook | grep -c 'prefix="img/"')"
check "GetBucketNotificationConfiguration" 1 "$(cli s3api get-bucket-notification-configuration --bucket photos | python3 -c 'import json,sys; d=json.load(sys.stdin); print(sum(1 for q in d["QueueConfigurations"] if q["QueueArn"]=="arn:minio:sqs::1:webhook" and "s3:ObjectCreated:*" in q["Events"]))')"

echo "== delivery and filters"
echo a | "$MC" pipe z/photos/img/a.jpg >/dev/null
echo b | "$MC" pipe z/photos/img/b.png >/dev/null
echo c | "$MC" pipe z/photos/doc/c.jpg >/dev/null
echo d | "$MC" pipe z/other/img/d.jpg >/dev/null
cli s3api put-object --bucket photos --key img/put.jpg --body "$ROOT/README.md" >/dev/null
head -c 12000000 /dev/urandom >"$WORK/big.bin"
cli s3 cp "$WORK/big.bin" s3://photos/img/big.jpg >/dev/null
cli s3api copy-object --bucket photos --key img/copy.jpg --copy-source photos/img/put.jpg >/dev/null
echo e | "$MC" pipe z/photos/env/e.txt >/dev/null
eventually "created events pass the filters" "env/e.txt img/a.jpg img/big.jpg img/copy.jpg img/put.jpg" keys "$HOOK" 's3:ObjectCreated:*' photos
check "single PUT event" img/put.jpg "$(keys "$HOOK" s3:ObjectCreated:Put photos)"
check "multipart completion event" 1 "$(keys "$HOOK" s3:ObjectCreated:CompleteMultipartUpload photos | grep -c img/big.jpg)"
eventually "copy event" img/copy.jpg keys "$HOOK" s3:ObjectCreated:Copy
eventually "env-configured target receives its rule" 1 count "$HOOK" '"Key":"photos/env/e.txt"'
check "auth token sent as bearer" 1 "$(grep -c '^Bearer s3cr3t$' "$HOOK.auth" | awk '{print ($1>0)}')"
REC="$(grep '"Key":"photos/img/put.jpg"' "$HOOK" | head -n1)"
check "record shape" "s3:ObjectCreated:Put|photos|img%2Fput.jpg|$(stat -c %s "$ROOT/README.md")|$AK|minio:s3|2.0" "$(python3 -c '
import json,sys; d=json.loads(sys.argv[1]); r=d["Records"][0]
print("|".join(str(x) for x in [d["EventName"], r["s3"]["bucket"]["name"], r["s3"]["object"]["key"], r["s3"]["object"]["size"], r["userIdentity"]["principalId"], r["eventSource"], r["eventVersion"]]))' "$REC")"
check "record has etag and source ip" "1|127.0.0.1" "$(python3 -c '
import json,sys; r=json.loads(sys.argv[1])["Records"][0]
print(str(int(len(r["s3"]["object"]["eTag"])==32))+"|"+r["source"]["host"])' "$REC")"
"$MC" cat z/photos/read/x.txt >/dev/null 2>&1 || true
echo r | "$MC" pipe z/photos/read/x.txt >/dev/null
"$MC" cat z/photos/read/x.txt >/dev/null
eventually "access event" read/x.txt keys "$HOOK" s3:ObjectAccessed:Get
"$MC" rm z/photos/img/a.jpg >/dev/null
eventually "delete event" img/a.jpg keys "$HOOK" s3:ObjectRemoved:Delete
check "png and other-bucket objects filtered out" 0 "$(count "$HOOK" 'img/b.png'; )"
check "doc/ prefix filtered out" 0 "$(count "$HOOK" 'doc/c.jpg')"
check "other bucket filtered out" 0 "$(count "$HOOK" 'other/img')"

echo "== more event types"
"$MC" mb z/types >/dev/null
"$MC" version enable z/types >/dev/null
"$MC" event add z/types arn:minio:sqs::1:webhook --event put,delete >/dev/null
echo t | "$MC" pipe z/types/t.txt >/dev/null
cli s3api put-object-tagging --bucket types --key t.txt --tagging 'TagSet=[{Key=k,Value=v}]' >/dev/null
cli s3api delete-object-tagging --bucket types --key t.txt >/dev/null
"$MC" rm z/types/t.txt >/dev/null
eventually "tagging events" t.txt keys "$HOOK" s3:ObjectCreated:PutTagging
eventually "tag delete event" t.txt keys "$HOOK" s3:ObjectCreated:DeleteTagging
eventually "delete marker event" t.txt keys "$HOOK" s3:ObjectRemoved:DeleteMarkerCreated
check "versioned record carries versionId" 1 "$(grep '"s3:ObjectCreated:PutTagging"' "$HOOK" | head -n1 | python3 -c 'import json,sys; print(int(len(json.loads(sys.stdin.readline())["Records"][0]["s3"]["object"]["versionId"])>0))')"

echo "== receiver outage, then recovery"
touch "$HOOK.fail"
for i in 1 2 3; do echo "o$i" | "$MC" pipe "z/photos/img/out$i.jpg" >/dev/null; done
eventually "events queue while the receiver fails" 3 metric 'zkfsm_notify_target_queue_length{target_id="1",target_name="notify_webhook"}'
check "target reported offline" 0 "$(metric 'zkfsm_notify_target_online{target_id="1",target_name="notify_webhook"}')"
rm -f "$HOOK.fail"
eventually "queued events delivered after recovery" "img/out1.jpg img/out2.jpg img/out3.jpg" sh -c "python3 '$H' keys '$HOOK' 's3:ObjectCreated:*' photos | grep out | sort | tr '\n' ' ' | sed 's/ \$//'"
eventually "queue drained" 0 metric 'zkfsm_notify_target_queue_length{target_id="1",target_name="notify_webhook"}'

echo "== crash with queued events"
recv_stop
for i in 1 2 3 4; do echo "c$i" | "$MC" pipe "z/photos/img/crash$i.jpg" >/dev/null; done
eventually "events queued on disk" 4 metric 'zkfsm_notify_target_queue_length{target_id="1",target_name="notify_webhook"}'
check "queue files on disk" 4 "$(ls "$WORK/d/.zkfsm/events/notify_webhook-1" | grep -c '\.event$')"
stop
start
eventually "queue reloaded after restart" 4 metric 'zkfsm_notify_target_queue_length{target_id="1",target_name="notify_webhook"}'
recv_start
eventually "queued events delivered after restart" "img/crash1.jpg img/crash2.jpg img/crash3.jpg img/crash4.jpg" sh -c "python3 '$H' keys '$HOOK' 's3:ObjectCreated:*' | grep crash | sort | tr '\n' ' ' | sed 's/ \$//'"
check "each crash event delivered once" 4 "$(count "$HOOK" '/img/crash')"
check "admin-configured target survived the restart" 1 "$(metric 'zkfsm_notify_target_online{target_id="1",target_name="notify_webhook"}')"

echo "== mc watch"
"$MC" watch z/photos --events put --prefix live/ >"$WORK/watch.out" 2>&1 &
PID[watch]=$!
sleep 1
echo w | "$MC" pipe z/photos/live/w.txt >/dev/null
echo w | "$MC" pipe z/photos/notlive/w.txt >/dev/null
eventually "mc watch streams matching events" 1 sh -c "grep -c 's3:ObjectCreated:Put.*photos/live/w.txt' '$WORK/watch.out'"
check "mc watch applies the prefix" 0 "$(grep -c notlive "$WORK/watch.out" || true)"
kill "${PID[watch]}" 2>/dev/null || true; unset "PID[watch]"

echo "== event rm"
"$MC" event rm z/photos arn:minio:sqs::1:webhook --event get --prefix read/ >/dev/null
check "rule removed" 2 "$("$MC" event ls z/photos | grep -c arn:minio:sqs)"
"$MC" event rm z/photos --force >/dev/null
check "all rules removed" 0 "$("$MC" event ls z/photos | grep -c arn:minio:sqs || true)"
before="$(count "$HOOK" '"Key":"photos/img/after-rm.jpg"')"
echo x | "$MC" pipe z/photos/img/after-rm.jpg >/dev/null
sleep 1
check "no events after removal" "$before" "$(count "$HOOK" '"Key":"photos/img/after-rm.jpg"')"

echo "== lifecycle expiration and replication events"
"$MC" mb z/ilm >/dev/null
cli s3api put-bucket-notification-configuration --bucket ilm --notification-configuration '{"QueueConfigurations":[{"Id":"ilm","QueueArn":"arn:minio:sqs::1:webhook","Events":["s3:LifecycleExpiration:*"]}]}'
cli s3api put-bucket-lifecycle-configuration --bucket ilm --lifecycle-configuration '{"Rules":[{"ID":"x","Status":"Enabled","Filter":{"Prefix":""},"Expiration":{"Days":1}}]}'
echo old | "$MC" pipe z/ilm/old.txt >/dev/null
eventually "lifecycle expiration event" old.txt keys "$HOOK" s3:LifecycleExpiration:Delete ilm
check "expiration record has no requester" "" "$(grep '"s3:LifecycleExpiration:Delete"' "$HOOK" | head -n1 | python3 -c 'import json,sys; print(json.loads(sys.stdin.readline())["Records"][0]["userIdentity"]["principalId"])')"
P2="$(freeport)"
ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$BIN" --data "$WORK/dst" --listen "127.0.0.1:$P2" >>"$WORK/dst.log" 2>&1 &
PID[dst]=$!
for _ in $(seq 300); do [[ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P2/health/ready")" == 200 ]] && break; sleep 0.1; done
"$MC" alias set dst "http://127.0.0.1:$P2" "$AK" "$SK" >/dev/null
"$MC" mb z/repsrc dst/repdst >/dev/null
"$MC" version enable z/repsrc >/dev/null
"$MC" version enable dst/repdst >/dev/null
"$MC" replicate add z/repsrc --remote-bucket "http://$AK:$SK@127.0.0.1:$P2/repdst" >/dev/null
cli s3api put-bucket-notification-configuration --bucket repsrc --notification-configuration '{"QueueConfigurations":[{"Id":"r","QueueArn":"arn:minio:sqs::1:webhook","Events":["s3:Replication:*"]}]}'
echo rep | "$MC" pipe z/repsrc/r.txt >/dev/null
eventually "replication completed event" r.txt keys "$HOOK" s3:Replication:OperationCompletedReplication repsrc
kill -9 "${PID[dst]}" 2>/dev/null || true; wait "${PID[dst]}" 2>/dev/null || true; unset "PID[dst]"

echo "== audit"
check "audit file has PutObject entries" 1 "$(grep '"name":"PutObject"' "$WORK/audit.log" | grep -c '"object":"img/put.jpg"')"
LINE="$(grep '"name":"PutObject"' "$WORK/audit.log" | grep '"object":"img/put.jpg"' | head -n1)"
check "audit entry fields" "1|photos|200|$AK|*REDACTED*|1" "$(python3 -c '
import json,sys; e=json.loads(sys.argv[1])
print("|".join(str(x) for x in [e["version"], e["api"]["bucket"], e["api"]["statusCode"], e["accessKey"], e["requestHeader"].get("Authorization"), int("X-Amz-Request-Id" in e["responseHeader"] or "x-amz-request-id" in e["responseHeader"])]))' "$LINE")"
check "audit records failures" 1 "$(grep -c '"statusCode":404' "$WORK/audit.log" | awk '{print ($1>0)}')"
"$MC" admin config set z audit_webhook:a endpoint="http://127.0.0.1:$WH/audit" >/dev/null
echo au | "$MC" pipe z/photos/audited.txt >/dev/null
eventually "audit webhook receives entries" 1 sh -c "grep -c '\"object\":\"audited.txt\"' '$HOOK.audit' | awk '{print (\$1>0)}'"
check "audit metrics" 1 "$(metric 'zkfsm_audit_target_online{target_id="a",target_name="audit_webhook"}')"

if [[ "$BROKERS" == 1 ]] && command -v docker >/dev/null && docker info >/dev/null 2>&1; then
  echo "== brokers"
  NET="zkev$$"
  run_c() { # name args...
    local n="zkev-$1-$$"; shift
    if ! docker run -d --rm --name "$n" "$@" >"$WORK/docker.err" 2>&1; then
      echo "docker cannot start $n: $(tail -n1 "$WORK/docker.err")"
      return 1
    fi
    CONTAINERS+=("$n")
  }
  KP="$(freeport)"; NP="$(freeport)"; MP="$(freeport)"; RP="$(freeport)"; GP="$(freeport)"; AP="$(freeport)"; AHP="$(freeport)"
  docker_ok=1
  run_c kafka --mount type=tmpfs,destination=/var/lib/redpanda/data,tmpfs-mode=1777,tmpfs-size=1g -p "$KP:$KP" redpandadata/redpanda:latest \
    redpanda start --overprovisioned --smp 1 --memory 512M --kafka-addr "PLAINTEXT://0.0.0.0:$KP" --advertise-kafka-addr "PLAINTEXT://127.0.0.1:$KP" --mode dev-container || docker_ok=0
  run_c nats -p "$NP:4222" nats:latest -js || docker_ok=0
  run_c mqtt -p "$MP:1883" eclipse-mosquitto:2 mosquitto -c /mosquitto-no-auth.conf || docker_ok=0
  run_c redis -p "$RP:6379" redis:7 || docker_ok=0
  run_c pg --tmpfs /var/lib/postgresql/data -e POSTGRES_PASSWORD=zkpass -p "$GP:5432" postgres:16 || docker_ok=0
  run_c amqp --tmpfs /var/lib/rabbitmq -p "$AP:5672" -p "$AHP:15672" rabbitmq:3-alpine \
    sh -c 'rabbitmq-plugins enable --offline rabbitmq_management >/dev/null && exec docker-entrypoint.sh rabbitmq-server' || docker_ok=0
  if [[ $docker_ok == 1 ]]; then
  K="zkev-kafka-$$"; R="zkev-redis-$$"; G="zkev-pg-$$"; Q="zkev-mqtt-$$"
  for _ in $(seq 120); do docker exec "$K" rpk cluster health 2>/dev/null | grep -q 'Healthy:.*true' && break; sleep 1; done
  for _ in $(seq 120); do docker exec "$G" pg_isready -U postgres >/dev/null 2>&1 && break; sleep 1; done
  for _ in $(seq 120); do curl -s -u guest:guest "http://127.0.0.1:$AHP/api/overview" >/dev/null 2>&1 && break; sleep 1; done
  docker exec "$K" rpk topic create zkev >/dev/null
  python3 "$H" js-create "127.0.0.1:$NP" ZKEV zkev.js
  curl -s -u guest:guest -X PUT -H 'content-type: application/json' "http://127.0.0.1:$AHP/api/queues/%2f/zkevq" -d '{"durable":true}' >/dev/null
  curl -s -u guest:guest -X POST -H 'content-type: application/json' "http://127.0.0.1:$AHP/api/bindings/%2f/e/amq.direct/q/zkevq" -d '{"routing_key":"zkev"}' >/dev/null
  python3 "$H" nats-sub "127.0.0.1:$NP" zkev.core "$WORK/nats.out" & PID[natsub]=$!
  docker exec "$Q" sh -c 'mosquitto_sub -t zkev/# -v > /tmp/sub.out' & PID[mqttsub]=$!
  sleep 1

  set_t() { "$MC" admin config set z "$@" 2>&1 | tail -n1; }
  check "kafka target" "Successfully applied new settings." "$(set_t notify_kafka:1 brokers="127.0.0.1:$KP" topic=zkev)"
  check "nats target" "Successfully applied new settings." "$(set_t notify_nats:1 address="127.0.0.1:$NP" subject=zkev.core)"
  check "jetstream target" "Successfully applied new settings." "$(set_t notify_nats:js address="127.0.0.1:$NP" subject=zkev.js jetstream=on)"
  check "mqtt 3.1.1 target" "Successfully applied new settings." "$(set_t notify_mqtt:1 broker="tcp://127.0.0.1:$MP" topic=zkev/v3 qos=1)"
  check "mqtt 5 target" "Successfully applied new settings." "$(set_t notify_mqtt:5 broker="tcp://127.0.0.1:$MP" topic=zkev/v5 qos=2 protocol_version=5)"
  check "redis namespace target" "Successfully applied new settings." "$(set_t notify_redis:ns address="127.0.0.1:$RP" key=zkev:ns format=namespace)"
  check "redis access target" "Successfully applied new settings." "$(set_t notify_redis:acc address="127.0.0.1:$RP" key=zkev:acc format=access)"
  check "postgres namespace target" "Successfully applied new settings." "$(set_t notify_postgres:ns connection_string="host=127.0.0.1 port=$GP user=postgres password=zkpass dbname=postgres sslmode=disable" table=zkevns format=namespace)"
  check "postgres access target" "Successfully applied new settings." "$(set_t notify_postgres:acc connection_string="host=127.0.0.1 port=$GP user=postgres password=zkpass dbname=postgres sslmode=disable" table=zkevacc format=access)"
  check "amqp target" "Successfully applied new settings." "$(set_t notify_amqp:1 url="amqp://guest:guest@127.0.0.1:$AP/" exchange=amq.direct exchange_type=direct routing_key=zkev publisher_confirms=on)"
  check "audit kafka target" "Successfully applied new settings." "$(set_t audit_kafka:k brokers="127.0.0.1:$KP" topic=zkaudit)"
  "$MC" mb z/brokers >/dev/null
  for arn in kafka:1 nats:1 nats:js mqtt:1 mqtt:5 redis:ns redis:acc postgresql:ns postgresql:acc amqp:1; do
    "$MC" event add z/brokers "arn:minio:sqs::${arn#*:}:${arn%%:*}" --event put,delete >/dev/null
  done
  check "ten broker rules" 10 "$("$MC" event ls z/brokers | grep -c arn:minio:sqs)"
  echo k1 | "$MC" pipe z/brokers/obj1.txt >/dev/null
  echo k2 | "$MC" pipe z/brokers/obj2.txt >/dev/null
  "$MC" rm z/brokers/obj2.txt >/dev/null
  eventually "kafka received the events" 3 sh -c "docker exec $K rpk topic consume zkev -n 3 -f '%v\n' 2>/dev/null | grep -c 'brokers/obj'"
  eventually "nats received the events" 3 sh -c "grep -c 'brokers/obj' '$WORK/nats.out'"
  eventually "jetstream stored the events" 3 python3 "$H" js-count "127.0.0.1:$NP" ZKEV
  eventually "mqtt 3.1.1 received the events" 3 sh -c "docker exec $Q grep -c '^zkev/v3 .*brokers/obj' /tmp/sub.out"
  eventually "mqtt 5 received the events" 3 sh -c "docker exec $Q grep -c '^zkev/v5 .*brokers/obj' /tmp/sub.out"
  eventually "redis namespace keeps live objects" "brokers/obj1.txt" sh -c "docker exec $R redis-cli HKEYS zkev:ns | tr -d '\r'"
  eventually "redis access log has every event" 3 sh -c "docker exec $R redis-cli LLEN zkev:acc"
  eventually "postgres namespace keeps live objects" "brokers/obj1.txt" sh -c "docker exec $G psql -U postgres -tAc 'select key from zkevns'"
  eventually "postgres access log has every event" 3 sh -c "docker exec $G psql -U postgres -tAc 'select count(*) from zkevacc'"
  check "postgres row holds the record" "s3:ObjectCreated:CompleteMultipartUpload" "$(docker exec "$G" psql -U postgres -tAc "select value->>'eventName' from zkevns")"
  eventually "amqp delivered the events" 3 sh -c "curl -s -u guest:guest 'http://127.0.0.1:$AHP/api/queues/%2f/zkevq' | python3 -c 'import json,sys; print(json.load(sys.stdin).get(\"messages\",0))'"
  eventually "audit kafka receives entries" 1 sh -c "docker exec $K rpk topic consume zkaudit -n 1 -f '%v\n' 2>/dev/null | grep -c '\"version\":\"1\"'"

  echo "== broker outage and recovery"
  docker stop "$R" >/dev/null
  for c in "${!CONTAINERS[@]}"; do [[ "${CONTAINERS[$c]}" == "$R" ]] && unset "CONTAINERS[$c]"; done
  echo k3 | "$MC" pipe z/brokers/obj3.txt >/dev/null
  eventually "redis events queue during the outage" 1 metric 'zkfsm_notify_target_queue_length{target_id="ns",target_name="notify_redis"}'
  run_c redis -p "$RP:6379" redis:7
  eventually "redis catches up after the outage" 1 sh -c "docker exec $R redis-cli HKEYS zkev:ns 2>/dev/null | grep -c obj3"
  if docker image inspect mysql:8 >/dev/null 2>&1; then
    echo "(mysql: image present but not wired here)"
  else
    echo "skip mysql: no mysql image available locally (verified by the in-process fake server tests)"
  fi
  else
    echo "SKIP brokers: docker could not start the broker containers (see above)"
  fi
else
  echo "skip brokers: EVENTS_BROKERS=0 or docker unavailable"
fi

if command -v initdb >/dev/null && command -v postgres >/dev/null && command -v psql >/dev/null; then
  echo "== postgres server (local binaries)"
  PGP="$(freeport)"
  echo zkpass >"$WORK/pgpw"
  initdb -D "$WORK/pg" -U postgres --auth=scram-sha-256 --pwfile="$WORK/pgpw" >"$WORK/initdb.log" 2>&1
  pg_up() {
    postgres -D "$WORK/pg" -p "$PGP" -k "$WORK" -c listen_addresses=127.0.0.1 >>"$WORK/pg.log" 2>&1 &
    PID[pg]=$!
    for _ in $(seq 100); do PGPASSWORD=zkpass psql -h 127.0.0.1 -p "$PGP" -U postgres -tAc 'select 1' >/dev/null 2>&1 && return 0; sleep 0.2; done
    echo "postgres did not start"; tail -n 20 "$WORK/pg.log"; exit 1
  }
  pg_down() { kill -INT "${PID[pg]}" 2>/dev/null || true; wait "${PID[pg]}" 2>/dev/null || true; unset "PID[pg]"; }
  pgq() { PGPASSWORD=zkpass psql -h 127.0.0.1 -p "$PGP" -U postgres -tAc "$1"; }
  pg_up
  CS="host=127.0.0.1 port=$PGP user=postgres password=zkpass dbname=postgres sslmode=disable"
  check "postgres namespace target (scram)" "Successfully applied new settings." "$("$MC" admin config set z notify_postgres:lns connection_string="$CS" table=lns format=namespace 2>&1 | tail -n1)"
  check "postgres access target" "Successfully applied new settings." "$("$MC" admin config set z notify_postgres:lacc connection_string="$CS" table=lacc format=access 2>&1 | tail -n1)"
  "$MC" mb z/pgb >/dev/null
  "$MC" event add z/pgb arn:minio:sqs::lns:postgresql --event put,delete >/dev/null
  "$MC" event add z/pgb arn:minio:sqs::lacc:postgresql --event put,delete >/dev/null
  echo 1 | "$MC" pipe z/pgb/a.txt >/dev/null
  echo 2 | "$MC" pipe z/pgb/b.txt >/dev/null
  "$MC" rm z/pgb/b.txt >/dev/null
  eventually "namespace table keeps live objects" "pgb/a.txt" pgq 'select key from lns order by key'
  eventually "access table logs every event" 3 pgq 'select count(*) from lacc'
  check "audit to postgres" "Successfully applied new settings." "$("$MC" admin config set z audit_postgres:pa connection_string="$CS" table=auditlog 2>&1 | tail -n1)"
  echo au | "$MC" pipe z/other/audited-pg.txt >/dev/null
  eventually "audit rows in postgres" 1 sh -c "PGPASSWORD=zkpass psql -h 127.0.0.1 -p $PGP -U postgres -tAc \"select count(*) > 0 from auditlog where event_data->'api'->>'object' = 'audited-pg.txt'\" | sed 's/t/1/;s/f/0/'"
  "$MC" admin config reset z audit_postgres:pa >/dev/null
  check "namespace row holds the record" "pgb" "$(pgq "select value->'Records'->0->'s3'->'bucket'->>'name' from lns")"
  pg_down
  echo 3 | "$MC" pipe z/pgb/c.txt >/dev/null
  eventually "events queue while postgres is down" 1 metric 'zkfsm_notify_target_queue_length{target_id="lns",target_name="notify_postgres"}'
  pg_up
  eventually "postgres catches up after restart" "pgb/a.txt pgb/c.txt" sh -c "PGPASSWORD=zkpass psql -h 127.0.0.1 -p $PGP -U postgres -tAc 'select key from lns order by key' | tr '\n' ' ' | sed 's/ \$//'"
  eventually "access log complete after restart" 4 pgq 'select count(*) from lacc'
  pg_down
fi

echo "== cluster: events on every node"
stop
CP=(0 "$(freeport)" "$(freeport)" "$(freeport)" "$(freeport)")
POOL=()
for i in 1 2 3 4; do POOL+=("http://127.0.0.1:${CP[$i]}$WORK/c$i/d{1...2}"); done
for i in 1 2 3 4; do
  ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$BIN" --data "${POOL[@]}" --listen "127.0.0.1:${CP[$i]}" --node-address "127.0.0.1:${CP[$i]}" --protection EC:4+2 --cluster-refresh 2 >>"$WORK/c$i.log" 2>&1 &
  PID[c$i]=$!
done
for i in 1 2 3 4; do
  for _ in $(seq 600); do [[ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${CP[$i]}/health/ready")" == 200 ]] && break; sleep 0.1; done
  "$MC" alias set "c$i" "http://127.0.0.1:${CP[$i]}" "$AK" "$SK" >/dev/null
done
"$MC" admin config set c1 notify_webhook:cl endpoint="http://127.0.0.1:$WH/hook" >/dev/null
"$MC" mb c1/clb >/dev/null
sleep 3
# Other nodes pick up the target within their config refresh.
eventually "target known on node 4" 0 sh -c "'$MC' event add c4/clb arn:minio:sqs::cl:webhook --event put >/dev/null 2>&1 && echo 0"
sleep 3
for i in 1 2 3 4; do echo "n$i" | "$MC" pipe "c$i/clb/from-node$i.txt" >/dev/null; done
eventually "every node publishes its own writes" "from-node1.txt from-node2.txt from-node3.txt from-node4.txt" sh -c "python3 '$H' keys '$HOOK' 's3:ObjectCreated:*' | grep from-node | sort | tr '\n' ' ' | sed 's/ \$//'"
check "each cluster event delivered once" 4 "$(count "$HOOK" '"Key":"clb/from-node')"
"$MC" watch c1/clb --events put >"$WORK/cwatch.out" 2>&1 &
PID[cwatch]=$!
sleep 2
for i in 2 3 4; do echo "w$i" | "$MC" pipe "c$i/clb/watched-$i.txt" >/dev/null; done
eventually "mc watch on one node sees writes on every node" 3 sh -c "grep -c 'clb/watched-' '$WORK/cwatch.out'"
kill "${PID[cwatch]}" 2>/dev/null || true; unset "PID[cwatch]"

echo "events: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
