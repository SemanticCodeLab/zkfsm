#!/usr/bin/env bash
# Outbound mutual TLS end to end: a private CA, a server certificate and client
# certificates from openssl; then each client against a server that demands a client
# certificate: webhook (local python HTTPS, TLS 1.3 and a TLS 1.2-only one), NATS,
# NSQ (IDENTIFY tls_v1 upgrade), Kafka, Vault (token and TLS cert auth) and OpenLDAP
# (LDAPS and StartTLS). Every case also checks the connection is refused without a
# client certificate. Containers that cannot be started print a SKIP line.
set -euo pipefail
S3CLI_BIN="${S3CLI_BIN:-aws}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
MC="${MC:-$(command -v mc || true)}"
if [[ -z "$MC" ]] || ! "$MC" --version >/dev/null 2>&1; then echo "mtls.sh needs the MinIO client (set MC)"; exit 1; fi
H="$ROOT/tests/mtls_helper.py"
TAG="zkfsm-mtls-$$"
declare -A PID=()
CONTAINERS=()
cleanup() {
  if [[ "${fail:-0}" -gt 0 ]]; then echo "--- server log tail"; tail -n 40 "$WORK/z.log" 2>/dev/null || true; fi
  for p in "${PID[@]}"; do kill -9 "$p" 2>/dev/null || true; done
  for c in "${CONTAINERS[@]}"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

pass=0
fail=0
skip=0
check() { # name expected actual
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); echo "ok   $1"
  else fail=$((fail + 1)); echo "FAIL $1: expected [$2] got [$3]"; fi
}
skipped() { skip=$((skip + 1)); echo "SKIP $1"; }
eventually() { # name expected command... (retries for up to 60 s)
  local name="$1" want="$2" got=""; shift 2
  for _ in $(seq 120); do got="$("$@" 2>/dev/null || true)"; [[ "$got" == "$want" ]] && break; sleep 0.5; done
  check "$name" "$want" "$got"
}
freeport() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
ok() { if "$@" >/dev/null 2>&1; then echo 0; else echo 1; fi; }
have_image() { docker image inspect "$1" >/dev/null 2>&1 || timeout 600 docker pull -q "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------- PKI
PKI="$WORK/pki"
mkdir -p "$PKI"
cat >"$PKI/ext.cnf" <<'EOF'
[ca]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
[srv]
basicConstraints=CA:FALSE
subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
[cli]
basicConstraints=CA:FALSE
extendedKeyUsage=clientAuth
EOF
mkca() { # name
  openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null | openssl pkcs8 -topk8 -nocrypt -out "$PKI/$1.key"
  openssl req -x509 -new -key "$PKI/$1.key" -subj "/CN=$1" -days 2 -out "$PKI/$1.pem" -config <(printf '[req]\ndistinguished_name=dn\n[dn]\n') -extensions ca -extfile "$PKI/ext.cnf" 2>/dev/null \
    || openssl req -x509 -new -key "$PKI/$1.key" -subj "/CN=$1" -days 2 -out "$PKI/$1.pem" -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign
}
mkcert() { # name cn ca ext [keytype]
  if [[ "${5:-ec}" == rsa ]]; then openssl genrsa -out "$PKI/$1.key" 2048 2>/dev/null
  else openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null | openssl pkcs8 -topk8 -nocrypt -out "$PKI/$1.key"; fi
  openssl req -new -key "$PKI/$1.key" -subj "/CN=$2" -out "$PKI/$1.csr" 2>/dev/null
  openssl x509 -req -in "$PKI/$1.csr" -CA "$PKI/$3.pem" -CAkey "$PKI/$3.key" -CAcreateserial -days 2 -extfile "$PKI/ext.cnf" -extensions "$4" -out "$PKI/$1.pem" 2>/dev/null
}
mkca ca
mkca rogue
mkcert server localhost ca srv
mkcert server-rsa localhost ca srv rsa
mkcert client zkfsm-client ca cli
mkcert client-rsa zkfsm-client-rsa ca cli rsa
mkcert rogue-client rogue-client rogue cli
cat "$PKI/server.pem" "$PKI/server.key" >"$PKI/server-bundle.pem"
chmod 644 "$PKI"/*
CA="$PKI/ca.pem"
CC="$PKI/client.pem"
CK="$PKI/client.key"
check "test PKI generated" 0 "$(ok openssl verify -CAfile "$CA" "$PKI/server.pem" "$CC")"

# ---------------------------------------------------------------- server
AK="mtlsadmin"
SK="mtls-admin-secret-0123"
export AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_DEFAULT_REGION=us-east-1 AWS_PAGER=""
export AWS_CONFIG_FILE="$WORK/s3cli.conf" AWS_SHARED_CREDENTIALS_FILE="$WORK/s3cli.creds"
printf '[default]\ns3 =\n  addressing_style = path\n' >"$AWS_CONFIG_FILE"
export MC_CONFIG_DIR="$WORK/mc"
(cd "$ROOT" && zig build -Doptimize=ReleaseSafe)
BIN="$ROOT/zig-out/bin/zkfsm"
P="$(freeport)"
ep="http://127.0.0.1:$P"
start() { # data dir, extra flags... (environment passes through)
  local data="$1"; shift
  env ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$BIN" --data "$data" --listen "127.0.0.1:$P" "$@" >>"$WORK/z.log" 2>&1 &
  PID[z]=$!
  for _ in $(seq 300); do [[ "$(curl -s -o /dev/null -w '%{http_code}' "$ep/health/ready")" == 200 ]] && return 0; sleep 0.1; done
  echo "server not ready"; tail -n 30 "$WORK/z.log"; exit 1
}
stop() { kill -9 "${PID[z]}" 2>/dev/null || true; wait "${PID[z]}" 2>/dev/null || true; unset "PID[z]"; }
metric() { curl -s "$ep/metrics" | awk -v m="$1" 'index($0, m" ")==1 {print $2}'; }
set_t() { "$MC" admin config set z "$@" 2>&1 | tail -n1; }
applied="Successfully applied new settings."
put() { echo "$2" | "$MC" pipe "z/$1/$2" >/dev/null; }
online() { metric "zkfsm_notify_target_online{target_id=\"$2\",target_name=\"$1\"}"; }

start "$WORK/d"
"$MC" alias set z "$ep" "$AK" "$SK" >/dev/null
"$MC" mb z/allow z/deny >/dev/null

# ---------------------------------------------------------------- webhook
WH="$(freeport)"
WH12="$(freeport)"
python3 "$H" https-recv "$WH" "$WORK/hook" "$PKI/server.pem" "$PKI/server.key" "$CA" & PID[wh]=$!
python3 "$H" https-recv "$WH12" "$WORK/hook12" "$PKI/server-rsa.pem" "$PKI/server-rsa.key" "$CA" tls1.2 & PID[wh12]=$!
sleep 0.5
echo "== webhook"
check "webhook target with client cert" "$applied" "$(set_t notify_webhook:mtls endpoint="https://localhost:$WH/mtls" client_cert="$CC" client_key="$CK" tls_ca_file="$CA")"
check "webhook target without client cert" "$applied" "$(set_t notify_webhook:nocert endpoint="https://localhost:$WH/nocert" tls_ca_file="$CA")"
check "webhook target with an untrusted client cert" "$applied" "$(set_t notify_webhook:rogue endpoint="https://localhost:$WH/rogue" client_cert="$PKI/rogue-client.pem" client_key="$PKI/rogue-client.key" tls_ca_file="$CA")"
check "webhook TLS 1.2-only target (RSA client key)" "$applied" "$(set_t notify_webhook:tls12 endpoint="https://127.0.0.1:$WH12/tls12" client_cert="$PKI/client-rsa.pem" client_key="$PKI/client-rsa.key" tls_ca_file="$CA")"
check "webhook min version 1.3 against a 1.2 server" "$applied" "$(set_t notify_webhook:min13 endpoint="https://localhost:$WH12/min13" client_cert="$CC" client_key="$CK" tls_ca_file="$CA" tls_min_version=1.3)"
check "missing client key file rejected" 1 "$(ok "$MC" admin config set z notify_webhook:bad endpoint="https://localhost:$WH/x" client_cert="$CC" client_key="$WORK/nope.key")"
check "bad min version rejected" 1 "$(ok "$MC" admin config set z notify_webhook:bad endpoint="https://localhost:$WH/x" tls_min_version=1.1)"
"$MC" event add z/allow arn:minio:sqs::mtls:webhook --event put --prefix wh/ >/dev/null
"$MC" event add z/allow arn:minio:sqs::tls12:webhook --event put --prefix wh12/ >/dev/null
"$MC" event add z/deny arn:minio:sqs::nocert:webhook --event put --prefix wh/ >/dev/null
"$MC" event add z/deny arn:minio:sqs::rogue:webhook --event put --prefix rogue/ >/dev/null
"$MC" event add z/deny arn:minio:sqs::min13:webhook --event put --prefix min13/ >/dev/null
put allow wh/a.txt
put allow wh12/b.txt
put deny wh/c.txt
put deny rogue/d.txt
put deny min13/e.txt
eventually "webhook event delivered over mTLS (TLS 1.3, client CN seen)" 1 sh -c "grep -c '^/mtls zkfsm-client TLSv1.3 .*allow/wh/a.txt' '$WORK/hook'"
eventually "webhook event delivered to a TLS 1.2-only server" 1 sh -c "grep -c '^/tls12 zkfsm-client-rsa TLSv1.2 .*allow/wh12/b.txt' '$WORK/hook12'"
eventually "webhook without client cert is offline" 0 online notify_webhook nocert
eventually "webhook with untrusted client cert is offline" 0 online notify_webhook rogue
eventually "webhook min version 1.3 refuses a 1.2 server" 0 online notify_webhook min13
check "receiver refused the handshakes" 1 "$(awk 'END{print (NR>=2)}' "$WORK/hook.refused" 2>/dev/null || echo 0)"
check "no deny events delivered" 0 "$(cat "$WORK/hook" "$WORK/hook12" | grep -c 'deny/' || true)"
check "mTLS webhook online" 1 "$(online notify_webhook mtls)"

docker_ok=1
command -v docker >/dev/null 2>&1 || docker_ok=0
run_c() { # name docker-create-args...; the PKI is copied to /pki (TMPDIR may not be shareable)
  local n="$TAG-$1"; shift
  docker rm -f "$n" >/dev/null 2>&1 || true
  docker create --name "$n" "$@" >/dev/null && CONTAINERS+=("$n")
  docker cp "$PKI/." "$n:/pki" && docker start "$n" >/dev/null
}

# ---------------------------------------------------------------- NATS
echo "== nats"
if [[ $docker_ok == 1 ]] && have_image nats:latest; then
  NP="$(freeport)"
  cat >"$PKI/nats.conf" <<'EOF'
tls { cert_file: "/pki/server.pem", key_file: "/pki/server.key", ca_file: "/pki/ca.pem", verify: true, timeout: 5 }
EOF
  chmod 644 "$PKI/nats.conf"
  run_c nats -p "127.0.0.1:$NP:4222" nats:latest -c /pki/nats.conf
  for _ in $(seq 100); do timeout 1 bash -c "head -c 4 </dev/tcp/127.0.0.1/$NP" 2>/dev/null | grep -q INFO && break; sleep 0.2; done
  python3 "$H" nats-sub "127.0.0.1:$NP" zkmtls "$WORK/nats.out" "$CA" "$CC" "$CK" & PID[natsub]=$!
  sleep 0.5
  check "nats target (client_cert, cert_authority)" "$applied" "$(set_t notify_nats:mtls address="localhost:$NP" subject=zkmtls tls=on client_cert="$CC" client_key="$CK" cert_authority="$CA")"
  check "nats target without client cert" "$applied" "$(set_t notify_nats:nocert address="localhost:$NP" subject=zkmtls tls=on cert_authority="$CA")"
  "$MC" event add z/allow arn:minio:sqs::mtls:nats --event put --prefix nats/ >/dev/null
  "$MC" event add z/deny arn:minio:sqs::nocert:nats --event put --prefix nats/ >/dev/null
  put allow nats/a.txt
  put deny nats/b.txt
  eventually "nats event delivered over mTLS" 1 sh -c "grep -c 'allow/nats/a.txt' '$WORK/nats.out'"
  eventually "nats without client cert is offline" 0 online notify_nats nocert
  check "nats received no deny events" 0 "$(grep -c 'deny/' "$WORK/nats.out" || true)"
else skipped "nats: docker or nats:latest unavailable"; fi

# ---------------------------------------------------------------- NSQ
echo "== nsq"
if [[ $docker_ok == 1 ]] && have_image nsqio/nsq; then
  QP="$(freeport)"
  QH="$(freeport)"
  run_c nsq -p "127.0.0.1:$QP:4150" -p "127.0.0.1:$QH:4151" nsqio/nsq /nsqd \
    --tls-cert=/pki/server.pem --tls-key=/pki/server.key --tls-root-ca-file=/pki/ca.pem \
    --tls-client-auth-policy=require-verify --tls-required=tcp-https
  for _ in $(seq 50); do curl -sf "http://127.0.0.1:$QH/ping" >/dev/null && break; sleep 0.2; done
  nsq_count() { curl -sf "http://127.0.0.1:$QH/stats?format=json&topic=$1" | python3 "$H" json-get topics 0 message_count; }
  check "nsq target (tls, client_cert)" "$applied" "$(set_t notify_nsq:mtls nsqd_address="localhost:$QP" topic=zkmtls tls=on client_cert="$CC" client_key="$CK" tls_ca_file="$CA")"
  check "nsq target without client cert" "$applied" "$(set_t notify_nsq:nocert nsqd_address="localhost:$QP" topic=zkdeny tls=on tls_ca_file="$CA")"
  check "nsq target without TLS" "$applied" "$(set_t notify_nsq:plain nsqd_address="localhost:$QP" topic=zkplain)"
  "$MC" event add z/allow arn:minio:sqs::mtls:nsq --event put --prefix nsq/ >/dev/null
  "$MC" event add z/deny arn:minio:sqs::nocert:nsq --event put --prefix nsq/ >/dev/null
  "$MC" event add z/deny arn:minio:sqs::plain:nsq --event put --prefix nsqplain/ >/dev/null
  put allow nsq/a.txt
  put allow nsq/b.txt
  put deny nsq/c.txt
  put deny nsqplain/d.txt
  eventually "nsq events delivered after the IDENTIFY tls_v1 upgrade" 2 nsq_count zkmtls
  eventually "nsq without client cert is offline" 0 online notify_nsq nocert
  eventually "nsq without TLS is refused (tls-required)" 0 online notify_nsq plain
  check "nsq stored nothing for refused targets" "|" "$(nsq_count zkdeny)|$(nsq_count zkplain)"
else skipped "nsq: docker or nsqio/nsq unavailable"; fi

# ---------------------------------------------------------------- Kafka
echo "== kafka"
KIMG="${KAFKA_IMAGE:-apache/kafka:3.9.0}"
if [[ $docker_ok == 1 ]] && have_image "$KIMG"; then
  KP="$(freeport)"
  cat >"$PKI/kafka.properties" <<EOF
process.roles=broker,controller
node.id=1
controller.quorum.voters=1@localhost:9094
listeners=PLAINTEXT://:9092,SSL://:$KP,CONTROLLER://:9094
advertised.listeners=PLAINTEXT://localhost:9092,SSL://localhost:$KP
listener.security.protocol.map=PLAINTEXT:PLAINTEXT,SSL:SSL,CONTROLLER:PLAINTEXT
controller.listener.names=CONTROLLER
inter.broker.listener.name=PLAINTEXT
log.dirs=/tmp/kraft-logs
offsets.topic.replication.factor=1
transaction.state.log.replication.factor=1
transaction.state.log.min.isr=1
auto.create.topics.enable=true
ssl.keystore.type=PEM
ssl.keystore.location=/pki/server-bundle.pem
ssl.truststore.type=PEM
ssl.truststore.location=/pki/ca.pem
ssl.client.auth=required
ssl.endpoint.identification.algorithm=
EOF
  chmod 644 "$PKI/kafka.properties"
  run_c kafka -p "127.0.0.1:$KP:$KP" "$KIMG" sh -c \
    "/opt/kafka/bin/kafka-storage.sh format -t q1Sh-9_ISia_zwGINzRvyQ -c /pki/kafka.properties >/dev/null && exec /opt/kafka/bin/kafka-server-start.sh /pki/kafka.properties"
  kup=0
  for _ in $(seq 120); do
    docker exec "$TAG-kafka" /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --create --if-not-exists --topic zkmtls >/dev/null 2>&1 && { kup=1; break; }
    sleep 1
  done
  if [[ $kup == 1 ]]; then
    docker exec "$TAG-kafka" /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --create --if-not-exists --topic zkdeny >/dev/null 2>&1
    kafka_count() { docker exec "$TAG-kafka" /opt/kafka/bin/kafka-get-offsets.sh --bootstrap-server localhost:9092 --topic "$1" 2>/dev/null | awk -F: '{s+=$3} END{print s+0}'; }
    check "kafka target (client_tls_cert, client_tls_key)" "$applied" "$(set_t notify_kafka:mtls brokers="localhost:$KP" topic=zkmtls tls=on client_tls_cert="$CC" client_tls_key="$CK" tls_ca_file="$CA")"
    check "kafka target without client cert" "$applied" "$(set_t notify_kafka:nocert brokers="localhost:$KP" topic=zkdeny tls=on tls_ca_file="$CA")"
    "$MC" event add z/allow arn:minio:sqs::mtls:kafka --event put --prefix kafka/ >/dev/null
    "$MC" event add z/deny arn:minio:sqs::nocert:kafka --event put --prefix kafka/ >/dev/null
    put allow kafka/a.txt
    put deny kafka/b.txt
    eventually "kafka event produced over mTLS" 1 kafka_count zkmtls
    eventually "kafka without client cert is offline" 0 online notify_kafka nocert
    check "kafka stored nothing for the refused target" 0 "$(kafka_count zkdeny)"
  else
    skipped "kafka: broker did not come up"
    docker logs "$TAG-kafka" 2>&1 | tail -n 15
  fi
else skipped "kafka: docker or $KIMG unavailable"; fi
stop

# ---------------------------------------------------------------- Vault
echo "== vault"
if [[ $docker_ok == 1 ]] && have_image hashicorp/vault:latest; then
  VP="$(freeport)"
  VS="$(freeport)"
  VTOKEN="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  cat >"$PKI/vault.hcl" <<'EOF'
listener "tcp" {
  address = "0.0.0.0:8201"
  tls_cert_file = "/pki/server.pem"
  tls_key_file = "/pki/server.key"
  tls_client_ca_file = "/pki/ca.pem"
  tls_require_and_verify_client_cert = "true"
}
EOF
  chmod 644 "$PKI/vault.hcl"
  run_c vault --cap-add=IPC_LOCK -p "127.0.0.1:$VP:8200" -p "127.0.0.1:$VS:8201" hashicorp/vault:latest \
    server -dev -dev-root-token-id="$VTOKEN" -dev-listen-address=0.0.0.0:8200 -config=/pki/vault.hcl
  VADDR="http://127.0.0.1:$VP"
  for _ in $(seq 100); do curl -sf "$VADDR/v1/sys/health" >/dev/null && break; sleep 0.2; done
  vapi() { curl -sf -H "X-Vault-Token: $VTOKEN" "$@"; }
  vapi -X POST -d '{"type":"transit"}' "$VADDR/v1/sys/mounts/transit" >/dev/null
  vapi -X PUT -d '{"policy":"path \"transit/*\" { capabilities = [\"create\",\"read\",\"update\",\"list\"] }"}' "$VADDR/v1/sys/policies/acl/zkfsm" >/dev/null
  vapi -X POST -d '{"type":"cert"}' "$VADDR/v1/sys/auth/cert" >/dev/null
  python3 -c 'import json,sys; print(json.dumps({"certificate": open(sys.argv[1]).read(), "token_policies": "zkfsm"}))' "$CA" >"$WORK/certrole.json"
  vapi -X POST --data @"$WORK/certrole.json" "$VADDR/v1/auth/cert/certs/zkfsm" >/dev/null
  check "vault mTLS listener refuses curl without a client cert" 1 "$(ok curl -sf --cacert "$CA" "https://localhost:$VS/v1/sys/health")"
  check "vault mTLS listener accepts the client cert" 0 "$(ok curl -sf --cacert "$CA" --cert "$CC" --key "$CK" "https://localhost:$VS/v1/sys/health")"
  head -c 100000 /dev/urandom >"$WORK/obj.bin"
  sse_rt() { # bucket key
    "$S3CLI_BIN" --endpoint-url "$ep" s3api put-object --bucket "$1" --key "$2" --body "$WORK/obj.bin" --server-side-encryption aws:kms >/dev/null 2>&1 \
      && "$S3CLI_BIN" --endpoint-url "$ep" s3api get-object --bucket "$1" --key "$2" "$WORK/rt.out" >/dev/null 2>&1 && cmp -s "$WORK/obj.bin" "$WORK/rt.out"
  }
  VAULT_ADDR="https://localhost:$VS" VAULT_TOKEN="$VTOKEN" VAULT_CACERT="$CA" VAULT_CLIENT_CERT="$CC" VAULT_CLIENT_KEY="$CK" \
    start "$WORK/dv1" --kms-backend vault
  "$S3CLI_BIN" --endpoint-url "$ep" s3api create-bucket --bucket kv1 >/dev/null
  check "SSE-KMS through Vault over mTLS (token auth)" 0 "$(ok sse_rt kv1 a)"
  check "default key created in Vault transit" 0 "$(ok vapi "$VADDR/v1/transit/keys/zkfsm-sse-s3")"
  stop
  VAULT_ADDR="https://localhost:$VS" KMS_VAULT_CAPATH="$CA" VAULT_CLIENT_CERT="$CC" VAULT_CLIENT_KEY="$CK" \
    start "$WORK/dv2" --kms-backend vault
  "$S3CLI_BIN" --endpoint-url "$ep" s3api create-bucket --bucket kv2 >/dev/null
  check "SSE-KMS through Vault TLS certificate auth (no token)" 0 "$(ok sse_rt kv2 b)"
  stop
  VAULT_ADDR="https://localhost:$VS" VAULT_TOKEN="$VTOKEN" VAULT_CACERT="$CA" start "$WORK/dv3" --kms-backend vault
  "$S3CLI_BIN" --endpoint-url "$ep" s3api create-bucket --bucket kv3 >/dev/null
  check "Vault refuses zkfsm without a client cert" 1 "$(ok sse_rt kv3 c)"
  stop
  VAULT_ADDR="https://localhost:$VS" VAULT_TOKEN="$VTOKEN" VAULT_CACERT="$PKI/rogue.pem" VAULT_CLIENT_CERT="$CC" VAULT_CLIENT_KEY="$CK" \
    start "$WORK/dv4" --kms-backend vault
  "$S3CLI_BIN" --endpoint-url "$ep" s3api create-bucket --bucket kv4 >/dev/null
  check "zkfsm refuses Vault's certificate from an unknown CA" 1 "$(ok sse_rt kv4 d)"
  stop
else skipped "vault: docker or hashicorp/vault unavailable"; fi

# ---------------------------------------------------------------- LDAP
echo "== ldap"
LIMG=osixia/openldap:1.5.0
if [[ $docker_ok == 1 ]] && have_image "$LIMG" && command -v ldapsearch >/dev/null 2>&1; then
  docker rm -f "$TAG-ldap" >/dev/null 2>&1 || true
  docker create --name "$TAG-ldap" -p 127.0.0.1::389 -p 127.0.0.1::636 \
    -e LDAP_TLS_VERIFY_CLIENT=demand -e LDAP_TLS_CIPHER_SUITE=NORMAL \
    -e LDAP_TLS_CRT_FILENAME=server.pem -e LDAP_TLS_KEY_FILENAME=server.key -e LDAP_TLS_CA_CRT_FILENAME=ca.pem \
    "$LIMG" >/dev/null && CONTAINERS+=("$TAG-ldap")
  docker cp "$PKI/server.pem" "$TAG-ldap:/container/service/slapd/assets/certs/server.pem"
  docker cp "$PKI/server.key" "$TAG-ldap:/container/service/slapd/assets/certs/server.key"
  docker cp "$CA" "$TAG-ldap:/container/service/slapd/assets/certs/ca.pem"
  docker start "$TAG-ldap" >/dev/null
  LP="$(docker port "$TAG-ldap" 389/tcp | head -1 | sed 's/.*://')"
  LSP="$(docker port "$TAG-ldap" 636/tcp | head -1 | sed 's/.*://')"
  cat >"$WORK/seed.ldif" <<'LDIF'
dn: ou=people,dc=example,dc=org
objectClass: organizationalUnit
ou: people

dn: uid=alice,ou=people,dc=example,dc=org
objectClass: inetOrgPerson
uid: alice
cn: Alice
sn: A
userPassword: alice-ldap-pw
LDIF
  for _ in $(seq 60); do
    docker exec -i "$TAG-ldap" ldapadd -x -H ldap://localhost -D cn=admin,dc=example,dc=org -w admin <"$WORK/seed.ldif" >/dev/null 2>&1 && break
    sleep 1
  done
  check "ldaps demands a client certificate (ldapsearch without one fails)" 1 "$(LDAPTLS_CACERT="$CA" ok ldapsearch -x -H "ldaps://localhost:$LSP" -b dc=example,dc=org -D cn=admin,dc=example,dc=org -w admin '(uid=alice)' dn)"
  start "$WORK/dl"
  sts() {
    local args=()
    for kv in "$@"; do args+=(--data-urlencode "$kv"); done
    curl -s -X POST "$ep/" -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode Version=2011-06-15 "${args[@]}"
  }
  akid() { sts Action=AssumeRoleWithLDAPIdentity LDAPUsername=alice LDAPPassword=alice-ldap-pw | python3 -c "import re,sys; m=re.search(r'<AccessKeyId>([^<]*)</AccessKeyId>', sys.stdin.read()); print(m.group(1)[:4] if m else 'none')"; }
  check "ldap idp with client cert (LDAPS)" 0 "$(ok "$MC" idp ldap add z "server_addr=localhost:$LSP" \
    lookup_bind_dn=cn=admin,dc=example,dc=org lookup_bind_password=admin \
    user_dn_search_base_dn=ou=people,dc=example,dc=org 'user_dn_search_filter=(uid=%s)' \
    tls_ca_file="$CA" tls_client_cert="$CC" tls_client_key="$CK")"
  "$MC" idp ldap policy attach z readwrite --user 'uid=alice,ou=people,dc=example,dc=org' >/dev/null
  eventually "ldap login over LDAPS with a client cert" ASIA akid
  check "ldap switch to StartTLS" 0 "$(ok "$MC" idp ldap update z "server_addr=localhost:$LP" server_starttls=on)"
  check "ldap login over StartTLS with a client cert" ASIA "$(akid)"
  check "ldap drop the client cert" 0 "$(ok "$MC" idp ldap update z "server_addr=localhost:$LSP" server_starttls=off tls_client_cert= tls_client_key=)"
  check "ldap login refused without a client cert" none "$(akid)"
  stop
else skipped "ldap: docker, $LIMG or ldapsearch unavailable"; fi

echo "mtls.sh: $pass passed, $fail failed, $skip skipped"
[[ $fail -eq 0 ]]
