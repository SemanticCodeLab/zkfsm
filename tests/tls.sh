#!/usr/bin/env bash
# TLS 1.3 interop: openssl, curl, an S3 CLI, mc, python ssl; negative and fuzz cases.
# Keys and certificates are generated per run in a temp dir and never kept.
set -euo pipefail
S3CLI_BIN="${S3CLI_BIN:-aws}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$WORK"; }
trap cleanup EXIT

freeport() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
pass=0
fail=0
check() { # name expected actual
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); echo "ok   $1"
  else fail=$((fail + 1)); echo "FAIL $1: expected [$2] got [$3]"; fi
}

AK="zkfsmtlsaccess"
SK="zkfsm/tls+secret0123456789"
export AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_DEFAULT_REGION=us-east-1
export AWS_CONFIG_FILE="$WORK/s3cli.conf" AWS_SHARED_CREDENTIALS_FILE="$WORK/s3cli.creds" AWS_PAGER=""
printf '[default]\ns3 =\n  addressing_style = path\n' >"$AWS_CONFIG_FILE"
export MC_CONFIG_DIR="$WORK/mc"
MC="${MC:-$(command -v mc || true)}"

(cd "$ROOT" && zig build)
BIN="$ROOT/zig-out/bin/zkfsm"

# ---- PKI: an EC CA signing an EC leaf and RSA leaves ----
cd "$WORK"
SAN="subjectAltName=IP:127.0.0.1,DNS:localhost"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.crt -days 2 -subj /CN=zkfsm-test-ca \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
leaf() { # name keyfile
  openssl req -new -key "$2" -subj /CN=localhost -out "$1.csr" 2>/dev/null
  openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 -extfile <(echo "$SAN") -out "$1.crt" 2>/dev/null
  cat "$1.crt" ca.crt >"$1.chain"
}
openssl ecparam -name prime256v1 -genkey -noout -out ec.sec1.key 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in ec.sec1.key -out ec.p8.key
leaf ec ec.p8.key
for bits in 2048 3072 4096; do
  openssl genrsa -traditional -out "rsa$bits.pkcs1.key" "$bits" 2>/dev/null
  openssl pkcs8 -topk8 -nocrypt -in "rsa$bits.pkcs1.key" -out "rsa$bits.p8.key"
  leaf "rsa$bits" "rsa$bits.p8.key"
done
mkdir -p certs && cp ec.chain certs/public.crt && cp ec.sec1.key certs/private.key

start() { # port, args...
  local port="$1"; shift
  local creds=(ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK")
  [[ " $* " == *" --anonymous "* ]] && creds=()
  env "${creds[@]}" "$BIN" --data "$WORK/data-$port" --listen "127.0.0.1:$port" "$@" 2>"$WORK/server-$port.log" &
  PIDS+=($!)
  for _ in $(seq 300); do grep -q listening "$WORK/server-$port.log" 2>/dev/null && return 0; sleep 0.1; done
  echo "server did not start:"; cat "$WORK/server-$port.log"; exit 1
}
sclient() { # port, extra args...; prints the transcript
  local port="$1"; shift
  timeout 20 openssl s_client -connect "127.0.0.1:$port" -CAfile "$WORK/ca.crt" -verify_return_error "$@" </dev/null 2>&1 || true
}
alive() { curl -s -o /dev/null -w '%{http_code}' --cacert "$WORK/ca.crt" "https://127.0.0.1:$1/minio/health/live"; }

PORT="$(freeport)"
EP="https://127.0.0.1:$PORT"
start "$PORT" --certs-dir "$WORK/certs"
SPID="${PIDS[-1]}"

# ---- openssl: suites x groups, HelloRetryRequest ----
for suite in TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256; do
  for groups in X25519 P-256 P-384:X25519 P-384:P-256; do
    out="$(sclient "$PORT" -tls1_3 -ciphersuites "$suite" -groups "$groups" -servername localhost -msg)"
    got="$(grep -c "Verify return code: 0 (ok)" <<<"$out")/$(grep -o "Cipher is $suite" <<<"$out" | head -1)"
    check "s_client $suite $groups" "1/Cipher is $suite" "$got"
    if [[ "$groups" == P-384:* ]]; then
      check "hello retry $groups" 2 "$(grep -c '>>> .*ClientHello' <<<"$out")"
    fi
  done
done
check "s_client group secp256r1" 1 "$(sclient "$PORT" -tls1_3 -groups P-256 | grep -c 'Temp Key: ECDH, prime256v1')"
check "s_client group x25519" 1 "$(sclient "$PORT" -tls1_3 -groups X25519 | grep -c 'Temp Key: X25519')"
check "s_client chain depth" 1 "$(sclient "$PORT" -tls1_3 -showcerts | grep -c 'depth=1 CN=zkfsm-test-ca')"
check "alpn http/1.1" 1 "$(sclient "$PORT" -tls1_3 -alpn h2,http/1.1 | grep -c 'ALPN protocol: http/1.1')"
check "alpn h2 only refused" 1 "$(sclient "$PORT" -tls1_3 -alpn h2 | grep -c 'alert no application protocol')"
check "sigalg mismatch refused" 1 "$(sclient "$PORT" -tls1_3 -sigalgs rsa_pss_rsae_sha256 | grep -c 'alert handshake failure')"

# KeyUpdate: client updates (k) and requests ours (K) mid-connection.
ku="$( (sleep 0.5; echo K; sleep 0.5; echo k; sleep 0.5; printf 'GET /minio/health/live HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n'; sleep 1) |
  timeout 20 openssl s_client -connect "127.0.0.1:$PORT" -CAfile ca.crt -tls1_3 2>&1 || true)"
check "key update" 1 "$(grep -c 'HTTP/1.1 200' <<<"$ku")"
check "key update sent" 2 "$(grep -c 'KEYUPDATE' <<<"$ku")"

# ---- negatives: old versions ----
for v in tls1 tls1_1 tls1_2; do
  out="$(sclient "$PORT" "-$v" -cipher 'DEFAULT:@SECLEVEL=0')"
  check "reject $v" 1 "$(grep -c 'Cipher is (NONE)' <<<"$out")"
done
check "tls1_2 alert protocol_version" 1 "$(sclient "$PORT" -tls1_2 | grep -c 'alert protocol version')"

# ---- RSA-PSS with each key size and format ----
for kf in rsa2048.pkcs1.key rsa3072.p8.key rsa4096.pkcs1.key rsa2048.p8.key; do
  bits="${kf:3:4}"
  rp="$(freeport)"
  start "$rp" --tls-cert "rsa$bits.chain" --tls-key "$kf"
  for sig in rsa_pss_rsae_sha256 rsa_pss_rsae_sha384 rsa_pss_rsae_sha512; do
    [[ "$bits" == 4096 && "$sig" != rsa_pss_rsae_sha256 ]] && continue
    out="$(sclient "$rp" -tls1_3 -sigalgs "$sig")"
    check "rsa $kf $sig" "1/1" "$(grep -c 'Verify return code: 0 (ok)' <<<"$out")/$(grep -c "Peer signature type: $sig" <<<"$out")"
  done
  kill "${PIDS[-1]}"; wait "${PIDS[-1]}" 2>/dev/null || true; unset 'PIDS[-1]'
done
check "ec pkcs8 key via env" ok "$(
  ep="$(freeport)"
  ZKFSM_TLS_CERT="$WORK/ec.chain" ZKFSM_TLS_KEY="$WORK/ec.p8.key" start "$ep" >/dev/null
  [[ "$(alive "$ep")" == 200 ]] && echo ok; kill "${PIDS[-1]}")"
check "mismatched key refused" 2 "$(set +e; "$BIN" --anonymous --data "$WORK/x" --listen 127.0.0.1:1 --tls-cert ec.crt --tls-key rsa2048.p8.key 2>/dev/null; echo $?)"

# ---- curl over https (anonymous instance) ----
head -c 3000000 /dev/urandom >obj.bin
MD5="$(md5sum obj.bin | cut -d' ' -f1)"
AP="$(freeport)"
start "$AP" --anonymous --tls-cert ec.chain --tls-key ec.sec1.key
AEP="https://127.0.0.1:$AP"
c=(--cacert "$WORK/ca.crt")
check "curl create bucket" 200 "$(curl -s -o /dev/null -w '%{http_code}' "${c[@]}" -X PUT "$AEP/tlsb")"
check "curl put" 200 "$(curl -s -o /dev/null -w '%{http_code}' "${c[@]}" -T obj.bin "$AEP/tlsb/obj.bin")"
check "curl get md5" "$MD5" "$(curl -s "${c[@]}" "$AEP/tlsb/obj.bin" | md5sum | cut -d' ' -f1)"
check "curl range" "$(head -c 20 obj.bin | tail -c 10 | md5sum)" "$(curl -s "${c[@]}" -r 10-19 "$AEP/tlsb/obj.bin" | md5sum)"
check "curl http version" "1.1" "$(curl -s -o /dev/null -w '%{http_version}' "${c[@]}" "$AEP/tlsb")"
check "curl untrusted refused" 60 "$(curl -s -o /dev/null "$AEP/" ; echo $?)"
check "curl keep-alive reuse" 2 "$(curl -sv "${c[@]}" "$AEP/tlsb" "$AEP/tlsb" 2>&1 | grep -c 'HTTP/1.1 200')"

# ---- S3 CLI ----
s3cli() { "$S3CLI_BIN" --endpoint-url "$EP" --ca-bundle "$WORK/ca.crt" "$@"; }
check "s3cli mb" 0 "$(s3cli s3 mb s3://clib >/dev/null 2>&1; echo $?)"
s3cli s3 cp obj.bin s3://clib/obj.bin >/dev/null
s3cli s3 cp s3://clib/obj.bin got-cli.bin >/dev/null
check "s3cli cp roundtrip" "$MD5" "$(md5sum got-cli.bin | cut -d' ' -f1)"
check "s3cli ls" 1 "$(s3cli s3 ls s3://clib | grep -c obj.bin)"

# ---- mc with a trusted CA ----
if [[ -n "$MC" ]] && "$MC" --version 2>/dev/null | grep -qi minio; then
  mkdir -p "$MC_CONFIG_DIR/certs/CAs" && cp ca.crt "$MC_CONFIG_DIR/certs/CAs/"
  "$MC" alias set z "$EP" "$AK" "$SK" >/dev/null
  check "mc mb" 0 "$("$MC" mb z/mcb >/dev/null 2>&1; echo $?)"
  "$MC" cp obj.bin z/mcb/obj.bin >/dev/null
  check "mc cat md5" "$MD5" "$("$MC" cat z/mcb/obj.bin | md5sum | cut -d' ' -f1)"
else
  echo "skip mc (MinIO client not found; set MC=)"
fi

# ---- python ssl client, including close_notify on shutdown ----
check "python ssl" "TLSv1.3 http/1.1 200 closed" "$(python3 - "$PORT" "$WORK/ca.crt" <<'EOF'
import socket, ssl, sys
ctx = ssl.create_default_context(cafile=sys.argv[2])
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.set_alpn_protocols(["http/1.1"])
with socket.create_connection(("127.0.0.1", int(sys.argv[1]))) as raw:
    s = ctx.wrap_socket(raw, server_hostname="localhost")
    s.sendall(b"GET /minio/health/live HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    data = b""
    while True:
        try:
            chunk = s.recv(4096)
        except ssl.SSLEOFError:
            print("no close_notify"); sys.exit(0)
        if not chunk: break
        data += chunk
    status = data.split(b" ")[1].decode()
    info = (s.version(), s.selected_alpn_protocol())
    s.unwrap()  # raises unless the server sent close_notify
    print(*info, status, "closed")
EOF
)"

# ---- fuzz: mutated ClientHellos and truncated records must not crash ----
python3 - "$PORT" <<'EOF'
import random, socket, ssl, sys
port = int(sys.argv[1])
inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
obj = ctx.wrap_bio(inc, out, server_hostname="localhost")
try: obj.do_handshake()
except ssl.SSLWantReadError: pass
hello = out.read()
rng = random.Random(1234)
def send(data, wait=0.3):
    s = socket.create_connection(("127.0.0.1", port)); s.settimeout(wait)
    try:
        s.sendall(data); s.shutdown(socket.SHUT_WR)
        while s.recv(4096): pass
    except OSError: pass
    s.close()
for i in range(400):
    b = bytearray(hello)
    for _ in range(rng.randint(1, 8)):
        op = rng.random(); j = rng.randrange(len(b))
        if op < 0.5: b[j] = rng.randrange(256)
        elif op < 0.7: b[j] ^= 1 << rng.randrange(8)
        elif op < 0.85: del b[j:j + rng.randint(1, 16)]
        else: b[j:j] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 16)))
        if not b: b = bytearray(hello[:5])
    send(bytes(b), 0.2)
for n in range(0, len(hello), 7): send(hello[:n], 0.1)          # truncated records
send(b"\x16\x03\x03\xff\xff" + b"\x00" * 64)                      # oversized length
send(b"\x17\x03\x03\x00\x10" + b"\x00" * 16)                      # app data before handshake
print("fuzz done")
EOF
check "survives fuzz" 200 "$(alive "$PORT")"
check "record overflow alert" 22 "$(python3 -c '
import socket,sys; s=socket.create_connection(("127.0.0.1",int(sys.argv[1]))); s.settimeout(3)
s.sendall(b"\x16\x03\x03\x48\x01"); r=s.recv(16); print(r[6] if len(r)>=7 else -1)' "$PORT")"
check "server process alive" 0 "$(kill -0 "$SPID"; echo $?)"

# ---- SIGHUP reload ----
old="$(sclient "$PORT" -tls1_3 | grep -m1 -o 'Server certificate' || true)"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout new.key -out new.crt -days 2 -subj /CN=reloaded -addext "$SAN" 2>/dev/null
echo "not a key" >certs/private.key
kill -HUP "$SPID"; sleep 0.6
check "bad reload keeps serving" 200 "$(alive "$PORT")"
cp new.crt certs/public.crt && cp new.key certs/private.key
kill -HUP "$SPID"; sleep 0.6
check "reload serves new cert" 1 "$(timeout 10 openssl s_client -connect "127.0.0.1:$PORT" -CAfile new.crt </dev/null 2>&1 | grep -c 'subject=CN=reloaded')"
check "old CA no longer matches" 60 "$(curl -s -o /dev/null --cacert ca.crt "$EP/"; echo $?)"
[[ -n "$old" ]] || true

echo "passed $pass, failed $fail"
[[ $fail -eq 0 ]]
