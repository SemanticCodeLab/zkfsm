#!/usr/bin/env bash
# FTP / FTPS gateway end to end: curl (ftp://, explicit --ssl-reqd, implicit ftps://)
# and python ftplib (FTP, FTP_TLS, implicit), checked against the S3 API.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRATCH="${ZKFSM_FTP_SCRATCH:-${TMPDIR:-/tmp}}"
mkdir -p "$SCRATCH"
WORK="$(mktemp -d "$SCRATCH/zkfsm-ftp.XXXXXX")"
PID=""
cleanup() { [[ -n "$PID" ]] && kill "$PID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

freeport() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
pass=0
fail=0
check() { # name expected actual
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); echo "ok   $1"
  else fail=$((fail + 1)); echo "FAIL $1: expected [$2] got [$3]"; fi
}

AK="zkfsmftpaccess"
SK="ftp+secret0123456789"
PY="${PYTHON:-python3}"

(cd "$ROOT" && zig build)
BIN="$ROOT/zig-out/bin/zkfsm"

cd "$WORK"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout tls.key -out tls.crt -days 2 \
  -subj /CN=localhost -addext subjectAltName=IP:127.0.0.1,DNS:localhost 2>/dev/null

S3P=$(freeport); FTPP=$(freeport); FTPSP=$(freeport)
PLO=$(( (RANDOM % 2000) + 40000 )); PHI=$((PLO + 40))
ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$BIN" --data "$WORK/data" --listen "127.0.0.1:$S3P" \
  --tls-cert tls.crt --tls-key tls.key --ftp "127.0.0.1:$FTPP" --ftps "127.0.0.1:$FTPSP" \
  --ftp-passive-ports "$PLO-$PHI" 2>"$WORK/server.log" &
PID=$!
for _ in $(seq 300); do grep -q "ftps listening" "$WORK/server.log" 2>/dev/null && break; sleep 0.1; done
grep -q "ftps listening" "$WORK/server.log" || { echo "server did not start:"; cat "$WORK/server.log"; exit 1; }

EP="https://127.0.0.1:$S3P"
s3() { curl -sk --aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" "$@"; }
FTP="ftp://127.0.0.1:$FTPP"
FTPS="ftps://127.0.0.1:$FTPSP"
C=(curl -s --user "$AK:$SK" --max-time 60)
CK=(curl -sk --user "$AK:$SK" --max-time 60)

head -c 300000 /dev/urandom >obj.bin
MD5=$(md5sum obj.bin | cut -d' ' -f1)

# ---- curl over plain FTP ----
check "curl mkd bucket" 0 "$("${C[@]}" "$FTP/" -Q "MKD /cbkt" -o /dev/null; echo $?)"
check "curl upload" 0 "$("${C[@]}" -T obj.bin "$FTP/cbkt/dir/obj.bin" --ftp-create-dirs; echo $?)"
check "curl download" "$MD5" "$("${C[@]}" "$FTP/cbkt/dir/obj.bin" | md5sum | cut -d' ' -f1)"
check "curl list" "obj.bin" "$("${C[@]}" -l "$FTP/cbkt/dir/" | tr -d '\r')"
check "curl list long" 1 "$("${C[@]}" "$FTP/cbkt/dir/" | grep -c ' obj.bin')"
check "curl epsv off (PASV)" "$MD5" "$("${C[@]}" --disable-epsv "$FTP/cbkt/dir/obj.bin" | md5sum | cut -d' ' -f1)"
head -c 100000 obj.bin >part.bin
"${C[@]}" -C - -o part.bin "$FTP/cbkt/dir/obj.bin"
check "curl resume -C -" "$MD5" "$(md5sum part.bin | cut -d' ' -f1)"
check "curl bad password" 67 "$(curl -s --user "$AK:wrong" "$FTP/" -o /dev/null; echo $?)"
check "curl missing file" 78 "$("${C[@]}" "$FTP/cbkt/nope" -o /dev/null; echo $?)"

# ---- visibility over S3 ----
check "s3 sees ftp upload" "$MD5" "$(s3 "$EP/cbkt/dir/obj.bin" | md5sum | cut -d' ' -f1)"
echo "from-s3" >s3.txt
s3 -T s3.txt "$EP/cbkt/s3.txt" -o /dev/null
check "ftp sees s3 upload" "from-s3" "$("${C[@]}" "$FTP/cbkt/s3.txt")"
check "curl delete" 0 "$("${C[@]}" "$FTP/cbkt/" -Q "DELE /cbkt/s3.txt" -o /dev/null; echo $?)"
check "s3 sees delete" 404 "$(s3 -o /dev/null -w '%{http_code}' "$EP/cbkt/s3.txt")"

# ---- curl explicit FTPS ----
check "explicit upload" 0 "$("${CK[@]}" --ssl-reqd -T obj.bin "$FTP/cbkt/tls.bin"; echo $?)"
check "explicit download" "$MD5" "$("${CK[@]}" --ssl-reqd "$FTP/cbkt/tls.bin" | md5sum | cut -d' ' -f1)"
check "explicit list" 1 "$("${CK[@]}" --ssl-reqd -l "$FTP/cbkt/" | tr -d '\r' | grep -cx tls.bin)"
check "explicit mkd" 0 "$("${CK[@]}" --ssl-reqd "$FTP/cbkt/" -Q "MKD /cbkt/newdir" -o /dev/null; echo $?)"
check "explicit control-only (--ftp-ssl-control)" "$MD5" "$("${CK[@]}" --ftp-ssl-control "$FTP/cbkt/tls.bin" | md5sum | cut -d' ' -f1)"

# ---- curl implicit FTPS ----
check "implicit upload" 0 "$("${CK[@]}" -T obj.bin "$FTPS/cbkt/imp.bin"; echo $?)"
check "implicit download" "$MD5" "$("${CK[@]}" "$FTPS/cbkt/imp.bin" | md5sum | cut -d' ' -f1)"
check "implicit list" 1 "$("${CK[@]}" -l "$FTPS/cbkt/" | tr -d '\r' | grep -cx imp.bin)"
head -c 1000 obj.bin >ipart.bin
"${CK[@]}" -C - -o ipart.bin "$FTPS/cbkt/imp.bin"
check "implicit resume" "$MD5" "$(md5sum ipart.bin | cut -d' ' -f1)"
check "implicit rmd" 0 "$("${CK[@]}" "$FTPS/cbkt/" -Q "RMD /cbkt/newdir" -o /dev/null; echo $?)"
check "implicit bad cert rejected" 60 "$(curl -s --user "$AK:$SK" "$FTPS/" -o /dev/null; echo $?)"
check "s3 sees implicit upload" "$MD5" "$(s3 "$EP/cbkt/imp.bin" | md5sum | cut -d' ' -f1)"

# ---- bucket quota (admin API, as mc admin bucket quota does) ----
"${C[@]}" "$FTP/" -Q "MKD /qbkt" -o /dev/null
s3 -X PUT -d '{"quota":200000,"quotatype":"hard"}' "$EP/minio/admin/v3/set-bucket-quota?bucket=qbkt" -o /dev/null
check "quota upload under limit" 0 "$(head -c 100000 obj.bin | "${C[@]}" -T - "$FTP/qbkt/small.bin"; echo $?)"
check "quota upload over limit rejected" 70"$("${C[@]}" -T obj.bin "$FTP/qbkt/big.bin"; echo $?)"
check "quota reply is 552" 1 "$("${C[@]}" -v -T obj.bin "$FTP/qbkt/big2.bin" 2>&1 | grep -c '^< 552 Quota exceeded')"

# ---- raw protocol checks ----
raw() { # commands...; prints the server's replies
  "$PY" - "$FTPP" "$@" <<'PYEOF'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10)
f = s.makefile("rb")
def resp():
    line = f.readline().decode()
    out = line
    if len(line) > 3 and line[3] == "-":
        while True:
            l = f.readline().decode(); out += l
            if l[:3] == line[:3] and l[3:4] == " ": break
    return out
print(resp().strip())
for c in sys.argv[2:]:
    s.sendall(c.encode() + b"\r\n"); print(resp().strip())
PYEOF
}
check "unauth list refused" "530" "$(raw "LIST" | sed -n 2p | cut -c1-3)"
check "long line rejected" "500" "$(raw "$(printf 'NOOP %05000d' 0)" | sed -n 2p | cut -c1-3)"
check "pasv reply" 1 "$(raw "USER $AK" "PASS $SK" "PASV" | sed -n 4p | grep -c '^227 Entering Passive Mode (127,0,0,1,')"
check "epsv reply" 1 "$(raw "USER $AK" "PASS $SK" "EPSV" | sed -n 4p | grep -c '^229 .*(|||[0-9]*|)')"
check "retr without pasv" "425" "$(raw "USER $AK" "PASS $SK" "RETR /cbkt/tls.bin" | sed -n 4p | cut -c1-3)"
check "rnto without rnfr" "503" "$(raw "USER $AK" "PASS $SK" "RNTO x" | sed -n 4p | cut -c1-3)"
check "help" "214" "$(raw "HELP" | tail -1 | cut -c1-3)"
check "auth tls" "234" "$(raw "AUTH TLS" | sed -n 2p | cut -c1-3)"

# ---- python ftplib ----
head -c 52428800 /dev/urandom >big.bin
for mode in plain explicit implicit; do
  port=$FTPP; [[ $mode == implicit ]] && port=$FTPSP
  bigarg=(); [[ $mode != explicit ]] && bigarg=(big.bin)
  if out=$("$PY" "$ROOT/tests/ftp_client.py" "$mode" 127.0.0.1 "$port" "$AK" "$SK" "$WORK" "${bigarg[@]}" 2>&1); then rc=0; else rc=$?; fi
  echo "$out" | grep -E '^(ok|FAIL)' || true
  p=$(echo "$out" | grep -c '^ok' || true); f=$(echo "$out" | grep -c '^FAIL' || true)
  pass=$((pass + p)); fail=$((fail + f))
  if [[ $rc -ne 0 && $f -eq 0 ]]; then fail=$((fail + 1)); echo "FAIL python $mode crashed:"; echo "$out" | tail -15; fi
done
check "python bucket gone over s3" 404 "$(s3 -o /dev/null -w '%{http_code}' "$EP/pyplain/")"

# ---- require-tls server ----
FTPP2=$(freeport); S3P2=$(freeport)
ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$BIN" --data "$WORK/data2" --listen "127.0.0.1:$S3P2" \
  --tls-cert tls.crt --tls-key tls.key --ftp "127.0.0.1:$FTPP2" --ftp-require-tls on 2>"$WORK/server2.log" &
PID2=$!
for _ in $(seq 300); do grep -q "ftp listening" "$WORK/server2.log" 2>/dev/null && break; sleep 0.1; done
check "require-tls refuses plain login" 67 "$(curl -s --user "$AK:$SK" "ftp://127.0.0.1:$FTPP2/" -o /dev/null; echo $?)"
check "require-tls allows explicit" 0 "$(curl -sk --ssl-reqd --user "$AK:$SK" "ftp://127.0.0.1:$FTPP2/" -o /dev/null; echo $?)"
check "require-tls refuses clear data" 1 "$(curl -sk --ftp-ssl-control --user "$AK:$SK" "ftp://127.0.0.1:$FTPP2/" -o /dev/null 2>&1; [[ $? -ne 0 ]] && echo 1 || echo 0)"
kill "$PID2" 2>/dev/null || true
wait "$PID2" 2>/dev/null || true

# ---- ftps without a certificate fails at start ----
if "$BIN" --anonymous --data "$WORK/data3" --listen "127.0.0.1:$(freeport)" --ftps "127.0.0.1:$(freeport)" 2>"$WORK/server3.log"; then rc=0; else rc=$?; fi
check "ftps without cert refuses to start" 1 "$([[ $rc -ne 0 ]] && grep -c 'need --tls-cert' "$WORK/server3.log")"

echo
echo "ftp: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
