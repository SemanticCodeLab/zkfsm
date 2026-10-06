#!/usr/bin/env bash
# SFTP gateway end-to-end: OpenSSH sftp over every cipher, kex and host key
# algorithm, a 100 MB round trip, reget/reput, paramiko checks, S3 visibility.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${ZKFSM_SFTP_PYTHON:-python3}"
freeport() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
PORT="$(freeport)"
SPORT="$(freeport)"
EP="http://127.0.0.1:$PORT"
AK=sftpuser
SK=sftp-secret-key-123
WORK="$(mktemp -d)"
DATA="$WORK/data"
PID=""
cleanup() { [[ -n "$PID" ]] && kill "$PID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

pass=0
fail=0
check() { # name expected actual
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); echo "ok   $1"
  else fail=$((fail + 1)); echo "FAIL $1: expected [$2] got [$3]"; fi
}
md5() { md5sum "$1" | cut -d' ' -f1; }
s3() { curl -s --aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" "$@"; }

# Release build: debug-mode crypto is too slow for the 100 MB transfers.
(cd "$ROOT" && zig build -Doptimize=ReleaseSafe -p "$WORK/out")
BIN="$WORK/out/bin/zkfsm"

start() { # extra flags...
  ZKFSM_ACCESS_KEY=$AK ZKFSM_SECRET_KEY=$SK "$BIN" --data "$DATA" --listen "127.0.0.1:$PORT" \
    --sftp "127.0.0.1:$SPORT" --sftp-authorized-keys "$WORK/authorized" "$@" 2>>"$WORK/server.log" &
  PID=$!
  for _ in $(seq 50); do curl -s -o /dev/null "$EP/" && return 0; sleep 0.1; done
  echo "server did not start:"; cat "$WORK/server.log"; exit 1
}
stop() { kill "$PID"; wait "$PID" 2>/dev/null || true; PID=""; }

ssh-keygen -q -t ed25519 -N '' -C '' -f "$WORK/id"
echo "$AK $(cut -d' ' -f1,2 "$WORK/id.pub") test" > "$WORK/authorized"
ssh-keygen -q -t ed25519 -N '' -C '' -f "$WORK/host_ed"
ssh-keygen -q -t rsa -b 3072 -m PEM -N '' -C '' -f "$WORK/host_rsa"

SSHOPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o LogLevel=ERROR)
if command -v sshpass >/dev/null; then
  AUTH=(sshpass -p "$SK" sftp -o PubkeyAuthentication=no -o BatchMode=no)
else
  AUTH=(sftp -i "$WORK/id")
fi
sftpb() { # batchfile, extra ssh options...
  local b="$1"; shift
  timeout 300 "${AUTH[@]}" "${SSHOPTS[@]}" "$@" -P "$SPORT" -b "$b" "$AK@127.0.0.1" >"$WORK/sftp.out" 2>&1
}

# Generated host key: persisted 0600 in the state directory, stable across restarts.
start
KEYFILE="$DATA/.zkfsm/sftp_host_ed25519_key"
check "host key generated" "600" "$(stat -c %a "$KEYFILE" 2>/dev/null)"
FP1=$(grep -o 'SHA256:[^ ]*' "$WORK/server.log" | tail -1)
stop
start
check "host key stable" "$FP1" "$(grep -o 'SHA256:[^ ]*' "$WORK/server.log" | tail -1)"
check "fingerprint matches client view" "$FP1" "$(ssh-keyscan -t ed25519 -p "$SPORT" 127.0.0.1 2>/dev/null | ssh-keygen -lf - | awk '{print $2}')"
stop

# Configured host keys plus a small rekey limit so server-started re-exchange runs too.
start --sftp-host-key "$WORK/host_ed" --sftp-host-key "$WORK/host_rsa" --sftp-rekey-bytes 4194304

printf 'mkdir /sftpbkt\nmkdir /sftpbkt/dir\nls /\n' > "$WORK/b1"
check "mkdir bucket and dir" 0 "$(sftpb "$WORK/b1"; echo $?)"
check "bucket via s3" 1 "$(s3 "$EP/" | grep -c '<Name>sftpbkt</Name>')"

head -c 100000000 /dev/urandom > "$WORK/big"
BIGMD5=$(md5 "$WORK/big")
printf 'small file\n' > "$WORK/small"
for cipher in chacha20-poly1305@openssh.com aes256-gcm@openssh.com aes128-gcm@openssh.com; do
  for kex in mlkem768x25519-sha256 curve25519-sha256 curve25519-sha256@libssh.org; do
    for hk in ssh-ed25519 rsa-sha2-512 rsa-sha2-256; do
      printf 'put %s /sftpbkt/dir/s.txt\nget /sftpbkt/dir/s.txt %s\n' "$WORK/small" "$WORK/small.out" > "$WORK/b2"
      rm -f "$WORK/small.out"
      sftpb "$WORK/b2" -c "$cipher" -o KexAlgorithms="$kex" -o HostKeyAlgorithms="$hk" || true
      check "round trip $cipher $kex $hk" "$(md5 "$WORK/small")" "$(md5 "$WORK/small.out" 2>/dev/null || echo none)"
    done
  done
done

for cipher in chacha20-poly1305@openssh.com aes256-gcm@openssh.com; do
  rm -f "$WORK/big.out"
  printf 'put %s /sftpbkt/dir/big\nget /sftpbkt/dir/big %s\n' "$WORK/big" "$WORK/big.out" > "$WORK/b3"
  sftpb "$WORK/b3" -c "$cipher" -o RekeyLimit=32M || true
  check "100MB md5 $cipher" "$BIGMD5" "$(md5 "$WORK/big.out" 2>/dev/null || echo none)"
done
check "100MB via s3" "$BIGMD5" "$(s3 "$EP/sftpbkt/dir/big" | md5sum | cut -d' ' -f1)"

# reget: resume a truncated local copy; reput: finish a truncated remote copy.
head -c 30000000 "$WORK/big" > "$WORK/big.out"
printf 'reget /sftpbkt/dir/big %s\n' "$WORK/big.out" > "$WORK/b4"
sftpb "$WORK/b4" || true
check "reget md5" "$BIGMD5" "$(md5 "$WORK/big.out")"
head -c 40000000 "$WORK/big" > "$WORK/part"
printf 'put %s /sftpbkt/dir/rp\nreput %s /sftpbkt/dir/rp\n' "$WORK/part" "$WORK/big" > "$WORK/b5"
sftpb "$WORK/b5" || true
check "reput md5" "$BIGMD5" "$(s3 "$EP/sftpbkt/dir/rp" | md5sum | cut -d' ' -f1)"

printf 'ls -l /sftpbkt/dir\nrename /sftpbkt/dir/s.txt /sftpbkt/dir/t.txt\nls /sftpbkt/dir\n' > "$WORK/b6"
sftpb "$WORK/b6" || true
check "ls -l long name" 1 "$(grep -c '^-rw-r--r-- .* 100000000 .* big$' "$WORK/sftp.out")"
check "rename visible" 1 "$(grep -c '^t\.txt *$' "$WORK/sftp.out")"
check "renamed via s3" "small file" "$(s3 "$EP/sftpbkt/dir/t.txt")"
check "old name gone via s3" 404 "$(s3 -o /dev/null -w '%{http_code}' "$EP/sftpbkt/dir/s.txt")"

printf 'df /\nrm /sftpbkt/dir/t.txt\nrm /sftpbkt/dir/big\nrm /sftpbkt/dir/rp\nrmdir /sftpbkt/dir\nls /sftpbkt\n' > "$WORK/b7"
check "rm and rmdir" 0 "$(sftpb "$WORK/b7"; echo $?)"
check "dir gone via s3" 0 "$(s3 "$EP/sftpbkt?list-type=2" | grep -c '<Key>')"
printf 'rmdir /sftpbkt/missing\n' > "$WORK/b8"
check "rmdir missing fails" 1 "$(sftpb "$WORK/b8" >/dev/null 2>&1; echo $?)"

# Publickey with a key that is not registered must not log in.
ssh-keygen -q -t ed25519 -N '' -C '' -f "$WORK/other"
check "unregistered key rejected" 255 "$(timeout 30 sftp -i "$WORK/other" "${SSHOPTS[@]}" -o PasswordAuthentication=no -P "$SPORT" -b "$WORK/b1" "$AK@127.0.0.1" >/dev/null 2>&1; echo $?)"

if "$PY" -c 'import paramiko' 2>/dev/null; then
  if "$PY" "$ROOT/tests/sftp_paramiko.py" "$SPORT" "$AK" "$SK" sftpbkt "$WORK" > "$WORK/pm.out" 2>&1; then rc=0; else rc=$?; fi
  grep -E '^(ok|FAIL) ' "$WORK/pm.out" | sed 's/^ok   /ok   paramiko: /; s/^FAIL /FAIL paramiko: /'
  pass=$((pass + $(grep -c '^ok ' "$WORK/pm.out" || true)))
  fail=$((fail + $(grep -c '^FAIL ' "$WORK/pm.out" || true)))
  [[ $rc -ne 0 && $(grep -c '^FAIL ' "$WORK/pm.out" || true) -eq 0 ]] && { fail=$((fail + 1)); echo "FAIL paramiko run:"; tail -20 "$WORK/pm.out"; }
else
  echo "skip paramiko checks (set ZKFSM_SFTP_PYTHON to a python with paramiko)"
fi
check "server still alive" 0 "$(kill -0 "$PID"; echo $?)"

echo "sftp: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
