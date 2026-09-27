#!/usr/bin/env bash
# IAM admin API and STS end-to-end: mc admin manages users, policies, groups, and
# service accounts; an S3 CLI verifies the resulting access, including STS sessions.
set -euo pipefail
S3CLI_BIN="${S3CLI_BIN:-aws}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')"
EP="http://127.0.0.1:$PORT"
DATA="$(mktemp -d)"
WORK="$(mktemp -d)"
PID=""
cleanup() { [[ -n "$PID" ]] && kill "$PID" 2>/dev/null || true; rm -rf "$DATA" "$WORK"; }
trap cleanup EXIT

AK="zkfsmadmin"
SK="zkfsm-admin-secret-0123"
export AWS_DEFAULT_REGION=us-east-1 AWS_PAGER=""
export AWS_CONFIG_FILE="$WORK/cli.conf" AWS_SHARED_CREDENTIALS_FILE="$WORK/cli.creds"
printf '[default]\ns3 =\n  addressing_style = path\n' >"$AWS_CONFIG_FILE"
export MC_CONFIG_DIR="$WORK/mc"
MC="${MC:-$(command -v mc || true)}"
if [[ -z "$MC" ]] || ! "$MC" --version 2>/dev/null | grep -q RELEASE; then echo "admin.sh needs the MinIO client (set MC)"; exit 1; fi

pass=0
fail=0
check() { # name expected actual
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); echo "ok   $1"
  else fail=$((fail + 1)); echo "FAIL $1: expected [$2] got [$3]"; fi
}
# as KEY SECRET [TOKEN] -- s3cli args...
as() {
  local k="$1" s="$2" t="$3"; shift 4
  AWS_ACCESS_KEY_ID="$k" AWS_SECRET_ACCESS_KEY="$s" AWS_SESSION_TOKEN="$t" "$S3CLI_BIN" --endpoint-url "$EP" "$@"
}
ok() { if "$@" >/dev/null 2>&1; then echo 0; else echo 1; fi; }
jfield() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }
signed() { curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 aws:amz:us-east-1:s3 --user "$AK:$SK" "$@"; }

(cd "$ROOT" && zig build)
BIN="$ROOT/zig-out/bin/zkfsm"
start() {
  ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$BIN" --data "$DATA" --listen "127.0.0.1:$PORT" "$@" 2>>"$WORK/server.log" &
  PID=$!
  for _ in $(seq 50); do curl -s -o /dev/null "$EP/" && break; sleep 0.1; done
}
stop() { kill "$PID"; wait "$PID" 2>/dev/null || true; PID=""; }

start
"$MC" alias set z "$EP" "$AK" "$SK" >/dev/null
echo "hello" >"$WORK/f.txt"
"$MC" mb z/teamb z/other >/dev/null

# Users.
check "user add" 0 "$(ok "$MC" admin user add z alice alicesecret1)"
check "user add second" 0 "$(ok "$MC" admin user add z bob bobsecret12)"
check "user list" "alice bob" "$("$MC" admin user list z --json | sed -n 's/.*"accessKey":"\([^"]*\)".*/\1/p' | sort | xargs)"
check "user info status" enabled "$("$MC" admin user info z alice --json | jfield '["userStatus"]')"
check "new user has no rights" 1 "$(ok as alice alicesecret1 "" -- s3 cp "$WORK/f.txt" s3://teamb/a.txt)"

# Canned policy attached to the user grants exactly its bucket.
cat >"$WORK/team.json" <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::teamb","arn:aws:s3:::teamb/*"]}]}
JSON
check "policy create" 0 "$(ok "$MC" admin policy create z team "$WORK/team.json")"
check "policy list" 1 "$("$MC" admin policy list z | grep -cx team)"
check "policy info" teamb "$("$MC" admin policy info z team --json | jfield '["policyInfo"]["Policy"]["Statement"][0]["Resource"][0]' | sed 's|.*:::||')"
check "policy attach" 0 "$(ok "$MC" admin policy attach z team --user alice)"
check "attach twice is idempotent" 0 "$(ok "$MC" admin policy attach z team --user alice)"
check "user info policy" team "$("$MC" admin user info z alice --json | jfield '["policyName"]')"
check "user put own bucket" 0 "$(ok as alice alicesecret1 "" -- s3 cp "$WORK/f.txt" s3://teamb/a.txt)"
check "user get own bucket" hello "$(as alice alicesecret1 "" -- s3 cp s3://teamb/a.txt -)"
check "user denied other bucket" 1 "$(ok as alice alicesecret1 "" -- s3 cp "$WORK/f.txt" s3://other/a.txt)"
check "policy in use not removable" 1 "$(ok "$MC" admin policy remove z team)"

# Disable and enable.
check "user disable" 0 "$(ok "$MC" admin user disable z alice)"
check "disabled user denied" 1 "$(ok as alice alicesecret1 "" -- s3 ls s3://teamb/)"
check "user info disabled" disabled "$("$MC" admin user info z alice --json | jfield '["userStatus"]')"
"$MC" admin user enable z alice >/dev/null
check "re-enabled user allowed" 0 "$(ok as alice alicesecret1 "" -- s3 ls s3://teamb/)"

# Non-admins cannot administer; a delegated admin:* policy can.
MC_ALICE="$WORK/mc-alice"
MC_CONFIG_DIR="$MC_ALICE" "$MC" alias set za "$EP" alice alicesecret1 >/dev/null
check "non-admin denied" 1 "$(ok env MC_CONFIG_DIR="$MC_ALICE" "$MC" admin user list za)"
cat >"$WORK/admins.json" <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["admin:ListUsers","admin:GetUser"]}]}
JSON
"$MC" admin policy create z useradmins "$WORK/admins.json" >/dev/null
"$MC" admin policy attach z useradmins --user alice >/dev/null
check "delegated admin lists users" 0 "$(ok env MC_CONFIG_DIR="$MC_ALICE" "$MC" admin user list za)"
check "delegated admin cannot add users" 1 "$(ok env MC_CONFIG_DIR="$MC_ALICE" "$MC" admin user add za eve evesecret12)"
"$MC" admin policy detach z useradmins --user alice >/dev/null

# Groups.
check "group add" 0 "$(ok "$MC" admin group add z devs bob)"
"$MC" admin policy attach z readonly --group devs >/dev/null
check "group info" "bob readonly" "$("$MC" admin group info z devs --json | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["members"][0], d["groupPolicy"])')"
check "group member reads" hello "$(as bob bobsecret12 "" -- s3 cp s3://teamb/a.txt -)"
check "group member cannot write" 1 "$(ok as bob bobsecret12 "" -- s3 cp "$WORK/f.txt" s3://teamb/b.txt)"
"$MC" admin group disable z devs >/dev/null
check "disabled group grants nothing" 1 "$(ok as bob bobsecret12 "" -- s3 cp s3://teamb/a.txt -)"
check "group list" devs "$("$MC" admin group ls z --json | jfield '["groups"][0]')"

# Service accounts inherit the parent's rights.
check "svcacct add" 0 "$(ok "$MC" admin user svcacct add z alice --access-key svcalice01 --secret-key svcalicesecret1)"
check "svcacct ls" svcalice01 "$("$MC" admin user svcacct ls z alice --json | jfield '["accessKey"]')"
check "svcacct info parent" alice "$("$MC" admin user svcacct info z svcalice01 --json | jfield '["parentUser"]')"
check "svcacct reads parent bucket" hello "$(as svcalice01 svcalicesecret1 "" -- s3 cp s3://teamb/a.txt -)"
check "svcacct denied elsewhere" 1 "$(ok as svcalice01 svcalicesecret1 "" -- s3 ls s3://other/)"
"$MC" admin user svcacct disable z svcalice01 >/dev/null
check "disabled svcacct denied" 1 "$(ok as svcalice01 svcalicesecret1 "" -- s3 ls s3://teamb/)"
"$MC" admin user svcacct enable z svcalice01 >/dev/null
check "svcacct rm" 0 "$(ok "$MC" admin user svcacct rm z svcalice01)"
check "removed svcacct denied" 1 "$(ok as svcalice01 svcalicesecret1 "" -- s3 ls s3://teamb/)"
GEN="$("$MC" admin user svcacct add z alice --json)"
GEN_AK="$(echo "$GEN" | jfield '["accessKey"]')"
GEN_SK="$(echo "$GEN" | jfield '["secretKey"]')"
check "generated svcacct works" 0 "$(ok as "$GEN_AK" "$GEN_SK" "" -- s3 ls s3://teamb/)"

# STS AssumeRole with a session policy narrowing the user's rights.
SESSION_POLICY='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::teamb/*"]}]}'
as alice alicesecret1 "" -- sts assume-role --role-arn arn:xxx:xxx:xxx:xxxx --role-session-name sess \
  --duration-seconds 900 --policy "$SESSION_POLICY" --output json >"$WORK/sts.json"
T_AK="$(jfield '["Credentials"]["AccessKeyId"]' <"$WORK/sts.json")"
T_SK="$(jfield '["Credentials"]["SecretAccessKey"]' <"$WORK/sts.json")"
T_TOK="$(jfield '["Credentials"]["SessionToken"]' <"$WORK/sts.json")"
check "sts temporary key" ASIA "${T_AK:0:4}"
check "sts expiration set" 1 "$(jfield '["Credentials"]["Expiration"]' <"$WORK/sts.json" | grep -c T)"
check "session reads" hello "$(as "$T_AK" "$T_SK" "$T_TOK" -- s3 cp s3://teamb/a.txt -)"
check "session policy blocks write" 1 "$(ok as "$T_AK" "$T_SK" "$T_TOK" -- s3 cp "$WORK/f.txt" s3://teamb/c.txt)"
check "session cannot exceed parent" 1 "$(ok as "$T_AK" "$T_SK" "$T_TOK" -- s3 ls s3://other/)"
check "session without token denied" 1 "$(ok as "$T_AK" "$T_SK" "" -- s3 cp s3://teamb/a.txt -)"
check "session cannot assume again" 1 "$(ok as "$T_AK" "$T_SK" "$T_TOK" -- sts assume-role --role-arn arn:xxx:xxx:xxx:xxxx --role-session-name sess)"
check "duration below minimum rejected" 1 "$(ok as alice alicesecret1 "" -- sts assume-role --role-arn arn:xxx:xxx:xxx:xxxx --role-session-name sess --duration-seconds 60)"
check "unknown caller rejected" 1 "$(ok as nobody nobodysecret1 "" -- sts assume-role --role-arn arn:xxx:xxx:xxx:xxxx --role-session-name sess)"
as alice alicesecret1 "" -- sts assume-role --role-arn arn:xxx:xxx:xxx:xxxx --role-session-name sess --output json >"$WORK/sts2.json"
check "session without policy has parent rights" 0 "$(ok as "$(jfield '["Credentials"]["AccessKeyId"]' <"$WORK/sts2.json")" \
  "$(jfield '["Credentials"]["SecretAccessKey"]' <"$WORK/sts2.json")" "$(jfield '["Credentials"]["SessionToken"]' <"$WORK/sts2.json")" \
  -- s3 cp "$WORK/f.txt" s3://teamb/d.txt)"

# Concurrent admin changes all land.
adders=()
for i in $(seq 1 12); do "$MC" admin user add z "par$i" "parsecret$i-x" >/dev/null & adders+=($!); done
wait "${adders[@]}"
check "concurrent user adds" 12 "$("$MC" admin user list z --json | grep -c '"par')"

# Removal, then persistence across restart.
check "user remove" 0 "$(ok "$MC" admin user remove z bob)"
check "removed user denied" 1 "$(ok as bob bobsecret12 "" -- s3 ls s3://teamb/)"
stop
start
check "state persists across restart" "team" "$("$MC" admin user info z alice --json | jfield '["policyName"]')"
check "svcacct persists" 0 "$(ok as "$GEN_AK" "$GEN_SK" "" -- s3 ls s3://teamb/)"
check "bob stays removed" 1 "$(ok "$MC" admin user info z bob)"
stop

# Custom prefix via flag: served there and at the native alias, not at the default.
"$MC" mb z/ops >/dev/null 2>&1 || true
start --admin-prefix /ops/admin
"$MC" mb z/ops >/dev/null 2>&1 || true
check "custom prefix served" 200 "$(signed "$EP/ops/admin/v3/list-canned-policies")"
check "native prefix served" 200 "$(signed "$EP/zkfsm/admin/v3/list-canned-policies")"
check "default prefix is plain S3 then" 404 "$(signed "$EP/minio/admin/v3/list-canned-policies")"
check "custom prefix requires auth" 403 "$(curl -s -o /dev/null -w '%{http_code}' "$EP/ops/admin/v3/list-canned-policies")"
check "custom prefix admin-only" 403 "$(curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 aws:amz:us-east-1:s3 --user alice:alicesecret1 "$EP/ops/admin/v3/list-canned-policies")"
check "bucket keys outside the prefix still S3" 0 "$(ok "$MC" cp "$WORK/f.txt" z/ops/data.txt)"
stop
start --admin-prefix /ops/admin
check "shadowed bucket warning" 1 "$(grep -c 'bucket ops: path-style keys under /ops/admin' "$WORK/server.log")"
stop
PID=""
ZKFSM_ADMIN_PREFIX=/env/admin ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$BIN" --data "$DATA" --listen "127.0.0.1:$PORT" 2>>"$WORK/server.log" &
PID=$!
for _ in $(seq 50); do curl -s -o /dev/null "$EP/" && break; sleep 0.1; done
check "prefix from environment" 200 "$(signed "$EP/env/admin/v3/groups")"
stop
set +e
for bad in / /x/ x/admin "/a?b" /a/../b; do
  ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$BIN" --data "$DATA" --listen "127.0.0.1:$PORT" --admin-prefix "$bad" 2>/dev/null
  check "invalid prefix $bad refused" 2 "$?"
done
set -e

echo "admin: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
