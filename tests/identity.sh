#!/usr/bin/env bash
# External identity end-to-end: OpenID Connect (mock IdP: discovery, JWKS, RS256/ES256
# tokens, key rotation), LDAP against an OpenLDAP container (plain, StartTLS, LDAPS),
# and tenant isolation. Needs the MinIO client (MC) and an S3 CLI; LDAP needs docker.
set -euo pipefail
S3CLI_BIN="${S3CLI_BIN:-aws}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
freeport() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
PORT="$(freeport)"
EP="http://127.0.0.1:$PORT"
DATA="$(mktemp -d)"
WORK="$(mktemp -d)"
PID=""
IDP_PID=""
LDAP_NAME="zkfsm-identity-ldap-$$"
LDAP_STARTED=""
DEX_NAME="zkfsm-identity-dex-$$"
DEX_STARTED=""
cleanup() {
  [[ -n "$DEX_STARTED" ]] && docker rm -f "$DEX_NAME" >/dev/null 2>&1 || true
  [[ -n "$PID" ]] && kill "$PID" 2>/dev/null || true
  [[ -n "$IDP_PID" ]] && kill "$IDP_PID" 2>/dev/null || true
  [[ -n "$LDAP_STARTED" ]] && docker rm -f "$LDAP_NAME" >/dev/null 2>&1 || true
  rm -rf "$DATA" "$WORK"
}
trap cleanup EXIT

AK="zkfsmadmin"
SK="zkfsm-admin-secret-0123"
export AWS_DEFAULT_REGION=us-east-1 AWS_PAGER=""
export AWS_CONFIG_FILE="$WORK/cli.conf" AWS_SHARED_CREDENTIALS_FILE="$WORK/cli.creds"
printf '[default]\ns3 =\n  addressing_style = path\n' >"$AWS_CONFIG_FILE"
export MC_CONFIG_DIR="$WORK/mc"
MC="${MC:-$(command -v mc || true)}"
if [[ -z "$MC" ]] || ! "$MC" --version 2>/dev/null | grep -q RELEASE; then echo "identity.sh needs the MinIO client (set MC)"; exit 1; fi

pass=0
fail=0
skip=0
check() { # name expected actual
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); echo "ok   $1"
  else fail=$((fail + 1)); echo "FAIL $1: expected [$2] got [$3]"; fi
}
as() { # as KEY SECRET TOKEN -- s3cli args...
  local k="$1" s="$2" t="$3"; shift 4
  AWS_ACCESS_KEY_ID="$k" AWS_SECRET_ACCESS_KEY="$s" AWS_SESSION_TOKEN="$t" "$S3CLI_BIN" --endpoint-url "$EP" "$@"
}
ok() { if "$@" >/dev/null 2>&1; then echo 0; else echo 1; fi; }
jfield() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }
admin() { # admin METHOD PATH -> HTTP status (signed by root)
  curl -s -o "$WORK/admin.out" -w '%{http_code}' -X "$1" --aws-sigv4 aws:amz:us-east-1:s3 --user "$AK:$SK" "$EP/minio/admin/v3$2"
}
# sts FORM-ARGS... -> response XML on stdout
sts() {
  local args=()
  for kv in "$@"; do args+=(--data-urlencode "$kv"); done
  curl -s -X POST "$EP/" -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode Version=2011-06-15 "${args[@]}"
}
xmlget() { python3 -c "import re,sys; m=re.search(r'<$1>([^<]*)</$1>', sys.stdin.read()); print(m.group(1) if m else '')"; }
# creds XML -> "AK SK TOKEN"
creds() { python3 -c "
import re,sys
x=sys.stdin.read()
g=lambda n: (re.search('<%s>([^<]*)</%s>'%(n,n),x) or [None,''])[1]
print(g('AccessKeyId'), g('SecretAccessKey'), g('SessionToken'))"; }
s3as() { # s3as "AK SK TOKEN" s3cli-args...
  local c=($1); shift
  as "${c[0]:-x}" "${c[1]:-x}" "${c[2]:-}" -- "$@"
}

(cd "$ROOT" && zig build)
BIN="$ROOT/zig-out/bin/zkfsm"
start() {
  ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK" "$BIN" --data "$DATA" --listen "127.0.0.1:$PORT" "$@" 2>>"$WORK/server.log" &
  PID=$!
  for _ in $(seq 50); do curl -s -o /dev/null "$EP/" && break; sleep 0.1; done
}
stop() { kill "$PID"; wait "$PID" 2>/dev/null || true; PID=""; }

# ---------------------------------------------------------------- mock IdP
python3 "$ROOT/tests/mock_idp.py" >"$WORK/idp.port" 2>"$WORK/idp.log" &
IDP_PID=$!
for _ in $(seq 100); do [[ -s "$WORK/idp.port" ]] && break; sleep 0.1; done
IDP="http://127.0.0.1:$(cat "$WORK/idp.port")"
DISCOVERY="$IDP/.well-known/openid-configuration"
token() { curl -s "$IDP/token?$1"; }

start
"$MC" alias set z "$EP" "$AK" "$SK" >/dev/null
echo "hello" >"$WORK/f.txt"
"$MC" mb z/teamb z/other >/dev/null
"$MC" cp "$WORK/f.txt" z/other/seed.txt >/dev/null
cat >"$WORK/teamb.json" <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::teamb","arn:aws:s3:::teamb/*"]}]}
JSON
"$MC" admin policy create z teamb-rw "$WORK/teamb.json" >/dev/null

# --- OpenID provider configuration through the admin API.
check "openid sts before config" InvalidParameterValue "$(sts Action=AssumeRoleWithWebIdentity "WebIdentityToken=$(token 'sub=u1&policy=teamb-rw')" | xmlget Code)"
check "openid add" 0 "$(ok "$MC" idp openid add z corp "config_url=$DISCOVERY" client_id=zkfsm claim_name=policy scopes=openid,email "redirect_uri=http://127.0.0.1:9001/oauth_callback")"
check "openid add duplicate refused" 1 "$(ok "$MC" idp openid add z corp "config_url=$DISCOVERY" client_id=zkfsm)"
check "openid add missing client_id refused" 1 "$(ok "$MC" idp openid add z bad "config_url=$DISCOVERY")"
check "openid add unknown key refused" 1 "$(ok "$MC" idp openid add z bad2 "config_url=$DISCOVERY" client_id=x bogus=1)"
check "openid ls" corp "$("$MC" idp openid ls z --json | jfield '[0]["name"]')"
INFO="$("$MC" idp openid info z corp --json)"
check "openid info client_id" zkfsm "$(echo "$INFO" | python3 -c 'import json,sys; d=json.load(sys.stdin); print([i["value"] for i in d["info"] if i["key"]=="client_id"][0])')"
check "openid info redirect_uri" "http://127.0.0.1:9001/oauth_callback" "$(echo "$INFO" | python3 -c 'import json,sys; d=json.load(sys.stdin); print([i["value"] for i in d["info"] if i["key"]=="redirect_uri"][0])')"

# --- AssumeRoleWithWebIdentity: claim -> policy, RS256 and ES256.
X="$(sts Action=AssumeRoleWithWebIdentity "WebIdentityToken=$(token 'sub=user-1&policy=teamb-rw')" DurationSeconds=900)"
C="$(echo "$X" | creds)"
check "web identity issues temp key" ASIA "$(echo "$C" | cut -c1-4)"
check "web identity subject echoed" user-1 "$(echo "$X" | xmlget SubjectFromWebIdentityToken)"
check "web identity session writes own bucket" 0 "$(ok s3as "$C" s3 cp "$WORK/f.txt" s3://teamb/a.txt)"
check "web identity session reads" hello "$(s3as "$C" s3 cp s3://teamb/a.txt -)"
check "web identity session denied elsewhere" 1 "$(ok s3as "$C" s3 cp "$WORK/f.txt" s3://other/a.txt)"
read -r C_AK C_SK C_TOK <<<"$C"
check "web identity session cannot administer" 403 "$(curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 aws:amz:us-east-1:s3 --user "$C_AK:$C_SK" -H "x-amz-security-token: $C_TOK" "$EP/minio/admin/v3/list-users")"
C2="$(sts Action=AssumeRoleWithWebIdentity "WebIdentityToken=$(token 'alg=ES256&sub=user-2&policy[]=teamb-rw,readonly')" | creds)"
check "ES256 token with policy array" hello "$(s3as "$C2" s3 cp s3://other/seed.txt -)"
check "ES256 session writes via teamb-rw" 0 "$(ok s3as "$C2" s3 cp "$WORK/f.txt" s3://teamb/es.txt)"
check "ES256 session readonly elsewhere" 1 "$(ok s3as "$C2" s3 cp "$WORK/f.txt" s3://other/es.txt)"
check "query-string form accepted" ASIA "$(curl -s -X POST "$EP/?Action=AssumeRoleWithWebIdentity&Version=2011-06-15&WebIdentityToken=$(token 'sub=q&policy=readonly')" | xmlget AccessKeyId | cut -c1-4)"

# --- Rejections.
check "expired token" ExpiredTokenException "$(sts Action=AssumeRoleWithWebIdentity "WebIdentityToken=$(token 'sub=u&policy=readonly&ttl=-120')" | xmlget Code)"
check "not-yet-valid token" InvalidIdentityToken "$(sts Action=AssumeRoleWithWebIdentity "WebIdentityToken=$(token 'sub=u&policy=readonly&nbf=600')" | xmlget Code)"
check "wrong audience" InvalidIdentityToken "$(sts Action=AssumeRoleWithWebIdentity "WebIdentityToken=$(token 'sub=u&policy=readonly&aud=someone-else')" | xmlget Code)"
check "wrong issuer" InvalidIdentityToken "$(sts Action=AssumeRoleWithWebIdentity "WebIdentityToken=$(token 'sub=u&policy=readonly&iss=http://evil')" | xmlget Code)"
TOK="$(token 'sub=u&policy=readonly')"
TAMPERED="$(python3 -c "
import base64,json,sys
h,p,s=sys.argv[1].split('.')
d=json.loads(base64.urlsafe_b64decode(p+'=='*2)); d['policy']='consoleAdmin'
print(h+'.'+base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b'=').decode()+'.'+s)" "$TOK")"
check "tampered token" InvalidIdentityToken "$(sts Action=AssumeRoleWithWebIdentity "WebIdentityToken=$TAMPERED" | xmlget Code)"
NONE="$(python3 -c "
import base64,json,sys
p=sys.argv[1].split('.')[1]
h=base64.urlsafe_b64encode(json.dumps({'alg':'none'}).encode()).rstrip(b'=').decode()
print(h+'.'+p+'.')" "$TOK")"
check "alg none token" InvalidIdentityToken "$(sts Action=AssumeRoleWithWebIdentity "WebIdentityToken=$NONE" | xmlget Code)"
check "garbage token" InvalidIdentityToken "$(sts Action=AssumeRoleWithWebIdentity "WebIdentityToken=not.a.jwt" | xmlget Code)"
check "unknown policy claim" AccessDenied "$(sts Action=AssumeRoleWithWebIdentity "WebIdentityToken=$(token 'sub=u&policy=no-such-policy')" | xmlget Code)"
check "missing policy claim" AccessDenied "$(sts Action=AssumeRoleWithWebIdentity "WebIdentityToken=$(token 'sub=u')" | xmlget Code)"
check "missing token parameter" MissingParameter "$(sts Action=AssumeRoleWithWebIdentity | xmlget Code)"
check "unknown action" InvalidAction "$(sts Action=GetFederationToken | xmlget Code)"
check "oversize token" InvalidIdentityToken "$(sts Action=AssumeRoleWithWebIdentity "WebIdentityToken=$(head -c 15000 /dev/zero | tr '\0' 'a').b.c" | xmlget Code)"

# --- Key rotation: a token signed by a new key is accepted after a JWKS refetch.
OLD="$(token 'sub=u&policy=readonly')"
sleep 11 # the refetch on an unknown key id is rate-limited to once per 10 s
curl -s -X POST "$IDP/rotate" >/dev/null
check "rotated key accepted" ASIA "$(sts Action=AssumeRoleWithWebIdentity "WebIdentityToken=$(token 'sub=u&policy=readonly')" | xmlget AccessKeyId | cut -c1-4)"
check "retired key rejected" InvalidIdentityToken "$(sts Action=AssumeRoleWithWebIdentity "WebIdentityToken=$OLD" | xmlget Code)"
J1="$(curl -s "$IDP/stats" | jfield '["jwks"]')"
for _ in 1 2 3 4 5; do sts Action=AssumeRoleWithWebIdentity "WebIdentityToken=$(token 'sub=u&policy=readonly&kid=unknown-kid')" >/dev/null; done
check "unknown kid refetch is rate-limited" 1 "$(( $(curl -s "$IDP/stats" | jfield '["jwks"]') - J1 <= 1 ? 1 : 0 ))"

# --- Client grants use the same validation.
CG="$(sts Action=AssumeRoleWithClientGrants "Token=$(token 'sub=svc-1&policy=teamb-rw')" | creds)"
check "client grants session" 0 "$(ok s3as "$CG" s3 cp "$WORK/f.txt" s3://teamb/cg.txt)"

# --- Role-policy provider selected by RoleArn (also via the S3 CLI's STS client).
check "role provider add" 0 "$(ok "$MC" idp openid add z ro "config_url=$DISCOVERY" client_id=zkfsm role_policy=readonly)"
ARN="$("$MC" idp openid ls z --json | python3 -c 'import json,sys; print([i.get("roleARN","") for i in json.load(sys.stdin) if i["name"]=="ro"][0])')"
check "role ARN listed" "arn:zkfsm:iam:::role/ro" "$ARN"
"$S3CLI_BIN" --endpoint-url "$EP" sts assume-role-with-web-identity --role-arn "arn:zkfsm:iam:::role/ro" --role-session-name sess \
  --web-identity-token "$(token 'sub=rouser')" --output json >"$WORK/ro.json" 2>"$WORK/ro.err" || true
RC="$(python3 -c 'import json,sys; c=json.load(open(sys.argv[1]))["Credentials"]; print(c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"])' "$WORK/ro.json" 2>/dev/null || true)"
check "S3 CLI assume-role-with-web-identity" hello "$(s3as "$RC" s3 cp s3://other/seed.txt -)"
check "role session is read-only" 1 "$(ok s3as "$RC" s3 cp "$WORK/f.txt" s3://other/ro.txt)"
check "unknown role ARN" InvalidParameterValue "$(sts Action=AssumeRoleWithWebIdentity RoleArn=arn:zkfsm:iam:::role/nope "WebIdentityToken=$(token 'sub=u')" | xmlget Code)"
check "openid rm" 0 "$(ok "$MC" idp openid rm z ro)"
check "removed provider unusable" InvalidParameterValue "$(sts Action=AssumeRoleWithWebIdentity RoleArn=arn:zkfsm:iam:::role/ro "WebIdentityToken=$(token 'sub=u')" | xmlget Code)"
check "openid update" 0 "$(ok "$MC" idp openid update z corp claim_name=roles)"
check "updated claim name used" ASIA "$(sts Action=AssumeRoleWithWebIdentity "WebIdentityToken=$(token 'sub=u&roles=readonly')" | xmlget AccessKeyId | cut -c1-4)"

# --- Configuration persists and providers can come from flags.
stop
start --identity-openid "config_url=$DISCOVERY client_id=zkfsm"
check "config persists across restart" ASIA "$(sts Action=AssumeRoleWithWebIdentity "WebIdentityToken=$(token 'sub=u&roles=readonly')" | xmlget AccessKeyId | cut -c1-4)"
check "flag provider listed as default" 1 "$("$MC" idp openid ls z --json | grep -c '"_"' || true)"
check "flag provider works" ASIA "$(sts Action=AssumeRoleWithWebIdentity "WebIdentityToken=$(token 'sub=u&policy=readonly')" | xmlget AccessKeyId | cut -c1-4)"
check "AssumeRoleWithCertificate needs mTLS" AccessDenied "$(sts Action=AssumeRoleWithCertificate | xmlget Code)"

# ---------------------------------------------------------------- dex (real IdP)
if command -v docker >/dev/null 2>&1 && command -v htpasswd >/dev/null 2>&1 && \
  { docker image inspect ghcr.io/dexidp/dex:v2.41.1 >/dev/null 2>&1 || docker pull -q ghcr.io/dexidp/dex:v2.41.1 >/dev/null 2>&1; }; then
  DEX_PORT="$(freeport)"
  cat >"$WORK/dex.yaml" <<EOF
issuer: http://127.0.0.1:$DEX_PORT/dex
storage:
  type: memory
web:
  http: 0.0.0.0:5556
oauth2:
  passwordConnector: local
  skipApprovalScreen: true
enablePasswordDB: true
staticClients:
- id: zkfsm
  secret: zkfsm-dex-secret
  name: zkfsm
  redirectURIs: ['http://127.0.0.1/cb']
staticPasswords:
- email: dexuser@example.com
  hash: "$(htpasswd -bnBC 10 "" dex-password | tr -d ':\n')"
  username: dexuser
  userID: 3f1c2a9e-0d4b-4e8f-9a51-6b7c8d9e0f12
EOF
  DEX_STARTED=1
  docker create --name "$DEX_NAME" -p "127.0.0.1:$DEX_PORT:5556" ghcr.io/dexidp/dex:v2.41.1 dex serve /tmp/dex.yaml >/dev/null
  docker cp "$WORK/dex.yaml" "$DEX_NAME:/tmp/dex.yaml"
  docker start "$DEX_NAME" >/dev/null
  dex_token() { # field
    curl -s -u zkfsm:zkfsm-dex-secret -d grant_type=password -d username=dexuser@example.com -d password=dex-password \
      -d 'scope=openid email' "http://127.0.0.1:$DEX_PORT/dex/token" | jfield "[\"$1\"]" 2>/dev/null || true
  }
  for _ in $(seq 100); do [[ -n "$(dex_token id_token)" ]] && break; sleep 0.2; done
  check "dex provider add" 0 "$(ok "$MC" idp openid add z dex "config_url=http://127.0.0.1:$DEX_PORT/dex/.well-known/openid-configuration" client_id=zkfsm client_secret=zkfsm-dex-secret role_policy=readonly)"
  DC="$(sts Action=AssumeRoleWithWebIdentity RoleArn=arn:zkfsm:iam:::role/dex "WebIdentityToken=$(dex_token id_token)" | creds)"
  check "dex id_token session reads" hello "$(s3as "$DC" s3 cp s3://other/seed.txt -)"
  check "dex id_token session is read-only" 1 "$(ok s3as "$DC" s3 cp "$WORK/f.txt" s3://other/dex.txt)"
  check "dex access token via client grants" ASIA "$(sts Action=AssumeRoleWithClientGrants RoleArn=arn:zkfsm:iam:::role/dex "Token=$(dex_token access_token)" | xmlget AccessKeyId | cut -c1-4)"
  check "mock IdP token refused by dex provider" InvalidIdentityToken "$(sts Action=AssumeRoleWithWebIdentity RoleArn=arn:zkfsm:iam:::role/dex "WebIdentityToken=$(token 'sub=u')" | xmlget Code)"
  "$MC" idp openid rm z dex >/dev/null
  docker rm -f "$DEX_NAME" >/dev/null 2>&1 || true
else
  skip=$((skip + 1)); echo "skip dex: docker, htpasswd, or the dex image is unavailable"
fi

# ---------------------------------------------------------------- tenants
check "tenant add" 200 "$(admin PUT '/tenant/add?name=acme')"
check "tenant add duplicate" 409 "$(admin PUT '/tenant/add?name=acme')"
check "tenant bad name" 400 "$(admin PUT '/tenant/add?name=Bad_Name')"
admin PUT '/tenant/add?name=globex' >/dev/null
"$MC" admin user add z alice alicesecret1 >/dev/null
"$MC" admin user add z bob bobsecret12 >/dev/null
"$MC" admin user add z gina ginasecret1 >/dev/null
"$MC" admin policy attach z readwrite --user alice >/dev/null
"$MC" admin policy attach z readwrite --user bob >/dev/null
"$MC" admin policy attach z readwrite --user gina >/dev/null
check "assign user" 200 "$(admin PUT '/tenant/assign-user?name=acme&accessKey=alice')"
check "assign user to unknown tenant" 404 "$(admin PUT '/tenant/assign-user?name=nope&accessKey=bob')"
admin PUT '/tenant/assign-user?name=globex&accessKey=gina' >/dev/null
check "tenant user creates bucket" 0 "$(ok as alice alicesecret1 "" -- s3 mb s3://acme-data)"
as alice alicesecret1 "" -- s3 cp "$WORK/f.txt" s3://acme-data/a.txt >/dev/null
check "tenant user lists only own buckets" "acme-data" "$(as alice alicesecret1 "" -- s3 ls | awk '{print $3}' | xargs)"
check "tenant user denied global bucket despite readwrite" 1 "$(ok as alice alicesecret1 "" -- s3 ls s3://teamb/)"
check "other tenant denied" 1 "$(ok as gina ginasecret1 "" -- s3 cp s3://acme-data/a.txt -)"
check "other tenant cannot see bucket" "" "$(as gina ginasecret1 "" -- s3 ls | awk '{print $3}' | xargs)"
check "global user denied tenant bucket" 1 "$(ok as bob bobsecret12 "" -- s3 cp s3://acme-data/a.txt -)"
check "global user list hides tenant buckets" 0 "$(as bob bobsecret12 "" -- s3 ls | grep -c acme-data || true)"
check "bucket names stay globally unique" 1 "$(ok as gina ginasecret1 "" -- s3 mb s3://acme-data)"
check "cross-tenant copy source denied" 1 "$(ok as gina ginasecret1 "" -- s3 cp s3://acme-data/a.txt s3://globex-x/a.txt)"
as gina ginasecret1 "" -- s3 mb s3://globex-data >/dev/null
check "cross-tenant server-side copy denied" 1 "$(ok as gina ginasecret1 "" -- s3api copy-object --bucket globex-data --key c --copy-source acme-data/a.txt)"
check "copy from global bucket into tenant denied" 1 "$(ok as alice alicesecret1 "" -- s3api copy-object --bucket acme-data --key c --copy-source teamb/a.txt)"
check "same-tenant copy allowed" 0 "$(ok as alice alicesecret1 "" -- s3api copy-object --bucket acme-data --key copy.txt --copy-source acme-data/a.txt)"
check "root sees every bucket" 1 "$("$MC" ls z | grep -c acme-data)"
check "root reads tenant data" hello "$("$MC" cat z/acme-data/a.txt)"
check "tenant users have no admin rights" 1 "$(ok env MC_CONFIG_DIR="$WORK/mc-alice" sh -c "\"$MC\" alias set za '$EP' alice alicesecret1 >/dev/null && \"$MC\" admin user list za")"
"$MC" admin user svcacct add z alice --access-key acmesvc0001 --secret-key acmesvcsecret1 >/dev/null
check "service account inherits tenant" "acme-data" "$(as acmesvc0001 acmesvcsecret1 "" -- s3 ls | awk '{print $3}' | xargs)"
admin GET '/tenant/list' >/dev/null
check "tenant list" "acme:alice:acme-data" "$(python3 -c 'import json; d=json.load(open("'"$WORK"'/admin.out")); t=[x for x in d if x["name"]=="acme"][0]; print(t["name"]+":"+",".join(t["users"])+":"+",".join(b["name"] for b in t["buckets"]))')"
check "non-empty tenant not removable" 409 "$(admin DELETE '/tenant/remove?name=acme')"

# Federated identities pick their tenant from a claim.
"$MC" idp openid update z corp tenant_claim=org >/dev/null
TC="$(sts Action=AssumeRoleWithWebIdentity "WebIdentityToken=$(token 'sub=fed&roles=readwrite&org=acme')" | creds)"
check "federated tenant session sees tenant buckets" "acme-data" "$(s3as "$TC" s3 ls | awk '{print $3}' | xargs)"
check "federated tenant session denied global" 1 "$(ok s3as "$TC" s3 ls s3://teamb/)"
check "unknown tenant claim refused" AccessDenied "$(sts Action=AssumeRoleWithWebIdentity "WebIdentityToken=$(token 'sub=fed&roles=readwrite&org=initech')" | xmlget Code)"
check "missing tenant claim refused" AccessDenied "$(sts Action=AssumeRoleWithWebIdentity "WebIdentityToken=$(token 'sub=fed&roles=readwrite')" | xmlget Code)"
"$MC" idp openid update z corp tenant_claim= >/dev/null 2>&1 || true

check "tenant disable" 200 "$(admin PUT '/tenant/set-status?name=acme&status=disabled')"
check "disabled tenant denied" 1 "$(ok as alice alicesecret1 "" -- s3 ls s3://acme-data/)"
check "disabled tenant federated session denied" 1 "$(ok s3as "$TC" s3 ls s3://acme-data/)"
admin PUT '/tenant/set-status?name=acme&status=enabled' >/dev/null
check "re-enabled tenant allowed" 0 "$(ok as alice alicesecret1 "" -- s3 ls s3://acme-data/)"
check "move bucket to global" 200 "$(admin PUT '/tenant/assign-bucket?bucket=acme-data&name=')"
check "moved bucket leaves tenant" 1 "$(ok as alice alicesecret1 "" -- s3 ls s3://acme-data/)"
check "moved bucket reachable by global user" 0 "$(ok as bob bobsecret12 "" -- s3 ls s3://acme-data/)"
check "unassign user" 200 "$(admin PUT '/tenant/assign-user?name=&accessKey=alice')"
check "unassigned user is global again" 0 "$(ok as alice alicesecret1 "" -- s3 ls s3://teamb/)"
stop
start
check "tenancy persists across restart" 1 "$(ok as gina ginasecret1 "" -- s3 ls s3://acme-data/)"

# ---------------------------------------------------------------- LDAP
ldap_ready() { ldapsearch -x -H "ldap://127.0.0.1:$LDAP_PORT" -b dc=example,dc=org -D cn=admin,dc=example,dc=org -w admin "(uid=alice)" dn 2>/dev/null | grep -q '^dn: uid=alice'; }
if command -v docker >/dev/null 2>&1 && docker image inspect osixia/openldap:1.5.0 >/dev/null 2>&1 || docker pull -q osixia/openldap:1.5.0 >/dev/null 2>&1; then
  mkdir -p "$WORK/ldif"
  cat >"$WORK/ldif/50-seed.ldif" <<'LDIF'
dn: ou=people,dc=example,dc=org
objectClass: organizationalUnit
ou: people

dn: ou=groups,dc=example,dc=org
objectClass: organizationalUnit
ou: groups

dn: uid=alice,ou=people,dc=example,dc=org
objectClass: inetOrgPerson
uid: alice
cn: Alice Liddell
sn: Liddell
userPassword: alice-ldap-pw

dn: uid=bob,ou=people,dc=example,dc=org
objectClass: inetOrgPerson
uid: bob
cn: Bob Builder
sn: Builder
userPassword: bob-ldap-pw

dn: cn=devs,ou=groups,dc=example,dc=org
objectClass: groupOfNames
cn: devs
member: uid=alice,ou=people,dc=example,dc=org
LDIF
  # TLS 1.3 (NORMAL): the image's default TLS 1.2 suites need an RSA certificate.
  docker run -d --name "$LDAP_NAME" -p 127.0.0.1::389 -p 127.0.0.1::636 \
    -e LDAP_TLS_CIPHER_SUITE=NORMAL -e LDAP_TLS_VERIFY_CLIENT=never osixia/openldap:1.5.0 >/dev/null
  LDAP_STARTED=1
  LDAP_PORT="$(docker port "$LDAP_NAME" 389/tcp | head -1 | sed 's/.*://')"
  LDAPS_PORT="$(docker port "$LDAP_NAME" 636/tcp | head -1 | sed 's/.*://')"
  for _ in $(seq 120); do
    docker exec -i "$LDAP_NAME" ldapadd -x -H ldap://localhost -D cn=admin,dc=example,dc=org -w admin <"$WORK/ldif/50-seed.ldif" >/dev/null 2>&1 && break
    sleep 0.5
  done
  for _ in $(seq 20); do ldap_ready && break; sleep 0.5; done
  check "openldap container seeded" 0 "$(ldap_ready && echo 0 || echo 1)"

  check "ldap sts before config" InvalidParameterValue "$(sts Action=AssumeRoleWithLDAPIdentity LDAPUsername=alice LDAPPassword=alice-ldap-pw | xmlget Code)"
  check "ldap add" 0 "$(ok "$MC" idp ldap add z "server_addr=127.0.0.1:$LDAP_PORT" server_insecure=on \
    lookup_bind_dn=cn=admin,dc=example,dc=org lookup_bind_password=admin \
    user_dn_search_base_dn=ou=people,dc=example,dc=org 'user_dn_search_filter=(uid=%s)' \
    group_search_base_dn=ou=groups,dc=example,dc=org 'group_search_filter=(&(objectclass=groupOfNames)(member=%d))')"
  check "ldap info redacts bind password" 1 "$("$MC" idp ldap info z --json | grep -c redacted || true)"
  check "ldap group policy attach" 0 "$(ok "$MC" idp ldap policy attach z teamb-rw --group 'cn=devs,ou=groups,dc=example,dc=org')"
  check "ldap attach unknown policy" 1 "$(ok "$MC" idp ldap policy attach z nope --user 'uid=bob,ou=people,dc=example,dc=org')"
  LX="$(sts Action=AssumeRoleWithLDAPIdentity LDAPUsername=alice LDAPPassword=alice-ldap-pw)"
  LC="$(echo "$LX" | creds)"
  check "ldap login (plain)" ASIA "$(echo "$LC" | cut -c1-4)"
  check "ldap session writes via group policy" 0 "$(ok s3as "$LC" s3 cp "$WORK/f.txt" s3://teamb/ldap.txt)"
  check "ldap session denied elsewhere" 1 "$(ok s3as "$LC" s3 cp "$WORK/f.txt" s3://other/ldap.txt)"
  check "ldap wrong password" AccessDenied "$(sts Action=AssumeRoleWithLDAPIdentity LDAPUsername=alice LDAPPassword=wrong | xmlget Code)"
  check "ldap empty password" AccessDenied "$(sts Action=AssumeRoleWithLDAPIdentity LDAPUsername=alice LDAPPassword= | xmlget Code)"
  check "ldap unknown user" AccessDenied "$(sts Action=AssumeRoleWithLDAPIdentity LDAPUsername=mallory LDAPPassword=x | xmlget Code)"
  check "ldap filter injection" AccessDenied "$(sts Action=AssumeRoleWithLDAPIdentity 'LDAPUsername=*' LDAPPassword=alice-ldap-pw | xmlget Code)"
  check "ldap user without mapping" AccessDenied "$(sts Action=AssumeRoleWithLDAPIdentity LDAPUsername=bob LDAPPassword=bob-ldap-pw | xmlget Code)"
  check "ldap user policy attach" 0 "$(ok "$MC" idp ldap policy attach z readonly --user 'uid=bob,ou=people,dc=example,dc=org')"
  BC="$(sts Action=AssumeRoleWithLDAPIdentity LDAPUsername=bob LDAPPassword=bob-ldap-pw | creds)"
  check "ldap user mapping grants read" hello "$(s3as "$BC" s3 cp s3://other/seed.txt -)"
  check "ldap user mapping no write" 1 "$(ok s3as "$BC" s3 cp "$WORK/f.txt" s3://other/b.txt)"
  check "ldap policy entities" 1 "$("$MC" idp ldap policy entities z --json | grep -c 'cn=devs,ou=groups,dc=example,dc=org' || true)"
  check "ldap policy detach" 0 "$(ok "$MC" idp ldap policy detach z readonly --user 'uid=bob,ou=people,dc=example,dc=org')"
  check "detached mapping denies" AccessDenied "$(sts Action=AssumeRoleWithLDAPIdentity LDAPUsername=bob LDAPPassword=bob-ldap-pw | xmlget Code)"

  check "ldap switch to StartTLS" 0 "$(ok "$MC" idp ldap update z server_insecure=off server_starttls=on tls_skip_verify=on)"
  check "ldap login (StartTLS)" ASIA "$(sts Action=AssumeRoleWithLDAPIdentity LDAPUsername=alice LDAPPassword=alice-ldap-pw | xmlget AccessKeyId | cut -c1-4)"
  check "ldap switch to LDAPS" 0 "$(ok "$MC" idp ldap update z "server_addr=127.0.0.1:$LDAPS_PORT" server_starttls=off tls_skip_verify=on)"
  check "ldap login (LDAPS)" ASIA "$(sts Action=AssumeRoleWithLDAPIdentity LDAPUsername=alice LDAPPassword=alice-ldap-pw | xmlget AccessKeyId | cut -c1-4)"
  check "ldaps wrong password" AccessDenied "$(sts Action=AssumeRoleWithLDAPIdentity LDAPUsername=alice LDAPPassword=nope | xmlget Code)"
  check "ldaps verifies certificates by default" ServiceUnavailable "$( "$MC" idp ldap update z tls_skip_verify=off >/dev/null; sts Action=AssumeRoleWithLDAPIdentity LDAPUsername=alice LDAPPassword=alice-ldap-pw | xmlget Code)"
  "$MC" idp ldap update z tls_skip_verify=on >/dev/null
  check "ldap tenant setting" 0 "$(ok "$MC" idp ldap update z tenant=globex)"
  TL="$(sts Action=AssumeRoleWithLDAPIdentity LDAPUsername=alice LDAPPassword=alice-ldap-pw | creds)"
  check "ldap tenant session loses global bucket" 1 "$(ok s3as "$TL" s3 cp "$WORK/f.txt" s3://teamb/tenant.txt)"
  docker stop -t 1 "$LDAP_NAME" >/dev/null
  check "directory down" ServiceUnavailable "$(sts Action=AssumeRoleWithLDAPIdentity LDAPUsername=alice LDAPPassword=alice-ldap-pw | xmlget Code)"
else
  skip=$((skip + 1)); echo "skip LDAP: docker or the osixia/openldap:1.5.0 image is unavailable"
fi
stop

# ---------------------------------------------------------------- client certificates
(
  cd "$WORK"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.crt -days 2 -subj /CN=zk-ca 2>/dev/null
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout bad.key -out bad.crt -days 2 -subj /CN=zk-bad-ca 2>/dev/null
  mk() { # name cn ca
    openssl ecparam -name prime256v1 -genkey -noout -out "$1.key" 2>/dev/null
    openssl req -new -key "$1.key" -subj "/CN=$2" -out "$1.csr" 2>/dev/null
    openssl x509 -req -in "$1.csr" -CA "$3.crt" -CAkey "$3.key" -CAcreateserial -days 1 -extfile <(echo "$4") -out "$1.crt" 2>/dev/null
  }
  mk srv localhost ca "subjectAltName=DNS:localhost,IP:127.0.0.1"
  mk cli readonly ca "extendedKeyUsage=clientAuth"
  mk evil readwrite bad "extendedKeyUsage=clientAuth"
  mk nopol no-such-policy ca "extendedKeyUsage=clientAuth"
)
start --tls-cert "$WORK/srv.crt" --tls-key "$WORK/srv.key" --tls-client-ca "$WORK/ca.crt"
for _ in $(seq 50); do curl -s -o /dev/null --cacert "$WORK/ca.crt" "https://127.0.0.1:$PORT/" && break; sleep 0.1; done
cstst() { curl -s -X POST --cacert "$WORK/ca.crt" "$@" "https://127.0.0.1:$PORT/?Action=AssumeRoleWithCertificate&Version=2011-06-15"; }
CX="$(cstst --cert "$WORK/cli.crt" --key "$WORK/cli.key")"
read -r M_AK M_SK M_TOK <<<"$(echo "$CX" | creds)"
check "certificate session issued" ASIA "${M_AK:0:4}"
check "certificate session reads" hello "$(AWS_ACCESS_KEY_ID="$M_AK" AWS_SECRET_ACCESS_KEY="$M_SK" AWS_SESSION_TOKEN="$M_TOK" "$S3CLI_BIN" --endpoint-url "https://127.0.0.1:$PORT" --ca-bundle "$WORK/ca.crt" s3 cp s3://other/seed.txt -)"
check "certificate session read-only" 1 "$(ok env AWS_ACCESS_KEY_ID="$M_AK" AWS_SECRET_ACCESS_KEY="$M_SK" AWS_SESSION_TOKEN="$M_TOK" "$S3CLI_BIN" --endpoint-url "https://127.0.0.1:$PORT" --ca-bundle "$WORK/ca.crt" s3 cp "$WORK/f.txt" s3://other/m.txt)"
check "no client certificate" AccessDenied "$(cstst | xmlget Code)"
check "untrusted client certificate refused" "" "$(cstst --cert "$WORK/evil.crt" --key "$WORK/evil.key" | xmlget AccessKeyId)"
check "CN without policy" AccessDenied "$(cstst --cert "$WORK/nopol.crt" --key "$WORK/nopol.key" | xmlget Code)"
check "plain HTTPS without a certificate still works" 200 "$(curl -s -o /dev/null -w '%{http_code}' --cacert "$WORK/ca.crt" "https://127.0.0.1:$PORT/health/live")"
stop

echo "identity: $pass passed, $fail failed, $skip skipped"
[[ $fail -eq 0 ]]
