#!/usr/bin/env bash
# S3 Tables and the Iceberg REST catalog end to end: control-plane calls with
# curl (SigV4, service s3tables), version-token CAS, hostile bodies, reserved
# keys, then PyIceberg (create/append/scan/evolve/conflicts/drop) and boto3.
# Needs python with pyiceberg[pyarrow] and boto3: TABLES_PY, else .venv-scratch.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')"
EP="http://127.0.0.1:$PORT"
WORK="$(mktemp -d)"
PID=""
stop() { if [[ -n "$PID" ]] && kill -0 "$PID" 2>/dev/null; then kill "$PID"; wait "$PID" 2>/dev/null || true; fi; PID=""; }
cleanup() { stop; rm -rf "$WORK"; }
trap cleanup EXIT

PY="${TABLES_PY:-$ROOT/.venv-scratch/bin/python}"
if ! "$PY" -c 'import pyiceberg, pyarrow, boto3' 2>/dev/null; then
  echo "tables.sh: creating $ROOT/.venv-scratch (pyiceberg[pyarrow], boto3)"
  python3 -m venv "$ROOT/.venv-scratch"
  "$ROOT/.venv-scratch/bin/pip" install -q --no-cache-dir 'pyiceberg[pyarrow]' boto3
  PY="$ROOT/.venv-scratch/bin/python"
fi

AK="zkfsmtablesaccess"
SK="zkfsm-tables-secret-123"
export ZKFSM_ACCESS_KEY="$AK" ZKFSM_SECRET_KEY="$SK"
export AWS_CONFIG_FILE="$WORK/aws.conf" AWS_SHARED_CREDENTIALS_FILE="$WORK/aws.creds" AWS_EC2_METADATA_DISABLED=true
export MC_CONFIG_DIR="$WORK/mc"
MC="${MC:-$(command -v mc || true)}"

pass=0
fail=0
check() { # name expected actual
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); echo "ok   $1"
  else fail=$((fail + 1)); echo "FAIL $1: expected [$2] got [$3]"; fi
}
tcurl() { curl -s --aws-sigv4 "aws:amz:us-east-1:s3tables" --user "$AK:$SK" "$@"; }
icurl() { curl -s --aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" "$@"; }
code() { tcurl -o "$WORK/out" -w '%{http_code}' "$@"; }
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2], {"d": d}))' "$WORK/out" "$1"; }
enc() { python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }

(cd "$ROOT" && zig build)
"$ROOT/zig-out/bin/zkfsm" --data "$WORK/data" --listen "127.0.0.1:$PORT" --scan-interval 0 >"$WORK/server.log" 2>&1 &
PID=$!
for _ in $(seq 100); do curl -s -o /dev/null "$EP/" && break; sleep 0.1; done

JSON=(-H 'content-type: application/json')
check "create table bucket" 200 "$(code -X PUT "${JSON[@]}" -d '{"name":"tb1"}' "$EP/buckets")"
ARN="$(jget 'd["arn"]')"
check "bucket arn" "arn:aws:s3tables:us-east-1:000000000000:bucket/tb1" "$ARN"
A="$(enc "$ARN")"
check "duplicate table bucket" 409 "$(code -X PUT "${JSON[@]}" -d '{"name":"tb1"}' "$EP/buckets")"
check "conflict error type" "ConflictException" "$(tcurl -D - -o /dev/null -X PUT "${JSON[@]}" -d '{"name":"tb1"}' "$EP/buckets" | tr -d '\r' | awk -F': ' 'tolower($1)=="x-amzn-errortype"{print $2}')"
check "invalid bucket name" 400 "$(code -X PUT "${JSON[@]}" -d '{"name":"BAD_name"}' "$EP/buckets")"
check "get table bucket" 200 "$(code "$EP/buckets/$A")"
check "get table bucket name" tb1 "$(jget 'd["name"]')"
check "list table buckets" 200 "$(code "$EP/buckets")"
check "list has tb1" True "$(jget '[b["name"] for b in d["tableBuckets"]] == ["tb1"]')"
check "unknown table bucket" 404 "$(code "$EP/buckets/$(enc arn:aws:s3tables:us-east-1:000000000000:bucket/nope)")"

check "create namespace" 200 "$(code -X PUT "${JSON[@]}" -d '{"namespace":["ns1"]}' "$EP/namespaces/$A")"
check "namespace echoed" ns1 "$(jget 'd["namespace"][0]')"
check "bad namespace name" 400 "$(code -X PUT "${JSON[@]}" -d '{"namespace":["Bad-Name"]}' "$EP/namespaces/$A")"
check "get namespace" 200 "$(code "$EP/namespaces/$A/ns1")"
check "list namespaces" True "$(code "$EP/namespaces/$A" >/dev/null; jget '[n["namespace"] for n in d["namespaces"]] == [["ns1"]]')"

SCHEMA='{"name":"t1","format":"ICEBERG","metadata":{"iceberg":{"schema":{"fields":[{"name":"id","type":"long","required":true},{"name":"v","type":"string"}]}}}}'
check "create table" 200 "$(code -X PUT "${JSON[@]}" -d "$SCHEMA" "$EP/tables/$A/ns1")"
TOKEN0="$(jget 'd["versionToken"]')"
check "create table without metadata" 200 "$(code -X PUT "${JSON[@]}" -d '{"name":"bare","format":"ICEBERG"}' "$EP/tables/$A/ns1")"
check "duplicate table" 409 "$(code -X PUT "${JSON[@]}" -d "$SCHEMA" "$EP/tables/$A/ns1")"
check "table in missing namespace" 404 "$(code -X PUT "${JSON[@]}" -d "$SCHEMA" "$EP/tables/$A/nons")"
check "get metadata location" 200 "$(code "$EP/tables/$A/ns1/t1/metadata-location")"
check "token stable" "$TOKEN0" "$(jget 'd["versionToken"]')"
LOC0="$(jget 'd["metadataLocation"]')"
KEY0="${LOC0#s3://tb1/}"
check "get-table query form" 200 "$(code "$EP/get-table?tableBucketARN=$A&namespace=ns1&name=t1")"
check "get-table format" ICEBERG "$(jget 'd["format"]')"
check "list tables" True "$(code "$EP/tables/$A?namespace=ns1" >/dev/null; jget 'sorted(t["name"] for t in d["tables"]) == ["bare", "t1"]')"
check "list tables prefix" True "$(code "$EP/tables/$A?namespace=ns1&prefix=ba" >/dev/null; jget '[t["name"] for t in d["tables"]] == ["bare"]')"
check "list tables paging" True "$(code "$EP/tables/$A?maxTables=1" >/dev/null; jget 'len(d["tables"]) == 1 and "continuationToken" in d')"

# Version-token CAS on the metadata pointer.
icurl -X PUT --data-binary @<(icurl "$EP/tb1/$KEY0") "$EP/tb1/tables/manual/metadata/00001-x.metadata.json" -o /dev/null
NEWLOC="s3://tb1/tables/manual/metadata/00001-x.metadata.json"
check "update with wrong token" 409 "$(code -X PUT "${JSON[@]}" -d "{\"versionToken\":\"bogus\",\"metadataLocation\":\"$NEWLOC\"}" "$EP/tables/$A/ns1/t1/metadata-location")"
check "update to missing file" 400 "$(code -X PUT "${JSON[@]}" -d "{\"versionToken\":\"$TOKEN0\",\"metadataLocation\":\"s3://tb1/none.json\"}" "$EP/tables/$A/ns1/t1/metadata-location")"
check "update outside bucket" 400 "$(code -X PUT "${JSON[@]}" -d "{\"versionToken\":\"$TOKEN0\",\"metadataLocation\":\"s3://other/x.json\"}" "$EP/tables/$A/ns1/t1/metadata-location")"
check "update with current token" 200 "$(code -X PUT "${JSON[@]}" -d "{\"versionToken\":\"$TOKEN0\",\"metadataLocation\":\"$NEWLOC\"}" "$EP/tables/$A/ns1/t1/metadata-location")"
TOKEN1="$(jget 'd["versionToken"]')"
check "token advanced" True "$([[ "$TOKEN1" != "$TOKEN0" ]] && echo True || echo False)"
check "replayed old token" 409 "$(code -X PUT "${JSON[@]}" -d "{\"versionToken\":\"$TOKEN0\",\"metadataLocation\":\"$LOC0\"}" "$EP/tables/$A/ns1/t1/metadata-location")"
check "pointer moved" "$NEWLOC" "$(code "$EP/tables/$A/ns1/t1/metadata-location" >/dev/null; jget 'd["metadataLocation"]')"

# Concurrent CAS: 8 updates from the same token, exactly one wins.
for n in $(seq 8); do
  tcurl -o /dev/null -w '%{http_code}\n' -X PUT "${JSON[@]}" -d "{\"versionToken\":\"$TOKEN1\",\"metadataLocation\":\"$LOC0\"}" "$EP/tables/$A/ns1/t1/metadata-location" >"$WORK/cas.$n" &
done
wait_jobs() { for j in $(jobs -p); do [[ "$j" == "$PID" ]] || wait "$j"; done; }
wait_jobs
check "concurrent CAS winners" 1 "$(cat "$WORK"/cas.* | grep -c '^200$')"
check "concurrent CAS conflicts" 7 "$(cat "$WORK"/cas.* | grep -c '^409$')"

check "rename table" 204 "$(code -X PUT "${JSON[@]}" -d '{"newName":"t1b"}' "$EP/tables/$A/ns1/t1/rename")"
check "old name gone" 404 "$(code "$EP/tables/$A/ns1/t1/metadata-location")"
check "delete with stale token" 409 "$(code -X DELETE "$EP/tables/$A/ns1/t1b?versionToken=$TOKEN0")"
check "delete non-empty namespace" 409 "$(code -X DELETE "$EP/namespaces/$A/ns1")"

POLICY='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3tables:GetTableBucket","Resource":"*"}]}'
check "put bucket policy" 200 "$(code -X PUT "${JSON[@]}" -d "$(python3 -c 'import json,sys;print(json.dumps({"resourcePolicy":sys.argv[1]}))' "$POLICY")" "$EP/buckets/$A/policy")"
check "get bucket policy" True "$(code "$EP/buckets/$A/policy" >/dev/null; jget '"s3tables:GetTableBucket" in d["resourcePolicy"]')"
check "invalid bucket policy" 400 "$(code -X PUT "${JSON[@]}" -d '{"resourcePolicy":"{nope"}' "$EP/buckets/$A/policy")"

# Hostile and unauthenticated input.
check "truncated JSON" 400 "$(code -X PUT "${JSON[@]}" -d '{"name":' "$EP/tables/$A/ns1")"
DEEP="$(python3 -c 'print("[" * 5000 + "]" * 5000)')"
check "deeply nested JSON" 400 "$(code -X PUT "${JSON[@]}" -d "$DEEP" "$EP/tables/$A/ns1")"
check "wrong JSON types" 400 "$(code -X PUT "${JSON[@]}" -d '{"name":7,"metadata":[1]}' "$EP/tables/$A/ns1")"
head -c $((9 * 1024 * 1024)) /dev/zero >"$WORK/big"
check "oversized body" 413 "$(code -X PUT "${JSON[@]}" --data-binary @"$WORK/big" "$EP/tables/$A/ns1")"
check "unsigned config allowed by bucket policy" 200 "$(curl -s -o /dev/null -w '%{http_code}' "$EP/iceberg/v1/config?warehouse=tb1")"
check "unsigned namespace list denied" 403 "$(curl -s -o /dev/null -w '%{http_code}' "$EP/iceberg/v1/tb1/namespaces")"
check "bad signature" 403 "$(curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 "aws:amz:us-east-1:s3tables" --user "$AK:wrong-secret" "$EP/buckets")"
check "s3tables-signed S3 path not served as S3" 400 "$(tcurl -o /dev/null -w '%{http_code}' "$EP/tb1?list-type=2&prefix=zz")"
check "iceberg config" 200 "$(icurl -o "$WORK/out" -w '%{http_code}' "$EP/iceberg/v1/config?warehouse=$A")"
check "config prefix override" tb1 "$(jget 'd["overrides"]["prefix"]')"
check "iceberg unknown warehouse" 404 "$(icurl -o /dev/null -w '%{http_code}' "$EP/iceberg/v1/nope/namespaces")"
check "iceberg load table" 200 "$(icurl -o "$WORK/out" -w '%{http_code}' "$EP/iceberg/v1/tb1/namespaces/ns1/tables/t1b")"
check "iceberg load metadata" True "$(jget 'd["metadata"]["format-version"] == 2 and d["metadata-location"].startswith("s3://tb1/")')"
check "iceberg commit garbage" 400 "$(icurl -o /dev/null -w '%{http_code}' -X POST "${JSON[@]}" -d '{"updates":[{"action":"nope"}]}' "$EP/iceberg/v1/tb1/namespaces/ns1/tables/t1b")"
check "iceberg commit stale uuid" 409 "$(icurl -o "$WORK/out" -w '%{http_code}' -X POST "${JSON[@]}" -d '{"requirements":[{"type":"assert-table-uuid","uuid":"x"}],"updates":[]}' "$EP/iceberg/v1/tb1/namespaces/ns1/tables/t1b")"
check "commit failed type" CommitFailedException "$(jget 'd["error"]["type"]')"

# Reserved catalog keys are not reachable through S3; table data is.
check "reserved key read denied" 403 "$(icurl -o /dev/null -w '%{http_code}' "$EP/tb1/.zkfsm-tables/bucket")"
check "reserved key write denied" 403 "$(icurl -o /dev/null -w '%{http_code}' -X PUT -d x "$EP/tb1/.zkfsm-tables/bucket")"
check "reserved key delete denied" 403 "$(icurl -o /dev/null -w '%{http_code}' -X DELETE "$EP/tb1/.zkfsm-tables/bucket")"
icurl -X PUT -d x "$EP/tb1/-early" -o /dev/null
icurl -X PUT -d y "$EP/tb1/zz/late" -o /dev/null
DEL='<Delete><Object><Key>.zkfsm-tables/bucket</Key></Object><Object><Key>-early</Key></Object></Delete>'
MD5="$(printf '%s' "$DEL" | openssl md5 -binary | base64)"
icurl -X POST -H "Content-MD5: $MD5" -d "$DEL" "$EP/tb1?delete" >"$WORK/del.xml"
check "DeleteObjects reserved key denied" 1 "$(grep -c '<Error><Key>.zkfsm-tables/bucket</Key><Code>AccessDenied</Code>' "$WORK/del.xml")"
check "DeleteObjects other key deleted" 1 "$(grep -c '<Deleted><Key>-early</Key>' "$WORK/del.xml")"
check "catalog intact after DeleteObjects" 200 "$(code "$EP/buckets/$A")"
icurl -X PUT -d x "$EP/tb1/-early" -o /dev/null
check "copy from reserved denied" 403 "$(icurl -o /dev/null -w '%{http_code}' -X PUT -H 'x-amz-copy-source: /tb1/.zkfsm-tables/bucket' "$EP/tb1/stolen")"
check "copy from reserved (encoded) denied" 403 "$(icurl -o /dev/null -w '%{http_code}' -X PUT -H 'x-amz-copy-source: tb1/%2Ezkfsm-tables%2Fbucket' "$EP/tb1/stolen")"
check "copy onto reserved denied" 403 "$(icurl -o /dev/null -w '%{http_code}' -X PUT -H 'x-amz-copy-source: /tb1/-early' "$EP/tb1/.zkfsm-tables/bucket")"
check "multipart create on reserved denied" 403 "$(icurl -o /dev/null -w '%{http_code}' -X POST "$EP/tb1/.zkfsm-tables/x?uploads")"
check "multipart part on reserved denied" 403 "$(icurl -o /dev/null -w '%{http_code}' -X PUT -d x "$EP/tb1/.zkfsm-tables/x?partNumber=1&uploadId=abc")"
check "multipart complete on reserved denied" 403 "$(icurl -o /dev/null -w '%{http_code}' -X POST -d '<CompleteMultipartUpload/>' "$EP/tb1/.zkfsm-tables/x?uploadId=abc")"
UPID="$(icurl -X POST "$EP/tb1/upl?uploads" | sed -n 's:.*<UploadId>\(.*\)</UploadId>.*:\1:p')"
check "UploadPartCopy from reserved denied" 403 "$(icurl -o /dev/null -w '%{http_code}' -X PUT -H 'x-amz-copy-source: /tb1/.zkfsm-tables/bucket' "$EP/tb1/upl?partNumber=1&uploadId=$UPID")"
check "ListObjects V1 hides reserved" 0 "$(icurl "$EP/tb1" | grep -c zkfsm-tables)"
check "ListObjects V2 hides reserved" 0 "$(icurl "$EP/tb1?list-type=2" | grep -c zkfsm-tables)"
check "ListObjects V2 delimiter hides reserved" 0 "$(icurl "$EP/tb1?list-type=2&delimiter=/" | grep -c zkfsm-tables)"
check "ListObjectVersions hides reserved" 0 "$(icurl "$EP/tb1?versions" | grep -c zkfsm-tables)"
check "ListMultipartUploads hides reserved" 0 "$(icurl "$EP/tb1?uploads" | grep -c zkfsm-tables)"
ALL="$(icurl "$EP/tb1?list-type=2" | grep -o '<Key>[^<]*</Key>' | tr '\n' ' ')"
walk=""; tok=""
for _ in $(seq 50); do
  pg="$(icurl "$EP/tb1?list-type=2&max-keys=1${tok:+&continuation-token=$(enc "$tok")}")"
  walk+="$(grep -o '<Key>[^<]*</Key>' <<<"$pg" | tr '\n' ' ')"
  grep -q '<IsTruncated>true</IsTruncated>' <<<"$pg" || break
  tok="$(sed -n 's:.*<NextContinuationToken>\([^<]*\)</NextContinuationToken>.*:\1:p' <<<"$pg")"
done
check "paged V2 walk equals full listing" "$ALL" "$walk"
check "paged walk spans reserved range" True "$([[ "$walk" == *"-early"* && "$walk" == *"zz/late"* ]] && echo True || echo False)"
VER="$(icurl "$EP/tb1?versions&max-keys=1")"
check "versions page truncates past reserved" 1 "$(grep -c '<IsTruncated>true</IsTruncated>' <<<"$VER")"
check "metadata file readable via S3" 200 "$(icurl -o /dev/null -w '%{http_code}' "$EP/tb1/$KEY0")"
if [[ -n "$MC" ]]; then
  "$MC" alias set z "$EP" "$AK" "$SK" >/dev/null
  check "mc sees table metadata" 1 "$("$MC" ls --recursive z/tb1/tables/ | grep -c "manual/metadata/00001-x.metadata.json")"
else
  echo "skip mc checks (no mc)"
fi

for t in t1b bare; do code -X DELETE "$EP/tables/$A/ns1/$t" >/dev/null; done
check "delete namespace" 204 "$(code -X DELETE "$EP/namespaces/$A/ns1")"

# PyIceberg and boto3 against a fresh table bucket.
check "create client table bucket" 200 "$(code -X PUT "${JSON[@]}" -d '{"name":"lakehouse"}' "$EP/buckets")"
WH_ARN="$(jget 'd["arn"]')"
if EP="$EP" AK="$AK" SK="$SK" TABLE_BUCKET_ARN="$WH_ARN" "$PY" "$ROOT/tests/tables_client.py" >"$WORK/client.log" 2>&1; then
  pass=$((pass + 1)); echo "ok   pyiceberg/boto3 client suite"
else
  fail=$((fail + 1)); echo "FAIL pyiceberg/boto3 client suite"
fi
grep -E '^(ok|FAIL)' "$WORK/client.log" | sed 's/^/     /'
grep -q '^tables client: 0 failure' "$WORK/client.log" || tail -30 "$WORK/client.log"

check "delete client table bucket" 204 "$(code -X DELETE "$EP/buckets/$(enc "$WH_ARN")")"
check "delete table bucket" 204 "$(code -X DELETE "$EP/buckets/$A")"
check "deleted bucket gone" 404 "$(code "$EP/buckets/$A")"
kill -0 "$PID" || { fail=$((fail + 1)); echo "FAIL server died"; tail -20 "$WORK/server.log"; }

echo "tables: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
