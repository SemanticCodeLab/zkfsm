# S3 CLI suite (high-level `s3` and low-level `s3api` commands); sourced by run.sh.
CLI="${S3CLI_BIN:-$(command -v aws || true)}"
if [[ -z "$CLI" ]]; then record FAIL "cli present" "S3 CLI not found (set S3CLI_BIN)"; return 0; fi
export AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_DEFAULT_REGION=us-east-1 AWS_PAGER=""
export AWS_CONFIG_FILE="$WORK/cli.conf" AWS_SHARED_CREDENTIALS_FILE="$WORK/cli.creds"
printf '[default]\ns3 =\n  addressing_style = path\n  multipart_threshold = 8MB\n  multipart_chunksize = 5MB\n' >"$AWS_CONFIG_FILE"
cli() { "$CLI" --endpoint-url "$EP" "$@"; }
q() { cli "$@" 2>>"$LOG"; }

B=$(rand_bucket cli)
head -c 21000000 /dev/urandom >"$WORK/big.bin"
echo "hello conformance" >"$WORK/small.txt"
mkdir -p "$WORK/tree/sub/deeper"
for i in 1 2 3; do echo "file $i" >"$WORK/tree/f$i.txt"; echo "sub $i" >"$WORK/tree/sub/s$i.txt"; done
echo deep >"$WORK/tree/sub/deeper/d.txt"
echo "with space" >"$WORK/tree/name with space.txt"

ok "mb" cli s3 mb "s3://$B"
check "ls buckets" 1 "$(q s3 ls | grep -c " $B\$")"
ok "cp small" cli s3 cp "$WORK/small.txt" "s3://$B/small.txt"
check "cp to stdout" "hello conformance" "$(q s3 cp "s3://$B/small.txt" -)"
ok "cp multipart upload" cli s3 cp "$WORK/big.bin" "s3://$B/big.bin"
check "multipart etag suffix" 1 "$(q s3api head-object --bucket "$B" --key big.bin --query ETag --output text | grep -c -- '-5"')"
ok "cp multipart download" cli s3 cp "s3://$B/big.bin" "$WORK/big.out"
check "multipart roundtrip md5" "$(md5 "$WORK/big.bin")" "$(md5 "$WORK/big.out")"
ok "cp from stdin" bash -c "echo piped | '$CLI' --endpoint-url '$EP' s3 cp - 's3://$B/piped.txt'"
check "stdin content" "piped" "$(q s3 cp "s3://$B/piped.txt" -)"
ok "sync up" cli s3 sync "$WORK/tree" "s3://$B/tree"
check "sync up count" 8 "$(q s3 ls --recursive "s3://$B/tree/" | wc -l)"
check "sync idempotent" 0 "$(q s3 sync "$WORK/tree" "s3://$B/tree" | wc -l)"
echo changed >"$WORK/tree/f1.txt"; rm "$WORK/tree/f2.txt"
ok "sync delete" cli s3 sync --delete "$WORK/tree" "s3://$B/tree"
check "sync delete count" 7 "$(q s3 ls --recursive "s3://$B/tree/" | wc -l)"
check "sync updated content" "changed" "$(q s3 cp "s3://$B/tree/f1.txt" -)"
ok "sync down" cli s3 sync "s3://$B/tree" "$WORK/down"
check "sync down tree" "$(cd "$WORK/tree" && find . -type f | sort | xargs -d '\n' md5sum)" "$(cd "$WORK/down" && find . -type f | sort | xargs -d '\n' md5sum)"
check "ls delimiter" 1 "$(q s3 ls "s3://$B/tree/" | grep -c 'PRE sub/')"
check "space key" "with space" "$(q s3 cp "s3://$B/tree/name with space.txt" -)"
ok "mv" cli s3 mv "s3://$B/small.txt" "s3://$B/moved.txt"
check "mv source gone" 0 "$(q s3 ls "s3://$B/small.txt" | wc -l)"
ok "cp server-side" cli s3 cp "s3://$B/big.bin" "s3://$B/copy.bin"
check "server-side copy size" 21000000 "$(q s3api head-object --bucket "$B" --key copy.bin --query ContentLength --output text)"
ok "rm recursive" cli s3 rm --recursive "s3://$B/tree"
check "rm recursive empty" 0 "$(q s3 ls --recursive "s3://$B/tree/" | wc -l)"

# s3api
ok "put-object metadata" cli s3api put-object --bucket "$B" --key m.txt --body "$WORK/small.txt" --metadata a=1 --content-type text/plain
check "head metadata" 1 "$(q s3api head-object --bucket "$B" --key m.txt --query Metadata.a --output text)"
check "head content-type" text/plain "$(q s3api head-object --bucket "$B" --key m.txt --query ContentType --output text)"
check "get range" "ello" "$(q s3api get-object --bucket "$B" --key m.txt --range bytes=1-4 "$WORK/range.out" >/dev/null; cat "$WORK/range.out")"
check "list-objects-v2 max-keys" 1 "$(q s3api list-objects-v2 --bucket "$B" --max-keys 1 --query 'length(Contents)' --output text)"
check "list-objects-v2 paging" 5 "$(q s3api list-objects-v2 --bucket "$B" --page-size 1 --query 'Contents[].Key' --output text | wc -w)"
check "list-objects v1" 5 "$(q s3api list-objects --bucket "$B" --page-size 2 --query 'Contents[].Key' --output text | wc -w)"
ok "put-object-tagging" cli s3api put-object-tagging --bucket "$B" --key m.txt --tagging 'TagSet=[{Key=k,Value=v}]'
check "get-object-tagging" v "$(q s3api get-object-tagging --bucket "$B" --key m.txt --query 'TagSet[0].Value' --output text)"
ok "put-bucket-versioning" cli s3api put-bucket-versioning --bucket "$B" --versioning-configuration Status=Enabled
check "get-bucket-versioning" Enabled "$(q s3api get-bucket-versioning --bucket "$B" --query Status --output text)"
q s3api put-object --bucket "$B" --key v.txt --body "$WORK/small.txt" >/dev/null
q s3api put-object --bucket "$B" --key v.txt --body "$WORK/small.txt" >/dev/null
check "list-object-versions" 2 "$(q s3api list-object-versions --bucket "$B" --prefix v.txt --query 'length(Versions)' --output text)"
UP=$(q s3api create-multipart-upload --bucket "$B" --key mpu --query UploadId --output text)
check "list-multipart-uploads" 1 "$(q s3api list-multipart-uploads --bucket "$B" --query 'length(Uploads)' --output text)"
ok "abort-multipart-upload" cli s3api abort-multipart-upload --bucket "$B" --key mpu --upload-id "$UP"
check "delete-objects" 2 "$(q s3api delete-objects --bucket "$B" --delete 'Objects=[{Key=moved.txt},{Key=piped.txt}]' --query 'length(Deleted)' --output text)"
URL=$(q s3 presign "s3://$B/m.txt" --expires-in 120)
check "presign curl" "hello conformance" "$(curl -s "$URL")"
check "head missing 404" 1 "$(cli s3api head-object --bucket "$B" --key nope 2>&1 | grep -c 404 || true)"
cli s3 rm --recursive "s3://$B" >/dev/null 2>&1 || true
# Versioned: remove every version, then the bucket.
cli s3api list-object-versions --bucket "$B" --query '[Versions,DeleteMarkers][][].[Key,VersionId]' --output text 2>/dev/null |
  while read -r k v; do [[ -n "$k" && "$k" != None ]] && cli s3api delete-object --bucket "$B" --key "$k" --version-id "$v" >/dev/null; done
ok "rb" cli s3 rb "s3://$B"
rm -f "$WORK/big.bin" "$WORK/big.out"
