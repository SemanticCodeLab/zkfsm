# s5cmd suite (pinned download): concurrent cp/ls/rm and large files; sourced by run.sh.
bash "$HERE/fetch_tools.sh" >>"$LOG" 2>&1 || { record FAIL "s5cmd download" "see log"; return 0; }
s5() {
  AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_REGION=us-east-1 AWS_SHARED_CREDENTIALS_FILE=/dev/null \
    "$HERE/.bin/s5cmd" --endpoint-url "$EP" --no-verify-ssl "$@" 2>>"$LOG"
}

B=$(rand_bucket s5cmd)
mkdir -p "$WORK/many"
for i in $(seq 1 200); do head -c $((RANDOM % 5000 + 1)) /dev/urandom >"$WORK/many/obj$i"; done
head -c 120000000 /dev/urandom >"$WORK/large.bin"

ok "mb" s5 mb "s3://$B"
ok "cp many (numworkers 32)" s5 --numworkers 32 cp "$WORK/many/*" "s3://$B/many/"
check "ls count" 200 "$(s5 ls "s3://$B/many/*" | wc -l)"
ok "cp large (concurrency 8, 8MB parts)" s5 cp --concurrency 8 --part-size 8 "$WORK/large.bin" "s3://$B/large.bin"
check "ls large size" 120000000 "$(s5 ls "s3://$B/large.bin" | awk '{print $3}')"
ok "cp large down (concurrency 8)" s5 cp --concurrency 8 --part-size 8 "s3://$B/large.bin" "$WORK/large.out"
check "large roundtrip md5" "$(md5 "$WORK/large.bin")" "$(md5 "$WORK/large.out")"
ok "cp many down" s5 --numworkers 32 cp "s3://$B/many/*" "$WORK/down/"
check "many roundtrip" "$(cd "$WORK/many" && md5sum * | sort)" "$(cd "$WORK/down" && md5sum * | sort)"
ok "cp server-side" s5 cp "s3://$B/many/obj1" "s3://$B/copy/obj1"
check "cat copy" "$(md5 "$WORK/many/obj1")" "$(s5 cat "s3://$B/copy/obj1" | md5sum | cut -d' ' -f1)"
check "ls prefixes" 2 "$(s5 ls "s3://$B/" | grep -c DIR)"
check "du" 200 "$(s5 du "s3://$B/many/*" | sed -n 's/.* in \([0-9]*\) objects.*/\1/p')"
ok "rm wildcard (batched DeleteObjects)" s5 rm "s3://$B/many/*"
check "ls after rm" 0 "$(s5 ls "s3://$B/many/*" | wc -l)"
ok "rm rest" s5 rm "s3://$B/*"
ok "rb" s5 rb "s3://$B"
rm -rf "$WORK/many" "$WORK/down" "$WORK/large.bin" "$WORK/large.out"
