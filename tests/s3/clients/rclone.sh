# rclone suite (pinned download); sourced by run.sh.
bash "$HERE/fetch_tools.sh" >>"$LOG" 2>&1 || { record FAIL "rclone download" "see log"; return 0; }
export RCLONE_CONFIG="$WORK/rclone.conf"
cat >"$RCLONE_CONFIG" <<EOF
[zk]
type = s3
provider = Other
access_key_id = $AK
secret_access_key = $SK
endpoint = $EP
region = us-east-1
force_path_style = true
EOF
rc() { "$HERE/.bin/rclone" --config "$RCLONE_CONFIG" "$@" 2>>"$LOG"; }

B=$(rand_bucket rclone)
mkdir -p "$WORK/src/dir/nested" "$WORK/src/spécial chars"
for i in $(seq 1 20); do head -c $((i * 3000)) /dev/urandom >"$WORK/src/dir/f$i"; done
head -c 40000000 /dev/urandom >"$WORK/src/large.bin"
echo "odd" >"$WORK/src/spécial chars/a+b%c#d?e.txt"
echo n >"$WORK/src/dir/nested/n.txt"
NFILES=$(find "$WORK/src" -type f | wc -l)

ok "mkdir" rc mkdir "zk:$B"
ok "copy up (multipart for large)" rc copy --s3-upload-cutoff 10M --s3-chunk-size 5M --transfers 8 "$WORK/src" "zk:$B/data"
ok "check after copy" rc check "$WORK/src" "zk:$B/data"
check "lsjson count" "$NFILES" "$(rc lsjson -R --files-only "zk:$B/data" | grep -c '"Path"')"
check "lsjson special name" 1 "$(rc lsjson -R --files-only "zk:$B/data" | grep -c 'a+b%c#d?e.txt')"
check "lsjson dirs" 1 "$(rc lsjson "zk:$B/data" | grep -c '"IsDir":true,"Tier"\|"Name":"dir"' | awk '{print ($1>0)}')"
check "size" "$NFILES" "$(rc size --json "zk:$B/data" | sed -n 's/.*"count":\([0-9]*\).*/\1/p')"
check "cat" odd "$(rc cat "zk:$B/data/spécial chars/a+b%c#d?e.txt")"
echo changed >"$WORK/src/dir/f1"; rm "$WORK/src/dir/f2"; echo new >"$WORK/src/dir/new.txt"
ok "sync" rc sync "$WORK/src" "zk:$B/data"
ok "check after sync" rc check "$WORK/src" "zk:$B/data"
ok "check --download" rc check --download "$WORK/src" "zk:$B/data"
ok "server-side copy" rc copy "zk:$B/data/dir" "zk:$B/copy"
ok "check server-side copy" rc check "$WORK/src/dir" "zk:$B/copy"
ok "copy down" rc copy "zk:$B/data" "$WORK/down"
check "roundtrip md5" "$(cd "$WORK/src" && find . -type f | sort | xargs -d '\n' md5sum)" "$(cd "$WORK/down" && find . -type f | sort | xargs -d '\n' md5sum)"
ok "moveto" rc moveto "zk:$B/data/dir/f3" "zk:$B/moved"
check "moveto source gone" 0 "$(rc lsf "zk:$B/data/dir" | grep -cx f3 || true)"
ok "delete filter" rc delete --include 'f1*' "zk:$B/data/dir"
check "delete filter left" 0 "$(rc lsf "zk:$B/data/dir" | grep -c '^f1' || true)"
ok "purge" rc purge "zk:$B"
check "bucket gone" 0 "$(rc lsf zk: | grep -c "^$B/\$" || true)"
rm -rf "$WORK/src" "$WORK/down"
