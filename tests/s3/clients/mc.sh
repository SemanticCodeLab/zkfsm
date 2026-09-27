# MinIO client suite; sourced by run.sh. Some distros ship Midnight Commander as `mc`, so MC can point elsewhere.
MCBIN="${MC:-$(command -v mc || true)}"
if [[ -z "$MCBIN" ]] || ! "$MCBIN" --version 2>/dev/null | grep -q RELEASE; then
  record FAIL "mc present" "MinIO client not found (set MC=/path/to/mc)"; return 0
fi
export MC_CONFIG_DIR="$WORK/mcconf"
m() { "$MCBIN" --no-color "$@" 2>>"$LOG"; }
m alias set zk "$EP" "$AK" "$SK" --api S3v4 --path on >/dev/null

B=$(rand_bucket mc)
head -c 70000000 /dev/urandom >"$WORK/big.bin"
mkdir -p "$WORK/tree/a/b"
for i in 1 2 3 4 5; do head -c $((i * 1000)) /dev/urandom >"$WORK/tree/f$i"; done
echo x >"$WORK/tree/a/b/deep"; echo y >"$WORK/tree/a/ü ñ+%.txt"

ok "mb" m mb "zk/$B"
ok "cp large (multipart, streaming signature)" m cp "$WORK/big.bin" "zk/$B/big.bin"
check "cat large md5" "$(md5 "$WORK/big.bin")" "$(m cat "zk/$B/big.bin" | md5sum | cut -d' ' -f1)"
check "stat size" 70000000 "$(m stat --json "zk/$B/big.bin" | sed -n 's/.*"size":\([0-9]*\).*/\1/p')"
ok "pipe" bash -c "echo piped | '$MCBIN' pipe 'zk/$B/piped'"
check "cat piped" piped "$(m cat "zk/$B/piped")"
ok "mirror up" m mirror "$WORK/tree" "zk/$B/tree"
check "ls recursive count" 7 "$(m ls --recursive "zk/$B/tree" | wc -l)"
check "unicode key" y "$(m cat "zk/$B/tree/a/ü ñ+%.txt")"
ok "mirror down" m mirror "zk/$B/tree" "$WORK/down"
check "mirror roundtrip" "$(cd "$WORK/tree" && find . -type f | sort | xargs -d '\n' md5sum)" "$(cd "$WORK/down" && find . -type f | sort | xargs -d '\n' md5sum)"
check "find by name" 1 "$(m find "zk/$B/tree" --name 'deep' | wc -l)"
ok "cp server-side" m cp "zk/$B/tree/f3" "zk/$B/copied"
check "diff identical" 0 "$(m diff "$WORK/tree" "zk/$B/tree" | wc -l)"
ok "tag set" m tag set "zk/$B/copied" "k1=v1&k2=v2"
check "tag list" 1 "$(m tag list --json "zk/$B/copied" | grep -c '"k1":"v1"')"
ok "version enable" m version enable "zk/$B"
check "version info" 1 "$(m version info "zk/$B" | grep -ci enabled)"
echo v1 | m pipe "zk/$B/ver" >/dev/null; echo v2 | m pipe "zk/$B/ver" >/dev/null
check "ls versions" 2 "$(m ls --versions "zk/$B/ver" | wc -l)"
URL=$(m share download --expire 5m --json "zk/$B/tree/f1" | sed -n 's/.*"share":"\([^"]*\)".*/\1/p')
check "share download" "$(md5 "$WORK/tree/f1")" "$(curl -s "$URL" | md5sum | cut -d' ' -f1)"
ok "rm recursive (DeleteObjects)" m rm --recursive --force --versions "zk/$B"
check "empty after rm" 0 "$(m ls --recursive --versions "zk/$B" | wc -l)"
ok "rb" m rb "zk/$B"
rm -f "$WORK/big.bin"
