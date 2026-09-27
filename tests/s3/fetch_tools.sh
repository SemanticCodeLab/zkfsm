#!/usr/bin/env bash
# Downloads pinned rclone and s5cmd into tests/s3/.bin (gitignored).
# Hashes are copied from each release's published checksum file (SHA256SUMS, s5cmd_checksums.txt).
set -euo pipefail
BIN="$(cd "$(dirname "$0")" && pwd)/.bin"
mkdir -p "$BIN"
RCLONE_VERSION=v1.75.1
S5CMD_VERSION=2.3.0
case "$(uname -m)" in
  x86_64) RARCH=amd64 SARCH=64bit
    RSHA=982b5aa772841168f8e380f139e9e787b2a105403e32b94da8676a0e1c0a13ab
    SSHA=de0fdbfa3aceae55e069ba81a0fc17b2026567637603734a387b2fca06c299b4 ;;
  aarch64) RARCH=arm64 SARCH=arm64
    RSHA=03f2504174034b6d004152ed7369251c9a9ec1f7e0836eda420f5c7a5ec0dff9
    SSHA=1439f0d00ecedcd2a2f1f2c6749bbb0152b2257bf5086f29646ec8ae38798e24 ;;
  *) echo "unsupported arch $(uname -m)"; exit 1 ;;
esac

fetch() { # url sha256 dest
  curl -fsSL -o "$3" "$1"
  echo "$2  $3" | sha256sum -c --quiet - || { rm -f "$3"; echo "checksum mismatch for $1"; exit 1; }
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
if [[ ! -x "$BIN/rclone" ]] || ! "$BIN/rclone" version 2>/dev/null | grep -q "rclone $RCLONE_VERSION"; then
  z="rclone-$RCLONE_VERSION-linux-$RARCH.zip"
  fetch "https://github.com/rclone/rclone/releases/download/$RCLONE_VERSION/$z" "$RSHA" "$TMP/$z"
  (cd "$TMP" && python3 -c 'import sys,zipfile;zipfile.ZipFile(sys.argv[1]).extractall()' "$z")
  install -m 755 "$TMP/rclone-$RCLONE_VERSION-linux-$RARCH/rclone" "$BIN/rclone"
fi
if [[ ! -x "$BIN/s5cmd" ]] || ! "$BIN/s5cmd" version 2>/dev/null | grep -q "v$S5CMD_VERSION"; then
  t="s5cmd_${S5CMD_VERSION}_Linux-$SARCH.tar.gz"
  fetch "https://github.com/peak/s5cmd/releases/download/v$S5CMD_VERSION/$t" "$SSHA" "$TMP/$t"
  tar -xzf "$TMP/$t" -C "$TMP" s5cmd
  install -m 755 "$TMP/s5cmd" "$BIN/s5cmd"
fi
