#!/usr/bin/env bash
# Enforces: imports only point down the layer stack.
# A module may import a module of strictly lower rank; main.zig may import anything.
set -euo pipefail
cd "$(dirname "$0")/../src"

rank() {
  case "$1" in
    core) echo 0 ;;
    io | device | metadata | tls | kms | select) echo 1 ;;
    backend) echo 2 ;;
    placement) echo 3 ;;
    protection) echo 4 ;;
    heal | object) echo 5 ;;
    metrics | iam) echo 6 ;;
    s3 | admin | gateway) echo 7 ;;
    cluster | replication | events | sse) echo 8 ;;
    lambda) echo 9 ;;
    *) echo -1 ;;
  esac
}

# Protocol adapters talk to ObjectService, never to storage.
forbidden() {
  case "$1:$2" in
    s3:backend | s3:placement | s3:metadata | s3:device) return 0 ;;
    admin:backend | admin:device) return 0 ;;
    gateway:backend | gateway:placement | gateway:metadata | gateway:device | gateway:protection) return 0 ;;
    *) return 1 ;;
  esac
}

fail=0
while IFS= read -r file; do
  from="${file%%/*}"
  from_rank=$(rank "$from")
  if [[ "$from_rank" -lt 0 ]]; then
    echo "unknown module: $from ($file)"; fail=1; continue
  fi
  while IFS= read -r target; do
    [[ "$target" == ../* ]] || continue
    to="${target#../}"; to="${to%%/*}"
    to_rank=$(rank "$to")
    if [[ "$to_rank" -lt 0 || "$to_rank" -ge "$from_rank" ]] || forbidden "$from" "$to"; then
      echo "layer violation: $file imports $target ($from:$from_rank -> $to:$to_rank)"
      fail=1
    fi
  done < <(grep -o '@import("[^"]*")' "$file" | sed 's/@import("\(.*\)")/\1/')
done < <(find . -mindepth 2 -name '*.zig' | sed 's|^\./||' | sort)

if [[ $fail -ne 0 ]]; then echo "check_layers: FAIL"; exit 1; fi
echo "check_layers: OK"
