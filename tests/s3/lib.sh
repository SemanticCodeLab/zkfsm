# Shared helpers for the shell client suites; sourced by run.sh.
# Each suite runs with EP, AK, SK, WORK, RESULTS, SUITE set, and records one line per check.

record() { # status name [detail]
  printf '%s\t%s::%s\n' "$1" "$SUITE" "$2" >>"$RESULTS"
  printf '%-5s %s::%s%s\n' "$1" "$SUITE" "$2" "${3:+  ($3)}"
}

check() { # name expected actual
  if [[ "$2" == "$3" ]]; then record PASS "$1"; else record FAIL "$1" "expected [$2] got [$3]"; fi
}

xcheck() { # reason name expected actual: known gap, passing is reported as XPASS
  if [[ "$3" == "$4" ]]; then record XPASS "$2"; else record XFAIL "$2" "$1"; fi
}

ok() { # name command...: passes when the command exits 0
  local n="$1"; shift
  if "$@" >>"$LOG" 2>&1; then record PASS "$n"; else record FAIL "$n" "exit $? (see log)"; fi
}

rand_bucket() { echo "$1-$(od -An -N4 -tx4 /dev/urandom | tr -d ' ')"; }
md5() { md5sum "$1" | cut -d' ' -f1; }
