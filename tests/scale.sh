#!/usr/bin/env bash
# Scale test: key index consistency across kill -9 and snapshot loss (single, replica,
# EC), listing vs. brute force on random keys, connection limits, slowloris cutoff,
# and SIGTERM draining a slow download.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/zig-out/bin/zkfsm"
LOAD="$ROOT/zig-out/bin/s3load"
WORK="$(mktemp -d)"
PID=""
cleanup() { [[ -n "$PID" ]] && kill -9 "$PID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

pass=0
fail=0
check() { # name expected actual
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); echo "ok   $1"
  else fail=$((fail + 1)); echo "FAIL $1: expected [$2] got [$3]"; fi
}

(cd "$ROOT" && zig build && zig build s3load)
PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')"
EP="http://127.0.0.1:$PORT"
DATA=""
EXTRA=()

start() { # the log holds only the latest run
  [[ -f "$WORK/server.log" ]] && cat "$WORK/server.log" >>"$WORK/all.log"
  : >"$WORK/server.log"
  "$BIN" --anonymous --scan-interval 0 --data "${DATA_ARGS[@]}" --listen "127.0.0.1:$PORT" "${EXTRA[@]}" 2>>"$WORK/server.log" &
  PID=$!
  for _ in $(seq 100); do curl -s -o /dev/null "$EP/" && return 0; sleep 0.1; done
  echo "server did not start:"; tail -20 "$WORK/server.log"; exit 1
}
stop_term() { kill -TERM "$PID"; RC=0; wait "$PID" || RC=$?; PID=""; }
stop_kill() { kill -9 "$PID"; wait "$PID" 2>/dev/null || true; PID=""; }

# Python helpers: full paged listing, brute-force comparison, HEAD truth.
cat >"$WORK/s3.py" <<'EOF'
import http.client, random, sys, urllib.parse, xml.etree.ElementTree as ET
NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
host, port = "127.0.0.1", int(sys.argv[1])

def req(method, path, body=None):
    c = http.client.HTTPConnection(host, port, timeout=30)
    c.request(method, path, body=body)
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, data

def q(s):
    return urllib.parse.quote(s, safe="")

def list_page(bucket, prefix="", delimiter="", max_keys=1000, token=None, start_after=""):
    qs = "list-type=2&max-keys=%d&prefix=%s&delimiter=%s" % (max_keys, q(prefix), q(delimiter))
    if token: qs += "&continuation-token=" + q(token)
    if start_after: qs += "&start-after=" + q(start_after)
    st, data = req("GET", "/%s?%s" % (bucket, qs))
    assert st == 200, (st, data)
    root = ET.fromstring(data)
    keys = [e.find(NS + "Key").text for e in root.findall(NS + "Contents")]
    cps = [e.find(NS + "Prefix").text for e in root.findall(NS + "CommonPrefixes")]
    trunc = root.find(NS + "IsTruncated").text == "true"
    nxt = root.find(NS + "NextContinuationToken")
    return keys, cps, trunc, nxt.text if nxt is not None else None

def list_all(bucket, prefix="", delimiter="", max_keys=1000):
    keys, cps, token = [], [], None
    while True:
        k, c, trunc, token = list_page(bucket, prefix, delimiter, max_keys, token)
        keys += k; cps += c
        if not trunc: return keys, cps
        assert token, "truncated without token"

def brute(keys, prefix, delimiter):
    out, cps = [], []
    for k in sorted(set(keys), key=lambda s: s.encode()):
        if not k.startswith(prefix): continue
        rest = k[len(prefix):]
        if delimiter and delimiter in rest:
            cp = prefix + rest[:rest.index(delimiter) + len(delimiter)]
            if not cps or cps[-1] != cp: cps.append(cp)
        else:
            out.append(k)
    return out, cps

cmd = sys.argv[2]
if cmd == "listed":  # every key in the bucket, one per line
    for k in list_all(sys.argv[3])[0]: print(k)
elif cmd == "present":  # which of k00000000..N answer HEAD 200
    bucket, n = sys.argv[3], int(sys.argv[4])
    c = http.client.HTTPConnection(host, port, timeout=30)
    for i in range(n):
        c.request("HEAD", "/%s/k%08d" % (bucket, i)); r = c.getresponse(); r.read()
        if r.status == 200: print("k%08d" % i)
elif cmd == "random":  # random keys, deletes, delimiters: index listing vs brute force
    bucket = sys.argv[3]
    rnd = random.Random(int(sys.argv[4]))
    alphabet = ["a", "b", "/", "c", "-", "é", "~", "z"]
    live = set()
    for _ in range(400):
        k = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(1, 8)))
        assert req("PUT", "/%s/%s" % (bucket, q(k)), b"x")[0] == 200
        live.add(k)
    for k in rnd.sample(sorted(live), 80):
        assert req("DELETE", "/%s/%s" % (bucket, q(k)))[0] == 204
        live.discard(k)
    bad = 0
    for prefix in ["", "a", "b/", "/", "é", "a/b"]:
        for d in ["", "/", "b", "-/"]:
            for mk in [1, 7, 1000]:
                got = list_all(bucket, prefix, d, mk)
                want = brute(live, prefix, d)
                if got != want:
                    bad += 1
                    print("mismatch prefix=%r delim=%r max=%d" % (prefix, d, mk), file=sys.stderr)
    print(bad)
EOF
py() { python3 "$WORK/s3.py" "$PORT" "$@"; }

# ---- key index: crash consistency and rebuild, per protection profile ----
for prof in single replica:2 EC:4+2; do
  case "$prof" in
    single) DATA_ARGS=("$WORK/$prof/d1") ;;
    replica:2) DATA_ARGS=("$WORK/$prof/d{1...2}" --protection "$prof") ;;
    EC:4+2) DATA_ARGS=("$WORK/ec/d{1...6}" --protection "$prof") ;;
  esac
  EXTRA=()
  start
  curl -sf -X PUT "$EP/idx" >/dev/null
  "$LOAD" put 127.0.0.1 "$PORT" idx 16 500 64 >/dev/null
  stop_term
  check "$prof: clean stop exits 0" 0 "$RC"
  start
  check "$prof: snapshot loaded after clean stop" 500 "$(py listed idx | wc -l)"
  check "$prof: no rebuild after clean stop" 0 "$(grep -c 'rebuilt from records' "$WORK/server.log" || true)"
  # Writes race kill -9: the listing must match exactly what HEAD can see.
  "$LOAD" put 127.0.0.1 "$PORT" idx 16 20000 64 >/dev/null 2>&1 &
  LPID=$!
  sleep 0.7
  stop_kill
  wait "$LPID" 2>/dev/null || true
  start
  py listed idx >"$WORK/listed"
  py present idx 20000 >"$WORK/present"
  check "$prof: rebuilt after kill -9" 1 "$(grep -c 'rebuilt from records' "$WORK/server.log" || true)"
  check "$prof: listing == HEAD-visible after kill -9" "$(md5sum <"$WORK/present")" "$(md5sum <"$WORK/listed")"
  check "$prof: some writes landed" 1 "$([[ $(wc -l <"$WORK/listed") -gt 500 ]] && echo 1 || echo 0)"
  stop_term
  # Snapshot deleted while the state says clean: rebuilt, same listing.
  find "$WORK" -path '*/system/*' -type f -exec python3 -c '
import sys
for f in sys.argv[1:]:
    with open(f, "rb") as fh:
        if fh.read(4) in (b"ZKIC", b"ZKIS"):
            import os; os.remove(f)' {} +
  start
  check "$prof: rebuilt after snapshot deleted" 1 "$(grep -c 'rebuilt from records' "$WORK/server.log" || true)"
  check "$prof: same listing after rebuild" "$(md5sum <"$WORK/listed")" "$(py listed idx | md5sum)"
  stop_term
done

# ---- listing vs brute force ----
DATA_ARGS=("$WORK/single2")
EXTRA=()
start
curl -sf -X PUT "$EP/rnd" >/dev/null
check "random keys: index listing == brute force" 0 "$(py random rnd 7)"
stop_term
start
curl -sf -X PUT "$EP/rnd2" >/dev/null
check "random keys: equal on a restarted server" 0 "$(py random rnd2 11)"
stop_term

# ---- connection handling ----
EXTRA=(--header-timeout 2 --idle-timeout 3 --max-conns 4 --workers 2 --shutdown-timeout 20)
start
cat >"$WORK/conn.py" <<'EOF'
import socket, sys, time
port, mode = int(sys.argv[1]), sys.argv[2]
def closed_after(s, feed):
    t0 = time.time()
    s.settimeout(1)
    while time.time() - t0 < 15:
        if feed:
            try: s.send(b"x-slow: 1\r\n")
            except OSError: return time.time() - t0
        try:
            if s.recv(4096) == b"": return time.time() - t0
        except socket.timeout: pass
        except OSError: return time.time() - t0
    return None
if mode == "slowloris":
    s = socket.create_connection(("127.0.0.1", port))
    s.send(b"GET / HTTP/1.1\r\nHost: x\r\n")
    t = closed_after(s, True)
    print("cut" if t is not None and t < 5 else "alive %r" % t)
elif mode == "idle":
    s = socket.create_connection(("127.0.0.1", port))
    t = closed_after(s, False)
    print("cut" if t is not None and 2 < t < 6 else "bad %r" % t)
elif mode == "limit":
    held = [socket.create_connection(("127.0.0.1", port)) for _ in range(4)]
    time.sleep(0.3)
    s = socket.create_connection(("127.0.0.1", port))
    s.settimeout(3)
    print(s.recv(64).split(b"\r\n")[0].decode())
EOF
check "slowloris client disconnected by header deadline" cut "$(python3 "$WORK/conn.py" "$PORT" slowloris)"
check "idle connection closed after idle timeout" cut "$(python3 "$WORK/conn.py" "$PORT" idle)"
check "over max-conns refused with 503" "HTTP/1.1 503 Service Unavailable" "$(python3 "$WORK/conn.py" "$PORT" limit)"
check "serves after limit test" 200 "$(sleep 4; curl -s -o /dev/null -w '%{http_code}' "$EP/")"

# ---- SIGTERM drains a slow download ----
head -c 12000000 /dev/urandom >"$WORK/big"
curl -sf -X PUT "$EP/drain" >/dev/null
curl -sf -T "$WORK/big" "$EP/drain/big" >/dev/null
curl -s --limit-rate 3M -o "$WORK/got" "$EP/drain/big" &
CPID=$!
sleep 1
kill -TERM "$PID"
sleep 0.5
check "no new connections while draining" 000 "$(curl -s -m 2 -o /dev/null -w '%{http_code}' "$EP/" || true)"
crc=0; wait "$CPID" || crc=$?
src=0; wait "$PID" || src=$?
PID=""
check "slow download completes during drain" 0 "$crc"
check "drained download intact" "$(md5sum <"$WORK/big")" "$(md5sum <"$WORK/got")"
check "server exits 0 after drain" 0 "$src"

echo "scale: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
