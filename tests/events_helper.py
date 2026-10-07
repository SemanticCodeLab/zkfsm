#!/usr/bin/env python3
"""Test helpers for tests/events.sh (stdlib only).

  recv PORT OUTFILE        HTTP receiver: appends each POST body as one line to OUTFILE
                           (path /audit* bodies go to OUTFILE.audit); answers 503
                           while OUTFILE.fail exists.
  nats-sub ADDR SUBJECT OUT  NATS subscriber appending each message payload as a line.
  count FILE PATTERN       lines of FILE containing PATTERN.
  keys FILE EVENT          object keys of records named EVENT in FILE (one per line).
"""
import json
import os
import socket
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def recv(port, out):
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("content-length", "0"))
            body = self.rfile.read(n)
            if os.path.exists(out + ".fail"):
                self.send_response(503)
                self.end_headers()
                return
            path = out + ".audit" if self.path.startswith("/audit") else out
            with open(path, "ab") as f:
                f.write(body.replace(b"\n", b" ") + b"\n")
            with open(out + ".auth", "a") as f:
                f.write((self.headers.get("authorization") or "") + "\n")
            self.send_response(200)
            self.send_header("content-length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    ThreadingHTTPServer(("127.0.0.1", int(port)), H).serve_forever()


def nats_sub(addr, subject, out):
    host, port = addr.rsplit(":", 1)
    s = socket.create_connection((host, int(port)))
    f = s.makefile("rb")
    f.readline()  # INFO
    s.sendall(b'CONNECT {"verbose":false}\r\nSUB ' + subject.encode() + b" 1\r\nPING\r\n")
    while True:
        line = f.readline()
        if not line:
            return
        if line.startswith(b"PING"):
            s.sendall(b"PONG\r\n")
        elif line.startswith(b"MSG"):
            n = int(line.split()[-1])
            data = f.read(n + 2)[:n]
            with open(out, "ab") as o:
                o.write(data.replace(b"\n", b" ") + b"\n")


def keys(path, event):
    if not os.path.exists(path):
        return
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        for r in d.get("Records") or []:
            if r.get("eventName") == event:
                print(urllib.parse.unquote_plus(r["s3"]["object"]["key"]))


def count(path, pattern):
    if not os.path.exists(path):
        print(0)
        return
    print(sum(1 for line in open(path, encoding="utf-8", errors="replace") if pattern in line))


if __name__ == "__main__":
    cmd, args = sys.argv[1], sys.argv[2:]
    {"recv": recv, "nats-sub": nats_sub, "keys": keys, "count": count}[cmd](*args)
