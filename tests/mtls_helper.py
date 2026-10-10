#!/usr/bin/env python3
"""Test helpers for tests/mtls.sh (stdlib only).

  https-recv PORT OUT CERT KEY CA [tls1.2]  HTTPS receiver demanding a client
      certificate signed by CA; appends "PATH CN VERSION BODY" per POST to OUT and
      each refused handshake to OUT.refused. "tls1.2" caps the protocol at 1.2.
  nats-sub ADDR SUBJECT OUT CA CERT KEY  NATS subscriber over mutual TLS.
  json-get FILE PATH...  prints a value from JSON on stdin (keys or indexes).
"""
import json
import socket
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def https_recv(port, out, cert, key, ca, cap=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.load_verify_locations(ca)
    ctx.verify_mode = ssl.CERT_REQUIRED
    if cap == "tls1.2":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("content-length", "0"))
            body = self.rfile.read(n)
            peer = self.connection.getpeercert() or {}
            cn = ""
            for rdn in peer.get("subject", ()):
                for k, v in rdn:
                    if k == "commonName":
                        cn = v
            with open(out, "ab") as f:
                f.write(self.path.encode() + b" " + cn.encode() + b" " + self.connection.version().encode() + b" " + body.replace(b"\n", b" ") + b"\n")
            self.send_response(200)
            self.send_header("content-length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    class S(ThreadingHTTPServer):
        def get_request(self):
            sock, addr = self.socket.accept()
            try:
                return ctx.wrap_socket(sock, server_side=True), addr
            except (ssl.SSLError, OSError) as e:
                with open(out + ".refused", "a") as f:
                    f.write(str(e) + "\n")
                sock.close()
                raise OSError("handshake refused")

        def handle_error(self, request, client_address):
            pass

    S(("127.0.0.1", int(port)), H).serve_forever()


def nats_sub(addr, subject, out, ca, cert, key):
    host, port = addr.rsplit(":", 1)
    raw = socket.create_connection((host, int(port)))
    f = raw.makefile("rb")
    f.readline()  # INFO, then the TLS upgrade
    ctx = ssl.create_default_context(cafile=ca)
    ctx.load_cert_chain(cert, key)
    s = ctx.wrap_socket(raw, server_hostname="localhost")
    f = s.makefile("rb")
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


def json_get(path):
    v = json.load(sys.stdin)
    for p in path:
        if isinstance(v, list):
            v = v[int(p)]
        else:
            v = v.get(p)
        if v is None:
            print("")
            return
    print(v)


if __name__ == "__main__":
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "https-recv":
        https_recv(*args)
    elif cmd == "nats-sub":
        nats_sub(*args)
    elif cmd == "json-get":
        json_get(args)
    else:
        sys.exit("unknown command " + cmd)
