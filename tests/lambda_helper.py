#!/usr/bin/env python3
"""Object Lambda test webhook: `lambda_helper.py PORT LOGDIR`.

Paths pick the behavior: /upper and /rot13 fetch inputS3Url (forwarding the
caller's Range) and transform it; /deny answers with x-amz-fwd-status 403;
/fail answers 500; /chunked streams the uppercase body in chunks.
Each event body is saved as LOGDIR/last.json; Authorization as LOGDIR/auth.
"""
import codecs
import json
import os
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1])
LOG = sys.argv[2]


def fetch(evt):
    url = evt["getObjectContext"]["inputS3Url"]
    hdrs = {}
    rng = evt["userRequest"]["headers"].get("Range")
    if rng:
        hdrs["Range"] = rng[0]
    req = urllib.request.Request(url, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read(), r.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        return e.code, e.read(), ""


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def reply(self, status, body, headers):
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        if "Transfer-Encoding" not in headers:
            self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if isinstance(body, list):
            for part in body:
                self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
            self.wfile.write(b"0\r\n\r\n")
        else:
            self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(n)
        with open(os.path.join(LOG, "last.json"), "wb") as f:
            f.write(raw)
        with open(os.path.join(LOG, "auth"), "w") as f:
            f.write(self.headers.get("Authorization", ""))
        evt = json.loads(raw)
        ctx = evt["getObjectContext"]
        base = {"x-amz-request-route": ctx["outputRoute"], "x-amz-request-token": ctx["outputToken"]}
        path = self.path.split("?")[0]
        if path == "/deny":
            base.update({
                "x-amz-fwd-status": "403",
                "x-amz-fwd-error-code": "AccessDenied",
                "x-amz-fwd-error-message": "blocked by lambda",
                "x-amz-fwd-header-X-Lambda": "denied",
            })
            return self.reply(200, b"", base)
        if path == "/fail":
            return self.reply(500, b"boom", {})
        status, data, ctype = fetch(evt)
        if status not in (200, 206):
            base.update({"x-amz-fwd-status": str(status), "x-amz-fwd-error-code": "FetchFailed",
                         "x-amz-fwd-error-message": data.decode(errors="replace")[:200]})
            return self.reply(200, b"", base)
        if path == "/rot13":
            out = codecs.encode(data.decode(), "rot13").encode()
        else:
            out = data.upper()
        base["x-amz-fwd-status"] = str(status)
        base["x-amz-fwd-header-Content-Type"] = "text/plain"
        base["x-amz-fwd-header-X-Transformed"] = path.strip("/")
        if path == "/chunked":
            base["Transfer-Encoding"] = "chunked"
            return self.reply(200, [out[i:i + 7] for i in range(0, len(out), 7)], base)
        return self.reply(200, out, base)


ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
