#!/usr/bin/env python3
"""Minimal Keystone v3 mock for tests/swift.sh.

POST /v3/auth/tokens issues tokens for password auth, GET /v3/auth/tokens validates
them (X-Auth-Token must be a service token, X-Subject-Token the token to check).
GET /stats reports how many validations were served.

usage: swift_keystone_mock.py PORT SWIFT_URL
"""
import datetime
import json
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1])
SWIFT = sys.argv[2].rstrip("/")
BASE = f"http://127.0.0.1:{PORT}"

# name -> (password, project id, project name)
USERS = {
    "svc": ("svcpass", "5e7f0000000000000000000000000001", "service"),
    "alice": ("alicepass", "aaaa1111", "alpha"),
    "bob": ("bobpass", "bbbb2222", "beta"),
    "carol": ("carolpass", "cccc3333", "gamma"),
}
TOKENS = {}
LOCK = threading.Lock()
STATS = {"validations": 0, "issued": 0}
DOMAIN = {"id": "default", "name": "Default"}


def token_body(user, with_catalog):
    _, pid, pname = USERS[user]
    now = datetime.datetime.now(datetime.timezone.utc)
    exp = now + datetime.timedelta(hours=1)
    fmt = "%Y-%m-%dT%H:%M:%S.000000Z"
    tok = {
        "methods": ["password"],
        "user": {"id": "u-" + user, "name": user, "domain": DOMAIN},
        "project": {"id": pid, "name": pname, "domain": DOMAIN},
        "roles": [{"id": "r-member", "name": "member"}],
        "issued_at": now.strftime(fmt),
        "expires_at": exp.strftime(fmt),
        "audit_ids": [uuid.uuid4().hex[:22]],
    }
    if with_catalog:
        url = f"{SWIFT}/v1/AUTH_{pid}"
        tok["catalog"] = [{
            "type": "object-store", "name": "swift", "id": "svc-swift",
            "endpoints": [{"id": "ep-" + i, "interface": i, "region": "RegionOne",
                           "region_id": "RegionOne", "url": url}
                          for i in ("public", "internal", "admin")],
        }, {
            "type": "identity", "name": "keystone", "id": "svc-ks",
            "endpoints": [{"id": "ep-ks-" + i, "interface": i, "region": "RegionOne",
                           "region_id": "RegionOne", "url": BASE + "/v3"}
                          for i in ("public", "internal", "admin")],
        }]
    return {"token": tok}


VERSION = {"id": "v3.14", "status": "stable", "updated": "2020-04-07T00:00:00Z",
           "links": [{"rel": "self", "href": BASE + "/v3/"}],
           "media-types": [{"base": "application/json",
                            "type": "application/vnd.openstack.identity-v3+json"}]}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def send(self, code, body=None, headers=()):
        data = json.dumps(body).encode() if body is not None else b""
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/")
        if path == "":
            return self.send(300, {"versions": {"values": [VERSION]}})
        if path == "/v3":
            return self.send(200, {"version": VERSION})
        if path == "/stats":
            return self.send(200, STATS)
        if path == "/v3/auth/tokens":
            with LOCK:
                STATS["validations"] += 1
                svc = TOKENS.get(self.headers.get("X-Auth-Token", ""))
                user = TOKENS.get(self.headers.get("X-Subject-Token", ""))
            if svc != "svc":
                return self.send(401, {"error": {"code": 401, "message": "service token required"}})
            if user is None:
                return self.send(404, {"error": {"code": 404, "message": "token not found"}})
            return self.send(200, token_body(user, "nocatalog" not in self.path))
        self.send(404, {"error": {"code": 404}})

    def do_POST(self):
        path = self.path.split("?")[0].rstrip("/")
        n = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(n)
        if path != "/v3/auth/tokens":
            return self.send(404, {"error": {"code": 404}})
        try:
            req = json.loads(raw)
            u = req["auth"]["identity"]["password"]["user"]
            name, pw = u["name"], u["password"]
        except (ValueError, KeyError, TypeError):
            return self.send(400, {"error": {"code": 400}})
        if name not in USERS or USERS[name][0] != pw:
            return self.send(401, {"error": {"code": 401, "message": "bad credentials"}})
        tok = "gAAAA" + uuid.uuid4().hex + uuid.uuid4().hex
        with LOCK:
            TOKENS[tok] = name
            STATS["issued"] += 1
        self.send(201, token_body(name, "nocatalog" not in self.path), [("X-Subject-Token", tok)])


ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
