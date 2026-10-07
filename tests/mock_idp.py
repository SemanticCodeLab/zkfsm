#!/usr/bin/env python3
"""Minimal OpenID Connect provider for tests: discovery, JWKS, and signed tokens.

Keys are generated with the openssl CLI (RS256 and ES256). Endpoints:
  GET  /.well-known/openid-configuration
  GET  /jwks                  current key set
  GET  /token?sub=..&...      a signed JWT; query params become claims
                              (alg=RS256|ES256, kid=..., ttl=seconds, policy/groups lists
                              comma-separated -> arrays when name ends with [])
  POST /rotate                replace the RSA key (new kid); old tokens stop validating
  GET  /stats                 fetch counters as JSON
Prints the listening port on stdout, then serves until killed.
"""
import base64
import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

WORK = tempfile.mkdtemp(prefix="mock-idp-")
LOCK = threading.Lock()
STATS = {"discovery": 0, "jwks": 0}


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def openssl(*args, data=None):
    return subprocess.run(["openssl", *args], input=data, capture_output=True, check=True).stdout


def new_rsa(kid):
    path = os.path.join(WORK, kid + ".pem")
    openssl("genrsa", "-out", path, "2048")
    mod = openssl("rsa", "-in", path, "-noout", "-modulus").decode().strip().split("=", 1)[1]
    n = bytes.fromhex(mod)
    return {"kid": kid, "alg": "RS256", "path": path,
            "jwk": {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": b64u(n), "e": "AQAB"}}


def new_ec(kid):
    path = os.path.join(WORK, kid + ".pem")
    openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", path)
    der = openssl("ec", "-in", path, "-pubout", "-outform", "DER")
    point = der[-65:]
    return {"kid": kid, "alg": "ES256", "path": path,
            "jwk": {"kty": "EC", "kid": kid, "use": "sig", "alg": "ES256", "crv": "P-256",
                    "x": b64u(point[1:33]), "y": b64u(point[33:])}}


def der_to_raw(sig):
    # ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
    i = 2 if sig[1] < 0x80 else 2 + (sig[1] & 0x7F)
    out = b""
    for _ in range(2):
        assert sig[i] == 0x02
        ln = sig[i + 1]
        v = sig[i + 2:i + 2 + ln].lstrip(b"\x00")
        out += v.rjust(32, b"\x00")
        i += 2 + ln
    return out


KEYS = {"rsa": new_rsa("rsa-1"), "ec": new_ec("ec-1")}
GEN = [1]


def sign(alg, kid, claims):
    key = KEYS["ec"] if alg == "ES256" else KEYS["rsa"]
    header = {"alg": alg, "typ": "JWT", "kid": kid or key["kid"]}
    signing_input = (b64u(json.dumps(header).encode()) + "." + b64u(json.dumps(claims).encode())).encode()
    sig = openssl("dgst", "-sha256", "-sign", key["path"], data=signing_input)
    if alg == "ES256":
        sig = der_to_raw(sig)
    return signing_input.decode() + "." + b64u(sig)


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def base(self):
        return "http://%s" % self.headers.get("Host")

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/.well-known/openid-configuration":
            STATS["discovery"] += 1
            b = self.base()
            return self.reply(200, json.dumps({
                "issuer": b, "jwks_uri": b + "/jwks", "authorization_endpoint": b + "/auth",
                "token_endpoint": b + "/token", "id_token_signing_alg_values_supported": ["RS256", "ES256"]}))
        if u.path == "/jwks":
            STATS["jwks"] += 1
            with LOCK:
                keys = [KEYS["rsa"]["jwk"], KEYS["ec"]["jwk"]]
            return self.reply(200, json.dumps({"keys": keys}))
        if u.path == "/stats":
            return self.reply(200, json.dumps(STATS))
        if u.path == "/token":
            q = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
            alg = q.pop("alg", "RS256")
            kid = q.pop("kid", None)
            ttl = int(q.pop("ttl", "3600"))
            now = int(time.time())
            claims = {"iss": q.pop("iss", self.base()), "aud": q.pop("aud", "zkfsm"), "iat": now, "exp": now + ttl}
            if "nbf" in q:
                claims["nbf"] = now + int(q.pop("nbf"))
            for k, v in q.items():
                if k.endswith("[]"):
                    claims[k[:-2]] = [x for x in v.split(",") if x]
                else:
                    claims[k] = v
            with LOCK:
                tok = sign(alg, kid, claims)
            return self.reply(200, tok, "text/plain")
        self.reply(404, "{}")

    def do_POST(self):
        if self.path == "/rotate":
            with LOCK:
                GEN[0] += 1
                KEYS["rsa"] = new_rsa("rsa-%d" % GEN[0])
            return self.reply(200, json.dumps({"kid": KEYS["rsa"]["kid"]}))
        self.reply(404, "{}")


def main():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 0), Handler)
    print(srv.server_address[1], flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
