#!/usr/bin/env python3
"""Credential and object-store mocks for remote-tier tests.

  POST /gcs/token                     JWT bearer grant; verifies the RS256 assertion
  POST /az/<tenant>/oauth2/v2.0/token client-credentials grant; issues a JWT that
                                      Azurite (--oauth basic) accepts
  PUT  /latest/api/token              instance-metadata session token
  GET  /latest/meta-data/iam/security-credentials/[role]
  GET  /creds                         container-style credentials (Authorization checked)
  *    /store/<bucket>/<key>          in-memory S3/GCS XML object store; accepts SigV4
                                      (unverified) or a Bearer token issued above
  GET  /stats                         counters and storage classes seen, as JSON
  POST /delay?s=N                     slow down object GETs

Usage: tier_oauth_mock.py WORKDIR [--ttl SECONDS] [--keys AK:SK]
Writes WORKDIR/sa.json (service-account key file) and prints the port.
"""
import base64
import hashlib
import http.server
import json
import os
import subprocess
import sys
import threading
import time
import urllib.parse
import xml.sax.saxutils as sx

WORK = sys.argv[1]
ARGS = sys.argv[2:]
TTL = int(ARGS[ARGS.index("--ttl") + 1]) if "--ttl" in ARGS else 3600
KEYS = (ARGS[ARGS.index("--keys") + 1] if "--keys" in ARGS else "ak:sk").split(":", 1)
EMAIL = "tier@zkfsm-test.iam.gserviceaccount.com"
AZ_CLIENT, AZ_SECRET = "zkfsm-client", "zkfsm-client-secret"
LOCK = threading.Lock()
STATS = {"gcs_tokens": 0, "az_tokens": 0, "imds": 0, "creds_uri": 0, "bearer_requests": 0,
         "sigv4_requests": 0, "rejected": 0, "storage_classes": []}
TOKENS = {}  # bearer token -> expiry
OBJECTS = {}  # (bucket, key) -> (bytes, mtime)
UPLOADS = {}  # upload id -> {part: bytes}
IMDS_TOKEN = "imds-session-token"
DELAY = [0.0]  # seconds added to object GETs (POST /delay?s=N)
CREDS_AUTH = "creds-uri-secret"


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def setup_key():
    key = os.path.join(WORK, "sa-key.pem")
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", key],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", key, "-pubout", "-out", os.path.join(WORK, "sa-pub.pem")],
                   check=True, capture_output=True)
    return open(key).read()


def verify_rs256(signing_input, sig):
    sp = os.path.join(WORK, "sig-%d.bin" % threading.get_ident())
    with open(sp, "wb") as f:
        f.write(sig)
    r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", os.path.join(WORK, "sa-pub.pem"), "-signature", sp],
                       input=signing_input, capture_output=True)
    os.unlink(sp)
    return r.returncode == 0


def issue(prefix):
    tok = "%s-%s" % (prefix, os.urandom(12).hex())
    with LOCK:
        TOKENS[tok] = time.time() + TTL
    return tok


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def reply(self, code, body=b"", ctype="application/xml", headers=()):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def count(self, k):
        with LOCK:
            STATS[k] += 1

    # ---- token endpoints ----
    def gcs_token(self):
        f = urllib.parse.parse_qs(self.body().decode())
        if f.get("grant_type") != ["urn:ietf:params:oauth:grant-type:jwt-bearer"]:
            return self.reply(400, '{"error":"unsupported_grant_type"}', "application/json")
        parts = f.get("assertion", [""])[0].split(".")
        if len(parts) != 3:
            return self.reply(400, '{"error":"invalid_grant"}', "application/json")
        hdr, claims = json.loads(unb64u(parts[0])), json.loads(unb64u(parts[1]))
        ok = (hdr.get("alg") == "RS256" and claims.get("iss") == EMAIL
              and claims.get("aud", "").endswith("/gcs/token") and "devstorage" in claims.get("scope", "")
              and claims.get("exp", 0) > time.time() and verify_rs256((parts[0] + "." + parts[1]).encode(), unb64u(parts[2])))
        if not ok:
            self.count("rejected")
            return self.reply(400, '{"error":"invalid_grant"}', "application/json")
        self.count("gcs_tokens")
        self.reply(200, json.dumps({"access_token": issue("gcs"), "expires_in": TTL, "token_type": "Bearer"}), "application/json")

    def az_token(self, tenant):
        f = urllib.parse.parse_qs(self.body().decode())
        if (f.get("grant_type") != ["client_credentials"] or f.get("client_id") != [AZ_CLIENT]
                or f.get("client_secret") != [AZ_SECRET] or f.get("scope") != ["https://storage.azure.com/.default"]):
            self.count("rejected")
            return self.reply(401, '{"error":"invalid_client"}', "application/json")
        now = int(time.time())
        claims = {"aud": "https://storage.azure.com", "iss": "https://sts.windows.net/%s/" % tenant, "iat": now - 5,
                  "nbf": now - 5, "exp": now + TTL, "tid": tenant, "oid": "00000000-0000-0000-0000-000000000001",
                  "appid": AZ_CLIENT}
        jwt = b64u(b'{"alg":"RS256","typ":"JWT"}') + "." + b64u(json.dumps(claims).encode()) + "." + b64u(b"sig")
        with LOCK:
            TOKENS[jwt] = time.time() + TTL
        self.count("az_tokens")
        self.reply(200, json.dumps({"access_token": jwt, "expires_in": TTL, "token_type": "Bearer"}), "application/json")

    def creds_doc(self):
        exp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + max(TTL, 60)))
        return json.dumps({"Code": "Success", "AccessKeyId": KEYS[0], "SecretAccessKey": KEYS[1], "Token": "", "Expiration": exp})

    # ---- object store ----
    def authorized(self):
        a = self.headers.get("Authorization", "")
        if a.startswith("AWS4-HMAC-SHA256 "):
            self.count("sigv4_requests")
            return True
        if a.startswith("Bearer "):
            with LOCK:
                exp = TOKENS.get(a[7:])
            if exp and exp > time.time():
                self.count("bearer_requests")
                return True
        self.count("rejected")
        return False

    def store(self, u):
        if not self.authorized():
            return self.reply(401, "<Error><Code>AccessDenied</Code></Error>")
        path = urllib.parse.unquote(u.path[len("/store/"):])
        bucket, _, key = path.partition("/")
        q = urllib.parse.parse_qs(u.query, keep_blank_values=True)
        m = self.command
        if not key:
            if m == "GET":
                prefix = q.get("prefix", [""])[0]
                with LOCK:
                    keys = sorted(k for (b, k) in OBJECTS if b == bucket and k.startswith(prefix))
                items = "".join("<Contents><Key>%s</Key></Contents>" % sx.escape(k) for k in keys)
                return self.reply(200, "<ListBucketResult><Name>%s</Name>%s<IsTruncated>false</IsTruncated></ListBucketResult>" % (bucket, items))
            return self.reply(200 if m in ("PUT", "HEAD") else 405)
        sc = self.headers.get("x-amz-storage-class") or self.headers.get("x-goog-storage-class")
        if m == "PUT" and "partNumber" in q:
            data = self.body()
            with LOCK:
                UPLOADS.setdefault(q["uploadId"][0], {})[int(q["partNumber"][0])] = data
            return self.reply(200, headers=[("ETag", '"%s"' % hashlib.md5(data).hexdigest())])
        if m == "POST" and "uploads" in q:
            uid = os.urandom(8).hex()
            with LOCK:
                UPLOADS[uid] = {}
                if sc:
                    STATS["storage_classes"].append(sc)
            return self.reply(200, "<InitiateMultipartUploadResult><UploadId>%s</UploadId></InitiateMultipartUploadResult>" % uid)
        if m == "POST" and "uploadId" in q:
            self.body()
            with LOCK:
                parts = UPLOADS.pop(q["uploadId"][0], {})
                OBJECTS[(bucket, key)] = (b"".join(parts[i] for i in sorted(parts)), time.time())
            return self.reply(200, "<CompleteMultipartUploadResult><ETag>\"x\"</ETag></CompleteMultipartUploadResult>")
        if m == "DELETE" and "uploadId" in q:
            with LOCK:
                UPLOADS.pop(q["uploadId"][0], None)
            return self.reply(204)
        if m == "PUT":
            data = self.body()
            with LOCK:
                OBJECTS[(bucket, key)] = (data, time.time())
                if sc:
                    STATS["storage_classes"].append(sc)
            return self.reply(200, headers=[("ETag", '"%s"' % hashlib.md5(data).hexdigest())])
        with LOCK:
            obj = OBJECTS.get((bucket, key))
        if m == "DELETE":
            with LOCK:
                OBJECTS.pop((bucket, key), None)
            return self.reply(204)
        if obj is None:
            return self.reply(404, "<Error><Code>NoSuchKey</Code></Error>")
        data, mt = obj
        if m == "GET" and DELAY[0] > 0:
            time.sleep(DELAY[0])
        hs = [("ETag", '"%s"' % hashlib.md5(data).hexdigest()),
              ("Last-Modified", time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(mt)))]
        rng = self.headers.get("Range")
        if rng and m == "GET":
            a, _, b = rng[len("bytes="):].partition("-")
            a = int(a)
            b = int(b) if b else len(data) - 1
            return self.reply(206, data[a:b + 1], "application/octet-stream", hs + [("Content-Range", "bytes %d-%d/%d" % (a, b, len(data)))])
        if m == "HEAD":
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            for k, v in hs:
                self.send_header(k, v)
            self.end_headers()
            return
        return self.reply(200, data, "application/octet-stream", hs)

    def route(self):
        u = urllib.parse.urlparse(self.path)
        p = u.path
        if p.startswith("/store/"):
            return self.store(u)
        if p == "/delay" and self.command == "POST":
            DELAY[0] = float(urllib.parse.parse_qs(u.query).get("s", ["0"])[0])
            return self.reply(200)
        if p == "/stats":
            with LOCK:
                return self.reply(200, json.dumps(STATS), "application/json")
        if p == "/gcs/token" and self.command == "POST":
            return self.gcs_token()
        if p.startswith("/az/") and p.endswith("/oauth2/v2.0/token") and self.command == "POST":
            return self.az_token(p.split("/")[2])
        if p == "/az-token":  # test helper: a token for direct Azurite calls
            return self.reply(200, self.direct_az_token(), "text/plain")
        if p == "/latest/api/token" and self.command == "PUT":
            if not self.headers.get("x-aws-ec2-metadata-token-ttl-seconds"):
                return self.reply(400)
            return self.reply(200, IMDS_TOKEN, "text/plain")
        if p.startswith("/latest/meta-data/iam/security-credentials/"):
            if self.headers.get("x-aws-ec2-metadata-token") != IMDS_TOKEN:
                return self.reply(401)
            role = p[len("/latest/meta-data/iam/security-credentials/"):]
            if not role:
                return self.reply(200, "tier-role\n", "text/plain")
            self.count("imds")
            return self.reply(200, self.creds_doc(), "application/json") if role == "tier-role" else self.reply(404)
        if p == "/creds":
            if self.headers.get("Authorization") != CREDS_AUTH:
                return self.reply(403)
            self.count("creds_uri")
            return self.reply(200, self.creds_doc(), "application/json")
        self.reply(404)

    def direct_az_token(self):
        now = int(time.time())
        claims = {"aud": "https://storage.azure.com", "iss": "https://sts.windows.net/test-tenant/", "iat": now - 5,
                  "nbf": now - 5, "exp": now + 3600, "oid": "00000000-0000-0000-0000-000000000002"}
        return b64u(b'{"alg":"RS256","typ":"JWT"}') + "." + b64u(json.dumps(claims).encode()) + "." + b64u(b"sig")

    do_GET = do_PUT = do_POST = do_DELETE = do_HEAD = route


def main():
    pem = setup_key()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    with open(os.path.join(WORK, "sa.json"), "w") as f:
        json.dump({"type": "service_account", "project_id": "zkfsm-test", "private_key_id": "k1", "private_key": pem,
                   "client_email": EMAIL, "client_id": "1", "token_uri": "http://127.0.0.1:%d/gcs/token" % port}, f)
    print(port, flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
