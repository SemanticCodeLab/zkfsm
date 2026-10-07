"""WebDAV client interop: webdavclient3 when installed, plus raw http.client checks.

Usage: webdav_client.py URL ACCESS_KEY SECRET_KEY. Prints ok/FAIL lines and a
final "ok" when everything passed.
"""
import base64
import hashlib
import http.client
import os
import ssl
import sys
import tempfile
import urllib.parse
import xml.etree.ElementTree as ET

url, user, password = sys.argv[1:4]
u = urllib.parse.urlparse(url)
failures = 0


def check(name, want, got):
    global failures
    if want == got:
        print(f"ok   {name}")
    else:
        failures += 1
        print(f"FAIL {name}: expected [{want}] got [{got}]")


def conn():
    if u.scheme == "https":
        ctx = ssl._create_unverified_context()
        return http.client.HTTPSConnection(u.hostname, u.port, context=ctx, timeout=30)
    return http.client.HTTPConnection(u.hostname, u.port, timeout=30)


AUTH = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def req(c, method, path, body=None, headers=None):
    h = {"Authorization": AUTH}
    h.update(headers or {})
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    return r.status, r.getheaders(), r.read()


# ---- raw protocol over one keep-alive connection ----
c = conn()
check("http mkcol", 201, req(c, "MKCOL", "/pyb")[0])
check("http put", 201, req(c, "PUT", "/pyb/%C3%BC%20x.txt", b"unicode")[0])
st, _, body = req(c, "PROPFIND", "/pyb/", None, {"Depth": "1"})
check("http propfind 207", 207, st)
ns = {"D": "DAV:"}
tree = ET.fromstring(body)
hrefs = sorted(e.text for e in tree.findall(".//D:href", ns))
check("http propfind hrefs", ["/pyb/", "/pyb/%C3%BC%20x.txt"], hrefs)
names = sorted(e.text or "" for e in tree.findall(".//D:displayname", ns))
check("http displayname utf-8", ["pyb", "ü x.txt"], names)
st, _, body = req(c, "GET", "/pyb/%C3%BC%20x.txt")
check("http get", (200, b"unicode"), (st, body))
c.close()

# ---- webdavclient3 ----
try:
    from webdav3.client import Client
except ImportError:
    Client = None
    print("skip webdavclient3 (not installed)")

if Client is not None:
    client = Client({
        "webdav_hostname": url,
        "webdav_login": user,
        "webdav_password": password,
        "webdav_disable_check": False,
    })
    client.verify = False
    import urllib3

    urllib3.disable_warnings()
    tmp = tempfile.mkdtemp()
    src = os.path.join(tmp, "up.bin")
    data = os.urandom(300_000)
    with open(src, "wb") as f:
        f.write(data)
    client.mkdir("pyb/sub")
    check("wdc check dir", True, client.check("pyb/sub"))
    client.upload_sync(remote_path="pyb/sub/up.bin", local_path=src)
    check("wdc list", True, "up.bin" in client.list("pyb/sub"))
    info = client.info("pyb/sub/up.bin")
    check("wdc info size", "300000", info.get("size"))
    check("wdc is_dir", True, client.is_dir("pyb/sub"))
    dst = os.path.join(tmp, "down.bin")
    client.download_sync(remote_path="pyb/sub/up.bin", local_path=dst)
    with open(dst, "rb") as f:
        check("wdc download md5", hashlib.md5(data).hexdigest(), hashlib.md5(f.read()).hexdigest())
    client.copy(remote_path_from="pyb/sub/up.bin", remote_path_to="pyb/copy.bin")
    client.move(remote_path_from="pyb/copy.bin", remote_path_to="pyb/moved.bin")
    check("wdc moved", (True, False), (client.check("pyb/moved.bin"), client.check("pyb/copy.bin")))
    client.clean("pyb/sub")
    check("wdc clean", False, client.check("pyb/sub"))
    client.clean("pyb")
    check("wdc clean bucket", False, client.check("pyb"))

print("ok" if failures == 0 else f"{failures} failed")
sys.exit(1 if failures else 0)
