#!/usr/bin/env python3
"""ftplib checks against the zkfsm FTP gateway; prints ok/FAIL lines.

usage: ftp_client.py MODE HOST PORT USER PASSWORD WORKDIR [BIGFILE]
MODE: plain | explicit | implicit
"""
import ftplib
import hashlib
import io
import socket
import ssl
import sys

mode, host, port, user, password, work = sys.argv[1:7]
big = sys.argv[7] if len(sys.argv) > 7 else None
port = int(port)
passed = failed = 0


def check(name, expected, actual):
    global passed, failed
    if expected == actual:
        passed += 1
        print(f"ok   [{mode}] {name}")
    else:
        failed += 1
        print(f"FAIL [{mode}] {name}: expected [{expected}] got [{actual}]")


class ImplicitFTP_TLS(ftplib.FTP_TLS):
    """FTP_TLS that wraps the control socket before the greeting."""

    def connect(self, host="", port=0, timeout=-999, source_address=None):
        if host:
            self.host = host
        if port:
            self.port = port
        if timeout != -999:
            self.timeout = timeout
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.af = sock.family
        self.sock = self.context.wrap_socket(sock, server_hostname=self.host)
        self.file = self.sock.makefile("r", encoding=self.encoding)
        self.welcome = self.getresp()
        return self.welcome


def ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def client():
    if mode == "plain":
        f = ftplib.FTP()
        f.connect(host, port, timeout=30)
        return f
    if mode == "explicit":
        f = ftplib.FTP_TLS(context=ctx())
        f.connect(host, port, timeout=30)
        f.auth()
        return f
    f = ImplicitFTP_TLS(context=ctx())
    f.connect(host, port, timeout=30)
    return f


def err_code(fn):
    try:
        fn()
        return "none"
    except ftplib.all_errors as e:
        return str(e)[:3]


# bad password rejected
f = client()
check("bad password", "530", err_code(lambda: f.login(user, password + "x")))
f.close()

f = client()
check("login", "230", f.login(user, password)[:3])
if mode != "plain":
    f.prot_p()
check("syst", "215", f.sendcmd("SYST")[:3])
feat = f.sendcmd("FEAT")
check("feat mlst", True, "MLST" in feat)
check("feat auth tls", True, "AUTH TLS" in feat)
check("opts utf8", "200", f.sendcmd("OPTS UTF8 ON")[:3])
check("type i", "200", f.sendcmd("TYPE I")[:3])
check("noop", "200", f.sendcmd("NOOP")[:3])
check("port refused", "502", err_code(lambda: f.sendcmd("PORT 127,0,0,1,1,1")))

bucket = f"py{mode}"
check("mkd bucket", f"/{bucket}", f.mkd(bucket))
check("cwd bucket", "250", f.cwd(bucket)[:3])
check("pwd", f"/{bucket}", f.pwd())
check("mkd sub", f"/{bucket}/sub", f.mkd("sub"))

data = bytes(range(256)) * 400 + b"tail"
check("stor", "226", f.storbinary("STOR sub/a.bin", io.BytesIO(data))[:3])
check("size", len(data), f.size("sub/a.bin"))
mdtm = f.sendcmd("MDTM sub/a.bin")
check("mdtm", True, mdtm.startswith("213 ") and len(mdtm) == 18)

out = io.BytesIO()
f.retrbinary("RETR sub/a.bin", out.write)
check("retr", data, out.getvalue())
out = io.BytesIO()
f.retrbinary("RETR sub/a.bin", out.write, rest=1000)
check("retr rest", data[1000:], out.getvalue())
check("rest past end", "554", err_code(lambda: f.retrbinary(f"RETR sub/a.bin", lambda b: None, rest=len(data) + 5)))

entries = dict(f.mlsd("sub"))
check("mlsd file", "file", entries.get("a.bin", {}).get("type"))
check("mlsd size", str(len(data)), entries.get("a.bin", {}).get("size"))
root = dict(f.mlsd(""))
check("mlsd dir", "dir", root.get("sub", {}).get("type"))
check("nlst", ["a.bin"], f.nlst("sub"))
lines = []
f.retrlines("LIST sub", lines.append)
check("list", True, len(lines) == 1 and lines[0].startswith("-rw") and lines[0].endswith(" a.bin"))
check("mlst", True, "type=file" in f.sendcmd("MLST sub/a.bin"))

f.storbinary("STOR app.txt", io.BytesIO(b"hello "))
f.storbinary("APPE app.txt", io.BytesIO(b"world"))
out = io.BytesIO()
f.retrbinary("RETR app.txt", out.write)
check("appe", b"hello world", out.getvalue())

check("rename", "250", f.rename("sub/a.bin", "sub/b.bin")[:3])
check("renamed size", len(data), f.size("sub/b.bin"))
check("old name gone", "550", err_code(lambda: f.size("sub/a.bin")))
check("rmd non-empty", "550", err_code(lambda: f.rmd("sub")))
check("delete", "250", f.delete("sub/b.bin")[:3])
check("delete missing", "550", err_code(lambda: f.delete("sub/b.bin")))
check("rmd", "250", f.rmd("sub")[:3])
check("cwd missing", "550", err_code(lambda: f.cwd("nope")))
check("cdup", "250", f.sendcmd("CDUP")[:3])
check("pwd root", "/", f.pwd())
check("stat", "211", f.sendcmd("STAT")[:3])
check("unknown", "500", err_code(lambda: f.sendcmd("BOGUS")))

if big:
    h = hashlib.md5()
    with open(big, "rb") as fh:
        check("big stor", "226", f.storbinary(f"STOR {bucket}/big.bin", fh, blocksize=1 << 20)[:3])
    f.retrbinary(f"RETR {bucket}/big.bin", h.update, blocksize=1 << 20)
    with open(big, "rb") as fh:
        want = hashlib.md5(fh.read()).hexdigest()
    check("big md5", want, h.hexdigest())
    f.delete(f"{bucket}/big.bin")

f.delete(f"{bucket}/app.txt")
check("rmd bucket", "250", f.rmd(bucket)[:3])
check("quit", "221", f.quit()[:3])

print(f"python {mode}: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
