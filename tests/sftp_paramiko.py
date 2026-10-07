"""Paramiko checks for the SFTP gateway: password auth, listing, transfers,
stat, ranged reads, resumed download, and rejection of a bad password.
usage: sftp_paramiko.py PORT USER PASSWORD BUCKET WORKDIR"""
import hashlib
import os
import sys

import paramiko

port, user, pw, bucket, work = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
passed = failed = 0


def check(name, want, got):
    global passed, failed
    if want == got:
        passed += 1
        print(f"ok   {name}")
    else:
        failed += 1
        print(f"FAIL {name}: expected [{want!r}] got [{got!r}]")


def connect(password, cipher=None):
    t = paramiko.Transport(("127.0.0.1", port))
    if cipher:
        t.get_security_options().ciphers = (cipher,)
    t.connect(username=user, password=password)
    return t, paramiko.SFTPClient.from_transport(t)


md5 = lambda b: hashlib.md5(b).hexdigest()
t, s = connect(pw)
check("paramiko cipher is AEAD", True, t.remote_cipher.endswith("gcm@openssh.com"))
base = f"/{bucket}/pm"
s.mkdir(base)
check("listdir bucket", True, "pm" in s.listdir(f"/{bucket}"))

data = os.urandom(3 * 1024 * 1024 + 12345)
src = os.path.join(work, "pm.src")
with open(src, "wb") as f:
    f.write(data)
s.put(src, f"{base}/file.bin")
check("listdir after put", ["file.bin"], s.listdir(base))
st = s.stat(f"{base}/file.bin")
check("stat size", len(data), st.st_size)
check("stat is regular file", 0o100644, st.st_mode)
check("stat dir mode", 0o040755, s.stat(base).st_mode)
dst = os.path.join(work, "pm.dst")
s.get(f"{base}/file.bin", dst)
check("get md5", md5(data), md5(open(dst, "rb").read()))

with s.open(f"{base}/file.bin", "rb") as f:
    f.seek(1_000_000)
    check("seek read", md5(data[1_000_000:1_000_100]), md5(f.read(100)))
    f.seek(len(data) - 10)
    check("read tail", data[-10:], f.read(100))
    check("read at eof", b"", f.read(10))
    check("readv ranges", [data[5:9], data[2_000_000:2_000_050]], list(f.readv([(5, 4), (2_000_000, 50)])))

# Resume a partial download: keep the first part, fetch the rest from its offset.
part = data[: 1_500_000]
with open(dst, "wb") as f:
    f.write(part)
with s.open(f"{base}/file.bin", "rb") as rf, open(dst, "ab") as lf:
    rf.seek(len(part))
    while True:
        chunk = rf.read(32768)
        if not chunk:
            break
        lf.write(chunk)
check("resumed download md5", md5(data), md5(open(dst, "rb").read()))

# Append-mode resume of an upload.
with s.open(f"{base}/resume.bin", "wb") as f:
    f.write(data[:1_000_000])
with s.open(f"{base}/resume.bin", "ab") as f:
    f.write(data[1_000_000:])
check("resumed upload size", len(data), s.stat(f"{base}/resume.bin").st_size)
with s.open(f"{base}/resume.bin", "rb") as f:
    check("resumed upload md5", md5(data), md5(f.read()))

# Random-offset writes land where asked.
with s.open(f"{base}/sparse.bin", "wb") as f:
    f.seek(10)
    f.write(b"tail")
    f.seek(0)
    f.write(b"head")
with s.open(f"{base}/sparse.bin", "rb") as f:
    check("offset writes", b"head" + b"\0" * 6 + b"tail", f.read())

s.rename(f"{base}/sparse.bin", f"{base}/moved.bin")
check("rename", sorted(["file.bin", "moved.bin", "resume.bin"]), sorted(s.listdir(base)))
try:
    s.rename(f"{base}/moved.bin", f"{base}/file.bin")
    check("rename onto existing refused", True, False)
except IOError:
    check("rename onto existing refused", True, True)
s.posix_rename(f"{base}/moved.bin", f"{base}/file.bin")
check("posix-rename replaces", 14, s.stat(f"{base}/file.bin").st_size)
try:
    s.stat(f"{base}/nope")
    check("stat missing", True, False)
except FileNotFoundError:
    check("stat missing", True, True)
for n in ("file.bin", "resume.bin"):
    s.remove(f"{base}/{n}")
s.rmdir(base)
check("rmdir", False, "pm" in s.listdir(f"/{bucket}"))
s.close()
t.close()

t, s = connect(pw, "aes256-gcm@openssh.com")
check("aes256-gcm session", "aes256-gcm@openssh.com", t.remote_cipher)
s.close()
t.close()

try:
    connect(pw + "x")
    check("bad password rejected", True, False)
except paramiko.AuthenticationException:
    check("bad password rejected", True, True)

print(f"paramiko: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
