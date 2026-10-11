#!/usr/bin/env python3
"""Snapshot of a server's buckets, versions, object data and metadata, bucket
configurations, and IAM, taken through the mc client; or compare two snapshots.

  migrate_snapshot.py take ALIAS OUT.json [--iam] [--buckets b1,b2]
  migrate_snapshot.py diff A.json B.json [--no-iam]
"""
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime

MC = os.environ.get("MC", "mc")

DROP_META = ("x-amz-object-lock", "x-amz-server-side", "x-amz-storage-class", "x-amz-checksum",
             "x-amz-replication", "x-minio", "last-modified", "etag", "content-length",
             "x-amz-version-id", "x-amz-restore", "accept-ranges", "x-amz-delete-marker")


def mc_lines(*args, check=True):
    p = subprocess.run([MC, "--json", *args], capture_output=True, text=True)
    out = [json.loads(l) for l in p.stdout.splitlines() if l.strip().startswith("{")]
    if check and p.returncode != 0:
        raise SystemExit(f"mc {' '.join(args)} failed: {p.stdout} {p.stderr}")
    return out


def mc_one(*args):
    p = subprocess.run([MC, "--json", *args], capture_output=True, text=True)
    lines = [json.loads(l) for l in p.stdout.splitlines() if l.strip().startswith("{")]
    return lines[0] if lines and lines[0].get("status") != "error" and p.returncode == 0 else None


def vid(v):
    return (v or "null").replace("-", "").lower()


def ms(ts):
    return int(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() * 1000)


def policy_norm(doc):
    if not doc:
        return None
    def norm(x):
        if isinstance(x, dict):
            return {k: norm(v) for k, v in sorted(x.items())}
        if isinstance(x, list):
            return sorted((norm(v) for v in x), key=lambda v: json.dumps(v, sort_keys=True))
        return x
    return norm(doc)


def take(alias, buckets, iam):
    snap = {"buckets": {}, "iam": {}}
    names = [b["key"].rstrip("/") for b in mc_lines("ls", alias)]
    for b in names:
        if buckets and b not in buckets:
            continue
        bs = {}
        v = mc_one("version", "info", f"{alias}/{b}")
        bs["versioning"] = (v or {}).get("versioning", {}).get("status", "") or "Unversioned"
        t = mc_one("tag", "list", f"{alias}/{b}")
        bs["tags"] = (t or {}).get("tagset") or {}
        p = subprocess.run([MC, "anonymous", "get-json", f"{alias}/{b}"], capture_output=True, text=True)
        try:
            bs["policy"] = policy_norm(json.loads(p.stdout)) if p.returncode == 0 and p.stdout.strip() else None
        except json.JSONDecodeError:
            bs["policy"] = None
        r = mc_one("retention", "info", "--default", f"{alias}/{b}")
        bs["lock"] = {"enabled": (r or {}).get("enabled", ""), "mode": (r or {}).get("mode", ""),
                      "validity": (r or {}).get("validity", "")}
        il = subprocess.run([MC, "ilm", "rule", "export", f"{alias}/{b}"], capture_output=True, text=True)
        rules = []
        if il.returncode == 0 and il.stdout.strip().startswith("{"):
            for rule in json.loads(il.stdout).get("Rules", []):
                rules.append({"ID": rule.get("ID"), "Status": rule.get("Status"),
                              "Days": (rule.get("Expiration") or {}).get("Days")})
        bs["ilm"] = rules
        objs = {}
        for e in mc_lines("ls", "-r", "--versions", f"{alias}/{b}"):
            if e.get("status") != "success":
                continue
            key = e["key"]
            ver = {"id": vid(e.get("versionId")), "dm": bool(e.get("isDeleteMarker")),
                   "mtime_ms": ms(e["lastModified"])}
            if not ver["dm"]:
                ver["size"] = e["size"]
                ver["etag"] = e["etag"].strip('"')
                ref = f"{alias}/{b}/{key}"
                vflag = [] if ver["id"] == "null" else ["--vid", e.get("versionId")]
                data = subprocess.run([MC, "cat", *([] if ver["id"] == "null" else ["--vid", e.get("versionId")]), ref],
                                      capture_output=True).stdout
                ver["md5"] = hashlib.md5(data).hexdigest()
                st = mc_one("stat", *vflag, ref) or {}
                ver["meta"] = {k.lower(): v for k, v in (st.get("metadata") or {}).items()
                               if not k.lower().startswith(DROP_META)}
                tv = [] if ver["id"] == "null" else ["--version-id", e.get("versionId")]
                tg = mc_one("tag", "list", *tv, ref)
                ver["tags"] = (tg or {}).get("tagset") or {}
                if bs["lock"]["enabled"] == "Enabled":
                    rt = mc_one("retention", "info", *tv, ref) or {}
                    until = rt.get("until", "")
                    # Servers differ in how many fraction digits they print.
                    ver["retention"] = [rt.get("mode", ""), until and ms(until) // 1000]
                    lh = mc_one("legalhold", "info", *tv, ref) or {}
                    ver["legalhold"] = lh.get("legalhold", "") or "OFF"
            objs.setdefault(key, []).append(ver)
        for k in objs:
            objs[k].sort(key=lambda x: (x["mtime_ms"], x["id"]))
        bs["objects"] = objs
        snap["buckets"][b] = bs
    if iam:
        users = {}
        for u in mc_lines("admin", "user", "list", alias):
            name = u.get("accessKey")
            info = mc_one("admin", "user", "info", alias, name) or {}
            users[name] = {"status": info.get("userStatus"),
                           "policies": sorted(filter(None, (info.get("policyName") or "").split(",")))}
        snap["iam"]["users"] = users
        groups = {}
        for g in mc_lines("admin", "group", "list", alias, check=False):
            for name in g.get("groups") or []:
                info = mc_one("admin", "group", "info", alias, name) or {}
                groups[name] = {"members": sorted(info.get("members") or []),
                                "policy": sorted(filter(None, (info.get("groupPolicy") or "").split(",")))}
        snap["iam"]["groups"] = groups
    return snap


def diff(a, b, path=""):
    out = []
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                out.append(f"{path}/{k}: only in {'source' if k in a else 'destination'}: {a.get(k, b.get(k))}")
            else:
                out += diff(a[k], b[k], f"{path}/{k}")
    elif isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        for i, (x, y) in enumerate(zip(a, b)):
            out += diff(x, y, f"{path}[{i}]")
    elif a != b:
        out.append(f"{path}: source {a!r} != destination {b!r}")
    return out


def main():
    if sys.argv[1] == "take":
        buckets = []
        if "--buckets" in sys.argv:
            buckets = sys.argv[sys.argv.index("--buckets") + 1].split(",")
        snap = take(sys.argv[2], buckets, "--iam" in sys.argv)
        with open(sys.argv[3], "w") as f:
            json.dump(snap, f, indent=1, sort_keys=True)
        return 0
    a = json.load(open(sys.argv[2]))
    b = json.load(open(sys.argv[3]))
    if "--no-iam" in sys.argv:
        a.pop("iam", None)
        b.pop("iam", None)
    d = diff(a, b)
    for line in d:
        print("  " + line)
    nv = sum(len(v) for bk in a["buckets"].values() for v in bk["objects"].values())
    print(f"compared {len(a['buckets'])} bucket(s), {nv} version(s): {len(d)} difference(s)")
    return 1 if d else 0


if __name__ == "__main__":
    sys.exit(main())
