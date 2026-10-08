#!/usr/bin/env python3
"""Minimal OTLP/HTTP protobuf receiver for tests (no protobuf library needed).

Usage: otlp_receiver.py PORT OUTDIR
Decodes ExportTraceServiceRequest / ExportLogsServiceRequest / ExportMetricsServiceRequest
and appends one JSON object per span, log record, or metric to OUTDIR/{spans,logs,metrics}.jsonl.
"""
import json
import os
import struct
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def fields(buf):
    i = 0
    while i < len(buf):
        key, i = varint(buf, i)
        num, wire = key >> 3, key & 7
        if wire == 0:
            v, i = varint(buf, i)
        elif wire == 1:
            v = buf[i:i + 8]
            i += 8
        elif wire == 5:
            v = buf[i:i + 4]
            i += 4
        elif wire == 2:
            n, i = varint(buf, i)
            v = buf[i:i + n]
            i += n
        else:
            raise ValueError("bad wire type %d" % wire)
        yield num, wire, v


def varint(buf, i):
    shift = result = 0
    while True:
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if b < 0x80:
            return result, i
        shift += 7


def any_value(buf):
    for num, wire, v in fields(buf):
        if num == 1:
            return v.decode()
        if num == 2:
            return bool(v)
        if num == 3:
            return v - (1 << 64) if v >= 1 << 63 else v
        if num == 4:
            return struct.unpack("<d", v)[0]
    return ""


def key_value(buf):
    k, val = "", ""
    for num, _, v in fields(buf):
        if num == 1:
            k = v.decode()
        elif num == 2:
            val = any_value(v)
    return k, val


def resource(buf):
    return dict(key_value(v) for num, _, v in fields(buf) if num == 1)


def span(buf, res):
    s = {"attrs": {}, "resource": res, "parent": ""}
    for num, wire, v in fields(buf):
        if num == 1:
            s["trace_id"] = v.hex()
        elif num == 2:
            s["span_id"] = v.hex()
        elif num == 4:
            s["parent"] = v.hex()
        elif num == 5:
            s["name"] = v.decode()
        elif num == 6:
            s["kind"] = v
        elif num == 7:
            s["start"] = struct.unpack("<Q", v)[0]
        elif num == 8:
            s["end"] = struct.unpack("<Q", v)[0]
        elif num == 9:
            k, val = key_value(v)
            s["attrs"][k] = val
        elif num == 15:
            for n2, _, v2 in fields(v):
                if n2 == 3:
                    s["status"] = v2
                if n2 == 2:
                    s["status_message"] = v2.decode()
    return s


def log_record(buf, res):
    r = {"attrs": {}, "resource": res}
    for num, wire, v in fields(buf):
        if num == 1:
            r["time"] = struct.unpack("<Q", v)[0]
        elif num == 2:
            r["severity"] = v
        elif num == 3:
            r["severity_text"] = v.decode()
        elif num == 5:
            r["body"] = any_value(v)
        elif num == 6:
            k, val = key_value(v)
            r["attrs"][k] = val
        elif num == 9:
            r["trace_id"] = v.hex()
    return r


def metric(buf, res):
    m = {"resource": res, "points": []}
    for num, wire, v in fields(buf):
        if num == 1:
            m["name"] = v.decode()
        elif num in (5, 7, 9):
            m["kind"] = {5: "gauge", 7: "sum", 9: "histogram"}[num]
            for n2, _, dp in fields(v):
                if n2 != 1:
                    continue
                p = {"attrs": {}}
                for n3, w3, x in fields(dp):
                    if (num != 9 and n3 == 7) or (num == 9 and n3 == 9):
                        k, val = key_value(x)
                        p["attrs"][k] = val
                    elif num != 9 and n3 == 4:
                        p["value"] = struct.unpack("<d", x)[0]
                    elif num == 9 and n3 == 4:
                        p["count"] = struct.unpack("<Q", x)[0]
                    elif num == 9 and n3 == 6:
                        p["buckets"] = list(struct.unpack("<%dQ" % (len(x) // 8), x))
                m["points"].append(p)
    return m


def decode(kind, body):
    out = []
    for _, _, rs in fields(body):  # Resource{Spans,Logs,Metrics}
        res = {}
        scopes = []
        for num, _, v in fields(rs):
            if num == 1:
                res = resource(v)
            elif num == 2:
                scopes.append(v)
        for sc in scopes:
            for num, _, v in fields(sc):
                if num != 2:
                    continue
                if kind == "spans":
                    out.append(span(v, res))
                elif kind == "logs":
                    out.append(log_record(v, res))
                else:
                    out.append(metric(v, res))
    return out


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(n)
        kind = {"/v1/traces": "spans", "/v1/logs": "logs", "/v1/metrics": "metrics"}.get(self.path)
        ok = kind is not None and self.headers.get("content-type") == "application/x-protobuf"
        if ok:
            try:
                items = decode(kind, body)
            except Exception as e:  # noqa: BLE001
                ok = False
                items = []
                sys.stderr.write("decode error: %s\n" % e)
            with open(os.path.join(OUT, kind + ".jsonl"), "a") as f:
                for it in items:
                    it["headers"] = {k.lower(): v for k, v in self.headers.items() if k.lower().startswith("x-")}
                    f.write(json.dumps(it) + "\n")
        self.send_response(200 if ok else 400)
        self.send_header("content-type", "application/x-protobuf")
        self.send_header("content-length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    OUT = sys.argv[2]
    os.makedirs(OUT, exist_ok=True)
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
