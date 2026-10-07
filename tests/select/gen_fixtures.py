#!/usr/bin/env python3
"""Generates S3 Select fixtures and expected outputs.

Parquet files come from pyarrow; expected results come from DuckDB running
the equivalent SQL, rendered the way S3 Select renders CSV output. Writes
tests/select/fixtures/* and tests/select/cases.zig.

Setup: python3 -m venv tests/select/.venv &&
       tests/select/.venv/bin/pip install pyarrow pandas duckdb
"""
import datetime as dt
import decimal
import gzip
import json
import os
import random

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures")
N = 1000


def rows():
    rnd = random.Random(42)
    out = []
    base_day = dt.date(2015, 1, 1)
    base_ts = dt.datetime(2020, 1, 1, 0, 0, 0)
    for i in range(N):
        name = f"n{i}"
        if i % 50 == 7:
            name = f'q"{i}, x'
        out.append({
            "id": i,
            "qty": rnd.randint(0, 100),
            "price": rnd.randint(0, 400) / 4.0,
            "name": name,
            "category": None if i % 13 == 0 else rnd.choice(["a", "b", "c", "d"]),
            "flag": rnd.random() < 0.5,
            "day": base_day + dt.timedelta(days=rnd.randint(0, 3000)),
            "ts": base_ts + dt.timedelta(milliseconds=rnd.randint(0, 10**11)),
            "amount": decimal.Decimal(rnd.randint(0, 99999)) / 100,
            "ratio": None if i % 17 == 0 else rnd.randint(0, 64) / 8.0,
        })
    return out


SCHEMA = pa.schema([
    ("id", pa.int64()),
    ("qty", pa.int32()),
    ("price", pa.float64()),
    ("name", pa.string()),
    ("category", pa.string()),
    ("flag", pa.bool_()),
    ("day", pa.date32()),
    ("ts", pa.timestamp("ms")),
    ("amount", pa.decimal128(10, 2)),
    ("ratio", pa.float32()),
])

PARQUET_VARIANTS = {
    "plain_none.parquet": dict(compression="none", use_dictionary=False, row_group_size=N),
    "dict_snappy.parquet": dict(compression="snappy", use_dictionary=True, row_group_size=300),
    "gzip_v2.parquet": dict(compression="gzip", use_dictionary=True, data_page_version="2.0", row_group_size=400),
    "zstd_plain_v2.parquet": dict(compression="zstd", use_dictionary=False, data_page_version="2.0", row_group_size=N),
}


def fmt_scalar(v):
    """S3 Select text rendering of a value."""
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        s = format(decimal.Decimal(repr(v)), "f")
        if "." in s:
            s = s.rstrip("0").rstrip(".")
        return s
    if isinstance(v, decimal.Decimal):
        return fmt_scalar(float(v))
    if isinstance(v, dt.datetime):
        return v.strftime("%Y-%m-%dT%H:%M:%S") + ".%03dZ" % (v.microsecond // 1000)
    if isinstance(v, dt.date):
        return v.isoformat() + "T"
    return str(v)


def csv_field(s):
    if any(c in s for c in ',"\n\r'):
        return '"' + s.replace('"', '""') + '"'
    return s


def csv_rows(result):
    return "".join(",".join(csv_field(fmt_scalar(v)) for v in r) + "\n" for r in result)


# (name, s3 sql, duckdb sql over table t, applies to csv/json text inputs too)
CASES = [
    ("count", "SELECT COUNT(*) FROM S3Object", "SELECT COUNT(*) FROM t", True),
    ("filter_limit",
     "SELECT s.id, s.name, s.price FROM S3Object s WHERE s.qty > 50 AND s.category = 'b' LIMIT 20",
     "SELECT id, name, price FROM t WHERE qty > 50 AND category = 'b' LIMIT 20", True),
    ("aggregates",
     "SELECT SUM(s.qty), MIN(s.price), MAX(s.price), AVG(s.price) FROM S3Object s WHERE s.flag = true",
     "SELECT SUM(qty), MIN(price), MAX(price), AVG(price) FROM t WHERE flag = true", True),
    ("count_nullable", "SELECT COUNT(s.category), COUNT(s.ratio), SUM(s.ratio) FROM S3Object s",
     "SELECT COUNT(category), COUNT(ratio), SUM(ratio) FROM t", False),
    ("is_null", "SELECT s.id FROM S3Object s WHERE s.category IS NULL",
     "SELECT id FROM t WHERE category IS NULL", False),
    ("strings",
     "SELECT UPPER(s.name), CHAR_LENGTH(s.name), SUBSTRING(s.name, 2, 3) FROM S3Object s WHERE s.name LIKE 'n1%5'",
     "SELECT UPPER(name), LENGTH(name), SUBSTRING(name, 2, 3) FROM t WHERE name LIKE 'n1%5'", True),
    ("quoted_names", "SELECT s.name FROM S3Object s WHERE s.name LIKE 'q%'",
     "SELECT name FROM t WHERE name LIKE 'q%'", True),
    ("dates",
     "SELECT s.id, EXTRACT(YEAR FROM s.day), EXTRACT(MONTH FROM s.ts), EXTRACT(HOUR FROM s.ts) FROM S3Object s WHERE s.id < 25",
     "SELECT id, EXTRACT(YEAR FROM day), EXTRACT(MONTH FROM ts), EXTRACT(HOUR FROM ts) FROM t WHERE id < 25", False),
    ("between_in",
     "SELECT COUNT(*) FROM S3Object s WHERE s.price BETWEEN 10 AND 20 OR s.category IN ('a', 'c')",
     "SELECT COUNT(*) FROM t WHERE price BETWEEN 10 AND 20 OR category IN ('a', 'c')", True),
    ("arith", "SELECT s.id, s.qty * 2 + 1, s.price / 2.0 FROM S3Object s WHERE s.id % 97 = 0",
     "SELECT id, qty * 2 + 1, price / 2.0 FROM t WHERE id % 97 = 0", True),
    ("star", "SELECT * FROM S3Object s WHERE s.id IN (0, 1, 7, 13, 17, 999)",
     "SELECT * FROM t WHERE id IN (0, 1, 7, 13, 17, 999)", False),
    ("nullable_float", "SELECT s.id, s.ratio FROM S3Object s WHERE s.ratio IS NULL OR s.ratio > 7.5",
     "SELECT id, ratio FROM t WHERE ratio IS NULL OR ratio > 7.5", False),
    ("not_like", "SELECT COUNT(*) FROM S3Object s WHERE s.name NOT LIKE '%5%' AND NOT s.flag",
     "SELECT COUNT(*) FROM t WHERE name NOT LIKE '%5%' AND NOT flag", False),
]


def zig_str(s):
    return json.dumps(s)


def main():
    os.makedirs(FIX, exist_ok=True)
    data = rows()
    table = pa.Table.from_pylist(data, schema=SCHEMA)
    for fname, kw in PARQUET_VARIANTS.items():
        pq.write_table(table, os.path.join(FIX, fname), **kw)

    # Text inputs carry the same rows (subset of columns) rendered as S3 would.
    text_cols = ["id", "qty", "price", "name", "category", "flag"]
    header = ",".join(text_cols) + "\n"
    body = "".join(",".join(csv_field(fmt_scalar(r[c])) for c in text_cols) + "\n" for r in data)
    with open(os.path.join(FIX, "rows.csv.gz"), "wb") as f:
        f.write(gzip.compress((header + body).encode(), mtime=0))
    with open(os.path.join(FIX, "rows.jsonl"), "w") as f:
        for r in data:
            f.write(json.dumps({c: r[c] for c in text_cols}) + "\n")

    con = duckdb.connect()
    con.execute("SET threads = 1")
    con.register("src", table)
    con.execute("CREATE TABLE t AS SELECT * FROM src")
    text_tbl = pa.Table.from_pylist([{c: r[c] for c in text_cols} for r in data])
    con.register("tsrc", text_tbl)
    con.execute("CREATE TABLE tt AS SELECT * FROM tsrc")

    out = ["//! Generated by gen_fixtures.py; do not edit.", "pub const Case = struct { name: []const u8, sql: []const u8, text_ok: bool, expected: []const u8 };",
           "pub const parquet_files = [_][]const u8{ " + ", ".join(zig_str(f) for f in PARQUET_VARIANTS) + " };",
           "pub const cases = [_]Case{"]
    for name, s3, duck, text_ok in CASES:
        res = con.execute(duck).fetchall()
        exp = csv_rows(res)
        if text_ok:
            # The same query over the text table must agree.
            res2 = con.execute(duck.replace(" FROM t", " FROM tt")).fetchall()
            assert csv_rows(res2) == exp, name
        out.append(f"    .{{ .name = {zig_str(name)}, .sql = {zig_str(s3)}, .text_ok = {'true' if text_ok else 'false'}, .expected = {zig_str(exp)} }},")
    out.append("};")
    with open(os.path.join(HERE, "cases.zig"), "w") as f:
        f.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
