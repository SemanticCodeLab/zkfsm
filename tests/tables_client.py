"""Iceberg REST + S3 Tables client checks against a running zkfsm (driven by tests/tables.sh)."""
import os
import sys
import threading

import boto3
import pyarrow as pa
from botocore.exceptions import ClientError
from pyiceberg.catalog.rest import RestCatalog
from pyiceberg.exceptions import (
    CommitFailedException,
    NamespaceAlreadyExistsError,
    NamespaceNotEmptyError,
    NoSuchTableError,
    TableAlreadyExistsError,
)
from pyiceberg.types import DoubleType

EP = os.environ["EP"]
AK = os.environ["AK"]
SK = os.environ["SK"]
ARN = os.environ["TABLE_BUCKET_ARN"]
failures = 0


def check(name, cond, detail=""):
    global failures
    if cond:
        print(f"ok   {name}")
    else:
        failures += 1
        print(f"FAIL {name} {detail}")


def expect_raise(name, exc, fn):
    try:
        fn()
    except exc:
        check(name, True)
        return
    except Exception as e:  # noqa: BLE001
        check(name, False, f"raised {type(e).__name__}: {e}")
        return
    check(name, False, "no exception")


def catalog(prefix="/iceberg", signing="s3tables"):
    return RestCatalog(
        "zk",
        **{
            "uri": EP + prefix,
            "warehouse": ARN,
            "rest.sigv4-enabled": "true",
            "rest.signing-name": signing,
            "rest.signing-region": "us-east-1",
            "client.access-key-id": AK,
            "client.secret-access-key": SK,
            "client.region": "us-east-1",
            "s3.endpoint": EP,
            "s3.access-key-id": AK,
            "s3.secret-access-key": SK,
            "s3.region": "us-east-1",
        },
    )


cat = catalog()
cat.create_namespace("analytics", {"owner": "qa"})
check("namespace listed", ("analytics",) in cat.list_namespaces())
expect_raise("duplicate namespace", NamespaceAlreadyExistsError, lambda: cat.create_namespace("analytics"))
cat.update_namespace_properties("analytics", removals={"owner"}, updates={"team": "data"})
props = cat.load_namespace_properties("analytics")
check("namespace properties updated", props.get("team") == "data" and "owner" not in props, str(props))
cat.create_namespace(("analytics", "nested"))
check("nested namespace listed", ("analytics", "nested") in cat.list_namespaces("analytics"))
check("top level lists only direct children", ("analytics", "nested") not in cat.list_namespaces())

schema = pa.schema([pa.field("id", pa.int64()), pa.field("name", pa.string())])
# No client-side retries, so CAS conflicts surface as CommitFailedException.
tbl = cat.create_table("analytics.events", schema=schema, properties={"commit.retry.num-retries": "0"})
check("table created with metadata", tbl.metadata_location.startswith("s3://"), tbl.metadata_location)
expect_raise("duplicate table", TableAlreadyExistsError, lambda: cat.create_table("analytics.events", schema=schema))
tbl.append(pa.table({"id": [1, 2], "name": ["a", "b"]}, schema=schema))
tbl.append(pa.table({"id": [3], "name": ["c"]}, schema=schema))
rows = cat.load_table("analytics.events").scan().to_arrow()
check("append and read back", sorted(rows["id"].to_pylist()) == [1, 2, 3], str(rows))

with tbl.update_schema() as upd:
    upd.add_column("score", DoubleType())
tbl = cat.load_table("analytics.events")
check("schema evolved", "score" in [f.name for f in tbl.schema().fields])
schema2 = pa.schema([pa.field("id", pa.int64()), pa.field("name", pa.string()), pa.field("score", pa.float64())])
tbl.append(pa.table({"id": [4], "name": ["d"], "score": [9.5]}, schema=schema2))
rows = cat.load_table("analytics.events").scan().to_arrow().sort_by("id")
check("old rows read with null new column", rows["score"].to_pylist() == [None, None, None, 9.5], str(rows["score"]))
check("history has snapshots", len(cat.load_table("analytics.events").history()) == 3)

# Stale writer: both load the same version, the second commit must lose.
t1 = cat.load_table("analytics.events")
t2 = cat.load_table("analytics.events")
t1.append(pa.table({"id": [5], "name": ["e"], "score": [1.0]}, schema=schema2))
expect_raise("stale commit rejected", CommitFailedException,
             lambda: t2.append(pa.table({"id": [6], "name": ["f"], "score": [2.0]}, schema=schema2)))

# Concurrent writers from one base: exactly one CAS winner.
handles = [cat.load_table("analytics.events") for _ in range(6)]
results = []
barrier = threading.Barrier(len(handles))


def writer(h, n):
    barrier.wait()
    try:
        h.append(pa.table({"id": [100 + n], "name": ["w"], "score": [0.0]}, schema=schema2))
        results.append("ok")
    except CommitFailedException:
        results.append("conflict")
    except Exception as e:  # noqa: BLE001
        results.append(f"error {type(e).__name__}: {e}")


threads = [threading.Thread(target=writer, args=(h, i)) for i, h in enumerate(handles)]
for th in threads:
    th.start()
for th in threads:
    th.join()
check("concurrent commits: one winner", results.count("ok") == 1 and results.count("conflict") == len(handles) - 1, str(results))
ids = cat.load_table("analytics.events").scan().to_arrow()["id"].to_pylist()
check("winner's rows visible, losers' not", len(ids) == 6 and 6 not in ids, str(ids))

# With client retries on, every concurrent writer lands via refresh-and-retry.
t = cat.load_table("analytics.events")
with t.transaction() as tx:
    tx.remove_properties("commit.retry.num-retries")
handles = [cat.load_table("analytics.events") for _ in range(3)]
results = []
barrier = threading.Barrier(len(handles))
threads = [threading.Thread(target=writer, args=(h, 10 + i)) for i, h in enumerate(handles)]
for th in threads:
    th.start()
for th in threads:
    th.join()
ids = cat.load_table("analytics.events").scan().to_arrow()["id"].to_pylist()
check("retrying writers all commit", results == ["ok"] * 3 and len(ids) == 9, f"{results} {ids}")

# Second profile: MinIO-style alias with the s3 signing name.
alias = catalog("/_iceberg", "s3")
check("alias profile lists tables", ("analytics", "events") in alias.list_tables("analytics"))
check("table exists", alias.table_exists("analytics.events"))

# Staged create (create-table transaction) publishes on commit.
with cat.create_table_transaction("analytics.staged", schema=schema) as txn:
    txn.set_properties(stage="yes")
staged = cat.load_table("analytics.staged")
check("staged create committed", staged.properties.get("stage") == "yes", str(staged.properties))

cat.rename_table("analytics.staged", "analytics.renamed")
check("rename moves table", cat.table_exists("analytics.renamed") and not cat.table_exists("analytics.staged"))

# The same table through the S3 Tables API.
st = boto3.client("s3tables", endpoint_url=EP, region_name="us-east-1", aws_access_key_id=AK, aws_secret_access_key=SK)
cur = cat.load_table("analytics.events")
got = st.get_table(tableBucketARN=ARN, namespace="analytics", name="events")
check("GetTable metadataLocation matches catalog", got["metadataLocation"] == cur.metadata_location, got.get("metadataLocation"))
loc = st.get_table_metadata_location(tableBucketARN=ARN, namespace="analytics", name="events")
check("GetTableMetadataLocation token", loc["versionToken"] == got["versionToken"])
try:
    st.update_table_metadata_location(tableBucketARN=ARN, namespace="analytics", name="events",
                                      versionToken="0" * 32, metadataLocation=cur.metadata_location)
    check("stale versionToken rejected", False, "accepted")
except ClientError as e:
    check("stale versionToken rejected", e.response["Error"]["Code"] == "ConflictException", str(e))
names = [t["name"] for t in st.list_tables(tableBucketARN=ARN, namespace="analytics")["tables"]]
check("ListTables via s3tables", "events" in names and "renamed" in names, str(names))
by_arn = st.get_table(tableArn=got["tableARN"])
check("GetTable by table ARN", by_arn["name"] == "events")

expect_raise("drop non-empty namespace", NamespaceNotEmptyError, lambda: cat.drop_namespace("analytics"))
cat.purge_table("analytics.events")
cat.drop_table("analytics.renamed")
check("dropped tables gone", not cat.table_exists("analytics.events") and not cat.table_exists("analytics.renamed"))
expect_raise("load dropped table", NoSuchTableError, lambda: cat.load_table("analytics.events"))
cat.drop_namespace(("analytics", "nested"))
cat.drop_namespace("analytics")
check("namespace dropped", ("analytics",) not in cat.list_namespaces())

print(f"tables client: {failures} failure(s)")
sys.exit(1 if failures else 0)
