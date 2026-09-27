import datetime
import hashlib
import os

import pytest
from botocore.exceptions import ClientError

MB = 1024 * 1024


def code(e):
    return e.value.response["Error"]["Code"]


def mp_etag(parts):
    return '"%s-%d"' % (hashlib.md5(b"".join(hashlib.md5(p).digest() for p in parts)).hexdigest(), len(parts))


# Multipart

def test_multipart_basic(s3, bucket):
    parts = [os.urandom(5 * MB), os.urandom(5 * MB), os.urandom(123)]
    up = s3.create_multipart_upload(Bucket=bucket, Key="mp", ContentType="text/mp", Metadata={"m": "1"})
    uid = up["UploadId"]
    done = []
    for i, p in enumerate(parts, 1):
        r = s3.upload_part(Bucket=bucket, Key="mp", UploadId=uid, PartNumber=i, Body=p)
        assert r["ETag"] == '"%s"' % hashlib.md5(p).hexdigest()
        done.append({"PartNumber": i, "ETag": r["ETag"]})
    r = s3.complete_multipart_upload(Bucket=bucket, Key="mp", UploadId=uid, MultipartUpload={"Parts": done})
    assert r["ETag"] == mp_etag(parts)
    g = s3.get_object(Bucket=bucket, Key="mp")
    assert g["Body"].read() == b"".join(parts)
    assert g["ContentType"] == "text/mp"
    assert g["Metadata"] == {"m": "1"}
    assert g["ETag"] == mp_etag(parts)


def test_multipart_range_across_parts(s3, bucket):
    parts = [os.urandom(5 * MB), os.urandom(2 * MB)]
    uid = s3.create_multipart_upload(Bucket=bucket, Key="mp")["UploadId"]
    done = [{"PartNumber": i, "ETag": s3.upload_part(Bucket=bucket, Key="mp", UploadId=uid, PartNumber=i, Body=p)["ETag"]}
            for i, p in enumerate(parts, 1)]
    s3.complete_multipart_upload(Bucket=bucket, Key="mp", UploadId=uid, MultipartUpload={"Parts": done})
    whole = b"".join(parts)
    lo, hi = 5 * MB - 100, 5 * MB + 100
    assert s3.get_object(Bucket=bucket, Key="mp", Range=f"bytes={lo}-{hi}")["Body"].read() == whole[lo:hi + 1]


def test_multipart_list_parts(s3, bucket):
    uid = s3.create_multipart_upload(Bucket=bucket, Key="lp")["UploadId"]
    for i in range(1, 4):
        s3.upload_part(Bucket=bucket, Key="lp", UploadId=uid, PartNumber=i, Body=b"x" * (i * 10))
    r = s3.list_parts(Bucket=bucket, Key="lp", UploadId=uid)
    assert [p["PartNumber"] for p in r["Parts"]] == [1, 2, 3]
    assert [p["Size"] for p in r["Parts"]] == [10, 20, 30]
    r = s3.list_parts(Bucket=bucket, Key="lp", UploadId=uid, MaxParts=2)
    assert r["IsTruncated"] and [p["PartNumber"] for p in r["Parts"]] == [1, 2]
    r = s3.list_parts(Bucket=bucket, Key="lp", UploadId=uid, PartNumberMarker=r["NextPartNumberMarker"])
    assert [p["PartNumber"] for p in r["Parts"]] == [3]
    s3.abort_multipart_upload(Bucket=bucket, Key="lp", UploadId=uid)


def test_multipart_list_uploads(s3, bucket):
    a = s3.create_multipart_upload(Bucket=bucket, Key="u/a")["UploadId"]
    b = s3.create_multipart_upload(Bucket=bucket, Key="u/b")["UploadId"]
    s3.create_multipart_upload(Bucket=bucket, Key="v/c")
    r = s3.list_multipart_uploads(Bucket=bucket, Prefix="u/")
    assert sorted(u["UploadId"] for u in r["Uploads"]) == sorted([a, b])
    r = s3.list_multipart_uploads(Bucket=bucket, Delimiter="/")
    assert sorted(p["Prefix"] for p in r.get("CommonPrefixes", [])) == ["u/", "v/"]


def test_multipart_abort(s3, bucket):
    uid = s3.create_multipart_upload(Bucket=bucket, Key="ab")["UploadId"]
    s3.upload_part(Bucket=bucket, Key="ab", UploadId=uid, PartNumber=1, Body=b"x")
    s3.abort_multipart_upload(Bucket=bucket, Key="ab", UploadId=uid)
    with pytest.raises(ClientError) as e:
        s3.list_parts(Bucket=bucket, Key="ab", UploadId=uid)
    assert code(e) == "NoSuchUpload"
    with pytest.raises(ClientError) as e:
        s3.head_object(Bucket=bucket, Key="ab")
    assert s3.list_multipart_uploads(Bucket=bucket).get("Uploads", []) == []


def test_multipart_small_part_rejected(s3, bucket):
    uid = s3.create_multipart_upload(Bucket=bucket, Key="sm")["UploadId"]
    e1 = s3.upload_part(Bucket=bucket, Key="sm", UploadId=uid, PartNumber=1, Body=b"small")["ETag"]
    e2 = s3.upload_part(Bucket=bucket, Key="sm", UploadId=uid, PartNumber=2, Body=b"small")["ETag"]
    with pytest.raises(ClientError) as e:
        s3.complete_multipart_upload(Bucket=bucket, Key="sm", UploadId=uid, MultipartUpload={"Parts": [
            {"PartNumber": 1, "ETag": e1}, {"PartNumber": 2, "ETag": e2}]})
    assert code(e) == "EntityTooSmall"


def test_multipart_bad_etag(s3, bucket):
    uid = s3.create_multipart_upload(Bucket=bucket, Key="be")["UploadId"]
    s3.upload_part(Bucket=bucket, Key="be", UploadId=uid, PartNumber=1, Body=b"x")
    with pytest.raises(ClientError) as e:
        s3.complete_multipart_upload(Bucket=bucket, Key="be", UploadId=uid, MultipartUpload={"Parts": [
            {"PartNumber": 1, "ETag": '"00000000000000000000000000000000"'}]})
    assert code(e) == "InvalidPart"


def test_multipart_bad_order(s3, bucket):
    uid = s3.create_multipart_upload(Bucket=bucket, Key="bo")["UploadId"]
    e1 = s3.upload_part(Bucket=bucket, Key="bo", UploadId=uid, PartNumber=1, Body=b"x" * (5 * MB))["ETag"]
    e2 = s3.upload_part(Bucket=bucket, Key="bo", UploadId=uid, PartNumber=2, Body=b"y")["ETag"]
    with pytest.raises(ClientError) as e:
        s3.complete_multipart_upload(Bucket=bucket, Key="bo", UploadId=uid, MultipartUpload={"Parts": [
            {"PartNumber": 2, "ETag": e2}, {"PartNumber": 1, "ETag": e1}]})
    assert code(e) == "InvalidPartOrder"


def test_multipart_no_such_upload(s3, bucket):
    with pytest.raises(ClientError) as e:
        s3.upload_part(Bucket=bucket, Key="x", UploadId="nonexistent", PartNumber=1, Body=b"x")
    assert code(e) == "NoSuchUpload"


def test_multipart_overwrite_part(s3, bucket):
    uid = s3.create_multipart_upload(Bucket=bucket, Key="ow")["UploadId"]
    s3.upload_part(Bucket=bucket, Key="ow", UploadId=uid, PartNumber=1, Body=b"first")
    et = s3.upload_part(Bucket=bucket, Key="ow", UploadId=uid, PartNumber=1, Body=b"second")["ETag"]
    s3.complete_multipart_upload(Bucket=bucket, Key="ow", UploadId=uid, MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": et}]})
    assert s3.get_object(Bucket=bucket, Key="ow")["Body"].read() == b"second"


def test_upload_part_copy(s3, bucket):
    src = os.urandom(6 * MB)
    s3.put_object(Bucket=bucket, Key="src", Body=src)
    uid = s3.create_multipart_upload(Bucket=bucket, Key="pc")["UploadId"]
    r1 = s3.upload_part_copy(Bucket=bucket, Key="pc", UploadId=uid, PartNumber=1, CopySource={"Bucket": bucket, "Key": "src"},
                             CopySourceRange=f"bytes=0-{5 * MB - 1}")
    r2 = s3.upload_part_copy(Bucket=bucket, Key="pc", UploadId=uid, PartNumber=2, CopySource={"Bucket": bucket, "Key": "src"})
    s3.complete_multipart_upload(Bucket=bucket, Key="pc", UploadId=uid, MultipartUpload={"Parts": [
        {"PartNumber": 1, "ETag": r1["CopyPartResult"]["ETag"]}, {"PartNumber": 2, "ETag": r2["CopyPartResult"]["ETag"]}]})
    assert s3.get_object(Bucket=bucket, Key="pc")["Body"].read() == src[:5 * MB] + src


def test_transfer_manager(s3, bucket, tmp_path):
    from boto3.s3.transfer import TransferConfig
    f = tmp_path / "big"
    data = os.urandom(20 * MB + 7)
    f.write_bytes(data)
    cfg = TransferConfig(multipart_threshold=5 * MB, multipart_chunksize=5 * MB, max_concurrency=8)
    s3.upload_file(str(f), bucket, "tm", Config=cfg)
    out = tmp_path / "out"
    s3.download_file(bucket, "tm", str(out), Config=cfg)
    assert out.read_bytes() == data


@pytest.mark.xfail(reason="GET/HEAD ?partNumber is not implemented yet", strict=False)
def test_get_part_number(s3, bucket):
    parts = [os.urandom(5 * MB), b"tail"]
    uid = s3.create_multipart_upload(Bucket=bucket, Key="pn")["UploadId"]
    done = [{"PartNumber": i, "ETag": s3.upload_part(Bucket=bucket, Key="pn", UploadId=uid, PartNumber=i, Body=p)["ETag"]}
            for i, p in enumerate(parts, 1)]
    s3.complete_multipart_upload(Bucket=bucket, Key="pn", UploadId=uid, MultipartUpload={"Parts": done})
    g = s3.get_object(Bucket=bucket, Key="pn", PartNumber=2)
    assert g["Body"].read() == b"tail"
    assert g["PartsCount"] == 2


# Versioning

def test_versioning_status(s3, bucket):
    assert "Status" not in s3.get_bucket_versioning(Bucket=bucket)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    assert s3.get_bucket_versioning(Bucket=bucket)["Status"] == "Enabled"
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Suspended"})
    assert s3.get_bucket_versioning(Bucket=bucket)["Status"] == "Suspended"


def test_versions_and_delete_marker(s3, bucket):
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    v1 = s3.put_object(Bucket=bucket, Key="v", Body=b"one")["VersionId"]
    v2 = s3.put_object(Bucket=bucket, Key="v", Body=b"two")["VersionId"]
    assert v1 != v2
    assert s3.get_object(Bucket=bucket, Key="v")["Body"].read() == b"two"
    assert s3.get_object(Bucket=bucket, Key="v", VersionId=v1)["Body"].read() == b"one"
    d = s3.delete_object(Bucket=bucket, Key="v")
    assert d["DeleteMarker"] is True
    with pytest.raises(ClientError) as e:
        s3.get_object(Bucket=bucket, Key="v")
    assert code(e) == "NoSuchKey"
    lv = s3.list_object_versions(Bucket=bucket)
    assert sorted(v["VersionId"] for v in lv["Versions"]) == sorted([v1, v2])
    assert len(lv["DeleteMarkers"]) == 1 and lv["DeleteMarkers"][0]["IsLatest"]
    s3.delete_object(Bucket=bucket, Key="v", VersionId=d["VersionId"])
    assert s3.get_object(Bucket=bucket, Key="v")["Body"].read() == b"two"
    s3.delete_object(Bucket=bucket, Key="v", VersionId=v2)
    assert s3.get_object(Bucket=bucket, Key="v")["Body"].read() == b"one"


def test_get_missing_version(s3, bucket):
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_object(Bucket=bucket, Key="v", Body=b"x")
    with pytest.raises(ClientError) as e:
        s3.get_object(Bucket=bucket, Key="v", VersionId="00000000000000000000000000000000")
    assert code(e) in ("NoSuchVersion", "InvalidArgument")


def test_suspended_null_version(s3, bucket):
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_object(Bucket=bucket, Key="n", Body=b"v1")
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Suspended"})
    r = s3.put_object(Bucket=bucket, Key="n", Body=b"null1")
    assert r.get("VersionId", "null") == "null"
    s3.put_object(Bucket=bucket, Key="n", Body=b"null2")
    vs = s3.list_object_versions(Bucket=bucket)["Versions"]
    assert len(vs) == 2
    assert s3.get_object(Bucket=bucket, Key="n", VersionId="null")["Body"].read() == b"null2"


def test_list_versions_paging(s3, bucket):
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    for k in ("a", "b", "c"):
        for _ in range(2):
            s3.put_object(Bucket=bucket, Key=k, Body=b"x")
    seen = []
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket, PaginationConfig={"PageSize": 2}):
        seen += [(v["Key"], v["VersionId"]) for v in page.get("Versions", [])]
    assert len(seen) == 6 and len(set(seen)) == 6


def test_versioned_copy_source_version(s3, bucket):
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    v1 = s3.put_object(Bucket=bucket, Key="s", Body=b"old")["VersionId"]
    s3.put_object(Bucket=bucket, Key="s", Body=b"new")
    s3.copy_object(Bucket=bucket, Key="d", CopySource={"Bucket": bucket, "Key": "s", "VersionId": v1})
    assert s3.get_object(Bucket=bucket, Key="d")["Body"].read() == b"old"


def test_delete_objects_versioned(s3, bucket):
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    v = s3.put_object(Bucket=bucket, Key="k", Body=b"x")["VersionId"]
    r = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": "k"}]})
    assert r["Deleted"][0]["DeleteMarker"] is True
    r = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": "k", "VersionId": v}]})
    assert r["Deleted"][0]["VersionId"] == v


# Object lock

def test_object_lock_configuration(s3, lock_bucket):
    assert s3.get_bucket_versioning(Bucket=lock_bucket)["Status"] == "Enabled"
    s3.put_object_lock_configuration(Bucket=lock_bucket, ObjectLockConfiguration={
        "ObjectLockEnabled": "Enabled", "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Days": 1}}})
    cfg = s3.get_object_lock_configuration(Bucket=lock_bucket)["ObjectLockConfiguration"]
    assert cfg["Rule"]["DefaultRetention"] == {"Mode": "GOVERNANCE", "Days": 1}
    v = s3.put_object(Bucket=lock_bucket, Key="d", Body=b"x")["VersionId"]
    assert s3.head_object(Bucket=lock_bucket, Key="d")["ObjectLockMode"] == "GOVERNANCE"
    with pytest.raises(ClientError):
        s3.delete_object(Bucket=lock_bucket, Key="d", VersionId=v)


def test_lock_config_on_unlocked_bucket(s3, bucket):
    with pytest.raises(ClientError) as e:
        s3.get_object_lock_configuration(Bucket=bucket)
    assert code(e) == "ObjectLockConfigurationNotFoundError"


def test_governance_retention(s3, lock_bucket):
    until = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    v = s3.put_object(Bucket=lock_bucket, Key="g", Body=b"x", ObjectLockMode="GOVERNANCE",
                      ObjectLockRetainUntilDate=until)["VersionId"]
    r = s3.get_object_retention(Bucket=lock_bucket, Key="g")["Retention"]
    assert r["Mode"] == "GOVERNANCE"
    with pytest.raises(ClientError) as e:
        s3.delete_object(Bucket=lock_bucket, Key="g", VersionId=v)
    assert code(e) == "AccessDenied"
    s3.delete_object(Bucket=lock_bucket, Key="g", VersionId=v, BypassGovernanceRetention=True)


def test_compliance_retention(s3, lock_bucket):
    until = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=30)
    v = s3.put_object(Bucket=lock_bucket, Key="c", Body=b"x", ObjectLockMode="COMPLIANCE",
                      ObjectLockRetainUntilDate=until)["VersionId"]
    with pytest.raises(ClientError):
        s3.delete_object(Bucket=lock_bucket, Key="c", VersionId=v, BypassGovernanceRetention=True)
    with pytest.raises(ClientError):
        s3.put_object_retention(Bucket=lock_bucket, Key="c", VersionId=v, Retention={
            "Mode": "GOVERNANCE", "RetainUntilDate": until})
    # Non-version delete just adds a marker.
    assert s3.delete_object(Bucket=lock_bucket, Key="c")["DeleteMarker"] is True


def test_legal_hold(s3, lock_bucket):
    v = s3.put_object(Bucket=lock_bucket, Key="h", Body=b"x", ObjectLockLegalHoldStatus="ON")["VersionId"]
    assert s3.get_object_legal_hold(Bucket=lock_bucket, Key="h")["LegalHold"]["Status"] == "ON"
    with pytest.raises(ClientError):
        s3.delete_object(Bucket=lock_bucket, Key="h", VersionId=v, BypassGovernanceRetention=True)
    s3.put_object_legal_hold(Bucket=lock_bucket, Key="h", LegalHold={"Status": "OFF"})
    s3.delete_object(Bucket=lock_bucket, Key="h", VersionId=v)


def test_retention_requires_lock_bucket(s3, bucket):
    until = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    with pytest.raises(ClientError) as e:
        s3.put_object(Bucket=bucket, Key="r", Body=b"x", ObjectLockMode="GOVERNANCE", ObjectLockRetainUntilDate=until)
    assert code(e) == "InvalidRequest"
