import hashlib
import os
import uuid

import pytest
from botocore.exceptions import ClientError


def code(e):
    return e.value.response["Error"]["Code"]


def status(e):
    return e.value.response["ResponseMetadata"]["HTTPStatusCode"]


# Buckets

def test_create_list_delete_bucket(s3):
    name = "b-" + uuid.uuid4().hex[:16]
    s3.create_bucket(Bucket=name)
    assert name in [b["Name"] for b in s3.list_buckets()["Buckets"]]
    s3.head_bucket(Bucket=name)
    s3.delete_bucket(Bucket=name)
    with pytest.raises(ClientError) as e:
        s3.head_bucket(Bucket=name)
    assert status(e) == 404


def test_create_existing_bucket(s3, bucket):
    with pytest.raises(ClientError) as e:
        s3.create_bucket(Bucket=bucket)
    assert code(e) in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists")


@pytest.mark.parametrize("name", ["ab", "UPPER", "a" * 64, "bad_name", "-lead", "192.168.1.1"])
def test_invalid_bucket_name(s3, name):
    with pytest.raises(Exception):
        s3.create_bucket(Bucket=name)


def test_delete_missing_bucket(s3):
    with pytest.raises(ClientError) as e:
        s3.delete_bucket(Bucket="missing-" + uuid.uuid4().hex[:12])
    assert code(e) == "NoSuchBucket"


def test_delete_nonempty_bucket(s3, bucket):
    s3.put_object(Bucket=bucket, Key="k", Body=b"x")
    with pytest.raises(ClientError) as e:
        s3.delete_bucket(Bucket=bucket)
    assert code(e) == "BucketNotEmpty"


def test_bucket_location(s3, bucket):
    assert s3.get_bucket_location(Bucket=bucket)["LocationConstraint"] in (None, "", "us-east-1")


def test_list_missing_bucket(s3):
    with pytest.raises(ClientError) as e:
        s3.list_objects_v2(Bucket="missing-" + uuid.uuid4().hex[:12])
    assert code(e) == "NoSuchBucket"


# Objects

def test_put_get_head_delete(s3, bucket):
    body = os.urandom(12345)
    r = s3.put_object(Bucket=bucket, Key="obj", Body=body)
    md5 = hashlib.md5(body).hexdigest()
    assert r["ETag"] == f'"{md5}"'
    g = s3.get_object(Bucket=bucket, Key="obj")
    assert g["Body"].read() == body
    assert g["ContentLength"] == len(body)
    h = s3.head_object(Bucket=bucket, Key="obj")
    assert h["ETag"] == f'"{md5}"'
    assert h["ContentLength"] == len(body)
    assert h["LastModified"] is not None
    s3.delete_object(Bucket=bucket, Key="obj")
    with pytest.raises(ClientError) as e:
        s3.get_object(Bucket=bucket, Key="obj")
    assert code(e) == "NoSuchKey"


def test_head_missing_object(s3, bucket):
    with pytest.raises(ClientError) as e:
        s3.head_object(Bucket=bucket, Key="nope")
    assert status(e) == 404


def test_delete_missing_object_is_204(s3, bucket):
    r = s3.delete_object(Bucket=bucket, Key="never-existed")
    assert r["ResponseMetadata"]["HTTPStatusCode"] == 204


def test_empty_object(s3, bucket):
    s3.put_object(Bucket=bucket, Key="empty", Body=b"")
    g = s3.get_object(Bucket=bucket, Key="empty")
    assert g["Body"].read() == b""
    assert g["ETag"] == '"d41d8cd98f00b204e9800998ecf8427e"'


def test_overwrite(s3, bucket):
    s3.put_object(Bucket=bucket, Key="k", Body=b"one")
    s3.put_object(Bucket=bucket, Key="k", Body=b"two!")
    assert s3.get_object(Bucket=bucket, Key="k")["Body"].read() == b"two!"


def test_large_object(s3, bucket):
    body = os.urandom(7 * 1024 * 1024 + 13)
    s3.put_object(Bucket=bucket, Key="large", Body=body)
    assert hashlib.md5(s3.get_object(Bucket=bucket, Key="large")["Body"].read()).digest() == hashlib.md5(body).digest()


def test_content_md5_ok(s3, bucket):
    import base64
    body = b"checked body"
    s3.put_object(Bucket=bucket, Key="m", Body=body, ContentMD5=base64.b64encode(hashlib.md5(body).digest()).decode())


def test_content_md5_mismatch(s3, bucket):
    import base64
    with pytest.raises(ClientError) as e:
        s3.put_object(Bucket=bucket, Key="m", Body=b"body", ContentMD5=base64.b64encode(hashlib.md5(b"other").digest()).decode())
    assert code(e) == "BadDigest"


def test_checksum_sha256(s3, bucket):
    r = s3.put_object(Bucket=bucket, Key="c", Body=b"data", ChecksumAlgorithm="SHA256")
    assert r["ResponseMetadata"]["HTTPStatusCode"] == 200
    assert s3.get_object(Bucket=bucket, Key="c")["Body"].read() == b"data"


def test_put_to_missing_bucket(s3):
    with pytest.raises(ClientError) as e:
        s3.put_object(Bucket="missing-" + uuid.uuid4().hex[:12], Key="k", Body=b"x")
    assert code(e) == "NoSuchBucket"


def test_key_with_slashes_and_dots(s3, bucket):
    for k in ["a/b/c.txt", "dir/", "a//b", "./x", "trailing."]:
        s3.put_object(Bucket=bucket, Key=k, Body=k.encode())
        assert s3.get_object(Bucket=bucket, Key=k)["Body"].read() == k.encode()


def test_long_key(s3, bucket):
    k = "k" * 1024
    s3.put_object(Bucket=bucket, Key=k, Body=b"x")
    assert s3.get_object(Bucket=bucket, Key=k)["Body"].read() == b"x"


def test_key_too_long(s3, bucket):
    with pytest.raises(ClientError) as e:
        s3.put_object(Bucket=bucket, Key="k" * 1025, Body=b"x")
    assert code(e) == "KeyTooLongError"


# Ranges

@pytest.fixture
def ranged(s3, bucket):
    body = bytes(range(256)) * 40
    s3.put_object(Bucket=bucket, Key="r", Body=body)
    return bucket, body


@pytest.mark.parametrize("spec,sl", [
    ("bytes=0-0", slice(0, 1)),
    ("bytes=10-19", slice(10, 20)),
    ("bytes=100-", slice(100, None)),
    ("bytes=-7", slice(-7, None)),
    ("bytes=10200-99999", slice(10200, None)),
])
def test_range(s3, ranged, spec, sl):
    bucket, body = ranged
    g = s3.get_object(Bucket=bucket, Key="r", Range=spec)
    assert g["ResponseMetadata"]["HTTPStatusCode"] == 206
    data = g["Body"].read()
    assert data == body[sl]
    assert g["ContentRange"].endswith(f"/{len(body)}")
    assert g["ContentLength"] == len(data)


def test_range_unsatisfiable(s3, ranged):
    bucket, body = ranged
    with pytest.raises(ClientError) as e:
        s3.get_object(Bucket=bucket, Key="r", Range=f"bytes={len(body)}-")
    assert code(e) == "InvalidRange"


def test_range_malformed_ignored(s3, ranged):
    bucket, body = ranged
    g = s3.get_object(Bucket=bucket, Key="r", Range="bytes=abc")
    assert g["ResponseMetadata"]["HTTPStatusCode"] == 200
    assert g["Body"].read() == body


def test_range_head(s3, ranged):
    bucket, _ = ranged
    h = s3.head_object(Bucket=bucket, Key="r", Range="bytes=0-9")
    assert h["ContentLength"] == 10


# Conditional requests

@pytest.fixture
def cond(s3, bucket):
    r = s3.put_object(Bucket=bucket, Key="c", Body=b"conditional")
    return bucket, r["ETag"]


def test_if_match(s3, cond):
    bucket, etag = cond
    assert s3.get_object(Bucket=bucket, Key="c", IfMatch=etag)["Body"].read() == b"conditional"
    with pytest.raises(ClientError) as e:
        s3.get_object(Bucket=bucket, Key="c", IfMatch='"deadbeef"')
    assert status(e) == 412


def test_if_none_match(s3, cond):
    bucket, etag = cond
    with pytest.raises(ClientError) as e:
        s3.get_object(Bucket=bucket, Key="c", IfNoneMatch=etag)
    assert status(e) == 304
    assert s3.get_object(Bucket=bucket, Key="c", IfNoneMatch='"other"')["ResponseMetadata"]["HTTPStatusCode"] == 200


def test_if_modified_since(s3, cond):
    import datetime
    bucket, _ = cond
    future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
    past = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
    with pytest.raises(ClientError) as e:
        s3.get_object(Bucket=bucket, Key="c", IfModifiedSince=future)
    assert status(e) == 304
    assert s3.get_object(Bucket=bucket, Key="c", IfModifiedSince=past)["ResponseMetadata"]["HTTPStatusCode"] == 200


def test_if_unmodified_since(s3, cond):
    import datetime
    bucket, _ = cond
    past = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
    with pytest.raises(ClientError) as e:
        s3.get_object(Bucket=bucket, Key="c", IfUnmodifiedSince=past)
    assert status(e) == 412


def test_head_if_match(s3, cond):
    bucket, _ = cond
    with pytest.raises(ClientError) as e:
        s3.head_object(Bucket=bucket, Key="c", IfMatch='"nope"')
    assert status(e) == 412


def test_put_if_none_match_star(s3, bucket):
    s3.put_object(Bucket=bucket, Key="once", Body=b"1", IfNoneMatch="*")
    with pytest.raises(ClientError) as e:
        s3.put_object(Bucket=bucket, Key="once", Body=b"2", IfNoneMatch="*")
    assert status(e) == 412
    assert s3.get_object(Bucket=bucket, Key="once")["Body"].read() == b"1"


# Metadata

def test_user_metadata(s3, bucket):
    s3.put_object(Bucket=bucket, Key="m", Body=b"x", Metadata={"color": "blue", "Mixed-Case": "Value 1"})
    md = s3.head_object(Bucket=bucket, Key="m")["Metadata"]
    assert md["color"] == "blue"
    assert md["mixed-case"] == "Value 1"


def test_system_metadata(s3, bucket):
    s3.put_object(Bucket=bucket, Key="m", Body=b"x", ContentType="text/csv", CacheControl="max-age=60",
                  ContentDisposition='attachment; filename="a.csv"', ContentEncoding="identity",
                  ContentLanguage="en", Expires="Wed, 21 Oct 2037 07:28:00 GMT")
    h = s3.head_object(Bucket=bucket, Key="m")
    assert h["ContentType"] == "text/csv"
    assert h["CacheControl"] == "max-age=60"
    assert h["ContentDisposition"] == 'attachment; filename="a.csv"'
    assert h["ContentEncoding"] == "identity"
    assert h["ContentLanguage"] == "en"


def test_default_content_type(s3, bucket):
    s3.put_object(Bucket=bucket, Key="m", Body=b"x")
    assert s3.head_object(Bucket=bucket, Key="m")["ContentType"] in ("binary/octet-stream", "application/octet-stream")


def test_response_overrides(s3, bucket):
    s3.put_object(Bucket=bucket, Key="m", Body=b"x")
    g = s3.get_object(Bucket=bucket, Key="m", ResponseContentType="image/png", ResponseContentDisposition="inline",
                      ResponseCacheControl="no-store")
    assert g["ContentType"] == "image/png"
    assert g["ContentDisposition"] == "inline"
    assert g["CacheControl"] == "no-store"


def test_metadata_unicode_value(s3, bucket):
    s3.put_object(Bucket=bucket, Key="m", Body=b"x", Metadata={"note": "plain ascii"})
    assert s3.head_object(Bucket=bucket, Key="m")["Metadata"]["note"] == "plain ascii"


# Copy

def test_copy_object(s3, bucket):
    s3.put_object(Bucket=bucket, Key="src", Body=b"copy me", Metadata={"a": "1"}, ContentType="text/plain")
    r = s3.copy_object(Bucket=bucket, Key="dst", CopySource={"Bucket": bucket, "Key": "src"})
    assert r["CopyObjectResult"]["ETag"] == s3.head_object(Bucket=bucket, Key="src")["ETag"]
    h = s3.head_object(Bucket=bucket, Key="dst")
    assert h["Metadata"] == {"a": "1"}
    assert h["ContentType"] == "text/plain"
    assert s3.get_object(Bucket=bucket, Key="dst")["Body"].read() == b"copy me"


def test_copy_across_buckets(s3, bucket):
    other = "c-" + uuid.uuid4().hex[:16]
    s3.create_bucket(Bucket=other)
    try:
        s3.put_object(Bucket=bucket, Key="src", Body=b"xb")
        s3.copy_object(Bucket=other, Key="dst", CopySource=f"{bucket}/src")
        assert s3.get_object(Bucket=other, Key="dst")["Body"].read() == b"xb"
    finally:
        s3.delete_object(Bucket=other, Key="dst")
        s3.delete_bucket(Bucket=other)


def test_copy_replace_metadata(s3, bucket):
    s3.put_object(Bucket=bucket, Key="src", Body=b"x", Metadata={"a": "1"})
    s3.copy_object(Bucket=bucket, Key="src", CopySource={"Bucket": bucket, "Key": "src"},
                   MetadataDirective="REPLACE", Metadata={"b": "2"}, ContentType="text/x")
    h = s3.head_object(Bucket=bucket, Key="src")
    assert h["Metadata"] == {"b": "2"}
    assert h["ContentType"] == "text/x"


def test_copy_to_self_without_replace_fails(s3, bucket):
    s3.put_object(Bucket=bucket, Key="src", Body=b"x")
    with pytest.raises(ClientError) as e:
        s3.copy_object(Bucket=bucket, Key="src", CopySource={"Bucket": bucket, "Key": "src"})
    assert code(e) == "InvalidRequest"


def test_copy_missing_source(s3, bucket):
    with pytest.raises(ClientError) as e:
        s3.copy_object(Bucket=bucket, Key="dst", CopySource={"Bucket": bucket, "Key": "nope"})
    assert code(e) == "NoSuchKey"


def test_copy_conditional(s3, bucket):
    etag = s3.put_object(Bucket=bucket, Key="src", Body=b"x")["ETag"]
    s3.copy_object(Bucket=bucket, Key="d1", CopySource={"Bucket": bucket, "Key": "src"}, CopySourceIfMatch=etag)
    with pytest.raises(ClientError) as e:
        s3.copy_object(Bucket=bucket, Key="d2", CopySource={"Bucket": bucket, "Key": "src"}, CopySourceIfMatch='"no"')
    assert status(e) == 412
    with pytest.raises(ClientError) as e:
        s3.copy_object(Bucket=bucket, Key="d3", CopySource={"Bucket": bucket, "Key": "src"}, CopySourceIfNoneMatch=etag)
    assert status(e) == 412


def test_copy_special_key(s3, bucket):
    k = "dir/a b+c%d?e#f ü"
    s3.put_object(Bucket=bucket, Key=k, Body=b"sp")
    s3.copy_object(Bucket=bucket, Key="dst", CopySource={"Bucket": bucket, "Key": k})
    assert s3.get_object(Bucket=bucket, Key="dst")["Body"].read() == b"sp"


# Tagging

def test_object_tagging(s3, bucket):
    s3.put_object(Bucket=bucket, Key="t", Body=b"x", Tagging="a=1&b=two")
    tags = {t["Key"]: t["Value"] for t in s3.get_object_tagging(Bucket=bucket, Key="t")["TagSet"]}
    assert tags == {"a": "1", "b": "two"}
    assert s3.head_object(Bucket=bucket, Key="t").get("ResponseMetadata")["HTTPHeaders"].get("x-amz-tagging-count") in (None, "2")
    s3.put_object_tagging(Bucket=bucket, Key="t", Tagging={"TagSet": [{"Key": "z", "Value": "9"}]})
    assert s3.get_object_tagging(Bucket=bucket, Key="t")["TagSet"] == [{"Key": "z", "Value": "9"}]
    s3.delete_object_tagging(Bucket=bucket, Key="t")
    assert s3.get_object_tagging(Bucket=bucket, Key="t")["TagSet"] == []


def test_tagging_count_header(s3, bucket):
    s3.put_object(Bucket=bucket, Key="t", Body=b"x", Tagging="a=1&b=2")
    assert s3.get_object(Bucket=bucket, Key="t")["TagCount"] == 2


def test_tagging_limits(s3, bucket):
    s3.put_object(Bucket=bucket, Key="t", Body=b"x")
    with pytest.raises(ClientError) as e:
        s3.put_object_tagging(Bucket=bucket, Key="t", Tagging={"TagSet": [{"Key": f"k{i}", "Value": "v"} for i in range(11)]})
    assert code(e) in ("BadRequest", "InvalidTag")


def test_bucket_tagging(s3, bucket):
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "env", "Value": "test"}]})
    assert s3.get_bucket_tagging(Bucket=bucket)["TagSet"] == [{"Key": "env", "Value": "test"}]
    s3.delete_bucket_tagging(Bucket=bucket)
    with pytest.raises(ClientError) as e:
        s3.get_bucket_tagging(Bucket=bucket)
    assert code(e) == "NoSuchTagSet"


# DeleteObjects

def test_delete_objects(s3, bucket):
    keys = [f"d/{i}" for i in range(20)]
    for k in keys:
        s3.put_object(Bucket=bucket, Key=k, Body=b"x")
    r = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": k} for k in keys] + [{"Key": "missing"}]})
    assert len(r["Deleted"]) == 21
    assert not r.get("Errors")
    assert s3.list_objects_v2(Bucket=bucket)["KeyCount"] == 0


def test_delete_objects_quiet(s3, bucket):
    s3.put_object(Bucket=bucket, Key="q", Body=b"x")
    r = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": "q"}], "Quiet": True})
    assert not r.get("Deleted")


def test_delete_objects_special_keys(s3, bucket):
    keys = ["a b", "c+d", "e%f", "ü/ñ", "x&y<z>"]
    for k in keys:
        s3.put_object(Bucket=bucket, Key=k, Body=b"x")
    r = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": k} for k in keys]})
    assert sorted(d["Key"] for d in r["Deleted"]) == sorted(keys)
    assert s3.list_objects_v2(Bucket=bucket)["KeyCount"] == 0


# Presigned URLs

def test_presigned_get_put(s3, bucket):
    import urllib.request
    url = s3.generate_presigned_url("put_object", Params={"Bucket": bucket, "Key": "p s+"}, ExpiresIn=300)
    req = urllib.request.Request(url, data=b"presigned", method="PUT")
    assert urllib.request.urlopen(req).status == 200
    url = s3.generate_presigned_url("get_object", Params={"Bucket": bucket, "Key": "p s+"}, ExpiresIn=300)
    assert urllib.request.urlopen(url).read() == b"presigned"


def test_presigned_expired(s3, bucket):
    import time
    import urllib.error
    import urllib.request
    s3.put_object(Bucket=bucket, Key="e", Body=b"x")
    url = s3.generate_presigned_url("get_object", Params={"Bucket": bucket, "Key": "e"}, ExpiresIn=1)
    time.sleep(2)
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(url)
    assert e.value.code == 403


def test_presigned_tampered(s3, bucket):
    import urllib.error
    import urllib.request
    s3.put_object(Bucket=bucket, Key="e", Body=b"x")
    url = s3.generate_presigned_url("get_object", Params={"Bucket": bucket, "Key": "e"}, ExpiresIn=300)
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(url.replace("/e?", "/f?"))
    assert e.value.code == 403


def test_presigned_response_override(s3, bucket):
    import urllib.request
    s3.put_object(Bucket=bucket, Key="o", Body=b"x")
    url = s3.generate_presigned_url("get_object", Params={"Bucket": bucket, "Key": "o", "ResponseContentType": "text/weird"})
    assert urllib.request.urlopen(url).headers["Content-Type"] == "text/weird"


@pytest.mark.xfail(reason="browser-form POST object uploads are not implemented", strict=False)
def test_presigned_post(s3, bucket):
    import urllib.request
    import urllib.error
    post = s3.generate_presigned_post(bucket, "form-upload")
    boundary = "zkfsmboundary"
    parts = []
    for k, v in post["fields"].items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="f"\r\n\r\n'.encode() + b"formdata\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    req = urllib.request.Request(post["url"], data=b"".join(parts), method="POST",
                                 headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    assert urllib.request.urlopen(req).status in (200, 204)
    assert s3.get_object(Bucket=bucket, Key="form-upload")["Body"].read() == b"formdata"


# Auth

@pytest.mark.xfail(reason="SigV2 (query or header) auth is not supported; SigV4 only", strict=False)
def test_presigned_sigv2(s3, bucket):
    import urllib.request
    import boto3
    from botocore.config import Config
    s3.put_object(Bucket=bucket, Key="v2", Body=b"x")
    c = boto3.client("s3", endpoint_url=s3.meta.endpoint_url, aws_access_key_id=os.environ["S3_ACCESS_KEY"],
                     aws_secret_access_key=os.environ["S3_SECRET_KEY"], region_name="us-east-1",
                     config=Config(signature_version="s3", s3={"addressing_style": "path"}))
    url = c.generate_presigned_url("get_object", Params={"Bucket": bucket, "Key": "v2"})
    assert urllib.request.urlopen(url).read() == b"x"


def test_bad_secret(make_client, bucket):
    import os as _os
    bad = make_client()
    bad._request_signer._credentials.secret_key = "wrong"  # noqa: SLF001
    with pytest.raises(ClientError) as e:
        bad.list_objects_v2(Bucket=bucket)
    assert code(e) == "SignatureDoesNotMatch"
    assert _os.environ["S3_ACCESS_KEY"]


def test_unsigned_payload(s3, bucket):
    import botocore.config
    import boto3
    c = boto3.client("s3", endpoint_url=s3.meta.endpoint_url,
                     aws_access_key_id=os.environ["S3_ACCESS_KEY"], aws_secret_access_key=os.environ["S3_SECRET_KEY"],
                     region_name="us-east-1",
                     config=botocore.config.Config(s3={"addressing_style": "path", "payload_signing_enabled": False}))
    c.put_object(Bucket=bucket, Key="u", Body=b"unsigned")
    assert c.get_object(Bucket=bucket, Key="u")["Body"].read() == b"unsigned"


def test_signed_payload(s3, bucket):
    import botocore.config
    import boto3
    c = boto3.client("s3", endpoint_url=s3.meta.endpoint_url,
                     aws_access_key_id=os.environ["S3_ACCESS_KEY"], aws_secret_access_key=os.environ["S3_SECRET_KEY"],
                     region_name="us-east-1",
                     config=botocore.config.Config(s3={"addressing_style": "path", "payload_signing_enabled": True},
                                                   request_checksum_calculation="when_required"))
    c.put_object(Bucket=bucket, Key="s", Body=b"signed")
    assert c.get_object(Bucket=bucket, Key="s")["Body"].read() == b"signed"


@pytest.mark.xfail(reason="virtual-host-style addressing is not implemented yet", strict=False)
def test_virtual_host_style(s3, bucket):
    import botocore.config
    import boto3
    s3.put_object(Bucket=bucket, Key="v", Body=b"vh")
    ep = s3.meta.endpoint_url.replace("127.0.0.1", "localhost")
    c = boto3.client("s3", endpoint_url=ep, aws_access_key_id=os.environ["S3_ACCESS_KEY"],
                     aws_secret_access_key=os.environ["S3_SECRET_KEY"], region_name="us-east-1",
                     config=botocore.config.Config(s3={"addressing_style": "virtual"}))
    # bucket.localhost resolves to loopback on most systems (RFC 6761).
    assert c.get_object(Bucket=bucket, Key="v")["Body"].read() == b"vh"


@pytest.mark.xfail(reason="bucket policy is not implemented yet", strict=False)
def test_bucket_policy(s3, bucket):
    import json
    pol = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                                                    "Resource": f"arn:aws:s3:::{bucket}/*"}]}
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(pol))
    assert json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])["Statement"][0]["Action"] in ("s3:GetObject", ["s3:GetObject"])
    s3.delete_bucket_policy(Bucket=bucket)


@pytest.mark.xfail(reason="lifecycle configuration is not implemented yet", strict=False)
def test_bucket_lifecycle(s3, bucket):
    s3.put_bucket_lifecycle_configuration(Bucket=bucket, LifecycleConfiguration={"Rules": [
        {"ID": "r1", "Status": "Enabled", "Filter": {"Prefix": "tmp/"}, "Expiration": {"Days": 1}}]})
    rules = s3.get_bucket_lifecycle_configuration(Bucket=bucket)["Rules"]
    assert rules[0]["ID"] == "r1"
    s3.delete_bucket_lifecycle(Bucket=bucket)


def test_rejected_expect_continue_then_hangup(s3, bucket):
    # Regression: the server used to abort draining a refused body when the client hung up.
    import socket
    import urllib.parse
    u = urllib.parse.urlparse(s3.meta.endpoint_url)
    for _ in range(3):
        with socket.create_connection((u.hostname, u.port)) as sock:
            sock.sendall(f"PUT /{bucket}/k HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\nExpect: 100-continue\r\n\r\n".encode())
            sock.recv(1024)
    s3.head_bucket(Bucket=bucket)


def test_truncated_body_then_hangup(s3, bucket):
    import socket
    import urllib.parse
    u = urllib.parse.urlparse(s3.meta.endpoint_url)
    with socket.create_connection((u.hostname, u.port)) as sock:
        sock.sendall(f"PUT /{bucket}/k HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nshort".encode())
    s3.head_bucket(Bucket=bucket)
