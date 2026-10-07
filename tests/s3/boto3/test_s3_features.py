"""ACLs, ownership, public access block, CORS, website, checksums, attributes, conditional
writes, POST policies, SigV2, and the small bucket configuration APIs."""
import base64
import hashlib
import http.client
import json
import os
import urllib.parse
import urllib.request
import zlib

import boto3
import pytest
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError


def code(e):
    return e.value.response["Error"]["Code"]


def status(e):
    return e.value.response["ResponseMetadata"]["HTTPStatusCode"]


def anon():
    return boto3.client("s3", endpoint_url=os.environ["S3_ENDPOINT"], region_name="us-east-1",
                        config=Config(signature_version=UNSIGNED, s3={"addressing_style": "path"}, retries={"max_attempts": 1}))


def raw(method, path, headers=None, body=None, host=None):
    u = urllib.parse.urlparse(os.environ["S3_ENDPOINT"])
    c = http.client.HTTPConnection(u.hostname, u.port, timeout=10)
    h = dict(headers or {})
    if host:
        h["Host"] = f"{host}:{u.port}"
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, dict((k.lower(), v) for k, v in r.getheaders()), data


# ACLs


def test_canned_acl_public_read_allows_anonymous(s3, bucket):
    s3.put_object(Bucket=bucket, Key="o", Body=b"pub")
    with pytest.raises(ClientError) as e:
        anon().get_object(Bucket=bucket, Key="o")
    assert status(e) == 403
    s3.put_object_acl(Bucket=bucket, Key="o", ACL="public-read")
    assert anon().get_object(Bucket=bucket, Key="o")["Body"].read() == b"pub"
    grants = s3.get_object_acl(Bucket=bucket, Key="o")["Grants"]
    assert {g["Permission"] for g in grants} == {"FULL_CONTROL", "READ"}
    # Listing still needs bucket READ.
    with pytest.raises(ClientError):
        anon().list_objects_v2(Bucket=bucket)
    s3.put_bucket_acl(Bucket=bucket, ACL="public-read")
    assert [o["Key"] for o in anon().list_objects_v2(Bucket=bucket)["Contents"]] == ["o"]
    s3.put_bucket_acl(Bucket=bucket, ACL="private")
    assert len(s3.get_bucket_acl(Bucket=bucket)["Grants"]) == 1


def test_acl_grants_and_errors(s3, bucket):
    s3.put_bucket_acl(Bucket=bucket, GrantRead='uri="http://acs.amazonaws.com/groups/global/AllUsers"')
    perms = sorted(g["Permission"] for g in s3.get_bucket_acl(Bucket=bucket)["Grants"])
    assert perms == ["READ"]
    with pytest.raises(ClientError) as e:
        s3.put_bucket_acl(Bucket=bucket, ACL="public-everything")
    assert status(e) == 400
    with pytest.raises(ClientError) as e:
        s3.put_bucket_acl(Bucket=bucket, GrantRead='id="no-such-user"')
    assert code(e) == "InvalidArgument"
    with pytest.raises(ClientError) as e:
        s3.put_bucket_acl(Bucket=bucket, GrantRead='emailAddress="a@example.com"')
    assert code(e) == "UnresolvableGrantByEmailAddress"


def test_anonymous_missing_bucket_is_404():
    with pytest.raises(ClientError) as e:
        anon().get_object(Bucket="no-such-bucket-zk", Key="k")
    assert code(e) == "NoSuchBucket"


def test_ownership_controls(s3, bucket):
    with pytest.raises(ClientError) as e:
        s3.get_bucket_ownership_controls(Bucket=bucket)
    assert code(e) == "OwnershipControlsNotFoundError"
    s3.put_bucket_ownership_controls(Bucket=bucket, OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]})
    rules = s3.get_bucket_ownership_controls(Bucket=bucket)["OwnershipControls"]["Rules"]
    assert rules[0]["ObjectOwnership"] == "BucketOwnerEnforced"
    with pytest.raises(ClientError) as e:
        s3.put_object(Bucket=bucket, Key="k", Body=b"x", ACL="public-read")
    assert code(e) == "AccessControlListNotSupported"
    s3.put_object(Bucket=bucket, Key="k", Body=b"x", ACL="bucket-owner-full-control")
    s3.delete_bucket_ownership_controls(Bucket=bucket)


def test_public_access_block(s3, bucket):
    with pytest.raises(ClientError) as e:
        s3.get_public_access_block(Bucket=bucket)
    assert code(e) == "NoSuchPublicAccessBlockConfiguration"
    conf = {"BlockPublicAcls": True, "IgnorePublicAcls": False, "BlockPublicPolicy": True, "RestrictPublicBuckets": False}
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration=conf)
    assert s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"] == conf
    with pytest.raises(ClientError) as e:
        s3.put_bucket_acl(Bucket=bucket, ACL="public-read")
    assert status(e) == 403
    pol = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                                                    "Resource": f"arn:aws:s3:::{bucket}/*"}]}
    with pytest.raises(ClientError) as e:
        s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(pol))
    assert status(e) == 403
    s3.delete_public_access_block(Bucket=bucket)
    assert s3.get_bucket_policy_status(Bucket=bucket)["PolicyStatus"]["IsPublic"] is False


# CORS


def test_cors_config_and_preflight(s3, bucket):
    with pytest.raises(ClientError) as e:
        s3.get_bucket_cors(Bucket=bucket)
    assert code(e) == "NoSuchCORSConfiguration"
    s3.put_bucket_cors(Bucket=bucket, CORSConfiguration={"CORSRules": [
        {"AllowedOrigins": ["https://*.example.com"], "AllowedMethods": ["GET", "PUT"], "AllowedHeaders": ["*"],
         "ExposeHeaders": ["ETag"], "MaxAgeSeconds": 600}]})
    rules = s3.get_bucket_cors(Bucket=bucket)["CORSRules"]
    assert rules[0]["AllowedMethods"] == ["GET", "PUT"]
    st, h, _ = raw("OPTIONS", f"/{bucket}/k", {"Origin": "https://app.example.com", "Access-Control-Request-Method": "PUT",
                                               "Access-Control-Request-Headers": "content-type"})
    assert st == 200
    assert h["access-control-allow-origin"] == "https://app.example.com"
    assert "PUT" in h["access-control-allow-methods"]
    assert h["access-control-max-age"] == "600"
    st, _, _ = raw("OPTIONS", f"/{bucket}/k", {"Origin": "https://evil.test", "Access-Control-Request-Method": "GET"})
    assert st == 403
    st, _, _ = raw("OPTIONS", f"/{bucket}/k", {})
    assert st == 400
    # Simple requests (even failing ones) carry the CORS headers.
    st, h, _ = raw("GET", f"/{bucket}/missing", {"Origin": "https://app.example.com"})
    assert st == 403 and h["access-control-allow-origin"] == "https://app.example.com"
    s3.delete_bucket_cors(Bucket=bucket)
    with pytest.raises(ClientError):
        s3.get_bucket_cors(Bucket=bucket)


# Website


def test_website_config_and_endpoint(s3, bucket):
    with pytest.raises(ClientError) as e:
        s3.get_bucket_website(Bucket=bucket)
    assert code(e) == "NoSuchWebsiteConfiguration"
    s3.put_bucket_website(Bucket=bucket, WebsiteConfiguration={
        "IndexDocument": {"Suffix": "index.html"}, "ErrorDocument": {"Key": "404.html"},
        "RoutingRules": [{"Condition": {"KeyPrefixEquals": "old/"}, "Redirect": {"ReplaceKeyPrefixWith": "new/"}}]})
    cfg = s3.get_bucket_website(Bucket=bucket)
    assert cfg["IndexDocument"]["Suffix"] == "index.html"
    for k, body in (("index.html", b"home"), ("docs/index.html", b"docs"), ("404.html", b"missing")):
        s3.put_object(Bucket=bucket, Key=k, Body=body, ContentType="text/html")
    host = f"{bucket}.{os.environ.get('S3_WEBSITE_DOMAIN', 's3-website.localhost')}"
    st, _, _ = raw("GET", "/", host=host)
    assert st == 403  # not public yet
    pol = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                                                    "Resource": f"arn:aws:s3:::{bucket}/*"}]}
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(pol))
    assert raw("GET", "/", host=host)[2] == b"home"
    assert raw("GET", "/docs/", host=host)[2] == b"docs"
    st, h, _ = raw("GET", "/docs", host=host)
    assert st == 302 and h["location"] == "/docs/"
    st, h, _ = raw("GET", "/old/page.html", host=host)
    assert st == 301 and h["location"].endswith("/new/page.html")
    st, _, body = raw("GET", "/nope.html", host=host)
    assert st == 404 and body == b"missing"
    s3.delete_bucket_website(Bucket=bucket)
    assert raw("GET", "/", host=host)[0] == 404


# Checksums and attributes


def b64(d):
    return base64.b64encode(d).decode()


def test_put_checksums(s3, bucket):
    body = b"checksum me" * 100
    sha = b64(hashlib.sha256(body).digest())
    r = s3.put_object(Bucket=bucket, Key="c", Body=body, ChecksumSHA256=sha)
    assert r["ChecksumSHA256"] == sha
    assert "ChecksumSHA256" not in s3.head_object(Bucket=bucket, Key="c")
    assert s3.head_object(Bucket=bucket, Key="c", ChecksumMode="ENABLED")["ChecksumSHA256"] == sha
    with pytest.raises(ClientError) as e:
        s3.put_object(Bucket=bucket, Key="c", Body=body, ChecksumSHA256=b64(hashlib.sha256(b"other").digest()))
    assert code(e) == "BadDigest"
    crc = b64(zlib.crc32(body).to_bytes(4, "big"))
    r = s3.put_object(Bucket=bucket, Key="c32", Body=body, ChecksumAlgorithm="CRC32")
    assert r["ChecksumCRC32"] == crc
    a = s3.get_object_attributes(Bucket=bucket, Key="c32", ObjectAttributes=["ETag", "Checksum", "ObjectSize", "StorageClass"])
    assert a["ObjectSize"] == len(body) and a["Checksum"]["ChecksumCRC32"] == crc and a["StorageClass"] == "STANDARD"


def test_multipart_composite_checksum_and_attributes(s3, bucket):
    parts_data = [os.urandom(5 * 1024 * 1024), os.urandom(1024)]
    up = s3.create_multipart_upload(Bucket=bucket, Key="m", ChecksumAlgorithm="SHA256")
    assert up["ChecksumAlgorithm"] == "SHA256"
    parts = []
    for i, d in enumerate(parts_data, 1):
        r = s3.upload_part(Bucket=bucket, Key="m", UploadId=up["UploadId"], PartNumber=i, Body=d, ChecksumAlgorithm="SHA256")
        assert r["ChecksumSHA256"] == b64(hashlib.sha256(d).digest())
        parts.append({"ETag": r["ETag"], "PartNumber": i, "ChecksumSHA256": r["ChecksumSHA256"]})
    listed = s3.list_parts(Bucket=bucket, Key="m", UploadId=up["UploadId"])
    assert listed["Parts"][0]["ChecksumSHA256"] == parts[0]["ChecksumSHA256"]
    want = b64(hashlib.sha256(b"".join(hashlib.sha256(d).digest() for d in parts_data)).digest()) + "-2"
    r = s3.complete_multipart_upload(Bucket=bucket, Key="m", UploadId=up["UploadId"], MultipartUpload={"Parts": parts})
    assert r["ChecksumSHA256"] == want
    # A retried complete answers with the same result.
    again = s3.complete_multipart_upload(Bucket=bucket, Key="m", UploadId=up["UploadId"], MultipartUpload={"Parts": parts})
    assert again["ETag"] == r["ETag"] and again["ChecksumSHA256"] == want
    a = s3.get_object_attributes(Bucket=bucket, Key="m", ObjectAttributes=["Checksum", "ObjectParts", "ObjectSize"], MaxParts=1)
    assert a["Checksum"]["ChecksumSHA256"] == want
    assert a["ObjectParts"]["TotalPartsCount"] == 2 and a["ObjectParts"]["IsTruncated"] is True
    assert a["ObjectParts"]["Parts"][0]["ChecksumSHA256"] == parts[0]["ChecksumSHA256"]


# Conditional writes


def test_conditional_writes(s3, bucket):
    s3.put_object(Bucket=bucket, Key="k", Body=b"1", IfNoneMatch="*")
    with pytest.raises(ClientError) as e:
        s3.put_object(Bucket=bucket, Key="k", Body=b"2", IfNoneMatch="*")
    assert status(e) == 412
    etag = s3.head_object(Bucket=bucket, Key="k")["ETag"]
    s3.put_object(Bucket=bucket, Key="k", Body=b"3", IfMatch=etag)
    with pytest.raises(ClientError) as e:
        s3.put_object(Bucket=bucket, Key="k", Body=b"4", IfMatch=etag)
    assert status(e) == 412
    up = s3.create_multipart_upload(Bucket=bucket, Key="k")
    p = s3.upload_part(Bucket=bucket, Key="k", UploadId=up["UploadId"], PartNumber=1, Body=b"mp")
    with pytest.raises(ClientError) as e:
        s3.complete_multipart_upload(Bucket=bucket, Key="k", UploadId=up["UploadId"], IfNoneMatch="*",
                                     MultipartUpload={"Parts": [{"ETag": p["ETag"], "PartNumber": 1}]})
    assert status(e) == 412
    with pytest.raises(ClientError) as e:
        s3.complete_multipart_upload(Bucket=bucket, Key="new", UploadId=up["UploadId"], IfMatch="*",
                                     MultipartUpload={"Parts": [{"ETag": p["ETag"], "PartNumber": 1}]})
    assert status(e) in (404, 400)


# POST policy and SigV2


def form(fields, data=b"formdata"):
    boundary = "zkfsmboundary"
    out = []
    for k, v in fields.items():
        out.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    out.append(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="f.txt"\r\n'
               f'Content-Type: text/plain\r\n\r\n'.encode() + data + b"\r\n")
    out.append(f"--{boundary}--\r\n".encode())
    return b"".join(out), {"Content-Type": f"multipart/form-data; boundary={boundary}"}


def test_post_policy_conditions(s3, bucket):
    post = s3.generate_presigned_post(bucket, "up/${filename}", Fields={"success_action_status": "201"},
                                      Conditions=[["starts-with", "$key", "up/"], {"success_action_status": "201"},
                                                  ["content-length-range", 1, 20]])
    body, hdrs = form(post["fields"])
    st, _, resp = raw("POST", f"/{bucket}", hdrs, body)
    assert st == 201 and b"<Key>up/f.txt</Key>" in resp
    assert s3.get_object(Bucket=bucket, Key="up/f.txt")["Body"].read() == b"formdata"
    body, hdrs = form(post["fields"], b"x" * 21)
    assert raw("POST", f"/{bucket}", hdrs, body)[0] == 400
    bad = dict(post["fields"], key="other/f.txt")
    body, hdrs = form(bad)
    assert raw("POST", f"/{bucket}", hdrs, body)[0] == 403


def test_sigv2_header_auth(s3, bucket):
    c = boto3.client("s3", endpoint_url=os.environ["S3_ENDPOINT"], aws_access_key_id=os.environ["S3_ACCESS_KEY"],
                     aws_secret_access_key=os.environ["S3_SECRET_KEY"], region_name="us-east-1",
                     config=Config(signature_version="s3", s3={"addressing_style": "path"}))
    c.put_object(Bucket=bucket, Key="dir/v2 key+.txt", Body=b"v2")
    assert c.get_object(Bucket=bucket, Key="dir/v2 key+.txt")["Body"].read() == b"v2"
    assert c.list_objects(Bucket=bucket)["Contents"][0]["Key"] == "dir/v2 key+.txt"
    bad = boto3.client("s3", endpoint_url=os.environ["S3_ENDPOINT"], aws_access_key_id=os.environ["S3_ACCESS_KEY"],
                       aws_secret_access_key="wrong-secret", region_name="us-east-1",
                       config=Config(signature_version="s3", s3={"addressing_style": "path"}))
    with pytest.raises(ClientError) as e:
        bad.list_objects(Bucket=bucket)
    assert code(e) == "SignatureDoesNotMatch"


# Small bucket configuration APIs


def test_bucket_config_stubs(s3, bucket):
    assert "LoggingEnabled" not in s3.get_bucket_logging(Bucket=bucket)
    s3.put_bucket_logging(Bucket=bucket, BucketLoggingStatus={"LoggingEnabled": {"TargetBucket": bucket, "TargetPrefix": "log/"}})
    assert s3.get_bucket_logging(Bucket=bucket)["LoggingEnabled"]["TargetPrefix"] == "log/"
    s3.put_bucket_logging(Bucket=bucket, BucketLoggingStatus={})
    assert "LoggingEnabled" not in s3.get_bucket_logging(Bucket=bucket)
    assert s3.get_bucket_request_payment(Bucket=bucket)["Payer"] == "BucketOwner"
    assert "Status" not in s3.get_bucket_accelerate_configuration(Bucket=bucket)
    s3.put_object(Bucket=bucket, Key="rp", Body=b"x", RequestPayer="requester")
    assert s3.get_object(Bucket=bucket, Key="rp", RequestPayer="requester")["Body"].read() == b"x"


def test_list_buckets_pages(s3, bucket):
    first = s3.list_buckets(MaxBuckets=1)
    assert len(first["Buckets"]) == 1
    names = [b["Name"] for b in s3.list_buckets()["Buckets"]]
    if len(names) > 1:
        nxt = s3.list_buckets(MaxBuckets=1, ContinuationToken=first["ContinuationToken"])
        assert nxt["Buckets"][0]["Name"] == names[1]
    assert bucket in [b["Name"] for b in s3.list_buckets(Prefix=bucket[:6])["Buckets"]]


def test_trailing_checksum(s3, bucket):
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials
    data = b"trailer body " * 50
    crc = b64(zlib.crc32(data).to_bytes(4, "big"))

    def send(value):
        body = f"{len(data):x}\r\n".encode() + data + b"\r\n0\r\n" + f"x-amz-checksum-crc32:{value}\r\n\r\n".encode()
        url = f"{os.environ['S3_ENDPOINT']}/{bucket}/trailed"
        req = AWSRequest(method="PUT", url=url, data=body, headers={
            "x-amz-content-sha256": "STREAMING-UNSIGNED-PAYLOAD-TRAILER", "content-encoding": "aws-chunked",
            "x-amz-decoded-content-length": str(len(data)), "x-amz-trailer": "x-amz-checksum-crc32",
            "content-length": str(len(body))})
        SigV4Auth(Credentials(os.environ["S3_ACCESS_KEY"], os.environ["S3_SECRET_KEY"]), "s3", "us-east-1").add_auth(req)
        u = urllib.parse.urlparse(url)
        c = http.client.HTTPConnection(u.hostname, u.port, timeout=10)
        c.request("PUT", u.path, body=body, headers=dict(req.headers))
        r = c.getresponse()
        r.read()
        c.close()
        return r.status, dict((k.lower(), v) for k, v in r.getheaders())

    st, h = send(crc)
    assert st == 200 and h["x-amz-checksum-crc32"] == crc
    assert s3.head_object(Bucket=bucket, Key="trailed", ChecksumMode="ENABLED")["ChecksumCRC32"] == crc
    assert s3.get_object(Bucket=bucket, Key="trailed")["Body"].read() == data
    st, _ = send(b64(b"\0\0\0\0"))
    assert st == 400
