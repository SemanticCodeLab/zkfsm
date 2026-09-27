import os
import uuid

import boto3
import pytest
from botocore.config import Config


def _client(**cfg):
    return boto3.client(
        "s3",
        endpoint_url=os.environ["S3_ENDPOINT"],
        aws_access_key_id=os.environ["S3_ACCESS_KEY"],
        aws_secret_access_key=os.environ["S3_SECRET_KEY"],
        region_name="us-east-1",
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}, retries={"max_attempts": 1}, **cfg),
    )


@pytest.fixture(scope="session")
def s3():
    return _client()


@pytest.fixture(scope="session")
def make_client():
    return _client


def empty_bucket(s3, name):
    try:
        pages = s3.get_paginator("list_object_versions").paginate(Bucket=name)
        for page in pages:
            for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
                try:
                    s3.put_object_legal_hold(Bucket=name, Key=v["Key"], VersionId=v["VersionId"], LegalHold={"Status": "OFF"})
                except Exception:
                    pass
                s3.delete_object(Bucket=name, Key=v["Key"], VersionId=v["VersionId"], BypassGovernanceRetention=True)
    except Exception:
        pass
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
        for o in page.get("Contents", []):
            s3.delete_object(Bucket=name, Key=o["Key"])
    for u in s3.list_multipart_uploads(Bucket=name).get("Uploads", []):
        s3.abort_multipart_upload(Bucket=name, Key=u["Key"], UploadId=u["UploadId"])


@pytest.fixture
def bucket(s3):
    name = "t-" + uuid.uuid4().hex[:20]
    s3.create_bucket(Bucket=name)
    yield name
    try:
        empty_bucket(s3, name)
        s3.delete_bucket(Bucket=name)
    except Exception:
        pass  # compliance-locked objects stay; the data dir is temporary


@pytest.fixture
def lock_bucket(s3):
    name = "l-" + uuid.uuid4().hex[:20]
    s3.create_bucket(Bucket=name, ObjectLockEnabledForBucket=True)
    yield name
    try:
        empty_bucket(s3, name)
        s3.delete_bucket(Bucket=name)
    except Exception:
        pass
