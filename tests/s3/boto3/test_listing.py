import urllib.parse

import pytest
from botocore.exceptions import ClientError

SPECIAL = ["plain", "with space", "plus+sign", "percent%25", "percent%", "question?mark", "hash#tag",
           "amp&er", "eq=ual", "semi;colon", "unicode/ü ñ 日本", "emoji/😀", "tab\tchar", "lt<gt>",
           "quote\"s", "apos'", "back\\slash", "tilde~", "comma,", "star*", "colon:x", "at@x", "dollar$",
           "bracket[0]", "brace{}", "caret^", "pipe|", "grave`"]


def keys(resp):
    return [o["Key"] for o in resp.get("Contents", [])]


def prefixes(resp):
    return [p["Prefix"] for p in resp.get("CommonPrefixes", [])]


@pytest.mark.parametrize("key", SPECIAL)
def test_special_key_roundtrip(s3, bucket, key):
    s3.put_object(Bucket=bucket, Key=key, Body=key.encode())
    assert s3.get_object(Bucket=bucket, Key=key)["Body"].read() == key.encode()
    assert s3.head_object(Bucket=bucket, Key=key)["ContentLength"] == len(key.encode())
    assert keys(s3.list_objects_v2(Bucket=bucket)) == [key]
    assert keys(s3.list_objects_v2(Bucket=bucket, Prefix=key)) == [key]
    s3.delete_object(Bucket=bucket, Key=key)
    assert keys(s3.list_objects_v2(Bucket=bucket)) == []


def test_special_keys_sorted(s3, bucket):
    for k in SPECIAL:
        s3.put_object(Bucket=bucket, Key=k, Body=b"x")
    got = keys(s3.list_objects_v2(Bucket=bucket))
    assert got == sorted(SPECIAL, key=lambda k: k.encode())


def test_encoding_type_url(s3, bucket):
    ks = ["a b", "c+d", "e%f", "ü/x", "t\tab"]
    for k in ks:
        s3.put_object(Bucket=bucket, Key=k, Body=b"x")
    # boto3 only decodes when it chose the encoding itself; an explicit request returns raw values.
    r = s3.list_objects_v2(Bucket=bucket, EncodingType="url")
    assert r.get("EncodingType") == "url"
    assert sorted(urllib.parse.unquote_plus(k) for k in keys(r)) == sorted(ks)
    raw = []

    def grab(http_response, **_):
        raw.append(http_response.content)
    s3.meta.events.register("after-call.s3.ListObjectsV2", grab)
    try:
        s3.list_objects_v2(Bucket=bucket, EncodingType="url", Delimiter="/")
    finally:
        s3.meta.events.unregister("after-call.s3.ListObjectsV2", grab)
    body = raw[0].decode()
    assert "<Key>a%20b</Key>" in body or "<Key>a+b</Key>" in body
    assert "<Prefix>%C3%BC/</Prefix>" in body


def test_delimiter(s3, bucket):
    for k in ["a/1", "a/2", "a/b/3", "b/4", "c", "d/"]:
        s3.put_object(Bucket=bucket, Key=k, Body=b"x")
    r = s3.list_objects_v2(Bucket=bucket, Delimiter="/")
    assert keys(r) == ["c"]
    assert prefixes(r) == ["a/", "b/", "d/"]
    assert r["KeyCount"] == 4
    r = s3.list_objects_v2(Bucket=bucket, Delimiter="/", Prefix="a/")
    assert keys(r) == ["a/1", "a/2"]
    assert prefixes(r) == ["a/b/"]


def test_non_slash_delimiter(s3, bucket):
    for k in ["x-1-a", "x-1-b", "x-2", "y"]:
        s3.put_object(Bucket=bucket, Key=k, Body=b"x")
    r = s3.list_objects_v2(Bucket=bucket, Delimiter="-", Prefix="x-")
    assert prefixes(r) == ["x-1-", "x-2"] or (prefixes(r) == ["x-1-"] and keys(r) == ["x-2"])
    r = s3.list_objects_v2(Bucket=bucket, Delimiter="-")
    assert prefixes(r) == ["x-"] and keys(r) == ["y"]


def test_multichar_delimiter(s3, bucket):
    for k in ["a::b", "a::c", "d"]:
        s3.put_object(Bucket=bucket, Key=k, Body=b"x")
    r = s3.list_objects_v2(Bucket=bucket, Delimiter="::")
    assert prefixes(r) == ["a::"] and keys(r) == ["d"]


def test_max_keys_paging(s3, bucket):
    ks = [f"k{i:03d}" for i in range(25)]
    for k in ks:
        s3.put_object(Bucket=bucket, Key=k, Body=b"")
    got, token, pages = [], None, 0
    while True:
        kw = {"ContinuationToken": token} if token else {}
        r = s3.list_objects_v2(Bucket=bucket, MaxKeys=7, **kw)
        pages += 1
        assert r["MaxKeys"] == 7
        assert r["KeyCount"] == len(keys(r))
        got += keys(r)
        if not r["IsTruncated"]:
            break
        token = r["NextContinuationToken"]
    assert got == ks and pages == 4


def test_paging_with_prefixes(s3, bucket):
    for k in ["a/1", "a/2", "b/1", "c", "d/1", "e"]:
        s3.put_object(Bucket=bucket, Key=k, Body=b"")
    got = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Delimiter="/", PaginationConfig={"PageSize": 1}):
        got += keys(page) + prefixes(page)
    assert got == ["a/", "b/", "c", "d/", "e"]


def test_max_keys_zero(s3, bucket):
    s3.put_object(Bucket=bucket, Key="a", Body=b"")
    r = s3.list_objects_v2(Bucket=bucket, MaxKeys=0)
    assert keys(r) == [] and r["KeyCount"] == 0


def test_max_keys_capped(s3, bucket):
    s3.put_object(Bucket=bucket, Key="a", Body=b"")
    assert s3.list_objects_v2(Bucket=bucket, MaxKeys=5000)["MaxKeys"] <= 5000


def test_start_after(s3, bucket):
    for k in ["a", "b", "c", "d"]:
        s3.put_object(Bucket=bucket, Key=k, Body=b"")
    r = s3.list_objects_v2(Bucket=bucket, StartAfter="b")
    assert keys(r) == ["c", "d"] and r["StartAfter"] == "b"
    assert keys(s3.list_objects_v2(Bucket=bucket, StartAfter="bb")) == ["c", "d"]
    assert keys(s3.list_objects_v2(Bucket=bucket, StartAfter="z")) == []


def test_fetch_owner(s3, bucket):
    s3.put_object(Bucket=bucket, Key="a", Body=b"")
    r = s3.list_objects_v2(Bucket=bucket, FetchOwner=True)
    assert "Owner" in r["Contents"][0]


def test_list_objects_v1_marker(s3, bucket):
    for k in ["a", "b", "c"]:
        s3.put_object(Bucket=bucket, Key=k, Body=b"")
    r = s3.list_objects(Bucket=bucket, MaxKeys=2)
    assert keys(r) == ["a", "b"] and r["IsTruncated"]
    r = s3.list_objects(Bucket=bucket, Marker="b")
    assert keys(r) == ["c"] and not r["IsTruncated"]


def test_list_objects_v1_next_marker_with_delimiter(s3, bucket):
    for k in ["a/1", "b/1", "c"]:
        s3.put_object(Bucket=bucket, Key=k, Body=b"")
    got = []
    for page in s3.get_paginator("list_objects").paginate(Bucket=bucket, Delimiter="/", PaginationConfig={"PageSize": 1}):
        got += keys(page) + prefixes(page)
    assert got == ["a/", "b/", "c"]


def test_list_v1_encoding_url(s3, bucket):
    s3.put_object(Bucket=bucket, Key="a b/c", Body=b"")
    r = s3.list_objects(Bucket=bucket, EncodingType="url", Delimiter="/")
    assert [urllib.parse.unquote_plus(p) for p in prefixes(r)] == ["a b/"]


def test_prefix_no_match(s3, bucket):
    s3.put_object(Bucket=bucket, Key="abc", Body=b"")
    r = s3.list_objects_v2(Bucket=bucket, Prefix="abd")
    assert r["KeyCount"] == 0 and not r["IsTruncated"]


def test_prefix_is_url_encoded_on_wire(s3, bucket):
    for k in ["p q/1", "p+q/2", "p%q/3"]:
        s3.put_object(Bucket=bucket, Key=k, Body=b"")
    for k in ["p q/1", "p+q/2", "p%q/3"]:
        assert keys(s3.list_objects_v2(Bucket=bucket, Prefix=k.split("/")[0] + "/")) == [k]


def test_list_after_delete_markers(s3, bucket):
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_object(Bucket=bucket, Key="gone", Body=b"x")
    s3.put_object(Bucket=bucket, Key="kept", Body=b"x")
    s3.delete_object(Bucket=bucket, Key="gone")
    assert keys(s3.list_objects_v2(Bucket=bucket)) == ["kept"]


def test_list_versions_key_marker(s3, bucket):
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    for k in ["a", "b", "c"]:
        s3.put_object(Bucket=bucket, Key=k, Body=b"x")
    r = s3.list_object_versions(Bucket=bucket, KeyMarker="a")
    assert [v["Key"] for v in r["Versions"]] == ["b", "c"]
    r = s3.list_object_versions(Bucket=bucket, Prefix="b")
    assert [v["Key"] for v in r["Versions"]] == ["b"]


def test_quoted_url_in_path(s3, bucket):
    k = "a/b%2Fc"
    s3.put_object(Bucket=bucket, Key=k, Body=b"x")
    assert keys(s3.list_objects_v2(Bucket=bucket)) == [k]
    assert urllib.parse.quote(k)
