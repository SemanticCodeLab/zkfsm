# zkfsm

S3-compatible object storage written in Zig: one object engine over local
disks, NAS, and remote object stores.

## Build

Requires Zig 0.15.2; no dependencies beyond `std`.

```sh
zig build                  # produces zig-out/bin/zkfsm
zig build test             # unit tests
scripts/check_layers.sh    # enforces the downward-only import rule
tests/smoke.sh             # end-to-end curl test against a temp data dir
```

## Run

```sh
zig-out/bin/zkfsm --data /var/lib/zkfsm --listen 0.0.0.0:9000
# or: ZKFSM_DATA=/var/lib/zkfsm zig-out/bin/zkfsm
```

Defaults: data root `$ZKFSM_DATA`, else `./data`; listen `0.0.0.0:9000`.
Path-style addressing only (`http://host:9000/bucket/key`).

```sh
curl -X PUT http://localhost:9000/photos
curl -T dog.jpg http://localhost:9000/photos/dog.jpg
curl http://localhost:9000/photos?list-type=2
curl -r 0-99 http://localhost:9000/photos/dog.jpg
```

## Status

0.1 in progress:

- Local filesystem backend: two-level fanout, data file + `.meta` record,
  write-temp + fsync + atomic rename, range reads.
- ObjectService: buckets, put/get/head/delete, ListObjectsV2 semantics
  (prefix, delimiter, start-after, continuation token, max-keys), MD5 ETag
  computed while streaming.
- S3 API: ListBuckets, CreateBucket, DeleteBucket, HeadBucket, GetBucketLocation,
  ListObjectsV2, PutObject, GetObject (single `Range`), HeadObject,
  DeleteObject, S3 XML error bodies. One thread per connection.
- `tests/smoke.sh`: 35/35 curl checks pass.

Not yet: **authentication is anonymous** (SigV4 is step 8, stub in
`src/s3/sigv4.zig`), multipart (step 9, requests return `NotImplemented`),
`/metrics` and health endpoints (step 10), CopyObject, aws-chunked uploads,
and the aws-cli/mc/rclone conformance suite (step 11). Do not expose this
build to untrusted networks.
