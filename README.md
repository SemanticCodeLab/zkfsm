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
tests/durability.sh        # drive loss, bitrot, and heal (replica:2 and EC:4+2)
tests/s3cli.sh             # SigV4 + IAM with an S3 CLI and the MinIO client (set MC=/path/to/mc)
tests/s3/run.sh            # S3 conformance across client SDKs and tools (see Compatibility)
tests/remote_backend.sh    # remote S3/Azure backends against local containers
```

## Run

```sh
export ZKFSM_ACCESS_KEY=admin ZKFSM_SECRET_KEY=change-me-please
zig-out/bin/zkfsm --data /var/lib/zkfsm --listen 0.0.0.0:9000
```

Root credentials come from `ZKFSM_ACCESS_KEY`/`ZKFSM_SECRET_KEY` (or
`MINIO_ROOT_USER`/`MINIO_ROOT_PASSWORD`). Without them the server refuses to
start unless `--anonymous` is passed. Defaults: data root `$ZKFSM_DATA`, else
`./data`; listen `0.0.0.0:9000`. Path-style addressing
(`http://host:9000/bucket/key`). Containers: `Dockerfile`,
`deploy/compose/`, and the Helm chart in `helm/zkfsm`.

### Multiple drives

```sh
zkfsm --data /mnt/disk{1...4} --protection replica:2 --scan-interval 600
zkfsm heal --data /mnt/disk{1...4}     # one scan/heal pass, exit 0 when fully redundant
```

- `--data` takes several paths; `{a...b}` expands like MinIO (`{01...12}` keeps padding).
- Each drive gets a `format.zkfsm` identity file (set id, drive id, position,
  profile). Drives from another set, reordered drives, a changed drive count,
  or a changed profile are refused at startup. An empty drive in a known set is
  formatted as a replacement and healed.
- Protection profiles are a closed set: `single`, `replica:2`, `replica:3`,
  `EC:4+2`, `EC:8+4`, `EC:12+4`. The default is `replica:2` with 2+ drives.
- Placement is rendezvous hashing on the object id over drive ids.
- Replicas: writes need a quorum of N/2+1; every 64 KiB chunk carries a CRC32C
  that is checked on read; a missing or corrupt replica is served from another
  one and rewritten inline.
- Erasure: 1 MiB blocks striped over k+m drives with Reed-Solomon parity,
  CRC32C per shard block; writes need k+1 shards; reads reconstruct from any k
  and rebuild bad shards inline. Records are replicated on all k+m drives.
- Healing runs in the background every `--scan-interval` seconds (0 disables):
  the scanner walks each drive with a bounded rate, the planner orders drive
  reformat, repairs of missing replicas, checksum scrubs, and removal of temp
  files older than an hour left by interrupted writes.

```sh
mc alias set z http://localhost:9000 admin change-me-please
mc mb z/photos
mc cp dog.jpg z/photos/
```

## Compatibility

`tests/s3/run.sh` drives each client against a single drive and against six
drives with `EC:4+2`, and prints one line per check plus a
`conformance: P/T passed (X xfail)` total. rclone and s5cmd are downloaded at
pinned, checksum-verified versions into `tests/s3/.bin`; boto3 runs from a
local venv in `tests/s3/.venv`. CI runs the boto3 and S3 CLI suites.

| Client | Checks per layout | Passed (single / EC:4+2) | Known gaps (xfail) |
| --- | --- | --- | --- |
| boto3 (pytest) | 145 | 139 / 139 | 6 |
| S3 CLI (`s3`, `s3api`) | 44 | 44 / 44 | 0 |
| MinIO client | 23 | 23 / 23 | 0 |
| rclone v1.75.1 | 21 | 21 / 21 | 0 |
| s5cmd v2.3.0 | 17 | 17 / 17 | 0 |

Total: 490/502 passed, 12 xfail. The xfails are features not implemented
yet: virtual-host-style addressing, bucket policy, lifecycle rules,
`GET ?partNumber`, browser-form POST uploads, and SigV2 signatures.

`SUITES=s3tests tests/s3/run.sh` also runs a subset of
[ceph/s3-tests](https://github.com/ceph/s3-tests) (MIT, cloned at a pinned
commit at test time), excluding feature groups zkfsm does not have (ACL-only
IAM, SSE, website, CORS, lifecycle, notifications, select). Reported
separately, not gating: 274/435 on a single drive, 271/435 on EC:4+2.

## Status

Pre-1.0. Working today and covered by tests:

- **S3 API**: buckets, objects, ListObjectsV2, ranges, CopyObject,
  DeleteObjects, multipart uploads (incl. UploadPartCopy), versioning with
  delete markers and ListObjectVersions, object lock (governance, compliance,
  legal hold), object and bucket tagging, conditional requests.
- **Security**: SigV4 header and presigned auth, aws-chunked uploads, payload
  hash checks; IAM users, groups, service accounts, S3 policy
  evaluation, STS session tokens.
- **Storage**: local drives with atomic writes; multiple drives with
  replica:2/3 or Reed-Solomon EC:4+2/8+4/12+4; per-chunk CRC32C bitrot
  detection; background scan and heal; remote S3, GCS and Azure backends and
  a NAS profile.
- **Operations**: `/health/live`, `/health/ready`, Prometheus `/metrics`
  (MinIO-compatible aliases), Docker image, compose files, Helm chart, CI.

Verified clients: standard S3 command-line clients (including 200 MB
multipart over EC:4+2) and the MinIO client (`mc cp`, `mirror`, `rm`, `share`).

Not yet: multi-node clustering, IAM admin HTTP API, SSE, bucket
notifications, lifecycle rules, virtual-host-style addressing, TLS
termination (run behind a proxy).
