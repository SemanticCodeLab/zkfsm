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
```

## Run

```sh
zig-out/bin/zkfsm --data /var/lib/zkfsm --listen 0.0.0.0:9000
# or: ZKFSM_DATA=/var/lib/zkfsm zig-out/bin/zkfsm
```

Defaults: data root `$ZKFSM_DATA`, else `./data`; listen `0.0.0.0:9000`.
Path-style addressing only (`http://host:9000/bucket/key`).

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
