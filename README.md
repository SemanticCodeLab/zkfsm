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
tests/tls.sh               # TLS 1.3 interop: openssl, curl, S3 CLI, mc, python; fuzzing
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
(`http://host:9000/bucket/key`); `--domain s3.example.com` (repeatable, or
`$ZKFSM_DOMAIN`) adds virtual-host style (`http://bucket.s3.example.com/key`),
and `--path-prefix /s3` (or `$ZKFSM_PATH_PREFIX`) serves the API under a base
path; requests outside it get `404 NoSuchBucket`. `--health-prefix`,
`--metrics-path`, and `--no-minio-compat` move or trim the operational
endpoints. `--lifecycle-interval` sets the lifecycle pass period (default
3600 s, 0 disables). Containers: `Dockerfile`,
`deploy/compose/`, and the Helm chart in `helm/zkfsm`.

### TLS

```sh
zkfsm --data /var/lib/zkfsm --tls-cert chain.pem --tls-key key.pem
zkfsm --data /var/lib/zkfsm --certs-dir /etc/zkfsm/certs   # public.crt + private.key
```

Native TLS 1.3 (no TLS 1.2): X25519 and P-256 key exchange, AES-GCM and
ChaCha20-Poly1305, ECDSA P-256 or RSA 2048-4096 (PSS) certificates. Keys may
be PKCS#8, SEC1, or PKCS#1 PEM, unencrypted. `ZKFSM_TLS_CERT`/`ZKFSM_TLS_KEY`
and `ZKFSM_CERTS_DIR` work too; `kill -HUP` reloads the files, keeping the old
pair if the new one fails to load.

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

### Cluster

Every node starts with the same endpoint list; each `--data` flag is one pool.

```sh
# on node1..node4 (same command, same root credentials)
zkfsm --data http://node{1...4}:9000/data{1...4} --protection EC:4+2
# local test: 4 processes, 4 drives each, one pool
zkfsm --data http://127.0.0.1:{9001...9004}/srv/d{1...4} --listen 127.0.0.1:9001 --node-address 127.0.0.1:9001
```

- **Topology** is fixed at startup. The node finds itself from `--listen` (or
  `--node-address host:port`). A pool is cut into erasure sets (`--set-size`, by
  default the largest divisor of the pool's drive count up to 16); drives are
  interleaved across nodes so each set takes as few drives from one node as the
  layout allows, and each object's k+m shards take at most ceil((k+m)/nodes)
  drives per node, so a node loss costs no more shards than the parity covers.
- **Format**: the owner of a pool's first endpoint formats the pool once every
  drive is reachable. Format files record the deployment id, pool, set, index,
  set size, profile, a fingerprint of the pool's endpoint list, and all drive
  ids of the set; a drive from another deployment, a moved drive, or a changed
  endpoint list or profile is refused. An empty local drive in a known set is
  formatted as a replacement and healed.
- **Expansion**: restart every node with a pool appended
  (`--data <pool1> --data <pool2>`). New objects go to the pool with the most
  room; reads and deletes find a key in whichever pool holds it. Pool
  decommission and rebalancing are not part of this edition.
- **Internal RPC** shares the S3 port (and its TLS) under `/zkfsm/rpc/v1/`.
  Each request is signed with HMAC-SHA256 over the method, path, sender, time,
  a nonce, and the body digest; requests outside a 60 s window or with a
  replayed nonce are refused. The secret is `--cluster-secret`
  (`$ZKFSM_CLUSTER_SECRET`) or is derived from the root credentials, which must
  match on every node (checked at startup). Over TLS, peers are verified
  against `--cluster-ca` files and the node's own certificate chain.
  Connections are pooled; calls have timeouts; a node that fails a call is
  marked offline and calls to it fail fast until the 1 s heartbeat sees it back.
- **Quorum**: erasure writes need k shards (k+1 when k == m) and reads need k;
  records need a majority, carry a hybrid-clock stamp (newest replica wins),
  and deletes leave tombstones, so a node that missed changes cannot bring old
  state back. A set refuses writes once fewer than its set write quorum of
  drives is reachable; clients get `503 WriteQuorumUnavailable` or
  `503 ReadQuorumUnavailable`.
- **Locks**: object writes, deletes, metadata changes, multipart completion,
  bucket creation/deletion, bucket configuration, and IAM changes take a
  lock granted by a majority of nodes (30 s leases refreshed every 10 s,
  unlocks retried, leases of crashed holders expire).
- **Shared state**: the bucket catalog, bucket configuration (versioning,
  lock, policy, lifecycle, tags), object records, and the IAM store live in
  the cluster store's system namespace. Nodes mirror changes through
  notifications sent when the lock is released, reload the catalog and IAM
  every `--cluster-refresh` seconds, and rebuild the key index when a peer
  returns or at startup.
- **Health**: `/health/ready` is 200 only when the node can reach a lock
  majority and write quorum for every set, so load balancers route around
  nodes in a minority. See `deploy/lb/nginx.conf`, `deploy/lb/haproxy.cfg`,
  `deploy/compose/docker-compose.cluster.yml`, and the Helm chart
  (`--set replicas=4 --set drives.count=4`).
- **Healing** runs per set on the lowest-numbered reachable node (and on any
  node holding a freshly formatted drive): it lists remote drives page by page,
  rebuilds missing or stale shards and records, spreads tombstones, and purges
  shards of interrupted writes after 15 minutes. A returning node triggers a
  pass right away.

### Users, policies, and temporary credentials

`mc admin` manages users, groups, canned policies, and service accounts
(`mc admin user add|ls|info|disable`, `mc admin policy create|attach|ls`,
`mc admin group ...`, `mc admin user svcacct add|ls|rm`). Only root or
identities whose policies allow the matching `admin:*` action may call it;
users may manage their own service accounts. State lives in
`<first drive>/.zkfsm/iam.json`, replaced atomically on every change (in a
cluster: a record in the cluster store, locked and propagated to every node).

The admin API is served under `--admin-prefix` (or `$ZKFSM_ADMIN_PREFIX`,
default `/minio/admin` so stock `mc` works) and always under `/zkfsm/admin`.
A prefix is `/seg[/seg...]` without a trailing slash, `?`, `..` or `//`.
Requests to `<prefix>/v3/...` and `<prefix>/v4/...` go to the admin API, so in
the bucket named like the prefix's first segment, path-style keys under the
rest of the prefix followed by `/v3/` or `/v4/` are unreachable (for the
default: keys `admin/v3/...` and `admin/v4/...` in bucket `minio`). The server
logs a warning at startup when such a bucket exists.

STS `AssumeRole` (`POST /`, form body) returns temporary credentials for the
signing user, for 900 to 43200 seconds (`DurationSeconds`), optionally
narrowed by a session `Policy`; standard `sts assume-role` clients work
unchanged against the server endpoint.

### External identity

Federated STS actions turn an external identity into temporary credentials
whose rights are a list of canned or stored policies (still narrowed by an
optional session `Policy`). The session token carries the policy names and the
tenant, so no per-session server state exists; every node accepts the tokens.

- **OpenID Connect** (`AssumeRoleWithWebIdentity`, `AssumeRoleWithClientGrants`):
  providers are added with `mc idp openid add ALIAS [NAME] config_url=...
  client_id=... [claim_name=policy] [claim_prefix=] [scopes=...]
  [redirect_uri=...] [role_policy=...] [tenant=...|tenant_claim=...]`
  (`ls`, `info`, `update`, `rm` as usual), or at startup with
  `--identity-openid "k=v ..."` / `$ZKFSM_IDENTITY_OPENID_<KEY>` (shown as the
  default provider `_`). The server reads the discovery document, caches the
  JWKS for an hour, refetches it when a token names an unknown key id (at most
  every 10 s per provider, and keeps the old keys if the refetch fails), and
  verifies RS256/384/512 and ES256/384 signatures, `exp`/`nbf` (60 s leeway),
  `iss` (the discovered issuer) and `aud`/`azp` (the client id). Policies come
  from the claim (a JSON array or a comma-separated string; names that do not
  exist are dropped, none left is AccessDenied). A provider with
  `role_policy` is selected by its role ARN `arn:zkfsm:iam:::role/<name>`
  (listed by `mc idp openid ls`) and grants exactly that policy list.
- **LDAP / Active Directory** (`AssumeRoleWithLDAPIdentity`, `LDAPUsername`
  and `LDAPPassword`): `mc idp ldap add ALIAS server_addr=host:636
  lookup_bind_dn=... lookup_bind_password=... user_dn_search_base_dn=...
  user_dn_search_filter=(uid=%s) [group_search_base_dn=...
  group_search_filter=(&(objectclass=groupOfNames)(member=%d))]
  [server_starttls=on | server_insecure=on] [tls_skip_verify=on]
  [tls_ca_file=...] [tenant=...]`. The built-in LDAPv3 client binds as the
  lookup account, finds exactly one user entry (the username is escaped per
  RFC 4515), binds as that DN with the password (empty passwords are refused),
  then collects group DNs. LDAPS is the default; StartTLS and plain TCP are
  opt-in. Policies are attached to user or group DNs with `mc idp ldap policy
  attach|detach ALIAS POLICY --user DN | --group DN` and listed with
  `mc idp ldap policy entities`. A directory that is down gives
  ServiceUnavailable; wrong credentials and unknown users both give
  AccessDenied.
- **Client certificates** (`AssumeRoleWithCertificate`): with
  `--tls-client-ca FILE` the TLS listener asks clients for a certificate
  (optional for every other request). A client presenting a certificate that
  chains to that CA gets credentials whose policy is the one named by the
  certificate's subject Common Name, for at most an hour and never past the
  certificate's expiry.

Secrets in IdP settings (`client_secret`, `lookup_bind_password`) are stored
in the IAM state and shown redacted by `info`. Configuration changes apply
immediately on every node (they live in the IAM store).

### Bucket quotas

`mc quota set ALIAS/BUCKET --size 10GiB`, `mc quota info`, `mc quota clear`
(admin `set-bucket-quota` / `get-bucket-quota`, actions `admin:SetBucketQuota`
and `admin:GetBucketQuota`). A hard quota rejects writes that would take the
bucket past the limit with `QuotaExceeded` (HTTP 400): PutObject (checked
before the body is read when its length is known, and again at commit),
CopyObject, UploadPart, and CompleteMultipartUpload. Usage is the sum of all
stored versions (delete markers excluded), kept in the key index next to the
names, so it is exact after every write, delete, and restart, and every
cluster node sees the same value. An overwrite in an unversioned bucket only
needs room for the difference. `get-bucket-quota` also reports `usage` and
`objects`.

### Multi-tenancy

Users already isolate through policies; tenants add a hard boundary on top,
like separate accounts sharing one server (the equivalent of the
project-scoped buckets other servers get from Keystone).

- A tenant is a name (`a-z0-9-`). A user belongs to at most one tenant; its
  service accounts and STS sessions inherit it. Federated sessions get it
  from the provider (`tenant=` fixed, or `tenant_claim=` for OpenID).
- A bucket created by a tenant identity is owned by that tenant. Tenant
  identities see (ListBuckets) and reach only their tenant's buckets, global
  identities only global buckets, whatever their policies say; a copy source
  in another tenant is refused as well. Bucket names stay globally unique.
  Root (and root's service accounts) reach everything. Anonymous requests
  are governed by bucket policies only, so a tenant can still publish a
  bucket on purpose.
- Tenant identities get no admin API rights except self-service (their own
  service accounts). Disabling a tenant blocks all of its identities at once.
- Admin routes (root or `admin:TenantAdmin`; sign with SigV4 like any admin
  call, e.g. `curl --aws-sigv4 aws:amz:us-east-1:s3 --user KEY:SECRET -X PUT`):
  `PUT /minio/admin/v3/tenant/add?name=T`, `DELETE .../tenant/remove?name=T`
  (only when it has no users or buckets), `GET .../tenant/list` (users,
  buckets, and usage per tenant), `PUT .../tenant/set-status?name=T&status=enabled|disabled`,
  `PUT .../tenant/assign-user?name=T&accessKey=U` (empty `name` makes the
  user global), `PUT .../tenant/assign-bucket?name=T&bucket=B`.

## Compatibility

`tests/s3/run.sh` drives each client against a single drive and against six
drives with `EC:4+2`, and prints one line per check plus a
`conformance: P/T passed (X xfail)` total. rclone and s5cmd are downloaded at
pinned, checksum-verified versions into `tests/s3/.bin`; boto3 runs from a
local venv in `tests/s3/.venv`. CI runs the boto3 and S3 CLI suites.

| Client | Checks per layout | Passed (single / EC:4+2) | Known gaps (xfail) |
| --- | --- | --- | --- |
| boto3 (pytest) | 145 | 142 / 142 | 3 |
| S3 CLI (`s3`, `s3api`) | 44 | 44 / 44 | 0 |
| MinIO client | 23 | 23 / 23 | 0 |
| rclone v1.75.1 | 21 | 21 / 21 | 0 |
| s5cmd v2.3.0 | 17 | 17 / 17 | 0 |

Total: 496/502 passed, 6 xfail. The xfails are features not implemented:
virtual-host-style addressing without a configured domain, browser-form POST
uploads, and SigV2 signatures.

`SUITES=s3tests tests/s3/run.sh` also runs a subset of
[ceph/s3-tests](https://github.com/ceph/s3-tests) (MIT, cloned at a pinned
commit at test time), excluding feature groups zkfsm does not have (ACL-only
IAM, SSE, website, CORS, lifecycle, notifications, select). Reported
separately, not gating: 283/435 on a single drive and 283/435 on EC:4+2.

## Status

Pre-1.0. Working today and covered by tests:

- **S3 API**: buckets, objects, ListObjectsV2, ranges, CopyObject,
  DeleteObjects, multipart uploads (incl. UploadPartCopy), versioning with
  delete markers and ListObjectVersions, object lock (governance, compliance,
  legal hold), object and bucket tagging, conditional requests, lifecycle
  expiration (current, noncurrent, delete markers, incomplete uploads),
  bucket policies (including anonymous access), GET/HEAD by `partNumber`,
  canned private ACLs, and ListObjects v1.
- **Security**: SigV4 header and presigned auth, aws-chunked uploads, payload
  hash checks; IAM users, groups, service accounts, S3 policy
  evaluation, STS session tokens; OpenID Connect, LDAP, and client
  certificate federation; tenants; hard bucket quotas.
- **Storage**: local drives with atomic writes; multiple drives with
  replica:2/3 or Reed-Solomon EC:4+2/8+4/12+4; per-chunk CRC32C bitrot
  detection; background scan and heal; remote S3, GCS and Azure backends and
  a NAS profile.
- **Cluster**: static multi-node deployments with erasure sets spanning
  nodes, signed internal RPC, majority locks, node-failure quorum, failover
  through any node, cross-node healing, and expansion by appending pools.
- **Operations**: `/health/live`, `/health/ready`, Prometheus `/metrics`
  (MinIO-compatible aliases), Docker image, compose files, Helm chart, CI.

Verified clients: standard S3 command-line clients (including 200 MB
multipart over EC:4+2) and the MinIO client (`mc cp`, `mirror`, `rm`, `share`).

Not yet: SSE, bucket
notifications, lifecycle transitions, non-private ACLs, TLS termination
(run behind a proxy).
