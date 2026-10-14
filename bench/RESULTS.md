# bench/compare.sh results

Run 2026-10-12 22:21–22:34 (local time), zkfsm and MinIO only. Raw warp logs are not committed.

## Machine

- CPU: 11th Gen Intel Core i7-11800H (8 cores / 16 threads), 62 GiB RAM, Linux 6.18.7
- Drives: tmpfs per drive inside each container (no disk I/O is measured)
- The host was not idle: a 5-node kind cluster and other sessions' processes were running
  at the same time. Treat the numbers as indicative, not as a controlled comparison.

## Versions

- zkfsm 0919413, ReleaseFast, x86_64-linux-musl, in a busybox container
- MinIO server built from source with `go install` (pseudo-version v0.0.0-20260212201848-7aac2a2c5b7c)
- RustFS image rustfs/rustfs@sha256:1803faef57627e2d9c2e7d89d655d712ddded5389040054987163043fecb6a3c
- Load: warp v1.8.2

## Limits and layout

| topology | containers | CPU per container | memory | drives |
|---|---|---|---|---|
| single | 1 | cpuset 0-3, --cpus 4 | 18 GiB | 4 x tmpfs 3584 MiB |
| cluster | 4 | one core each (0,1,2,3), --cpus 1 | 3 GiB each | 4 x tmpfs 512 MiB each |

The warp client runs in its own container on cores 4-7 (--cpus 4) on the same docker
network and round-robins across all server containers.

Protection:
- single: zkfsm EC:2+2; MinIO EC:2 (its default for 4 drives): the same two data and two parity shards.
- cluster: zkfsm EC:12+4; MinIO EC:4 (default for 16 drives, 12+4); RustFS uses its default.

## Method

Every workload uses concurrency 32 against bucket `zc-bench`. Each run lasts 20 s, except
put-1m, which lasts 5 s so it does not fill the tmpfs drives (they are charged to the
container; a run that fills them measures a full drive). Products run one at a time, and
each target is restarted with empty drives before its workloads. The mixed workload is warp's
default split: 45% GET, 30% STAT, 15% PUT, 10% DELETE.

    bench/compare.sh                        # full matrix
    PRODUCTS=zkfsm TOPOS=single bench/compare.sh

## Results

obj/s and MiB/s are warp's averages. p50 and p99 are per-request latencies. The host was
shared (load average 1.5 to 10 during the run); repeated runs moved single numbers by up
to 30 %.

| product | topology | workload | op | obj/s | MiB/s | p50 | p99 | notes |
|---|---|---|---|---|---|---|---|---|
| zkfsm | single | put-4k | PUT | 12748.33 | 49.80 | 2.3ms | 12.2ms |  |
| zkfsm | single | put-1m | PUT | 970.56 | 970.56 | 32.1ms | 89.3ms |  |
| zkfsm | single | get-4k | GET | 38599.83 | 150.78 | 1.1ms | 12.6ms |  |
| zkfsm | single | get-1m | GET | 5493.06 | 5493.06 | 6.6ms | 30.0ms |  |
| zkfsm | single | list-4k | LIST | 168252.35 | - | 14.2ms | 43.4ms |  |
| zkfsm | single | mixed-4k | DELETE | 2695.19 | - | 1.1ms | 16.4ms |  |
| zkfsm | single | mixed-4k | GET | 12127.57 | 47.37 | 1.2ms | 11.6ms |  |
| zkfsm | single | mixed-4k | PUT | 4043.06 | 15.79 | 1.6ms | 16.9ms |  |
| zkfsm | single | mixed-4k | STAT | 8085.12 | - | 1.2ms | 16.5ms |  |
| zkfsm | single | mixed-4k | Total | 26950.94 | 63.17 | - | - |  |
| zkfsm | single | mixed-1m | DELETE | 365.47 | - | 3.7ms | 23.4ms |  |
| zkfsm | single | mixed-1m | GET | 1643.71 | 1643.71 | 4.5ms | 25.4ms |  |
| zkfsm | single | mixed-1m | PUT | 548.00 | 548.00 | 28.1ms | 59.1ms |  |
| zkfsm | single | mixed-1m | STAT | 1095.87 | - | 3.3ms | 24.4ms |  |
| zkfsm | single | mixed-1m | Total | 3653.04 | 2191.70 | - | - |  |
| minio | single | put-4k | PUT | 5096.49 | 19.91 | 5.5ms | 23.1ms |  |
| minio | single | put-1m | PUT | 797.31 | 797.31 | 41.3ms | 73.3ms |  |
| minio | single | get-4k | GET | 9643.76 | 37.67 | 3.0ms | 16.2ms |  |
| minio | single | get-1m | GET | 3337.26 | 3337.26 | 10.7ms | 42.6ms |  |
| minio | single | list-4k | LIST | 59034.52 | - | 40.8ms | 88.0ms |  |
| minio | single | mixed-4k | DELETE | 784.80 | - | 5.0ms | 18.7ms |  |
| minio | single | mixed-4k | GET | 3530.10 | 13.79 | 3.8ms | 17.0ms |  |
| minio | single | mixed-4k | PUT | 1176.51 | 4.60 | 4.9ms | 18.7ms |  |
| minio | single | mixed-4k | STAT | 2353.42 | - | 2.8ms | 13.4ms |  |
| minio | single | mixed-4k | Total | 7844.83 | 18.39 | - | - |  |
| minio | single | mixed-1m | FAILED | - | - | - | - | rc=1 |
| zkfsm | cluster | put-4k | PUT | 631.11 | 2.47 | 42.8ms | 159.1ms |  |
| zkfsm | cluster | put-1m | PUT | 261.41 | 261.41 | 97.7ms | 371.5ms |  |
| zkfsm | cluster | get-4k | GET | 3557.43 | 13.90 | 5.3ms | 71.1ms |  |
| zkfsm | cluster | get-1m | GET | 714.71 | 714.71 | 31.4ms | 152.6ms |  |
| zkfsm | cluster | list-4k | LIST | 189218.69 | - | 11.7ms | 46.5ms |  |
| zkfsm | cluster | mixed-4k | DELETE | 160.46 | - | 25.3ms | 124.0ms |  |
| zkfsm | cluster | mixed-4k | GET | 723.75 | 2.83 | 6.9ms | 90.6ms |  |
| zkfsm | cluster | mixed-4k | PUT | 241.41 | 0.94 | 32.1ms | 123.4ms |  |
| zkfsm | cluster | mixed-4k | STAT | 483.30 | - | 5.8ms | 72.4ms |  |
| zkfsm | cluster | mixed-4k | Total | 1608.92 | 3.77 | - | - |  |
| zkfsm | cluster | mixed-1m | DELETE | 65.88 | - | 43.3ms | 211.4ms |  |
| zkfsm | cluster | mixed-1m | GET | 296.16 | 296.16 | 26.0ms | 159.4ms |  |
| zkfsm | cluster | mixed-1m | PUT | 99.31 | 99.31 | 82.5ms | 293.3ms |  |
| zkfsm | cluster | mixed-1m | STAT | 197.15 | - | 10.5ms | 141.4ms |  |
| zkfsm | cluster | mixed-1m | Total | 658.50 | 395.47 | - | - |  |
| minio | cluster | put-4k | PUT | 736.37 | 2.88 | 2.9ms | 340.5ms |  |
| minio | cluster | put-1m | PUT | 228.35 | 228.35 | 97.8ms | 406.1ms |  |
| minio | cluster | get-4k | GET | 1653.93 | 6.46 | 17.7ms | 41.5ms |  |
| minio | cluster | get-1m | GET | 696.46 | 696.46 | 42.3ms | 97.5ms |  |
| minio | cluster | list-4k | LIST | 15852.99 | - | 153.2ms | 271.2ms |  |
| minio | cluster | mixed-4k | DELETE | 142.14 | - | 10.2ms | 34.7ms |  |
| minio | cluster | mixed-4k | GET | 640.37 | 2.50 | 5.2ms | 19.4ms |  |
| minio | cluster | mixed-4k | PUT | 213.22 | 0.83 | 50.3ms | 364.0ms |  |
| minio | cluster | mixed-4k | STAT | 426.24 | - | 5.1ms | 19.9ms |  |
| minio | cluster | mixed-4k | Total | 1421.98 | 3.33 | - | - |  |
| minio | cluster | mixed-1m | DELETE | 65.42 | - | 48.5ms | 96.3ms | err_lines=223 |
| minio | cluster | mixed-1m | GET | 294.53 | 294.53 | 21.3ms | 52.9ms | err_lines=223 |
| minio | cluster | mixed-1m | PUT | 100.96 | 100.96 | 130.0ms | 433.0ms | err_lines=223 |
| minio | cluster | mixed-1m | STAT | 196.34 | - | 23.3ms | 55.4ms | err_lines=223 |
| minio | cluster | mixed-1m | Total | 671.46 | 402.96 | - | - | err_lines=223 |

## PUT before and after (zkfsm)

| topology | workload | 5993cf1 obj/s | 0919413 obj/s | MinIO obj/s (this run) |
|---|---|---|---|---|
| single | put-4k | 1384 (replica:2) | 12748 | 5096 |
| single | put-1m | 28.5 (replica:2) | 971 | 797 |
| cluster | put-4k | 63.3 | 631 | 736 |
| cluster | put-1m | 20.7 | 261 | 228 |

What changed: a portable (baseline x86-64) build now uses SHA-NI, SSE4.2 CRC-32C and pshufb
when the CPU has them (the standard library's portable SHA-256 ran at about 30 MB/s);
erasure shards of the last block hold only the object's bytes instead of a padded 1 MiB
block; bucket documents are served from memory; aws-chunked uploads keep their connection;
the node-to-node replay guard no longer scans a table of every nonce.

## Anomalies

- MinIO single mixed-1m failed in warp's prepare step (rc=1); no result.
- MinIO cluster mixed-1m logged 223 error lines.
- RustFS was not run again; its rows from 2026-10-08 are in this file's history.
- zkfsm cluster put-4k is still behind MinIO: a small PUT costs about 45 node-to-node
  calls (lock, record read, shard and record writes, notices).

## Tier transport: std.http.Client vs pooled outbound client (bench/tier_transport.sh)

512 MiB object, zkfsm hot node over a zkfsm tier on one laptop (shared, noisy);
old = main 7e47494, new = feat/tiercert. Seconds; read is a full read-through GET,
ranges is 64 sequential 64 KiB ranged GETs.

| run | transition old/new | read old/new | ranges old/new |
|---|---|---|---|
| http 1 | 13.06 / 16.43 | 0.42 / 0.66 | 0.87 / 1.11 |
| http 2 | 17.92 / 11.78 | 0.80 / 0.47 | 2.08 / 0.85 |
| http 3 | 10.50 / 10.12 | 0.41 / 0.78 | 1.10 / 1.14 |
| http 4 | 11.21 / 8.93 | 0.60 / 0.52 | 1.14 / 0.89 |
| http 5 | 7.63 / 6.95 | 0.34 / 0.53 | 0.46 / 1.04 |
| https 1 | 9.26 / 9.26 | 0.87 / 0.63 | 3.33 / 3.18 |
| https 2 | 7.70 / 12.37 | 0.91 / 0.82 | 3.19 / 3.49 |

Medians: transition 10.50 / 10.12 (http), reads 0.42 / 0.53 (http) and 0.89 / 0.73
(https), ranges 1.10 / 1.04. Run-to-run spread is wider than the old/new gap.
