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

## feat/smallput: small-object PUT path (preliminary)

PRELIMINARY: run 2026-10-14 18:47–19:02 on a shared host; other agents kept the
1-minute load average at 25–60 for most of the day (samples taken right after the
run: 0.4–1.4; load during the run was not recorded). Throughput mostly measures
contention. The RPC counts below do not depend on load and are the primary evidence.

### Node-to-node calls per PUT (bench/rpc_count.sh)

4 nodes x 4 drives, EC:4+2, 200 new keys then 200 overwrites through node 1, summed
over all nodes (zkfsm_cluster_rpc_sent_total).

| op | 4 KiB before (7e47494) | 4 KiB after | 1 MiB after |
|---|---|---|---|
| lock | 3.00 | 3.00 | 3.00 |
| unlock | 3.00 | 0 | 0 |
| notify | 3.01 | 3.00 | 3.02 |
| write (shard streams) | 4.51 | 0 | 4.51 |
| rput | 4.55 | 1.05 | 1.04 |
| rputs (batched per node) | - | 1.73 | 1.74 |
| rget | 9.45 | 0 | 0 |
| rgets (batched per node) | - | 1.16 | 1.2-2.3 |
| other (hello, diskinfo, scan) | 0.27 | 0.30 | 0.36 |
| total | 27.79 | 10.24 | ~14.9 |

### Throughput (warp, compare.sh limits, PFX=zc-sp, server cpus 8-11, client 12-15)

Protection: single zkfsm EC:2+2 vs MinIO EC:2; cluster zkfsm EC:12+4 vs MinIO EC:4.

| product | topology | workload | obj/s | MiB/s | p50 | p99 |
|---|---|---|---|---|---|---|
| zkfsm before (7e47494) | single | put-4k | 10645.32 | 41.58 | 8.3ms | 20.3ms |
| zkfsm after | single | put-4k | 10583.75 | 41.34 | 2.8ms | 18.4ms |
| minio | single | put-4k | 5483.32 | 21.42 | 7.9ms | 24.7ms |
| zkfsm before | single | put-1m | 846.44 | 846.44 | 34.1ms | 98.2ms |
| zkfsm after | single | put-1m | 964.35 | 964.35 | 30.1ms | 92.7ms |
| minio | single | put-1m | 1068.64 | 1068.64 | 30.4ms | 72.2ms |
| zkfsm before | single | get-4k | 32413.57 | 126.62 | 7.0ms | 25.6ms |
| zkfsm after | single | get-4k | 22726.03 | 88.77 | 1.2ms | 17.0ms |
| minio | single | get-4k | 10000.58 | 39.06 | 6.3ms | 23.3ms |
| zkfsm before | single | get-1m | 5605.43 | 5605.43 | 5.0ms | 22.1ms |
| zkfsm after | single | get-1m | 5447.51 | 5447.51 | 5.1ms | 36.8ms |
| minio | single | get-1m | 3414.38 | 3414.38 | 8.2ms | 38.9ms |
| zkfsm before | cluster | put-4k | 663.40 | 2.59 | 37.3ms | 132.3ms |
| zkfsm after | cluster | put-4k | 2766.37 | 10.81 | 8.8ms | 62.2ms |
| minio | cluster | put-4k | 839.03 | 3.28 | 2.3ms | 339.0ms |
| zkfsm before | cluster | put-1m | 232.56 | 232.56 | 106.9ms | 432.4ms |
| zkfsm after | cluster | put-1m | 374.69 | 374.69 | 46.3ms | 545.1ms |
| minio | cluster | put-1m | 311.66 | 311.66 | 34.9ms | 369.5ms |
| zkfsm before | cluster | get-4k | 3480.52 | 13.60 | 4.1ms | 68.7ms |
| zkfsm after | cluster | get-4k | 8077.93 | 31.55 | 2.7ms | 19.7ms |
| minio | cluster | get-4k | 1721.80 | 6.73 | 16.3ms | 44.6ms |
| zkfsm before | cluster | get-1m | 720.90 | 720.90 | 55.0ms | 241.0ms |
| zkfsm after | cluster | get-1m | 912.35 | 912.35 | 27.1ms | 196.5ms |
| minio | cluster | get-1m | 765.89 | 765.89 | 40.7ms | 82.1ms |
