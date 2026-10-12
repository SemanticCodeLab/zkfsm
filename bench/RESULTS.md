# bench/compare.sh results

Run 2026-10-08 14:23–15:00 (local time). Raw warp logs are not committed.

## Machine

- CPU: 11th Gen Intel Core i7-11800H (8 cores / 16 threads), 62 GiB RAM, Linux 6.18.7
- Drives: tmpfs per drive inside each container (no disk I/O is measured)
- The host was not idle: a 5-node kind cluster and other sessions' processes were running
  at the same time. Treat the numbers as indicative, not as a controlled comparison.

## Versions

- zkfsm 5993cf1, ReleaseFast, x86_64-linux-musl, in a busybox container
- MinIO server built from source with `go install` (pseudo-version v0.0.0-20260212201848-7aac2a2c5b7c)
- RustFS image rustfs/rustfs@sha256:1803faef57627e2d9c2e7d89d655d712ddded5389040054987163043fecb6a3c
- Load: warp v1.8.2

## Limits and layout

| topology | containers | CPU per container | memory | drives |
|---|---|---|---|---|
| single | 1 | cpuset 0-3, --cpus 4 | 8 GiB | 4 x tmpfs 1536 MiB |
| cluster | 4 | one core each (0,1,2,3), --cpus 1 | 3 GiB each | 4 x tmpfs 512 MiB each |

The warp client runs in its own container on cores 4-7 (--cpus 4) on the same docker
network and round-robins across all server containers.

Protection:
- single: zkfsm replica:2; MinIO EC:2 (its default for 4 drives); RustFS uses its default.
  These are not equivalent. replica:2 writes 2x the bytes, EC:2+2 writes 2x as well, but in shards.
- cluster: zkfsm EC:12+4; MinIO EC:4 (default for 16 drives, 12+4); RustFS uses its default.

## Method

Every workload uses concurrency 32 against bucket `zc-bench`. Each run lasts 20 s, except
put-1m, which lasts 4 s so it does not fill the tmpfs drives. Products run one at a time, and
each target is restarted with empty drives before its workloads. The mixed workload is warp's
default split: 45% GET, 30% STAT, 15% PUT, 10% DELETE.

    bench/compare.sh                        # full matrix
    PRODUCTS=zkfsm TOPOS=single bench/compare.sh

## Results

obj/s and MiB/s are warp's averages. p50 and p99 are per-request latencies.

| product | topology | workload | op | obj/s | MiB/s | p50 | p99 | notes |
|---|---|---|---|---|---|---|---|---|
| zkfsm | single | put-4k | PUT | 1383.99 | 5.41 | 25.7ms | 80.6ms |  |
| zkfsm | single | put-1m | PUT | 28.50 | 28.50 | 1024.4ms | 1977.8ms |  |
| zkfsm | single | get-4k | GET | 3816.73 | 14.91 | 10.8ms | 52.2ms |  |
| zkfsm | single | get-1m | GET | 550.84 | 550.84 | 42.4ms | 404.7ms |  |
| zkfsm | single | list-4k | LIST | 41032.31 | - | 73.0ms | 227.9ms |  |
| zkfsm | single | mixed-4k | DELETE | 327.67 | - | 5.9ms | 48.5ms |  |
| zkfsm | single | mixed-4k | GET | 1475.96 | 5.77 | 7.4ms | 37.4ms |  |
| zkfsm | single | mixed-4k | PUT | 492.05 | 1.92 | 14.5ms | 61.8ms |  |
| zkfsm | single | mixed-4k | STAT | 984.04 | - | 6.5ms | 35.5ms |  |
| zkfsm | single | mixed-4k | Total | 3279.73 | 7.69 | - | - |  |
| zkfsm | single | mixed-1m | DELETE | 15.24 | - | 7.8ms | 69.5ms |  |
| zkfsm | single | mixed-1m | GET | 71.38 | 71.38 | 49.5ms | 161.4ms |  |
| zkfsm | single | mixed-1m | PUT | 23.31 | 23.31 | 1133.8ms | 1854.1ms |  |
| zkfsm | single | mixed-1m | STAT | 47.41 | - | 7.6ms | 58.6ms |  |
| zkfsm | single | mixed-1m | Total | 158.64 | 94.92 | - | - |  |
| minio | single | put-4k | PUT | 1164.77 | 4.55 | 39.3ms | 147.6ms |  |
| minio | single | put-1m | PUT | 286.79 | 286.79 | 100.8ms | 540.2ms |  |
| minio | single | get-4k | GET | 2360.22 | 9.22 | 14.2ms | 50.3ms |  |
| minio | single | get-1m | GET | 928.80 | 928.80 | 30.3ms | 91.4ms |  |
| minio | single | list-4k | LIST | 15291.51 | - | 150.6ms | 415.7ms |  |
| minio | single | mixed-4k | DELETE | 239.10 | - | 15.7ms | 55.9ms |  |
| minio | single | mixed-4k | GET | 1079.91 | 4.22 | 11.9ms | 46.2ms |  |
| minio | single | mixed-4k | PUT | 359.99 | 1.41 | 14.5ms | 54.1ms |  |
| minio | single | mixed-4k | STAT | 719.76 | - | 9.0ms | 38.5ms |  |
| minio | single | mixed-4k | Total | 2398.77 | 5.62 | - | - |  |
| minio | single | mixed-1m | FAILED | - | - | - | - | rc=1 |
| rustfs | single | put-4k | PUT | 334.09 | 1.31 | 94.2ms | 152.4ms |  |
| rustfs | single | get-4k | GET | 3896.87 | 15.22 | 9.4ms | 31.2ms |  |
| rustfs | single | get-1m | GET | 1024.54 | 1024.54 | 32.0ms | 72.2ms |  |
| rustfs | single | list-4k | LIST | 3443.06 | - | 619.8ms | 877.7ms |  |
| rustfs | single | mixed-4k | DELETE | 115.69 | - | 100.1ms | 175.1ms |  |
| rustfs | single | mixed-4k | GET | 521.82 | 2.04 | 10.5ms | 26.7ms |  |
| rustfs | single | mixed-4k | PUT | 173.86 | 0.68 | 84.9ms | 139.9ms |  |
| rustfs | single | mixed-4k | STAT | 346.72 | - | 7.8ms | 24.2ms |  |
| rustfs | single | mixed-4k | Total | 1158.09 | 2.72 | - | - |  |
| rustfs | single | mixed-1m | DELETE | 3.02 | - | 2917.4ms | 5681.6ms | err_lines=1213 |
| rustfs | single | mixed-1m | GET | 12.25 | 12.25 | 15.4ms | 48.7ms | err_lines=1213 |
| rustfs | single | mixed-1m | PUT | 3.99 | 3.99 | 2938.4ms | 6191.1ms | err_lines=1213 |
| rustfs | single | mixed-1m | STAT | 7.88 | - | 7.2ms | 31.0ms | err_lines=1213 |
| rustfs | single | mixed-1m | Total | 23.17 | 13.86 | - | - | err_lines=1213 |
| zkfsm | cluster | put-4k | PUT | 63.30 | 0.25 | 466.3ms | 1106.8ms |  |
| zkfsm | cluster | put-1m | PUT | 20.65 | 20.65 | 1576.7ms | 2212.2ms |  |
| zkfsm | cluster | get-4k | GET | 165.04 | 0.64 | 169.1ms | 794.6ms |  |
| zkfsm | cluster | get-1m | GET | 169.79 | 169.79 | 151.9ms | 798.2ms |  |
| zkfsm | cluster | list-4k | LIST | 50256.57 | - | 41.2ms | 277.1ms |  |
| zkfsm | cluster | mixed-4k | DELETE | 13.06 | - | 351.3ms | 691.0ms |  |
| zkfsm | cluster | mixed-4k | GET | 59.49 | 0.23 | 150.8ms | 550.4ms |  |
| zkfsm | cluster | mixed-4k | PUT | 19.80 | 0.08 | 501.2ms | 917.6ms |  |
| zkfsm | cluster | mixed-4k | STAT | 38.74 | - | 95.9ms | 495.6ms |  |
| zkfsm | cluster | mixed-4k | Total | 131.09 | 0.31 | - | - |  |
| zkfsm | cluster | mixed-1m | DELETE | 8.51 | - | 800.1ms | 1367.4ms |  |
| zkfsm | cluster | mixed-1m | GET | 39.25 | 39.25 | 167.0ms | 835.0ms |  |
| zkfsm | cluster | mixed-1m | PUT | 13.05 | 13.05 | 1267.3ms | 2334.7ms |  |
| zkfsm | cluster | mixed-1m | STAT | 25.96 | - | 84.5ms | 629.8ms |  |
| zkfsm | cluster | mixed-1m | Total | 86.78 | 52.30 | - | - |  |
| minio | cluster | put-4k | PUT | 325.14 | 1.27 | 91.8ms | 381.8ms |  |
| minio | cluster | put-1m | PUT | 102.54 | 102.54 | 330.5ms | 935.4ms |  |
| minio | cluster | get-4k | GET | 565.91 | 2.21 | 51.8ms | 137.2ms |  |
| minio | cluster | get-1m | GET | 270.28 | 270.28 | 118.7ms | 237.1ms |  |
| minio | cluster | list-4k | LIST | 5700.71 | - | 445.1ms | 691.2ms |  |
| minio | cluster | mixed-4k | DELETE | 55.14 | - | 49.3ms | 105.2ms |  |
| minio | cluster | mixed-4k | GET | 245.20 | 0.96 | 22.7ms | 53.9ms |  |
| minio | cluster | mixed-4k | PUT | 82.04 | 0.32 | 185.1ms | 435.6ms |  |
| minio | cluster | mixed-4k | STAT | 164.93 | - | 24.4ms | 60.8ms |  |
| minio | cluster | mixed-4k | Total | 547.31 | 1.28 | - | - |  |
| minio | cluster | mixed-1m | DELETE | 32.92 | - | 125.0ms | 185.0ms |  |
| minio | cluster | mixed-1m | GET | 148.50 | 148.50 | 57.0ms | 107.4ms |  |
| minio | cluster | mixed-1m | PUT | 49.51 | 49.51 | 302.1ms | 529.5ms |  |
| minio | cluster | mixed-1m | STAT | 99.16 | - | 59.1ms | 108.4ms |  |
| minio | cluster | mixed-1m | Total | 330.09 | 198.01 | - | - |  |
| rustfs | cluster | put-4k | PUT | 52.34 | 0.20 | 558.0ms | 924.8ms |  |
| rustfs | cluster | get-4k | GET | 168.99 | 0.66 | 189.7ms | 436.6ms |  |
| rustfs | cluster | get-1m | GET | 248.08 | 248.08 | 123.2ms | 298.6ms |  |
| rustfs | cluster | list-4k | LIST | 1871.45 | - | 664.2ms | 4449.8ms |  |
| rustfs | cluster | mixed-4k | DELETE | 15.66 | - | 567.0ms | 825.1ms |  |
| rustfs | cluster | mixed-4k | GET | 70.85 | 0.28 | 76.1ms | 130.3ms |  |
| rustfs | cluster | mixed-4k | PUT | 23.43 | 0.09 | 557.1ms | 976.7ms |  |
| rustfs | cluster | mixed-4k | STAT | 46.77 | - | 63.0ms | 131.1ms |  |
| rustfs | cluster | mixed-4k | Total | 156.68 | 0.37 | - | - |  |

## Anomalies

- MinIO single mixed-1m failed: the 1536 MiB tmpfs drives reached MinIO's minimum
  free-space threshold during the run.
- RustFS put-1m has no result in either topology. warp's prepare step failed with
  "You did not provide the number of bytes specified by the Content-Length HTTP header".
- RustFS single mixed-1m logged 1213 error lines. Its numbers are not comparable.
- RustFS cluster mixed-1m did not finish: the run hung and was stopped. There is no result.
- zkfsm put-1m (28.5 obj/s single, 20.7 obj/s cluster) is about 10x slower than MinIO on
  the same limits. 4 KiB PUT and GET are on par with MinIO or faster.
