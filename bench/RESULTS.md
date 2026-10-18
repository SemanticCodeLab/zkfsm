# bench/compare.sh results

Reported results: the gated run below (LOAD_MAX=4: each run starts only when the
1-minute load average is below 4). The earlier run under load (2026-10-14) is kept at the
end as preliminary and is not comparable.

## Machine

- CPU: 11th Gen Intel Core i7-11800H (8 cores / 16 threads), 62 GiB RAM, Linux 6.18.7
- Drives: tmpfs per drive inside each container (no disk I/O is measured)

## Versions

- zkfsm 7e47494 (source; the bench branch only changes bench/), ReleaseFast, x86_64-linux-musl, busybox container
- MinIO: the official minio/minio image is not pullable (access denied); used
  pgsty/minio@sha256:b6bfe7239bfc83fb90d31612d9704d86039dd714f7904b3f1ad68f211e602372,
  `minio version RELEASE.2026-08-04T00-00-00Z (commit-id=d88f46ccee345a9c2fabe2d221d9a9e56bc11aec)`
- RustFS: rustfs/rustfs@sha256:1803faef57627e2d9c2e7d89d655d712ddded5389040054987163043fecb6a3c,
  `rustfs 1.0.1` (commit 6de965ae3c965a78ff819fbcd7acd4aa44177d92)
- Load generator: warp v1.8.2

## Limits and layout

| topology | containers | CPU per container | memory | drives |
|---|---|---|---|---|
| single | 1 | cpuset 0-3, --cpus 4 | 20 GiB | 4 x tmpfs 4096 MiB |
| cluster | 4 | one core each (0,1,2,3), --cpus 1 | 3 GiB each | 4 x tmpfs 512 MiB each |

warp runs in its own container on cores 4-7 (--cpus 4), same docker network, round-robin
across all server containers. tmpfs is charged to the container's memory limit.

Protection (erasure coding on all three):
- single: zkfsm EC:2+2; MinIO MINIO_STORAGE_CLASS_STANDARD=EC:2; RustFS RUSTFS_STORAGE_CLASS_STANDARD=EC:2.
- cluster: zkfsm EC:12+4; MinIO EC:4; RustFS EC:4 (16 drives: 12 data + 4 parity).

RustFS honouring the variable was checked: a 4 MiB object writes 2 MiB part files on each of
4 drives with EC:2, and 1.33 MiB with EC:1.

## Method

- Concurrency 32, bucket `zc-bench`. PUT runs use --disable-multipart (single-request PUT).
- Durations: 15 s, except PUT of 1 MiB and 16 MiB (6 s) and multipart (10 s), so the
  tmpfs drives can hold the run.
- GET/mixed prepare 2500 objects (4 KiB, 64 KiB), 1000 (1 MiB) or 100 (16 MiB). LIST uses 2500 x 4 KiB.
- mixed: warp's default split 45% GET, 30% STAT, 15% PUT, 10% DELETE; the table reports the Total.
- mp-64m: 64 MiB objects uploaded by minio-go as multipart with its default 16 MiB parts (4 parts).
- With LOAD_MAX set, each run waits until the 1-minute load average is below it, and
  until OUT has 512 MiB free.
- Every (workload, product) gets a freshly started target with empty drives, and a 3 s 4 KiB
  PUT as readiness gate and warm-up.
- 3 rounds. In each round, for every topology and workload, the three products run back to
  back; the product order rotates per round. The 1-minute load average is recorded before every run.
- Tables: median of 3 runs, min-max spread, warp averages; p50/p99 are medians of the per-run values.

    bench/compare.sh                                   # full matrix, 3 rounds
    PRODUCTS=rustfs TOPOS=single ROUNDS=1 bench/compare.sh

## Results (gated run, LOAD_MAX=4)

<!-- gated:start -->
Rounds included: 1, 2.

### Headline: obj/s median (min-max)


single

| workload | zkfsm | MinIO | RustFS |
|---|---|---|---|
| put-4k | 12478.6 (9463.3-15493.9) | 6100.5 (4836.7-7364.4) | 1411.5 (1133.5-1689.4) |
| put-64k | 6613.1 (6551.9-6674.4) | 3889.4 (3614.0-4164.9) | 1106.5 (1035.9-1177.0) |
| put-1m | 975.3 (750.2-1200.3) | 923.4 (752.9-1093.8) | 531.2 (428.9-633.6) |
| put-16m | 66.0 (53.5-78.4) | 65.8 (55.7-75.8) | 59.7 (50.4-68.9) |
| get-4k | 37467.8 (31747.1-43188.5) | 11248.6 (8911.6-13585.6) | 17704.2 (16775.7-18632.7) |
| get-64k | 16867.7 (13448.0-20287.4) | 8682.2 (8057.4-9306.9) | 12672.7 (12030.7-13314.7) |
| get-1m | 7338.6 (6771.8-7905.4) | 4796.7 (4480.4-5113.1) | 2515.2 (2453.3-2577.1) |
| get-16m | 416.8 (399.0-434.6) | 515.6 (470.5-560.7) | 143.1 (132.5-153.8) |
| list-4k | 264841.8 (261173.2-268510.4) | 72773.1 (62284.1-83262.0) | 12957.1 (12229.0-13685.3) |
| mixed-4k | 35066.7 (32253.1-37880.2) | 8521.6 (7990.1-9053.1) | 3568.5 (3519.8-3617.1) |
| mixed-1m | 4569.6 (4491.4-4647.8) | 3782.6 (3507.8-4057.5) | 1573.2 (1556.2-1590.3) |
| mp-64m | 10.3 (10.2-10.3) | 82.6 (61.6-103.7) | 8.5 (7.8-9.2) |

cluster

| workload | zkfsm | MinIO | RustFS |
|---|---|---|---|
| put-4k | 733.4 (676.6-790.2) | 856.7 (854.2-859.1) | 155.0 (154.7-155.3) |
| put-64k | 573.4 (529.9-616.8) | 859.8 (853.8-865.8) | 138.8 (138.4-139.2) |
| put-1m | 315.8 (304.4-327.1) | 320.8 (315.6-325.9) | 112.6 (112.4-112.8) |
| put-16m | 33.0 (31.4-34.5) | 35.1 (33.7-36.5) | 28.7 (28.5-29.0) |
| get-4k | 4241.8 (3801.8-4681.7) | 2032.6 (2005.8-2059.4) | 1347.3 (1344.8-1349.9) |
| get-64k | 2810.5 (2658.3-2962.7) | 1749.6 (1733.0-1766.1) | 1263.5 (1249.1-1278.0) |
| get-1m | 751.0 (699.0-803.0) | 953.8 (912.3-995.4) | 567.7 (558.6-576.8) |
| get-16m | 174.4 (171.6-177.2) | 238.8 (237.7-239.9) | 120.8 (120.8-120.8) [1 failed] |
| list-4k | 259738.8 (259087.4-260390.3) | 22506.7 (21713.1-23300.3) | 4775.3 (4736.2-4814.4) |
| mixed-4k | 2015.3 (2000.6-2029.9) | 1959.3 (1894.4-2024.1) | 381.3 (377.6-385.0) |
| mixed-1m | 732.8 (699.3-766.4) | 917.3 (898.1-936.4) | 296.8 (291.3-302.3) |
| mp-64m | 4.3 (4.0-4.7) | 0.3 (0.0-0.6) | 6.3 (5.4-7.2) |

### Detail: single

| workload | product | runs | obj/s median | obj/s min-max | MiB/s median | p50 ms | p99 ms | warp error lines per run | load1 at start (min-max) |
|---|---|---|---|---|---|---|---|---|---|
| put-4k | zkfsm | 2 | 12478.6 | 9463.3-15493.9 | 48.7 | 2.4 | 7.3 | 0,0 | 3.26-3.80 |
| put-4k | minio | 2 | 6100.5 | 4836.7-7364.4 | 23.8 | 4.6 | 19.9 | 0,0 | 1.99-4.05 |
| put-4k | rustfs | 2 | 1411.5 | 1133.5-1689.4 | 5.5 | 23.3 | 30.0 | 0,0 | 3.77-4.24 |
| put-64k | zkfsm | 2 | 6613.1 | 6551.9-6674.4 | 413.3 | 4.2 | 16.9 | 0,0 | 3.07-3.37 |
| put-64k | minio | 2 | 3889.4 | 3614.0-4164.9 | 243.1 | 7.1 | 29.6 | 0,0 | 2.89-3.31 |
| put-64k | rustfs | 2 | 1106.5 | 1035.9-1177.0 | 69.2 | 28.8 | 36.5 | 0,0 | 2.65-4.13 |
| put-1m | zkfsm | 2 | 975.3 | 750.2-1200.3 | 975.3 | 30.5 | 98.0 | 0,0 | 3.23-3.90 |
| put-1m | minio | 2 | 923.4 | 752.9-1093.8 | 923.4 | 34.5 | 82.5 | 0,0 | 2.62-3.89 |
| put-1m | rustfs | 2 | 531.2 | 428.9-633.6 | 531.2 | 61.9 | 77.3 | 0,0 | 3.18-4.07 |
| put-16m | zkfsm | 2 | 66.0 | 53.5-78.4 | 1055.7 | 499.2 | 637.4 | 0,0 | 3.84-4.13 |
| put-16m | minio | 2 | 65.8 | 55.7-75.8 | 1052.1 | 446.3 | 1113.2 | 0,0 | 3.45-3.65 |
| put-16m | rustfs | 2 | 59.7 | 50.4-68.9 | 954.6 | 530.0 | 965.3 | 0,0 | 3.55-4.93 |
| get-4k | zkfsm | 2 | 37467.8 | 31747.1-43188.5 | 146.4 | 0.6 | 3.8 | 0,0 | 3.27-3.27 |
| get-4k | minio | 2 | 11248.6 | 8911.6-13585.6 | 43.9 | 2.5 | 11.3 | 0,0 | 2.95-3.91 |
| get-4k | rustfs | 2 | 17704.2 | 16775.7-18632.7 | 69.2 | 1.8 | 4.4 | 0,0 | 3.74-4.13 |
| get-64k | zkfsm | 2 | 16867.7 | 13448.0-20287.4 | 1054.2 | 1.9 | 4.7 | 0,0 | 3.50-4.39 |
| get-64k | minio | 2 | 8682.2 | 8057.4-9306.9 | 542.6 | 3.2 | 17.2 | 0,0 | 3.73-3.76 |
| get-64k | rustfs | 2 | 12672.7 | 12030.7-13314.7 | 792.0 | 2.4 | 6.3 | 0,0 | 4.32-4.86 |
| get-1m | zkfsm | 2 | 7338.6 | 6771.8-7905.4 | 7338.6 | 4.2 | 13.6 | 0,0 | 3.12-5.12 |
| get-1m | minio | 2 | 4796.7 | 4480.4-5113.1 | 4796.7 | 5.8 | 21.7 | 0,0 | 3.42-3.50 |
| get-1m | rustfs | 2 | 2515.2 | 2453.3-2577.1 | 2515.2 | 12.6 | 24.9 | 0,0 | 2.96-4.70 |
| get-16m | zkfsm | 2 | 416.8 | 399.0-434.6 | 6668.5 | 79.5 | 120.8 | 0,0 | 2.88-3.99 |
| get-16m | minio | 2 | 515.6 | 470.5-560.7 | 8249.5 | 64.9 | 111.6 | 0,0 | 3.30-3.46 |
| get-16m | rustfs | 2 | 143.1 | 132.5-153.8 | 2290.4 | 217.0 | 387.4 | 0,0 | 3.42-5.67 |
| list-4k | zkfsm | 2 | 264841.8 | 261173.2-268510.4 | - | 7.8 | 32.2 | 0,0 | 3.14-3.70 |
| list-4k | minio | 2 | 72773.1 | 62284.1-83262.0 | - | 33.7 | 77.9 | 0,0 | 3.03-3.10 |
| list-4k | rustfs | 2 | 12957.1 | 12229.0-13685.3 | - | 195.2 | 273.5 | 0,0 | 3.07-4.30 |
| mixed-4k | zkfsm | 2 | 35066.7 | 32253.1-37880.2 | 82.2 | - | - | 0,0 | 3.60-4.54 |
| mixed-4k | minio | 2 | 8521.6 | 7990.1-9053.1 | 20.0 | - | - | 0,0 | 3.16-3.62 |
| mixed-4k | rustfs | 2 | 3568.5 | 3519.8-3617.1 | 8.4 | - | - | 0,0 | 3.02-5.05 |
| mixed-1m | zkfsm | 2 | 4569.6 | 4491.4-4647.8 | 2742.0 | - | - | 0,0 | 2.91-3.43 |
| mixed-1m | minio | 2 | 3782.6 | 3507.8-4057.5 | 2269.3 | - | - | 1093,722 | 3.18-3.43 |
| mixed-1m | rustfs | 2 | 1573.2 | 1556.2-1590.3 | 944.6 | - | - | 0,0 | 3.27-3.72 |
| mp-64m | zkfsm | 2 | 10.3 | 10.2-10.3 | 658.3 | 3085.8 | 4238.9 | 0,0 | 3.08-3.13 |
| mp-64m | minio | 2 | 82.6 | 61.6-103.7 | 865.3 | 49.8 | 2340.9 | 1107,799 | 3.49-3.71 |
| mp-64m | rustfs | 2 | 8.5 | 7.8-9.2 | 402.6 | 3956.9 | 6786.7 | 149,156 | 3.39-4.60 |

### Detail: cluster

| workload | product | runs | obj/s median | obj/s min-max | MiB/s median | p50 ms | p99 ms | warp error lines per run | load1 at start (min-max) |
|---|---|---|---|---|---|---|---|---|---|
| put-4k | zkfsm | 2 | 733.4 | 676.6-790.2 | 2.9 | 32.4 | 157.9 | 0,0 | 4.93-6.17 |
| put-4k | minio | 2 | 856.7 | 854.2-859.1 | 3.3 | 2.0 | 337.4 | 0,0 | 2.68-3.79 |
| put-4k | rustfs | 2 | 155.0 | 154.7-155.3 | 0.6 | 208.1 | 324.4 | 0,0 | 2.54-3.59 |
| put-64k | zkfsm | 2 | 573.4 | 529.9-616.8 | 35.8 | 40.2 | 191.3 | 0,0 | 4.58-8.14 |
| put-64k | minio | 2 | 859.8 | 853.8-865.8 | 53.7 | 2.7 | 336.9 | 0,0 | 3.12-5.51 |
| put-64k | rustfs | 2 | 138.8 | 138.4-139.2 | 8.7 | 239.1 | 319.0 | 0,0 | 2.87-2.89 |
| put-1m | zkfsm | 2 | 315.8 | 304.4-327.1 | 315.8 | 78.2 | 320.5 | 0,0 | 3.95-8.14 |
| put-1m | minio | 2 | 320.8 | 315.6-325.9 | 320.8 | 33.0 | 373.2 | 0,0 | 3.08-3.54 |
| put-1m | rustfs | 2 | 112.6 | 112.4-112.8 | 112.6 | 286.0 | 590.2 | 0,0 | 3.00-3.25 |
| put-16m | zkfsm | 2 | 33.0 | 31.4-34.5 | 495.9 | 3159.7 | 5145.8 | 27,24 | 4.19-4.70 |
| put-16m | minio | 2 | 35.1 | 33.7-36.5 | 562.0 | 899.0 | 1600.6 | 0,0 | 3.50-4.02 |
| put-16m | rustfs | 2 | 28.7 | 28.5-29.0 | 459.8 | 1112.8 | 1643.8 | 0,0 | 3.04-3.07 |
| get-4k | zkfsm | 2 | 4241.8 | 3801.8-4681.7 | 16.6 | 2.9 | 66.7 | 0,0 | 3.95-5.03 |
| get-4k | minio | 2 | 2032.6 | 2005.8-2059.4 | 7.9 | 13.1 | 37.5 | 0,0 | 3.16-3.32 |
| get-4k | rustfs | 2 | 1347.3 | 1344.8-1349.9 | 5.3 | 23.6 | 45.3 | 0,0 | 2.41-2.71 |
| get-64k | zkfsm | 2 | 2810.5 | 2658.3-2962.7 | 175.7 | 4.5 | 91.8 | 0,0 | 3.21-4.39 |
| get-64k | minio | 2 | 1749.6 | 1733.0-1766.1 | 109.3 | 15.8 | 41.0 | 0,0 | 2.90-3.22 |
| get-64k | rustfs | 2 | 1263.5 | 1249.1-1278.0 | 79.0 | 24.5 | 52.2 | 0,0 | 3.03-3.15 |
| get-1m | zkfsm | 2 | 751.0 | 699.0-803.0 | 751.0 | 23.4 | 214.1 | 0,0 | 4.58-6.10 |
| get-1m | minio | 2 | 953.8 | 912.3-995.4 | 953.8 | 31.2 | 67.5 | 0,0 | 3.00-3.46 |
| get-1m | rustfs | 2 | 567.7 | 558.6-576.8 | 567.7 | 48.8 | 117.5 | 0,0 | 3.14-3.48 |
| get-16m | zkfsm | 2 | 174.4 | 171.6-177.2 | 2790.3 | 162.0 | 383.9 | 0,0 | 3.39-5.50 |
| get-16m | minio | 2 | 238.8 | 237.7-239.9 | 3820.4 | 130.6 | 222.9 | 0,0 | 2.94-3.29 |
| get-16m | rustfs | 1 (1 failed) | 120.8 | 120.8-120.8 | 1932.6 | 265.8 | 441.2 | 0 | 3.15-3.15 |
| list-4k | zkfsm | 2 | 259738.8 | 259087.4-260390.3 | - | 8.0 | 36.0 | 0,0 | 3.39-6.42 |
| list-4k | minio | 2 | 22506.7 | 21713.1-23300.3 | - | 103.3 | 195.1 | 0,0 | 3.14-3.67 |
| list-4k | rustfs | 2 | 4775.3 | 4736.2-4814.4 | - | 198.3 | 1961.0 | 0,0 | 4.84-5.04 |
| mixed-4k | zkfsm | 2 | 2015.3 | 2000.6-2029.9 | 4.7 | - | - | 0,0 | 4.95-5.24 |
| mixed-4k | minio | 2 | 1959.3 | 1894.4-2024.1 | 4.6 | - | - | 0,0 | 2.59-3.77 |
| mixed-4k | rustfs | 2 | 381.3 | 377.6-385.0 | 0.9 | - | - | 0,0 | 3.26-3.73 |
| mixed-1m | zkfsm | 2 | 732.8 | 699.3-766.4 | 440.3 | - | - | 0,0 | 4.70-5.04 |
| mixed-1m | minio | 2 | 917.3 | 898.1-936.4 | 550.7 | - | - | 0,0 | 2.75-3.34 |
| mixed-1m | rustfs | 2 | 296.8 | 291.3-302.3 | 177.5 | - | - | 0,0 | 2.96-3.42 |
| mp-64m | zkfsm | 2 | 4.3 | 4.0-4.7 | 278.0 | 7171.8 | 9967.5 | 0,0 | 0.95-5.00 |
| mp-64m | minio | 2 | 0.3 | 0.0-0.6 | 12.8 | 509020.1 | 510594.6 | 39,100 | 3.23-3.52 |
| mp-64m | rustfs | 2 | 6.3 | 5.4-7.2 | 395.8 | 5385.4 | 6353.6 | 101,0 | 0.40-0.91 |

Load average (1 min) at the start of each run: min 0.40, median 3.43, max 8.14.

- FAILED: rustfs cluster get-16m round 1: rc=1 ok

versions.txt of the run:

    warp: v1.8.2
    zkfsm: 3c9b267 ReleaseFast x86_64-linux-musl
    minio: minio version RELEASE.2026-08-04T00-00-00Z (commit-id=d88f46ccee345a9c2fabe2d221d9a9e56bc11aec) pgsty/minio@sha256:b6bfe7239bfc83fb90d31612d9704d86039dd714f7904b3f1ad68f211e602372
    rustfs: rustfs 1.0.1 rustfs/rustfs@sha256:1803faef57627e2d9c2e7d89d655d712ddded5389040054987163043fecb6a3c
<!-- gated:end -->

The load average recorded is taken just before each run starts. The benchmark itself
puts about 8 runnable threads on the host (4 server cores, 4 client cores), so the load
rises during a run; the gate keeps other work from overlapping as far as it can.

## Preliminary results (2026-10-14 13:28-16:19, load average 4.7-74.6, median 34; do not cite)
### single

| workload | product | n | obj/s median | obj/s min-max | MiB/s median | p50 ms median | p99 ms median | err lines | load1 range |
|---|---|---|---|---|---|---|---|---|---|
| put-4k | zkfsm | 3 | 3875.7 | 2090.7-6044.6 | 15.1 | 7.0 | 27.2 | 0,0,0 | 4.7-45.5 |
| put-4k | minio | 3 | 1701.2 | 973.9-2144.1 | 6.7 | 15.8 | 64.2 | 0,0,0 | 10.3-55.1 |
| put-4k | rustfs | 3 | 492.4 | 304.0-595.0 | 1.9 | 64.0 | 97.0 | 0,0,0 | 11.6-39.0 |
| put-64k | zkfsm | 3 | 3446.6 | 1042.6-3504.2 | 215.4 | 8.3 | 40.2 | 0,0,0 | 11.8-57.1 |
| put-64k | minio | 3 | 1455.1 | 693.8-1710.7 | 90.9 | 18.6 | 65.5 | 0,0,0 | 15.0-60.0 |
| put-64k | rustfs | 3 | 518.8 | 243.6-713.3 | 32.4 | 59.2 | 91.9 | 0,0,0 | 12.1-58.5 |
| put-1m | zkfsm | 3 | 516.5 | 225.5-611.3 | 516.5 | 55.6 | 147.9 | 0,0,0 | 11.1-64.5 |
| put-1m | minio | 3 | 455.3 | 214.1-578.6 | 455.3 | 68.0 | 131.4 | 0,0,0 | 11.5-71.5 |
| put-1m | rustfs | 3 | 174.4 | 134.0-295.2 | 174.4 | 175.7 | 292.0 | 0,0,0 | 10.5-64.0 |
| put-16m | zkfsm | 3 | 32.6 | 29.0-33.2 | 522.0 | 947.7 | 1816.2 | 0,0,0 | 22.4-72.5 |
| put-16m | minio | 3 | 27.3 | 23.8-27.7 | 437.5 | 1053.5 | 2529.9 | 0,0,0 | 14.1-68.0 |
| put-16m | rustfs | 3 | 27.4 | 18.6-29.5 | 438.0 | 1120.4 | 2411.1 | 0,0,0 | 20.1-73.6 |
| get-4k | zkfsm | 3 | 15196.7 | 11707.5-20026.3 | 59.4 | 1.5 | 10.7 | 0,0,0 | 16.1-63.9 |
| get-4k | minio | 3 | 5741.0 | 2789.2-5787.9 | 22.4 | 4.8 | 20.7 | 0,0,0 | 19.9-61.3 |
| get-4k | rustfs | 3 | 5605.7 | 3658.6-5709.6 | 21.9 | 5.8 | 18.9 | 0,0,0 | 16.1-65.4 |
| get-64k | zkfsm | 3 | 4353.3 | 4088.8-5599.1 | 272.1 | 4.3 | 25.5 | 0,0,0 | 18.4-60.6 |
| get-64k | minio | 3 | 2886.7 | 2454.0-3780.4 | 180.4 | 8.9 | 38.1 | 0,0,0 | 18.7-65.1 |
| get-64k | rustfs | 3 | 5012.2 | 2378.8-5049.4 | 313.3 | 5.8 | 18.5 | 0,0,0 | 16.3-61.5 |
| get-1m | zkfsm | 3 | 2789.1 | 2351.4-2989.8 | 2789.1 | 9.8 | 40.7 | 0,0,0 | 22.2-62.5 |
| get-1m | minio | 3 | 1605.1 | 1332.9-2404.4 | 1605.1 | 16.9 | 55.4 | 0,0,0 | 20.9-63.2 |
| get-1m | rustfs | 3 | 1231.2 | 1008.5-1544.2 | 1231.2 | 24.5 | 58.6 | 0,0,0 | 15.2-64.1 |
| get-16m | zkfsm | 3 | 197.8 | 193.9-211.3 | 3164.9 | 156.8 | 290.7 | 0,0,0 | 12.1-72.2 |
| get-16m | minio | 3 | 198.8 | 186.2-208.3 | 3180.9 | 160.7 | 328.4 | 0,0,0 | 17.8-73.9 |
| get-16m | rustfs | 3 | 101.7 | 71.8-108.9 | 1627.9 | 301.5 | 720.2 | 0,0,0 | 16.8-69.1 |
| list-4k | zkfsm | 3 | 53367.3 | 44270.7-68109.1 | - | 41.0 | 179.5 | 0,0,0 | 24.7-73.2 |
| list-4k | minio | 3 | 21419.6 | 12580.2-33800.4 | - | 103.8 | 281.5 | 0,0,0 | 21.2-74.5 |
| list-4k | rustfs | 3 | 3203.3 | 2870.3-3920.8 | - | 760.7 | 1245.5 | 0,0,0 | 18.6-74.5 |
| mixed-4k | zkfsm | 3 | 7801.2 | 5497.3-11243.8 | 18.3 | - | - | 0,0,0 | 26.8-73.6 |
| mixed-4k | minio | 3 | 2691.9 | 2113.2-3612.0 | 6.3 | - | - | 0,0,0 | 22.4-74.6 |
| mixed-4k | rustfs | 3 | 1126.3 | 815.4-1211.6 | 2.6 | - | - | 0,0,0 | 21.5-70.7 |
| mixed-1m | zkfsm | 3 | 1335.7 | 1158.6-2134.5 | 801.3 | - | - | 0,0,0 | 25.1-43.2 |
| mixed-1m | minio | 3 | 1279.6 | 786.4-1281.2 | 767.2 | - | - | 0,0,0 | 31.0-44.4 |
| mixed-1m | rustfs | 3 | 773.2 | 364.2-849.8 | 464.2 | - | - | 0,0,0 | 27.2-57.3 |
| mp-64m | zkfsm | 3 | 4.7 | 3.9-5.2 | 301.9 | 6640.6 | 10016.1 | 0,0,0 | 24.4-44.5 |
| mp-64m | minio | 3 | 8.6 | 5.7-9.1 | 547.5 | 3551.2 | 5679.9 | 0,0,0 | 30.3-40.4 |
| mp-64m | rustfs | 3 | 7.4 | 3.5-8.7 | 472.5 | 4079.9 | 7413.8 | 0,0,0 | 24.5-43.6 |

### cluster

| workload | product | n | obj/s median | obj/s min-max | MiB/s median | p50 ms median | p99 ms median | err lines | load1 range |
|---|---|---|---|---|---|---|---|---|---|
| put-4k | zkfsm | 3 | 351.4 | 345.6-368.3 | 1.4 | 81.0 | 212.9 | 0,0,0 | 25.5-46.1 |
| put-4k | minio | 3 | 408.0 | 347.6-452.4 | 1.6 | 14.7 | 358.2 | 0,0,0 | 28.2-46.2 |
| put-4k | rustfs | 3 | 48.9 | 46.6-73.1 | 0.2 | 620.0 | 1109.3 | 0,0,0 | 19.2-40.5 |
| put-64k | zkfsm | 3 | 367.8 | 320.7-376.8 | 23.0 | 79.4 | 208.1 | 0,0,0 | 15.2-52.9 |
| put-64k | minio | 3 | 431.1 | 306.8-502.2 | 26.9 | 16.7 | 361.6 | 0,0,0 | 16.1-51.5 |
| put-64k | rustfs | 3 | 48.1 | 38.5-62.1 | 3.0 | 662.2 | 937.8 | 0,0,0 | 16.3-54.4 |
| put-1m | zkfsm | 3 | 185.4 | 170.6-211.3 | 185.4 | 157.3 | 432.7 | 0,0,0 | 15.9-61.1 |
| put-1m | minio | 3 | 122.7 | 104.9-178.4 | 122.7 | 248.0 | 539.7 | 0,0,0 | 15.1-54.4 |
| put-1m | rustfs | 3 | 34.8 | 30.3-53.7 | 34.8 | 909.2 | 1211.2 | 0,0,0 | 14.1-58.2 |
| put-16m | zkfsm | 3 | 26.4 | 26.4-29.5 | 422.8 | 1144.3 | 1606.2 | 0,0,0 | 22.7-51.0 |
| put-16m | minio | 3 | 12.7 | 12.0-16.7 | 203.3 | 2464.7 | 4271.6 | 0,0,0 | 25.6-56.5 |
| put-16m | rustfs | 3 | 8.5 | 8.3-10.1 | 135.8 | 4011.8 | 4944.7 | 0,0,0 | 21.0-48.4 |
| get-4k | zkfsm | 3 | 1403.2 | 1288.9-1743.4 | 5.5 | 9.1 | 128.9 | 0,0,0 | 26.9-42.9 |
| get-4k | minio | 3 | 602.0 | 578.3-769.9 | 2.4 | 45.9 | 127.5 | 0,0,0 | 36.7-51.8 |
| get-4k | rustfs | 3 | 483.0 | 476.8-646.9 | 1.9 | 61.1 | 107.3 | 0,0,0 | 35.4-49.0 |
| get-64k | zkfsm | 3 | 1312.8 | 1197.6-1401.4 | 82.0 | 13.1 | 154.3 | 0,0,0 | 34.2-41.1 |
| get-64k | minio | 3 | 631.6 | 515.4-664.5 | 39.5 | 44.8 | 124.6 | 0,0,0 | 45.5-48.8 |
| get-64k | rustfs | 3 | 548.2 | 483.7-580.0 | 34.3 | 54.8 | 137.9 | 0,0,0 | 34.7-55.4 |
| get-1m | zkfsm | 3 | 372.6 | 349.7-473.7 | 372.6 | 73.0 | 253.0 | 0,0,0 | 30.8-46.0 |
| get-1m | minio | 3 | 308.3 | 305.8-360.8 | 308.3 | 96.8 | 211.8 | 0,0,0 | 44.1-72.6 |
| get-1m | rustfs | 3 | 251.4 | 229.3-259.1 | 251.4 | 121.9 | 254.9 | 0,0,0 | 36.2-55.6 |
| get-16m | zkfsm | 3 | 93.6 | 39.1-93.8 | 1497.5 | 278.1 | 1006.8 | 0,0,0 | 15.7-29.3 |
| get-16m | minio | 3 | 118.2 | 111.4-122.4 | 1890.7 | 268.0 | 499.0 | 32,0,0 | 27.5-39.6 |
| get-16m | rustfs | 3 | 56.9 | 36.8-76.5 | 910.7 | 543.4 | 924.6 | 0,0,0 | 22.2-25.7 |
| list-4k | zkfsm | 3 | 75730.1 | 73985.9-86919.8 | - | 28.7 | 86.5 | 0,0,0 | 13.8-31.9 |
| list-4k | minio | 3 | 6962.2 | 5726.5-9959.2 | - | 342.2 | 694.1 | 0,0,0 | 20.4-33.1 |
| list-4k | rustfs | 3 | 1956.1 | 1563.5-2686.9 | - | 1348.9 | 3348.7 | 0,0,0 | 12.5-26.6 |
| mixed-4k | zkfsm | 3 | 1108.1 | 1043.0-1692.0 | 2.6 | - | - | 0,0,0 | 8.3-54.2 |
| mixed-4k | minio | 3 | 746.4 | 673.6-756.4 | 1.8 | - | - | 0,0,0 | 13.8-53.5 |
| mixed-4k | rustfs | 3 | 144.0 | 129.6-298.8 | 0.3 | - | - | 0,0,0 | 8.4-36.9 |
| mixed-1m | zkfsm | 3 | 483.9 | 440.1-588.7 | 290.8 | - | - | 0,0,0 | 10.1-57.5 |
| mixed-1m | minio | 3 | 336.7 | 308.6-610.7 | 202.0 | - | - | 0,0,0 | 10.9-53.4 |
| mixed-1m | rustfs | 3 | 124.6 | 93.0-204.5 | 74.8 | - | - | 0,0,0 | 10.4-49.3 |
| mp-64m | zkfsm | 3 | 2.1 | 1.9-2.9 | 132.8 | 15478.9 | 15820.2 | 0,0,0 | 17.1-40.8 |
| mp-64m | minio | 3 | 4.1 | 2.9-4.3 | 263.1 | 7808.6 | 9809.9 | 0,0,0 | 15.8-49.0 |
| mp-64m | rustfs | 3 | 2.8 | 2.4-3.0 | 181.2 | 11385.6 | 11479.7 | 0,0,0 | 12.2-40.7 |


## RustFS failures in the earlier run (2026-10-08)

That run saw RustFS put-1m fail in both topologies ("You did not provide the number of bytes
specified by the Content-Length HTTP header"), 1213 error lines in single mixed-1m, and a hung
cluster mixed-1m. Findings:

- Cause on our side: the harness ran every workload against one target, relying on warp's
  cleanup between runs. RustFS moves deleted objects to `.rustfs.sys/tmp/.trash` on each drive
  and did not reclaim them within 120 s after a delete (measured: 1210 MiB per drive remained
  in .trash 2 minutes after a 5 s 16 MiB PUT run's cleanup). With small tmpfs drives, later
  runs hit a full drive. A probe with the old flow reproduced it: put-1m and put-16m then
  mp-64m on one target gave 32 "We encountered an internal error" upload errors, and the
  RustFS log showed `DiskFull` (scanner journal, heal state, usage cache writes).
- RustFS writes its logs to /logs on the container's overlay by default
  (RUSTFS_OBS_LOG_DIRECTORY); the harness now sets it empty so logs go to stdout.
- Fix in compare.sh: a fresh target with empty drives for every (workload, product), applied
  to all three products; drives enlarged to 4 GiB (single), large PUTs capped at 6 s.
- Also a harness issue: 4 s large-object PUT runs gave warp "Skipping PUT too few samples"
  (no result row, no error) for RustFS; durations are now 6 s / 10 s.
- With these changes, RustFS completed every workload in all 3 rounds with 0 warp error lines,
  including put-1m and mixed-1m in both topologies. The Content-Length error was not reproduced.
  What remains RustFS behaviour: deleted data is not reclaimed promptly, so a drive near capacity
  under a delete-heavy load reports DiskFull.

## Other anomalies

- MinIO cluster get-16m round 1: 32 warp errors "Resource requested is unwritable, please
  reduce your request rate" (prepare step; 3 GiB-per-node memory limit, load average ~25). Rounds 2-3 clean.
- A first attempt at the quiet re-run (2026-10-14 19:47) lost its quiet window after round 1
  (rounds 2-3 started at load 20-51) and was stopped. In it, RustFS cluster mixed-1m round 2
  failed with rc=1 and empty logs: the host /tmp tmpfs (which held OUT) was full from other
  processes, so warp's and docker's output could not be written. That is a harness/host
  failure, not RustFS; compare.sh now waits for free space in OUT before each run.
