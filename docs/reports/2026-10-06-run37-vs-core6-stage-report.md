# IBD stage report: Core v31.1 vs bmc

Segments of 100,000 heights. Times are seconds unless written h:mm:ss; elapsed times are from each run's own start.

## Runs

| | log | start (UTC) | max height | blocks w/ stage lines | IBD end | ready | ready height |
|---|---|---|---|---|---|---|---|
| Core | `/srv/nvme8tb/bench/core31-rerun6-20261004-logs/debug.log` | 2026-10-04 18:20:24 | 969,958 | 969,959 | 10:41:21 | 10:42:05 (tip 10:41:35) | 969,958 |
| bmc | `/srv/nvme8tb/bench/run37/data/main/debug.log` | 2026-10-06 00:06:24 | 970,133 | 970,134 | 4:49:12 | 4:50:52 | 970,101 |

Core: IBD end = "Leaving InitialBlockDownload"; ready = READY_INDEXES (the first getindexinfo after READY_TIP with every index at that height), READY_TIP = its UpdateTip at the oracle's tip. bmc: IBD end = "[dlc] catch-up done" (or phase.log IBD_END); ready = "[ready] all indexes at height N".

## Milestones (elapsed to the first block at or past each height)

| height | Core | bmc | bmc/Core |
|---|---|---|---|
| 100,000 | 0:04:12 | 0:05:22 | 1.28 |
| 200,000 | 0:08:15 | 0:09:22 | 1.13 |
| 300,000 | 0:23:34 | 0:16:03 | 0.68 |
| 400,000 | 0:54:56 | 0:30:27 | 0.55 |
| 500,000 | 2:02:42 | 0:58:53 | 0.48 |
| 600,000 | 3:19:14 | 1:31:26 | 0.46 |
| 700,000 | 4:53:00 | 2:13:15 | 0.45 |
| 800,000 | 6:35:51 | 2:54:02 | 0.44 |
| 900,000 | 9:01:23 | 4:03:31 | 0.45 |
| 970,133 | -- | 4:51:15 | -- |

## Wall time per segment

| segment | Core wall | bmc wall | bmc/Core |
|---|---|---|---|
| 0-99,999 | 252.0 | 322.5 | 1.28 |
| 100,000-199,999 | 243.3 | 239.5 | 0.98 |
| 200,000-299,999 | 919.2 | 401.9 | 0.44 |
| 300,000-399,999 | 1881.8 | 864.0 | 0.46 |
| 400,000-499,999 | 4066.1 | 1705.9 | 0.42 |
| 500,000-599,999 | 4592.0 | 1953.1 | 0.43 |
| 600,000-699,999 | 5626.5 | 2508.2 | 0.45 |
| 700,000-799,999 | 6170.9 | 2447.4 | 0.40 |
| 800,000-899,999 | 8732.0 | 4168.9 | 0.48 |
| 900,000-970,133 | 6012.3 | 2864.6 | 0.48 |

## Core: stages per segment (sum over blocks, seconds)

| segment | wall | blocks | connect block | load | sanity | fork | connect txs | verify wait | undo | index writing | flush | write chainstate | postprocess | outside connect | UTXO flushes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0-99,999 | 252.0 | 100,000 | 3.5 | 0.3 | 0.1 | 0.1 | 0.1 | 0.2 | 0.4 | 0.0 | 0.0 | 0.0 | 0.2 | 248.5 | 0 / 0.0 |
| 100,000-199,999 | 243.3 | 100,000 | 34.4 | 6.1 | 1.9 | 8.9 | 8.1 | 0.2 | 3.0 | 0.0 | 4.6 | 0.0 | 0.4 | 208.8 | 0 / 0.0 |
| 200,000-299,999 | 919.2 | 100,000 | 164.2 | 24.4 | 7.9 | 10.3 | 50.6 | 0.5 | 12.7 | 0.0 | 55.0 | 0.2 | 0.7 | 754.9 | 0 / 0.0 |
| 300,000-399,999 | 1881.8 | 100,000 | 557.0 | 73.7 | 23.2 | 0.7 | 186.4 | 0.9 | 36.7 | 0.1 | 230.1 | 0.7 | 1.2 | 1324.8 | 0 / 0.0 |
| 400,000-499,999 | 4066.1 | 100,000 | 1301.6 | 159.4 | 52.6 | 1.4 | 499.4 | 1.4 | 73.9 | 0.4 | 503.8 | 1.3 | 2.6 | 2764.5 | 2 / 58.2 |
| 500,000-599,999 | 4592.0 | 100,000 | 1610.6 | 242.2 | 56.3 | 1.5 | 582.6 | 1.5 | 76.8 | 0.6 | 588.5 | 52.3 | 2.6 | 2981.4 | 2 / 103.9 |
| 600,000-699,999 | 5626.5 | 100,000 | 2044.8 | 321.4 | 66.5 | 1.7 | 752.0 | 1.7 | 92.4 | 0.6 | 744.4 | 55.2 | 3.1 | 3581.7 | 2 / 104.5 |
| 700,000-799,999 | 6170.9 | 100,000 | 2202.4 | 393.0 | 69.9 | 1.7 | 761.4 | 1.7 | 99.7 | 1.2 | 816.0 | 48.1 | 3.2 | 3968.5 | 2 / 100.4 |
| 800,000-899,999 | 8732.0 | 100,000 | 3627.0 | 603.6 | 99.7 | 2.0 | 1532.2 | 2.2 | 100.9 | 1.1 | 949.1 | 321.1 | 3.0 | 5105.0 | 6 / 336.4 |
| 900,000-970,133 | 6012.3 | 69,959 | 2363.7 | 464.9 | 75.1 | 1.4 | 949.9 | 102.4 | 66.0 | 0.6 | 572.2 | 115.5 | 2.8 | 3648.6 | 2 / 99.7 |
| **total** | 38496.0 | 969,959 | 13909.2 | 2289.1 | 453.2 | 30.0 | 5322.7 | 112.6 | 562.5 | 4.7 | 4463.8 | 594.5 | 19.8 | 24586.7 | 16 / 802.9 |

connect block = Core's own per-block total (load .. postprocess). verify wait = "Verify" minus "Connect N transactions" (Verify is timed from the same start). outside connect = wall minus connect block: waiting for blocks to arrive, header sync, and anything ActivateBestChain does between blocks (index callbacks run on their own threads). UTXO flushes = count / seconds of "write coins cache to disk" (already inside write chainstate when IF_NEEDED; periodic ones fall between blocks).

Core flush and coindb lines: 18 chainstate writes (FORCE_FLUSH 2, IF_NEEDED 10, PERIODIC 6); 715,445,080 txouts committed; block index writes 18 (2.0 s); block/undo file flushes 18 (1.4 s); disconnects 0.

## bmc: stages per segment (sum over blocks, seconds)

| segment | wall | blocks | total | read | idx | verify | get | put | ckpt | flush | csi | put.ins | put.get | put.undo | put.del | put.wal | other | ix txindex | ix txospender | ix bfilter | ix addr | ix zmq | outside |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0-99,999 | 322.5 | 100,000 | 4.1 | 0.0 | 0.0 | 0.1 | 0.0 | 1.7 | 2.0 | 0.0 | 0.0 | 0.8 | 0.0 | 0.1 | 0.3 | 0.0 | 0.2 | 0.0 | 0.0 | 0.4 | 0.0 | 0.0 | 318.0 |
| 100,000-199,999 | 239.5 | 100,000 | 35.0 | 0.1 | 2.8 | 2.8 | 4.0 | 20.5 | 2.6 | 0.0 | 1.7 | 9.8 | 0.0 | 3.8 | 5.1 | 0.3 | 0.5 | 1.8 | 0.0 | 3.4 | 0.0 | 0.0 | 199.3 |
| 200,000-299,999 | 401.9 | 100,000 | 175.1 | 0.8 | 15.5 | 7.9 | 17.8 | 90.5 | 7.9 | 25.6 | 8.6 | 29.2 | 0.0 | 19.0 | 33.7 | 1.8 | 0.4 | 8.7 | 0.0 | 8.5 | 0.0 | 0.0 | 209.7 |
| 300,000-399,999 | 864.0 | 100,000 | 614.1 | 2.2 | 47.3 | 17.6 | 85.0 | 326.5 | 21.3 | 89.2 | 24.1 | 93.2 | 1.0 | 55.8 | 152.5 | 4.3 | 0.9 | 22.8 | 0.0 | 21.7 | 0.0 | 0.0 | 205.4 |
| 400,000-499,999 | 1705.9 | 100,000 | 1454.2 | 15.5 | 112.6 | 33.3 | 365.4 | 692.5 | 34.1 | 147.9 | 48.5 | 211.9 | 5.0 | 109.5 | 318.3 | 8.8 | 4.4 | 48.9 | 0.0 | 42.0 | 0.0 | 0.0 | 160.9 |
| 500,000-599,999 | 1953.1 | 100,000 | 1686.6 | 7.7 | 161.5 | 38.7 | 544.8 | 663.2 | 24.5 | 186.4 | 53.9 | 188.7 | 7.5 | 116.9 | 298.2 | 9.0 | 6.0 | 46.2 | 0.0 | 46.2 | 0.0 | 0.0 | 174.1 |
| 600,000-699,999 | 2508.2 | 100,000 | 2219.6 | 30.4 | 191.2 | 49.0 | 691.9 | 949.6 | 34.0 | 197.8 | 67.9 | 265.4 | 9.3 | 146.6 | 462.3 | 10.7 | 7.8 | 50.5 | 0.0 | 58.7 | 0.0 | 0.0 | 179.4 |
| 700,000-799,999 | 2447.4 | 100,000 | 2131.4 | 31.4 | 193.6 | 53.0 | 605.6 | 918.7 | 35.2 | 213.7 | 72.1 | 239.3 | 8.1 | 149.9 | 455.9 | 8.3 | 8.0 | 45.4 | 0.0 | 62.6 | 0.0 | 0.0 | 208.0 |
| 800,000-899,999 | 4168.9 | 100,000 | 3775.2 | 69.0 | 267.8 | 75.3 | 1567.4 | 1305.9 | 28.0 | 356.9 | 93.9 | 410.9 | 24.4 | 193.6 | 591.8 | 8.3 | 11.0 | 60.3 | 0.0 | 74.8 | 0.0 | 0.0 | 258.6 |
| 900,000-970,133 | 2864.6 | 70,134 | 2507.2 | 53.6 | 186.0 | 497.3 | 768.2 | 718.1 | 26.2 | 185.4 | 64.3 | 213.1 | 10.4 | 132.7 | 303.9 | 7.2 | 8.1 | 42.5 | 0.0 | 48.1 | 0.0 | 0.0 | 266.8 |
| **total** | 17476.0 | 970,134 | 14602.4 | 210.7 | 1178.4 | 774.9 | 4650.1 | 5687.1 | 215.8 | 1403.0 | 435.0 | 1662.1 | 65.7 | 927.9 | 2621.9 | 58.7 | 47.5 | 327.1 | 0.0 | 366.4 | 0.0 | 0.0 | 2180.0 |

total = the block line's own total; other = total minus the named stages. ix = the choke-point index work outside the block total ([bench] index lines). outside = wall minus (total + ix): download waits and everything off the apply path. bmc applies on a pipeline, so outside is not idle time by itself.

Other bmc [bench] lines: flush x110 (1394.1 s)

Download chunks ([dlc] chunk lines): 60650; bytes 774.06 GB; wait sum 5200 s, p50 0.05 s, p90 0.15 s, max 8.04 s; wall sum 80821 s, p50 1.15 s, p90 2.92 s, max 168.43 s; 68 distinct peers. Final [dlc] summary line, after the download ended (recv is the idle tail, not the run): recv 0.0B/s (avg 42.9MB/s), pool idle 6%. Peer status lines named 38 distinct peers.

