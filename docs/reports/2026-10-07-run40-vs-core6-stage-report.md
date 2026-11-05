# IBD stage report: Core v31.1 vs bmc

Segments of 100,000 heights. Times are seconds unless written h:mm:ss; elapsed times are from each run's own start.

## Runs

| | log | start (UTC) | max height | blocks w/ stage lines | IBD end | ready | ready height |
|---|---|---|---|---|---|---|---|
| Core | `/srv/nvme8tb/bench/core31-rerun6-20261004-logs/debug.log` | 2026-10-04 18:20:24 | 969,958 | 969,959 | 10:41:21 | 10:42:05 (tip 10:41:35) | 969,958 |
| bmc | `/srv/nvme8tb/bench/run40/data/main/debug.log` | 2026-10-06 20:34:00 | 970,267 | 970,268 | 4:41:02 | 4:42:41 | 970,267 |

Core: IBD end = "Leaving InitialBlockDownload"; ready = READY_INDEXES (the first getindexinfo after READY_TIP with every index at that height), READY_TIP = its UpdateTip at the oracle's tip. bmc: IBD end = "[dlc] catch-up done" (or phase.log IBD_END); ready = "[ready] all indexes at height N".

## Milestones (elapsed to the first block at or past each height)

| height | Core | bmc | bmc/Core |
|---|---|---|---|
| 100,000 | 0:04:12 | 0:04:16 | 1.02 |
| 200,000 | 0:08:15 | 0:08:12 | 0.99 |
| 300,000 | 0:23:34 | 0:15:36 | 0.66 |
| 400,000 | 0:54:56 | 0:30:11 | 0.55 |
| 500,000 | 2:02:42 | 0:56:47 | 0.46 |
| 600,000 | 3:19:14 | 1:30:21 | 0.45 |
| 700,000 | 4:53:00 | 2:09:39 | 0.44 |
| 800,000 | 6:35:51 | 2:49:21 | 0.43 |
| 900,000 | 9:01:23 | 3:55:58 | 0.44 |
| 970,267 | -- | 4:42:41 | -- |

## Wall time per segment

| segment | Core wall | bmc wall | bmc/Core |
|---|---|---|---|
| 0-99,999 | 252.0 | 256.2 | 1.02 |
| 100,000-199,999 | 243.3 | 236.0 | 0.97 |
| 200,000-299,999 | 919.2 | 444.5 | 0.48 |
| 300,000-399,999 | 1881.8 | 875.2 | 0.47 |
| 400,000-499,999 | 4066.1 | 1595.6 | 0.39 |
| 500,000-599,999 | 4592.0 | 2014.0 | 0.44 |
| 600,000-699,999 | 5626.5 | 2358.1 | 0.42 |
| 700,000-799,999 | 6170.9 | 2382.1 | 0.39 |
| 800,000-899,999 | 8732.0 | 3996.9 | 0.46 |
| 900,000-970,267 | 6012.3 | 2802.8 | 0.47 |

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
| 900,000-970,267 | 6012.3 | 69,959 | 2363.7 | 464.9 | 75.1 | 1.4 | 949.9 | 102.4 | 66.0 | 0.6 | 572.2 | 115.5 | 2.8 | 3648.6 | 2 / 99.7 |
| **total** | 38496.0 | 969,959 | 13909.2 | 2289.1 | 453.2 | 30.0 | 5322.7 | 112.6 | 562.5 | 4.7 | 4463.8 | 594.5 | 19.8 | 24586.7 | 16 / 802.9 |

connect block = Core's own per-block total (load .. postprocess). verify wait = "Verify" minus "Connect N transactions" (Verify is timed from the same start). outside connect = wall minus connect block: waiting for blocks to arrive, header sync, and anything ActivateBestChain does between blocks (index callbacks run on their own threads). UTXO flushes = count / seconds of "write coins cache to disk" (already inside write chainstate when IF_NEEDED; periodic ones fall between blocks).

Core flush and coindb lines: 18 chainstate writes (FORCE_FLUSH 2, IF_NEEDED 10, PERIODIC 6); 715,445,080 txouts committed; block index writes 18 (2.0 s); block/undo file flushes 18 (1.4 s); disconnects 0.

## bmc: stages per segment (sum over blocks, seconds)

| segment | wall | blocks | total | read | idx | verify | get | put | ckpt | flush | csi | put.ins | put.get | put.undo | put.del | put.wal | other | ix txindex | ix txospender | ix bfilter | ix addr | ix zmq | ixw | outside |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0-99,999 | 256.2 | 100,000 | 4.1 | 0.0 | 0.0 | 0.1 | 0.0 | 1.7 | 2.0 | 0.0 | 0.0 | 0.7 | 0.0 | 0.1 | 0.3 | 0.0 | 0.2 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.4 | 252.0 |
| 100,000-199,999 | 236.0 | 100,000 | 33.5 | 0.1 | 2.8 | 2.3 | 3.7 | 19.0 | 3.4 | 0.0 | 1.6 | 8.5 | 0.0 | 3.9 | 4.8 | 0.3 | 0.6 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 5.1 | 202.5 |
| 200,000-299,999 | 444.5 | 100,000 | 212.2 | 1.0 | 15.3 | 7.6 | 16.3 | 130.0 | 18.6 | 14.2 | 8.8 | 49.5 | 0.0 | 22.9 | 48.1 | 2.6 | 0.5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 17.4 | 232.3 |
| 300,000-399,999 | 875.2 | 100,000 | 603.4 | 2.3 | 45.8 | 16.8 | 89.9 | 378.9 | 37.4 | 6.2 | 25.3 | 125.4 | 0.7 | 62.2 | 165.7 | 5.6 | 0.7 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 42.8 | 271.8 |
| 400,000-499,999 | 1595.6 | 100,000 | 1397.0 | 12.0 | 107.8 | 32.2 | 361.1 | 754.4 | 61.7 | 13.7 | 50.2 | 259.3 | 3.8 | 111.0 | 334.5 | 8.4 | 3.9 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 88.0 | 198.6 |
| 500,000-599,999 | 2014.0 | 100,000 | 1648.1 | 10.3 | 157.9 | 37.8 | 510.0 | 776.6 | 75.5 | 18.5 | 55.7 | 261.4 | 6.7 | 122.2 | 336.4 | 9.0 | 5.8 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 92.4 | 365.9 |
| 600,000-699,999 | 2358.1 | 100,000 | 2159.1 | 36.7 | 187.0 | 47.6 | 626.5 | 1087.7 | 72.4 | 18.9 | 73.1 | 357.9 | 8.2 | 155.3 | 503.8 | 10.3 | 9.3 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 110.2 | 199.0 |
| 700,000-799,999 | 2382.1 | 100,000 | 2211.9 | 46.1 | 191.8 | 51.5 | 561.3 | 1186.3 | 70.3 | 20.7 | 76.3 | 392.5 | 7.5 | 160.0 | 562.1 | 8.1 | 7.5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 107.2 | 170.2 |
| 800,000-899,999 | 3996.9 | 100,000 | 3791.3 | 82.0 | 262.5 | 72.4 | 1524.6 | 1662.1 | 56.8 | 22.1 | 98.3 | 665.2 | 22.3 | 200.1 | 692.2 | 7.9 | 10.4 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 134.0 | 205.6 |
| 900,000-970,267 | 2802.8 | 70,268 | 2589.1 | 51.9 | 182.7 | 492.6 | 593.6 | 1138.4 | 34.1 | 17.2 | 69.0 | 500.2 | 9.1 | 140.8 | 431.1 | 6.8 | 9.6 | 0.0 | 0.0 | 0.4 | 0.0 | 0.0 | 90.5 | 213.3 |
| **total** | 16961.4 | 970,268 | 14649.8 | 242.4 | 1153.7 | 761.0 | 4287.0 | 7135.3 | 432.2 | 131.3 | 458.2 | 2620.7 | 58.3 | 978.5 | 3079.0 | 59.1 | 48.6 | 0.0 | 0.0 | 0.4 | 0.0 | 0.0 | 688.0 | 2311.2 |

total = the block line's own total; other = total minus the named stages. ix = the choke-point index work outside the block total ([bench] index lines printed by the applying process: on its wall). ixw = the same writers run in the forked index worker (the [bench] index lines between its started and stopped lines): off the apply path, not in outside. outside = wall minus (total + ix): download waits and everything off the apply path. bmc applies on a pipeline, so outside is not idle time by itself.

Index worker (plan B4): 969,572 block(s) indexed in the worker over 2 start(s); worker time by writer: txindex 337.3 s, txospender 0.0 s, bfilter 350.7 s, addr 0.0 s, zmq 0.0 s.

Other bmc [bench] lines: flush x112 (96.9 s); freeze x112 (96.9 s)

Download chunks ([dlc] chunk lines): 60694; bytes 774.50 GB; wait sum 6790 s, p50 0.06 s, p90 0.22 s, max 10.37 s; wall sum 84821 s, p50 0.80 s, p90 3.72 s, max 23.81 s; 70 distinct peers. Final [dlc] summary line, after the download ended (recv is the idle tail, not the run): recv 0.0B/s (avg 0.0B/s), pool idle 5%. Peer status lines named 49 distinct peers.

