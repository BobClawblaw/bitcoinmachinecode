# IBD stage report: Core v31.1 vs bmc

Segments of 100,000 heights. Times are seconds unless written h:mm:ss; elapsed times are from each run's own start.

## Runs

| | log | start (UTC) | max height | blocks w/ stage lines | IBD end | ready | ready height |
|---|---|---|---|---|---|---|---|
| Core | `/srv/nvme8tb/bench/core31-rerun6-20261004-logs/debug.log` | 2026-10-04 18:20:24 | 969,958 | 969,959 | 10:41:21 | 10:42:05 (tip 10:41:35) | 969,958 |
| bmc | `/srv/nvme8tb/bench/run38/data/main/debug.log` | 2026-10-06 06:42:09 | 970,165 | 970,166 | 4:15:43 | 4:17:09 | 970,145 |

Core: IBD end = "Leaving InitialBlockDownload"; ready = READY_INDEXES (the first getindexinfo after READY_TIP with every index at that height), READY_TIP = its UpdateTip at the oracle's tip. bmc: IBD end = "[dlc] catch-up done" (or phase.log IBD_END); ready = "[ready] all indexes at height N".

## Milestones (elapsed to the first block at or past each height)

| height | Core | bmc | bmc/Core |
|---|---|---|---|
| 100,000 | 0:04:12 | 0:05:08 | 1.22 |
| 200,000 | 0:08:15 | 0:09:03 | 1.10 |
| 300,000 | 0:23:34 | 0:15:52 | 0.67 |
| 400,000 | 0:54:56 | 0:29:54 | 0.54 |
| 500,000 | 2:02:42 | 0:55:42 | 0.45 |
| 600,000 | 3:19:14 | 1:24:39 | 0.42 |
| 700,000 | 4:53:00 | 1:59:52 | 0.41 |
| 800,000 | 6:35:51 | 2:35:50 | 0.39 |
| 900,000 | 9:01:23 | 3:35:43 | 0.40 |
| 970,165 | -- | 4:19:16 | -- |

## Wall time per segment

| segment | Core wall | bmc wall | bmc/Core |
|---|---|---|---|
| 0-99,999 | 252.0 | 308.5 | 1.22 |
| 100,000-199,999 | 243.3 | 234.5 | 0.96 |
| 200,000-299,999 | 919.2 | 409.1 | 0.45 |
| 300,000-399,999 | 1881.8 | 842.8 | 0.45 |
| 400,000-499,999 | 4066.1 | 1547.6 | 0.38 |
| 500,000-599,999 | 4592.0 | 1736.5 | 0.38 |
| 600,000-699,999 | 5626.5 | 2113.3 | 0.38 |
| 700,000-799,999 | 6170.9 | 2158.6 | 0.35 |
| 800,000-899,999 | 8732.0 | 3592.4 | 0.41 |
| 900,000-970,165 | 6012.3 | 2613.0 | 0.43 |

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
| 900,000-970,165 | 6012.3 | 69,959 | 2363.7 | 464.9 | 75.1 | 1.4 | 949.9 | 102.4 | 66.0 | 0.6 | 572.2 | 115.5 | 2.8 | 3648.6 | 2 / 99.7 |
| **total** | 38496.0 | 969,959 | 13909.2 | 2289.1 | 453.2 | 30.0 | 5322.7 | 112.6 | 562.5 | 4.7 | 4463.8 | 594.5 | 19.8 | 24586.7 | 16 / 802.9 |

connect block = Core's own per-block total (load .. postprocess). verify wait = "Verify" minus "Connect N transactions" (Verify is timed from the same start). outside connect = wall minus connect block: waiting for blocks to arrive, header sync, and anything ActivateBestChain does between blocks (index callbacks run on their own threads). UTXO flushes = count / seconds of "write coins cache to disk" (already inside write chainstate when IF_NEEDED; periodic ones fall between blocks).

Core flush and coindb lines: 18 chainstate writes (FORCE_FLUSH 2, IF_NEEDED 10, PERIODIC 6); 715,445,080 txouts committed; block index writes 18 (2.0 s); block/undo file flushes 18 (1.4 s); disconnects 0.

## bmc: stages per segment (sum over blocks, seconds)

| segment | wall | blocks | total | read | idx | verify | get | put | ckpt | flush | csi | put.ins | put.get | put.undo | put.del | put.wal | other | ix txindex | ix txospender | ix bfilter | ix addr | ix zmq | ixw | outside |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0-99,999 | 308.5 | 100,000 | 4.0 | 0.0 | 0.0 | 0.1 | 0.0 | 1.6 | 2.0 | 0.0 | 0.0 | 0.6 | 0.0 | 0.1 | 0.2 | 0.0 | 0.3 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.4 | 304.5 |
| 100,000-199,999 | 234.5 | 100,000 | 33.6 | 0.1 | 2.9 | 2.7 | 3.8 | 18.7 | 3.1 | 0.0 | 1.8 | 8.3 | 0.0 | 3.9 | 4.8 | 0.3 | 0.5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 5.3 | 201.0 |
| 200,000-299,999 | 409.1 | 100,000 | 184.4 | 0.8 | 15.8 | 7.8 | 17.6 | 96.8 | 11.9 | 24.2 | 9.0 | 30.8 | 0.0 | 21.4 | 35.3 | 2.1 | 0.6 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 18.0 | 224.7 |
| 300,000-399,999 | 842.8 | 100,000 | 599.9 | 3.7 | 47.3 | 17.3 | 87.4 | 299.7 | 30.1 | 88.4 | 25.2 | 78.7 | 0.8 | 57.4 | 137.5 | 5.4 | 0.8 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 44.9 | 242.9 |
| 400,000-499,999 | 1547.6 | 100,000 | 1352.0 | 12.6 | 110.0 | 32.8 | 346.3 | 594.2 | 50.2 | 153.4 | 48.6 | 165.4 | 4.2 | 109.4 | 268.4 | 8.4 | 3.9 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 90.4 | 195.6 |
| 500,000-599,999 | 1736.5 | 100,000 | 1579.5 | 9.9 | 157.8 | 37.4 | 497.6 | 605.4 | 39.7 | 174.5 | 51.7 | 168.2 | 6.4 | 120.2 | 261.4 | 8.7 | 5.4 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 91.7 | 157.0 |
| 600,000-699,999 | 2113.3 | 100,000 | 1964.8 | 41.6 | 186.6 | 46.8 | 610.8 | 758.8 | 53.4 | 193.3 | 66.2 | 193.6 | 7.8 | 144.0 | 352.7 | 9.9 | 7.3 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 108.3 | 148.5 |
| 700,000-799,999 | 2158.6 | 100,000 | 2003.6 | 36.7 | 191.0 | 51.0 | 554.1 | 815.8 | 59.1 | 216.6 | 71.4 | 196.4 | 7.2 | 152.1 | 397.9 | 8.2 | 7.9 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 107.3 | 155.0 |
| 800,000-899,999 | 3592.4 | 100,000 | 3393.7 | 52.8 | 260.2 | 70.9 | 1396.2 | 1114.5 | 55.6 | 339.8 | 93.5 | 319.3 | 21.2 | 192.0 | 504.4 | 7.8 | 10.3 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 133.5 | 198.7 |
| 900,000-970,165 | 2613.0 | 70,166 | 2247.7 | 36.7 | 177.8 | 477.4 | 582.3 | 688.7 | 49.1 | 169.9 | 59.0 | 216.0 | 8.1 | 132.9 | 279.6 | 6.2 | 6.9 | 0.0 | 0.0 | 0.2 | 0.0 | 0.0 | 88.5 | 365.0 |
| **total** | 15556.2 | 970,166 | 13363.1 | 194.9 | 1149.2 | 744.3 | 4096.1 | 4994.0 | 354.1 | 1360.1 | 426.5 | 1377.3 | 55.7 | 933.4 | 2242.2 | 56.9 | 44.0 | 0.0 | 0.0 | 0.2 | 0.0 | 0.0 | 688.2 | 2192.9 |

total = the block line's own total; other = total minus the named stages. ix = the choke-point index work outside the block total ([bench] index lines printed by the applying process: on its wall). ixw = the same writers run in the forked index worker (the [bench] index lines between its started and stopped lines): off the apply path, not in outside. outside = wall minus (total + ix): download waits and everything off the apply path. bmc applies on a pipeline, so outside is not idle time by itself.

Index worker (plan B4): 969,746 block(s) indexed in the worker over 1 start(s); worker time by writer: txindex 336.3 s, txospender 0.0 s, bfilter 351.9 s, addr 0.0 s, zmq 0.0 s.

Other bmc [bench] lines: flush x109 (1352.6 s)

Download chunks ([dlc] chunk lines): 60639; bytes 773.86 GB; wait sum 3591 s, p50 0.06 s, p90 0.08 s, max 2.37 s; wall sum 64809 s, p50 0.39 s, p90 2.92 s, max 63.22 s; 25 distinct peers. Final [dlc] summary line, after the download ended (recv is the idle tail, not the run): recv 0.0B/s (avg 48.5MB/s), pool idle 5%. Peer status lines named 18 distinct peers.

