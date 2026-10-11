# IBD stage report: Core v31.1 vs bmc

Segments of 100,000 heights. Times are seconds unless written h:mm:ss; elapsed times are from each run's own start.

## Runs

| | log | start (UTC) | max height | blocks w/ stage lines | IBD end | ready | ready height |
|---|---|---|---|---|---|---|---|
| Core | `/srv/nvme8tb/bench/core31-rerun7-20261007-logs/debug.log` | 2026-10-07 01:24:50 | 970,333 | 970,334 | 9:49:43 | 9:50:04 (tip 9:49:59) | 970,333 |
| bmc | `/srv/nvme8tb/bench/run46/debug.log` | 2026-10-09 23:15:30 | 970,711 | 970,712 | 3:17:32 | 3:17:55 | 970,688 |

Core: IBD end = "Leaving InitialBlockDownload"; ready = READY_INDEXES (the first getindexinfo after READY_TIP with every index at that height), READY_TIP = its UpdateTip at the oracle's tip. bmc: IBD end = "[dlc] catch-up done" (or phase.log IBD_END); ready = "[ready] all indexes at height N".

## Milestones (elapsed to the first block at or past each height)

| height | Core | bmc | bmc/Core |
|---|---|---|---|
| 100,000 | 0:02:06 | 0:01:22 | 0.65 |
| 200,000 | 0:04:44 | 0:02:35 | 0.55 |
| 300,000 | 0:15:30 | 0:06:35 | 0.43 |
| 400,000 | 0:44:37 | 0:18:00 | 0.40 |
| 500,000 | 1:43:30 | 0:40:49 | 0.39 |
| 600,000 | 2:52:17 | 1:03:39 | 0.37 |
| 700,000 | 4:18:21 | 1:30:36 | 0.35 |
| 800,000 | 5:54:00 | 2:03:21 | 0.35 |
| 900,000 | 8:13:37 | 2:44:26 | 0.33 |
| 970,711 | -- | 3:23:04 | -- |

## Wall time per segment

| segment | Core wall | bmc wall | bmc/Core |
|---|---|---|---|
| 0-99,999 | 126.4 | 82.1 | 0.65 |
| 100,000-199,999 | 158.4 | 73.4 | 0.46 |
| 200,000-299,999 | 645.5 | 240.5 | 0.37 |
| 300,000-399,999 | 1747.1 | 684.1 | 0.39 |
| 400,000-499,999 | 3532.8 | 1369.9 | 0.39 |
| 500,000-599,999 | 4127.4 | 1369.2 | 0.33 |
| 600,000-699,999 | 5163.5 | 1617.8 | 0.31 |
| 700,000-799,999 | 5739.6 | 1964.5 | 0.34 |
| 800,000-899,999 | 8377.1 | 2465.2 | 0.29 |
| 900,000-970,711 | 5781.4 | 2318.2 | 0.40 |

## Core: stages per segment (sum over blocks, seconds)

| segment | wall | blocks | connect block | load | sanity | fork | connect txs | verify wait | undo | index writing | flush | write chainstate | postprocess | outside connect | UTXO flushes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0-99,999 | 126.4 | 100,000 | 3.3 | 0.3 | 0.0 | 0.1 | 0.1 | 0.1 | 0.4 | 0.0 | 0.0 | 0.0 | 0.2 | 123.1 | 0 / 0.0 |
| 100,000-199,999 | 158.4 | 100,000 | 32.6 | 5.5 | 1.7 | 8.4 | 7.6 | 0.2 | 3.6 | 0.0 | 4.1 | 0.0 | 0.3 | 125.8 | 0 / 0.0 |
| 200,000-299,999 | 645.5 | 100,000 | 155.2 | 23.1 | 7.4 | 9.6 | 46.4 | 0.4 | 17.4 | 0.0 | 48.5 | 0.1 | 0.6 | 490.2 | 0 / 0.0 |
| 300,000-399,999 | 1747.1 | 100,000 | 495.2 | 68.3 | 21.4 | 0.5 | 164.6 | 0.6 | 40.7 | 0.1 | 194.7 | 0.4 | 1.0 | 1251.9 | 0 / 0.0 |
| 400,000-499,999 | 3532.8 | 100,000 | 1143.6 | 142.6 | 44.2 | 1.1 | 440.7 | 1.0 | 70.5 | 0.9 | 435.1 | 0.9 | 2.1 | 2389.2 | 2 / 51.1 |
| 500,000-599,999 | 4127.4 | 100,000 | 1496.8 | 223.3 | 49.1 | 1.3 | 555.5 | 1.3 | 68.9 | 0.9 | 540.7 | 48.8 | 2.3 | 2630.7 | 2 / 101.6 |
| 600,000-699,999 | 5163.5 | 100,000 | 1879.5 | 322.7 | 61.6 | 1.5 | 699.2 | 1.5 | 83.2 | 0.5 | 699.7 | 1.4 | 2.9 | 3284.0 | 1 / 58.3 |
| 700,000-799,999 | 5739.6 | 100,000 | 2199.5 | 375.1 | 64.5 | 1.5 | 803.6 | 1.6 | 87.0 | 0.7 | 766.0 | 91.2 | 2.3 | 3540.1 | 3 / 133.9 |
| 800,000-899,999 | 8377.1 | 100,000 | 3655.5 | 573.3 | 92.2 | 1.8 | 1490.8 | 2.1 | 118.0 | 0.9 | 929.3 | 432.6 | 2.6 | 4721.6 | 6 / 388.4 |
| 900,000-970,711 | 5781.4 | 70,334 | 2278.2 | 479.1 | 71.1 | 1.3 | 924.9 | 106.8 | 82.6 | 0.5 | 528.0 | 67.0 | 2.7 | 3503.1 | 2 / 134.6 |
| **total** | 35399.3 | 970,334 | 13339.6 | 2213.3 | 413.4 | 27.1 | 5133.5 | 115.6 | 572.3 | 4.6 | 4146.3 | 642.6 | 17.0 | 22059.7 | 16 / 867.8 |

connect block = Core's own per-block total (load .. postprocess). verify wait = "Verify" minus "Connect N transactions" (Verify is timed from the same start). outside connect = wall minus connect block: waiting for blocks to arrive, header sync, and anything ActivateBestChain does between blocks (index callbacks run on their own threads). UTXO flushes = count / seconds of "write coins cache to disk" (already inside write chainstate when IF_NEEDED; periodic ones fall between blocks).

Core flush and coindb lines: 18 chainstate writes (FORCE_FLUSH 2, IF_NEEDED 10, PERIODIC 6); 712,257,154 txouts committed; block index writes 18 (2.0 s); block/undo file flushes 18 (0.9 s); disconnects 0.

## bmc: stages per segment (sum over blocks, seconds)

| segment | wall | blocks | total | read | idx | verify | get | put | ckpt | flush | csi | put.ins | put.get | put.undo | put.del | put.wal | other | ix txindex | ix txospender | ix bfilter | ix addr | ix zmq | ixw | outside |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0-99,999 | 82.1 | 100,000 | 2.8 | 0.0 | 0.0 | 0.1 | 0.0 | 0.8 | 1.0 | 0.0 | 0.0 | 0.1 | 0.0 | 0.2 | 0.2 | 0.0 | 0.7 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.2 | 79.3 |
| 100,000-199,999 | 73.4 | 100,000 | 27.1 | 0.1 | 2.7 | 2.5 | 3.7 | 10.6 | 5.3 | 0.0 | 1.6 | 1.4 | 0.0 | 3.9 | 3.4 | 0.4 | 0.6 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 4.5 | 46.3 |
| 200,000-299,999 | 240.5 | 100,000 | 141.6 | 0.8 | 14.7 | 7.5 | 19.3 | 62.7 | 25.5 | 2.0 | 8.5 | 9.6 | 0.0 | 19.0 | 25.3 | 2.0 | 0.6 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 17.0 | 99.0 |
| 300,000-399,999 | 684.1 | 100,000 | 453.0 | 2.0 | 44.4 | 16.7 | 75.1 | 216.5 | 68.6 | 5.2 | 23.7 | 30.5 | 0.7 | 55.5 | 106.0 | 4.8 | 0.8 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 43.4 | 231.0 |
| 400,000-499,999 | 1369.9 | 100,000 | 993.6 | 11.1 | 102.7 | 31.4 | 262.6 | 406.8 | 117.6 | 10.9 | 46.7 | 60.9 | 2.5 | 109.6 | 188.1 | 9.3 | 3.7 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 89.3 | 376.3 |
| 500,000-599,999 | 1369.2 | 100,000 | 1181.1 | 19.3 | 145.5 | 36.6 | 372.4 | 415.4 | 123.9 | 10.6 | 51.2 | 55.9 | 3.5 | 121.8 | 184.1 | 10.6 | 6.2 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 92.5 | 188.1 |
| 600,000-699,999 | 1617.8 | 100,000 | 1433.8 | 24.9 | 163.0 | 46.1 | 476.4 | 513.7 | 124.3 | 13.3 | 64.6 | 62.9 | 4.1 | 147.2 | 238.2 | 11.4 | 7.5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 109.0 | 184.0 |
| 700,000-799,999 | 1964.5 | 100,000 | 1508.0 | 21.8 | 169.3 | 50.3 | 464.2 | 587.2 | 124.3 | 15.2 | 68.2 | 70.8 | 4.5 | 154.4 | 296.3 | 9.0 | 7.4 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 109.6 | 456.5 |
| 800,000-899,999 | 2465.2 | 100,000 | 2162.1 | 67.4 | 230.7 | 69.2 | 736.3 | 781.2 | 162.4 | 15.8 | 88.4 | 111.3 | 8.5 | 195.0 | 391.1 | 8.6 | 10.6 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 136.1 | 303.1 |
| 900,000-970,711 | 2318.2 | 70,712 | 1787.6 | 35.3 | 159.5 | 498.0 | 460.1 | 458.7 | 93.5 | 14.2 | 61.3 | 62.8 | 4.4 | 134.9 | 204.0 | 7.3 | 7.0 | 0.0 | 0.0 | 0.2 | 0.0 | 0.0 | 92.5 | 530.4 |
| **total** | 12184.9 | 970,712 | 9690.7 | 182.8 | 1032.5 | 758.6 | 2870.3 | 3453.6 | 846.5 | 87.2 | 414.2 | 466.3 | 28.1 | 941.6 | 1636.7 | 63.7 | 45.1 | 0.0 | 0.0 | 0.2 | 0.0 | 0.0 | 694.0 | 2493.9 |

total = the block line's own total; other = total minus the named stages. ix = the choke-point index work outside the block total ([bench] index lines printed by the applying process: on its wall). ixw = the same writers run in the forked index worker (the [bench] index lines between its started and stopped lines): off the apply path, not in outside. outside = wall minus (total + ix): download waits and everything off the apply path. bmc applies on a pipeline, so outside is not idle time by itself.

Index worker (plan B4): 970,431 block(s) indexed in the worker over 1 start(s); worker time by writer: txindex 341.5 s, txospender 0.0 s, bfilter 352.6 s, addr 0.0 s, zmq 0.0 s.

Other bmc [bench] lines: flush x217 (36.4 s); freeze x217 (29.5 s)

Download chunks ([dlc] chunk lines): 60720; bytes 775.07 GB; wait sum 5696 s, p50 0.06 s, p90 0.21 s, max 8.20 s; wall sum 76383 s, p50 0.55 s, p90 3.08 s, max 28.65 s; 71 distinct peers. Final [dlc] summary line, after the download ended (recv is the idle tail, not the run): recv 0.0B/s (avg 62.6MB/s), pool idle 7%. Peer status lines named 42 distinct peers.

