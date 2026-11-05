# IBD stage report: Core v31.1 vs bmc

Segments of 100,000 heights. Times are seconds unless written h:mm:ss; elapsed times are from each run's own start.

## Runs

| | log | start (UTC) | max height | blocks w/ stage lines | IBD end | ready | ready height |
|---|---|---|---|---|---|---|---|
| Core | `/srv/nvme8tb/bench/core31-rerun7-20261007-logs/debug.log` | 2026-10-07 01:24:50 | 970,333 | 970,334 | 9:49:43 | 9:50:04 (tip 9:49:59) | 970,333 |
| bmc | `/srv/nvme8tb/bench/run41/data/main/debug.log` | 2026-10-07 12:52:26 | 970,365 | 970,366 | 3:47:48 | 3:48:22 | 970,342 |

Core: IBD end = "Leaving InitialBlockDownload"; ready = READY_INDEXES (the first getindexinfo after READY_TIP with every index at that height), READY_TIP = its UpdateTip at the oracle's tip. bmc: IBD end = "[dlc] catch-up done" (or phase.log IBD_END); ready = "[ready] all indexes at height N".

## Milestones (elapsed to the first block at or past each height)

| height | Core | bmc | bmc/Core |
|---|---|---|---|
| 100,000 | 0:02:06 | 0:01:35 | 0.76 |
| 200,000 | 0:04:44 | 0:02:55 | 0.62 |
| 300,000 | 0:15:30 | 0:06:57 | 0.45 |
| 400,000 | 0:44:37 | 0:18:28 | 0.41 |
| 500,000 | 1:43:30 | 0:44:25 | 0.43 |
| 600,000 | 2:52:17 | 1:11:15 | 0.41 |
| 700,000 | 4:18:21 | 1:42:57 | 0.40 |
| 800,000 | 5:54:00 | 2:15:53 | 0.38 |
| 900,000 | 8:13:37 | 3:10:02 | 0.38 |
| 970,365 | -- | 3:54:22 | -- |

## Wall time per segment

| segment | Core wall | bmc wall | bmc/Core |
|---|---|---|---|
| 0-99,999 | 126.4 | 95.7 | 0.76 |
| 100,000-199,999 | 158.4 | 80.0 | 0.51 |
| 200,000-299,999 | 645.5 | 241.4 | 0.37 |
| 300,000-399,999 | 1747.1 | 691.7 | 0.40 |
| 400,000-499,999 | 3532.8 | 1557.1 | 0.44 |
| 500,000-599,999 | 4127.4 | 1609.2 | 0.39 |
| 600,000-699,999 | 5163.5 | 1902.5 | 0.37 |
| 700,000-799,999 | 5739.6 | 1976.1 | 0.34 |
| 800,000-899,999 | 8377.1 | 3248.4 | 0.39 |
| 900,000-970,365 | 5781.4 | 2660.6 | 0.46 |

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
| 900,000-970,365 | 5781.4 | 70,334 | 2278.2 | 479.1 | 71.1 | 1.3 | 924.9 | 106.8 | 82.6 | 0.5 | 528.0 | 67.0 | 2.7 | 3503.1 | 2 / 134.6 |
| **total** | 35399.3 | 970,334 | 13339.6 | 2213.3 | 413.4 | 27.1 | 5133.5 | 115.6 | 572.3 | 4.6 | 4146.3 | 642.6 | 17.0 | 22059.7 | 16 / 867.8 |

connect block = Core's own per-block total (load .. postprocess). verify wait = "Verify" minus "Connect N transactions" (Verify is timed from the same start). outside connect = wall minus connect block: waiting for blocks to arrive, header sync, and anything ActivateBestChain does between blocks (index callbacks run on their own threads). UTXO flushes = count / seconds of "write coins cache to disk" (already inside write chainstate when IF_NEEDED; periodic ones fall between blocks).

Core flush and coindb lines: 18 chainstate writes (FORCE_FLUSH 2, IF_NEEDED 10, PERIODIC 6); 712,257,154 txouts committed; block index writes 18 (2.0 s); block/undo file flushes 18 (0.9 s); disconnects 0.

## bmc: stages per segment (sum over blocks, seconds)

| segment | wall | blocks | total | read | idx | verify | get | put | ckpt | flush | csi | put.ins | put.get | put.undo | put.del | put.wal | other | ix txindex | ix txospender | ix bfilter | ix addr | ix zmq | ixw | outside |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0-99,999 | 95.7 | 100,000 | 2.4 | 0.0 | 0.0 | 0.1 | 0.0 | 0.9 | 0.6 | 0.0 | 0.0 | 0.2 | 0.0 | 0.1 | 0.2 | 0.0 | 0.7 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.1 | 93.3 |
| 100,000-199,999 | 80.0 | 100,000 | 27.1 | 0.1 | 2.8 | 2.6 | 3.8 | 12.9 | 2.7 | 0.0 | 1.7 | 3.7 | 0.0 | 3.9 | 3.5 | 0.4 | 0.6 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 4.7 | 52.9 |
| 200,000-299,999 | 241.4 | 100,000 | 148.6 | 0.8 | 15.1 | 7.6 | 15.8 | 68.1 | 21.5 | 10.8 | 8.6 | 14.1 | 0.0 | 18.7 | 26.6 | 2.0 | 0.4 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 17.2 | 92.8 |
| 300,000-399,999 | 691.7 | 100,000 | 475.1 | 2.5 | 45.4 | 17.2 | 94.4 | 224.8 | 59.6 | 7.0 | 23.4 | 36.8 | 0.7 | 55.4 | 107.7 | 5.5 | 0.9 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 43.2 | 216.7 |
| 400,000-499,999 | 1557.1 | 100,000 | 1152.8 | 7.3 | 109.5 | 33.4 | 401.0 | 443.6 | 94.8 | 11.7 | 46.9 | 74.1 | 4.5 | 107.2 | 210.3 | 10.7 | 4.5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 88.8 | 404.3 |
| 500,000-599,999 | 1609.2 | 100,000 | 1394.4 | 7.6 | 157.5 | 38.3 | 573.5 | 459.2 | 85.2 | 15.2 | 52.1 | 78.4 | 6.9 | 114.7 | 210.3 | 9.6 | 5.8 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 92.8 | 214.7 |
| 600,000-699,999 | 1902.5 | 100,000 | 1679.6 | 17.1 | 183.6 | 47.7 | 657.6 | 568.6 | 115.6 | 16.7 | 65.5 | 92.2 | 7.4 | 142.6 | 267.4 | 10.5 | 7.3 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 108.3 | 222.9 |
| 700,000-799,999 | 1976.1 | 100,000 | 1788.6 | 29.5 | 189.0 | 51.9 | 624.2 | 642.3 | 153.5 | 19.7 | 70.1 | 103.0 | 7.0 | 153.0 | 318.8 | 8.9 | 8.4 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 108.3 | 187.5 |
| 800,000-899,999 | 3248.4 | 100,000 | 3035.8 | 62.5 | 259.0 | 72.9 | 1508.8 | 881.3 | 126.2 | 24.0 | 90.6 | 161.2 | 21.3 | 190.6 | 433.2 | 8.2 | 10.4 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 136.2 | 212.6 |
| 900,000-970,365 | 2660.6 | 70,366 | 2137.6 | 36.5 | 181.0 | 491.8 | 727.9 | 540.3 | 71.3 | 19.5 | 61.8 | 100.2 | 9.2 | 134.7 | 243.6 | 7.3 | 7.5 | 0.0 | 0.0 | 0.4 | 0.0 | 0.0 | 91.4 | 522.7 |
| **total** | 14062.8 | 970,366 | 11842.0 | 163.9 | 1142.8 | 763.5 | 4607.1 | 3841.9 | 731.1 | 124.5 | 420.6 | 663.8 | 57.1 | 920.9 | 1821.5 | 63.1 | 46.5 | 0.0 | 0.0 | 0.4 | 0.0 | 0.0 | 691.0 | 2220.4 |

total = the block line's own total; other = total minus the named stages. ix = the choke-point index work outside the block total ([bench] index lines printed by the applying process: on its wall). ixw = the same writers run in the forked index worker (the [bench] index lines between its started and stopped lines): off the apply path, not in outside. outside = wall minus (total + ix): download waits and everything off the apply path. bmc applies on a pipeline, so outside is not idle time by itself.

Index worker (plan B4): 969,835 block(s) indexed in the worker over 1 start(s); worker time by writer: txindex 338.7 s, txospender 0.0 s, bfilter 352.4 s, addr 0.0 s, zmq 0.0 s.

Other bmc [bench] lines: flush x110 (98.8 s); freeze x110 (98.8 s)

Download chunks ([dlc] chunk lines): 60700; bytes 774.46 GB; wait sum 5872 s, p50 0.06 s, p90 0.21 s, max 4.65 s; wall sum 70731 s, p50 0.62 s, p90 3.00 s, max 21.29 s; 69 distinct peers. Final [dlc] summary line, after the download ended (recv is the idle tail, not the run): recv 0.0B/s (avg 54.3MB/s), pool idle 8%. Peer status lines named 34 distinct peers.

