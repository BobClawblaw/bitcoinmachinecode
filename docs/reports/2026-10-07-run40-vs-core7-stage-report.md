# IBD stage report: Core v31.1 vs bmc

Segments of 100,000 heights. Times are seconds unless written h:mm:ss; elapsed times are from each run's own start.

## Runs

| | log | start (UTC) | max height | blocks w/ stage lines | IBD end | ready | ready height |
|---|---|---|---|---|---|---|---|
| Core | `/srv/nvme8tb/bench/core31-rerun7-20261007-logs/debug.log` | 2026-10-07 01:24:50 | 970,333 | 970,334 | 9:49:43 | 9:50:04 (tip 9:49:59) | 970,333 |
| bmc | `/srv/nvme8tb/bench/run40/data/main/debug.log` | 2026-10-06 20:34:00 | 970,267 | 970,268 | 4:41:02 | 4:42:41 | 970,267 |

Core: IBD end = "Leaving InitialBlockDownload"; ready = READY_INDEXES (the first getindexinfo after READY_TIP with every index at that height), READY_TIP = its UpdateTip at the oracle's tip. bmc: IBD end = "[dlc] catch-up done" (or phase.log IBD_END); ready = "[ready] all indexes at height N".

## Milestones (elapsed to the first block at or past each height)

| height | Core | bmc | bmc/Core |
|---|---|---|---|
| 100,000 | 0:02:06 | 0:04:16 | 2.03 |
| 200,000 | 0:04:44 | 0:08:12 | 1.73 |
| 300,000 | 0:15:30 | 0:15:36 | 1.01 |
| 400,000 | 0:44:37 | 0:30:11 | 0.68 |
| 500,000 | 1:43:30 | 0:56:47 | 0.55 |
| 600,000 | 2:52:17 | 1:30:21 | 0.52 |
| 700,000 | 4:18:21 | 2:09:39 | 0.50 |
| 800,000 | 5:54:00 | 2:49:21 | 0.48 |
| 900,000 | 8:13:37 | 3:55:58 | 0.48 |
| 970,333 | 9:49:59 | -- | -- |

## Wall time per segment

| segment | Core wall | bmc wall | bmc/Core |
|---|---|---|---|
| 0-99,999 | 126.4 | 256.2 | 2.03 |
| 100,000-199,999 | 158.4 | 236.0 | 1.49 |
| 200,000-299,999 | 645.5 | 444.5 | 0.69 |
| 300,000-399,999 | 1747.1 | 875.2 | 0.50 |
| 400,000-499,999 | 3532.8 | 1595.6 | 0.45 |
| 500,000-599,999 | 4127.4 | 2014.0 | 0.49 |
| 600,000-699,999 | 5163.5 | 2358.1 | 0.46 |
| 700,000-799,999 | 5739.6 | 2382.1 | 0.42 |
| 800,000-899,999 | 8377.1 | 3996.9 | 0.48 |
| 900,000-970,333 | 5781.4 | 2802.8 | 0.48 |

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
| 900,000-970,333 | 5781.4 | 70,334 | 2278.2 | 479.1 | 71.1 | 1.3 | 924.9 | 106.8 | 82.6 | 0.5 | 528.0 | 67.0 | 2.7 | 3503.1 | 2 / 134.6 |
| **total** | 35399.3 | 970,334 | 13339.6 | 2213.3 | 413.4 | 27.1 | 5133.5 | 115.6 | 572.3 | 4.6 | 4146.3 | 642.6 | 17.0 | 22059.7 | 16 / 867.8 |

connect block = Core's own per-block total (load .. postprocess). verify wait = "Verify" minus "Connect N transactions" (Verify is timed from the same start). outside connect = wall minus connect block: waiting for blocks to arrive, header sync, and anything ActivateBestChain does between blocks (index callbacks run on their own threads). UTXO flushes = count / seconds of "write coins cache to disk" (already inside write chainstate when IF_NEEDED; periodic ones fall between blocks).

Core flush and coindb lines: 18 chainstate writes (FORCE_FLUSH 2, IF_NEEDED 10, PERIODIC 6); 712,257,154 txouts committed; block index writes 18 (2.0 s); block/undo file flushes 18 (0.9 s); disconnects 0.

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
| 900,000-970,333 | 2802.8 | 70,268 | 2589.1 | 51.9 | 182.7 | 492.6 | 593.6 | 1138.4 | 34.1 | 17.2 | 69.0 | 500.2 | 9.1 | 140.8 | 431.1 | 6.8 | 9.6 | 0.0 | 0.0 | 0.4 | 0.0 | 0.0 | 90.5 | 213.3 |
| **total** | 16961.4 | 970,268 | 14649.8 | 242.4 | 1153.7 | 761.0 | 4287.0 | 7135.3 | 432.2 | 131.3 | 458.2 | 2620.7 | 58.3 | 978.5 | 3079.0 | 59.1 | 48.6 | 0.0 | 0.0 | 0.4 | 0.0 | 0.0 | 688.0 | 2311.2 |

total = the block line's own total; other = total minus the named stages. ix = the choke-point index work outside the block total ([bench] index lines printed by the applying process: on its wall). ixw = the same writers run in the forked index worker (the [bench] index lines between its started and stopped lines): off the apply path, not in outside. outside = wall minus (total + ix): download waits and everything off the apply path. bmc applies on a pipeline, so outside is not idle time by itself.

Index worker (plan B4): 969,572 block(s) indexed in the worker over 2 start(s); worker time by writer: txindex 337.3 s, txospender 0.0 s, bfilter 350.7 s, addr 0.0 s, zmq 0.0 s.

Other bmc [bench] lines: flush x112 (96.9 s); freeze x112 (96.9 s)

Download chunks ([dlc] chunk lines): 60694; bytes 774.50 GB; wait sum 6790 s, p50 0.06 s, p90 0.22 s, max 10.37 s; wall sum 84821 s, p50 0.80 s, p90 3.72 s, max 23.81 s; 70 distinct peers. Final [dlc] summary line, after the download ended (recv is the idle tail, not the run): recv 0.0B/s (avg 0.0B/s), pool idle 5%. Peer status lines named 49 distinct peers.

