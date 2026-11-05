# IBD stage report: Core v31.1 vs bmc

Segments of 100,000 heights. Times are seconds unless written h:mm:ss; elapsed times are from each run's own start.

## Runs

| | log | start (UTC) | max height | blocks w/ stage lines | IBD end | ready | ready height |
|---|---|---|---|---|---|---|---|
| Core | `/srv/nvme8tb/bench/core31-rerun7-20261007-logs/debug.log` | 2026-10-07 01:24:50 | 970,333 | 970,334 | 9:49:43 | 9:50:04 (tip 9:49:59) | 970,333 |
| bmc | `/srv/nvme8tb/bench/run39/data/main/debug.log` | 2026-10-06 13:11:02 | 970,209 | 970,210 | 4:33:11 | 4:34:48 | 970,177 |

Core: IBD end = "Leaving InitialBlockDownload"; ready = READY_INDEXES (the first getindexinfo after READY_TIP with every index at that height), READY_TIP = its UpdateTip at the oracle's tip. bmc: IBD end = "[dlc] catch-up done" (or phase.log IBD_END); ready = "[ready] all indexes at height N".

## Milestones (elapsed to the first block at or past each height)

| height | Core | bmc | bmc/Core |
|---|---|---|---|
| 100,000 | 0:02:06 | 0:04:15 | 2.02 |
| 200,000 | 0:04:44 | 0:08:14 | 1.74 |
| 300,000 | 0:15:30 | 0:15:00 | 0.97 |
| 400,000 | 0:44:37 | 0:29:45 | 0.67 |
| 500,000 | 1:43:30 | 0:56:03 | 0.54 |
| 600,000 | 2:52:17 | 1:29:14 | 0.52 |
| 700,000 | 4:18:21 | 2:06:29 | 0.49 |
| 800,000 | 5:54:00 | 2:45:06 | 0.47 |
| 900,000 | 8:13:37 | 3:49:50 | 0.47 |
| 970,333 | 9:49:59 | -- | -- |

## Wall time per segment

| segment | Core wall | bmc wall | bmc/Core |
|---|---|---|---|
| 0-99,999 | 126.4 | 255.5 | 2.02 |
| 100,000-199,999 | 158.4 | 239.0 | 1.51 |
| 200,000-299,999 | 645.5 | 405.5 | 0.63 |
| 300,000-399,999 | 1747.1 | 884.9 | 0.51 |
| 400,000-499,999 | 3532.8 | 1578.3 | 0.45 |
| 500,000-599,999 | 4127.4 | 1991.5 | 0.48 |
| 600,000-699,999 | 5163.5 | 2235.2 | 0.43 |
| 700,000-799,999 | 5739.6 | 2316.4 | 0.40 |
| 800,000-899,999 | 8377.1 | 3884.5 | 0.46 |
| 900,000-970,333 | 5781.4 | 2730.0 | 0.47 |

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
| 0-99,999 | 255.5 | 100,000 | 4.4 | 0.0 | 0.0 | 0.1 | 0.0 | 1.7 | 2.3 | 0.0 | 0.0 | 0.7 | 0.0 | 0.1 | 0.3 | 0.0 | 0.2 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.5 | 251.1 |
| 100,000-199,999 | 239.0 | 100,000 | 38.3 | 0.1 | 2.9 | 2.4 | 3.6 | 22.8 | 3.4 | 0.0 | 2.6 | 11.4 | 0.0 | 4.2 | 5.4 | 0.4 | 0.6 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 5.1 | 200.7 |
| 200,000-299,999 | 405.5 | 100,000 | 180.7 | 0.8 | 14.9 | 7.4 | 16.6 | 95.0 | 13.9 | 23.2 | 8.4 | 32.5 | 0.0 | 19.5 | 33.4 | 2.7 | 0.5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 16.8 | 224.8 |
| 300,000-399,999 | 884.9 | 100,000 | 621.9 | 2.3 | 44.9 | 16.5 | 89.6 | 318.5 | 35.3 | 90.7 | 23.2 | 97.7 | 0.6 | 57.7 | 138.7 | 4.6 | 0.9 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 42.4 | 263.0 |
| 400,000-499,999 | 1578.3 | 100,000 | 1343.1 | 8.7 | 105.9 | 31.3 | 338.4 | 610.0 | 53.7 | 144.6 | 46.7 | 186.9 | 3.6 | 106.0 | 269.0 | 7.6 | 3.8 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 86.7 | 235.2 |
| 500,000-599,999 | 1991.5 | 100,000 | 1620.1 | 15.1 | 154.2 | 36.4 | 481.3 | 647.6 | 55.8 | 172.2 | 52.3 | 205.4 | 5.9 | 115.6 | 273.4 | 7.9 | 5.3 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 89.5 | 371.4 |
| 600,000-699,999 | 2235.2 | 100,000 | 2068.6 | 18.4 | 182.6 | 46.0 | 616.4 | 874.9 | 59.2 | 196.3 | 68.0 | 259.2 | 7.2 | 144.9 | 404.3 | 9.5 | 6.8 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 105.8 | 166.6 |
| 700,000-799,999 | 2316.4 | 100,000 | 2068.5 | 33.8 | 186.9 | 49.4 | 531.9 | 894.0 | 67.3 | 227.0 | 70.3 | 250.2 | 6.6 | 151.3 | 425.5 | 7.8 | 7.9 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 105.1 | 247.9 |
| 800,000-899,999 | 3884.5 | 100,000 | 3680.8 | 53.7 | 258.5 | 70.6 | 1459.4 | 1338.6 | 61.0 | 335.0 | 93.8 | 467.9 | 21.3 | 189.9 | 582.0 | 7.7 | 10.1 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 132.7 | 203.7 |
| 900,000-970,333 | 2730.0 | 70,210 | 2433.7 | 32.2 | 177.6 | 479.5 | 596.5 | 857.5 | 45.3 | 174.6 | 63.6 | 333.4 | 8.4 | 132.2 | 331.0 | 6.2 | 6.9 | 0.0 | 0.0 | 0.4 | 0.0 | 0.0 | 88.9 | 295.9 |
| **total** | 16520.9 | 970,210 | 14060.1 | 165.2 | 1128.5 | 739.4 | 4133.8 | 5660.6 | 397.1 | 1363.6 | 429.0 | 1845.4 | 53.7 | 921.4 | 2462.8 | 54.5 | 42.9 | 0.0 | 0.0 | 0.4 | 0.0 | 0.0 | 673.6 | 2460.4 |

total = the block line's own total; other = total minus the named stages. ix = the choke-point index work outside the block total ([bench] index lines printed by the applying process: on its wall). ixw = the same writers run in the forked index worker (the [bench] index lines between its started and stopped lines): off the apply path, not in outside. outside = wall minus (total + ix): download waits and everything off the apply path. bmc applies on a pipeline, so outside is not idle time by itself.

Index worker (plan B4): 969,487 block(s) indexed in the worker over 1 start(s); worker time by writer: txindex 334.0 s, txospender 0.0 s, bfilter 339.6 s, addr 0.0 s, zmq 0.0 s.

Other bmc [bench] lines: flush x110 (1356.9 s)

Download chunks ([dlc] chunk lines): 60677; bytes 774.29 GB; wait sum 5160 s, p50 0.05 s, p90 0.22 s, max 5.72 s; wall sum 83600 s, p50 0.94 s, p90 3.17 s, max 56.10 s; 81 distinct peers. Final [dlc] summary line, after the download ended (recv is the idle tail, not the run): recv 0.0B/s (avg 45.2MB/s), pool idle 6%. Peer status lines named 44 distinct peers.

