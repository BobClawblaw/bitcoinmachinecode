# IBD stage report: Core v31.1 vs bmc

Segments of 100,000 heights. Times are seconds unless written h:mm:ss; elapsed times are from each run's own start.

## Runs

| | log | start (UTC) | max height | blocks w/ stage lines | IBD end | ready | ready height |
|---|---|---|---|---|---|---|---|
| Core | `/srv/nvme8tb/bench/core31-rerun6-20261004-logs/debug.log` | 2026-10-04 18:20:24 | 969,958 | 969,959 | 10:41:21 | 10:42:05 (tip 10:41:35) | 969,958 |
| bmc | `/srv/nvme8tb/bench/run39/data/main/debug.log` | 2026-10-06 13:11:02 | 970,209 | 970,210 | 4:33:11 | 4:34:48 | 970,177 |

Core: IBD end = "Leaving InitialBlockDownload"; ready = READY_INDEXES (the first getindexinfo after READY_TIP with every index at that height), READY_TIP = its UpdateTip at the oracle's tip. bmc: IBD end = "[dlc] catch-up done" (or phase.log IBD_END); ready = "[ready] all indexes at height N".

## Milestones (elapsed to the first block at or past each height)

| height | Core | bmc | bmc/Core |
|---|---|---|---|
| 100,000 | 0:04:12 | 0:04:15 | 1.01 |
| 200,000 | 0:08:15 | 0:08:14 | 1.00 |
| 300,000 | 0:23:34 | 0:15:00 | 0.64 |
| 400,000 | 0:54:56 | 0:29:45 | 0.54 |
| 500,000 | 2:02:42 | 0:56:03 | 0.46 |
| 600,000 | 3:19:14 | 1:29:14 | 0.45 |
| 700,000 | 4:53:00 | 2:06:29 | 0.43 |
| 800,000 | 6:35:51 | 2:45:06 | 0.42 |
| 900,000 | 9:01:23 | 3:49:50 | 0.42 |
| 970,209 | -- | 4:35:20 | -- |

## Wall time per segment

| segment | Core wall | bmc wall | bmc/Core |
|---|---|---|---|
| 0-99,999 | 252.0 | 255.5 | 1.01 |
| 100,000-199,999 | 243.3 | 239.0 | 0.98 |
| 200,000-299,999 | 919.2 | 405.5 | 0.44 |
| 300,000-399,999 | 1881.8 | 884.9 | 0.47 |
| 400,000-499,999 | 4066.1 | 1578.3 | 0.39 |
| 500,000-599,999 | 4592.0 | 1991.5 | 0.43 |
| 600,000-699,999 | 5626.5 | 2235.2 | 0.40 |
| 700,000-799,999 | 6170.9 | 2316.4 | 0.38 |
| 800,000-899,999 | 8732.0 | 3884.5 | 0.44 |
| 900,000-970,209 | 6012.3 | 2730.0 | 0.45 |

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
| 900,000-970,209 | 6012.3 | 69,959 | 2363.7 | 464.9 | 75.1 | 1.4 | 949.9 | 102.4 | 66.0 | 0.6 | 572.2 | 115.5 | 2.8 | 3648.6 | 2 / 99.7 |
| **total** | 38496.0 | 969,959 | 13909.2 | 2289.1 | 453.2 | 30.0 | 5322.7 | 112.6 | 562.5 | 4.7 | 4463.8 | 594.5 | 19.8 | 24586.7 | 16 / 802.9 |

connect block = Core's own per-block total (load .. postprocess). verify wait = "Verify" minus "Connect N transactions" (Verify is timed from the same start). outside connect = wall minus connect block: waiting for blocks to arrive, header sync, and anything ActivateBestChain does between blocks (index callbacks run on their own threads). UTXO flushes = count / seconds of "write coins cache to disk" (already inside write chainstate when IF_NEEDED; periodic ones fall between blocks).

Core flush and coindb lines: 18 chainstate writes (FORCE_FLUSH 2, IF_NEEDED 10, PERIODIC 6); 715,445,080 txouts committed; block index writes 18 (2.0 s); block/undo file flushes 18 (1.4 s); disconnects 0.

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
| 900,000-970,209 | 2730.0 | 70,210 | 2433.7 | 32.2 | 177.6 | 479.5 | 596.5 | 857.5 | 45.3 | 174.6 | 63.6 | 333.4 | 8.4 | 132.2 | 331.0 | 6.2 | 6.9 | 0.0 | 0.0 | 0.4 | 0.0 | 0.0 | 88.9 | 295.9 |
| **total** | 16520.9 | 970,210 | 14060.1 | 165.2 | 1128.5 | 739.4 | 4133.8 | 5660.6 | 397.1 | 1363.6 | 429.0 | 1845.4 | 53.7 | 921.4 | 2462.8 | 54.5 | 42.9 | 0.0 | 0.0 | 0.4 | 0.0 | 0.0 | 673.6 | 2460.4 |

total = the block line's own total; other = total minus the named stages. ix = the choke-point index work outside the block total ([bench] index lines printed by the applying process: on its wall). ixw = the same writers run in the forked index worker (the [bench] index lines between its started and stopped lines): off the apply path, not in outside. outside = wall minus (total + ix): download waits and everything off the apply path. bmc applies on a pipeline, so outside is not idle time by itself.

Index worker (plan B4): 969,487 block(s) indexed in the worker over 1 start(s); worker time by writer: txindex 334.0 s, txospender 0.0 s, bfilter 339.6 s, addr 0.0 s, zmq 0.0 s.

Other bmc [bench] lines: flush x110 (1356.9 s)

Download chunks ([dlc] chunk lines): 60677; bytes 774.29 GB; wait sum 5160 s, p50 0.05 s, p90 0.22 s, max 5.72 s; wall sum 83600 s, p50 0.94 s, p90 3.17 s, max 56.10 s; 81 distinct peers. Final [dlc] summary line, after the download ended (recv is the idle tail, not the run): recv 0.0B/s (avg 45.2MB/s), pool idle 6%. Peer status lines named 44 distinct peers.

