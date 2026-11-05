# Run 49 vs Core #7: the pread lookups (B15), cut at block 847,331

Run 49 (2026-10-11, branch `perf/2026-10-11-b15-lsm-reads-pread` at
90c1de3b, `bmc.lsmreads=pread`, the sampler beside it) measured plan
B15: the UTXO run records read with `pread()` instead of through the
mapping, so the run files leave the process's PSS. It was cut by the
operator session at block 847,331 (4:03:15 elapsed; run 46 was at
900,000 by then) once its finding was complete. The figures below are
to the cut; the stage script's "IBD end" is the last block line.

**The PSS row flips.** Sampler to the cut: PSS mean 9.6 GB, peak 19.2
GB (run 46 to ready: 34.1 / 56.3; Core #7: 17.6 / 34.3); anon mean 8.0,
peak 10.8 (run 46: 8.2 / 13.3). The peak was at 17:10Z, the fourth
full compaction's edge (49, 46 and 43 runs merged at 14:37Z, 15:44Z
and 16:54Z, 200–216 s each). The run files are page cache, not the
worker's resident set, which is what B15 set out to do.

**The applier pays four times the estimate, and not in syscalls.** The
get column is 8,867 s to the cut against run 46's 2,870 for the whole
sync (931 s to block 650,000 against 3,824); the applier's block total
is 13,654 s at 847,331, already past Core #7's 13,340 for 970,333. The
CPU is lower than run 46's at the same point (7,796 against 11,429 s
at +2 h): the applier is waiting on the disk. The worker's
`read_bytes` was 212 GB at +2 h; `/proc/meminfo` read `Active(file)`
1.3 GB against `Inactive(file)` 50 GB; mincore over the run files at
block 650,000 found 30.9 of 40.5 GB resident, the older generation
runs at 43–65% and the 4.3 GB base run at 67%. The blk and rev append
streams (294 + 104 GB by block 650,000) go through the same page cache,
each page referenced once, and a pread'd run page, referenced once as
well, is evicted with them. A mapped page is referenced through the
page table and the reclaim keeps it, which is why the mmap path never
showed this, and why its pages count in the PSS.

**What follows.** Plan B16 (`bmc.dropappends=1`, built after this run):
the undo stream is written back and dropped behind the applier every
16 MB and the blk file it has left is dropped whole, so the inactive
list is left to the run files. Run 50 measures pread + dropappends
together. The default stays `mmap` until it does.

Run 49's other rows, to the cut: 0 WARNING/FATAL; block 1 at 41 s;
100,000 at 2:11, 300,000 at 6:59, 500,000 at 56:46, 800,000 at
3:31:02; 160 memtable flushes (36.5 s), 160 freezes (31.4 s); 53,022
download chunks, 579.9 GB, wait sum 2,966 s.

---

# IBD stage report: Core v31.1 vs bmc

Segments of 100,000 heights. Times are seconds unless written h:mm:ss; elapsed times are from each run's own start.

## Runs

| | log | start (UTC) | max height | blocks w/ stage lines | IBD end | ready | ready height |
|---|---|---|---|---|---|---|---|
| Core | `/srv/nvme8tb/bench/core31-rerun7-20261007-logs/debug.log` | 2026-10-07 01:24:50 | 970,333 | 970,334 | 9:49:43 | 9:50:04 (tip 9:49:59) | 970,333 |
| bmc | `/srv/nvme8tb/bench/run49/data/main/debug.log` | 2026-10-11 13:27:02 | 847,331 | 847,332 | 4:04:07 | -- | -- |

Core: IBD end = "Leaving InitialBlockDownload"; ready = READY_INDEXES (the first getindexinfo after READY_TIP with every index at that height), READY_TIP = its UpdateTip at the oracle's tip. bmc: IBD end = "[dlc] catch-up done" (or phase.log IBD_END); ready = "[ready] all indexes at height N".

## Milestones (elapsed to the first block at or past each height)

| height | Core | bmc | bmc/Core |
|---|---|---|---|
| 100,000 | 0:02:06 | 0:02:11 | 1.04 |
| 200,000 | 0:04:44 | 0:03:10 | 0.67 |
| 300,000 | 0:15:30 | 0:06:59 | 0.45 |
| 400,000 | 0:44:37 | 0:20:54 | 0.47 |
| 500,000 | 1:43:30 | 0:56:46 | 0.55 |
| 600,000 | 2:52:17 | 1:30:42 | 0.53 |
| 700,000 | 4:18:21 | 2:26:56 | 0.57 |
| 800,000 | 5:54:00 | 3:31:02 | 0.60 |
| 900,000 | 8:13:37 | -- | -- |
| 970,333 | 9:49:59 | -- | -- |

## Wall time per segment

| segment | Core wall | bmc wall | bmc/Core |
|---|---|---|---|
| 0-99,999 | 126.4 | 131.6 | 1.04 |
| 100,000-199,999 | 158.4 | 58.4 | 0.37 |
| 200,000-299,999 | 645.5 | 229.6 | 0.36 |
| 300,000-399,999 | 1747.1 | 835.3 | 0.48 |
| 400,000-499,999 | 3532.8 | 2151.3 | 0.61 |
| 500,000-599,999 | 4127.4 | 2036.7 | 0.49 |
| 600,000-699,999 | 5163.5 | 3373.7 | 0.65 |
| 700,000-799,999 | 5739.6 | 3845.4 | 0.67 |
| 800,000-899,999 | 8377.1 | 1982.0 | 0.24 |
| 900,000-970,333 | 5781.4 | -- | -- |

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
| 0-99,999 | 131.6 | 100,000 | 2.6 | 0.0 | 0.0 | 0.1 | 0.0 | 0.8 | 0.9 | 0.0 | 0.0 | 0.1 | 0.0 | 0.2 | 0.2 | 0.0 | 0.7 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.2 | 129.0 |
| 100,000-199,999 | 58.4 | 100,000 | 27.7 | 0.1 | 2.7 | 2.7 | 4.0 | 12.2 | 3.6 | 0.0 | 1.8 | 3.0 | 0.0 | 4.0 | 3.3 | 0.5 | 0.6 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 4.5 | 30.7 |
| 200,000-299,999 | 229.6 | 100,000 | 158.6 | 0.8 | 15.0 | 7.9 | 28.8 | 64.0 | 26.9 | 5.7 | 8.9 | 9.9 | 0.1 | 20.2 | 24.6 | 2.5 | 0.6 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 17.7 | 71.0 |
| 300,000-399,999 | 835.3 | 100,000 | 719.0 | 3.5 | 44.4 | 17.1 | 331.5 | 215.5 | 75.2 | 7.3 | 23.6 | 31.1 | 1.2 | 57.1 | 101.9 | 5.3 | 0.8 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 42.7 | 116.3 |
| 400,000-499,999 | 2151.3 | 100,000 | 2025.0 | 12.2 | 105.1 | 32.8 | 1307.3 | 412.6 | 92.3 | 12.6 | 46.1 | 62.2 | 4.8 | 109.2 | 190.5 | 9.0 | 4.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 88.0 | 126.3 |
| 500,000-599,999 | 2036.7 | 100,000 | 1900.3 | 7.3 | 153.7 | 38.0 | 1099.2 | 427.9 | 90.9 | 11.7 | 65.8 | 63.2 | 5.7 | 121.4 | 187.4 | 10.4 | 5.8 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 90.8 | 136.4 |
| 600,000-699,999 | 3373.7 | 100,000 | 3234.1 | 21.5 | 181.5 | 47.9 | 2246.1 | 547.0 | 73.4 | 12.7 | 96.4 | 77.7 | 7.6 | 144.4 | 256.1 | 10.9 | 7.6 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 106.6 | 139.6 |
| 700,000-799,999 | 3845.4 | 100,000 | 3696.7 | 36.8 | 179.6 | 52.0 | 2652.6 | 593.7 | 61.6 | 12.3 | 100.5 | 78.5 | 8.3 | 148.9 | 297.1 | 8.6 | 7.7 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 105.3 | 148.7 |
| 800,000-899,999 | 1982.0 | 47,332 | 1890.4 | 17.2 | 113.1 | 34.6 | 1197.5 | 408.9 | 56.7 | 8.1 | 49.6 | 62.5 | 5.4 | 87.1 | 217.9 | 3.5 | 4.7 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 63.4 | 91.7 |
| **total** | 14644.2 | 847,332 | 13654.5 | 99.3 | 795.1 | 233.2 | 8867.0 | 2682.8 | 481.5 | 70.4 | 392.6 | 388.2 | 33.1 | 692.4 | 1279.0 | 50.7 | 32.5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 519.1 | 989.7 |

total = the block line's own total; other = total minus the named stages. ix = the choke-point index work outside the block total ([bench] index lines printed by the applying process: on its wall). ixw = the same writers run in the forked index worker (the [bench] index lines between its started and stopped lines): off the apply path, not in outside. outside = wall minus (total + ix): download waits and everything off the apply path. bmc applies on a pipeline, so outside is not idle time by itself.

Index worker (plan B4): 847,315 block(s) indexed in the worker over 1 start(s); worker time by writer: txindex 258.2 s, txospender 0.0 s, bfilter 260.8 s, addr 0.0 s, zmq 0.0 s.

Other bmc [bench] lines: flush x160 (36.5 s); freeze x160 (31.4 s)

Download chunks ([dlc] chunk lines): 53022; bytes 579.90 GB; wait sum 2966 s, p50 0.05 s, p90 0.08 s, max 2.67 s; wall sum 51028 s, p50 0.65 s, p90 2.36 s, max 15.05 s; 30 distinct peers. Final [dlc] summary line, after the download ended (recv is the idle tail, not the run): recv 9.3MB/s (avg 37.9MB/s), pool idle 5%. Peer status lines named 19 distinct peers.

