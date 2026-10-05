# 2026-10-05 — The logged IBD pair: Core v31.1 rerun #6 vs bmc run 34, on Core's download rules

Operator ask (2026-10-04): "full logged runs to test module level perf of each
core and bmc for ibd to rpc service. Equivalent parameters for bmc to download
just like core does." Plan: `worklog/2026-10-04-logged-ibd-runs-plan.md`.
Generated tables: appendix (from `validation/ibd_stage_report.py`).

Both runs: fresh datadir on /srv/nvme8tb, dbcache=8192, txindex +
coinstatsindex + blockfilterindex, assumevalid = the chain default (both logs
show scripts skipped through 938,343 and resumed above), 10 download peers,
16 blocks in flight per peer, 1,024-block window, stallers disconnected and
never banned, no speed ranking (`bmc.dlshape=core`, PR #380). One at a time,
nothing else on the box, no RPC to either node until its finish line.

## 1. The finish line: every index at the tip

| | Core rerun #6 | bmc run 34 | bmc/Core |
|---|---|---|---|
| headers to the first block | 1 m 15 s | 5 m 06 s (one peer at 200 KB/s) | |
| IBD end (tip stored and applied) | 10:41:21 | 7:16:01 | 0.68 |
| **ready: every index at the tip** | **10:42:05** (38,525 s) | **7:17:39** (26,259 s) | **0.68 — bmc 1.47× faster** |
| logging overhead (vs the unlogged rerun #5 / run 33) | +9 m 17 s (1.5%) | not measurable (one line per block) | |

bmc's `[ready]` came 98 s after its tip, with no coinstats history rebuild
(PR #381: the live rows from genesis are the history). Core's indexes were at
the tip 30 s after its tip.

## 2. Where the time went (applier-thread seconds, summed over blocks)

Core's `[bench]` lines time `ConnectTip` on its validation thread; bmc's
`[bench] block` lines time the fold process per block, plus `[bench] index`
for the choke-point index work. "Outside" is wall minus that sum: the time
the applier was NOT applying.

| | Core | bmc |
|---|---|---|
| wall to the tip | 38,496 | 26,923 |
| applier busy | **13,909 (36%)** | **17,166 (64%)** |
| applier waiting ("outside") | **24,587 (64%)** | **9,757 (36%)** |
| of which: header sync | ~75 | 306 |
| of which: the last segment (900k–tip) | 3,649 | 4,632 |

**bmc's applier is not faster than Core's; it is 23% slower in thread-seconds.
bmc wins the run because its applier waits 2.5× less.** Core's download and
its block connection share the message-handling thread: `ProcessNewBlock` →
`ActivateBestChain` runs there, and `SendMessages` (which refills the 16 in
flight per peer) does not run until it returns, so download and apply take
turns. bmc downloads in ten worker processes into a window above the STORED
frontier, so the applier always has a queue (median apply lag 364–564 blocks
through 400k–900k) and the workers never wait on the applier. Core's log
cannot say how much of its 24,587 s is socket waiting versus thread
contention (that needs `-debug=net` or a profile); the structure is the
explanation, the number is the measurement.

## 3. The apply path, stage by stage

| stage | Core (s) | bmc (s) | note |
|---|---|---|---|
| UTXO lookups + updates | connect txs 5,323 + flush 4,464 + write chainstate 595 + coins flushes 803 ≈ 10.4k–11.2k | get 4,638 + **put 7,812** + ckpt 54 + flush 1,359 = **13,863** | bmc ~25–30% more |
| script verification | verify wait 113 (15 threads keep up) | verify 773 (492 of it above assumevalid) | both small: assumevalid |
| block read | load 2,289 | read 124 | flat archive vs block files + index |
| undo | 563 | (inside put) | |
| per-block index work | index writing 5 (callbacks on their own threads) | idx 1,194 + txindex 329 + bfilter 375 + csi 460 | bmc pays it inline |
| sanity / fork / postprocess | 503 | other 48 | |

Per input, late chain (800k–900k): bmc get 2.0 µs, put 3.1 µs. Put is the
largest single stage of the whole run: 7,812 s = 29% of bmc's wall. With
ranked peers (run 31, 5:28:11 = 19,691 s) bmc becomes apply-bound, and the
applier's ~17.2k s is then the floor: **the UTXO put path is bmc's next
lever, not the download.**

## 4. Per segment (wall, s)

| segment | Core | bmc | bmc/Core | bmc was |
|---|---|---|---|---|
| 0–100k | 252 | 533 | 2.11 | header sync 306 s from one slow peer, then apply-bound (window full) |
| 100k–200k | 243 | 266 | 1.09 | apply-bound (window full 75% of heartbeats) |
| 200k–300k | 919 | 555 | 0.60 | balanced |
| 300k–400k | 1,882 | 1,346 | 0.72 | balanced |
| 400k–500k | 4,066 | 2,047 | 0.50 | download and apply overlapped, applier 10–20% idle |
| 500k–600k | 4,592 | 2,590 | 0.56 | same |
| 600k–700k | 5,627 | 2,880 | 0.51 | same |
| 700k–800k | 6,171 | 3,024 | 0.49 | same |
| 800k–900k | 8,732 | 6,148 | 0.70 | download slowing: 27 MB/s aggregate (was 41–45) |
| 900k–tip | 6,012 | 7,537 | **1.25** | **download-bound: 14.5 MB/s aggregate; 75 stall disconnects in two hours** |

Core's slope is steady. bmc's last two segments are where Core's peer rules
cost it: the window is committed in height order, so the stored frontier
moves at the pace of the slowest of ten random peers; when it blocks, the
staller is disconnected (2 s doubling to 64 s) and the chunk re-fetched from
another random pick. bmc hit that 108 times (Core: 25), 75 of them after
10:00Z. The peer set was 24 addresses, one of them (194.156.188.249) at
92 MB/s carrying 35% of all bytes from height 65 to the tip; the rest 1.5–7
MB/s. Under bmc's own rules (runs 31–33: rank 130+ live peers, rotate under
0.5× median) the same stretch took 50–57 min instead of 113.

## 5. What this settles, and what it does not

1. **On equal download terms bmc syncs to "every index at the tip" 1.47×
   faster than Core v31.1** (7:17:39 vs 10:42:05). Runs 31–33's 1.75–1.93×
   add bmc's peer ranking on top; that is a real feature but not an equal-terms
   number.
2. **The win is concurrency, not a faster per-block apply.** Core serialises
   download and connection on one thread (13.9k busy + 24.6k waiting); bmc
   overlaps them (17.2k busy, 9.8k waiting, most of that in the last segment).
3. **bmc's UTXO store costs more applier time than Core's cache: 13.9k vs
   ~11k s, put alone 7.8k s.** The "own LSM store" is a durability/memory
   design, not a speed win per block. It is the next target.
4. **Script verification is irrelevant to both under assumevalid**; the asm
   hot paths matter below the UTXO work. The 2026-09-28 module benchmarks
   (archive read 2.8–3×, MuHash 6×) show up as bmc's read 124 s vs Core's load
   2,289 s and csi 460 s off the critical path — real, but ~2k s of a 38k s
   gap.
5. **Not settled:** the split of Core's 24.6k s "outside" between socket
   waits and thread contention; whether Core's 25 vs bmc's 108 stalls is the
   chunked committer or a different peer draw (one run each).

Harness notes: the `[dlc] == elapsed` heartbeat printed "in flight 0" for the
whole run — in every run since the in-order committer (2026-09-08), run 33
included: it counted holes below the stored tip, which that committer keeps at
zero. Fixed with this report: the field is now the heights claimed above the
stored frontier. "pool idle" is wait-before-first-byte, not throughput — it
read 4–5% while the aggregate rate fell to 14.5 MB/s; the `[dlc] -- recv`
line beside it carries the rate, and the report now says that its final
instance is the idle tail.

## Appendix: the generated report
# IBD stage report: Core v31.1 vs bmc

Segments of 100,000 heights. Times are seconds unless written h:mm:ss; elapsed times are from each run's own start.

## Runs

| | log | start (UTC) | max height | blocks w/ stage lines | IBD end | ready | ready height |
|---|---|---|---|---|---|---|---|
| Core | `/srv/nvme8tb/bench/core31/debug.log` | 2026-10-04 18:20:24 | 969,958 | 969,959 | 10:41:21 | 10:42:05 (tip 10:41:35) | 969,958 |
| bmc | `/srv/nvme8tb/bench/run34/data/main/debug.log` | 2026-10-05 05:05:34 | 970,019 | 970,020 | 7:16:01 | 7:17:39 | 969,958 |

Core: IBD end = "Leaving InitialBlockDownload"; ready = READY_INDEXES (the first getindexinfo after READY_TIP with every index at that height), READY_TIP = its UpdateTip at the oracle's tip. bmc: IBD end = "[dlc] catch-up done" (or phase.log IBD_END); ready = "[ready] all indexes at height N".

## Milestones (elapsed to the first block at or past each height)

| height | Core | bmc | bmc/Core |
|---|---|---|---|
| 100,000 | 0:04:12 | 0:08:52 | 2.11 |
| 200,000 | 0:08:15 | 0:13:18 | 1.61 |
| 300,000 | 0:23:34 | 0:22:33 | 0.96 |
| 400,000 | 0:54:56 | 0:44:58 | 0.82 |
| 500,000 | 2:02:42 | 1:19:05 | 0.64 |
| 600,000 | 3:19:14 | 2:02:14 | 0.61 |
| 700,000 | 4:53:00 | 2:50:14 | 0.58 |
| 800,000 | 6:35:51 | 3:40:38 | 0.56 |
| 900,000 | 9:01:23 | 5:23:05 | 0.60 |
| 970,019 | -- | 7:28:43 | -- |

## Wall time per segment

| segment | Core wall | bmc wall | bmc/Core |
|---|---|---|---|
| 0-99,999 | 252.0 | 532.6 | 2.11 |
| 100,000-199,999 | 243.3 | 265.9 | 1.09 |
| 200,000-299,999 | 919.2 | 554.5 | 0.60 |
| 300,000-399,999 | 1881.8 | 1345.5 | 0.72 |
| 400,000-499,999 | 4066.1 | 2046.6 | 0.50 |
| 500,000-599,999 | 4592.0 | 2589.5 | 0.56 |
| 600,000-699,999 | 5626.5 | 2880.1 | 0.51 |
| 700,000-799,999 | 6170.9 | 3023.5 | 0.49 |
| 800,000-899,999 | 8732.0 | 6147.7 | 0.70 |
| 900,000-970,019 | 6012.3 | 7537.4 | 1.25 |

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
| 900,000-970,019 | 6012.3 | 69,959 | 2363.7 | 464.9 | 75.1 | 1.4 | 949.9 | 102.4 | 66.0 | 0.6 | 572.2 | 115.5 | 2.8 | 3648.6 | 2 / 99.7 |
| **total** | 38496.0 | 969,959 | 13909.2 | 2289.1 | 453.2 | 30.0 | 5322.7 | 112.6 | 562.5 | 4.7 | 4463.8 | 594.5 | 19.8 | 24586.7 | 16 / 802.9 |

connect block = Core's own per-block total (load .. postprocess). verify wait = "Verify" minus "Connect N transactions" (Verify is timed from the same start). outside connect = wall minus connect block: waiting for blocks to arrive, header sync, and anything ActivateBestChain does between blocks (index callbacks run on their own threads). UTXO flushes = count / seconds of "write coins cache to disk" (already inside write chainstate when IF_NEEDED; periodic ones fall between blocks).

Core flush and coindb lines: 18 chainstate writes (FORCE_FLUSH 2, IF_NEEDED 10, PERIODIC 6); 715,445,080 txouts committed; block index writes 18 (2.0 s); block/undo file flushes 18 (1.4 s); disconnects 0.

## bmc: stages per segment (sum over blocks, seconds)

| segment | wall | blocks | total | read | idx | verify | get | put | ckpt | flush | csi | other | ix txindex | ix txospender | ix bfilter | ix addr | ix zmq | outside |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0-99,999 | 532.6 | 100,000 | 2.3 | 0.0 | 0.0 | 0.1 | 0.0 | 1.6 | 0.3 | 0.0 | 0.0 | 0.3 | 0.0 | 0.0 | 0.4 | 0.0 | 0.0 | 529.9 |
| 100,000-199,999 | 265.9 | 100,000 | 25.8 | 0.1 | 2.9 | 2.7 | 4.2 | 12.7 | 0.9 | 0.0 | 1.8 | 0.5 | 1.8 | 0.0 | 3.5 | 0.0 | 0.0 | 234.8 |
| 200,000-299,999 | 554.5 | 100,000 | 154.3 | 0.9 | 16.0 | 8.0 | 18.6 | 77.1 | 2.7 | 21.5 | 9.0 | 0.5 | 8.7 | 0.0 | 9.0 | 0.0 | 0.0 | 382.5 |
| 300,000-399,999 | 1345.5 | 100,000 | 559.1 | 2.7 | 47.9 | 17.5 | 95.5 | 283.6 | 4.0 | 81.9 | 25.2 | 0.8 | 22.7 | 0.0 | 21.5 | 0.0 | 0.0 | 742.3 |
| 400,000-499,999 | 2046.6 | 100,000 | 1489.7 | 6.7 | 114.9 | 33.8 | 386.1 | 734.2 | 6.2 | 151.8 | 51.5 | 4.5 | 48.5 | 0.0 | 43.2 | 0.0 | 0.0 | 465.2 |
| 500,000-599,999 | 2589.5 | 100,000 | 2003.6 | 8.7 | 165.9 | 39.5 | 599.6 | 934.3 | 5.8 | 185.7 | 57.7 | 6.3 | 46.8 | 0.0 | 48.0 | 0.0 | 0.0 | 491.1 |
| 600,000-699,999 | 2880.1 | 100,000 | 2433.7 | 15.0 | 195.3 | 49.7 | 713.2 | 1170.3 | 6.4 | 204.0 | 71.8 | 8.1 | 51.4 | 0.0 | 60.9 | 0.0 | 0.0 | 334.0 |
| 700,000-799,999 | 3023.5 | 100,000 | 2383.0 | 21.5 | 197.5 | 54.3 | 653.1 | 1155.5 | 7.3 | 210.5 | 74.7 | 8.4 | 46.1 | 0.0 | 64.7 | 0.0 | 0.0 | 529.7 |
| 800,000-899,999 | 6147.7 | 100,000 | 4596.4 | 30.0 | 268.5 | 75.5 | 1484.5 | 2287.8 | 7.5 | 330.9 | 100.8 | 10.9 | 60.6 | 0.0 | 75.0 | 0.0 | 0.0 | 1415.7 |
| 900,000-970,019 | 7537.4 | 70,020 | 2814.1 | 38.0 | 184.9 | 492.2 | 682.9 | 1155.4 | 13.1 | 172.8 | 67.2 | 7.6 | 42.5 | 0.0 | 48.6 | 0.0 | 0.0 | 4632.2 |
| **total** | 26923.2 | 970,020 | 16462.0 | 123.6 | 1193.8 | 773.4 | 4637.7 | 7812.4 | 54.2 | 1359.1 | 459.8 | 48.0 | 329.1 | 0.0 | 374.7 | 0.0 | 0.0 | 9757.4 |

total = the block line's own total; other = total minus the named stages. ix = the choke-point index work outside the block total ([bench] index lines). outside = wall minus (total + ix): download waits and everything off the apply path. bmc applies on a pipeline, so outside is not idle time by itself.

Other bmc [bench] lines: flush x113 (1349.9 s)

Download chunks ([dlc] chunk lines): 60624; bytes 773.67 GB; wait sum 5250 s, p50 0.03 s, p90 0.20 s, max 6.68 s; wall sum 105720 s, p50 0.30 s, p90 5.05 s, max 29.49 s; 24 distinct peers. Last download summary: recv 0.0B/s (avg 51.6KB/s), pool idle 1%. Peer status lines named 25 distinct peers.


## The logging-overhead control

Core rerun #5 (same settings, default logging): IBD_END 2026-10-04T16:28:45Z (from the log) elapsed=37924s = 10 h 32 m 4 s
Core rerun #6 (debug=bench, debug=coindb, logtimemicros): IBD_END 2026-10-05T05:01:45.543049Z (from the log) elapsed=38481s = 10 h 41 m 21 s
