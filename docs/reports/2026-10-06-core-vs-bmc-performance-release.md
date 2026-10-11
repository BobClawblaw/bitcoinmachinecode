# Core v31.1 vs bmc — performance for the first release

Every number here comes from a log or a script named beside it; nothing is
estimated. The bmc numbers are run 38 (2026-10-06, main `020b13dc`, the
index worker of PR #390), the Core numbers are rerun #6 (2026-10-04,
v31.1). Run 37 (main `8e81ffb5`, the same morning, before the index
worker) and run 34 (the same bmc code family under Core's own download
rules, before the 2026-10-05 batches) are kept as the "before" columns.
Run 39 (main `7eb763ab`, run 38 plus PR #392, started 13:11Z the same
day) is the repeat of the release build and is shown beside run 38
wherever it was measured; where the two differ the text says by how much.
Run 40 (main `b194dd01`: run 39 plus the async memtable flush B3, the
chainwork sync B8 and the memory naming M1, PRs #394–#396; started 20:34Z
the same day, finished 01:16Z on the 7th) is the release build's third
sync and the one with the `[mem]` lines; it is the right-hand column
wherever it was measured. Core rerun #7 (2026-10-07 01:24Z, v31.1, the
same box, with the process sampler beside it) is the Core run the verdict
is judged against: it is 52 minutes faster than rerun #6, all of it on the
early chain, and it is the only Core run with a memory measurement. Both
Core runs are shown; where they differ the text says so.

## 0. Setup

One machine, both nodes one at a time for the sync, both live for the RPC
rows. Core v31.1 from source (`/storage/bitcoin-core-v31.1`), bmc from main.
Sync runs: fresh datadir on the same NVMe (/srv/nvme8tb), `dbcache=8192`,
txindex + coinstatsindex + blockfilterindex, assumevalid = the chain default
on both (both logs show scripts skipped through 938,343), 10 download peers,
1,024-block window. Core: `debug=bench`, `debug=coindb`, `logtimemicros=1`.
bmc: `bmc.benchlog=1`. The finish line on both sides is "every index at the
tip": Core's first `getindexinfo` after its `UpdateTip` at the oracle's tip;
bmc's `[ready]` line. A proc sampler (PSS, anonymous, CPU every 5 s) ran
beside every bmc run and beside Core rerun #7; rerun #6 had none (its CPU
time is systemd's "Consumed" line; its peak memory was not captured).

| | Core rerun #6 | Core rerun #7 (with the sampler) | bmc run 34 (Core's download rules) | bmc run 37 (bmc's rules) | bmc run 38 (+ index worker, this release) | bmc run 39 (+ PR #392, the repeat) | bmc run 40 (+ B3, B8, M1) | bmc run 41 (+ B9 part 2, B11, B10) | bmc run 46 (+ M2, M3, B12 ranges, B13, B14, the frozen copy, the Bloom sizing: the release build) |
|---|---|---|---|---|---|---|---|---|---|
| started (UTC) | 2026-10-04 18:20:24 | 2026-10-07 01:24:50 | 2026-10-05 05:05:34 | 2026-10-06 00:06:24 | 2026-10-06 06:42:09 | 2026-10-06 13:11:02 | 2026-10-06 20:34:00 | 2026-10-07 12:52:34 | 2026-10-09 23:15:30 |
| commit | v31.1 | v31.1 | 56bbe8c2 | 8e81ffb5 | 020b13dc | 7eb763ab | b194dd01 | 7027c734 | a79bcdca |
| download rules | Core's | Core's | Core's (`bmc.dlshape=core`) | bmc's (ranked peers, rotation, first-eviction reassignment) | run 37's | run 38's, with the probes ending on their own clocks (PR #392) | run 39's, with the chainwork records appended during the download (PR #395) | run 40's, with the idle wait ended by the committer's tip (B9 part 2) and the top-up's claim bounded by the last ranking (B10) (PR #400) | run 41's; the header chain in 19 parallel ranges from four peers (B12, #410/#412/#413), a staller banned on its second stall (B13, #405), the dead-weight rule judging only a worker's free time (B14, #409) |
| index writers | callback threads | callback threads | on the applier | on the applier | a forked index worker during the download (PR #390) | run 38's | run 38's; the memtable flush in a forked writer (PR #396) | run 40's; the memtable in anonymous memory, not a file mapping (B11, PR #400) | run 41's; `dbcache` is the whole UTXO heap, no fork copies of the memtable (M2, #407), the merge budget at any run count (M3, #408), the frozen copy keeps its pages (#416), a run's Bloom filter sized to its records (#417) |
| logs | `bench/core31-rerun6-20261004-logs/` | `bench/core31-rerun7-20261007-logs/` (debug.log, proc.log, watch.log) | `bench/run34/` | `bench/run37/` (debug.log copied beside the harness logs) | `bench/run38/` (same) | `bench/run39/` (debug.log under `data/main/`) | `bench/run40/` (same) | `bench/run41/` (same) | `bench/run46/` (debug.log beside the harness logs) |
| correctness | — | — | — | UTXO muhash identical to Core at 970,133 (harness capstone) | identical at 970,165 | identical at 970,209 | identical at 970,267 | identical at 970,364 | identical at 970,710 |

## 1. Initial block download, genesis to every index at the tip

| | Core #6 | Core #7 | bmc 34 | bmc 37 | bmc 38 | bmc 39 | bmc 40 | bmc 41 | bmc 46 | bmc 38 / Core #6 | bmc 39 / Core #6 | bmc 40 / Core #6 | bmc 40 / Core #7 | bmc 41 / Core #7 | bmc 46 / Core #7 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| headers → first block | 1:15 | 0:45 | 5:06 | 1:58 | 1:39 | 0:50 | 0:47 | 0:48 | **0:34** | 1.32 | 0.66 | 0.62 | 1.03 | 1.07 | **0.76** |
| 100,000 | 4:12 | 2:06 | — | 5:22 | 5:08 | 4:15 | 4:16 | **1:35** | **1:22** | 1.22 | 1.01 | 1.02 | **2.03** | **0.76** | **0.65** |
| 200,000 | 8:15 | 4:44 | — | 9:22 | 9:03 | 8:14 | 8:12 | **2:55** | **2:35** | 1.10 | 1.00 | 0.99 | **1.73** | **0.62** | **0.55** |
| 300,000 | 23:34 | 15:30 | — | 16:03 | 15:52 | 15:00 | 15:36 | 6:57 | 6:35 | 0.67 | 0.64 | 0.66 | 1.01 | 0.45 | 0.43 |
| 500,000 | 2:02:42 | 1:43:30 | 1:19:05 | 0:58:53 | 0:55:42 | 0:56:03 | 0:56:47 | 44:25 | 40:49 | 0.45 | 0.46 | 0.46 | 0.55 | 0.43 | 0.39 |
| 800,000 | 6:35:51 | 5:54:00 | 3:40:38 | 2:54:02 | 2:35:50 | 2:45:06 | 2:49:21 | 2:15:53 | 2:03:21 | 0.39 | 0.42 | 0.43 | 0.48 | 0.38 | 0.35 |
| 900,000 | 9:01:23 | 8:13:37 | 5:23:05 | 4:03:31 | 3:35:43 | 3:49:50 | 3:55:58 | 3:10:02 | 2:44:26 | 0.40 | 0.42 | 0.44 | 0.48 | 0.38 | 0.33 |
| IBD end (tip stored + applied) | 10:41:21 | 9:49:43 | 7:16:01 | 4:49:12 | 4:15:43 | 4:33:11 | 4:41:02 | 3:47:48 | 3:17:32 | 0.40 | 0.43 | 0.44 | 0.48 | 0.39 | 0.33 |
| **every index at the tip** | **10:42:05** | **9:50:04** | **7:17:39** | **4:50:52** | **4:17:09** | **4:34:48** | **4:42:41** | **3:48:22** | **3:17:55** | **0.40** | **0.43** | **0.44** | **0.48** | **0.39** | **0.34** |
| CPU time consumed, all processes | 13 h 50 m (journal) | 13 h 15 m (systemd CPUUsageNSec, 47,700 s; the sampler's 56,396 s less its 8,044 s baseline agrees) | — | 8 h 17 m (sampler, 29,819 s) | 7 h 48 m (sampler, 28,108 s) | 7 h 56 m (sampler, 28,535 s) | 8 h 24 m (sampler, 30,218 s; 1,545 s of it the forked flush writer) | 7 h 39 m (sampler, 27,567 s; 1,859 s of it the flush writer) | 7 h 13 m (sampler, 25,968 s; 2,508 s of it the flush writer) | 0.56 | 0.57 | 0.61 | 0.63 | 0.58 | 0.54 |
| peak memory | not captured | see §5 (sampler) | — | see §5 | see §5 | see §5 | see §5 (the `[mem]` lines) | see §5 | see §5 | — | — | — | §5 | §5 | §5 |

Milestones and segment walls: `docs/reports/2026-10-06-run38-vs-core6-stage-report.md`,
`2026-10-06-run39-vs-core6-stage-report.md`,
`2026-10-07-run40-vs-core6-stage-report.md`, and against Core #7
`2026-10-07-run39-vs-core7-stage-report.md`,
`2026-10-07-run40-vs-core7-stage-report.md`,
`2026-10-07-run41-vs-core7-stage-report.md` and
`2026-10-11-run46-vs-core7-stage-report.md`
(validation/ibd_stage_report.py; run 37's is beside them). Core is ahead
for the first 200,000 blocks in run 38 (by 56 s at 100,000 and 48 s at
200,000), and the gap is the probe minute before block 1 (below), not the
request shape: the #392 build's two fresh syncs of the same afternoon
reached 100,000 at 4:16 and 4:20 and 200,000 at 8:21 and 8:15 against
Core's 4:12 and 8:15, while a rolling per-block pipeline below 300,000
(`bmc.dlcrollbelow`, two arms against those two controls) was 13% slower
or tied. From 300,000 on bmc is ahead in every segment, by 2.2–2.9×.

Run 39, the repeat on the same code plus PR #392, settles the early chain:
boot to block 1 took 49.6 s (liveness 5.8 s, ranking 8.2 s, headers 35.3
s) against run 38's 99 s and Core's 75, and 100,000 / 200,000 came at
4:15 / 8:14 against Core's 4:12 / 8:15. From there it ran 17 minutes
behind run 38 (ready 4:34:48 against 4:17:09; still 2.3× Core). The
stage reports put the difference in two places, neither of them touched
by PR #392: the applier's own time rose from 13,363 to 14,060 s (put
4,994 → 5,661 s, of which the memtable insert 1,377 → 1,845 s and the
the spent output's delete 2,242 → 2,463 s (this read "undo capture"
until 2026-10-07, one column off; see §2); get, verify, read and the index columns
within 1%), and the download's per-chunk wait sum rose from 3,591 to
5,160 s over 81 distinct peers against run 38's 25 (the pool banned 22 of
135 by the end against 4 of 141; chunk wall p50 0.94 s against 0.39 s).
The tree's CPU time was the same (28,535 against 28,108 s), the box's I/O
pressure the same (mean `psi_io_full` 5.5 against 4.1), the flush count
the same (110 against 109). The applier's extra 700 s is not explained
by the logs of either run; run 40 (the async flush, plan B3) changes that
column on purpose and is the next data point. The peer set is the
suspect for the download side: with every probe in flight at once the
ranking's per-peer rate is a share of the box's uplink, not the peer's,
and the top of the ranking it produced churned (plan B9, part 1, open).

Run 40, the release build (run 39 plus plans B3, B8 and M1), is the
third sync of the same download rules and the first with the flush off
the applier. Boot to block 1 took 46.5 s (liveness 4.0 s, ranking 8.6 s,
headers 33.3 s), 100,000 / 200,000 came at 4:16 / 8:12, and from there it
ran 8 minutes behind run 39 (ready 4:42:41 against 4:34:48; 2.3× Core).
The two fixes measured as built: the pause between the download's end and
the first drained block, 65 s in run 39, was 0.55 s (B8: the chainwork
records are appended during the download, and the gate line reports
970,229 of them in step with the archive); and the memtable flush, 1,357
s inline on the applier in run 39 over 110 flushes, was 131 s over 112
(B3: each flush now freezes the memtable in 0.47–0.68 s on the applier —
the first one 11.9 s, faulting the copy in — and a forked writer builds
the 1.8 GB run in 13.6 s median, 1,545 s in all off the applier; zero
waits on a writer and zero inline fallbacks over the run). The applier's
total nonetheless rose, 14,060 → 14,650 s: the put column went 5,661 →
7,135 s (insert 1,845 → 2,621, the spent output's delete 2,463 → 3,079,
labelled "undo capture" until 2026-10-07; get, verify
and the index columns within 4%), the third rise in a row for the same
put code (run 38: 4,994 s). It is not the writer's presence: the insert
cost per 1,000 inputs was 0.77 ms in the blocks applied while a writer
child was alive and 0.74 ms in the rest. The tree's CPU rose by the
writer's own 1,545 s and little else (28,535 → 30,218 s), so the put
column's extra 1,475 s was waited for, not computed; the memtable's table
and blob are file-backed shared mappings whose dirty pages the kernel
writes back and reclaims under pressure, and the box carried its usual
other services with its 8 GB swap full (§5). The download side: 70
distinct peers and a per-chunk wait sum of 6,790 s against run 39's 81
and 5,160 s (run 38: 25 and 3,591 s), this time with no peer banned (0 of
161 against 22 of 135), so the churn is in the ranking, not the bans
(plan B9, part 1, still open). The tail from the download's end to ready
was 99 s: 23 s to drain the last 629 blocks, then a top-up round for the
37 blocks that arrived during the 4.7 hours, which re-probed and re-ranked
the whole pool (161 peers, 22.3 s) before asking for them (plan B10).

Core rerun #7 ran the same night on the same box with the sampler
beside it, right after run 40 (01:24Z to 11:15Z): 9:50:04 to every
index at the tip, 52 minutes faster than rerun #6, and all of the
difference is before 500,000: 100,000 at 2:06 against #6's 4:12,
200,000 at 4:44 against 8:15, 500,000 at 1:43:30 against 2:02:42, then
the same pace (800,000 to 900,000: 8,377 s against 8,732). Its connect
columns are within 4% of #6's (13,340 against 13,909 s), so the
difference is the peers it was given, not the box. Against it bmc's
early chain is a loss: 2.0× at 100,000 and 1.7× at 200,000, parity at
300,000, ahead from 400,000 on by 1.8–2.1× per milestone, and the sync
2.1× (0.48). The cause is in run 40's own log. Below 100,000 the chunk
completions come in bursts 2.09 s apart (p50 over 99 bursts), one
burst per 1,024-block window: the helpers fill a window of tiny blocks
in ~0.3 s and then block at its edge, because the window is anchored to
the connected tip and the download loop, having found nothing
connectable the instant after its last connect pass, sleeps its whole
2 s idle before connecting them. Core connects each block on arrival,
so its window never waits on a timer; its first 100,000 blocks landed
at 1,205 a second against bmc's 746 while the helpers were busy and
nothing at all in the other 76 of the 210 s. The fix (the idle wait
reads the committer's tip every 20 ms and ends when it moves; plan B9
part 2, `perf/2026-10-07-b9-idle-tick`) is built and pinned by
`tests/test_dlc_interleave`; its A/B to 300,000 and the full run that
carries it are below (§7).

Run 41, the release build (run 40 plus plans B9 part 2, B11 and B10 and
the writer reap at the tip; main `7027c734`, PR #400), ran the same
afternoon under the same box load as run 40 and Core #7: 3:48:22 to
every index at the tip, 54 minutes off run 40 and 2.6× Core #7 (0.39).
Boot to block 1 took 48 s (liveness 1.3 s, ranking 8.2 s over 132 live
peers, headers 38 s) against Core's 45. The early chain is bmc's from the
first block: 100,000 at 1:35 against Core #7's 2:06 and run 40's 4:16,
200,000 at 2:55 against 4:44 and 8:12 (B9 part 2: the gate line reads
`idle waits cut short 1670`), 300,000 at 6:57 against 15:30, and every
later milestone at 0.38–0.43 of Core's clock. The applier's own time
fell from 14,650 to 11,842 s, 11% under Core #7's 13,340 (§2): the put
column 7,135 → 3,842 s with the memtable in anonymous memory (B11; the
insert 2,621 → 664 s, the spent output's delete 3,079 → 1,822 s; the
undo capture itself was 979 → 921 s and was never the mover — the
earlier text's "undo capture" named this delete column, see §2). The
writer: 110 freezes, 0.82 s mean after the first (8.9 s, faulting the
copy in), the writer's run built in 16.6 s median, 1,859 s in all off
the applier, zero waits and zero inline fallbacks. The tail from the
download's end to ready was 34 s (run 40: 99 s), 25 s of it draining
the last 491 blocks and no top-up re-ranking (B10: the pool's claims
stayed within the ranking's bound, so nothing was re-probed). The
download side: 69 distinct peers, a per-chunk wait sum of 5,872 s (run
40: 6,790), the average 54 MB/s with the pool 8% idle; 34 of 132 peers
banned, 29 of them by the window-stall rule between 390,000 and 430,000
when fresh peers did not answer their first 16-block request inside the
2 s stall timeout (Core's rule disconnects the same peers; ours also
bans — plan B13, not a cost to this run: the pool never ran short).

Runs 42 to 46 (10-08 to 10-10) carry the plan items that run 41 left
open and the memory work (M2), each measured by a fresh sync; the four
syncs 42–45 are in `docs/releases/2026-10-08-the-heap-the-merge-budget-and-header-ranges.md`
and `worklog/2026-10-09.md`, and only run 46, the release build, is in
the tables here. M2 (#407) made `dbcache` the whole UTXO heap and
stopped the forked children copying the memtable: the heap fell from
run 41's 15.3 GB mean / 32.2 GB peak to 6.4 / 11.8 GB in run 42 — and
the sync slowed to 5:31:27, because a halved memtable doubled the
freezes and the runs on disk, a merge deferral then held the run count
high (M3, #408, run 43: 4:05:03) and each freeze re-faulted the frozen
copy's 3 GB of huge pages behind a memory compaction (2.4 s a freeze in
run 45; the copy keeps its pages since #416) while the flush runs'
Bloom filters, capped at 4 MiB, passed 55% of absent keys to a sparse
search (#417 sizes them to the run). Run 46 (main `a79bcdca`): 3:17:55
to every index at the tip, 30 minutes under run 41 and 3.0× Core #7
(0.34). Boot to block 1 took 34 s (liveness 1.4 s, ranking 7.4 s over
136 peers, the 970k headers in 19 ranges from four peers in 15.8 s at
4.6 MB/s — B12; run 41's single stream took 38 s) against Core's 45;
100,000 at 1:22 and 200,000 at 2:35 against Core's 2:06 / 4:44; every
later milestone at 0.33–0.43 of Core's clock. The applier's own time
fell to 9,691 s, 27% under Core #7's 13,340: `get` 4,607 → 2,870 s (the
sized filters: per spent input ~880 ns over 575k–875k against 1,248 in
run 41), the freezes 217 at 136 ms mean (30 s on the applier; the
writer's 2,508 s in its child, zero waits), put 3,454 (insert 466, the
spent output's delete 1,637, the undo capture 942). The tail from the
download's end to ready was 23 s. The download: 71 distinct peers, a
per-chunk wait sum of 5,696 s, 62.6 MB/s average with the pool 7% idle;
9 of 136 peers banned (run 41: 34 — B13 bans on the second stall; 30
stall evictions, 2 dead-weight). Memory: heap 8.2 GB mean, 13.3 GB
peak; PSS 34.1 GB mean, 56.3 GB peak (§5).

Download, run 38: 60,639 chunks, 774 GB, 25 distinct peers; per-chunk wait
p50 0.06 s, p90 0.08 s; 2 stall evictions over the run, both answered by
their worker and the chunk reassigned at the first signal (0 unanswered;
run 37 had 7); no apply gap over 45 s during the download. The applier
waited for blocks 2,193 s in all against Core's 24,587 s (§2): with ranked
peers the download is no longer the bound. Run 38 took 33 minutes off run
37 with the download rules unchanged: the index worker (§2) took the
index writes off the applier, and the applier's own UTXO columns fell with
them (less contention in the applying process: get 4,650 → 4,096 s, put
5,687 → 4,994 s).

The header phase, from run 38's log: of the 99 s between boot and block 1,
48.8 s were the peer ranking (141 live peers probed 32 to a batch, each
batch waiting out its silent members' 10 s alarm), 8 s the liveness
round's full timeout, 37 s the header download from the best peer at 2.0
MB/s (the held pages are stored once the chain crosses minimumchainwork;
Core's own 75 s is its presync plus a redownload). PR #392 runs the
probes concurrently and ends the liveness round after two quiet seconds;
a fresh sync of that build (12:03Z, the early-chain A/B's control arm)
reached block 1 in 50.5 s: liveness 2.3 s, ranking 7.0 s, headers 36 s.
Run 39 carries it through the whole chain.

## 2. Where the applier's time goes (thread-seconds over the whole chain)

| | Core #6 | Core #7 | bmc 34 | bmc 37 | bmc 38 | bmc 39 | bmc 40 | bmc 41 | bmc 46 |
|---|---|---|---|---|---|---|---|---|---|
| applier busy (Core: connect block; bmc: the block line's total) | 13,909 | 13,340 | 17,166 | 14,602 | **13,363** | 14,060 | 14,650 | **11,842** | **9,691** |
| applier waiting for blocks / outside connect | 24,587 | 22,060 | 9,757 | 2,180 | 2,193 | 2,460 | 2,311 | 2,220 | 2,412 |
| UTXO (Core: connect txs + flush + write chainstate + coins flushes; bmc: get + put + ckpt + flush) | ~11,185 | ~10,791 | 13,863 | 11,956 | 10,804 | 11,556 | 11,985 | 9,305 | 7,258 |
| ↳ put | — | — | 7,812 | 5,687 | 4,994 | 5,661 | 7,135 | **3,842** | **3,454** |
| ↳ put split (ins / get / undo / del / wal; the first version of this row shifted the labels — it printed ins / undo / del / wal / other — corrected 10-07 with run 41) | — | — | — | 1,662 / 66 / 928 / 2,622 / 59 | 1,377 / 56 / 933 / 2,242 / 57 | 1,845 / 54 / 921 / 2,463 / 55 | 2,621 / 58 / 979 / 3,079 / 59 | 664 / 57 / 921 / 1,822 / 63 | 466 / 28 / 942 / 1,637 / 64 |
| ↳ memtable / cache flush (inline on the applier) | 803 | 868 (16 flushes) | 1,350 | 1,403 (110 flushes) | 1,360 (109 flushes) | 1,357 (110 flushes) | 131 (112 freezes, 97 s; the writer's 1,545 s in a forked child) | 125 (110 freezes, 99 s; the writer's 1,859 s in a forked child) | 87 (217 freezes, 30 s; the writer's 2,508 s in a forked child) |
| script verification | 113 (wait on 15 threads) | 116 | 773 | 775 | 744 | 739 | 761 | 764 | 759 |
| block read | 2,289 | 2,213 | 124 | 211 | 195 | 165 | 242 | 164 | 183 |
| per-block index work on the applier (idx + csi + txindex + bfilter) | 5 | 5 | 2,360 | 2,306 | 1,576 (idx 1,149 + csi 427; txindex + bfilter 0.2) | 1,558 (idx 1,129 + csi 429; 0.4) | 1,612 (idx 1,154 + csi 458; 0.4) | 1,564 (idx 1,143 + csi 421; 0.4) | 1,447 (idx 1,033 + csi 414; 0.2) |
| index writes off the applier (Core: callback threads; bmc: the index worker) | not logged | not logged | — | — | 688 (txindex 336 + bfilter 352; 969,746 blocks) | 674 (txindex 334 + bfilter 340; 969,487 blocks) | 688 (txindex 337 + bfilter 351; 969,572 blocks) | 691 (txindex 339 + bfilter 352; 969,835 blocks) | 694 (txindex 342 + bfilter 353; 970,431 blocks) |

bmc's applier was 4% faster per block than Core #6's in run 38, 1%
slower in run 39 and 5% slower in run 40 (run 37: 5% slower; run 34:
23% slower); against Core #7's 13,340 s the same three runs read parity
(run 38, +0.2%), 5% behind and 10% behind. Run 41, with the memtable in
anonymous memory (B11), is 11% ahead of Core #7 and 15% ahead of #6:
11,842 s, the put column 3,842 s against run 40's 7,135 and run 38's
4,994. The spread between runs 38–40 was in the memtable insert and the
spent output's delete (the two columns that write the table and blob
pages; the undo capture, 921–979 s, never moved), and run 41 took 1,957
s off the insert and 1,257 s off the delete by changing nothing in the
code that runs them — the pages they wrote were file-backed, and the
kernel's write-back and reclaim were the cost. Run 46 is 27% ahead of
Core #7 and 30% ahead of #6 at 9,691 s: the lookups (`get`) fell 4,607
→ 2,870 s once each flush run's Bloom filter was sized to its records
(the 4 MiB cap had let 55% of absent keys through to a sparse search),
the freezes 99 → 30 s with the frozen copy's pages kept resident, and
the WAL checkpoint (`ckpt`) 731 → 847 s and the index step 1,564 →
1,447 s stayed within the noise of a halved memtable (M2: twice the
freezes, 217).
Run 40 took the flush column off the applier as plan B3 intended (1,357
→ 131 s) and the put column absorbed the gain and more (5,661 → 7,135
s); the applier's lookups, verification and index steps were within 4%
of run 39's. Run 41 then took the put column down to 3,842 s (B11) and
the applier to 11,842 s; its `ckpt` column rose 432 → 731 s and `get`
4,287 → 4,607 s (the WAL checkpoint and the lookups now compete with the
writer child's 1,859 s on the same cores), the only two columns that
grew. Run 37's UTXO put fell 27% from run 34 (the undo
capture reuses the resolved prevout, PR #383); run 38's index worker (PR
#390) took the txindex and filter writes off the applier -- 693 s of
inline work in run 37 became 688 s in a forked process that trails the
applier by ~20 blocks -- and the applier's remaining columns fell with
them (put 5,687 → 4,994 s, get 4,650 → 4,096 s: the applying process no
longer shares its page cache and CPU with four index writers). The put
split names what is left: the spent output's delete (2,242 s) and the
insert (1,377 s) are the two halves of put — the undo record itself is
933 s — and the WAL and the sampled get are negligible. Two columns remain off Core's shape: the inline flush (1,360
s; Core's cache flush is 803 s and its writes are batched) and the
per-block `idx` and `csi` steps (1,576 s; Phase 0.5 and the coinstats
fold, inside the block line). The flush was plan item B3
(`worklog/2026-10-05-performance-holes-plan.md`), and run 40 has it off
the applier; the put column is the one left, and its three readings for
the same code (4,994 / 5,661 / 7,135 s) say its cost is set by the box as
much as by the code: the memtable's table and blob are file-backed shared
mappings (plan B11, the next lever).

bmc wins the sync mostly by overlapping download and apply: the "waiting"
row is 22,100–22,400 of the ~22,000–23,000 thread-seconds between the
runs. The apply path itself bracketed parity through run 40 (546 s ahead in
run 38, 151 s behind in run 39, 741 s behind in run 40), is 1,498 s
ahead of Core #7 in run 41 and 3,649 s ahead in run 46.

(The stage report's total row subtracted the put sub-timers a second time
and printed "other = −5,289 s" on the first render of run 37; fixed in
`validation/ibd_stage_report.py` with a self-test check, same day.)

## 3. RPC, 32 simultaneous clients × 5 calls, median ms (validation/rpc_concurrency_bench.sh)

Measured 2026-10-05 before the lane work (bmc pool 71,348 tx, Core pool
29,961 tx); 2026-10-06 05:20Z after it (bmc pool 64,793 tx, Core pool
24,074 tx); and 2026-10-06 06:10Z after the two fixes that row found
(PRs #387 and #388, production `deploy-20261006b`). Core is re-measured in
the same minute as each bmc column. Fixed-work rows use block 969,000
(`00000000000000000000fb6c31229d2253cd7161c9cb72cf03d2e3d847e9a22a`) and
its second transaction (`75fbbbf4…1d70`, in the txindex's unsorted tail);
the 06:10Z mempool rows are not comparable (production's pool was
refilling after the restart: 2,252 tx against Core's 21,133) and keep the
05:20Z column. Both nodes live on the same box, both at the tip, loopback.

| method | Core (10-05) | bmc before | Core (10-06 05:20Z) | bmc after the lanes | Core (06:10Z) | bmc after #387/#388 | Core (12:02Z) | bmc final (#392, the JSON arena) |
|---|---|---|---|---|---|---|---|---|
| getblockcount | 5 | 5 | 5 | 4 | 5 | 5 | — | — |
| getblockhash | 5 | 5 | 5 | 4 | 5 | 4 | — | — |
| getmempoolinfo | 5 | 177 | 5 | 5 | — | (05:20Z) 5 | — | — |
| getrawmempool | 687 | 249 | 496 | 216 (pool 2.7× Core's) | — | (05:20Z) 216 | 484 (pool 25,508) | **114** (pool 26,757) |
| getblock (verbosity 2) | 494 | 704 | 498 | 597 (wave 4,107 ms vs Core's 4,829) | 451 | 607 (wave 3,932 vs 4,589) | 449 / 459 (two waves; p90 641 / 586; wave 4,473 / 4,436) | **441 / 483** (p90 487 / 521; wave 3,187 / 3,224) |
| getblock (verbosity 2), single client | 88 | 75 | — | — | — | 73 | 87 | **58** |
| getblock (verbosity 1), 32 clients | — | — | — | — | — | — | 19 | **9** |
| getblock (verbosity 3), single client | 140 | 102 | — | — | — | — | 126 | **84** |
| getrawtransaction (verbosity 1), tail tx | 6 | 6 | 5 | **382** | 5 | **5** (single client 3 vs 3) | 5 | 5 |
| getrawtransaction (verbosity 1), tx in a sorted run (block 950,000) | — | — | 5 | 5 | 5 | 6 | — | — |
| getdeploymentinfo | — | — | 5 | (2,000 single; exclusive hold) | 5 | 5 (single 4 vs 4) | 5 | 5 |
| getpeerinfo | 7 | 5 | 6 | 5 | 6 | 5 | — | — |
| exec-lock waits ≥ 2 s per day under BlockYard + mempool.space | n/a | ~10 | n/a | 0 since 17:46Z 10-05 | n/a | 0 | n/a | 0 |

What the 05:20Z column found, and what fixed it the same morning:

- **getrawtransaction** was a loss the 10-05 "6 vs 6" row had hidden (its
  transaction was never recorded). Pinned: 14 ms single-client against
  Core's 4, and 382 ms at 32 clients against 5. Three causes, in
  `rpc_chain.c`: the txindex lane's verify read the WHOLE block into a
  static 4 MB buffer to compare one txid (and that buffer was why the lane
  admitted one reader at a time); the handler then read the block again
  and walked every transaction before the one asked for; and for a
  transaction in the index's unsorted tail -- every block since the last
  fold, up to 20,000 of them, 564 MB on production -- the lookup scanned
  the tail from the start. PR #387: the verify and verbosity 0/1 read the
  transaction at the record's byte range (as Core reads it at its file
  position), the txid recomputed and compared. PR #388: the tail gets an
  in-memory hash table of record numbers (4 bytes a slot, ≤ 256 MB at the
  fold's worst point), built as the tail grows. Result: 3 ms single, 5 ms
  at 32 clients, tail or run -- Core's numbers.
- **getdeploymentinfo** was the one remaining exclusive-lock holder over
  2 s on production (seven a day, 2.0–2.1 s each, 1–2 callers queued): the
  BIP9 walk re-read ~10k headers from genesis on every call. PR #387 caches
  the decided state at every period boundary with the boundary block's
  hash (Core's VersionBitsCache); a lookup verifies the highest cached
  boundary is still in the chain with one index read. First call after a
  restart 1.6 s (the walk, once), then 4 ms.
- **getblock verbosity 2** at 32 clients was mixed through the 06:10Z
  column: bmc's wave finished 14–15% sooner but the median call was 20–35%
  slower. Measured before building anything (plan A5): both nodes answer
  from a 4-thread pool (`rpcthreads` default on both), bmc's listener took
  no overflow during a wave, and bmc's latencies were the FIFO model's
  (p90 = median + 10% = 32/4 × the single call) -- the lane was not
  narrower than Core's pool; the per-call cost was the lever. perf on a
  micro-benchmark of the render (3,573 transactions, 6.8 MB of JSON): a
  third of the time in malloc/free of the ~400,000 JSON values, 11% in the
  byte-at-a-time string escaper, 4% in hex encoding. PR #392 (production
  `deploy-20261006c`, 11:59Z, every saved response byte-identical to the
  previous build): one JSON arena per request, released whole after the
  body is written; a span-copying escaper; hex encoded straight into the
  value; a per-thread txid scratch. Micro-benchmark 37 → 26 ms; the
  single call 73 → 58 ms (Core 87). At 32 clients the 12:02Z pair: median
  441 / 483 against Core's 449 / 459 over two waves each (parity -- the
  FIFO median is 8 × the service time on both), p90 487 / 521 against 641
  / 586, wave 3,187 / 3,224 ms against 4,473 / 4,436 (28% sooner). Every
  other getblock row is bmc's: v1 at 32 clients 9 vs 19, v3 single 84 vs
  126.
- **getrawmempool** at 32 clients, re-measured 12:02Z on pools of the same
  size for the first time (26,757 vs 25,508 transactions): 114 vs 484 ms.

## 4. Modules (from docs/reports/2026-09-28-the-module-benchmarks-gaps-closed.md)

Archive read 2.8–3×, MuHash insert 6×, SHA-256 / ChaCha20 / BIP324 AEAD at or
ahead of Core; signature verification at parity with libsecp256k1.

## 5. Disk and memory

| | Core | bmc (run 37 datadir, 2026-10-06 05:15Z) |
|---|---|---|
| blocks | 721 GB | 721 GB |
| UTXO set on disk | 11 GB (chainstate) | 13 GB (the compacted run; a superseded 13 GB run not yet reclaimed when measured) |
| txindex | 70 GB | 28 GB (2.5× smaller) |
| block filters | 13 GB | 13 GB |
| undo | 101 GB (rev files) | 2.5× larger (carries spent scripts; feeds the address history) — 2026-10-05 measurement |
| coinstats history | — | 0.9 GB |

Since `deploy-20261006b` the serve process also holds the txindex tail's
hash table: 4 bytes a slot at ≤ 3/4 load, 128–256 MB over the fold cycle
(not in run 37's figures).

**Correction (10-06 15:30Z, read on run 39's /proc):** the anonymous
figures in this paragraph are inflated by the sampler's arithmetic, not
by the node. It summed smaps_rollup's `Anonymous` over the tree, and that
field counts the download worker's inherited copy-on-write pages once in
every forked child: run 39's 13 children each reported 1,479 MB of which
1,476 MB were the worker's own pages (`Shared_Dirty`). By proportional
share (`Pss_Anon`) the tree's anonymous memory two hours into run 39 was
~10 GB (the worker 8.3 GB: flush scratch, tombstone list and hash, the
inherited block hash index; the parent 0.16 GB; 0.11 GB per child), the
"compaction peak" one more copy of that set in the compaction child, and
the post-ready 44.9/53.6 GB the same fork arithmetic on the downshift's
compaction. Core is one process and never had the inflation. The sampler
sums `Pss_Anon` from run 40 on, and the node prints a `[mem]` line by
mapping at both marks (plan M1); run 40 and Core rerun #7 give this row
two honest sides. The PSS figures were always right.

Memory, bmc run 38, proc sampler every 5 s over every process of the
daemon's tree: anonymous (heap) memory held 27.9 GB steadily through the
sync (mean 27.5 GB; run 37: 26.4 GB), PSS peaked at 66.9 GB (09:30Z; run
37: 67.7 GB) — PSS counts the archive's mapped pages, which the kernel
drops under pressure, so it is a ceiling, not a footprint; it rises and
falls with each memtable generation (18 → 60 GB over ~70 minutes, back to
18 GB at the flush). The index worker added no measurable anonymous
memory (it maps the same files). Between IBD end and two minutes after
`[ready]` anonymous memory rose to 44.9 GB and briefly 53.6 GB (procs 7–8:
the serve process taking the tail's blocks, then the caught-up downshift's
compaction and fold workers), then settled at 10.6 GB at the tip. Run 37
showed the same 53.6 GB at the same point; this report's first version
attributed it to the harness's capstone, which in fact ran three minutes
later (the harness polls the log every few minutes). Core's rerun had no
sampler; the memory row has one side and is not a comparison. The plan's
next Core rerun carries the sampler.

Run 39, the same sampler: PSS peaked at 63.5 GB (16:09Z, 16 processes: a
compaction child beside the applier's generation), RSS at 92.4 GB; at IBD
end and at ready the tree was 3 processes at 48.5 GB PSS (the serve
process holding the tail's blocks and the fold worker). Its anonymous
column is the old arithmetic and is not quoted; the one honest anonymous
figure is the 10.6 GB read from `/proc` at 15:30Z (above). The first
sample of the run, 59 processes at boot, is PR #392's concurrent peer
probes: 135 forked probes each reporting the parent's pages, 78 GB by
the old column, 3.3 GB PSS.

Run 40, the sampler summing `Pss_Anon` and the node's own `[mem]` lines:
at IBD end the tree (3 processes) held 40.7 GB PSS, of which 2.7 GB
anonymous, 37.9 GB file-backed (the mapped UTXO runs: the compacted run
12.8 GB, seven generation runs of 1.6–1.7 GB each, the memtable blob 1.6
GB) and 70 MB shared; at ready 42.1 GB (3.7 GB anonymous). Over the sync
the anonymous memory of the tree was 9.6–11.4 GB, with a peak of 22.1 GB
at 21:47Z during a compaction (the child's own copy of the set), and PSS
peaked at 67.9 GB at the same minute (17 processes). The sampler's RSS
peak of 245 GB at 01:15:55Z is 27 processes — the top-up round's forked
peer probes — each counting the worker's pages, and is not a footprint.
The box: 8 GB of swap fully used through the run by other services (a
vLLM server holding 30 GB of GPU memory with 4.5 GB of its host memory
swapped, the mempool.space backend, BlockYard), 85 GB of page cache, and
the production bmc node beside the benchmark.

Run 41 (the memtable in anonymous memory, B11): the 2^25-slot table
and the 6 GB blob moved from the file column to the anonymous column,
and the sampler shows exactly that — anonymous mean 15.3 GB (run 40:
10.0), peak 32.2 GB at 15:23Z during a compaction (run 40: 22.1), PSS
mean 39.9 GB (38.5), PSS peak 75.6 GB in the same minute (67.9). At IBD
end the tree held 38.5 GB PSS, 3.8 GB anonymous (the steady-state
memtable: `utxo-memtable-table` 383 MB and `utxo-memtable-blob` 505 MB
named in the `[mem]` line); at ready 36.9 GB, 2.1 GB anonymous. The
memory is the same memory counted in a different column: what was a
dirty file page the kernel wrote back is now a heap page it never
touches, and the applier's put column paid for the difference (§2).

Run 46 (M2, #407, and after): `dbcache` is the whole UTXO heap — the
live memtable, its frozen copy and the flush scratch inside the 8 GB —
and the forked children no longer carry a copy of the memtable (the
compaction and index children map the files; the writer takes the
frozen copy only). The sampler over the sync: heap 8.2 GB mean, 13.3 GB
peak (at IBD end, the serve process taking the tail beside the worker;
run 41: 15.3 / 32.2), PSS 34.1 GB mean, 56.3 GB peak (run 41: 39.9 /
75.6). The node's `[mem]` line at IBD end: 26.7 GB PSS, of which 4.2 GB
anonymous and 22.5 GB the mapped run files (the compacted run 12.9 GB
and twelve 0.8 GB generation runs — the halved memtable makes smaller,
more numerous runs); at ready 24.7 GB, 2.1 GB anonymous.

Core rerun #7, the same sampler every 5 s (one process; `dbcache=8192`,
so the UTXO set lives in its heap and is flushed 16 times):

| | Core #7 | bmc run 40 | bmc run 41 | bmc run 46 (release) |
|---|---|---|---|---|
| anonymous (heap) memory, mean over the sync | 10.0 GB | 10.0 GB (9.6–11.4 GB) | 15.3 GB (the memtable's table and blob are heap now) | **8.2 GB** |
| anonymous, peak | 12.0 GB (09:20Z) | 22.1 GB (21:47Z, a compaction child's own copy of the set; 2 samples) | 32.2 GB (15:23Z, a compaction) | 13.3 GB (02:33Z, IBD end: the serve process beside the worker) |
| PSS including mapped files, mean | 17.6 GB | 38.5 GB | 39.9 GB | 34.1 GB |
| PSS, peak | 34.3 GB (09:58Z; 20 s above 30 GB) | 67.9 GB (21:47Z; 215 s above 60 GB) | 75.6 GB (15:23Z) | 56.3 GB (00:41Z) |
| at IBD end | 25.4 GB PSS, 11.3 GB anonymous | 40.7 GB PSS, 2.7 GB anonymous | 38.5 GB PSS, 3.8 GB anonymous | 26.7 GB PSS, 4.2 GB anonymous |
| cgroup peak (systemd MemoryPeak, page cache included) | 76.2 GB | not a unit; the `[mem]` lines are the node's own figure | not a unit | not a unit |

The heap is the same on both sides, 10 GB on average: Core's dbcache
and bmc's flush scratch, tombstone list and block hash index. The two
ceilings differ in kind. bmc's working set is the UTXO run files it
maps (12.8 GB compacted plus one 1.6 GB run per generation, 37.9 GB of
file-backed pages at IBD end), which count in its PSS while the kernel
keeps them cached and are the kernel's to drop; Core's chainstate is
read through LevelDB's own cache and the rest of its page cache is not
in its PSS. On the page-cache-inclusive measure (the cgroup peak) Core
#7 reached 76 GB. The honest row, on run 40: heap, parity; peak heap, Core by 10 GB for
ten seconds of compaction; PSS ceiling, Core by 2×, with bmc's half of
it reclaimable. On run 41, the release build, the heap row moves to
Core's side by 5 GB on the mean (15.3 against 10.0) and 20 GB on the
peak, because the memtable is heap now; the PSS ceiling is Core's by
2.2×. Memory was the one category run 41 did not take, and the trade was
deliberate: the same pages in the heap column cost the applier 3,300 s
less than they did as file pages. Run 46 takes the heap row back: with
`dbcache` the whole UTXO heap (M2) the mean is 8.2 GB against Core's
10.0 and the peak 13.3 against 12.0 — parity within 1.3 GB, for the
seconds at IBD end when the serve process starts beside the worker.
The PSS ceiling stays Core's, 56.3 against 34.3 GB at the peak and
34.1 against 17.6 on the mean, and it is the mapped UTXO run files:
22.5 GB of file-backed pages at IBD end that count in bmc's PSS while
the kernel keeps them cached and are the kernel's to drop (Core's
equivalent, its chainstate's page cache, is outside its PSS; its cgroup
peak with page cache was 76 GB). The honest row for the release: heap,
bmc's on the mean and parity on the peak; PSS ceiling, Core's by 1.6×,
all of the excess reclaimable file pages. Why that row does not move
with a knob: the peak (56.3 GB at 00:41Z) is the minute before a full
compaction, when the worker maps 46 generation runs plus the compacted
run (~49 GB of files, nearly all of it touched by the random lookups
and so counted) and the compaction child, which reads with `read()`
and writes with `write()`, has none of it in its own PSS; compacting
sooner (`bmc.utxocompactthreshold`, ×4 in bulk mode; the run budget of
35% of RAM) lowers the peak toward the floor set by the compacted run
itself, 12.9 GB fully resident because every page of it is a lookup
target, plus the heap — about 30 GB at best, and at the price of
rewriting the base run every few minutes. The lever that would take
the row is a `pread` path for the base run's lookups, as LevelDB reads,
which moves those pages out of PSS and into the same page cache Core's
chainstate lives in; it is slower than the mapped fast path and is not
in this release.

## 6. Verdict, category by category

| category | result | bmc / Core |
|---|---|---|
| sync, genesis to every index at the tip | **bmc, 3.0× vs Core #7, 3.2× vs #6** (run 46, the release build) | 3:17:55 (run 46) vs 9:50:04 (#7) and 10:42:05 (#6); the release line's syncs 4:17:09 / 4:34:48 / 4:42:41 / 3:48:22 (runs 38–41) |
| every milestone from 400,000 up | **bmc, 1.8–2.1×** vs #7 (2.2–2.9× vs #6) | §1, all three runs; 300,000 is parity against #7 |
| CPU time for the sync | **bmc, 1.6×** less (1.6–1.8× vs #6) | 8 h 24 m vs 13 h 15 m (#7); 7 h 48 m / 7 h 56 m / 8 h 24 m vs 13 h 50 m (#6) |
| download: applier time spent waiting | **bmc, 9.5×** less (10–11× vs #6) | 2,311 s vs 22,060 s (#7); 2,193 / 2,460 / 2,311 vs 24,587 (#6) |
| headers → first block | **bmc, 1.3× vs #7, 2.2× vs #6** (run 46; parity in runs 40–41) | run 46: 0:34 (liveness 1.4 s, ranking 7.4 s, the headers in 19 parallel ranges from four peers in 15.8 s — B12, #410) vs #7's 0:45 and #6's 1:15; runs 40–41 0:47 / 0:48 with a single 33–38 s stream; run 38 was 1:39 (ranking 48.8 s) |
| the first 200,000 blocks | **bmc, 1.5× / 1.8× vs #7** (run 46; run 41 1.3× / 1.6×; was Core #7's by 2.0× / 1.7× in run 40) | run 46: 100,000 at 1:22, 200,000 at 2:35; run 41: 1:35 / 2:55 vs #7's 2:06 / 4:44 (#6: 4:12 / 8:15; run 40: 4:16 / 8:12). bmc's download loop slept a 2 s idle tick at every 1,024-block window edge (99 bursts 2.09 s apart below 100,000 in run 40); the fix (B9 part 2, PR #400) ends the wait when the committer's tip moves. The earlier rolling per-block shape (`bmc.dlcrollbelow`) was not the lever and stays off |
| apply path per block (thread-seconds) | **bmc, by 27% vs #7, 30% vs #6** (run 46; run 41 11%; Core's by 10% in run 40, parity in run 38) | 9,691 (run 46) and 11,842 (run 41) vs 13,340 (#7) and 13,909 (#6); runs 38–40: 13,363 / 14,060 / 14,650. The memtable in anonymous memory (B11) took the put column from 7,135 to 3,842 s; the sized Bloom filters (#417) took the lookups from 4,607 to 2,870 s (§2) |
| pause after the download's end | **bmc** (was Core) | 0.55 s in run 40 vs 65 s in run 39 (PR #395; Core has no such pause, its drain is the same loop); the whole tail from the download's end to ready 34 s in run 41 and 23 s in run 46 against run 40's 99 (B10: no re-ranking for the top-up) |
| index writes, on the applier | parity (both off it) | 0.2–0.4 s vs 5 s; the worker's 688 s runs beside the applier as Core's callback threads do |
| RPC: getblockcount, getblockhash, getmempoolinfo, getpeerinfo | parity | 4–5 ms both |
| RPC: getrawmempool, 32 clients | **bmc, 4.2×** on pools of the same size (12:02Z) | 114 vs 484 ms (26.8k vs 25.5k tx) |
| RPC: getblock v2, 32 clients | parity on the median, **bmc** on p90 and the wave (was: median 20% slower) | 441/483 vs 449/459; p90 487/521 vs 641/586; wave 28% sooner; §3 |
| RPC: getblock, single client, every verbosity | **bmc, 1.5×** | v2 58 vs 87, v3 84 vs 126 ms; v1 at 32 clients 9 vs 19 |
| RPC: getrawtransaction (tail or run) | parity | 5 vs 5 ms at 32 clients; 3 vs 3 single (was 382 vs 5 at 05:20Z) |
| RPC: getdeploymentinfo | parity | 5 vs 5 ms; the 2 s exclusive holds are gone |
| RPC lock-ups under BlockYard + mempool.space | **bmc** (was ~10/day) | 0 waits ≥ 2 s since the deploy |
| modules (archive read, MuHash, hashes, AEAD, sigs) | **bmc or parity** | §4 |
| txindex on disk | **bmc, 2.5× smaller** | 28 vs 70 GB |
| UTXO set on disk | Core (a trade: 2 GB) | 13 vs 11 GB |
| undo on disk | Core (by design: spent scripts) | 2.5× |
| memory: heap (anonymous), mean | **bmc, by 1.8 GB** (run 46; Core's by 5 GB in run 41, parity in run 40) | 10.0 vs 8.2 GB (§5): `dbcache` is the whole UTXO heap since M2 (#407); run 41's 15.3 GB had the memtable's table and blob outside the budget |
| memory: heap, peak | parity within 1.3 GB (run 46; Core's by 20 GB in run 41) | 12.0 vs 13.3 GB (run 46, at IBD end when the serve process starts beside the worker; run 41: 32.2, a compaction child's copy of the set — M2 removed the fork copies) |
| memory: PSS ceiling (mapped files included) | Core, 1.6× (run 46; 2.2× in run 41) | 34.3 vs 56.3 GB peak (run 46; run 41: 75.6), 17.6 vs 34.1 GB mean; bmc's excess is the mapped UTXO runs (22.5 GB at IBD end), page cache the kernel may drop; the cgroup peak with page cache is 76 GB on Core's side |
| correctness | identical | muhash at 970,133 / 970,165 / 970,209 / 970,267 / 970,364 / 970,710 |

Not beaten in run 38, beaten or tied in run 39 with the fix named: the
first 200,000 blocks and the header phase. Run 38's log puts 49 of the 99
s before block 1 in the peer ranking (probes 32 to a batch, each batch
waiting out its silent members' 10 s alarm) and 8 s in the liveness
round's full timeout; PR #392 makes both end on their own clocks, and run
39 (the full sync of that build) reached block 1 in 49.6 s against Core's
75 and the first 200,000 blocks at Core's pace (100,000 at 4:15, 200,000
at 8:14 against 4:12 and 8:15), as the two fresh syncs of 12:02Z and
12:52Z had.
The early-chain request shape (plan B9 part 2, `bmc.dlcrollbelow`, a
rolling per-block pipeline below a height) was A/B'd against the chunked
default on four fresh syncs to 300,000 and lost: 1066 s and 941 s against
the controls' 941 s and 900 s. It stays off. getblock v2's median
at 32 clients moved from a 20% loss to parity with PR #392 (the JSON
arena; p90 and the wave are bmc's). The apply path per block moved from
Core's column to bmc's with run 38 (the index worker, PR #390) and back
by 1% and 5% in runs 39 and 40; run 40 took the flush off the applier
(B3: 1,357 → 131 s, zero waits) and its applier still came in 741 s
behind Core's because the memtable insert and the spent output's delete rose
again for the same code (§2). Three readings of the same put path spread
2,141 s; the next lever is the memtable's backing (file-backed shared
mappings; plan B11), and the claim for this row stays "parity, within
±5%" until a run moves it. The memory row needs the Core rerun with the
sampler before it can be claimed either way; bmc's side is in §5.

Against Core rerun #7 (10-07), the better of the two Core runs and the
one with a memory side, the table reads differently in three rows and
the text above is kept for the record. The early chain is a loss, not
parity: 2.0× at 100,000 and 1.7× at 200,000, and the cause is a 2 s
idle tick the download loop paid at every 1,024-block window edge
(§1); the fix is built, pinned and in its A/B as this is written (§7).
The apply path is Core's by 10% in run 40 (parity in run 38): the flush
is off the applier and the memtable insert and the spent output's delete rose for
the same code; the memtable's file-backed mappings are the next lever
(plan B11). The memory row has two sides now: the heap is the same 10
GB; the peak heap is Core's by 10 GB for a ten-second compaction; the
PSS ceiling is Core's by 2× because bmc's working set is mapped run
files the kernel keeps cached. Everything else holds against #7: the
sync 2.1×, CPU 1.6× less, waiting 9.5× less, every milestone from
400,000 1.8–2.1×, the header phase at parity, the RPC rows unchanged.

Run 41 (10-07, main `7027c734`, PR #400), the release build, settles
the two rows that were Core's. The early chain: 100,000 at 1:35 and
200,000 at 2:55 against Core #7's 2:06 and 4:44 — the idle tick is
gone (B9 part 2) and bmc leads from the first block. The apply path:
11,842 s against Core's 13,340, 11% ahead (B11: the memtable in
anonymous memory; the put column halved). The sync is 2.6× (3:48:22
against 9:50:04), the CPU 1.7× less (27,567 against 47,700 s), the
waiting 9.9× less, every milestone from 100,000 at 0.38–0.76 of Core's
clock. The memory rows are Core's, and more so than in run 40: the
memtable is heap now (mean 15.3 against 10.0 GB; peak 32.2 against
12.0), the PSS ceiling 2.2×; §5 names the trade and the knob. Every
other row is bmc's or parity.

Run 46 (10-10, main `a79bcdca`), the release build, moves the table a
last time. The sync is 3.0× (3:17:55 against 9:50:04), the CPU 1.8×
less (25,968 against 47,700 s), the header phase 1.3× (34 s against
45: the headers in parallel ranges, B12), the first 200,000 blocks
1.5× / 1.8×, the apply path 27% ahead (9,691 against 13,340: the
sized Bloom filters and the resident frozen copy), and the heap row is
bmc's on the mean (8.2 against 10.0 GB) and parity on the peak (13.3
against 12.0) since `dbcache` became the whole UTXO heap (M2). What
Core keeps is the PSS ceiling with mapped files counted, 1.6×, all of
it the UTXO run files the kernel caches and may drop, and the two disk
rows it kept before. The release is run 46's build; production has run
`deploy-20261010a` since 10-10 04:28Z (the binary's size and strings
are the tree's build of `a79bcdca`; NRestarts=0 at the time of writing).

## 7. What changed between run 34 and run 38

Runs 35 and 36 were started on the way and stopped: run 35 (main
`0319e1eb`) at 72% when a download worker never answered its eviction and
the window sat 7 minutes; run 36 (main `12ed7aa1`, the first fix) at 70.5%
by the operator, for a clean run once the fix's own log lines were found
misreporting. Neither is in the tables.

- **UTXO put** (`47c6e12c`, PR #383): the undo capture reused Phase 1's
  resolved prevout instead of looking it up again (1.29 of the 2.30 µs per
  spent input with runs on disk). Bench, one pinned core, 2^25 slots, 20M
  coins: 2.30 → 1.13 µs per spent input. Every 64th input is still
  re-resolved and compared (the 2026-09-01 inconsistency guard). Run 37:
  put 7,812 → 5,687 s.
- **RPC** (`3b807cc6`, PR #383): the Esplora facade had taken the exclusive
  execution lock for every dispatch, lane methods included — the production
  convoy (2.1–2.7 s waits behind 0–16 ms holders). It now takes what the
  method's class needs. A txindex lane (private store handle and block
  buffer, one mutex `irs_refresh` also takes) serves
  `rpc_chain_tx_blockhash` and `getrawtransaction` v0/v1; the facade's
  mempool batch enters it once per batch; `getblock` runs in a per-RPC-thread
  reader lane; `getmempoolinfo`'s totals are memoised on the mempool
  sequence. Production: 0 waits ≥ 2 s since the deploy. *(2026-10-07: the
  reader lane was never released when its thread exited, and the facade runs
  a thread per connection. Each facade block read leaked three descriptors
  until production's RPC stopped accepting at 1,023/1,024 for 2 h 17 m. Fixed
  by #402: `devlog/INCIDENT_2026-10-07_reader_lane_fd_leak.md`.)*
- **Header sync** (`c5aecada`, PR #383): the first 2,000-header page is asked
  of four peers at once and the fastest leads (run 37: 1,155 KB/s chosen in
  0.4 s), with the others as fallbacks. Headers → first block 5:06 → 1:58.
- **Eviction** (PR #384, `ea7a41f5`): an eviction the holder never answers.
  Run 35's holder was "dropped" twelve times and never released its chunk;
  run 34 had the same shape four times at ~20 minutes each (78 minutes of
  what the pair report had called "download-bound under random peers").
  The eviction signal now shuts the worker's socket so a handshake or read
  ends; the full-window wait loop takes the committer's cursor help; the
  eviction line names the holder's phase and kernel state; the BIP324
  handshake's second loop got a real-time deadline.
- **Eviction accounting and reassignment** (PR #385, `ca9796a4`): run 36's
  log showed the fix's lines misreporting (an answered eviction called
  unanswered; a stale flag printing "acknowledged late" after every drop)
  and the window still sitting 15–30 s on each eviction while the evicted
  worker redialed. The worker now counts the evictions it acts on and the
  parent reads it; the first eviction puts the chunk on the retry ring
  (Core's semantics: a disconnected staller's blocks are re-requested at
  once) and the evicted worker releases a chunk its redial finds delivered.
  Run 37: 7 evictions, 7 reassigned, 0 unanswered, 3 released on redial.
- **After run 37, from its RPC rows** (PRs #387 and #388, production
  `deploy-20261006a`/`b`, both verified on the next block with zero
  restarts): getrawtransaction by the record's byte range and the tail's
  hash index; the BIP9 walk cached per period boundary. §3 carries the
  before/after.
- **Index writes off the applier** (PR #390, `edb09c4c`, run 38): during
  the download the applier pushes each connected height onto a 1,024-slot
  ring in the shared status block and a forked index worker reads the
  block from the archive and runs the txid tail, the txospender tail, the
  filter index and the address journal, publishing the watermarks the
  `[ready]` line gates on; the trailing builders' folds go through the
  same ring so the process holding a tail's fd is the one that rotates it.
  At the download's end a STOP record drains the ring and the parent
  re-boots its writer state from the files; the tip's blocks are indexed
  inline as before. Run 38: 969,746 blocks indexed in the worker, which
  trailed the applier by ~20 blocks the whole run and stopped within 1 s
  of the download's end; the stage report counts its lines in their own
  column (`ixw`). Ready 4:50:52 → 4:17:09; applier 14,602 → 13,363 s.
- **The JSON arena and the peer probes** (PR #392, `6e8cc448`, production
  `deploy-20261006c` at 11:59Z, verified byte-identical on thirteen saved
  responses): every JSON value a request builds lives in one per-thread
  arena released after the body is written (a third of a getblock v2
  render had been malloc/free), the string escaper copies spans, hex is
  encoded straight into the value; getblock v2 single 73 → 58 ms, the
  32-client median to parity (§3). The download's peer ranking runs its
  probes concurrently and the liveness round ends after two quiet seconds:
  run 38 had spent 57 of its first 99 s there (§6). The same PR's
  `bmc.dlcrollbelow` (a rolling per-block pipeline on the early chain) was
  A/B'd the same afternoon and lost; the default stays off.
- **The async flush, the chainwork sync and the memory line** (PRs
  #394–#396, `b194dd01`, production `deploy-20261006d` at 20:03Z, verified
  on the next block with zero restarts; run 40): the memtable flush
  freezes the live table and blob into a private copy on the applier
  (0.47–0.68 s; the first 11.9 s, faulting the copy in) and a forked
  writer builds the run from the copy (13.6 s median) while the applier
  goes on; the run is adopted at the next block boundary, the WAL is
  hole-punched below the checkpoint, never truncated. Run 40: 112
  freezes, 97 s on the applier, 1,545 s in the writer, zero waits and zero
  inline fallbacks; the flush column 1,357 → 131 s. The chainwork records
  are appended during the parallel download, so the first rotation after
  it has nothing to read back: the 65 s pause before the final drain (run
  39) was 0.55 s in run 40. The node prints a `[mem]` line by mapping at
  IBD end and at ready, and the sampler sums `Pss_Anon` (§5). What run 40
  did not deliver: the applier total (14,650 s, 590 s above run 39) — the
  put column absorbed the flush's gain, §2 — and the tail: 99 s from the
  download's end to ready, of which 23 s is the drain and ~62 s a top-up
  round for the 37 blocks that arrived during the sync, re-probing and
  re-ranking the whole peer pool before asking for them (plan B10).
- **The idle tick on the early chain** (B9 part 2, branch
  `perf/2026-10-07-b9-idle-tick`, built 10-07 after Core rerun #7):
  the download loop connects what the helpers have delivered each pass
  and, when a pass found nothing, slept its whole 2 s idle; the window
  is anchored to the connected tip, so on the early chain the helpers
  filled a 1,024-block window in ~0.3 s and waited at its edge for the
  tick. Run 40 below 100,000: 99 bursts of chunk completions 2.09 s
  apart; 746 blocks a second while the helpers were busy and nothing in
  76 of 210 s. The idle wait now reads the committer's tip every 20 ms
  and ends when it moves (once per distinct tip; the connect-failure
  backoff is honoured); the gate line reports the count.
  `tests/test_dlc_interleave` gained a phase with the real 2 s idle and
  a 120-block window (count ≥ 1; 0 with the cut forced off). A/B, fresh
  syncs the same morning: the fix arm reached 200,000 at 320 s with 165
  s of that in a one-peer header phase (plan B12), i.e. 134 s from the
  first block against run 40's 445 and Core #7's 239; the control arm
  drew a starved pool and was stopped (run 40 is the control). Run 41:
  100,000 at 1:35, 200,000 at 2:55 (Core #7: 2:06 / 4:44; run 40: 4:16
  / 8:12); the gate line `idle waits cut short 1670`. Landed in PR #400.
- **The memtable's backing** (B11, PR #400, `bmc.memtableanon` default
  1): the live table and blob were `MAP_SHARED` file mappings — every
  insert and every delete dirtied a file page the kernel wrote back and,
  under this box's cache pressure, reclaimed and re-faulted; the put
  column read 4,994 / 5,661 / 7,135 s over three runs of the same code,
  waited for, not computed. They are anonymous memory with
  `MADV_HUGEPAGE` now; the files stay at their sizes for the tools, and
  the table's first page is the file's first page so the serve process's
  live-count cross-check (`tx_accept.c`) still reads it. Run 41: put
  3,842 s (insert 664, delete 1,822; run 40: 2,621 and 3,079), the
  applier 11,842 s against Core #7's 13,340. The cost is in the memory
  column (§5). Pinned by `tests/test_utxo_memtable_anon` (file sizes,
  the count through the shared page, the named maps).
- **The top-up's claim** (B10, PR #400): run 40's tail spent 62 s
  re-probing and re-ranking 161 peers for 37 blocks because two fresh
  legs claimed a height 5,716 blocks above the ranking's median four
  seconds after it. A claim more than 50 blocks plus a block a minute
  above the last ranking's median is not believed. Run 41's tail: 34 s,
  no re-ranking. Five cases in `tests/test_parallel_trigger`.
- **The writer reaped at the tip** (B3, PR #400): the writer's and the
  compaction's polls ran only after a pass that applied something, so at
  one block an hour a finished writer sat unadopted for a block interval
  (found on production). Every catch-up pass and the worker's idle
  rotation poll now; adoption within ~200 ms.
- **After run 41 (10-07 to 10-10; #402–#417; runs 42–46).** #402: the
  getblock reader lane leaked three descriptors per Esplora facade
  connection (production's RPC dead 2 h 17 m on 10-07; a pthread-key
  destructor closes the lane). #405 (B13): a staller is banned on its
  second stall, not its first (run 41: 29 fresh peers banned on their
  first chunk; run 46: 9 of 136 banned). #407 (M2): `dbcache` is the
  whole UTXO heap — the live memtable, its frozen copy and the flush
  scratch inside it — and the forked children no longer carry a copy of
  the memtable (heap 15.3 → 6.4 GB mean in run 42, at first for a slower
  sync, 5:31:27). #408 (M3): a deferred merge obeys the run budget at any
  run count (run 42's run count ran away; run 43: 4:05:03). #409 (B14):
  the dead-weight rule judges only the time a worker was free to fetch,
  not its wait at the full window. #410/#412/#413 (B12): the header chain
  is fetched in 19 parallel ranges from anchor hashes every 50,000
  heights across the probe's four fastest peers, and the phase ends when
  every range is settled (run 44 waited 180 s for a peer holding none);
  run 46: 73 MB in 15.8 s. #416: the frozen copy keeps its pages — M2
  released them at every adopt, so each freeze re-faulted ~3 GB of huge
  pages behind a memory compaction (run 45: 2.4 s a freeze, 231 freezes;
  run 46: 136 ms mean). #417: a run's Bloom filter is sized to its
  records — the 4 MiB cap gave a 19M-record run 1.8 bits per key and
  passed 55% of absent keys to a sparse search (run 46: `get` 4,607 →
  2,870 s). The runs: 42 5:31:27, 43 4:05:03, 44 4:02:04, 45 4:05:13,
  **46 3:17:55**; each with a muhash identical to Core's. Details:
  `docs/releases/2026-10-08-the-heap-the-merge-budget-and-header-ranges.md`,
  `worklog/2026-10-09.md`, `worklog/2026-10-10.md`.

## 8. Method and reproducibility

- Sync pair: `validation/logged_pair_run.sh` (Core) and
  `validation/fresh_ibd_run.sh` with `BENCHLOG=1 READY_WAIT=1` (bmc);
  `validation/ibd_stage_report.py` builds the stage tables from the two logs
  (`--selftest` first).
- RPC: `validation/rpc_concurrency_bench.sh <url> <cookie> 32 5 <method> [params]`,
  both nodes in the same minute, the block and transaction pinned in §3.
- CPU/memory: Core from systemd's "Consumed" journal line; bmc from
  `validation/proc_sampler.sh` beside the run (PSS, anonymous, peaks; MEM
  lines at IBD_END and READY in phase.log).
- Stalls: `validation/stall_watch.sh` beside the run dumps PSI, per-process
  state and sockets whenever the stored counter stops for 30 s.
- Never an RPC call to a node during its timed run.
