# IBD benchmarks, bmc vs Bitcoin Core v31.1 — the state of the pair at 2026-09-30

This is the write-up of the most recent initial-block-download comparisons
between this node and Bitcoin Core v31.1: what was run, on what, under which
settings, what each side's clock says at every 50,000 blocks, what the
margin is and where it comes from, and what is and is not clean about the
pairing. Every number is read from the two nodes' own logs against a start
stamp written the instant before each launch; nothing was read from either
node over RPC during its sync.

## The short version

| | bmc run 30 | Core v31.1 rerun #4 |
|---|---:|---:|
| started | 2026-09-28 06:47:10Z | 2026-09-29 13:54:00Z |
| time to height 968,987 (run 30's end) | **4 h 54 m 30 s** | **11 h 01 m 00 s** |
| ratio | | **bmc in 44.6% of Core's time: 2.24× faster, 55.4% ahead** |
| capstone | MuHash of the UTXO set identical to Core's at 968,987 | — |

The margin is flat from 350,000 to the end (55–62% ahead at every 50,000),
and run 30's own status lines say why: its download waited on its apply for
the whole sync, so on this link both nodes are bound by how fast they
connect blocks, and the ratio is the apply rate. Run 30 ran on the *less*
favourable network settings of the two (8 download peers to Core's 10, a
4,096-block window to Core's 1,024, idle legs held beside the workers);
those defaults were matched to Core's on 2026-09-29, and run 31, the first
bmc sync on the matched defaults, started at 01:14Z on 2026-09-30 and is in
progress as this is written.

## The box, the drive, the link

One machine for every run in the series: 32 cores, 123 GB, a Corsair MP600
PRO XT 8 TB NVMe for the benchmark datadirs (`/mnt/nvme8tb`, since 09-29
also reachable as `/srv/nvme8tb`, a bind mount of the same filesystem that a
mount on `/mnt` cannot shadow — see "What went wrong on the way"). The bmc
production node and a Core v31.1 oracle run on the box during every run;
they have for every pair in the series and are the only other load.

The link changed twice during the period, which is why there are several
Core runs:

| period | link | runs |
|---|---|---|
| through 09-22 | the old backhaul, ~88 Mbit/s of peer traffic sustained | bmc run 29 and Core "core31" (the old-link pair) |
| 09-28 | the backhaul repaired by the operator | bmc run 30, Core rerun #2 |
| 09-29 from ~13:30Z | a faster backhaul, measured 636 Mbit/s sustained inbound from two streams, ~800 Mbit/s burst | Core rerun #4, bmc run 31 |

## What each node was running

| | bmc run 30 | Core rerun #4 |
|---|---|---|
| build | main `1370d041` (#319–#335, the 2026-09-28 tree: the MuHash safegcd inverse, the constant-time ElligatorSwift multiplies, ChaCha20 in AVX2, SHA-1 by SHA-NI, SHA-512 unrolled, Base58 by limbs, the comb at every k·G) | Bitcoin Core v31.1, built from source on the box |
| datadir | fresh, `/mnt/nvme8tb/bench/run30` | fresh, `/srv/nvme8tb/bench/core31` |
| dbcache | 8192 | 8192 |
| indexes | txindex, coinstatsindex, blockfilterindex, all built during the sync | the same three |
| prune / listen | 0 / on | 0 / on |
| maxconnections | 48 | 48 |
| peers at start | none: an empty address book, the DNS seeds | none: an empty peers.dat, the DNS seeds |
| assumevalid | Core's v31.1 default, block 938,343 | the same |
| script threads | 16 (Core's cap: 15 workers plus the caller) | 16 |
| download peers | **8** (`bmc.catchupworkers=8`, the harness default since run 27) | **10** (every outbound peer that can serve blocks: 8 full-relay + 2 block-relay-only) |
| download window | **4,096** blocks above the connected tip | **1,024** |
| connections beside the download | **4 idle legs** held beside the 8 workers | none: the download peers are the outbound set |
| blocks in flight per peer | one 40-block chunk per request | 16, refilled as each lands |
| ZMQ | none | four topics published to a port nobody reads |
| scheduling | Nice 0, default I/O class | Nice 0, default I/O class (systemd unit) |
| RPC during the sync | none (the harness names any client in `phase.log`; it named none) | none (a watcher reads the log) |

The three bold rows are the ones that favoured Core; they were found in a
line-by-line comparison of the two nodes' defaults against Core's source on
09-29 and matched (#344, #347: `bmc.catchupworkers` now derived from the two
outbound classes, the window Core's 1,024, the idle legs closed for an
IBD-sized download; the harness writes the indexes, `maxconnections=48` and
the four ZMQ topics by default). The full checklist is
`docs/devlog/BENCHMARKS.md`, "The even comparison". Run 31 runs on it.

## The milestones

Elapsed from each run's own start, at each height, from bmc's
`catchup progress` lines and Core's `UpdateTip` lines. Core reruns #2 and #3
did not finish (below); their rows are shown for the run-to-run spread on
Core's side, which is a few percent from 500,000 on.

| height | bmc run 30 | Core #4 (the pair) | bmc ahead | Core #3 (cut at 939k) | Core #2 (died at 924k) |
|---:|---:|---:|---:|---:|---:|
| 50,000 | 0:02:23 | 0:09:54 | 76% | 0:06:24 | 0:04:11 |
| 100,000 | 0:02:45 | 0:10:43 | 74% | 0:07:23 | 0:04:43 |
| 200,000 | 0:04:33 | 0:15:34 | 71% | 0:11:32 | 0:08:19 |
| 300,000 | 0:09:40 | 0:29:56 | 68% | 0:25:38 | 0:21:20 |
| 400,000 | 0:24:13 | 1:02:57 | 62% | 0:56:58 | 0:55:29 |
| 500,000 | 0:54:17 | 2:11:51 | 59% | 2:01:34 | 2:09:57 |
| 600,000 | 1:28:54 | 3:23:46 | 56% | 3:12:15 | 3:25:34 |
| 700,000 | 2:10:21 | 4:53:24 | 56% | 4:42:01 | 4:58:50 |
| 800,000 | 2:51:55 | 7:01:59 | 59% | 6:20:56 | 6:40:41 |
| 850,000 | 3:23:09 | 8:15:10 | 59% | 7:31:24 | 7:50:36 |
| 900,000 | 4:11:32 | 9:27:42 | 56% | 8:44:34 | 9:05:13 |
| 950,000 | 4:42:20 | 10:32:45 | 55% | — | — |
| **968,987** | **4:54:30** | **11:01:00** | **55.4%** | — | — |
| Core's IBD-exit line | — | 11:01:07 at 969,077 | | | |

**Why the end row is "time to the same height".** The two nodes' own "end"
lines do not mean the same thing. bmc's harness writes `IBD_END` when the
applied tip equals the stored tip equals the oracle's live tip. Core's
`Leaving InitialBlockDownload` latches when its tip is within 24 hours of
now, which here fired at 969,077 while the real tip was 969,187; Core then
kept syncing. Comparing the two lines would hand Core up to a day of blocks
for free, so the end row is the time each log shows at the height run 30
ended on.

## Where the margin comes from

Run 30's downloader prints a status line every few minutes with the blocks
stored, the connected (applied) tip and the lag between them. From the
eleventh minute to the end the lag sat at 3,500–4,100 blocks: the window's
edge. Samples:

| elapsed | stored | applied | lag |
|---:|---:|---:|---:|
| 0:08:27 | 309,841 | 305,898 | 3,942 |
| 1:39:09 | 639,641 | 636,321 | 3,319 |
| 2:53:14 | 809,281 | 805,533 | 3,747 |
| 3:42:38 | 880,641 | 876,726 | 3,914 |

The download was waiting on the apply the whole way. On this link neither
node is download-bound, so the pair measures how fast each connects blocks
and updates its UTXO set and indexes, and bmc does that a bit over twice as
fast as Core at every height from 350,000 on.

The old-link pair (run 29 vs core31, 09-20/22) told the opposite story:
bmc 10.8% ahead at 400,000, 6.9% at 500,000, 4.8% at 900,000, 5.5% at the
end (18:28:54 against 19:32:54). Both nodes were bound by the ~88 Mbit/s
link there, their clocks converged on the link's rate, and the apply
difference was hidden. That pair is not comparable to this one on wall
clock at all; run 30 reached 400,000 in 24 minutes where run 29 needed 92.

The early rows (76% ahead at 50,000, narrowing to 55–62% by 350,000) are
the small-block era, where per-block overhead and header handling dominate;
Core rerun #4 also had the slowest start of the three Core runs (539 s from
launch to its first block against 314 s in rerun #3), which is where its
50,000 row comes from.

## What is and is not clean

- **Same box, same drive, same link, same protocol, sequential, never
  concurrent.** The two never shared the NVMe or the link.
- **The bench settings were not the same, in Core's favour**, for run 30:
  the three bold rows above. Run 31 removes that; if its time lands below
  run 30's, the matched defaults cost bmc nothing; if above, the report
  will say by how much.
- **One Core run finished on the new link.** Core's run-to-run spread from
  the three attempts is 5–8% per row from 500,000 on; the bmc side's
  old-link spread was 4 m 52 s between runs 28 and 29.
- **Two things ran on the box during Core rerun #4's last hour** that
  should not have: a full test gate from another of the operator's sessions
  (23:55–00:13Z) and that session's production deploy at 00:16Z. Core was at
  925,000–940,000, apply-bound; its 950,000 row is in line with its trend,
  so the cost is minutes, and against Core, not bmc.
- **Core's own defaults not matched**, deliberately: Core XORs its block
  files on disk (default since v28) and caps script verification at 16
  threads; both are Core's choices, and a Core user cannot change the
  second. bmc's 40-block chunk per request and its peer selection are bmc's.
- **The link repair is not quantified beyond the two measurements above**;
  its effect on the pair is inferred from the 400,000 rows of runs 29 and 30.

## What went wrong on the way

Two Core runs on the new link did not finish, neither for a reason in
either node:

- **Rerun #2** (started 09-28 16:02:29Z) died at 924,616 after 9 h 38 m 24 s.
  Core's block-file write found its datadir on a read-only filesystem and
  treated it as fatal. The NVMe was never read-only: a VM-test session on
  the same box mounted a disk image read-only on `/mnt` and unmounted it in
  the same second, which shadows every path under `/mnt/nvme8tb` for that
  second. The bench units, their config and the datadir path moved to
  `/srv/nvme8tb`, a bind mount of the same filesystem, which a mount on
  `/mnt` cannot shadow.
- **Rerun #3** (started 09-29 04:07:55Z) was stopped by the operator at
  939,450 after 9 h 46 m because the backhaul changed under it; its rows
  through 900,000 are in the table.
- **Run 30's own capstone passed**: with the network disabled and the set
  quiesced at 968,987, its MuHash equalled Core's for the same height, and
  the live answer agreed with the indexed record.

## Run 31, in progress

Started 2026-09-30T01:14:07Z, main `49e26354`, on the matched defaults. Its
log shows the three markers the matching predicts: 16 script threads, 10
download workers derived from the outbound classes, and its 5 idle legs
closed before the parallel download. It will be reported against Core
rerun #4 by the same rule, time to the same height, with the bmc side's
run-to-run spread (run 30 vs run 31) as a new row of evidence.

## Sources

- `run30/phase.log`, `run30/data/main/debug.log` (the `catchup progress`
  and `[dlc] ==` lines), `run30/FINAL_TABLE.md` (the finisher's table)
- `core31-20260930-rerun4-logs/` (`BENCH_START.txt`, `debug.log`,
  `watch.log`), `core31-20260929-0407-cut-at-939k-logs/`,
  `core31-20260928-cut-logs/` under `/srv/nvme8tb/bench/`
- `docs/reports/2026-09-28-run30-vs-core.md` (the pair's own report, with
  the history of the cut runs), `docs/reports/2026-09-22-run29-vs-core.md`
  (the old-link pair), `docs/devlog/BENCHMARKS.md` ("The even comparison"),
  `docs/releases/2026-09-29-core-download-shape-matched.md`
