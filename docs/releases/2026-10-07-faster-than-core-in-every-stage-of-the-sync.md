# 2026-10-07 — Faster than Core in every stage of the sync

The performance release. Four benchmark syncs of the release line and two
of Bitcoin Core v31.1 on the same machine, the same NVMe, the same
indexes, the same other services running beside them; the full tables
are in `docs/reports/2026-10-06-core-vs-bmc-performance-release.md`
and the per-segment stage reports beside it. The build is main
`7027c734` (PR #400). Production runs `deploy-20261006d` (main
`b194dd01`, PR #396) at the time of writing; the deploy of `7027c734`
is the operator's next step.

## The headline

| genesis to every index at the tip | Core v31.1 rerun #7 | bmc run 41 | bmc / Core |
|---|---|---|---|
| 100,000 | 2:06 | 1:35 | 0.76 |
| 200,000 | 4:44 | 2:55 | 0.62 |
| 300,000 | 15:30 | 6:57 | 0.45 |
| 500,000 | 1:43:30 | 44:25 | 0.43 |
| 800,000 | 5:54:00 | 2:15:53 | 0.38 |
| 900,000 | 8:13:37 | 3:10:02 | 0.38 |
| **every index at the tip** | **9:50:04** | **3:48:22** | **0.39** |
| CPU time, all processes | 13 h 15 m | 7 h 39 m | 0.58 |
| the applier's own time (thread-seconds) | 13,340 | 11,842 | 0.89 |
| UTXO set | muhash at 970,333 | identical at 970,364 | — |

Both nodes build txindex, coinstatsindex and blockfilterindex during
the sync with `dbcache=8192`; the finish line is the first moment every
index is at the tip. Core's run had a process sampler beside it like
ours (PSS, heap and CPU every 5 s), and both ran under the box's usual
load: a vLLM server, the mempool.space backend, BlockYard and the
production node, with the 8 GB swap full.

Two of these rows were Core's two days ago. Run 40 (10-06) lost the
first 200,000 blocks by 2.0× and the applier by 10%; the release report
records both, their causes and the fixes measured as built.

## What changed since run 40 (PR #400)

- **The early chain (plan B9 part 2).** bmc's download loop connects
  what the helpers have delivered on each pass and, when a pass found
  nothing, slept its whole 2 s idle. The window is anchored to the
  connected tip, so on the early chain the helpers filled a 1,024-block
  window of tiny blocks in ~0.3 s and waited at its edge for the tick:
  run 40 below 100,000 shows 99 bursts of chunk completions 2.09 s
  apart, nothing at all in 76 of 210 s. The idle wait now reads the
  committer's tip every 20 ms and ends when it moves. Run 41 reached
  100,000 at 1:35 and 200,000 at 2:55 (run 40: 4:16 and 8:12).
- **The memtable's backing (plan B11).** The live UTXO memtable's table
  and blob were `MAP_SHARED` file mappings: every insert and every
  delete dirtied a file page the kernel wrote back and, under this
  box's cache pressure, reclaimed and re-faulted. The put column read
  4,994, 5,661 and 7,135 s over three runs of the same code — waited
  for, not computed. They are anonymous memory with `MADV_HUGEPAGE`
  now (`bmc.memtableanon`, default 1; the files stay at their sizes for
  the tools and the table's first page is still the file's first page,
  so the serve process's live-count cross-check reads it as before).
  Run 41: put 3,842 s (the insert 2,621 → 664 s, the spent output's
  delete 3,079 → 1,822 s), the applier 11,842 s against Core's 13,340.
  The same pages now count in the heap column (below).
- **The top-up after the download (plan B10).** Run 40's last 99 s
  included 62 s of re-probing and re-ranking the whole peer pool for
  37 blocks, because two fresh legs claimed a height 5,716 blocks above
  the ranking's median four seconds after it. A claim more than 50
  blocks plus a block a minute above the last ranking's median is not
  believed. Run 41's tail from the download's end to ready: 34 s.
- **The flush writer at the tip (plan B3).** The forked memtable writer
  was polled only after a pass that applied something; at one block an
  hour a finished writer sat unadopted for a block interval (seen on
  production). Every catch-up pass and the worker's idle rotation poll
  now; adoption within ~200 ms.

Each fix has a test that was watched to fail with the fix reverted:
`tests/test_dlc_interleave` (the idle tick), `tests/test_utxo_memtable_anon`
(the file sizes, the shared header page, the named maps),
`tests/test_parallel_trigger` (the claim bound). The full gate passed
(376 ALL TESTS PASSED, `asm/gate-20261007b.build`).

## The one category Core keeps: memory

| | Core #7 | bmc run 41 |
|---|---|---|
| heap (anonymous), mean over the sync | 10.0 GB | 15.3 GB |
| heap, peak | 12.0 GB | 32.2 GB (a compaction child's copy of the set) |
| PSS with mapped files, mean / peak | 17.6 / 34.3 GB | 39.9 / 75.6 GB |
| at IBD end | 25.4 GB PSS, 11.3 GB heap | 38.5 GB PSS, 3.8 GB heap |

bmc's working set is the UTXO run files it maps (the compacted run plus
one per generation), which count in its PSS while the kernel keeps them
cached and are the kernel's to drop; Core's chainstate is read through
LevelDB's cache and its page cache is not in its PSS (its cgroup peak
with page cache was 76 GB). The heap row moved to Core's side with this
release on purpose: the memtable's 2^25-slot table and 6 GB blob are
heap now instead of file pages, and that is where the applier's 3,300 s
went. `bmc.memtableanon=0` restores the file mapping for a box where the
ceiling matters more than the clock.

## Everything else

Unchanged from the 10-06 report and still bmc's or parity: the header
phase (48 s to block 1 against Core's 45), the RPC rows (getrawmempool
4.2× at 32 clients, getblock 1.5× single-client, the rest at parity, no
lock-ups since the 10-05 deploy), the modules, txindex 2.5× smaller on
disk. Core keeps the UTXO set on disk by 2 GB and the undo files by
design (ours carry the spent scripts for the address history).

## Open, not in this release

- The window-stall rule bans a fresh peer that does not answer its
  first 16-block request within the 2 s stall timeout (run 41: 29 of
  the 34 bans, between 390,000 and 430,000). Core's rule disconnects
  the same peers; ours also bans them. The pool never ran short and the
  download averaged 54 MB/s, so it cost nothing here (plan B13).
- The header download is one peer's speed: 33–38 s on a good draw, 165
  s on a bad one (plan B12).
- The ranking's top churns across runs (69–81 distinct peers serve a
  sync that 25 served in run 38; plan B9 part 1).

## Addendum, later on 2026-10-07

- **Deployed.** `7027c734` went live inside `deploy-20261007a` (main
  `54ffb790`, 18:42:56Z), together with #402.
- **"No lock-ups since the 10-05 deploy" needs a qualifier.** It holds for
  exec-lock waits, but production's RPC was dead for 2 h 17 m on 10-07, from
  16:26Z, for a different reason. The getblock reader lane leaked three
  descriptors per Esplora facade connection until accept() hit the 1,024
  limit. Fixed by #402:
  `devlog/INCIDENT_2026-10-07_reader_lane_fd_leak.md`.
- **The B3 reap at the tip has a test.** #403 added
  `tests/test_utxo_reap_at_tip`.
- **Two of the open items are built.** B12, the header leader switch, is
  #404. B13, the stall rule banning on a second stall, is #405. Neither has
  been measured on a benchmark yet. See
  `releases/2026-10-07-the-descriptor-outage-and-the-header-leader.md`.
