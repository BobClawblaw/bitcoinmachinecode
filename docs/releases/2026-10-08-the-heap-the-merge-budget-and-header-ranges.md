# 2026-10-08 — The heap, the merge budget, and the headers in ranges

Four changes after the descriptor outage, all plan items from the run 41
report (`worklog/2026-10-05-performance-holes-plan.md`), and three
benchmark syncs. #407 (M2) cuts the heap. #408 (M3) fixes the merge
deferral that M2 exposed in run 42. #409 (B14) stops the dead-weight
rule from judging a worker that is waiting at the full window. #410 (B12)
fetches the header chain in parallel ranges. Main is `abeae7fd`; run 44
measured it, and #412 (`15b2ce7f`) fixed what run 44 found in the ranges.
Production still runs `deploy-20261007a`, and none of the four is
deployed. #409 and #410 change only a node's own initial download. #407
and #408 change the UTXO store of every node, and wait for a deploy
decision.

Memory figures are from the proc sampler beside every run (every 5 s, the
daemon's whole process tree), as the sampler's MiB / 1024. Run 42's PSS
peak was first written as 68.7 GB (the MiB / 1000); it is 67.1 here.

## The runs

| | run 41 (release) | run 42 (M2 + B12 switch + B13) | run 43 (+ M3) | run 44 (+ B14 + B12 ranges) |
|---|---|---|---|---|
| main | `7027c734` | `6554de3f` | `06e4b323` | `abeae7fd` |
| every index at the tip | **3:48:22** | 5:31:27 | 4:05:03 | 4:02:04 |
| UTXO set at the tip | MuHash = Core | MuHash = Core (970,461) | MuHash = Core (970,510) | MuHash = Core (970,536) |
| heap (anonymous) mean over the sync | 15.3 GB | 6.4 GB | 6.5 GB | 6.5 GB |
| heap peak | 32.2 GB | 11.8 GB | **10.7 GB** | 11.3 GB |
| PSS peak (file-backed run pages included) | 75.6 GB | 67.1 GB | **55.1 GB** | 55.9 GB |
| memtable freezes; applier time in them | 110; 99 s | 222; 519 s | 218; 456 s | 218; 471 s |
| merges; their total time | 5; 771 s | 7; 1,425 s | 5; 998 s | 5; 1,042 s |
| first block asked for | 48 s | ~66 s | ~50 s | ~3.5 min (headers 182 s, below) |
| peers banned | — | 29 | 1 | **0** |

Core rerun #7 for scale: 9:50:04, heap mean 10.0 GB and peak 12.0 GB, a
cgroup peak of 76.2 GB with page cache. Elapsed at each height, from the
5-minute heartbeat:

| height | run 41 | run 42 | run 43 | run 44 |
|---|---|---|---|---|
| 500,000 | 0:44:17 | 0:43:51 | 0:49:17 | 0:46:45 |
| 600,000 | 1:14:13 | 1:19:01 | 1:19:22 | 1:11:53 |
| 700,000 | 1:44:23 | **3:19:14** | 1:54:25 | 1:46:46 |
| 800,000 | 2:19:10 | 3:54:13 | 2:29:33 | 2:21:52 |
| 900,000 | 3:09:19 | 4:49:19 | 3:24:38 | 3:21:59 |
| 950,000 | 3:34:28 | 5:19:19 | 3:49:40 | 3:47:06 |

## M2: the heap (#407)

Run 41's heap was steady at 15.3 GB against Core's 10.0, with a 32.2 GB
peak. Steady, there were two memtables: `dbcache=8192` built a 7.6 GB
memtable, and the asynchronous flush (B3) a second one of the same shape,
the frozen copy, which kept its pages for the whole generation. The peak
was copy-on-write. A merge child forked while the next freeze rewrote the
copy and the applier kept writing the memtable: +17.5 GB in two samples,
for a child that reads neither.

- The merge child and the flush writer are forked without the buffers they
  never read (`MADV_DONTFORK` around those two forks only).
- `dbcache` is the total, as Core's is. With the async flush, the live
  memtable and the frozen copy get half each.
- The frozen copy releases its pages when its writer is adopted.

The heap targets are met: mean 6.5 GB (target ≤ 10) and peak 10.7 GB
(target ≤ 16), both under Core's. The sync-time target (within 3% of
3:48:22) is not. Run 43 is 16 minutes (7%) behind run 41, and the
heartbeat shows it as a steady drift, 5 minutes by 500,000 and 15 by
900,000, not one stall. The cost M2 predicted is in the freezes: twice as
many at half the size, each one faulting in fresh pages after the
release. That is 456 s of applier time against 99 s, about 6 of the 16
minutes. The rest is not yet decomposed; more runs and lookups against a
smaller memtable are the candidates. Run 44 gives a third point: 4:02:04,
3 minutes ahead of run 43 after losing 2 minutes to its header ranges,
with the same 218 freezes (471 s). The gap to run 41 is still there.

## M3: the merge budget (#408)

Run 42 took 2 h 00 m from 600,000 to 700,000, against run 41's 30 min. While the apply is 256
or more blocks behind the download, a merge waits until twice the count
threshold (48 → 96 runs), unless the run files are over the run budget
(35% of RAM, 46.3 GB on this box). "Over the budget" was computed as "under
the count threshold", which was true only when the byte rule had picked the
merge. Run 41's runs crossed 46.3 GB at about 27 runs, before the count
of 48, so it never mattered. M2 halved each run: the count came first,
and the store waited to 96 runs and 72.7 GB, every lookup probing up to 96
runs from disk, until the merge at 05:02Z.

The deferral now reads the run files' bytes at any count. In run 43 one
merge deferred and started 4 minutes later (the log does not say which
rule released it), and every merge took 176–219 s. New log line: `[utxo_live] merge of N run(s) deferred:
...` (`docs/OPERATIONS.md`). Test: `tests/test_utxo_merge_budget`,
watched to fail with the old expression put back.

## B14: the dead-weight rule and the full window (#409)

Run 42's 29 bans were not the stall rule's: B13 (#405) banned nobody. They
came during the merge stall, when the applier held the window full and
the workers had nothing they were allowed to fetch. The dead-weight rule
measured each worker over the whole 10 s tick, so 57 were dropped (one
had served 9,600 blocks and "measured 2.8KB/s"), and the early-kill path
banned the peer while the pool was above its floor. The worker now
records its time at the window, the rule judges only the time it was free
to fetch, and a tick less than half free is not judged. Run 43, with M3
and without B14, had 3 drops and 1 ban: without the stall the window
rarely fills. Run 44, the first run with B14, had 0 drops and 0 bans
("banned 0/131"); it logged 4 "stalling the window" lines and banned none
of them. The lesson is in
`docs/ENGINEERING_RULES.md` §11, beside the two earlier dead-weight
thresholds. Test: `test_dialhelper`, nine cases, watched to fail with the
wait ignored.

## B12: the headers in parallel ranges (#410)

B12's first arm (#404) switches to the next header candidate when the
leader slows. In run 42 it never fired: the one peer was steady at 1.3
MB/s for 61 s, and the first block was asked for ~66 s after boot. Run 43
drew a 2.2 MB/s peer and was at ~50 s with no switch either.

The second arm needs a hash to start each range from, and Core ships none
below 840,000, so this node now has a table of its own (19 mainnet hashes
every 50,000, each checked against Core v31.1). This is a divergence from
Core, written up in `docs/CORE_DIVERGENCES.md`. The probe's answering
peers fetch the ranges in parallel. Each range must end on its anchor, and
the contiguous prefix is stored by the same code that stores a single
peer's pages, `-minimumchainwork` hold included. The log lines are in
`docs/OPERATIONS.md`. Tests: `test_dlc_header_probe`, five cases, each
part watched to fail with its code removed.

**Run 44, and the fix (#412).** All 19 ranges came in and were stored
correctly, but the phase took 182 s against run 43's 49 s. This was first
put down to one peer whose child stuck before taking a range. The real
cause is that the download worker runs with `SIGCHLD = SIG_IGN`: an exited
child is reaped by the kernel, `waitpid` fails with ECHILD and never
returns the pid, and the parent compared only against the pid. It never
saw a child exit, so the wait could only end at its 180 s cap. #412 ends
the phase once every range is done or given up, which covered it. Run 45
(main `15b2ce7f`) fetched all 19 ranges in 21.5 s and asked for its first
block about 50 s after launch. Its settle line still counted all four
peers as "holding none" when three had fetched: the same reaping. That fix
(the reaps through `dl_reap_bounded`, the line naming who was still
connected) is on `fix/2026-10-08-b12-settle-count`, a PR after its gate.
