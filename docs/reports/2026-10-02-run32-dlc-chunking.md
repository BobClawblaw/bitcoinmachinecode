# Run 32 — 16-block download requests (bmc.dlcchunk=16), 2026-10-01/02

**Question.** Run 31 (2026-09-30, matched to Core: 10 workers, a 1,024-block
window) lost 11.5% to run 30 (4,096-block window). The diagnosis was that our
40-block requests starve the apply inside a short window. #361 made the request
size `bmc.dlcchunk`, default 16. Run 32 measures how much of that 11.5% comes
back.

**Answer: none that this run can show. It finished 9.7% *behind* run 31, but the
run is confounded and does not settle the question.**

## Result

| | run 31 (40-block requests) | run 32 (16-block requests) |
|---|---:|---:|
| source | 2026-09-30, main at the time | `f332e791` (main + #361), third start 2026-10-01 20:49:38Z |
| protocol | `PARITY=1`, derived 10 workers, dbcache=8192, coinstatsindex=1, nice 0 | the same |
| time to 968,987 (milestone script) | **5:29:45** | **6:01:38** (+31:53, +9.7%) |
| IBD end (log) | — | 02:49:42Z, 21,604 s, applied = stored = 969,525 |
| capstone | PASS | **PASS**, MuHash identical to Core at 969,525 (`10833b52…6271b94`) |

Milestones (`TZ=UTC validation/ibd_milestones.sh`, the same script for both runs):

| height | run 31 | run 32 | run 32 − run 31 |
|---:|---:|---:|---:|
| 50,000 | 0:04:15 | 0:03:45 | −0:30 |
| 100,000 | 0:05:48 | 0:05:17 | −0:31 |
| 200,000 | 0:09:58 | 0:09:19 | −0:39 |
| 300,000 | 0:16:59 | 0:16:27 | −0:32 |
| 400,000 | 0:34:25 | 0:34:19 | −0:06 |
| 500,000 | 1:05:55 | 1:09:58 | +4:03 |
| 600,000 | 1:44:37 | 1:51:20 | +6:43 |
| 700,000 | 2:29:03 | 2:41:30 | +12:27 |
| 800,000 | 3:15:50 | 3:33:02 | +17:12 |
| 900,000 | 4:39:32 | 5:05:11 | +25:39 |
| 950,000 | 5:11:52 | 5:41:55 | +30:03 |
| 968,987 | 5:29:45 | 6:01:38 | +31:53 |

The 16-block requests are ahead to 300,000 (about 3%), which is the range the
A/B (`ab-chunk`, four arms to 300k) measured and where #361's default came from.
From 400,000 on, run 32 falls behind in every 100,000-block segment.

## Why it does not settle the question

The box was not quiet. The development session that evening ran next to the
benchmark: daemon builds, unit tests, and about twenty regtest end-to-end runs,
each starting a Core and a bmc node (all at nice 10–19). In clock time against
the run's milestones:

| segment | clock (UTC) | segment vs run 31 | overlapping work |
|---|---|---:|---|
| 400k→500k | 21:24–22:00 | +13% | gate checks and three tests, 21:07–21:32 |
| 500k→600k | 22:00–22:41 | +7% | little |
| 600k→700k | 22:41–23:31 | +13% | builds and tests, 22:58–23:04 |
| 700k→800k | 23:31–00:22 | +10% | continuous from 23:50 |
| 800k→900k | 00:22–01:54 | +10% | continuous (builds, ~15 regtest runs) |

Contention explains part of the loss, maybe most. It does not explain the
quietest segment, 500k→600k, also running 7% behind. Two readings fit:
the 16-block requests cost something late in the chain (more requests per
byte once blocks are large), or the production node and the oracle were busier
than during run 31. This run cannot tell them apart.

## What to do

- **Rerun quiet** (run 33): the same protocol from current main, nothing else
  on the box beyond production and the oracle, no builds or tests until the
  RESULT file appears.
- If run 33 also loses from 400k on, the next step is a late-chain A/B,
  `bmc.dlcchunk` 16 against 40, from a 600k snapshot. The 0–300k A/B cannot
  see this regime.
- Until then, `bmc.dlcchunk=16` stays the default: it measured best where it
  was measured, and run 32 is not clean evidence against it.

Run directory: `/srv/nvme8tb/bench/run32` (the two earlier aborted starts are
`run32-cut-20261001-1735` and `run32-cut-20261001-1920`).
