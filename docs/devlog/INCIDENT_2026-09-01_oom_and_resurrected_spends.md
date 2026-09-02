# Incident 2026-09-01 — a set-diff pipeline took the box down at 20:00 UTC; the muhash gap it was chasing is 2,596 spends resurrected by eight blind recoveries

Two defects, one evening. The first (a shell idiom in an ad-hoc analysis
command) hard-froze the host and cost a reset, every running session, the
oracle sync and the guarded watch on deploy `ag`. The second is the thing
that analysis was hunting: the mainnet UTXO set rebuilt today carries
**2,596 coins (5,589.97458543 BTC) that the chain has spent**. Both are
fully explained below with the evidence; neither is fixed in the store yet.

## Summary

| | |
|---|---|
| Host outage | 20:00:33 → 20:03:39 UTC (journal end → reboot). Hard reset; no OOM-kill was ever logged. |
| Trigger | `awk '... (k[$1" "$2]) ...'` over a 13.5 GB, 165.7M-line dump: referencing an array element in a condition **creates** it, so gawk built a ~62 GB hash. |
| Why fatal | Swap (8 GB) had been 100 % full since at least 18:40; anon memory went 9.3 → 54.3 GB in two minutes; the kernel thrashed instead of killing. |
| UTXO defect | At every height ≥ 539,017 our set = Core's set + exactly 2,596 outpoints. Zero outpoints missing. Sum of the extras = the `gettxoutsetinfo` amount delta to the satoshi. |
| Origin | Eight `FATAL: apply_block failed → in-place recovery (compact)` rounds during today's from-genesis rebuild, 13:37–14:23 UTC, at heights 428471 … 539017. Each round lost the spends of the one block applied just before the failure. |
| Underlying bug | Deploy `y` = commit `b3d47a9` (13:29, buffered memtable flush) left the sparse-index samples on the pre-buffer file offset. Fixed for lookups in `bc098fd` (14:23). The damage done by the eight recoveries in between was never assessed. |
| State now | **REPAIRED 21:23 UTC and PROVEN 21:28**: the 2,596 outpoints were deleted offline (`daemon/utxo_repair_del`), the coinstats state re-seeded from a full walk, and `gettxoutsetinfo muhash` at height 965085 is `7b3938df…8c44` on both nodes, 165,721,328 txouts, 20,078,163.63377124 BTC. The blind recovery path is still in place (to-do below). |

## Part 1 — the host outage

### Timeline (UTC)

- **19:13–19:27** deploy `af` boots into a SEGV loop (plain `pthread_create`
  threads under the 12 MB TLS, see `project-tls-thread-stacks`); `ag` with
  `bmc_pthread_create` is live from 19:27:13. Unrelated to what follows.
- **19:39:47** first muhash comparison at 965073/965074: ours 165,734,400
  txouts / `563fae16…`, Core 165,731,804 / `a0c14ccc…`. +2,596, +5,589.97 BTC.
- **19:48:27** the session starts an offline key dump of our set
  (`daemon/utxo_dump_keys`, new, untracked) and a parser of Core's
  `dumptxoutset` at 965074. Both stream; both fine.
- **19:52:45–19:55:00** two `sort -S 6G --parallel=8` in parallel: +12 GB
  anon, released. Fine.
- **19:57:26** `comm` produces `only_ours.keys` / `only_core.keys`. (These
  were also wrong — see "second defect in the analysis" — but harmless.)
- **19:58:26** `awk 'NR==FNR{k[$1" "$2]=1; next} (k[$1" "$2]){print $4}'
  only_ours.keys bmc-diff-ours.sorted` starts.
- **19:58:30 → 20:00:30** node_exporter, 30 s samples, AnonPages:
  9.3 → 12.0 → 27.4 → 41.4 → **54.3 GB**; MemAvailable 47 → 2.1 GB;
  SwapFree 0 throughout.
- **20:00:33** last journal line. **20:01:48** last daemon log line (a 128 s
  heartbeat gap — the daemon itself was healthy at tip 965079, 10/10 peers,
  and starved). **20:03:39** reboot.

### Root cause

In awk, `k[x]` in an expression is not a membership test: it inserts `x`
with an empty value. The first file (20,561 keys) populated the array as
intended; the second file then inserted **every one of its 165.7 million
lines**. Measured on a 300 MB slice under `ulimit -v`: 1,427 MB RSS for
3.86 M lines (≈ 390 B/line) with the bad form, 8 MB with `(($1" "$2) in k)`.
Scaled: ~62 GB against a 60 GB box whose swap was already full.

No OOM-kill line exists because the kernel never got that far: with all
swap consumed and 2 GB of reclaimable cache left it thrashed the file-backed
working set (the daemon's mmaps, every binary) until nothing could run.

### What was damaged, and what was not

- Not damaged: the block archive, the UTXO store (mmapped, dirty pages
  were flushed by 20:00 — `Dirty` was 0 in the last samples), the mempool
  file, the wallet. The daemon reloaded at applied_height 965079 and
  applied 965080 in 0.97 s.
- Lost: the guarded watch on `ag`, the oracle's catch-up (it was at tip
  965079 by 19:56 and had produced its side of the comparison), every
  interactive session, the `$CLAUDE_JOB_DIR` err files of the dumps.
- Production Core (`bitcoind.service`, user-run, disabled) came back down and
  was NOT restarted by us (hard constraint). The scratch oracle was
  restarted by hand on `-port=8354`.

### Second defect in the analysis (harmless, but it would have misled)

`ours.keys`/`core.keys` were produced by `sort -k1,1 -k2,2n` (txid, then
vout **numeric**), but `comm` requires plain byte order. For any txid with
outputs numbered both < 10 and ≥ 10 the two orders disagree, and `comm`
listed those outpoints on both sides: 20,561 "only ours" / 28,415 "only
Core", of which only 2,596 / 0 were real. Redone with `LC_ALL=C sort` on
both, then `comm`, then the 3-block height gap between the dumps (ours at
965077, Core's at 965074) subtracted using `getblock … 3` from the oracle
with OP_RETURN outputs excluded:

```
only_ours2 16297 - created(spendable) 17408 in 965075..965077 = 2596 TRUE EXTRAS
only_core2 24151 - spent 27858 in 965075..965077              =    0 TRUE MISSING
sum(extras.value) = 5589.97458543 BTC  == 20083737.98335667 - 20078148.00877124
```

All 2,596 are spendable, distinct outpoints (no duplicate keys in either
dump), created between heights 410k and 539,015.

## Part 2 — the resurrected spends

### How the origin was found

Our replay logs `now at height H, live=N` at every stop and at every
recovery; Core's `coinstatsindex` answers `gettxoutsetinfo muhash H` for
any H. Comparing at the logged heights:

| height | ours (live) | Core (txouts) | diff |
|---:|---:|---:|---:|
| 340578 | 16,642,432 | 16,642,432 | 0 |
| 618297 | 65,518,132 | 65,515,536 | **+2596** |
| 964960 … 965027 (yesterday's set, before it was lost) | = | = | 0 |
| 965074 | 165,734,400 | 165,731,804 | +2596 |
| 965082 | 165,721,342 | 165,718,746 | +2596 |

So the whole surplus was minted between 340,578 and 618,297 of **today's
from-genesis rebuild** (started 12:29 after the header-sync incident's
archive truncation; resumed from a 340,578 checkpoint at 12:53). In that
window the log shows exactly eight of these:

```
[utxo_live] REJECT h=539017 tx=5: input references a missing/already-spent UTXO
[utxo_live] FATAL: apply_block failed at height 539017 -- stopping catch-up
[dl] utxo_live_catchup FAILED at height 539016 -- attempting in-place recovery
[utxo_live] recover: compact manifest_n=2 -> 1 (result=1)
[dl] utxo recovery SUCCEEDED (1 compaction round(s)) -- tracking continues at height 539017
```

at 428471, 445239, 460559, 475154, 491025, 503548, 520440, 539017 (13:37 →
14:23 UTC, one per memtable flush). The extras' creation heights cluster
right below those numbers (428318 ×116, 460556 ×90, 475152 ×72, 539013 ×60,
…): consolidation-style spends of recently created coins.

Scanning the oracle's blocks around each failure for transactions whose
inputs are in the extras set:

| # | failed at | block whose spends were lost | coins | UTC |
|--:|--:|--:|--:|---|
| 1 | 428,471 | 428,470 | 491 | 13:37:31 |
| 2 | 445,239 | 445,238 | 35 | 13:43:24 |
| 3 | 460,559 | 460,558 | 389 | 13:49:09 |
| 4 | 475,154 | 475,153 | 280 | 13:55:36 |
| 5 | 491,025 | 491,024 | 395 | 14:01:41 |
| 6 | 503,548 | 503,547 | 408 | 14:07:51 |
| 7 | 520,440 | 520,439 | 127 | 14:16:14 |
| 8 | 539,017 | 539,016 | 471 | 14:23:15 |
| | | **total** | **2,596** | |

Every round lost the spends of **exactly one block: the block applied
immediately before the one that failed** — i.e. the last block whose
operations were in the memtable when it flushed.

### Root cause (pinned 2026-09-02 by the regtest repro, `tests/test_utxo_lost_tombstones`)

- **The trigger.** `b3d47a9` (13:29, deploy `y`): the memtable flush writes
  records through a 1 MB buffer, but the sparse-index samples still used
  `lseek(SEEK_CUR)`, which excludes the buffered bytes. The buffer drains at a
  *piece* boundary (a record is written as key, value-portion, script), so
  with mainnet's mixed 22-34-byte scripts the drain lands mid-record and every
  sample after it points into the middle of a record: the read-side scan
  parses garbage and 10-15% of point lookups through such a run MISS.
  (Fixed-size short records never straddle the drain, which is why the first
  repro attempts saw no misses -- the fault is shape-dependent.)
- **The mechanism.** The replay ran with undo capture on (`g_undo_enabled`
  defaults to 1; `daemon/main.c` never clears it), so every spend went
  through `undo_capture_and_del` = `utxo_lsm_get` THEN `utxo_lsm_del`. A
  flush lands in the middle of a block. For the spends after that point whose
  coins had just gone into the fresh run, the capture's lookup missed,
  returned 0, and `live_on_input` accepted 0 as "already absent -- a
  crash-resumed re-apply" and SKIPPED the spend. The coin stayed in the run.
  Verification of the NEXT block missed too and rejected; the blind recovery
  compacted (a sequential rewrite, correct offsets) and the retry passed.
  So the damage was exactly the post-flush spends of the block the flush
  landed in, at the lookup-miss rate. The block data confirms it to the
  transaction: in 539016 the first lost spend is tx 61, none of the 170
  in-window spends before it were lost, 471 of the 4,691 after it were
  (10%), and none of the 274 spends of older-run coins were -- their run had
  been rewritten by an earlier compaction.
- **What the store did NOT do.** The store never lost a record. In every
  sequence the repro can drive -- flush, reject, compaction, reload,
  post-flush spends of run-resident coins -- the ground-truth walk stays
  exact. Only point lookups lied, and one caller believed them.
- **The mask.** `daemon/main.c` treated every catch-up failure as "manifest
  full", compacted, retried, and called the retry's success proof. Fixed in
  `874c1a8` (gated, walk-verified recovery).
- **The missed signal.** `bc098fd` (14:23) fixed the read side and stopped
  the trigger; its message records the rejects as "each recovered by a full
  compaction". Nobody asked what the spends between a flush and its reject
  had seen.

### Why it had never happened before

The buffered flush was one day old, and the "0 is not fatal" branch in
`live_on_input` had been dead in practice since Stage D began verifying a
block before applying it (a re-applied block is rejected by verification,
and crash-resumed blocks are handled by the ghost rollback at boot). It
took a lookup that lies to reach it.

### What was damaged, and what was not

- Damaged: the live mainnet UTXO set (`data/main/utxo_lsm_*`, runs
  000072–000075): +2,596 spent coins. Every derived number since 14:23 —
  `gettxoutsetinfo`, the coinstats muhash, `gettxout` for those outpoints,
  fee/amount checks that touch them — is wrong by that set. Muhash parity
  with Core is broken at every height ≥ 539,017.
- Not damaged: consensus validation of new blocks (an extra unspent coin
  cannot make a valid block fail; it could only let a double-spend of one of
  those 2,596 coins through, which the chain will never present). The block
  archive, headers, indexes, wallet, mempool are unaffected. Signet/regtest
  stores were built on different binaries and are proven identical.

## Fixes

Done tonight:

1. `docs/`: this report; memory notes `incident-20260901-oom-awk` and
   `feedback-awk-membership-and-memory-caps`.
2. Evidence kept under `/storage/bmc-diff-work/`: `extras2.keys` (the 2,596
   outpoints), `extras2.full` (with value/height), `extras_spenders*.json`
   (spending block/tx per outpoint), `ours_live_by_height.txt`; and the raw
   dumps in `/storage/bmc-diff-{ours,core}.{txt,sorted}` (50 GB — delete
   when the repair is proven).

3. **Surgical repair, applied 21:21–21:28 UTC.** `daemon/utxo_repair_del.c`
   (new): stop the daemon, `utxo_lsm_reload` the store read-write, verify every
   key with `utxo_lsm_get` (2,596 present, 0 missing, sum 5,589.97458543 BTC),
   `utxo_lsm_del` each, `utxo_store_wal_drain`, verify all gone. Live count
   165,723,924 → 165,721,328 at applied height 965085 = Core's txouts at
   965085. `coinstats.dat` retired so the index re-seeded from a walk
   (4 min 40 s). Result at 965085, both nodes:
   `muhash 7b3938df2364a51dadf52f41fc453027116188f89fb642e7607f58a9ff808c44`,
   txouts 165,721,328, total_amount 20,078,163.63377124. Pre-repair copies of
   the store's metadata files are in `/storage/bmc-diff-work/pre-repair/`.

To do (in this order):

1. **Repro, then root-cause the lost tombstones** -- DONE 2026-09-02 (this
   branch). `tests/bitcoin_utxo_lsm_badsparse.o` is the LSM assembled with the
   read-side fix compiled out; `test_lsm_lost_tombstones{,_bad}` (store level)
   shows the lie and the walk staying exact; `test_utxo_lost_tombstones{,_bad}`
   (daemon level: 32-tx blocks, 86-byte records so the drain lands mid-record,
   undo capture on, the old main.c loop) reproduced the loss -- `resurrected_
   spent=11 of 31904`, +10 at the first flush and +1 at the second -- and now
   proves the fix. **Fix:** an absent coin at apply time is a store lookup
   inconsistency: the block fails, the partial apply is rolled back without
   trusting a lookup, UTXO tracking HALTS (sticky, heartbeat marker) and the
   worker stops retrying with an operator message. The repro halts at the
   first lying lookup with the walk equal to the pre-block state and zero
   earlier spends lost.
2. **Make recovery honest** -- DONE, `874c1a8` (2026-09-01 23:30 UTC, gate
   green twice: 310 gated tests on the branch and again on `main`). Every
   catch-up failure is classified (consensus reject / store error /
   archive); `daemon/main.c` compacts only when
   `utxo_live_recovery_applicable()` reports a store error with a full
   manifest; a consensus reject backs off and retries from the checkpoint
   without touching the runs and the log names it; after any compaction
   `utxo_live_verify_after_recovery()` walks the set and requires
   walk == counter == pre-recovery count, else UTXO tracking HALTS for the
   process (sticky; heartbeat shows `[UTXO HALTED ...]`).
   `tests/test_utxo_recover_gate` covers all three outcomes. NOT YET
   DEPLOYED to the live daemon (still on `ag`); deploy = relink + restart at
   a quiet moment.
3. **Repair the live set**:
   DONE (surgical, see above); the muhash match is the proof. A from-genesis
   rebuild on `bc098fd`+ remains the independent confirmation if wanted.
4. Delete the untracked `daemon/utxo_dump_keys` binary or make it a real
   tool with a Makefile rule; the `.c` is useful (offline read-only walk).

## Lessons

- **awk membership is `(key in arr)`, never `(arr[key])`.** One character
  cost the box.
- **Every one-off pass over a multi-GB file runs under a cap** —
  `ulimit -v` or `systemd-run -p MemoryMax=` — and only after looking at
  `free -h`. This box runs with its swap full for hours at a time; there is
  no cushion, and a memory spike freezes it without an OOM-kill line.
- **`comm`/`join` inputs must be sorted in the tool's collation**, not the
  order that was convenient for the previous step.
- **A recovery that "succeeds" is a claim, not a proof.** The daemon's
  blind compact-and-retry hid eight consensus disagreements; the commit that
  fixed the trigger recorded them as benign. After any FATAL, count the
  set (`utxo_live_walk_count`) before trusting the counter, and compare
  with Core before deploying.
- **Bisect with what is already logged.** The `live=N` lines plus Core's
  coinstatsindex located the origin in one query per logged height; no dump
  was needed for that step.

## Resolution sequence (what actually happened, including the missteps)

1. Journal, sar and node_exporter established the 19:58:30–20:00:30 anon
   spike and the full swap; the transcript of the session gave the exact
   command; a bounded re-run measured the per-line cost. Daemon exonerated.
2. Relaunch: `bmc-bitcoind` (deploy `ag`, reload exact at 965079, applied
   965080 in 0.97 s); oracle on 8354; both at tip 965080/1.
3. Reproduced the mismatch at 965080 (+2,596 / +5,589.97458543 BTC).
4. Found the previous set-diff was doubly wrong (awk, comm order); redid it
   under a 14 GB cap; got exactly 2,596 extras, 0 missing, amount exact.
5. Tried the spender index (not built for mainnet); bisected with logged
   counts vs coinstatsindex instead; found the 340578→618297 window; found
   the eight REJECT/recover rounds; matched the extras' creation heights.
6. Scanned the oracle's blocks around each failing height: one block per
   round, the one before the failure. Found `b3d47a9` / `bc098fd`.

## Operator notes

- The daemon is up on `ag`, tracking the tip, and its UTXO set is
  muhash-identical to Core again as of 965085.
- `bitcoind.service` (production Core) is down since the reset and is the
  user's to start.
- `/storage/bmc-diff-work/` and `/storage/bmc-diff-*` hold ~62 GB of
  evidence; keep until the repair is proven, then delete.
