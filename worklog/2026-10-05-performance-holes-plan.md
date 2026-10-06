# 2026-10-05 — Plan: the remaining performance holes vs Core, and the RPC lock-ups

Operator ask: "resolve the rest of the performance holes and any rpc
improvements so we don't lock up so much compared to core."

Evidence this plan is built on: the logged pair
(`docs/reports/2026-10-05-logged-ibd-pair.md`), `docs/PERFORMANCE.md` §4,
and production's `[rpc] exec lock:` lines since `deploy-20261003h` (21
lines in two days; every one a 2.1–2.7 s wait behind holders of 0–16 ms).

## The numbers to move

| metric | now | Core | target |
|---|---|---|---|
| applier thread-seconds, genesis → 970k | 17,166 | 13,909 | ≤ 12,000 |
| ↳ UTXO put | 7,812 | — | ≤ 4,500 |
| ↳ memtable flush on the applier | 1,350 | 803 | ~0 (async) |
| ↳ inline index work (idx + txindex + bfilter + csi) | 2,360 | 5 | ≤ 300 |
| headers → first block | 306 s | 75 s | ≤ 90 s |
| ready-at-tip, ranked peers | 5:28 (run 31, + 39 min rebuild then) | 10:42 | ≤ 4:45 |
| RPC: waits ≥ 2 s on the exec lock | ~10/day under BlockYard + mempool.space | n/a | 0/day |
| `getmempoolinfo`, 32 clients | 55 ms | 22 ms | ≤ 22 ms |

Every step below has (a) a measurement that must move, (b) a test that
fails with the step reverted, (c) a gate, (d) a `--no-ff` merge, as the
standing rules require. Nothing lands on a guess.

## Part A — RPC: stop the lock-ups (BlockYard-visible)

The lock is `g_exec_lock` (`rpc_server.c`), a writer-preferring rwlock.
Classes today: FAST (no lock, intake thread; the chain "lanes" with private
store handles), NOLOCK, SHARED (empty since 09-30), EXCL (everything else:
`rpc_chain`'s shared `g_st`, block buffer and caches). The production stalls
are a **convoy**: the Esplora facade's `POST /internal/mempool/txs`
(`rpc_esplora.c` ~l.410) takes the exclusive lock twice per parent — once for
`rpc_chain_tx_blockhash`, once for the `getrawtransaction` dispatch — so a
batch of 100 parents is 200 exclusive holds of ~15 ms, and `getblockhash`,
`getrawmempool`, `gettxoutsetinfo` queue 2+ s behind the burst while the
writer-preferring lock parks every reader too.

### A1. A txindex lane (small; first)
A private store handle + block buffer for the txid-index reads
(`rpc_chain_tx_blockhash`, `getrawtransaction` by txid/blockhash,
`getblockhash`), on its own rwlock where `irs_refresh` is the **only
writer** (it zeroes each kept run's map while rebuilding the table — the
10-02 crash). Readers take the read side; they never touch `rpc_chain`'s
shared scratch. Same shape as the FAST lane (`rpc_chain.c` "lanes") and the
mempool lane (09-30). A real lock, not lock-free: `lock-free-callers-bypass-
the-exec-lock` is why.
- Test: a refresh racing 32 lookups under ThreadSanitizer-free assertions
  (the test from #373 extended to the lane); `test_rpc_responsive` gains a
  case where a 200-parent batch runs beside `getblockhash` and the latter's
  wait is < 50 ms.
- Measure: `[rpc] exec lock:` waits ≥ 2 s per day → 0 under the facade
  batch; BlockYard's `rpc timeout` count stays 0.

### A2. The facade batch takes its lane once per batch (small)
After A1, resolve all parents' block hashes under one read hold, then fetch
the raw transactions in one `getrawtransaction` batch per slice (≤ 64), so
a batch is a handful of lane reads, not 2N exclusive holds.

### A3. `getmempoolinfo`: O(1) totals (small)
Keep `bytes` (vsize sum) as a running total updated on add/remove, as Core's
`m_total_fee`/`totalTxSize`; keep the full slot walk as a `checkmempool`-
style consistency check, not the answer path. 55 → ~20 ms at 32 clients.

### A4. The 150 s freeze after a restart into catch-up (diagnosis, then fix)
#376 logs the per-step split of any call over 1 s. The next restart into a
catch-up names the step (`chainwork.dat` was ruled out on 10-03). Until it
reproduces: no change. When it does, the step goes to a lane or gets a
cold-start precompute before the RPC port opens.

### A5. Heavy chain reads on the read side (medium; after A1–A3)
`getblock` verbosity 2 (31 ms) and `getrawmempool verbose` (63 ms) still
queue 32 clients. Give `getblock` the txindex lane's private handle; give
`getrawmempool verbose` the mempool lane with a snapshot per call.
PERFORMANCE §4's lesson applies first: profile the call before moving its
lock — `getblockchaininfo`'s "lock problem" was 5,763 `stat()`s.

### A6. The metric that says we are done
A daily line from the log: count of exec-lock waits ≥ 2 s, the max wait,
the top holder — beside BlockYard's timeout count. Zero waits for a week
under BlockYard + mempool.space is the exit criterion.

## Part B — IBD: the applier (the floor once peers are fast)

The pair showed the applier (fold process) is 23% slower than Core's
`ConnectTip` per block; with ranked peers it is the bottleneck. Every B step
is measured on a **loopback replay** of 800k–900k from the Core oracle
(`replay-loopback-peer-rate-rule`): ~1 h per iteration, `bmc.benchlog=1`,
the `[bench] block` columns are the measurement. No mainnet sync until the
replay numbers move.

### B1. Decompose `put` (measurement first; 1 day)
`put` (`utxo_live.c` Phase 5) = per-output `utxo_lsm_put` + per-input
`utxo_lsm_del` (tombstone) + undo capture + the block-end WAL drain
(`utxo_store_wal_drain`), minus flush and csi. 2–3 µs per input is too much
for a hash insert (a cache miss is ~0.1 µs): the suspects are WAL syscalls,
the undo record write, and tombstone bookkeeping. Add four sub-timers under
`bmc.benchlog` (insert / del / undo / wal), replay, read the split. The
plan for B2 is chosen from this, not before.

### B2. Batch the per-block writes (small, after B1)
Whatever B1 names: one WAL write per block (the buffer exists:
`test_utxo_wal_buffer`), undo records buffered per block and written once
with the END marker (`undo_commit`), tombstones as a per-block append. Target
put ≤ 1.5 µs/input → ~3k s off the chain.
- Test: `test_utxo_crash_recovery` / `_bulk` and `test_undo_log` must still
  pass with a crash injected between the batch write and the marker — the
  batch must not widen the torn window those tests pin.

### B3. Memtable flush off the applier (medium)
A flush (113 × 12 s) sorts the memtable and writes a run inline in a put.
Make it double-buffered: freeze the full memtable, start a new one, a flush
thread sorts and writes the frozen one and publishes the manifest (the
compaction hook already runs in the background — same pattern); `get`
consults new, frozen, then runs. Crash semantics: the frozen memtable's WAL
segment is kept until its run is published, so recovery replays it.
- Test: `test_utxo_catchup_crash_resume` with a kill during the frozen
  flush; `test_lsm_count_drift` (live count across the two memtables).
- Measure: flush column → ~0; the flush line still prints its wall from the
  thread.

### B4. Index work off the applier (medium)
`idx` 1,194 s is the Phase 0.5 index build inside `apply_block_inner`;
txindex 329 s + bfilter 375 s + csi 460 s are the choke-point writers. Core
does these on callback threads (5 s on its validation thread). Give the
choke point a ring: the applier publishes (height, block, undo run) and a
worker builds txindex, bfilter and the address/txospender tails from it —
bfilter needs the spent prevout scripts, which the undo record already
carries (that is why undo is 2.5× Core's). The `[ready]` line already waits
for every index, so the finish line stays honest while indexes trail by a
few blocks during the sync.
- Test: `test_index_trail` extended; `test_bfilter_index` equality against
  the inline build on a 1,000-block regtest chain.

### B5. Header sync: fastest of several (small)
The header phase takes one random peer and waits for the whole chain to pass
`minimumchainwork` before the first block request (5:06 from a 200 KB/s peer
in run 34; Core drew a fast one: 1:15). Probe the first 2,000-header page
from 4 peers in parallel, continue with the fastest, keep the others as
fallbacks. Target ≤ 90 s.

### B6. Optional: a per-block window under `dlshape=core`
108 stall disconnects vs Core's 25: the in-order committer waits for a whole
16-block chunk. Only the benchmark mode is affected; do it if a third pair
is scheduled, otherwise document it as the known difference.

### B7. An eviction the holder never answers (found during run 35; small; done on the branch)
Run 35 at 19:57:44Z: the holder of the window's oldest chunk was "dropped"
twelve times (2 s doubling to 64 s) and never printed its drop line or
released the chunk; nine workers idle at the full window, 64 chunks staged,
the applier at 0 CPU for 7 minutes. Run 34 had it four times, ~20 minutes
each (Core-mode's 1,200 s read timeout), 78 minutes in all — most of what
the pair report called "download-bound under random peers"; B6 above is
smaller than this. The cursor help was published every time and read by
nobody (its only reader was the claim path; `cursorhelp 0` both runs).
Fix: the second eviction of the same holder for the same chunk rings the
chunk from the parent (Core: a disconnected staller's blocks are
re-requested elsewhere at once); the full-window wait loop takes the cursor
help; the eviction signal shuts the worker's socket (`mux_budget_fd`, as the
relay legs); a drop that arrives outside the fetch is acknowledged in the
log instead of being reset silently; the eviction line names the holder's
phase, its age there, and its /proc state, wchan and syscall. Gate:
test_dialhelper (the unanswered-eviction and cursor-taker cases,
revert-checked), test_v2transport (the handshake's second loop gained the
real-time deadline; a trickling peer held it 8 s on a 1 s budget before).
The next ranked run (36) shows `unanswered N` on the status line and no
`[bench] block` gap over 60 s that is not a flush. Open: the exact wait the
worker sat in for 415 s. The log places it outside the fetch (its own
120 s alarm never fired either, and no drop line or failed-fetch line was
printed); the eviction line now answers this on the first recurrence.
Run 35 was stopped at 21:00Z (72%) for the re-run; its logs are in
`bench/run35/` (debug.log copied out of the datadir).

Run 36 (the re-run, on the fix) at 2 h: 20 evictions, every one acted on
within a millisecond, no apply gap over 45 s, the ring path exercised once
(w2 fetched the ringed chunk in 680 ms). Two accounting defects in the fix
itself, read off that log and corrected on
`fix/2026-10-05-eviction-ack-accounting` (not in run 36's binary; neither
touches the run's timing): (1) the parent cannot see the worker's ack, so
"did not answer" was printed on a second eviction whose first WAS answered
(the holder's fresh peer stalled too) — the worker now counts its acks in
`evict_acks`, the parent reads it before and after its signal, and the
second eviction is "reassigned" (answered) or "unanswered" (the run-35
shape), both on the status line; (2) the drop path never cleared the fired
flag, so the next pass's pre-fetch check printed a false "acknowledged late
... in the handshake" after every drop line (20 of 20) and counted each
eviction twice — the flag is consumed with the drop line, and the late-ack
line names the phase the handler saw, not the phase at the check.
And one behaviour change from the same log: the five 30 s pauses the stall
watcher dumped were each the window full on one evicted holder redialing,
shaking hands and refetching its chunk itself (15–30 s) while nine workers
waited and the applier sat at zero lag; the one chunk that reached the
ring was fetched by an idle worker in 680 ms. So (3) the FIRST eviction
rings the chunk (Core re-requests a disconnected staller's blocks at
once), counted as "reassigned" on the status line; the evicted worker
releases the chunk when its redial finds it staged or committed (one
`access()` per dial; "delivered by another worker" line); the second
eviction keeps only its diagnosis (unanswered when the acks did not move).
Expected on run 37: ~20 × 15–25 s = 5–8 min less applier idle.
Test: the rewritten eviction block in `test_dialhelper` (ring at the first
eviction, unanswered vs answered second, no double ring; revert-checked on
the parent side; the worker side has no unit seam — run 37's log is the
check: a "delivered by another worker" line after each drop line, and no
late-ack line beside one).

## Part C — later, not for the first release
- UTXO on disk 12.8 GB vs Core's 10.6: run encoding (compressed scripts and
  varint amounts as Core's `CTxOutCompressor`). Space, not speed.
- Memory and boot-to-RPC time vs Core: unmeasured; a pair of their own.

## Order and sizing

| step | size | gate on |
|---|---|---|
| A1 txindex lane | small | production: waits ≥ 2 s → 0 |
| A2 facade batch | small | same |
| B1 put decomposition | 1 day | the split, in the replay |
| A3 mempool totals | small | 32-client bench |
| B2 batched writes | small | put ≤ 1.5 µs/input |
| B5 header probe | small | ≤ 90 s on a fresh start |
| B3 async flush | medium | flush column ~0, crash tests |
| B4 async indexes | medium | applier ≤ 12k s on the replay |
| A5 heavy reads | medium | 32-client bench |
| A4 150 s freeze | when it reproduces | the named step |
| B6, Part C | optional / later | |

Exit for the whole plan: one ranked-peer mainnet sync (benchlog on) at
≤ 4:45 to `[ready]`, and a week of production with zero exec-lock waits
≥ 2 s under BlockYard and mempool.space.

## 2026-10-06 — run 37 against the targets, and the next holes

Run 37 (main `8e81ffb5`, ranked peers, benchlog): ready at **4:50:52**
against the ≤ 4:45 exit above (6 minutes short), Core 10:42:05; applier
14,602 thread-seconds against the ≤ 12,000 target (Core 13,909); put 5,687
(target ≤ 4,500; split: undo 2,622, ins 1,662, get 928, del 66, wal 59);
headers → first block 1:58 (target ≤ 90 s); exec-lock waits ≥ 2 s: 0 since
the 10-05 deploy; `getmempoolinfo` 5 ms (target ≤ 22). Report:
`docs/reports/2026-10-06-core-vs-bmc-performance-release.md`.

Found by the post-run RPC rows and the run-37 log, in the order to take them:

### A7. getrawtransaction: 14 ms single, 382 ms at 32 clients (Core 4 / 5) — DONE 10-06 (#387, #388)
Done the same morning, measured on production after `deploy-20261006b`:
3 ms single, 5 ms at 32 clients, for a transaction in a run or in the
tail (Core 3 / 5). Three causes, not two: the whole-block verify, the
handler's second read and walk, and -- the one the 05:20Z row could not
see -- the linear scan of the unsorted tail (564 MB on production) for
every recent transaction. The record format did not need to change: the
record already carries the offset and length; the reads just never used
them. The lane is still one reader at a time (its static buffers are
gone, so a reader-writer lock is now possible: A5's lane-width work).
Original note:
The txindex lane admits one reader (shared static 4 MB verify buffers) and
a lookup reads the whole block to extract one transaction. Two steps:
per-thread lane buffers under a reader-writer lock (`irs_refresh` the only
writer) — the 32-client row falls to the single-call cost; then the
transaction's byte offset in the txindex record so the read is the
transaction, not the block — the 14 ms. The second changes the record
format (a rebuild; the builders are in place). Test: the #373 race test
over the rwlock; a differential of 1,000 random txids against the oracle.
### A8. getdeploymentinfo holds the exclusive lock 2.0–2.1 s — DONE 10-06 (#387)
Cached per period boundary with the boundary hash; production: 1.6 s once
after a restart, then 4 ms; 5 ms at 32 clients. Original note:
It re-walks the BIP9 state from genesis on every call (~10k header reads
and MTPs). Cache the state per period boundary as Core's version-bits
cache does; serve from the reader lane. Test: a regtest signalling period
walked cached and uncached gives the same answer. Measure: the hold is
gone from the lock log.
### A5 (rest). getblock v2 at 32 clients: median 597 vs 498, wave 15% faster
The reader lane is narrower than Core's thread pool. Widen the per-thread
lane (more concurrent readers) once A7's rwlock pattern exists; measure the
32-client median.
### B8. The 100 s tail after IBD end has a 62 s pause
Run 37: no block line between 04:55:36 and 04:56:38 while the daemon
switched to live mode (relay dials); the catch-up then finished at
9.7 blk/s. Name the pause (a checkpoint? the dial burst taking the apply
lock?) from the log's split, then move it off the apply path. Small.
### B9. The first 200,000 blocks: Core ahead by ~70 s
Round-trip bound on tiny blocks: bmc asks for 16-block chunks per round
trip, Core pipelines per block. A per-peer in-flight pipeline across chunk
boundaries on the early chain (what `dlshape=core` already does) under the
ranked rules until blocks reach ~100 KB. Measure: the 100,000 and 200,000
milestones.
### M1. Memory: name the 26 GB
Anonymous memory held 26.4 GB through the sync with dbcache=8192 (peak 35.2
GB in a compaction). A per-subsystem `[mem]` line under benchlog at the MEM
marks (memtable, header tree, download window, index builders, RPC caches),
and the Core rerun WITH the sampler so the row has two sides.

Order (A7 and A8 done 10-06): B4 → B3 (the applier target) → B8 → A5 →
B9 → M1 alongside the Core rerun.
Exit for the next release run: ready ≤ 4:30, applier ≤ 12,000 s,
getrawtransaction ≤ 10 ms at 32 clients, no exclusive hold ≥ 1 s.
