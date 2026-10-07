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

**BUILT 10-06 (branch perf/2026-10-06-b3-async-flush; gate and run 40 pending):**
not a second memtable -- the applier copies the live table + blob prefix
into a private copy and forks a writer that builds the run from it
(`utxo_lsm_freeze` / `utxo_lsm_build_run`, `bmc.asyncflush`, default on);
reads consult live → frozen → runs; the WAL is retired by a `utxo.idx`
checkpoint offset + a punched hole, never truncated. Two reload defects
fixed on the way (tombstone pass from byte 0; the idx not emptied by an
inline flush). Design as built: worklog/2026-10-05-b3-b4-design.md, last
section. Expected: the per-block `flush` stage becomes the copy
(~0.3-0.6 s × ~109) and the applier drops ~1,200 thread-seconds.
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

**Gate finding (10-06 18:08Z, integration tree main + M1 + B8 + B3):**
`tests/test_utxo_lost_tombstones_bad` (the 2026-09-01 incident's repro with
the b3d47a9 object) failed under the async flush: 701 blocks, 0 rejects, walk
exact, no halt, 114 of 31,904 spent coins read back as live. The incident is
the inline flush's shape: the flush lands mid-block and the same block's later
spends look their coins up in the run it just wrote. Under the async flush the
frozen copy answers every lookup until the writer's run is adopted at a block
boundary, so a lying run first meets a later block's verify pass (a missing
input, a rejected block, never a skipped spend); the 114 were point lookups
of the adopted runs missing their tombstones (a compaction rewrote the
offsets and the count went to 0; the walk was exact throughout). The arm now
sets `g_cfg.async_flush = 0` and pins the inline path, which is still shipped
(bmc.asyncflush=0, build_utxo, the tools); the shipped-object arm keeps the
default (dfc41338 on the branch).

**Run 40 (10-06/07, main b194dd01, the full sync with the fix):** 112
freezes of 0.47–0.68 s each on the applier (p50 680 ms; the first one
11.9 s at block 228,769, gen 0: the copy's pages faulted in on first
touch — a touch pass or MAP_POPULATE at init would take that off the
first flush), 97 s in all; the writer's run build 13.6 s median (0.3–25.5
s), 1,545 s in the forked child, 187 GB of runs; every adopt line `waits
0, inline 0`; no WARNING. The flush column 1,357 → 131 s. The applier
total still rose, 14,060 → 14,650 s: put 5,661 → 7,135 s (ins 1,845 →
2,621, undo 2,463 → 3,079), the third rise in a row for the same put code
(run 38: 4,994). Not the writer: per 1,000 inputs the insert cost 0.77 ms
in the blocks applied while a writer child was alive (the 30 s after each
freeze, blocks 300,000+) and 0.74 ms in the rest. The tree's CPU rose by
the writer's 1,545 s and little else (28,535 → 30,218 s), so the extra
1,475 s of put was waited for, not computed. See B11. B3 itself: done.

**Production, steady state (10-07 01:16Z, found by the other session on
deploy-20261006d):** the writer is reaped only by `fz_poll`, and `fz_poll`
runs only per applied block (utxo_live.c, the per-block call in catch-up
and the post-catch-up call), both firing right after the fork, before the
writer has exited. At the tip the writer (3.9 MB run, written in ms) sat
as a zombie for the whole block interval; the adopt, the WAL hole-punch
and the frozen copy's release lag by one block (10 min to 1 h+). Safe (a
crash replays the WAL, the hook waits before the next freeze, shutdown
reaps) but not the shape intended: poll from the idle heartbeat or on
SIGCHLD (the compaction child's `compact_poll` has the same shape). Small;
after Core #7, with B10.

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

**Measured 10-06 (after run 38), before building anything:** both nodes
answer from a 4-thread pool (`rpcthreads` default on both; the oracle's
conf sets none), bmc's listener took no overflow during a 32-client wave
(`nstat TcpExtListenOverflows` unchanged), and the latency distribution is
the FIFO model's: median 600, p90 664 = 32/4 × the 75 ms single call.
Core: median 491, p90 669, single 100 ms. So the lane is not narrower --
the per-call cost under load is the lever, and it is CPU. perf on a
micro-benchmark of the render (block 969,000, 3,573 tx, 6.8 MB of JSON
without the per-tx hex): malloc/free 35% (malloc_consolidate 14%,
unlink_chunk 7%, _int_malloc/_int_free 9%), the byte-at-a-time string
escaper 11%, the descriptor checksum 7%, bech32 5%, hex_of 4%, printf 2.5%.
Fix (branch perf/2026-10-06-a5-json-arena): a per-request bump arena for
every rj_val the server builds (begun in `render_request`, released after
the body is written; rj_free of an arena value is a no-op), a span-copying
escaper, a hand integer formatter for the seven integer formats, `rj_hex`
(hex encoded straight into the value instead of malloc + copy + free), a
per-thread txid scratch (a malloc per transaction went to mmap above 128
KB), and the three places that freed JSON internals by hand (rest.c's
obj_del, grt_splice, the decoderawtransaction strip) moved into
`rj_obj_del`/`rj_obj_splice`. Micro-benchmark: build+write+free 37 → 26
ms. Core's UniValue pays the same allocation shape; the arena is the
classic answer. Measure after the deploy: the 32-client median and the
single call against Core in the same minute.
**DONE 10-06 (#392, deploy-20261006c 11:59Z, thirteen saved responses
byte-identical):** 12:02Z pair, two waves each: median 441 / 483 vs Core
449 / 459 (parity: the FIFO median is 8 × the service time on both), p90
487 / 521 vs 641 / 586, wave 3,187 / 3,224 vs 4,473 / 4,436 ms; single
call 58 vs 87 (was 73). v1 at 32 clients 9 vs 19; v3 single 84 vs 126;
getrawmempool 114 vs 484 on pools of the same size (26.8k vs 25.5k).
What is left in the render (perf under the arena): the descriptor
checksum 9%, bech32 7%, sha256 5% -- Core pays the same three.
### B8. The 100 s tail after IBD end has a 62 s pause — BUILT 10-06 (branch perf/2026-10-06-b8-chainwork-in-step; gate pending)
**Re-read on run 38 (10-06, 10:57:52 → 10:58:58), the run 37 reading
below was wrong about the cause:** the sampler shows the daemon's RSS
FLAT (82.8 GB) and its CPU idle (1 s per 6 s tick) across the 66 s gap,
while the stall watcher shows one reader at queue depth 1 pulling
~250 MB per 5 s (3.3 GB in all, io_ms ≈ wall). Nothing was faulting a
map; one thread was blocked on small reads. The code between the gap's
two log lines ("[dl] parallel downloader wrote" and the first catch-up
block) is the rotation's `reorg_chainwork_sync(store_buf, 0)`: the
parallel download never appends a chainwork record (run 39's
chainwork.dat was 16 bytes two hours in), so the first rotation after the
download walks every height from 1 to the tip with an 80-byte pread into
blk files long out of the page cache — 970 k reads × ~68 µs (NVMe latency
at queue depth 1) = 66 s, 3.4 KB read per record (one page each). Fix:
`dl_catchup` runs a bounded sync (65,536 records) every pass, on the
heights the committer wrote seconds earlier and still has in cache, and
an unbounded one at the download gate, logged as "[dlc] chainwork in step
with the archive at the download gate: N record(s) appended during the
download". test_dlc_interleave asserts one record per stored height at the
gate in both arms. Expected: the IBD_END → ready tail drops from 86 s to
~20 s (14 s drain + 3 s flush + 3 s index gaps).
Run 37's sampler and stall watcher over 04:55:36–04:56:38: the catch-up's
applier (the dlc child) finished; the serve process took the remaining 694
blocks ("applying before syncing legs") and sat in state D
(folio_wait_bit_common) for a minute while its RSS grew 48 → 74 GB and the
box read 11 GB -- the shared memtable (utxo_lsm_blob.map 6 GB +
table.map 1.6 GB) and the run set being faulted into the serve process
before its first block; no compaction ran in that window (the 13 GB merge
started at 04:57:22, after the downshift). Dirty pages were 27 MB, so not
writeback throttling. Fix: apply the drain in the process that already
holds the set (the dlc child), or pre-fault the maps in the serve process
while the download still runs. ~60 s once per sync; after B3/B4.
Original note:
Run 37: no block line between 04:55:36 and 04:56:38 while the daemon
switched to live mode (relay dials); the catch-up then finished at
9.7 blk/s. Name the pause (a checkpoint? the dial burst taking the apply
lock?) from the log's split, then move it off the apply path. Small.

**Run 39 (10-06, main 7eb763ab, without the fix):** the same gap again,
65 s between `[dl] parallel downloader wrote` (17:44:13.4) and the first
drained block (17:45:18.5); the tail was 97 s from IBD end to ready (drain 23
s, downshift flush, latch, index gaps). The test's two record assertions fail
with both sync sites disabled (revert check 18:00Z).

**Run 40 (with the fix):** the gate line `[dlc] chainwork in step with
the archive at the download gate: 970229 record(s) appended during the
download` at 01:15:01.9, `parallel downloader wrote` at 01:15:02.787, the
first drained block line at 01:15:03.336: 0.55 s against run 39's 65 s.
The drain of the remaining 629 blocks took 23 s (to 01:15:26). The tail
to ready was still 99 s: at 01:15:40 the rotation probed the pool again
(161 live peers, 1 round), ranked it by a 2,000-header sample in 22.3 s,
and fetched the 37 blocks that had arrived during the sync (01:16:03 →
01:16:28); ready at 01:16:41. The ~62 s of re-probe and re-rank for 37
blocks is a new item (B10). B8: done.

### B9. The first 200,000 blocks: Core ahead by ~70 s
Round-trip bound on tiny blocks: bmc asks for 16-block chunks per round
trip, Core pipelines per block. A per-peer in-flight pipeline across chunk
boundaries on the early chain (what `dlshape=core` already does) under the
ranked rules until blocks reach ~100 KB. Measure: the 100,000 and 200,000
milestones.

**Read from run 38's log 10-06, before building anything:** of the 99 s
from boot to block 1 (Core: 75), 49 s were the peer RANKING (`ranked 141
live peer(s) by a 2000-header sample in 48.8s`: probes 32 to a batch, each
batch waiting for its slowest member, 49 of 141 silent → nearly every batch
sat out the 10 s alarm), 8 s the liveness round (its full timeout, waiting
on 20 dropped SYNs), 37 s the header download from the best peer at 2.0
MB/s (held pages stored once the chain crosses minimumchainwork -- no
redownload, which is where Core spends its own 75 s: presync + redownload),
3 s to the first block. So the early-chain chunk shape is at most the
remaining ~30 s of the 100,000 gap (3:29 vs Core's 2:57 for the blocks
themselves); the pre-block minute was the probe.
Part 1 (branch perf/2026-10-06-a5-json-arena, with A5): the ranking
probes run up to 128 at once and are reaped as they finish (alarm 6 s: the
slowest answering peer took 3 s), so the ranking takes one silent peer's
timeout; the liveness round ends after 2 s of quiet once 10 connects have
completed (`DLC_PROBE_QUIET_MIN/MS`, dlc_rules.h). Expected on run 39:
boot → block 1 ≈ 55–60 s against Core's 75. Verify in the log: the
"ranked ... in N s" line and the liveness line's timing.
**Measured 10-06 12:03Z on the A/B's control arm (main 01d235f6, a fresh
sync):** liveness 135 live in 2.3 s (was 8.0), ranking 7.0 s (was 48.8;
87 of 135 answered, best 1393 KB/s), headers 36 s, block 1 at 50.5 s
after boot (run 38: 99 s; Core #6: 75 s).
Part 2 (`bmc.dlcrollbelow`, PR #392, default 0 = off): the rolling
16-in-flight fetch under the ranked rules below a height threshold.
**A/B'd 10-06 12:02–13:07Z** (validation/ab_dlcchunk.sh, main 01d235f6,
four fresh syncs to 300,000 one after another, chunk 16, production
running beside them as on every run; /srv/nvme8tb/bench/ab-roll):

| arm | 50k | 100k | 150k | 200k | 250k | 300k |
|---|---|---|---|---|---|---|
| ctl16a (off) | 165 | 256 | 371 | 501 | 716 | 941 |
| roll16a (rollbelow=300000) | 195 | 295 | 410 | 550 | 801 | 1066 |
| roll16b (rollbelow=300000) | 165 | 255 | 370 | 490 | 715 | 941 |
| ctl16b (off) | 170 | 260 | 375 | 495 | 715 | 900 |

The rolling arm is a 13% loss or a tie, never a win; the two control arms
agree within 4%. **Decision: the default stays 0; part 2 is closed.** The
knob stays for the dlshape=core comparison. What the control arms also
say: with part 1 the first 200,000 blocks are at Core's pace (100,000 at
4:16/4:20 against Core #6's 4:12; 200,000 at 8:21/8:15 against 8:15; run
38 had 5:08 and 9:03) -- the ~50 s Core had on the early chain was the
probe minute, not the request shape. Run 39 confirms on a full sync.

**Run 39 (10-06, the full sync of the #392 build):** boot to block 1 in
49.6 s (liveness 5.8 s, ranking 8.2 s, headers 35.3 s) against run 38's 99 s
and Core's 75; 100,000 at 4:15 and 200,000 at 8:14 against Core's 4:12 and
8:15. Part 1 is measured. Open question from the same run: the download
churned peers (81 distinct against run 38's 25; the pool banned 22 of 135 by
the end against 4 of 141; per-chunk wait sum 5,160 s against 3,591; chunk wall
p50 0.94 s against 0.39) and ready came 17 minutes after run 38's. With every
probe in flight at once the ranking's per-peer rate is a share of the box's
uplink, not the peer's, which would put slow peers at the top of the ranking.
Not isolated: the applier's own columns rose by 700 s in the same run (memtable
insert and undo capture) with PR #392 touching neither. Run 40 is the next
data point; if the churn repeats, rank by a second, staggered sample.

**Run 40:** boot to block 1 in 46.5 s (liveness 4.0 s, ranking 8.6 s,
headers 33.3 s); 100,000 at 4:16, 200,000 at 8:12 (Core 4:12 / 8:15). The
churn repeated: 70 distinct chunk peers (run 39: 81, run 38: 25), chunk
wait sum 6,790 s (5,160; 3,591), chunk wall p50 0.80 s (0.94; 0.39) — and
this time with no bans at all (`banned 0/161` at the end against 22/135),
so the churn is the ranking's, not the eviction's. Part 1 (rank by a
second, staggered sample so each peer's rate is its own and not a share
of the uplink) stays open; A/B to 300,000 after Core #7, the distinct
peer count and the wait sum are the metrics.

### M1. Memory: name the 26 GB — BUILT 10-06 (branch perf/2026-10-06-m1-mem-naming; gate pending)
Anonymous memory held 26.4 GB through the sync with dbcache=8192 (peak 35.2
GB in a compaction). A per-subsystem `[mem]` line under benchlog at the MEM
marks (memtable, header tree, download window, index builders, RPC caches),
and the Core rerun WITH the sampler so the row has two sides.

**Read on run 39 (10-06 15:20Z, two hours in), before building:** the 26 GB
was the sampler's arithmetic, not the node's memory. `proc_sampler.sh`
summed smaps_rollup's `Anonymous` across the tree, and that field counts
a forked child's inherited copy-on-write pages once PER CHILD: the
download worker's 13 children (10 dlc helpers, the committer, the index
worker, the coinstats worker) each reported 1,479 MB "Anonymous" of
which 1,476 MB was `Shared_Dirty` (the worker's pages) and 113 MB their
own share (`Pss_Anon`). The tree's real anonymous footprint by `Pss_Anon`
was ~10 GB: the worker 8.3 GB (the flush scratch 6.1 GB virtual, the
tombstone list 1.1 GB, the tombstone hash 0.5 GB, the inherited block
hash index 0.4 GB), the serve parent 0.16 GB, the children 0.11 GB each.
The 35.2 GB "compaction peak" was one more copy of the worker's set (the
compaction child), and "anon rose to 44.9 GB after ready" the same fork
arithmetic on the downshift's compaction. Core is one process, so its
figure never had the inflation; the memory rows before run 40 compare an
inflated bmc number with Core's.
Built: (1) the sampler sums `Pss_Anon` (header comment says why; the
`pss` column was always right); (2) `benchlog_mem_line` reads
/proc/self/smaps and prints this process's Pss by mapping, largest first,
at the two marks under bmc.benchlog — `[mem] at IBD end: pss N MB (anon
A, file F, shmem S) | utxo-flush-scratch N | utxo_lsm_blob.map N | ... |
other N`; (3) the big anonymous regions are named with prctl
PR_SET_VMA_ANON_NAME (kernel 5.17+; a no-op elsewhere) at their
allocation: utxo-tombstones, utxo-flush-scratch, utxo-manifest,
utxo-tomb-hash (the asm's mmap, named from C after init), block-hash-index
(main.c, inherited by every fork), txdv-table/-blob/-tombstones/-flush-scratch
(tx_accept's boot snapshot), dlc-stage (the committer), dlc-side/dlc-hold
(each helper's pipeline buffers). The file maps (utxo_lsm_table.map,
utxo_lsm_blob.map, the runs, the archive) already carry their names.
test_benchlog maps 48 MB, names it bl_probe and expects it in the line by
name and size. B3's frozen copy gets "utxo-frozen" once the branches meet.

Order (A7, A8 and B4 done 10-06): B3 (the applier target) → B8 → A5 →
B9 → M1 alongside the Core rerun.
Exit for the next release run: ready ≤ 4:30, applier ≤ 12,000 s,
getrawtransaction ≤ 10 ms at 32 clients, no exclusive hold ≥ 1 s.
Run 38 (B4, 10-06 11:00Z): ready **4:17:09** (exit met), applier 13,363 s
(Core 13,909; target 12,000 still open: the flush, B3), getrawtransaction
5 ms, no exclusive hold ≥ 2 s on production.

**Run 40:** `[mem] at IBD end: pss 40667 MB (anon 2716, file 37880,
shmem 70)` with the mapped runs named (utxo_run_000096.dat 12,807 MB,
seven generation runs of 1.6–1.7 GB, utxo_lsm_blob.map 1,619 MB); `[mem]
at ready: pss 42074 MB (anon 3660, file 38256, shmem 157)`. The sampler
(Pss_Anon): 9.6–11.4 GB anonymous through the sync, peak 22.1 GB during a
compaction at 21:47Z, PSS peak 67.9 GB in the same minute; the RSS peak
of 245 GB at 01:15:55Z is the top-up round's 27 forked probes each
counting the worker's pages (the Pss columns are the honest ones). M1:
done; the Core side comes from rerun #7's sampler.

### B4 — built 2026-10-06 (branch perf/2026-10-06-b4-index-worker)
`daemon/index_worker.{c,h}`: the applier pushes (BLOCK h) onto a 1,024-slot
ring in the shared status block after each connected block; a forked
worker reads the block from the archive, runs the four writers (txid tail,
txospender tail, filter index, address journal) and publishes the
watermarks the `[ready]` line reads while it runs. The trailing builders'
fold callbacks go through the ring as ADV records so the process holding
the tail's fd is the one that rotates it. STOP drains the ring at the end
of dl_catchup; the parent then re-boots its own writer state from the
files (`txit_close`/`tsp_close`/`axt_close` + the boots, `bfi_close`). A
dead worker is noticed at the next push (0), the writers are re-booted,
and the block is indexed inline. At the tip the writers run inline as
before. Not moved: the choke's own block read (ZMQ, mempool, notify hooks
still need it), `csi` (inside the block line), `idx` (Phase 0.5, not
movable). Test `tests/test_index_worker` (order across BLOCK and ADV
records in the worker's pid, reload-retry, backpressure, STOP drain, a
killed worker, SIGTERM ignored); revert-checked with three mutants (5, 3
and 6 FAIL). Measurement: the next ranked run's §2 -- ix txindex/bfilter
columns go from the applier's 693 s to the worker's lines, the applier's
wall by as much.

**DONE 10-06, run 38 (main `020b13dc`, PR #390 merged):** ready 4:17:09
(run 37: 4:50:52), applier 14,602 → 13,363 s against Core's 13,909 -- the
apply path is ahead of Core's for the first time. The worker indexed
969,746 blocks (txindex 336 s + bfilter 352 s in its own process), trailed
the applier by ~20 blocks, stopped within 1 s of the download's end, no
unreadable block, no death. The applier's other columns fell too (put
5,687 → 4,994, get 4,650 → 4,096): the applying process no longer shares
its cache with the writers. Follow-ups in the same batch: the worker's
started/stopped lines printed without a timestamp (`log_ts.h` after
`<stdio.h>`); `validation/ibd_stage_report.py` brackets the index lines
between the worker's started/stopped lines into an `ixw` column (off the
wall) with a selftest check and a mutant (3 FAIL).

## 2026-10-07 — run 40 against the targets, and the next holes

Run 40 (main b194dd01, B3 + B8 + M1; 20:34Z → 01:16Z): PASS 970,267,
ready 4:42:41, 2.3× Core; the applier 14,650 s against Core's 13,909 (5%
behind) with the flush off it; details above under B3, B8, B9 and M1 and
in `docs/reports/2026-10-06-core-vs-bmc-performance-release.md` (§1, §2,
§5, §6, §7) and `docs/reports/2026-10-07-run40-vs-core6-stage-report.md`.
The box during the run, for the record: production bmcbitcoind
(deploy-20261006d), mempool-backend (restarted 21:33:41Z with a 16 GB
heap by the other session, heavy for 78 s at ~block 508,000), BlockYard,
a vLLM server holding 30 GB of GPU memory with 4.5 GB of its host memory
in swap, the 8 GB swap file full the whole time, 85 GB of page cache.
None of it is ours to stop; Core rerun #7 (started 01:24:50Z, with the
sampler) runs on the same box in the same state, which is what makes the
pair comparable.

### B10. The top-up round after the download re-probes and re-ranks the whole pool (run 40: ~62 of the 99 s tail)

The parallel download ends at the archive tip the gate knew (970,229);
the blocks that arrived during the 4.7 h sync (37) are fetched by the
rotation's next pass, which first runs the full liveness probe (161
peers) and the 2,000-header ranking (22.3 s) as if the pool were unknown.
Fix: when the pool was ranked within the last few minutes and the top-up
is under a window's worth of blocks, reuse the ranking (or let the
download gate extend itself to the current header tip before it closes).
Small. Measure: the tail from `parallel downloader wrote` to `[ready]`,
99 s → ~40 s.

### B11. The memtable's backing: file-backed shared mappings, and a put column that moves 2,141 s between runs of the same code

Evidence: put 4,994 / 5,661 / 7,135 s over runs 38 / 39 / 40 (ins 1,377 /
1,845 / 2,621; undo 2,242 / 2,463 / 3,079) with no change to the put path
between them; the per-input cost the same with and without a writer child
alive (run 40); the tree's CPU flat apart from the writer, so the time is
waited, not computed; and the table and blob are `mmap(MAP_SHARED)` on
`utxo_lsm_table.map` / `utxo_lsm_blob.map` (utxo_live.c, `mmap_file`),
2^25 slots and 6 GB of blob in bulk mode: every insert dirties a file
page the kernel writes back, and under page-cache pressure (85 GB of
cache, the swap full, the mapped runs competing) a reclaimed page is
re-faulted from the file on the next touch. The writer side appears never
to read the files back: the boot and every inbound child rebuild their
view by `utxo_lsm_reload`, a WAL replay from the checkpoint (the header
comment of utxo_live.c) — to be confirmed in the asm before anything
changes. A within-run check was tried and is not usable: put.ins per
input rises with height on its own (more outputs per input late in the
chain), so only the same blocks across runs compare.

Change: back the live table and blob with anonymous private memory
(`MAP_PRIVATE|MAP_ANONYMOUS`, `madvise(MADV_HUGEPAGE)`: the box's THP
mode is `madvise`, and the frozen copy already asks for it), the WAL as
the sole durability, `utxo_lsm_reload` unchanged. The tools that map the
files (build_utxo, utxo_probe_one, utxo_dump_keys, utxo_repair_del,
utxo_setinfo's size probe) keep the file path or read the WAL;
archive_verify's file list loses two entries. Risk: a crash loses nothing
the WAL does not hold, if the files were indeed never read back; the
reload path must be shown to rebuild a full generation (test: kill -9
mid-generation, reboot, compare the walk to the oracle; the async-flush
test's crash phase covers the adopt window).

Measure: A/B to 300,000 after Core #7 (two arms in the same hour, the
box quiet): put.ins and put.undo per 1,000 inputs at the same heights;
then a full run. Target: put at or under run 38's 4,994 s, which puts the
applier at ~12,500 s against Core's 13,909.
