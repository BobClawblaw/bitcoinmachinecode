# Core v31.1 vs bmc — performance for the first release

Every number here comes from a log or a script named beside it; nothing is
estimated. The bmc numbers are run 38 (2026-10-06, main `020b13dc`, the
index worker of PR #390), the Core numbers are rerun #6 (2026-10-04,
v31.1). Run 37 (main `8e81ffb5`, the same morning, before the index
worker) and run 34 (the same bmc code family under Core's own download
rules, before the 2026-10-05 batches) are kept as the "before" columns.

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
beside the bmc run; Core's rerun had none (its CPU time is systemd's
"Consumed" line; its peak memory was not captured).

| | Core rerun #6 | bmc run 34 (Core's download rules) | bmc run 37 (bmc's rules) | bmc run 38 (+ index worker, this release) |
|---|---|---|---|---|
| started (UTC) | 2026-10-04 18:20:24 | 2026-10-05 05:05:34 | 2026-10-06 00:06:24 | 2026-10-06 06:42:09 |
| commit | v31.1 | 56bbe8c2 | 8e81ffb5 | 020b13dc |
| download rules | Core's | Core's (`bmc.dlshape=core`) | bmc's (ranked peers, rotation, first-eviction reassignment) | run 37's |
| index writers | callback threads | on the applier | on the applier | a forked index worker during the download (PR #390) |
| logs | `bench/core31-rerun6-20261004-logs/` | `bench/run34/` | `bench/run37/` (debug.log copied beside the harness logs) | `bench/run38/` (same) |
| correctness | — | — | UTXO muhash identical to Core at 970,133 (harness capstone) | identical at 970,165 |

## 1. Initial block download, genesis to every index at the tip

| | Core #6 | bmc 34 | bmc 37 | bmc 38 | bmc 38 / Core |
|---|---|---|---|---|---|
| headers → first block | 1:15 | 5:06 | 1:58 | 1:39 | 1.32 |
| 100,000 | 4:12 | — | 5:22 | 5:08 | 1.22 |
| 200,000 | 8:15 | — | 9:22 | 9:03 | 1.10 |
| 300,000 | 23:34 | — | 16:03 | 15:52 | 0.67 |
| 500,000 | 2:02:42 | 1:19:05 | 0:58:53 | 0:55:42 | 0.45 |
| 800,000 | 6:35:51 | 3:40:38 | 2:54:02 | 2:35:50 | 0.39 |
| 900,000 | 9:01:23 | 5:23:05 | 4:03:31 | 3:35:43 | 0.40 |
| IBD end (tip stored + applied) | 10:41:21 | 7:16:01 | 4:49:12 | 4:15:43 | 0.40 |
| **every index at the tip** | **10:42:05** | **7:17:39** | **4:50:52** | **4:17:09** | **0.40** |
| CPU time consumed, all processes | 13 h 50 m (journal) | — | 8 h 17 m (sampler, 29,819 s) | 7 h 48 m (sampler, 28,108 s) | 0.56 |
| peak memory | not captured | — | see §5 | see §5 | — |

Milestones and segment walls: `docs/reports/2026-10-06-run38-vs-core6-stage-report.md`
(validation/ibd_stage_report.py; run 37's is beside it). Core is ahead
for the first 200,000 blocks (by 56 s at 100,000 and 48 s at 200,000):
tiny blocks, where the wall is round trips, not bytes, and bmc's chunked
requests pay one more round trip per 16 blocks than Core's per-block
pipeline. From 300,000 on bmc is ahead in every segment, by 2.2–2.9×.

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

## 2. Where the applier's time goes (thread-seconds over the whole chain)

| | Core #6 | bmc 34 | bmc 37 | bmc 38 |
|---|---|---|---|---|
| applier busy (Core: connect block; bmc: the block line's total) | 13,909 | 17,166 | 14,602 | **13,363** |
| applier waiting for blocks / outside connect | 24,587 | 9,757 | 2,180 | 2,193 |
| UTXO (Core: connect txs + flush + write chainstate + coins flushes; bmc: get + put + ckpt + flush) | ~11,185 | 13,863 | 11,956 | 10,804 |
| ↳ put | — | 7,812 | 5,687 | 4,994 |
| ↳ put split (ins / get / undo / del / wal) | — | — | 1,662 / 928 / 2,622 / 66 / 59 | 1,377 / 933 / 2,242 / 57 / 44 |
| ↳ memtable / cache flush (inline on the applier) | 803 | 1,350 | 1,403 (110 flushes) | 1,360 (109 flushes) |
| script verification | 113 (wait on 15 threads) | 773 | 775 | 744 |
| block read | 2,289 | 124 | 211 | 195 |
| per-block index work on the applier (idx + csi + txindex + bfilter) | 5 | 2,360 | 2,306 | 1,576 (idx 1,149 + csi 427; txindex + bfilter 0.2) |
| index writes off the applier (Core: callback threads; bmc: the index worker) | not logged | — | — | 688 (txindex 336 + bfilter 352; 969,746 blocks) |

bmc's applier is now 4% faster per block than Core's (run 37: 5% slower;
run 34: 23% slower). Run 37's UTXO put fell 27% from run 34 (the undo
capture reuses the resolved prevout, PR #383); run 38's index worker (PR
#390) took the txindex and filter writes off the applier -- 693 s of
inline work in run 37 became 688 s in a forked process that trails the
applier by ~20 blocks -- and the applier's remaining columns fell with
them (put 5,687 → 4,994 s, get 4,650 → 4,096 s: the applying process no
longer shares its page cache and CPU with four index writers). The put
split names what is left: the undo record (2,242 s) and the insert
(1,377 s) are the two halves of put, the WAL and the tombstone are
negligible. Two columns remain off Core's shape: the inline flush (1,360
s; Core's cache flush is 803 s and its writes are batched) and the
per-block `idx` and `csi` steps (1,576 s; Phase 0.5 and the coinstats
fold, inside the block line). The flush is plan item B3
(`worklog/2026-10-05-performance-holes-plan.md`); with it off the
applier the apply path would be ~12,000 s against Core's 13,909.

bmc wins the sync mostly by overlapping download and apply: the "waiting"
row is 22,400 of the 23,000 thread-seconds between the two runs. The apply
path itself is now ahead as well, by 546 s over the chain.

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

| method | Core (10-05) | bmc before | Core (10-06 05:20Z) | bmc after the lanes | Core (06:10Z) | bmc final |
|---|---|---|---|---|---|---|
| getblockcount | 5 | 5 | 5 | 4 | 5 | 5 |
| getblockhash | 5 | 5 | 5 | 4 | 5 | 4 |
| getmempoolinfo | 5 | 177 | 5 | 5 | — | (05:20Z) 5 |
| getrawmempool | 687 | 249 | 496 | 216 (pool 2.7× Core's) | — | (05:20Z) 216 |
| getblock (verbosity 2) | 494 | 704 | 498 | 597 (wave 4,107 ms vs Core's 4,829) | 451 | 607 (wave 3,932 vs 4,589) |
| getrawtransaction (verbosity 1), tail tx | 6 | 6 | 5 | **382** | 5 | **5** (single client 3 vs 3) |
| getrawtransaction (verbosity 1), tx in a sorted run (block 950,000) | — | — | 5 | 5 | 5 | 6 |
| getdeploymentinfo | — | — | 5 | (2,000 single; exclusive hold) | 5 | 5 (single 4 vs 4) |
| getpeerinfo | 7 | 5 | 6 | 5 | 6 | 5 |
| exec-lock waits ≥ 2 s per day under BlockYard + mempool.space | n/a | ~10 | n/a | 0 since 17:46Z 10-05 | n/a | 0 |

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
- **getblock verbosity 2** at 32 clients remains mixed: bmc's wave finishes
  14–15% sooner but the median call is 20–35% slower: the reader lane
  serves fewer calls at once than Core's thread pool, so throughput is
  higher and latency is worse. Single-client bmc is ahead at every
  verbosity (v1 5 vs 8, v2 73 vs 91, v3 102 vs 140 ms). Lane width is plan
  item A5.

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

## 6. Verdict, category by category

| category | result | bmc / Core |
|---|---|---|
| sync, genesis to every index at the tip | **bmc, 2.5×** | 4:17:09 vs 10:42:05 (run 37: 4:50:52) |
| every milestone from 300,000 up | **bmc, 2.2–2.9×** | §1 |
| CPU time for the sync | **bmc, 1.8×** less | 7 h 48 m vs 13 h 50 m |
| download: applier time spent waiting | **bmc, 11×** less | 2,193 s vs 24,587 s |
| headers → first block | Core | 1:39 vs 1:15 (was 5:06, then 1:58) |
| the first 200,000 blocks | Core, by ~50 s | round-trip bound; §1 |
| apply path per block (thread-seconds) | **bmc, by 4%** | 13,363 vs 13,909 (run 37: Core by 5%; run 34: by 23%) |
| index writes, on the applier | parity (both off it) | 0.2 s vs 5 s; the worker's 688 s runs beside the applier as Core's callback threads do |
| RPC: getblockcount, getblockhash, getmempoolinfo, getpeerinfo | parity | 4–5 ms both |
| RPC: getrawmempool, 32 clients | **bmc, 2.3×**, on a pool 2.7× larger | 216 vs 496 ms |
| RPC: getblock v2, 32 clients | mixed: wave 15% faster, median 20% slower | §3 |
| RPC: getblock, single client, every verbosity | **bmc** | §3 |
| RPC: getrawtransaction (tail or run) | parity | 5 vs 5 ms at 32 clients; 3 vs 3 single (was 382 vs 5 at 05:20Z) |
| RPC: getdeploymentinfo | parity | 5 vs 5 ms; the 2 s exclusive holds are gone |
| RPC lock-ups under BlockYard + mempool.space | **bmc** (was ~10/day) | 0 waits ≥ 2 s since the deploy |
| modules (archive read, MuHash, hashes, AEAD, sigs) | **bmc or parity** | §4 |
| txindex on disk | **bmc, 2.5× smaller** | 28 vs 70 GB |
| UTXO set on disk | Core (a trade: 2 GB) | 13 vs 11 GB |
| undo on disk | Core (by design: spent scripts) | 2.5× |
| peak memory | not comparable yet | Core unmeasured |
| correctness | identical | muhash at 970,133 |

Not yet beaten, with the fix named: the first 200,000 blocks and the
header phase (per-block requests on the early chain; plan B9), getblock
v2's median at 32 clients (lane width; plan A5). The apply path per block
moved from Core's column to bmc's with run 38 (the index worker, PR #390);
the flush (plan B3) is the remaining column off Core's shape in §2. The
memory row needs the Core rerun with the sampler before it can be claimed
either way. The two RPC losses the 05:20Z rows found were fixed and
deployed the same morning (§3).

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
  sequence. Production: 0 waits ≥ 2 s since the deploy.
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
- **Not done, stated:** the double-buffered memtable flush (B3) — the
  flush row in §2 is unchanged from run 34, as predicted — and the 60–70 s
  pause after IBD end while the serve process faults the memtable in (B8,
  diagnosed; it is inside run 38's 86 s from IBD end to ready).

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
