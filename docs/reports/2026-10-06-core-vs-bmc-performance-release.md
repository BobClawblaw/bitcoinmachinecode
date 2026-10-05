# Core v31.1 vs bmc — performance for the first release

DRAFT, being filled as run 35 completes. Every number here comes from a log
or a script named beside it; nothing is estimated.

## 0. Setup

One machine, both nodes one at a time for the sync, both live for the RPC
rows. Core v31.1 from source (`/storage/bitcoin-core-v31.1`), bmc from main
(commit filled in below). Sync runs: fresh datadir on the same NVMe
(/srv/nvme8tb), `dbcache=8192`, txindex + coinstatsindex + blockfilterindex,
assumevalid = the chain default on both (both logs show scripts skipped
through 938,343), 10 download peers, 1,024-block window. Core: `debug=bench`,
`debug=coindb`, `logtimemicros=1`. bmc: `bmc.benchlog=1`. The finish line on
both sides is "every index at the tip": Core's first `getindexinfo` after its
`UpdateTip` at the oracle's tip; bmc's `[ready]` line.

| | Core rerun #6 | bmc run 34 (Core's download rules) | bmc run 35 (bmc's rules, optimized) |
|---|---|---|---|
| started (UTC) | 2026-10-04 18:20:24 | 2026-10-05 05:05:34 | |
| commit | v31.1 | 56bbe8c2 | |
| download rules | Core's | Core's (`bmc.dlshape=core`) | bmc's (ranked peers, rotation) |
| logs | `bench/core31-rerun6-20261004-logs/` | `bench/run34/` | `bench/run35/` |

## 1. Initial block download, genesis to every index at the tip

| | Core #6 | bmc 34 | bmc 35 | best bmc / Core |
|---|---|---|---|---|
| headers → first block | 1:15 | 5:06 | | |
| 500,000 | 2:02:42 | 1:19:05 | | |
| 800,000 | 6:35:51 | 3:40:38 | | |
| 900,000 | 9:01:23 | 5:23:05 | | |
| IBD end (tip stored + applied) | 10:41:21 | 7:16:01 | | |
| **every index at the tip** | **10:42:05** | **7:17:39** | | |
| CPU time consumed (journal / proc sampler) | 13 h 50 m | — | | |
| peak RSS | — (not captured) | — | | |

## 2. Where the applier's time goes (thread-seconds over the whole chain)

| | Core #6 | bmc 34 | bmc 35 |
|---|---|---|---|
| applier busy | 13,909 | 17,166 | |
| applier waiting for blocks | 24,587 | 9,757 | |
| UTXO (Core: connect txs + flush + write chainstate + coins flushes; bmc: get + put + ckpt + flush) | ~11,000 | 13,863 | |
| ↳ put | — | 7,812 | |
| ↳ memtable / cache flush | 803 | 1,350 | |
| script verification | 113 (wait on 15 threads) | 773 | |
| block read | 2,289 | 124 | |
| per-block index work on the applier | 5 | 2,360 | |

## 3. RPC, 32 simultaneous clients × 5 calls, median ms (validation/rpc_concurrency_bench.sh)

Measured 2026-10-05 before the lane work (bmc pool 71,348 tx, Core pool
29,961 tx; fixed-work rows use block 969,000), and again after it.

| method | Core | bmc before | bmc after |
|---|---|---|---|
| getblockcount | 5 | 5 | |
| getblockhash | 5 | 5 | |
| getmempoolinfo | 5 | 177 | |
| getrawmempool | 687 | 249 | |
| getblock (verbosity 2) | 494 | 704 | |
| getrawtransaction | 6 | 6 | |
| getpeerinfo | 7 | 5 | |
| exec-lock waits ≥ 2 s per day under BlockYard + mempool.space | n/a | ~10 | |

## 4. Modules (from docs/reports/2026-09-28-the-module-benchmarks-gaps-closed.md)

Archive read 2.8–3×, MuHash insert 6×, SHA-256 / ChaCha20 / BIP324 AEAD at or
ahead of Core; signature verification at parity with libsecp256k1.

## 5. Disk and memory

| | Core | bmc |
|---|---|---|
| UTXO set on disk | 10.6 GB | 12.8 GB |
| txindex | — | 2.6× smaller than Core's |
| undo | — | 2.5× larger (carries spent scripts; feeds the address history) |

## 6. Verdict, category by category

(filled when run 35 and the post-change RPC rows are in)

## 7. What changed between run 34 and run 35

All in PR #383 (main `0319e1eb`), gated 447/447, each test revert-checked:

- **UTXO put** (`47c6e12c`): the undo capture reused Phase 1's resolved
  prevout instead of looking it up again (the second lookup was 1.29 of the
  2.30 µs per spent input with runs on disk). Bench, one pinned core, 2^25
  slots, 20M coins: 2.30 → 1.13 µs per spent input. Every 64th input is
  still re-resolved and compared (the 2026-09-01 inconsistency guard).
- **RPC** (`3b807cc6`): the Esplora facade had taken the exclusive execution
  lock for every dispatch, lane methods included — the production convoy
  (2.1–2.7 s waits behind 0–16 ms holders). It now takes what the method's
  class needs. A txindex lane (private store handle and block buffer, one
  mutex `irs_refresh` also takes) serves `rpc_chain_tx_blockhash` and
  `getrawtransaction` v0/v1; the facade's mempool batch enters it once per
  batch; `getblock` runs in a per-RPC-thread reader lane; `getmempoolinfo`'s
  totals are memoised on the mempool sequence.
- **Header sync** (`c5aecada`): the first 2,000-header page is asked of four
  peers at once and the fastest leads, with the others as fallbacks; off
  under `bmc.dlshape=core` (Core syncs headers from one peer).
- **Not done, stated:** the double-buffered memtable flush (plan B3) and the
  async index work (B4) — the flush column and the inline index columns in
  §2 are therefore expected to be unchanged in run 35.
- **Download rules:** run 34 ran Core's (`bmc.dlshape=core`); run 35 runs
  bmc's own (ranked peers, rotation), which is what a release ships.
- **Found during run 35, fixed after it (not in run 35's numbers):** an
  eviction the holder never answers. At 19:57:44Z the worker holding the
  window's oldest chunk (560,689–560,704) was "dropped" twelve times, 2 s
  doubling to 64 s, and never printed its drop line, never released the
  chunk; the other nine workers sat at the full window polling an empty
  retry ring with 64 chunks staged above the hole, the applier idle, the
  whole process set at 0 CPU for 7 minutes (proc.log 19:58–20:04). Run 34
  had the same shape four times at 878k, 910k, 915k and 925k, each ~20
  minutes (Core-mode's 1,200 s read timeout), 78 minutes in all — most of
  what the pair report called "download-bound under random peers". The
  committer's cursor help (30 s, a third of the window staged) was published
  every time and read by nobody: its only reader was the claim path, and
  every idle worker was in the full-window wait loop. Run 35 was stopped at
  21:00Z (72% stored) on the operator's instruction and re-run as run 36 on
  the fix. What the logs could and could not establish: the worker's own
  120 s stall alarm never fired either, and the worker neither printed a
  drop line nor failed a fetch visibly, which places it outside the fetch
  (dialing, in a handshake, or reading the chunk's headers) when the
  evictions arrived — the one place where a received signal was reset
  without a word before the next fetch. The exact wait it sat in for 415 s
  with no bytes and no CPU is not in the log; the kernel's hung-task
  warnings were already exhausted on this box. Five changes on the fix
  branch: the second eviction of the same holder for the same chunk puts
  the chunk on the retry ring from the parent's side (Core's semantics: a
  disconnected staller's blocks are re-requested elsewhere at once); the
  wait loop takes the cursor help; the eviction signal shuts the worker's
  socket down (the relay legs' arming), so a worker blocked in a handshake
  or a read sees it; a drop that arrives outside the fetch is acknowledged
  in the log instead of discarded; and the eviction line now names the
  holder's phase, how long it has been there, and its kernel state, wait
  channel and syscall. Also found reading for this: the BIP324 handshake's
  second loop had no real-time deadline, so a trickling peer could hold it
  indefinitely (relay legs; the download workers speak v1). All of it is
  revert-checked in `test_dialhelper` and `test_v2transport`.

## 8. Method and reproducibility

- Sync pair: `validation/logged_pair_run.sh` (Core) and
  `validation/fresh_ibd_run.sh` with `BENCHLOG=1 READY_WAIT=1` (bmc);
  `validation/ibd_stage_report.py` builds the stage tables from the two logs.
- RPC: `validation/rpc_concurrency_bench.sh`.
- CPU/RSS: Core from systemd's "Consumed" journal line; bmc from
  `validation/proc_sampler.sh` beside the run.
- Never an RPC call to a node during its timed run.
