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

(the branches landed: UTXO put, RPC lanes, header probe — PR numbers and the
measured effect of each)

## 8. Method and reproducibility

- Sync pair: `validation/logged_pair_run.sh` (Core) and
  `validation/fresh_ibd_run.sh` with `BENCHLOG=1 READY_WAIT=1` (bmc);
  `validation/ibd_stage_report.py` builds the stage tables from the two logs.
- RPC: `validation/rpc_concurrency_bench.sh`.
- CPU/RSS: Core from systemd's "Consumed" journal line; bmc from
  `validation/proc_sampler.sh` beside the run.
- Never an RPC call to a node during its timed run.
