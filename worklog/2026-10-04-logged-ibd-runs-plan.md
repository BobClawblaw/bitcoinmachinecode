# 2026-10-04 — Fully logged IBD runs, Core v31.1 vs bmc, on equal download terms

Operator ask: "set up full logged runs to test module level perf of each core
and bmc for ibd to rpc service. Equivalent parameters for bmc to download just
like core does."

## 1. bmc downloads like Core (`bmc.dlshape=core`)

Core v31.1, from its source (research 2026-10-04; net_processing.cpp line
numbers in the session notes):

| Core behaviour | bmc today | Core mode |
|---|---|---|
| 10 download peers (8 full-relay + 2 block-relay-only outbound) | 10 workers | unchanged |
| up to 16 blocks in flight per peer, topped up as each lands | one getdata of a 16-block chunk, then the pipe drains to zero before the next | claim the next chunk ahead; keep 16 in flight across the boundary |
| 1,024-block window above the tip | the same | unchanged (two chunks per worker: 320 ≤ 1,024) |
| no speed ranking; a replacement is a random addrman pick | a 2,000-header timing sample ranks 133 live peers (46 s), EMA picker | random pick from the live pool, no ranking phase |
| no rotation of slow peers | rotate under 0.5× median at a chunk boundary | off |
| no dead-weight eviction | floor-based kill after 3 ticks, with a ban | off |
| staller: disconnected, never banned; 2 s doubling to 64 s, ×0.85 per block | the same timeout, then BANNED for the run | disconnect, no ban |
| block download timeout 600 s × (1 + 0.5 × (peers − 1)) on the front block | 120 s with no block (alarm), SO_RCVTIMEO 20 s | Core's formula |

Not copied, stated: bmc's workers are their own TCP connections, not the
outbound legs (the legs are closed during the download, so the peer count is
equal); the probe dials IPv4 only.

## 2. Stage timing on both sides, from logs only

- Core: `debug=bench` (12 lines per connected block: sanity, fork checks,
  connect N txs, verify, undo, index writing, load, connect total, flush,
  writing chainstate, postprocess, connect block) and `debug=coindb` (each UTXO
  flush and its batches). The timers run regardless; only the logging is gated.
  ~1 GB of log. UpdateTip is already per block.
- bmc (`bmc.benchlog=1`): a per-block line with the same split utxo_live
  already measures (read, idx, verify, get, put, ckpt, flush, csi) in ms, plus
  the choke-point index work that runs outside it (txindex, txospender,
  bfilter, addr, ZMQ); a line per memtable flush; a line per download chunk
  (peer, wall, wait before the first byte, bytes, in flight).

## 3. One finish line: ready to serve RPC with every index at the tip

- bmc: a new log line `[ready] all indexes at height N` once the UTXO set,
  txindex, bfilter and the coinstats history are all at the tip. The
  coinstats history rebuild that runs after IBD (38 m 47 s in run 31) counts.
  Check whether that rebuild is redundant on a genesis sync (the tail already
  holds every row).
- Core: its indexes trail the tip by at most ~32–42 blocks by construction
  (ActivateBestChain waits on >10 queued callbacks), and nothing in its log
  marks "synced". Finish = UpdateTip at the oracle's tip, then ONE
  getindexinfo after that to confirm (not inside the timed span).

## 4. Order

1. Core rerun #5 (unlogged) finishes ~16:15Z: the logging-overhead control.
2. Build + test the bmc changes (box free once #5 ends).
3. Core rerun #6, logged. Then bmc run 34, logged, `dlshape=core`. Never
   concurrent. A report per segment and per stage from both logs.
