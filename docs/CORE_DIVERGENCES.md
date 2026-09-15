# Where this node still differs from Core — issues to resolve (2026-09-09)

An inventory taken after the 09-09 leg and compact-block work, extended the same night with the initial-sync rows from the run 19 measurements, ordered by measured payoff. Each row names what Core does, what this node does, the measured cost, and the fix. Rows move to "closed" with the PR that closes them. Consensus is not on this list: every consensus rule is proven against Core's vectors and the regtest differentials, and the two decided refusals (`assumeutxo`, testnet3) are documented in `FEATURE_GAPS.md`.

## Open

| # | area | Core | this node | cost measured | fix |
|---|---|---|---|---|---|
| 1 | mempool overlap with the network | a peer's mempool holds nearly every transaction a new block carries (blocktxn a few KB); every peer relays transactions to it, inbound included | production holds 4,000-9,000 entries; the first measured blocks on snapshot x (2026-09-10 04:53Z): 966,304 had 40% of its 2,093 transactions in the mempool and fetched 690 KB, 966,305 had 65% of 1,398 and fetched 460 KB; of the fetched, 98% and 87% were NEVER ANNOUNCED to us, the rest orphans (28, 16), announced-not-requested (0, 43), policy rejects (0, 3), unanswered requests (2, 0) | the miss is coverage, not policy: three to eight full-relay legs and inbound relay at 50% see a fraction of the network's transactions; a 460 KB blocktxn is still seven round trips under slow start | the announced-not-requested class is closed (#168: the request queue drains like Core's tracker); what remains is coverage -- inbound peers (the router forward on 8333, inboundrelaypercent=100 already set), then remeasure the never-announced share |

| 2 | download occupancy | Core keeps up to 16 blocks in flight per peer and reassigns on completion, across 8 outbound full-relay peers it cannot exceed | one getdata carries a whole 40-block chunk, so the peer is never short of work inside a chunk; but a worker holds one peer and 8 workers is a configured cap, not an architectural one, with 112 peers sitting free | run 22, 2026-09-11, measured at 96% of the chain: aggregate pinned at 10.1 MB/s for 19 hours (99% of 6,157 samples in 9-11 MB/s) with per-worker rates 0.94-1.74 MB/s; sampling /proc/<pid>/io at 50 ms showed each worker BLOCKED IN THE SOCKET READ 11-20% of wall time, 332 gaps in 30 s, median 50 ms, none over 0.7 s. Workers burn 0.2-0.6% CPU, the applier averages 20% of one core, iowait is 0, the link is 2500 Mb/s with no shaping. The wait is the peer's, not ours | the node now REPORTS it (`pool_idle_pct` on `bmcgetdownloadinfo`, `idle=N%` per worker and `pool idle N%` on the [dlc] tick line) -- it previously printed "8/8 worker(s) active", which is true and useless for a worker holding a peer that cannot fill the pipe. `validation/download_worker_sweep.sh` then answers the question the register cannot: whether throughput rises with peer count (per-peer limited, add peers), stays flat at low idle (a shared WAN ceiling), or stays flat at high idle (peer selection, not peer count). The default stays 8 until that runs: 64 was adopted unmeasured once already |

| 3 | UTXO set metadata after a fresh sync | Core's UTXO record carries the coin's height and coinbase flag, and muhash commits to both | the fresh parallel-download sync produces correct outpoints, values and scripts but at least one coin's height/coinbase metadata is wrong; the chain, txouts, bogosize and total_amount are all exactly right | run 22, 2026-09-11 at height 966,495 on the same block with the node FROZEN: txouts 165,203,925 = Core's, bogosize 12,942,059,030 = Core's, total_amount 20,082,569.88121624 = Core's, muhash `2f8a7959…` vs Core's `dcfaa870…`. Production, built by reindex, matches Core on BOTH its walk and its index, so the code is sound and the data is not. First time this comparison has ever completed: earlier runs timed out and an empty result compared equal to an empty oracle value | the next run carries `coinstatsindex=1` so the node records a muhash per height and the harness bisects the first divergent height against the oracle (`validation/fresh_ibd_run.sh`); from one block it is one coin, and `utxo_setinfo --override <txid>:<n>=<height>` confirms it offline against the archived store without a 20-hour sync. Full account: `docs/reports/2026-09-11-run22-muhash-divergence.md` |

## Closed today

| # | what | PR |
|---|---|---|
| ad | `getnetworkinfo` carries `bmc_build_commit`/`bmc_build_dirty`: Core has no build attestation over RPC and a monitor could not tell a fixed node from a broken one | #180 |
| ac | `bmcgetdownloadinfo`: an RPC Core has no counterpart for, exposing the forked downloader's worker->peer->chunk->rate map and window state. Deliberate addition, not a gap | #179 |
| ab | download concurrency costs a PROCESS per peer here (node_ibd_blocks_s blocks for a chunk and cannot multiplex); Core multiplexes 8 peers in one ThreadMessageHandler thread. Same peer count now, different mechanism | open (architectural) |
| aa | a peer evicted for stalling the download window is remembered for the run, so the picker cannot hand it the same chunk again (run 20: fourteen times on one chunk) | #177 |
| z | a v2 session exports with the message in flight (the 64 KB blob refused a headers reply and closed healthy legs on snapshot ab); the refusal names its size | #174 |
| y | the reorg probe runs before the pass on an idle leg (it had probed the socket a pass child was reading: every leg reset within seconds on snapshot aa); no pass runs inline; eight dial helpers | #172 |
| x | a leg's pass runs in a helper; the sweep, pongs, relay and pushes continue while a block is fetched | #169 |
| w | the transaction request queue drains as Core's does (announced-not-requested closed) | #168 |
| v | a BIP324 session travels with its socket across the dial helper's fork (export/import); helper-dialed legs are v2 again where advertised | #167 |
| u | helper-dialed legs speak v1 (the v2 state stays in the child); the worker creates the dial memory (it was null on production since 09-09: "0 min" backoffs) | #163 |
| t | the block filter index and the address history repair themselves in the daemon (the coinstats supervisor as a module, one instance per index) | #162 |
| s | the live coin counter after a crash under the bulk memtable: the ghost rollback restores only what is gone (a lookup before the put) | #162 |
| r | the legs stay served through a reorg handoff (the sweep runs inside the parallel download); helpers bounded by the span | #162 |
| q | every outbound dial runs in a helper (re-dials fill their slot when they land, the top-up dials one at a time); the per-block mempool-overlap line and the missing-transaction classifier (row 5's measurement) | #161 |
| p | high-bandwidth compact blocks from the three most recent block sources, pushed blocks stored from the sweep, the apply right after a store | #159 |
| o | sendheaders after the handshake; announcements (inv, pushed headers) drive a leg's pass; no polling for headers between announcements (30 s safety net) | #159 |
| n | the parallel download takes Core's shape: the window scales and anchors to the connected tip, the window's tail evicts stallers, replacement only when a free peer exists. Peers downloading at once defaults to 8, Core's MAX_OUTBOUND_FULL_RELAY_CONNECTIONS (was 64, never measured); the ceiling stays 64 for a fatter link | #157, #178 |
| m | the coinstats index folds per block during a bulk sync through the fold worker (the walk-at-caught-up deferral is gone; history rows from block 0) | #156 |
| l | bulk mode checkpoints every 1,024 blocks or 60 s, a bounded pass carries its batch and never downshifts the memtable | #155 |
| k | a background merge waits while the apply is behind and yields when it runs | #154 |
| j | a fresh sync uses the dbcache: an empty set takes the bulk memtable | #153 |
| i | a block another leg just stored ends the pass well; the fetch gate skips hashes the store holds | #152 |
| g | one request per block across the legs (`daemon/inflight.c`, the sync loop's fetch gate) | #150 |
| h | pings every 2 min per leg, 20-minute timeout, the round trip recorded | #150 |
| a | compact-block receive completed nothing: `blocktxn` matched as `block` | #145 |
| b | a bad reconstruction cost the block: Core's full-block fallback, `bmc.cmpctrecv` removed | #148 |
| c | every close named (`ours/<reason>` / `theirs`), failed dials remembered with backoff, the streak per peer, pongs within a pass | #143, #146, #149 |
| d | the version message: wall-clock timestamp, random nonce, our port, our tip | #144 |
| e | chain selection like Core's: handoff, header mirror, fork tree, leg gate; the announced-height rule (median) | #137, #139, #140 |
| f | no consensus caps where Core has none; BIP30 originals | #129, #131, #133 |

---

## `getchainstates`: `coins_db_cache_bytes` and `coins_tip_cache_bytes` are omitted

Found 2026-09-12 by `validation/rpc_field_parity.py` once its case table was
extended past the original 39 calls.

Core reports two cache sizes per chainstate: `coins_db_cache_bytes`, the
LevelDB block cache, and `coins_tip_cache_bytes`, the in-memory `CCoinsViewCache`
budget. **This node has neither.** Its UTXO set is an LSM with its own sizing —
a memtable, run files and a blob map — and no structure in it is the opposite
number of either field.

The fields are omitted rather than filled. A number here would describe a cache
that does not exist, and a caller reading `coins_tip_cache_bytes` to reason
about memory would be reasoning about the wrong engine entirely. This follows
the rule that a Core-named key must carry Core's exact semantics: where the
semantics cannot be honoured, the key is absent, not approximated.

A caller wanting this node's cache sizing should read `bmcgetdownloadinfo` and
the `dbcache` setting, which describe what is actually allocated.

---

## `bmc.catchupworkers` is pinned at 8 because Core's is, and is not a tuning knob

Recorded 2026-09-14, after retiring `validation/download_worker_sweep.sh`.

Core's block-download concurrency is **fixed**: `MAX_OUTBOUND_FULL_RELAY_CONNECTIONS`
is 8 and is not configurable. This node exposes `bmc.catchupworkers`, which
looks like a tuning knob and is not one — it exists so this node can be set to
**match** Core, and 8 is the value that does.

**Why this is written down rather than left to judgement.** The count has twice
been set from an unmeasured number: 64 arrived as the size of the worker arrays,
and 8 replaced it on a comparison the release note itself called "not a
controlled A/B". A sweep was then built to measure it properly, and the
measurement was the wrong thing to want:

1. Raising the count above 8 makes Core comparisons meaningless. The IBD report
   states it directly — earlier runs at 16 to 64 against Core's 8 "is not a
   comparison of anything". A benchmark at a different peer count measures peer
   count, not implementation.
2. The performance question is already answered where it can be asked honestly:
   run 23, at 8 workers, is the fastest of four measured runs and beats an
   unhandicapped Core v31.1.
3. Each additional download slot is another connection to a stranger's node, for
   our benefit. Core chose 8 deliberately.

**What remains genuinely open** is peer *selection*, not peer count. Download
workers spend 17 to 31% of their wall-clock blocked before the first byte —
slots held by peers that cannot fill the pipe. Adding slots does not fix that;
choosing better peers might. Measure it against the local oracle's sixteen
loopback listeners, where no stranger's node is involved.

Raising `bmc.catchupworkers` above 8 for a benchmark invalidates that benchmark.
Raising it in production is a deliberate divergence from Core and belongs in this
file with its own entry.

---

## Chunk ordering: Core divides by adjusted WEIGHT, this node by adjusted VSIZE

Measured 2026-09-14, after unifying the three cluster implementations.

**What Core does.** `CTxMemPool::AddTransaction` hands the transaction graph
`FeePerWeight(fee, GetSigOpsAdjustedWeight(GetTransactionWeight(tx),
sigops_cost, nBytesPerSigOp))` (`txmempool.cpp:1066`). Its linearization and
chunking therefore order by **fee ÷ adjusted weight**.

**What this node does.** The mempool stores each entry's size as the
sigops-adjusted **vsize** — `ceil(max(weight, sigop_cost × bytespersigop) / 4)`,
the max taken on the weight scale and the rounding done once at the end, which
is Core's `GetVirtualTransactionSize` exactly and the same figure Core's own
`CTxMemPoolEntry::GetTxSize()` returns. `mempool_cluster.c` is handed that, so
chunk ordering is **fee ÷ adjusted vsize**.

**The difference is the division by four, and only the rounding survives it.**
`vsize = ceil(adjw / 4)`, so the two orderings agree except where the ceiling
tips a comparison. Measured over 2,000,000 random `(fee, weight)` pairs in
realistic ranges: **5 disagreements, 0.0003%** — roughly three per million, all
at rounding boundaries.

**Why it is recorded rather than fixed.** The cost is asymmetric between the two
consumers:

* the **mining** path can compute adjusted weight cheaply — it already holds the
  transaction's weight and sigop cost.
* the **eviction** path cannot. `mpol_node` stores adjusted vsize and sigop cost
  but no weight, and vsize is not invertible: `ceil(adjw/4)` discards which of
  four weights produced it. Recovering exactness means adding a field to a
  struct that lives in a **MAP_SHARED** region — a shared-memory layout change,
  for a rounding tie.

Changing only the mining path would re-split the linearization implementation
that was just unified into one tested module, which is a worse outcome than the
divergence. So both paths use adjusted vsize, consistently, and this entry
records the gap with its size measured rather than guessed.

**If this is ever closed**, close it in both paths at once: add the weight to
`mpol_node` (a shared-memory layout change, so it needs its own migration
reasoning), then hand `max(weight, sigop_cost × bytespersigop)` to
`mempool_cluster.c` from both call sites. The module itself needs no change — it
is denominator-agnostic and compares `fee/weight` by cross-multiplication.

---

## OPEN DEFECT: `signrawtransactionwithkey` claims `complete: true` for inputs it cannot resolve

Found 2026-09-15 by the RPC shape differential. **Not yet fixed** — recorded with
its reproduction so it is not rediscovered from scratch.

**Reproduction.** Take any confirmed transaction and ask both nodes to sign it
with no keys and no prevtxs:

```
RAW=$(bitcoin-cli getrawtransaction <txid> 0 <blockhash>)
signrawtransactionwithkey "$RAW" '[]'
```

| | Core v31.1 | this node |
|---|---|---|
| `complete` | **false** | **true** |
| `errors` | present, one entry per input | **absent** |
| error text | `Input not found or already spent` | — |

Core's `errors` entries carry `txid`, `vout`, `witness`, `scriptSig`,
`sequence` and `error`. This node emits none of them.

**Why it matters beyond the missing field.** `complete: true` is a statement
that every input carries a valid signature verified against its prevout. When
the prevout cannot be found, that has not been checked, and a caller reading
`complete` would believe the transaction is ready to broadcast. The missing
`errors` array is a shape gap; the wrong `complete` is a correctness one.

**What is known.** The code path looks right on inspection: `prev` is populated
only from the caller's `prevtxs` argument, so an empty array should leave
`prev_of[i] == NULL`, set `err = "Input not found or already spent"`, clear
`complete` and push an `errors` entry. It does not, on a transaction that
already carries witnesses. Verified on the wire with curl, so this is the
server's answer and not a CLI artefact. The mechanism was not found before this
was written down, and finding it is the first step of the fix.

**When fixing:** `complete` must mean "verified against the prevout", and an
unresolvable input must appear in `errors` with Core's field set. The machinery
is already there — `rpc_commands.c` builds the array and emits it when non-empty.
