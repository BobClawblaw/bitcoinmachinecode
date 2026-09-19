# Where this node still differs from Core — issues to resolve (2026-09-09)

An inventory taken after the 09-09 leg and compact-block work, extended the same night with the initial-sync rows from the run 19 measurements, ordered by measured payoff. Each row names what Core does, what this node does, the measured cost, and the fix. Rows move to "closed" with the PR that closes them. Consensus is not on this list: every consensus rule is proven against Core's vectors and the regtest differentials, and the two decided refusals (`assumeutxo`, testnet3) are documented in `FEATURE_GAPS.md`.

## Open

| # | area | Core | this node | cost measured | fix |
|---|---|---|---|---|---|
| 1 | mempool overlap with the network | a peer's mempool holds nearly every transaction a new block carries | **REMEASURED 2026-09-16 and largely CLOSED.** 73 compact blocks over heights 967,199-967,270: steady-state overlap (more than 20 min after a restart) **median 95.8%**, `getblocktxn` **median 34 KB**. The row was written from two blocks at 40% and 65% fetching 690 KB and 460 KB; inbound relay at 100% and 12 outbound legs have closed that. Within 20 min of a restart the median is 89.5% at 143 KB, which is the pool refilling and not a coverage gap. | what did NOT change: **89% of the transactions still fetched were never announced to us** (the row said 98% and 87%), so the residual really is coverage rather than request handling -- announced-not-requested is 267 of 70,400. | nothing to do on overlap. The remaining bandwidth is now dominated by REPEAT RECONSTRUCTIONS, recorded as row 4 below. |

| ~~2~~ | ~~download occupancy~~ **CLOSED 2026-09-16 — it was never an open divergence** | Core fixes block-download concurrency at 8 (`MAX_OUTBOUND_FULL_RELAY_CONNECTIONS`, not configurable) | this row read "8 workers is a configured cap, not an architectural one, with 112 peers sitting free", which frames a PARITY DECISION as a limitation. `bmc.catchupworkers` exists so this node can be set to MATCH Core; 8 is the value that does. The register already says so two sections below, and said the opposite here. | the row's own fix column named `validation/download_worker_sweep.sh` as what would answer it — and that script was RETIRED on 2026-09-14 with the note "it answers a question this project should not act on, and answering it cost a day and an outage" (four failed runs and the LAN saturation). So the row demanded a measurement whose instrument had been deliberately destroyed, for a number it must not change. The performance question is separately answered: run 23, at 8 workers, is the fastest of four runs in every segment and on the total, beating an unhandicapped Core v31.1 by nine minutes (`docs/reports/2026-09-11-ibd-vs-core.md`). | nothing to do. Raising the count would also make every future Core comparison measure peer count rather than implementation. The one REAL observation inside this row is not about worker count and survives as row 5. |

| ~~3~~ | ~~UTXO set metadata after a fresh sync~~ **DISPROVED 2026-09-12 — do not re-open on the old evidence** | — | run 22's UTXO set is byte-identical to Core: walked OFFLINE with `bmc_utxo_setinfo --muhash` at height 966,496 it gives `df1b0340…073d0165`, matching the oracle on muhash, txouts, bogosize and total_amount alike. Run 23 matches at 966,674 (`b75303cd…71290099`). There is no coin-height bug. | the capstone had hashed a LIVE, still-flushing set: a walk over a moving LSM is not a set, and `txouts` agreed because it is a maintained counter, not the walk's own count — aggregates matching while the hash differed was the signature of a torn read, not of correct data with wrong metadata | nothing to fix. The harness lesson landed instead: pin the height on BOTH sides, take our applied height from a quiesced walk, then ask Core for that height. |

| 4 | the same block reconstructed several times | Core tracks a block in flight per peer and will not re-fetch one it already has | **FOUND 2026-09-16 while remeasuring row 1; the first write-up of this row keyed on HEIGHT and was wrong to.** The logged height was `tip + 1` -- the height we EXPECT next, not the block's own, which a header does not carry -- so one block appeared under two heights. Re-keyed on transaction count and checked against the chain, which confirms every FIRST reconstruction matches the real block: **12.3 MB** of redundant `getblocktxn` in one morning. The worst is a 4,469-transaction block reconstructed **five times in nine seconds** from five different peers at ~1.4 MB each -- **6.8 MB for one block** -- and a 5,052-transaction block fetched twice **in the same second** by two peers at 1,085 KB each. | concurrent pushes, not honest re-arrivals: the fetch gate that gives one request per block across the legs (`daemon/inflight.c`, PR #150) does not cover the pushed-compact path. The repeats show 0-16% mempool overlap because the FIRST reconstruction already connected the block and cleared those transactions from the pool, so the later ones find nothing to reuse and fetch almost the whole block. | `[cmpct]` now prints the block HASH, so a repeat is identifiable without inferring it from a transaction count (landed 2026-09-16). With that in the log, the de-duplication itself can be measured before and after rather than argued about. |

| 5 | peer selection: slots held by peers that cannot fill the pipe | Core reassigns in-flight blocks on completion, so a slow peer costs one block rather than a slot | **the residual of row 2, kept because it is real and is NOT about worker count.** `pool_idle` measured 17-31% of worker wall-clock spent blocked BEFORE THE FIRST BYTE, and run 22 sampling `/proc/<pid>/io` at 50 ms showed each worker blocked in the socket read 11-20% of wall time — 332 gaps in 30 s, median 50 ms, none over 0.7 s, while workers burned 0.2-0.6% CPU, iowait was 0 and the link is 2500 Mb/s unshaped. The wait is the peer's, not ours. | a worker holds ONE peer for a whole 40-block chunk, so a peer that cannot fill the pipe idles a slot for the length of the chunk rather than for one block. That is a selection and reassignment question, and changing the worker COUNT does not touch it. | measurable WITHOUT a sweep and without touching the LAN: against the local Core oracle's sixteen loopback listeners, where no stranger's node is involved. Not yet run. Requires a fresh sync to observe at all — `bmcgetdownloadinfo` reports `active: false` on a caught-up node, so production cannot answer this. |

| 6 | the connection counts | `getconnectioncount` is the size of the vector `getpeerinfo` renders; the two cannot disagree | **FIXED 2026-09-16.** They came from different places: `getpeerinfo` walked the shared peer table, `getconnectioncount`/`getnetworkinfo` returned `n_out + n_inbound`, counters only the serve/leg path maintains. The download worker fills peer slots and never touched them, so during IBD the three disagreed | run 26, mid-sync: `getpeerinfo` 13, `getconnectioncount` 5, `getnetworkinfo.connections` 5, while 11 MB/s came in through 8 download peers the count could not see. A monitor graphing the count drew a node with no peers for 28 minutes | one walk, one liveness test (`rpc_peer_live`), shared by all three; `test_rpc_node` pins Core's invariant and fails 6 ways against the old code |

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

## ZMQ publishing: ~~a slow subscriber is disconnected~~ FIXED 2026-09-19 (MEM-22); one byte ceiling remains

**What was wrong.** The publisher (`asm/daemon/zmq_pub.c`) had no queue. Each
subscriber's kernel send buffer was sized to `hwm x 256` bytes (~256 KB at the
default hwm of 1000), the three frames were written with non-blocking `send`,
and a subscriber that could not take the whole message was **closed**. A
rawblock is 1-2 MB, so it hit `EAGAIN` mid-message every time: **rawblock was
never delivered to anyone, and every block disconnected every subscriber on
its endpoint.** Production, 2026-09-19 01:07Z: a pyzmq (libzmq 4.3.5)
subscriber got 3,180 hashtx, 3,178 rawtx, 2 hashblock and **zero rawblock**
over two blocks, with 4 per-topic sequence gaps from the reconnects; the log
said `subscriber could not take a rawblock message; dropping it`. The audit
had recorded the disconnect as a known divergence (MEM-22); what it missed is
that for rawblock it was not an edge case but the only outcome.

**What Core does** (libzmq PUB, `src/zmq/zmqpublishnotifier.cpp`): one socket
per address, `ZMQ_SNDHWM` = `-zmqpub<topic>hwm` (default 1000) set by the
notifier that creates the socket. SNDHWM counts **messages** per subscriber
pipe. When a pipe is full, PUB silently discards the new message for that
subscriber and keeps the connection; the per-topic sequence number shows the
gap. `0` means no limit.

**What this node does now.** The same thing, in the same unit. Each
subscriber has a user-space queue of whole messages, at most hwm of them; the
publish call frames the message once into a refcounted buffer shared by every
queue that takes it and never touches a socket (measured: 0.3-0.7 ms for a
hashblock + 2 MB rawblock publish, with a stalled subscriber attached). The
servicing thread writes each queue as its socket drains. A full queue drops
the new message for that subscriber only, and the connection stays. The hwm
that governs a shared endpoint is the first configured topic's in Core's
factory order (hashblock, hashtx, rawblock, rawtx), as Core's socket reuse
gives. `getzmqnotifications` reports each topic's configured `hwm` (it
reported `0` while there was no queue).

**The divergence that remains, deliberately:** a **512 MiB per-subscriber
byte ceiling** on top of the message count. Core's worst case is 1000
rawblocks — up to 4 GB — held for each subscriber that has stopped reading;
this box has been OOM-killed before, and the download worker that owns the
publisher is not where that memory should go. 512 MiB is ~250 full blocks,
more than a day of blocks at the tip, so it binds only during a catch-up
burst to a subscriber that is not reading. Past it, new messages are dropped
exactly as at the hwm (gap, connection kept), and a message into an empty
queue is always accepted so none is undeliverable. With `hwm=0` the ceiling
is the only limit, where Core would have none.

Tests: `asm/tests/test_zmq_queue.c` (in the gate) and
`asm/tests/zmq_queue_interop.py` against real libzmq (manual; against the old
publisher it reproduces production: 0 rawblock, a disconnect per block).

---

## ZMQ `sequence` (-zmqpubsequence): implemented 2026-09-19; where it is not Core's

Refused until 2026-09-19 (removals had no choke point; the reorg reconcile
emptied the pool with raw `mpool_del`). Now: one hook in the policy layer
(`bitcoin_mempool_policy.c` `g_seq_cb`) sees every insert (`mpool_policy_add`)
and every removal (`remove_node`, `mpol_remove_marked`); the counter (Core's
`m_sequence_number`, from 1) and a 65,536-event ring live in a MAP_SHARED
region created before the fork and are written under the pool lock by
whichever process changed the pool; the worker publishes
(`asm/daemon/mempool_seq.h`). A block's own transactions take a number and
publish nothing, as Core's `BLOCK` removal does, and the conflicts it causes
are numbered in block order. `getrawmempool(false, true)` and REST
`?mempool_sequence=true` read the same counter under the same lock as the
txid list.

**Measured against v31.1** (`validation/zmq_sequence_core_diff.py`, regtest):
add, child add, RBF (R before A), a block with a mined tx and a conflict
(R, silent number, C), invalidateblock (D, A, A), reconsiderblock (C, two
silent numbers) and a one-step two-block reorg delivered by submitblock
(D, R, A, C, C) are **identical event for event, hashes and mempool sequence
numbers included**, and the two `getrawmempool` snapshots agree on txids and
`mempool_sequence`. What is not the same:

1. **Where the pool counts itself full.** Core measures DynamicMemoryUsage,
   this node raw transaction bytes. With `maxmempool=5` and 80 KB
   transactions at rising feerates, Core began trimming one transaction
   earlier (14 evictions to 13); the evictions came in the same order and each
   'R' followed the 'A' that forced it on both. The accounting, not the topic.
2. **A multi-block reorg's interleaving.** The reconcile rebuilds the pool
   and publishes its NET change (`asm/daemon/reorg.c`, section 5, says why
   the rebuild stays). So the D's come from the disconnect loop, then every
   'R' and every 'A' of the reconcile, then the C's from the block-connect
   choke point. Core publishes, per ActivateBestChain step, D's, the
   connected blocks' conflict R's, the re-adds, then R's for anything
   `removeForReorg` or `LimitMempoolSize` then drops, then the C's. For a
   one-step reorg the two orders coincide (measured); they differ when the
   reorg also drops a transaction for finality/maturity (here its 'R' comes
   before the re-adds, in Core after them), and for a MULTI-block
   `invalidateblock`, where Core re-adds after each block (D, A.., D, A..)
   and this node after the last (D, D, A..). Core also stops re-adding after
   ten invalidated blocks; this node re-offers the whole captured branch
   (20 MB / 256 blocks, as before).
3. **Order inside one multi-transaction removal.** An expiry or a conflict
   takes a transaction's descendants with it; the numbers go to this
   engine's order (descendants first), Core's to its txgraph's. The set, the
   count and the position of the group in the stream are the same.
4. **When expiry happens.** Core expires on the next accept after
   -mempoolexpiry (so its 'R's follow that accept's 'A'); this node sweeps
   every 60 s on the wall clock. Not driven in the differential (Core's is
   mocktime-driven); `asm/tests/test_mempool_sequence.c` covers the path.
5. **Loss.** Core has no staging step; here a worker that falls 65,536
   events behind skips to the oldest intact one, counts the loss, and
   advances the topic's 4-byte sequence by it, so a subscriber sees the same
   gap a high-water-mark drop leaves (and a jump in the mempool sequence).
6. **A reloaded mempool.dat** publishes an 'A' per transaction on both; on
   Core it usually happens before a restarted subscriber has rejoined (the
   PUB slow joiner), so the differential checks Core's counter there, not
   its stream.

Tests: `asm/tests/test_mempool_sequence.c` (every event path through the real
engine, the cross-process counter, the wire bytes, the overrun gap, the cost
per event: ~8 ns), the reorg cases in `asm/tests/test_reorg.c`, and the RPC /
REST / config cases in `test_rpc_node`, `test_rest`, `test_node_config`.

**Open, found while reading Core for this, not fixed:** Core's
`BlockConnected` and `BlockDisconnected` also publish `hashtx`/`rawtx` for
EVERY transaction of the block (`zmqnotificationinterface.cpp`), coinbase
included. This node publishes those two topics only for mempool accepts
(`daemon/zmq_notify.c`), so a `hashtx` subscriber here never sees a
transaction that arrived in a block without passing through the pool, nor a
disconnected block's transactions.

---

## `getrawaddrman`: `source` and `source_network` are omitted

Found 2026-09-16 by diffing the 26 served methods the parity harness never
checked. Core reports, per address, **which peer told us about it** (`source`)
and that peer's network (`source_network`). This node reports neither.

It is not an oversight in the RPC: `ab2_rec_t` (`daemon/addrbook.h`) stores
`src_group` — the NETGROUP of the peer that told us — and not the address
itself. The netgroup is what the eviction and diversity rules need, and it is
all that was ever kept. Reporting Core's field means widening the address-book
record and rebuilding the book, which is a format change, not an RPC change.

Recorded rather than faked: a `source` reconstructed from a netgroup would be
a plausible-looking address that no peer ever sent, which is worse than the
field being absent.

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

**Re-examined 2026-09-18 against v31.1's source**, to see whether the two roles
map onto anything real here. They do not. `coins_db_cache_bytes` is the
LevelDB block cache for the coins DB (`kernel/caches.h`: `min(total/2, 8 MiB)`
of what `-dbcache` leaves after the index caches); this node's UTXO reads go to
LSM run files through the OS page cache, and there is no DB read cache to
size. `coins_tip_cache_bytes` is the `CCoinsViewCache` budget, a read-and-write
coin cache; this node's in-memory table is a write buffer of pending changes
that lookups do not populate, sized by mode (from `-dbcache` in bulk catch-up,
a fixed 2^16 slots / 64 MB blob in steady state) inside the download worker,
which the RPC process cannot observe. Reporting `dbcache` or the memtable size
under Core's names would be the invented number the rule forbids. The
omission is also declared in `tests/test_rpc_core_fields.c`
(`declared_omission`), against a fixture that now captures both fields from
v31.1.

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

## ~~OPEN DEFECT~~ FIXED 2026-09-15: `signrawtransactionwithkey` claimed `complete: true` for inputs it cannot resolve

> **RESOLVED the same day. The mechanism was a segwit parse, and the trigger was
> my own fix earlier that morning.**
>
> `cmd_signrawtransactionwithkey` read the input count at offset 4
> **unconditionally**. A segwit transaction carries `0x00 0x01` there — marker
> and flag — so the varint read `0x00` and `n_in` came out **zero**. The signing
> loop never ran, `complete` stayed true and `errors` stayed empty: the node
> answered "fully signed" for a transaction it had never looked at.
> `converttopsbt`, in the same file, has always skipped the marker.
>
> **It was masked, and I removed the mask.** The `n_in == 0` guard rejected such
> a transaction as "TX decode failed" — wrong, but safe. Relaxing that guard
> (correctly: `createpsbt [] {}` needs it, and Core accepts zero inputs there)
> removed the accident that was hiding a real parse bug, and turned a wrong
> ERROR into a wrong SUCCESS. The second is far more dangerous. The lesson is
> not "do not relax guards" but "ask what else a guard is catching before you
> relax it".
>
> Fixed by skipping the marker, as `converttopsbt` does. Both shapes now match
> Core exactly — unsigned and signed segwit, `complete: false` with one error
> each. Three regression tests in `test_rpc_signraw.c`, verified by removing the
> marker skip and watching all three fail; the first asserts the transaction is
> DECODED rather than silently skipped, which is the property that was violated.
>
> Nothing in the gate would have caught this: no test drove a signed segwit
> transaction through that path. The RPC shape differential found it, by
> reporting six missing `errors` fields that were a symptom of a parse that
> never ran.

### The original report, kept as written

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
`sequence` and `error`. This node emits none of them. **All six are emitted as of
2026-09-15**, in Core's order.

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

---

## ~~OPEN~~ FIXED 2026-09-15: `createrawtransaction` / `createpsbt` argument checking — and a rule the previous commit got wrong

Closes the gap left open above. Two findings, one of which is not a message
defect at all and one of which invalidates a claim made in the commit before.

### The version argument was ignored, and two arguments were silently defaulted

`createrawtransaction` **always emitted version 2** whatever position 5 said.
A caller asking for a v3 (TRUC) transaction got a v2 one, with no error.
`createpsbt` honoured version in its own copy of the parse, which accepted
**4 and beyond** — Core's standard range is 1..3
(`TX_MIN/MAX_STANDARD_VERSION`), so this node could build a transaction the
network will not relay.

Positions 3, 4 and 5 had **no type check at all**: the body tested
`items[n]->typ == RJ_NUM` and fell through to the default when it was not. So

```
createrawtransaction [..] {..} "500000"      -> locktime 0, reported as SUCCESS
createrawtransaction [..] {..} 0 "true"      -> non-replaceable, reported as SUCCESS
```

A string where a number belongs is an ordinary mistake, and the node answered
it by building a **different transaction from the one asked for**. That is a
silent wrong-output defect, not a wrong message, and no error-string test would
have caught it — the round trips in `tests/test_rpc_rawtx.c` assert the version
and locktime actually reach the serialized bytes.

### Core reports EVERY failing position, not the first

**The previous commit claimed "the lowest failing position wins." That was
wrong.** Core collects every positional type failure into one object, in
position order:

```
Wrong type passed:
{
    "Position 1 (inputs)": "JSON value of type string is not of expected type array",
    "Position 3 (locktime)": "JSON value of type string is not of expected type number",
    "Position 4 (replaceable)": "JSON value of type string is not of expected type bool",
    "Position 5 (version)": "JSON value of type string is not of expected type number"
}
```

The error came from reading probe output truncated to ~95 characters, which cut
everything after the first entry. Two assertions written on that basis —
`getblockheader 5 5` and `estimaterawfee "y" "x"` — checked only that the lower
position *appeared*, which is also true of a message naming it alone, so they
passed against code that dropped the rest. Both are corrected against the full
message, and `rj_typeerrs` in `rpc_json.c` now accumulates. Every multi-position
site was converted: `createrawtransaction`, `createpsbt`, `getblockheader`,
`gettxoutsetinfo`, `gettxspendingprevout`, `estimaterawfee`,
`prioritisetransaction`.

**A UNION-typed position is never in that object.** `createrawtransaction`'s
`outputs` (array or object) is not typed by `RPCHelpMan`, so it does not appear
even when it is wrong — `[.., 5, "a"]` reports Position 3 **alone** — and the
body reports it afterwards with the bare sentence. The union check therefore
sits *after* the collection, never inside it. `gettxoutsetinfo`'s
`hash_or_height` is the same shape; a nested value (an `inputs` entry that is
not an object) also takes the bare sentence, and was `-8`.

### Boundaries

`version` is parsed as uint32 **first**: `-1` and `4294967296` are
`-1 "JSON integer out of range"`, not `-8`; `0`, `4`, `2147483648` and
`4294967295` are `-8 "Invalid parameter, version out of range(1~3)"`; `1` and
`3` succeed. `locktime` stays int64-then-range, which this node already had.
Arity is `-1`, not `-8`.

**Verification.** 91 differential cases against the oracle across both methods,
every position and every JSON type, plus 11 multi-position cases: `DIFFERS: 0`.
The four remaining message differences are the missing-argument help text.
Eight reintroductions, each watched to fail — including "report only the first
position", which fails in all three suites.

---

## ~~OPEN~~ FIXED 2026-09-15: the `Wrong type passed` wrapper at the remaining nine sites

Follow-up to the error-code change below, which fixed four methods and left
nine sites that had the right CODE (`-3`) with a hand-written message. Measuring
those against Core v31.1 for every JSON type turned up three rules the codebase
did not have, and one of them makes most of the others unreachable.

**1. Two message shapes, not one.** A POSITIONAL argument gets the wrapper:

```
Wrong type passed:
{
    "Position 2 (options)": "JSON value of type string is not of expected type object"
}
```

A FIELD inside an options object gets a different message with no wrapper and
no position:

```
JSON value of type string for field mempool_only is not of expected type bool
```

and a **null** field drops the `for field` clause entirely:

```
JSON value of type null is not of expected type bool
```

Now `rj_wrong_type_msg` and `rj_wrong_field_type_msg` in `rpc_json.c`.

**2. Every site hardcoded the type it reported** — `"string"`, `"number"` or
`"null"` depending on which one the author happened to hit. Pass a number where
a bool is expected and the node said you had passed a string.

**3. Every argument's TYPE is checked before ANY argument's VALUE, and the
lowest failing position wins.** Measured across five methods:

| call | Core answers |
|---|---|
| `gettxspendingprevout [] "x"` | Position 2 (options) — not the empty-outputs `-8` |
| `estimaterawfee 0 "x"` | Position 2 (threshold) — not the out-of-range `-8` |
| `getblockheader <unknown hash> 5` | Position 2 (verbose) — not `-5 Block not found` |
| `gettxoutsetinfo "bogus" null "x"` | Position 3 (use_index) — not the invalid hash_type `-8` |
| `converttopsbt <signed tx> false true "x"` | Position 4 (psbt_version) — not the `-22` |
| `estimaterawfee "y" "x"` | Position 1 (conf_target) — the lower position wins |

This is the rule that mattered. `psbt_version_arg` ran at the END of both
`createpsbt` and `converttopsbt`, so its `-3` was **unreachable for any
transaction that failed to decode or carried signatures** — the message was
written and could not be produced. Same for `getblockheader`'s verbose, masked
by the blockhash lookup, and `gettxoutsetinfo`'s `use_index`, which had no type
check at all. Fixing the strings without the ordering would have left a change
`grep` could see and a caller could not — the same trap as the previous commit.

Where a helper did both stages it is now split: `fee_parse_target_type` /
`fee_parse_target`, and `psbt_version_type` / `psbt_version_arg`.

**Verification.** 65 differential cases against the oracle covering every JSON
type at every site, plus 12 more for `psbt_version` against a real signed
mainnet transaction. `CODE DIFFERS: 0`. The four remaining message differences
are all the missing-argument help text this node does not carry. `getblockheader`
and `gettxoutsetinfo` cannot be reached through the plain dispatch harness — the
chain dispatcher answers `-28 "Loading block index..."` until a chain is open,
which is Core's own warm-up behaviour — so they are asserted in
`tests/test_rpc_chain.c`, which opens a real chain fixture.

Nine reintroductions, each watched to fail: the wrapper, the field clause, the
null special case, the hardcoded type name, and five orderings.

**Two more assertions were pinning the defect.** One asserted
`getmempoolcluster` with no txid is `-3` and said it was "verified against
v31.1" — the probe behind that had passed a **null** txid while the assertion
passes **no** txid, and Core answers those differently (`-3` vs `-1`). It was
written as the replacement for an earlier pinned assertion and pinned the next
defect in turn. The other froze `estimatesmartfee`'s bare message.

**Left open, deliberately:** `createpsbt` has no type check at all on `inputs`,
`locktime`, `replaceable` or `version` (Core: Positions 1, 3, 4, 5), and its
version-range message reads `between 1 and 2147483647` where Core says
`out of range(1~3)`. `gettxoutsetinfo`'s `hash_or_height` is a union type and
takes Core's third shape, a bare sentence with no position. Those are absent
checks rather than wrong messages — a different gap, not measured here.

---

## ~~OPEN~~ FIXED 2026-09-15: wallet-absent and argument-type error codes

> **RESOLVED.** Both recorded mismatches are closed, and closing them turned up
> two things the records had wrong and one regression the fix introduced.
>
> **1. Wallet absent: -4 -> -18 at 15 sites** (the record said ten; it was 12 in
> `rpc_wallet_ops.c` and 3 in `rpc_commands.c`). Core answers
> `RPC_WALLET_NOT_FOUND` with a specific text, now a single
> `RPC_NO_WALLET_CODE`/`RPC_NO_WALLET_MSG` pair in `rpc_wallet_ops.h`:
>
> ```
> No wallet is loaded. Load a wallet using loadwallet or create a new one with
> createwallet. (Note: A default wallet is no longer automatically created)
> ```
>
> The record claimed "the message matches; the code does not." **The message did
> not match either** -- this node emitted only the first sentence. The text read
> close enough to pass for a match, which is how the code stayed wrong: a human
> skims the text, a caller branches on the number.
>
> **2. The order mattered as much as the code.** Core resolves the wallet after
> the argument type check and before the value check. This file checked the
> RESCAN first, and with no wallet there is never a completed rescan -- so ten
> methods answered `-4 "no wallet rescan has completed"` and the new `-18` was
> unreachable at those sites. Changing the code alone would have been a fix
> `grep` could see and a caller could not. `wop_need_wallet` now runs first, and
> `wop_txid_from_arg` is split so the wallet check can sit between the type
> stage and the value stage where Core puts it.
>
> **3. Argument types: -8 -> -3.** Measured on the oracle for every JSON type,
> Core answers a bad argument three different ways:
>
> | condition | Core | this node, before |
> |---|---|---|
> | missing required argument | `-1` + the method's full help text | `-8` |
> | wrong JSON type | `-3`, `Wrong type passed: {"Position 1 (txid)": ...}` | `-8` |
> | right type, bad value | `-8` + a specific message | `-8` |
>
> `getmempoolentry`, `getmempoolancestors`, `getmempooldescendants` and
> `prioritisetransaction` collapsed the first two into one `-8` **and named the
> passed type as "null" whatever it really was** -- a caller that sent a number
> was told it had sent null. The formatter now lives in `rpc_json.c`
> (`rj_wrong_type_msg`) so the three files that emit it agree.
>
> The `-1` text cannot match Core: this node deliberately carries no per-method
> usage text (`cmd_help`), so it answers Core's CODE with a short usage line.
> That is what the tests assert -- what this node can honestly produce, not a
> Core string it will never emit.
>
> **Verification.** Two differentials against Core v31.1: 31 argument cases
> against the oracle and 29 wallet cases against a throwaway regtest Core with
> **genuinely no wallet loaded**. `CODE DIFFERS: 0` on both; 53 of 60 match the
> message byte for byte, and all 7 that do not are the missing-argument help
> text. The no-wallet Core mattered: probing the oracle with a bad `-rpcwallet`
> name also returns `-18`, but with a DIFFERENT message ("Requested wallet does
> not exist or is not loaded"), and freezing that string would have pinned the
> wrong one.
>
> Six reintroductions, each watched to fail. Two initially reported ZERO
> failures and were non-results: one had failed to build, so a stale binary ran;
> the other passed because a completed rescan was in place in the fixture, which
> is precisely the state where the guard order is invisible. The test now clears
> the rescan first, and that reversion fails 8 assertions.
>
> **A regression the fix introduced, caught by the existing suite:** a
> WATCH-ONLY wallet is a loaded wallet with NO SEED, so `w && w->seed` refused
> every one of those methods for watch-only wallets. The predicate is now
> `wop_wallet_loaded()`, the one `wop_keyset_cached` already used.
>
> **Three existing assertions were pinning the defect** and failed on the fix
> (`bumpfee with no txid -> -8`, `fundrawtransaction ... refuses at the funding
> step` expecting the rescan `-4`, and one that named `-4` "the honest
> refusal"). Each read as a statement that a method was wired up, and each was
> in fact freezing the wrong answer. The `fundrawtransaction` one is the clearest
> case of the order problem: with no wallet there is never a completed rescan,
> so the rescan message was the only one that could ever appear and the test
> could not have distinguished a correct node from this one.

### The original report, kept as written

Found 2026-09-15, after loading a wallet on the oracle so the wallet methods
could be diffed at all.

With no wallet loaded, Core answers wallet RPCs with **`-18`**
(`RPC_WALLET_NOT_FOUND`). This node answers **`-4`** with the message
"No wallet is loaded".

The message matches; the code does not. A caller branching on the numeric code
— which is what the code is for — takes the wrong branch.

**Not changed in the same pass that found it.** Ten call sites across
`rpc_wallet_ops.c` return `-4`, and a returned error code is caller-visible
behaviour: changing ten of them belongs in its own commit with its own release
note, not bundled into a differential's findings. The same reasoning applied to
the `-8` versus `-3` mismatch, which was recorded in `PARITY_RPC_FIELDS.md`
rather than here — narrative cross-references drop things, and this one said
"recorded above" pointing at a section that was never in this file.

**What WAS fixed in that pass**, because it was a different and worse defect:
seven of those sites reported **`-7 "out of memory"`** for a missing wallet.
`wop_keyset_cached` returns NULL both when no wallet is loaded and when a malloc
fails, and the call sites collapsed the two — telling an operator with no wallet
that the node was out of RAM. They now distinguish the cases, and match the
three sites in the same file that always answered correctly.
---

## ~~OPEN DEFECT~~ FIXED 2026-09-15: `signrawtransactionwithkey` DROPPED existing witness data

> **RESOLVED the same day, and it needed three changes rather than one.**
>
> 1. **The scriptSig and witness are now stored.** The parse skipped each
>    scriptSig without keeping it and never read the witness section; inputs the
>    signer does not re-sign now keep what they arrived with.
> 2. **The locktime was also wrong.** It was read immediately after the outputs,
>    but in a segwit transaction the WITNESS SECTION sits there — so locktime was
>    reading witness bytes. Fixed by the same parse.
> 3. **The segwit marker now follows the input.** `any_segwit` was set only when
>    THIS function produced a witness, so a transaction that arrived with
>    witnesses but got no new signature would have been serialized without the
>    marker, silently discarding them.
>
> Verified against Core on three real segwit transactions from block 966,000 —
> 444, 468 and 632 hex characters, all byte-identical to Core's output. The
> unsigned legacy path still matches: `complete: false`, one error, hex
> unchanged.
>
> Three defect classes verified by reintroduction. The test asserts the
> transaction **comes back unchanged**, which is the property that was violated
> — asserting only on `complete` or the error count would pass against a signer
> that still dropped the data.
>
> **Also from the same report, CLOSED 2026-09-15:** the `errors` entries now
> carry Core's `witness` and `scriptSig`, in Core's field order — `txid`,
> `vout`, `witness`, `scriptSig`, `sequence`, `error`
> (`rpc/rawtransaction_util.cpp` `TxInErrorToJSON`). They were unimplementable
> until the parse above started keeping that data.
>
> The subtle part is WHICH bytes an entry reports. Core builds the array from
> the final `mtx` — `TxInErrorToJSON` reads the fields off `mtx.vin[i]` after
> `UpdateInput` has written back whatever sigdata was produced — so a partially
> signed input reports its partial data and an input nothing could be done with
> reports the bytes it arrived with. These must be the same bytes the function
> is about to serialize into `hex` for that input, never the bare values.
>
> Differentially verified against Core v31.1 on 12 real mainnet transactions
> from blocks 966,000–966,002: all 12 identical **including key order**. The
> coverage that matters is a 5-input transaction where only one input is
> P2SH-P2WPKH — scriptSig and witness on the SAME input, which is where a
> single is-this-segwit flag goes wrong. Two of those are frozen in
> `tests/test_rpc_signraw.c` with Core's own compact JSON, so order is pinned
> as well as the values. Three reintroductions each fail both fixtures: drop
> the fields; report the witness from our own buffer only; report the scriptSig
> from our own buffer only.

### The original report, kept as written

Found 2026-09-15 by the RPC shape differential, immediately after the segwit
marker fix made the input loop run at all. **Not fixed** — recorded with its
reproduction because a signing path is not a thing to change in a hurry.

**Reproduction.** Sign any already-signed segwit transaction with no keys:

```
RAW=$(bitcoin-cli getrawtransaction <segwit txid> 0 <blockhash>)   # 444 hex chars
signrawtransactionwithkey "$RAW" '[]'
```

| | Core v31.1 | this node |
|---|---|---|
| returned `hex` | 444 chars — **unchanged** | **226 chars** |
| the witness section | preserved | **gone** |

A caller round-tripping a signed transaction through this call gets back an
unsigned one. In a multi-party signing flow — where passing a partially-signed
transaction between signers is the whole point — this destroys the previous
signer's work.

**Cause.** The input parse skips each scriptSig without storing it
(`p += cc + ssl`) and never reads the witness section after the outputs. The
serializer then writes what it has, which for an input it did not re-sign is
nothing. The function has NEVER preserved witnesses; before the segwit marker
fix the loop did not run at all, so the output was wrong in a different way and
this was invisible.

**What a fix needs**, in this order:
1. store each input's original scriptSig (pointer and length) during the parse;
2. parse the witness section into per-input original witness bytes;
3. carry both through for any input the signer does not itself sign;
4. then `errors` entries can finally carry Core's `witness` and `scriptSig`
   fields, which are the ORIGINAL input's — that is the same data, and the
   reason those two fields are still missing from the error entries.

Core's error entry order is `txid, vout, witness, scriptSig, sequence, error`
(`rpc/rawtransaction_util.cpp:178-187`); this node emits txid, vout, sequence,
error.
