# Serving performance: bitcoinmachinecode vs Bitcoin Core

**Living document.** Last measured 2026-09-17, node commit `31cffbc0`, against
the Bitcoin Core v31.99 oracle on the same machine.

This covers the node **after** the sync: the RPC surface, memory, and disk.
Micro-benchmarks of the verification hot paths (hashing, secp256k1, UTXO I/O)
live in [devlog/BENCHMARKS.md](devlog/BENCHMARKS.md). Initial block download
is **not** covered here — see *What we have not measured*, below, and read
that section before quoting anything as a head-to-head result.

## How to read this

Every number is best-of-5 over loopback, both nodes on one machine, both at
height 967,468. A single-call latency here is a *floor*, not a service level:
it is what one idle client sees.

**The confound that matters most: the mempools are not the same size.** bmc had
6,882 transactions and Core 74,333 — bmc only reached the tip today and its
pool is still filling. Any call whose cost scales with the mempool is therefore
**not** directly comparable, and those rows are normalised per transaction and
flagged. Rows on fixed work (a specific block, a specific UTXO set) are
directly comparable.

---

## 1. Trivial calls — parity

Both nodes answer in 2–3 ms; at this scale the number is HTTP and connection
setup, not the node.

| method | bmc | Core |
|---|---|---|
| `getblockcount` | 3 ms | 2 ms |
| `getbestblockhash` | 3 ms | 2 ms |
| `getblockhash` | 2 ms | 2 ms |
| `getnetworkinfo` | 2 ms | 2 ms |
| `getpeerinfo` | 2 ms | 2 ms |
| `getmininginfo` | 2 ms | 2 ms |
| `getindexinfo` | 2 ms | 2 ms |
| `getdeploymentinfo` | 2 ms | 3 ms |
| `getaddrmaninfo` | 2 ms | 2 ms |
| `listbanned` | 2 ms | 2 ms |
| `uptime` | 2 ms | 3 ms |
| `getdifficulty` | 2 ms | 2 ms |
| `getconnectioncount` | 2 ms | 2 ms |
| `getblockchaininfo` | 5 ms | 2 ms |

## 2. Fixed workload — directly comparable

Same block, same UTXO set, no mempool dependence. **These are the honest
head-to-head rows.**

| call | bmc | Core | ratio |
|---|---|---|---|
| `getblock` 900,000 verbosity 1 | **3 ms** | 5 ms | 1.7× faster |
| `getblock` 900,000 verbosity 2 | **31 ms** | 53 ms | 1.7× faster |
| `gettxoutsetinfo muhash` | 4 ms | 4 ms | parity |
| `getchaintips` | **2 ms** | 97 ms | 48× faster |

## 3. Mempool-dependent — normalised, because the pools differ 10×

| call | bmc (6,882 tx) | Core (74,333 tx) | per transaction |
|---|---|---|---|
| `getrawmempool` (ids) | 5 ms | 104 ms | bmc 0.73 µs vs Core 1.40 µs — **bmc ~1.9×** |
| `getrawmempool verbose` | 63 ms | 664 ms | bmc 9.15 µs vs Core 8.93 µs — **parity, Core marginally ahead** |
| `getmempoolinfo` | 4 ms | 2 ms | bmc still walks every slot for `bytes`; Core keeps a counter |
| `getblocktemplate` | 22 ms | 53 ms | **not comparable** — the templates are built from different pools |

The raw `getrawmempool verbose` numbers look like a 10× bmc win. They are not.
Per transaction it is a wash, and Core is very slightly ahead.

## 4. Concurrency — partly fixed, and still the largest gap

Total wall time for N simultaneous clients. Three methods, because they now
behave differently from one another:

| clients | `getpeerinfo` bmc | Core | `getmempoolinfo` bmc | Core | `getblockchaininfo` bmc | Core |
|---|---|---|---|---|---|---|
| 1 | 4 ms | 3 ms | 7 ms | 3 ms | 9 ms | 4 ms |
| 4 | 4 ms | 4 ms | — | — | — | — |
| 16 | **5 ms** | 6 ms | 38 ms | 5 ms | 47 ms | 5 ms |
| 32 | **8 ms** | 10 ms | 55 ms | 22 ms | **82 ms** | 7 ms |

Three different situations, and the difference between them is the whole
story:

**`getpeerinfo` is flat and now beats Core.** As of PR #255 it takes the READ
side of `g_exec_lock`, which became a writer-preferring `pthread_rwlock`. It
could, because the exec lock was never what protected it: the peer tables and
`g_node_status` are written by the download worker *without* that lock
(`dl_publish_peer_table`), so serialising readers against each other bought
nothing. The same applies to `getconnectioncount` and `getnetworkinfo`.

**`getmempoolinfo` improved and still rises.** It is on the concurrent list,
but it takes the *mempool's* lock, which is a mutex — so concurrent callers
now serialise there instead. A different serialiser, a partial win.

**`getblockchaininfo` is unchanged, and stands for every chain read method.**
`refresh()` calls `store_reload()` on the single shared store handle
(`g_st`), so two of these cannot run at once. `getblock`,
`getrawtransaction`, and everything else that reads the archive share that
handle and one block buffer. They all still take the write side.

So the gap is no longer "bmc serialises everything" — it is "bmc serialises
everything that touches chain state", which is most of the interesting surface.
Core runs 16 RPC threads with fine-grained locks (`cs_main`, the mempool lock).

## 5. Memory

| | processes | RSS |
|---|---|---|
| bmc | 3 | 7.0 GB |
| Core | 2 | 6.7 GB |

Both configured `dbcache=8192` / `4096` respectively. Roughly level.

## 6. Disk

| component | bmc | Core |
|---|---|---|
| blocks (`blk*.dat`) | 716.6 GB | 716.6 GB |
| undo (`rev*.dat`) | **246.6 GB** | 100.0 GB |
| txindex | **26.9 GB** | 68.8 GB |
| block filter index | 12.2 GB | 12.3 GB |
| coinstatsindex | 1.8 GB | 0.2 GB |
| UTXO set | 12.8 GB (LSM runs) | 10.6 GB (chainstate) |
| address history + journal | 203.6 GB | *no equivalent* |
| txospender index | 91.5 GB | *no equivalent* |
| **total datadir** | **1312.4 GB** | **917.7 GB** |

Block storage matches to the tenth of a GB, which is an independent check on
the archive alongside the hash comparison in
[reports/2026-09-17-run26-vs-core.md](reports/2026-09-17-run26-vs-core.md).

---

## Why each difference exists

**txindex, 2.6× smaller than Core's.** It is a set of sorted runs with a sparse
index, in a fixed record format; Core's is a LevelDB keyspace, which pays SST
block overhead, key duplication across levels, and space amplification from
compaction. The same structure is why `getrawmempool` ids and the `getblock`
paths are cheap: a sparse binary search plus a direct read, no block cache.

**Undo, 2.5× larger than Core's — and this is deliberate.** bmc stores each
spent prevout's *script and value* in its block's undo record. Core stores the
minimum needed to disconnect a block. That extra data is what makes a height
range self-contained, which is what lets the address history build in runs
*during* the sync instead of by a whole-chain join afterwards. The 700 GB of
temp the old whole-chain builder needed existed precisely because it had no
undo to read. It is the price of a feature Core does not have.

**`getchaintips`, 48× faster.** Core enumerates candidate tips by walking its
whole block index. bmc keeps a header tree and answers from it. This is a real
structural difference, though `getchaintips` is a rare call.

**`getmempoolinfo`, still behind.** Core maintains running totals
(`totalTxSize`, `m_total_fee`, `cachedInnerUsage`) updated on add and remove —
O(1). bmc now gets `total_fee` in one pass but still walks every slot to
compute `bytes`, deliberately: that keeps `bytes` an independent computation
from the policy registry's own vsize, which is what makes the two cross-checkable.

**Concurrency.** Core's handlers take fine-grained locks (`cs_main`, the
mempool lock) and run on a thread pool. bmc serialises every handler under one
lock. That is a correctness decision, not an oversight — the handlers share
mutable state (a single block buffer, per-query caches, the run-set globals) —
but it is the dominant limit on multi-client throughput.

**`getblock` verbosity 2, 1.7× faster — hypothesis, not a measured cause.**
bmc reads the block from the flat archive and renders directly; Core goes
through its block index and deserialises. I have not profiled either side, so
treat the *reason* as unverified even though the number is not.

---

## What we have NOT measured

Nothing below has a number yet. Do not let the tables above stand in for them.

1. **Initial block download, head to head.** The only Core baseline on this box
   (19h 14m) ran on a Samsung Portable SSD T5 at 0.40 GB/s while run 26 ran on
   NVMe. That comparison was withdrawn. A matched pair — same device, same day,
   every index each node supports, configs recorded before launch — is pending
   the new SSD.
2. **Block validation throughput** — blocks per second connected, and the
   time from a new block arriving to the tip advancing. This is the number that
   actually matters for a node keeping up with the chain.
3. **Reorg handling time.**
4. **Equal-mempool comparison.** Every mempool row here is normalised
   arithmetic, not a measurement at matched size. Re-run when bmc's pool
   reaches Core's.
5. **Sustained load and tail latency.** Everything here is best-of-5 on an idle
   node. p99 under continuous load is a different question, and given the
   serial execution lock, probably a much less flattering one.
6. **Cold cache.** All RPC rows are warm. `getaddressbalance` measured 40 s cold
   against 0.6 s warm on a 191 GB run set — a 60× spread that the warm number
   hides completely.
7. **Boot time.** bmc takes 30–75 s from launch to answering RPC; Core's is
   unmeasured.
8. **Address queries under concurrency**, and at a journal near its rotation
   size (see below).
9. **Memory under mempool pressure** — both were measured with bmc's pool at a
   tenth of Core's.

---

## Closing or exceeding the gaps

**1. RPC concurrency — still the biggest one, now half done.** The
reader/writer split landed in PR #255, and the four methods that share no
mutable state are concurrent. What remains is the chain read path, and the
specific blocker is named: `refresh()` mutates the single shared store handle
`g_st`, and the archive readers share one `g_blockbuf`.

The tractable path from here:
  - `g_st` and `g_blockbuf` become thread-local (4 KB and ~4 MB per thread —
    cheap at 8–16 threads);
  - `idx_sync` and the `irunset_t` run-set remapping get their own mutex,
    since those genuinely mutate shared mappings;
  - the concurrent list then grows to `getblock`, `getrawtransaction`,
    `getblockchaininfo`, `getblockheader` — the bulk of what an explorer polls.

The risk is real and specific: `store_read_at` and `store_reload` are
assembly, and whether they keep per-call state in the handle has to be read
out of `bitcoin_store_fast.asm` before any of this is safe. A missed piece of
shared state is a data race, not a slow query.

A cheaper intermediate that needs none of that: the response *write* is
outside the lock (PR #248), but the *render* is not. Rendering a 5 MB
`getrawmempool` reply still holds the write lock for its duration.

**2. `getmempoolinfo` `bytes`.** Maintain a running byte total the way Core
does, and keep the full walk as a periodic audit rather than the hot path.
Gets the last mempool-dependent term off the per-call cost.

**3. The address-query floor (~300 ms).** Dominated by scanning the journal,
which is 12.6 GB now and grows to roughly 33 GB before the next rotation at
`bmc.indexrunblocks=20000`. Two options: a smaller run interval for
`addr_hist` specifically, so the journal rotates sooner; or a height index over
the journal so a windowed query seeks instead of scanning. The second is
strictly better and composes with the pagination already added in PR #247.

**4. `getrawmempool verbose`.** At parity per transaction, so there is no
algorithmic win left — the cost is the reply size (5 MB at 6,882 transactions,
and it will be ~50 MB at Core's pool size). Pagination is the answer, as it
was for `getaddresstxids`.

**5. Where bmc should stay ahead.** The sorted-run index format is genuinely
cheaper than LevelDB for this access pattern, and the flat archive is cheaper
than a block-index lookup. Those advantages are structural and worth protecting
when the indexes change.

---

## Regressions found and fixed on 2026-09-17

All seven were the same shape: a per-item lookup that is itself a scan, inside
a loop over all items. Two of them would have become *unusable* rather than
merely slow as bmc's mempool grew toward Core's, because the cost rises with
the square.

| call | before | after | what it was |
|---|---|---|---|
| `getaddresstxids` (1dice8EM) | 13,555 ms | 410 ms | three separate O(n²) dedups |
| `getaddressbalance` | 4,596 ms | 319 ms | whole-journal slurp per query |
| `getblocktemplate` | 1,664 ms | 22 ms | four quadratic passes |
| `getmempoolentry` | 36 ms | 4 ms | full scan per descendant walk |
| `getmempoolinfo` | 15 ms | 4 ms | fee lookup per slot, each a scan |

The root cause of the last three was that `mpool_policy_entry`/`entry_info`
scanned the node array while a maintained hash index sat unused beside them
(PR #252), and that no reverse index existed for children (PR #253).

Concurrency (PR #255) is counted separately because it is not a quadratic
loop: `getpeerinfo` went from rising linearly with client count to flat, by
taking the read side of a lock that never protected it.

| | before | after |
|---|---|---|
| `getpeerinfo`, 32 clients | 80 ms (serialised) | 8 ms |

**One of these was a correctness bug, not a performance bug**: past 2 GB of
journal, `getaddressbalance` silently answered from the history runs alone and
returned wrong balances, because a short `pread` was reported as an error and
the caller discarded it. See PR #246.

---

## Known failing test

`test_rpc_esplora_stress` fails and has since before this work began — the
Esplora `/address` route makes 371 RPC dispatches where the suite asserts at
most 2. It is an efficiency assertion, not a wrong answer, and it is
undiagnosed. Written up in
[FEATURE_GAPS.md](FEATURE_GAPS.md#update-2026-09-17--a-failing-test-nobody-was-running).

Every other figure in this document comes from a suite that passes, or from a
direct measurement against the live node.
