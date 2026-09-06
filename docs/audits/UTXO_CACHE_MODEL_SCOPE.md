# Moving the UTXO store to Core's in-RAM cache model — scope

**Date:** 2026-09-06. **Companions:** `UTXO_INLINE_BUILD_PERF_SCOPE.md`
(the 3-hour gap is a *serial* phase; interleaving connect into the download
removes it) and `UTXO_INLINE_CONNECT_SCOPE.md` (the semantics). This
document scopes the third thing: making the connect step itself cheaper by
adopting Core's cache-and-flush model. It is **additive** to the interleave
work, and it only pays where connect is the bottleneck — which, after the
interleave, is the `assumevalid=0` headline run and the tip-end lag, not
the default IBD.

## 1. Core's model, precisely

`CCoinsViewCache` is an in-RAM map outpoint → coin with two flags per entry:
*dirty* (differs from the layer below) and *fresh* (created since the last
flush, so the layer below has never seen it). Every `ConnectBlock` reads
and writes only the cache. There is **no write-ahead log**. The cache is
written to LevelDB in one batch — a *flush* — when it exceeds `-dbcache`
(8 GB in the benchmark, ≈ 100M coins), on a periodic timer, or at
shutdown; a *fresh* coin that was spent before the flush is simply dropped
and never touches disk. After a crash the database is consistent at its
recorded best block and the node **re-connects the blocks above it from the
block files**. Reads that miss the cache go to LevelDB, which compacts
incrementally (leveled), never rewriting the whole set at once.

The three properties that matter for IBD: no per-operation durability
cost; most short-lived outputs never reach disk; the redo log *is* the
block archive.

## 2. What we have, mapped onto it

| Core | here | file |
|---|---|---|
| `CCoinsViewCache` | the memtable: 48-byte slots + a blob; 4M slots / 1 GB in bulk mode, 64k / 64 MB in steady state | `bitcoin_utxo.asm`, `utxo_live.c:166-197` |
| — (none) | **`utxo.dat`, a WAL**: every PUSH and DEL appended; **checkpoint** (`utxo.idx`) fsyncs both files every 64 blocks or 2 s | `bitcoin_utxo_store.asm`, `utxo_live.c:2891` |
| LevelDB | immutable sorted **runs** with Bloom filters and a crash-safe manifest; a *flush* writes the memtable's live entries plus tombstones as a new run | `bitcoin_utxo_lsm.asm` |
| leveled compaction | **size-tiered merge** since 79d4c9c (2026-08-31): `lsm_compact_pick` walks the manifest newest-first over the run files' sizes, a run joins the batch while it is at most 4x (`LSM_COMPACT_RATIO`) everything newer than it, and `utxo_lsm_compact_range` merges just that batch, keeping its tombstones when runs remain below it. The base is rewritten only once everything above it has grown to a quarter of it. (This document's first draft said "all runs → one"; that was stale on the day it was written -- see §4.2.) | `utxo_lsm_compact_range`, `daemon/lsm_manifest.c`, `compact_pick_now` in `utxo_live.c` |
| re-connect from block files | `utxo_applied_height.dat` + WAL replay from the last checkpoint + undo-based unapply of a half-applied block | `utxo_live_recover_at_boot` |
| single process, one lock | **many processes**: every inbound serve child and the RPC path take a read snapshot by replaying the current WAL generation (`utxo_lsm_reload`, `reload_ro`) | `tx_accept.c:5-8`, `utxo_setinfo_rpc.c` |

So the structural idea is already Core's — a bounded cache in front of an
LSM. Three things differ, and they are the whole of this scope:

1. **The WAL.** Every one of the ~6.4 billion PUSH/DEL operations in a full
   sync is appended to `utxo.dat` (≈ 380 GB of sequential writes at ~60
   bytes each) and fsynced every 64 blocks. Core writes nothing per
   operation.
2. **The cache size and flush cadence.** 4M entries flush roughly every
   ~600 tip-era blocks; an 8 GB `dbcache` flushes every ~100M coins. A
   smaller cache means more flushes *and* a lower hit rate for spends of
   older outputs (each miss is a Bloom-gated run lookup).
3. **Compaction.** Already tiered (79d4c9c): a compaction rewrites the
   young tier, and the base only when the young tier has reached a quarter
   of it. The all-runs-to-one merge that the 2026-08-18 measurement in
   `utxo_live.c` describes (and that led to bulk mode and background
   compaction) is the negative control now, not the shipped path -- see
   §4.2 for the measured numbers.

Fresh-coin elision, the property that sounds like the big one, we already
have at flush time: a coin created and spent within one memtable
generation is written as nothing. What we pay for it is the WAL entry, twice.

## 3. The constraint Core does not have

Every inbound serve child validates transactions against a snapshot it takes
at connection start by replaying the WAL generation; the RPC parent does the
same for `gettxout`/`gettxoutsetinfo`. **Remove the WAL and those readers
see only the last flushed state** — with an 8 GB cache that could be tens of
thousands of blocks stale: a spend of an output created after the last
flush would be judged against a set that does not contain it.

This is why the model cannot simply be adopted wholesale, and it is also
what makes the split obvious:

- **Bulk mode** (catching up, applied height far below the stored tip):
  Core does not accept mempool transactions during IBD, and our children's
  snapshot is already stale by the catch-up's own definition. Readers do
  not need the WAL here.
- **Steady state** (at the tip): readers need a current view; the WAL and
  the 64-block checkpoint stay exactly as they are. The cost is a few
  operations per block, invisible.

So: **Core's model in bulk mode only; today's model at the tip.** The mode
switch already exists (`utxo_live.c:3076`, the "caught up — downshifting"
transition) and only its thresholds change.

## 4. Design

### 4.1 Cache mode (bulk): no WAL, size-triggered flush, archive redo

- **No `utxo.dat` appends and no checkpoints while in bulk mode.** The
  memtable is the only record of the current generation.
- **Flush when the memtable reaches its size** (the `dbcache` analogue,
  `bmc.utxocache` in MiB, default sized to the machine: the bench host ran
  30 GB RSS in bulk mode already) **or every `N` blocks** (a redo bound;
  proposal 10,000 blocks ≈ minutes of redo, seconds at the light end). A
  flush is what it is today — live entries plus tombstones as a new run,
  manifest rename — followed by `utxo_applied_height.dat` = the flushed
  height, fsynced. That file becomes the *only* durable height in bulk mode.
- **Recovery = redo from the archive.** At boot, if the persisted applied
  height is below the stored tip, connect forward from it — which is exactly
  what `utxo_live_catchup` already does. The half-applied-block unapply path
  (`recover_partial_block`) becomes unnecessary in bulk mode because nothing
  partial was ever persisted; it stays for steady state. The undo files
  (`undo_<height>.dat`) are unchanged: reorg handling does not depend on
  the WAL.
- **Cache sizing.** 48-byte slots + blob: 2^26 slots (3.2 GB) with a
  4 GB blob holds ~40–60M coins; 2^27 / 8 GB holds ~100M, Core's 8 GB
  equivalent. The knob, not a constant; the RSS on the bench re-run decides
  the default.

### 4.2 Compaction: stop rewriting the whole set — already landed

**Correction (2026-09-06):** this section was written as if compaction were
still all-runs-to-one. It was not: commit 79d4c9c (2026-08-31, "utxo:
leveled compaction -- merge the newest runs by size ratio, keep their
tombstones") landed six days before this document. What the code does:

- `utxo_lsm_compact_range(lst, lo, k)` (`bitcoin_utxo_lsm.asm`) merges
  manifest entries `[lo, lo+k)` into one run that takes index `lo`, through
  the same streaming k-way merge and scratch layout as the full merge.
  `lo == 0` is the classic base merge; `lo > 0` must end at the newest run
  (a merge in the middle would put a fresh-generation run below older
  survivors and break the gen-ascending order `utxo_lsm_get` scans). The
  emit rule is "PUSH always; DEL only when runs exist below the batch": a
  tail merge **keeps** its tombstones -- they still cancel puts in the runs
  below, including the copy an in-batch PUT was shadowing (the BIP30 /
  reorg shapes) -- and a batch anchored at the oldest run drops them, as
  before, because nothing is below it.
- `lsm_compact_pick` (`daemon/lsm_manifest.c`) chooses the batch from the
  run files' sizes: walking from the newest run backwards, a run joins
  while it is at most `LSM_COMPACT_RATIO` (4) times everything newer than
  it combined; the first run that dwarfs the rest stops the walk. So
  fresh runs fold into a medium one, the medium joins once the smalls reach
  a quarter of it, and the base is rewritten only when everything above it
  has grown to a quarter of the base. `lsm_compact_pick_budget` adds the
  RAM-budget rule (above 35% of MemTotal in run files the count threshold
  becomes 2). `compact_pick_now` in `utxo_live.c` applies it for the forked
  background merge and for the boot-time pre-catch-up compaction.

Lookups still walk newest-first through Bloom filters, so read cost grows
with the number of *tiers*, not runs. **Measured** (`tests/test_utxo_tiered_compact`,
deterministic: 160 flushes of ~350 KB into a set that grows to 51.8 MB,
compact at 4 runs, spends aimed at every tier plus reorg- and BIP30-shaped
keys): the tiered policy ran 87 compactions -- 74 tail merges, 13 base
rewrites -- and wrote 335.6 MB, **6.5x** the final set; a tail merge's
output never exceeded its own inputs (+ Bloom rounding) and was under a
quarter of what was on disk (max 8.0 MB against 51.8 MB). The all-runs-to-one
control on the same workload ran 53 compactions and wrote 1394.5 MB,
**27.1x** the final set -- 4.15x the tiered total at this size, and the gap
widens with the set because the control is quadratic. Both end with the
identical live set. The earlier bench in 79d4c9c's message (500 MB set,
compact at 12) measured 22.5x vs 5.3x.

What remains open in this section is only the trigger: the count threshold
(`bmc.utxocompactthreshold`, x4 in bulk mode) and the RAM budget decide
*when*; the ratio decides *what*. Neither is gated on §4.1.

### 4.3 What does not change

The memtable's layout and the run format (the 2026-08-19 record shape,
readable by every tool in `daemon/`), the manifest, the Bloom filters,
`utxo_lsm_get`, the undo log, the coinstats fold on connect, and the
steady-state WAL + checkpoint path that every reader depends on.

## 5. What it is expected to buy

Honest framing: **§4.1 removes ~380 GB of sequential writes and ~15,000
fsync pairs from a full sync and raises the cache hit rate; it does not
change the script verification, which is the other half of connect.** Where
that lands depends on what step 0 of the perf scope measures:

- If WAL + checkpoint I/O is a first-order share of the 4.5 h bulk phase,
  cache mode takes that share out — and for the `assumevalid=0` run, where
  connect is the bottleneck end to end, it is worth hours.
- If verification dominates (the bench host has 26.6 effective cores of
  parallel verify, so this is plausible), cache mode is a memory-for-I/O
  trade with a small return, and §4.2 is the part still worth doing.

The interleave scope removes the 3-hour gap on its own; this scope is
about how fast the connect step can run once it is inside the download,
and it should be decided by the instrumentation, not by the analogy.

## 6. Tests and the proof

- `test_utxo_cache_mode` (gated): a synthetic chain in bulk mode with
  `N`-block flushes; kill (SIGKILL, not SIGTERM) at every phase — mid-block,
  between blocks, mid-flush, after the manifest rename, before the
  applied-height rename — and prove the boot redo reaches the same set
  (muhash equality against an uninterrupted run). **Negative control**: the
  same kills against today's WAL mode recover through the WAL path, and the
  two modes reach the same muhash.
- `test_utxo_tiered_compact` (gated, landed 2026-09-06): runs of known
  sizes through the real flush path; the policy touches only the tier it
  should (identity and bytes of the runs below every batch); lookups and
  the full walk resolve every key and every tombstone through every tier
  (the `test_lsm_lost_tombstones` / `test_utxo_lost_tombstones` cases
  extended across tiers with reorg- and BIP30-shaped keys); bytes written
  per compaction are bounded by the batch's inputs; **negative control**:
  all-runs-to-one on the same input, same resulting set, 4x the bytes.
  Watched to fail twice on scratch copies: ratio disabled (every pick the
  whole manifest) and `keep_dels` forced off (14,480 resurrected spends).
- The existing crash and checkpoint suites unchanged for steady state.
- **Proof**: the benchmark re-run with the perf scope's interleave *and*
  cache mode, reporting the bulk phase's write volume (from `/proc/<pid>/io`,
  which the bench driver already samples), fsync count, RSS peak, and the
  `assumevalid=0` end to end — the headline chart in the bench's own plan
  (its item 6).

## 7. Risks

- **Redo bound.** A crash in bulk mode costs re-connecting up to `N`
  blocks; at the tip end that is `N × ~200 ms`. 10,000 blocks is ~30 min
  worst case — acceptable for a mode the node is only in during a sync.
- **Memory.** A real `dbcache`-sized memtable plus the verify workers plus
  16 download helpers, if the interleave scope lands first. The bench
  already tolerated 30 GB; the knob and the re-run's RSS line are the
  guard.
- **Readers during bulk mode.** They see the last flushed state. Document
  it in `gettxout`'s and the serve child's behaviour during IBD
  (Core's equivalent: `-1` / "not in IBD" gating), and gate
  `gettxoutsetinfo` on the applied height as CSI-1 already does.
- **Two code paths.** Cache mode and WAL mode share the memtable and the
  runs but differ in durability. The test above kills both; the mode
  switch is the one place they meet, and it exists today.

## 8. Order, and the decision point

1. Perf scope step 0 (instrumentation) — it decides whether §4.1 is worth
   its risk. Nothing here starts before those numbers exist.
2. §4.2 tiered compaction: landed (79d4c9c) and now measured; nothing left to build here.
3. §4.1 cache mode, behind `bmc.utxocache` with WAL mode as the default
   until the re-run says otherwise.
4. The benchmark re-run, both halves, and the `assumevalid=0` chart.
