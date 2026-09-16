# Every index builds during the sync (2026-09-16)

> The operator's requirement, verbatim: *"Make it so there is nothing left to
> do after ibd but just sit and update. Everything should be generated during
> ibd."* This is the design that meets it, and the record of what stood in the
> way.

## What stood in the way

Before today a fresh sync ended with four things still to build, and they were
built by hand or by a supervisor that refused to run until the sync was over:

| index | during the sync | after the sync |
|---|---|---|
| txindex | tail *disabled* without a base ("a from-genesis tail would be a 29 GB linear scan") | `bmc_build_tx_index`, one walk of the whole archive, output sorted |
| txospenderindex | same | `bmc_build_txospender_index`, same |
| address history (`addr_hist`) | the journal grew unbounded (165 GB at 43% of mainnet on run 24; one balance query scanned it all and starved the sync) | `bmc_build_addr_hist`: three passes, ~700 GB of temp, hours; and only a *fresh* journal adopted the result |
| block filters | the daemon refused to touch the files until an offline backfill came within the undo window | `bmc_build_block_filters`, resolving every prevout through the txid index |
| coinstatsindex | **invalidated at height 91,842** by the first BIP30 duplicate coinbase ("will re-seed") and gone for the rest of the sync | a full UTXO walk at the next boot |

The deferrals were explicit in code (`index_repair.c`: `if (in_ibd) ... "waits
for initial block download to finish"`) and each had a reason that was true when
it was written. None of them is fundamental.

## The design: sorted runs, a bounded tail, a trailing builder

Three of the four indexes are "a sorted base file plus an unsorted tail". The
base could only be made by a whole-chain walk, so it could not be made during
the sync. The LSM answer:

- **A run set** (`daemon/index_runs.h`): the index is any number of sorted
  files, each covering a contiguous height range, in exactly the base's on-disk
  format. `<name>.dat` (a node's existing base) is simply the run that starts
  at 0; new runs are `<name>.r<from>-<to>.dat`, zero-padded so a listing sorts
  by height. A lookup asks each run (sparse binary search, then the archive
  verifies every candidate as it always did), then the tail.
- **A trailing builder** (`daemon/index_trail.h`): at the block choke point
  (and at the caught-up loop's heartbeat, where the choke point is quiet),
  once `bmc.indexrunblocks` heights (default 20,000) are applied below a safety
  margin of 144 (the undo window; a reorg deeper than that is already the
  node's general limit), it spawns the builder over that range into a new run
  file, at nice 10, one child per index. On success it tells the tail to
  rotate. There is no IBD gate and no attempt cap: this is a standing job on a
  node that runs for months, not a one-shot repair. It keeps trailing after the
  sync at the same cadence, which is what "sit and update" means.
- **Tail rotation**: when a run to height H commits, the tail's records at or
  below H are duplicates of sorted ones and are dropped by rewriting the file
  (the tails are height-ordered, so this is a prefix). The linear scan a lookup
  makes over the tail is therefore bounded by the run interval, never the
  chain — which is the argument that made "no base ⇒ tail disabled" necessary,
  inverted.
- **Merging** (`daemon/merge_index_runs.c`): at six runs the supervisor spawns
  a streaming k-way merge into one run over the union range — no re-walk of the
  archive, no temp buckets — written `.tmp` and renamed, the inputs unlinked
  only afterwards (a reader that still has an input mapped keeps a valid
  mapping: the inode outlives the name). For the fixed-record formats the
  merged file is byte-identical to a single build over the union range, and
  `test_index_runs` asserts exactly that.

The builders already took `[from] [to]`; they gained `[out]`. The address
history builder gained a **run mode** in which spends come from **undo**
instead of a whole-chain join: undo is kept for every block now
(`undo_store.h`, 2026-09-08), so a range is self-contained — each spent
prevout's script and value are in its block's own undo records, and the
spender's `(txpos, vin)` are in the block. That is the fact that makes the
address history buildable in runs at all; the 700 GB of temp existed because
the whole-chain builder had no undo to read.

Block filters need none of this: they are positional by height and the daemon
already had a per-block builder from undo. It now creates the files itself and
builds from genesis at the choke point, closing any gap in slices of 256
heights per call so a large catch-up never stalls the apply path.

The coinstats index needed one thing: describing the BIP30 overwrite as
`remove(old coin) + add(new coin)` — what Core's coinstatsindex does — instead
of invalidating. The old coin *is* in scope at that point (it is still in the
set until the `del` that follows), which the comment there said it was not.

## What a fresh sync looks like now

`txindex=1`, `txospenderindex=1`, `addrindex=1`, `blockfilterindex=1`,
`coinstatsindex=1`: every one is built by the daemon, behind the applied
height, from the first blocks; `getindexinfo` reports each one's reach as it
grows; and when the sync ends nothing starts — the same trailing builders keep
folding the tails every 20,000 blocks, forever. The `[idx]` and `[txindex]` /
`[txospender]` / `[addr_hist]` trail lines in `debug.log` are the record.

`txindex=1` now means what it means in Core. It used to print "has no effect".

## Costs, honestly

- Disk during the sync: a run costs one archive walk over its range (its
  blocks are still in page cache from the apply, mostly) and its output is the
  compacted size; the tails never exceed one run interval. The address journal
  on run 26 was 46 GB at 366k before this landed; it will be ≤ one run's worth
  afterwards.
- CPU: one nice-10 builder per index at a time; the merge is streaming.
  Nothing runs on the apply path except the filter construction per block
  (milliseconds) and the tails' appends, both of which were already there.
- Lookups: each run is one sparse binary search; the merge policy keeps the
  count small. Address balances now come from the history runs' events plus
  the journal, and `getaddresstxids` resolves a run event's txid by reading its
  block — one read per distinct height per call.

## Measured, on a fresh node

Run 26, wiped and restarted from genesis on `b28ffcf1`, five minutes in at
height 188,400:

```
txindex                   synced: true    188,400
txospenderindex           synced: true    188,400
basic block filter index  synced: true    188,400
addressindex              synced: true    188,400
coinstatsindex            synced: false   187,391   (normal apply lag)
```

Nine runs per index by then, each built in 1-4 seconds, with the tails rotated
after every one (`[addrindex] journal rotated: 6,285,189 records folded into
history runs (to 179999), 1,796,864 kept`) and the merger already collapsing
them: 27 runs built, 12 files on disk. Compare the same node before this
work: at 43% of the chain its address journal alone was 165 GB, one balance
query scanned all of it, and four indexes had not started.

## The bug this nearly shipped with

The first version put the supervisors' tick in the caught-up loop's heartbeat.
Initial block download never reaches that heartbeat -- the node runs the
parallel catch-up loop instead -- so during the one phase the feature exists
for, nothing ticked and no run was ever built. Every index looked healthy;
only the absence of run files showed it, and the supervisors were silent
because a supervisor idle for a reason logs nothing.

Two things fixed it and both are worth keeping: the tick moved to the block
choke point (which runs in every phase, and is where the filter index and the
tails are already fed), and a `[trail]` line every five minutes prints each
supervisor's state through `it_status()` -- a function the module had and
nothing ever called. Silence in a log reads exactly like "working".

## Pins

Every piece has a test that fails against the code it replaced, checked by
reverting: `test_index_runs` (set, merge byte-identity), `test_index_trail`
(the supervisor's state machine through its spawn seam),
`test_rpc_chain` (base + run + tail, all three lookup paths on every txid),
`test_txindex_tail` / `test_txospender_index` (genesis start, rotation),
`test_bfilter_index` (self-build, sliced gap close), `test_addr_hist` (run mode
from undo equals the whole-chain build; two runs read as one; the merge),
`test_addr_index_tail` (journal rotation), `test_bip30_overwrite` (coinstats
survives the overwrite: remove old, add new, no invalidation).

## What is left

- The two `bmc_build_*` whole-chain modes and the post-IBD orchestrator script
  are retired for fresh syncs; they still work for a node that wants a single
  base rebuilt.
- `bmc.indexrunblocks` is one knob for all three run sets; the address history
  may want a smaller interval late in the chain (its journal is the largest per
  block). Measure on run 26 before changing it.
