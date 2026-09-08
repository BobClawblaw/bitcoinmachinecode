# 2026-09-08 — Undo data is kept for every block, like Core

The node wrote one `undo_<h>.dat` per block and deleted them behind a
200-block window. Everything that reads undo data stopped at that window:
`getblock` verbosity 2 and 3 lost `fee` and `prevout` for older blocks,
`getrawtransaction` verbosity 2 and `getblockstats` the same, the address
index could not backfill past it, and a reorg deeper than the window was
physically impossible. mempool.space wants fees and prevouts for the whole
chain. Core keeps undo data for every block unless the node prunes, in
`rev*.dat` files beside the `blk*.dat` files. So do we now.

## The store

`daemon/undo_store.h`, header-only. `rev%05u.dat` files hold append-only
runs, one run per block, rotated at 128 MiB like the block files; a run is
the block's spent-input records in spend order (the same record the module
always wrote), closed by an END marker. `undo.idx` has 16 bytes per height:
file, offset, tag. The module's API is unchanged for its callers; two calls
were added. `undo_commit(height)` writes END after a successful apply, and a
block that spent nothing gets an empty run, so "undo exists for h" means "h
was applied". `undo_exists(height)` replaces the callers' `stat()` of the
old file name.

The semantics every consumer relied on with one file per height survive.
An entry above the applied height is a ghost block whose spends were
durable before its checkpoint; boot recovery rolls it back as before. A run
that has no END yet reads as its whole records, as a file read to its end;
a partial record is torn, which the strict readers refuse and the tolerant
replay stops at. A discard clears the entry and leaves the bytes as
unreachable orphans, so a block reconnected at the same height starts a
fresh run and can never have a stale file prepended to it. A run left open
by a failed apply is sealed before the next run starts, so runs never bleed
into each other.

## Retention

None in steady state. When the block store prunes below a height, every
height below loses its entry and the rev files that hold only such heights
are deleted, Core's whole-file rule. `REORG_MAX_DEPTH` (100) is policy now,
not a physical limit.

## Existing archives

A node upgraded to this build folds its remaining `undo_<h>.dat` files into
the store once at start, so its recent history and reorg depth survive. It
has no undo data for older blocks, because none was ever kept; a full
history needs `-reindex-chainstate`, the UTXO replay that regenerates it,
which is what Core would need too. Production's history therefore starts at
this deploy until that replay is scheduled.

## Tests

`test_undo_log` rewritten on the store: retention (watched to fail on the
old module: `undo_load(10)` after the old window's prune returned 0 there
and 1 here), prune-below, open, closed and torn runs, discard and a fresh
run at the same height, the legacy migration. `test_rpc_chain` writes its
fixture run through the store; `test_reorg` discards through the API. The
crash-recovery, checkpoint-batch, ghost-resume, rollback, reorg-ordering,
address-index and filter-index tests pass with their assertions unchanged.
`bitcoin_undo.asm`, never linked into the daemon, keeps its diff test against
a frozen copy of the old module.
