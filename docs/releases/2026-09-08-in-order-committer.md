# 2026-09-08 — The in-order committer: the archive is written by one process in height order

"WHY IS THE BLOCK DATA STILL NOT MONOTONIC FOR US?!"

Every node this download built printed, at boot, `[check] block data is
NOT laid out monotonically (first break at height 41) -- truncation and
pruning will refuse to run`. The archive is a set of `blk*.dat` files plus
an index with one 48-byte record per height naming the file and offset.
"Laid out monotonically" means the offset increases with the height.
Sixteen workers each landed a 40-block chunk as it arrived, so the first
chunk boundary broke the order at height 41. In-place pruning refused on
such an archive and physical truncation fell back to the index-only path,
which reclaims no space. The monotonic-download work of 2026-09-07 (PR #77)
had made the claim window monotonic, not the layout: nothing was requested
past 4,096 blocks above the first hole, but a block's bytes still landed
wherever its worker happened to be.

## What changed

A worker no longer touches the archive. It fetches and verifies its chunk
exactly as before (`cons_verify`, the header hash, the prev link) and
writes the blocks, in ascending height order, to a staging file
`stage/c<lo>.chunk` in the chain directory through a sink hook on the
fetch pipeline, then renames the file complete.

One committer process, forked beside the workers, appends staged chunks
to the archive strictly from the first hole upward. It validates a whole
file before appending any of it, so a torn or misordered file is discarded
and fetched again; it skips heights that are already present, which is
what a resumed datadir looks like; it deletes each file after the append
and publishes the first hole and the committed tip in the shared control
block. The archive is therefore written by a single sequential writer and
never has a hole. A staging file that lives a few seconds never reaches
the disk; the page cache absorbs it.

A chunk missing at the cursor is the case the window's help path already
handles: an idle worker fetches it after two seconds. A chunk that is
staged and waiting for the committer is guarded from being fetched again.
The committer does `store_reload` before its first append so that it
writes to the newest `blk` file (`store_init` names file 0, and an append
there would have filled the end of the first file, another route to a
non-monotonic layout). The parent restarts it if it dies, drains it when
the last worker is reaped, before the final status tick, and stops it with
the workers on shutdown or a mid-download rejection. Stale staging files
from an earlier run are discarded at start.

The tick line gains two figures: `staged N commit M`, the chunks waiting
for the committer right now and the chunks it has appended.

## What it means for an existing archive

An archive built before this change keeps its arrival-order layout; the
boot check keeps saying so, and `tests/tool_archive_relayout` rewrites it
in height order (see OPERATIONS, "Archive re-layout"). A fresh sync on this
build passes the check. Run 17 on the benchmark box was stopped and run 18
started fresh on this build for that reason.

## Tests

- `test_dialhelper` +19: the sink and the publish rename; a commit in order
  with the staged bytes and hashes; the present-height skip; a torn file
  and a gap commit nothing and are discarded; a not-yet-staged chunk is a
  wait; the loop drains two chunks and exits at the missing one once STOP
  is set, publishing first hole 180 and committed tip 179; the help guard;
  the wipe.
- `test_dlc_interleave` asserts `archive_layout_monotonic == -1` after its
  real three-worker download and that the committer reported. Watched to
  fail on the reverted daemon: first break at height 40.

Gate `make -j8 test`: 0 failures (the one expected test_rpc_signer
segfault); 8 static audits exit 0.
