# The frontier guard, verified on a live restart (2026-09-18)

`b95e0d19` shipped with an explicit caveat in its own commit message:

> STATE: dry-run assembled (the project's asm rule), 18 archive/store/sync/reorg
> suites pass, deployed to run 26 and the node is healthy. **NOT verified on a
> real append landing at the frontier** -- that was in progress when the
> corruption surfaced. That verification is the gate before this merges.

That gate is now closed, twice: once synthetically, once on the live archive.

## 1. The synthetic gate (`tests/test_frontier_append.c`)

Builds the run 26 condition -- a cursor that is merely BEHIND while a newer
`blk` file already exists -- then appends for real and reads the payload back
through the on-disk index record.

| height | condition | must land in |
| --- | --- | --- |
| h0 | cursor *is* the frontier | `blk00000` |
| h1 | `blk00001` exists, cursor still 0 | `blk00001`, past its existing bytes |
| h2 | `blk00002` + `blk00003` exist | `blk00003` (the guard loops) |
| h3 | a second handle at the frontier | `blk00003` |
| h4 | the first handle's cursor falls back to 0 | not below h3's file |

**Watched to fail.** With the guard reverted and both objects rebuilt from
scratch, 8 checks go red: h1 lands in `blk00000` at offset 72 -- the tail gap --
and `blk00000` grows 72 -> 144. With the guard, 30 of 30 pass.

One assertion had to be rewritten before it meant anything. The monotonic check
was VACUOUS in its first form: h0..h2 all landed in file 0 with rising offsets,
so the records were monotonic among themselves and the check passed even
unfixed, because the synthetic newer files held no INDEXED blocks. The h3/h4
two-handle phase exists to fix that.

## 2. The live gate: run 26's restart, 2026-09-18 02:07 UTC

Run 26 was stopped cleanly at 22:48 on 09-17. On restart `store_reload` set the
cursor from the tip record, and the tip lived in an old file -- the exact
self-perpetuating condition the guard was written for, at a severity none of the
synthetic cases reached:

```
cursor restored to file 3399   (tip h=967473 at 3399:132376343)
frontier on disk    file 5762
gap                 2363 files
```

Every one of run 26's six existing layout breaks was the first block after a
restart. Without the guard this restart produces the seventh. What actually
happened:

```
height    file          pos
967473     3399    132376343
967474     5762     69588239   <-- moved up 2363 files
967475     5762     71121462
967476     5762     72786835
...        5762     (sequential from here)
```

`69588239` is exactly the prior size of `blk05762.dat`. The append landed at the
true end of the frontier file, not in anybody's tail gap.

**Layout breaks across the whole archive: 6 before the restart, 6 after.** The
binary in use (`bmcbitcoind.run26`, built 22:40:49) carries the guard --
confirmed by disassembly, `store_append_shared_x.frontier` and `.frontier_done`
present with `mov $0x15,%eax` (access) + syscall right after `fmt_blkname`.
Its `BUILD_COMMIT` file says `07256990` and is STALE; it was written at 21:41,
an hour before the binary. Read the symbols, not the sidecar.

## 3. Block 967422, repaired

The corruption recorded in `RESUME_2026-09-17.md` was real and still present:
genesis sat at offset 0 of `blk05762.dat`, where 967422 should start, and the
index pointed h=967422 there. Diffed against the production archive's copy of
the same block, the damage was exactly bytes `[0, 292]` -- 293 bytes, and
nothing else in the 1.58 MB block differed.

Repaired with a single 293-byte write at offset 0, sourced from
`data/main/blk05758.dat:43644797` and hash-verified before it was written. The
old bytes were captured first. Afterwards: file size unchanged, frame length
1577505 and magic `f9beb4d9` correct, header double-SHA equal to the index
record's hash, and the full 1,577,513-byte frame byte-identical to production.
Through run 26's own RPC the block now answers `nTx 4098, size 1577505`; before
the repair it answered as a 1-transaction block.

## What is still open

The six pre-existing breaks are untouched. They are why truncation and pruning
still refuse to run, and closing them needs `tests/tool_archive_relayout` to
rewrite the archive in height order -- 1.3 TB of rewriting -- or run 27 to
replace it. Chain correctness was never affected by them.
