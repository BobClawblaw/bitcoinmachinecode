# The UTXO store's durability protocol, as the code implements it

Reverse-engineered from the integration branch `integ/2026-10-23-sec-all`
(b841251b), including the ST2-1..9 fixes. Paths are relative to `asm/`. "Synced"
means an fsync/fdatasync of that file returned 0; "dir-synced" means an fsync of
the chain directory did. Every file lives in the one chain directory.

## Files

| file | written by | content | synced when |
|---|---|---|---|
| `utxo.dat` (WAL) | `bitcoin_utxo_store.asm` `mac_wr_log` (199) via a 1 MB process buffer, `mac_wal_drain_fd` (253) | PUSH (59 B + script) / DEL (44 B) records, magic + op byte, no checksum | checkpoint only: `persist_applied_height` `fsync(log_fd)` (`daemon/utxo_live.c:1297`); `utxo_store_close` |
| `utxo.idx` | inline flush: `ftruncate` to 0 (`bitcoin_utxo_lsm.asm:3307`); async: `fz_retire_wal` tmp+rename (`daemon/utxo_live.c:767-797`) | `{magic, log_off, n=0}`: WAL bytes below `log_off` are retired | tmp fsynced before the rename (772); dir fsync result ignored (781) |
| `utxo_run_NNNNNN.dat` | `mac_build_run` (`bitcoin_utxo_lsm.asm:2693-3148`), inline or in the forked writer; the compaction (`utxo_lsm_compact`, 4537-5400) | sorted PUSH/tombstone records, Bloom, sparse index | fsynced before close, result checked (ST2-1: 3105-3118, 5123-5136) |
| `utxo_manifest.dat` | asm flush (3225-3293), asm compaction (5270-5342), C `lsm_manifest_publish` (`daemon/lsm_manifest.c:64-80`) | the run list (oldest first) + persisted live count | tmp fsynced before rename (checked everywhere); dir fsync checked in asm (3276-3293, 5335-5341), **ignored in C** (lsm_manifest.c:77-78) |
| `utxo_applied_height.dat` | `persist_applied_height` (`daemon/utxo_live.c:1259-1325`) | the checkpoint height | tmp write+fsync (1308-1312), rename (1313), dir fsync **result ignored** (1317-1318) |
| `rev%05u.dat` | `undo_append_record` (`daemon/undo_log.c:143-163`, `writev`, O_APPEND), `undo_commit` END marker (132-141) | per-block undo runs | only `undo_sync` (96-118), called by the checkpoint (ST2-4, `utxo_live.c:1291`) |
| `undo.idx` | `us_slot_put` at a block's first undo write (`undo_store.h:136-139`, from `undo_fd_for`, `undo_log.c:55-86`); `us_slot_clear` by `undo_discard` (`undo_log.c:268-271`, `undo_store.h:140-146`) | 16-byte slot per height: "undo exists for h" | only `undo_sync`, at the checkpoint |
| `blk%05u.dat`, `index.dat` | `store_append` (`bitcoin_store.asm:1023-1250`), `store_append_shared` | block frames; 48-byte record per height (`index.dat`'s length is the tip) | block bytes fdatasync'd before the record is written (STO-11, 1192-1201, 1461-1470); **the index record is never synced on this path** (only the download committer fdatasyncs it per chunk, `daemon/main.c:5594-5598`) |

## The write path (one block at height h; `apply_block_at`, `utxo_live.c:2986-3016`)

1. **Ghost guard** (3048-3051): if `undo_exists(h)` the slot is a previous
   process's application of h; `rollback_unapplied_block` (3297-3326) undoes it first.
2. **Verify** (`apply_block_inner` -> `tx_verify_block_connect_all`): every prevout
   is resolved through `utxo_lsm_get`; a missing one is a consensus REJECT. The
   first REJECT invalidates the block through `g_reject_fn` (4271-4290).
3. For each input, `live_on_input` (1341) -> `undo_capture_and_del[_resolved]`
   (`undo_log.c:385-417`):
   1. `undo_fd_for(h)`: at the block's first record, `us_slot_put` writes h's slot
      to `undo.idx` (page cache only);
   2. `undo_append_record`: `writev` of the record to the rev file (page cache only);
   3. `utxo_lsm_del` -> `utxo_store_del`: the DEL record goes into the **process
      buffer** `wal_buf`; the memtable is updated; a tombstone is recorded.
4. For each output, `utxo_lsm_put` -> `utxo_store_put`: the PUSH record into `wal_buf`.
5. **The flush threshold** may be crossed after ANY put/del (3-4 above; `.lp_do_flush`
   1789, `.ld_do_flush` 1885), i.e. in the middle of a block. See "Flush" below.
6. `undo_commit(h)` writes the END marker; `undo_close_current`.
7. `utxo_store_wal_drain`: `wal_buf` -> `write(2)` to `utxo.dat` (page cache only).
8. `g_applied_height = h` (4327). If `utxo_live_ckpt_due` (3988-3996: per block near the
   tip, every 64 blocks / 2 s mid-chain, every 1,024 blocks / 60 s in bulk mode,
   always at the loop's exit, 4527, and at `utxo_live_close`, 4719) -> **Checkpoint**.

### Checkpoint (`persist_applied_height`, 1259-1325)
1. drain `wal_buf` (1261);
2. `undo_sync`: fdatasync the rev files written since the last call, then `undo.idx`
   (ST2-4; a failure refuses the checkpoint);
3. `fsync(utxo.dat)` (a failure refuses the checkpoint);
4. `utxo_applied_height.dat.tmp`: write, fsync, close; `rename` over the height file;
5. `open(".")` + `fsync` — **result ignored**, and skipped silently if the open fails;
6. coinstats commit.

### Flush, inline (`mac_flush`, `bitcoin_utxo_lsm.asm:3150-3365`; `bmc.asyncflush=0`, tools)
1. the compaction gate hook (`compact_flush_hook`, `utxo_live.c:539`);
2. drain `wal_buf` (3176-3179);
3. `mac_build_run`: create `utxo_run_<n>.dat`, write, **fsync (checked)**, close;
4. manifest: `utxo_manifest.tmp` write, **fsync (checked)**, close, `rename` (3271);
5. `open(".")` + fsync: a failed fsync fails the flush (ST2-1); **a failed open skips
   the fsync and goes on to step 6** (3282-3283);
6. `ftruncate(utxo.idx, 0)` (3307), `ftruncate(utxo.dat, 0)` + `lseek` (3331-3343) —
   neither synced; memtable and tombstones cleared.

There is no directory fsync between the run's create and the manifest rename.

### Flush, async (plan B3, the default: `fz_hook`, `utxo_live.c:864-905`)
1. `utxo_lsm_freeze` (asm 2550-2640): gate hook, drain `wal_buf`, copy the memtable
   and tombstones into the frozen copy, reserve gen/run number,
   `fz_wal_end = log_len` (the WAL's logical length now), clear the live memtable;
2. fork the writer: `utxo_lsm_build_run` on the copy (create, write, fsync checked), `_exit`;
3. **adopt** (`fz_adopt`, 806-841) at the next poll between catch-up passes or at the
   next threshold crossing (`fz_wait`):
   1. append the run to the in-memory manifest; `lsm_manifest_publish`: tmp write +
      fsync (checked), rename, `open(".")`+fsync **result ignored**;
   2. `fz_retire_wal` (767-797): `utxo.idx.tmp` = `{log_off = fz_wal_end}`, fsync
      (a failure only warns), rename, `open(".")`+fsync **result ignored**, reopen the idx fd;
   3. `fallocate(PUNCH_HOLE)` over `[g_wal_live_start, fz_wal_end)` of `utxo.dat`
      (785) — the retired bytes read as zeros from now on; `g_wal_live_start = fz_wal_end`.

   **The WAL is not fsynced anywhere in this sequence**: `utxo.idx`'s `log_off` is made
   durable while the WAL bytes below it are only as durable as the last checkpoint.

### Compaction (background; `compact_start_async` 594-666, `compact_adopt` 492-527)
1. child: `utxo_lsm_compact_range` with unlink and publish deferred: merged run created,
   written, fsynced (checked); `utxo_manifest.child` written + fsynced (checked); no rename;
2. parent at the next gate/poll: `lsm_manifest_adopt_child` (`lsm_manifest.c:90-169`):
   reconcile, `lsm_manifest_publish` (dir fsync ignored), commit to memory (UTX-5 order);
3. `unlink` each input the manifest no longer names (515) — no dir fsync.
The inline compaction (`utxo_live_init` pre-catch-up loop 3906-3916, fork failure 631-637)
does the same in asm with the dir fsync checked; an `open(".")` failure skips it and
still unlinks the inputs (`.cc_dirsync_skip`, 5332-5342).

## The recovery path (a restarted process)

1. `utxo_live_init` (3647-3955): `utxo_lsm_reload` (3818) =
   1. `utxo_store_init` (open WAL + idx); read `utxo_manifest.dat` (a missing file =
      fresh, an unreadable one = fatal, UTX-6);
   2. `utxo_store_reload` (`bitcoin_utxo_store.asm:852-1175`): `log_len = lseek(SEEK_END)`
      — **the physical size**; read `utxo.idx` -> `ckpt_log_off`; replay records from
      `ckpt_log_off` up to `log_len`, stopping at the first record whose prefix or body
      is short or whose op byte is not 1/2 (a zero record stops it); there the WAL is
      `ftruncate`d (UTX-4, 1091-1126, unsynced). **If `ckpt_log_off > log_len` nothing
      is replayed, `log_len` stays the physical size, and every later append lands
      below `ckpt_log_off`.**
   3. rebuild the tombstone list from the same tail; recount the live total;
2. the pre-catch-up inline compaction (only above the threshold);
3. `g_applied_height = read_applied_height()` (3925);
4. `lsm_manifest_sweep_orphans` (`lsm_manifest.c:171-193`): if the file and memory
   agree, unlink `utxo_manifest.child`, the tmp, and every run the manifest does not
   name — no dir fsync first;
5. `utxo_live_recover_at_boot` (3440-3492, from `main.c:10085`):
   1. STO-1 guard: applied height > archive tip (`index.dat` length - 1) -> FATAL,
      refuse to start (3471-3489);
   2. `utxo_live_recover_partial_block` (3393-3431): `lo = applied+1`, `hi` = the end of
      the contiguous run of heights with an undo slot; for h = hi down to lo:
      `rollback_unapplied_block` (3297-3326):
      1. `undo_replay_tolerant` -> `undo_restore_cb` (3168-3191): each recorded coin
         is `utxo_lsm_put` back if absent — into `wal_buf`;
      2. `del_created_on_output`: each output of h is `utxo_lsm_del`eted if present —
         into `wal_buf`;
      3. `undo_discard(h)` -> `us_slot_clear`: the slot is zeroed by `pwrite` —
         **immediately in the page cache, while the rollback's own WAL records are
         still in the process buffer.** Nothing drains or syncs before the next block's
         end (step 7 of the write path), or before a flush.
6. catch-up resumes at `applied+1` with the write path above.

## Indexes and the archive, as far as recovery depends on them

* The archive tip is `index.dat`'s record count. The UTXO checkpoint asserts blocks
  up to the applied height are applied, and recovery refuses to start when that height
  exceeds the tip (step 5.1). Since the record is never synced on the `store_append`
  path, a power loss can leave `index.dat` shorter than a durable applied height
  (finding STO-C below); `archive_trim_derived_tails` (`daemon/archive_verify.c:1066`)
  also cuts zero records left by a size update whose data did not reach the disk.
* The coinstats index commits at the checkpoint (1321) and re-seeds on mismatch.
* The trailing index runs (`index_runs.c`, `index_trail.c`, `addr_hist.c`) are built by
  separate processes from the archive and never read the UTXO store; ST2-2 made their
  readers ignore a merge's leftover inputs. Recovery of the UTXO set does not depend on
  them, so they are not in the model.

## What the model abstracts

* Data: blocks 1..N in a chain (block b spends coin b-1 and creates coin b; coin 0 is
  in the base run), so the set after block h is exactly {h}. One spend and one output
  per block; one undo record per block.
* A run is written and fsynced atomically by its writer; its name is a separate
  directory operation. Run content after a full merge = concatenation of the inputs
  (same fold as dropping tombstones at the bottom level).
* The flush threshold is nondeterministic: any put/del may cross it (thresholds 1-2
  ops with the bound `MaxFlush`). The checkpoint cadence is nondeterministic: any
  block may or may not checkpoint, the last one always does.
* The async writer runs to completion at its adopt (its fsync commits the ext4
  journal at that point; earlier spontaneous commits are covered by the crash
  choosing any journal prefix).
* Not modelled: reorgs (disconnect/rewind), the rollback's own puts crossing the
  flush threshold, torn records inside a page (record granularity only), the
  inline pre-catch-up compaction at init, `utxo_store_sync`'s full checkpoint (tools only).

## Mutations (each must make TLC fail; see README)

| MUT | what it removes or reorders | code site |
|---|---|---|
| `noWalFsync` | the WAL fsync in the checkpoint | `utxo_live.c:1297` |
| `noUndoSync` | `undo_sync` in the checkpoint (reverts ST2-4) | `utxo_live.c:1291` |
| `noDirSync` | every directory fsync | `lsm_manifest.c:77`, `utxo_live.c:781,1317`, asm 3279-3293 |
| `truncBeforeDir` | the inline flush truncates the WAL before the manifest dir fsync | asm 3276-3343 |
| `punchBeforeIdx` | the punch hole before the `utxo.idx` rename | `utxo_live.c:778-790` |
| `noRunFsync` | the run file's fsync (reverts ST2-1's premise) | asm 3105-3118 |
