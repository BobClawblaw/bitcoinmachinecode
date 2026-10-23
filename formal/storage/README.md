# formal/storage: crash consistency of the UTXO store

Question: after a crash (SIGKILL or power loss) at any point, followed by
recovery, is the UTXO set exactly the set after the blocks up to the recovered
height, with that height between the last durable checkpoint and the last applied
block, the undo data and the archive index agreeing with it, nothing durable lost
or resurrected, and is recovery itself crash-safe?

Answer for the code at b841251b: **no**. TLC finds five classes of hole in the
faithful model; four are reproduced on the real code (section "Findings"). With
five candidate changes switched on in the model, every property holds under both
file-system models.

* `PROTOCOL.md` — the protocol as the code implements it, step by step, with
  file:line citations, the abstraction, and the mutation list.
* `tla/StorageCrash.tla` — the TLA+ model.
* `crash/crash_storage.c`, `crash/durable_image.h`, `crash/build.sh` — the
  crash-injection driver, linked against the worktree's real objects.
* `run.sh` — every TLC configuration and every crash scenario, each against its
  expected outcome; exits 0 only if all end as recorded below.

## Tools and reproduction

* TLC2 2.19 (08 Aug 2024, rev 5a47802) on Temurin OpenJDK 21.0.13, `-workers 4 -Xmx6g`.
* gcc with the flags of `asm/Makefile`'s `tests/test_utxo_ghost_resume` rule; the
  crash driver uses that rule's exact link set (`crash/build.sh`).
* `FORMAL_TOOLS=$HOME/.local/opt/formal SCRATCH=<dir> formal/storage/run.sh` —
  every process runs under `systemd-run --user --scope -p MemoryMax=8G
  -p MemorySwapMax=0 nice -n15 timeout`. Total: **617 s** (the largest
  configuration, 81 M states, is 370 s of it). `ONLY=<regex>` selects checks.

## The model (summary; details in PROTOCOL.md and the spec's comments)

Blocks 1..N form a chain: block b spends coin b-1 and creates coin b; coin 0 is
in the base run. The set after block h is exactly {h}, so a resurrected spend is
an extra coin and a lost creation a missing one. Every file has a page-cache
state (what the next process sees after SIGKILL) and a durable state (what a
power loss keeps). Two file-system models:

* **ext4** (data=ordered, the deployment): any successful sync commits the whole
  journal (every create/rename/unlink/truncate/punch so far); a power loss keeps a
  prefix of the uncommitted journal; unsynced appended data survives as a prefix,
  and nothing appended after a lost metadata op survives.
* **weak** (POSIX only): a name op is durable after a directory fsync, a file's own
  truncate/punch after that file's fsync; a power loss keeps any subset of the
  uncommitted ops independently, and each unsynced undo slot independently.

Actions: the block apply (ghost guard, verify, undo slot, undo record, DEL, PUT,
block-end drain), the checkpoint (undo_sync, WAL fsync, height tmp+fsync+rename,
dir fsync), the inline flush and the async flush (freeze, writer, manifest
publish, utxo.idx retire, punch), one background compaction, the reload
(manifest, WAL replay from `log_off` to the physical end with the torn-tail
truncate, orphan sweep, STO-1 guard), the ghost rollback (restore, delete
created, `undo_discard`), SIGKILL and power loss anywhere, including during
recovery. A flush may fire after any put/del; a checkpoint after any block.

Properties, checked when recovery completes (`pc = "rec_done"`):
`RecConsistent` (set = expected set at the recovered height), `NoResurrection`,
`NoLoss`, `HeightInRange` (last durable checkpoint <= recovered height <= last
applied), `UndoAgrees` (every applied block has its undo), and as invariants
everywhere: `StoreReadable` (no manifest names a missing or torn run),
`NoFalseReject` (no valid block is rejected), `ArchiveCovers` (the STO-1 guard
never refuses to start), `SteadyState` (every block boundary holds the expected
set). Crash-safety of recovery and the idempotence of Recover are covered by
allowing a second crash anywhere during or after recovery (`MaxCrash = 2`): every
recovery run, first or repeated, must satisfy the same invariants. Liveness was
not checked.

Candidate changes (model switches, used to separate the holes and to show the
rest of the protocol holds; they are not patches to the code):

| switch | the change | closes |
|---|---|---|
| `FixUndo` | a block's undo record and slot are durable before its DEL can reach the WAL page cache or a run | A |
| `FixRecov` | the rollback drains and fsyncs the WAL before `undo_discard` clears the slot | B |
| `FixArch` | the `index.dat` record is fdatasync'd before the block is applied | C |
| `FixLogOff` | the WAL is fsynced before `utxo.idx` names a `log_off` in it | E |
| `FixDir` | the C-side directory fsyncs halt on failure instead of continuing | D (weak only) |
| `FixWeakDir` | a directory fsync between a run's create and the manifest rename, and before the boot sweep | W (weak only) |

## Results

Bounds: N = 3 blocks unless noted (N = 2 where the full feature set is on),
MaxFlush = flushes per behaviour, one compaction, MaxCrash crashes, MaxDirFail
failing directory fsyncs. All checks are exhaustive within those bounds
(BOUNDED-OK = no violation in the complete state space).

| ID | configuration | bound | result | states | time |
|---|---|---|---|---|---|
| T1 | faithful, ext4 | N3 F1 C0 X1 | VIOLATED RecConsistent (hole A') | 331 | 1 s |
| T2 | faithful, weak | N3 F1 C0 X1 | VIOLATED RecConsistent | 370 | 1 s |
| T3 | all fixes but FixUndo, ext4 / weak | N2 F2 C1 X2 D1 | VIOLATED RecConsistent (A) | 385 / 364 | 1 s |
| T4 | all fixes but FixRecov, SIGKILL only | N2 F2 C1 X2 | VIOLATED RecConsistent (B) | 618 | 1 s |
| T5 | all fixes, SIGKILL only | N3 F2 C1 X2 D1 | BOUNDED-OK | 13.9 M | 51 s |
| T6 | all fixes but FixArch, ext4 | N2 F2 C1 X2 D1 | VIOLATED ArchiveCovers (C) | 825 | 1 s |
| T7 | all fixes but FixLogOff, ext4 / weak | N2 F2 C1 X2 D1 | VIOLATED RecConsistent (E) | 5,363 / 5,861 | 1 s |
| T8 | all fixes but FixDir, ext4 | N2 F2 C1 X2 D1 | BOUNDED-OK | 5.2 M | 17 s |
| T9 | all fixes but FixDir, weak | N2 F2 C1 X2 D1 | VIOLATED RecConsistent (D) | 5,618 | 1 s |
| T10 | all fixes but FixWeakDir, weak / ext4 | N2 F2 C1 X2 D1 | VIOLATED StoreReadable (W) / BOUNDED-OK (3.5 M) | 453 | 1 s / 12 s |
| T11 | all fixes; {ext4, weak} x {async, inline} | N2 F2 C1 X2 D1 | BOUNDED-OK (all four) | 3.5-6.8 M | 12-27 s |
| T12 | all fixes; {ext4, weak} x {async, inline} | N3 F1 C0 X2 D0 | BOUNDED-OK (all four) | 2.3-3.1 M | 10-45 s |
| T13 | all fixes, ext4, async | N3 F2 C1 X2 D1 | BOUNDED-OK | 81.0 M | 370 s |
| V1 | vacuity: `rec_done` reachable / the end reachable | as T11 | VIOLATED as required | 22 / 7,224 | 1 s |

Mutations of the fixed model (T11 bounds); each must and does fail:

| mutation | code site it removes | result | TLC trace |
|---|---|---|---|
| `noWalFsync` | WAL fsync in the checkpoint, `utxo_live.c:1297` | VIOLATED RecConsistent | checkpoint durable, the block's WAL records lost, recovered set behind the height |
| `noUndoSync` | `undo_sync`, `utxo_live.c:1291` (reverts ST2-4) | VIOLATED RecConsistent | WAL written back, undo lost, ghost invisible |
| `noDirSync` (weak) | every directory fsync | VIOLATED RecConsistent | renames never durable |
| `truncBeforeDir` (inline, weak) | WAL/idx truncate moved before the manifest dir fsync, asm 3276-3343 | VIOLATED RecConsistent | truncate durable, manifest rename lost: the generation is gone |
| `punchBeforeIdx` | punch before the `utxo.idx` rename, `utxo_live.c:778-790` | VIOLATED RecConsistent | the replay from the old `log_off` hits the hole, stops and truncates the live generation |
| `noRunFsync` | the run's fsync (ST2-1 premise), asm 3105-3118 | VIOLATED StoreReadable | the manifest names a run whose content was lost |

Crash injection on the real code (section "Findings"): 10 scenarios, 5 defect
reproductions and 5 controls, all as expected, under 2 s in total.

## Findings (confirmed on the real code)

Each is a TLC trace, mapped to the code, then reproduced by `crash_storage`
(SIGKILL is real; a power loss is the image `durable_image.h` records from the
real fsync/fdatasync calls with ext4 namespace semantics: every name as of the
last sync, every file's content as of its last fsync). The controls run the
same sequence with the one lost write kept, and heal.

**STO-B. Recovery is not crash-safe: a SIGKILL after the ghost rollback loses
the rollback.** (TLC T4; `crash:ghostkill`, controls `ghostkill-ctl`,
`ghostkill-close`.) `rollback_unapplied_block` (`utxo_live.c:3297-3326`)
restores and deletes through `utxo_lsm_put/del`, whose records sit in the 1 MB
process buffer, then `undo_discard` clears the slot with a `pwrite` to
`undo.idx` (`undo_store.h:140-146`) at once. Nothing drains the buffer before the
next block's end. A process killed in between (SIGKILL, OOM, systemd's stop
timeout during the boot catch-up) leaves the ghost blocks' effects on disk and
their slots gone. Reproduced: blocks 151-152 applied after checkpoint 150, process
dies; process 2 runs `utxo_live_recover_at_boot` (returns 1, both rolled back) and
is killed; process 3: `recover_at_boot -> 0` (no ghost visible), catch-up of 151
fails: `REJECT h=151 tx=0: bad-txns-BIP30 (tried to overwrite transaction: output
0 already unspent)`. Expected: 151..152 re-applied, applied 152, 153 coins. In the
daemon the first such reject invalidates block 151 (`g_reject_fn`,
`utxo_live.c:4271-4290`): a valid block is marked invalid. Core reference: Core
writes the coins and the best block in one atomic LevelDB batch
(`CCoinsViewDB::BatchWrite`, src/txdb.cpp) and replays blocks forward with
`ReplayBlocks` (src/validation.cpp) from the head-blocks marker, so a crash during
its recovery repeats the recovery. Severity: high (a valid block invalidated
after a kill at boot; the node stays off the chain until an operator runs
`reconsiderblock` after repairing the set). Needs only a process kill, no power
loss.

**STO-A. Spends of un-checkpointed blocks become durable without their undo.**
(TLC T1-T3; `crash:flushundo` with control `flushundo-ctl`, `crash:walwb`.) The
undo store is synced only by the checkpoint (`undo_sync`, ST2-4). Two paths make
a block's DELs durable before that: (1) a memtable flush, which fsyncs a run
holding them and retires the WAL bytes (`fz_adopt`/`mac_flush`) — deterministic,
every flush between checkpoints, i.e. every flush in bulk mode where checkpoints
are 1,024 blocks / 60 s apart; (2) the kernel writing WAL pages back before undo
pages (the ST2-4 commit's acknowledged window). After a power loss the ghost
guard cannot see the blocks (`undo_exists` reads lost slots), so recovery leaves
their spends in place. Reproduced (1): 151-152 applied after checkpoint 150,
`utxo_live_flush_now`, power loss: the image's run holds 151-152, `undo.idx` and
`rev00000.dat` are as of the checkpoint; recovery returns 0 and catch-up rejects
151 with `bad-txns-BIP30`. (2) the same with no flush and the WAL written back:
same reject. Answer to the audit's residual: ST2-4's window is a real
consistency hole (a rejected, and in the daemon invalidated, valid block), not
lost redo work; the flush widens it from a writeback race to every flush. Core
reference: `Chainstate::FlushStateToDisk` (src/validation.cpp:2785-2818) flushes
the block and undo files first, then the block index, then the coins in one
batch; no coin state reaches disk before the undo that disconnects it.
Severity: high (power loss during IBD or catch-up).

**STO-E. `utxo.idx` can name a `log_off` past the WAL's durable end; records
appended after the crash are then skipped by every reload.** (TLC T7, found by
the model, not by the audit; `crash:logoff`, control `logoff-ctl`.)
`fz_retire_wal` (`utxo_live.c:767-797`) makes `utxo.idx = {log_off = fz_wal_end}`
durable (tmp fsync, rename, dir fsync) without syncing the WAL. After a power
loss the WAL's size can be below `log_off`. `utxo_store_reload` then replays
nothing, sets `log_len` to the physical size, and new records are written below
`log_off` (`bitcoin_utxo_store.asm:886-895, 989-1006`); the next reload skips them
— even after a WAL fsync and a clean `utxo_live_close`. Reproduced: image after
the flush has `utxo.dat` 9,164 bytes and `log_off` 9,492; process 2 recovers,
re-applies 151-152, applies 153 (spends C, creates D), checkpoints and closes
cleanly; process 3 at applied height 153 has **C present (spent, resurrected)
and D absent (created, lost)**. Expected C absent, D present. A later block
spending D is rejected (and invalidated), and a block double-spending C would be
accepted. The window lasts until the next async flush retires the WAL again.
Core reference: Core never leaves a coins-DB marker ahead of its data (one atomic
batch). Severity: critical (silent wrong UTXO set; consensus divergence), after a
power loss in the async-flush default.

**STO-C. The archive's `index.dat` record is never synced, the applied height
is.** (TLC T6; `crash:archive`, control `archive-ctl`.) `store_append`
fdatasyncs the block bytes before writing the 48-byte record (STO-11) but never
syncs the record (`bitcoin_store.asm:1192-1236`); the checkpoint then makes the
applied height durable. A power loss that loses the last record leaves applied
height > archive tip, and boot refuses to start (STO-1 guard,
`utxo_live.c:3471-3489`), naming `reindex-chainstate`. Reproduced: per-block
checkpoints to 150 (`index.dat` never appears among the synced files), image with
block 150's record lost: `FATAL: applied height 150 is AHEAD of the archive tip
149 ... Refusing to start`. Expected: boot (block 150's bytes are durable; only
its index record is not). Fail-closed: no wrong state is served, but a node at
the tip that loses power within the writeback window after a block needs a full
reindex. Core reference: the same `FlushStateToDisk` order — block files,
then `WriteBlockIndexDB`, then the coins with their best block — so the coins'
best block never names a block the index has not durably recorded.
Severity: medium (availability).

## Model-only results (not confirmed on the real code)

* **D (ignored directory fsync results, `lsm_manifest.c:77-78`,
  `utxo_live.c:781`, `utxo_live.c:1317-1318`).** Under ext4 (T8) an ignored
  failure only costs redo work: the next successful sync commits the journal, and
  the model holds. Under the weak model (T9) it is a loss: the manifest publish's
  directory fsync fails, `fz_retire_wal` renames `utxo.idx`, and a power loss keeps
  the second rename without the first, so the retired generation is in no named
  run. Not confirmed: it needs a file system that persists a later rename in a
  directory without an earlier one, which ext4 (the deployment) does not do, plus an
  injected directory-fsync EIO. The checkpoint's ignored result (height file) is
  redo only in both models.
* **W (weak only, T10).** No directory fsync between a run's create and the
  manifest rename (asm flush, `lsm_manifest_publish` callers), and the boot orphan
  sweep unlinks runs on the strength of a manifest whose rename may not be durable
  (`lsm_manifest_sweep_orphans`). A POSIX file system may keep the rename without
  the create (or the unlink without the rename): the manifest names a missing run.
  Holds under ext4; not confirmed for the same reason as D.
* A stale undo slot above the recovered height (weak model, per-slot loss) is
  left behind in some traces (`NoStaleSlot`, informational); the apply's ghost
  guard rolls it back harmlessly in a single chain. Not a finding.

## Assumptions and trusted base

* The model is hand-written from the code (PROTOCOL.md); its fidelity is argued by
  the citations, by the mutations, and by the crash tests reproducing its four
  traces on the real code — not proved.
* Record granularity: torn records inside a page and out-of-order page writeback
  inside the WAL are reduced to "a prefix survives" (a zero hole stops the replay
  there; a garbage record mid-page is not modelled). ext4 undo-slot loss is
  all-or-nothing per file (one page in practice); weak is per slot.
* The ext4 model assumes every sync commits the journal and that delalloc data is
  not forced out by a commit. The crash images use the "every unsynced write lost"
  corner, which is reachable under ext4 while the data is still delalloc (the
  ~30 s writeback window); they do not prove the state is reached on a given box.
* Not covered: reorgs (disconnect, `utxo_live_rewind_to`, STO-1's own window), the
  rollback's puts crossing the flush threshold, the inline pre-catch-up compaction,
  `utxo_store_sync` (tools), the coinstats index beyond its commit point, the
  trailing index runs (derived from the archive; recovery does not read them),
  disk-full and other write errors beyond fsync results, multiple chains.
* Bounds: N <= 3 blocks, <= 2 flushes, 1 compaction, <= 2 crashes, <= 1 failing
  directory fsync. Holes needing more blocks or crashes would not be found.
