# 2026-09-10 — Bulk mode checkpoints on its own cadence, and a bounded pass never downshifts

Row 1 of `docs/CORE_DIVERGENCES.md` (checkpoint cadence during initial sync), and a defect PR #153 exposed. Core writes nothing durable during initial block download: the coin cache lands when it is full or at the end, and a crash costs the whole cache. This engine checkpointed every block whenever the apply was within 64 blocks of the archive tip, and during the parallel download the archive tip is the download's frontier, which the apply reaches every few passes. Run 19's progress lines (steady-state memtable):

| tick | apply lag | ckpt share of block time |
|---|---|---|
| 23:57:18Z, 763,601 | 0 | 23% |
| 23:58:15Z, 763,721 | 0 | 72% |
| 23:58:45Z, 764,336 (105 blocks) | behind | 0% |

Each checkpoint is a WAL drain, a WAL fsync, a tmp write, its fsync, a rename, a directory fsync and the coinstats commit. On top of the per-block rule every bounded pass landed its batch on exit and then persisted the height a second time: ten fsyncs a pass at 8 s.

- **Bulk mode checkpoints every 1,024 blocks or 60 s**, with no "near the tip" rule (`utxo_live_ckpt_due` takes the sizing mode). A crash mid-sync rolls at most that many ghost blocks back from the per-block undo files at boot, which recovery already does for any batch. Steady state keeps 64 blocks, 2 s, and per block at the tip.
- **A bounded pass carries its batch.** In bulk mode a pass that stops at a hole, its budget or the frontier leaves the checkpoint pending for the next pass; the time bound, the unbounded drain, a failure, a rejection, shutdown and a clean close land it. The second persist after the loop is gone: it retries only if the landing failed.
- **A bounded pass never downshifts.** The caught-up downshift to the steady-state memtable fired whenever the apply reached the archive tip, bounded or not. With PR #153 a fresh sync would have booted with the dbcache-sized memtable and thrown it away minutes later, the first time the apply caught the download. Only the unbounded drain, which the rotation runs after the download, is at the chain's tip. No fresh sync had run bulk before #153, so nothing showed it.
- **Consequence for the coinstats index on a fresh sync:** it is deferred while the engine is bulk and seeds from a walk of the set at the downshift, so it becomes available when the download is over, not per block from the start. That is Core's shape (the index builds after).

`test_utxo_ckpt_batch`: the bulk decision cases, and a bulk bounded pass to the frontier that stays bulk, lands no checkpoint, lands it on close, and downshifts only from the unbounded drain (watched to fail six ways against the unfixed engine). `test_utxo_catchup_bounded` moved from "the checkpoint equals the applied height after every call" to "trails by at most the batch, the close lands it"; the old assertion pinned the fsync storm.

**To measure on the next fresh run:** the ckpt share on the progress lines (expected under 3%), "downshifting" absent until the download ends, and the 634,561 and 800,000 marks against run 19's 6h52m and its 800k time.
