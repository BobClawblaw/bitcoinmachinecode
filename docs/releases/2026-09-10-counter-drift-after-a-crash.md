# 2026-09-10 — The live coin counter after a crash in bulk mode

Inventory row 4. Under the bulk memtable, `test_utxo_crash_recovery`'s mid-block scenario recovered with a live count of 153 against the reference's 151, every key identical. The counter is what the heartbeat and `gettxoutsetinfo` report; Core's is exact after replay.

**What it was.** The base chain sits in a run after the caught-up flush, so the memtable is empty. The child that dies mid-block has captured two spends to the undo file but its two deletes never left the WAL buffer. The reload is right (150, the walk agrees). The ghost rollback then restores the two "spent" coins from undo, and `utxo_lsm_put` of a key that lives in an older run cannot see it without a lookup, so it inserts a second copy in the memtable and counts it as new. The walk deduplicates; the counter does not. Under the steady-state memtable the base chain is still in the memtable, the put sees the key, and nothing drifts, which is why the scenario only failed once fresh syncs became bulk (#153).

**The fix** mirrors the delete side's gate from 2026-09-03: the restore looks the coin up first and skips it when it is still there (`undo_restore_cb`), counting the skips. One lookup per restored prevout, on rollback paths only.

**Verified:** `test_utxo_crash_recovery_bulk` (the same source with `-DCRASH_RECOVERY_BULK`: scenarios (a) and (b) under the bulk memtable, as production runs) fails 153 against 151 with the gate off and passes with it on. The original binary keeps (c)'s own 4-slot sizing.
