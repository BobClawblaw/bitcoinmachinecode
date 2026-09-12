# 2026-09-09 — One record per key per run: the UTXO defect behind bench run 18's rejected block

Run 18 ended when the engine rejected mainnet's 963,311 for spending a coin the set "lacked" and invalidated it. The coin, created at 962,871, was in the set: `bmc_utxo_probe_one` found it on the full walk and missed it on the point lookup. A one-run manifest pinned the file: the run the background compaction had just written held the key twice, a PUSH followed by a DEL, with the sparse index pointing at the DEL. 11,362 keys were duplicated in that 52-million-record run; the flush-written runs beside it had none.

Two defects, one shape -- a stale block spends K, the unapply restores K, the replacement block spends K again:

- **`utxo_lsm_del` appended a tombstone on every call.** del K / put K / del K in one generation left K in the list twice and `mac_flush` wrote both: two DEL records for one key. Now the tombstone hash probe that already runs on every del decides: a key already listed this generation is kept once.
- **The k-way merge advanced a matching input slot by ONE record.** An input holding a key twice handed the key to the next iteration, which emitted it again -- and once a PUSH from a newer run had been emitted, the stale DEL followed it into the output. The compaction's advance loop and the recount/walk's now re-examine the slot until its key changes, so an input's duplicate collapses to the first record (the one the walk always reported). A run written before the fix is repaired by its next compaction.

The point lookup takes whichever record the sparse index lands on; the walk takes the first. They disagreed, `gettxoutsetinfo` matched the oracle, and consensus rejected a valid block. The `live=` figure in the logs is a counter, not a scan, so an equal count proved nothing.

`test_utxo_lsm_dups` (new, **watched to fail**, 8 assertions): del/put/del in one generation flushes one DEL; a merge over a hand-written run holding [DEL K, DEL K] and a newer run holding 63 fillers and PUSH K writes 64 records with one PUSH K, and get() finds it (the stale DEL used to be the 64th record, exactly the sparse sample); the bench's own shape, [PUSH K, DEL K] with the sparse index on the DEL, prints "get says spent, the walk says live" before the merge and one PUSH after it. `test_lsm_flush_sort_diff` expected the duplicate tombstones (a test that encoded the defect); it now counts distinct tombstoned keys.

**Diagnosis recipe** (OPERATIONS.md): `daemon/bmc_utxo_probe_one <datadir> <txid> <vout>` compares get() with the walk; symlink the run files into a scratch directory with a hand-written one-entry manifest to test a run alone.

---

PR #139 (`batch/2026-09-09-lsm-dups-header-select`, two commits), merged 09:33Z as `fcfe834d`; tag `one-record-per-key-2026-09-09`. Staged as `deploy-20260909g`.
