# 2026-09-08 — The address index boots after the UTXO engine and stops at its applied height

Every production boot from 17:16Z disabled the live address index: "[axt] h=966097: undo has 0 records but the block spends 6870 -- refusing to index a height with missing spends", then 966106, 966110, 966111 on the next three boots. Each of those heights indexed fine on the boot after, so the undo was not missing; it did not exist YET. A stop lands blocks it does not connect, so at every boot the archive is a few blocks ahead of the engine, and `axt_boot` ran before `utxo_live_init` with the ARCHIVE tip as its target. It reached the first unapplied block, read an undo the engine had not written, and disabled the index for the session. Thirty seconds later the engine wrote exactly that undo.

- `axt_boot` runs after the engine and backfills to `min(archive tip, applied height)`; the applied height reaches the tail as a registered function (`axt_set_applied_height`, the undo replay's pattern), so the tail's own tests keep their stub.
- `axt_on_block` defers a height above the applied one instead of failing on its absent undo; the next call above it closes the gap from the archive, whose undo exists by then. The index never disables for "not applied yet"; the disables that remain are real losses (unreadable block, undo short below the applied height, a gap beyond the retention window).
- The LIVE line says when the archive is ahead: "the rest lands as the engine applies it".

`test_addr_index_tail` section 6 builds the production shape: block 2 stored, not applied, no undo; boot must stay live at covered=1, the choke point must defer height 2, and the gap must close once the block is applied (covered=2, balances back). **Watched to fail** against the unfixed logic (4 of 5 assertions), passes with the fix. Gate `make -j8 test`: MAKE_EXIT 0, 0 failures (one expected test_rpc_signer segfault); audits exit 0.

---

PR #123 (`batch/2026-09-08-addrindex-boot-race`), merged 22:35Z as `617f1154`; tag `addrindex-boot-race-2026-09-08`. Deployed as snapshot `deploy-20260908m`.
