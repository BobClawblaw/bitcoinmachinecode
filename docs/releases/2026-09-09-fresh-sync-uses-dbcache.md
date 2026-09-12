# 2026-09-09 — A fresh sync uses the dbcache

Core fills `-dbcache` during initial block download and writes it out when full or at the end; that cache is most of why its IBD takes the time it takes. This engine has the equivalent, the bulk memtable sizing, and the bench's `dbcache=8192` maps to it at boot (2^25 slots, a 6 GB blob, 48 runs to a merge). It was taken only when a boot found the archive 50,000 or more blocks ahead of the applied height, or a large WAL tail. A fresh datadir boots with no archive at all -- `applied=-1 tip=0 gap=1` -- and so every benchmark run since the engine landed synced the entire chain through the 64 MB steady-state memtable, flushing every hundred-odd thousand operations and merging a thousand times, while the configured cache sat unused. Run 19 at height 700,000: 300 ms a block, lookups 35%, writes 39%, checkpoints 13 to 24%, the apply 969 blocks behind the download in bursts.

- **An empty set is initial block download.** `utxo_live_pick_bulk` (`daemon/utxo_live_sizing.h`, header-only so the decision is pinned): `applied < 0` takes the bulk sizing regardless of gap; the gap rule and the WAL-tail rule stay for restarts. A reindex-chainstate boot was already bulk by the gap rule and stays so.
- **Tests that need the small memtable say so** through `utxo_live_test_force_sizing`, the way they already forced the tiny bulk memtable.

`test_utxo_sizing` (new): a fresh datadir is bulk, a restart at the tip is not, 50,000 behind is, 49,999 is not, a reindex boot is. `test_utxo_catchup_bounded`: the engine on a fresh directory reports bulk. Gate: see the trailer.

**Found on the way, left open** (`docs/CORE_DIVERGENCES.md`): under the bulk memtable, `test_utxo_crash_recovery`'s steady-state scenario recovers from a kill mid-block with a live count of 153 against the never-crashed reference's 151, every key identical. The count is the engine's counter, not the set; the set is right. The steady-state variant keeps its small memtable, and the drift is its own item.

The next benchmark run is the measurement: the 634,561 and 800,000 marks against run 19's 6h52m and its 800,000 time, and the apply lag.

---

PR #153 (`batch/2026-09-09-fresh-sync-dbcache`), merged 23:0xZ as `47d97491`; tag `fresh-sync-dbcache-2026-09-09`. Gate MAKE_EXIT 0, 349 passes (the first run failed test_dlc_interleave's lag assertion under load; it keeps the small memtable). Staged as `deploy-20260909p`; live on production from 23:16:38Z (inert there: production is at the tip).
