# 2026-09-07 — Records above an index hole are kept when the header chain anchors them; every executable carries the bmc_ prefix

**Index holes.** The boot chain-continuation walk stopped at the first hole and cut every stored record above it: up to ~640 valid blocks re-downloaded after any restart mid-sync (566 on today's scratch node). A record above a hole is now anchored to the header chain (same hash at that height, linked beneath, the block's own prevhash agreeing); the cut, if any, is at the first bad record and holes below it stay holes. `test_archive_trim` +3, watched to fail (3 failures).

**bmc_ on the whole suite.** Twelve tools renamed (`bmc_wallet_cli`, `bmc_build_*`, `bmc_chainwork_build`, `bmc_pverify`, `bmc_utxo_*`), 36 files; sources keep their names; old names ignored. `build_addr_index` had not compiled under -Werror (the gate never builds it): buffer sized; all 14 `bmc_*` binaries build. `test_e2e_sighash`, `test_rpc_chain`, `test_txospender_index`, `test_utxo_recover_gate` pass on the new paths.

Full gate 0 failures; 8 audits exit 0.

---

PR #85 (`batch/2026-09-07-index-holes-and-bmc-tools`), merged 22:47Z as `82007465`; tag `index-holes-bmc-tools-2026-09-07`.
