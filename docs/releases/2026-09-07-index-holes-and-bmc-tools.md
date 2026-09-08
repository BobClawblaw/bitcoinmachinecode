# 2026-09-07 — A hole in the index is in-flight work; the whole suite carries the `bmc_` prefix

## Records above a hole are kept

The boot self-heal's chain-continuation walk stopped at the first hole in
`index.dat` and cut every stored record above it. With sixteen workers a
restart in the middle of a sync always has chunks in flight, so up to
about 640 valid blocks were discarded and re-downloaded after any
restart; the scratch node lost 566 this afternoon.

A record above a hole cannot be linked to the record below it, so it is
anchored to the header chain instead: `headers.dat` must carry the same
hash at that height, that header must link to the one beneath it, and
the stored block's own prevhash must agree. The 2026-09-01 incident's
junk, real early blocks recorded at fake heights, fails that anchor
exactly as it failed the prev-hash link. When there is a cut it lands at
the first bad record, and holes below it stay holes for the download to
fill. `test_archive_trim` gains three checks and was watched to fail on
the old rule with three failures.

## `bmc_` on every executable

Following this morning's rule, the twelve remaining tools are renamed:
`bmc_wallet_cli`, `bmc_build_addr_index`, `bmc_build_block_filters`,
`bmc_build_tx_index`, `bmc_build_txospender_index`, `bmc_build_utxo`,
`bmc_chainwork_build`, `bmc_pverify`, `bmc_utxo_dump_keys`,
`bmc_utxo_probe_one`, `bmc_utxo_repair_del`, `bmc_utxo_setinfo`. Every
script, validation harness, test and current document that runs one by
path follows; source files keep their names. With `bmcbitcoind`,
`bmc_cli` and `bmc_rpcd` that is all fourteen binaries.

Found on the way: `build_addr_index` had not built under the current
`-Werror` flags for some time, because the gate never builds it. A
64-byte bucket path against a 256-byte directory name; sized to fit.
