# 2026-09-08 — getblockstats without undo errors like Core; the facade omits an unknown fee

Two lies below production's undo boundary (965,826, where its rev files begin), both found by mempool.space's block indexer on the way to the hashrate graph.

- `getblockstats` used to OMIT the eleven fee fields for a block whose undo it cannot read, an "honest divergence" from the days of the 200-block undo window. Core's `GetUndoChecked` throws `RPC_MISC_ERROR` "Can't read undo data from disk" (the genesis block excepted), and mempool's indexer read our omission as `stats.feerate_percentiles[2]` of undefined and died on the first such block. It errors like Core now; `getblock`'s fee omission already matched Core and is unchanged.
- The Esplora facade reported `fee: 0` for a transaction whose prevouts the node cannot resolve. That is a claim, and a false one; mempool summed it into block fee statistics. The key is omitted when the fee is unknown.

`test_rpc_chain`: a height without undo answers Core's error, the genesis block answers. `test_rpc_esplora`: a tx whose prevouts Core's JSON lacks has no fee key (the assertion had pinned the 0). Both **watched to fail** with the code reverted. Gate `make -j8 test`: MAKE_EXIT 0, 0 failures (the expected test_rpc_signer segfault); audits exit 0.

---

PR_LINE
