# 2026-09-08 — Getrawtransaction verbosity 2 attaches the RIGHT prevouts, by txid and by block hash

Two defects in the undo-slice logic, found through production's Esplora facade (fee 0 on every `/tx`, then a wrong fee once that was fixed):

1. Through the txindex the handler jumps to the transaction's offset and walks one transaction, so its index in the block read as 0 and the undo slice was skipped as if the transaction were the coinbase. One pass over the block up to the indexed offset now counts the transactions before it.
2. The walk that sums the inputs of the earlier transactions started at the block header, so `tx_walk` failed on its first step and `skip` stayed 0: every transaction past the first got the first transaction's prevouts and fee, on both paths. It starts at the first transaction.

Test: `test_rpc_chain` asks for tx2 at verbosity 2 by txid alone over the fixture index: fee 49.98999 and the prevout, and the prevout is tx1's 49.99 output, not the coinbase's 50; watched to FAIL on the old handler. Gate `make -j8 test`: 0 failures (one expected test_rpc_signer segfault); 8 static audits exit 0.

---

PR #105 (`batch/2026-09-08-rawtx-txindex-prevout`), merged 10:33Z as `ff22a941`; tag `rawtx-prevouts-2026-09-08`.
