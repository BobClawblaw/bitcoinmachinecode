# 2026-09-08 — The address routes include the mempool

The Esplora facade's address routes covered confirmed history only; mempool.space's address page shows unconfirmed activity from `mempool_stats`, the transaction list, and `/utxo`.

- An in-process mempool-by-address view (`mp_refresh`/`mp_view_of`): a cache keyed by address, refreshed lazily from `getrawmempool`, at most 2,000 new transactions decoded per refresh so a refresh cannot hold the dispatch lock through a whole 40,000-entry mempool.
- `/address/:a` fills `mempool_stats` (funded/spent txo counts and sums, tx_count); `/address/:a/txs` lists unconfirmed transactions first; `/address/:a/utxo` includes unconfirmed outputs and drops outputs spent in the mempool.
- test_rpc_esplora +4 (69 checks).
- Worklog: session 32, and #109/#110's entries.

Gate: `make -j8 test` MAKE_EXIT=0; the eight static audits pass (gate-log-check flags test_rpc_signer's intentional segfault, as always).

---

PR #111 (`batch/2026-09-08-address-mempool`), merged 12:57Z as `1e1af84d`; tag `address-mempool-2026-09-08`.
