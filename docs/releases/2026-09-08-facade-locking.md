# 2026-09-08 — The Esplora facade locks per dispatch and never asks gettxout for a mempool prevout

Production incident 2026-09-08 09:41 to 09:53Z: switching mempool.space's backend to the facade sent a 1,000-txid batch load. For each unconfirmed transaction the facade asked `gettxout` per input; on this node `gettxout` is a request over a socketpair to the download worker, answered only at that worker's service points, each waiting up to its timeout. The facade held the RPC server's execution lock for the whole request, so every JSON-RPC caller waited behind it: nine threads on the lock, none running, `getblockcount` at 30 s, until a restart.

- The execution lock is taken around each `rpc_dispatch` inside the facade (`rpc_server.c` installs the hooks), so a batch route interleaves with JSON-RPC callers.
- A mempool transaction's prevouts come from its previous transactions (`getrawtransaction` verbosity 1: txindex, or the mempool for an unconfirmed parent), never from `gettxout`. The outspends fallback without the txospender index still uses `gettxout`, bounded by one transaction's outputs; production has the index.

`test_rpc_esplora` +2: the unconfirmed transaction's prevout comes without a single `gettxout`; the lock hooks are called once per dispatch, balanced. Gate `make -j8 test`: 0 failures (one expected test_rpc_signer segfault); 8 static audits exit 0.

---

PR #103 (`batch/2026-09-08-facade-locking`), merged 10:09Z as `ef3502a7`; tag `facade-locking-2026-09-08`.
