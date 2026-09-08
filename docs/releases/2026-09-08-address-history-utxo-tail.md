# 2026-09-08 — /address/:addr/utxo from funding events and the spender index; the tail journal adopts the history base

Two follow-ups to stage 2, plus its documentation.

- `/utxo` no longer reads the reverse UTXO index (a snapshot from Aug 18 on production, past its tail's adoption window, no heights). It takes the address's funding events from the history base plus the tail's ADDs, asks `gettxspendingprevout` for them 500 at a time, and returns the ones with no spender, each with its block height. No `gettxout` anywhere.
- A fresh `addrindex.tail` on a node that has the history base adopts the base's `to_height` as its coverage and backfills from there over the undo data now kept for every block. The history reader is a weak reference in the tail, so the tail still links without the facade.
- Docs: the address-history release note, OPERATIONS procedure (build, `addrindex=1`, restart), the docs index, the scope document's size correction (about 200 GB, not 30 to 40), worklog session 31.

Tests: `test_rpc_esplora` +1 (spent per the spender index; tail ADD cancelled by DEL; a tail ADD with no DEL is one utxo with its height); `test_addr_index_tail` +2 (the adoption). Gate `make -j8 test`: 0 failures (one expected test_rpc_signer segfault); 8 static audits exit 0.

---

PR #108 (`batch/2026-09-08-addr-hist-utxo-tail`), merged 11:17Z as `2d0c8bf0`; tag `address-history-utxo-tail-2026-09-08`.
