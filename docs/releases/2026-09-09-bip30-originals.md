# 2026-09-09 — BIP30: the unspendable coinbases are the originals, as in Core

The first history base the self-repair built (1 h 54 m, pass 3 sized to seven workers from RAM) was quarantined by its own seam check: the set's counters equalled the live index's at 966,096 and the digests differed. Bisected against Core's coinstatsindex with the row extractor: every height up to 91,721 matched, 91,722 did not, with our coin count one above Core's. That is the first BIP30 original coinbase.

Core's `IsBIP30Unspendable` names 91,722 and 91,812, the ORIGINALS whose txids the coinbases of 91,842 and 91,880 repeated. Core's database overwrote the originals with the duplicates (same txid, later height), so the coins that exist carry the later heights and the originals' subsidy is `unspendables.bip30`. This node named the duplicates instead, in the builder and in the live index's accounting: the coin count converged at the tip either way, but each of those coins hashed with the wrong height and the whole base disagreed with Core's MuHash from 91,722 on. The live tail matched Core because it folds the real set.

- One definition now, `csh_bip30_unspendable` in `coinstats_hist_fmt.h`, used by the builder and the live index.
- `test_coinstats_hist` pins the heights both ways and off-mainnet; **watched to fail** on the old heights (2). The proof at scale is the rebuilt base agreeing with Core: a rebuild with the fixed tool is running on production as this lands (the daemon adopts it at the seam check). Gate `make -j8 test`: MAKE_EXIT 0, 0 failures (the expected test_rpc_signer segfault); audits exit 0.

---

PR_LINE
