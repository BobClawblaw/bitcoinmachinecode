# 2026-09-09 — BIP30: the unspendable coinbases are the originals, as in Core

The first history base the self-repair built (1 h 54 m, pass 3 sized to seven workers from RAM) was quarantined by its own seam check: the set's counters equalled the live index's at 966,096 and the digests differed. Bisected against Core's coinstatsindex with the row extractor: every height up to 91,721 matched, 91,722 did not, with our coin count one above Core's. That is the first BIP30 original coinbase.

Core's `IsBIP30Unspendable` names 91,722 and 91,812, the ORIGINALS whose txids the coinbases of 91,842 and 91,880 repeated. Core's database overwrote the originals with the duplicates (same txid, later height), so the coins that exist carry the later heights and the originals' subsidy is `unspendables.bip30`. This node named the duplicates instead, in the builder and in the live index's accounting: the coin count converged at the tip either way, but each of those coins hashed with the wrong height and the whole base disagreed with Core's MuHash from 91,722 on. The live tail matched Core because it folds the real set.

- One definition now, `csh_bip30_unspendable` in `coinstats_hist_fmt.h`, used by the builder and the live index.
- `test_coinstats_hist` pins the heights both ways and off-mainnet; **watched to fail** on the old heights (2). The proof at scale is the rebuilt base agreeing with Core: a rebuild with the fixed tool is running on production as this lands (the daemon adopts it at the seam check). Gate `make -j8 test`: MAKE_EXIT 0, 0 failures (the expected test_rpc_signer segfault); audits exit 0.

---

PR #133 (`batch/2026-09-09-bip30-originals`), merged 02:14Z as `0011b2a8`; tag `bip30-originals-2026-09-09`. **Proven at scale at 06:10Z:** the base rebuilt with the fixed tool passed the seam check and was adopted ("history base complete to 966142"); at 963,967 our row's raw MuHash3072 hashes to Core's `1e3c77ad25f40961f1f757a77960b7c49a5c7bd091597bd925d561a5c202c118`, and `gettxoutsetinfo muhash 963967` on production matches Core in every field.
