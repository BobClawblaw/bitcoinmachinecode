# 2026-09-09 — A bad compact-block reconstruction falls back to the full block; `bmc.cmpctrecv` is gone

Core has no switch for compact-block receive because it never needs one: a `PartiallyDownloadedBlock` that fails to become a valid block is re-requested in full, so a bug in the path costs bandwidth, never a block. This node lacked that fallback, so on 09-08, when the receive path was found never to complete, the only safe move was an emergency valve, `bmc.cmpctrecv=0`, and production ran with it from 18:38Z today.

- **The fallback.** In `bitcoind.asm`'s sync drain, a block assembled through the compact path (either the mempool-and-prefilled assembly or the one after `blocktxn`) that fails `cons_verify` is re-requested once with a `MSG_WITNESS_BLOCK` getdata and the drain continues; only a full block that also fails ends the pass with failure code 8, as before. The fallback is counted on the `[cmpct] reconstructed ... fell back` line through `cmpct_recv_note_fallback`.
- **The valve is removed**: the `bmc.cmpctrecv` key, its config field, its default, its boot line and its test. A conf that still carries the key is ignored, as Core ignores unknown keys. The regtest differential that set it no longer does.

`test_cmpct_fallback` (new, **watched to fail**: where=8, nothing stored): a fake peer answers the compact request for block 0 with a prefilled coinbase whose value byte is flipped, so the assembled block's merkle root no longer matches; the node must fetch block 0 in full, store both blocks, and count one fallback and one clean reconstruction. It did, once the drain had the fallback. The frame grew by 16 bytes for the two flags; assembled first on a scratch copy.

Production's conf line comes out at its next restart; until then it is inert.

---

PR #148 (`batch/2026-09-09-cmpct-fallback`), merged 20:0xZ as `ef705eea`; tag `cmpct-fallback-2026-09-09`. Staged as `deploy-20260909l`; live on production from 20:11:40Z with the conf line removed. First hour: 6 new blocks, 4 reconstructed, 12 round trips, 0 fallbacks, tip = public.
