# 2026-09-10 — The transaction request queue drains, as Core's does

Inventory row 2's code piece. Core's TxRequestTracker keeps every announcement it hears and requests transactions as the per-peer in-flight budget frees up. Ours requested at most 32 per pass (`TXR_MAX_REQ`) and left the rest noted as announced but never requested: the per-block overlap line on production counted 43 of those in block 966,305 and 106 in block 966,308.

Each poll of a leg now requests, from what that leg announced and nothing has fetched since, up to 32 more while the per-peer in-flight budget of 100 has room (`txr_drain_pending`), with the same dedup ring, notfound memory and mempool check the first request uses. The heartbeat's relay line reports the drained count.

`test_tx_relay` scenario 10: an inv of 40 gets a getdata of 32 on the first pass and, with nothing else buffered, a getdata of the remaining 8 on the next, and nothing on a third; watched to fail (nothing on the second poll) before the drain existed. The other half of row 2, coverage, waits on inbound peers: 87 to 98% of the missing transactions were never announced to us at all.
