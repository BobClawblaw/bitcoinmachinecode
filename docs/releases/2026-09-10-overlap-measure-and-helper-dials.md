# 2026-09-10 — Row 5's measurement, and no dial ever blocks the leg loop again

Two things the first hour of snapshot t on production asked for.

**The measurement row 5 wants.** Every block that goes through the compact receiver now prints one line:

```
[cmpct] block 966298 (host): 4280 tx: 2190 from the mempool (51.2%), 1 prefilled, 2089 fetched by getblocktxn (812 KB): 1700 never announced, 300 announced not requested, 30 requested no reply, 5 orphans, 54 rejected by policy
```

The receiver counts what the mempool supplied, what the peer prefilled and what getblocktxn had to fetch (`cmpct_recv_last_block`); a classifier the relay module provides (`txrelay_classify_missing`) says where each fetched transaction had gone: refused by the shared recent-rejects filter, parked as an orphan, requested and never answered (in flight or in the request ring), announced by a leg but never requested, or never announced to us at all. The split decides the fix: the first three are ours, the last is coverage. `test_cmpct_recv` pins the accounting and the classifier's call per fetched transaction.

**No dial in the loop that reads the legs.** The first block on t was stored 27 s after the oracle. The log said why: the worker was inside an outbound top-up, four inline connects at the 10 s timeout each, and read no leg while it waited. The clearnet re-dial after a leg closed had the same shape. Core's message loop never blocks on a connect. Both now go through the dial helper that the anonymity legs already used: a re-dial starts a helper for its slot and the leg stays down until it lands (`dh_install_leg` fills that slot), the top-up starts one background dial per tick, and the helper count is four. The dial helper test's cap scenario moved with it.

**Also on production:** `blockfilterindex=1` (Core's key) in the config. The basic block filter index sat at 966,181 with the daemon told not to maintain it; with the key set the daemon adopts a built index within 144 blocks of the tip and closes the gap from undo data. The undo history reaches below 965,826 since yesterday's reindex (`getblockstats 960000` answers with fees), so the depth cap on mempool.space's indexer is no longer needed.
