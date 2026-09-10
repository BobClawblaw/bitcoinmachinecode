# 2026-09-10 — The sweep records the peer's sendcmpct

Block 966,302 on snapshot w: the announcement reached us the second Core had the block, and the fetch then took 11.5 s because the pass asked for a full 1.6 MB block from one slow peer. The peer's `sendcmpct` arrives right after verack; the sync drains used to record it during the leg's first pass, and since #159 the sweep reads every leg before its first pass and discarded it. Every leg installed since then fetched full blocks, and the "accepts compact blocks" line had all but vanished from the log.

The sweep hands `sendcmpct` to the daemon (`txrelay_on_sendcmpct`), which records version 2 on the leg and logs it, so the next pass requests `MSG_CMPCT_BLOCK` and the high-bandwidth set gets pushes that reconstruct from the mempool. `test_tx_relay` scenario 9 sends one and checks the hook.
