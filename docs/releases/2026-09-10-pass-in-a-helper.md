# 2026-09-10 — A leg's pass runs in a helper, so a slow fetch stalls nobody

Inventory row 1 (leg service). Core serves every peer from one loop; a slow fetch never stalls the rest. Here a leg's pass (getheaders, the block, verify, store) blocked the worker for its whole length, 4 to 12 s per block on production this evening, and every other leg's sweep, pongs, relay, announcements and pushes waited for it.

- **The pass runs in a forked child** (`leg_pass_start`) that owns the leg's socket until it reports, under the same budget alarm. The archive appends are file-level and locked, the mempool is shared, and the report back is small: the verdict, the tip it stored to, whether the peer took sendcmpct, a reorg-gate rewind, and the BIP324 session with its advanced cipher (the handover from #167).
- **The parent replays the bookkeeping once** (`leg_pass_finish`): the store reload, the session import, the hash index for the new heights, the chainwork sync, the locator, and the fail rules as one function shared with the synchronous path (`pass_fail_bookkeeping`). In the child a close is recorded, not done.
- **While a pass runs**, the sweep, the announced pick and the hang-up check skip that leg; up to four passes run at once; the reports are collected at the top of every rotation (`leg_pass_poll`), and a child that outlives its budget by fifteen seconds is killed and treated as a budget close. If a helper cannot start, the pass runs inline as before.

Verified: the regtest end-to-end syncs the initial 110 blocks through helper passes and follows Core's pushed blocks to 116 of 116; `test_dialhelper` and `test_dlc_interleave` pass. On production the `[mux]` lines keep coming while a block is being fetched.
