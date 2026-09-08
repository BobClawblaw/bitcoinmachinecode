# 2026-09-08 — The far-behind trigger believes the second-highest announce, not one peer's claim

Production logged `archive at 966062, peers announce 969817: 3755 blocks behind -- running the parallel downloader` every ten minutes on one peer's version `start_height`. Each run was a two-minute header phase that wrote nothing and paused the tip loop; nine of them today.

- `dl_trigger_height`: the far-behind trigger believes the second-highest announce among connected peers (the top one with a single peer). One liar cannot start a run; two agreeing peers can.
- A claim that already produced zero blocks at the same archive tip is not retried (`noop_best`/`noop_tip`), so a lying pair costs one run, not one every ten minutes.
- test_dialhelper +4: one peer, two with a liar, five with a liar, none.

Gate: `make -j8 test` MAKE_EXIT=0; the eight static audits pass (gate-log-check flags test_rpc_signer's intentional segfault, as always).

---

PR #109 (`batch/2026-09-08-announce-cap`), merged 12:27Z as `91a94e3c`; tag `announce-cap-2026-09-08`.
