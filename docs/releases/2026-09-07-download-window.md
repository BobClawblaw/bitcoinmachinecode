# 2026-09-07 — The download window is 4096 blocks with a fresh anchor and a 2 s help

Run 11, the first run on the window (#77), was monotonic (0 holes, connect lag 0) and throttled: 32,241 blocks at five minutes against run 9's 86,000, 512 window waits.

- **Fresh anchor.** The parent published the first hole once per 10 s tick; the early chain drains a 1024-block window in seconds, so workers idled between ticks. A worker blocked at the window now rescans the index itself (two asm scans) and shares the fresher anchor; it waits, in 200 ms steps, only when the frontier really is there.
- **Window 4096.** Core's 1024 stands against ~128-160 blocks in flight (6-8x); ours stood against 640 (1.6x), so the fast workers were always waiting. 4096 is the same slack ratio; the archive stays consolidated behind it.
- **Help after 2 s** (Core's BLOCK_STALLING_TIMEOUT_DEFAULT), not 120 s, with a CAS-claimed helper slot so one waiter duplicates the blocking chunk.

**Proof.** A fresh scratch node on this build: **101,591 blocks at 5:52** against run 9's 86,266 with no window at all; holes bounded ~300 inside the window; connect caught up; 31 helps, 140 waits, 0 abandons; 289 rotations over 59 peers. `test_dialhelper` updated for 4096; full gate 13,310 lines, 0 failures; 8 audits exit 0.

---

PR #78 (`batch/2026-09-07-fresh-anchor`), merged 15:54Z as `7500a984`; tag `download-window-2026-09-07`.
