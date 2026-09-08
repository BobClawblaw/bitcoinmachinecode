# 2026-09-08 — The catch-up tick is two lines, per-block lines silent in IBD, one line per compaction, peer table every five minutes

Run 16's log was 40,779 lines in 8.6 h (78/min), 95% six line types. Now: the tick is the status line plus ONE dashed line (recv/write with run averages, floor and pool median, bans, event counts this tick and run totals); the NODE_WITNESS count only when it changes; '[dl] new block' follows the announcement's IBD gate (Core's rule) and returns at the tip; a compaction is one line at completion that also says what it was; the peer table every 30th tick. About 10 lines/min, every number still available at the same cadence except the table. test_dlc_interleave accepts the once-only IBD line as proof the choke point fired. OPERATIONS.md updated. Full gate 0 failures, 8 audits exit 0.

---

PR #92 (`batch/2026-09-08-quieter-log`), merged 02:39Z as `bf05a834`; tag `quieter-log-2026-09-08`.
