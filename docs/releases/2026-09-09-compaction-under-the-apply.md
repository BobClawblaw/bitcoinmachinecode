# 2026-09-09 — A background merge waits while the apply is behind, and yields when it runs

Row 1 of `docs/CORE_DIVERGENCES.md`. Core has no merges: one coin cache, written once when full or at the end. This engine merges immutable runs in a background child that reads and rewrites the set on the disk the apply is reading from and the archive is being written to. Measured: run 19, on the 64 MB steady-state memtable, merged 3,382 times in ten hours, 3.5 hours of merge time, one every ten seconds by height 750,000, while the apply fell up to 969 blocks behind the download; production's bulk reindex merged 18 times for 1,778 s.

- **A merge waits while the apply is behind.** `compact_should_defer` (`utxo_live_compact_policy.h`): when the applied height trails the archive by 256 blocks or more, a merge that the count threshold would start is deferred, until the run count reaches twice the threshold (lookups scan every run, and the manifest has a hard cap) and never when the run files are over the memory budget. The catch-up loop hands the engine its lag; the first deferral of a streak is logged and the completion line carries the running count.
- **The merge child yields**: nice 10 and best-effort I/O at the lowest priority. Not the idle class, which starves outright under a busy apply and never lands (the 09-08 note on background writers).

The dbcache sizing (PR #153) removes most of the merges a fresh sync used to make; this batch governs the ones that remain and every merge on a restart with a backlog.

`test_compact_policy` (new): keep up, merge; lag 256 at the threshold, wait; run 19's worst lag, wait; twice the threshold, merge; over budget, merge; the steady-state numbers. The engine's compaction tests unchanged. Gate: see the trailer.

**To measure on the next fresh run**, from lines the engine prints: merges, their durations, deferrals, the apply lag over the run, and the 634,561 and 800,000 marks against run 19's.
