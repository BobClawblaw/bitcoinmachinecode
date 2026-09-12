/* daemon/utxo_live_compact_policy.h -- when a background merge may start
 * while blocks are being applied (2026-09-09, docs/CORE_DIVERGENCES.md row 1).
 *
 * Core has no merges: one coin cache, written once when full or at the end.
 * This engine merges immutable runs in a background child that reads and
 * rewrites the set on the same disk the apply is reading and the archive is
 * being written to. Run 19 (64 MB steady-state memtable) merged 3,382 times
 * in ten hours, 3.5 hours of merge time; production's bulk reindex merged
 * 18 times, 1,778 s. A merge that starts while the apply is already behind
 * the download only widens the gap, so: while the apply lags, wait -- up to
 * a ceiling on the run count (lookups scan every run, and the manifest has
 * a hard cap), and never when the run files are over the memory budget. */
#ifndef BMC_UTXO_LIVE_COMPACT_POLICY_H
#define BMC_UTXO_LIVE_COMPACT_POLICY_H
#define COMPACT_DEFER_LAG_BLOCKS 256L   /* the apply this far behind the archive: the disk is theirs */
#define COMPACT_DEFER_CEILING_MULT 2    /* ... until the run count reaches this multiple of the threshold */
/* 1 = defer this merge (the apply is behind and the run count is under the ceiling) */
static inline int compact_should_defer(long apply_lag, long manifest_n, long threshold, int over_budget){
    if (over_budget) return 0;
    if (apply_lag < COMPACT_DEFER_LAG_BLOCKS) return 0;
    if (manifest_n >= threshold * COMPACT_DEFER_CEILING_MULT) return 0;
    return 1;
}
#endif
