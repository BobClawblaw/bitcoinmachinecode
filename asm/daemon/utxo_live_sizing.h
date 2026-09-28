/* daemon/utxo_live_sizing.h -- the memtable sizing decision, header-only so a
 * test pins it (2026-09-09).
 *
 * Bulk sizing is the dbcache: -dbcache maps to bulk_slots/bulk_blob at boot,
 * and Core spends that whole cache during initial block download, writing it
 * out when full or at the end. This engine took the bulk sizing only when a
 * boot found the archive far ahead of the applied height (gap >= 50,000) or a
 * large WAL tail -- so a FRESH datadir, which boots with no archive (tip 0,
 * applied -1, gap 1), synced the entire chain through the 64 MB steady-state
 * memtable while the configured 6 GB sat unused. Every benchmark run since the
 * engine landed did that (run 19: "sizing: steady-state (applied=-1 tip=0
 * gap=1) slots=2^16 blob=64MB", 300 ms a block at height 700,000). An empty
 * set is initial block download by definition. */
#ifndef BMC_UTXO_LIVE_SIZING_H
#define BMC_UTXO_LIVE_SIZING_H
/* 1 = bulk (dbcache-sized), 0 = steady-state */
static inline int utxo_live_pick_bulk(long applied, long tip, long gap_threshold){
    if (applied < 0) return 1;                                   /* nothing applied yet: a fresh sync */
    long gap = tip >= 0 ? tip - applied : 0;
    return gap >= gap_threshold;
}
/* The third signal (issue #294, 2026-09-28): the STORE'S SHAPE. The block gap
 * says how much work is left and the WAL tail how much is about to be
 * replayed; neither says what each lookup will cost, which is the run count
 * and the run bytes. A node restarted mid-sync with gap 3,345, a 0.25 GB WAL
 * (just under the 256 MB line) and 17 runs totalling 42 GB took the 64 MB
 * steady-state memtable, probed 17 runs per lookup through it, and applied
 * nothing for 25 minutes at 100% CPU -- silent, because nothing logs during
 * the load. bmc.utxobulkgapblocks=500 made the same load finish in 162 s.
 * Bulk when the runs are at or past the compaction threshold (the store is
 * already due a merge) or their bytes are past the run budget (the 35%-of-RAM
 * line the compactor uses: past it lookups fault from disk). Bulk sizing
 * costs address space, not resident memory, so over-selecting is cheap. */
static inline int utxo_live_pick_bulk_shape(long runs, unsigned long long run_bytes,
                                            long compact_threshold, unsigned long long run_budget){
    if (compact_threshold > 0 && runs >= compact_threshold) return 1;
    if (run_budget > 0 && run_bytes >= run_budget) return 1;
    return 0;
}
#endif
