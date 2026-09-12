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
#endif
