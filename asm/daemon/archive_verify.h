/* daemon/archive_verify.h -- archive integrity + prune decision surface.
 *
 * Exists so the PRUNE DECISION can be tested independently of the deletion it
 * authorises. See archive_prune_decide's own comment for why that separation
 * is not optional here.
 */
#ifndef ARCHIVE_VERIFY_H
#define ARCHIVE_VERIFY_H

typedef enum {
    ARCHIVE_PRUNE_NOTHING = 0,      /* budget already covers the whole archive */
    ARCHIVE_PRUNE_OK,               /* safe: delete below *out_height          */
    ARCHIVE_PRUNE_REFUSE_LAYOUT,    /* blocks not laid out monotonically       */
    ARCHIVE_PRUNE_REFUSE_HOLE,      /* a height below the gate was never fetched */
    ARCHIVE_PRUNE_ERROR             /* could not be computed at all            */
} archive_prune_verdict_t;

long archive_scan(long* out_entries, long* out_unique, long* out_dups);
long archive_scan_duplicates(long* out_heights, long max_out);
long archive_repair_duplicates(void);
long archive_layout_monotonic(long upto);
long archive_check(long nblocks, int level);
long archive_first_hole(long upto);
long archive_prune_height_for_budget(long long budget_bytes);
archive_prune_verdict_t archive_prune_decide(long long budget_bytes,
                                             long* out_height, long* out_detail);
int  archive_verify_and_repair(void* store_buf, int repair);
long archive_drop_utxo_state(void);

#endif
