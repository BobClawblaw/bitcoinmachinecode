/* daemon/lsm_manifest.h -- re-read utxo_manifest.dat into an lsm_state.
 * Used by the parent after a background compaction child has published a new
 * manifest: the child's in-memory update is invisible to the parent, and the
 * file is the truth. Returns 0 ok / -1 (unreadable, bad magic, too many runs
 * for manifest_cap); total_live is left alone, see below. Advances next_gen and next_run_no past every entry so
 * later flushes cannot collide with the merged run. */
#ifndef LSM_MANIFEST_H
#define LSM_MANIFEST_H
#include "lsm_state.h"
/* persisted_live (may be NULL) receives the file's RUNS-ONLY live count, or
 * ~0ULL for an OLD-format manifest that has none. The running counter
 * lst->total_live is NOT touched: it includes the WAL tail, and the adopter
 * heals it the way compaction itself does -- running += new_base - old_base
 * (see lsm_manifest_persisted_live and utxo_live.c compact_adopt). */
int lsm_manifest_read(struct lsm_state* lst, uint64_t* persisted_live);
/* Just the header's persisted live count (~0ULL if none/unreadable). */
uint64_t lsm_manifest_persisted_live(void);
#endif
