/* daemon/lsm_manifest.h -- the manifest file (utxo_manifest.dat) from C.
 *
 * Format (bitcoin_utxo_lsm.asm): UMN2 header = magic(4) manifest_n(8)
 * total_live(8), then manifest_n entries of [gen:8][run_no:8]. The OLD UMAN
 * header lacks total_live (12 bytes). The persisted total_live is RUNS-ONLY;
 * the running counter lst->total_live also includes the WAL tail, so no
 * reader here ever overwrites it -- adopt_child heals it by the persisted
 * base's movement, exactly as the inline compaction does.
 *
 * Used by background compaction (daemon/utxo_live.c): the forked child merges
 * with deferred unlink AND deferred publish, leaving utxo_manifest.child; the
 * parent, which may have flushed runs meanwhile, calls adopt_child. */
#ifndef LSM_MANIFEST_H
#define LSM_MANIFEST_H
#include "lsm_state.h"
#define LSM_MANIFEST_FILE   "utxo_manifest.dat"
#define LSM_MANIFEST_CHILD  "utxo_manifest.child"
#define LSM_MANIFEST_PUB    "utxo_manifest.dat.pub"   /* our tmp; the asm writers use utxo_manifest.tmp */
/* Read a manifest file into lst (entries, manifest_n; next_gen/next_run_no
 * advanced past every entry). persisted_live (may be NULL) gets the file's
 * runs-only count, ~0ULL if OLD format. 0 ok / -1. */
int lsm_manifest_read_file(const char* path, struct lsm_state* lst, uint64_t* persisted_live);
int lsm_manifest_read(struct lsm_state* lst, uint64_t* persisted_live);
/* Just the header's persisted count (~0ULL if none/unreadable). */
uint64_t lsm_manifest_persisted_live_file(const char* path);
uint64_t lsm_manifest_persisted_live(void);
/* Write lst's in-memory manifest crash-safely (tmp + fsync + rename + dir
 * fsync). persisted_live ~0ULL writes an OLD-format header so the next
 * reload recounts instead of trusting a number we could not derive. */
int lsm_manifest_publish(const struct lsm_state* lst, uint64_t persisted_live);
/* The parent's half of a background compaction. inputs[k] are the run_nos the
 * child merged (the oldest k at fork); is_full says k was the whole manifest
 * then; base_at_fork is lsm_manifest_persisted_live() taken at fork. Reads
 * utxo_manifest.child, checks it against lst's current manifest, builds
 * [child's entries] + [runs lst flushed since fork], heals lst->total_live,
 * publishes, deletes the child file. 0 ok / -1 (lst untouched: the child's
 * output run is then an orphan for the boot sweep). */
int lsm_manifest_adopt_child(struct lsm_state* lst, const uint64_t* inputs, int k,
                             int is_full, uint64_t base_at_fork, uint64_t* new_persisted);
/* Boot only, before any writer: delete run files the manifest does not name
 * (crash leftovers of publish-before-unlink and of background merges) plus a
 * stale utxo_manifest.child/.pub. Guard: the on-disk manifest must exist and
 * match lst's in-memory entries byte for byte, else nothing is touched and -1
 * is returned -- a sweep against an unloaded state would delete the store. */
int lsm_manifest_sweep_orphans(const struct lsm_state* lst);
#endif
