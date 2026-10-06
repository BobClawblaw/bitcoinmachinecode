/* daemon/lsm_state.h -- the C view of bitcoin_utxo_lsm.asm's lsm_state.
 * ONE definition. utxo_live.c and lsm_manifest.c both include it; a second
 * hand-written copy is how a struct grows a field on one side only (see
 * bitcoin_taproot_ctx.h for the day that cost). Offsets are the asm's. */
#ifndef LSM_STATE_H
#define LSM_STATE_H
#include <stdint.h>
struct lsm_state {
    long log_fd, idx_fd;
    uint64_t log_len, ckpt_log_off, ckpt_n;
    uint64_t op_count, op_threshold, fill_threshold;
    void* tomb_buf; uint64_t tomb_cap, tomb_n, total_live, next_gen;
    void* manifest_buf; uint64_t manifest_cap, manifest_n;
    void* scratch_buf; uint64_t scratch_cap;
    uint64_t next_run_no;
    void* tomb_hash_buf; uint64_t tomb_hash_mask; /* LSM-owned, see bitcoin_utxo_lsm.asm */
    /* the frozen generation (plan B3, 2026-10-06): read by the asm only after
     * utxo_lsm_fz_enable(1); see the asm's struct comment for each field */
    void* fz_u;                                   /* +168 the copy of the live table (its own blob at +16) */
    void* fz_tomb_buf; uint64_t fz_tomb_n;        /* +176 the spare/frozen tombstone list, +184 its count */
    void* fz_tomb_hash_buf; uint64_t fz_tomb_hash_mask;   /* +192/+200 LSM-owned */
    uint64_t fz_active, fz_gen, fz_run_no, fz_wal_end;    /* +208..+232 */
};
#endif
