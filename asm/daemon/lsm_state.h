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
};
#endif
