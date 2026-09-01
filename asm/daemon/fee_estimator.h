/* daemon/fee_estimator.h -- Core's CBlockPolicyEstimator (policy/fees/
 * block_policy_estimator.{h,cpp}, v31.99) in C, living in ONE contiguous
 * region so it can be MAP_SHARED between the download worker (which sees
 * blocks and admits transactions) and the RPC process (estimatesmartfee /
 * estimaterawfee). The caller serialises access with the mempool's own
 * process-shared lock (mp_lock/mp_unlock); nothing in here locks.
 *
 * Three TxConfirmStats horizons exactly as Core: short (12 periods x scale
 * 1, decay .962), medium (24 x 2, .9952), long (42 x 24, .99931); feerate
 * buckets 100 sat/kvB .. 1e7 spaced x1.05 plus an INF bucket; the same
 * moving averages, the same EstimateMedianVal walk, the same smart-fee
 * ladder (60% at target/2, 85% at target, 95% at 2x target, conservative).
 * Numbers are computed in the same order with the same double arithmetic so
 * the regtest differential (validation/feeest_core_diff.sh) can demand
 * identical output. */
#ifndef BMC_FEE_ESTIMATOR_H
#define BMC_FEE_ESTIMATOR_H

typedef struct { double start, end, within_target, total_confirmed, in_mempool, left_mempool; } fest_bucket_t;
typedef struct { fest_bucket_t pass, fail; double decay; unsigned scale; } fest_result_t;
enum { FEST_SHORT = 0, FEST_MED = 1, FEST_LONG = 2 };

/* sizing/creation: map_cap = tracked-tx table capacity (rounded up to a
 * power of two >= 1024). The region must be zero-filled by the caller
 * (fresh mmap) or fest_init zeroes it itself. */
unsigned long fest_state_size(unsigned long map_cap);
int  fest_init(void* st, unsigned long map_cap);
int  fest_valid(const void* st);

/* writer side -- Core's processTransaction / processBlock / removeTx.
 * `valid` mirrors NewMempoolTransactionInfo's validForFeeEstimation:
 * !limit_bypassed && !submitted_in_package && chainstate_is_current &&
 * has_no_mempool_parents. `height` is the tip height the tx was admitted at
 * (Core's txHeight); a tx is only tracked when it equals the best height the
 * estimator has seen a block for. */
void fest_process_transaction(void* st, const unsigned char txid[32],
                              unsigned long long fee, unsigned long long vsize,
                              unsigned height, int valid);
/* A connected block: begin(height) rolls the counters (returns 0 when the
 * height is not above the best seen -- the block's txs are then merely
 * forgotten, Core leaks them), tx() per confirmed txid, end() finishes. */
int  fest_block_begin(void* st, unsigned height);
int  fest_block_tx(void* st, const unsigned char txid[32]);
void fest_block_end(void* st);
/* removed WITHOUT confirming (eviction, replacement, expiry, conflict) */
int  fest_remove_tx(void* st, const unsigned char txid[32]);

/* readers -- sat/kvB, 0 = "no estimate" (Core's CFeeRate(0)) */
unsigned long long fest_estimate_smart(const void* st, int conf_target, int conservative,
                                       int* returned_target, fest_result_t* res);
unsigned long long fest_estimate_raw(const void* st, int conf_target, double threshold,
                                     int horizon, fest_result_t* res);
unsigned fest_highest_target(const void* st, int horizon);   /* GetMaxConfirms */
unsigned fest_best_height(const void* st);
unsigned long fest_tracked(const void* st);                  /* mapMemPoolTxs.size() */

/* persistence (fee_estimates.dat; own format, same content as Core's Write) */
int  fest_write_file(const void* st, const char* path);
int  fest_read_file(void* st, const char* path, long max_age_hours);  /* <0 = no age limit */
void fest_flush_unconfirmed(void* st);                       /* Core FlushUnconfirmed */

#endif
