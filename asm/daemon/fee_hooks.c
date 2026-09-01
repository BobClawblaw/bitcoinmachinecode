/* daemon/fee_hooks.c -- the daemon-side glue between the mempool paths and
 * the fee estimator (daemon/fee_estimator.c). The estimator state is the
 * MAP_SHARED region mempool_configure() allocates pre-fork (mp_ext_feeest),
 * so the download worker (blocks, admission), the serve parent (expiry) and
 * the RPC readers all see one estimator. Every entry point here is reached
 * with the mempool's process-shared lock held by the caller (tx_accept.c's
 * admission and block-connect paths, mempool_cfg.c's expiry), except
 * fest_shutdown_flush, which takes it itself.
 *
 * The same names exist as WEAK no-op stubs in tx_accept.c / mempool_cfg.c
 * so the many test binaries that link those without this file still link;
 * these strong definitions win in the daemon. */
#include "fee_estimator.h"
#include <stdio.h>
#include "log_ts.h"
#include <time.h>

extern void* mp_ext_feeest;                     /* daemon/mempool_cfg.c */
extern void  mp_lock(void);
extern void  mp_unlock(void);

#define FEE_FLUSH_INTERVAL_S (60L * 60L)       /* Core FEE_FLUSH_INTERVAL{1h} */
static long g_last_flush;

void fest_on_accept(const unsigned char* txid, unsigned long long fee, unsigned long long vsize, long height, int valid){
    if (!mp_ext_feeest || height < 0) return;
    fest_process_transaction(mp_ext_feeest, txid, fee, vsize, (unsigned)height, valid);
}
void fest_on_confirmed(const unsigned char* txid){
    if (mp_ext_feeest) fest_block_tx(mp_ext_feeest, txid);
}
void fest_on_block_begin(long height){
    if (mp_ext_feeest && height > 0) fest_block_begin(mp_ext_feeest, (unsigned)height);
}
void fest_on_block_end(void){
    if (!mp_ext_feeest) return;
    fest_block_end(mp_ext_feeest);
    long now = (long)time(NULL);
    if (!g_last_flush) g_last_flush = now;
    if (now - g_last_flush >= FEE_FLUSH_INTERVAL_S){
        g_last_flush = now;
        if (!fest_write_file(mp_ext_feeest, "fee_estimates.dat"))
            fprintf(stderr, "[feeest] WARNING: failed to write fee_estimates.dat (continuing)\n");
    }
}
void fest_on_forget(const unsigned char* txid){
    if (mp_ext_feeest) fest_remove_tx(mp_ext_feeest, txid);
}
/* Core's Flush() at shutdown: every still-unconfirmed tracked tx is booked
 * as "left the mempool" (FlushUnconfirmed), then the file is written. */
void fest_shutdown_flush(void){
    if (!mp_ext_feeest) return;
    mp_lock();
    unsigned long n = fest_tracked(mp_ext_feeest);
    fest_flush_unconfirmed(mp_ext_feeest);
    int ok = fest_write_file(mp_ext_feeest, "fee_estimates.dat");
    mp_unlock();
    fprintf(stderr, "[feeest] shutdown: %lu unconfirmed tx flushed, fee_estimates.dat %s (best height %u)\n",
            n, ok ? "written" : "NOT written", fest_best_height(mp_ext_feeest));
}
