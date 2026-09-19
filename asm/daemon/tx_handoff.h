/* daemon/tx_handoff.h -- inbound serve children hand the transactions their
 * peers send to the download worker, which validates them against the LIVE
 * UTXO set. See tx_handoff.c for why. */
#ifndef TX_HANDOFF_H
#define TX_HANDOFF_H

#define TXHO_RING_BYTES (8UL << 20)      /* shared byte ring */
#define TXHO_MAX_TX     400000UL         /* MAX_STANDARD_TX_WEIGHT: a bigger raw tx is non-standard */

/* parent, once, BEFORE the serve and worker forks. 1 = ring ready. */
int  txho_create(void);
/* 1 when the ring exists in this process (created, or inherited across fork) */
int  txho_ready(void);
/* producer (an inbound serve child): 1 queued, 0 dropped (ring full, or a tx
 * no policy could accept), -1 no ring -- the caller validates locally */
int  txho_push(const unsigned char* tx, unsigned long len, int src_slot);
/* consumer (the worker only): calls fn for up to `max` queued transactions,
 * oldest first; returns how many were handed out */
typedef void (*txho_fn)(const unsigned char* tx, unsigned long len, int src_slot, void* ctx);
long txho_drain(txho_fn fn, void* ctx, long max);
/* counters for the heartbeat and the tests */
void txho_stats(unsigned long long* pushed, unsigned long long* popped,
                unsigned long long* dropped_full, unsigned long long* dropped_big);
/* test seam: forget the ring (the mapping stays; tests run one per process) */
void txho_detach(void);
int  txho_test_lock_and_die(void);    /* test seam: lock, scribble, return holding it */
#endif
