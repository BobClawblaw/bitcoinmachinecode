/* index_worker.h -- the index writers off the applier (2026-10-06, plan B4;
 * worklog/2026-10-05-b3-b4-design.md).
 *
 * The new-block choke point ran the txid tail, the txospender tail, the
 * block-filter index and the address journal IN the applying process after
 * every connected block: 693 thread-seconds over the chain in run 37 (ix
 * txindex 327 + ix bfilter 366), serial with the apply. Core does its
 * index writes on the validation-interface callback threads (5 s on its
 * validation thread over the chain).
 *
 * Shape: the applier pushes (BLOCK h) onto a bounded ring in the shared
 * status block after the block is connected; a FORKED worker consumes in
 * order -- reads the block from the archive itself, runs the four writers,
 * publishes the watermarks the [ready] line gates on. The trailing
 * builders' fold callbacks (drop the tail's records a run now covers:
 * txit_runs_advanced and friends rewrite the tail file and reopen its fd)
 * go through the same ring as ADV records, so the process that holds the
 * tail's fd is the one that rotates it. A full ring blocks the applier --
 * the inline cost, only under a worker slower than apply. A STOP record
 * ends the worker after everything before it; the parent then re-boots
 * its own (stale since the fork) writer state from the files. A worker
 * that dies is noticed at the next push, which returns 0: the caller
 * re-boots the writers and indexes inline, as before the worker.
 *
 * The same discipline as the coinstats fold worker (coinstats_index.c):
 * only the STOP record or the parent's death ends the worker, never a
 * SIGTERM to the process group. */
#ifndef BMC_INDEX_WORKER_H
#define BMC_INDEX_WORKER_H
#include "../rpc_node.h"

enum { IXW_K_BLOCK = 1, IXW_K_ADV_TXI = 2, IXW_K_ADV_TSP = 3, IXW_K_ADV_AH = 4, IXW_K_STOP = 5 };
#define IXW_NS_N 8   /* the per-writer timing slots on_block fills (BL_IX_N <= this) */

typedef struct {
    long (*read_block)(long h, unsigned char* buf, long cap);   /* block h from the archive; <= 0 unreadable */
    void (*reload)(void);                                        /* see the committer's appends before retrying a read */
    void (*on_block)(long h, const unsigned char* blk, long blen, unsigned long long ns[IXW_NS_N]);   /* the writers, timed */
    void (*runs_advanced)(int kind, long to);                    /* IXW_K_ADV_*: the tail's fold */
    long (*covered)(void);                                       /* the txid index's watermark, in the worker */
    long (*bfi_count)(void);                                     /* the filter index's count, in the worker */
    void (*log_index)(long h, const unsigned long long ns[IXW_NS_N]);   /* the [bench] index line, or NULL */
    void (*in_child)(void);                                      /* once, in the worker, before its loop (or NULL) */
    long  block_cap;                                             /* the worker's block buffer */
} ixw_hooks_t;

int  ixw_start(node_status_t* st, const ixw_hooks_t* hooks);    /* 1 = a worker owns the writers now; 0 = inline */
int  ixw_on(void);                                              /* a worker was started and has not been stopped or found dead */
int  ixw_push(int kind, long a);                                /* 1 queued; 0 = no worker (or it died: the caller goes inline) */
int  ixw_dead(void);                                            /* the worker exited (reaped here) */
void ixw_stop(void);                                            /* STOP, bounded wait, SIGKILL; ixw_on() is 0 after */
long ixw_current_height(void);                                  /* in the worker: the BLOCK being indexed (the address tail's applied-height seam) */
long ixw_pid(void);
#endif
