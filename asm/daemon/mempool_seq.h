/* daemon/mempool_seq.h -- Core's mempool sequence number and the event ring
 * behind the ZMQ `sequence` topic (-zmqpubsequence).
 *
 * WHAT CORE PUBLISHES (zmq/zmqpublishnotifier.cpp SendSequenceMsg, v31.1):
 *   [32-byte hash, display order][1-byte label][8-byte LE mempool sequence]
 * with the last part present only for the two MEMPOOL labels:
 *   'A'  a transaction entered the mempool      (TransactionAddedToMempool)
 *   'R'  a transaction left it for any reason   (TransactionRemovedFromMempool)
 *        EXCEPT inclusion in a block -- removeUnchecked skips the signal for
 *        MemPoolRemovalReason::BLOCK. EXPIRY, SIZELIMIT, REORG, CONFLICT and
 *        REPLACED all fire it.
 *   'C'  a block was connected                  (BlockConnected)
 *   'D'  a block was disconnected               (BlockDisconnected)
 *
 * THE MEMPOOL SEQUENCE is CTxMemPool::m_sequence_number: it starts at 1 and
 * GetAndIncrementSequence() is taken on EVERY add and EVERY removal --
 * including the BLOCK removals that publish nothing, which is why a
 * subscriber sees the number jump by the count of mined transactions across
 * a 'C'. getrawmempool(false, true) returns {txids, mempool_sequence} with
 * the CURRENT value (the next one to be handed out), read under the same lock
 * as the txid list, so a subscriber can line a snapshot up with the stream:
 * every event numbered below it is already reflected in the snapshot.
 *
 * WHY A SHARED RING. The mempool is mutated from several PROCESSES here (the
 * download worker: RPC submits, block connect, reorg, expiry; every inbound
 * serve child: relay accepts) while the ZMQ publisher -- which owns the
 * sockets -- lives only in the download worker. So a mutation site cannot
 * publish; it STAGES the event here, in a MAP_SHARED region created by
 * mempool_configure before any fork, and the worker drains it in order
 * (daemon/zmq_notify.c zmqn_drain).
 *
 * ORDER IS THE WHOLE POINT, and it comes from the pool lock. Every mempool
 * mutation already runs under mp_lock (daemon/mempool_cfg.c). The counter is
 * bumped and the event staged INSIDE that critical section, so the order of
 * ring slots is the order the pool changed in and the numbers are strictly
 * increasing along the ring. 'C'/'D' are staged under the same lock, so they
 * land between the pool events exactly where the block's effect on the pool
 * does. The slot claim is still an atomic increment, so a writer that is not
 * under the lock (a test, the per-process fallback pool) cannot corrupt the
 * ring -- it can only interleave.
 *
 * LOSS IS VISIBLE. A consumer that is lapped skips to the oldest intact slot
 * and advances the topic's own 4-byte ZMQ sequence by the number lost
 * (zmqpub_skip), so the subscriber sees a gap exactly as it would for a
 * high-water-mark drop -- and the mempool sequence jumps too.
 */
#ifndef MEMPOOL_SEQ_H
#define MEMPOOL_SEQ_H

/* 65,536 events. A reorg or a mempool.dat reload is a burst of A/R events;
 * the worker drains once per loop, once per connected block, and -- since
 * 2026-09-19 -- after each of its own accepts (zmq_notify.c), so a reload
 * never stages more than a handful ahead of the drain. 56 bytes per
 * slot -> 3.5 MiB of anonymous shared memory, touched only as it is used. */
#define MPSEQ_RING 65536u

typedef struct {
    volatile unsigned long long ready;   /* slot+1 once filled; 0 = never     */
    unsigned long long          mseq;    /* mempool sequence ('A'/'R' only)   */
    unsigned char               hash[32];/* txid / block hash, WIRE order     */
    unsigned char               label;   /* 'A' 'R' 'C' 'D'                   */
    unsigned char               pad[7];
} mpseq_ev;

typedef struct {
    volatile unsigned long long next;    /* Core m_sequence_number (starts 1) */
    volatile unsigned long long head;    /* ring slots claimed                */
    volatile unsigned long long lost;    /* events the consumer was lapped by */
    volatile unsigned long long pad;
    mpseq_ev ev[MPSEQ_RING];
} mpseq_area_t;

/* daemon/mempool_cfg.c ---------------------------------------------------- */
/* Create the shared area (pre-fork) and register the policy layer's hook.
 * Idempotent. Returns 1 when the area exists. */
int  mempool_seq_configure(void);
mpseq_area_t* mpseq_area(void);
/* The value getrawmempool reports (Core GetSequence). Read it under mp_lock
 * together with whatever it is meant to agree with. 1 when unconfigured. */
unsigned long long mempool_sequence(void);
/* The policy layer's hook: kind 'A' add, 'R' removal, 'M' mined (bump only).
 * Suppressed while held (see mempool_seq_hold). Caller holds mp_lock. */
void mempool_seq_note(const unsigned char txid[32], int kind);
/* The same, NOT suppressed by the hold: the reorg reconcile publishes the
 * net difference of its rebuild through this. Caller holds mp_lock. */
void mempool_seq_emit(const unsigned char txid[32], int kind);
/* Suppress the hook while a rebuild re-adds a pool it just emptied. */
void mempool_seq_hold(int on);
/* 'C' / 'D' for a block (hash in WIRE order). _locked: caller holds mp_lock. */
void mempool_seq_block_locked(const unsigned char hash[32], int label);
void mempool_seq_block(const unsigned char hash[32], int label);

#endif
