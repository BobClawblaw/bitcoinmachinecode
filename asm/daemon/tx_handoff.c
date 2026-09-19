/* daemon/tx_handoff.c -- a transaction received from an INBOUND peer is
 * validated by the download worker, not by the serve child that read it.
 *
 * WHY (2026-09-19): each inbound connection is a forked serve child, and the
 * child validated a `tx` itself -- against the read-only UTXO snapshot the
 * serve parent built ONCE at boot (serve_txdv_preinit, main.c) and every
 * child inherits copy-on-write. That snapshot never moves. Every coin created
 * after the node started was missing from it, and every coin spent since was
 * still in it, so a relayed transaction spending anything younger than the
 * process was refused as missing-inputs and silently dropped. On regtest,
 * where every spendable coin is younger than the node, a Core peer's
 * relayed transactions NEVER reached the mempool through an inbound leg
 * (reproduced: Core `sending tx` x3, bmc `[tx_accept] ... rejected: 3
 * missing-inputs`, getrawmempool empty). On mainnet the loss grows with
 * uptime and was masked by the outbound legs, which validate in the worker
 * against the live set (incident #48's resolver).
 *
 * The worker is the one process whose UTXO view is coherent (it is the
 * writer), and it already carries the whole relay pipeline: orphan parking,
 * 1p1c, the reject filter, announcement. So the child no longer judges; it
 * queues the raw bytes here and the worker drains them once per rotation
 * through the same path its own legs' transactions take.
 *
 * SHAPE: one MAP_SHARED byte ring, created by the serve parent before any
 * fork (a shared table needs a creator every process inherits). Producers
 * (the children) serialize on a ROBUST process-shared mutex and publish a
 * record by advancing `head` only after its bytes are in place, so a child
 * killed mid-copy leaves nothing half-visible: the next producer recovers
 * the lock and overwrites the unpublished bytes. The single consumer (the
 * worker) needs no lock; it reads [tail, head) and publishes `tail`.
 * A full ring drops the newest transaction and counts it -- the peer will
 * announce it again, or another peer will; a queue that blocked a serve
 * child would stall that peer's block service instead.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <pthread.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include "tx_handoff.h"

typedef struct {
    pthread_mutex_t mu;                     /* producers only */
    volatile unsigned long long head;       /* bytes published (producers, under mu) */
    volatile unsigned long long tail;       /* bytes consumed (the worker only) */
    volatile unsigned long long pushed, popped, dropped_full, dropped_big;
    unsigned char buf[TXHO_RING_BYTES];
} txho_ring_t;

static txho_ring_t* g_r = 0;

int txho_ready(void){ return g_r != 0; }
void txho_detach(void){ g_r = 0; }

int txho_create(void){
    if (g_r) return 1;
    void* p = mmap(0, sizeof(txho_ring_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;
    txho_ring_t* r = (txho_ring_t*)p;
    pthread_mutexattr_t a;
    pthread_mutexattr_init(&a);
    pthread_mutexattr_setpshared(&a, PTHREAD_PROCESS_SHARED);
    pthread_mutexattr_setrobust(&a, PTHREAD_MUTEX_ROBUST);
    if (pthread_mutex_init(&r->mu, &a) != 0){ pthread_mutexattr_destroy(&a); munmap(p, sizeof(txho_ring_t)); return 0; }
    pthread_mutexattr_destroy(&a);
    g_r = r;
    return 1;
}

static void ring_put(unsigned long long pos, const void* src, unsigned long n){
    unsigned long off = (unsigned long)(pos % TXHO_RING_BYTES), first = TXHO_RING_BYTES - off;
    if (first > n) first = n;
    memcpy(g_r->buf + off, src, first);
    if (n > first) memcpy(g_r->buf, (const unsigned char*)src + first, n - first);
}
static void ring_get(unsigned long long pos, void* dst, unsigned long n){
    unsigned long off = (unsigned long)(pos % TXHO_RING_BYTES), first = TXHO_RING_BYTES - off;
    if (first > n) first = n;
    memcpy(dst, g_r->buf + off, first);
    if (n > first) memcpy((unsigned char*)dst + first, g_r->buf, n - first);
}
static unsigned long rec_bytes(unsigned long len){ return 8 + ((len + 7) & ~7UL); }

int txho_push(const unsigned char* tx, unsigned long len, int src_slot){
    txho_ring_t* r = g_r;
    if (!r) return -1;
    if (!tx || len == 0 || len > TXHO_MAX_TX){ __sync_fetch_and_add(&r->dropped_big, 1ULL); return 0; }
    unsigned long need = rec_bytes(len);
    int lr = pthread_mutex_lock(&r->mu);
    if (lr == EOWNERDEAD) pthread_mutex_consistent(&r->mu);   /* its record was never published */
    else if (lr != 0) return 0;
    __sync_synchronize();
    unsigned long long head = r->head, tail = r->tail;
    if (head - tail + need > TXHO_RING_BYTES){
        pthread_mutex_unlock(&r->mu);
        __sync_fetch_and_add(&r->dropped_full, 1ULL);
        return 0;
    }
    unsigned int hdr[2] = { (unsigned int)len, (unsigned int)src_slot };
    ring_put(head, hdr, 8);
    ring_put(head + 8, tx, len);
    __sync_synchronize();                    /* the bytes before the index that publishes them */
    r->head = head + need;
    pthread_mutex_unlock(&r->mu);
    __sync_fetch_and_add(&r->pushed, 1ULL);
    return 1;
}

long txho_drain(txho_fn fn, void* ctx, long max){
    txho_ring_t* r = g_r;
    if (!r || !fn) return 0;
    static unsigned char tx[TXHO_MAX_TX];    /* the worker is single-threaded */
    long n = 0;
    while (n < max){
        unsigned long long head = r->head, tail = r->tail;
        __sync_synchronize();
        if (tail == head) break;
        unsigned int hdr[2];
        ring_get(tail, hdr, 8);
        unsigned long len = hdr[0];
        if (len == 0 || len > TXHO_MAX_TX || rec_bytes(len) > head - tail){
            /* cannot happen with the producer above; if it ever does, the
             * ring's framing is lost -- skip everything queued, loudly */
            fprintf(stderr, "[txhandoff] corrupt record (len %lu, %llu bytes queued): discarding the queue\n",
                    len, head - tail);
            r->tail = head;
            break;
        }
        ring_get(tail + 8, tx, len);
        __sync_synchronize();
        r->tail = tail + rec_bytes(len);     /* the slot is free before the (slow) validation */
        __sync_fetch_and_add(&r->popped, 1ULL);
        fn(tx, len, (int)hdr[1], ctx);
        n++;
    }
    return n;
}

void txho_stats(unsigned long long* pushed, unsigned long long* popped,
                unsigned long long* dropped_full, unsigned long long* dropped_big){
    txho_ring_t* r = g_r;
    if (pushed) *pushed = r ? r->pushed : 0;
    if (popped) *popped = r ? r->popped : 0;
    if (dropped_full) *dropped_full = r ? r->dropped_full : 0;
    if (dropped_big) *dropped_big = r ? r->dropped_big : 0;
}

/* test seam: take the producers' lock and scribble an unpublished record at
 * `head`, then return STILL HOLDING the lock -- the caller _exit()s, exactly
 * as a serve child SIGKILLed mid-copy would leave things */
int txho_test_lock_and_die(void){
    if (!g_r) return 0;
    pthread_mutex_lock(&g_r->mu);
    unsigned int junk[2] = { 0x7fffffffu, 0xdeadu };
    ring_put(g_r->head, junk, 8);
    return 1;
}
