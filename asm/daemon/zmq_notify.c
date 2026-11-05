/* daemon/zmq_notify.c -- the bridge between "a transaction was accepted"
 * (which happens in several processes) and "publish it" (which can happen in
 * only one).
 *
 * See the zmq_ring comment in rpc_node.h for why the ring exists at all. In
 * short: transactions can be accepted outside the download worker, but the
 * ZMQ publisher owns socket state and lives only in the worker.
 *
 * This file is deliberately tiny and holds no ZMTP knowledge; zmq_pub.c holds
 * no knowledge of the node. The producer half is safe to call from any
 * process at any time, including before ZMQ is configured (it is then a
 * no-op), because it is wired into the mempool accept path -- which must not
 * grow a dependency on whether the operator turned notifications on.
 *
 * PUBLISH AT ACCEPT TIME IN THE PUBLISHER'S OWN PROCESS (2026-09-19). The
 * worker is where nearly every accept happens -- its outbound legs' relay,
 * the inbound handoff (tx_handoff.c), sendrawtransaction, and the boot-time
 * mempool.dat reload, which it services up to 2,048 per rotation -- but it
 * drained the ring once per rotation, so a 64-slot ring lost 61,836 of a
 * 72,952-tx reload (deploy-20260919a) and a few dozen an hour in steady
 * state. Core has no such window: TransactionAddedToMempool is queued on
 * the validation interface's unbounded queue, and libzmq's per-subscriber
 * SNDHWM is the one place a message can drop. The equivalent here is
 * zmqpub_notify, which never touches a socket (it frames the message and
 * appends it to each subscriber's hwm-bounded queue; zmq_pub.c's thread does
 * the writing), so the worker calls the drain right after staging and a
 * slow subscriber costs the accept path nothing but that append. Core
 * publishes reloaded transactions too (init.cpp registers the ZMQ interface
 * before LoadMempool, which goes through AcceptToMemoryPool and so signals),
 * so the reload's messages are owed, not noise. */
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include "log_ts.h"   /* timestamped fprintf(stderr), like every other daemon line */
#include "../rpc_node.h"
#include "mempool_seq.h"

extern void zmqpub_notify(const char* topic, const void* body, unsigned long blen);
extern int  zmqpub_active(void);
extern int  zmqpub_topic_active(const char* topic);
extern void zmqpub_skip(const char* topic, unsigned long n);

static node_status_t* g_zn_status = 0;
static unsigned long long g_zn_cursor = 0;   /* consumer position (worker only) */
/* The process that owns the publisher (zmqn_set_publisher). A process forked
 * from it inherits the value but not the pid, so it stages like any other. */
static pid_t g_zn_owner = 0;
/* One drainer at a time within the owner (the cursor and the topic sequences
 * are this process's). trylock: an accept never waits for another thread's
 * drain -- that drain re-reads the head and takes what was staged meanwhile. */
static pthread_mutex_t g_zn_mu = PTHREAD_MUTEX_INITIALIZER;

/* Called once, before the worker fork, so every process inherits the pointer. */
void zmqn_set_status(node_status_t* st){ g_zn_status = st; g_zn_cursor = 0; }

/* Called by the process that bound the publisher, after binding: from then
 * on its own accepts are published as they are staged. */
void zmqn_set_publisher(void){ g_zn_owner = getpid(); }

int zmqn_drain(void);

/* PRODUCER -- any process, called from the mempool accept path.
 *
 * Note this does NOT check zmqpub_active(): in another process that flag is
 * meaningless (the publisher lives in the worker), so it must stage
 * unconditionally. The cost when nobody is publishing is two atomic
 * increments and a copy into memory that is already mapped, which is not
 * worth a cross-process flag to avoid. */
void zmqn_tx_accepted(const unsigned char txid[32], const unsigned char* tx,
                      unsigned long txlen){
    node_status_t* st = g_zn_status;
    if (!st || !tx || txlen == 0 || txlen > RPC_ZMQ_TXMAX) return;
    unsigned long long seq = __atomic_fetch_add(&st->zmq_seq, 1ULL, __ATOMIC_ACQ_REL);
    unsigned long long off = __atomic_fetch_add(&st->zmq_bytes, (unsigned long long)txlen, __ATOMIC_ACQ_REL);
    unsigned k = (unsigned)(seq % RPC_ZMQ_RING);
    /* a consumer lapped onto this entry must not take it while it is refilled */
    __atomic_store_n(&st->zmq_ring[k].ready, 0ULL, __ATOMIC_RELEASE);
    __atomic_thread_fence(__ATOMIC_RELEASE);   /* ARM64 (2026-09-25): a release STORE orders what came before it, not the
                                                  payload stores after -- without this fence they can land before ready=0 */
    memcpy((void*)st->zmq_ring[k].txid, txid, 32);
    st->zmq_ring[k].off = off;
    st->zmq_ring[k].len = txlen;
    unsigned long at = (unsigned long)(off % RPC_ZMQ_ARENA);
    unsigned long first = txlen <= RPC_ZMQ_ARENA - at ? txlen : RPC_ZMQ_ARENA - at;
    memcpy(st->zmq_arena + at, tx, first);
    if (first < txlen) memcpy(st->zmq_arena, tx + first, txlen - first);
    __atomic_store_n(&st->zmq_ring[k].ready, seq + 1, __ATOMIC_RELEASE);   /* fill BEFORE announcing */
    if (g_zn_owner && g_zn_owner == getpid()) zmqn_drain();
}

/* ---- the `sequence` topic (Core -zmqpubsequence) ---------------------------
 * The events are staged by the mempool itself, in daemon/mempool_cfg.c's
 * shared ring (mempool_seq.h has the why), under the pool lock and in the
 * order the pool changed. This is the consumer: download worker only, one
 * cursor, publishing Core's body -- the hash in DISPLAY order (Core's
 * SendSequenceMsg reverses it like every other hash topic), the label, and
 * for 'A'/'R' the 8-byte little-endian mempool sequence.
 *
 * mpseq_area is WEAK: several test binaries link this file without the
 * mempool, and then there is simply nothing to drain. */
extern mpseq_area_t* mpseq_area(void) __attribute__((weak));
static unsigned long long g_zs_cursor = 0;
int zmqn_drain_sequence(void){
    mpseq_area_t* a = mpseq_area ? mpseq_area() : 0;
    if (!a) return 0;
    unsigned long long head = __atomic_load_n(&a->head, __ATOMIC_ACQUIRE);
    if (head == g_zs_cursor) return 0;
    /* nobody publishes the topic: keep up, build nothing */
    if (!zmqpub_active() || !zmqpub_topic_active("sequence")){ g_zs_cursor = head; return 0; }
    if (head - g_zs_cursor > MPSEQ_RING){
        unsigned long long lost = head - g_zs_cursor - MPSEQ_RING;
        a->lost += lost;
        zmqpub_skip("sequence", (unsigned long)lost);   /* the gap a subscriber can see */
        { static long last; long now = (long)time(NULL);
          if (now - last >= 60){
              fprintf(stderr, "[zmq] sequence ring overrun: %llu event(s) not published (total %llu); "
                              "subscribers see the gap in the topic sequence\n", lost, a->lost);
              last = now; } }
        g_zs_cursor = head - MPSEQ_RING;
    }
    int n = 0;
    while (g_zs_cursor < head){
        const mpseq_ev* e = &a->ev[g_zs_cursor % MPSEQ_RING];
        if (__atomic_load_n(&e->ready, __ATOMIC_ACQUIRE) != g_zs_cursor + 1) break;  /* mid-write: next time */
        unsigned char body[41];
        for (int b = 0; b < 32; b++) body[b] = e->hash[31 - b];
        body[32] = e->label;
        unsigned long blen = 33;
        if (e->label == 'A' || e->label == 'R'){
            for (int b = 0; b < 8; b++) body[33 + b] = (unsigned char)(e->mseq >> (8 * b));
            blen = 41;
        }
        /* the slot may have been lapped while it was read: publish only what
         * was still this slot's event after the copy */
        __atomic_thread_fence(__ATOMIC_ACQUIRE);   /* ARM64: the copy's loads complete before the re-check (an acquire LOAD does not hold back earlier loads) */
        if (__atomic_load_n(&e->ready, __ATOMIC_ACQUIRE) != g_zs_cursor + 1) continue;
        zmqpub_notify("sequence", body, blen);
        g_zs_cursor++; n++;
    }
    return n;
}

/* A loss upstream of the publisher, made visible: counted, logged (1/min --
 * during a mempool reload the old 64-slot ring fired this several times a
 * second), and -- the part that reaches a subscriber -- the hashtx/rawtx
 * topic sequences advance by it, the same gap a high-water-mark drop leaves.
 * Before 2026-09-19 the count reached only the log: the topic sequence ran
 * on contiguously over 61,836 missing transactions. */
static void zmqn_note_lost(node_status_t* st, unsigned long long lost, const char* why){
    st->zmq_lost += lost;
    zmqpub_skip("hashtx", (unsigned long)lost);
    zmqpub_skip("rawtx",  (unsigned long)lost);
    static long ovr_last; static int ovr_muted;
    long now = (long)time(NULL);
    if (now - ovr_last >= 60){
        fprintf(stderr, "[zmq] notification ring overrun (%s): %llu transaction(s) not published "
                        "(total %llu); subscribers see the gap in the hashtx/rawtx sequence%s\n",
                why, lost, st->zmq_lost,
                ovr_muted ? " (repeats muted; the total is cumulative)" : "");
        ovr_last = now; ovr_muted = 1;
    }
}

/* The drain proper; caller holds g_zn_mu. */
static unsigned char g_zn_buf[RPC_ZMQ_TXMAX];
static int zmqn_drain_locked(void){
    node_status_t* st = g_zn_status;
    zmqn_drain_sequence();
    if (!st || !zmqpub_active()) return 0;
    unsigned long long head = __atomic_load_n(&st->zmq_seq, __ATOMIC_ACQUIRE);
    if (head == g_zn_cursor) return 0;

    /* Producers lapped the index: the oldest entries have been reused. Skip
     * to the oldest one still intact and account for the rest. */
    if (head - g_zn_cursor > RPC_ZMQ_RING){
        zmqn_note_lost(st, head - g_zn_cursor - RPC_ZMQ_RING, "index lapped");
        g_zn_cursor = head - RPC_ZMQ_RING;
    }

    int n = 0;
    while (g_zn_cursor < head){
        unsigned k = (unsigned)(g_zn_cursor % RPC_ZMQ_RING);
        if (__atomic_load_n(&st->zmq_ring[k].ready, __ATOMIC_ACQUIRE) != g_zn_cursor + 1)
            break;                                             /* producer mid-write: next time */
        unsigned long long off = st->zmq_ring[k].off;
        unsigned long len = st->zmq_ring[k].len;
        unsigned char rev[32];
        /* Core REVERSES the hash on the hashtx/hashblock topics -- its
         * notifier does data[31-i] = hash.begin()[i], so what crosses the
         * wire is DISPLAY order, the same string getrawtransaction prints.
         * This file's first version assumed wire order, which is the
         * plausible-but-wrong choice: hashes that look right and match
         * nothing a subscriber compares them to. */
        for (int b = 0; b < 32; b++) rev[b] = st->zmq_ring[k].txid[31 - b];
        if (len == 0 || len > RPC_ZMQ_TXMAX){ g_zn_cursor++; continue; }   /* never staged so */
        unsigned long at = (unsigned long)(off % RPC_ZMQ_ARENA);
        unsigned long first = len <= RPC_ZMQ_ARENA - at ? len : RPC_ZMQ_ARENA - at;
        memcpy(g_zn_buf, st->zmq_arena + at, first);
        if (first < len) memcpy(g_zn_buf + first, st->zmq_arena, len - first);
        /* Publish only what was still this entry after the copy: the index
         * entry not reclaimed, and no producer holding arena bytes a lap
         * past this transaction's start (which is where its bytes are
         * rewritten). A torn copy is a loss, never a message. */
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        if (__atomic_load_n(&st->zmq_ring[k].ready, __ATOMIC_ACQUIRE) != g_zn_cursor + 1 ||
            __atomic_load_n(&st->zmq_bytes, __ATOMIC_ACQUIRE) > off + RPC_ZMQ_ARENA){
            zmqn_note_lost(st, 1, "arena lapped");
            g_zn_cursor++;
            continue;
        }
        zmqpub_notify("hashtx", rev, 32);
        zmqpub_notify("rawtx",  g_zn_buf, len);
        n++;
        g_zn_cursor++;
    }
    return n;
}

/* CONSUMER -- the publisher's process only: the worker's main loop once per
 * rotation and per connected block, and zmqn_tx_accepted right after each of
 * the worker's own accepts. Drains everything staged since the last call and
 * publishes hashtx/rawtx for each (and the `sequence` topic's events).
 * Returns the number of transactions published. */
int zmqn_drain(void){
    int n = 0;
    /* Twice at most: a producer that staged while another thread held the
     * lock found it busy and left its entry to the holder, who may already
     * have read the head. The second pass takes it; a third would only spin
     * on an entry another process is still writing. */
    for (int pass = 0; pass < 2; pass++){
        if (pthread_mutex_trylock(&g_zn_mu) != 0) return n;
        n += zmqn_drain_locked();
        unsigned long long cur = g_zn_cursor;
        pthread_mutex_unlock(&g_zn_mu);
        node_status_t* st = g_zn_status;
        if (!st || __atomic_load_n(&st->zmq_seq, __ATOMIC_ACQUIRE) == cur) break;
    }
    return n;
}
