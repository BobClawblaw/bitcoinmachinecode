/* tests/test_zmq_ring.c -- the cross-process notification ring
 * (daemon/zmq_notify.c) under the conditions that actually break it.
 *
 * The ring's job is to carry accepted transactions to the one process that
 * owns the publisher (the download worker). Its risky properties are the MPSC
 * discipline -- many producers claiming entries concurrently, one consumer,
 * a ring that can be lapped -- and, since 2026-09-19, THROUGHPUT: production
 * lost 61,836 of the 72,952 transactions of a mempool.dat reload to the
 * 64-slot ring (deploy-20260919a, 11:52-11:56Z), and a few dozen an hour in
 * steady state, because the worker accepts up to 2,048 submissions per
 * rotation and drained once. Every lost one was a hashtx/rawtx a subscriber
 * never got, with NO gap in the topic sequence to tell it so. Core publishes
 * the reload too (LoadMempool -> AcceptToMemoryPool -> TransactionAdded-
 * ToMempool, with the ZMQ interface registered first), so those messages
 * were owed; validation/zmq_reload_burst_core_diff.py measures both nodes.
 *
 * Real forked producers are used, not a simulation of them -- the ring lives
 * in a MAP_SHARED region precisely so that separate processes can write it.
 *
 * The PUBLISHER is a recording fake (this file defines zmqpub_notify and
 * friends; daemon/zmq_pub.c is not linked), so every message the drain emits
 * is checked byte for byte -- the hash against the transaction it names, the
 * raw bytes against the pattern they were staged with (arena wrap included)
 * -- and the per-topic sequence is modelled exactly as zmq_pub.c keeps it:
 * +1 per notify, +n per zmqpub_skip. What the real publisher puts ON the wire
 * is covered by tests/test_zmq_queue.c and tests/zmq_interop.py.
 *
 *   1. ordinary staging and draining, content intact
 *   2. an oversized transaction is refused, not truncated
 *   3. THE RELOAD SHAPE: the publisher's own process accepts 80,000
 *      transactions with no drain in between -- every one is published, in
 *      order, by the time the last accept returns
 *   4. a cross-process burst while the consumer is stalled (a block connect):
 *      4 forked producers x 10,000, then one drain -- none lost
 *   5. the owner accepting while 4 other processes stage concurrently
 *   6. in extremis, the INDEX lapped: counted, and the hashtx/rawtx topic
 *      sequences jump by the loss (the gap a subscriber sees)
 *   7. in extremis, the ARENA lapped by large transactions: the overwritten
 *      ones are counted and gapped, never published torn
 *   8. an entry claimed but not yet filled stops the drain there
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include "../rpc_node.h"

extern void zmqn_set_status(node_status_t* st);
/* weak: a build without it (the fix reverted) must FAIL the checks, not
 * fail to link */
extern void zmqn_set_publisher(void) __attribute__((weak));
extern void zmqn_tx_accepted(const unsigned char txid[32], const unsigned char* tx,
                             unsigned long txlen);
extern int  zmqn_drain(void);

static int failures = 0;
static void ck(int cond, const char* what, long got, long want){
    if (cond){ printf("  ok   %s\n", what); return; }
    printf("  FAIL %s (got %ld, want %ld)\n", what, got, want);
    failures++;
}

/* ---- the recording publisher -------------------------------------------- */
static unsigned long long f_seq_hashtx, f_seq_rawtx;   /* next topic sequence */
static long f_hashtx, f_rawtx, f_bad, f_order_bad;
static unsigned char f_last_hash[32];
static long f_last_id = -1, f_last_id_ok;
static long f_max_id = -1;          /* for the in-order check within a phase */

/* A transaction's identity lives in its txid: bytes 0..3 = id (LE), byte 4 =
 * a producer tag; the raw bytes are a pattern of (id, length). The fake
 * checks rawtx against the hashtx that preceded it. */
static void mk(unsigned char txid[32], unsigned char* tx, unsigned long len, long id, int tag){
    memset(txid, 0, 32);
    for (int i = 0; i < 4; i++) txid[i] = (unsigned char)(id >> (8 * i));
    txid[4] = (unsigned char)tag;
    txid[31] = 0xC3;
    for (unsigned long i = 0; i < len; i++) tx[i] = (unsigned char)(id * 131 + i * 7 + tag);
}
static long id_of_disp(const unsigned char* disp){      /* display order: reversed */
    long id = 0;
    for (int i = 0; i < 4; i++) id |= (long)disp[31 - i] << (8 * i);
    return id;
}
static int tag_of_disp(const unsigned char* disp){ return disp[27]; }

int  zmqpub_active(void){ return 1; }
int  zmqpub_topic_active(const char* t){ (void)t; return 1; }
void zmqpub_skip(const char* topic, unsigned long n){
    if (!strcmp(topic, "hashtx")) f_seq_hashtx += n;
    else if (!strcmp(topic, "rawtx")) f_seq_rawtx += n;
}
void zmqpub_notify(const char* topic, const void* body, unsigned long blen){
    const unsigned char* b = body;
    if (!strcmp(topic, "hashtx")){
        f_seq_hashtx++; f_hashtx++;
        if (blen != 32 || b[0] != 0xC3){ f_bad++; f_last_id_ok = 0; return; }
        memcpy(f_last_hash, b, 32);
        f_last_id = id_of_disp(b); f_last_id_ok = 1;
        if (tag_of_disp(b) == 0){                         /* the owner's own: strictly in order */
            if (f_last_id <= f_max_id) f_order_bad++;
            f_max_id = f_last_id;
        }
    } else if (!strcmp(topic, "rawtx")){
        f_seq_rawtx++; f_rawtx++;
        if (!f_last_id_ok){ f_bad++; return; }
        long id = f_last_id; int tag = tag_of_disp(f_last_hash);
        for (unsigned long i = 0; i < blen; i++)
            if (b[i] != (unsigned char)(id * 131 + i * 7 + tag)){ f_bad++; break; }
        f_last_id_ok = 0;
    }
}
static void f_reset(void){ f_hashtx = f_rawtx = f_bad = f_order_bad = 0; f_max_id = -1; }

static node_status_t* g_st;

/* stage `n` transactions of `len` bytes from a forked child (a process that
 * is NOT the publisher's), ids base.., tag `tag` */
static pid_t stage_in_child(long base, long n, unsigned long len, int tag){
    pid_t pid = fork();
    if (pid == 0){
        static unsigned char tx[RPC_ZMQ_TXMAX];
        unsigned char t[32];
        for (long i = 0; i < n; i++){ mk(t, tx, len, base + i, tag); zmqn_tx_accepted(t, tx, len); }
        _exit(0);
    }
    return pid;
}

int main(void){
    printf("test_zmq_ring: cross-process ZMQ notification ring\n");

    g_st = mmap(NULL, sizeof(node_status_t), PROT_READ|PROT_WRITE,
                MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (g_st == MAP_FAILED){ printf("  FAIL mmap\n"); return 1; }
    zmqn_set_status(g_st);

    static unsigned char tx[RPC_ZMQ_TXMAX + 16];
    unsigned char txid[32];

    /* 1. ordinary staging and draining (not yet the publisher's process: the
     *    drain is what publishes) */
    for (int i = 0; i < 5; i++){ mk(txid, tx, 256, 1000 + i, 1); zmqn_tx_accepted(txid, tx, 256); }
    ck(zmqn_drain() == 5, "drain publishes the 5 staged transactions", 0, 5);
    ck(f_hashtx == 5 && f_rawtx == 5 && f_bad == 0, "5 hashtx + 5 rawtx, hash and bytes intact", f_bad, 0);
    ck(zmqn_drain() == 0, "a second drain publishes nothing (cursor advanced)", 0, 0);

    /* 2. a transaction larger than any a slot may carry is REFUSED, not
     *    truncated: a truncated raw tx would not deserialize */
    unsigned long long before = g_st->zmq_seq;
    memset(txid, 0xAA, 32);
    zmqn_tx_accepted(txid, tx, RPC_ZMQ_TXMAX + 16);
    ck(g_st->zmq_seq == before, "oversized tx claims no entry (not truncated)",
       (long)(g_st->zmq_seq - before), 0);

    /* 3. THE RELOAD SHAPE. The worker services up to 2,048 submissions per
     *    rotation (and a reload is tens of thousands) with no drain in
     *    between; production lost 61,836 of 72,952 this way. From here this
     *    process is the publisher's. */
    if (zmqn_set_publisher) zmqn_set_publisher();
    f_reset();
    unsigned long long sq0 = f_seq_hashtx, lost0 = g_st->zmq_lost;
    const long RELOAD = 80000;
    for (long i = 0; i < RELOAD; i++){
        unsigned long len = 150 + (unsigned long)(i % 700);   /* mainnet-ish sizes */
        mk(txid, tx, len, i, 0); zmqn_tx_accepted(txid, tx, len);
    }
    ck(f_hashtx == RELOAD, "reload: all 80,000 published by the time the last accept returns",
       f_hashtx, RELOAD);
    ck(f_rawtx == RELOAD && f_bad == 0, "reload: every rawtx intact and matching its hashtx", f_bad, 0);
    ck(f_order_bad == 0, "reload: published in accept order", f_order_bad, 0);
    ck(zmqn_drain() == 0, "reload: the main loop's next drain finds nothing left", 0, 0);
    ck(g_st->zmq_lost == lost0, "reload: nothing lost", (long)(g_st->zmq_lost - lost0), 0);
    ck(f_seq_hashtx - sq0 == (unsigned long long)RELOAD, "reload: hashtx topic sequence advanced by exactly 80,000",
       (long)(f_seq_hashtx - sq0), RELOAD);

    /* 4. a cross-process burst while the consumer is stalled -- the worker
     *    inside a block connect while other processes keep accepting */
    f_reset(); lost0 = g_st->zmq_lost;
    const int NPROC = 4; const long PER = 10000;
    for (int p = 0; p < NPROC; p++) stage_in_child(p * PER, PER, 300, 10 + p);
    for (int p = 0; p < NPROC; p++) wait(NULL);
    ck(f_hashtx == 0, "stalled consumer: other processes' accepts wait in the ring (nothing published yet)", f_hashtx, 0);
    int got = zmqn_drain();
    ck(got == NPROC * PER, "stalled consumer: one drain publishes all 40,000 from 4 processes", got, NPROC * PER);
    ck(f_bad == 0, "stalled consumer: every message intact", f_bad, 0);
    ck(g_st->zmq_lost == lost0, "stalled consumer: nothing lost", (long)(g_st->zmq_lost - lost0), 0);

    /* 5. the owner accepting (and so draining) while 4 other processes stage
     *    concurrently: everything arrives, nothing is torn */
    f_reset(); lost0 = g_st->zmq_lost;
    pid_t kids[4];
    for (int p = 0; p < NPROC; p++) kids[p] = stage_in_child(500000 + p * 5000, 5000, 400, 20 + p);
    for (long i = 0; i < 20000; i++){ mk(txid, tx, 250, 200000 + i, 0); zmqn_tx_accepted(txid, tx, 250); }
    for (int p = 0; p < NPROC; p++) waitpid(kids[p], NULL, 0);
    zmqn_drain();
    ck(f_hashtx == 40000, "concurrent: 20,000 own + 20,000 from 4 processes, all published", f_hashtx, 40000);
    ck(f_bad == 0 && f_order_bad == 0, "concurrent: intact, own accepts in order", f_bad + f_order_bad, 0);
    ck(g_st->zmq_lost == lost0, "concurrent: nothing lost", (long)(g_st->zmq_lost - lost0), 0);

    /* 6. IN EXTREMIS, the index lapped (65,536 entries) by a process that is
     *    not the publisher's: the oldest are gone, the drain must count them
     *    AND tell subscribers -- a jump in both tx topics' sequence */
    f_reset(); lost0 = g_st->zmq_lost;
    unsigned long long sh0 = f_seq_hashtx, sr0 = f_seq_rawtx;
    long over = (long)RPC_ZMQ_RING + 3;
    waitpid(stage_in_child(1000000, over, 100, 30), NULL, 0);
    int drained = zmqn_drain();
    ck(drained == (int)RPC_ZMQ_RING, "index lapped: drains exactly a ring's worth", drained, (long)RPC_ZMQ_RING);
    ck(g_st->zmq_lost - lost0 == 3, "index lapped: the 3 lost are COUNTED", (long)(g_st->zmq_lost - lost0), 3);
    ck(f_seq_hashtx - sh0 == (unsigned long long)over && f_seq_rawtx - sr0 == (unsigned long long)over,
       "index lapped: hashtx AND rawtx sequences advance by all staged (the subscriber sees a 3-message gap)",
       (long)(f_seq_hashtx - sh0), over);
    ck(f_bad == 0, "index lapped: what was published is intact", f_bad, 0);

#ifdef RPC_ZMQ_ARENA
    /* 7. IN EXTREMIS, the arena lapped: 100 transactions of 400,000 bytes are
     *    40 MB against a 32 MiB arena. The first ones' bytes are rewritten by
     *    the last ones; they must be counted and gapped, never published
     *    torn. */
    f_reset(); lost0 = g_st->zmq_lost; sh0 = f_seq_hashtx;
    unsigned long long b0 = g_st->zmq_bytes;
    const long BIG = 100; const unsigned long BLEN = 400000;
    waitpid(stage_in_child(2000000, BIG, BLEN, 40), NULL, 0);
    long want_lost = 0;
    for (long i = 0; i < BIG; i++) if (b0 + BIG * BLEN > b0 + i * BLEN + RPC_ZMQ_ARENA) want_lost++;
    drained = zmqn_drain();
    ck(want_lost > 0 && drained == BIG - want_lost, "arena lapped: publishes exactly the intact ones", drained, BIG - want_lost);
    ck((long)(g_st->zmq_lost - lost0) == want_lost, "arena lapped: the overwritten ones are counted",
       (long)(g_st->zmq_lost - lost0), want_lost);
    ck(f_seq_hashtx - sh0 == (unsigned long long)BIG, "arena lapped: the hashtx sequence shows the gap",
       (long)(f_seq_hashtx - sh0), BIG);
    ck(f_bad == 0, "arena lapped: nothing torn was published (the wrap copies are intact)", f_bad, 0);

    /* 8. an entry claimed but not yet filled must stop the drain there --
     *    publishing it would emit a half-written transaction */
    f_reset();
    unsigned long long seq = __sync_fetch_and_add(&g_st->zmq_seq, 1ULL);
    unsigned long long off = __sync_fetch_and_add(&g_st->zmq_bytes, 64ULL);
    unsigned k = (unsigned)(seq % RPC_ZMQ_RING);
    g_st->zmq_ring[k].ready = 0;                       /* producer mid-write */
    ck(zmqn_drain() == 0, "drain stops at an entry still being written", 0, 0);
    mk(txid, tx, 64, 777, 50);
    memcpy((void*)g_st->zmq_ring[k].txid, txid, 32);
    g_st->zmq_ring[k].off = off; g_st->zmq_ring[k].len = 64;
    for (int i = 0; i < 64; i++) g_st->zmq_arena[(off + i) % RPC_ZMQ_ARENA] = tx[i];
    __sync_synchronize();
    g_st->zmq_ring[k].ready = seq + 1;
    ck(zmqn_drain() == 1 && f_bad == 0, "the completed entry is published intact on the next drain", f_bad, 0);

#else
    ck(0, "the ring has no arena (a fixed-slot ring: the fix is not in this build)", 0, 1);
#endif

    if (failures){ printf("test_zmq_ring: %d failure(s)\n", failures); return 1; }
    printf("test_zmq_ring: all checks passed\n");
    return 0;
}
