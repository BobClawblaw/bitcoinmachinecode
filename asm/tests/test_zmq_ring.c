/* tests/test_zmq_ring.c -- the cross-process notification ring
 * (daemon/zmq_notify.c) under the conditions that actually break it.
 *
 * The ring's job is to carry transactions accepted in the inbound serve
 * CHILDREN across to the download worker, which owns the publisher. Its risky
 * property is therefore not "does a message get through" but the MPSC
 * discipline: many producers claiming slots concurrently, one consumer, and a
 * ring that can be lapped. Those are the cases here.
 *
 * Real forked producers are used, not a simulation of them -- the ring lives
 * in a MAP_SHARED region precisely so that separate processes can write it,
 * and a single-process test would exercise none of that.
 *
 * The publisher is bound to a loopback port with no subscribers, which is
 * enough for zmqpub_active() to be true so the drain runs; what the drain
 * puts ON the wire is covered by tests/zmq_interop.py against real libzmq.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include "../rpc_node.h"

extern void zmqn_set_status(node_status_t* st);
extern void zmqn_tx_accepted(const unsigned char txid[32], const unsigned char* tx,
                             unsigned long txlen);
extern int  zmqn_drain(void);
extern int  zmqpub_add(const char* topic, const char* addr);
extern int  zmqpub_active(void);

static int failures = 0;
static void ck(int cond, const char* what, long got, long want){
    if (cond){ printf("  ok   %s\n", what); return; }
    printf("  FAIL %s (got %ld, want %ld)\n", what, got, want);
    failures++;
}

static node_status_t* g_st;

static void mktx(unsigned char* tx, unsigned long len, unsigned char tag){
    for (unsigned long i = 0; i < len; i++) tx[i] = (unsigned char)(tag + i);
}

int main(void){
    printf("test_zmq_ring: cross-process ZMQ notification ring\n");

    g_st = mmap(NULL, sizeof(node_status_t), PROT_READ|PROT_WRITE,
                MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (g_st == MAP_FAILED){ printf("  FAIL mmap\n"); return 1; }
    memset(g_st, 0, sizeof *g_st);
    zmqn_set_status(g_st);

    /* Bind somewhere unlikely to collide; the port is never connected to. */
    int bound = 0;
    for (int p = 28540; p < 28560 && !bound; p++){
        char a[64]; snprintf(a, sizeof a, "tcp://127.0.0.1:%d", p);
        bound = zmqpub_add("hashtx", a) && zmqpub_add("rawtx", a);
    }
    ck(bound && zmqpub_active(), "publisher bound (drain is live)", bound, 1);
    if (!bound){ printf("test_zmq_ring: 1 failure\n"); return 1; }

    unsigned char txid[32], tx[256];

    /* 1. ordinary staging and draining */
    for (int i = 0; i < 5; i++){
        memset(txid, i + 1, 32); mktx(tx, sizeof tx, (unsigned char)i);
        zmqn_tx_accepted(txid, tx, sizeof tx);
    }
    ck(zmqn_drain() == 5, "drain publishes the 5 staged transactions", 0, 5);
    ck(zmqn_drain() == 0, "a second drain publishes nothing (cursor advanced)", 0, 0);

    /* 2. a transaction larger than a slot is REFUSED, not truncated. A
     *    truncated raw tx would be published as though it were genuine and
     *    would not deserialize for the subscriber. */
    unsigned long long before = g_st->zmq_seq;
    static unsigned char huge[RPC_ZMQ_TXMAX + 16];
    memset(txid, 0xAA, 32);
    zmqn_tx_accepted(txid, huge, sizeof huge);
    ck(g_st->zmq_seq == before, "oversized tx claims no slot (not truncated)",
       (long)(g_st->zmq_seq - before), 0);

    /* 3. OVERRUN. Stage more than the ring holds without draining: the oldest
     *    are gone, and the consumer must notice rather than replay whatever
     *    bytes happen to sit in the lapped slots. */
    int over = RPC_ZMQ_RING + 3;
    for (int i = 0; i < over; i++){
        memset(txid, (unsigned char)i, 32); mktx(tx, sizeof tx, (unsigned char)i);
        zmqn_tx_accepted(txid, tx, sizeof tx);
    }
    int drained = zmqn_drain();
    ck(drained == RPC_ZMQ_RING, "overrun drains exactly a ring's worth", drained, RPC_ZMQ_RING);
    ck(g_st->zmq_lost == 3, "the 3 lapped transactions are COUNTED, not silent",
       (long)g_st->zmq_lost, 3);

    /* 4. a slot claimed but not yet filled must stop the drain there --
     *    publishing it would emit a half-written transaction. */
    unsigned long long seq = __sync_fetch_and_add(&g_st->zmq_seq, 1ULL);
    unsigned k = (unsigned)(seq % RPC_ZMQ_RING);
    g_st->zmq_ring[k].ready = 0;                       /* producer mid-write */
    ck(zmqn_drain() == 0, "drain stops at a slot still being written", 0, 0);
    /* now let the producer finish */
    memset((void*)g_st->zmq_ring[k].txid, 0x5A, 32);
    g_st->zmq_ring[k].len = 64;
    __sync_synchronize();
    g_st->zmq_ring[k].ready = seq + 1;
    ck(zmqn_drain() == 1, "the completed slot is published on the next drain", 0, 1);

    /* 5. REAL CONCURRENT PRODUCERS. Four forked processes staging at once,
     *    which is the shape the serve children actually produce. Every
     *    claimed slot must be distinct: a lost atomic here would show up as
     *    two producers overwriting one slot and a permanently stuck drain. */
    g_st->zmq_seq = 0; g_st->zmq_lost = 0;
    memset((void*)g_st->zmq_ring, 0, sizeof g_st->zmq_ring);
    zmqn_set_status(g_st);                              /* reset consumer cursor */

    const int NPROC = 4, PER = 3;                       /* 12 <= RPC_ZMQ_RING */
    for (int p = 0; p < NPROC; p++){
        pid_t pid = fork();
        if (pid == 0){
            for (int i = 0; i < PER; i++){
                unsigned char t[32], b[128];
                memset(t, (unsigned char)(p * 16 + i), 32);
                mktx(b, sizeof b, (unsigned char)p);
                zmqn_tx_accepted(t, b, sizeof b);
            }
            _exit(0);
        }
    }
    for (int p = 0; p < NPROC; p++) wait(NULL);

    ck(g_st->zmq_seq == (unsigned long long)(NPROC * PER),
       "4 forked producers claimed 12 distinct slots (no lost atomic)",
       (long)g_st->zmq_seq, NPROC * PER);
    int got = zmqn_drain();
    ck(got == NPROC * PER, "all 12 cross-process transactions drain", got, NPROC * PER);
    ck(g_st->zmq_lost == 0, "no loss reported when the ring was not lapped",
       (long)g_st->zmq_lost, 0);

    if (failures){ printf("test_zmq_ring: %d failure(s)\n", failures); return 1; }
    printf("test_zmq_ring: all checks passed\n");
    return 0;
}
