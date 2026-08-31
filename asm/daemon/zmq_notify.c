/* daemon/zmq_notify.c -- the bridge between "a transaction was accepted"
 * (which happens in several processes) and "publish it" (which can happen in
 * only one).
 *
 * See the zmq_ring comment in rpc_node.h for why the ring exists at all. In
 * short: inbound transactions are accepted by the forked serve CHILDREN, but
 * the ZMQ publisher owns socket state and lives only in the download worker.
 *
 * This file is deliberately tiny and holds no ZMTP knowledge; zmq_pub.c holds
 * no knowledge of the node. The producer half is safe to call from any
 * process at any time, including before ZMQ is configured (it is then a
 * no-op), because it is wired into the mempool accept path -- which must not
 * grow a dependency on whether the operator turned notifications on.
 */
#include <string.h>
#include <stdio.h>
#include "log_ts.h"   /* timestamped fprintf(stderr), like every other daemon line */
#include "../rpc_node.h"

extern void zmqpub_notify(const char* topic, const void* body, unsigned long blen);
extern int  zmqpub_active(void);

static node_status_t* g_zn_status = 0;
static unsigned long long g_zn_cursor = 0;   /* consumer position (worker only) */

/* Called once, before the worker fork, so every process inherits the pointer. */
void zmqn_set_status(node_status_t* st){ g_zn_status = st; g_zn_cursor = 0; }

/* PRODUCER -- any process, called from the mempool accept path.
 *
 * Note this does NOT check zmqpub_active(): in a serve child that flag is
 * meaningless (the publisher lives in the worker), so a child must stage
 * unconditionally. The cost when nobody is publishing is one atomic increment
 * and a memcpy into memory that is already mapped, which is not worth a
 * cross-process flag to avoid. */
void zmqn_tx_accepted(const unsigned char txid[32], const unsigned char* tx,
                      unsigned long txlen){
    node_status_t* st = g_zn_status;
    if (!st || !tx || txlen == 0 || txlen > RPC_ZMQ_TXMAX) return;
    unsigned long long seq = __sync_fetch_and_add(&st->zmq_seq, 1ULL);
    unsigned k = (unsigned)(seq % RPC_ZMQ_RING);
    memcpy((void*)st->zmq_ring[k].txid, txid, 32);
    memcpy((void*)st->zmq_ring[k].tx, tx, txlen);
    st->zmq_ring[k].len = txlen;
    __sync_synchronize();                 /* fill BEFORE announcing */
    st->zmq_ring[k].ready = seq + 1;
}

/* CONSUMER -- download worker only. Drains everything staged since the last
 * call and publishes hashtx/rawtx for each. Returns the number published. */
int zmqn_drain(void){
    node_status_t* st = g_zn_status;
    if (!st || !zmqpub_active()) return 0;
    unsigned long long head = st->zmq_seq;
    if (head == g_zn_cursor) return 0;

    /* Producers lapped us: the oldest slots have already been overwritten.
     * Skip to the oldest one still intact and COUNT the loss -- a subscriber
     * that sees a per-topic sequence jump deserves a matching log line on
     * this side to explain it. */
    if (head - g_zn_cursor > RPC_ZMQ_RING){
        unsigned long long lost = head - g_zn_cursor - RPC_ZMQ_RING;
        st->zmq_lost += lost;
        /* 1/min: during a mempool reload this fired several times a second,
         * and the cumulative total makes per-event lines redundant. */
        { static long ovr_last; static int ovr_muted;
          long now = (long)time(NULL);
          if (now - ovr_last >= 60){
              fprintf(stderr, "[zmq] notification ring overrun: %llu transaction(s) not published "
                              "(total %llu)%s\n", lost, st->zmq_lost,
                              ovr_muted ? " (repeats muted; the total is cumulative)" : "");
              ovr_last = now; ovr_muted = 1;
          } }
        g_zn_cursor = head - RPC_ZMQ_RING;
    }

    int n = 0;
    while (g_zn_cursor < head){
        unsigned k = (unsigned)(g_zn_cursor % RPC_ZMQ_RING);
        if (st->zmq_ring[k].ready != g_zn_cursor + 1) break;   /* producer mid-write: next time */
        __sync_synchronize();                                  /* read AFTER the ready check */
        unsigned long len = st->zmq_ring[k].len;
        if (len > 0 && len <= RPC_ZMQ_TXMAX){
            /* Core REVERSES the hash on the hashtx/hashblock topics -- its
             * notifier does data[31-i] = hash.begin()[i], so what crosses the
             * wire is DISPLAY order, the same string getrawtransaction
             * prints. This file's first version assumed wire order, which is
             * the plausible-but-wrong choice: hashes that look right and
             * match nothing a subscriber compares them to. */
            unsigned char rev[32];
            for (int b = 0; b < 32; b++) rev[b] = st->zmq_ring[k].txid[31 - b];
            zmqpub_notify("hashtx", rev, 32);
            zmqpub_notify("rawtx",  (const void*)st->zmq_ring[k].tx, len);
            n++;
        }
        g_zn_cursor++;
    }
    return n;
}
