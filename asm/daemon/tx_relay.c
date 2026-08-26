/* daemon/tx_relay.c -- receive-side transaction relay on the worker's
 * outbound legs.
 *
 * WHY: the daemon advertised relay=1 in its version message, so peers have
 * been announcing transactions to us on all eight full-relay legs the whole
 * time -- and node_sync_multi's drains read those invs off the socket and
 * threw them away unexamined. The production mempool had therefore never
 * held a single P2P transaction: getrawmempool answered from an empty pool,
 * estimatesmartfee's accepted-feerate EMA never fed, getblocktemplate built
 * empty templates. This module is the missing receive half: between sync
 * passes it drains a leg's buffered messages, requests announced
 * transactions, and feeds the replies through the same tx_accept_validate
 * (full signature + policy validation) the inbound serve path uses.
 *
 * MSG_WITNESS_TX, not MSG_TX: requesting type 1 hands back the WITNESS-
 * STRIPPED serialization -- the exact bug shape that silently stripped the
 * whole segwit-era block archive (incident #10) -- and a stripped segwit
 * transaction fails signature validation, so every segwit tx would be
 * fetched, rejected, and re-fetched forever. Peers announce with type 1
 * (we do not negotiate BIP339 wtxidrelay, so announcements are txid-based);
 * the REQUEST flags the witness bit, exactly as the block fetch asks for
 * MSG_WITNESS_BLOCK.
 *
 * WHAT THIS DOES NOT DO, deliberately, stated rather than implied:
 *   - no re-announcement of accepted transactions to other peers (Core
 *     trickles invs; our user-originated txs are pushed by tx_submit.c --
 *     the propagation duty for txs that exist nowhere else. A relay-received
 *     tx already propagates through the peers who sent it);
 *   - no BIP339 wtxidrelay negotiation (announcements reach us fine as
 *     txids; wtxid-based dedupe would need per-connection negotiation state
 *     in the handshake);
 *   - block-type inv entries are ignored here exactly as the sync drains
 *     ignore them today -- block keep-up is headers-driven per rotation.
 *
 * A getdata's replies may not all arrive within this pass's budget; the
 * remainder are read -- and discarded -- by the next sync pass's drain.
 * That is an accepted loss: the txid stays out of the request ring's most
 * recent window only briefly, and mempool traffic re-announces from other
 * legs continuously. The ring is a bounded FIFO, so nothing is remembered
 * forever and a dropped tx becomes requestable again as the window rolls.
 */
#include <string.h>
#include <poll.h>
#include <time.h>

typedef unsigned char u8;

extern int  p2p_read(int fd, char cmd_out[12], void* payload, unsigned cap, unsigned* plen);
extern long p2p_write(int fd, const char* cmd, unsigned cmdlen, const void* pl, unsigned plen);
extern const u8* mpool_get(void* mp, const u8* txid, unsigned long* len_out);
extern long tx_accept_validate(void* mp, const u8 txid[32], const u8* tx, unsigned long len);
extern int  tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* scratch, unsigned long scratchcap);

#define TXR_MSG_TX          1u
#define TXR_MSG_WITNESS_TX  0x40000001u
#define TXR_MAX_REQ         32          /* getdata entries per pass */
#define TXR_MAX_MSGS        64          /* messages per pass -- a leg cannot monopolise the rotation */
#define TXR_PAYLOAD_CAP     (2u << 20)  /* > max consensus tx size */

/* Recently-requested ring: 8-byte txid prefixes, FIFO. A false positive
 * (prefix collision) skips one fetch of one tx on one pass -- it will be
 * re-announced. Deliberately NOT a permanent set: entries age out by
 * wrap-around, so a tx whose reply was lost becomes requestable again. */
#define TXR_RING 4096
static u8  txr_ring[TXR_RING][8];
static unsigned txr_ring_w;

static int txr_ring_has(const u8* txid){
    for (unsigned i = 0; i < TXR_RING; i++)
        if (!memcmp(txr_ring[i], txid, 8)) return 1;
    return 0;
}
static void txr_ring_add(const u8* txid){
    memcpy(txr_ring[txr_ring_w % TXR_RING], txid, 8);
    txr_ring_w++;
}

static long long txr_now_ms(void){
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec*1000 + ts.tv_nsec/1000000;
}

static unsigned long txr_varint(const u8* p, const u8* end, unsigned* consumed){
    *consumed = 0;
    if (p >= end) return 0;
    if (p[0] < 0xfd){ *consumed = 1; return p[0]; }
    if (p[0] == 0xfd){ if (p+3 > end) return 0; *consumed = 3;
        return (unsigned long)p[1] | ((unsigned long)p[2]<<8); }
    /* longer counts than 0xfffe entries are not real inv messages */
    return 0;
}

/* Drain one leg's buffered messages; fetch + validate announced txs.
 * Called between sync passes, single-threaded, so it cannot interleave with
 * node_sync_multi on the same fd. `max_ms` bounds the wait for getdata
 * replies; with nothing buffered and nothing requested the cost is one
 * poll(2) returning empty. Returns the number of transactions accepted. */
long txrelay_poll_leg(int fd, void* mp, int max_ms){
    static u8 pl[TXR_PAYLOAD_CAP];
    static u8 scratch[2000*81 + 8];      /* worker is single-threaded */
    char cmd[12];
    unsigned plen;
    long accepted = 0;
    int outstanding = 0;                 /* getdata entries awaiting replies */
    long long deadline = txr_now_ms() + max_ms;

    for (int msgs = 0; msgs < TXR_MAX_MSGS; msgs++){
        /* wait only while replies to OUR requests are outstanding;
         * otherwise just take what is already buffered */
        int wait = 0;
        if (outstanding > 0){
            long long left = deadline - txr_now_ms();
            if (left <= 0) break;
            wait = (int)left;
        }
        struct pollfd pf = { fd, POLLIN, 0 };
        int pr = poll(&pf, 1, wait);
        if (pr <= 0 || !(pf.revents & POLLIN)) break;
        if (p2p_read(fd, cmd, pl, sizeof pl, &plen) != 1) break;

        if (!memcmp(cmd, "ping", 5)){
            /* consumed a keepalive meant for the sync loop -- answer it,
             * or the peer times this connection out */
            if (plen == 8) p2p_write(fd, "pong", 4, pl, 8);
            continue;
        }
        if (!memcmp(cmd, "inv", 4)){
            unsigned cc;
            unsigned long n = txr_varint(pl, pl + plen, &cc);
            if (!cc) continue;
            /* getdata payload: count(1) + 36 per entry */
            static u8 gd[1 + TXR_MAX_REQ*36];
            unsigned want = 0;
            for (unsigned long i = 0; i < n && want < TXR_MAX_REQ; i++){
                const u8* e = pl + cc + i*36;
                if (e + 36 > pl + plen) break;
                unsigned type = (unsigned)e[0] | (unsigned)e[1]<<8 |
                                (unsigned)e[2]<<16 | (unsigned)e[3]<<24;
                if (type != TXR_MSG_TX) continue;      /* blocks: headers-driven keep-up */
                unsigned long got_len;
                if (txr_ring_has(e + 4)) continue;     /* recently requested */
                if (mpool_get(mp, e + 4, &got_len)) continue;   /* already have it */
                u8* o = gd + 1 + want*36;
                o[0] = (u8)(TXR_MSG_WITNESS_TX);       o[1] = 0;
                o[2] = 0; o[3] = (u8)(TXR_MSG_WITNESS_TX >> 24);
                memcpy(o + 4, e + 4, 32);
                txr_ring_add(e + 4);
                want++;
            }
            if (want){
                gd[0] = (u8)want;
                if (p2p_write(fd, "getdata", 7, gd, 1 + want*36) > 0)
                    outstanding += (int)want;
            }
            continue;
        }
        if (!memcmp(cmd, "tx", 3)){
            if (outstanding > 0) outstanding--;
            u8 txid[32];
            if (plen >= 60 && tx_txid(txid, pl, plen, scratch, sizeof scratch) == 1){
                if (tx_accept_validate(mp, txid, pl, plen) == 1) accepted++;
                /* rejects are already logged by tx_accept_validate with the
                 * failing stage; nothing useful to add here */
            }
            continue;
        }
        if (!memcmp(cmd, "notfound", 9)){
            if (outstanding > 0) outstanding = 0;      /* stop waiting */
            continue;
        }
        /* headers/addr/cmpctblock/...: not ours -- same discard the sync
         * drains apply. A `block` push lost here is re-fetched by the next
         * headers-driven pass. */
    }
    return accepted;
}
