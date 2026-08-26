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
#include <stdlib.h>
#include <poll.h>
#include <time.h>

typedef unsigned char u8;
typedef unsigned int u32;

extern int  p2p_read(int fd, char cmd_out[12], void* payload, unsigned cap, unsigned* plen);
extern long p2p_write(int fd, const char* cmd, unsigned cmdlen, const void* pl, unsigned plen);
extern const u8* mpool_get(void* mp, const u8* txid, unsigned long* len_out);
extern long tx_accept_validate(void* mp, const u8 txid[32], const u8* tx, unsigned long len);
extern long tx_accept_validate_reason(void* mp, const u8 txid[32], const u8* tx,
                                      unsigned long len, char* reason, unsigned long rcap);
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

/* ---- orphan pool ---------------------------------------------------------
 * Out-of-order relay is ordinary: a child is announced moments after (or
 * alongside) its parent, and whichever fetch completes first can arrive
 * with its parent still in flight -- Core parks these in its orphanage and
 * resolves them when the parent lands; without one, every such child is a
 * "missing-inputs" reject and a re-fetch cycle. This pool is deliberately
 * small and disposable: bounded count and bytes, oldest-evicted, 120 s
 * expiry -- an orphan that cannot be resolved quickly will be re-announced
 * by the network anyway. Parents are requested immediately on the same leg
 * (MSG_WITNESS_TX, same reasoning as every other fetch here). On every
 * accepted transaction the pool is re-swept, so multi-level chains resolve
 * in cascade. */
#define TXR_ORPHAN_MAX       256
#define TXR_ORPHAN_BYTES     (2u << 20)
#define TXR_ORPHAN_TTL_MS    120000
#define TXR_ORPHAN_PARENTS   8          /* parent txids remembered per orphan */
typedef struct {
    u8* buf; u32 len;
    u8 txid[32];
    u8 parent[TXR_ORPHAN_PARENTS][32]; u32 nparent;
    long long t_ms;
} txr_orphan_t;
static txr_orphan_t txr_orph[TXR_ORPHAN_MAX];
static unsigned txr_orph_bytes;
static long txr_orph_parked, txr_orph_resolved, txr_orph_dropped;   /* counters for the caller's log */

/* ---- announce queue ------------------------------------------------------
 * A relay-received transaction we accepted should propagate onward: queue
 * its txid (with the fd it CAME from, so the sender is not told about its
 * own tx) and let txrelay_announce -- called once per worker rotation --
 * send one inv per leg covering everything accepted since the last call.
 * Announcements use MSG_TX (type 1): we do not negotiate BIP339, so txid-
 * based announcement is the correct dialect, and a peer that wants the tx
 * asks with getdata -- which the drain below now answers from the pool
 * (the pool stores the full witness serialization we validated). Bounded:
 * a rotation that accepts more than the queue holds simply announces the
 * first TXR_ANN_MAX; the rest still propagate through every other node
 * that accepted them. */
#define TXR_ANN_MAX 64
static u8  txr_ann[TXR_ANN_MAX][32];
static int txr_ann_src[TXR_ANN_MAX];
static int txr_ann_n;

static void txr_ann_add(const u8 txid[32], int src_fd){
    if (txr_ann_n >= TXR_ANN_MAX) return;
    memcpy(txr_ann[txr_ann_n], txid, 32);
    txr_ann_src[txr_ann_n] = src_fd;
    txr_ann_n++;
}

/* announce everything queued since the last call to every live leg except
 * each tx's own source; returns entries flushed */
long txrelay_announce(const int* fds, int nfds){
    if (!txr_ann_n) return 0;
    static u8 inv[1 + TXR_ANN_MAX*36];
    long flushed = txr_ann_n;
    for (int f = 0; f < nfds; f++){
        if (fds[f] < 0) continue;
        unsigned n = 0;
        for (int i = 0; i < txr_ann_n; i++){
            if (txr_ann_src[i] == fds[f]) continue;    /* not back to the sender */
            u8* e = inv + 1 + n*36;
            e[0] = 1; e[1] = 0; e[2] = 0; e[3] = 0;    /* MSG_TX */
            memcpy(e + 4, txr_ann[i], 32);
            n++;
        }
        if (n){ inv[0] = (u8)n; p2p_write(fds[f], "inv", 3, inv, 1 + n*36); }
    }
    txr_ann_n = 0;
    return flushed;
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

/* first TXR_ORPHAN_PARENTS distinct parent txids of a raw tx */
static u32 txr_tx_parents(const u8* tx, unsigned long len, u8 out[][32], u32 cap){
    const u8* p = tx + 4; const u8* end = tx + len;
    if (len < 10) return 0;
    if (p + 2 <= end && p[0] == 0x00 && p[1] == 0x01) p += 2;
    unsigned cc; unsigned long nin = txr_varint(p, end, &cc);
    if (!cc) return 0;
    p += cc;
    u32 n = 0;
    for (unsigned long i = 0; i < nin && p + 36 <= end; i++){
        int dup = 0;
        for (u32 k = 0; k < n; k++) if (!memcmp(out[k], p, 32)) { dup = 1; break; }
        if (!dup && n < cap){ memcpy(out[n], p, 32); n++; }
        p += 36;
        unsigned long sl = txr_varint(p, end, &cc); if (!cc) return n;
        if ((unsigned long)(end - p) < sl + 4) return n;
        p += sl + 4;
    }
    return n;
}

static void txr_orphan_free(txr_orphan_t* o){
    if (o->buf){ free(o->buf); txr_orph_bytes -= o->len; }
    memset(o, 0, sizeof *o);
}

static void txr_orphan_add(const u8 txid[32], const u8* tx, unsigned long len){
    if (len == 0 || len > (TXR_ORPHAN_BYTES / 4)) return;   /* one tx may not hog the pool */
    for (int i = 0; i < TXR_ORPHAN_MAX; i++)
        if (txr_orph[i].buf && !memcmp(txr_orph[i].txid, txid, 32)) return;   /* already parked */
    /* pick a free slot, else evict the oldest; evict oldest until the byte
     * budget fits too */
    for (;;){
        int slot = -1; long long oldest = 0; int oldi = -1;
        for (int i = 0; i < TXR_ORPHAN_MAX; i++){
            if (!txr_orph[i].buf){ slot = i; break; }
            if (oldi < 0 || txr_orph[i].t_ms < oldest){ oldest = txr_orph[i].t_ms; oldi = i; }
        }
        if (slot >= 0 && txr_orph_bytes + len <= TXR_ORPHAN_BYTES){
            txr_orphan_t* o = &txr_orph[slot];
            o->buf = malloc(len);
            if (!o->buf){ memset(o, 0, sizeof *o); return; }
            memcpy(o->buf, tx, len); o->len = (u32)len;
            memcpy(o->txid, txid, 32);
            o->nparent = txr_tx_parents(tx, len, o->parent, TXR_ORPHAN_PARENTS);
            o->t_ms = txr_now_ms();
            txr_orph_bytes += (u32)len;
            txr_orph_parked++;
            return;
        }
        if (oldi < 0) return;
        txr_orphan_free(&txr_orph[oldi]); txr_orph_dropped++;
    }
}

/* retry every orphan that lists `accepted` as a parent; cascade until a
 * sweep makes no progress (bounded by the pool size, in practice 1-2). */
static long txr_orphan_resolve(void* mp, const u8 accepted[32]){
    static u8 scratch2[2000*81 + 8];
    long got = 0;
    int progress = 1;
    u8 want[32]; memcpy(want, accepted, 32);
    while (progress){
        progress = 0;
        for (int i = 0; i < TXR_ORPHAN_MAX; i++){
            txr_orphan_t* o = &txr_orph[i];
            if (!o->buf) continue;
            int hit = 0;
            for (u32 k = 0; k < o->nparent; k++) if (!memcmp(o->parent[k], want, 32)) { hit = 1; break; }
            if (!hit) continue;
            u8 id[32];
            char reason[96];
            if (tx_txid(id, o->buf, o->len, scratch2, sizeof scratch2) == 1 &&
                tx_accept_validate_reason(mp, id, o->buf, o->len, reason, sizeof reason) == 1){
                got++; txr_orph_resolved++;
                txr_ann_add(id, -1);           /* cascaded accepts announce everywhere */
                memcpy(want, id, 32);          /* this accept may unlock ITS children */
                txr_orphan_free(o);
                progress = 1;
                break;                          /* restart the sweep with the new parent */
            }
            /* still unresolvable (another parent missing, or a real reject):
             * leave it for the TTL; a definitive non-missing reject frees it */
            if (!strstr(reason, "missing/already-spent")){ txr_orphan_free(o); txr_orph_dropped++; }
        }
    }
    return got;
}

static long txr_orphan_resolve(void* mp, const u8 accepted[32]);
#define txr_orphan_resolve_ann(mp, id, fd) txr_orphan_resolve((mp), (id))

static void txr_orphan_expire(void){
    long long now = txr_now_ms();
    for (int i = 0; i < TXR_ORPHAN_MAX; i++)
        if (txr_orph[i].buf && now - txr_orph[i].t_ms > TXR_ORPHAN_TTL_MS){
            txr_orphan_free(&txr_orph[i]); txr_orph_dropped++;
        }
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
    txr_orphan_expire();
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
                char reason[96];
                long r = tx_accept_validate_reason(mp, txid, pl, plen, reason, sizeof reason);
                if (r == 1){
                    accepted++;
                    txr_ann_add(txid, fd);
                    accepted += txr_orphan_resolve_ann(mp, txid, fd);   /* cascade waiting children */
                } else if (r == -25){
                    /* missing inputs: ordinary out-of-order relay. Park the
                     * child and fetch its parents from THIS leg right now --
                     * the resolve sweep on the parent's accept finishes the
                     * job. */
                    txr_orphan_add(txid, pl, plen);
                    u8 par[TXR_ORPHAN_PARENTS][32];
                    u32 npar = txr_tx_parents(pl, plen, par, TXR_ORPHAN_PARENTS);
                    static u8 gd[1 + TXR_ORPHAN_PARENTS*36];
                    unsigned want = 0;
                    for (u32 k = 0; k < npar; k++){
                        unsigned long got_len;
                        if (txr_ring_has(par[k])) continue;
                        if (mpool_get(mp, par[k], &got_len)) continue;
                        u8* o = gd + 1 + want*36;
                        o[0] = (u8)(TXR_MSG_WITNESS_TX);       o[1] = 0;
                        o[2] = 0; o[3] = (u8)(TXR_MSG_WITNESS_TX >> 24);
                        memcpy(o + 4, par[k], 32);
                        txr_ring_add(par[k]);
                        want++;
                    }
                    if (want){
                        gd[0] = (u8)want;
                        if (p2p_write(fd, "getdata", 7, gd, 1 + want*36) > 0)
                            outstanding += (int)want;
                    }
                }
                /* other rejects are counted in tx_accept's own summary */
            }
            continue;
        }
        if (!memcmp(cmd, "getdata", 8)){
            /* a peer we announced to is asking: serve MSG_TX/MSG_WITNESS_TX
             * from the pool (we store the full witness serialization), and
             * answer misses with one notfound so the peer's in-flight
             * bookkeeping is not left hanging. Block-type entries are not
             * ours -- the serve path owns those. */
            unsigned cc;
            unsigned long n = txr_varint(pl, pl + plen, &cc);
            if (!cc) continue;
            static u8 nf[1 + TXR_MAX_REQ*36];
            unsigned nmiss = 0;
            for (unsigned long i = 0; i < n && i < TXR_MAX_REQ; i++){
                const u8* e = pl + cc + i*36;
                if (e + 36 > pl + plen) break;
                unsigned type = (unsigned)e[0] | (unsigned)e[1]<<8 |
                                (unsigned)e[2]<<16 | (unsigned)e[3]<<24;
                if (type != TXR_MSG_TX && type != TXR_MSG_WITNESS_TX) continue;
                unsigned long got_len = 0;
                const u8* bytes = mpool_get(mp, e + 4, &got_len);
                if (bytes && got_len){
                    p2p_write(fd, "tx", 2, bytes, (unsigned)got_len);
                } else {
                    memcpy(nf + 1 + nmiss*36, e, 36);
                    nmiss++;
                }
            }
            if (nmiss){ nf[0] = (u8)nmiss; p2p_write(fd, "notfound", 8, nf, 1 + nmiss*36); }
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
