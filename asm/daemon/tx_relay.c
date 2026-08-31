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
#include <stdio.h>
#include "log_ts.h"
#include "../rpc_node.h"   /* the orphan mirror lives in the shared status block */   /* timestamped fprintf(stderr), like every other daemon line */
#include <stdlib.h>
#include <poll.h>
#include <time.h>

typedef unsigned char u8;
typedef unsigned int u32;

extern int  p2p_read(int fd, char cmd_out[12], void* payload, unsigned cap, unsigned* plen);
extern long p2p_write(int fd, const char* cmd, unsigned cmdlen, const void* pl, unsigned plen);
extern const u8* mpool_get(void* mp, const u8* txid, unsigned long* len_out);
extern long tx_accept_validate(void* mp, const u8 txid[32], const u8* tx, unsigned long len);
extern long tx_accept_validate_p2p(void* mp, const u8 txid[32], const u8* tx,
                                   unsigned long len);
extern int  tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* scratch, unsigned long scratchcap);
/* package validation, shared verbatim with the submitpackage RPC path so a
 * package that arrives over the wire and one that arrives over RPC are held
 * to exactly the same rules */
extern int  mpol_package_well_formed(const u8* const* txs, const unsigned long* lens,
                                     int n, u8* txids, unsigned long long* vsz,
                                     const char** why);
extern void mpol_package_fee_context(unsigned long long fee, unsigned long long vsize);
extern void mpol_package_context(const u8* const* txs, const unsigned long* lens,
                                 const u8* txids, int n);
extern void txacc_package_overlay(const u8* const* txs, const unsigned long* lens,
                                  const u8* txids, int n);
extern long tx_accept_test_reason(void* mp, const u8* txid, const u8* tx, unsigned long len,
                                  char* reason, unsigned long rcap, unsigned long long* fee);
extern int  txacc_fee_reconsiderable(const char* reason);

#define TXR_MSG_TX          1u
#define TXR_MSG_WITNESS_TX  0x40000001u
#define TXR_MSG_WTX         5u          /* BIP339: wtxid-based tx inv/getdata */
#define TXR_MAX_REQ         32          /* getdata entries per pass */
#define TXR_MAX_MSGS        64          /* messages per pass -- a leg cannot monopolise the rotation */
#define TXR_PAYLOAD_CAP     (2u << 20)  /* > max consensus tx size */

/* Recently-requested ring: 8-byte txid prefixes, FIFO. A false positive
 * (prefix collision) skips one fetch of one tx on one pass -- it will be
 * re-announced. Deliberately NOT a permanent set: entries age out by
 * wrap-around, so a tx whose reply was lost becomes requestable again. */
#define TXR_RING 4096
#define TXR_REQ_TTL_MS 60000            /* Core's GETDATA_TX_INTERVAL: a request is forgotten after 60 s */
static u8  txr_ring[TXR_RING][8];
static long long txr_ring_t[TXR_RING];
static unsigned txr_ring_w;
static long long txr_req_ttl_ms = TXR_REQ_TTL_MS;
static long txr_req_refetch;            /* announcements re-requested because the earlier request timed out */
static long long txr_now_ms(void);
/* "Did we request this recently?" -- recently meaning within the request
 * TTL. Without the TTL a getdata whose reply never came (the leg dropped and
 * re-dialed, the peer ignored it) blocked every later announcement of that
 * tx until 4,096 other requests aged the entry out (~14 minutes at 5 tx/s),
 * and every child announced meanwhile died as an orphan. Core forgets a
 * request after 60 s and asks the next announcer. */
static int txr_ring_has(const u8* txid){
    for (unsigned i = 0; i < TXR_RING; i++)
        if (!memcmp(txr_ring[i], txid, 8)){
            if (txr_now_ms() - txr_ring_t[i] < txr_req_ttl_ms) return 1;
            txr_req_refetch++;
            return 0;                                   /* timed out: ask again */
        }
    return 0;
}
static void txr_ring_add(const u8* txid){
    memcpy(txr_ring[txr_ring_w % TXR_RING], txid, 8);
    txr_ring_t[txr_ring_w % TXR_RING] = txr_now_ms();
    txr_ring_w++;
}
void txrelay_test_set_req_ttl_ms(long long ms){ txr_req_ttl_ms = ms; }   /* tests shrink the 60 s */
/* A `notfound` for something we asked for: forget that we asked, so the
 * next announcement (or the next orphan wanting it as a parent) requests it
 * again. Core does the same by dropping the in-flight entry. Without this,
 * an orphan whose parent was too fresh for the peer to serve (Core will not
 * hand out a tx it has not announced to us unless it is 2 minutes old) could
 * never be resolved: the ring suppressed every later fetch and the child
 * expired -- production 2026-08-31: 6,324 parked, 538 resolved, 5,530 dropped
 * in one hour AFTER the fee-floor fix. */
static void txr_ring_del(const u8* txid){
    for (unsigned i = 0; i < TXR_RING; i++)
        if (!memcmp(txr_ring[i], txid, 8)) memset(txr_ring[i], 0xff, 8);   /* never a real prefix in practice */
}
static long txr_notfound_seen;              /* counter for the stats line */

/* ---- per-peer notfound memory ---------------------------------------------
 * A notfound is this peer saying it cannot serve THAT transaction. The
 * failover asks someone else immediately (below), but once the want entry
 * is gone nothing remembered the refusal: the next announcement -- or the
 * next parked orphan naming it as a parent -- happily asked the same peer
 * again, burning a 5 s retry round on an answer already given. Remember
 * (peer, tx) pairs for ten minutes; the picker and the parent fetch skip
 * them. Keyed by fd + 8-byte prefix like the request ring; an fd reused by
 * a NEW peer inside the window costs at worst one skipped candidate. */
#define TXR_NF_MAX    512
#define TXR_NF_TTL_MS 600000
static struct { int fd; u8 h8[8]; long long t; } txr_nf_mem[TXR_NF_MAX];
static unsigned txr_nf_w;
static long long txr_nf_ttl_ms = TXR_NF_TTL_MS;
static void txr_nf_note(int fd, const u8* h){
    txr_nf_mem[txr_nf_w % TXR_NF_MAX].fd = fd;
    memcpy(txr_nf_mem[txr_nf_w % TXR_NF_MAX].h8, h, 8);
    txr_nf_mem[txr_nf_w % TXR_NF_MAX].t = txr_now_ms();
    txr_nf_w++;
}
static int txr_nf_has(int fd, const u8* h){
    for (int i = 0; i < TXR_NF_MAX; i++)
        if (txr_nf_mem[i].fd == fd && !memcmp(txr_nf_mem[i].h8, h, 8) &&
            txr_now_ms() - txr_nf_mem[i].t < txr_nf_ttl_ms) return 1;
    return 0;
}
void txrelay_test_set_nf_ttl_ms(long long ms){ txr_nf_ttl_ms = ms; }

/* ---- reconsiderable set (Core's m_lazy_recent_rejects_reconsiderable) ----
 * A transaction rejected ONLY because it did not clear a fee floor is the
 * one reject a CPFP child can overturn, so it must not be treated like any
 * other reject. Core keeps those identifiers in a filter SEPARATE from its
 * ordinary recent-rejects filter for exactly one reason: AlreadyHaveTx must
 * answer "no" for them, so that when a child turns up later the parent can
 * be requested AGAIN and the pair resubmitted as a package.
 *
 * Our request ring is the analogue of that already-have check, and it would
 * otherwise suppress precisely the re-fetch 1p1c depends on. So membership
 * here buys a bounded number of ring bypasses -- bounded, because an
 * unbounded one is a re-fetch loop with a peer that keeps sending a tx we
 * keep rejecting. Entries expire on the same 120 s clock as the orphan pool
 * they pair with; nothing is remembered longer than the child that might
 * rescue it. */
static long long txr_now_ms(void);      /* defined with the orphan pool below */

#define TXR_RECON_MAX      64
#define TXR_RECON_TTL_MS   120000
#define TXR_RECON_REFETCH  2            /* ring bypasses granted per entry */
typedef struct { u8 txid[32]; int used; int refetch; long long t_ms; } txr_recon_t;
static txr_recon_t txr_recon[TXR_RECON_MAX];
static long txr_recon_n, txr_1p1c_ok, txr_1p1c_fail;   /* counters for the caller's log */

static void txr_recon_add(const u8 txid[32]){
    long long now = txr_now_ms();
    int oldest = 0;
    for (int i = 0; i < TXR_RECON_MAX; i++){
        if (txr_recon[i].used && !memcmp(txr_recon[i].txid, txid, 32)){
            txr_recon[i].t_ms = now; txr_recon[i].refetch = TXR_RECON_REFETCH; return; }
        if (!txr_recon[i].used){ oldest = i; goto place; }
        if (txr_recon[i].t_ms < txr_recon[oldest].t_ms) oldest = i;
    }
place:
    memcpy(txr_recon[oldest].txid, txid, 32);
    txr_recon[oldest].used = 1;
    txr_recon[oldest].refetch = TXR_RECON_REFETCH;
    txr_recon[oldest].t_ms = now;
    txr_recon_n++;
}

/* is this txid a fee-only reject worth re-fetching? consumes one bypass */
static int txr_recon_allow_refetch(const u8 txid[32]){
    long long now = txr_now_ms();
    for (int i = 0; i < TXR_RECON_MAX; i++){
        if (!txr_recon[i].used || memcmp(txr_recon[i].txid, txid, 32)) continue;
        if (now - txr_recon[i].t_ms > TXR_RECON_TTL_MS){ txr_recon[i].used = 0; return 0; }
        if (txr_recon[i].refetch <= 0) return 0;
        txr_recon[i].refetch--;
        return 1;
    }
    return 0;
}

static void txr_recon_expire(void){
    long long now = txr_now_ms();
    for (int i = 0; i < TXR_RECON_MAX; i++)
        if (txr_recon[i].used && now - txr_recon[i].t_ms > TXR_RECON_TTL_MS)
            txr_recon[i].used = 0;
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
/* Sized against Core v31's orphanage reservations: 404,000 weight units per
 * peer (~101 kvB) and a 3,000-announcement latency score per peer -- with 8
 * outbound legs that is ~800 kvB / 24k announcements. 256 slots / 2 MB pinned
 * at capacity after every restart (production 2026-08-31: 1,198 of 1,209
 * drops were evictions once nothing expired by TTL any more). */
#define TXR_ORPHAN_MAX       2048
#define TXR_ORPHAN_BYTES     (8u << 20)
#define TXR_ORPHAN_TTL_MS    300000    /* 5 min: deep chains resolve slower than 2 min; 2048 slots absorb the residency */
#define TXR_ORPHAN_PARENTS   8          /* parent txids remembered per orphan */
typedef struct {
    u8* buf; u32 len;
    u8 txid[32];
    u8 parent[TXR_ORPHAN_PARENTS][32]; u32 nparent;
    long long t_ms;
} txr_orphan_t;
static txr_orphan_t txr_orph[TXR_ORPHAN_MAX];

/* ---- orphan mirror for getorphantxs --------------------------------------
 * This pool is process-local to the download worker and is touched from one
 * thread (txrelay_poll_leg is driven sequentially per leg), so publishing a
 * snapshot needs no lock. Only republish when something actually changed --
 * a generation counter, not a timer, so the RPC never shows a stale pool and
 * the copy does not run on every poll for nothing. */
static void*         txr_status;
static unsigned long txr_orph_gen, txr_orph_gen_pub = (unsigned long)-1;
void txrelay_set_status(void* st){ txr_status = st; }
void txrelay_publish_orphans(void){
    if (!txr_status || txr_orph_gen == txr_orph_gen_pub) return;
    node_status_t* ns = (node_status_t*)txr_status;
    int n = 0;
    for (int i = 0; i < TXR_ORPHAN_MAX && n < RPC_MAX_ORPHANS; i++){
        if (!txr_orph[i].buf) continue;
        memcpy((void*)ns->orphans[n].txid, txr_orph[i].txid, 32);
        ns->orphans[n].len     = txr_orph[i].len;
        ns->orphans[n].nparent = txr_orph[i].nparent;
        ns->orphans[n].t_ms    = txr_orph[i].t_ms;
        n++;
    }
    __sync_synchronize();
    ns->n_orphans = n;                 /* count published last */
    txr_orph_gen_pub = txr_orph_gen;
}
static unsigned txr_orph_bytes;
static long txr_orph_parked, txr_orph_resolved, txr_orph_dropped;   /* counters for the caller's log */
static long txr_drop_ttl, txr_drop_evict, txr_drop_reject, txr_parent_req;   /* why they dropped; how many parents we asked for */

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
    txr_orph_gen++;
    if (o->buf){ free(o->buf); txr_orph_bytes -= o->len; }
    memset(o, 0, sizeof *o);
}

static void txr_orphan_add(const u8 txid[32], const u8* tx, unsigned long len){
    txr_orph_gen++;
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
        txr_orphan_free(&txr_orph[oldi]); txr_orph_dropped++; txr_drop_evict++;
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
            long rr = -26;
            if (tx_txid(id, o->buf, o->len, scratch2, sizeof scratch2) == 1 &&
                (rr = tx_accept_validate_p2p(mp, id, o->buf, o->len)) == 1){
                got++; txr_orph_resolved++;
                txr_ann_add(id, -1);           /* cascaded accepts announce everywhere */
                memcpy(want, id, 32);          /* this accept may unlock ITS children */
                txr_orphan_free(o);
                progress = 1;
                break;                          /* restart the sweep with the new parent */
            }
            /* still unresolvable (another parent missing, or a real reject):
             * leave it for the TTL; a definitive non-missing reject frees it.
             * -28 is NOT definitive -- a fee-only reject is the verdict a
             * descendant can still overturn, so that child stays parked. */
            if (rr != -25 && rr != -28){ txr_orphan_free(o); txr_orph_dropped++; txr_drop_reject++; }
        }
    }
    return got;
}

/* ---- 1p1c package relay (Core's Find1P1CPackage) -------------------------
 * The case this exists for: a parent that pays too little to enter the
 * mempool on its own, and a child that pays for both. Validated one at a
 * time -- which is all the drain could do before this -- the parent is
 * rejected on fee and the child is then a permanent orphan, so the pair
 * never propagates no matter how much the child pays. Core's answer is to
 * notice that a just-rejected-for-fee parent has a child waiting in the
 * orphanage and submit the two together as a package, where the child's fee
 * is allowed to lift the parent over the floor.
 *
 * One parent and one child is the whole of it, deliberately: that is the
 * shape Core relays (package relay proper, with sendpackages negotiation,
 * is a separate protocol) and it covers ordinary CPFP. Deeper chains still
 * resolve the way they always did, through the orphan pool, whenever every
 * member clears the floor by itself.
 *
 * The validation is not a second implementation -- it is the same
 * well-formedness check, the same overlay, the same two passes, and the
 * same fee context that submitpackage runs. A package off the wire and a
 * package off the RPC socket must not be able to disagree. */
static int txr_submit_1p1c(void* mp, const u8* parent, unsigned long plen,
                           const u8* child, unsigned long clen){
    const u8* txs[2]  = { parent, child };
    unsigned long lens[2] = { plen, clen };
    u8 txids[64];
    unsigned long long vsz[2];
    const char* why = "";

    if (!mpol_package_well_formed(txs, lens, 2, txids, vsz, &why)) return 0;

    /* pass 1: dry run under the overlay, to learn the real fees. The overlay
     * is what lets the child resolve its prevout against a parent that is
     * not in the mempool yet. */
    unsigned long long tot_fee = 0, tot_vsize = 0;
    int all_ok = 1;
    mpol_package_context(txs, lens, txids, 2);
    txacc_package_overlay(txs, lens, txids, 2);
    for (int i = 0; i < 2; i++){
        char r[128]; r[0] = 0; unsigned long long fee = 0;
        long rc = tx_accept_test_reason(mp, txids + i*32, txs[i], lens[i], r, sizeof r, &fee);
        if (rc == 1 || txacc_fee_reconsiderable(r)){ tot_fee += fee; tot_vsize += vsz[i]; }
        else { all_ok = 0; break; }     /* not something a package can rescue */
    }
    txacc_package_overlay(NULL, NULL, NULL, 0);
    mpol_package_context(NULL, NULL, NULL, 0);
    if (!all_ok) return 0;

    /* pass 2: commit with the package feerate in effect */
    int committed = 1;
    mpol_package_fee_context(tot_fee, tot_vsize);
    mpol_package_context(txs, lens, txids, 2);
    txacc_package_overlay(txs, lens, txids, 2);
    for (int i = 0; i < 2; i++)
        if (tx_accept_validate_p2p(mp, txids + i*32, txs[i], lens[i]) != 1) committed = 0;
    /* ALWAYS cleared, on every path: a fee context left set would relax the
     * floor for ordinary single-transaction relay, and an overlay left set
     * would let an unrelated transaction resolve against a package member. */
    txacc_package_overlay(NULL, NULL, NULL, 0);
    mpol_package_context(NULL, NULL, NULL, 0);
    mpol_package_fee_context(0, 0);

    if (committed){
        txr_ann_add(txids,      -1);    /* both are new to the network: */
        txr_ann_add(txids + 32, -1);    /* announce on every leg */
        txr_1p1c_ok++;
        /* Worth a line each time: a 1p1c acceptance is a rare event, not the
         * per-transaction firehose the drain deliberately keeps out of the
         * log. Txids are printed the way Core displays them -- byte-reversed
         * from the wire order they are stored in. */
        char ph[17], ch[17];
        for (int b = 0; b < 8; b++){
            sprintf(ph + b*2, "%02x", txids[31 - b]);
            sprintf(ch + b*2, "%02x", txids[63 - b]);
        }
        fprintf(stderr, "[txrelay] 1p1c accepted: parent %s.. + child %s.. "
                        "(package %llu sat / %llu vB)\n",
                ph, ch, (unsigned long long)tot_fee, (unsigned long long)tot_vsize);
    } else {
        txr_1p1c_fail++;
    }
    return committed;
}

/* A parent has just been rejected for fee alone. If some parked orphan
 * names it as a parent, that orphan is the child the package needs; try
 * each such child until one package sticks. Returns transactions accepted
 * (2 on success -- both members entered the mempool). */
static long txr_try_1p1c(void* mp, const u8 parent_txid[32],
                         const u8* parent, unsigned long plen){
    for (int i = 0; i < TXR_ORPHAN_MAX; i++){
        txr_orphan_t* o = &txr_orph[i];
        if (!o->buf) continue;
        int hit = 0;
        for (u32 k = 0; k < o->nparent; k++)
            if (!memcmp(o->parent[k], parent_txid, 32)) { hit = 1; break; }
        if (!hit) continue;
        if (txr_submit_1p1c(mp, parent, plen, o->buf, o->len)){
            u8 cid[32]; memcpy(cid, o->txid, 32);
            txr_orphan_free(o);
            txr_orph_resolved++;
            /* the CHILD is what a grandchild names as its parent, so the
             * cascade sweep has to run on the child's txid, not the
             * parent's -- sweeping the parent would find nothing. */
            return 2 + txr_orphan_resolve(mp, cid);
        }
    }
    return 0;
}

static long txr_orphan_resolve(void* mp, const u8 accepted[32]);
#define txr_orphan_resolve_ann(mp, id, fd) txr_orphan_resolve((mp), (id))

static void txr_orphan_expire(void){
    long long now = txr_now_ms();
    for (int i = 0; i < TXR_ORPHAN_MAX; i++)
        if (txr_orph[i].buf && now - txr_orph[i].t_ms > TXR_ORPHAN_TTL_MS){
            txr_orphan_free(&txr_orph[i]); txr_orph_dropped++; txr_drop_ttl++;
        }
}

/* ---- addr gossip on outbound legs (2026-08-28) ----------------------------
 * A peer announces itself (Core's AdvertiseLocal) and relays a trickle of
 * addresses it learned, as `addr` or -- to a peer that negotiated BIP155 --
 * `addrv2`. This drain discarded both, so every leg's gossip was lost and
 * the book only ever grew through the separate replenish connections
 * (daemon/addr_ingest.c). Now folded into the book through the same parsers,
 * with Core's per-peer token bucket (MAX_ADDR_PROCESSING_TOKEN_BUCKET = 1000
 * to start, refilled at MAX_ADDR_RATE_PER_SECOND = 0.1) so a flooding peer
 * cannot fill the book. Per address, as in Core: a message that declares
 * more entries than the bucket holds is processed up to the budget and the
 * rest is dropped (the parser takes a record limit).
 * The book (daemon/addrbook.c, peers2.dat) is owned by daemon/addr_ingest.c
 * in this single-threaded worker; the serve children and the RPC parent
 * open it read-only. */
extern long addr_ingest_msg_n(void* ab, const char* cmd, const unsigned char* pl, long plen, long limit);
extern long p2p_addr_count(const void* pl, long plen);
/* weak default: targets that link tx_relay.c without daemon/addr_ingest.c
 * (a strong definition anywhere in the link wins) */
__attribute__((weak)) long addr_ingest_msg_n(void* ab, const char* cmd, const unsigned char* pl, long plen, long limit){
    (void)ab; (void)cmd; (void)pl; (void)plen; (void)limit; return 0;
}
#define TXR_ADDR_BUCKET_MAX   1000.0     /* Core MAX_ADDR_PROCESSING_TOKEN_BUCKET */
#define TXR_ADDR_RATE_PER_S   0.1        /* Core MAX_ADDR_RATE_PER_SECOND */
#define TXR_ADDR_LEGS         64
static struct { int fd; double tokens; long long t_ms; } txr_addr_bucket[TXR_ADDR_LEGS];
long txr_addr_gossip_added, txr_addr_gossip_msgs, txr_addr_gossip_limited;

/* number of entries a payload declares (v1: 30-byte records; v2: CompactSize
 * count only -- the parser validates the rest) */
static long txr_addr_declared(const char* cmd, const u8* pl, unsigned plen){
    if (!memcmp(cmd, "addrv2", 7)){
        if (plen < 1) return -1;
        if (pl[0] < 0xfd) return pl[0];
        if (pl[0] == 0xfd && plen >= 3) return (long)pl[1] | ((long)pl[2] << 8);
        return -1;                                   /* > 65535: not a real message */
    }
    return p2p_addr_count(pl, plen);
}
static long txr_addr_ingest(int fd, const char* cmd, const u8* pl, unsigned plen){
    long n = txr_addr_declared(cmd, pl, plen);
    if (n <= 0 || n > 1000) return 0;                /* Core: > MAX_ADDR_TO_SEND misbehaves */
    /* per-leg token bucket, keyed by fd (a leg's fd is stable for its life) */
    long long now = txr_now_ms();
    int slot = -1, free_slot = -1;
    for (int i = 0; i < TXR_ADDR_LEGS; i++){
        if (txr_addr_bucket[i].fd == fd){ slot = i; break; }
        if (free_slot < 0 && txr_addr_bucket[i].fd == 0) free_slot = i;
    }
    if (slot < 0){
        if (free_slot < 0) free_slot = (int)(fd % TXR_ADDR_LEGS);
        slot = free_slot;
        txr_addr_bucket[slot].fd = fd; txr_addr_bucket[slot].tokens = TXR_ADDR_BUCKET_MAX;
        txr_addr_bucket[slot].t_ms = now;
    }
    double* tk = &txr_addr_bucket[slot].tokens;
    *tk += (double)(now - txr_addr_bucket[slot].t_ms) / 1000.0 * TXR_ADDR_RATE_PER_S;
    if (*tk > TXR_ADDR_BUCKET_MAX) *tk = TXR_ADDR_BUCKET_MAX;
    txr_addr_bucket[slot].t_ms = now;
    long budget = (long)*tk;                          /* whole tokens available */
    if (budget <= 0){ txr_addr_gossip_limited += n; return 0; }
    if (budget > n) budget = n;
    else txr_addr_gossip_limited += n - budget;         /* the tail Core would drop too */
    *tk -= (double)budget;
    long added = addr_ingest_msg_n(NULL, cmd, pl, (long)plen, budget);
    txr_addr_gossip_msgs++;
    if (added > 0) txr_addr_gossip_added += added;
    return added;
}

/* Drain one leg's buffered messages; fetch + validate announced txs.
 * Called between sync passes, single-threaded, so it cannot interleave with
 * node_sync_multi on the same fd. `max_ms` bounds the wait for getdata
 * replies; with nothing buffered and nothing requested the cost is one
 * poll(2) returning empty. Returns the number of transactions accepted. */
/* ---- replies still owed to us, per leg ------------------------------------
 * A getdata's reply can arrive after this poll's wait expires. The very next
 * thing the worker does on that fd is the header-sync pass, whose drain
 * discards every message that is not a header or block -- so a parent fetched
 * for a parked orphan from any peer slower than the wait was eaten every
 * time (production 2026-08-31: 822 parents requested, 65 notfound, 37
 * resolved). Remember what is outstanding per fd, carry it into the next
 * poll so it keeps waiting, and let the worker ask (txrelay_replies_pending)
 * before it runs a sync pass on that leg. Bounded: an entry expires after
 * TXR_PEND_TTL_MS so a peer that never answers cannot stall the sync. */
#define TXR_PEND_MAX    64
#define TXR_PEND_TTL_MS 1500
static struct { int fd; int n; long long t; } txr_pend[TXR_PEND_MAX];
static long long txr_pend_ttl_ms = TXR_PEND_TTL_MS;
static long txr_sync_deferred;
static int txr_pend_get(int fd){
    for (int i = 0; i < TXR_PEND_MAX; i++)
        if (txr_pend[i].fd == fd && txr_pend[i].n > 0){
            if (txr_now_ms() - txr_pend[i].t < txr_pend_ttl_ms) return txr_pend[i].n;
            txr_pend[i].n = 0;                          /* gave up on that peer */
        }
    return 0;
}
static void txr_pend_set(int fd, int n){
    int free_i = -1;
    for (int i = 0; i < TXR_PEND_MAX; i++){
        if (txr_pend[i].fd == fd){ txr_pend[i].n = n; txr_pend[i].t = txr_now_ms(); return; }
        if (free_i < 0 && txr_pend[i].n == 0) free_i = i;
    }
    if (free_i >= 0){ txr_pend[free_i].fd = fd; txr_pend[free_i].n = n; txr_pend[free_i].t = txr_now_ms(); }
}
int txrelay_replies_pending(int fd){ return txr_pend_get(fd) > 0; }
void txrelay_note_sync_deferred(void){ txr_sync_deferred++; }
long txrelay_sync_deferred_count(void){ return txr_sync_deferred; }
void txrelay_test_set_pending_ttl_ms(long long ms){ txr_pend_ttl_ms = ms; }

/* ---- per-peer request tracking (Core's TxRequestTracker, simplified) ------
 * Every announcement is remembered with WHO announced it (up to 4 legs). A
 * request that is not answered within TXR_REQ_RETRY_MS is retried on a
 * DIFFERENT leg -- an announcer not yet tried, else any other live leg (any
 * peer with the tx in its mempool serves getdata) -- and a notfound fails
 * over immediately. Before this, a lost or refused request simply waited for
 * the next announcement of the same tx, which for a parked orphan's parent
 * usually never came: production 2026-08-31 logged ~1,500 re-requests-after-
 * timeout per 10 minutes with 690 orphans dropping on TTL. Bounded: at most
 * TXR_WANT_TRIES requests per tx, then the entry is dropped (a later inv
 * recreates it). Entries clear on arrival -- keyed by txid AND wtxid, since
 * BIP339 peers announce by wtxid (sha256d of the full serialization). */
#define TXR_WANT_MAX    4096
#define TXR_WANT_PEERS  4
#define TXR_WANT_TRIES  4
#define TXR_REQ_RETRY_MS_DEF 5000
typedef struct {
    u8  hash[32];
    u32 rtype;                  /* the getdata type to use (WITNESS_TX or WTX) */
    int fds[TXR_WANT_PEERS];    /* announcers */
    u8  nfd, tries, inflight, used, ntried;
    int req_fd;                 /* where the in-flight request went */
    int tried_fd[6];            /* every fd this entry was ever requested from */
    long long t_req, t_seen;
} txr_want_t;
static txr_want_t txr_want_tab[TXR_WANT_MAX];
static long long txr_req_retry_ms = TXR_REQ_RETRY_MS_DEF;
static long long txr_retry_last;            /* driver throttle (below) */
static long txr_retry_other, txr_want_gaveup;
void txrelay_test_set_retry_ms(long long ms){ txr_req_retry_ms = ms; txr_retry_last = 0; }
/* legs learned from the polls themselves; "live" = polled within 5 s */
#define TXR_LEG_MAX 16
static struct { int fd; long long t; } txr_legs[TXR_LEG_MAX];
static void txr_note_leg(int fd){
    long long now = txr_now_ms(); int free_i = -1;
    for (int i = 0; i < TXR_LEG_MAX; i++){
        if (txr_legs[i].fd == fd){ txr_legs[i].t = now; return; }
        if (free_i < 0 && now - txr_legs[i].t > 5000) free_i = i;
    }
    if (free_i >= 0){ txr_legs[free_i].fd = fd; txr_legs[free_i].t = now; }
}
static txr_want_t* txr_want_find(const u8* h){
    for (int i = 0; i < TXR_WANT_MAX; i++)
        if (txr_want_tab[i].used && !memcmp(txr_want_tab[i].hash, h, 32)) return &txr_want_tab[i];
    return 0;
}
static void txr_want_clear(const u8* h){
    txr_want_t* w = txr_want_find(h);
    if (w) memset(w, 0, sizeof *w);
}
static void txr_want_note(const u8* h, u32 rtype, int fd, int requested){
    txr_want_t* w = txr_want_find(h);
    if (!w){
        int slot = -1; long long oldest = 0;
        for (int i = 0; i < TXR_WANT_MAX; i++){
            if (!txr_want_tab[i].used){ slot = i; break; }
            if (slot < 0 || txr_want_tab[i].t_seen < oldest || i == 0){ if (i == 0 || txr_want_tab[i].t_seen < oldest){ oldest = txr_want_tab[i].t_seen; slot = i; } }
        }
        w = &txr_want_tab[slot]; memset(w, 0, sizeof *w);
        memcpy(w->hash, h, 32); w->rtype = rtype; w->used = 1;
    }
    w->t_seen = txr_now_ms();
    int have = 0;
    for (int i = 0; i < w->nfd; i++) if (w->fds[i] == fd) have = 1;
    if (!have && w->nfd < TXR_WANT_PEERS) w->fds[w->nfd++] = fd;
    if (requested){
        w->req_fd = fd; w->t_req = txr_now_ms(); w->inflight = 1;
        if (w->tries < 255) w->tries++;
        if (w->ntried < 6) w->tried_fd[w->ntried++] = fd;
    }
}
static int txr_want_tried(const txr_want_t* w, int fd){
    for (int i = 0; i < w->ntried; i++) if (w->tried_fd[i] == fd) return 1;
    return 0;
}
static void txr_leg_dead(int fd){
    for (int i = 0; i < TXR_LEG_MAX; i++) if (txr_legs[i].fd == fd){ txr_legs[i].fd = 0; txr_legs[i].t = 0; }
}
static int txr_leg_alive(int fd){
    for (int i = 0; i < TXR_LEG_MAX; i++)
        if (txr_legs[i].fd == fd && txr_now_ms() - txr_legs[i].t <= 5000) return 1;
    return 0;
}
/* an announcer this entry has not asked yet, else any other live leg it has
 * not asked yet */
static int txr_want_pick(txr_want_t* w){
    for (int i = 0; i < w->nfd; i++)
        if (!txr_want_tried(w, w->fds[i]) && !txr_nf_has(w->fds[i], w->hash) &&
            txr_leg_alive(w->fds[i])) return w->fds[i];
    for (int i = 0; i < TXR_LEG_MAX; i++)
        if (txr_legs[i].fd > 0 && !txr_want_tried(w, txr_legs[i].fd) &&
            !txr_nf_has(txr_legs[i].fd, w->hash) &&
            txr_now_ms() - txr_legs[i].t <= 5000) return txr_legs[i].fd;
    return -1;
}
/* fail over now (timeout or notfound), walking candidates until a write
 * lands: a dead leg is dropped from the registry and the next one is tried,
 * so a stale fd never eats the entry. Drop the entry when candidates or the
 * try budget run out -- a later announcement recreates it. */
static void txr_want_failover(txr_want_t* w){
    for (;;){
        if (w->tries >= TXR_WANT_TRIES){ txr_want_gaveup++; memset(w, 0, sizeof *w); return; }
        int fd = txr_want_pick(w);
        if (fd < 0){ txr_want_gaveup++; memset(w, 0, sizeof *w); return; }
        if (w->ntried < 6) w->tried_fd[w->ntried++] = fd;
        u8 gd[37]; gd[0] = 1;
        gd[1] = (u8)w->rtype; gd[2] = (u8)(w->rtype >> 8); gd[3] = (u8)(w->rtype >> 16); gd[4] = (u8)(w->rtype >> 24);
        memcpy(gd + 5, w->hash, 32);
        if (p2p_write(fd, "getdata", 7, gd, 37) > 0){
            txr_ring_del(w->hash); txr_ring_add(w->hash);   /* refresh the dedup window */
            w->req_fd = fd; w->t_req = txr_now_ms(); w->inflight = 1; w->tries++;
            txr_retry_other++;
            return;
        }
        txr_leg_dead(fd);                                   /* try the next candidate */
    }
}
/* the retry driver: runs from any leg's poll, at most twice a second */
static void txr_retry_timeouts(void* mp){
    long long now = txr_now_ms();
    long long gap = txr_req_retry_ms / 2 < 500 ? txr_req_retry_ms / 2 : 500;
    if (now - txr_retry_last < gap) return;
    txr_retry_last = now;
    for (int i = 0; i < TXR_WANT_MAX; i++){
        txr_want_t* w = &txr_want_tab[i];
        if (!w->used || !w->inflight) continue;
        if (now - w->t_req < txr_req_retry_ms) continue;
        unsigned long got_len;
        if (w->rtype == TXR_MSG_WITNESS_TX && mpool_get(mp, w->hash, &got_len)){ memset(w, 0, sizeof *w); continue; }
        txr_want_failover(w);
    }
}
/* test-only introspection */
void txrelay_debug_dump(void){
    long long now = txr_now_ms();
    fprintf(stderr, "[txr-dump] legs:");
    for (int i = 0; i < TXR_LEG_MAX; i++) if (txr_legs[i].fd) fprintf(stderr, " %d(age %lldms)", txr_legs[i].fd, now - txr_legs[i].t);
    fprintf(stderr, "\n");
    for (int i = 0; i < TXR_WANT_MAX; i++){
        txr_want_t* w = &txr_want_tab[i];
        if (!w->used) continue;
        fprintf(stderr, "[txr-dump] want %02x.. req_fd=%d inflight=%d tries=%d ntried=%d age_req=%lldms announcers:", w->hash[0], w->req_fd, w->inflight, w->tries, w->ntried, now - w->t_req);
        for (int k = 0; k < w->nfd; k++) fprintf(stderr, " %d", w->fds[k]);
        fprintf(stderr, "\n");
    }
}
void txrelay_stats3(long* retried_other, long* gaveup, long* active){
    long n = 0;                 /* requests IN FLIGHT (announcement-only memory is not counted) */
    for (int i = 0; i < TXR_WANT_MAX; i++) if (txr_want_tab[i].used && txr_want_tab[i].inflight) n++;
    if (retried_other) *retried_other = txr_retry_other;
    if (gaveup) *gaveup = txr_want_gaveup;
    if (active) *active = n;
}

long txrelay_poll_leg(int fd, void* mp, int max_ms){
    static u8 pl[TXR_PAYLOAD_CAP];
    static u8 scratch[2000*81 + 8];      /* worker is single-threaded */
    char cmd[12];
    unsigned plen;
    long accepted = 0;
    txr_note_leg(fd);
    txr_retry_timeouts(mp);
    int outstanding = txr_pend_get(fd);  /* getdata entries awaiting replies, carried from the last poll */
    txr_orphan_expire();
    txr_recon_expire();
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
                if (outstanding + (int)want >= 100) break;     /* Core's per-peer in-flight cap */
                const u8* e = pl + cc + i*36;
                if (e + 36 > pl + plen) break;
                unsigned type = (unsigned)e[0] | (unsigned)e[1]<<8 |
                                (unsigned)e[2]<<16 | (unsigned)e[3]<<24;
                /* accept BOTH txid (MSG_TX) and wtxid (MSG_WTX, BIP339)
                 * announcements; blocks are headers-driven keep-up */
                unsigned req_type;
                if (type == TXR_MSG_TX) req_type = TXR_MSG_WITNESS_TX;   /* request witness form */
                else if (type == TXR_MSG_WTX) req_type = TXR_MSG_WTX;    /* wtxid: the getdata echoes it */
                else continue;
                unsigned long got_len;
                txr_want_note(e + 4, req_type, fd, 0);           /* remember the announcer either way */
                if (txr_ring_has(e + 4)) continue;     /* recently requested */
                /* pool-dedup only makes sense for a txid announcement; a
                 * wtxid keys differently, so a wtxid we already hold may be
                 * re-fetched once -- tx_accept's own dedup absorbs it */
                if (type == TXR_MSG_TX && mpool_get(mp, e + 4, &got_len)) continue;
                u8* o = gd + 1 + want*36;
                o[0] = (u8)req_type; o[1] = (u8)(req_type >> 8);
                o[2] = (u8)(req_type >> 16); o[3] = (u8)(req_type >> 24);
                memcpy(o + 4, e + 4, 32);
                txr_ring_add(e + 4);
                txr_want_note(e + 4, req_type, fd, 1);
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
                { extern void sha256d(u8 out[32], const void* p, unsigned long n);
                  u8 wtxid[32]; sha256d(wtxid, pl, plen);       /* BIP339 announcements key by this */
                  txr_want_clear(txid); txr_want_clear(wtxid); }
                long r = tx_accept_validate_p2p(mp, txid, pl, plen);
                if (r == 1){
                    accepted++;
                    txr_ann_add(txid, fd);
                    accepted += txr_orphan_resolve_ann(mp, txid, fd);   /* cascade waiting children */
                } else if (r == -28){
                    /* fee-only reject -- the one verdict a CPFP child can
                     * overturn. If a child is already parked for this
                     * parent, the two go in together; if not, remember the
                     * parent as reconsiderable so that when a child does
                     * turn up we are allowed to fetch this parent again. */
                    long got = txr_try_1p1c(mp, txid, pl, plen);
                    if (got) accepted += got;
                    else     txr_recon_add(txid);
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
                        /* a parent we rejected on fee alone is exactly the
                         * one we DO want again, now that its child is here:
                         * the ring would otherwise suppress the re-fetch
                         * that 1p1c is built on */
                        if (txr_ring_has(par[k]) && !txr_recon_allow_refetch(par[k])) continue;
                        if (mpool_get(mp, par[k], &got_len)) continue;
                        if (txr_nf_has(fd, par[k])){
                            /* THIS peer already notfounded that parent: do
                             * not ask it again -- route the request to
                             * another leg through the want table instead. */
                            txr_want_note(par[k], TXR_MSG_WITNESS_TX, fd, 0);
                            { txr_want_t* w = txr_want_find(par[k]);
                              if (w && !w->inflight){ txr_parent_req++; txr_want_failover(w); } }
                            continue;
                        }
                        u8* o = gd + 1 + want*36;
                        o[0] = (u8)(TXR_MSG_WITNESS_TX);       o[1] = 0;
                        o[2] = 0; o[3] = (u8)(TXR_MSG_WITNESS_TX >> 24);
                        memcpy(o + 4, par[k], 32);
                        txr_ring_add(par[k]);
                        txr_want_note(par[k], TXR_MSG_WITNESS_TX, fd, 1);
                        want++;
                    }
                    if (want){
                        gd[0] = (u8)want;
                        if (p2p_write(fd, "getdata", 7, gd, 1 + want*36) > 0){
                            outstanding += (int)want; txr_parent_req += (long)want;
                        }
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
            unsigned cc;
            unsigned long n = txr_varint(pl, pl + plen, &cc);
            for (unsigned long i = 0; cc && i < n; i++){
                const u8* e = pl + cc + i*36;
                if (e + 36 > pl + plen) break;
                unsigned type = (unsigned)e[0] | (unsigned)e[1]<<8 | (unsigned)e[2]<<16 | (unsigned)e[3]<<24;
                if (type == TXR_MSG_TX || type == TXR_MSG_WITNESS_TX || type == TXR_MSG_WTX){
                    txr_ring_del(e + 4); txr_notfound_seen++;
                    txr_nf_note(fd, e + 4);                   /* never ask this peer for it again */
                    { txr_want_t* w = txr_want_find(e + 4);       /* this peer cannot serve it: ask another NOW */
                      if (w && w->inflight && w->req_fd == fd) txr_want_failover(w); }
                }
            }
            continue;
        }
        if (!memcmp(cmd, "addr", 5) || !memcmp(cmd, "addrv2", 7)){
            long added = txr_addr_ingest(fd, cmd, pl, plen);
            if (added > 0)
                fprintf(stderr, "[txrelay] %s gossip: +%ld address(es) to the book\n", cmd, added);
            continue;
        }
        /* headers/cmpctblock/...: not ours -- same discard the sync drains
         * apply. A `block` push lost here is re-fetched by the next
         * headers-driven pass. */
    }
    txr_pend_set(fd, outstanding);
    return accepted;
}

/* Relay-pool counters for the heartbeat. These existed from the start but
 * nothing ever read them, so the orphan pool's behaviour was invisible in
 * the log -- a pool that was silently dropping everything would have looked
 * exactly like a quiet one. Returns non-zero if anything is worth printing. */
long txrelay_notfound_count(void){ return txr_notfound_seen; }
/* The second stats line: why orphans dropped, and how the parent fetching went. */
void txrelay_stats2(long* ttl, long* evict, long* reject, long* parent_req, long* notfound, long* refetch){
    if (ttl) *ttl = txr_drop_ttl; if (evict) *evict = txr_drop_evict; if (reject) *reject = txr_drop_reject;
    if (parent_req) *parent_req = txr_parent_req; if (notfound) *notfound = txr_notfound_seen; if (refetch) *refetch = txr_req_refetch;
}
long txrelay_stats(long* parked, long* resolved, long* dropped,
                   long* p1c_ok, long* p1c_fail, long* orphans_held){
    long held = 0;
    for (int i = 0; i < TXR_ORPHAN_MAX; i++) if (txr_orph[i].buf) held++;
    if (parked)   *parked   = txr_orph_parked;
    if (resolved) *resolved = txr_orph_resolved;
    if (dropped)  *dropped  = txr_orph_dropped;
    if (p1c_ok)   *p1c_ok   = txr_1p1c_ok;
    if (p1c_fail) *p1c_fail = txr_1p1c_fail;
    if (orphans_held) *orphans_held = held;
    return txr_orph_parked || txr_1p1c_ok || txr_1p1c_fail || held;
}
