/* tests/test_public_tip.c -- 3.1 of docs/audits/UTXO_INLINE_CONNECT_SCOPE.md
 * (2026-09-06): the node's PUBLIC tip is the CONNECTED tip, not the stored
 * one.
 *
 * Two functions carry that rule, and this test drives both against a real
 * store and a real live UTXO set:
 *
 *   utxo_live_public_tip(store, live)  -- daemon/utxo_live.c: what the
 *       download worker reports (status block, heartbeat, the new-block
 *       choke point that feeds ZMQ / -blocknotify / the outbound announce).
 *       With live tracking ON it is min(stored tip, applied height); OFF it
 *       is the stored tip -- the pre-3.1 behaviour, kept as the negative
 *       control.
 *   serve_public_tip(store)            -- daemon/serve_invbounds.c: what the
 *       inbound serve children (bitcoin_serve.asm: getheaders, getblocks,
 *       the tip-watch announce, node_announce_tip) tell a peer. It caps the
 *       stored tip by the connected height the worker publishes into the
 *       shared status block; no pointer registered, or the field at
 *       NODE_TIP_UNTRACKED (-2), means the stored tip.
 *
 * Chain: 11 coinbase-only blocks (0..10). Heights 0..7 are stored and
 * connected, then 8..10 are stored WITHOUT a catch-up -- exactly the
 * download-ahead-of-connect state the parallel downloader produces. The
 * public tip must be 7 while the archive says 10; after the catch-up the
 * two agree at 10; and with tracking off the stored 10 comes back.
 *
 * Watched to FAIL before the change (utxo_live_public_tip returned the
 * stored tip): "store 10 / applied 7 -> public tip 7" reported 10.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "test_tmpdir.h"

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

extern long store_init(void* st);
extern long store_append(void* st, const u8 hash[32], const void* raw, long len);
extern void block_hash(u8 out[32], const u8 hdr[80]);
extern int  pow_check(const u8 hdr[80]);
extern int  tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* buf, unsigned long buflen);

extern int  utxo_live_init(const char* dir);
extern long utxo_live_catchup(void* store_buf);
extern long utxo_live_applied_height(void);
extern long utxo_live_public_tip(void* store_buf, long live);
extern long utxo_live_persisted_height(void);
extern void utxo_live_close(void);

extern void serve_set_connected_tip_ptr(const volatile long long* p);
extern long serve_public_tip(const void* st);

/* bitcoin_mempool_policy.c's object resolves this extern; never reached. */
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u; (void)txid; (void)index; (void)value; (void)script; (void)slen;
    fprintf(stderr, "test_public_tip: unexpected call to mempool_resolve_confirmed_utxo\n");
    abort();
}

static int failures = 0;
static void ck(const char* l, long got, long exp){
    if (got==exp) printf("PASS %s (got %ld)\n", l, got);
    else { printf("FAIL %s got=%ld exp=%ld\n", l, got, exp); failures++; }
}

static void put32(u8* p, u32 v){ p[0]=(u8)v; p[1]=(u8)(v>>8); p[2]=(u8)(v>>16); p[3]=(u8)(v>>24); }
static void put64(u8* p, u64 v){ for(int i=0;i<8;i++) p[i]=(u8)(v>>(8*i)); }
static u8 g_txid_scratch[1<<12];

/* Same shape as test_apply_block_rollback.c's mk_and_mine: one coinbase,
 * scriptPubKey OP_1, minimum difficulty (instant mining). */
static long mk_and_mine(u8* raw, u8 hash[32], const u8 prev[32], u32 tag, u32 tstamp){
    u8 tx[80], txid[32];
    u8* q = tx;
    put32(q,1); q+=4;
    *q++ = 1;
    memset(q,0,32); q+=32;
    put32(q,0xffffffffu); q+=4;
    *q++ = 4; put32(q, tag); q+=4;
    put32(q,0xffffffffu); q+=4;
    *q++ = 1;
    put64(q, 50000000ULL); q+=8;
    *q++ = 1; *q++ = 0x51;
    put32(q,0); q+=4;
    long txlen = q - tx;
    if (!tx_txid(txid, tx, (unsigned long)txlen, g_txid_scratch, sizeof g_txid_scratch)) {
        printf("FAIL tx_txid (coinbase)\n"); failures++;
    }
    u8* o = raw;
    put32(o,1); o+=4;
    memcpy(o, prev, 32); o+=32;
    memcpy(o, txid, 32); o+=32;
    put32(o, tstamp); o+=4;
    put32(o, 0x207fffffu); o+=4;
    put32(o, 0); o+=4;
    *o++ = 1;
    memcpy(o, tx, (size_t)txlen); o += txlen;
    long len = o - raw;
    u32 nonce = 0;
    while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
    block_hash(hash, raw);
    return len;
}

static u8 store_buf[4096];
static u8 prev[32];

static void mine_range(long from, long to){
    for (long h=from; h<=to; h++){
        u8 raw[256], hash[32];
        long len = mk_and_mine(raw, hash, prev, 0x50000000u+(u32)h, 1800000000u+(u32)h);
        long r = store_append(store_buf, hash, raw, len);
        if (r != h) { printf("FAIL store_append h=%ld got=%ld\n", h, r); failures++; }
        memcpy(prev, hash, 32);
    }
}

int main(void){
    tt_isolate();
    memset(store_buf,0,sizeof store_buf);
    memset(prev,0,32);
    ck("store_init", store_init(store_buf), 1);
    ck("utxo_live_init", utxo_live_init("."), 1);

    /* ---- stored 7 / connected 7: the two agree ---- */
    mine_range(0, 7);
    ck("catch-up connects 0..7", utxo_live_catchup(store_buf), 8);
    ck("applied height 7", utxo_live_applied_height(), 7);
    ck("stored 7 / applied 7 -> public tip 7 (live)", utxo_live_public_tip(store_buf, 1), 7);

    /* ---- the archive runs ahead: stored 10, connected still 7 ---- */
    mine_range(8, 10);
    ck("archive tip is 10", (long)*(int*)(store_buf+24), 10);
    ck("applied height still 7 (no catch-up ran)", utxo_live_applied_height(), 7);
    ck("store 10 / applied 7 -> public tip 7 (live)", utxo_live_public_tip(store_buf, 1), 7);
    /* negative control: live tracking OFF = the pre-3.1 node = the stored tip */
    ck("store 10 / applied 7 -> public tip 10 with live tracking OFF (negative control)",
       utxo_live_public_tip(store_buf, 0), 10);

    /* ---- the serve children's reader: caps the stored tip by the published
     * connected height, never raises it, and NODE_TIP_UNTRACKED (-2) means
     * "no cap" ---- */
    volatile long long cap;
    ck("serve_public_tip with no pointer registered = stored 10", serve_public_tip(store_buf), 10);
    serve_set_connected_tip_ptr(&cap);
    cap = 7;   ck("serve_public_tip caps 10 by connected 7 -> 7", serve_public_tip(store_buf), 7);
    cap = 10;  ck("serve_public_tip equal -> 10", serve_public_tip(store_buf), 10);
    cap = 12;  ck("serve_public_tip never raises the stored tip (cap 12 -> 10)", serve_public_tip(store_buf), 10);
    cap = -1;  ck("serve_public_tip: tracking on, nothing connected -> -1", serve_public_tip(store_buf), -1);
    cap = -2;  ck("serve_public_tip: NODE_TIP_UNTRACKED -> stored 10 (negative control)", serve_public_tip(store_buf), 10);
    serve_set_connected_tip_ptr(0);
    ck("serve_public_tip pointer cleared -> stored 10", serve_public_tip(store_buf), 10);

    /* ---- connect the rest: equal again ---- */
    ck("catch-up connects 8..10", utxo_live_catchup(store_buf), 3);
    ck("applied height 10", utxo_live_applied_height(), 10);
    ck("store 10 / applied 10 -> public tip 10 (live)", utxo_live_public_tip(store_buf, 1), 10);
    ck("persisted applied height (what the parent seeds the status block from) is 10",
       utxo_live_persisted_height(), 10);

    utxo_live_close();
    printf("\n%s (%d failures)\n", failures==0 ? "ALL TESTS PASSED" : "TESTS FAILED", failures);
    return failures ? 1 : 0;
}
