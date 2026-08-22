/* tests/test_apply_block_rollback.c -- a block that fails partway through
 * (verification rejects a LATER transaction) must leave the UTXO set
 * byte-identical to its state before the block was attempted -- including
 * undoing the coinbase's own output and any earlier-in-the-same-block
 * transaction that already applied cleanly. Without this, a retry of the
 * same height re-walks from tx 0 and its own first spend of an
 * already-consumed input fails with a confusing "missing/already-spent
 * UTXO" that buries the real rejection reason -- exactly what happened
 * live at height 212613 on 2026-08-19 (the OP_NOP1 bug's real error got
 * hidden behind this artifact on every retry).
 *
 * Chain: heights 0..149 are ordinary coinbase-only blocks (height 0's
 * coinbase scriptPubKey is OP_1, mk_and_mine's own default -- spendable,
 * and mature well past COINBASE_MATURITY=100 by height 150). Height 150 is
 * hand-built with THREE transactions:
 *   tx0 (coinbase): as usual.
 *   tx1: spends height 0's now-mature coinbase output (scriptSig=empty vs
 *        scriptPubKey=OP_1 -- valid) and creates ONE new output whose own
 *        scriptPubKey is OP_0 (a single 0x00 byte -- pushes an empty
 *        array, i.e. deliberately unspendable/always-false).
 *   tx2: spends tx1's just-created output, in the SAME block (the exact
 *        within-block spend-chain shape apply_block_inner's own header
 *        comment calls out) -- scriptSig=empty vs scriptPubKey=OP_0 fails
 *        with SCRIPT_ERR_EVAL_FALSE, rejecting the whole block.
 *
 * If rollback is correct, applying height 150 must fail cleanly (catchup
 * returns -1, applied_height stays at 149) with the live UTXO count back
 * to EXACTLY what it was before the attempt -- coinbase reward, tx1's
 * spend of height 0, and tx1's own created-then-abandoned output all
 * undone together, not just the failing tx2.
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
extern long utxo_live_count(void);
extern long utxo_live_applied_height(void);
extern void utxo_live_close(void);

/* Never actually reached -- every prevout here is already confirmed on
 * chain, not mempool-chained -- but bitcoin_mempool_policy.c's object
 * resolves this extern, so link needs a definition. */
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u; (void)txid; (void)index; (void)value; (void)script; (void)slen;
    fprintf(stderr, "test_apply_block_rollback: unexpected call to mempool_resolve_confirmed_utxo\n");
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

/* Same shape as test_utxo_checkpoint.c's mk_and_mine: one coinbase tx,
 * scriptPubKey = OP_1 (0x51), minimum difficulty (instant mining). */
static long mk_and_mine(u8* raw, u8 hash[32], const u8 prev[32], u32 tag, u32 tstamp){
    u8 tx[64], txid[32];
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

/* One coinbase (OP_1 payout) + tx1 (spends `spend_txid:0`, empty scriptSig,
 * creates one OP_0 output) + tx2 (spends tx1's own output 0, empty
 * scriptSig -- fails EVAL_FALSE against OP_0). Merkle root over 3 leaves,
 * Bitcoin's own duplicate-last-if-odd pairing (sha256d each level). */
static long mk_and_mine_poison(u8* raw, u8 hash[32], const u8 prev[32],
                               const u8 spend_txid[32], u32 tag, u32 tstamp){
    u8 cb[64], cb_txid[32];
    u8* q = cb;
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
    long cblen = q - cb;
    if (!tx_txid(cb_txid, cb, (unsigned long)cblen, g_txid_scratch, sizeof g_txid_scratch)) {
        printf("FAIL tx_txid (poison coinbase)\n"); failures++;
    }

    u8 tx1[128], tx1_txid[32];
    q = tx1;
    put32(q,1); q+=4;
    *q++ = 1;                        /* n_in */
    memcpy(q, spend_txid, 32); q+=32; put32(q,0); q+=4;   /* prevout */
    *q++ = 0;                        /* scriptSig len 0 */
    put32(q,0xffffffffu); q+=4;      /* sequence */
    *q++ = 1;                        /* n_out */
    put64(q, 40000000ULL); q+=8;
    *q++ = 1; *q++ = 0x00;           /* scriptPubKey: OP_0 (always false) */
    put32(q,0); q+=4;                /* locktime */
    long tx1len = q - tx1;
    if (!tx_txid(tx1_txid, tx1, (unsigned long)tx1len, g_txid_scratch, sizeof g_txid_scratch)) {
        printf("FAIL tx_txid (tx1)\n"); failures++;
    }

    u8 tx2[128], tx2_txid[32];
    q = tx2;
    put32(q,1); q+=4;
    *q++ = 1;
    memcpy(q, tx1_txid, 32); q+=32; put32(q,0); q+=4;      /* spends tx1:0 */
    *q++ = 0;
    put32(q,0xffffffffu); q+=4;
    *q++ = 1;
    put64(q, 30000000ULL); q+=8;
    *q++ = 1; *q++ = 0x51;           /* irrelevant -- tx2 fails before this matters */
    put32(q,0); q+=4;
    long tx2len = q - tx2;
    if (!tx_txid(tx2_txid, tx2, (unsigned long)tx2len, g_txid_scratch, sizeof g_txid_scratch)) {
        printf("FAIL tx_txid (tx2)\n"); failures++;
    }

    /* Bitcoin merkle tree, 3 leaves: level 1 = [sha256d(cb||tx1),
     * sha256d(tx2||tx2)] (odd count -> duplicate the last leaf for its
     * pairing), root = sha256d(level1[0] || level1[1]). */
    extern void sha256d(u8 out[32], const void* msg, long len);
    u8 pair[64], h01[32], h22[32], root[32];
    memcpy(pair, cb_txid, 32);  memcpy(pair+32, tx1_txid, 32); sha256d(h01, pair, 64);
    memcpy(pair, tx2_txid, 32); memcpy(pair+32, tx2_txid, 32); sha256d(h22, pair, 64);
    memcpy(pair, h01, 32);      memcpy(pair+32, h22, 32);      sha256d(root, pair, 64);

    u8* o = raw;
    put32(o,1); o+=4;
    memcpy(o, prev, 32); o+=32;
    memcpy(o, root, 32); o+=32;
    put32(o, tstamp); o+=4;
    put32(o, 0x207fffffu); o+=4;
    put32(o, 0); o+=4;
    *o++ = 3;                         /* n_tx */
    memcpy(o, cb, (size_t)cblen); o += cblen;
    memcpy(o, tx1, (size_t)tx1len); o += tx1len;
    memcpy(o, tx2, (size_t)tx2len); o += tx2len;
    long len = o - raw;

    u32 nonce = 0;
    while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
    block_hash(hash, raw);
    return len;
}

static u8 store_buf[4096];

int main(void){
    tt_isolate();
    memset(store_buf,0,sizeof store_buf);
    ck("store_init", store_init(store_buf), 1);
    ck("utxo_live_init", utxo_live_init("."), 1);

    /* Heights 0..149: ordinary coinbase-only chain. Height 0's coinbase is
     * what tx1 spends at height 150 (conf = 150, well past the 100-block
     * maturity rule). */
    long n1 = 150;
    u8 prev[32]; memset(prev,0,32);
    u8 height0_txid[32];
    for (long h=0; h<n1; h++){
        u8 raw[256], hash[32];
        long len = mk_and_mine(raw, hash, prev, 0x50000000u+(u32)h, 1800000000u+(u32)h);
        long r = store_append(store_buf, hash, raw, len);
        if (r != h) { printf("FAIL store_append h=%ld got=%ld\n", h, r); failures++; }
        if (h==0){
            /* the coinbase txid is the merkle root of a single-tx block */
            u8 blk_hdr[80]; memcpy(blk_hdr, raw, 80);
            memcpy(height0_txid, blk_hdr+36, 32);
        }
        memcpy(prev, hash, 32);
    }

    long applied1 = utxo_live_catchup(store_buf);
    ck("clean chain (0..149) catch-up applied exactly n1 blocks", applied1, n1);
    ck("applied_height after clean catch-up", utxo_live_applied_height(), n1-1);
    long count_before = utxo_live_count();
    printf("live UTXO count before the poison block: %ld\n", count_before);

    /* Height 150: coinbase + tx1 (spends height 0, creates an OP_0 output)
     * + tx2 (spends tx1's output, fails EVAL_FALSE). */
    {
        u8 raw[512], hash[32];
        long len = mk_and_mine_poison(raw, hash, prev, height0_txid, 0x60000000u, 1800100000u);
        long r = store_append(store_buf, hash, raw, len);
        if (r != n1) { printf("FAIL store_append (poison) got=%ld\n", r); failures++; }
    }

    long applied2 = utxo_live_catchup(store_buf);
    ck("poisoned height 150 fails the whole catch-up call", applied2, -1);
    ck("applied_height did NOT advance past the failed height",
       utxo_live_applied_height(), n1-1);
    ck("live UTXO count is back to EXACTLY pre-attempt (coinbase + tx1 spend "
       "+ tx1's own created output all rolled back together)",
       utxo_live_count(), count_before);

    /* Retry the SAME failing catch-up call again -- must fail the SAME way
     * every time (deterministic), not cascade into a DIFFERENT error on
     * the second attempt the way the unfixed code did in production
     * (REJECT tx=112 legacy-script-verification-failed on the first
     * attempt, then REJECT tx=1 missing-UTXO on every retry after). */
    long applied3 = utxo_live_catchup(store_buf);
    ck("retry fails the same way (still -1), not a cascaded different error", applied3, -1);
    ck("applied_height still unchanged after the retry",
       utxo_live_applied_height(), n1-1);
    ck("live UTXO count still exactly pre-attempt after the retry",
       utxo_live_count(), count_before);

    utxo_live_close();
    printf("\n%s (%d failures)\n", failures==0 ? "ALL TESTS PASSED" : "TESTS FAILED", failures);
    return failures ? 1 : 0;
}
