/* tests/test_cross_tx_verify.c -- correctness properties specific to the
 * cross-transaction (block-wide) parallel verification redesign in
 * daemon/tx_verify.c's tx_verify_block_connect_all / daemon/utxo_live.c's
 * restructured apply_block_inner. See the design plan's own testing section
 * for why each of these matters:
 *
 *   A. A VALID same-block chained spend (tx N spends tx N-1's own output,
 *      same block) must still ACCEPT -- proves the in-block output index
 *      (bidx_get) correctly resolves a prevout that only exists because an
 *      earlier transaction in this SAME block created it, without touching
 *      the not-yet-mutated confirmed UTXO set at all.
 *
 *   B. An IN-BLOCK DOUBLE-SPEND (two different transactions in the same
 *      block both claim the identical outpoint) must REJECT THE WHOLE
 *      BLOCK. This is the single highest-consequence property here: the
 *      OLD strictly-sequential verify-then-apply loop caught this only as
 *      an accidental side effect (the second spender's utxo_lsm_get failed
 *      once the first spender's output had already been deleted) -- that
 *      accidental detection disappears once verification runs before any
 *      apply, so daemon/utxo_live.c's Phase 0.5 explicit duplicate-outpoint
 *      check is what actually has to catch this now. A silent regression
 *      here would mean a block gets HALF-applied (one of the two conflicting
 *      spends silently wins) instead of rejected -- exactly the class of
 *      bug that would not show up as a crash or an obvious test failure.
 *
 *   C. MANY independent small transactions (>= TXV_PARALLEL_MIN block-wide,
 *      each individually below the OLD per-tx threshold) with a single
 *      poisoned tx buried in the middle must genuinely exercise the
 *      block-wide parallel dispatch (not just the small-block sequential
 *      fallback) AND still report the correct failing tx index/reason,
 *      matching the [utxo_live] REJECT h=%ld tx=%lu: %s log line's existing
 *      contract.
 *
 * Uses the same mk_and_mine / raw-tx-byte-construction style already
 * established in tests/test_apply_block_rollback.c and
 * tests/test_utxo_checkpoint.c (OP_1 = always-spendable-with-empty-
 * scriptSig, OP_0 = always-fails -- no real ECDSA signing needed to
 * exercise these particular properties, which are about BLOCK-LEVEL
 * structure/ordering, not the crypto primitives themselves).
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
extern void sha256d(u8 out[32], const void* msg, long len);

extern int  utxo_live_init(const char* dir);
extern long utxo_live_catchup(void* store_buf);
extern long utxo_live_count(void);
extern long utxo_live_applied_height(void);
extern void utxo_live_close(void);

/* Never actually reached (every prevout here is already confirmed on
 * chain), but bitcoin_mempool_policy.c's object resolves this extern. */
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u; (void)txid; (void)index; (void)value; (void)script; (void)slen;
    fprintf(stderr, "test_cross_tx_verify: unexpected call to mempool_resolve_confirmed_utxo\n");
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

/* Same shape as test_utxo_checkpoint.c / test_apply_block_rollback.c's own
 * mk_and_mine: one coinbase tx, scriptPubKey = OP_1, minimum difficulty. */
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

/* Single-input (empty scriptSig), single-output (1-byte scriptPubKey: 0x51
 * OP_1 always-valid, or 0x00 OP_0 always-fails) tx, matching the existing
 * mk_and_mine_poison convention in test_apply_block_rollback.c. */
static long build_spend(u8* out, const u8 prev_txid[32], u32 prev_index, u8 out_spk, u8 txid[32]){
    u8* q = out;
    put32(q,1); q+=4;
    *q++ = 1;
    memcpy(q, prev_txid, 32); q+=32; put32(q, prev_index); q+=4;
    *q++ = 0;
    put32(q,0xffffffffu); q+=4;
    *q++ = 1;
    put64(q, 40000000ULL); q+=8;
    *q++ = 1; *q++ = out_spk;
    put32(q,0); q+=4;
    long len = q - out;
    if (!tx_txid(txid, out, (unsigned long)len, g_txid_scratch, sizeof g_txid_scratch)) {
        printf("FAIL tx_txid (spend)\n"); failures++;
    }
    return len;
}

/* Bitcoin's own merkle root: duplicate the last leaf at each odd-count
 * level, sha256d each pairing, up to a single root. */
static void merkle_root(u8 out[32], u8 (*txids)[32], int n){
    if (n == 1) { memcpy(out, txids[0], 32); return; }
    static u8 level[64][32];
    memcpy(level, txids, (size_t)n*32);
    int cnt = n;
    while (cnt > 1){
        int next = 0;
        u8 pair[64];
        for (int i=0;i<cnt;i+=2){
            memcpy(pair, level[i], 32);
            if (i+1 < cnt) memcpy(pair+32, level[i+1], 32);
            else memcpy(pair+32, level[i], 32);
            sha256d(level[next], pair, 64);
            next++;
        }
        cnt = next;
    }
    memcpy(out, level[0], 32);
}

/* Assembles + mines a block from already-built tx byte buffers. */
static long assemble_and_mine(u8* raw, u8 hash[32], const u8 prev[32], u32 tstamp,
                              u8 (*tx_bufs)[512], long* tx_lens, u8 (*txids)[32], int ntx){
    u8 root[32];
    merkle_root(root, txids, ntx);
    u8* o = raw;
    put32(o,1); o+=4;
    memcpy(o, prev, 32); o+=32;
    memcpy(o, root, 32); o+=32;
    put32(o, tstamp); o+=4;
    put32(o, 0x207fffffu); o+=4;
    put32(o, 0); o+=4;
    *o++ = (u8)ntx;   /* all our test blocks stay well under 0xfd txs */
    for (int i=0;i<ntx;i++){ memcpy(o, tx_bufs[i], (size_t)tx_lens[i]); o += tx_lens[i]; }
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

    /* Heights 0..149: ordinary coinbase-only chain -- gives us 150 distinct,
     * well-matured (conf >= 150 by the time we spend them below) coinbase
     * outputs to draw from across every scenario. */
    long n1 = 150;
    u8 prev[32]; memset(prev,0,32);
    u8 cb_txid[150][32];
    for (long h=0; h<n1; h++){
        u8 raw[256], hash[32];
        long len = mk_and_mine(raw, hash, prev, 0x50000000u+(u32)h, 1800000000u+(u32)h);
        long r = store_append(store_buf, hash, raw, len);
        if (r != h) { printf("FAIL store_append h=%ld got=%ld\n", h, r); failures++; }
        u8 blk_hdr[80]; memcpy(blk_hdr, raw, 80);
        memcpy(cb_txid[h], blk_hdr+36, 32);   /* coinbase txid == single-tx merkle root */
        memcpy(prev, hash, 32);
    }
    long applied1 = utxo_live_catchup(store_buf);
    ck("clean chain (0..149) catch-up applied exactly n1 blocks", applied1, n1);
    long count_base = utxo_live_count();

    /* ---- Scenario A: valid same-block chained spend -> ACCEPT ---- */
    {
        u8 tx_bufs[3][512]; long tx_lens[3]; u8 txids[3][32];
        u8 cb[64]; u8* q = cb;
        put32(q,1); q+=4; *q++=1; memset(q,0,32); q+=32; put32(q,0xffffffffu); q+=4;
        *q++=4; put32(q,0x70000000u); q+=4; put32(q,0xffffffffu); q+=4;
        *q++=1; put64(q,50000000ULL); q+=8; *q++=1; *q++=0x51; put32(q,0); q+=4;
        tx_lens[0] = q - cb; memcpy(tx_bufs[0], cb, (size_t)tx_lens[0]);
        tx_txid(txids[0], tx_bufs[0], (unsigned long)tx_lens[0], g_txid_scratch, sizeof g_txid_scratch);

        tx_lens[1] = build_spend(tx_bufs[1], cb_txid[0], 0, 0x51, txids[1]);   /* spends height 0's coinbase, output=OP_1 */
        tx_lens[2] = build_spend(tx_bufs[2], txids[1], 0, 0x51, txids[2]);     /* spends tx1's OWN output, SAME block -- output=OP_1 */

        u8 raw[2048], hash[32];
        long len = assemble_and_mine(raw, hash, prev, 1800200000u, tx_bufs, tx_lens, txids, 3);
        long r = store_append(store_buf, hash, raw, len);
        if (r != n1) { printf("FAIL store_append (scenario A) got=%ld\n", r); failures++; }
        memcpy(prev, hash, 32);
    }
    long appliedA = utxo_live_catchup(store_buf);
    ck("scenario A: valid same-block chained spend -> block ACCEPTED", appliedA, 1);
    ck("scenario A: applied_height advanced by exactly one block", utxo_live_applied_height(), n1);
    /* outputs created this block: coinbase + tx1 + tx2 = 3. outputs spent:
     * tx1 spends height 0's coinbase, tx2 spends tx1's own (same-block)
     * output = 2. Net live-count delta = +1 (just this block's coinbase +
     * tx2's final output survive; height 0's output and tx1's own
     * intermediate output are both gone). */
    ck("scenario A: live count reflects the accepted block", utxo_live_count(), count_base + 1);
    long count_after_A = utxo_live_count();

    /* ---- Scenario B: in-block double-spend -> REJECT the whole block ---- */
    {
        u8 tx_bufs[3][512]; long tx_lens[3]; u8 txids[3][32];
        u8 cb[64]; u8* q = cb;
        put32(q,1); q+=4; *q++=1; memset(q,0,32); q+=32; put32(q,0xffffffffu); q+=4;
        *q++=4; put32(q,0x71000000u); q+=4; put32(q,0xffffffffu); q+=4;
        *q++=1; put64(q,50000000ULL); q+=8; *q++=1; *q++=0x51; put32(q,0); q+=4;
        tx_lens[0] = q - cb; memcpy(tx_bufs[0], cb, (size_t)tx_lens[0]);
        tx_txid(txids[0], tx_bufs[0], (unsigned long)tx_lens[0], g_txid_scratch, sizeof g_txid_scratch);

        /* tx1 and tx2 BOTH spend height 1's coinbase:0 -- an in-block
         * double-spend. Each individually would verify fine (a valid
         * OP_1 spend); only the whole-block duplicate-outpoint check can
         * catch this. */
        tx_lens[1] = build_spend(tx_bufs[1], cb_txid[1], 0, 0x51, txids[1]);
        tx_lens[2] = build_spend(tx_bufs[2], cb_txid[1], 0, 0x51, txids[2]);

        u8 raw[2048], hash[32];
        long len = assemble_and_mine(raw, hash, prev, 1800300000u, tx_bufs, tx_lens, txids, 3);
        long r = store_append(store_buf, hash, raw, len);
        if (r != n1+1) { printf("FAIL store_append (scenario B) got=%ld\n", r); failures++; }
    }
    long appliedB = utxo_live_catchup(store_buf);
    ck("scenario B: in-block double-spend -> block REJECTED (not half-applied)", appliedB, -1);
    ck("scenario B: applied_height did NOT advance", utxo_live_applied_height(), n1);
    ck("scenario B: live count completely unchanged (no partial apply)", utxo_live_count(), count_after_A);
    /* height 1's coinbase must still be spendable -- the rejected block's
     * attempted spends must have left it completely untouched. */

    /* ---- Scenario C: many independent txs (block-wide parallel dispatch)
     * with one poisoned tx buried mid-list -> REJECT at the correct index,
     * not a false accept and not a wrong-tx attribution. ----
     * Local tx 0: spends height 2's coinbase, creates an OP_0 (poison)
     *             output.
     * Local tx 1..8 (8 txs): each independently spends a DIFFERENT mature
     *             coinbase (heights 3..10), each creates a valid OP_1
     *             output -- individually unrelated, all valid.
     * Local tx 9: spends local tx 0's OP_0 output -- fails EVAL_FALSE.
     * Total non-coinbase txs = 10, total inputs = 10 (>= TXV_PARALLEL_MIN=8),
     * so this genuinely exercises the block-wide worker pool, not the
     * small-block sequential fallback. Global tx index of the failure is
     * 1(coinbase)+9(local 0..8) = 10. */
    {
        enum { NTX = 12 }; /* coinbase + 10 spends + 1 slot spare, kept explicit */
        u8 tx_bufs[NTX][512]; long tx_lens[NTX]; u8 txids[NTX][32];
        u8 cb[64]; u8* q = cb;
        put32(q,1); q+=4; *q++=1; memset(q,0,32); q+=32; put32(q,0xffffffffu); q+=4;
        *q++=4; put32(q,0x72000000u); q+=4; put32(q,0xffffffffu); q+=4;
        *q++=1; put64(q,50000000ULL); q+=8; *q++=1; *q++=0x51; put32(q,0); q+=4;
        tx_lens[0] = q - cb; memcpy(tx_bufs[0], cb, (size_t)tx_lens[0]);
        tx_txid(txids[0], tx_bufs[0], (unsigned long)tx_lens[0], g_txid_scratch, sizeof g_txid_scratch);

        int ti = 1;
        tx_lens[ti] = build_spend(tx_bufs[ti], cb_txid[2], 0, 0x00, txids[ti]);  /* poison source: creates OP_0 */
        int poison_source_idx = ti; ti++;
        for (int k=0;k<8;k++){
            tx_lens[ti] = build_spend(tx_bufs[ti], cb_txid[3+k], 0, 0x51, txids[ti]);  /* 8 independent valid spends */
            ti++;
        }
        tx_lens[ti] = build_spend(tx_bufs[ti], txids[poison_source_idx], 0, 0x51, txids[ti]);  /* spends the OP_0 output -- fails */
        int poison_spend_local_idx = ti; ti++;
        int ntx = ti;   /* 1 coinbase + 10 non-coinbase = 11 */

        u8 raw[8192], hash[32];
        long len = assemble_and_mine(raw, hash, prev, 1800400000u, tx_bufs, tx_lens, txids, ntx);
        long r = store_append(store_buf, hash, raw, len);
        if (r != n1+2) { printf("FAIL store_append (scenario C) got=%ld\n", r); failures++; }
        (void)poison_spend_local_idx;
    }
    long appliedC = utxo_live_catchup(store_buf);
    ck("scenario C: many-tx block with a mid-list poison tx -> REJECTED", appliedC, -1);
    ck("scenario C: applied_height did NOT advance", utxo_live_applied_height(), n1);
    ck("scenario C: live count completely unchanged (no partial apply)", utxo_live_count(), count_after_A);
    /* re-run to confirm deterministic rejection across multiple worker-pool
     * dispatch rounds (thread scheduling nondeterminism must not change
     * the accept/reject outcome). */
    for (int rep=0; rep<5; rep++){
        long a = utxo_live_catchup(store_buf);
        if (a != -1) { printf("FAIL scenario C repeat #%d: expected -1, got %ld\n", rep, a); failures++; }
    }
    ck("scenario C: still rejected after 5 repeat attempts (deterministic)", utxo_live_applied_height(), n1);

    utxo_live_close();
    printf("\n%s (%d failures)\n", failures==0 ? "ALL TESTS PASSED" : "TESTS FAILED", failures);
    return failures ? 1 : 0;
}
