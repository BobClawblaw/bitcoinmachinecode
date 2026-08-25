/* tests/test_utxo_ghost_resume.c -- a MULTI-BLOCK ghost run (blocks durably
 * applied in a previous process without their checkpoints landing) must be
 * fully healed on resume, and re-applying a ghost block must never destroy
 * its own repair data.
 *
 * This is the production failure of 2026-08-24 at height 963915, distilled:
 *
 *   - test_utxo_catchup_crash_resume.c already proves the ONE-block window
 *     (kill between "block N durable in WAL" and "checkpoint N persisted")
 *     heals at boot via utxo_live_recover_partial_block.
 *   - But the drift is only guaranteed <= 1 block when every checkpoint
 *     persists. A failing persist_applied_height used to warn AND CONTINUE
 *     ("safe, puts/dels are idempotent" -- false since Stage D verifies
 *     before applying), and the reorg reconnect's checkpoint failure also
 *     continues -- so the ghost run can be several blocks deep.
 *   - With a multi-block run, boot recovery healed only applied+1. When
 *     catch-up then reached the NEXT ghost, apply_block_at blindly
 *     undo_discard()ed that height "so a fresh apply starts clean" --
 *     destroying the one piece of data that could reverse the ghost -- and
 *     then rejected the block on the ghost's own already-spent inputs.
 *     From that moment the state was unrecoverable and the daemon's
 *     DEGRADED retry loop span forever.
 *
 * The fix under test: (1) utxo_live_recover_partial_block rolls back the
 * WHOLE contiguous ghost run, descending (disconnect is LIFO); (2)
 * apply_block_at's ghost guard -- an undo file at a height ABOVE the
 * checkpoint is rolled back, not discarded, before the fresh apply.
 *
 * The blocks chain spends ACROSS the ghost run (151 spends 150's tx output,
 * 152 spends 151's) so the LIFO rollback order is load-bearing: rolling the
 * run back in the wrong order, or only partially, leaves inputs missing and
 * the re-apply rejects.
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
extern int  utxo_live_apply_block(const void* blockbuf, u64 blocklen, long height);

/* Linked object resolves this extern; never reached here (no mempool chains). */
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u; (void)txid; (void)index; (void)value; (void)script; (void)slen;
    fprintf(stderr, "test_utxo_ghost_resume: unexpected mempool_resolve_confirmed_utxo\n");
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

/* Coinbase-only block, scriptPubKey OP_1, min difficulty (same shape as
 * test_utxo_catchup_crash_resume.c). Returns len; fills hash + cb txid. */
static long mk_and_mine(u8* raw, u8 hash[32], u8 cb_txid_out[32],
                        const u8 prev[32], u32 tag, u32 tstamp){
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
    if (cb_txid_out) memcpy(cb_txid_out, txid, 32);

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

/* Coinbase + tx1 spending `spend_txid`:0 (empty scriptSig vs OP_1 -- valid),
 * creating one new OP_1 output. Fills tx1's txid so the NEXT block can chain
 * its spend onto this one. */
static long mk_and_mine_spend(u8* raw, u8 hash[32], u8 tx1_txid_out[32],
                              const u8 prev[32], const u8 spend_txid[32],
                              u32 tag, u32 tstamp){
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
        printf("FAIL tx_txid (spend-block coinbase)\n"); failures++;
    }

    u8 tx1[128], tx1_txid[32];
    q = tx1;
    put32(q,1); q+=4;
    *q++ = 1;
    memcpy(q, spend_txid, 32); q+=32; put32(q,0); q+=4;
    *q++ = 0;
    put32(q,0xffffffffu); q+=4;
    *q++ = 1;
    put64(q, 40000000ULL); q+=8;
    *q++ = 1; *q++ = 0x51;
    put32(q,0); q+=4;
    long tx1len = q - tx1;
    if (!tx_txid(tx1_txid, tx1, (unsigned long)tx1len, g_txid_scratch, sizeof g_txid_scratch)) {
        printf("FAIL tx_txid (tx1)\n"); failures++;
    }
    if (tx1_txid_out) memcpy(tx1_txid_out, tx1_txid, 32);

    u8 pair[64], root[32];
    memcpy(pair, cb_txid, 32); memcpy(pair+32, tx1_txid, 32);
    sha256d(root, pair, 64);

    u8* o = raw;
    put32(o,1); o+=4;
    memcpy(o, prev, 32); o+=32;
    memcpy(o, root, 32); o+=32;
    put32(o, tstamp); o+=4;
    put32(o, 0x207fffffu); o+=4;
    put32(o, 0); o+=4;
    *o++ = 2;
    memcpy(o, cb, (size_t)cblen); o += cblen;
    memcpy(o, tx1, (size_t)tx1len); o += tx1len;
    long len = o - raw;

    u32 nonce = 0;
    while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
    block_hash(hash, raw);
    return len;
}

static u8 store_buf[4096];
static u8 raw[4096];
static u8 blk151[4096], blk152[4096], blk153[4096];
static long len151, len152, len153;

int main(void){
    tt_isolate();
    memset(store_buf,0,sizeof store_buf);
    ck("store_init", store_init(store_buf), 1);
    ck("utxo_live_init", utxo_live_init("."), 1);

    /* Heights 0..149: coinbase-only. Height 0's coinbase matures far before
     * the spend at height 150 (conf=150 >= 100). */
    u8 prev[32]; memset(prev,0,32);
    u8 height0_txid[32];
    for (long h=0; h<150; h++){
        u8 hash[32], cbt[32];
        long len = mk_and_mine(raw, hash, cbt, prev, (u32)h, 1600000000u + (u32)h);
        if (h==0) memcpy(height0_txid, cbt, 32);
        if (store_append(store_buf, hash, raw, len) != h){ printf("FAIL append h=%ld\n", h); failures++; }
        memcpy(prev, hash, 32);
    }
    /* Height 150: spends height 0's coinbase, creating chainable output A. */
    u8 hash150[32], txA[32];
    long len150 = mk_and_mine_spend(raw, hash150, txA, prev, height0_txid, 150, 1600000150u);
    ck("append 150", store_append(store_buf, hash150, raw, len150), 150);
    memcpy(prev, hash150, 32);

    ck("catchup applies 0..150", utxo_live_catchup(store_buf), 151);
    ck("checkpointed at 150", utxo_live_applied_height(), 150);
    long count150 = utxo_live_count();
    ck("count == height+1 invariant (each block nets +1)", count150, 151);

    /* Heights 151/152: a chained spend run -- 151 spends A creating B, 152
     * spends B creating C. Appended to the store, then applied WITHOUT
     * checkpoints (utxo_live_apply_block does not persist a height; the
     * reorg driver persists separately) => a 2-block GHOST RUN, exactly what
     * a dead process leaves when its checkpoints never landed. */
    u8 hash151[32], txB[32], hash152[32], txC[32];
    len151 = mk_and_mine_spend(blk151, hash151, txB, prev, txA, 151, 1600000151u);
    ck("append 151", store_append(store_buf, hash151, blk151, len151), 151);
    memcpy(prev, hash151, 32);
    len152 = mk_and_mine_spend(blk152, hash152, txC, prev, txB, 152, 1600000152u);
    ck("append 152", store_append(store_buf, hash152, blk152, len152), 152);
    memcpy(prev, hash152, 32);

    ck("ghost-apply 151", utxo_live_apply_block(blk151, (u64)len151, 151), 1);
    ck("ghost-apply 152", utxo_live_apply_block(blk152, (u64)len152, 152), 1);
    ck("checkpoint still 150 (ghosts un-checkpointed)", utxo_live_applied_height(), 150);

    /* Process restart. Old code: boot recovery healed 151 only, then
     * catch-up's blind undo_discard destroyed 152's repair data and the
     * re-apply REJECTed on 152's own already-spent inputs (returned -1).
     * New code: recovery rolls back BOTH ghosts (152 then 151 -- LIFO), and
     * catch-up re-applies 151..152 cleanly. */
    utxo_live_close();
    ck("re-init (simulated restart)", utxo_live_init("."), 1);
    ck("resume catchup heals the 2-block ghost run", utxo_live_catchup(store_buf), 2);
    ck("applied lands at 152", utxo_live_applied_height(), 152);
    ck("count consistent after heal", utxo_live_count(), 153);

    /* The guard alone, same process (the DEGRADED-retry-loop shape): ghost-
     * apply 153, then apply it AGAIN. Old code: undo_discard destroyed the
     * ghost's undo data and the re-apply rejected (0). New code: the guard
     * rolls the ghost back and the fresh apply succeeds (1). */
    u8 hash153[32], txD[32];
    len153 = mk_and_mine_spend(blk153, hash153, txD, prev, txC, 153, 1600000153u);
    ck("append 153", store_append(store_buf, hash153, blk153, len153), 153);
    ck("ghost-apply 153", utxo_live_apply_block(blk153, (u64)len153, 153), 1);
    ck("re-apply of ghost 153 heals via the guard", utxo_live_apply_block(blk153, (u64)len153, 153), 1);
    ck("count consistent after guard re-apply", utxo_live_count(), 154);

    /* And the healed state must still be fully usable: catch-up sees 153
     * as the tip; a fresh restart replays nothing and rejects nothing. */
    utxo_live_close();
    ck("final re-init", utxo_live_init("."), 1);
    long r = utxo_live_catchup(store_buf);
    ck("final catchup clean (heals 153's ghost then stops at tip)", (r >= 0), 1);
    ck("final applied 153", utxo_live_applied_height(), 153);
    ck("final count 154", utxo_live_count(), 154);

    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL TESTS PASSED\n", failures);
    return failures ? 1 : 0;
}
