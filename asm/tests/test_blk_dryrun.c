/* tests/test_blk_dryrun.c -- utxo_live_dryrun_block: the submitblock connect
 * step's safety gate. The dry run executes the SAME verification phases the
 * real apply does (parse, witness commitment, BIP30, in-block dup, full
 * script verify) and stops at the Phase 5 boundary -- the first mutation.
 * Three properties proven on a real synthetic chain (the
 * test_apply_block_rollback fixture):
 *   PURITY    a clean dry run changes NOTHING (count, applied height).
 *   REASONS   a rejecting dry run reports the reject reason and also
 *             changes nothing.
 *   COHERENCE the exact block a dry run passed then APPLIES cleanly
 *             through the normal store_append + catch-up pipeline -- the
 *             property the connect step's correctness argument rests on.
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
extern long utxo_live_dryrun_block(const u8* blockbuf, u64 blocklen, long height);
extern const char* utxo_live_last_reject(void);

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u;(void)txid;(void)index;(void)value;(void)script;(void)slen;
    fprintf(stderr, "test_blk_dryrun: unexpected mempool_resolve_confirmed_utxo\n");
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

static long mk_coinbase(u8* tx, u8 txid[32], u32 tag){
    u8* q = tx;
    put32(q,1); q+=4; *q++ = 1;
    memset(q,0,32); q+=32; put32(q,0xffffffffu); q+=4;
    *q++ = 4; put32(q, tag); q+=4; put32(q,0xffffffffu); q+=4;
    *q++ = 1; put64(q, 50000000ULL); q+=8; *q++ = 1; *q++ = 0x51;
    put32(q,0); q+=4;
    long n = q - tx;
    tx_txid(txid, tx, (unsigned long)n, g_txid_scratch, sizeof g_txid_scratch);
    return n;
}
static long mk_and_mine(u8* raw, u8 hash[32], const u8 prev[32], u32 tag, u32 tstamp){
    /* 80, not 64: the hand-built coinbase is 65 bytes -- a 64-byte buffer
     * overflowed by one byte, and where that byte landed depended on the
     * BINARY's stack layout (adding any code moved it). Found because this
     * test's layout put the clobber inside the tx bytes AFTER the txid was
     * computed: merkle != embedded tx -> the spend referenced a key the
     * store never had. test_apply_block_rollback had the same latent bug
     * and passed by layout luck. */
    u8 tx[80], txid[32];
    long txlen = mk_coinbase(tx, txid, tag);
    u8* o = raw;
    put32(o,1); o+=4; memcpy(o, prev, 32); o+=32; memcpy(o, txid, 32); o+=32;
    put32(o, tstamp); o+=4; put32(o, 0x207fffffu); o+=4; put32(o, 0); o+=4;
    *o++ = 1; memcpy(o, tx, (size_t)txlen); o += txlen;
    long len = o - raw;
    u32 nonce = 0;
    while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
    block_hash(hash, raw);
    return len;
}
/* coinbase + one spend of `spend_txid:0` (OP_1 prevout, empty scriptSig --
 * valid); poison=1 swaps the spend's prevout for a NONEXISTENT txid so the
 * script-verify phase rejects (missing UTXO), exercising the reason path. */
static long mk_and_mine_spend(u8* raw, u8 hash[32], const u8 prev[32],
                              const u8 spend_txid[32], u32 tag, u32 tstamp, int poison){
    u8 cb[80], cb_txid[32];   /* 65-byte coinbase: 64 overflowed by one */
    long cblen = mk_coinbase(cb, cb_txid, tag);
    u8 tx1[128], tx1_txid[32];
    u8* q = tx1;
    put32(q,1); q+=4; *q++ = 1;
    memcpy(q, spend_txid, 32); if (poison) q[0] ^= 0xFF; q+=32; put32(q,0); q+=4;
    *q++ = 0; put32(q,0xffffffffu); q+=4;
    *q++ = 1; put64(q, 40000000ULL); q+=8; *q++ = 1; *q++ = 0x51;
    put32(q,0); q+=4;
    long tx1len = q - tx1;
    tx_txid(tx1_txid, tx1, (unsigned long)tx1len, g_txid_scratch, sizeof g_txid_scratch);
    u8 pair[64], root[32];
    memcpy(pair, cb_txid, 32); memcpy(pair+32, tx1_txid, 32); sha256d(root, pair, 64);
    u8* o = raw;
    put32(o,1); o+=4; memcpy(o, prev, 32); o+=32; memcpy(o, root, 32); o+=32;
    put32(o, tstamp); o+=4; put32(o, 0x207fffffu); o+=4; put32(o, 0); o+=4;
    *o++ = 2;
    memcpy(o, cb, (size_t)cblen); o += cblen;
    memcpy(o, tx1, (size_t)tx1len); o += tx1len;
    long len = o - raw;
    u32 nonce = 0;
    while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
    block_hash(hash, raw);
    return len;
}

static long mk_and_mine_poison(u8* raw, u8 hash[32], const u8 prev[32],
                               const u8 spend_txid[32], u32 tag, u32 tstamp){
    u8 cb[80], cb_txid[32];   /* 65-byte coinbase: 64 overflowed by one */
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

    long n1 = 150;
    u8 prev[32]; memset(prev,0,32);
    u8 height0_txid[32];
    for (long h=0; h<n1; h++){
        u8 raw[256], hash[32];
        long len = mk_and_mine(raw, hash, prev, 0x50000000u+(u32)h, 1800000000u+(u32)h);
        if (store_append(store_buf, hash, raw, len) != h){ printf("FAIL append h=%ld\n",h); failures++; }
        if (h==0) memcpy(height0_txid, raw+36, 32);
        memcpy(prev, hash, 32);
    }
    ck("catch-up applied 0..149", utxo_live_catchup(store_buf), n1);
    long count0 = utxo_live_count();
    long applied0 = utxo_live_applied_height();
    ck("applied height 149", applied0, n1-1);

    /* ---- PURITY: dry-run of a VALID next block mutates nothing ---- */
    static u8 valid[512]; u8 vhash[32];
    long vlen = mk_and_mine_spend(valid, vhash, prev, height0_txid, 0x60000000u, 1800100000u, 0);
    ck("dry run of the valid block -> 1", utxo_live_dryrun_block(valid, (u64)vlen, n1), 1);
    ck("PURITY: UTXO count unchanged after clean dry run", utxo_live_count(), count0);
    ck("PURITY: applied height unchanged", utxo_live_applied_height(), applied0);

    /* ---- REASONS: dry-run of a bad-spend block rejects + mutates nothing ---- */
    { static u8 bad[512]; u8 bhash[32];
      long blen = mk_and_mine_spend(bad, bhash, prev, height0_txid, 0x61000000u, 1800100001u, 1);
      ck("dry run of the missing-input block -> 0", utxo_live_dryrun_block(bad, (u64)blen, n1), 0);
      const char* rr = utxo_live_last_reject();
      printf("reject reason: [%s]\n", rr ? rr : "(null)");
      ck("reject reason captured (non-empty)", rr && rr[0] ? 1 : 0, 1);
      ck("UTXO count unchanged after rejecting dry run", utxo_live_count(), count0);
      ck("applied height unchanged after rejecting dry run", utxo_live_applied_height(), applied0); }

    /* ---- COHERENCE: the dry-run-passed block then APPLIES cleanly ---- */
    ck("store_append(valid) at 150", store_append(store_buf, vhash, valid, vlen), n1);
    ck("catch-up applies the dry-run-passed block", utxo_live_catchup(store_buf), 1);
    ck("applied height now 150", utxo_live_applied_height(), n1);
    /* net UTXO change: +1 coinbase out, -1 spent height-0 out, +1 tx1 out */
    ck("UTXO count = before + 1", utxo_live_count(), count0 + 1);

    utxo_live_close();
    printf("\n%s (%d failures)\n", failures==0 ? "ALL TESTS PASSED" : "TESTS FAILED", failures);
    return failures ? 1 : 0;
}
