/* tests/test_con_arena_fail.c -- CON-12 (audit 2026-10-23): the in-block
 * index arenas must not be used after a failed growth.
 *
 * bidx_reset / bspent_reset called grow_arena and ignored its result, then
 * set the mask for the NEW table size and filled that many slots -- in the
 * OLD, smaller table when the realloc had failed: a heap overflow. They now
 * report the failure and apply_block_inner fails the block with no reason,
 * i.e. as a store error (the block itself is not at fault).
 *
 * The failure is injected with the linker: this binary is linked with
 * -Wl,--wrap=realloc, and __wrap_realloc refuses exactly one request size
 * while armed -- the size the arena under test grows to for the block
 * built here (8,192 slots: 3,001 outputs or inputs, doubled, rounded up).
 * Each case is then run again unarmed, which must get past the arena.
 *
 * Fixture: test_val_connect's 150 regtest coinbase-only blocks; every case
 * is a dry run of block 150.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
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
extern int chainparams_select(const char* name);
extern int  utxo_live_init(const char* dir);
extern long utxo_live_catchup(void* store_buf);
extern void utxo_live_close(void);
extern long utxo_live_dryrun_block(const u8* blockbuf, u64 blocklen, long height);
extern const char* utxo_live_last_reject(void);
extern long utxo_live_last_mutated(void);

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u;(void)txid;(void)index;(void)value;(void)script;(void)slen;
    fprintf(stderr, "test_con_arena_fail: unexpected mempool_resolve_confirmed_utxo\n");
    abort();
}

/* ---- realloc failure injection ---- */
void* __real_realloc(void* p, size_t n);
static size_t g_fail_size = 0;          /* 0 = disarmed */
static int    g_fail_hits = 0;
void* __wrap_realloc(void* p, size_t n){
    if (g_fail_size && n == g_fail_size){ g_fail_hits++; return NULL; }
    return __real_realloc(p, n);
}

static int failures = 0;
static void ck(const char* l, long got, long exp){
    if (got==exp) printf("PASS %s (got %ld)\n", l, got);
    else { printf("FAIL %s got=%ld exp=%ld\n", l, got, exp); failures++; }
}
static void put32(u8* p, u32 v){ p[0]=(u8)v; p[1]=(u8)(v>>8); p[2]=(u8)(v>>16); p[3]=(u8)(v>>24); }
static void put64(u8* p, u64 v){ for(int i=0;i<8;i++) p[i]=(u8)(v>>(8*i)); }
static u8 g_txid_scratch[1<<17];

static long mk_coinbase(u8* tx, u8 txid[32], long h){
    u8* q = tx;
    put32(q,1); q+=4; *q++ = 1;
    memset(q,0,32); q+=32; put32(q,0xffffffffu); q+=4;
    u8 ss[6]; int n = 0;
    if (h >= 1 && h <= 16) ss[n++] = (u8)(0x50 + h);
    else { u8 num[4]; int nn = 0; u64 v = (u64)h; while (v){ num[nn++] = (u8)v; v >>= 8; }
           if (num[nn-1] & 0x80) num[nn++] = 0;
           ss[n++] = (u8)nn;
           for (int i=0;i<nn;i++) ss[n++] = num[i]; }
    while (n < 6){ ss[n] = (u8)(0x11 + n); n++; }
    *q++ = 6; memcpy(q, ss, 6); q += 6;
    put32(q,0xffffffffu); q+=4;
    *q++ = 1; put64(q, 50000000ULL); q+=8; *q++ = 1; *q++ = 0x51;
    put32(q,0); q+=4;
    long len = q - tx;
    tx_txid(txid, tx, (unsigned long)len, g_txid_scratch, sizeof g_txid_scratch);
    return len;
}
static long assemble(u8* raw, const u8 prev[32], long height, const u8* cb, long cblen, const u8 cbtxid[32],
                     const u8* sp, long splen, const u8 sptxid[32]){
    u8 pair[64], root[32];
    memcpy(pair, cbtxid, 32); memcpy(pair+32, sptxid, 32); sha256d(root, pair, 64);
    u8* p = raw;
    put32(p,0x20000000u); p+=4; memcpy(p, prev, 32); p+=32; memcpy(p, root, 32); p+=32;
    put32(p, 1800000000u + (u32)height); p+=4; put32(p, 0x207fffffu); p+=4; put32(p,0); p+=4;
    *p++ = 2;
    memcpy(p, cb, (size_t)cblen); p += cblen;
    memcpy(p, sp, (size_t)splen); p += splen;
    u32 nonce = 0;
    while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
    return p - raw;
}

static u8 store_buf[4096];
static u8 g_sp[200000], g_blk[210000];
#define K 3000                        /* + the coinbase's 1 = 3,001 -> 8,192 slots */

int main(void){
    tt_isolate();
    ck("select regtest", chainparams_select("regtest"), 1);
    memset(store_buf,0,sizeof store_buf);
    ck("store_init", store_init(store_buf), 1);
    ck("utxo_live_init", utxo_live_init("."), 1);
    long n1 = 150;
    u8 prev[32]; memset(prev,0,32);
    u8 h1_cbtxid[32]; memset(h1_cbtxid, 0, 32);
    for (long h=0; h<n1; h++){
        u8 raw[256], hash[32], cb[128], txid[32];
        long txlen = mk_coinbase(cb, txid, h);
        if (h == 1) memcpy(h1_cbtxid, txid, 32);
        u8* o = raw;
        put32(o,1); o+=4; memcpy(o, prev, 32); o+=32; memcpy(o, txid, 32); o+=32;
        put32(o, 1800000000u+(u32)h); o+=4; put32(o, 0x207fffffu); o+=4; put32(o, 0); o+=4;
        *o++ = 1; memcpy(o, cb, (size_t)txlen); o += txlen;
        long len = o - raw;
        u32 nonce=0; while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
        block_hash(hash, raw);
        if (store_append(store_buf, hash, raw, len) != h){ printf("FAIL append h=%ld\n",h); failures++; }
        memcpy(prev, hash, 32);
    }
    ck("catch-up applied 150 blocks", utxo_live_catchup(store_buf), n1);

    u8 cb[128], cbtxid[32], sptxid[32];
    long cblen = mk_coinbase(cb, cbtxid, n1);

    /* ---- bidx: a spend of h1's coinbase with 3,000 outputs ---- */
    {
        u8* q = g_sp;
        put32(q,1); q+=4; *q++ = 1;
        memcpy(q, h1_cbtxid, 32); q+=32; put32(q,0); q+=4; *q++ = 0; put32(q,0xffffffffu); q+=4;
        *q++ = 0xfd; *q++ = (u8)(K & 0xff); *q++ = (u8)(K >> 8);
        for (int i = 0; i < K; i++){ put64(q, 10000ULL); q+=8; *q++ = 1; *q++ = 0x51; }
        put32(q,0); q+=4;
        long splen = q - g_sp;
        tx_txid(sptxid, g_sp, (unsigned long)splen, g_txid_scratch, sizeof g_txid_scratch);
        long blen = assemble(g_blk, prev, n1, cb, cblen, cbtxid, g_sp, splen, sptxid);
        g_fail_size = 8192 * 48; g_fail_hits = 0;                 /* bidx table: 8,192 x sizeof(bidx_slot_t) */
        long r = utxo_live_dryrun_block(g_blk, (u64)blen, n1);
        g_fail_size = 0;
        ck("CON-12 fixture: the bidx table growth was refused", g_fail_hits >= 1, 1);
        ck("CON-12 a failed bidx growth fails the block", r, 0);
        ck("CON-12 ...with no reason (a store error, not a reject)", utxo_live_last_reject()[0] == 0, 1);
        ck("CON-12 ...and not as a mutation", utxo_live_last_mutated(), 0);
        ck("CON-12 control: unarmed, the same block dry-runs clean", utxo_live_dryrun_block(g_blk, (u64)blen, n1), 1);
    }
    /* ---- bspent: a tx with 3,000 inputs (made-up prevouts) ---- */
    {
        u8* q = g_sp;
        put32(q,1); q+=4;
        *q++ = 0xfd; *q++ = (u8)(K & 0xff); *q++ = (u8)(K >> 8);
        for (int i = 0; i < K; i++){
            memset(q, 0x3c, 32); q[0] = (u8)i; q[1] = (u8)(i >> 8); q += 32; put32(q, 0); q += 4;
            *q++ = 0; put32(q,0xffffffffu); q+=4;
        }
        *q++ = 1; put64(q, 10000ULL); q+=8; *q++ = 1; *q++ = 0x51;
        put32(q,0); q+=4;
        long splen = q - g_sp;
        tx_txid(sptxid, g_sp, (unsigned long)splen, g_txid_scratch, sizeof g_txid_scratch);
        long blen = assemble(g_blk, prev, n1, cb, cblen, cbtxid, g_sp, splen, sptxid);
        g_fail_size = 8192 * 36; g_fail_hits = 0;                 /* bspent keys: 8,192 x 36 */
        long r = utxo_live_dryrun_block(g_blk, (u64)blen, n1);
        g_fail_size = 0;
        ck("CON-12 fixture: the bspent keys growth was refused", g_fail_hits >= 1, 1);
        ck("CON-12 a failed bspent growth fails the block", r, 0);
        ck("CON-12 ...with no reason (a store error, not a reject)", utxo_live_last_reject()[0] == 0, 1);
        r = utxo_live_dryrun_block(g_blk, (u64)blen, n1);
        ck("CON-12 control: unarmed, the same block gets past the arena to a real refusal",
           r == 0 && utxo_live_last_reject()[0] != 0, 1);
        printf("      (unarmed reason: %s)\n", utxo_live_last_reject());
    }

    utxo_live_close();
    printf("\n%s (%d failures)\n", failures ? "CON_ARENA_FAIL FAILED" : "CON_ARENA_FAIL PASSED", failures);
    return failures ? 1 : 0;
}
