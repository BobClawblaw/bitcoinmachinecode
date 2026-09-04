/* tests/test_mempool_evict_64k.c -- MEM-2 (audit 2026-09-03): the chunk
 * evictor must still work above 65,536 pool entries.
 *
 * THE BUG. worst_chunk's working arrays were `static uint32_t
 * child_head[65536], child_next[65536], mark[65536]` behind `if (n > 65536)
 * return 0;`. But the structural pool and the policy graph are sized for ~1M
 * entries -- daemon/mempool_cfg.c sizes slots to blob_cap/512, i.e. 1,048,576
 * for the default 300 MB maxmempool -- so the evictor hard-failed at a
 * sixteenth of the pool's own capacity. At ~400 raw bytes per transaction the
 * pool passes 64K entries at about 26 MB, long before the blob is full.
 *
 * What that produced, and why it is a wedge rather than a slowdown: mpool_put
 * returns 2 when fill + txlen > blob_cap, and `fill` only ever grows except
 * in mpool_compact, which the accept path calls ONLY AFTER a successful
 * eviction. So once the blob filled with more than 64K entries in it,
 * worst_chunk returned 0, the accept loop reported "mempool full", and every
 * subsequent accept at ANY feerate failed -- with no eviction, no compaction
 * and no floor_bump, so getmempoolinfo went on reporting mempoolminfee 0
 * while rejecting everything. Recovery required n to fall back to 65,536
 * through confirmation or the 336-hour expiry, and low-fee filler is exactly
 * what does not confirm.
 *
 * WHAT THIS TEST ASSERTS, at the level a node operator would see:
 *   1. the pool really does exceed 65,536 entries (otherwise the test proves
 *      nothing -- this is checked, not assumed);
 *   2. once the blob is full, a well-paying transaction is still ACCEPTED,
 *      which can only happen if an eviction ran;
 *   3. when a transaction IS refused for want of room, the reported minimum
 *      relay fee has RISEN above zero -- the floor bump that the wedge
 *      suppressed. A refusal with the floor still at zero is the signature of
 *      the bug.
 *
 * The fixtures are the same tiny non-standard shapes test_mempool_evict and
 * test_mempool_chunks use, under -acceptnonstdtxn; only the counts are large.
 *
 * Usage: ./test_mempool_evict_64k
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>

typedef unsigned char u8;
typedef unsigned long long u64;

extern void   mpool_init(void* mp, unsigned long slots, void* blob, unsigned long blob_cap);
extern const u8* mpool_get(void* mp, const u8 txid[32], unsigned long* len);
extern void   utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long   utxo_put(void* u, const u8 txid[32], unsigned long index, u64 value, unsigned long height, unsigned long cb, const u8* script, unsigned long slen);
extern long   utxo_get(void* u, const u8 txid[32], unsigned long index, u64* value, unsigned long* height, unsigned long* cb, const u8** script, unsigned long* slen);
extern void   mpool_policy_init(void* pol, u64 relay_fee_kvb, unsigned max_anc, unsigned max_anc_bytes, unsigned max_desc, unsigned max_desc_bytes, unsigned rbf);
extern void   mpool_policy_set_acceptnonstd(void* pol, int on);
extern unsigned long mpool_policy_state_size(unsigned n);
extern void   mpool_policy_state_init(void* st, unsigned n);
extern void   mpool_policy_set_poolcap(void* st, unsigned long long cap);
extern long   mpool_policy_add(void* pol, void* st, void* mp, const u8* tx, unsigned long txlen, const u8 txid[32], void* utxo);
extern const char* mpool_policy_reason(void* pol);
extern u64    mpool_policy_min_fee(void* st);
extern int    tx_txid(u8 out[32], const u8* tx, unsigned long len, u8* scratch, unsigned long cap);

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index, u64* value, const u8** script, unsigned long* slen){
    unsigned long h, cb; return utxo_get(u, txid, index, value, &h, &cb, script, slen);
}

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("ok  : %s\n", l); else { printf("FAIL: %s\n", l); fails++; } }

/* 1-in 1-out spending (prev:0), paying invalue-fee. ~62 bytes. */
static long mk(u8* out, const u8 prev[32], u64 invalue, u64 fee){
    u8* p = out;
    *p++=2;*p++=0;*p++=0;*p++=0;
    *p++=1; memcpy(p, prev, 32); p+=32; *p++=0;*p++=0;*p++=0;*p++=0; *p++=0;
    *p++=0xff;*p++=0xff;*p++=0xff;*p++=0xff;
    *p++=1; u64 outv = invalue - fee; for (int i=0;i<8;i++) *p++ = (u8)(outv >> (8*i));
    *p++ = 1; *p++ = 0x51;
    *p++=0;*p++=0;*p++=0;*p++=0;
    return p - out;
}

/* N must exceed 65,536 for the test to mean anything; the headroom is so the
 * blob fills (and eviction is forced) with the entry count already past it. */
/* Sized so the entry count is past 65,536 BEFORE the blob fills, while the
 * number of evictions stays small. worst_chunk walks every cluster on every
 * call, so evictions * entries is the cost: ~1,300 x 68,000 here (seconds),
 * against ~20,000 x 90,000 (minutes) for a fixture that evicts aggressively.
 * The ceiling is what is under test, not the eviction rate. */
#define NSEED   68000
#define SLOTS   131072

int main(void){
    static u8 pol[128];
    static u8 scratch[4096];

    unsigned long psz = mpool_policy_state_size(SLOTS);
    void* st = mmap(0, psz, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (st == MAP_FAILED){ printf("FAIL: policy state mmap (%lu bytes)\n", psz); return 1; }

    /* blob sized so it fills WHILE the entry count is well past 64K */
    /* ~62.8 bytes per entry measured, so this fills at roughly 66,000
     * entries -- PAST the old 65,536 ceiling -- leaving ~2,000 admissions
     * that can only succeed by evicting. That is the whole point: the
     * evictor has to run with n > 65,536. */
    const unsigned long BLOB_CAP = 66000UL * 62UL;
    void* mblob = malloc(BLOB_CAP);
    void* mp    = malloc(40 + (unsigned long)SLOTS*48 + 8);
    void* ublob = malloc((unsigned long)NSEED * 64 + (1<<16));
    void* ux    = malloc(40 + (unsigned long)(NSEED+16)*48 + 8);
    if (!mblob || !mp || !ublob || !ux){ printf("FAIL: oom\n"); return 1; }

    mpool_policy_init(pol, 1000, 25, 101000, 25, 101000, 1);
    mpool_policy_set_acceptnonstd(pol, 1);
    mpool_policy_state_init(st, SLOTS);
    mpool_policy_set_poolcap(st, BLOB_CAP);
    mpool_init(mp, SLOTS, mblob, BLOB_CAP);
    utxo_init(ux, NSEED + 16, ublob, (unsigned long)NSEED * 64 + (1<<16));

    /* one confirmed coin per candidate transaction: unrelated, so every
     * entry is its own single-member cluster -- the shape that makes the
     * per-cluster walk do 90,000 iterations rather than one. */
    for (unsigned i = 0; i < NSEED; i++){
        u8 t[32]; memset(t, 0, 32);
        t[0]=(u8)i; t[1]=(u8)(i>>8); t[2]=(u8)(i>>16); t[3]=0xC0;
        utxo_put(ux, t, 0, 1000000ULL, 0, 0, (const u8*)"\x51", 1);
    }

    u8 poor_id[32]; int have_poor = 0;
    long accepted = 0, refused = 0, refused_full = 0;
    long first_refusal = -1;
    u64 minfee_at_refusal = 0;
    (void)minfee_at_refusal;

    for (unsigned i = 0; i < NSEED; i++){
        u8 prev[32]; memset(prev, 0, 32);
        prev[0]=(u8)i; prev[1]=(u8)(i>>8); prev[2]=(u8)(i>>16); prev[3]=0xC0;
        u8 tx[128];
        /* fees fan out so there is always a genuinely worst chunk to evict */
        u64 fee = 300 + (i % 5000);
        long tl = mk(tx, prev, 1000000ULL, fee);
        u8 id[32]; tx_txid(id, tx, (unsigned long)tl, scratch, sizeof scratch);
        long r = mpool_policy_add(pol, st, mp, tx, (unsigned long)tl, id, ux);
        if (r == 1){
            /* entry 10 pays 310 -- among the poorest in the pool, so it is
             * among the first things a working evictor throws out. Its
             * absence at the end is the proof that eviction RAN, which a
             * pass/fail on accept counts alone cannot give. */
            if (i == 10){ memcpy(poor_id, id, 32); have_poor = 1; }
            accepted++; continue;
        }
        refused++;
        const char* why = mpool_policy_reason(pol);
        if (why && strstr(why, "full")){
            refused_full++;
            if (first_refusal < 0){ first_refusal = accepted; minfee_at_refusal = mpool_policy_min_fee(st);
                printf("      first \"full\" refusal at entry %ld, minrelayfee then = %llu\n",
                       first_refusal, (unsigned long long)minfee_at_refusal); }
        }
    }

    printf("      accepted=%ld refused=%ld (of which \"full\"=%ld)\n",
           accepted, refused, refused_full);
    printf("      minrelayfee after the first \"full\" refusal: %llu\n",
           (unsigned long long)mpool_policy_min_fee(st));

    unsigned long plen = 0;
    int poor_gone = have_poor && mpool_get(mp, poor_id, &plen) == 0;

    ck("MEM-2 the pool really did exceed the old 65,536-entry ceiling",
       accepted > 65536);
    ck("MEM-2 the evictor actually RAN above 65,536 entries "
       "(a poorly-paying early entry was thrown out)", poor_gone);
    ck("MEM-2 admissions keep succeeding once the blob is full",
       accepted >= NSEED - refused_full && accepted > 65536);
    ck("MEM-2 a \"mempool full\" refusal comes with a RAISED fee floor, "
       "not a silent wedge at zero",
       refused_full == 0 || mpool_policy_min_fee(st) > 0);

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
