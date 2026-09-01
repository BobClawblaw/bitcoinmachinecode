/* tests/test_mempool_chunks.c -- TrimToSize evicts linearization CHUNKS
 * (Core v31 cluster mempool), not the worst leaf.
 *
 * A cluster's linearization is cut into chunks of non-increasing feerate; a
 * child that pays for its parent shares the parent's chunk. Core removes the
 * worst chunk of all clusters and sets the floor to that chunk's feerate plus
 * the incremental relay fee. These scenarios pin that:
 *   1. a bumped parent is judged by its chunk, not its own feerate;
 *   2. the worst chunk is evicted WHOLE (parent and child together);
 *   3. a chunk that pays more than the incoming tx refuses it as "mempool
 *      full" with the floor raised to the chunk's feerate;
 *   4. a poor sibling forms its own chunk and goes alone, the paying chain
 *      stays.
 * Same synthetic fixtures as test_mempool_evict (tiny pool, non-standard
 * txs under -acceptnonstdtxn). */
#include <stdio.h>
#include <string.h>
typedef unsigned char u8;
typedef unsigned long long u64;
extern void   mpool_init(void* mp, unsigned long slots, void* blob, unsigned long blob_cap);
extern const u8* mpool_get(void* mp, const u8 txid[32], unsigned long* len);
extern void   utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long   utxo_put(void* u, const u8 txid[32], unsigned long index, u64 value, unsigned long height, unsigned long cb, const u8* script, unsigned long slen);
extern void   mpool_policy_init(void* pol, u64 relay_fee_kvb, unsigned max_anc, unsigned max_anc_bytes, unsigned max_desc, unsigned max_desc_bytes, unsigned rbf);
extern void   mpool_policy_set_acceptnonstd(void* pol, int on);
extern void   mpool_policy_state_init(void* st, unsigned long slots);
extern long   mpool_policy_add(void* pol, void* st, void* mp, const u8* tx, unsigned long txlen, const u8 txid[32], void* utxo);
extern const char* mpool_policy_reason(void* pol);
extern u64    mpool_policy_min_fee(void* st);
extern int    tx_txid(u8 out[32], const u8* tx, unsigned long len, u8* scratch, unsigned long cap);
extern long   utxo_get(void* u, const u8 txid[32], unsigned long index, u64* value, unsigned long* height, unsigned long* cb, const u8** script, unsigned long* slen);
/* the policy layer resolves confirmed prevouts through this hook; the test's UTXO store answers */
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index, u64* value, const u8** script, unsigned long* slen){
    unsigned long h, cb; return utxo_get(u, txid, index, value, &h, &cb, script, slen);
}

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static u8 sc[4096];
/* 1-in 1-out spending (prev:0) paying invalue-fee; pad varies the size */
static long mk(u8* out, const u8 prev[32], u64 invalue, u64 fee, int pad){
    u8* p = out; *p++=2;*p++=0;*p++=0;*p++=0; *p++=1; memcpy(p, prev, 32); p+=32; *p++=0;*p++=0;*p++=0;*p++=0; *p++=0; *p++=0xff;*p++=0xff;*p++=0xff;*p++=0xff;
    *p++=1; u64 outv = invalue - fee; for (int i=0;i<8;i++) *p++ = (u8)(outv >> (8*i)); *p++ = (u8)(1+pad); *p++ = 0x51; for (int i=0;i<pad;i++) *p++ = 0; *p++=0;*p++=0;*p++=0;*p++=0; return p - out; }
static int present(void* mp, const u8 id[32]){ unsigned long l; return mpool_get(mp, id, &l) != 0; }

int main(void){
    static u8 pol[128], st[1<<20], mp[40 + 64*48 + 8], mblob[300], ux[40 + 256*48 + 8], ublob[1<<14];   /* the blob holds four ~70-byte txs */
    #define RESET() do{ memset(st,0,sizeof st); mpool_policy_init(pol, 1000, 25, 101000, 25, 101000, 1); mpool_policy_set_acceptnonstd(pol, 1); \
        mpool_policy_state_init(st, 256); mpool_init(mp, 64, mblob, sizeof mblob); utxo_init(ux, 256, ublob, sizeof ublob); \
        for (int i=1;i<=8;i++){ u8 t[32]; memset(t,(u8)i,32); utxo_put(ux, t, 0, 1000000ULL, 0, 0, (const u8*)"\x51", 1); } }while(0)
    u8 coin[9][32]; for (int i=1;i<=8;i++) memset(coin[i], (u8)i, 32);
    u8 tx[256]; long n; u8 P[32], C[32], S[32], X[32], C2[32];

    printf("== 1/2. a cheap parent bumped by its child is one chunk; the worst chunk goes WHOLE ==\n");
    RESET();
    /* F: filler fee 500 (~7 sat/vB). P: fee 70 (~1.0 sat/vB); C spends P, fee 140 (~2.0): chunk {P,C} = 210/140 = 1.5.
     * S: single fee 120 (~1.7). Four txs fill the blob; the next arrival must evict the WORST CHUNK: {P,C} at 1.5, not S. */
    { u8 F[32]; n = mk(tx, coin[3], 1000000, 500, 0); tx_txid(F, tx, n, sc, sizeof sc); ck("filler accepted", mpool_policy_add(pol, st, mp, tx, n, F, ux) == 1); }
    n = mk(tx, coin[1], 1000000, 70, 0);  tx_txid(P, tx, n, sc, sizeof sc); ck("P (1.0 sat/vB) accepted", mpool_policy_add(pol, st, mp, tx, n, P, ux) == 1);
    n = mk(tx, P, 1000000-70, 140, 0);    tx_txid(C, tx, n, sc, sizeof sc); ck("C child of P (2.0 sat/vB) accepted", mpool_policy_add(pol, st, mp, tx, n, C, ux) == 1);
    n = mk(tx, coin[2], 1000000, 120, 0); tx_txid(S, tx, n, sc, sizeof sc); ck("S single (1.7 sat/vB) accepted", mpool_policy_add(pol, st, mp, tx, n, S, ux) == 1);
    n = mk(tx, coin[4], 1000000, 500, 0); tx_txid(X, tx, n, sc, sizeof sc);
    ck("a fifth tx (7 sat/vB) is admitted by eviction", mpool_policy_add(pol, st, mp, tx, n, X, ux) == 1);
    ck("S (1.7 sat/vB single) is still in the pool", present(mp, S));
    ck("P is gone -- its chunk (1.5 sat/vB) was the worst", !present(mp, P));
    ck("C went with its parent: the chunk is evicted whole", !present(mp, C));
    printf("  floor now %llu sat/kvB\n", (unsigned long long)mpool_policy_min_fee(st));
    /* these txs are 61 vB: chunk {P,C} = 210 sat / 122 vB = 1721 sat/kvB; the test policy's incremental relay fee is 1000 sat/kvB */
    ck("the floor is the evicted chunk's feerate + incremental (2721 sat/kvB)", mpool_policy_min_fee(st) >= 2700 && mpool_policy_min_fee(st) <= 2750);

    printf("== 3. an incoming tx below the worst chunk's feerate is refused ==\n");
    RESET();
    { u8 F[32]; n = mk(tx, coin[3], 1000000, 500, 0); tx_txid(F, tx, n, sc, sizeof sc); mpool_policy_add(pol, st, mp, tx, n, F, ux); }
    n = mk(tx, coin[1], 1000000, 70, 0);  tx_txid(P, tx, n, sc, sizeof sc); mpool_policy_add(pol, st, mp, tx, n, P, ux);
    n = mk(tx, P, 1000000-70, 140, 0);    tx_txid(C, tx, n, sc, sizeof sc); mpool_policy_add(pol, st, mp, tx, n, C, ux);
    n = mk(tx, coin[2], 1000000, 120, 0); tx_txid(S, tx, n, sc, sizeof sc); mpool_policy_add(pol, st, mp, tx, n, S, ux);
    /* full: worst chunk is {P,C} at 1.5; a 1.2 sat/vB newcomer loses to it */
    n = mk(tx, coin[5], 1000000, 84, 0); tx_txid(X, tx, n, sc, sizeof sc);
    long rx = mpool_policy_add(pol, st, mp, tx, n, X, ux);
    ck("a 1.2 sat/vB newcomer is refused as mempool full", rx != 1 && strstr(mpool_policy_reason(pol), "mempool full"));
    ck("...and nothing was evicted for it: P, C and S all remain", present(mp, P) && present(mp, C) && present(mp, S));
    ck("...while the floor now names the chunk it lost to (2721)", mpool_policy_min_fee(st) >= 2700 && mpool_policy_min_fee(st) <= 2750);

    printf("== 4. a poor grandchild is its own chunk: it goes, the paying chain stays ==\n");
    RESET();
    { u8 F[32]; n = mk(tx, coin[3], 1000000, 500, 0); tx_txid(F, tx, n, sc, sizeof sc); mpool_policy_add(pol, st, mp, tx, n, F, ux); }
    n = mk(tx, coin[1], 1000000, 70, 0);   tx_txid(P, tx, n, sc, sizeof sc);  ck("P accepted", mpool_policy_add(pol, st, mp, tx, n, P, ux) == 1);
    n = mk(tx, P, 1000000-70, 700, 0);     tx_txid(C, tx, n, sc, sizeof sc);  ck("C1 (10 sat/vB, bumps P: chunk {P,C1} ~5.5) accepted", mpool_policy_add(pol, st, mp, tx, n, C, ux) == 1);
    n = mk(tx, C, 1000000-770, 75, 0);     tx_txid(C2, tx, n, sc, sizeof sc); ck("C2 grandchild (1.07 sat/vB) accepted", mpool_policy_add(pol, st, mp, tx, n, C2, ux) == 1);
    n = mk(tx, coin[4], 1000000, 500, 0);  tx_txid(X, tx, n, sc, sizeof sc);  ck("a fifth tx is admitted by eviction", mpool_policy_add(pol, st, mp, tx, n, X, ux) == 1);
    ck("C2 (its own chunk, the worst) was evicted", !present(mp, C2));
    ck("P and C1 (one chunk at ~5.5 sat/vB) stayed", present(mp, P) && present(mp, C));

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
