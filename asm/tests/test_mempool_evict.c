/* tests/test_mempool_evict.c -- TrimToSize eviction + dynamic mempoolminfee
 * (bitcoin_mempool_policy.c).
 *
 * Fills a deliberately tiny mempool, then proves Core's size-management
 * behaviour:
 *   - a higher-feerate tx EVICTS the lowest-feerate resident when the pool
 *     is full (the cheap one leaves, the dear one enters, count stays at
 *     capacity);
 *   - the dynamic mempoolminfee floor rises after eviction;
 *   - a tx below that floor is rejected up front (not accepted, nothing
 *     evicted for it);
 *   - the graph stays consistent (every survivor still resolvable).
 */
#include <stdio.h>
#include <string.h>

typedef unsigned char u8;
typedef unsigned long long u64;

extern void   mpool_init(void* mp, unsigned long slots, void* blob, unsigned long blob_cap);
extern const u8* mpool_get(void* mp, const u8 txid[32], unsigned long* len);
extern long   utxo_get(void* u, const u8 txid[32], unsigned long index, u64* value,
                       unsigned long* height, unsigned long* cb, const u8** script, unsigned long* slen);
extern void   utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long   utxo_put(void* u, const u8 txid[32], unsigned index, u64 value, u64 h, u64 cb, const u8* spk, unsigned slen);
extern void   mpool_policy_init(void* pol, u64 relay, unsigned, unsigned, unsigned, unsigned, unsigned);
extern void mpool_policy_set_acceptnonstd(void*, unsigned);
extern void   mpool_policy_state_init(void* st, unsigned n);
extern long   mpool_policy_add(void* pol, void* st, void* mp, const u8* tx, unsigned long txlen, const u8 txid[32], void* utxo);
extern const char* mpool_policy_reason(void* pol);
extern u64    mpool_policy_min_fee(void* st);
extern void   tx_txid_helper(u8 out[32], const u8* tx, unsigned long len);   /* maybe absent */
extern int    tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* buf, unsigned long buflen);

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    unsigned long h, cb; return utxo_get(u, txid, index, value, &h, &cb, script, slen);
}

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }

/* minimal 1-in 1-out tx spending coin `in_tag`:0, paying (invalue - fee).
 * `pad` bytes of output script vary the size so feerate can be controlled. */
static long mk_tx(u8* out, u8 in_tag, u64 invalue, u64 fee, int pad){
    u8* p = out;
    *p++=2;*p++=0;*p++=0;*p++=0;                 /* version */
    *p++=1;                                      /* nin */
    memset(p, in_tag, 32); p+=32;                /* prevout txid */
    *p++=0;*p++=0;*p++=0;*p++=0;                 /* prevout index 0 */
    *p++=0;                                      /* scriptSig len */
    *p++=0xff;*p++=0xff;*p++=0xff;*p++=0xff;     /* sequence */
    *p++=1;                                      /* nout */
    u64 outv = invalue - fee;
    for (int i=0;i<8;i++) *p++ = (u8)(outv >> (8*i));
    *p++ = (u8)(1+pad);                          /* spk len */
    *p++ = 0x51;                                 /* OP_TRUE */
    for (int i=0;i<pad;i++) *p++ = 0x00;
    *p++=0;*p++=0;*p++=0;*p++=0;                 /* locktime */
    return p - out;
}

int main(void){
    static u8 pol[128], st[1<<20];
    memset(st, 0, sizeof st);
    mpool_policy_init(pol, 1000 /* sat/kvB: 1 sat/vB, as before */, 25, 101000, 25, 101000, 1);
    /* fixtures are synthetic, deliberately non-standard txs: run under
     * Core's own regtest escape hatch (-acceptnonstdtxn) so this test
     * keeps exercising fee/graph mechanics, not IsStandardTx. */
    mpool_policy_set_acceptnonstd(pol, 1);
    mpool_policy_state_init(st, 256);

    /* TINY pool: blob holds only ~4 of these ~70-byte txs */
    static u8 mp[40 + 64*48 + 8];
    static u8 mblob[300];
    mpool_init(mp, 64, mblob, sizeof mblob);

    static u8 ux[40 + 256*48 + 8]; static u8 ublob[1<<14];
    utxo_init(ux, 256, ublob, sizeof ublob);
    /* 8 confirmed coins, tags 1..8, each 1,000,000 sat */
    for (int i=1;i<=8;i++){ u8 t[32]; memset(t,(u8)i,32); utxo_put(ux, t, 0, 1000000ULL, 0, 0, (const u8*)"\x51", 1); }

    static u8 sc[4096];
    u8 ids[10][32];
    /* four txs, increasing fee: 100,200,300,400 sat, same size */
    u64 fees[4] = {100,200,300,400};
    printf("== fill the tiny pool with 4 txs (fees 100..400) ==\n");
    int inpool = 0;
    for (int i=0;i<4;i++){
        u8 tx[128]; long n = mk_tx(tx, (u8)(i+1), 1000000ULL, fees[i], 0);
        tx_txid(ids[i], tx, n, sc, sizeof sc);
        long r = mpool_policy_add(pol, st, mp, tx, n, ids[i], ux);
        if (r == 1) inpool++;
        printf("  add fee=%llu -> %ld (%s)\n", (unsigned long long)fees[i], r, r==1?"in":mpool_policy_reason(pol));
    }
    ck("pool filled to capacity (all 4 in)", inpool == 4);
    ck("min-fee floor still 0 before any eviction", mpool_policy_min_fee(st) == 0);

    printf("\n== a fee=1000 tx evicts the cheapest (fee=100) ==\n");
    { u8 tx[128]; long n = mk_tx(tx, 5, 1000000ULL, 1000, 0);
      tx_txid(ids[4], tx, n, sc, sizeof sc);
      long r = mpool_policy_add(pol, st, mp, tx, n, ids[4], ux);
      ck("high-fee tx accepted (evicting to fit)", r == 1);
      unsigned long l;
      ck("the fee=100 tx was evicted", mpool_get(mp, ids[0], &l) == NULL);
      ck("the high-fee tx is present", mpool_get(mp, ids[4], &l) != NULL);
      ck("the fee=200 tx survived", mpool_get(mp, ids[1], &l) != NULL);
      ck("dynamic min-fee floor rose above 0", mpool_policy_min_fee(st) > 0); }

    printf("\n== a fee=50 tx is below the floor -> rejected, nothing evicted ==\n");
    { u8 tx[128]; long n = mk_tx(tx, 6, 1000000ULL, 50, 0);
      u8 id[32]; tx_txid(id, tx, n, sc, sizeof sc);
      long r = mpool_policy_add(pol, st, mp, tx, n, id, ux);
      ck("below-floor tx rejected", r == 0);
      const char* why = mpool_policy_reason(pol);
      ck("...for a fee/min-fee reason (Core strings: relay floor or rolling floor)",
         why && (strstr(why,"min relay fee not met") || strstr(why,"mempool min fee not met") || strstr(why,"mempool full")));
      unsigned long l;
      ck("...and it is NOT in the pool", mpool_get(mp, id, &l) == NULL);
      ck("...survivors still resolvable (graph intact)",
         mpool_get(mp, ids[4], &l) != NULL && mpool_get(mp, ids[1], &l) != NULL); }

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
