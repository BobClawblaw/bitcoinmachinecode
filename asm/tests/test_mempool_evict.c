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
extern long   mpool_policy_remove_package(void* st, void* mp, const u8 txid[32]);
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

    /* ==================================================================
     * MEM-13 (audit 2026-09-03): dead blob bytes caused a spurious
     * eviction and a mempoolminfee bump.
     *
     * mpool_del leaves the removed transaction's bytes in the blob and does
     * not move `fill`; only daemon/mempool_compact.c reclaims them, and it
     * used to be called ONLY from inside the eviction loop -- that is, only
     * AFTER an eviction had already happened. Removals that are not
     * evictions (remove_confirmed at every block connect, expiry, RBF) left
     * the blob permanently "full" of bytes nothing referenced.
     *
     * So once `fill` had ever reached blob_cap, blocks could confirm away
     * most of the pool and the next accept still saw put == 2: it scored the
     * worst chunk, refused the newcomer (or evicted a survivor) and called
     * floor_bump, raising mempoolminfee for 12+ hours, while the room it
     * needed was already free.
     *
     * A FRESH pool and policy state, so the floor from the eviction case
     * above cannot be mistaken for this one's.
     * ================================================================== */
    printf("\n== MEM-13: confirmed-away bytes are reclaimed before scoring ==\n");
    {
        static u8 st2[1<<20]; memset(st2, 0, sizeof st2);
        mpool_policy_state_init(st2, 256);
        static u8 mp2[40 + 64*48 + 8];
        static u8 mblob2[300];
        mpool_init(mp2, 64, mblob2, sizeof mblob2);

        u8 fid[4][32];
        int nin2 = 0;
        for (int i=0;i<4;i++){
            u8 tx[128]; long n = mk_tx(tx, (u8)(i+1), 1000000ULL, fees[i], 0);
            tx_txid(fid[i], tx, n, sc, sizeof sc);
            if (mpool_policy_add(pol, st2, mp2, tx, n, fid[i], ux) == 1) nin2++;
        }
        ck("MEM-13 fresh pool filled to capacity", nin2 == 4);
        ck("MEM-13 floor still 0 (nothing evicted yet)", mpool_policy_min_fee(st2) == 0);

        /* Confirm three of them away. This is a NON-eviction removal: it is
         * what a block connect does, and it is the case that used to leave
         * the blob full of bytes nothing referenced. */
        int removed = 0;
        for (int i=0;i<3;i++) removed += (int)mpool_policy_remove_package(st2, mp2, fid[i]);
        ck("MEM-13 three transactions confirmed away", removed >= 3);
        { unsigned long l;
          ck("MEM-13 ...and they really are gone from the pool",
             mpool_get(mp2, fid[0], &l) == NULL && mpool_get(mp2, fid[2], &l) == NULL); }

        /* A newcomer CHEAPER than the one survivor (fee 400). Under the old
         * code put == 2 was still returned, the survivor was the worst chunk,
         * the newcomer lost the feerate comparison against it, and the accept
         * became "mempool full" + floor_bump -- with three quarters of the
         * blob actually free. */
        { u8 tx[128]; long n = mk_tx(tx, 7, 1000000ULL, 150, 0);
          u8 id[32]; tx_txid(id, tx, n, sc, sizeof sc);
          long r = mpool_policy_add(pol, st2, mp2, tx, n, id, ux);
          printf("      (add fee=150 into a 3/4-freed pool -> %ld, floor %llu)\n",
                 r, (unsigned long long)mpool_policy_min_fee(st2));
          ck("MEM-13 a modest-fee tx is ACCEPTED into the freed space", r == 1);
          unsigned long l;
          ck("MEM-13 ...it is actually stored", mpool_get(mp2, id, &l) != NULL);
          ck("MEM-13 ...the fee=400 survivor was NOT evicted for it",
             mpool_get(mp2, fid[3], &l) != NULL);
          ck("MEM-13 ...and mempoolminfee did NOT bump (no eviction happened)",
             mpool_policy_min_fee(st2) == 0); }
    }

    /* ==================================================================
     * MEM-6 (audit 2026-09-03): the RBF eviction is not applied unless
     * the replacement can actually be stored.
     *
     * Step 1a removed every conflict (and its descendants) and recorded them
     * in _mpol_replaced; step 1b then called mpool_put, which on a byte-full
     * pool can end in "mempool full" with nothing stored. The original was
     * gone, the replacement was not in, and this file's own header claim --
     * "Accept is atomic: on any policy failure both the structural mempool
     * and this state are untouched" -- was false. Because RBF requires
     * signing authority over the original's inputs, the practical victim is
     * a two-party construction: an LN counterparty's commitment transaction
     * dropped from this node while Core nodes keep it.
     *
     * The fixture: a full pool of cheap transactions, plus a dearer original
     * O to replace. The replacement pays more than O in total AND more per
     * byte (so it clears RBF and MEM-7's PaysMoreThanConflicts), but its
     * feerate is below the worst chunk, so the store cannot succeed. What is
     * asserted is not the refusal -- that was always the outcome -- but that
     * O SURVIVES it.
     * ================================================================== */
    printf("\n== MEM-6: a refused replacement does not destroy what it conflicts with ==\n");
    {
        static u8 st3[1<<20]; memset(st3, 0, sizeof st3);
        mpool_policy_state_init(st3, 256);
        static u8 mp3[40 + 64*48 + 8];
        static u8 mblob3[300];
        mpool_init(mp3, 64, mblob3, sizeof mblob3);

        /* Three expensive residents, so the worst chunk is dear. */
        u8 rid[3][32];
        int rin = 0;
        for (int i=0;i<3;i++){
            u8 tx[128]; long n = mk_tx(tx, (u8)(i+1), 1000000ULL, 50000, 0);
            tx_txid(rid[i], tx, n, sc, sizeof sc);
            if (mpool_policy_add(pol, st3, mp3, tx, n, rid[i], ux) == 1) rin++;
        }
        /* The original to be replaced: cheap enough that it is the pool's
         * worst, dear enough to be worth replacing. */
        u8 oid[32];
        { u8 tx[128]; long n = mk_tx(tx, 4, 1000000ULL, 300, 0);
          tx_txid(oid, tx, n, sc, sizeof sc);
          rin += (mpool_policy_add(pol, st3, mp3, tx, n, oid, ux) == 1); }
        ck("MEM-6 fixture: pool filled", rin == 4);
        { unsigned long l; ck("MEM-6 the original O is in the pool", mpool_get(mp3, oid, &l) != NULL); }

        /* R conflicts with O (same prevout, tag 4), pays 800 > 300 and at a
         * higher feerate than O, so RBF rules 3+4 and MEM-7 all pass -- but
         * the pool is byte-full of 50,000-sat residents, so the store cannot
         * succeed and the accept ends "mempool full". */
        { /* R is PADDED to ~200 bytes. Evicting O frees only ~70, and
           * MEM-13's compaction reclaims only what is genuinely dead, so the
           * store still cannot fit -- which is the whole point: without the
           * pre-check, O would be destroyed on the way to that failure.
           * R pays 10,000 sat over ~200 vB = ~50 sat/vB: far above O's ~4
           * (so RBF and MEM-7 pass) and far below the 50,000-sat residents'
           * ~700 (so it loses the worst-chunk comparison and cannot be
           * stored). */
          u8 tx[512]; long n = mk_tx(tx, 4, 1000000ULL, 10000, 130);
          u8 id[32]; tx_txid(id, tx, n, sc, sizeof sc);
          long r = mpool_policy_add(pol, st3, mp3, tx, n, id, ux);
          printf("      (replacement -> %ld, reason %s)\n", r,
                 r == 1 ? "accepted" : mpool_policy_reason(pol));
          unsigned long l;
          if (r == 1){
              /* It fit after all -- then O must be gone, which is the correct
               * outcome and not what this case is about. Say so rather than
               * assert a property the fixture did not reach. */
              ck("MEM-6 (fixture did not reach a full pool; replacement accepted, O evicted)",
                 mpool_get(mp3, oid, &l) == NULL);
          } else {
              ck("MEM-6 the REFUSED replacement is not in the pool",
                 mpool_get(mp3, id, &l) == NULL);
              ck("MEM-6 ...and the original it conflicted with SURVIVED",
                 mpool_get(mp3, oid, &l) != NULL);
          } }
    }

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
