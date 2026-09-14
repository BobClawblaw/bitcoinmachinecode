/* test_mempool_cluster.c -- the chunking rule and the topological check.
 *
 * Both are exactly specified by Core, so these are equality tests against the
 * specification rather than property tests. The chunking rule is the one in
 * ChunkLinearizationInfo; the absorb condition is STRICTLY greater, and the
 * equal-feerate case is pinned because getting it wrong would silently merge
 * chunks that Core keeps apart and change every chunkfee we report. */
#include <stdio.h>
#include <string.h>
#include "../mempool_cluster.h"

static int pass, fail;
static void ck(const char* name, int ok){
    if (ok){ printf("ok  : %s\n", name); pass++; }
    else   { printf("FAIL: %s\n", name); fail++; }
}

/* helper: a cluster of n independent members with the given fee/weight */
static void mk(mpc_cluster* cl, int n, const uint64_t* fees, const uint64_t* wts){
    memset(cl, 0, sizeof *cl); cl->n = n;
    for (int i = 0; i < n; i++){
        cl->m[i].fee = fees[i]; cl->m[i].weight = wts[i];
        cl->m[i].ancestors = (uint64_t)1 << i;      /* self only */
        cl->m[i].descendants = (uint64_t)1 << i;
    }
}

int main(void){
    printf("== feerate comparison (Core FeeFrac semantics) ==\n");
    ck("2000/1000 > 1000/1000", mpc_feerate_cmp(2000,1000,1000,1000) > 0);
    ck("equal ratios compare equal (1000/500 == 2000/1000)",
       mpc_feerate_cmp(1000,500,2000,1000) == 0);
    /* the reason this is __int128: these products exceed 64 bits */
    ck("no overflow at realistic magnitudes",
       mpc_feerate_cmp(5000000ULL, 4000000ULL, 5000001ULL, 4000000ULL) < 0);
    ck("huge values still ordered correctly",
       mpc_feerate_cmp(1ULL<<62, 1ULL<<40, 1ULL<<61, 1ULL<<40) > 0);
    ck("zero weight sorts lowest, comparator stays total",
       mpc_feerate_cmp(100,0,1,1000) < 0 && mpc_feerate_cmp(1,1000,100,0) > 0);

    printf("== chunking ==\n");
    mpc_cluster cl; mpc_chunking ch;
    {   /* descending feerate: no absorption, one chunk per tx */
        uint64_t f[3] = {3000,2000,1000}, w[3] = {1000,1000,1000};
        mk(&cl,3,f,w); int lin[3] = {0,1,2};
        ck("descending feerates -> 3 chunks",
           mpc_chunk_linearization(&cl,lin,&ch)==0 && ch.n==3);
        ck("...each holds one member", ch.c[0].members==1 && ch.c[1].members==2 && ch.c[2].members==4);
    }
    {   /* a low-fee parent followed by a high-fee child: CPFP. The child must
         * absorb the parent, which is the entire point of chunking. */
        uint64_t f[2] = {0, 4000}, w[2] = {1000,1000};
        mk(&cl,2,f,w);
        cl.m[1].ancestors |= 1; cl.m[0].descendants |= 2;   /* 1 is child of 0 */
        int lin[2] = {0,1};
        ck("CPFP: the paying child absorbs its free parent",
           mpc_chunk_linearization(&cl,lin,&ch)==0 && ch.n==1);
        ck("...the merged chunk holds both, fee 4000 over weight 2000",
           ch.c[0].members==3 && ch.c[0].fee==4000 && ch.c[0].weight==2000);
    }
    {   /* EQUAL feerates must NOT merge: Core absorbs only on strictly greater */
        uint64_t f[3] = {1000,1000,1000}, w[3] = {1000,1000,1000};
        mk(&cl,3,f,w); int lin[3] = {0,1,2};
        ck("equal feerates do NOT absorb -> 3 chunks",
           mpc_chunk_linearization(&cl,lin,&ch)==0 && ch.n==3);
    }
    {   /* cascade: each later tx richer than the last, so all collapse to one */
        uint64_t f[4] = {100,200,400,800}, w[4] = {1000,1000,1000,1000};
        mk(&cl,4,f,w); int lin[4] = {0,1,2,3};
        ck("a rising cascade collapses to a single chunk",
           mpc_chunk_linearization(&cl,lin,&ch)==0 && ch.n==1 && ch.c[0].fee==1500);
    }
    {   /* chunk feerates must be non-increasing -- the invariant the whole
         * structure exists to provide */
        uint64_t f[5] = {500,3000,100,2000,50}, w[5] = {1000,1000,1000,1000,1000};
        mk(&cl,5,f,w); int lin[5] = {0,1,2,3,4};
        mpc_chunk_linearization(&cl,lin,&ch);
        int mono = 1;
        for (int i = 1; i < ch.n; i++)
            if (mpc_feerate_cmp(ch.c[i].fee, ch.c[i].weight,
                                ch.c[i-1].fee, ch.c[i-1].weight) > 0) mono = 0;
        ck("chunk feerates come out non-increasing", mono);
    }
    {   /* a malformed ordering must be REFUSED, not chunked into a
         * plausible-looking answer over the wrong set */
        uint64_t f[3] = {1,2,3}, w[3] = {1,1,1};
        mk(&cl,3,f,w);
        int dup[3] = {0,0,1}, oob[3] = {0,1,9};
        ck("a repeated member is refused", mpc_chunk_linearization(&cl,dup,&ch) == -1);
        ck("an out-of-range member is refused", mpc_chunk_linearization(&cl,oob,&ch) == -1);
    }

    printf("== topological validity ==\n");
    {   /* chain 0 <- 1 <- 2 */
        uint64_t f[3] = {1,1,1}, w[3] = {1,1,1};
        mk(&cl,3,f,w);
        cl.m[1].ancestors |= 1; cl.m[2].ancestors |= 3;
        cl.m[0].descendants |= 6; cl.m[1].descendants |= 4;
        int good[3] = {0,1,2}, bad[3] = {2,1,0}, mid[3] = {0,2,1};
        ck("parents-first is topological", mpc_is_topological(&cl,good));
        ck("reversed is NOT", !mpc_is_topological(&cl,bad));
        ck("a child before its parent is NOT", !mpc_is_topological(&cl,mid));
    }
    {   /* diamond: 0 -> {1,2} -> 3 */
        uint64_t f[4] = {1,1,1,1}, w[4] = {1,1,1,1};
        mk(&cl,4,f,w);
        cl.m[1].ancestors |= 1; cl.m[2].ancestors |= 1; cl.m[3].ancestors |= 0x7;
        int a[4] = {0,1,2,3}, b[4] = {0,2,1,3}, c[4] = {1,0,2,3};
        ck("diamond, both sibling orders are topological",
           mpc_is_topological(&cl,a) && mpc_is_topological(&cl,b));
        ck("diamond, child before parent is not", !mpc_is_topological(&cl,c));
    }
    {   /* a partial ordering is not a linearization */
        uint64_t f[3] = {1,1,1}, w[3] = {1,1,1};
        mk(&cl,3,f,w);
        int dup[3] = {0,1,1};
        ck("a repeated member is not topological", !mpc_is_topological(&cl,dup));
    }

    printf("\npassed %d, failed %d\n", pass, fail);
    if (fail) { printf("TESTS FAILED (%d failure(s))\n", fail); return 1; }
    printf("ALL TESTS PASSED (0 failures)\n");
    return 0;
}
