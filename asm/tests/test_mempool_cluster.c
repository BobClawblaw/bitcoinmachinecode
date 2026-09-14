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

/* test-only: locate a txid in a built cluster */
static int mpc_find_test(const mpc_cluster* cl, const unsigned char* id){
    for (int i = 0; i < cl->n; i++) if (!memcmp(cl->txid[i], id, 32)) return i;
    return -1;
}

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

    printf("== linearization (ancestor-score greedy) ==\n");
    {   /* independent txs must come out in descending feerate */
        uint64_t f[3] = {1000,3000,2000}, w[3] = {1000,1000,1000};
        mk(&cl,3,f,w); int lin[3];
        ck("independent txs linearize", mpc_linearize_ancestor_score(&cl,lin)==0);
        ck("...in descending feerate (1 then 2 then 0)",
           lin[0]==1 && lin[1]==2 && lin[2]==0);
        ck("...and the result is topological", mpc_is_topological(&cl,lin));
    }
    {   /* CPFP: a free parent with a rich child must be pulled forward TOGETHER,
         * ahead of a middling independent tx. This is the case the whole
         * structure exists for: scoring the child alone would strand the parent,
         * scoring the parent alone would bury the child. */
        uint64_t f[3] = {0, 6000, 2000}, w[3] = {1000,1000,1000};
        mk(&cl,3,f,w);
        cl.m[1].ancestors |= 1; cl.m[0].descendants |= 2;   /* 1 is child of 0 */
        int lin[3];
        ck("CPFP cluster linearizes", mpc_linearize_ancestor_score(&cl,lin)==0);
        ck("...parent immediately before its paying child",
           lin[0]==0 && lin[1]==1);
        ck("...and the middling independent tx comes last", lin[2]==2);
        ck("...topological", mpc_is_topological(&cl,lin));
        /* and the pair must chunk as ONE chunk: 6000 over 2000 beats 2000/1000 */
        mpc_chunk_linearization(&cl,lin,&ch);
        ck("...the CPFP pair forms one chunk ahead of the loner",
           ch.n==2 && ch.c[0].members==3 && ch.c[1].members==4);
    }
    {   /* a rich parent with a poor child: the parent goes first ALONE, the
         * child is not dragged forward by its parent's feerate */
        uint64_t f[2] = {8000, 10}, w[2] = {1000,1000};
        mk(&cl,2,f,w);
        cl.m[1].ancestors |= 1; cl.m[0].descendants |= 2;
        int lin[2];
        mpc_linearize_ancestor_score(&cl,lin);
        ck("a poor child does not ride its rich parent forward",
           lin[0]==0 && lin[1]==1);
        mpc_chunk_linearization(&cl,lin,&ch);
        ck("...and they chunk separately", ch.n==2);
    }
    {   /* chain where the LAST tx pays for everything */
        uint64_t f[4] = {0,0,0,40000}, w[4] = {1000,1000,1000,1000};
        mk(&cl,4,f,w);
        cl.m[1].ancestors |= 0x1; cl.m[2].ancestors |= 0x3; cl.m[3].ancestors |= 0x7;
        cl.m[0].descendants |= 0xe; cl.m[1].descendants |= 0xc; cl.m[2].descendants |= 0x8;
        int lin[4];
        ck("a chain paid for by its tip linearizes", mpc_linearize_ancestor_score(&cl,lin)==0);
        ck("...in chain order", lin[0]==0&&lin[1]==1&&lin[2]==2&&lin[3]==3);
        ck("...topological", mpc_is_topological(&cl,lin));
        mpc_chunk_linearization(&cl,lin,&ch);
        ck("...and the whole chain is one chunk", ch.n==1 && ch.c[0].fee==40000);
    }
    {   /* determinism: equal feerates must not produce an arbitrary order */
        uint64_t f[4] = {1000,1000,1000,1000}, w[4] = {1000,1000,1000,1000};
        mk(&cl,4,f,w);
        int a[4], b[4];
        mpc_linearize_ancestor_score(&cl,a);
        mpc_linearize_ancestor_score(&cl,b);
        ck("equal feerates linearize deterministically",
           memcmp(a,b,sizeof a)==0);
        ck("...breaking the tie by lowest index",
           a[0]==0 && a[1]==1 && a[2]==2 && a[3]==3);
    }
    {   /* the output must always be a valid permutation, on a wide graph */
        uint64_t f[8], w[8];
        for (int i=0;i<8;i++){ f[i]=(uint64_t)(7-i)*500; w[i]=1000; }
        mk(&cl,8,f,w);
        for (int i=4;i<8;i++){ cl.m[i].ancestors |= 1; cl.m[0].descendants |= (uint64_t)1<<i; }
        int lin[8];
        ck("a wide fan-out linearizes topologically",
           mpc_linearize_ancestor_score(&cl,lin)==0 && mpc_is_topological(&cl,lin));
        ck("...and chunking accepts it", mpc_chunk_linearization(&cl,lin,&ch)==0);
        int mono=1;
        for (int i=1;i<ch.n;i++)
            if (mpc_feerate_cmp(ch.c[i].fee,ch.c[i].weight,ch.c[i-1].fee,ch.c[i-1].weight)>0) mono=0;
        ck("...producing non-increasing chunk feerates", mono);
    }

    printf("== cluster discovery ==\n");
    {   /* A tiny in-memory mempool the lookup callback reads. Edges are given
         * as direct parents only; children are derived, so the fixture cannot
         * disagree with itself the way a hand-written pair of lists can. */
        static struct { unsigned char id[32]; uint64_t fee, wt; int np; int par[4]; } POOL[] = {
            /* 0 */ {{0xA0}, 1000, 1000, 0, {0}},
            /* 1 */ {{0xA1}, 2000, 1000, 1, {0}},        /* child of 0 */
            /* 2 */ {{0xA2}, 3000, 1000, 1, {0}},        /* sibling of 1 */
            /* 3 */ {{0xA3}, 4000, 1000, 2, {1,2}},      /* diamond tip */
            /* 4 */ {{0xB0}, 9000, 1000, 0, {0}},        /* a SEPARATE cluster */
        };
        static const int NPOOL = 5;
        /* the callback: find by id, report direct parents and derived children */
        int lookup(void* c, const unsigned char* id, mpc_entry* o){
            (void)c;
            for (int i = 0; i < NPOOL; i++){
                if (memcmp(POOL[i].id, id, 32)) continue;
                memset(o, 0, sizeof *o);
                o->fee = POOL[i].fee; o->weight = POOL[i].wt;
                o->n_parents = POOL[i].np;
                for (int k = 0; k < POOL[i].np; k++)
                    memcpy(o->parents[k], POOL[POOL[i].par[k]].id, 32);
                for (int j = 0; j < NPOOL; j++)
                    for (int k = 0; k < POOL[j].np; k++)
                        if (POOL[j].par[k] == i)
                            memcpy(o->children[o->n_children++], POOL[j].id, 32);
                return 1;
            }
            return 0;
        }
        mpc_cluster c2;
        ck("a diamond cluster is discovered from its ROOT",
           mpc_build_cluster(0, lookup, POOL[0].id, &c2)==0 && c2.n==4);
        ck("...and from its TIP, giving the same membership",
           mpc_build_cluster(0, lookup, POOL[3].id, &c2)==0 && c2.n==4);
        /* the sibling is in the cluster although it is nobody's ancestor --
         * this is the whole reason clusters are components, not ancestor sets */
        ck("...a sibling is included though it is not an ancestor",
           mpc_find_test(&c2, POOL[2].id) >= 0);
        ck("...the separate cluster is NOT pulled in",
           mpc_find_test(&c2, POOL[4].id) < 0);
        ck("...and that one stands alone",
           mpc_build_cluster(0, lookup, POOL[4].id, &c2)==0 && c2.n==1);

        mpc_build_cluster(0, lookup, POOL[0].id, &c2);
        int r = mpc_find_test(&c2, POOL[0].id), t = mpc_find_test(&c2, POOL[3].id);
        ck("the tip's ancestors are the whole cluster",
           c2.m[t].ancestors == (((uint64_t)1 << c2.n) - 1));
        ck("the root's descendants are the whole cluster",
           c2.m[r].descendants == (((uint64_t)1 << c2.n) - 1));
        ck("the root has only itself as an ancestor",
           c2.m[r].ancestors == ((uint64_t)1 << r));
        int lin[MPC_MAX_CLUSTER];
        ck("a discovered cluster linearizes topologically",
           mpc_linearize_ancestor_score(&c2, lin)==0 && mpc_is_topological(&c2, lin));
        { unsigned char nosuch[32]; memset(nosuch, 0xff, sizeof nosuch);
          ck("an absent seed is refused",
             mpc_build_cluster(0, lookup, nosuch, &c2) == -1); }
    }

    printf("== the 64 bound ==\n");
    {   /* Core rejects a transaction that would exceed DEFAULT_CLUSTER_LIMIT, so
         * a real Core cluster always fits. This node's limits are not identical,
         * so a component CAN exceed it -- and a truncated walk is NOT a cluster.
         * Reporting one as if it were would describe a block-space competition
         * that omits most of its competitors. A 100-long chain forces it. */
        int chain_lookup(void* c, const unsigned char* id, mpc_entry* o){
            (void)c;
            int i = id[0] | (id[1] << 8);
            if (id[2] != 0x5A || i < 0 || i >= 100) return 0;
            memset(o, 0, sizeof *o);
            o->fee = 1000; o->weight = 1000;
            if (i > 0){ o->parents[0][0] = (unsigned char)((i-1) & 0xff);
                        o->parents[0][1] = (unsigned char)((i-1) >> 8);
                        o->parents[0][2] = 0x5A; o->n_parents = 1; }
            if (i < 99){ o->children[0][0] = (unsigned char)((i+1) & 0xff);
                         o->children[0][1] = (unsigned char)((i+1) >> 8);
                         o->children[0][2] = 0x5A; o->n_children = 1; }
            return 1;
        }
        unsigned char seed[32]; memset(seed, 0, sizeof seed); seed[2] = 0x5A;
        mpc_cluster c3;
        ck("a 100-long chain does not overflow the cluster",
           mpc_build_cluster(0, chain_lookup, seed, &c3)==0);
        ck("...it stops at the 64 bound", c3.n <= MPC_MAX_CLUSTER);
        ck("...and SAYS it was truncated", c3.truncated == 1);
        /* a component that fits must NOT be flagged */
        int short_lookup(void* c, const unsigned char* id, mpc_entry* o){
            (void)c;
            int i = id[0] | (id[1] << 8);
            if (id[2] != 0x5A || i < 0 || i >= 10) return 0;
            memset(o, 0, sizeof *o);
            o->fee = 1000; o->weight = 1000;
            if (i > 0){ o->parents[0][0] = (unsigned char)(i-1); o->parents[0][2] = 0x5A; o->n_parents = 1; }
            if (i < 9){ o->children[0][0] = (unsigned char)(i+1); o->children[0][2] = 0x5A; o->n_children = 1; }
            return 1;
        }
        ck("a 10-long chain fits and is NOT flagged truncated",
           mpc_build_cluster(0, short_lookup, seed, &c3)==0 && c3.n==10 && c3.truncated==0);
    }

    printf("== index order is NOT topological order ==\n");
    {   /* Every hand-built case above happens to number parents below children,
         * so emitting a chosen set in plain index order looks correct. Real
         * clusters carry whatever indices the mempool handed out. Here member 0
         * is the CHILD of member 2: emitting by index would place the child
         * first. */
        uint64_t f[3] = {5000, 100, 0}, w[3] = {1000,1000,1000};
        mk(&cl,3,f,w);
        cl.m[0].ancestors |= (uint64_t)1 << 2;      /* 0 is a child of 2 */
        cl.m[2].descendants |= (uint64_t)1 << 0;
        int lin[3];
        ck("a cluster whose index order is not topological linearizes",
           mpc_linearize_ancestor_score(&cl,lin)==0);
        ck("...and the parent (2) precedes its child (0)",
           mpc_is_topological(&cl,lin));
        int p2=-1,p0=-1;
        for (int i=0;i<3;i++){ if(lin[i]==2)p2=i; if(lin[i]==0)p0=i; }
        ck("...explicitly: 2 before 0", p2 >= 0 && p0 >= 0 && p2 < p0);
    }
    {   /* deeper: a reversed chain, 3 <- 2 <- 1 <- 0 by index */
        uint64_t f[4] = {9000,0,0,0}, w[4] = {1000,1000,1000,1000};
        mk(&cl,4,f,w);
        cl.m[2].ancestors |= (uint64_t)1<<3;
        cl.m[1].ancestors |= cl.m[2].ancestors;
        cl.m[0].ancestors |= cl.m[1].ancestors;
        for (int i=0;i<4;i++) for (int j=0;j<4;j++)
            if (cl.m[j].ancestors & ((uint64_t)1<<i)) cl.m[i].descendants |= (uint64_t)1<<j;
        int lin[4];
        mpc_linearize_ancestor_score(&cl,lin);
        ck("a chain numbered backwards still comes out topological",
           mpc_is_topological(&cl,lin));
        ck("...emitted in dependency order 3,2,1,0",
           lin[0]==3 && lin[1]==2 && lin[2]==1 && lin[3]==0);
    }

    printf("== tie-breaks are exercised, not just present ==\n");
    {   /* equal feerate, different weight: Core prefers the SMALLER. Without a
         * weight tie-break the scan keeps whichever it met first, so this is the
         * only case that can tell the two apart. */
        uint64_t f[2] = {2000, 1000}, w[2] = {2000, 1000};   /* both 1 sat/wu */
        mk(&cl,2,f,w);
        int lin[2];
        mpc_linearize_ancestor_score(&cl,lin);
        ck("equal feerate: the smaller transaction goes first", lin[0]==1 && lin[1]==0);
    }

    printf("== randomised DAGs: the invariants must hold for ANY cluster ==\n");
    {   /* Hand-built cases test what the author thought of. These test what he
         * did not. A linearization that is merely usually topological would have
         * a block template spend an output before creating it. */
        unsigned seed = 20260914u;
        int bad_topo = 0, bad_mono = 0, bad_rc = 0, bad_perm = 0, n_cases = 0;
        for (int trial = 0; trial < 4000; trial++) {
            /* xorshift, so the corpus is reproducible from the seed alone */
            seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5;
            int n = 1 + (int)(seed % 16);
            memset(&cl, 0, sizeof cl); cl.n = n;
            for (int i = 0; i < n; i++) {
                seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5;
                /* fee 0 is legal and important: free CPFP parents are the case
                 * chunking exists for */
                cl.m[i].fee = seed % 50000;
                cl.m[i].weight = 400 + (seed % 3600);
                cl.m[i].ancestors = (uint64_t)1 << i;
                cl.m[i].descendants = (uint64_t)1 << i;
            }
            /* random DAG: edges only from lower to higher index, so it is
             * acyclic by construction; then close ancestors transitively */
            /* Edges follow a random PERMUTATION of the indices, not the index
             * order itself. Generating only low->high edges makes index order
             * always topological, which silently stops testing the dependency
             * check in the emit loop -- a defect this suite missed until the
             * fix was reverted and nothing failed. */
            int perm[MPC_MAX_CLUSTER];
            for (int i = 0; i < n; i++) perm[i] = i;
            for (int i = n - 1; i > 0; i--) {
                seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5;
                int j = (int)(seed % (unsigned)(i + 1));
                int t = perm[i]; perm[i] = perm[j]; perm[j] = t;
            }
            for (int ci = 1; ci < n; ci++)
                for (int pi = 0; pi < ci; pi++) {
                    seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5;
                    if (seed % 100 < 25)
                        cl.m[perm[ci]].ancestors |= cl.m[perm[pi]].ancestors;
                }
            for (int i = 0; i < n; i++)
                for (int j = 0; j < n; j++)
                    if (cl.m[j].ancestors & ((uint64_t)1 << i))
                        cl.m[i].descendants |= (uint64_t)1 << j;

            int lin[MPC_MAX_CLUSTER];
            if (mpc_linearize_ancestor_score(&cl, lin) != 0) { bad_rc++; continue; }
            n_cases++;
            if (!mpc_is_topological(&cl, lin)) bad_topo++;
            uint64_t seen = 0; int dup = 0;
            for (int i = 0; i < n; i++) {
                if (lin[i] < 0 || lin[i] >= n) { dup = 1; break; }
                if (seen & ((uint64_t)1 << lin[i])) { dup = 1; break; }
                seen |= (uint64_t)1 << lin[i];
            }
            if (dup) bad_perm++;
            if (mpc_chunk_linearization(&cl, lin, &ch) != 0) { bad_rc++; continue; }
            for (int i = 1; i < ch.n; i++)
                if (mpc_feerate_cmp(ch.c[i].fee, ch.c[i].weight,
                                    ch.c[i-1].fee, ch.c[i-1].weight) > 0) { bad_mono++; break; }
            /* the chunks must partition the cluster exactly -- no member lost,
             * none counted twice */
            uint64_t cover = 0; int overlap = 0;
            for (int i = 0; i < ch.n; i++) {
                if (cover & ch.c[i].members) overlap = 1;
                cover |= ch.c[i].members;
            }
            if (overlap || cover != seen) bad_perm++;
        }
        printf("      %d random DAGs, up to 16 members, ~25%% edge density\n", n_cases);
        ck("every linearization is topological", bad_topo == 0);
        ck("every linearization is a permutation, chunks partition it", bad_perm == 0);
        ck("every chunking is non-increasing in feerate", bad_mono == 0);
        ck("no call failed unexpectedly", bad_rc == 0);
    }

    printf("\npassed %d, failed %d\n", pass, fail);
    if (fail) { printf("TESTS FAILED (%d failure(s))\n", fail); return 1; }
    printf("ALL TESTS PASSED (0 failures)\n");
    return 0;
}
