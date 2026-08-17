/* test_idx.c -- harness for asm bitcoin_idx.asm hash->height index.
 * Inserts (random hash, height) pairs, checks idx_get returns each by its FULL
 * 32-byte key, verifies duplicates rejected, negative lookups, and heavy-
 * collision probing all behave. Uses a PRNG with unique first-8 bytes so hash
 * collisions are genuine (not from weak random data). */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

extern void idx_init(void* idx, unsigned long slots);
extern int  idx_put(void* idx, const unsigned char hash[32], long height);
extern int  idx_get(void* idx, const unsigned char hash[32], long* height);
extern long idx_count(void* idx);

static double now_s(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); return ts.tv_sec+ts.tv_nsec*1e-9; }

static int failures=0;
static void ck(const char* l,int g,int e){ if(g==e)printf("PASS %s\n",l); else{printf("FAIL %s got=%d exp=%d\n",l,g,e);failures++;} }

#define N 5000
static unsigned char hashes[N][32];
static uint64_t sx=0x9E3779B97F4A7C15ull;
static uint64_t rnd64(void){ sx^=sx<<13; sx^=sx>>7; sx^=sx<<17; return sx; }

int main(void){
    /* big table: 16384 slots (mask 16383), 5000 inserts (30% load) */
    static unsigned char idxbuf[24 + 16384*48];
    idx_init(idxbuf, 16384);
    ck("init n=0", (int)idx_count(idxbuf), 0);
    unsigned char nh0[32]={0}; long h0=0;
    ck("init empty get", idx_get(idxbuf, nh0, &h0), 0);

    /* insert N hashes: ensure unique first-8-bytes so real hash distribution */
    for(int i=0;i<N;i++){
        uint64_t t=rnd64();
        for(int k=0;k<8;k++) hashes[i][k]=(unsigned char)(t>>(8*k));
        for(int k=8;k<32;k++) hashes[i][k]=(unsigned char)rnd64();
        int r=idx_put(idxbuf, hashes[i], i*3+1);
        if(r!=1){ printf("FAIL insert %d got=%d\n",i,r); failures++; break; }
    }
    ck("count==#inserted", (int)idx_count(idxbuf), N);

    /* lookup every inserted hash by its full 32-byte key */
    long got; int bad=0;
    for(int i=0;i<N;i++){
        if(idx_get(idxbuf, hashes[i], &got)!=1 || got!=(long)(i*3+1)){ bad++; if(bad<5)printf("  miss i=%d\n",i); }
    }
    ck("all 5000 lookups found", bad, 0);

    /* negative: random non-inserted hash */
    unsigned char nh[32]; for(int k=0;k<32;k++) nh[k]=(unsigned char)rnd64();
    ck("random unseen not found", idx_get(idxbuf, nh, &got), 0);

    /* duplicate insert returns 0, count unchanged */
    ck("re-insert dup rejected", idx_put(idxbuf, hashes[0], 777), 0);
    ck("dup did not change count", (int)idx_count(idxbuf), N);

    /* heavy-collision probe: many DISTINCT keys that hash to the SAME slot
     * (bytes 0-7 fixed -> identical hash slot; bytes 8-31 vary -> distinct
     * full 32-byte keys), forcing a deep linear-probe chain. */
    static unsigned char idxb2[24 + 512*48];
    idx_init(idxb2, 512);
    static unsigned char h2[400][32];
    for(int i=0;i<400;i++){
        for(int k=0;k<8;k++) h2[i][k]=0xAA;        /* fixed -> same slot */
        h2[i][8]=(unsigned char)(i&0xff);          /* encode i in bytes 8-9 */
        h2[i][9]=(unsigned char)((i>>8)&0xff);
        for(int k=10;k<32;k++) h2[i][k]=0x55;      /* constant tail (unique via 8-9) */
        if(idx_put(idxb2, h2[i], i*11)!=1){ printf("FAIL insert2 %d\n",i); failures++; }
    }
    int miss2=0;
    for(int i=0;i<400;i++){
        long g2; if(idx_get(idxb2,h2[i],&g2)!=1 || g2!=(long)(i*11)) miss2++;
    }
    ck("heavy-collision: all 400 found", miss2, 0);
    ck("count2==400", (int)idx_count(idxb2), 400);

    /* REGRESSION GUARD (found on the real ~962k-record mainnet archive):
     * idx_hash originally hashed only the first 8 bytes of the 32-byte key.
     * Every REAL Bitcoin block hash's leading bytes (in the byte order this
     * table is queried with) are near-zero BY CONSTRUCTION -- that's what a
     * valid proof-of-work hash is -- so a hash function that only looks at
     * those bytes sees almost no entropy across different real inputs and
     * clusters catastrophically (measured: 400,000 real hashes took 15.8s
     * to insert vs 0.04s for 400,000 uniform-random hashes into the same
     * table). The tests above never caught this because they deliberately
     * randomize the first 8 bytes to avoid exactly this collision pattern.
     * This case targets the actual mechanism directly (see the inner
     * comment below for why) and asserts insertion stays fast -- if
     * idx_hash regresses to prefix-only hashing, this will time out/fail
     * loudly instead of silently reintroducing a ~1800x slowdown (and
     * degrading live getdata-by-hash serving, which uses the same idx_hash
     * via idx_get). */
    {
        const int M = 500000;
        static unsigned char idxb3[24 + (1<<21)*48];   /* ~24% load factor at M=500000, matching production's HT_SLOTS scale */
        idx_init(idxb3, 1<<21);
        static unsigned char h3[500000][32];
        for(int i=0;i<M;i++){
            /* IDENTICAL first 8 bytes for every key, varying only bytes 8-31.
             * Real Bitcoin data doesn't go this far (real hashes vary a bit
             * within their first 8 bytes even under heavy PoW), but weaker
             * synthetic variants (a shared 4- or 6-byte zero prefix with a
             * random remainder) turned out NOT to reproduce the real
             * slowdown at this M/table-size -- FNV+mask still spreads a
             * partially-varying 8-byte window well enough. This fully-fixed
             * prefix directly targets the actual mechanism instead: an
             * 8-byte-only hash provably collides on ONE bucket for every
             * item here, so it's an unambiguous regression guard against
             * "idx_hash stops looking past byte 8", which is the exact
             * defect that caused the real-archive slowdown. */
            for(int k=0;k<8;k++) h3[i][k]=0xAB;
            for(int k=8;k<32;k++) h3[i][k]=(unsigned char)rnd64();
        }
        double t0=now_s();
        int ins_bad=0;
        for(int i=0;i<M;i++) if(idx_put(idxb3, h3[i], i)!=1) ins_bad++;
        double dt=now_s()-t0;
        ck("pow-prefix: all inserted (0 unexpected dup/full)", ins_bad, 0);
        int lookup_bad=0; long g3;
        for(int i=0;i<M;i++) if(idx_get(idxb3,h3[i],&g3)!=1 || g3!=(long)i) lookup_bad++;
        ck("pow-prefix: all lookups found", lookup_bad, 0);
        /* generous bound: healthy distribution does this in well under 1s;
         * the original bug took 15.8s for 400k similarly-shared-prefix
         * inserts into a comparably-loaded table -- 3s is miles below that
         * and far above any plausible healthy-hash runtime, so this can't
         * flake on a slow CI box while still catching a real regression. */
        ck("pow-prefix: insertion stayed fast (no clustering)", dt < 3.0 ? 1 : 0, 1);
        if(dt>=3.0) printf("  (took %.3fs for %d inserts -- clustering regression?)\n", dt, M);
    }

    printf(failures? "FAILURES %d\n" : "ALL TESTS PASSED (0 failures)\n", failures);
    return failures?1:0;
}
