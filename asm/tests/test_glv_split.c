/* test_glv_split.c -- PERF_SCOPE.md 4.3 (b): sc_mul_512 and sc_split_lambda.
 *
 *  1. sc_mul_512 vs an independent C schoolbook (unsigned __int128 limb
 *     products) over the edge pairs {0, 1, n-1, 2^256-1}^2 and >= 1e6 random
 *     operands -- all 8 limbs byte-exact.
 *  2. sc_split_lambda vs validation/glv_split_oracle.py's EXACT (r1, r2) for
 *     every vector in glv_split_vec.h (edge set + 2000 random k). Exactness
 *     matters: an off-by-one in the rounding bit still satisfies the
 *     identity but can push a half past 128 bits, where the 129-slot wNAF
 *     would silently misrepresent it.
 *  3. >= 1e6 random k < n: the call succeeds, LAMBDA*r2 + r1 == k (mod n)
 *     recomputed here with sc_mul/sc_add, and each half is within Core's
 *     own VERIFY-build bounds (k1_bound / k2_bound, scalar_impl.h:283-312):
 *     r < bound or (n - r) < bound, which implies the < 2^128 magnitude.
 *
 *  --dump N  prints "k r1 r2" hex lines (edges + N random) for
 *  validation/glv_split_oracle.py check -- the out-of-tree exact comparison
 *  at 1e6 scale, too big for a header.
 *
 * Seed printed; argv[1] = seed, argv[2] = scale (default 1).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned long long u64;
typedef unsigned __int128 u128;

extern void sc_mul_512(u64 r[8], const u64 a[4], const u64 b[4]);
extern int  sc_split_lambda(u64 r1[4], u64 r2[4], const u64 k[4]);
extern void sc_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern void sc_add(u64 r[4], const u64 a[4], const u64 b[4]);

#include "glv_split_vec.h"

static const u64 N[4]      = {0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL};
static const u64 LAMBDA[4] = {0xDF02967C1B23BD72ULL,0x122E22EA20816678ULL,0xA5261C028812645AULL,0x5363AD4CC05C30E0ULL};
static const u64 K1B[4]    = {0x2016D0B917E4DD77ULL,0xA2A8918CA85BAFE2ULL,0,0};   /* (a1+a2+1)/2 */
static const u64 K2B[4]    = {0x2BE08846CEA267EDULL,0x8A65287BD47179FBULL,0,0};   /* (-b1+b2)/2+1 */

static long failures = 0;
#define CK(c, ...) do{ if(!(c)){ failures++; if(failures<=20){ printf("FAIL "); printf(__VA_ARGS__); printf("\n"); } } }while(0)

static u64 rng_s;
static u64 rnd(void){ u64 x=rng_s; x^=x<<13; x^=x>>7; x^=x<<17; rng_s=x; return x; }
static int ge4(const u64 a[4], const u64 b[4]){ for(int i=3;i>=0;i--){ if(a[i]>b[i]) return 1; if(a[i]<b[i]) return 0; } return 1; }
static int lt4(const u64 a[4], const u64 b[4]){ return !ge4(a,b); }
static void sub4(u64 r[4], const u64 a[4], const u64 b[4]){ u128 br=0; for(int i=0;i<4;i++){ u128 t=(u128)a[i]-b[i]-br; r[i]=(u64)t; br=(t>>64)&1; } }
static void rnd_mod_n(u64 k[4]){ do { for(int i=0;i<4;i++) k[i]=rnd(); } while (ge4(k,N)); }

static void ref_mul_512(u64 r[8], const u64 a[4], const u64 b[4]){
    u64 acc[9]; memset(acc,0,sizeof acc);
    for(int i=0;i<4;i++){
        u64 carry=0;
        for(int j=0;j<4;j++){
            u128 t=(u128)a[i]*b[j] + acc[i+j] + carry;
            acc[i+j]=(u64)t; carry=(u64)(t>>64);
        }
        acc[i+4]+=carry;
    }
    memcpy(r,acc,64);
}

static void campaign1(long nrand){
    static const u64 E[4][4] = {{0,0,0,0},{1,0,0,0},
        {0xBFD25E8CD0364140ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL},
        {~0ULL,~0ULL,~0ULL,~0ULL}};
    long n=0; u64 got[8], want[8];
    for(int i=0;i<4;i++) for(int j=0;j<4;j++){ sc_mul_512(got,E[i],E[j]); ref_mul_512(want,E[i],E[j]); CK(memcmp(got,want,64)==0,"mul_512 edge %d x %d",i,j); n++; }
    for(long t=0;t<nrand;t++){ u64 a[4],b[4]; for(int i=0;i<4;i++){a[i]=rnd();b[i]=rnd();}
        sc_mul_512(got,a,b); ref_mul_512(want,a,b); CK(memcmp(got,want,64)==0,"mul_512 random #%ld",t); n++; }
    printf("campaign 1: sc_mul_512 vs C schoolbook: %ld cases\n", n);
}

static void campaign2(void){
    long n=0;
    for(int v=0; v<GLV_SPLIT_NVEC; v++){
        const u64* k=&glv_split_vec[v][0]; const u64* e1=&glv_split_vec[v][4]; const u64* e2=&glv_split_vec[v][8];
        u64 r1[4],r2[4]; int rc=sc_split_lambda(r1,r2,k);
        CK(rc==1,"vec %d: rc=%d",v,rc);
        CK(memcmp(r1,e1,32)==0 && memcmp(r2,e2,32)==0,"vec %d: split != python (k=%016llx%016llx%016llx%016llx)",v,k[3],k[2],k[1],k[0]);
        n++;
    }
    printf("campaign 2: sc_split_lambda exact vs python oracle: %ld vectors (incl. edge set)\n", n);
}

static int within_bound(const u64 r[4], const u64 bound[4]){
    u64 neg[4]; if ((r[0]|r[1]|r[2]|r[3])==0) return 1;
    sub4(neg, N, r);
    return lt4(r,bound) || lt4(neg,bound);
}
static void campaign3(long nrand){
    long n=0;
    for(long t=0;t<nrand;t++){
        u64 k[4],r1[4],r2[4],s[4]; rnd_mod_n(k);
        int rc=sc_split_lambda(r1,r2,k);
        CK(rc==1,"random #%ld: rc=%d",t,rc);
        sc_mul(s,LAMBDA,r2); sc_add(s,s,r1);
        CK(memcmp(s,k,32)==0,"random #%ld: identity r1 + LAMBDA*r2 != k",t);
        CK(within_bound(r1,K1B),"random #%ld: |r1| >= k1_bound",t);
        CK(within_bound(r2,K2B),"random #%ld: |r2| >= k2_bound",t);
        n++;
    }
    printf("campaign 3: sc_split_lambda identity + Core bounds: %ld random k\n", n);
}

static void dump(long nrand){
    for(int v=0; v<GLV_SPLIT_NVEC; v++){
        const u64* k=&glv_split_vec[v][0]; u64 r1[4],r2[4]; sc_split_lambda(r1,r2,k);
        printf("%016llx%016llx%016llx%016llx %016llx%016llx%016llx%016llx %016llx%016llx%016llx%016llx\n",
               k[3],k[2],k[1],k[0], r1[3],r1[2],r1[1],r1[0], r2[3],r2[2],r2[1],r2[0]);
    }
    for(long t=0;t<nrand;t++){ u64 k[4],r1[4],r2[4]; rnd_mod_n(k); sc_split_lambda(r1,r2,k);
        printf("%016llx%016llx%016llx%016llx %016llx%016llx%016llx%016llx %016llx%016llx%016llx%016llx\n",
               k[3],k[2],k[1],k[0], r1[3],r1[2],r1[1],r1[0], r2[3],r2[2],r2[1],r2[0]); }
}

int main(int argc, char** argv){
    if (argc>=2 && strcmp(argv[1],"--dump")==0){ rng_s=0x9e3779b97f4a7c15ULL; dump(argc>=3?atol(argv[2]):1000000L); return 0; }
    rng_s = (argc>1) ? strtoull(argv[1],0,0) : 0x9e3779b97f4a7c15ULL;
    long scale = (argc>2) ? atol(argv[2]) : 1;
    printf("seed=0x%llx scale=%ld\n", rng_s, scale);
    campaign1(1000000L*scale);
    campaign2();
    campaign3(1000000L*scale);
    if (failures){ printf("TESTS FAILED (%ld failures)\n", failures); return 1; }
    printf("ALL TESTS PASSED (0 failures)\n"); return 0;
}
