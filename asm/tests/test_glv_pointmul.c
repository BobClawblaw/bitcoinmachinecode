/* test_glv_pointmul.c -- PERF_SCOPE.md 4.3 (d): point_scalar_mul_glv vs
 * point_scalar_mul, the oracle-validated w=4 windowed multiply it replaces.
 *
 * Comparison is PROJECTIVE -- X1*Z2^2 == X2*Z1^2 and Y1*Z2^3 == Y2*Z1^3,
 * or both infinite -- so no test-side inversion is involved and a wrong
 * final "R.z *= Z" is caught as loudly as a wrong digit.
 *
 *  - lambda*G == (beta*Gx, Gy): the constants in secp256k1_scalar.asm and
 *    secp256k1_point.asm are the matching pair (not the conjugate roots).
 *  - k x Q grid: k in {1, 2, n-1, n-2, lambda, n-lambda, 2^128-1, 2^128,
 *    2^128+1, 2^255, n>>1} x Q in {G, 2G, -G, lambda*G, random}.
 *  - halves with every sign combination: k = (+-a) + lambda*(+-b) mod n
 *    for random a, b < 2^127, so the split must produce a negative half
 *    (bit 255 set) in three of the four cases.
 *  - >= 1e5 random (k, Q), Q = q*G for random q.
 *  - k == 0 -> infinity on both.
 *  - the kill switch is irrelevant to this function (it is applied by
 *    ecdsa_verify); both paths are called directly here.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned long long u64;
typedef unsigned __int128 u128;

extern void point_scalar_mul(u64 r[12], const u64 xy[8], const u64 k[4]);
extern void point_scalar_mul_glv(u64 r[12], const u64 xy[8], const u64 k[4]);
extern void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sqr(u64 r[4], const u64 a[4]);
extern void fe_inv(u64 r[4], const u64 a[4]);
extern void sc_add(u64 r[4], const u64 a[4], const u64 b[4]);
extern void sc_sub(u64 r[4], const u64 a[4], const u64 b[4]);
extern void sc_mul(u64 r[4], const u64 a[4], const u64 b[4]);

static const u64 N[4]      = {0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL};
static const u64 P[4]      = {0xFFFFFFFEFFFFFC2FULL,~0ULL,~0ULL,~0ULL};
static const u64 LAMBDA[4] = {0xDF02967C1B23BD72ULL,0x122E22EA20816678ULL,0xA5261C028812645AULL,0x5363AD4CC05C30E0ULL};
static const u64 BETA[4]   = {0xC1396C28719501EEULL,0x9CF0497512F58995ULL,0x6E64479EAC3434E9ULL,0x7AE96A2B657C0710ULL};
static const u64 Gaf[8]={
    0x59F2815B16F81798ULL,0x029BFCDB2DCE28D9ULL,0x55A06295CE870B07ULL,0x79BE667EF9DCBBACULL,
    0x9C47D08FFB10D4B8ULL,0xFD17B448A6855419ULL,0x5DA4FBFC0E1108A8ULL,0x483ADA7726A3C465ULL};

static long failures = 0, cases = 0;
#define CK(c, ...) do{ if(!(c)){ failures++; if(failures<=20){ printf("FAIL "); printf(__VA_ARGS__); printf("\n"); } } }while(0)
static u64 rng_s;
static u64 rnd(void){ u64 x=rng_s; x^=x<<13; x^=x>>7; x^=x<<17; rng_s=x; return x; }
static int ge4(const u64 a[4], const u64 b[4]){ for(int i=3;i>=0;i--){ if(a[i]>b[i]) return 1; if(a[i]<b[i]) return 0; } return 1; }
static void rnd_mod_n(u64 k[4]){ do { for(int i=0;i<4;i++) k[i]=rnd(); } while (ge4(k,N)); }
static int isinf(const u64 j[12]){ return (j[8]|j[9]|j[10]|j[11])==0; }
static void toaff(u64 ox[4], u64 oy[4], const u64 j[12]){ u64 zi[4],z2[4],z3[4]; fe_inv(zi,&j[8]); fe_sqr(z2,zi); fe_mul(z3,z2,zi); fe_mul(ox,&j[0],z2); fe_mul(oy,&j[4],z3); }

/* projective equality of two Jacobian points */
static int jac_eq(const u64 a[12], const u64 b[12]){
    if (isinf(a) || isinf(b)) return isinf(a) && isinf(b);
    u64 za2[4], zb2[4], za3[4], zb3[4], l[4], r[4];
    fe_sqr(za2,&a[8]); fe_sqr(zb2,&b[8]); fe_mul(za3,za2,&a[8]); fe_mul(zb3,zb2,&b[8]);
    fe_mul(l,&a[0],zb2); fe_mul(r,&b[0],za2); if (memcmp(l,r,32)) return 0;
    fe_mul(l,&a[4],zb3); fe_mul(r,&b[4],za3); return memcmp(l,r,32)==0;
}

static void one(const u64 Q[8], const u64 k[4], const char* lbl){
    u64 a[12], b[12];
    point_scalar_mul(a, Q, k);
    point_scalar_mul_glv(b, Q, k);
    cases++;
    CK(jac_eq(a,b), "%s: k=%016llx%016llx%016llx%016llx (ref inf=%d glv inf=%d)", lbl, k[3],k[2],k[1],k[0], isinf(a), isinf(b));
}

static void aff_of_scalar(u64 Q[8], const u64 q[4]){ u64 j[12]; point_scalar_mul(j, Gaf, q); toaff(&Q[0],&Q[4],j); }

int main(int argc, char** argv){
    rng_s = (argc>1) ? strtoull(argv[1],0,0) : 0x9e3779b97f4a7c15ULL;
    long nrand = (argc>2) ? atol(argv[2]) : 100000L;
    printf("seed=0x%llx random=%ld\n", rng_s, nrand);

    /* ---- lambda*G == (beta*Gx, Gy) ---- */
    { u64 j[12], x[4], y[4], bx[4];
      point_scalar_mul(j, Gaf, LAMBDA); toaff(x,y,j); fe_mul(bx, &Gaf[0], BETA);
      CK(memcmp(x,bx,32)==0 && memcmp(y,&Gaf[4],32)==0, "lambda*G != (beta*Gx, Gy): constants are not the matching pair");
      printf("lambda*G == (beta*Gx, Gy): %s\n", failures?"FAIL":"ok"); }

    /* ---- Q set ---- */
    u64 Qs[5][8]; const char* Qn[5] = {"G","2G","-G","lambda*G","random"};
    memcpy(Qs[0], Gaf, 64);
    { u64 two[4]={2,0,0,0}; aff_of_scalar(Qs[1], two); }
    memcpy(Qs[2], Gaf, 64); { u128 br=0; for(int i=0;i<4;i++){ u128 t=(u128)P[i]-Gaf[4+i]-br; Qs[2][4+i]=(u64)t; br=(t>>64)&1; } }
    memcpy(Qs[3], Gaf, 64); fe_mul(&Qs[3][0], &Gaf[0], BETA);
    { u64 q[4]; rnd_mod_n(q); aff_of_scalar(Qs[4], q); }

    /* ---- k edge set ---- */
    u64 ks[11][4]; int nk=0;
    { u64 t[4];
      t[0]=1;t[1]=0;t[2]=0;t[3]=0; memcpy(ks[nk++],t,32);
      t[0]=2; memcpy(ks[nk++],t,32);
      u64 one4[4]={1,0,0,0}, two4[4]={2,0,0,0};
      sc_sub(t, N, one4); memcpy(ks[nk++],t,32);            /* n-1 */
      sc_sub(t, N, two4); memcpy(ks[nk++],t,32);            /* n-2 */
      memcpy(ks[nk++], LAMBDA, 32);
      sc_sub(t, N, LAMBDA); memcpy(ks[nk++],t,32);          /* n-lambda */
      t[0]=~0ULL;t[1]=~0ULL;t[2]=0;t[3]=0; memcpy(ks[nk++],t,32);   /* 2^128-1 */
      t[0]=0;t[1]=0;t[2]=1;t[3]=0; memcpy(ks[nk++],t,32);           /* 2^128 */
      t[0]=1; memcpy(ks[nk++],t,32);                                 /* 2^128+1 */
      t[0]=0;t[1]=0;t[2]=0;t[3]=0x8000000000000000ULL; memcpy(ks[nk++],t,32); /* 2^255 */
      for(int i=0;i<4;i++){ t[i]=(N[i]>>1)|(i<3?(N[i+1]<<63):0); } memcpy(ks[nk++],t,32); /* n>>1 */
    }
    for (int qi=0; qi<5; qi++) { for (int ki=0; ki<nk; ki++){ char l[64]; snprintf(l,sizeof l,"grid Q=%s k#%d",Qn[qi],ki); one(Qs[qi], ks[ki], l); } }
    printf("grid: %d k x 5 Q\n", nk);

    /* ---- every sign combination of the halves ---- */
    for (int t=0; t<2000; t++){
        u64 a[4]={rnd(),rnd()&0x7FFFFFFFFFFFFFFFULL,0,0}, b[4]={rnd(),rnd()&0x7FFFFFFFFFFFFFFFULL,0,0};  /* < 2^127 */
        u64 na[4], nb[4], lb[4], k[4];
        sc_sub(na, N, a); sc_sub(nb, N, b);
        const u64* A = (t&1) ? na : a; const u64* B = (t&2) ? nb : b;
        sc_mul(lb, LAMBDA, B); sc_add(k, A, lb);
        char l[48]; snprintf(l,sizeof l,"signs %c%c", (t&1)?'-':'+', (t&2)?'-':'+');
        one(Qs[t%5], k, l);
    }
    printf("sign combinations: 2000 (500 per combination)\n");

    /* ---- k == 0 ---- */
    { u64 z[4]={0,0,0,0}; u64 b[12]; point_scalar_mul_glv(b, Gaf, z); CK(isinf(b), "k=0 must give infinity"); cases++; }

    /* ---- random ---- */
    for (long t=0; t<nrand; t++){
        u64 Q[8], q[4], k[4]; rnd_mod_n(q); aff_of_scalar(Q, q); rnd_mod_n(k);
        one(Q, k, "random");
    }
    printf("random (k, Q): %ld\n", nrand);

    printf("%ld cases compared\n", cases);
    if (failures){ printf("TESTS FAILED (%ld failures)\n", failures); return 1; }
    printf("ALL TESTS PASSED (0 failures)\n"); return 0;
}
