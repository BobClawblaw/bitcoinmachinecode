/* test_ecdsa_inverse.c -- PERF_SCOPE.md 4.2 levers A+B differential test.
 *
 *   A. ecdsa_verify's affine x-compare (fe_inv) was replaced by the
 *      projective test ecdsa_x_eq_mod_n: r*Z^2 == X  or  (r+n < p and
 *      (r+n)*Z^2 == X).
 *   B. w = s^{-1} moved from Fermat sc_inv (450 sc_mul) to the variable-time
 *      binary-xgcd sc_inv_var.
 *
 * Three campaigns, every one a byte-exact comparison against something that
 * did NOT change:
 *   1. sc_inv_var vs sc_inv over >= 1e6 random scalars + edge values, plus
 *      the identity a * inv(a) == 1 for each.
 *   2. ecdsa_x_eq_mod_n at function level, including the r+n branch (which a
 *      real signature reaches with probability ~2^-127, so only a constructed
 *      Jacobian point can exercise it) and the r == p-n boundary.
 *   3. ecdsa_verify (new) vs ecdsa_verify_ref (tests/ecdsa_verify_ref.asm, a
 *      frozen copy of the pre-change code) over the libsecp256k1-signed
 *      fixtures in ecdsa_inverse_vec.h, tampered variants of each, and random
 *      tuples -- plus the 8 vectors of tests/test_ecdsa.c.
 *
 * Seed is printed; pass it as argv[1] to reproduce. argv[2] scales the random
 * counts (default 1).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned long long u64;

extern int  ecdsa_verify(const u64 z[4], const u64 r[4], const u64 s[4], const u64 Qx[4], const u64 Qy[4]);
extern int  ecdsa_verify_ref(const u64 z[4], const u64 r[4], const u64 s[4], const u64 Qx[4], const u64 Qy[4]);
extern int  ecdsa_x_eq_mod_n(const u64 r[4], const u64 X[4], const u64 Z[4]);
extern void sc_inv(u64 r[4], const u64 a[4]);
extern int  sc_inv_var(u64 r[4], const u64 a[4]);
extern void sc_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_add(u64 r[4], const u64 a[4], const u64 b[4]);

#include "ecdsa_inverse_vec.h"

static const u64 N[4]   = {0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL};
static const u64 PMN[4] = {0x402DA1722FC9BAEEULL,0x4551231950B75FC4ULL,1ULL,0ULL}; /* p - n */
static const u64 ONE[4] = {1,0,0,0};

static long failures = 0;
#define CK(cond, ...) do{ if(!(cond)){ failures++; printf("FAIL "); printf(__VA_ARGS__); printf("\n"); } }while(0)

static u64 rng_s;
static u64 rnd(void){ u64 x=rng_s; x^=x<<13; x^=x>>7; x^=x<<17; rng_s=x; return x; }
static void rnd4(u64 a[4]){ for(int i=0;i<4;i++) a[i]=rnd(); }

static int ge(const u64 a[4], const u64 b[4]){ /* a >= b */
    for(int i=3;i>=0;i--){ if(a[i]>b[i]) return 1; if(a[i]<b[i]) return 0; } return 1;
}
static void sub4(u64 r[4], const u64 a[4], const u64 b[4]){ /* plain, caller ensures a>=b */
    unsigned __int128 br=0;
    for(int i=0;i<4;i++){ unsigned __int128 t=(unsigned __int128)a[i]-b[i]-br; r[i]=(u64)t; br=(t>>64)&1; }
}
static void add4(u64 r[4], const u64 a[4], const u64 b[4]){ /* plain, no carry-out expected */
    unsigned __int128 c=0;
    for(int i=0;i<4;i++){ unsigned __int128 t=(unsigned __int128)a[i]+b[i]+c; r[i]=(u64)t; c=t>>64; }
}
static void rnd_scalar(u64 a[4]){ /* uniform-ish in [1,n) */
    rnd4(a); if(ge(a,N)) sub4(a,a,N);
    if(!(a[0]|a[1]|a[2]|a[3])) a[0]=1;
}
static void pow2(u64 a[4], int k){ memset(a,0,32); a[k>>6]=1ULL<<(k&63); }

/* ---------------- campaign 1: sc_inv_var vs sc_inv ---------------- */
static long c1_cases=0;
static void check_inv(const u64 a[4], const char* lbl){
    u64 v[4], f[4], t[4];
    int ok = sc_inv_var(v, a);
    sc_inv(f, a);
    c1_cases++;
    CK(ok==1, "sc_inv_var returned 0 for %s", lbl);
    CK(memcmp(v,f,32)==0, "sc_inv_var != sc_inv for %s: var=%016llx.. fermat=%016llx..", lbl, v[0], f[0]);
    sc_mul(t, a, v);
    CK(memcmp(t,ONE,32)==0, "a*inv(a) != 1 for %s", lbl);
}
static void campaign1(long nrand){
    u64 a[4], zero[4]={0,0,0,0}, v[4]={7,7,7,7};
    /* a == 0 must fail and leave r untouched */
    CK(sc_inv_var(v, zero)==0, "sc_inv_var(0) should return 0");
    CK(v[0]==7 && v[3]==7, "sc_inv_var(0) must not write r");
    /* edges */
    a[0]=1; a[1]=a[2]=a[3]=0;            check_inv(a,"1");
    a[0]=2;                               check_inv(a,"2");
    sub4(a,N,ONE);                        check_inv(a,"n-1");
    { u64 two[4]={2,0,0,0}; sub4(a,N,two); check_inv(a,"n-2"); }
    for(int k=0;k<256;k++){ char l[32]; pow2(a,k); if(ge(a,N)) continue; snprintf(l,sizeof l,"2^%d",k); check_inv(a,l); }
    for(int k=0;k<256;k++){ char l[32]; u64 p[4]; pow2(p,k); if(ge(p,N)) continue; sub4(a,N,p); snprintf(l,sizeof l,"n-2^%d",k); check_inv(a,l); }
    for(int k=1;k<=255;k++){ char l[32]; pow2(a,k); sub4(a,a,ONE); if(ge(a,N)) continue; snprintf(l,sizeof l,"2^%d-1",k); check_inv(a,l); }
    { /* (2^256-1) mod n = 2^256-1-n */ u64 all[4]={~0ULL,~0ULL,~0ULL,~0ULL}; sub4(a,all,N); check_inv(a,"2^256-1 mod n"); }
    for(int k=0;k<=250;k++){ char l[32]; u64 o[4]={0x1f,0,0,0}; /* 0x1f << k : long trailing-zero runs */
        memset(a,0,32); int w=k>>6, b=k&63; a[w]=o[0]<<b; if(b>59 && w<3) a[w+1]=o[0]>>(64-b);
        if(ge(a,N)) continue; snprintf(l,sizeof l,"0x1f<<%d",k); check_inv(a,l); }
    /* random */
    for(long i=0;i<nrand;i++){ rnd_scalar(a); check_inv(a,"random"); if(failures>20) return; }
    printf("campaign 1: sc_inv_var vs sc_inv: %ld cases (%ld random)\n", c1_cases, nrand);
}

/* ---------------- campaign 2: ecdsa_x_eq_mod_n ---------------- */
static void campaign2(long nrand){
    u64 r[4], Z[4], z2[4], X[4], rn[4], t[4];
    long cases=0;
    /* r small (< p-n): first branch, second branch, and tampered */
    r[0]=0x123456789abcdefULL; r[1]=0xfedcba9876543210ULL; r[2]=0; r[3]=0;   /* < p-n (limb2 == 0 < 1) */
    rnd4(Z); Z[3]&=0x7fffffffffffffffULL; if(!(Z[0]|Z[1]|Z[2]|Z[3])) Z[0]=5;
    fe_mul(z2, Z, Z);
    fe_mul(X, r, z2);          CK(ecdsa_x_eq_mod_n(r,X,Z)==1, "branch1: r*Z^2 == X must accept"); cases++;
    add4(rn, r, N);            /* r+n < p, plain add */
    fe_mul(X, rn, z2);         CK(ecdsa_x_eq_mod_n(r,X,Z)==1, "branch2: (r+n)*Z^2 == X must accept (r+n branch)"); cases++;
    X[0]^=1;                   CK(ecdsa_x_eq_mod_n(r,X,Z)==0, "branch2 tampered X must reject"); cases++;
    /* r >= p-n: the r+n branch must be SKIPPED even when (r+n mod p)*Z^2 == X */
    sub4(r, N, ONE);           /* r = n-1 >= p-n */
    fe_add(rn, r, N);          /* (r+n) mod p */
    fe_mul(X, rn, z2);         CK(ecdsa_x_eq_mod_n(r,X,Z)==0, "r>=p-n: wrapped r+n must NOT match"); cases++;
    fe_mul(X, r, z2);          CK(ecdsa_x_eq_mod_n(r,X,Z)==1, "r>=p-n: first branch still works"); cases++;
    /* boundary r == p-n exactly: r+n == p == 0 mod p; X = 0 must NOT be accepted via branch 2 */
    memcpy(r, PMN, 32);
    memset(X,0,32);            CK(ecdsa_x_eq_mod_n(r,X,Z)==0, "r == p-n boundary: branch 2 must be skipped"); cases++;
    fe_mul(X, r, z2);          CK(ecdsa_x_eq_mod_n(r,X,Z)==1, "r == p-n: branch 1 accepts"); cases++;
    /* r == p-n-1: branch 2 allowed, r+n = p-1 */
    sub4(r, PMN, ONE); add4(rn, r, N);
    fe_mul(X, rn, z2);         CK(ecdsa_x_eq_mod_n(r,X,Z)==1, "r == p-n-1: r+n = p-1 branch accepts"); cases++;
    /* random: X = r*Z^2 -> 1 ; random X -> 0 ; r < p-n with X=(r+n)Z^2 -> 1 */
    for(long i=0;i<nrand;i++){
        rnd_scalar(r); rnd4(Z); Z[3]&=0x7fffffffffffffffULL; if(!(Z[0]|Z[1]|Z[2]|Z[3])) Z[0]=3;
        fe_mul(z2,Z,Z);
        fe_mul(X,r,z2);   CK(ecdsa_x_eq_mod_n(r,X,Z)==1, "random branch1 #%ld", i);
        rnd4(t); t[3]&=0x7fffffffffffffffULL; CK(ecdsa_x_eq_mod_n(r,t,Z)==0, "random X must reject #%ld", i);
        r[2]=0; r[3]=0; if(ge(r,PMN)) r[1]&=0x3fffffffffffffffULL;   /* force r < p-n */
        add4(rn,r,N); fe_mul(X,rn,z2); CK(ecdsa_x_eq_mod_n(r,X,Z)==1, "random branch2 #%ld", i);
        cases+=3; if(failures>20) return;
    }
    printf("campaign 2: ecdsa_x_eq_mod_n: %ld cases (incl. r+n branch, r==p-n boundary)\n", cases);
}

/* ---------------- campaign 3: ecdsa_verify new vs ref ---------------- */
static long c3_cases=0, c3_accepts=0;
static void diff(const u64 z[4], const u64 r[4], const u64 s[4], const u64 Qx[4], const u64 Qy[4], int expect /* -1 = just compare */, const char* lbl){
    int a = ecdsa_verify(z,r,s,Qx,Qy);
    int b = ecdsa_verify_ref(z,r,s,Qx,Qy);
    c3_cases++; c3_accepts += (a==1);
    CK(a==b, "new(%d) != ref(%d): %s", a, b, lbl);
    if(expect>=0) CK(a==expect, "new=%d expected %d: %s", a, expect, lbl);
}
static void campaign3(long nrand){
    u64 z[4], r[4], s[4], Qx[4], Qy[4], t[4], zero[4]={0,0,0,0};
    for(int i=0;i<EIV_N;i++){
        const u64 *Z=eiv[i], *R=eiv[i]+4, *S=eiv[i]+8, *X=eiv[i]+12, *Y=eiv[i]+16;
        diff(Z,R,S,X,Y, 1, "valid fixture");
        memcpy(r,R,32); r[0]^=1;             diff(Z,r,S,X,Y, 0, "tamper r");
        memcpy(s,S,32); s[0]^=1;             diff(Z,R,s,X,Y, 0, "tamper s");
        memcpy(z,Z,32); z[0]^=1;             diff(z,R,S,X,Y, 0, "tamper z");
        memcpy(Qx,X,32); Qx[0]^=1;           diff(Z,R,S,Qx,Y, -1, "tamper Qx (off-curve)");
        memcpy(Qy,Y,32); Qy[0]^=1;           diff(Z,R,S,X,Qy, -1, "tamper Qy (off-curve)");
        diff(Z,R,zero,X,Y, 0, "s=0");
        diff(Z,R,N,X,Y, 0, "s=n");
        diff(Z,zero,S,X,Y, 0, "r=0");
        diff(Z,N,S,X,Y, 0, "r=n");
        sub4(t,N,S);                          diff(Z,R,t,X,Y, 1, "high-S (n-s) is still a valid signature");
        diff(zero,R,S,X,Y, -1, "z=0");
        rnd_scalar(z);                        diff(z,R,S,X,Y, 0, "random z");
        if(failures>20) return;
    }
    /* legacy fixed vectors from tests/test_ecdsa.c */
    {
        u64 z1[4] = {0x0123456789abcdefULL,0x0123456789abcdefULL,0x0123456789abcdefULL,0x0123456789abcdefULL};
        u64 r1[4] = {0x2af4a71489e9f1dbULL,0xc0cb2fd43c3b6e75ULL,0x5fbff28aa15cced7ULL,0x592cb214ca60184fULL};
        u64 s1[4] = {0xc4a2c025aa14e92aULL,0x010761c8cf1d4450ULL,0x812cf05ef8411d64ULL,0x23d627acd53ebcd7ULL};
        u64 x1[4] = {0xfd723873aa170695ULL,0xe7bcc89470d63e1aULL,0x8947c271ac274529ULL,0x9651c463c001f731ULL};
        u64 y1[4] = {0x21837fb0e654eaf7ULL,0x3b16ba7a5a9b154dULL,0x73d6d17fe8b63c99ULL,0x4e362e7fe8ff06daULL};
        u64 zB[4] = {0x0000000000000123ULL,0,0,0};
        u64 rB[4] = {0xa3153339064fe63eULL,0xa65c4156d690fb12ULL,0xd91eea399c0858aeULL,0x3527053278c9f1ffULL};
        u64 sB[4] = {0xb58e7e068ce2863aULL,0x8a9e493d602e86c7ULL,0x9a4c396fc74cbeb6ULL,0x5f4061d3e796efdbULL};
        u64 n_1[4]= {0xbfd25e8cd0364140ULL,0xbaaedce6af48a03bULL,0xfffffffffffffffeULL,0xffffffffffffffffULL};
        diff(z1,r1,s1,x1,y1,1,"test_ecdsa valid");  diff(zB,rB,sB,x1,y1,1,"test_ecdsa 2nd valid");
        diff(z1,n_1,s1,x1,y1,0,"test_ecdsa r=n-1");
    }
    /* random tuples (almost all invalid): in-range paths + rejection paths must agree */
    for(long i=0;i<nrand;i++){
        rnd4(z); rnd4(r); rnd4(s); rnd4(Qx); rnd4(Qy);
        if(i&1){ if(ge(z,N)) sub4(z,z,N); if(ge(r,N)) sub4(r,r,N); if(ge(s,N)) sub4(s,s,N); } /* half in-range */
        diff(z,r,s,Qx,Qy,-1,"random tuple");
        if(failures>20) return;
    }
    printf("campaign 3: ecdsa_verify new vs ref: %ld cases (%ld accepted by both, %d fixtures x 13 variants, %ld random)\n",
           c3_cases, c3_accepts, EIV_N, nrand);
}

int main(int argc, char** argv){
    rng_s = (argc>1) ? strtoull(argv[1],0,0) : 0x9E3779B97F4A7C15ULL;
    long scale = (argc>2) ? atol(argv[2]) : 1;
    printf("seed=0x%llx scale=%ld\n", rng_s, scale);
    campaign1(1000000L*scale);
    campaign2(2000L*scale);
    campaign3(100000L*scale);
    printf("\n%s (%ld failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
