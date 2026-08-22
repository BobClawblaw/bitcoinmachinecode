/* test_ecdsa_glv_switch.c -- PERF_SCOPE.md 4.3 (e): ecdsa_verify with the
 * GLV path ON vs OFF (bmc_ecdsa_glv_set_enabled), compared against EACH
 * OTHER and against the frozen pre-4.2 reference verifier
 * (tests/ecdsa_verify_ref.asm), over the libsecp256k1-signed fixtures in
 * ecdsa_inverse_vec.h plus tampered variants (r, s, z, Qx, Qy each flipped;
 * s -> n - s; r = 0; s = 0; s = n) and random tuples. All three verdicts
 * must agree on every case.
 *
 * tests/test_ecdsa_inverse.c (campaign 3, 113,315 cases) already compares
 * the default path -- GLV on -- to the reference; this test pins the
 * kill-switch path to the same answers so the fallback is never a
 * different verifier.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned long long u64;
extern int  ecdsa_verify(const u64 z[4], const u64 r[4], const u64 s[4], const u64 Qx[4], const u64 Qy[4]);
extern int  ecdsa_verify_ref(const u64 z[4], const u64 r[4], const u64 s[4], const u64 Qx[4], const u64 Qy[4]);
extern void bmc_ecdsa_glv_set_enabled(int on);
#include "ecdsa_inverse_vec.h"

static const u64 N[4] = {0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL};
static long failures = 0, cases = 0, accepted = 0;
static u64 rng_s = 0x9e3779b97f4a7c15ULL;
static u64 rnd(void){ u64 x=rng_s; x^=x<<13; x^=x>>7; x^=x<<17; rng_s=x; return x; }

static void tri(const u64 z[4], const u64 r[4], const u64 s[4], const u64 Qx[4], const u64 Qy[4], const char* lbl){
    bmc_ecdsa_glv_set_enabled(1); int g = ecdsa_verify(z,r,s,Qx,Qy);
    bmc_ecdsa_glv_set_enabled(0); int p = ecdsa_verify(z,r,s,Qx,Qy);
    int f = ecdsa_verify_ref(z,r,s,Qx,Qy);
    cases++; if (f) accepted++;
    if (!(g==p && p==f)) { failures++; if (failures<=20) printf("FAIL %s: glv=%d plain=%d ref=%d\n", lbl, g, p, f); }
}

int main(int argc, char** argv){
    long nrand = (argc>1) ? atol(argv[1]) : 20000L;
    for (int i = 0; i < EIV_N; i++) {
        const u64 *z=&eiv[i][0], *r=&eiv[i][4], *s=&eiv[i][8], *Qx=&eiv[i][12], *Qy=&eiv[i][16];
        u64 t[4];
        tri(z,r,s,Qx,Qy,"fixture");
        memcpy(t,r,32);  t[0]^=1; tri(z,t,s,Qx,Qy,"r^1");
        memcpy(t,s,32);  t[0]^=1; tri(z,r,t,Qx,Qy,"s^1");
        memcpy(t,z,32);  t[0]^=1; tri(t,r,s,Qx,Qy,"z^1");
        memcpy(t,Qx,32); t[0]^=1; tri(z,r,s,t,Qy,"Qx^1");
        memcpy(t,Qy,32); t[0]^=1; tri(z,r,s,Qx,t,"Qy^1");
        { unsigned __int128 br=0; for(int k=0;k<4;k++){ unsigned __int128 v=(unsigned __int128)N[k]-s[k]-br; t[k]=(u64)v; br=(v>>64)&1; } tri(z,r,t,Qx,Qy,"n-s"); }
        memset(t,0,32); tri(z,t,s,Qx,Qy,"r=0"); tri(z,r,t,Qx,Qy,"s=0");
        memcpy(t,N,32); tri(z,r,t,Qx,Qy,"s=n");
    }
    for (long i = 0; i < nrand; i++) {
        u64 z[4],r[4],s[4],Qx[4],Qy[4];
        for(int k=0;k<4;k++){ z[k]=rnd(); r[k]=rnd(); s[k]=rnd(); Qx[k]=rnd(); Qy[k]=rnd(); }
        if (i & 1) { int f = (int)(rnd() % EIV_N); memcpy(Qx,&eiv[f][12],32); memcpy(Qy,&eiv[f][16],32); }   /* on-curve Q, random sig */
        tri(z,r,s,Qx,Qy,"random");
    }
    bmc_ecdsa_glv_set_enabled(1);
    printf("ecdsa_verify glv vs plain vs frozen ref: %ld cases (%ld accepted by all three)\n", cases, accepted);
    if (failures){ printf("TESTS FAILED (%ld failures)\n", failures); return 1; }
    printf("ALL TESTS PASSED (0 failures)\n"); return 0;
}
