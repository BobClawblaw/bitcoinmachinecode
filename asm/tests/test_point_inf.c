/* test_point_inf.c -- Z=0 (infinity) OPERANDS to point_add / point_add_mixed.
 *
 * Before 2026-08-22 neither routine checked its inputs for Z=0: the generic
 * formulas then produce Z3 = Z1*Z2*H = 0, i.e. "infinity" instead of the
 * other operand. point_scalar_mul never hit it (it seeds R from the top
 * window digit), but a ladder that starts at infinity -- Core's own
 * strauss_wnaf shape, which the GLV path uses -- hits it on its very first
 * add. Every case here compares against the affine value of the finite
 * operand, both canonical (1,1,0) and non-canonical (X,Y,0) infinities, both
 * operand positions, in place and out of place, plus inf+inf.
 */
#include <stdio.h>
#include <string.h>
typedef unsigned long long u64;
extern void point_double(u64 r[12], const u64 p[12]);
extern void point_add_mixed(u64 r[12], const u64 p[12], const u64 xy[8]);
extern void point_add(u64 r[12], const u64 p[12], const u64 q[12]);
extern void fe_inv(u64 r[4], const u64 a[4]);
extern void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sqr(u64 r[4], const u64 a[4]);

static int failures = 0;
static void toaff(u64 ox[4], u64 oy[4], const u64 j[12]){
    u64 zi[4], z2[4], z3[4];
    fe_inv(zi, &j[8]); fe_sqr(z2, zi); fe_mul(z3, z2, zi);
    fe_mul(ox, &j[0], z2); fe_mul(oy, &j[4], z3);
}
static int isinf(const u64 j[12]){ return (j[8]|j[9]|j[10]|j[11]) == 0; }
static void ck_eq_aff(const char* l, const u64 got[12], const u64 want[12]){
    if (isinf(got) || isinf(want)) { printf("FAIL %s: unexpected infinity (got inf=%d want inf=%d)\n", l, isinf(got), isinf(want)); failures++; return; }
    u64 gx[4],gy[4],wx[4],wy[4];
    toaff(gx,gy,got); toaff(wx,wy,want);
    if (memcmp(gx,wx,32)==0 && memcmp(gy,wy,32)==0) printf("PASS %s\n", l);
    else { printf("FAIL %s (affine mismatch)\n", l); failures++; }
}
static void ck_inf(const char* l, const u64 got[12]){
    if (isinf(got)) printf("PASS %s\n", l); else { printf("FAIL %s: expected infinity\n", l); failures++; }
}

static const u64 Gaf[8]={
    0x59F2815B16F81798ULL,0x029BFCDB2DCE28D9ULL,0x55A06295CE870B07ULL,0x79BE667EF9DCBBACULL,
    0x9C47D08FFB10D4B8ULL,0xFD17B448A6855419ULL,0x5DA4FBFC0E1108A8ULL,0x483ADA7726A3C465ULL};
static const u64 G12[12]={
    0x59F2815B16F81798ULL,0x029BFCDB2DCE28D9ULL,0x55A06295CE870B07ULL,0x79BE667EF9DCBBACULL,
    0x9C47D08FFB10D4B8ULL,0xFD17B448A6855419ULL,0x5DA4FBFC0E1108A8ULL,0x483ADA7726A3C465ULL,
    1,0,0,0};
static const u64 INF[12]={1,0,0,0, 1,0,0,0, 0,0,0,0};
static const u64 INF2[12]={5,6,7,8, 9,10,11,12, 0,0,0,0};   /* non-canonical: Z=0, X/Y garbage */

int main(void){
    u64 r[12], twoG[12];
    point_double(twoG, G12);              /* a Z != 1 finite point */

    /* ---- point_add ---- */
    point_add(r, INF, G12);   ck_eq_aff("point_add(inf, G) == G", r, G12);
    point_add(r, G12, INF);   ck_eq_aff("point_add(G, inf) == G", r, G12);
    point_add(r, INF2, twoG); ck_eq_aff("point_add(inf', 2G) == 2G", r, twoG);
    point_add(r, twoG, INF2); ck_eq_aff("point_add(2G, inf') == 2G", r, twoG);
    point_add(r, INF, INF);   ck_inf("point_add(inf, inf) == inf", r);
    point_add(r, INF, INF2);  ck_inf("point_add(inf, inf') == inf", r);
    /* in place: accumulator starts at infinity (the ladder shape) */
    memcpy(r, INF, 96); point_add(r, r, G12);  ck_eq_aff("in-place: r=inf; r = r + G", r, G12);
    memcpy(r, INF, 96); point_add(r, twoG, r); ck_eq_aff("in-place: r=inf; r = 2G + r", r, twoG);

    /* ---- point_add_mixed ---- */
    point_add_mixed(r, INF, Gaf);   ck_eq_aff("point_add_mixed(inf, G) == G", r, G12);
    if (!(r[8]==1 && r[9]==0 && r[10]==0 && r[11]==0)) { printf("FAIL point_add_mixed(inf, G): Z must be exactly 1\n"); failures++; }
    point_add_mixed(r, INF2, Gaf);  ck_eq_aff("point_add_mixed(inf', G) == G", r, G12);
    memcpy(r, INF, 96); point_add_mixed(r, r, Gaf); ck_eq_aff("in-place: r=inf; r = r + G (mixed)", r, G12);

    /* ---- the finite paths are unchanged ---- */
    point_add(r, G12, G12);   ck_eq_aff("point_add(G, G) == 2G (double path)", r, twoG);
    u64 threeG[12], threeG2[12];
    point_add(threeG, twoG, G12); point_add_mixed(threeG2, twoG, Gaf);
    ck_eq_aff("point_add(2G,G) == point_add_mixed(2G,G)", threeG, threeG2);
    u64 negG[12]; memcpy(negG, G12, 96);
    /* -G = (x, p - y) */
    static const u64 P[4]={0xFFFFFFFEFFFFFC2FULL,~0ULL,~0ULL,~0ULL};
    { unsigned __int128 br=0; for(int i=0;i<4;i++){ unsigned __int128 t=(unsigned __int128)P[i]-G12[4+i]-br; negG[4+i]=(u64)t; br=(t>>64)&1; } }
    point_add(r, G12, negG);  ck_inf("point_add(G, -G) == inf (opposite path)", r);

    if (failures) { printf("TESTS FAILED (%d failures)\n", failures); return 1; }
    printf("ALL TESTS PASSED (0 failures)\n"); return 0;
}
