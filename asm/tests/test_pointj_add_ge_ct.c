/* tests/test_pointj_add_ge_ct.c -- pointj_add_ge_ct (secp256k1_point_ct.asm,
 * 2026-10-02), the constant-time Jacobian + affine add the Jacobian GLV
 * multiply runs 51 times per ECDH: libsecp256k1's secp256k1_gej_add_ge.
 *
 * Every case its comment enumerates, with the Jacobian operand at a random Z
 * (so the formulas see a representative, not the affine point), against the
 * variable-time point_add_mixed (secp256k1_point.asm, proven by
 * tests/run_pointmul_diff.py) and point_double:
 *   - distinct points (the generic formula);
 *   - a == b (the unified formula doubles);
 *   - a == -b (degenerate, Z3 = 0: infinity);
 *   - y1 == -y2, x1 != x2: a = (beta*x, -y) and (beta^2*x, -y) against b =
 *     (x, y) (degenerate, the alternative lambda (y1 - y2)/(x1 - x2));
 *   - a = infinity (Z = 0, garbage X, Y): the result is b with Z = 1;
 *   - r aliasing a.
 * Results compared in affine form, infinity as its own case.
 * argv[1] = random rounds (default 2000). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned long long u64;
extern void pointj_add_ge_ct(u64 r[12], const u64 a[12], const u64 b[8]);
extern void point_add_mixed(u64 r[12], const u64 p[12], const u64 xy[8]);
extern void point_double(u64 r[12], const u64 p[12]);
extern void point_scalar_mul_ct(u64 r[12], const u64 xy[8], const u64 k[4]);
extern void fe_inv(u64 r[4], const u64 a[4]);
extern void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sqr(u64 r[4], const u64 a[4]);
extern void fe_sub(u64 r[4], const u64 a[4], const u64 b[4]);

static const u64 G_AFF[8] = {
    0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL, 0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL,
    0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL, 0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL };
static const u64 BETA[4] = {
    0xC1396C28719501EEULL, 0x9CF0497512F58995ULL, 0x6E64479EAC3434E9ULL, 0x7AE96A2B657C0710ULL };
static const u64 ZERO[4] = { 0, 0, 0, 0 };

static long checks, failures;
#define CK(c, ...) do{ checks++; if(!(c)){ if(failures++ < 15){ printf("FAIL "); printf(__VA_ARGS__); printf("\n"); } } }while(0)

static u64 rs = 0xD1B54A32D192ED03ULL;
static u64 rnd(void){ rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }

static int is_inf(const u64 J[12]){ return (J[8] | J[9] | J[10] | J[11]) == 0; }
static int to_aff(u64 x[4], u64 y[4], const u64 J[12]){
    if (is_inf(J)) return 0;
    u64 zi[4], z2[4], z3[4];
    fe_inv(zi, J + 8); fe_sqr(z2, zi); fe_mul(z3, z2, zi);
    fe_mul(x, J, z2); fe_mul(y, J + 4, z3);
    return 1;
}
static int same_point(const u64 A[12], const u64 B[12]){
    u64 ax[4], ay[4], bx[4], by[4];
    int a = to_aff(ax, ay, A), b = to_aff(bx, by, B);
    if (a != b) return 0;
    if (!a) return 1;
    return !memcmp(ax, bx, 32) && !memcmp(ay, by, 32);
}
/* J := affine (x, y) at a random nonzero Z: (x Z^2, y Z^3, Z) */
static void jac_at_random_z(u64 J[12], const u64 xy[8]){
    u64 z[4], z2[4], z3[4];
    do { for (int i = 0; i < 4; i++) z[i] = rnd(); z[3] &= 0x7FFFFFFFFFFFFFFFULL; } while (!(z[0] | z[1] | z[2] | z[3]));
    fe_sqr(z2, z); fe_mul(z3, z2, z);
    fe_mul(J, xy, z2); fe_mul(J + 4, xy + 4, z3); memcpy(J + 8, z, 32);
}
static void random_point(u64 P[8]){
    for (;;){
        u64 s[4], J[12]; for (int i = 0; i < 4; i++) s[i] = rnd();
        point_scalar_mul_ct(J, G_AFF, s);
        if (to_aff(P, P + 4, J)) return;
    }
}
static void check_pair(const u64 a_aff[8], const u64 b[8], const char* what){
    u64 A[12], R[12], E[12];
    jac_at_random_z(A, a_aff);
    point_add_mixed(E, A, b);
    pointj_add_ge_ct(R, A, b);
    CK(same_point(R, E), "%s: pointj_add_ge_ct != point_add_mixed", what);
    pointj_add_ge_ct(A, A, b);                     /* r aliasing a */
    CK(same_point(A, E), "%s: aliased result differs", what);
}

int main(int argc, char** argv){
    long n = argc > 1 ? atol(argv[1]) : 2000;
    printf("test_pointj_add_ge_ct: n=%ld\n", n);
    long degenerate_sums = 0;
    for (long i = 0; i < n; i++){
        u64 a[8], b[8], m[8];
        random_point(a); random_point(b);
        check_pair(a, b, "distinct");

        /* a == b: doubling through the unified formula */
        { u64 A[12], R[12], D[12];
          jac_at_random_z(A, b);
          pointj_add_ge_ct(R, A, b);
          point_double(D, A);
          CK(same_point(R, D), "a == b: not 2b"); }

        /* a == -b: infinity */
        { memcpy(m, b, 32); fe_sub(m + 4, ZERO, b + 4);
          u64 A[12], R[12]; jac_at_random_z(A, m);
          pointj_add_ge_ct(R, A, b);
          CK(is_inf(R), "a == -b: not infinity"); }

        /* y1 == -y2, x1 != x2: a = (beta*x, -y), (beta^2*x, -y) */
        for (int e = 1; e <= 2; e++){
            fe_mul(m, b, BETA); if (e == 2) fe_mul(m, m, BETA);
            fe_sub(m + 4, ZERO, b + 4);
            u64 A[12], R[12], E[12];
            jac_at_random_z(A, m);
            point_add_mixed(E, A, b);
            pointj_add_ge_ct(R, A, b);
            CK(!is_inf(R) && same_point(R, E), "y1 == -y2, x1 = beta^%d x2: wrong sum", e);
            degenerate_sums++;
        }

        /* a infinity (Z = 0, garbage X and Y): the result is b at Z = 1 */
        { u64 A[12], R[12];
          for (int j = 0; j < 8; j++) A[j] = rnd();
          memset(A + 8, 0, 32);
          pointj_add_ge_ct(R, A, b);
          CK(!memcmp(R, b, 64) && R[8] == 1 && !(R[9] | R[10] | R[11]), "a infinity: not (b.x, b.y, 1)"); }
    }
    /* G against G and -G, the fixed edges */
    check_pair(G_AFF, G_AFF, "G + G");
    printf("%ld checks (%ld beta-case sums)\n", checks, degenerate_sums);
    if (failures){ printf("\nTESTS FAILED (%ld failures)\n", failures); return 1; }
    printf("\nALL TESTS PASSED (0 failures)\n");
    return 0;
}
