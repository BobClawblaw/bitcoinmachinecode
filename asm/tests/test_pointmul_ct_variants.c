/* tests/test_pointmul_ct_variants.c -- the two constant-time multiplies added
 * to secp256k1_point_ct.asm on 2026-09-28 for the BIP324 handshake:
 *
 *   point_scalar_mul_gen_ct(out, k)      k*G by a cmov-scanned comb table
 *   point_scalar_mul_win_ct(out, xy, k)  k*P by a fixed w=4 window
 *
 * against the constant-time ladder point_scalar_mul_ct (the oracle: proven
 * against a Python multiplier by tests/run_pointmul_ct_diff.py) and, for
 * k < n, the variable-time point_scalar_mul. Results are compared in affine
 * form (the Jacobian representatives legitimately differ), with infinity as
 * its own case.
 *
 * Scalars: the edges (0, 1, 2, 15, 16, 2^64-1, 2^255, n-1, n, n+1, 2^256-1,
 * every nibble 0xF, alternating 0x0F / 0xF0 -- the digit-0 path of the comb
 * and every table entry of the window), then N random ones. Bases for the
 * window: G and N random points (random scalars times G, by the ladder),
 * including P with k=1 (the table's TB[1] path alone) and P with k = n-1
 * (-P: the add of R = P + ... hits the complete formula's P == -Q case).
 *
 * argv[1] = N (default 400); the ladder costs 52 us per call. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef unsigned long long u64;
extern void point_scalar_mul_ct(u64 r[12], const u64 xy[8], const u64 k[4]);
extern void point_scalar_mul_gen_ct(u64 r[12], const u64 k[4]);
extern void point_scalar_mul_win_ct(u64 r[12], const u64 xy[8], const u64 k[4]);
extern void point_scalar_mul_glv_ct(u64 r[12], const u64 xy[8], const u64 k[4]);   /* k < n */
extern void point_scalar_mul_glvj_ct(u64 r[12], const u64 xy[8], const u64 k[4]);  /* k < n, Jacobian (2026-10-02) */
extern void point_ct_force_scan(int p);   /* 0 probe, 1 AVX2 blend scan, 2 cmov scan */
extern void point_scalar_mul(u64 r[12], const u64 xy[8], const u64 k[4]);
extern void fe_inv(u64 r[4], const u64 a[4]);
extern void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sqr(u64 r[4], const u64 a[4]);

static const u64 G_AFF[8] = {
    0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL, 0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL,
    0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL, 0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL };
static const u64 ORDER_N[4] = {
    0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL, 0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL };

static long checks, failures;
#define CK(c, ...) do{ checks++; if(!(c)){ if(failures++ < 15){ printf("FAIL "); printf(__VA_ARGS__); printf("\n"); } } }while(0)

static u64 rs = 0x9E3779B97F4A7C15ULL;
static u64 rnd(void){ rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }

/* Jacobian -> affine; 0 for infinity (Z == 0) */
static int to_aff(u64 x[4], u64 y[4], const u64 J[12]){
    if ((J[8] | J[9] | J[10] | J[11]) == 0) return 0;
    u64 zi[4], z2[4], z3[4];
    fe_inv(zi, J + 8); fe_sqr(z2, zi); fe_mul(z3, z2, zi);
    fe_mul(x, J, z2); fe_mul(y, J + 4, z3);
    return 1;
}
/* 1 if the two Jacobian points are the same affine point (or both infinity) */
static int same_point(const u64 A[12], const u64 B[12]){
    u64 ax[4], ay[4], bx[4], by[4];
    int a = to_aff(ax, ay, A), b = to_aff(bx, by, B);
    if (a != b) return 0;
    if (!a) return 1;
    return !memcmp(ax, bx, 32) && !memcmp(ay, by, 32);
}
static int lt_n(const u64 k[4]){
    for (int i = 3; i >= 0; i--){ if (k[i] < ORDER_N[i]) return 1; if (k[i] > ORDER_N[i]) return 0; }
    return 0;
}

static void check_gen(const u64 k[4], const char* what){
    u64 A[12], B[12];
    point_scalar_mul_ct(A, G_AFF, k);
    point_scalar_mul_gen_ct(B, k);
    CK(same_point(A, B), "%s: gen_ct != ladder (k0=%016llx)", what, k[0]);
    if (lt_n(k) && (k[0] | k[1] | k[2] | k[3])){
        u64 C[12]; point_scalar_mul(C, G_AFF, k);
        CK(same_point(A, C), "%s: ladder != point_scalar_mul (k0=%016llx)", what, k[0]);
    }
}
static void check_win(const u64 P[8], const u64 k[4], const char* what){
    u64 A[12], B[12];
    point_scalar_mul_ct(A, P, k);
    point_scalar_mul_win_ct(B, P, k);
    CK(same_point(A, B), "%s: win_ct != ladder (k0=%016llx)", what, k[0]);
    if (lt_n(k)){                                  /* the GLV routine requires k < n */
        u64 G[12]; point_scalar_mul_glv_ct(G, P, k);
        CK(same_point(A, G), "%s: glv_ct != ladder (k0=%016llx)", what, k[0]);
        u64 H[12]; point_scalar_mul_glvj_ct(H, P, k);
        CK(same_point(A, H), "%s: glvj_ct != ladder (k0=%016llx)", what, k[0]);
        /* infinity is returned canonically, as the other routines do */
        if ((H[8] | H[9] | H[10] | H[11]) == 0)
            CK(H[0] == 1 && H[4] == 1 && !(H[1]|H[2]|H[3]|H[5]|H[6]|H[7]), "%s: glvj_ct infinity not (1,1,0)", what);
    }
    if (lt_n(k) && (k[0] | k[1] | k[2] | k[3])){
        u64 C[12]; point_scalar_mul(C, P, k);
        CK(same_point(A, C), "%s: ladder != point_scalar_mul (k0=%016llx)", what, k[0]);
    }
}

static int run_all(long n);
int main(int argc, char** argv){
    long n = argc > 1 ? atol(argv[1]) : 400;
    printf("test_pointmul_ct_variants: n=%ld\n", n);
    /* first through the probe (the path a real caller takes: its cpuid must not
     * disturb the arguments), then each scan body forced */
    { u64 k[4] = { 7, 0, 0, 0 }, A[12], B[12]; point_ct_force_scan(0);
      point_scalar_mul_glv_ct(A, G_AFF, k); point_scalar_mul_ct(B, G_AFF, k);
      CK(same_point(A, B), "glv_ct through the CPU probe"); }
    { u64 k[4] = { 7, 0, 0, 0 }, A[12], B[12]; point_ct_force_scan(0);
      point_scalar_mul_glvj_ct(A, G_AFF, k); point_scalar_mul_ct(B, G_AFF, k);
      CK(same_point(A, B), "glvj_ct through the CPU probe"); }
    /* the GLV routine's table scan has an AVX2 body and a cmov body: both run */
    for (int scan = 2; scan >= 1; scan--){
        point_ct_force_scan(scan); rs = 0x9E3779B97F4A7C15ULL;
        printf("-- table scan: %s --\n", scan == 1 ? "AVX2 blend" : "cmov");
        if (run_all(n)) return 1;
    }
    point_ct_force_scan(0);
    printf("%ld checks\n", checks);
    if (failures){ printf("\nTESTS FAILED (%ld failures)\n", failures); return 1; }
    printf("\nALL TESTS PASSED (0 failures)\n");
    return 0;
}
static int run_all(long n){

    /* edge scalars */
    u64 edges[20][4]; int ne = 0; const char* names[20];
#define EDGE(nm, a, b, c, d) do{ edges[ne][0]=(a); edges[ne][1]=(b); edges[ne][2]=(c); edges[ne][3]=(d); names[ne++]=(nm); }while(0)
    EDGE("0", 0, 0, 0, 0);
    EDGE("1", 1, 0, 0, 0);
    EDGE("2", 2, 0, 0, 0);
    EDGE("15", 15, 0, 0, 0);
    EDGE("16", 16, 0, 0, 0);
    EDGE("2^64-1", ~0ULL, 0, 0, 0);
    EDGE("2^255", 0, 0, 0, 1ULL << 63);
    EDGE("n-1", ORDER_N[0] - 1, ORDER_N[1], ORDER_N[2], ORDER_N[3]);
    EDGE("n", ORDER_N[0], ORDER_N[1], ORDER_N[2], ORDER_N[3]);
    EDGE("n+1", ORDER_N[0] + 1, ORDER_N[1], ORDER_N[2], ORDER_N[3]);
    EDGE("2^256-1", ~0ULL, ~0ULL, ~0ULL, ~0ULL);
    EDGE("0x0F..0F", 0x0F0F0F0F0F0F0F0FULL, 0x0F0F0F0F0F0F0F0FULL, 0x0F0F0F0F0F0F0F0FULL, 0x0F0F0F0F0F0F0F0FULL);
    EDGE("0xF0..F0", 0xF0F0F0F0F0F0F0F0ULL, 0xF0F0F0F0F0F0F0F0ULL, 0xF0F0F0F0F0F0F0F0ULL, 0xF0F0F0F0F0F0F0F0ULL);
    EDGE("0x8000..0001", 1, 0, 0, 1ULL << 63);
    EDGE("2^128", 0, 0, 1, 0);
    EDGE("2^128-1", ~0ULL, ~0ULL, 0, 0);
    EDGE("lambda", 0xDF02967C1B23BD72ULL, 0x122E22EA20816678ULL, 0xA5261C028812645AULL, 0x5363AD4CC05C30E0ULL);

    /* the multiples of G that must be infinity or +-G, stated directly */
    { u64 J[12]; point_scalar_mul_gen_ct(J, edges[0]); CK((J[8]|J[9]|J[10]|J[11]) == 0, "gen_ct(0) must be infinity");
      point_scalar_mul_gen_ct(J, edges[8]); CK((J[8]|J[9]|J[10]|J[11]) == 0, "gen_ct(n) must be infinity");
      u64 x[4], y[4]; point_scalar_mul_gen_ct(J, edges[1]); CK(to_aff(x, y, J) && !memcmp(x, G_AFF, 32) && !memcmp(y, G_AFF + 4, 32), "gen_ct(1) must be G");
      point_scalar_mul_win_ct(J, G_AFF, edges[0]); CK((J[8]|J[9]|J[10]|J[11]) == 0, "win_ct(G, 0) must be infinity");
      point_scalar_mul_win_ct(J, G_AFF, edges[8]); CK((J[8]|J[9]|J[10]|J[11]) == 0, "win_ct(G, n) must be infinity");
      point_scalar_mul_win_ct(J, G_AFF, edges[1]); CK(to_aff(x, y, J) && !memcmp(x, G_AFF, 32) && !memcmp(y, G_AFF + 4, 32), "win_ct(G, 1) must be G"); }

    for (int i = 0; i < ne; i++){ check_gen(edges[i], names[i]); check_win(G_AFF, edges[i], names[i]); }

    /* random scalars on G */
    for (long i = 0; i < n; i++){
        u64 k[4]; for (int j = 0; j < 4; j++) k[j] = rnd();
        check_gen(k, "random k*G");
        check_win(G_AFF, k, "random k*G (window)");
    }
    /* random bases: P = s*G by the ladder, then every edge scalar and random scalars on P */
    for (long i = 0; i < n; i++){
        u64 s[4], J[12], P[8], k[4];
        for (int j = 0; j < 4; j++) s[j] = rnd();
        point_scalar_mul_ct(J, G_AFF, s);
        if (!to_aff(P, P + 4, J)) continue;
        for (int j = 0; j < 4; j++) k[j] = rnd();
        check_win(P, k, "random k*P");
        if (i < 8) for (int e = 0; e < ne; e++) check_win(P, edges[e], names[e]);
    }
    return failures != 0;
}
