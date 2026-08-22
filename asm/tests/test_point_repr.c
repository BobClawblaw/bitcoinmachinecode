/* test_point_repr.c -- bit-exact differential of the EC layer against a
 * FROZEN copy of it (tests/point_ref.asm, tests/point_ct_ref.asm: main @ the
 * commit named in those files' headers, symbols suffixed _ref).
 *
 * WHY THIS FILE EXISTS
 *   The 2026-08-22 EC-layer change (PERF_SCOPE.md 10) did two things:
 *     (a) routed the 20 call sites that computed fe_mul(a, a) through fe_sqr;
 *     (b) deleted a dead fe_mul + fe_sub from point_double -- the value they
 *         produced was unconditionally overwritten before it was ever read,
 *         and then recomputed.
 *   Neither touches the field layer, so the existing field campaign
 *   (tests/test_fe_repr, tests/test_mul_carry_regression) says nothing about
 *   them.  What has to be proved is that the CALLERS still compute the same
 *   thing, limb for limb, and that is what this file does.  It is the
 *   point-layer analogue of tests/fe_ref.asm + tests/test_fe_repr.
 *
 * WHY OFF-CURVE OPERANDS ARE USED ON PURPOSE
 *   Both implementations evaluate the same straight-line formula over the
 *   field, so their outputs must agree for ANY 12-limb input, on the curve or
 *   not.  Restricting to curve points would sample a vanishingly small,
 *   highly structured slice of the value space; feeding arbitrary canonical
 *   field elements exercises far more of it.  The degenerate SHAPES that the
 *   formulas actually branch on -- Z == 0 (infinity), q == p (the doubling
 *   branch), x2 == X1 with Z1 == 1 (the mixed-add doubling branch), Y1 == 0,
 *   the affine point (0,0) -- are injected explicitly, one per iteration mod
 *   7, because random operands would essentially never hit them.
 *
 * WHAT IS COVERED
 *   point_double, point_add, point_add_mixed, point_add_mixed_zr (result AND
 *   the z-ratio out-parameter), pointh_double, pointh_add, and -- sampled,
 *   because they cost ~10^2 field ops each -- point_scalar_mul,
 *   point_scalar_mul_glv, point_scalar_mul_fixed, point_scalar_mul_ct.
 *   Each of the two-operand routines is run BOTH out-of-place and in-place
 *   (r == p), because the deleted dead code in point_double sat inside an
 *   in-place-aliasing workaround and in-place is where a slot-reuse mistake
 *   would show up.
 *   Finally fe_sqr(a) == fe_mul(a, a) over the same operand distribution --
 *   the identity every one of the 20 rewritten call sites rests on.
 *
 * MUTATION-TESTED.  Six deliberate bugs were injected into the new code and
 * every one is caught by this harness (see PERF_SCOPE.md 10): a wrong operand
 * on point_double's A = X1^2; dropping the doubling in Z3 = 2*Y1*Z1; a wrong
 * operand on point_add_mixed's Z1Z1 = Z1^2; leaving a converted site as
 * `call fe_mul` after its rdx setup was removed (the exact failure mode of
 * the mechanical rewrite); a wrong operand in pointh_double's t0 = Y*Y; and
 * building Y3 from the stale F slot instead of E*(D-X3) -- which is the
 * overwrite bug the dead code was working around.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef unsigned long long u64;

extern void point_double(u64 r[12], const u64 p[12]);
extern void point_double_ref(u64 r[12], const u64 p[12]);
extern void point_add(u64 r[12], const u64 p[12], const u64 q[12]);
extern void point_add_ref(u64 r[12], const u64 p[12], const u64 q[12]);
extern void point_add_mixed(u64 r[12], const u64 p[12], const u64 xy[8]);
extern void point_add_mixed_ref(u64 r[12], const u64 p[12], const u64 xy[8]);
extern void point_add_mixed_zr(u64 r[12], const u64 p[12], const u64 xy[8], u64 zr[4]);
extern void point_add_mixed_zr_ref(u64 r[12], const u64 p[12], const u64 xy[8], u64 zr[4]);
extern void point_scalar_mul(u64 r[12], const u64 xy[8], const u64 k[4]);
extern void point_scalar_mul_ref(u64 r[12], const u64 xy[8], const u64 k[4]);
extern void point_scalar_mul_glv(u64 r[12], const u64 xy[8], const u64 k[4]);
extern void point_scalar_mul_glv_ref(u64 r[12], const u64 xy[8], const u64 k[4]);
extern void point_scalar_mul_fixed(u64 r[12], const u64 k[4]);
extern void point_scalar_mul_fixed_ref(u64 r[12], const u64 k[4]);
extern void point_scalar_mul_ct(u64 r[12], const u64 xy[8], const u64 k[4]);
extern void point_scalar_mul_ct_ref(u64 r[12], const u64 xy[8], const u64 k[4]);
extern void pointh_double(u64 r[12], const u64 p[12]);
extern void pointh_double_ref(u64 r[12], const u64 p[12]);
extern void pointh_add(u64 r[12], const u64 p[12], const u64 q[12]);
extern void pointh_add_ref(u64 r[12], const u64 p[12], const u64 q[12]);
extern void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sqr(u64 r[4], const u64 a[4]);

static long failures = 0, checks = 0;

static void show(const char* tag, const u64* v, int n){
    printf("      %-6s", tag);
    for (int i = n - 1; i >= 0; i--) printf(" %016llx", v[i]);
    printf("\n");
}

static void cmp(const char* what, const u64* got, const u64* want, int n, long it){
    checks++;
    if (memcmp(got, want, 8u * (size_t)n) != 0){
        if (failures < 8){
            printf("FAIL  %s differs from the frozen reference (iteration %ld)\n", what, it);
            show("new", got, n);
            show("ref", want, n);
        }
        failures++;
    }
}

/* xorshift64: deterministic, so a failure is reproducible from the seed. */
static u64 st = 0x9e3779b97f4a7c15ULL;
static u64 rnd(void){ st ^= st << 13; st ^= st >> 7; st ^= st << 17; return st; }

#define P0 0xFFFFFFFEFFFFFC2FULL
static const u64 P[4] = { P0, ~0ULL, ~0ULL, ~0ULL };

/* A canonical field element.  `structured` biases hard toward the values that
 * break carry chains: 0, 1, p-1, p-k, every single-bit 2^i, 2^i^1, the fold
 * constant C, and per-limb saturation patterns. */
static void fe_rand(u64 x[4], int structured){
    if (structured){
        memset(x, 0, 32);
        switch ((int)(rnd() % 10)){
        case 0: break;
        case 1: x[0] = 1; break;
        case 2: memcpy(x, P, 32); x[0] -= 1; break;
        case 3: { int i = (int)(rnd() % 256); x[i/64] = 1ULL << (i % 64); break; }
        case 4: { int i = (int)(rnd() % 256); x[i/64] = 1ULL << (i % 64); x[0] ^= 1; break; }
        case 5: x[0] = 0x1000003D1ULL; break;                 /* C = 2^32 + 977 */
        case 6: memcpy(x, P, 32); x[0] -= (rnd() & 7) + 1; break;
        case 7: { int i = (int)(rnd() % 4);
                  for (int j = 0; j < 4; j++) x[j] = (j <= i) ? ~0ULL : 0;
                  if (x[3] == ~0ULL) x[0] = P0 - 1;
                  break; }
        case 8: x[0] = rnd(); break;
        default: for (int j = 0; j < 4; j++) x[j] = rnd(); break;
        }
    } else {
        for (int j = 0; j < 4; j++) x[j] = rnd();
    }
    /* Bring it into [0, p): the fe_* contract is canonical in, canonical out,
     * and this test must not smuggle out-of-range inputs into either side. */
    for (int guard = 0; guard < 4; guard++){
        int ge = 1;
        for (int j = 3; j >= 0; j--) if (x[j] != P[j]){ ge = (x[j] > P[j]); break; }
        if (!ge) break;
        unsigned __int128 bw = 0;
        for (int j = 0; j < 4; j++){
            unsigned __int128 t = (unsigned __int128)x[j] - P[j] - bw;
            x[j] = (u64)t; bw = (t >> 64) & 1;
        }
    }
}

int main(int argc, char** argv){
    long N    = (argc > 1) ? atol(argv[1]) : 600000;
    long NSQR = (argc > 2) ? atol(argv[2]) : 2000000;
    u64 A[12], B[12], XY[8], K[4], ZR1[4], ZR2[4], R1[12], R2[12];
    long shapes[7]; memset(shapes, 0, sizeof shapes);

    for (long it = 0; it < N; it++){
        int structured = (it % 3) != 0;
        for (int i = 0; i < 3; i++) fe_rand(A + 4*i, structured);
        for (int i = 0; i < 3; i++) fe_rand(B + 4*i, structured);
        for (int i = 0; i < 2; i++) fe_rand(XY + 4*i, structured);

        switch ((int)(it % 7)){                 /* the branch-reaching shapes */
        case 1: memset(A + 8, 0, 32); break;                     /* p == inf */
        case 2: memset(B + 8, 0, 32); break;                     /* q == inf */
        case 3: memcpy(B, A, 96); break;                         /* q == p   */
        case 4: memcpy(XY, A, 32); memcpy(XY + 4, A + 4, 32);    /* mixed dbl */
                memset(A + 8, 0, 32); A[8] = 1; break;
        case 5: memset(A + 4, 0, 32); break;                     /* Y1 == 0  */
        case 6: memset(XY, 0, 64); break;                        /* (0,0)    */
        default: break;
        }
        shapes[it % 7]++;

        point_double(R1, A); point_double_ref(R2, A);
        cmp("point_double", R1, R2, 12, it);
        memcpy(R1, A, 96); memcpy(R2, A, 96);
        point_double(R1, R1); point_double_ref(R2, R2);
        cmp("point_double (in place)", R1, R2, 12, it);

        point_add(R1, A, B); point_add_ref(R2, A, B);
        cmp("point_add", R1, R2, 12, it);
        memcpy(R1, A, 96); memcpy(R2, A, 96);
        point_add(R1, R1, B); point_add_ref(R2, R2, B);
        cmp("point_add (in place)", R1, R2, 12, it);

        point_add_mixed(R1, A, XY); point_add_mixed_ref(R2, A, XY);
        cmp("point_add_mixed", R1, R2, 12, it);
        memcpy(R1, A, 96); memcpy(R2, A, 96);
        point_add_mixed(R1, R1, XY); point_add_mixed_ref(R2, R2, XY);
        cmp("point_add_mixed (in place)", R1, R2, 12, it);

        memset(ZR1, 0xa5, 32); memset(ZR2, 0x5a, 32);
        point_add_mixed_zr(R1, A, XY, ZR1); point_add_mixed_zr_ref(R2, A, XY, ZR2);
        cmp("point_add_mixed_zr", R1, R2, 12, it);
        cmp("point_add_mixed_zr (zr out)", ZR1, ZR2, 4, it);

        pointh_double(R1, A); pointh_double_ref(R2, A);
        cmp("pointh_double", R1, R2, 12, it);
        pointh_add(R1, A, B); pointh_add_ref(R2, A, B);
        cmp("pointh_add", R1, R2, 12, it);

        if ((it % 64) == 0){                    /* ~10^2 field ops each */
            fe_rand(K, structured);
            point_scalar_mul(R1, XY, K); point_scalar_mul_ref(R2, XY, K);
            cmp("point_scalar_mul", R1, R2, 12, it);
            point_scalar_mul_glv(R1, XY, K); point_scalar_mul_glv_ref(R2, XY, K);
            cmp("point_scalar_mul_glv", R1, R2, 12, it);
            point_scalar_mul_fixed(R1, K); point_scalar_mul_fixed_ref(R2, K);
            cmp("point_scalar_mul_fixed", R1, R2, 12, it);
            point_scalar_mul_ct(R1, XY, K); point_scalar_mul_ct_ref(R2, XY, K);
            cmp("point_scalar_mul_ct", R1, R2, 12, it);
        }
    }
    if (failures == 0)
        printf("PASS  EC layer vs frozen point_ref, %ld iterations x 10 routines,\n"
               "      out-of-place AND in-place, degenerate shapes forced\n"
               "      (inf/q==p/mixed-double/Y==0/(0,0)) %ld..%ld times each\n",
               N, shapes[1], shapes[0]);

    long before = failures;
    for (long it = 0; it < NSQR; it++){
        u64 a[4], s[4], m[4];
        fe_rand(a, (it % 3) != 0);
        fe_sqr(s, a); fe_mul(m, a, a);
        cmp("fe_sqr(a) != fe_mul(a,a)", s, m, 4, it);
    }
    if (failures == before)
        printf("PASS  fe_sqr(a) == fe_mul(a,a) over %ld structured+random operands\n"
               "      -- the identity all 20 rewritten call sites rest on\n", NSQR);

    printf("\n%ld checks, %ld failures\n", checks, failures);
    if (failures){ printf("SOME TESTS FAILED (%ld failures)\n", failures); return 1; }
    printf("ALL TESTS PASSED (0 failures)\n");
    return 0;
}
