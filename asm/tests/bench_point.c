/* bench_point.c -- EC-layer microbenchmark: point_double, point_add,
 * point_add_mixed.  Written for PERF_SCOPE.md 12 (inlining the field
 * add/sub into the EC formulas): the field-level bench (tests/bench_fe)
 * cannot see the effect of removing a call boundary INSIDE these routines,
 * so this is the level at which that lever has to be measured.
 *
 * METHODOLOGY -- identical discipline to tests/bench_fe and tests/bench_ecdsa,
 * and for the same reason (a full-chain replay runs alongside every
 * measurement on this box):
 *   - CLOCK_THREAD_CPUTIME_ID, so the clock stops while descheduled;
 *   - min over N rounds, because interference can only ADD time;
 *   - min / median / max all printed, so the reader can judge the spread.
 *
 * The loops are SERIAL dependency chains (r = 2r, r = r + Q), which is
 * exactly the shape of the ladders that call these routines, and it is the
 * regime in which the store->load round trip through the stack frame that
 * inlining removes actually costs latency.
 *
 * Operands are real curve points (k*G from point_scalar_mul_fixed), so every
 * call takes the generic .distinct / finite path -- the one the ladder takes
 * ~99.99 % of the time -- and the final Z != 0 assertion proves the chain
 * never collapsed to infinity and the timed work was real.
 *
 *   argv[1] = iterations per round (default 200000)
 *   argv[2] = rounds (default 15)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef unsigned long long u64;

/* The additive field ops, both ways, measured in ONE binary at one moment so
 * the comparison is not exposed to bench_fe's +-0.5 ns alignment sensitivity.
 * fe_*_inl are tests/fe_inline_probe.asm: the SAME macro bodies the EC
 * routines expand, wrapped in a SysV function. The wrapper costs three
 * push/pop pairs plus a ret that the in-situ expansion does not pay, so the
 * inline rows here are an UPPER bound on the real per-operation cost. */
extern void fe_add(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sub(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_add_inl(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sub_inl(u64 r[4], const u64 a[4], const u64 b[4]);

extern void point_double(u64 r[12], const u64 p[12]);
extern void point_add(u64 r[12], const u64 p[12], const u64 q[12]);
extern void point_add_mixed(u64 r[12], const u64 p[12], const u64 xy[8]);
extern void point_scalar_mul_fixed(u64 r[12], const u64 k[4]);

/* G, affine, little-endian limbs. */
static const u64 GX[4] = {0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL,
                          0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL};
static const u64 GY[4] = {0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL,
                          0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL};

static double cpu_s(void){
    struct timespec ts; clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return ts.tv_sec + ts.tv_nsec*1e-9;
}
static int cmpd(const void* a, const void* b){
    double x = *(const double*)a, y = *(const double*)b;
    return (x>y) - (x<y);
}

#define BENCH(name, reps, rounds, init, body)                                \
    do {                                                                     \
        double *s = malloc(sizeof(double)*(rounds));                         \
        for (int _r = 0; _r < (rounds); _r++){                               \
            init;                                                            \
            double _t0 = cpu_s();                                            \
            for (long _i = 0; _i < (reps); _i++){ body }                     \
            s[_r] = (cpu_s() - _t0) / (double)(reps);                        \
            if (!(R[8]|R[9]|R[10]|R[11])){                                    \
                printf("FAIL: %s chain reached infinity -- timing invalid\n", \
                       name); return 1; }                                    \
        }                                                                    \
        qsort(s, (rounds), sizeof(double), cmpd);                            \
        printf("%-18s min %8.2f ns  med %8.2f  max %8.2f   (min-of-%d, %ld calls/round)\n", \
               name, s[0]*1e9, s[(rounds)/2]*1e9, s[(rounds)-1]*1e9,         \
               (rounds), (long)(reps));                                      \
        fflush(stdout);                                                      \
        free(s);                                                             \
    } while (0)

int main(int argc, char** argv){
    long reps   = (argc>1)? atol(argv[1]) : 200000;
    int  rounds = (argc>2)? atoi(argv[2]) : 15;

    u64 R[12], P0[12], Q[12], XY[8];
    u64 k1[4] = {0x0123456789abcdefULL, 0xfedcba9876543210ULL,
                 0x13579bdf2468ace0ULL, 0x0f1e2d3c4b5a6978ULL};
    u64 k2[4] = {0xdeadbeefcafef00dULL, 0x0102030405060708ULL,
                 0xa5a5a5a5a5a5a5a5ULL, 0x1122334455667788ULL};
    point_scalar_mul_fixed(P0, k1);
    point_scalar_mul_fixed(Q,  k2);
    memcpy(XY,     GX, 32);
    memcpy(XY + 4, GY, 32);
    if (!(P0[8]|P0[9]|P0[10]|P0[11]) || !(Q[8]|Q[9]|Q[10]|Q[11])){
        printf("FAIL: fixture point is infinity\n"); return 1; }

    for (int i = 0; i < 20000; i++) point_double(P0, P0);   /* warm-up */

    BENCH("point_double",    reps,   rounds, memcpy(R, P0, 96),
          point_double(R, R););
    BENCH("point_add",       reps/4, rounds, memcpy(R, P0, 96),
          point_add(R, R, Q););
    BENCH("point_add_mixed", reps/4, rounds, memcpy(R, P0, 96),
          point_add_mixed(R, R, XY););

    /* ---- the field additive ops, call vs inline, serial chains ---- */
    {
        u64 x[4], y[4];
        memcpy(y, GY, 32);
#define BENCHF(name, body)                                                   \
        do {                                                                 \
            double *s = malloc(sizeof(double)*(rounds));                     \
            for (int _r = 0; _r < (rounds); _r++){                           \
                memcpy(x, GX, 32);                                           \
                double _t0 = cpu_s();                                        \
                for (long _i = 0; _i < reps; _i++){ body }                   \
                s[_r] = (cpu_s() - _t0) / (double)reps;                      \
                if (x[0] == 0x1234) printf("(unlikely)\n");                  \
            }                                                                \
            qsort(s, (rounds), sizeof(double), cmpd);                        \
            printf("%-18s min %8.3f ns  med %8.3f  max %8.3f   (min-of-%d, %ld calls/round)\n", \
                   name, s[0]*1e9, s[(rounds)/2]*1e9, s[(rounds)-1]*1e9,     \
                   (rounds), reps);                                          \
            fflush(stdout); free(s);                                         \
        } while (0)
        BENCHF("fe_add CALL",   fe_add(x, x, y););
        BENCHF("fe_add inline", fe_add_inl(x, x, y););
        BENCHF("fe_sub CALL",   fe_sub(x, x, y););
        BENCHF("fe_sub inline", fe_sub_inl(x, x, y););
#undef BENCHF
    }
    return 0;
}
