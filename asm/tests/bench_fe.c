/* bench_fe.c -- field-primitive microbenchmark.
 *
 * METHODOLOGY (deliberate; see PERF_SCOPE.md and commit 879554b for why).
 * This box runs a full-chain replay alongside every measurement (load
 * average ~10 on 32 threads), so wall clock is meaningless here.
 *   - CLOCK_THREAD_CPUTIME_ID: the clock stops while this thread is
 *     descheduled, removing scheduler noise at the source.
 *   - min-of-N rounds: interference only ever ADDS time, so the minimum
 *     over many rounds is the best estimate of intrinsic cost.
 *   - the spread (min, median, max) is printed so a reader can judge how
 *     noisy the sample was rather than trusting a bare number.
 *
 * TWO REGIMES, both reported, because they bound the real cost:
 *   - LAT  : a serial dependency chain (r = r*a). Latency-bound.
 *   - THRU : 4 independent chains interleaved. Throughput-bound; this is
 *            closer to what point arithmetic actually achieves, since a
 *            point double/add has several independent multiplies.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef unsigned long long u64;

extern void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sqr(u64 r[4], const u64 a[4]);
extern void fe_add(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sub(u64 r[4], const u64 a[4], const u64 b[4]);

static double cpu_s(void){
    struct timespec ts; clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return ts.tv_sec + ts.tv_nsec*1e-9;
}

static int cmpd(const void* a, const void* b){
    double x = *(const double*)a, y = *(const double*)b;
    return (x>y) - (x<y);
}

/* Run `body` ROUNDS times, report ns per CALL (per_iter = calls in body)
 * for min / median / max. */
#define BENCHN(name, reps, rounds, per_iter, body)                           \
    do {                                                                     \
        double *s = malloc(sizeof(double)*(rounds));                         \
        for (int _r = 0; _r < (rounds); _r++){                               \
            double _t0 = cpu_s();                                            \
            for (long _i = 0; _i < (reps); _i++){ body }                     \
            s[_r] = (cpu_s() - _t0) / ((double)(reps) * (per_iter));         \
        }                                                                    \
        qsort(s, (rounds), sizeof(double), cmpd);                            \
        printf("%-18s min %7.3f ns  med %7.3f  max %7.3f   (min-of-%d, %ld calls/round)\n", \
               name, s[0]*1e9, s[(rounds)/2]*1e9, s[(rounds)-1]*1e9,         \
               (rounds), (long)(reps)*(per_iter));                           \
        fflush(stdout);                                                      \
        free(s);                                                             \
    } while (0)
#define BENCH(name, reps, rounds, body) BENCHN(name, reps, rounds, 1, body)

int main(int argc, char** argv){
    long reps   = (argc>1)? atol(argv[1]) : 200000;
    int  rounds = (argc>2)? atoi(argv[2]) : 25;

    /* Non-trivial, non-structured operands so no data-dependent shortcut
     * (there is none in this code, but keep the benchmark honest). */
    u64 a[4] = {0xfd723873aa170695ULL,0xe7bcc89470d63e1aULL,
                0x8947c271ac274529ULL,0x9651c463c001f731ULL};
    u64 b[4] = {0x21837fb0e654eaf7ULL,0x3b16ba7a5a9b154dULL,
                0x73d6d17fe8b63c99ULL,0x4e362e7fe8ff06daULL};
    u64 r0[4], r1[4], r2[4], r3[4];
    memcpy(r0,a,32); memcpy(r1,b,32); memcpy(r2,a,32); memcpy(r3,b,32);
    r1[0] ^= 3; r2[0] ^= 5; r3[0] ^= 7;

    /* warm-up */
    for (int i=0;i<20000;i++) fe_mul(r0,r0,b);

    BENCH("fe_mul LAT",  reps, rounds, fe_mul(r0,r0,b););
    BENCHN("fe_mul THRU", reps/4, rounds, 4,
          fe_mul(r0,r0,b); fe_mul(r1,r1,b); fe_mul(r2,r2,b); fe_mul(r3,r3,b););
    BENCH("fe_sqr LAT",  reps, rounds, fe_sqr(r0,r0););
    BENCHN("fe_sqr THRU", reps/4, rounds, 4,
          fe_sqr(r0,r0); fe_sqr(r1,r1); fe_sqr(r2,r2); fe_sqr(r3,r3););
    BENCH("fe_add LAT",  reps, rounds, fe_add(r0,r0,b););
    BENCH("fe_sub LAT",  reps, rounds, fe_sub(r0,r0,b););

    /* consume results so nothing is dead */
    u64 acc = r0[0]^r1[1]^r2[2]^r3[3];
    if (acc == 0x1234) printf("(unlikely)\n");
    return 0;
}
