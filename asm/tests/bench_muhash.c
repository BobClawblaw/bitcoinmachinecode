/* tests/bench_muhash.c -- ns per num3072_mul and per muhash_insert on ONE
 * pinned core.
 *
 * WHY. docs/audits/UTXO_INLINE_BUILD_PERF_SCOPE.md ("the MuHash fold is on
 * the bulk connect path") puts one MuHash element at 1.66 us on this host and
 * a full sync at ~6.4 billion elements -- ~3 h of the connect thread. The
 * lever is the 3072-bit modular multiply in bitcoin_muhash.asm. This tool is
 * the ruler for that work: it times the multiply alone (num3072_mul, the
 * thing being rewritten) and the whole element fold (muhash_insert: SHA256 +
 * ChaCha20 expansion + the multiply), so a speed-up in the multiply can be
 * read off next to its share of the end-to-end cost.
 *
 * Print-only, run by hand; NOT in `make test` (makefile_runlist_audit.py only
 * audits test_*.c, so a bench_* needs no allow-list entry). Build and run:
 *     make tests/bench_muhash && tests/bench_muhash [N] [cpu]
 *
 * Method. sched_setaffinity pins the process to one core (default: the one it
 * started on) so the number is one core's, not a migration average. The
 * multiply loop is a DEPENDENCY CHAIN -- acc = acc * b, the shape every real
 * caller has (muhash_insert folds into a running accumulator) -- so it
 * measures latency, not throughput of independent multiplies, which is what
 * the connect thread actually pays. Each measurement is taken three times and
 * the MINIMUM is reported: the minimum is the least-disturbed run, and the
 * spread between min and max is printed so a noisy host is visible.
 *
 * Every multiply body the CPU can run is timed in turn through the
 * num3072_mul_force_path seam, so the table always carries a "generic" row:
 * that body is what the daemon ran before the ADX body existed, and it is
 * the negative control for any claimed speed-up (its number must match the
 * baseline recorded when this tool was added: 949 ns / 1640 ns here).
 */
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

extern void muhash_init(void* acc);
extern void muhash_insert(void* acc, const void* data, unsigned long len);
extern void num3072_mul(void* a, const void* b);
extern void num3072_mul_force_path(int p);   /* 0 re-probe, 1 ADX, 2 generic, 3 IFMA */
extern int  num3072_mul_current_path(void);
extern int  num3072_cpu_has_adx(void);
extern int  num3072_cpu_has_ifma(void);

static double now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e9 + ts.tv_nsec;
}

/* splitmix64: deterministic operands, so two runs time the same work */
static uint64_t sm(uint64_t* s)
{
    *s += 0x9E3779B97F4A7C15ULL;
    uint64_t z = *s;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static void fill(uint64_t* limbs, int n, uint64_t* seed)
{
    for (int i = 0; i < n; i++) limbs[i] = sm(seed);
}

struct row { const char* name; double mul_ns, mul_spread, ins_ns, ins_spread; };

/* returns ns/call, minimum of `reps` runs; *spread = max - min */
static double time_mul(long n, int reps, double* spread)
{
    uint64_t seed = 0x1234567ULL;
    static uint64_t acc[48], b[48];
    double best = 1e30, worst = 0;
    for (int r = 0; r < reps; r++) {
        fill(acc, 48, &seed);
        fill(b, 48, &seed);
        acc[47] &= 0x7fffffffffffffffULL;   /* below the modulus */
        b[47]   &= 0x7fffffffffffffffULL;
        double t0 = now_ns();
        for (long i = 0; i < n; i++) num3072_mul(acc, b);
        double dt = (now_ns() - t0) / (double)n;
        if (dt < best) best = dt;
        if (dt > worst) worst = dt;
    }
    /* keep the result observable so nothing can be hoisted */
    if (acc[0] == 0x123456789abcdefULL) printf("(unlikely)\n");
    *spread = worst - best;
    return best;
}

static double time_insert(long n, int reps, double* spread)
{
    static uint64_t acc[48];
    static unsigned char coin[100];
    double best = 1e30, worst = 0;
    for (int r = 0; r < reps; r++) {
        muhash_init(acc);
        memset(coin, 0x5a, sizeof coin);
        double t0 = now_ns();
        for (long i = 0; i < n; i++) {
            memcpy(coin, &i, sizeof i);       /* a different element each time */
            muhash_insert(acc, coin, sizeof coin);
        }
        double dt = (now_ns() - t0) / (double)n;
        if (dt < best) best = dt;
        if (dt > worst) worst = dt;
    }
    if (acc[0] == 0x123456789abcdefULL) printf("(unlikely)\n");
    *spread = worst - best;
    return best;
}

int main(int argc, char** argv)
{
    long n   = argc > 1 ? atol(argv[1]) : 200000;
    int  cpu = argc > 2 ? atoi(argv[2]) : sched_getcpu();
    const int reps = 3;

    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof set, &set) != 0) {
        perror("sched_setaffinity");
        return 1;
    }

    /* every body this CPU can run, generic first: it is the pre-change
     * daemon's path and is always present */
    struct { int path; const char* name; int avail; } paths[] = {
        { 2, "generic (mul/adc, pre-change)", 1 },
        { 1, "bmi2/adx (mulx/adcx/adox)",     num3072_cpu_has_adx()  },
        { 3, "avx512-ifma (52-bit limbs)",    num3072_cpu_has_ifma() },
    };
    struct row rows[sizeof paths / sizeof paths[0]];
    int nrows = 0;

    printf("bench_muhash: N=%ld per measurement, min of %d, pinned to cpu %d\n",
           n, reps, cpu);
    for (unsigned p = 0; p < sizeof paths / sizeof paths[0]; p++) {
        if (!paths[p].avail) {
            printf("  path %d (%s): not available on this CPU, skipped\n",
                   paths[p].path, paths[p].name);
            continue;
        }
        num3072_mul_force_path(paths[p].path);
        struct row* r = &rows[nrows++];
        r->name   = paths[p].name;
        r->mul_ns = time_mul(n, reps, &r->mul_spread);
        r->ins_ns = time_insert(n, reps, &r->ins_spread);
        if (num3072_mul_current_path() != paths[p].path) {
            printf("path %d did not stay selected\n", paths[p].path);
            return 1;
        }
    }
    num3072_mul_force_path(0);   /* back to the daemon's default: re-probe */

    printf("\n  %-34s %14s %14s\n", "path", "num3072_mul", "muhash_insert");
    for (int i = 0; i < nrows; i++)
        printf("  %-34s %9.1f ns   %9.1f ns   (spread %.1f / %.1f)\n",
               rows[i].name, rows[i].mul_ns, rows[i].ins_ns,
               rows[i].mul_spread, rows[i].ins_spread);
    for (int i = 1; i < nrows; i++)
        printf("  %-34s %8.2fx      %8.2fx     vs generic\n", rows[i].name,
               rows[0].mul_ns / rows[i].mul_ns, rows[0].ins_ns / rows[i].ins_ns);
    return 0;
}
