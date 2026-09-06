/* tests/test_muhash_mul_diff.c -- the BMI2/ADX body of num3072_mul against
 * the generic mul/adc body, limb for limb.
 *
 * WHY. num3072_mul dispatches once from CPUID and every multiply in the
 * process then takes one body. Core's vectors in tests/muhash_vectors.h are
 * a few dozen products; they pin each body to Core, but a carry that only
 * fails one time in a million would sail through them. This test forces each
 * body in turn through num3072_mul_force_path and compares the two on
 *   - 100,000 random operand pairs, drawn from four limb populations
 *     (uniform; limbs from {0, all-ones, 2^63, 1, random}; values within a
 *     few of the modulus and of 2^3072; single-bit values), so all-ones
 *     limbs and the values around p are dense rather than incidental;
 *   - every pair from an explicit edge list (0, 1, 2, n-1, n, n+1, p-2, p-1,
 *     p, p+1, 2^3072-2, 2^3072-1, 2^3071, ...), a and b both ways;
 *   - a 20,000-step chained accumulator (acc = acc*b), the shape every
 *     caller has, compared at every step so a divergence in a NON-canonical
 *     intermediate cannot be masked by a later reduction.
 * Byte-identical output is the requirement, not "same residue class":
 * Core's Multiply can leave a non-canonical value, and the ADX body must
 * leave the same one (see the identity argument at num3072_mul_adx).
 *
 * Failure-first: with one carry deliberately broken in a scratch copy of the
 * ADX body (the closing `adox r11, r8` of a row removed) this test reported
 * mismatches in the first hundred random pairs -- recorded in the commit.
 *
 * SKIPs, exit 0, on a CPU without BMI2/ADX: there is only one body to run
 * there, and tests/test_muhash still holds it to Core's vectors.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#define NLIMBS 48
#define MAX_PRIME_DIFF 1103717ULL

extern void num3072_mul(void* a, const void* b);
extern void num3072_mul_force_path(int p);   /* 0 re-probe, 1 ADX, 2 generic */
extern int  num3072_mul_current_path(void);
extern int  num3072_cpu_has_adx(void);

static uint64_t g_seed = 0x5DEECE66DULL;
static uint64_t sm(void)
{
    g_seed += 0x9E3779B97F4A7C15ULL;
    uint64_t z = g_seed;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static long g_checked = 0, g_bad = 0;

static void show(const char* what, const uint64_t* v)
{
    printf("    %s =", what);
    for (int i = NLIMBS - 1; i >= 0; i--) printf(" %016llx", (unsigned long long)v[i]);
    printf("\n");
}

/* one comparison: generic vs ADX on the same operands; returns 1 on mismatch */
static int compare(const char* label, long idx, const uint64_t* a, const uint64_t* b)
{
    uint64_t g[NLIMBS], x[NLIMBS];
    memcpy(g, a, sizeof g);
    memcpy(x, a, sizeof x);
    num3072_mul_force_path(2);
    num3072_mul(g, b);
    if (num3072_mul_current_path() != 2) { printf("FAIL: generic path did not stay selected\n"); exit(1); }
    num3072_mul_force_path(1);
    num3072_mul(x, b);
    if (num3072_mul_current_path() != 1) { printf("FAIL: ADX path did not stay selected\n"); exit(1); }
    g_checked++;
    if (memcmp(g, x, sizeof g) != 0) {
        g_bad++;
        if (g_bad <= 3) {
            int first = -1;
            for (int i = 0; i < NLIMBS; i++) if (g[i] != x[i]) { first = i; break; }
            printf("FAIL %s[%ld]: bodies differ, first at limb %d\n", label, idx, first);
            show("a      ", a);
            show("b      ", b);
            show("generic", g);
            show("adx    ", x);
        }
        return 1;
    }
    return 0;
}

/* ---- operand populations ------------------------------------------------ */
static void set_u64(uint64_t* v, uint64_t lo)          /* v = lo */
{
    memset(v, 0, NLIMBS * 8);
    v[0] = lo;
}
static void set_modulus_plus(uint64_t* v, int64_t k)   /* v = p + k, |k| small */
{
    /* p = 2^3072 - n: limbs 1..47 all ones, limb 0 = 2^64 - n */
    memset(v, 0xff, NLIMBS * 8);
    v[0] = (uint64_t)(0 - MAX_PRIME_DIFF) + (uint64_t)k;   /* no borrow for |k| < n */
}
static void set_top_minus(uint64_t* v, uint64_t k)     /* v = 2^3072 - k, k >= 1 */
{
    memset(v, 0xff, NLIMBS * 8);
    v[0] = ~(k - 1);
}
static void set_bit(uint64_t* v, int bit)
{
    memset(v, 0, NLIMBS * 8);
    v[bit / 64] = 1ULL << (bit % 64);
}
static void fill_random(uint64_t* v, int population)
{
    switch (population) {
    case 0:                                             /* uniform */
        for (int i = 0; i < NLIMBS; i++) v[i] = sm();
        break;
    case 1:                                             /* structured limbs */
        for (int i = 0; i < NLIMBS; i++) {
            switch (sm() % 5) {
            case 0: v[i] = 0; break;
            case 1: v[i] = ~0ULL; break;
            case 2: v[i] = 1ULL << 63; break;
            case 3: v[i] = 1; break;
            default: v[i] = sm(); break;
            }
        }
        break;
    case 2:                                             /* around p / 2^3072 */
        if (sm() & 1) set_modulus_plus(v, (int64_t)(sm() % 7) - 3);
        else          set_top_minus(v, 1 + sm() % 4);
        /* sometimes knock a hole into the all-ones run */
        if ((sm() & 3) == 0) v[1 + sm() % (NLIMBS - 1)] = sm();
        break;
    default:                                            /* one bit, or a few */
        set_bit(v, (int)(sm() % 3072));
        if (sm() & 1) v[sm() % NLIMBS] |= 1ULL << (sm() % 64);
        break;
    }
}

int main(int argc, char** argv)
{
    long n_random = argc > 1 ? atol(argv[1]) : 100000;
    long n_chain  = argc > 2 ? atol(argv[2]) : 20000;

    if (!num3072_cpu_has_adx()) {
        printf("SKIP test_muhash_mul_diff: this CPU has no BMI2/ADX, only the generic body runs here\n");
        return 0;
    }

    static uint64_t a[NLIMBS], b[NLIMBS];

    /* ---- 1. random pairs, four populations, both operands ---- */
    for (long i = 0; i < n_random; i++) {
        fill_random(a, (int)(sm() % 4));
        fill_random(b, (int)(sm() % 4));
        compare("random", i, a, b);
    }
    printf("%s random pairs: %ld checked, %ld mismatched\n", g_bad ? "FAIL" : "ok  ", g_checked, g_bad);

    /* ---- 2. the explicit edge list, every ordered pair ---- */
    enum { NEDGE = 16 };
    static uint64_t edge[NEDGE][NLIMBS];
    set_u64(edge[0], 0);
    set_u64(edge[1], 1);
    set_u64(edge[2], 2);
    set_u64(edge[3], MAX_PRIME_DIFF - 1);
    set_u64(edge[4], MAX_PRIME_DIFF);
    set_u64(edge[5], MAX_PRIME_DIFF + 1);
    set_modulus_plus(edge[6], -2);
    set_modulus_plus(edge[7], -1);
    set_modulus_plus(edge[8], 0);
    set_modulus_plus(edge[9], 1);
    set_top_minus(edge[10], 2);
    set_top_minus(edge[11], 1);                          /* every limb all-ones */
    set_bit(edge[12], 3071);
    set_bit(edge[13], 64);
    memset(edge[14], 0xff, NLIMBS * 8); edge[14][0] = 0;  /* ones above a zero limb */
    memset(edge[15], 0, NLIMBS * 8); edge[15][NLIMBS - 1] = ~0ULL; /* only the top limb */
    long before = g_bad, checked0 = g_checked;
    for (int i = 0; i < NEDGE; i++)
        for (int j = 0; j < NEDGE; j++)
            compare("edge", i * NEDGE + j, edge[i], edge[j]);
    printf("%s edge pairs: %ld checked, %ld mismatched\n",
           g_bad != before ? "FAIL" : "ok  ", g_checked - checked0, g_bad - before);

    /* ---- 3. chained accumulator, compared at every step ---- */
    before = g_bad; checked0 = g_checked;
    {
        static uint64_t accg[NLIMBS], accx[NLIMBS];
        fill_random(accg, 0);
        accg[NLIMBS - 1] &= 0x7fffffffffffffffULL;
        memcpy(accx, accg, sizeof accg);
        for (long i = 0; i < n_chain; i++) {
            fill_random(b, (int)(sm() % 4));
            num3072_mul_force_path(2);
            num3072_mul(accg, b);
            num3072_mul_force_path(1);
            num3072_mul(accx, b);
            g_checked++;
            if (memcmp(accg, accx, sizeof accg) != 0) {
                g_bad++;
                if (g_bad <= 3) {
                    printf("FAIL chain[%ld]: bodies diverged\n", i);
                    show("b      ", b);
                    show("generic", accg);
                    show("adx    ", accx);
                }
                break;           /* everything after the first divergence is noise */
            }
        }
    }
    printf("%s chained accumulator: %ld steps, %ld divergence\n",
           g_bad != before ? "FAIL" : "ok  ", g_checked - checked0, g_bad - before);

    num3072_mul_force_path(0);
    if (g_bad) {
        printf("\ntest_muhash_mul_diff: %ld of %ld comparisons FAILED\n", g_bad, g_checked);
        return 1;
    }
    printf("\ntest_muhash_mul_diff: all %ld comparisons identical (generic vs ADX)\n", g_checked);
    return 0;
}
