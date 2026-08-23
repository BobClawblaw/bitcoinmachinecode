/* bench_merkle.c -- transaction merkle root over 9,001 leaves, the exact leaf
 * count Bitcoin Core's src/bench/merkle_root.cpp uses, so the two numbers are
 * directly comparable per leaf.
 *
 * Core's MerkleRoot bench fills 9,001 uint256 leaves from a deterministic
 * FastRandomContext and times ComputeMerkleRoot over them, reporting ns/leaf.
 * This file times merkle_root() (bitcoin_hash.asm) over 9,001 leaves and
 * reports the same unit.
 *
 * WHAT DIFFERS, stated rather than buried:
 *  - Leaf CONTENT differs. Core seeds from its own ChaCha20-based
 *    FastRandomContext; reproducing that here would mean vendoring Core code
 *    into this repo for a benchmark. Merkle timing is content-independent --
 *    SHA-256 has no data-dependent branches and every leaf is hashed exactly
 *    once per level regardless of value -- so the comparison is sound, but the
 *    roots are different values and this file therefore cannot cross-check its
 *    result against Core's expected_root constant.
 *  - Core's ComputeMerkleRoot uses SHA256D64, a 2-way-interleaved SHA-NI
 *    kernel that hashes two 64-byte pairs at once. merkle_root() in this repo
 *    calls sha256d sequentially. That is a real algorithmic difference in
 *    Core's favour and is the point of measuring it.
 *  - Core also benches MerkleRootWithMutation (duplicate-leaf detection, the
 *    CVE-2012-2459 guard). merkle_root() has no mutation-detection mode, so
 *    there is no row for it here; cons_verify's caller does not currently
 *    perform that check at all. See BENCHMARKS.md.
 *
 * MEASUREMENT: CLOCK_THREAD_CPUTIME_ID, min over N rounds, spread printed.
 * The leaf buffer is refilled before every timed call because merkle_root
 * consumes its input buffer in place (it writes each level over the previous
 * one); the refill is done OUTSIDE the timed region.
 *
 *   argv[1] = rounds (default 15)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

extern void merkle_root(unsigned char out[32], unsigned char hashes[], unsigned long n);

#define NLEAF 9001          /* merkle_root.cpp: hashes.resize(9001) */

static double cpu_s(void){
    struct timespec ts;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}
static int cmpd(const void* a, const void* b){
    double x = *(const double*)a, y = *(const double*)b;
    return (x > y) - (x < y);
}

/* splitmix64 -- a deterministic filler so successive runs of THIS benchmark
 * are reproducible. Deliberately not an attempt to match Core's RNG stream. */
static uint64_t sm64(uint64_t* s){
    uint64_t z = (*s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

int main(int argc, char** argv){
    int rounds = (argc > 1) ? atoi(argv[1]) : 15;
    if (rounds < 3) rounds = 3;

    /* merkle_root duplicates the last hash on an odd level, and it does so in
     * the caller's buffer -- so the buffer must have room for one extra slot
     * at every level. n+1 is enough for the first (largest) level and every
     * level after it is smaller. */
    unsigned char* seed = malloc((size_t)(NLEAF + 1) * 32);
    unsigned char* work = malloc((size_t)(NLEAF + 1) * 32);
    if (!seed || !work){ printf("alloc failed\n"); return 1; }

    uint64_t s = 0x0123456789ABCDEFULL;
    for (int i = 0; i < NLEAF; i++)
        for (int k = 0; k < 4; k++){
            uint64_t v = sm64(&s);
            memcpy(seed + (size_t)i*32 + (size_t)k*8, &v, 8);
        }

    unsigned char root[32], first[32];
    memcpy(work, seed, (size_t)NLEAF * 32);
    merkle_root(first, work, NLEAF);

    double* t = malloc((size_t)rounds * sizeof(double));
    if (!t) return 1;
    for (int r = 0; r < rounds; r++){
        memcpy(work, seed, (size_t)NLEAF * 32);     /* outside the timed region */
        double a = cpu_s();
        merkle_root(root, work, NLEAF);
        t[r] = cpu_s() - a;
        /* Determinism gate: every round must produce the same root, or the
         * buffer reuse is corrupting the input and the timing is meaningless. */
        if (memcmp(root, first, 32) != 0){
            printf("FAIL: merkle root changed between rounds -- buffer reuse is unsound\n");
            return 1;
        }
    }
    qsort(t, (size_t)rounds, sizeof(double), cmpd);

    printf("== merkle root, %d leaves (Core src/bench/merkle_root.cpp leaf count) ==\n", NLEAF);
    printf("   CPU time (CLOCK_THREAD_CPUTIME_ID), min-of-%d rounds\n", rounds);
    printf("merkle_root %d leaves   min %9.2f us   med %9.2f   max %9.2f   -> %7.2f ns/leaf\n",
           NLEAF, t[0]*1e6, t[rounds/2]*1e6, t[rounds-1]*1e6, t[0]*1e9/NLEAF);
    printf("   Core opposite number: MerkleRoot (ns/leaf)\n");
    free(t); free(seed); free(work);
    return 0;
}
