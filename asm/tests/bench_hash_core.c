/* bench_hash_core.c -- hash primitives measured in EXACTLY the shapes Bitcoin
 * Core's own bench_bitcoin measures them, so the two tables compare directly.
 *
 * tests/bench_hash.c already exists and compares this repo's asm SHA-256
 * against OpenSSL in GB/s. That is a useful number but it is NOT comparable to
 * Core's, because Core's src/bench/crypto_hash.cpp benchmarks a different set
 * of shapes and reports ns/byte off a different clock. This file exists so a
 * Tier-1 row in BENCHMARKS.md is a like-for-like comparison rather than two
 * numbers that merely sound similar.
 *
 * SHAPES -- each mirrors one Core benchmark, byte-for-byte:
 *   sha256_1MB     <- SHA256_SHANI            : one CSHA256 over 1,000,000 B
 *                                               (BUFFER_SIZE in crypto_hash.cpp)
 *   sha256_32b     <- SHA256_32b_SHANI        : one CSHA256 over 32 B
 *   sha256d64_64Bx1024 <- SHA256D64_1024_SHANI : 1024 double-SHA256 of 64 B each
 *                                               (Core's SHA256D64, the merkle
 *                                               pair kernel; batch = 65,536 B)
 *   sha1_1MB       <- SHA1                    : one CSHA1 over 1,000,000 B
 *   sha512_1MB     <- SHA512                  : one CSHA512 over 1,000,000 B
 *   ripemd160_1MB  <- BenchRIPEMD160          : one CRIPEMD160 over 1,000,000 B
 *
 * Core's buffers are zero-filled (std::vector<uint8_t> in(N, 0)); so are these.
 * Content does not affect SHA-2/RIPEMD timing -- there are no data-dependent
 * branches -- but it is matched anyway so the inputs are identical.
 *
 * MEASUREMENT (the discipline PERF_SCOPE.md section 9 insists on, because this
 * box runs a full-chain replay next to every benchmark):
 *   - CLOCK_THREAD_CPUTIME_ID: the clock stops while this thread is
 *     descheduled, so a busy machine cannot inflate the number.
 *   - min over N rounds: interference only ever ADDS time, so the minimum is
 *     the best estimate of intrinsic cost.
 *   - min, median and max are all printed, so a reader can see the spread
 *     rather than trusting a bare figure.
 *
 * Core's nanobench, by contrast, uses WALL clock and reports the median of its
 * epochs. Its -output-csv does emit a per-epoch `min` column, and that is the
 * column scripts/bench_vs_core.sh reads, so both sides end up compared
 * min-to-min. The remaining difference -- wall vs CPU time -- is reported by
 * that script as a cpu/wall ratio per Core process, so a reader can see
 * whether Core's side was preempted.
 *
 *   argv[1] = rounds (default 15)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern void sha256_full(unsigned char out[32], const void* m, long len);
extern void sha256d(unsigned char out[32], const void* m, long len);
extern void sha256d64(unsigned char* out, const unsigned char* in, unsigned long pairs);
extern void sha1_full(unsigned char out[20], const void* m, long len);
extern void sha512_full(unsigned char out[64], const void* m, long len);
extern void ripemd160(unsigned char out[20], const void* in, long long len);

/* tests/bench_abi_guard.S -- see that file's header. `ripemd160` destroys the
 * caller's r15 and the low half of r14 (its stack locals overlap its own
 * pushed register saves). Before the guard was added this harness spun forever
 * on the RIPEMD-160 row, because the clobber landed on a loop bound. The row
 * is measured through the trampoline instead of being dropped; the six
 * push/pop pairs it costs are under one part in a million of a 3 ms call, and
 * the row is marked `*` in the output so the reader knows.
 * tests/bench_abi_audit.c is the standing check for this across the suite. */
extern long bench_call_guarded(void* fn, const unsigned long args[6]);

#define CORE_BUFFER_SIZE 1000000   /* crypto_hash.cpp BUFFER_SIZE */
#define D64_PAIRS        1024      /* SHA256D64(in, in, 1024) */

static double cpu_s(void){
    struct timespec ts;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static int cmpd(const void* a, const void* b){
    double x = *(const double*)a, y = *(const double*)b;
    return (x > y) - (x < y);
}

/* One measured shape. `iters` calls of `fn` per round; `bytes` is the number of
 * input bytes ONE call consumes, matching Core's bench.batch() argument, so the
 * ns/byte column means the same thing on both sides. */
typedef void (*shape_fn)(unsigned char* buf);

static void run_shape(const char* name, const char* core_name, shape_fn fn,
                      unsigned char* buf, long iters, long bytes, int rounds)
{
    double* t = malloc((size_t)rounds * sizeof(double));
    if (!t) { printf("%-18s OOM\n", name); return; }
    for (int r = 0; r < rounds; r++){
        double a = cpu_s();
        for (long i = 0; i < iters; i++) fn(buf);
        t[r] = cpu_s() - a;
    }
    qsort(t, (size_t)rounds, sizeof(double), cmpd);
    double mn = t[0] / (double)iters;
    double md = t[rounds/2] / (double)iters;
    double mx = t[rounds-1] / (double)iters;
    printf("%-18s %10.2f %10.2f %10.2f   %8.4f  %11.3f   %s\n",
           name, mn*1e9, md*1e9, mx*1e9,
           mn*1e9/(double)bytes, (double)bytes/mn/1e9, core_name);
    free(t);
}

static void s_sha256_1mb (unsigned char* b){ unsigned char o[32]; sha256_full(o, b, CORE_BUFFER_SIZE); }
static void s_sha256_32b (unsigned char* b){ unsigned char o[32]; sha256_full(o, b, 32); }
static unsigned char d64_out[D64_PAIRS * 32];
static void s_sha256d_64 (unsigned char* b){
    /* Core's SHA256D64(out, in, 1024): 1024 32-byte digests from 1024 64-byte
     * inputs, all in one call. `sha256d64` (bitcoin_hash.asm, 2026-08-23) is
     * the same signature and the same work, so this row is now like for like.
     * The row below keeps the OLD one-at-a-time shape so the improvement is
     * visible in the same table rather than only in a commit message. */
    sha256d64(d64_out, b, D64_PAIRS);
}
static void s_sha256d_64_seq (unsigned char* b){
    unsigned char o[32];
    for (int i = 0; i < D64_PAIRS; i++) sha256d(o, b + (long)i*64, 64);
}
static void s_sha1_1mb   (unsigned char* b){ unsigned char o[20]; sha1_full(o, b, CORE_BUFFER_SIZE); }
static void s_sha512_1mb (unsigned char* b){ unsigned char o[64]; sha512_full(o, b, CORE_BUFFER_SIZE); }
static void s_rmd160_1mb (unsigned char* b){
    unsigned char o[20];
    unsigned long args[6] = { (unsigned long)o, (unsigned long)b, CORE_BUFFER_SIZE, 0, 0, 0 };
    bench_call_guarded((void*)ripemd160, args);
}

int main(int argc, char** argv){
    int rounds = (argc > 1) ? atoi(argv[1]) : 15;
    if (rounds < 3) rounds = 3;

    unsigned char* buf = calloc(1, CORE_BUFFER_SIZE);
    if (!buf){ printf("alloc failed\n"); return 1; }

    /* Correctness gate before timing: SHA-256 of 32 zero bytes has a known
     * digest. A benchmark of a broken primitive is worse than no benchmark. */
    {
        unsigned char o[32];
        static const unsigned char want[32] = {
            0x66,0x68,0x7a,0xad,0xf8,0x62,0xbd,0x77,0x6c,0x8f,0xc1,0x8b,0x8e,0x9f,0x8e,0x20,
            0x08,0x97,0x14,0x85,0x6e,0xe2,0x33,0xb3,0x90,0x2a,0x59,0x1d,0x0d,0x5f,0x29,0x25 };
        sha256_full(o, buf, 32);
        if (memcmp(o, want, 32) != 0){ printf("FAIL: sha256(32 zero bytes) wrong\n"); return 1; }
    }

    printf("== hash primitives, Core's own benchmark shapes ==\n");
    printf("   CPU time (CLOCK_THREAD_CPUTIME_ID), min-of-%d rounds\n", rounds);
    printf("%-18s %10s %10s %10s   %8s  %11s   %s\n",
           "shape", "min ns/op", "med", "max", "ns/byte", "GB/s", "Core benchmark");

    run_shape("sha256_1MB",       "SHA256_SHANI",           s_sha256_1mb,  buf,   30, CORE_BUFFER_SIZE,     rounds);
    run_shape("sha256_32b",       "SHA256_32b_SHANI",       s_sha256_32b,  buf, 300000, 32,                 rounds);
    run_shape("sha256d64_64Bx1024","SHA256D64_1024_SHANI",  s_sha256d_64,  buf,  300, 64L*D64_PAIRS,        rounds);
    run_shape("sha256d_seq_x1024","(no Core opposite)",     s_sha256d_64_seq, buf, 300, 64L*D64_PAIRS,      rounds);
    run_shape("sha1_1MB",         "SHA1",                   s_sha1_1mb,    buf,   30, CORE_BUFFER_SIZE,     rounds);
    run_shape("sha512_1MB",       "SHA512",                 s_sha512_1mb,  buf,   30, CORE_BUFFER_SIZE,     rounds);
    run_shape("ripemd160_1MB*",   "BenchRIPEMD160",         s_rmd160_1mb,  buf,   20, CORE_BUFFER_SIZE,     rounds);

    printf("   * ripemd160 is called through tests/bench_abi_guard.S -- it does not\n"
           "     preserve r14/r15 and corrupts an unguarded caller. See tests/bench_abi_audit.\n");

    free(buf);
    return 0;
}
