/* test_ripemd160_thread_stress.c -- ripemd160 from many threads at once.
 *
 * WHY THIS EXISTS
 *   2026-08-23: ripemd160.asm's round loop was rewritten fully unrolled
 *   (BENCHMARKS.md tier 1 had it 3.16x slower than Core; the rewrite measures
 *   ~1.15 ns/B, parity). The rewrite kept all state in registers and the
 *   message schedule in the caller's frame -- there is NO process-global
 *   mutable state left, and this test pins that property under load, the same
 *   way test_schnorr_thread_stress pins schnorr_verify's (whose global-buffer
 *   bug produced 1,982 false rejects in 160k verifications across 8 threads,
 *   found the SAME DAY the TLS conversion was declared complete). "No shared
 *   state by inspection" has been wrong twice; this makes it measured.
 *
 * WHAT IT ASSERTS
 *   Truth digests for a rotation of messages are computed single-threaded
 *   first. The message lengths straddle every padding boundary (0, 1, 20, 32,
 *   55, 56, 63, 64, 65, 119, 120, 128, 1000): 55/56 is where the length field
 *   forces a second block, 63/64/65 the block edge itself. Then N threads
 *   recompute all of them ITERS times each, every digest memcmp'd against
 *   truth. One mismatch anywhere fails the test.
 *
 * Usage: ./test_ripemd160_thread_stress [threads] [iters]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>

extern void ripemd160(uint8_t out[20], const void* in, long len);

static const long LENS[] = {0,1,20,32,55,56,63,64,65,119,120,128,1000};
#define NLEN ((int)(sizeof LENS / sizeof LENS[0]))
static uint8_t MSG[NLEN][1000];
static uint8_t TRUTH[NLEN][20];

#define MAXT 32
static long bad[MAXT];
static int NT = 8, ITERS = 20000;

static void* worker(void* arg){
    long t = (long)arg;
    uint8_t d[20];
    for (int i = 0; i < ITERS; i++){
        /* start each thread at a different offset so concurrent calls hold
         * DIFFERENT lengths/messages at the same instant */
        for (int k = 0; k < NLEN; k++){
            int v = (int)((t + i + k) % NLEN);
            ripemd160(d, MSG[v], LENS[v]);
            if (memcmp(d, TRUTH[v], 20) != 0) bad[t]++;
        }
    }
    return 0;
}

int main(int argc, char** argv){
    if (argc > 1) NT = atoi(argv[1]);
    if (argc > 2) ITERS = atoi(argv[2]);
    if (NT < 1 || NT > MAXT){ fprintf(stderr, "threads 1..%d\n", MAXT); return 1; }

    for (int v = 0; v < NLEN; v++){
        for (long i = 0; i < LENS[v]; i++) MSG[v][i] = (uint8_t)(v*131 + i*7 + 1);
        ripemd160(TRUTH[v], MSG[v], LENS[v]);       /* single-threaded truth */
    }
    /* sanity: the empty-message digest is a published constant */
    static const uint8_t EMPTY[20] = {0x9c,0x11,0x85,0xa5,0xc5,0xe9,0xfc,0x54,0x61,0x28,
                                      0x08,0x97,0x7e,0xe8,0xf5,0x48,0xb2,0x25,0x8d,0x31};
    if (memcmp(TRUTH[0], EMPTY, 20) != 0){ printf("FAIL empty-message truth vector\n"); return 1; }

    pthread_t th[MAXT];
    for (long t = 0; t < NT; t++) pthread_create(&th[t], 0, worker, (void*)t);
    long total_bad = 0, total = 0;
    for (long t = 0; t < NT; t++){ pthread_join(th[t], 0); total_bad += bad[t]; total += (long)ITERS * NLEN; }

    printf("%ld digests across %d thread(s): %ld mismatch(es)\n", total, NT, total_bad);
    if (total_bad){ printf("TESTS FAILED (shared mutable state in ripemd160)\n"); return 1; }
    printf("ALL TESTS PASSED (0 failures)\n");
    return 0;
}
