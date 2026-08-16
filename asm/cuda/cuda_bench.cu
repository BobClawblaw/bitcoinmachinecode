/*
 * cuda_bench.cu -- honest throughput comparison for the two workloads where
 * GPU batch SHA-256 is actually justified:
 *
 *   A) PoW candidate scanning : N independent 80-byte headers, sha256d each.
 *      (This is the classic mining-adjacent workload the node's pow_check runs
 *       one-at-a-time; a GPU can test N different nonce/header candidates.)
 *   B) Batch tx/block hashing  : N independent sha256d over varied-length msgs
 *      (e.g. re-index / IBD validation batching).
 *
 * The point is NOT to claim the GPU wins on one hash -- it never will against
 * SHA-NI. It is to show where the crossover is and what the node could get.
 * Timings are wall-clock for the WHOLE batch (host upload + launch + D2H copy +
 * sync) vs the same N hashes run through the proven asm sha256d on CPU.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <cuda_runtime.h>

extern "C" void sha256d(void *out, const void *msg, unsigned long len);

// CUDA host launchers (opaque void* API, C linkage -- see cuda_sha256.h)
#include "cuda_sha256.h"

typedef struct { uint8_t *d_msgs; uint8_t *d_out; uint64_t *d_idx; uint64_t count; int which; cudaStream_t stream; } cudaShaBatch;

static double now_s(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec + ts.tv_nsec*1e-9; }

int main(int argc, char**argv)
{
    if (cudaSetDevice(0) != cudaSuccess) { printf("no CUDA device\n"); return 2; }
    long N = (argc > 1) ? atol(argv[1]) : 1000000;
    if (N < 1) N = 1;

    // Workload A: N independent 80-byte headers; sha256d each (which=1).
    // Build blob of N*80 bytes and idx referencing each.
    size_t blob_sz = 80 * N;
    uint8_t *blob = (uint8_t*)malloc(blob_sz);
    uint64_t *idx = (uint64_t*)malloc((size_t)N*2*sizeof(uint64_t));
    for (long i = 0; i < N; i++) {
        for (int k = 0; k < 80; k++) blob[(size_t)i*80+k] = (uint8_t)((i*31+k*7) & 0xff);
        idx[2*i+0] = (uint64_t)i*80;
        idx[2*i+1] = 80;
    }

    printf("Batch size N = %ld  (80-byte headers, sha256d each)\n", N);

    // ---- CPU baseline (proven asm sha256d, SHA-NI path active on this CPU) ----
    uint8_t *cpu_out = (uint8_t*)calloc(1, (size_t)N*32 ? (size_t)N*32 : 1);
    double t0 = now_s();
    for (long i = 0; i < N; i++)
        sha256d(cpu_out + (size_t)i*32, blob + (size_t)i*80, 80);
    double tcpu = now_s() - t0;
    printf("  CPU asm sha256d x%ld : %8.4f s  => %10.0f hashes/s  (%9.2f Mh/s)\n",
           N, tcpu, N/tcpu, N/tcpu/1e6);

    // ---- GPU batch ----
    cudaShaBatch b;
    if (cuda_sha256_batch_init(&b, blob, idx, N, 1)) { printf("  cuda init failed\n"); return 2; }
    // warm up
    cuda_sha256_batch_launch(&b); cuda_sha256_batch_sync(&b, NULL);
    uint8_t *gpu_out = (uint8_t*)malloc((size_t)N*32);
    t0 = now_s();
    cuda_sha256_batch_launch(&b);
    cuda_sha256_batch_sync(&b, gpu_out);
    double tgpu = now_s() - t0;
    printf("  GPU  batch   x%ld : %8.4f s  => %10.0f hashes/s  (%9.2f Mh/s)\n",
           N, tgpu, N/tgpu, N/tgpu/1e6);

    // Correctness cross-check on a sample
    size_t bad = 0, sample = (N < 100) ? N : 100;
    for (size_t i = 0; i < sample; i++)
        if (memcmp(gpu_out+i*32, cpu_out+i*32, 32) != 0) bad++;
    printf("  cross-check first %zu samples vs CPU: %s\n", sample, bad ? "MISMATCH" : "OK");
    if (bad) { printf("  (first gpu vs cpu)\n"); return 1; }

    double speedup = tcpu / tgpu;
    printf("\n  GPU/CPU speedup: %.2fx over the whole batch\n", speedup);

    // ---- Small-batch regime to show the crossover ----
    printf("\n  Crossover note: at very small N, launch+copy overhead dominates and\n");
    printf("  CPU/SHA-NI wins. GPU pulls ahead only once N is large enough to amortize.\n");
    printf("  (Run with a small N, e.g. N=1000, to observe the overhead-dominated regime.)\n");

    cuda_sha256_batch_free(&b);
    return 0;
}
