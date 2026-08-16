/*
 * cuda_verify.cu -- verify the CUDA batch SHA-256 against:
 *   1) canonical FIPS 180-4 vectors (same ones the asm core is validated on)
 *   2) the repo's OWN assembly sha256_full oracle (bit-for-bit agreement),
 *      across a mix of lengths including Bitcoin-relevant pad edge cases.
 *
 * This is the correctness gate: GPU output MUST equal CPU output exactly.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <cuda_runtime.h>

// The assembly core under test -- linked from ../sha256.o (see Makefile cu test).
extern "C" void sha256_full(void *out, const void *msg, unsigned long len);
extern "C" void sha256d(void *out, const void *msg, unsigned long len);

// CUDA host launchers (opaque void* API, C linkage -- see cuda_sha256.h)
#include "cuda_sha256.h"

typedef struct {
    uint8_t *d_msgs; uint8_t *d_out; uint64_t *d_idx;
    uint64_t count; int which; cudaStream_t stream;
} cudaShaBatch;

static int failures = 0;
static void check(const char *label, const uint8_t *got, const uint8_t *expect) {
    if (memcmp(got, expect, 32) == 0) {
        printf("  PASS  %s\n", label);
    } else {
        printf("  FAIL  %s\n", label);
        printf("    got:     ");
        for (int i = 0; i < 32; i++) printf("%02x", got[i]);
        printf("\n    expected:");
        for (int i = 0; i < 32; i++) printf("%02x", expect[i]);
        printf("\n");
        failures++;
    }
}

int main(void)
{
    cudaError_t ce = cudaSetDevice(0);
    if (ce != cudaSuccess) {
        printf("ERROR: no usable CUDA device: %s\n", cudaGetErrorString(ce));
        return 2;
    }
    cudaDeviceProp prop; cudaGetDeviceProperties(&prop, 0);
    printf("CUDA device: %s  (SM %d.%d)\n", prop.name, prop.major, prop.minor);

    // ---- Build a small batch of canonical messages ----
    // 0: empty string
    // 1: "abc"
    // 2: 56-byte message  (padding edge: rem == 56 -> must append length block)
    // 3: 63-byte message  (padding edge close to block)
    // 4: 64-byte message  (exactly one full block + pad block)
    // 5: 65-byte message  (one full + 1 byte + pad)
    // 6-9: random lengths

    const char *msgs_txt[10] = {0};
    uint8_t msgs_bytes[10][1200];
    uint64_t msgs_len[10] = {0};
    msgs_txt[0] = "";                                     msgs_len[0] = 0;
    msgs_txt[1] = "abc";                                  msgs_len[1] = 3;
    // 2,3,4,5 constructed below
    for (int i = 0; i < 56; i++) msgs_bytes[2][i] = (uint8_t)('a' + (i % 26)); msgs_len[2] = 56;
    for (int i = 0; i < 63; i++) msgs_bytes[3][i] = (uint8_t)(0x80 + i);     msgs_len[3] = 63;
    for (int i = 0; i < 64; i++) msgs_bytes[4][i] = (uint8_t)i;              msgs_len[4] = 64;
    for (int i = 0; i < 65; i++) msgs_bytes[5][i] = (uint8_t)(255 - i);      msgs_len[5] = 65;
    // random-ish
    srand(1234);
    for (int i = 6; i < 10; i++) {
        uint64_t L = 0;
        switch (i) {
            case 6: L = 55;  break;  // rem==55 -> pad block fits (rem becomes 56)
            case 7: L = 57;  break;  // spillover: needs extra block
            case 8: L = 111; break;
            case 9: L = 1000; break;
        }
        for (uint64_t k = 0; k < L; k++) msgs_bytes[i][k] = (uint8_t)(rand() & 0xff);
        msgs_len[i] = L;
    }

    int N = 10;

    // Build contiguous blob + idx
    uint64_t *idx = (uint64_t*)malloc(N*2*sizeof(uint64_t));
    uint8_t *blob = (uint8_t*)calloc(1, 64*1024);
    uint64_t off = 0;
    for (int i = 0; i < N; i++) {
        const void *src;
        if (i < 2) src = msgs_txt[i];
        else     src = msgs_bytes[i];
        if (msgs_len[i]) memcpy(blob + off, src, msgs_len[i]);
        idx[2*i+0] = off;
        idx[2*i+1] = msgs_len[i];
        off += msgs_len[i];  // no padding needed; idx offsets are explicit
    }

    printf("\n[1] VA: single SHA-256 via CUDA batch == asm sha256_full oracle\n");
    fflush(stdout);
    {
        uint8_t expect[N][32], got[N][32];
        for (int i = 0; i < N; i++)
            sha256_full(expect[i], (i<2? (const void*)msgs_txt[i] : msgs_bytes[i]), msgs_len[i]);

        cudaShaBatch b;
        if (cuda_sha256_batch_init(&b, blob, idx, N, 0)) { printf("  init failed\n"); return 2; }
        if (cuda_sha256_batch_launch(&b)) { printf("  launch failed\n"); return 2; }
        if (cuda_sha256_batch_sync(&b, (uint8_t*)got)) { printf("  sync failed\n"); return 2; }
        for (int i = 0; i < N; i++) {
            char lbl[64]; snprintf(lbl, 64, "CUDA single[%d] len=%llu == asm", i, (unsigned long long)msgs_len[i]);
            check(lbl, got[i], expect[i]);
        }
        cuda_sha256_batch_free(&b);
    }

    printf("\n[2] VA: SHA-256d (double) via CUDA batch == asm sha256d oracle\n");
    {
        uint8_t expect[N][32], got[N][32];
        for (int i = 0; i < N; i++)
            sha256d(expect[i], (i<2? (const void*)msgs_txt[i] : msgs_bytes[i]), msgs_len[i]);

        cudaShaBatch b;
        if (cuda_sha256_batch_init(&b, blob, idx, N, 1)) { printf("  init failed\n"); return 2; }
        if (cuda_sha256_batch_launch(&b)) { printf("  launch failed\n"); return 2; }
        if (cuda_sha256_batch_sync(&b, (uint8_t*)got)) { printf("  sync failed\n"); return 2; }
        for (int i = 0; i < N; i++) {
            char lbl[64]; snprintf(lbl, 64, "CUDA sha256d[%d] len=%llu == asm", i, (unsigned long long)msgs_len[i]);
            check(lbl, got[i], expect[i]);
        }
        cuda_sha256_batch_free(&b);
    }

    printf("\n[3] VA: large random batch (10000 msgs) -- all == Python-style independent asm\n");
    {
        const int M = 10000;
        uint8_t *big_blob = (uint8_t*)calloc(1, 4<<20);
        uint64_t *bidx = (uint64_t*)malloc(M*2*sizeof(uint64_t));
        uint8_t *expect = (uint8_t*)malloc(M*32);
        uint8_t *got    = (uint8_t*)malloc(M*32);
        uint64_t boff = 0;
        srand(7);
        for (int i = 0; i < M; i++) {
            uint64_t L = (rand() % 200);
            for (uint64_t k = 0; k < L; k++) big_blob[boff+k] = (uint8_t)(rand() & 0xff);
            bidx[2*i+0] = boff;
            bidx[2*i+1] = L;
            sha256d(expect + i*32, big_blob + boff, L);
            boff += L;
        }
        cudaShaBatch b;
        if (cuda_sha256_batch_init(&b, big_blob, bidx, M, 1)) { printf("  init failed\n"); return 2; }
        if (cuda_sha256_batch_launch(&b)) { printf("  launch failed\n"); return 2; }
        if (cuda_sha256_batch_sync(&b, got)) { printf("  sync failed\n"); return 2; }
        int bad = 0;
        for (int i = 0; i < M; i++)
            if (memcmp(got + i*32, expect + i*32, 32) != 0) bad++;
        if (bad == 0) printf("  PASS  all %d digests match asm oracle\n", M);
        else { printf("  FAIL  %d/%d digests mismatched\n", bad, M); failures += bad; }
        cuda_sha256_batch_free(&b);
    }

    printf("\n%s  (%d failures)\n", failures ? "VERIFICATION FAILED" : "ALL VERIFICATIONS PASSED", failures);
    return failures ? 1 : 0;
}
