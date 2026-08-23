/* test_taproot_thread_stress.c -- secp256k1_taproot.asm's helpers from many
 * threads at once.
 *
 * WHY THIS EXISTS
 *
 *   tagged_hash256 / tap_leaf_hash / tap_branch_hash / tap_merkle_root staged
 *   every hash they computed in two PROCESS-GLOBAL buffers: `tagh_buf` in
 *   .data and `tap_preimg` (4 MiB) in .bss. Two threads inside any of them at
 *   the same moment therefore built their preimages on top of each other and
 *   each hashed a blend of both.
 *
 *   That was survivable only because daemon/tx_verify.c refused to use the
 *   worker pool for taproot: both block-connection entry points skipped
 *   TXV_SHAPE_P2TR in the parallel pass and verified every taproot input
 *   sequentially afterwards. The file's own header said as much --
 *   "Global scratch (tagh_buf, tap_preimg) ... is single-threaded" -- which is
 *   an assumption written down rather than enforced, and PERF_SCOPE.md
 *   section 14 measured what it cost: 32 worker threads asleep and one thread
 *   running, on an 85%-idle box, with the main thread 67% field arithmetic
 *   because it was doing every taproot signature by itself.
 *
 *   The buffers are thread-local as of 2026-08-23, and both P2TR skips are
 *   gone with them -- taproot inputs now fan out across the worker pool like
 *   every other shape (PERF_SCOPE.md section 14.7, tests/
 *   test_taproot_parallel_arena, tests/test_taproot_block_diff). This test is
 *   what stops the buffers quietly becoming global again, which would now be
 *   a live corrupted-sighash bug rather than a latent one.
 *
 * WHAT IT ASSERTS
 *
 *   Each thread walks a rotation of DISTINCT inputs -- different tags,
 *   different message lengths, different script lengths spanning the
 *   compact-size boundaries (0xfd and 0x10000) that make tap_leaf_hash write
 *   different amounts into the shared buffer -- and compares every digest
 *   against the value the same call produced single-threaded, before any
 *   thread started. Identical inputs across threads would make the race
 *   invisible, which is the whole point of the rotation.
 *
 *   A single mismatched digest anywhere fails the test.
 *
 *   Precedent: tests/test_schnorr_thread_stress.c (2026-08-23) and
 *   tests/test_scriptverify_thread_stress.c (2026-08-19). The 08-19 TLS
 *   conversion covered the interpreter's scratch and missed the schnorr
 *   preimage; the 08-23 one caught that and missed these. Hence a test per
 *   file rather than a claim per file.
 *
 * Usage: ./test_taproot_thread_stress [threads] [iters]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>

extern void tagged_hash256(uint8_t* out, const char* tag, uint64_t taglen,
                           const uint8_t* msg, uint64_t msglen);
extern long tap_leaf_hash(uint8_t out[32], uint8_t leaf_version,
                          const uint8_t* script, uint64_t slen);
extern void tap_branch_hash(uint8_t* out, const uint8_t* a, const uint8_t* b);

#define NCASE 12
#define MAXT  32

/* Script lengths chosen to straddle tap_leaf_hash's compact-size branches:
 * < 0xfd (1-byte), >= 0xfd (3-byte), >= 0x10000 (5-byte). Each writes a
 * different number of bytes into the staging buffer at +64. */
static const uint64_t SLEN[NCASE] = {
    1, 32, 71, 252, 253, 254, 999, 4096, 65535, 65536, 65537, 100000
};
static const char* TAG[NCASE] = {
    "TapLeaf", "TapBranch", "TapTweak", "TapSighash",
    "BIP0340/challenge", "BIP0340/aux", "BIP0340/nonce", "TapLeaf",
    "TapBranch", "TapTweak", "TapSighash", "TapLeaf"
};

static uint8_t* SCRIPT[NCASE];
static uint8_t  EXP_LEAF[NCASE][32];
static uint8_t  EXP_TAG[NCASE][32];
static uint8_t  EXP_BRANCH[NCASE][32];
static uint8_t  BR_A[NCASE][32], BR_B[NCASE][32];

static long mismatch[MAXT], done_n[MAXT];
static int  NT = 8, ITERS = 4000;

static void fill(uint8_t* p, uint64_t n, uint64_t seed){
    for (uint64_t i = 0; i < n; i++) p[i] = (uint8_t)(i*167 + seed*31 + 13);
}

static void* worker(void* arg){
    long id = (long)arg;
    uint8_t out[32];
    for (int it = 0; it < ITERS; it++){
        /* stagger the starting case per thread so concurrent calls are
         * genuinely holding different preimages at the same instant */
        int c = (int)((id + it) % NCASE);

        if (tap_leaf_hash(out, 0xc0, SCRIPT[c], SLEN[c]) != 1) { mismatch[id]++; }
        else if (memcmp(out, EXP_LEAF[c], 32) != 0)            { mismatch[id]++; }

        tagged_hash256(out, TAG[c], strlen(TAG[c]), SCRIPT[c], SLEN[c] > 4096 ? 4096 : SLEN[c]);
        if (memcmp(out, EXP_TAG[c], 32) != 0)                  { mismatch[id]++; }

        tap_branch_hash(out, BR_A[c], BR_B[c]);
        if (memcmp(out, EXP_BRANCH[c], 32) != 0)               { mismatch[id]++; }
    }
    done_n[id] = 1;
    return NULL;
}

int main(int argc, char** argv){
    if (argc > 1) NT = atoi(argv[1]);
    if (argc > 2) ITERS = atoi(argv[2]);
    if (NT < 1 || NT > MAXT) NT = 8;

    for (int c = 0; c < NCASE; c++){
        SCRIPT[c] = malloc(SLEN[c]);
        if (!SCRIPT[c]) { printf("FAIL out of memory\n"); return 1; }
        fill(SCRIPT[c], SLEN[c], (uint64_t)c);
        fill(BR_A[c], 32, (uint64_t)c + 1000);
        fill(BR_B[c], 32, (uint64_t)c + 2000);
    }

    /* Ground truth, single-threaded, before any thread exists. */
    for (int c = 0; c < NCASE; c++){
        if (tap_leaf_hash(EXP_LEAF[c], 0xc0, SCRIPT[c], SLEN[c]) != 1){
            printf("FAIL tap_leaf_hash rejected case %d (slen=%llu) single-threaded\n",
                   c, (unsigned long long)SLEN[c]);
            return 1;
        }
        tagged_hash256(EXP_TAG[c], TAG[c], strlen(TAG[c]), SCRIPT[c],
                       SLEN[c] > 4096 ? 4096 : SLEN[c]);
        tap_branch_hash(EXP_BRANCH[c], BR_A[c], BR_B[c]);
    }

    /* A digest of all-zeroes would make every comparison pass vacuously. */
    for (int c = 0; c < NCASE; c++){
        static const uint8_t z[32] = {0};
        if (memcmp(EXP_LEAF[c], z, 32) == 0 || memcmp(EXP_TAG[c], z, 32) == 0){
            printf("FAIL case %d produced an all-zero digest -- the harness is not measuring anything\n", c);
            return 1;
        }
    }
    /* ...and two different cases must not collide, or the rotation is not
     * actually varying the data the threads hold. */
    for (int c = 1; c < NCASE; c++){
        if (memcmp(EXP_LEAF[c], EXP_LEAF[0], 32) == 0){
            printf("FAIL cases 0 and %d hash identically -- rotation is not distinct\n", c);
            return 1;
        }
    }
    printf("PASS  %d distinct cases, single-threaded ground truth established\n", NCASE);
    printf("      script lengths %llu..%llu, spanning both compact-size boundaries\n",
           (unsigned long long)SLEN[0], (unsigned long long)SLEN[NCASE-1]);

    pthread_t t[MAXT];
    for (long i = 0; i < NT; i++)
        if (pthread_create(&t[i], NULL, worker, (void*)i) != 0){
            printf("FAIL pthread_create\n"); return 1;
        }
    for (int i = 0; i < NT; i++) pthread_join(t[i], NULL);

    long bad = 0, ran = 0;
    for (int i = 0; i < NT; i++){ bad += mismatch[i]; ran += done_n[i]; }
    if (ran != NT){ printf("FAIL only %ld of %d threads finished\n", ran, NT); return 1; }

    long total = (long)NT * ITERS * 3;
    if (bad){
        printf("FAIL  %d threads x %d iterations = %ld hashes: %ld WRONG DIGESTS\n",
               NT, ITERS, total, bad);
        printf("FAIL  a corrupted taproot hash is a wrong sighash -- a valid block is rejected\n");
        printf("\nTESTS FAILED (1 failures)\n");
        return 1;
    }
    printf("PASS  %d threads x %d iterations = %ld concurrent hashes: 0 wrong digests\n",
           NT, ITERS, total);
    printf("\nALL TESTS PASSED (0 failures)\n");
    return 0;
}
