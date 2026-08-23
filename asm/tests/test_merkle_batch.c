/* test_merkle_batch.c -- the batched merkle inner-node hash, against the
 * one-node-at-a-time algorithm it replaced.
 *
 * WHY THIS EXISTS
 *   On 2026-08-23 merkle_root stopped calling sha256d(concat, 64) once per
 *   inner node and started calling sha256d64 over a batch of staged nodes
 *   (PERF_SCOPE.md section 13.2). A wrong merkle root REJECTS VALID BLOCKS,
 *   so the new code has to be shown identical to the old on every shape, not
 *   just on the shapes a couple of fixtures happen to have.
 *
 *   The shapes that can go wrong are all about boundaries:
 *     - a level with an ODD node count (Bitcoin duplicates the last node);
 *     - a level shorter than one batch, exactly one batch, or one node more
 *       than a batch (the staging buffer's flush path);
 *     - the in-place overwrite, which is only safe because every batch copies
 *       all of its inputs out before any output is written back.
 *   Sweeping every leaf count from 1 to 2050 hits all of them, at every level
 *   of every tree, including MK_STAGE (16 pairs = 32 nodes) and its
 *   neighbours at every level.
 *
 *   The reference here is a plain C transcription of the PREVIOUS assembly
 *   loop, driven through the same sha256d this repo has always shipped. It is
 *   deliberately not a second copy of the new logic.
 *
 *   Real-chain evidence is separate and stronger: cons_verify recomputes the
 *   merkle root of every block it checks and compares it to the header, and
 *   the tests in `make test` that drive real mainnet blocks through it
 *   (test_cons, test_block_genesis, test_ibd_blocks, test_ibd_full) all pass.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

extern void merkle_root(unsigned char out[32], unsigned char* hashes, unsigned long n);
extern void sha256d(unsigned char out[32], const void* msg, long len);
extern void sha256d64(unsigned char* out, const unsigned char* in, unsigned long pairs);

#define MAXN 2050

static unsigned char leaves[MAXN * 32];
static unsigned char work[MAXN * 32];

static uint64_t st = 0x243F6A8885A308D3ULL;
static uint64_t rnd(void){
    st ^= st >> 12; st ^= st << 25; st ^= st >> 27;
    return st * 0x2545F4914F6CDD1DULL;
}

/* The pre-2026-08-23 algorithm, transcribed. */
static void merkle_ref(unsigned char out[32], unsigned char* h, long n){
    unsigned char cat[64];
    while (n > 1){
        long w = 0;
        for (long i = 0; i < n; i += 2){
            memcpy(cat, h + i*32, 32);
            memcpy(cat + 32, h + ((i + 1 < n) ? (i + 1) : i) * 32, 32);
            sha256d(h + w*32, cat, 64);
            w++;
        }
        n = w;
    }
    memcpy(out, h, 32);
}

int main(void){
    int failures = 0;
    long checks = 0;

    /* ---- 1. sha256d64 == sha256d, over every batch size and both tails ---- */
    {
        static unsigned char in[128*64], got[128*32], want[128*32];
        long diffs = 0;
        for (int rep = 0; rep < 200; rep++){
            for (size_t i = 0; i < sizeof in; i++) in[i] = (unsigned char)rnd();
            for (unsigned long n = 0; n <= 128; n++){
                memset(got, 0xA5, sizeof got);
                sha256d64(got, in, n);
                for (unsigned long i = 0; i < n; i++) sha256d(want + i*32, in + i*64, 64);
                if (n && memcmp(got, want, n*32)){
                    if (!diffs) printf("FAIL sha256d64 != sha256d at rep %d n %lu\n", rep, n);
                    diffs++;
                }
                /* and it must not write past its last pair */
                for (unsigned long i = n*32; i < (n+4)*32 && i < sizeof got; i++)
                    if (got[i] != 0xA5){
                        if (!diffs) printf("FAIL sha256d64 wrote past pair %lu (byte %lu)\n", n, i);
                        diffs++; break;
                    }
                checks++;
            }
        }
        if (diffs){ printf("FAIL  %ld sha256d64 differences\n", diffs); failures++; }
        else printf("PASS  sha256d64 == sha256d for every count 0..128, 200 random fills "
                    "(%ld cases, incl. the odd-count tail and the no-overrun check)\n", checks);
    }

    /* ---- 2. merkle_root == the one-node-at-a-time reference ---- */
    {
        long diffs = 0, n_checked = 0;
        unsigned char r1[32], r2[32];
        for (long n = 1; n <= MAXN; n++){
            for (long i = 0; i < n*32; i++) leaves[i] = (unsigned char)rnd();
            memcpy(work, leaves, n*32);
            merkle_root(r1, leaves, n);      /* consumes `leaves` in place */
            memcpy(leaves, work, n*32);
            merkle_ref(r2, work, n);         /* consumes `work` in place */
            if (memcmp(r1, r2, 32)){
                if (!diffs) printf("FAIL merkle_root != reference at n=%ld\n", n);
                diffs++;
            }
            n_checked++; checks++;
        }
        if (diffs){ printf("FAIL  %ld merkle differences\n", diffs); failures++; }
        else printf("PASS  merkle_root == pre-batch reference for every leaf count 1..%ld\n", n_checked);
    }

    /* ---- 3. the single-leaf identity: a 1-leaf tree is the leaf itself ---- */
    {
        unsigned char r[32];
        for (int i = 0; i < 32; i++) leaves[i] = (unsigned char)(i*7+3);
        unsigned char save[32]; memcpy(save, leaves, 32);
        merkle_root(r, leaves, 1);
        if (memcmp(r, save, 32)){ printf("FAIL  merkle_root(n=1) is not the leaf\n"); failures++; }
        else printf("PASS  merkle_root(n=1) == the leaf\n");
        checks++;
    }

    printf("\n%ld checks, %d failures\n", checks, failures);
    if (failures){ printf("FAILURES: %d\n", failures); return 1; }
    printf("ALL TESTS PASSED (0 failures)\n");
    return 0;
}
