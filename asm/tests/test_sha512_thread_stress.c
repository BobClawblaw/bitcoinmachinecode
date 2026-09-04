/* test_sha512_thread_stress.c -- SHA-512 and HMAC-SHA512 from many threads.
 *
 * WHY THIS EXISTS
 *   CRY-4 (audit 2026-09-03): sha512_block built its 80-word message schedule
 *   in `Wbuf: resb 80*8` in .bss -- ONE buffer shared by every caller in the
 *   process -- and hmac_sha512 did the same with `kpad` (the padded HMAC key)
 *   and `tmp` (the concatenation scratch). Two threads hashing concurrently
 *   overwrote each other mid-round and both returned wrong results, silently.
 *
 *   That is not hypothetical here. It is the same class of defect as the
 *   schnorr false-reject incident, whose global buffer produced 1,982 false
 *   rejects in 160k verifications across 8 threads -- found the same day the
 *   TLS conversion was declared complete. It was latent for SHA-512 only
 *   because every caller (BIP32 and BIP39 derivation, wallet_crypter,
 *   wallet_store, the RPC key paths) happens to run under rpc_server.c's
 *   g_exec_lock. Nothing enforced that, and a caller from a tx_verify worker
 *   or the ZMQ/i2p threads would have derived wrong child keys --
 *   getnewaddress handing out an address nobody can spend.
 *
 *   Both are now in their callers' stack frames. "No shared state by
 *   inspection" has been wrong twice in this repo, so this makes it measured.
 *
 * WHAT IT ASSERTS
 *   Truth digests are computed single-threaded first, over message lengths
 *   that straddle every SHA-512 padding boundary -- 111/112 is where the
 *   16-byte length field forces a second block, 127/128/129 the block edge.
 *   Then N threads recompute all of them ITERS times each and every result is
 *   compared against truth. One mismatch anywhere fails.
 *
 *   HMAC is exercised with a DIFFERENT key per thread: a shared kpad corrupts
 *   across threads only when the keys differ, so identical keys would hide
 *   exactly the bug under test.
 *
 * Usage: ./test_sha512_thread_stress [threads] [iters]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>

extern void sha512_full(uint8_t out[64], const void* in, long len);
extern void hmac_sha512(uint8_t out[64], const uint8_t* key, long keylen,
                        const uint8_t* msg, long msglen);

/* lengths across both block edges and the length-field boundary */
static const long LENS[] = {0,1,32,64,111,112,127,128,129,200,255,256,1000};
#define NLEN ((int)(sizeof LENS / sizeof LENS[0]))
static uint8_t MSG[NLEN][1000];
static uint8_t TRUTH[NLEN][64];

#define NKEY 8
static uint8_t KEY[NKEY][80];
static uint8_t HTRUTH[NKEY][NLEN][64];

static int nthreads = 8, iters = 400;
static volatile long mismatches_sha, mismatches_hmac;

static void* worker(void* arg){
    long id = (long)arg;
    uint8_t out[64];
    for (int it = 0; it < iters; it++){
        for (int i = 0; i < NLEN; i++){
            sha512_full(out, MSG[i], LENS[i]);
            if (memcmp(out, TRUTH[i], 64) != 0) __sync_fetch_and_add(&mismatches_sha, 1);
        }
        /* each thread uses its OWN key: a shared key block only corrupts
         * across threads when the keys differ */
        int k = (int)(id % NKEY);
        for (int i = 0; i < NLEN; i++){
            hmac_sha512(out, KEY[k], (long)sizeof KEY[k], MSG[i], LENS[i]);
            if (memcmp(out, HTRUTH[k][i], 64) != 0) __sync_fetch_and_add(&mismatches_hmac, 1);
        }
    }
    return 0;
}

int main(int argc, char** argv){
    if (argc > 1) nthreads = atoi(argv[1]);
    if (argc > 2) iters = atoi(argv[2]);
    if (nthreads < 2) nthreads = 2;
    if (nthreads > 64) nthreads = 64;

    for (int i = 0; i < NLEN; i++)
        for (long j = 0; j < 1000; j++) MSG[i][j] = (uint8_t)(i*31 + j*17 + 5);
    for (int k = 0; k < NKEY; k++)
        for (size_t j = 0; j < sizeof KEY[k]; j++) KEY[k][j] = (uint8_t)(0xC0 + k*7 + j);

    /* truth, single-threaded */
    for (int i = 0; i < NLEN; i++) sha512_full(TRUTH[i], MSG[i], LENS[i]);
    for (int k = 0; k < NKEY; k++)
        for (int i = 0; i < NLEN; i++)
            hmac_sha512(HTRUTH[k][i], KEY[k], (long)sizeof KEY[k], MSG[i], LENS[i]);

    printf("sha512/hmac thread stress: %d threads x %d iters x %d lengths\n",
           nthreads, iters, NLEN);

    pthread_t th[64];
    for (long t = 0; t < nthreads; t++)
        if (pthread_create(&th[t], 0, worker, (void*)t) != 0){ printf("FAIL: pthread_create\n"); return 1; }
    for (int t = 0; t < nthreads; t++) pthread_join(th[t], 0);

    long total = (long)nthreads * iters * NLEN;
    printf("  %ld sha512 digests, %ld mismatches\n", total, mismatches_sha);
    printf("  %ld hmac digests,   %ld mismatches\n", total, mismatches_hmac);
    int fails = 0;
    if (mismatches_sha){ printf("FAIL: sha512_block has shared mutable state\n"); fails++; }
    else printf("ok  : sha512 agrees with the single-threaded truth on every call\n");
    if (mismatches_hmac){ printf("FAIL: hmac_sha512 has shared mutable state\n"); fails++; }
    else printf("ok  : hmac_sha512 agrees with the single-threaded truth on every call\n");

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
