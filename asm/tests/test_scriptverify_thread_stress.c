/* tests/test_scriptverify_thread_stress.c -- concurrency stress test for the
 * 2026-08-19 thread-local-storage conversion of sv_verify_script's scratch
 * state (bitcoin_scriptverify.c's 8 __thread buffers, bitcoin_interp.asm's
 * 6 TLS labels, bitcoin_sighash.asm's legacy_sighash_scfbuf).
 *
 * The existing test suite (test_scriptverify_parity.c, test_hashtype_e2e.c,
 * etc.) only proves the TLS rewiring preserved single-threaded correctness
 * -- it never actually calls sv_verify_script from more than one thread at
 * once, so it cannot catch a missed shared buffer. This test is the one
 * that actually matters for the redesign: many threads call
 * sv_verify_script CONCURRENTLY and repeatedly, half with a genuinely
 * valid 2-of-3 P2SH spend (real signatures, from p2sh_vectors.h,
 * previously differentially validated against Bitcoin Core -- see that
 * header), half with a deliberately wrong-signature variant of the SAME
 * transaction shape. If any of the converted buffers were still
 * accidentally shared across threads, a fast-enough interleaving would
 * corrupt one thread's in-flight verification with another's script/stack
 * bytes -- most dangerously, a "wrong" thread spuriously computing a
 * PASSING result by reading a "valid" thread's stack contents. Every
 * thread's own verdict must be internally consistent across ALL of its
 * own iterations for the test to pass: a single wrong verdict anywhere is
 * a real bug (in this project's normal severity terms: possible consensus
 * divergence, since sv_verify_script IS the real consensus verifier).
 *
 * This exercises ALL of the buffers in one call: OP_CHECKMULTISIG
 * (cms_keyrefs/cms_sigrefs, interp_slice, interp_err), CHECKSIG's own
 * sighash+FindAndDelete path (needle/scF/legacy_sighash_scfbuf), the P2SH
 * redeem-script re-execution (copy_e/redeem), and general interpretation
 * (main_e/alt/scratch/scopy/interp_tmp/bool_buf).
 */
#include <stdio.h>
#include <stdint.h>
#include <pthread.h>

extern int sv_verify_script(const unsigned char* ss, unsigned long ssl,
                            const unsigned char* spk, unsigned long spl,
                            uint64_t flags, unsigned long nIn,
                            const unsigned char* tx, unsigned long txlen,
                            unsigned char* work, unsigned long workcap);

#define FLAGS_MODERN 0x20e15ULL
#define LEN(a) (unsigned long)sizeof(a)

#include "p2sh_vectors.h"

#define N_THREADS 48
#define ITERS_PER_THREAD 1000

typedef struct {
    int thread_id;
    int want_valid;      /* 1 = must always get SCRIPT_ERR_OK, 0 = must always fail */
    long mismatches;
} worker_arg_t;

static void* worker(void* argp){
    worker_arg_t* a = (worker_arg_t*)argp;
    static __thread unsigned char work[1<<20];
    for (int i=0;i<ITERS_PER_THREAD;i++){
        int r;
        if (a->want_valid){
            r = sv_verify_script(SS_23, LEN(SS_23), SPK_23, LEN(SPK_23),
                                 FLAGS_MODERN, 0, TX_23, LEN(TX_23), work, sizeof work);
            if (r != 0) { a->mismatches++; printf("  thread %d iter %d: got err=%d\n", a->thread_id, i, r); }
        } else {
            r = sv_verify_script(SS_WRONG, LEN(SS_WRONG), SPK_23, LEN(SPK_23),
                                 FLAGS_MODERN, 0, TX_WRONG, LEN(TX_WRONG), work, sizeof work);
            if (r == 0) a->mismatches++;   /* must NOT report success */
        }
    }
    return 0;
}

int main(void){
    pthread_t th[N_THREADS];
    worker_arg_t args[N_THREADS];
    for (int i=0;i<N_THREADS;i++){
        args[i].thread_id = i;
        args[i].want_valid = (i % 2 == 0);
        args[i].mismatches = 0;
        if (pthread_create(&th[i], 0, worker, &args[i]) != 0){
            printf("FAIL pthread_create thread %d\n", i);
            return 1;
        }
    }
    long total_mismatches = 0;
    for (int i=0;i<N_THREADS;i++){
        pthread_join(th[i], 0);
        total_mismatches += args[i].mismatches;
        if (args[i].mismatches){
            printf("FAIL thread %d (%s): %ld/%d wrong verdict(s)\n",
                   i, args[i].want_valid ? "valid" : "wrong-sig",
                   args[i].mismatches, ITERS_PER_THREAD);
        }
    }
    printf("scriptverify_thread_stress: %d threads x %d iters, %ld total mismatch(es)\n",
           N_THREADS, ITERS_PER_THREAD, total_mismatches);
    printf(total_mismatches==0 ? "ALL TESTS PASSED (0 failures)\n" : "TESTS FAILED\n");
    return total_mismatches ? 1 : 0;
}
