/* test_schnorr_thread_stress.c -- schnorr_verify from many threads at once.
 *
 * WHY THIS EXISTS: it caught a live consensus bug, on 2026-08-23.
 *
 *   schnorr_verify built its BIP340 challenge preimage
 *   (tagged_hash("BIP0340/challenge", r || pk || m)) in a PROCESS-GLOBAL
 *   `.data` buffer. daemon/tx_verify.c verifies a block's inputs on several
 *   worker threads (bmc_pthread_create at tx_verify.c:451 and :955), so two
 *   taproot key-path inputs verified at the same moment wrote over each
 *   other's preimage and each computed the other's challenge e. A wrong e
 *   gives a wrong R, so a PERFECTLY VALID SIGNATURE IS REJECTED -- and a
 *   rejected valid signature inside a block is a rejected valid block.
 *
 *   This harness, run against the pre-fix code, produced 1,982 false rejects
 *   in 160,000 verifications of known-good official BIP340 vectors across 8
 *   threads. After moving the preimage into schnorr_verify's own stack frame:
 *   zero, and that is what this test now pins.
 *
 *   The failure direction is false REJECT rather than false accept -- a
 *   corrupted preimage would have to hash to a challenge that happens to make
 *   the signature check out, which is a ~2^-256 accident. That makes it a
 *   liveness/consensus-split bug rather than a "money can be stolen" bug, and
 *   it is exactly the shape that would surface as an unexplained "block
 *   rejected" in a replay and be blamed on something else.
 *
 *   The precedent is tests/test_scriptverify_thread_stress.c, written for the
 *   2026-08-19 thread-local-storage conversion. That conversion covered the
 *   interpreter's scratch buffers and MISSED this one.
 *
 * WHAT IT ASSERTS
 *   Every thread verifies BOTH a known-valid signature and a known-invalid one
 *   in the same loop, on a rotation of distinct (pk, msg, sig) triples so that
 *   concurrent calls really do hold different preimages. A single wrong
 *   verdict anywhere -- in either direction -- fails the test.
 *
 * Usage: ./test_schnorr_thread_stress <bip340_test_vectors.csv> [threads] [iters]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>

extern int schnorr_verify(const uint8_t* sig, const uint8_t* pk,
                          const uint8_t* msg, int msglen);

#define MAXV 32
static uint8_t PK[MAXV][32], MSG[MAXV][32], SIG[MAXV][64];
static int  WANT[MAXV];
static int  NV = 0;

#define MAXT 32
static long bad_accept[MAXT], bad_reject[MAXT], done[MAXT];
static int  NT = 8, ITERS = 20000;

static int unhex(const char* h, uint8_t* o, int n){
    if ((int)strlen(h) != 2*n) return 0;
    for (int i = 0; i < n; i++){ unsigned v; if (sscanf(h+2*i, "%2x", &v) != 1) return 0; o[i] = (uint8_t)v; }
    return 1;
}

static void* worker(void* a){
    long id = (long)a;
    for (int i = 0; i < ITERS; i++){
        int k = (int)((id * 7 + i) % NV);
        int got = schnorr_verify(SIG[k], PK[k], MSG[k], 32) ? 1 : 0;
        if (got != WANT[k]){
            if (got) bad_accept[id]++; else bad_reject[id]++;
        }
        done[id]++;
    }
    return NULL;
}

int main(int argc, char** argv){
    if (argc < 2){ printf("usage: %s <bip340_test_vectors.csv> [threads] [iters]\n", argv[0]); return 2; }
    if (argc > 2) NT = atoi(argv[2]);
    if (argc > 3) ITERS = atoi(argv[3]);
    if (NT < 2) NT = 2;
    if (NT > MAXT) NT = MAXT;

    /* Load every 32-byte-message vector, valid and invalid alike. The invalid
     * ones matter as much as the valid ones: a race that made everything
     * accept would be worse than one that made everything reject. */
    FILE* f = fopen(argv[1], "r");
    if (!f){ perror(argv[1]); return 2; }
    char line[4096];
    if (!fgets(line, sizeof line, f)){ printf("FAIL empty csv\n"); return 1; }   /* header */
    while (NV < MAXV && fgets(line, sizeof line, f)){
        char* col[8]; int nc = 0;
        for (char* p = line; nc < 8; ){
            col[nc++] = p;
            char* c = strchr(p, ',');
            if (!c) break;
            *c = 0; p = c + 1;
        }
        if (nc < 7) continue;
        for (char* p = col[6]; *p; p++) if (*p=='\n'||*p=='\r') { *p = 0; break; }
        if (!unhex(col[2], PK[NV], 32)) continue;
        if (!unhex(col[4], MSG[NV], 32)) continue;   /* 32-byte messages only */
        if (!unhex(col[5], SIG[NV], 64)) continue;
        WANT[NV] = (col[6][0]=='T' || col[6][0]=='t') ? 1 : 0;
        NV++;
    }
    fclose(f);
    if (NV < 4){ printf("FAIL only %d usable vectors\n", NV); return 1; }

    /* Gate: single-threaded, every vector must already give the right answer.
     * Racing a verifier that is wrong on its own would prove nothing. */
    int nvalid = 0;
    for (int k = 0; k < NV; k++){
        int got = schnorr_verify(SIG[k], PK[k], MSG[k], 32) ? 1 : 0;
        if (got != WANT[k]){ printf("FAIL vector %d wrong single-threaded (want %d got %d)\n", k, WANT[k], got); return 1; }
        nvalid += WANT[k];
    }
    printf("PASS  %d BIP340 vectors (%d valid, %d invalid) correct single-threaded\n",
           NV, nvalid, NV - nvalid);

    pthread_t t[MAXT];
    for (long i = 0; i < NT; i++)
        if (pthread_create(&t[i], NULL, worker, (void*)i) != 0){ printf("FAIL pthread_create\n"); return 1; }
    for (int i = 0; i < NT; i++) pthread_join(t[i], NULL);

    long ba = 0, br = 0, n = 0;
    for (int i = 0; i < NT; i++){ ba += bad_accept[i]; br += bad_reject[i]; n += done[i]; }

    printf("%s  %d threads x %d iterations = %ld concurrent verifications: "
           "%ld false accepts, %ld false rejects\n",
           (ba||br) ? "FAIL " : "PASS ", NT, ITERS, n, ba, br);
    if (ba){
        printf("FAIL  a FALSE ACCEPT under concurrency is a consensus split\n");
        return 1;
    }
    if (br){
        printf("FAIL  a FALSE REJECT under concurrency rejects valid blocks\n");
        return 1;
    }
    printf("\n%ld checks, 0 failures\nALL TESTS PASSED (0 failures)\n", n + NV);
    return 0;
}
