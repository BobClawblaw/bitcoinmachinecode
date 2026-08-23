/* bench_schnorr.c -- BIP340 Schnorr verifications per second, single core.
 * The taproot counterpart of tests/bench_ecdsa.c, and the direct opposite
 * number to libsecp256k1's own `bench schnorrsig_verify`.
 *
 * Why it exists: PERF_SCOPE.md section 1 measured the ECDSA gap to
 * libsecp256k1 (5.5x at the time) and that single number reframed the whole
 * optimisation plan. No equivalent measurement had ever been taken for
 * Schnorr, even though every taproot key-path spend from height 709,632
 * onward pays it, and FEATURE_GAPS.md notes taproot usage goes script-path
 * heavy from ~775,000 -- i.e. this is the verify that dominates the part of
 * the chain the replay has NOT reached yet. Guessing it from the ECDSA ratio
 * would be exactly the "state it from memory" error ENGINEERING_RULES.md
 * section 1 exists to stop: the two share fe/sc arithmetic but not their
 * multiply structure (ECDSA verify is a two-scalar interleaved multiply with
 * a modular inversion; BIP340 verify is a two-scalar multiply with no
 * inversion but a tagged-hash challenge).
 *
 * The signature is NOT hardcoded here. It is read from the official BIP340
 * test vector CSV that tests/test_schnorr.c already validates against
 * (tests/bip340_test_vectors.csv, from bitcoin/bips bip-0340). Row 0 of that
 * file is a 32-byte message with verification result TRUE, which is the same
 * shape libsecp256k1's schnorrsig_verify bench uses (32-byte message).
 * Benchmarking a signature this repo cannot actually verify would measure the
 * reject path, so the fixture is verified once before the timing loop and the
 * program refuses to print a number if it does not accept.
 *
 * MEASUREMENT: thread CPU time, min over N rounds -- identical discipline to
 * tests/bench_ecdsa.c and for the same reason (this box runs a full-chain
 * replay next to every benchmark; interference can only ADD time, so the
 * minimum is the best estimate of intrinsic cost). The spread is printed.
 *
 *   argv[1] = verifications per round (default 2000)
 *   argv[2] = rounds (default 5)
 *   argv[3] = path to bip340_test_vectors.csv (default tests/bip340_test_vectors.csv)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

extern int schnorr_verify(const uint8_t* sig, const uint8_t* pk,
                          const uint8_t* msg, int msglen);

static double cpu_s(void){
    struct timespec ts;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static int hex2b(const char* h, uint8_t* out, int max){
    int n = 0;
    while (h[0] && h[1] && n < max){
        unsigned v;
        if (sscanf(h, "%2x", &v) != 1) break;
        out[n++] = (uint8_t)v;
        h += 2;
    }
    return n;
}

/* Pull the first row whose verification-result column is TRUE and whose
 * message is exactly 32 bytes -- the shape libsecp256k1 benches. */
static int load_vector(const char* path, uint8_t pk[32], uint8_t msg[32], uint8_t sig[64]){
    FILE* fp = fopen(path, "rb");
    if (!fp){ fprintf(stderr, "cannot open %s\n", path); return 0; }
    char line[1024];
    int lineno = 0;
    while (fgets(line, sizeof line, fp)){
        lineno++;
        if (lineno == 1) continue;                 /* header */
        size_t l = strlen(line);
        while (l && (line[l-1]=='\n' || line[l-1]=='\r')) line[--l] = 0;
        if (!line[0]) continue;
        /* index,secret key,public key,aux_rand,message,signature,result,comment */
        char* f[8] = {0};
        int nf = 0; char* p = line;
        while (nf < 8){
            f[nf++] = p;
            char* c = strchr(p, ',');
            if (!c) break;
            *c = 0; p = c + 1;
        }
        if (nf < 7) continue;
        if (strcmp(f[6], "TRUE") != 0) continue;
        uint8_t m[128];
        int mlen = hex2b(f[4], m, (int)sizeof m);
        if (mlen != 32) continue;
        if (hex2b(f[2], pk, 32) != 32) continue;
        if (hex2b(f[5], sig, 64) != 64) continue;
        memcpy(msg, m, 32);
        fclose(fp);
        return lineno - 1;                          /* 1-based row number */
    }
    fclose(fp);
    fprintf(stderr, "no usable TRUE/32-byte-message row in %s\n", path);
    return 0;
}

static int cmpd(const void* a, const void* b){
    double x = *(const double*)a, y = *(const double*)b;
    return (x > y) - (x < y);
}

int main(int argc, char** argv){
    long n      = (argc > 1) ? atol(argv[1]) : 2000;
    int  rounds = (argc > 2) ? atoi(argv[2]) : 5;
    const char* csv = (argc > 3) ? argv[3] : "tests/bip340_test_vectors.csv";
    if (rounds < 1) rounds = 1;

    uint8_t pk[32], msg[32], sig[64];
    int row = load_vector(csv, pk, msg, sig);
    if (!row) return 1;

    if (schnorr_verify(sig, pk, msg, 32) != 1){
        printf("FAIL: BIP340 fixture (csv row %d) does not verify -- refusing to time the reject path\n", row);
        return 1;
    }

    double* t = malloc((size_t)rounds * sizeof(double));
    if (!t) return 1;
    for (int r = 0; r < rounds; r++){
        double a = cpu_s();
        long acc = 0;
        for (long i = 0; i < n; i++) acc += schnorr_verify(sig, pk, msg, 32);
        t[r] = cpu_s() - a;
        if (acc != n){ printf("FAIL: %ld of %ld verifications did not accept\n", n - acc, n); return 1; }
    }
    qsort(t, (size_t)rounds, sizeof(double), cmpd);

    double best = t[0], worst = t[rounds-1];
    printf("%ld BIP340 verifications (csv row %d), min-of-%d CPU-time rounds: %.3fs "
           "-> %.0f/s per core (%.2f us each; worst round %.2f us)\n",
           n, row, rounds, best, n / best, best / n * 1e6, worst / n * 1e6);
    free(t);
    return 0;
}
