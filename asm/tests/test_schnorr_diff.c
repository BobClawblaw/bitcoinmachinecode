/* test_schnorr_diff.c -- BIP340 verify, differentially against BITCOIN CORE.
 *
 * WHY THIS EXISTS, and why test_schnorr.c is not enough
 *   tests/test_schnorr.c runs the 19 official BIP340 vectors. Those are the
 *   standard's own tests and they must pass, but 19 cases cannot cover a
 *   restructured verifier: 2026-08-23 moved s*G onto the fixed-base G comb,
 *   e*P onto the GLV + wNAF ladder, and turned the x(R) == r test projective
 *   (r*Z^2 == X mod p, no inversion) -- see PERF_SCOPE.md section 13.
 *
 *   The failure mode that matters for consensus is a FALSE ACCEPT, and the two
 *   branches most likely to be lost by a fast path are exactly the two the
 *   official vectors touch once each:
 *     - x(R) == r but y(R) is ODD           (must reject)
 *     - s*G - e*P is the point at infinity  (must reject)
 *   This corpus carries hundreds of each, plus every range edge, plus
 *   single-bit perturbations of valid signatures spread across r, s, the
 *   message and the public key.
 *
 *   Every expected verdict in schnorr_diff_vec.h is CORE's, produced by
 *   libsecp256k1's secp256k1_schnorrsig_verify through the SCHNORR command in
 *   validation/core_verify_oracle.cpp. None of it is this project's own
 *   previous answer, which is the whole point (ENGINEERING_RULES.md section 1).
 *
 *   The GLV ladder is additionally run BOTH WAYS: BMC_ECDSA_GLV also gates
 *   schnorr's e*P now, so the harness re-runs the entire corpus with the kill
 *   switch off, through bmc_ecdsa_glv_set_enabled (secp256k1_glv_c.c, which
 *   exists for exactly this). A GLV-path bug and a plain-ladder bug then both
 *   show up, and so would a DISAGREEMENT between the two paths.
 *
 * Regenerate the corpus with the command in schnorr_diff_vec.h's header.
 *
 * BULK MODE:  tests/test_schnorr_diff <corpus-file>
 *   reads "<class> <pk_hex> <msg_hex> <sig_hex> <core_verdict>" lines instead
 *   of the committed header, so the same comparison can be run out of tree
 *   over millions of cases without committing them. The committed header is
 *   the regression gate; the bulk run is the evidence.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "schnorr_diff_vec.h"

extern int schnorr_verify(const uint8_t* sig, const uint8_t* pk,
                          const uint8_t* msg, int msglen);
extern void bmc_ecdsa_glv_set_enabled(int on);
extern int  schnorr_x_eq_r(const uint64_t r[4], const uint64_t X[4], const uint64_t Z[4]);
extern void fe_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
extern void fe_sqr(uint64_t r[4], const uint64_t a[4]);

static const uint64_t PLIMB[4] = {0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL,
                                  0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL};

/* Direct unit test of the projective x(R) == r compare.
 *
 * WHY IT CANNOT BE DONE THROUGH SIGNATURES: to notice that the compare skips,
 * say, the top limb, you need an (r, X, Z) where r*Z^2 agrees with X in three
 * limbs and differs in the fourth. A signature cannot be steered into that --
 * r is committed to by the challenge hash, so changing r changes R entirely,
 * and a partial agreement is a ~2^-192 accident. schnorr_x_eq_r is exported
 * precisely so the operands can be constructed instead of searched for.
 * (Confirmed by scripts/mutate_check.py: the "drop one limb" mutation SURVIVES
 * the 250,500-case Core corpus and is caught only here.)
 */
static int check_x_eq_r(void){
    uint64_t st = 0x9E3779B97F4A7C15ULL;
    #define NXT (st = st*6364136223846793005ULL + 1442695040888963407ULL, st ^ (st>>29))
    int bad = 0;
    long cases = 0;
    for (int t = 0; t < 20000; t++){
        uint64_t Z[4], r[4], z2[4], X[4], Xp[4];
        do { for (int i=0;i<4;i++) Z[i]=NXT; Z[3] >>= 2; } while (!(Z[0]|Z[1]|Z[2]|Z[3]));
        for (int i=0;i<4;i++) r[i]=NXT;
        r[3] >>= 2;                                   /* keep r < p */
        fe_sqr(z2, Z);
        fe_mul(X, r, z2);                             /* X = r*Z^2 -> must match */
        if (schnorr_x_eq_r(r, X, Z) != 1){ if(!bad) printf("FAIL x_eq_r said no on a matching triple\n"); bad++; }
        cases++;
        /* perturb X in EXACTLY ONE limb -- each limb in turn */
        for (int L = 0; L < 4; L++){
            memcpy(Xp, X, 32);
            Xp[L] ^= 1ULL << (t % 64);
            /* stay canonical: if the flip pushed it >= p, skip (rare) */
            int ge = 0;
            for (int i = 3; i >= 0; i--){ if (Xp[i] != PLIMB[i]) { ge = Xp[i] > PLIMB[i]; break; } if(!i) ge = 1; }
            if (ge) continue;
            if (schnorr_x_eq_r(r, Xp, Z) != 0){
                if (!bad) printf("FAIL x_eq_r accepted an X differing only in limb %d\n", L);
                bad++;
            }
            cases++;
        }
        /* and perturb r in exactly one limb */
        for (int L = 0; L < 4; L++){
            uint64_t rp[4];
            memcpy(rp, r, 32);
            rp[L] ^= 1ULL << ((t+7) % 64);
            if (rp[3] >> 62) continue;                /* keep it well under p */
            if (schnorr_x_eq_r(rp, X, Z) != 0){
                if (!bad) printf("FAIL x_eq_r accepted an r differing only in limb %d\n", L);
                bad++;
            }
            cases++;
        }
    }
    /* The documented Z == 0 hazard: the compare ALONE does not reject a point
     * at infinity whose X happens to be 0, which is why schnorr_verify's
     * explicit infinity test must stay even though point_add's canonical
     * infinity (1,1,0) makes it unreachable today. */
    {
        uint64_t zero[4] = {0,0,0,0};
        if (schnorr_x_eq_r(zero, zero, zero) != 1){
            printf("FAIL x_eq_r(0,0,Z=0) changed -- re-read schnorr_verify's infinity check\n");
            bad++;
        }
        cases++;
    }
    if (bad) printf("FAIL  %d schnorr_x_eq_r failures\n", bad);
    else printf("PASS  %ld schnorr_x_eq_r cases (matching triples + every single-limb "
                "perturbation of X and of r + the Z==0 hazard)\n", cases);
    #undef NXT
    return bad ? 1 : 0;
}

static int unhex(const char* h, uint8_t* out, int nbytes){
    for (int i = 0; i < nbytes; i++){
        unsigned v;
        if (sscanf(h + 2*i, "%2x", &v) != 1) return 0;
        out[i] = (uint8_t)v;
    }
    return (int)strlen(h) == 2*nbytes;
}

struct tally { const char* cls; long n, fa, fr; };

/* Either the committed header, or a corpus file in bulk mode. */
static const schnorr_diff_t* CASES = SCHNORR_DIFF;
static int NCASES = 0;

static void load_file(const char* path){
    FILE* f = fopen(path, "r");
    if (!f){ perror(path); exit(2); }
    size_t cap = 4096, n = 0;
    schnorr_diff_t* v = malloc(cap * sizeof *v);
    char cls[64], pk[80], msg[80], sig[160];
    int want;
    while (fscanf(f, "%63s %79s %79s %159s %d", cls, pk, msg, sig, &want) == 5){
        if (n == cap){ cap *= 2; v = realloc(v, cap * sizeof *v); }
        v[n].cls = strdup(cls); v[n].pk = strdup(pk);
        v[n].msg = strdup(msg); v[n].sig = strdup(sig); v[n].want = want;
        n++;
    }
    fclose(f);
    CASES = v; NCASES = (int)n;
    printf("bulk mode: %d cases from %s\n", NCASES, path);
}

int main(int argc, char** argv){
    int failures = 0;
    long checks = 0;
    NCASES = SCHNORR_DIFF_N;
    if (argc > 1) load_file(argv[1]);

    for (int pass = 0; pass < 2; pass++){
        /* pass 0: GLV on (the shipping configuration). pass 1: kill switch. */
        bmc_ecdsa_glv_set_enabled(pass == 0);

        struct tally t[64];
        int nt = 0;
        long false_accept = 0, false_reject = 0, badhex = 0;

        for (int i = 0; i < NCASES; i++){
            const schnorr_diff_t* v = &CASES[i];
            uint8_t pk[32], msg[32], sig[64];
            if (!unhex(v->pk, pk, 32) || !unhex(v->msg, msg, 32) || !unhex(v->sig, sig, 64)){
                badhex++; continue;
            }
            int got = schnorr_verify(sig, pk, msg, 32) ? 1 : 0;

            int k = -1;
            for (int j = 0; j < nt; j++) if (t[j].cls == v->cls || !strcmp(t[j].cls, v->cls)) { k = j; break; }
            if (k < 0){ k = nt++; t[k].cls = v->cls; t[k].n = t[k].fa = t[k].fr = 0; }
            t[k].n++;
            checks++;

            if (got != v->want){
                if (got == 1){ false_accept++; t[k].fa++; } else { false_reject++; t[k].fr++; }
                if (false_accept + false_reject <= 5){
                    printf("FAIL  [%s] case %d: core says %d, we say %d\n"
                           "        pk  %s\n        msg %s\n        sig %s\n",
                           v->cls, i, v->want, got, v->pk, v->msg, v->sig);
                }
            }
        }

        if (badhex){ printf("FAIL  %ld malformed hex entries in the corpus\n", badhex); failures++; }

        printf("-- BIP340 vs Core, %s --\n",
               pass == 0 ? "GLV on (shipping)" : "BMC_ECDSA_GLV=0 (plain ladder)");
        for (int j = 0; j < nt; j++)
            printf("   %-9s %6ld cases   false-accept %ld   false-reject %ld\n",
                   t[j].cls, t[j].n, t[j].fa, t[j].fr);

        if (false_accept){
            printf("FAIL  %ld FALSE ACCEPTS -- this is a consensus split\n", false_accept);
            failures++;
        }
        if (false_reject){
            printf("FAIL  %ld false rejects\n", false_reject);
            failures++;
        }
        if (!false_accept && !false_reject)
            printf("PASS  %d cases agree with Core exactly\n", NCASES);
    }

    failures += check_x_eq_r();

    printf("\n%ld checks, %d failures\n", checks, failures);
    if (failures){ printf("FAILURES: %d\n", failures); return 1; }
    printf("ALL TESTS PASSED (0 failures)\n");
    return 0;
}
