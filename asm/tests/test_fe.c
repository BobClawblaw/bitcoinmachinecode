/*
 * test_fe.c -- 100% AI-generated test harness for secp256k1 field assembly.
 *
 * Validates fe_add / fe_sub / fe_mul against expected values produced by
 * Python's arbitrary-precision integers (embedded as hex constants in
 * vectors.h), and fe_sqr / fe_inv via algebraic identities (sqr==mul(a,a),
 * a*inv(a)==1). A failure means the machine code mis-implements the field
 * arithmetic.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "vectors.h"

extern void fe_add(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
extern void fe_sub(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
extern void fe_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
extern void fe_sqr(uint64_t r[4], const uint64_t a[4]);
extern void fe_inv(uint64_t r[4], const uint64_t a[4]);

static int failures = 0;

static void check(const char *label, int idx, const uint64_t got[4], const uint64_t exp[4])
{
    if (memcmp(got, exp, 32) == 0) {
        printf("PASS  %s%d\n", label, idx);
    } else {
        printf("FAIL  %s%d\n", label, idx);
        printf("  got: %016llx %016llx %016llx %016llx\n",
               (unsigned long long)got[0], (unsigned long long)got[1],
               (unsigned long long)got[2], (unsigned long long)got[3]);
        printf("  exp: %016llx %016llx %016llx %016llx\n",
               (unsigned long long)exp[0], (unsigned long long)exp[1],
               (unsigned long long)exp[2], (unsigned long long)exp[3]);
        failures++;
    }
}

#define VERIFY(OP, NAME, A, B, EXP)                        \
    do {                                                   \
        uint64_t r[4];                                     \
        fe_##OP(r, A, B);                                  \
        check(NAME, i, r, EXP);                            \
    } while (0)

int main(void)
{
    const uint64_t *A[8] = {A0, A1, A2, A3, A4, A5, A6, A7};
    const uint64_t *B[8] = {B0, B1, B2, B3, B4, B5, B6, B7};
    const uint64_t *S[8] = {S0, S1, S2, S3, S4, S5, S6, S7};
    const uint64_t *D[8] = {D0, D1, D2, D3, D4, D5, D6, D7};
    const uint64_t *M[8] = {M0, M1, M2, M3, M4, M5, M6, M7};
    for (int i = 0; i < 8; i++) {
        VERIFY(add, "fe_add v", A[i], B[i], S[i]);
        VERIFY(sub, "fe_sub v", A[i], B[i], D[i]);
        VERIFY(mul, "fe_mul v", A[i], B[i], M[i]);

        /* fe_sqr must equal fe_mul(a,a) -- cross-check against verified mul */
        uint64_t q1[4], q2[4];
        fe_sqr(q1, A[i]);
        fe_mul(q2, A[i], A[i]);
        if (memcmp(q1, q2, 32) != 0) {
            printf("FAIL  fe_sqr v%d (sqr != mul(a,a))\n", i);
            failures++;
        } else {
            printf("PASS  fe_sqr v%d\n", i);
        }

        /* fe_inv must satisfy a * inv(a) == 1 (skip only the zero element) */
        if (!(A[i][0] == 0 && A[i][1] == 0 && A[i][2] == 0 && A[i][3] == 0)) {
            uint64_t inv[4], one[4] = {1, 0, 0, 0}, prod[4];
            fe_inv(inv, A[i]);
            fe_mul(prod, inv, A[i]);
            if (memcmp(prod, one, 32) != 0) {
                printf("FAIL  fe_inv v%d (a*inv(a) != 1)\n", i);
                failures++;
            } else {
                printf("PASS  fe_inv v%d\n", i);
            }
        }
    }

    printf("\n%s (%d failures)\n", failures ? "TESTS FAILED" : "ALL TESTS PASSED", failures);
    return failures ? 1 : 0;
}
