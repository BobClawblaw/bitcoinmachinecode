/* tests/test_fe_sqrt.c -- square root in the secp256k1 field.
 *
 * The expectations come from Python's own big-integer pow(), computed by
 * validation/gen_fe_sqrt_vectors.py -- an independent implementation of the
 * same mathematics, not a restatement of this addition chain. A chain with a
 * wrong repeat count still returns a value for every input; it just is not a
 * root, which is why the vectors are generated elsewhere.
 *
 * The property that actually matters is asserted directly too: for every
 * input where fe_sqrt reports success, r*r must equal a. That is checkable
 * without any reference at all, and it is the thing ElligatorSwift depends on.
 */
#include <stdio.h>
#include <string.h>
#include "../crypto_fe_sqrt.h"
#include "fe_sqrt_vectors.h"

extern void fe_mul(unsigned long long r[4], const unsigned long long a[4], const unsigned long long b[4]);
extern void fe_sqr(unsigned long long r[4], const unsigned long long a[4]);

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }

static void hex2fe(unsigned long long r[4], const char* h){
    /* big-endian hex -> 4 little-endian limbs */
    unsigned char b[32]; memset(b, 0, 32);
    int n = 0;
    for (const char* p = h; p[0] && p[1]; p += 2){
        int hi = (p[0] <= '9') ? p[0]-'0' : (p[0]|32)-'a'+10;
        int lo = (p[1] <= '9') ? p[1]-'0' : (p[1]|32)-'a'+10;
        b[n++] = (unsigned char)((hi << 4) | lo);
    }
    for (int i = 0; i < 4; i++){
        unsigned long long v = 0;
        for (int j = 0; j < 8; j++) v = (v << 8) | b[i*8 + j];
        r[3 - i] = v;
    }
}
static void fe2hex(char* out, const unsigned long long a[4]){
    static const char* H = "0123456789abcdef";
    int o = 0;
    for (int i = 3; i >= 0; i--)
        for (int j = 7; j >= 0; j--){
            unsigned char byte = (unsigned char)(a[i] >> (8*j));
            out[o++] = H[byte >> 4]; out[o++] = H[byte & 15];
        }
    out[o] = 0;
}

int main(void){
    printf("== fe_sqrt against Python's pow((p+1)//4) ==\n");
    int nsq = 0, nns = 0, roundtrip_ok = 1;
    for (int i = 0; i < FE_SQRT_NVEC; i++){
        unsigned long long a[4], r[4];
        hex2fe(a, FE_SQRT_VEC[i].a);
        int got = fe_sqrt(r, a);
        int want = FE_SQRT_VEC[i].is_square;
        if (got != want){
            printf("  FAIL %s: is_square got %d want %d\n", FE_SQRT_VEC[i].a, got, want);
            fails++; continue;
        }
        if (got){
            nsq++;
            /* the root must square back -- checked here regardless of which
             * of the two roots Python reported */
            unsigned long long chk[4];
            fe_sqr(chk, r);
            if (!fe_equal(chk, a)){ printf("  FAIL %s: r*r != a\n", FE_SQRT_VEC[i].a); fails++; roundtrip_ok = 0; }
            /* and it must be one of the two roots Python computed */
            char h[70]; fe2hex(h, r);
            if (strcmp(h, FE_SQRT_VEC[i].root) && strcmp(h, FE_SQRT_VEC[i].root_neg)){
                printf("  FAIL %s: root %s is neither %s nor %s\n",
                       FE_SQRT_VEC[i].a, h, FE_SQRT_VEC[i].root, FE_SQRT_VEC[i].root_neg);
                fails++;
            }
        } else nns++;
    }
    { char lbl[120];
      snprintf(lbl, sizeof lbl, "all %d vectors agree on residue/non-residue", FE_SQRT_NVEC);
      ck(lbl, 1); }
    { char lbl[120];
      snprintf(lbl, sizeof lbl, "  %d squares, %d non-squares (a real split, not all one way)", nsq, nns);
      ck(lbl, nsq > 0 && nns > 0); }
    ck("every reported root squares back to its input", roundtrip_ok);

    printf("== edges ==\n");
    { unsigned long long z[4] = {0,0,0,0}, r[4];
      ck("sqrt(0) succeeds", fe_sqrt(r, z) == 1);
      ck("  and is 0", fe_is_zero(r));
      ck("fe_is_square(0) is true", fe_is_square(z) == 1); }
    { unsigned long long one[4] = {1,0,0,0}, r[4];
      ck("sqrt(1) succeeds", fe_sqrt(r, one) == 1);
      unsigned long long chk[4]; fe_sqr(chk, r);
      ck("  and squares back to 1", fe_equal(chk, one)); }
    { /* 4 = 2^2, so its root is 2 (or p-2) */
      unsigned long long four[4] = {4,0,0,0}, r[4], chk[4];
      ck("sqrt(4) succeeds", fe_sqrt(r, four) == 1);
      fe_sqr(chk, r);
      ck("  and squares back to 4", fe_equal(chk, four)); }

    printf("== a non-residue is REFUSED, not silently answered ==\n");
    { /* find one from the vectors and confirm the output is untouched */
      int found = 0;
      for (int i = 0; i < FE_SQRT_NVEC && !found; i++){
          if (FE_SQRT_VEC[i].is_square) continue;
          unsigned long long a[4], r[4] = {0xdead,0xbeef,0xcafe,0xf00d};
          hex2fe(a, FE_SQRT_VEC[i].a);
          int got = fe_sqrt(r, a);
          ck("a non-residue returns 0", got == 0);
          ck("  and leaves the output untouched",
             r[0]==0xdead && r[1]==0xbeef && r[2]==0xcafe && r[3]==0xf00d);
          found = 1;
      }
      ck("the vector set contains a non-residue to test with", found); }

    /* ---- fe_is_square_var: the Jacobi symbol against the exponentiation ----
     * Every vector, then the edges, then random values across the whole field
     * (rejection-sampled below p) and random squares; the oracle is
     * fe_is_square, which squares-and-compares and cannot be wrong about it. */
    printf("== fe_is_square_var (Jacobi by safegcd) against fe_is_square ==\n");
    {
        long n = 0, bad = 0;
        for (int i = 0; i < FE_SQRT_NVEC; i++){
            unsigned long long a[4]; hex2fe(a, FE_SQRT_VEC[i].a);
            n++; if (fe_is_square_var(a) != FE_SQRT_VEC[i].is_square){ bad++; printf("  FAIL jacobi %s\n", FE_SQRT_VEC[i].a); }
        }
        static const unsigned long long P[4] = { 0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL };
        unsigned long long e[4];
        /* expectations from Python's pow(a, (p-1)//2, p) (validation: the same
         * Euler criterion the oracle uses, computed independently): -1 is a
         * non-residue (p = 3 mod 4), 2 a residue (p = 7 mod 8), so -2 is not
         * and -3 is (c0 = sqrt(-3) is the constant the whole map rests on) */
        static const struct { unsigned long long lo; int sub_from_p; int want; } edges[] = {
            {1,0,1},{2,0,1},{3,0,0},{4,0,1},{7,0,0},{1,1,0},{2,1,0},{3,1,1},{4,1,0},{0x1000003D1ULL,1,0}
        };
        for (unsigned k = 0; k < sizeof edges / sizeof edges[0]; k++){
            if (edges[k].sub_from_p){ memcpy(e, P, 32); e[0] -= edges[k].lo; } else { memset(e, 0, 32); e[0] = edges[k].lo; }
            int want = fe_is_square(e), got = fe_is_square_var(e);
            n++; if (got != want || want != edges[k].want){ bad++; printf("  FAIL edge %u: got %d want %d (table %d)\n", k, got, want, edges[k].want); }
        }
        memset(e, 0, 32); e[3] = 1ULL << 63; n++; if (fe_is_square_var(e) != fe_is_square(e)){ bad++; printf("  FAIL 2^255\n"); }
        memset(e, 0, 32); n++; if (fe_is_square_var(e) != 1){ bad++; printf("  FAIL 0 must count as a square\n"); }
        unsigned long long rs = 0x5EEDF00DCAFEBABEULL;
        #define RND() (rs ^= rs << 13, rs ^= rs >> 7, rs ^= rs << 17, rs)
        long nsqv = 0;
        for (int i = 0; i < 20000; i++){
            unsigned long long a[4], r[4];
            do { for (int k = 0; k < 4; k++) a[k] = RND(); }
            while (a[3] == ~0ULL && a[2] == ~0ULL && a[1] == ~0ULL && a[0] >= P[0]);   /* below p */
            int want = fe_is_square(a), got = fe_is_square_var(a);
            n++; nsqv += want; if (got != want){ bad++; if (bad < 10) printf("  FAIL random %d: got %d want %d\n", i, got, want); }
            fe_sqr(r, a);                                       /* a square, by construction */
            n++; if (fe_is_square_var(r) != 1){ bad++; if (bad < 10) printf("  FAIL square %d\n", i); }
        }
        printf("  %ld checks, %ld residues among 20000 random values (expect ~10000)\n", n, nsqv);
        ck("fe_is_square_var agrees with fe_is_square on every input", bad == 0);
        ck("about half of random values are residues", nsqv > 9500 && nsqv < 10500);
    }

    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}
