/* crypto_fe_sqrt.c -- square root in the secp256k1 field.
 *
 * WHY THIS DID NOT EXIST. Nothing before BIP324 needed one: ECDSA and Schnorr
 * verification never take a square root, and point decompression in this
 * codebase has always been handed an explicit y parity. ElligatorSwift needs
 * both a root and a "is this a square?" predicate, so here it is.
 *
 * p = 2^256 - 2^32 - 977 is congruent to 3 mod 4, which makes the root a
 * single exponentiation:  sqrt(a) = a^((p+1)/4).  That exponent is
 * 2^254 - 2^30 - 244, and it is reached with the same x_k = a^(2^k - 1)
 * ladder fe_inv already uses for a^(p-2) -- libsecp256k1's chain, mirrored
 * here so the two agree step for step.
 *
 * NOT EVERY ELEMENT HAS A ROOT. Exactly half do. a^((p+1)/4) always produces
 * SOMETHING; when a is a non-residue that something simply does not square
 * back to a. So the result is verified before being returned, and the caller
 * gets 0. Skipping that check is the classic way to end up with a "square
 * root" of a non-square and a curve point that is not on the curve.
 *
 * This is C over the existing fe_mul/fe_sqr rather than assembly on purpose:
 * BIP324 takes a handful of roots per handshake, where the network dominates
 * completely, and the chain is far easier to audit against libsecp256k1 in
 * this form.
 */
#include <string.h>
#include "crypto_fe_sqrt.h"

extern void fe_mul(unsigned long long r[4], const unsigned long long a[4], const unsigned long long b[4]);
extern void fe_sqr(unsigned long long r[4], const unsigned long long a[4]);

typedef unsigned long long fe4[4];

static void fe_copy(fe4 r, const fe4 a){ memcpy(r, a, 32); }
/* r = a^(2^n), i.e. n repeated squarings */
static void fe_sqr_n(fe4 r, const fe4 a, int n){
    fe_copy(r, a);
    for (int i = 0; i < n; i++) fe_sqr(r, r);
}

int fe_is_zero(const unsigned long long a[4]){
    return (a[0] | a[1] | a[2] | a[3]) == 0;
}
int fe_equal(const unsigned long long a[4], const unsigned long long b[4]){
    unsigned long long d = 0;
    for (int i = 0; i < 4; i++) d |= a[i] ^ b[i];
    return d == 0;
}

/* r = sqrt(a) if one exists (1), else r is untouched and 0 is returned.
 * When a root exists there are two; this returns the one a^((p+1)/4) gives,
 * which is what libsecp256k1 returns, so callers that care about parity must
 * negate explicitly rather than assume. */
int fe_sqrt(unsigned long long r[4], const unsigned long long a[4]){
    fe4 x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t1, chk;

    /* the x_k ladder: x_k = a^(2^k - 1) */
    fe_sqr(x2, a);      fe_mul(x2, x2, a);              /* x2  */
    fe_sqr(x3, x2);     fe_mul(x3, x3, a);              /* x3  */
    fe_sqr_n(x6, x3, 3);   fe_mul(x6, x6, x3);
    fe_sqr_n(x9, x6, 3);   fe_mul(x9, x9, x3);
    fe_sqr_n(x11, x9, 2);  fe_mul(x11, x11, x2);
    fe_sqr_n(x22, x11, 11);fe_mul(x22, x22, x11);
    fe_sqr_n(x44, x22, 22);fe_mul(x44, x44, x22);
    fe_sqr_n(x88, x44, 44);fe_mul(x88, x88, x44);
    fe_sqr_n(x176, x88, 88);fe_mul(x176, x176, x88);
    fe_sqr_n(x220, x176, 44);fe_mul(x220, x220, x44);
    fe_sqr_n(x223, x220, 3); fe_mul(x223, x223, x3);

    /* and the tail: ((x223)^(2^23) * x22)^(2^6) * x2, then two squarings */
    fe_sqr_n(t1, x223, 23); fe_mul(t1, t1, x22);
    fe_sqr_n(t1, t1, 6);    fe_mul(t1, t1, x2);
    fe_sqr(t1, t1);
    fe_sqr(t1, t1);

    /* verify: a non-residue also produces a value here, just not a root */
    fe_sqr(chk, t1);
    if (!fe_equal(chk, a)) return 0;
    fe_copy(r, t1);
    return 1;
}

/* 1 if a is a quadratic residue (0 counts as one, since 0*0 == 0). */
int fe_is_square(const unsigned long long a[4]){
    fe4 r;
    if (fe_is_zero(a)) return 1;
    return fe_sqrt(r, a);
}
