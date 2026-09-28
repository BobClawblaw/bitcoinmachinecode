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
#include <stdint.h>
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

/* ---- the square predicate WITHOUT a root: the Jacobi symbol by safegcd ----
 *
 * fe_is_square above answers by exponentiation (a full 255-squaring chain,
 * ~2.1 us) and then throws the root away. ElligatorSwift asks the question
 * far more often than it needs a root -- valid_x on every decode candidate,
 * and two or three times per branch of the inverse map -- so the predicate
 * is where the encode/decode time went.
 *
 * The Jacobi symbol (a|p) is +1 exactly when a is a non-zero square mod p
 * (p is prime, so Jacobi = Legendre). It can be read off a binary gcd: each
 * "divide g by 2" flips the sign when f = 3 or 5 mod 8, each swap flips it
 * when both are 3 mod 4. libsecp256k1's secp256k1_jacobi64_maybe_var tracks
 * exactly that through its 62-bit safegcd rounds (modinv64_impl.h), and this
 * is that routine, step for step, over the same signed-62-bit limbs. It runs
 * in about the time of one fe_inv_var, and it is VARIABLE TIME: the inputs
 * on every path that calls it (u, t, x of the ElligatorSwift map) are public.
 *
 * "maybe": libsecp256k1 bounds the round count (25 rounds of 62 posdivsteps)
 * and reports "unknown" if f has not reached 1 by then, which for random
 * input is astronomically rare; fe_is_square_var then falls back to the
 * exponentiation, so the answer is always exact. */
typedef struct { int64_t v[5]; } fe_s62;

static void fe_to_s62(fe_s62* r, const unsigned long long a[4]){
    const unsigned long long M62 = ~0ULL >> 2;
    r->v[0] = (int64_t)(a[0] & M62);
    r->v[1] = (int64_t)(((a[0] >> 62) | (a[1] << 2)) & M62);
    r->v[2] = (int64_t)(((a[1] >> 60) | (a[2] << 4)) & M62);
    r->v[3] = (int64_t)(((a[2] >> 58) | (a[3] << 6)) & M62);
    r->v[4] = (int64_t)(a[3] >> 56);
}

typedef struct { int64_t u, v, q, r; } fe_trans2x2;

/* 62 "posdivsteps" on the low limbs of f and g (both kept positive), the
 * aggregate transition matrix in t, the Jacobi sign bit accumulated in *jacp.
 * libsecp256k1's secp256k1_modinv64_posdivsteps_62_var. */
static int64_t fe_posdivsteps_62_var(int64_t eta, uint64_t f0, uint64_t g0, fe_trans2x2* t, int* jacp){
    uint64_t u = 1, v = 0, q = 0, r = 1;
    uint64_t f = f0, g = g0, m;
    uint32_t w;
    int i = 62, limit, zeros;
    int jac = *jacp;
    for (;;){
        zeros = __builtin_ctzll(g | (~0ULL << i));   /* a sentinel bit caps the count at i */
        g >>= zeros; u <<= zeros; v <<= zeros; eta -= zeros; i -= zeros;
        /* dividing g by an odd power of two flips the symbol when f = 3 or 5 mod 8 */
        jac ^= (int)(zeros & ((f >> 1) ^ (f >> 2)));
        if (i == 0) break;
        if (eta < 0){
            uint64_t tmp;
            eta = -eta;
            tmp = f; f = g; g = tmp;
            tmp = u; u = q; q = tmp;
            tmp = v; v = r; r = tmp;
            /* swapping f and g flips the symbol when both are 3 mod 4 */
            jac ^= (int)((f & g) >> 1);
            limit = ((int)eta + 1) > i ? i : ((int)eta + 1);
            m = (~0ULL >> (64 - limit)) & 63U;
            w = (uint32_t)((f * g * (f * f - 2)) & m);   /* cancels up to 6 low bits of g */
        } else {
            limit = ((int)eta + 1) > i ? i : ((int)eta + 1);
            m = (~0ULL >> (64 - limit)) & 15U;
            w = (uint32_t)(f + (((f + 1) & 4) << 1));
            w = (uint32_t)((-(uint64_t)w * g) & m);       /* cancels up to 4 low bits of g */
        }
        g += f * w; q += u * w; r += v * w;
    }
    t->u = (int64_t)u; t->v = (int64_t)v; t->q = (int64_t)q; t->r = (int64_t)r;
    *jacp = jac;
    return eta;
}

/* [f, g] = t * [f, g] / 2^62 over `len` limbs (the low 62 bits are zero by
 * construction). libsecp256k1's secp256k1_modinv64_update_fg_62_var. */
static void fe_update_fg_62_var(int len, fe_s62* f, fe_s62* g, const fe_trans2x2* t){
    const uint64_t M62 = ~0ULL >> 2;
    const int64_t u = t->u, v = t->v, q = t->q, r = t->r;
    __int128 cf, cg;
    int64_t fi = f->v[0], gi = g->v[0];
    cf = (__int128)u * fi + (__int128)v * gi;
    cg = (__int128)q * fi + (__int128)r * gi;
    cf >>= 62; cg >>= 62;
    for (int i = 1; i < len; i++){
        fi = f->v[i]; gi = g->v[i];
        cf += (__int128)u * fi + (__int128)v * gi;
        cg += (__int128)q * fi + (__int128)r * gi;
        f->v[i - 1] = (int64_t)((uint64_t)cf & M62); cf >>= 62;
        g->v[i - 1] = (int64_t)((uint64_t)cg & M62); cg >>= 62;
    }
    f->v[len - 1] = (int64_t)cf;
    g->v[len - 1] = (int64_t)cg;
}

/* (x|p) for 0 < x < p: +1 / -1, or 0 when the bounded loop did not converge.
 * libsecp256k1's secp256k1_jacobi64_maybe_var with the field's modulus
 * p = 2^256 - 2^32 - 977 = {-0x1000003D1, 0, 0, 0, 256} in signed-62 limbs. */
static int fe_jacobi_maybe_var(const fe_s62* x){
    fe_s62 f = {{ -0x1000003D1LL, 0, 0, 0, 256 }};
    fe_s62 g = *x;
    int len = 5, jac = 0;
    int64_t eta = -1, cond, fn, gn;
    for (int count = 0; count < 25; count++){
        fe_trans2x2 t;
        eta = fe_posdivsteps_62_var(eta, (uint64_t)f.v[0] | ((uint64_t)f.v[1] << 62),
                                         (uint64_t)g.v[0] | ((uint64_t)g.v[1] << 62), &t, &jac);
        fe_update_fg_62_var(len, &f, &g, &t);
        if (f.v[0] == 1){                        /* f may be 1: then (g|f) = 1 and the sign is jac */
            cond = 0;
            for (int j = 1; j < len; j++) cond |= f.v[j];
            if (cond == 0) return 1 - 2 * (jac & 1);
        }
        fn = f.v[len - 1]; gn = g.v[len - 1];
        cond = ((int64_t)len - 2) >> 63;
        cond |= fn; cond |= gn;
        if (cond == 0) --len;                    /* both top limbs empty: shrink */
    }
    return 0;
}

int fe_is_square_var(const unsigned long long a[4]){
    if (fe_is_zero(a)) return 1;                 /* 0 = 0*0; the gcd loop cannot take it */
    fe_s62 s; fe_to_s62(&s, a);
    int jac = fe_jacobi_maybe_var(&s);
    if (jac == 0){ unsigned long long dummy[4]; return fe_sqrt(dummy, a); }
    return jac > 0;
}
