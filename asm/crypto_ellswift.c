/* crypto_ellswift.c -- ElligatorSwift for secp256k1 (BIP324).
 *
 * BIP324's handshake exchanges public keys that must be indistinguishable
 * from uniform random bytes -- a v2 connection has no plaintext header, so an
 * observer must not be able to recognise one from the first bytes on the
 * wire. A compressed pubkey fails that immediately: its leading byte is 02 or
 * 03. ElligatorSwift instead encodes a key as 64 bytes (u, t) whose decoding
 * is a curve x-coordinate, and every 64-byte string decodes to something, so
 * the encoding carries no distinguisher.
 *
 * THE MAP (SwiftEC), exactly as libsecp256k1's ellswift module states it:
 *
 *     c0 = sqrt(-3)
 *     if u = 0: u = 1
 *     if t = 0: t = 1
 *     if u^3 + 7 + t^2 = 0: t = 2t
 *     X = (u^3 + 7 - t^2) / (2t)
 *     Y = (X + t) / (c0 * u)
 *     x3 = u + 4Y^2          -- return if it is a valid x
 *     x2 = (-X/Y - u) / 2    -- return if it is a valid x
 *     x1 = (X/Y - u) / 2     -- guaranteed valid, return it
 *
 * "valid x" means x^3 + 7 is a square, i.e. the point exists on the curve.
 * The three candidates are tried in that fixed order; a different order still
 * yields curve points, just not the ones every other implementation derives,
 * which is why the official decode vectors below name the branch each one
 * exercises.
 *
 * This is the unoptimised form. libsecp256k1 substitutes Y^2 and X/Y to avoid
 * evaluating X and Y explicitly, which is worth it there and not here: BIP324
 * decodes one key per connection, and the algebraic form above can be read
 * straight against the specification.
 */
#include <string.h>
#include "crypto_ellswift.h"
#include "crypto_fe_sqrt.h"

/* forward decls used before their definitions below */
void ellswift_be32_to_fe(unsigned long long r[4], const unsigned char b[32]);
void ellswift_fe_to_be32(unsigned char b[32], const unsigned long long a[4]);

extern void fe_add(unsigned long long r[4], const unsigned long long a[4], const unsigned long long b[4]);
extern void fe_sub(unsigned long long r[4], const unsigned long long a[4], const unsigned long long b[4]);
extern void fe_mul(unsigned long long r[4], const unsigned long long a[4], const unsigned long long b[4]);
extern void fe_sqr(unsigned long long r[4], const unsigned long long a[4]);
extern void fe_inv(unsigned long long r[4], const unsigned long long a[4]);

typedef unsigned long long fe4[4];

/* sqrt(-3) mod p, the constant the whole map is built around */
/* Limbs verified against Python: c0*c0 == -3 mod p. Transcribing a 64-digit
 * hex constant into four little-endian limbs by hand is a nibble-alignment
 * trap -- the first cut here was off by one nibble in every limb, which does
 * not fail loudly: the map still returns points ON the curve, just not the
 * ones any other implementation derives. The official decode vectors are what
 * catch it. */
static const fe4 FE_C0 = {
    0x7d8d27ae1cd5f852ULL, 0xc61f6d15da14ecd4ULL,
    0x233770c2a797962cULL, 0x0a2d2ba93507f1dfULL
};

static void fe_set_u64(fe4 r, unsigned long long v){ r[0]=v; r[1]=r[2]=r[3]=0; }
static void fe_neg(fe4 r, const fe4 a){ fe4 z; fe_set_u64(z,0); fe_sub(r, z, a); }
static void fe_copy4(fe4 r, const fe4 a){ memcpy(r, a, 32); }

/* x is a valid x-coordinate iff x^3 + 7 is a square */
static int valid_x(const fe4 x){
    fe4 t, seven;
    fe_sqr(t, x); fe_mul(t, t, x);
    fe_set_u64(seven, 7);
    fe_add(t, t, seven);
    return fe_is_square(t);
}

void ellswift_xswiftec(unsigned long long x[4],
                       const unsigned long long u_in[4], const unsigned long long t_in[4]){
    fe4 u, t, s, g, seven, tmp, X, Y, Yinv, x1, x2, x3, inv2;

    fe_copy4(u, u_in); fe_copy4(t, t_in);
    if (fe_is_zero(u)) fe_set_u64(u, 1);
    if (fe_is_zero(t)) fe_set_u64(t, 1);

    /* g = u^3 + 7, s = t^2 */
    fe_sqr(g, u); fe_mul(g, g, u);
    fe_set_u64(seven, 7); fe_add(g, g, seven);
    fe_sqr(s, t);

    /* if g + s == 0 the division below is undefined; the spec doubles t */
    fe_add(tmp, g, s);
    if (fe_is_zero(tmp)){ fe_add(t, t, t); fe_sqr(s, t); }

    /* X = (g - s) / (2t) */
    fe_sub(tmp, g, s);
    { fe4 t2; fe_add(t2, t, t); fe_inv(t2, t2); fe_mul(X, tmp, t2); }

    /* Y = (X + t) / (c0 * u) */
    fe_add(tmp, X, t);
    { fe4 d; fe_mul(d, FE_C0, u); fe_inv(d, d); fe_mul(Y, tmp, d); }

    fe_set_u64(inv2, 2); fe_inv(inv2, inv2);

    /* x3 = u + 4Y^2 */
    fe_sqr(tmp, Y);
    fe_add(tmp, tmp, tmp); fe_add(tmp, tmp, tmp);   /* *4 */
    fe_add(x3, u, tmp);
    if (valid_x(x3)){ fe_copy4(x, x3); return; }

    /* x2 = (-X/Y - u)/2 */
    fe_inv(Yinv, Y);
    fe_mul(tmp, X, Yinv);                            /* X/Y */
    { fe4 n; fe_neg(n, tmp); fe_sub(n, n, u); fe_mul(x2, n, inv2); }
    if (valid_x(x2)){ fe_copy4(x, x2); return; }

    /* x1 = (X/Y - u)/2 -- guaranteed valid at this point */
    { fe4 n; fe_sub(n, tmp, u); fe_mul(x1, n, inv2); }
    fe_copy4(x, x1);
}


/* c1 = (sqrt(-3)-1)/2, c2 = -(c1+1), c3 = -c1, c4 = -c2.
 * Computed and checked in Python, not transcribed by eye -- see the note on
 * FE_C0 above for why that distinction earned its place. */
static const fe4 FE_C3 = {
    0xc1396c28719501efULL, 0x9cf0497512f58995ULL,
    0x6e64479eac3434e9ULL, 0x7ae96a2b657c0710ULL
};
static const fe4 FE_C4 = {
    0x3ec693d68e6afa41ULL, 0x630fb68aed0a766aULL,
    0x919bb86153cbcb16ULL, 0x851695d49a83f8efULL
};

/* ---- the reverse map: given x and u, find t such that xswiftec(u,t) = x ---
 *
 * Not every (x, u) pair has a solution, and that is by design: encoding works
 * by picking u at random and retrying until one does. `c` selects which of
 * the eight solution branches to attempt -- bit 1 chooses the x3 family over
 * the x1/x2 family, and bits 0 and 2 pick the sign and which constant.
 *
 * The (c & 2) == 0 case must FIRST reject any (x,u) where -x-u is also a
 * valid x-coordinate. Such a pair would round-trip through the x3 formula
 * instead, and x3 is tried first during decoding -- so the encoding would
 * decode to a DIFFERENT point. That check is the whole reason encode and
 * decode agree, and dropping it produces encodings that look fine until the
 * peer derives a different key.
 *
 * Returns 1 and writes t on success, 0 on a branch that has no solution.
 */
int ellswift_xswiftec_inv(unsigned long long t_out[4],
                          const unsigned long long x_in[4],
                          const unsigned long long u_in[4], int c){
    fe4 x, u, g, v, s, m, r, w, tmp, tmp2, seven, inv2;
    fe_copy4(x, x_in); fe_copy4(u, u_in);
    fe_set_u64(seven, 7);
    fe_set_u64(inv2, 2); fe_inv(inv2, inv2);

    /* g = u^3 + 7 */
    fe_sqr(g, u); fe_mul(g, g, u); fe_add(g, g, seven);

    if (!(c & 2)){
        /* would this encoding round-trip through x3 instead? then refuse */
        fe_add(m, x, u); fe_neg(m, m);
        if (valid_x(m)) return 0;
        /* s = -(u^3+7) / (u^2 + u*x + x^2) */
        fe_sqr(tmp, u);                       /* u^2 */
        fe_mul(tmp2, u, x);                   /* u*x */
        fe_add(tmp, tmp, tmp2);
        fe_sqr(tmp2, x);                      /* x^2 */
        fe_add(tmp, tmp, tmp2);
        if (fe_is_zero(tmp)) return 0;
        fe_inv(tmp, tmp);
        fe_neg(tmp2, g);
        fe_mul(s, tmp2, tmp);
        if (!fe_is_square(s)) return 0;
        fe_copy4(v, x);
    } else {
        /* s = x - u */
        fe_sub(s, x, u);
        if (!fe_is_square(s)) return 0;
        /* r = sqrt(-s * (4g + 3*u^2*s)) */
        fe_add(tmp, g, g); fe_add(tmp, tmp, tmp);        /* 4g */
        fe_sqr(tmp2, u); fe_mul(tmp2, tmp2, s);          /* u^2*s */
        { fe4 three_u2s; fe_add(three_u2s, tmp2, tmp2); fe_add(three_u2s, three_u2s, tmp2);
          fe_add(tmp, tmp, three_u2s); }                 /* 4g + 3u^2 s */
        { fe4 ns; fe_neg(ns, s); fe_mul(tmp, ns, tmp); }
        if (!fe_sqrt(r, tmp)) return 0;
        if ((c & 1) && fe_is_zero(r)) return 0;
        if (fe_is_zero(s)) return 0;
        /* v = (r/s - u)/2 */
        fe_inv(tmp, s); fe_mul(tmp, r, tmp);
        fe_sub(tmp, tmp, u);
        fe_mul(v, tmp, inv2);
    }

    if (!fe_sqrt(w, s)) return 0;

    switch (c & 5){
    case 0: fe_mul(tmp, FE_C3, u); fe_add(tmp, tmp, v); fe_mul(tmp, w, tmp); fe_neg(t_out, tmp); break;
    case 1: fe_mul(tmp, FE_C4, u); fe_add(tmp, tmp, v); fe_mul(t_out, w, tmp); break;
    case 4: fe_mul(tmp, FE_C3, u); fe_add(tmp, tmp, v); fe_mul(t_out, w, tmp); break;
    default:/* 5 */
            fe_mul(tmp, FE_C4, u); fe_add(tmp, tmp, v); fe_mul(tmp, w, tmp); fe_neg(t_out, tmp); break;
    }
    return 1;
}


/* 64 bytes big-endian (u || t) -> 32-byte big-endian x */
void ellswift_decode(unsigned char x_out[32], const unsigned char ellswift64[64]){
    fe4 u, t, x;
    ellswift_be32_to_fe(u, ellswift64);
    ellswift_be32_to_fe(t, ellswift64 + 32);
    ellswift_xswiftec(x, u, t);
    ellswift_fe_to_be32(x_out, x);
}

/* The wire form is big-endian and MAY exceed p: BIP324 says the 64 bytes are
 * interpreted mod p, precisely so that every 64-byte string is a valid
 * encoding and the format carries no distinguisher. Reducing here is what
 * makes that true; rejecting out-of-range input would reintroduce one. */
void ellswift_be32_to_fe(unsigned long long r[4], const unsigned char b[32]){
    fe4 v;
    for (int i = 0; i < 4; i++){
        unsigned long long w = 0;
        for (int j = 0; j < 8; j++) w = (w << 8) | b[i*8 + j];
        v[3 - i] = w;
    }
    /* fe_add with zero reduces mod p for values already < 2^256; the field
     * routines keep results canonical, and adding 0 is the cheapest way to
     * put an arbitrary 256-bit value through that reduction. */
    fe4 z; fe_set_u64(z, 0);
    fe_add(r, v, z);
}

void ellswift_fe_to_be32(unsigned char b[32], const unsigned long long a[4]){
    for (int i = 0; i < 4; i++){
        unsigned long long w = a[3 - i];
        for (int j = 0; j < 8; j++) b[i*8 + j] = (unsigned char)(w >> (8 * (7 - j)));
    }
}
