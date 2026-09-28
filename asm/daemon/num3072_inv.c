/* daemon/num3072_inv.c -- the modular inverse of a MuHash3072 accumulator,
 * x^{-1} mod p, p = 2^3072 - 1103717, by a variant of Bernstein-Yang's safegcd
 * (Fast constant-time gcd computation and modular inversion, 2019), in its
 * variable-time form: 62 divsteps at a time on the low limbs of f and g, the
 * resulting 2x2 transition applied to the full-width f, g and the cofactors
 * d, e, with p^{-1} mod 2^62 making each division by 2^62 exact.
 *
 * WHY. gettxoutsetinfo's digest is H(num * den^{-1}); until 2026-09-28 the
 * inverse was a Fermat exponentiation, den^(p-2): 3,072 squarings and 3,070
 * multiplies of 3072-bit numbers, 1.8 ms on this box, 66x Bitcoin Core's
 * 28 us for the same digest (its Num3072::GetInverse is this algorithm). Paid
 * once per gettxoutsetinfo call and per parity check, never per block.
 *
 * WHAT IT MIRRORS. Bitcoin Core's src/crypto/muhash.cpp (Num3072Signed,
 * ComputeDivstepMatrix, UpdateDE, UpdateFG, Normalize, GetInverse), which is
 * in turn modelled on libsecp256k1's modinv64 -- step for step, so that the
 * two can be read side by side; the constants are checked in
 * tests/test_num3072_inv.c. The 256-bit version of the same algorithm is
 * asm/safegcd_var.inc (sc_inv_var, fe_inv_var, 2026-09-27).
 *
 * REPRESENTATION. In and out are the accumulator's 48 little-endian u64 limbs
 * (byte-identical to Core's Num3072::limbs); any value below 2^3072 is
 * accepted (the accumulator may sit in its "overflow" form, >= p), and the
 * result is canonical, in [0, p). Inside, 50 signed 62-bit limbs. Variable
 * time: the accumulator is a public value.
 *
 * Returns 1 and writes out; returns 0 and leaves out untouched if x == 0
 * (mod p), which has no inverse -- a denominator is never 0, so a caller
 * treating 0 as an error is right to. */
#include <stdint.h>
#include <string.h>

typedef uint64_t limb_t;
typedef int64_t slimb_t;
typedef unsigned __int128 dlimb_t;
typedef __int128 sdlimb_t;

#define LIMBS 48
#define LIMB_SIZE 64
#define SIGNED_LIMBS 50
#define SIGNED_LIMB_SIZE 62
#define FINAL_LIMB_POSITION (3072 / SIGNED_LIMB_SIZE)      /* 49 */
#define FINAL_LIMB_MODULUS_BITS (3072 % SIGNED_LIMB_SIZE)  /* 34 */
#define MAX_LIMB ((limb_t)-1)
#define MAX_SIGNED_LIMB ((((limb_t)1) << SIGNED_LIMB_SIZE) - 1)
#define MAX_PRIME_DIFF ((limb_t)1103717)
#define MODULUS_INVERSE ((limb_t)0x70a1421da087d93ULL)     /* p^{-1} mod 2^62 */

typedef struct { slimb_t limbs[SIGNED_LIMBS]; } n3072s_t;
typedef struct { slimb_t u, v, q, r; } smat_t;

static void from_num3072(n3072s_t* o, const limb_t in[LIMBS]){
    dlimb_t c = 0; int b = 0, outpos = 0;
    for (int i = 0; i < LIMBS; i++){
        c += ((dlimb_t)in[i]) << b;
        b += LIMB_SIZE;
        while (b >= SIGNED_LIMB_SIZE){
            o->limbs[outpos++] = (slimb_t)((limb_t)c & MAX_SIGNED_LIMB);
            c >>= SIGNED_LIMB_SIZE;
            b -= SIGNED_LIMB_SIZE;
        }
    }
    o->limbs[SIGNED_LIMBS - 1] = (slimb_t)c;     /* outpos == SIGNED_LIMBS - 1 here */
}

static void to_num3072(limb_t out[LIMBS], const n3072s_t* in){
    dlimb_t c = 0; int b = 0, outpos = 0;
    for (int i = 0; i < SIGNED_LIMBS; i++){
        c += ((dlimb_t)(sdlimb_t)in->limbs[i]) << b;
        b += SIGNED_LIMB_SIZE;
        if (b >= LIMB_SIZE){
            out[outpos++] = (limb_t)c;
            c >>= LIMB_SIZE;
            b -= LIMB_SIZE;
        }
    }
}

/* Take a value in 1-2*2^3072..2^3072-1; optionally negate it; add the modulus
 * once or twice as needed; leave every limb in 0..2^62-1: the value in [0, p). */
static void normalize(n3072s_t* x, int negate){
    slimb_t cond_add = x->limbs[SIGNED_LIMBS - 1] >> (LIMB_SIZE - 1);
    x->limbs[0] += (slimb_t)(-(slimb_t)MAX_PRIME_DIFF) & cond_add;
    x->limbs[FINAL_LIMB_POSITION] += (((slimb_t)1) << FINAL_LIMB_MODULUS_BITS) & cond_add;
    slimb_t cond_negate = -(slimb_t)negate;
    for (int i = 0; i < SIGNED_LIMBS; i++) x->limbs[i] = (x->limbs[i] ^ cond_negate) - cond_negate;
    for (int i = 0; i < SIGNED_LIMBS - 1; i++){
        x->limbs[i + 1] += x->limbs[i] >> SIGNED_LIMB_SIZE;
        x->limbs[i] &= (slimb_t)MAX_SIGNED_LIMB;
    }
    cond_add = x->limbs[SIGNED_LIMBS - 1] >> (LIMB_SIZE - 1);
    x->limbs[0] += (slimb_t)(-(slimb_t)MAX_PRIME_DIFF) & cond_add;
    x->limbs[FINAL_LIMB_POSITION] += (((slimb_t)1) << FINAL_LIMB_MODULUS_BITS) & cond_add;
    for (int i = 0; i < SIGNED_LIMBS - 1; i++){
        x->limbs[i + 1] += x->limbs[i] >> SIGNED_LIMB_SIZE;
        x->limbs[i] &= (slimb_t)MAX_SIGNED_LIMB;
    }
}

/* 62 divsteps on the low limbs; returns the new eta, fills the matrix scaled by 2^62 */
static slimb_t divstep_matrix(slimb_t eta, limb_t f, limb_t g, smat_t* out){
    static const uint8_t NEGINV256[128] = {   /* -1/(2i+1) mod 256 */
        0xFF, 0x55, 0x33, 0x49, 0xC7, 0x5D, 0x3B, 0x11, 0x0F, 0xE5, 0xC3, 0x59,
        0xD7, 0xED, 0xCB, 0x21, 0x1F, 0x75, 0x53, 0x69, 0xE7, 0x7D, 0x5B, 0x31,
        0x2F, 0x05, 0xE3, 0x79, 0xF7, 0x0D, 0xEB, 0x41, 0x3F, 0x95, 0x73, 0x89,
        0x07, 0x9D, 0x7B, 0x51, 0x4F, 0x25, 0x03, 0x99, 0x17, 0x2D, 0x0B, 0x61,
        0x5F, 0xB5, 0x93, 0xA9, 0x27, 0xBD, 0x9B, 0x71, 0x6F, 0x45, 0x23, 0xB9,
        0x37, 0x4D, 0x2B, 0x81, 0x7F, 0xD5, 0xB3, 0xC9, 0x47, 0xDD, 0xBB, 0x91,
        0x8F, 0x65, 0x43, 0xD9, 0x57, 0x6D, 0x4B, 0xA1, 0x9F, 0xF5, 0xD3, 0xE9,
        0x67, 0xFD, 0xDB, 0xB1, 0xAF, 0x85, 0x63, 0xF9, 0x77, 0x8D, 0x6B, 0xC1,
        0xBF, 0x15, 0xF3, 0x09, 0x87, 0x1D, 0xFB, 0xD1, 0xCF, 0xA5, 0x83, 0x19,
        0x97, 0xAD, 0x8B, 0xE1, 0xDF, 0x35, 0x13, 0x29, 0xA7, 0x3D, 0x1B, 0xF1,
        0xEF, 0xC5, 0xA3, 0x39, 0xB7, 0xCD, 0xAB, 0x01
    };
    limb_t u = 1, v = 0, q = 0, r = 1;
    int i = SIGNED_LIMB_SIZE;
    for (;;){
        int zeros = __builtin_ctzll(g | (MAX_LIMB << i));
        g >>= zeros; u <<= zeros; v <<= zeros; eta -= zeros; i -= zeros;
        if (i == 0) break;
        if (eta < 0){
            limb_t tmp;
            eta = -eta;
            tmp = f; f = g; g = -tmp;
            tmp = u; u = q; q = -tmp;
            tmp = v; v = r; r = -tmp;
        }
        int limit = ((int)eta + 1) > i ? i : ((int)eta + 1);
        limb_t m = (MAX_LIMB >> (LIMB_SIZE - limit)) & 255U;
        limb_t w = (g * NEGINV256[(f >> 1) & 127]) & m;
        g += f * w; q += u * w; r += v * w;
    }
    out->u = (slimb_t)u; out->v = (slimb_t)v; out->q = (slimb_t)q; out->r = (slimb_t)r;
    return eta;
}

/* (d, e) = t * (d, e) / 2^62 mod p; d and e stay in 1-2p..p-1 */
static void update_de(n3072s_t* d, n3072s_t* e, const smat_t* t){
    const slimb_t u = t->u, v = t->v, q = t->q, r = t->r;
    slimb_t sd = d->limbs[SIGNED_LIMBS - 1] >> (LIMB_SIZE - 1);
    slimb_t se = e->limbs[SIGNED_LIMBS - 1] >> (LIMB_SIZE - 1);
    slimb_t md = (u & sd) + (v & se);
    slimb_t me = (q & sd) + (r & se);
    slimb_t di = d->limbs[0], ei = e->limbs[0];
    sdlimb_t cd = (sdlimb_t)u * di + (sdlimb_t)v * ei;
    sdlimb_t ce = (sdlimb_t)q * di + (sdlimb_t)r * ei;
    md -= (slimb_t)((MODULUS_INVERSE * (limb_t)cd + (limb_t)md) & MAX_SIGNED_LIMB);
    me -= (slimb_t)((MODULUS_INVERSE * (limb_t)ce + (limb_t)me) & MAX_SIGNED_LIMB);
    cd -= (sdlimb_t)1103717 * md;
    ce -= (sdlimb_t)1103717 * me;
    cd >>= SIGNED_LIMB_SIZE;      /* the low 62 bits are zero by construction */
    ce >>= SIGNED_LIMB_SIZE;
    for (int i = 1; i < SIGNED_LIMBS - 1; i++){
        di = d->limbs[i]; ei = e->limbs[i];
        cd += (sdlimb_t)u * di + (sdlimb_t)v * ei;
        ce += (sdlimb_t)q * di + (sdlimb_t)r * ei;
        d->limbs[i - 1] = (slimb_t)((limb_t)cd & MAX_SIGNED_LIMB); cd >>= SIGNED_LIMB_SIZE;
        e->limbs[i - 1] = (slimb_t)((limb_t)ce & MAX_SIGNED_LIMB); ce >>= SIGNED_LIMB_SIZE;
    }
    di = d->limbs[SIGNED_LIMBS - 1]; ei = e->limbs[SIGNED_LIMBS - 1];
    cd += (sdlimb_t)u * di + (sdlimb_t)v * ei;
    ce += (sdlimb_t)q * di + (sdlimb_t)r * ei;
    cd += ((sdlimb_t)md) << FINAL_LIMB_MODULUS_BITS;
    ce += ((sdlimb_t)me) << FINAL_LIMB_MODULUS_BITS;
    d->limbs[SIGNED_LIMBS - 2] = (slimb_t)((limb_t)cd & MAX_SIGNED_LIMB); cd >>= SIGNED_LIMB_SIZE;
    e->limbs[SIGNED_LIMBS - 2] = (slimb_t)((limb_t)ce & MAX_SIGNED_LIMB); ce >>= SIGNED_LIMB_SIZE;
    d->limbs[SIGNED_LIMBS - 1] = (slimb_t)cd;
    e->limbs[SIGNED_LIMBS - 1] = (slimb_t)ce;
}

/* (f, g) = t * (f, g) / 2^62 over the live length */
static void update_fg(n3072s_t* f, n3072s_t* g, const smat_t* t, int len){
    const slimb_t u = t->u, v = t->v, q = t->q, r = t->r;
    slimb_t fi = f->limbs[0], gi = g->limbs[0];
    sdlimb_t cf = (sdlimb_t)u * fi + (sdlimb_t)v * gi;
    sdlimb_t cg = (sdlimb_t)q * fi + (sdlimb_t)r * gi;
    cf >>= SIGNED_LIMB_SIZE;      /* the low 62 bits are zero: the divsteps cleared them */
    cg >>= SIGNED_LIMB_SIZE;
    for (int i = 1; i < len; i++){
        fi = f->limbs[i]; gi = g->limbs[i];
        cf += (sdlimb_t)u * fi + (sdlimb_t)v * gi;
        cg += (sdlimb_t)q * fi + (sdlimb_t)r * gi;
        f->limbs[i - 1] = (slimb_t)((limb_t)cf & MAX_SIGNED_LIMB); cf >>= SIGNED_LIMB_SIZE;
        g->limbs[i - 1] = (slimb_t)((limb_t)cg & MAX_SIGNED_LIMB); cg >>= SIGNED_LIMB_SIZE;
    }
    f->limbs[len - 1] = (slimb_t)cf;
    g->limbs[len - 1] = (slimb_t)cg;
}

int num3072_inv_var(unsigned char out[384], const unsigned char in[384]){
    limb_t x[LIMBS]; memcpy(x, in, 384);
    n3072s_t d, e, f, g;
    memset(&d, 0, sizeof d); memset(&e, 0, sizeof e); memset(&f, 0, sizeof f);
    e.limbs[0] = 1;
    f.limbs[0] = -(slimb_t)MAX_PRIME_DIFF;                       /* f = p = 2^3072 - 1103717 */
    f.limbs[FINAL_LIMB_POSITION] = ((slimb_t)1) << FINAL_LIMB_MODULUS_BITS;
    from_num3072(&g, x);
    { slimb_t any = 0; for (int i = 0; i < SIGNED_LIMBS; i++) any |= g.limbs[i];
      if (any == 0) return 0; }                                 /* 0 has no inverse */
    int len = SIGNED_LIMBS;
    slimb_t eta = -1;
    for (;;){
        smat_t t;
        eta = divstep_matrix(eta, (limb_t)f.limbs[0], (limb_t)g.limbs[0], &t);
        update_fg(&f, &g, &t, len);
        update_de(&d, &e, &t);
        if (g.limbs[0] == 0){
            slimb_t cond = 0;
            for (int j = 1; j < len; j++) cond |= g.limbs[j];
            if (cond == 0) break;
        }
        slimb_t fn = f.limbs[len - 1], gn = g.limbs[len - 1];
        slimb_t cond = ((slimb_t)len - 2) >> (LIMB_SIZE - 1);
        cond |= fn ^ (fn >> (LIMB_SIZE - 1));
        cond |= gn ^ (gn >> (LIMB_SIZE - 1));
        if (cond == 0){
            f.limbs[len - 2] |= (slimb_t)((limb_t)f.limbs[len - 1] << SIGNED_LIMB_SIZE);
            g.limbs[len - 2] |= (slimb_t)((limb_t)g.limbs[len - 1] << SIGNED_LIMB_SIZE);
            --len;
        }
    }
    /* f is now +-1 (gcd(p, x) = 1 for x != 0 mod p): x^{-1} = d * f. If x was a
     * multiple of p (the value 0 in overflow form), f ends at +-p instead. */
    limb_t f0 = (limb_t)f.limbs[0] & MAX_SIGNED_LIMB;
    if (f0 != 1 && f0 != MAX_SIGNED_LIMB) return 0;
    normalize(&d, (int)((limb_t)f.limbs[len - 1] >> (LIMB_SIZE - 1)));
    limb_t o[LIMBS]; to_num3072(o, &d);
    memcpy(out, o, 384);
    return 1;
}
