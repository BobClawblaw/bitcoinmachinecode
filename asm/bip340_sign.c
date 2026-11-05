/* bip340_sign.c -- BIP340 Schnorr signing over secp256k1, in C.
 *
 * The node verifies Schnorr signatures in consensus (schnorr_verify, asm);
 * until 2026-09-01 nothing SIGNED one, so P2TR outputs the wallet or a
 * descriptor controlled could not be spent by this node. This is BIP340's
 * reference algorithm over the same field/point kernels the ECDSA signer
 * uses (point_scalar_mul_ct, fe_*, sc_*), proven against Core's
 * bip340_test_vectors.csv (tests/test_bip340_sign). No thread-local
 * storage: it links and runs on any thread. */
#include <string.h>
#include <stdint.h>
#include "daemon/secure_zero.h"
typedef unsigned char u8;
extern void sha256_full(u8 out[32], const void* msg, unsigned long len);
extern void point_scalar_mul_gen_ct(uint64_t r[12], const uint64_t k[4]);   /* k*G, constant time: the cmov-scanned comb (2026-09-28), 9 us for the ladder's 52 */
extern void fe_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
extern void fe_sqr(uint64_t r[4], const uint64_t a[4]);
extern void fe_inv(uint64_t r[4], const uint64_t a[4]);
extern void sc_add(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
extern void sc_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
extern void fe_sub(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
extern void point_scalar_mul(uint64_t r[12], const uint64_t xy[8], const uint64_t k[4]);   /* variable time: public inputs only */
extern void point_add(uint64_t r[12], const uint64_t p[12], const uint64_t q[12]);

static const uint64_t N_LIMBS[4] = { 0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL, 0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL };

static void be32_to_limbs(uint64_t out[4], const u8 be[32]){
    for (int i = 0; i < 4; i++) out[i] = 0;
    for (int i = 0; i < 32; i++) out[i/8] |= ((uint64_t)be[31 - i]) << ((i % 8) * 8);
}
static void limbs_to_be32(u8 be[32], const uint64_t in[4]){
    for (int i = 0; i < 32; i++) be[31 - i] = (u8)((in[i/8] >> ((i % 8) * 8)) & 0xff);
}
static int limb_cmp(const uint64_t a[4], const uint64_t b[4]){
    for (int i = 3; i >= 0; i--){ if (a[i] < b[i]) return -1; if (a[i] > b[i]) return 1; }
    return 0;
}
static int is_zero(const uint64_t a[4]){ return (a[0] | a[1] | a[2] | a[3]) == 0; }
/* ---------------------------------------------------------------- CRY-2
 * (audit 2026-10-23) neg_n computed each limb's borrow as
 * `N_LIMBS[i] < a[i] + c`. When a[i] is all ones and c is 1, a[i] + c wraps
 * to 0 and the borrow is lost, so n - a came out wrong by 2^(64(i+1)). For a
 * private key or nonce with an all-ones limb (one in ~2^64 per limb, but any
 * caller can choose one) bip340_sign returned 1 with a signature that does
 * not verify. reduce_n has the same expression; there the only wrapping limb
 * is the top one, whose borrow-out is discarded, so its value was right, but
 * it and the parity negations branched on secret data.
 *
 * Both now subtract through a 128-bit difference, whose high half is the
 * borrow and cannot wrap, and select results with masks instead of
 * branches. libsecp256k1's secp256k1_scalar_negate / _cond_negate have the
 * same shape. */
typedef unsigned __int128 u128;
/* r = a - b over four limbs; returns the borrow out (0 or 1) */
static uint64_t sub4(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]){
    uint64_t c = 0;
    for (int i = 0; i < 4; i++){
        u128 t = (u128)a[i] - b[i] - c;
        r[i] = (uint64_t)t;
        c = (uint64_t)(t >> 64) & 1;
    }
    return c;
}
/* r = mask ? a : b, mask all ones or zero */
static void sel4(uint64_t r[4], uint64_t mask, const uint64_t a[4], const uint64_t b[4]){
    for (int i = 0; i < 4; i++) r[i] = (a[i] & mask) | (b[i] & ~mask);
}
/* r = a mod n for a < 2^256 (< 2n): a sha256 output or a 256-bit key */
static void reduce_n(uint64_t r[4], const uint64_t a[4]){
    uint64_t s[4];
    uint64_t borrow = sub4(s, a, N_LIMBS);     /* 1 iff a < n */
    sel4(r, borrow - 1, s, a);                 /* no borrow -> a - n */
}
/* r = flag ? n - a : a, for a in [1, n); flag 0 or 1. No secret branch. */
static void cneg_n(uint64_t r[4], const uint64_t a[4], int flag){
    uint64_t neg[4];
    (void)sub4(neg, N_LIMBS, a);
    sel4(r, (uint64_t)0 - (uint64_t)(flag & 1), neg, a);
}
/* affine (x, y) of a Jacobian point with Z != 0 */
static void jac_to_affine(uint64_t x[4], uint64_t y[4], const uint64_t J[12]){
    uint64_t z2[4], z3[4], zi2[4], zi3[4];
    fe_sqr(z2, J + 8); fe_mul(z3, z2, J + 8);
    fe_inv(zi2, z2); fe_inv(zi3, z3);
    fe_mul(x, J, zi2); fe_mul(y, J + 4, zi3);
}
/* affine (x, y-parity) of a Jacobian point */
static void jac_to_x_parity(u8 x32[32], int* odd, const uint64_t J[12]){
    uint64_t z2[4], z3[4], zi2[4], zi3[4], x[4], y[4];
    fe_sqr(z2, J + 8); fe_mul(z3, z2, J + 8);
    fe_inv(zi2, z2); fe_inv(zi3, z3);
    fe_mul(x, J, zi2); fe_mul(y, J + 4, zi3);
    limbs_to_be32(x32, x); *odd = (int)(y[0] & 1);
}
/* ---------------------------------------------------------------- CRY-5
 * (audit 2026-09-03) This returned VOID and, on overflow, returned WITHOUT
 * WRITING `out`. bip340_sign uses it for the nonce and the challenge, so for
 * msglen past the buffer both kh and eh were uninitialised stack: k0 and e
 * came from whatever happened to be there, and the signature was emitted
 * anyway -- computed with an attacker-unknown but non-random nonce. Two such
 * calls with the same stack state give the same k, which with known messages
 * is the classic private-key recovery; what prevents it today is that `e` is
 * garbage too, and that every current caller passes a 32-byte sighash. That
 * is luck and a footgun for the next caller, since BIP340 explicitly allows
 * messages of any length.
 *
 * It now returns a status and bip340_sign FAILS rather than signing with
 * uninitialised material. (Streaming the tagged hash would lift the length
 * limit entirely and is the better long-term shape; refusing is the change
 * that removes the danger without touching the hash path.) */
static int tagged(u8 out[32], const char* tag, const u8* a, unsigned long al, const u8* b, unsigned long bl, const u8* c, unsigned long cl){
    u8 th[32]; sha256_full(th, tag, strlen(tag));
    u8 buf[64 + 32 + 32 + 4096]; unsigned long n = 0;
    if (al > sizeof buf || bl > sizeof buf || cl > sizeof buf ||
        al + bl + cl > sizeof buf - 64) return 0;
    memcpy(buf, th, 32); memcpy(buf + 32, th, 32); n = 64;
    memcpy(buf + n, a, al); n += al;
    if (b){ memcpy(buf + n, b, bl); n += bl; }
    if (c){ memcpy(buf + n, c, cl); n += cl; }
    sha256_full(out, buf, n);
    return 1;
}

/* ---------------------------------------------------------------- CRY-2
 * Verify-after-sign: the signer checks its own output before returning it,
 * and fails closed. Core's libsecp256k1 does not (it relies on its proofs and
 * tests); this node's arithmetic is its own, and a wrong signature that a
 * wallet broadcasts is at best a stuck spend. The check is BIP340 Verify's
 * equation with the values the signer already has: P = (px, even y) from
 * the public key it computed, R' = s*G - e*P, and R' must be finite with
 * even y and x == r. Only public values (s, e, P) enter the variable-time
 * multiply. */
static int self_verify(const uint64_t Pjac[12], const u8 rx[32], const uint64_t e[4], const uint64_t s[4]){
    static const uint64_t ZERO[4] = {0, 0, 0, 0};
    uint64_t pxy[8], sG[12], eP[12], Rv[12], ne[4], x[4], y[4];
    jac_to_affine(pxy, pxy + 4, Pjac);
    if (pxy[4] & 1) fe_sub(pxy + 4, ZERO, pxy + 4);    /* lift_x: the even-y point (public) */
    point_scalar_mul_gen_ct(sG, s);
    if (is_zero(e)){
        memcpy(Rv, sG, sizeof Rv);
    } else {
        (void)sub4(ne, N_LIMBS, e);                    /* n - e, e in [1, n) */
        point_scalar_mul(eP, pxy, ne);
        point_add(Rv, sG, eP);
    }
    if (is_zero(Rv + 8)) return 0;                     /* infinity */
    jac_to_affine(x, y, Rv);
    if (y[0] & 1) return 0;
    u8 xb[32]; limbs_to_be32(xb, x);
    return memcmp(xb, rx, 32) == 0;
}

/* x-only public key of a private key, and whether its Y was odd (the
 * caller negates the key for signing then, as BIP340 does) */
int bip340_pubkey(u8 xonly[32], const u8 priv_be[32]){
    uint64_t d[4], J[12]; be32_to_limbs(d, priv_be);
    if (is_zero(d) || limb_cmp(d, N_LIMBS) >= 0) return 0;
    point_scalar_mul_gen_ct(J, d);
    int odd; jac_to_x_parity(xonly, &odd, J);
    return 1;
}

/* BIP340 Sign(sk, m, a): 64-byte signature. Messages may be any length.
 * Returns 1, or 0 for an invalid key or a (negligible) zero nonce. */
int bip340_sign(u8 sig[64], const u8* msg, unsigned long msglen, const u8 priv_be[32], const u8 aux[32]){
    /* every secret lives in this frame and is wiped on every exit (CRY-3) */
    uint64_t d0[4], d[4], J[12], k0r[4], k0[4], k[4], R[12], er[4], e[4], ed[4], s[4];
    u8 px[32], dbe[32], t[32], kh[32], rx[32], eh[32];
    int podd, rodd, ok = 0;
    be32_to_limbs(d0, priv_be);
    if (is_zero(d0) || limb_cmp(d0, N_LIMBS) >= 0) goto out;
    point_scalar_mul_gen_ct(J, d0);
    jac_to_x_parity(px, &podd, J);
    cneg_n(d, d0, podd);
    limbs_to_be32(dbe, d);
    /* t = d xor TaggedHash("BIP0340/aux", a) */
    if (!tagged(t, "BIP0340/aux", aux, 32, NULL, 0, NULL, 0)) goto out;
    for (int i = 0; i < 32; i++) t[i] ^= dbe[i];
    /* k0 = int(TaggedHash("BIP0340/nonce", t || P || m)) mod n */
    if (!tagged(kh, "BIP0340/nonce", t, 32, px, 32, msg, msglen)) goto out;
    be32_to_limbs(k0r, kh); reduce_n(k0, k0r);
    if (is_zero(k0)) goto out;
    point_scalar_mul_gen_ct(R, k0);
    jac_to_x_parity(rx, &rodd, R);
    cneg_n(k, k0, rodd);
    /* e = int(TaggedHash("BIP0340/challenge", R || P || m)) mod n */
    if (!tagged(eh, "BIP0340/challenge", rx, 32, px, 32, msg, msglen)) goto out;
    be32_to_limbs(er, eh); reduce_n(e, er);
    /* s = (k + e*d) mod n */
    sc_mul(ed, e, d); sc_add(s, k, ed);
    ok = self_verify(J, rx, e, s);                     /* CRY-2: fail closed */
    if (ok){ memcpy(sig, rx, 32); limbs_to_be32(sig + 32, s); }
out:
    if (!ok) memset(sig, 0, 64);
    secure_zero(d0, sizeof d0); secure_zero(d, sizeof d); secure_zero(dbe, sizeof dbe);
    secure_zero(t, sizeof t); secure_zero(kh, sizeof kh); secure_zero(k0r, sizeof k0r);
    secure_zero(k0, sizeof k0); secure_zero(k, sizeof k); secure_zero(R, sizeof R);
    secure_zero(ed, sizeof ed);
    return ok;
}

/* the BIP341 key-path signing key for internal key `priv` under `tweak`
 * (TapTweak(P || root)): d' = (d if P even else n-d) + t mod n. Returns 1,
 * or 0 for a bad key/tweak. */
int bip340_tweak_privkey(u8 out_priv[32], const u8 priv_be[32], const u8 tweak[32]){
    uint64_t d0[4], d[4], J[12], t[4], r[4]; int ok = 0;
    be32_to_limbs(d0, priv_be);
    if (is_zero(d0) || limb_cmp(d0, N_LIMBS) >= 0) goto out;
    point_scalar_mul_gen_ct(J, d0);
    u8 px[32]; int podd; jac_to_x_parity(px, &podd, J);
    cneg_n(d, d0, podd);
    be32_to_limbs(t, tweak); if (limb_cmp(t, N_LIMBS) >= 0) goto out;
    sc_add(r, d, t); if (is_zero(r)) goto out;
    limbs_to_be32(out_priv, r);
    ok = 1;
out:
    secure_zero(d0, sizeof d0); secure_zero(d, sizeof d); secure_zero(r, sizeof r);
    return ok;
}
