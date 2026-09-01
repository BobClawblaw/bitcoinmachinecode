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
typedef unsigned char u8;
extern void sha256_full(u8 out[32], const void* msg, unsigned long len);
extern void point_scalar_mul_ct(uint64_t r[12], const uint64_t xy[8], const uint64_t k[4]);
extern void fe_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
extern void fe_sqr(uint64_t r[4], const uint64_t a[4]);
extern void fe_inv(uint64_t r[4], const uint64_t a[4]);
extern void sc_add(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
extern void sc_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);

static const uint64_t N_LIMBS[4] = { 0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL, 0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL };
static const uint64_t G_AFF[8] = {
    0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL, 0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL,
    0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL, 0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL };

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
/* r = a mod n for a < 2n (a sha256 output or a 256-bit key) */
static void reduce_n(uint64_t r[4], const uint64_t a[4]){
    memcpy(r, a, 32);
    if (limb_cmp(r, N_LIMBS) >= 0){
        uint64_t c = 0;
        for (int i = 0; i < 4; i++){ uint64_t s = r[i] - N_LIMBS[i] - c; c = (r[i] < N_LIMBS[i] + c) ? 1 : 0; r[i] = s; }
    }
}
/* r = n - a  (a in [1, n)) */
static void neg_n(uint64_t r[4], const uint64_t a[4]){
    uint64_t c = 0;
    for (int i = 0; i < 4; i++){ uint64_t s = N_LIMBS[i] - a[i] - c; c = (N_LIMBS[i] < a[i] + c) ? 1 : 0; r[i] = s; }
}
/* affine (x, y-parity) of a Jacobian point */
static void jac_to_x_parity(u8 x32[32], int* odd, const uint64_t J[12]){
    uint64_t z2[4], z3[4], zi2[4], zi3[4], x[4], y[4];
    fe_sqr(z2, J + 8); fe_mul(z3, z2, J + 8);
    fe_inv(zi2, z2); fe_inv(zi3, z3);
    fe_mul(x, J, zi2); fe_mul(y, J + 4, zi3);
    limbs_to_be32(x32, x); *odd = (int)(y[0] & 1);
}
static void tagged(u8 out[32], const char* tag, const u8* a, unsigned long al, const u8* b, unsigned long bl, const u8* c, unsigned long cl){
    u8 th[32]; sha256_full(th, tag, strlen(tag));
    u8 buf[64 + 32 + 32 + 4096]; unsigned long n = 0;
    if (al + bl + cl > sizeof buf - 64) return;
    memcpy(buf, th, 32); memcpy(buf + 32, th, 32); n = 64;
    memcpy(buf + n, a, al); n += al;
    if (b){ memcpy(buf + n, b, bl); n += bl; }
    if (c){ memcpy(buf + n, c, cl); n += cl; }
    sha256_full(out, buf, n);
}

/* x-only public key of a private key, and whether its Y was odd (the
 * caller negates the key for signing then, as BIP340 does) */
int bip340_pubkey(u8 xonly[32], const u8 priv_be[32]){
    uint64_t d[4], J[12]; be32_to_limbs(d, priv_be);
    if (is_zero(d) || limb_cmp(d, N_LIMBS) >= 0) return 0;
    point_scalar_mul_ct(J, G_AFF, d);
    int odd; jac_to_x_parity(xonly, &odd, J);
    return 1;
}

/* BIP340 Sign(sk, m, a): 64-byte signature. Messages may be any length.
 * Returns 1, or 0 for an invalid key or a (negligible) zero nonce. */
int bip340_sign(u8 sig[64], const u8* msg, unsigned long msglen, const u8 priv_be[32], const u8 aux[32]){
    uint64_t d0[4], d[4], J[12]; be32_to_limbs(d0, priv_be);
    if (is_zero(d0) || limb_cmp(d0, N_LIMBS) >= 0) return 0;
    point_scalar_mul_ct(J, G_AFF, d0);
    u8 px[32]; int podd; jac_to_x_parity(px, &podd, J);
    if (podd) neg_n(d, d0); else memcpy(d, d0, 32);
    u8 dbe[32]; limbs_to_be32(dbe, d);
    /* t = d xor TaggedHash("BIP0340/aux", a) */
    u8 t[32]; tagged(t, "BIP0340/aux", aux, 32, NULL, 0, NULL, 0);
    for (int i = 0; i < 32; i++) t[i] ^= dbe[i];
    /* k0 = int(TaggedHash("BIP0340/nonce", t || P || m)) mod n */
    u8 kh[32]; tagged(kh, "BIP0340/nonce", t, 32, px, 32, msg, msglen);
    uint64_t k0r[4], k0[4]; be32_to_limbs(k0r, kh); reduce_n(k0, k0r);
    if (is_zero(k0)) return 0;
    uint64_t R[12]; point_scalar_mul_ct(R, G_AFF, k0);
    u8 rx[32]; int rodd; jac_to_x_parity(rx, &rodd, R);
    uint64_t k[4]; if (rodd) neg_n(k, k0); else memcpy(k, k0, 32);
    /* e = int(TaggedHash("BIP0340/challenge", R || P || m)) mod n */
    u8 eh[32]; tagged(eh, "BIP0340/challenge", rx, 32, px, 32, msg, msglen);
    uint64_t er[4], e[4]; be32_to_limbs(er, eh); reduce_n(e, er);
    /* s = (k + e*d) mod n */
    uint64_t ed[4], s[4]; sc_mul(ed, e, d); sc_add(s, k, ed);
    memcpy(sig, rx, 32); limbs_to_be32(sig + 32, s);
    return 1;
}

/* the BIP341 key-path signing key for internal key `priv` under `tweak`
 * (TapTweak(P || root)): d' = (d if P even else n-d) + t mod n. Returns 1,
 * or 0 for a bad key/tweak. */
int bip340_tweak_privkey(u8 out_priv[32], const u8 priv_be[32], const u8 tweak[32]){
    uint64_t d0[4], d[4], J[12], t[4], r[4]; be32_to_limbs(d0, priv_be);
    if (is_zero(d0) || limb_cmp(d0, N_LIMBS) >= 0) return 0;
    point_scalar_mul_ct(J, G_AFF, d0);
    u8 px[32]; int podd; jac_to_x_parity(px, &podd, J);
    if (podd) neg_n(d, d0); else memcpy(d, d0, 32);
    be32_to_limbs(t, tweak); if (limb_cmp(t, N_LIMBS) >= 0) return 0;
    sc_add(r, d, t); if (is_zero(r)) return 0;
    limbs_to_be32(out_priv, r);
    return 1;
}
