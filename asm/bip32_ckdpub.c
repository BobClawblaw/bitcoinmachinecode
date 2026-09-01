/* bip32_ckdpub.c -- BIP32 public child key derivation (CKDpub), the crypto
 * kernel behind deriveaddresses/getdescriptorinfo for xpub-keyed descriptors.
 *
 * Given a parent extended PUBLIC key (xpub), derive a non-hardened child
 * public key without any private material:
 *   I  = HMAC-SHA512(key = chaincode, data = ser33(K_par) || ser32be(i))
 *   IL = I[0..31] (big-endian scalar < n),  IR = I[32..63] = child chaincode
 *   K_i = point(IL)*G + K_par        (elliptic-curve point addition)
 *
 * This is C glue over the project's verified asm field/point primitives
 * (fe_mul/fe_sqr/fe_inv, point_scalar_mul_ct, point_add, hmac_sha512), the
 * same primitives wallet_msgsign.c uses for pubkey recovery. The fe_* helpers
 * (fe_sqrt/fe_neg/jac_to_aff/decompress) are duplicated here rather than shared
 * so this module stays self-contained and does not perturb wallet_msgsign.c's
 * verified linkage. Verified end-to-end against Bitcoin Core's own
 * deriveaddresses (BIP32 test-vector-1 xpub) in tests/test_bip32_ckdpub.c.
 * ====================================================================== */
#include <stdint.h>
#include <string.h>

extern void fe_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
extern void fe_sqr(uint64_t r[4], const uint64_t a[4]);
extern void fe_inv(uint64_t r[4], const uint64_t a[4]);
extern void point_scalar_mul_ct(uint64_t r[12], const uint64_t xy[8], const uint64_t k[4]);
extern void point_add(uint64_t r[12], const uint64_t p[12], const uint64_t q[12]);
extern void hmac_sha512(unsigned char out[64], const void* key, long long keylen,
                        const void* data, long long datalen);
extern int  wallet_base58check_decode(unsigned char* out, long cap, long* outlen, const char* str);

/* secp256k1 domain constants (little-endian limbs). p = 2^256-2^32-977. */
static const uint64_t P_FE[4] = {
    0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL };
/* group order n. */
static const uint64_t N_SC[4] = {
    0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL,
    0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL };
/* generator G affine (X,Y). */
static const uint64_t G_X[4] = {
    0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL,
    0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL };
static const uint64_t G_Y[4] = {
    0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL,
    0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL };

static int  fe_is_zero(const uint64_t a[4]){ return (a[0]|a[1]|a[2]|a[3])==0; }
static void fe_cpy(uint64_t r[4], const uint64_t a[4]){ memcpy(r,a,32); }
static int  fe_eq(const uint64_t a[4], const uint64_t b[4]){ return memcmp(a,b,32)==0; }
static void fe_set1(uint64_t r[4]){ r[0]=1; r[1]=r[2]=r[3]=0; }
static void fe_set0(uint64_t r[4]){ r[0]=r[1]=r[2]=r[3]=0; }

/* mod-p sqrt: p == 3 (mod 4) => sqrt(a) = a^{(p+1)/4}. Returns -1 if a is a
 * non-residue (no root). Identical to wallet_msgsign.c's fe_sqrt. */
static int fe_sqrt(uint64_t r[4], const uint64_t a[4]){
    uint64_t e[4];
    unsigned long long carry;
    e[0] = P_FE[0] + 1ULL; carry = (e[0] < 1ULL);
    e[1] = P_FE[1] + carry; carry = (e[1] < carry) ? 0 : (e[1] == 0 && carry);
    e[2] = P_FE[2] + carry; carry = (e[2] < carry) ? 0 : (e[2] == 0 && carry);
    e[3] = P_FE[3] + carry;
    for (int i = 0; i < 4; i++){
        uint64_t hi = (i+1 < 4) ? (e[i+1] << 62) : 0;
        e[i] = (e[i] >> 2) | hi;
    }
    uint64_t res[4], base[4];
    fe_cpy(base, a); fe_set1(res);
    for (int bit = 255; bit >= 0; bit--){
        uint64_t b = (e[bit/64] >> (bit%64)) & 1;
        fe_sqr(res, res);
        if (b) fe_mul(res, res, base);
    }
    uint64_t chk[4]; fe_sqr(chk, res);
    if (!fe_eq(chk, a)) return -1;
    fe_cpy(r, res);
    return 0;
}
/* r = p - a (mod p); -0 == 0. */
static void fe_neg(uint64_t r[4], const uint64_t a[4]){
    unsigned long long bb = 0;
    for (int i = 0; i < 4; i++){
        unsigned long long ai = a[i], pi = P_FE[i];
        unsigned long long d = (pi - ai) - bb;
        r[i] = (uint64_t)d;
        bb = (pi < ai + bb) ? 1 : 0;
    }
    if (bb) fe_set0(r);
}
/* Jacobian (X,Y,Z: 12 limbs) -> affine x,y. 0 ok, -1 if point at infinity. */
static int jac_to_aff(uint64_t fx[4], uint64_t fy[4], const uint64_t J[12]){
    uint64_t Z[4] = {J[8],J[9],J[10],J[11]};
    if (fe_is_zero(Z)) return -1;
    uint64_t zi[4], zi2[4], zi3[4];
    fe_inv(zi, Z); fe_sqr(zi2, zi); fe_mul(zi3, zi2, zi);
    fe_mul(fx, J, zi2); fe_mul(fy, J+4, zi3);
    return 0;
}

/* 32 big-endian bytes -> 4 ascending little-endian limbs. */
static void be32_to_limbs(uint64_t k[4], const unsigned char b[32]){
    for (int i = 0; i < 4; i++){
        const unsigned char* p = b + (3 - i) * 8;
        uint64_t v = 0;
        for (int j = 0; j < 8; j++) v = (v << 8) | p[j];
        k[i] = v;
    }
}
/* 0 <= a < n ? (a,n as LE limbs) */
static int lt_n(const uint64_t a[4]){
    for (int i = 3; i >= 0; i--){ if (a[i] != N_SC[i]) return a[i] < N_SC[i]; }
    return 0;  /* equal -> not < */
}
/* compress affine (Xk,Yk limbs) -> SEC1 33 bytes: [02|03][x big-endian]. */
static void comp_from_aff(unsigned char out[33], const uint64_t Xk[4], const uint64_t Yk[4]){
    out[0] = (unsigned char)(0x02 | (Yk[0] & 1));
    for (int i = 0; i < 32; i++)
        out[1+i] = (unsigned char)(Xk[3 - i/8] >> (8 * (7 - i%8)));
}
/* decompress SEC1 33-byte pubkey -> affine limbs (Xk,Yk). 0 ok, -1 invalid. */
static int decompress(const unsigned char pub[33], uint64_t Xk[4], uint64_t Yk[4]){
    if (pub[0] != 0x02 && pub[0] != 0x03) return -1;
    be32_to_limbs(Xk, pub + 1);
    /* Xk must be < p */
    { int ge = 0; for (int i = 3; i >= 0; i--) if (Xk[i] != P_FE[i]){ ge = Xk[i] > P_FE[i]; break; } if (ge) return -1; }
    /* alpha = X^3 + 7 (mod p) */
    uint64_t x2[4], x3[4], alpha[4], seven[4] = {7,0,0,0};
    fe_sqr(x2, Xk); fe_mul(x3, x2, Xk);
    unsigned long long cc = 0;
    for (int i = 0; i < 4; i++){
        uint64_t ai = x3[i], bi = seven[i], ci = cc;
        uint64_t s1 = ai + bi; uint64_t c1 = (s1 < ai);
        uint64_t s2 = s1 + ci;  uint64_t c2 = (s2 < ci);
        cc = c1 | c2; alpha[i] = s2;
    }
    if (cc){ /* alpha >= 2^256: reduce by 2^256 mod p = 2^32+977 */
        uint64_t corr = ((uint64_t)cc) * 0x1000003D1ULL, k = 0;
        unsigned long long c3 = 0;
        for (int i = 0; i < 4; i++){
            uint64_t ai = alpha[i], bi = (i==0?corr:0)+k, ci = c3;
            uint64_t s1 = ai + bi; uint64_t d1 = (s1 < ai);
            uint64_t s2 = s1 + ci; uint64_t d2 = (s2 < ci);
            c3 = d1 | d2; alpha[i] = s2; k = 0;
        }
    }
    { int ge = 0; for (int i = 3; i >= 0; i--) if (alpha[i] != P_FE[i]){ ge = alpha[i] > P_FE[i]; break; }
      if (ge){ uint64_t bw = 0; for (int i = 0; i < 4; i++){ uint64_t cur = alpha[i], sub = P_FE[i] + bw; alpha[i] = cur - sub; bw = (cur < sub); } } }
    uint64_t y[4];
    if (fe_sqrt(y, alpha) != 0) return -1;
    unsigned yodd = (unsigned)(y[0] & 1);
    if ((yodd ^ (unsigned)(pub[0] & 1)) != 0) fe_neg(y, y);
    fe_cpy(Yk, y);
    return 0;
}

/* Parse & validate a mainnet xpub. Fills pub33 (compressed key) and cc32
 * (chaincode). Returns 1 on success, 0 if not a valid xpub. */
int bip32_xpub_parse(const char* xpub_b58, unsigned char pub33[33], unsigned char cc32[32]){
    unsigned char dec[128]; long dl = 0;
    if (!wallet_base58check_decode(dec, sizeof dec, &dl, xpub_b58)) return 0;
    if (dl != 78) return 0;
    /* version: 0x0488B21E = mainnet xpub */
    if (!(dec[0]==0x04 && dec[1]==0x88 && dec[2]==0xB2 && dec[3]==0x1E)) return 0;
    if (dec[45] != 0x02 && dec[45] != 0x03) return 0;   /* key must be compressed pub */
    memcpy(cc32, dec + 13, 32);
    memcpy(pub33, dec + 45, 33);
    /* the point must be on-curve */
    uint64_t Xk[4], Yk[4];
    if (decompress(pub33, Xk, Yk) != 0) return 0;
    return 1;
}

/* One CKDpub step: (K_par,cc) + index -> (K_child,cc_child). index must be
 * non-hardened (< 2^31). Returns 1 on success, 0 on invalid (IL>=n or
 * resulting point at infinity -- astronomically rare). */
static int ckdpub_step(const unsigned char Kpar[33], const unsigned char ccpar[32],
                       unsigned index, unsigned char Kout[33], unsigned char ccout[32]){
    if (index & 0x80000000u) return 0;                  /* hardened: impossible from xpub */
    unsigned char data[37];
    memcpy(data, Kpar, 33);
    data[33] = (unsigned char)(index >> 24); data[34] = (unsigned char)(index >> 16);
    data[35] = (unsigned char)(index >> 8);  data[36] = (unsigned char)(index);
    unsigned char I[64];
    hmac_sha512(I, ccpar, 32, data, 37);
    uint64_t IL[4];
    be32_to_limbs(IL, I);                               /* IL as scalar */
    if (fe_is_zero(IL) || !lt_n(IL)) return 0;          /* invalid per BIP32 */
    /* point(IL)*G  (Jacobian) */
    uint64_t Gaff[8] = {G_X[0],G_X[1],G_X[2],G_X[3], G_Y[0],G_Y[1],G_Y[2],G_Y[3]};
    uint64_t ILG[12]; point_scalar_mul_ct(ILG, Gaff, IL);
    /* parent point as Jacobian (Z=1) */
    uint64_t Px[4], Py[4];
    if (decompress(Kpar, Px, Py) != 0) return 0;
    uint64_t Pj[12] = {Px[0],Px[1],Px[2],Px[3], Py[0],Py[1],Py[2],Py[3], 1,0,0,0};
    uint64_t Cj[12]; point_add(Cj, ILG, Pj);
    uint64_t Cx[4], Cy[4];
    if (jac_to_aff(Cx, Cy, Cj) != 0) return 0;          /* point at infinity */
    comp_from_aff(Kout, Cx, Cy);
    memcpy(ccout, I + 32, 32);
    return 1;
}

/* Derive a child compressed pubkey from an xpub over `path` (all non-hardened,
 * applied in order). Returns 1 on success (out_pub filled), 0 on failure. */
int bip32_ckdpub_derive(const char* xpub_b58, const unsigned* path, int pathlen,
                        unsigned char out_pub[33]){
    unsigned char K[33], cc[32];
    if (!bip32_xpub_parse(xpub_b58, K, cc)) return 0;
    for (int i = 0; i < pathlen; i++){
        unsigned char Kn[33], ccn[32];
        if (!ckdpub_step(K, cc, path[i], Kn, ccn)) return 0;
        memcpy(K, Kn, 33); memcpy(cc, ccn, 32);
    }
    memcpy(out_pub, K, 33);
    return 1;
}
/* ---- exported steps for the descriptor engine (descriptor.c) ---------- */
int bip32_ckdpub_step_pub(const unsigned char Kpar[33], const unsigned char ccpar[32], unsigned index,
                          unsigned char Kout[33], unsigned char ccout[32]){
    return ckdpub_step(Kpar, ccpar, index, Kout, ccout);
}
int bip32_pubkey_decompress(const unsigned char pub33[33], unsigned char out65[65]){
    uint64_t X[4], Y[4];
    if (decompress(pub33, X, Y) != 0) return 0;
    out65[0] = 0x04;
    for (int i = 0; i < 32; i++){ out65[1+i] = (unsigned char)(X[3 - i/8] >> (8 * (7 - i%8))); out65[33+i] = (unsigned char)(Y[3 - i/8] >> (8 * (7 - i%8))); }
    return 1;
}

/* Q = lift_x(x) + t*G, the BIP341 output key for internal x-only key `x`
 * and tweak `t` (already reduced by the caller's check t < n). Returns 1
 * with Q's x coordinate, 0 if x is not on the curve, t is out of range, or
 * Q is the point at infinity. Plain C over the same field/point kernels as
 * CKDpub: no thread-local scratch, so it links into any thread. */
int bip32_xonly_tweak_add(const unsigned char x[32], const unsigned char t[32], unsigned char out_x[32]){
    unsigned char comp[33]; comp[0] = 0x02; memcpy(comp + 1, x, 32);
    uint64_t Px[4], Py[4];
    if (decompress(comp, Px, Py) != 0) return 0;
    uint64_t T[4]; be32_to_limbs(T, t);
    if (fe_is_zero(T) || !lt_n(T)) return 0;
    uint64_t Gaff[8] = {G_X[0],G_X[1],G_X[2],G_X[3], G_Y[0],G_Y[1],G_Y[2],G_Y[3]};
    uint64_t TG[12]; point_scalar_mul_ct(TG, Gaff, T);
    uint64_t Pj[12] = {Px[0],Px[1],Px[2],Px[3], Py[0],Py[1],Py[2],Py[3], 1,0,0,0};
    uint64_t Qj[12]; point_add(Qj, TG, Pj);
    uint64_t Qx[4], Qy[4];
    if (jac_to_aff(Qx, Qy, Qj) != 0) return 0;
    for (int i = 0; i < 32; i++) out_x[i] = (unsigned char)(Qx[3 - i/8] >> (8 * (7 - i%8)));
    return 1;
}
