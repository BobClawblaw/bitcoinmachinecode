/* ============================================================================
 * pubkey_schnorr_twin.c -- secp256k1 pubkey parse + BIP340 Schnorr verify
 * for the macOS/AArch64 port.  Functional twins of asm/bitcoin_pubkey.asm
 * and asm/secp256k1_schnorr.asm (branch bmc_osx).
 *
 *   int pubkey_parse(const u8 *pub, unsigned long publen,
 *                    u64 qx[4], u64 qy[4]);
 *   int  schnorr_verify(const u8 sig[64], const u8 pub_xonly[32],
 *                       const u8 *msg, int msglen);
 *   void fe_pow(u64 out[4], const u64 base[4], const u64 exp[4]);
 *
 * Transcribed from the x86 listings; fe_pow is the x86 square-and-multiply
 * over bits 255..0 of a little-endian exponent.
 * -------------------------------------------------------------------------- */
#include <stdint.h>
#include <string.h>
#include <stdio.h>

typedef uint64_t u64;
typedef unsigned __int128 u128;
typedef unsigned char u8;

void fe_sqr(u64 r[4], const u64 a[4]);
void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
void fe_add(u64 r[4], const u64 a[4], const u64 b[4]);
void fe_sub(u64 r[4], const u64 a[4], const u64 b[4]);
void fe_inv(u64 r[4], const u64 a[4]);
void sha256_full(u8 *out, const u8 *in, unsigned long len);
void point_scalar_mul(u64 r[12], const u64 xy[8], const u64 k[4]);
void point_scalar_mul_fixed(u64 r[12], const u64 k[4]);
void point_scalar_mul_glv(u64 r[12], const u64 xy[8], const u64 k[4]);
void point_add(u64 r[12], const u64 p[12], const u64 q[12]);
int  bmc_ecdsa_glv_enabled(void);

static const u64 P_LIMBS[4]  = { 0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL, \
                                 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL };
static const u64 N_LIMBS[4]  = {
    0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL,
    0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL
};
/* (p+1)/4, the QR exponent for p = 3 mod 4 */
static const u64 EXP_QR[4]   = {
    0xFFFFFFFFBFFFFF0CULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0x3FFFFFFFFFFFFFFFULL
};
static const u64 CURVE7[4]   = { 7, 0, 0, 0 };

/* ---- fe_pow: out = base^exp (mod p), exp little-endian 256-bit ---------- */
void fe_pow(u64 out[4], const u64 base[4], const u64 exp[4])
{
    u64 acc[4] = { 1, 0, 0, 0 };
    for (int bit = 255; bit >= 0; bit--) {
        u64 t[4];
        fe_sqr(t, acc);
        memcpy(acc, t, 32);
        if ((exp[bit >> 6] >> (bit & 63)) & 1) {
            fe_mul(t, acc, base);
            memcpy(acc, t, 32);
        }
    }
    memcpy(out, acc, 32);
}

/* 1 iff x < p (limb compare, x86-faithful ja/jb ladder) */
static int lt_p(const u64 x[4])
{
    if (x[3] != P_LIMBS[3]) return x[3] < P_LIMBS[3];
    if (x[2] != P_LIMBS[2]) return x[2] < P_LIMBS[2];
    if (x[1] != P_LIMBS[1]) return x[1] < P_LIMBS[1];
    return x[0] < P_LIMBS[0];
}

/* load 32 BE bytes into 4 LE limbs */
static void load_be(u64 d[4], const u8 *src)
{
    for (int i = 0; i < 4; i++) {
        u64 v = 0;
        for (int b = 0; b < 8; b++)
            v = (v << 8) | src[(3 - i) * 8 + b];
        d[i] = v;
    }
}

int pubkey_parse(const u8 *pub, unsigned long publen, u64 qx[4], u64 qy[4])
{
    u64 x[4], rhs[4], y[4], t[4];

    if (publen == 33) {
        if (pub[0] != 0x02 && pub[0] != 0x03) return 0;
        load_be(x, pub + 1);
        if (!lt_p(x)) return 0;
        /* rhs = x^3 + 7 */
        fe_sqr(t, x);
        fe_mul(rhs, t, x);
        fe_add(rhs, rhs, CURVE7);
        /* y = rhs^((p+1)/4) */
        fe_pow(y, rhs, EXP_QR);
        /* verify y^2 == rhs */
        fe_sqr(t, y);
        if (t[0] != rhs[0] || t[1] != rhs[1] ||
            t[2] != rhs[2] || t[3] != rhs[3]) return 0;
        /* match parity: y or p-y (x86 sbb chain: p - y with borrow) */
        if ((y[0] & 1) != (u64)(pub[0] & 1)) {
            u64 borrow = 0, v[4];
            for (int i = 0; i < 4; i++) {
                u128 s = (u128)P_LIMBS[i] - y[i] - borrow;
                v[i] = (u64)s;
                borrow = (u64)((s >> 64) & 1);
            }
            memcpy(y, v, 32);
        }
        memcpy(qx, x, 32);
        memcpy(qy, y, 32);
        return 1;
    }
    if (publen == 65) {
        if (pub[0] != 0x04) return 0;
        load_be(x, pub + 1);
        load_be(y, pub + 33);
        if (!lt_p(x) || !lt_p(y)) return 0;
        fe_sqr(t, x);
        fe_mul(rhs, t, x);
        fe_add(rhs, rhs, CURVE7);
        fe_sqr(t, y);
        if (t[0] != rhs[0] || t[1] != rhs[1] ||
            t[2] != rhs[2] || t[3] != rhs[3]) return 0;
        memcpy(qx, x, 32);
        memcpy(qy, y, 32);
        return 1;
    }
    return 0;
}


/* ---- BIP340 tagged hash: SHA256(SHA256(tag)||SHA256(tag)||data) --------- */
static void tagged_hash(const char *tag, unsigned long taglen,
                        const unsigned char *data, unsigned long datalen, unsigned char out[32])
{
    unsigned char th[32], pre[128 + 192];
    sha256_full(th, (const unsigned char *)tag, taglen);
    memcpy(pre, th, 32);
    memcpy(pre + 32, th, 32);
    memcpy(pre + 64, data, datalen);
    sha256_full(out, pre, 64 + datalen);
}

static const char CHALLENGE_TAG[] = "BIP0340/challenge";

/* forward decl of the x-eq-r helper (defined below) */
static int schnorr_x_eq_r_pub(const u64 r[4], const u64 X[4], const u64 Z[4]);

int schnorr_verify(const unsigned char sig[64], const unsigned char pub_xonly[32],
                   const unsigned char *msg, int msglen)
{
    u64 rL[4], sL[4], eL[4];
    u64 P_aff[8];
    u64 SG[12], EP[12], RPT[12];
    u64 z3[4], zi[4], yr[4];
    unsigned char pre[128 + 192];
    unsigned char digest[32];
    unsigned char keyscr[33];

    if (msglen < 0 || (unsigned long)msglen > 192) return 0;

    /* P = lift_x(pk) via pubkey_parse([0x02||pk], 33, ...) */
    keyscr[0] = 0x02;
    memcpy(keyscr + 1, pub_xonly, 32);
    if (!pubkey_parse(keyscr, 33, P_aff, P_aff + 4)) return 0;

    load_be(rL, sig);               /* r = BE bytes 0..31 */
    load_be(sL, sig + 32);          /* s = BE bytes 32..63 */
    if (!lt_p(rL)) return 0;        /* r >= p -> invalid */
    /* s >= n -> invalid */
    if (sL[3] != N_LIMBS[3]) { if (sL[3] > N_LIMBS[3]) return 0; }
    else if (sL[2] != N_LIMBS[2]) { if (sL[2] > N_LIMBS[2]) return 0; }
    else if (sL[1] != N_LIMBS[1]) { if (sL[1] > N_LIMBS[1]) return 0; }
    else if (sL[0] >= N_LIMBS[0]) return 0;

    /* e = int(tagged_hash("BIP0340/challenge", r || P.x || m)) mod n */
    memcpy(pre, sig, 32);           /* r BE */
    memcpy(pre + 32, pub_xonly, 32);
    memcpy(pre + 64, msg, (unsigned long)msglen);
    tagged_hash(CHALLENGE_TAG, sizeof(CHALLENGE_TAG) - 1, pre,
                64 + (unsigned long)msglen, digest);
    load_be(eL, digest);
    /* reduce e mod n: e -= n if e >= n (e < 2^256 < 2n) */
    {
        u64 borrow = 0, v[4];
        int ge = 1;
        for (int i = 3; i >= 0; i--) {
            if (eL[i] != N_LIMBS[i]) { ge = eL[i] > N_LIMBS[i]; break; }
        }
        if (ge) {
            for (int i = 0; i < 4; i++) {
                u128 t = (u128)eL[i] - N_LIMBS[i] - borrow;
                v[i] = (u64)t;
                borrow = (u64)((t >> 64) & 1);
            }
            memcpy(eL, v, 32);
        }
    }

    point_scalar_mul_fixed(SG, sL);          /* SG = s*G (restored: the debug
                                                block removal had swallowed
                                                the real call) */
    if (bmc_ecdsa_glv_enabled())
        point_scalar_mul_glv(EP, P_aff, eL);
    else
        point_scalar_mul(EP, P_aff, eL);

    /* R = sG - eP : negate EP's Y (p - y) if not infinity */
    if ((EP[5] | EP[6] | EP[7]) != 0) {
        u64 borrow = 0, v[4];
        for (int i = 0; i < 4; i++) {
            u128 t = (u128)P_LIMBS[i] - EP[4 + i] - borrow;
            v[i] = (u64)t;
            borrow = (u64)((t >> 64) & 1);
        }
        memcpy(EP + 4, v, 32);
    }
    point_add(RPT, SG, EP);
    if ((RPT[8] | RPT[9] | RPT[10] | RPT[11]) == 0) return 0;

    if (!schnorr_x_eq_r_pub(rL, RPT, RPT + 8)) return 0;

    /* y(R) must be even: yr = Y * Z^{-3}; test bit 0 */
    fe_inv(zi, RPT + 8);
    fe_sqr(z3, zi);
    fe_mul(z3, z3, zi);
    fe_mul(yr, RPT + 4, z3);
    if (yr[0] & 1) return 0;

    return 1;
}

/* x(R) == r (mod n), projective: r*Z^2 == X (mod p) */
static int schnorr_x_eq_r_pub(const u64 r[4], const u64 X[4], const u64 Z[4])
{
    u64 t[4], lhs[4];
    fe_sqr(t, Z);
    fe_mul(lhs, r, t);
    return lhs[0] == X[0] && lhs[1] == X[1] &&
           lhs[2] == X[2] && lhs[3] == X[3];
}
