/* crypto_ellswift_ecdh.c -- the BIP324 v2 handshake key agreement.
 *
 * Both sides send a 64-byte ElligatorSwift encoding of their ephemeral public
 * key. Each then computes the x-coordinate of (their point * our secret) and
 * hashes it together with BOTH encodings, in a fixed initiator-then-responder
 * order, to get the 32-byte ECDH secret that seeds the session keys.
 *
 * Two details are easy to get wrong and both are silent:
 *
 *  1. THE ORDER IS BY ROLE, NOT BY WHO IS COMPUTING. The hash always eats the
 *     initiator's encoding first. So the two peers, who hold the same two
 *     64-byte strings in opposite local roles, must sort them the same way or
 *     they derive different secrets and the handshake fails with no clue as to
 *     why. That is why `initiating` is a parameter rather than something
 *     inferred here.
 *
 *  2. THE Y COORDINATE DOES NOT MATTER. Decoding gives only x, and lifting it
 *     picks one of the two possible points. The other is its negation, and
 *     negating a point negates only y, so k*P and k*(-P) share an
 *     x-coordinate. This is a genuine x-only ECDH; the lift's sign choice
 *     cannot make the two peers disagree.
 *
 * The scalar multiply uses point_scalar_mul_ct, the constant-time ladder, not
 * the faster windowed one: the scalar here is a private key.
 */
#include <string.h>
#include "crypto_ellswift.h"
#include "crypto_fe_sqrt.h"

typedef unsigned long long u64;
typedef u64 fe4[4];

extern void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sqr(u64 r[4], const u64 a[4]);
extern void fe_add(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_inv(u64 r[4], const u64 a[4]);
extern void point_scalar_mul_ct(u64 r[12], const u64 xy[8], const u64 k[4]);
extern void sha256_full(unsigned char* out, const void* msg, long long len);

/* group order n, for the range check on the secret key */
static const u64 ORDER_N[4] = {
    0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL,
    0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL
};

/* 32 big-endian bytes -> 4 little-endian limbs, WITHOUT reducing.
 *
 * Deliberately not ellswift_be32_to_fe: that one reduces mod p, which is
 * correct for the field elements u and t (BIP324 says to reduce them) and
 * badly wrong for a secret key. A key of 0xff..ff is above the group order
 * and must be REFUSED; reduced mod p it becomes a small number that passes
 * every range check and yields a public key no other implementation agrees
 * with. Scalars and field elements are different types living in the same
 * 32 bytes, and this is where they part company. */
static void be32_to_scalar(u64 r[4], const unsigned char b[32]){
    for (int i = 0; i < 4; i++){
        u64 v = 0;
        for (int j = 0; j < 8; j++) v = (v << 8) | b[i * 8 + j];
        r[3 - i] = v;
    }
}

static int scalar_in_range(const u64 k[4]){
    if (fe_is_zero(k)) return 0;                 /* 0 is not a valid key */
    for (int i = 3; i >= 0; i--){                /* k < n ? */
        if (k[i] < ORDER_N[i]) return 1;
        if (k[i] > ORDER_N[i]) return 0;
    }
    return 0;                                    /* k == n */
}

/* x -> a point on the curve. Either root works (see note 2 above), so the
 * one fe_sqrt returns is taken as-is. 0 if x is not on the curve, which
 * cannot happen for a decoded ellswift but is checked rather than assumed. */
static int lift_x(fe4 y, const fe4 x){
    fe4 t, seven;
    memset(seven, 0, sizeof seven); seven[0] = 7;
    fe_sqr(t, x); fe_mul(t, t, x); fe_add(t, t, seven);   /* x^3 + 7 */
    return fe_sqrt(y, t);
}

/* Jacobian (X,Y,Z) -> affine x = X/Z^2. 0 at infinity. */
static int jac_x(fe4 x, const u64 J[12]){
    fe4 z, zi, zi2;
    memcpy(z, J + 8, 32);
    if (fe_is_zero(z)) return 0;
    fe_inv(zi, z);
    fe_sqr(zi2, zi);
    fe_mul(x, (const u64*)J, zi2);
    return 1;
}

/* SHA256("bip324_ellswift_xonly_ecdh" tagged) over ell_a || ell_b || x.
 * Spelled as the plain BIP340 construction -- SHA256(H(tag) || H(tag) || m) --
 * rather than a hardcoded midstate, so there is no constant to mistranscribe. */
static void ecdh_tagged_hash(unsigned char out[32],
                             const unsigned char ell_a64[64],
                             const unsigned char ell_b64[64],
                             const unsigned char x32[32]){
    static const char TAG[] = "bip324_ellswift_xonly_ecdh";
    unsigned char th[32], buf[64 + 64 + 64 + 32];
    sha256_full(th, TAG, (long long)(sizeof TAG - 1));
    memcpy(buf, th, 32);
    memcpy(buf + 32, th, 32);
    memcpy(buf + 64, ell_a64, 64);
    memcpy(buf + 128, ell_b64, 64);
    memcpy(buf + 192, x32, 32);
    sha256_full(out, buf, (long long)sizeof buf);
    memset(buf, 0, sizeof buf);
}


static const u64 G_AFF[8] = {
    0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL, 0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL,
    0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL, 0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL
};

/* Our side of the handshake: the 64-byte encoding of seckey*G that we put on
 * the wire. `rnd` picks which of the many valid encodings we send; passing
 * NULL yields a deterministic one, which is fine for tests but NOT for the
 * wire -- on a real connection the encoding is the thing an observer sees, so
 * it has to come from a CSPRNG or the traffic stops being indistinguishable.
 * Returns 1 on success. */
int ellswift_create(unsigned char ellswift64[64],
                    const unsigned char seckey32[32],
                    const unsigned char* rnd, unsigned long rndlen){
    u64 k[4], J[12], x[4];
    be32_to_scalar(k, seckey32);
    if (!scalar_in_range(k)) return 0;
    point_scalar_mul_ct(J, G_AFF, k);
    memset(k, 0, sizeof k);
    if (!jac_x(x, J)) return 0;
    return ellswift_encode_x(ellswift64, x, rnd, rndlen);
}

/* The BIP324 ECDH. `initiating` is this node's role, and it is what decides
 * the hash order -- see note 1. Returns 1 on success, 0 if our secret key is
 * out of range or their encoding somehow yields no curve point. */
int ellswift_ecdh(unsigned char out32[32],
                  const unsigned char their_ellswift64[64],
                  const unsigned char our_ellswift64[64],
                  const unsigned char our_seckey32[32],
                  int initiating){
    u64 k[4], x[4], y[4], J[12];
    unsigned char xb[32];

    be32_to_scalar(k, our_seckey32);
    if (!scalar_in_range(k)) return 0;

    ellswift_decode(xb, their_ellswift64);
    ellswift_be32_to_fe(x, xb);
    if (!lift_x(y, x)){ memset(k, 0, sizeof k); return 0; }

    { u64 aff[8];
      memcpy(aff, x, 32); memcpy(aff + 4, y, 32);
      point_scalar_mul_ct(J, aff, k); }
    memset(k, 0, sizeof k);
    if (!jac_x(x, J)) return 0;                  /* our key times their point
                                                  * is infinity only if their
                                                  * point had order dividing
                                                  * our key -- impossible on a
                                                  * prime-order curve, but a
                                                  * corrupt input reaches here */
    ellswift_fe_to_be32(xb, x);

    if (initiating) ecdh_tagged_hash(out32, our_ellswift64, their_ellswift64, xb);
    else            ecdh_tagged_hash(out32, their_ellswift64, our_ellswift64, xb);
    memset(xb, 0, sizeof xb);
    return 1;
}
