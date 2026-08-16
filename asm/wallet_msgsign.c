/*
 * wallet_msgsign.c -- Bitcoin message signing / verification (BIP137 digest).
 *
 * WHY: the wallet CLI could sign TRANSACTIONS but had no way to sign or verify
 * an arbitrary MESSAGE (no signmessage / verifymessage). Message signatures are
 * how a wallet proves ownership of an address/a key for identity and
 * attestation purposes, so this closes that gap using only the project's
 * verified asm primitives.
 *
 * Scheme (self-consistent, uses the BIP137 message-digest so the signed hash is
 * Core-compatible):
 *   digest = double_sha256( "\x18Bitcoin Signed Message:\n"
 *                           || varint(len(message)) || message )
 *   signature = ECDSA(digest) over the secp256k1 private key, serialized as the
 *               64-byte big-endian concatenation r||s (hex, 128 chars).
 *   Verification: recompute the digest, parse the public key, hash160 it (and
 *   if an address is supplied, require the h160 match), then ecdsa_verify.
 *
 * NOTE on Core emission compatibility: Bitcoin Core's signmessage additionally
 * uses signature RECOVERY (to allow verifying from just an address) and base64
 * compact serialization with a recovery-byte. This module intentionally uses a
 * plain r||s serialization signed over the SAME BIP137 digest, which verifies
 * identically and is fully self-consistent; emitting Core's recoverable base64
 * form is a separate increment (requires computing the recovery id). The
 * digest itself is byte-for-byte Core-compatible.
 *
 * ABI (plain C, stdio-only, no new deps beyond the linked asm primitives):
 *   int  msg_sign(const unsigned char priv_be[32], const char* message,
 *                 char sig_b64[?]/hex out, int cap);
 *     -> fills <r||s hex (128 chars)+NUL>. Returns 0 ok, -1 on error.
 *   int  msg_verify(const unsigned char pub[33], const char* message,
 *                   const char* rs_hex, int allow_any_encoding);
 *     -> returns 1 if the r||s signature verifies over the BIP137 digest for
 *        pub, 0 if it does not, -1 on malformed input.
 *   int  msg_match_address(const unsigned char pub[33], const char* address);
 *     -> 1 if hash160(pub) matches the base58check-decoded address.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* linked asm / wallet primitives */
extern void sha256d(unsigned char out[32], const void* msg, long len);
extern void scalar_to_pubkey(unsigned char pub[33], const unsigned char k[32]);
extern void wallet_key_h160(unsigned char h[20], const unsigned char priv_be[32]);
extern int  wallet_ecdsa_sign(uint64_t out_r[4], uint64_t out_s[4],
                              const unsigned char z_be[32],
                              const unsigned char priv_be[32]);
/* verification primitives */
extern int pubkey_parse(const unsigned char* pub, unsigned long publen,
                        uint64_t Qx[4], uint64_t Qy[4]);
extern int ecdsa_verify(const uint64_t z[4], const uint64_t r[4],
                        const uint64_t s[4], const uint64_t Qx[4],
                        const uint64_t Qy[4]);
extern void be_to_limbs(uint64_t out[4], const unsigned char* bytes,
                        unsigned long len);
/* field/point/scalar ops (asm) used by recovery */
extern void fe_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
extern void fe_sqr(uint64_t r[4], const uint64_t a[4]);
extern void fe_inv(uint64_t r[4], const uint64_t a[4]);
extern void sc_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
extern void sc_inv(uint64_t r[4], const uint64_t a[4]);
extern void point_scalar_mul_ct(uint64_t r[12], const uint64_t xy[8],
                                const uint64_t k[4]);
extern void point_add_mixed(uint64_t r[12], const uint64_t p[12],
                            const uint64_t q[8]);
extern void point_add(uint64_t r[12], const uint64_t p[12], const uint64_t q[12]);
typedef unsigned long long u64;

/* ---------------------------------------------------------------- helpers */

/* Compute the BIP137 message digest into out32 (Core-compatible): */
static int msg_digest(unsigned char out32[32], const char* message) {
    size_t mlen = message ? strlen(message) : 0;
    if (mlen > 253) { /* do not bother with multi-byte varints for this tool */
        /* BIP137 uses a varint message length; support up to 65535 for safety */
        if (mlen > 65535) return -1;
    }
    /* prefix: 0x18 ++ "Bitcoin Signed Message:\n" ++ varint(mlen) ++ message */
    unsigned char buf[16 + 2 + 65535];
    size_t n = 0;
    static const char prefix[] = "Bitcoin Signed Message:\n";
    buf[n++] = 0x18;
    memcpy(buf + n, prefix, sizeof prefix - 1); n += sizeof prefix - 1;
    if (mlen < 253) {
        buf[n++] = (unsigned char)mlen;
    } else {
        buf[n++] = 0xfd;
        buf[n++] = (unsigned char)(mlen & 0xff);
        buf[n++] = (unsigned char)((mlen >> 8) & 0xff);
    }
    memcpy(buf + n, message, mlen); n += mlen;
    sha256d(out32, buf, (long)n);
    return 0;
}

/* r,s limbs -> big-endian 32-byte each (mirrors wallet_core limbs_to_be32) */
static void limbs_to_be(unsigned char be[32], const uint64_t v[4]) {
    for (int i = 0; i < 32; i++)
        be[31 - i] = (unsigned char)(v[i / 8] >> ((i % 8) * 8));
}

/* ---------------------------------------------------------------- public */

int msg_sign(const unsigned char priv_be[32], const char* message,
             char rs_hex[129]) {
    unsigned char zbe[32], pub[33];
    uint64_t r[4], s[4];
    if (msg_digest(zbe, message) != 0) return -1;
    wallet_ecdsa_sign(r, s, zbe, priv_be);
    unsigned char rbe[32], sbe[32];
    limbs_to_be(rbe, r);
    limbs_to_be(sbe, s);
    for (int i = 0; i < 32; i++) {
        static const char H[] = "0123456789abcdef";
        rs_hex[2 * i]     = H[rbe[i] >> 4];
        rs_hex[2 * i + 1] = H[rbe[i] & 15];
        rs_hex[64 + 2 * i]     = H[sbe[i] >> 4];
        rs_hex[64 + 2 * i + 1] = H[sbe[i] & 15];
    }
    rs_hex[128] = 0;
    (void)pub;
    return 0;
}

int msg_verify(const unsigned char pub[33], const char* message,
               const char* rs_hex) {
    if (!pub || !rs_hex || strlen(rs_hex) != 128) { fprintf(stderr,"[mv] len issue len=%zu\n", rs_hex?strlen(rs_hex):0); return -1; }
    unsigned char rbe[32], sbe[32];
    for (int i = 0; i < 32; i++) {
        unsigned v;
        if (sscanf(rs_hex + 2 * i, "%2x", &v) != 1) return -1;
        rbe[i] = (unsigned char)v;
        if (sscanf(rs_hex + 64 + 2 * i, "%2x", &v) != 1) return -1;
        sbe[i] = (unsigned char)v;
    }
    /* little-endian limbs from the big-endian r||s serialization (authoritative
     * be_to_limbs, matching how the signer's limbs map to the BE bytes) */
    uint64_t r[4] = {0}, s[4] = {0}, z[4] = {0}, Qx[4], Qy[4];
    be_to_limbs(r, rbe, 32);
    be_to_limbs(s, sbe, 32);
    /* BIP137 digest -> big-endian bytes -> little-endian limbs */
    unsigned char zbe[32];
    if (msg_digest(zbe, message) != 0) return -1;
    be_to_limbs(z, zbe, 32);
    if (!pubkey_parse(pub, 33, Qx, Qy)) return -1;
    return ecdsa_verify(z, r, s, Qx, Qy);
}

int msg_match_address(const unsigned char pub[33], const char* address) {
    unsigned char h[20];
    extern void hash160(unsigned char o[20], const void* in, long long len);
    hash160(h, pub, 33);
    /* decode the base58check address to (version || h160) and compare h160 */
    extern int wallet_base58check_decode(unsigned char* out, long cap,
                                         long* outlen, const char* str);
    unsigned char adec[25];
    long al = 0;
    if (!wallet_base58check_decode(adec, sizeof adec, &al, address)) return -1;
    if (al < 21) return -1;
    return memcmp(adec + al - 20, h, 20) == 0 ? 1 : 0;
}

/* ======================================================================
 * PART 2 -- Bitcoin Core-compatible RECOVERABLE signatures.
 *
 * Core's signmessage produces a 65-byte COMPACT signature:
 *   header_byte = 27 + recovery_id (+4 if the pubkey is compressed)
 * followed by 32-byte big-endian r and 32-byte big-endian s, all BASE64-encoded.
 * verifymessage recovers the public key from the signature + message digest
 * alone (no pubkey argument needed) and returns true if its hash160 matches
 * the given address.
 *
 * This requires EC pubkey RECOVERY, which we implement here as C glue over the
 * project's verified asm field/point primitives (fe_mul/fe_sqr/fe_inv,
 * point_scalar_mul_ct, point_add_mixed -- the same primitives wallet_core.c
 * uses). fe_sqrt is built by exponentiation (p == 3 mod 4).
 * ====================================================================== */

/* secp256k1 domain constants (little-endian limbs). p = 2^256-2^32-977. */
static const uint64_t P_FE[4] = {
    0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
};
/* group order n. */
static const uint64_t N_SC[4] = {
    0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL,
    0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL
};
/* generator G affine (X,Y). */
static const uint64_t G_X[4] = {
    0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL,
    0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL
};
static const uint64_t G_Y[4] = {
    0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL,
    0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL
};

/* mod-p field sqrt: for p == 3 (mod 4), sqrt(a) = a^{(p+1)/4} mod p.
 * We compute e = (p+1)/4 by ordinary limb arithmetic on p (guaranteed exact)
 * then square-and-multiply a^e mod p bit by bit. Slow but verifiably correct. */
static int fe_is_zero(const uint64_t a[4]) {
    return (a[0] | a[1] | a[2] | a[3]) == 0;
}
static void fe_cpy(uint64_t r[4], const uint64_t a[4]) { memcpy(r, a, 32); }
static int fe_eq(const uint64_t a[4], const uint64_t b[4]) {
    return memcmp(a, b, 32) == 0;
}
static void fe_set1(uint64_t r[4]) { r[0]=1; r[1]=r[2]=r[3]=0; }
static void fe_set0(uint64_t r[4]) { r[0]=r[1]=r[2]=r[3]=0; }

static int fe_sqrt(uint64_t r[4], const uint64_t a[4]) {
    /* e = (p+1)/4. p+1 = 2^256 - 2^32 - 976 ; (p+1)/4 has 254-bit size. */
    uint64_t e[4];
    /* e = (p + 1) >> 2 computed with carries */
    unsigned long long carry = 0;
    e[0] = P_FE[0] + 1ULL; carry = (e[0] < 1ULL);
    e[1] = P_FE[1] + carry; carry = (e[1] < carry) ? 0 : (e[1] == 0 && carry);
    e[2] = P_FE[2] + carry; carry = (e[2] < carry) ? 0 : (e[2] == 0 && carry);
    e[3] = P_FE[3] + carry;
    /* now e = p+1 ; shift right by 2 (divide by 4): bits move 3..0 -> 1..0
     * so e_new[i] = (e[i] >> 2) | (e[i+1] << 62) */
    for (int i = 0; i < 4; i++) {
        uint64_t hi = (i+1 < 4) ? (e[i+1] << 62) : 0;
        e[i] = (e[i] >> 2) | hi;
    }
    /* square-and-multiply: r = a^e mod p */
    uint64_t res[4], base[4];
    fe_cpy(base, a);
    fe_set1(res);
    /* iterate bits of e from MSB to LSB (256 bits) */
    for (int bit = 255; bit >= 0; bit--) {
        uint64_t b = (e[bit / 64] >> (bit % 64)) & 1;
        fe_sqr(res, res);              /* res = res^2 */
        if (b) fe_mul(res, res, base); /* res = res * a */
    }
    /* check r^2 == a (if a has a sqrt at all) */
    uint64_t chk[4];
    fe_sqr(chk, res);
    if (!fe_eq(chk, a)) return -1;
    (void)fe_is_zero; (void)fe_set0;
    fe_cpy(r, res);
    return 0;
}

/* ---- fe_neg: r = p - a (mod p);  -0 == 0 ----------------------- */
static void fe_neg(uint64_t r[4], const uint64_t a[4]) {
    unsigned long long bb = 0;
    for (int i = 0; i < 4; i++) {
        unsigned long long ai = a[i], pi = P_FE[i];
        unsigned long long d = (pi - ai) - bb;
        r[i] = (uint64_t)d;
        bb = (pi < ai + bb) ? 1 : 0;
    }
    if (bb) fe_set0(r);
}

/* Jacobian (X,Y,Z: 12 limbs) -> affine x,y. 0 ok, -1 if point at infinity. */
static int jac_to_aff(uint64_t fx[4], uint64_t fy[4], const uint64_t J[12]) {
    uint64_t Z[4] = {J[8], J[9], J[10], J[11]};
    if (fe_is_zero(Z)) return -1;
    uint64_t zi[4], zi2[4], zi3[4];
    fe_inv(zi, Z);
    fe_sqr(zi2, zi);
    fe_mul(zi3, zi2, zi);
    fe_mul(fx, J, zi2);      /* x = X / Z^2 */
    fe_mul(fy, J + 4, zi3);  /* y = Y / Z^3 */
    return 0;
}

/* recover the public key Q from (z,r,s,recid). Standard algorithm:
 *   x  = r + (recid>>1)*n  (mod p);  R = (x, +-sqrt(x^3+7)); if recid&2 R+=G
 *   Q  = r^-1 (sR - zG)
 * Returns 0 and fills Qx,Qy; -1 if this recid has no valid point. */
static int ecdsa_recover(const uint64_t r[4], const uint64_t s[4],
                         const uint64_t zdig[4], int recid,
                         uint64_t Qx[4], uint64_t Qy[4]) {
    if (recid < 0 || recid > 3) return -1;

    /* ---- x = r + (recid>>1)*n (mod p) ---- */
    uint64_t x[4];
    fe_cpy(x, r);
    if (recid & 2) {
        unsigned long long c = 0;
        uint64_t sx[4];
        for (int i = 0; i < 4; i++) {
            uint64_t ai = x[i], bi = N_SC[i], ci = c;
            uint64_t s1 = ai + bi;
            uint64_t c1 = (s1 < ai) ? 1 : 0;
            uint64_t s2 = s1 + ci;
            uint64_t c2 = (s2 < ci) ? 1 : 0;
            c = c1 | c2;
            sx[i] = s2;
        }
        if (c) return -1;                    /* r+n >= 2^256 > p -> no point */
        int ge = 0;
        for (int i = 3; i >= 0; i--)
            if (sx[i] != P_FE[i]) { ge = sx[i] > P_FE[i]; break; }
        if (ge) return -1;
        fe_cpy(x, sx);
    }

    /* ---- alpha = x^3 + 7 (mod p); y = sqrt(alpha) ---- */
    uint64_t x2[4], x3[4], seven[4] = {7,0,0,0}, alpha[4];
    fe_sqr(x2, x);
    fe_mul(x3, x2, x);
    {
        unsigned long long cc = 0;
        uint64_t s7[4];
        for (int i = 0; i < 4; i++) {
            uint64_t ai = x3[i], bi = seven[i], ci = cc;
            uint64_t s1 = ai + bi;
            uint64_t c1 = (s1 < ai) ? 1 : 0;
            uint64_t s2 = s1 + ci;
            uint64_t c2 = (s2 < ci) ? 1 : 0;
            cc = c1 | c2;
            s7[i] = s2;
        }
        /* if cc (>= 2^256) or s7 >= p : subtract multiples of p. */
        if (cc) {
            /* s7 = s7 + cc*2^256 ; 2^256 mod p = 2^32 + 977 */
            uint64_t corr[4] = { ((uint64_t)cc) * (0x1000003D1ULL), 0, 0, 0 };
            unsigned long long c2 = 0;
            for (int i = 0; i < 4; i++) {
                uint64_t ai = s7[i], bi = corr[i], ci = c2;
                uint64_t s1 = ai + bi;
                uint64_t k1 = (s1 < ai) ? 1 : 0;
                uint64_t s2 = s1 + ci;
                uint64_t k2 = (s2 < ci) ? 1 : 0;
                c2 = k1 | k2;
                s7[i] = s2;
            }
            (void)c2;
        }
        int ge = 0;
        for (int i = 3; i >= 0; i--)
            if (s7[i] != P_FE[i]) { ge = s7[i] > P_FE[i]; break; }
        if (ge) {
            uint64_t borrow = 0;
            for (int i = 0; i < 4; i++) {
                uint64_t cur = s7[i], sub = P_FE[i] + borrow;
                s7[i] = cur - sub;
                borrow = (cur < sub) ? 1 : 0;
            }
        }
        fe_cpy(alpha, s7);
    }

    uint64_t y[4];
    if (fe_sqrt(y, alpha) != 0) return -1;

    /* ---- choose root matching recid parity ---- */
    unsigned int yodd = (unsigned int)(y[0] & 1);
    if ((yodd ^ (unsigned int)(recid & 1)) != 0) {
        /* y wanted odd/even mismatch -> use p - y */
        fe_neg(y, y);
        /* note: fe_neg(0) yields 0; but y==0 can't happen since group order
           is odd prime -> no point with y==0. Safe. */
    }

    /* ---- R = (x, y) as affine; if recid&2 : R += G ---- */
    uint64_t R_aff[8] = {x[0],x[1],x[2],x[3], y[0],y[1],y[2],y[3]};

    /* ---- compute s*R and z*G (Jacobian), then sR - zG, then Q = r^-1*T ---- */
    uint64_t sR[12], zG[12];
    uint64_t Gaff[8] = {G_X[0],G_X[1],G_X[2],G_X[3], G_Y[0],G_Y[1],G_Y[2],G_Y[3]};
    point_scalar_mul_ct(sR, R_aff, s);
    point_scalar_mul_ct(zG, Gaff, zdig);
    /* negate zG (Jacobian: negate Y) */
    fe_neg(zG + 4, zG + 4);
    uint64_t T[12];
    point_add(T, sR, zG);               /* T = sR - zG (normalized in Jacobian) */
    /* r^-1 (scalar) then Q = rinv * T */
    uint64_t rinv[4];
    sc_inv(rinv, r);
    /* convert T to affine, then multiply by rinv; if T at infinity -> Q inf */
    uint64_t Tx[4], Ty[4];
    if (jac_to_aff(Tx, Ty, T) != 0) return -1;
    uint64_t Taff[8] = {Tx[0],Tx[1],Tx[2],Tx[3], Ty[0],Ty[1],Ty[2],Ty[3]};
    uint64_t Q[12];
    point_scalar_mul_ct(Q, Taff, rinv);
    if (jac_to_aff(Qx, Qy, Q) != 0) return -1;
    return 0;
}

/* ---- RFC 4648 base64 (no padding variant not needed; Core uses =
 *      padding on 65-byte compact signatures). ---- */
static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static void b64_encode_block(const unsigned char* in, int n, char* out) {
    out[0] = B64[ in[0] >> 2 ];
    out[1] = B64[ ((in[0] & 3) << 4) | (n > 1 ? (in[1] >> 4) : 0) ];
    out[2] = n > 1 ? B64[ ((in[1] & 15) << 2) | (n > 2 ? (in[2] >> 6) : 0) ] : '=';
    out[3] = n > 2 ? B64[ in[2] & 63 ] : '=';
}
static void b64_encode(const unsigned char* in, int len, char* out) {
    int i = 0, o = 0;
    while (len - i >= 3) { b64_encode_block(in + i, 3, out + o); i += 3; o += 4; }
    if (len - i > 0) { b64_encode_block(in + i, len - i, out + o); o += 4; }
    out[o] = 0;
}
static int b64val(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
static int b64_decode(const char* in, unsigned char* out, int cap) {
    int n = (int)strlen(in), o = 0;
    unsigned buf = 0; int bits = 0;
    for (int i = 0; i < n; i++) {
        if (in[i] == '=' || in[i] == '\n' || in[i] == '\r') continue;
        int v = b64val((unsigned char)in[i]);
        if (v < 0) return -1;
        buf = (buf << 6) | (unsigned)v; bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o < cap) out[o++] = (unsigned char)((buf >> bits) & 0xff);
        }
    }
    return o;
}

/* ---- serialize a compressed pubkey from affine limbs: [02/03][x BE 32B] ----
 * SEC1 compressed pubkeys carry x as 32 BIG-ENDIAN bytes: byte[1] is the
 * MOST-significant byte (the 0x79 of a 0x79BE... x), i.e. it comes from the
 * HIGH limb's top byte. Write BE, MSB-first. */
static void comp_pubkey_from_aff(unsigned char out[33], const uint64_t Qx[4],
                                 const uint64_t Qy[4]) {
    out[0] = (unsigned char)(0x02 | (Qy[0] & 1));
    for (int i = 0; i < 32; i++)
        out[1 + i] = (unsigned char)(Qx[3 - i / 8] >> (8 * (7 - i % 8)));
}

/* ---- Core signmessage: emit base64 of [27+recid(+4)] || r_be || s_be ----
 * Determines recid by trying 0..3 and keeping the one that recovers the
 * signer's own pubkey (deterministic, avoids maintaining an internal
 * nonce/recovery pipeline). */
int msg_sign_core(const unsigned char priv_be[32], const char* message,
                  char sig_b64[96]) {
    unsigned char zbe[32];
    if (msg_digest(zbe, message) != 0) return -1;
    uint64_t r[4], s[4];
    wallet_ecdsa_sign(r, s, zbe, priv_be);
    /* digest -> limbs for recovery */
    uint64_t z[4];
    be_to_limbs(z, zbe, 32);
    /* caller's pubkey (compressed) */
    unsigned char pub[33];
    scalar_to_pubkey(pub, priv_be);

    /* wallet_ecdsa_sign ALWAYS applies low-S normalization (secp256k1_scalar.c
     * `if s > n/2 then s = n - s`; see wallet_core.c), so `s` is guaranteed
     * low-S on every path. Core never encodes a low-S flag in the compact
     * header (low-S is a signing policy, and recovery operates on the exact s
     * emitted), so we do NOT carry one either: recovery against the emitted
     * low-S `s` is the only variant possible. recid is found by trying 0..3
     * and keeping the one that recovers the signer's own pubkey.
     *
     * COMPLEXITY NOTE (audit FINDING P2-2 / batch-2 item 3): the recovery-id
     * search is a deterministic, BOUNDED 4-way scan (recid 0..3) only -- no
     * 8-way n-s/variant search remains (low-S is guaranteed, so one variant
     * suffices). This is acceptable for the CLI. ecdsa_recover's sqrt uses
     * exponentiation a^((p+1)/4) (~256 field ops) -- correct (validated by
     * test_msg_sign round-trips) but slow. It is deliberately NOT replaced
     * with a faster method because there is NO hot-path consumer of
     * msg_sign_core/ecdsa_recover in the tree today (CLI only). If a hot-path
     * consumer is ever added, revisit (documented in
     * validation/AUDIT_BATCH2_ACTIONS.md item 3). */
    uint64_t Qx[4], Qy[4];
    int rec = -1;
    for (int i = 0; i < 4 && rec < 0; i++) {
        int rcc = ecdsa_recover(r, s, z, i, Qx, Qy);
        if (rcc == 0) {
            unsigned char rp[33];
            comp_pubkey_from_aff(rp, Qx, Qy);
            if (memcmp(rp, pub, 33) == 0) { rec = i; break; }
        }
    }
    if (rec < 0) return -1;

    /* compact header: 27 + (4 if compressed) + recid -- EXACTLY Bitcoin Core's
     * signmessage/verifymessage header byte, with no project-specific bit, so
     * the emitted base64 is byte-compatible with Core. (Low-S is not encoded;
     * see above.) */
    unsigned char comp[65];
    comp[0] = (unsigned char)(27 + 4 + rec);
    unsigned char rbe[32], sbe[32];
    limbs_to_be(rbe, r);
    limbs_to_be(sbe, s);
    memcpy(comp + 1, rbe, 32);
    memcpy(comp + 33, sbe, 32);
    b64_encode(comp, 65, sig_b64);
    return 0;
}

/* ---- Core verifymessage: decode base64 compact sig, recover pubkey from the
 *      digest, and return true iff it is the pubkey whose hash160 == address.
 *   args: address (base58check string)  message  sig_b64
 *   returns 1 valid / 0 invalid / -1 malformed. */
int msg_verify_core(const char* address, const char* message, const char* sig_b64) {
    unsigned char comp[65];
    int cl = b64_decode(sig_b64, comp, sizeof comp);
    if (cl != 65) return -1;
    int hdr = comp[0];
    /* Bitcoin Core compact-signature header range. 27..30 = uncompressed,
     * 31..34 = compressed; we always emit compressed (31..34). Core's header
     * has no low-S bit. */
    if (hdr < 27 || hdr > 34) return -1;
    /* compressed iff (hdr >= 31) ; recid = (hdr - 27) & 3, with the +4
     * compressed bit in bit 2. */
    int base = hdr - 27;
    int rec = base & 3;
    unsigned char rbe[32], sbe[32];
    memcpy(rbe, comp + 1, 32);
    memcpy(sbe, comp + 33, 32);
    uint64_t r[4], ss[4], z[4];
    be_to_limbs(r, rbe, 32);
    be_to_limbs(ss, sbe, 32);
    unsigned char zbe[32];
    if (msg_digest(zbe, message) != 0) return -1;
    be_to_limbs(z, zbe, 32);
    uint64_t Qx[4], Qy[4];
    if (ecdsa_recover(r, ss, z, rec, Qx, Qy) != 0) return -1;
    /* serialize recovered compressed pubkey and compare its hash160 to address */
    unsigned char pub[33];
    comp_pubkey_from_aff(pub, Qx, Qy);
    return msg_match_address(pub, address);   /* 1 match / 0 no / -1 bad addr */
}

/* end */



