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
