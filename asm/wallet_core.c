/* wallet_core.c -- wallet CLI core logic.
 *
 * Implements the three wallet commands by wiring the VERIFIED assembly
 * primitives (scalar_to_pubkey, hash160, base58check_encode, sighash_all,
 * ecdsa_verify) plus direct use of the verified scalar/point/field primitives
 * (point_scalar_mul, fe_*, sc_*) to build ECDSA signatures.
 *
 * All multi-limb buffers follow the asm convention: 4 LITTLE-ENDIAN u64 limbs,
 * ascending (limb0 = least significant). Byte-string scalars that are inputs to
 * the asm primitives (e.g. scalar_to_pubkey's 32-byte key) are BIG-ENDIAN bytes.
 *
 * No external crypto libraries. Pure C glue over the repo's own verified asm.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ---------------- verified asm primitives (declared, resolved at link) ------ */
extern void scalar_to_pubkey(unsigned char pub[33], const unsigned char k[32]);
extern void hash160(unsigned char out[20], const void* in, long long len);
extern void base58check_encode(char* out, const unsigned char* payload, long long paylen);
extern void sha256d(unsigned char out[32], const void* msg, long len);
extern int  sighash_all(unsigned char out32[32], const unsigned char* tx,
                        unsigned long txlen, unsigned long input_index,
                        const unsigned char* script, unsigned long script_len,
                        unsigned char* preimg, unsigned long cap);
/* scalar ops over secp256k1 order n: r,a,b = 4 ascending little-endian u64 */
extern void sc_add(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
extern void sc_sub(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
extern void sc_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
extern void sc_inv(uint64_t r[4], const uint64_t a[4]);
/* point ops: point_scalar_mul(r_jac[12], xy_aff[8], k[4]) */
extern void point_scalar_mul(uint64_t r[12], const uint64_t xy[8], const uint64_t k[4]);
/* field ops over prime p: r,a,b = 4 ascending little-endian u64 */
extern void fe_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
extern void fe_sqr(uint64_t r[4], const uint64_t a[4]);
extern void fe_inv(uint64_t r[4], const uint64_t a[4]);
/* ecdsa_verify(z[4], r[4], s[4], Qx[4], Qy[4]) -> 1 if valid */
extern int  ecdsa_verify(const uint64_t z[4], const uint64_t r[4],
                         const uint64_t s[4], const uint64_t Qx[4], const uint64_t Qy[4]);
/* scalar_small_nonzero: BIP32 range check 0<k<n */
extern int  scalar_small_nonzero(const unsigned char k[32]);

/* ---------------- constants ------------------------------------------------ */
/* secp256k1 curve order n, 4 ascending LE limbs. */
static const uint64_t N_LIMBS[4] = {
    0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL,
    0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL
};
/* n/2 for low-S normalization */
static const uint64_t N_HALF[4] = {
    0xDFE92F46681B20A0ULL, 0x5D576E7357A4501DULL,
    0xFFFFFFFFFFFFFFFFULL, 0x7FFFFFFFFFFFFFFFULL
};
/* generator G affine (LE limbs): [x0..x3, y0..y3] */
static const uint64_t G_AFF[8] = {
    0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL, 0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL,
    0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL, 0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL
};

/* ---------------- byte/limb helpers (C, endianness glue) ------------------- */
/* 32 big-endian bytes -> 4 ascending little-endian limbs */
static void be32_to_limbs(uint64_t out[4], const unsigned char be[32]) {
    for (int i = 0; i < 4; i++) out[i] = 0;
    for (int i = 0; i < 32; i++) {
        int limb = i / 8;          /* 0 = least significant group */
        int sh   = (i % 8) * 8;
        out[limb] |= ((uint64_t)be[31 - i]) << sh;   /* be[31]=LSB */
    }
}
/* 4 ascending little-endian limbs -> 32 big-endian bytes */
static void limbs_to_be32(unsigned char be[32], const uint64_t in[4]) {
    for (int i = 0; i < 32; i++) {
        int limb = i / 8;
        int sh   = (i % 8) * 8;
        be[31 - i] = (unsigned char)((in[limb] >> sh) & 0xff);
    }
}
/* little-endian limb compare: returns -1,0,1 for a vs b (unsigned 256-bit) */
static int limb_cmp(const uint64_t a[4], const uint64_t b[4]) {
    for (int i = 3; i >= 0; i--) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return  1;
    }
    return 0;
}
/* reduce a 32-byte BE value to [1, n) as limbs; never returns 0 for sane input */
static void be32_to_scalar(uint64_t out[4], const unsigned char be[32]) {
    be32_to_limbs(out, be);
    /* if out >= n, out -= n ; guaranteed < 2n since 2^256 < 2n */
    if (limb_cmp(out, N_LIMBS) >= 0) {
        uint64_t a[4]; uint64_t c = 0;
        memcpy(a, out, 32);
        for (int i = 0; i < 4; i++) {
            uint64_t s = a[i] - N_LIMBS[i] - c;
            c = (a[i] < N_LIMBS[i] + c) ? 1 : 0;
            out[i] = s;
        }
    }
    /* guard against zero */
    int zero = 1;
    for (int i = 0; i < 4; i++) if (out[i]) { zero = 0; break; }
    if (zero) out[0] = 1;
}

/* ---------------- public wallet API ---------------------------------------- */
/* Derive compressed pubkey from a 32-byte big-endian private key. */
void wallet_pubkey(unsigned char pub[33], const unsigned char priv_be[32]) {
    scalar_to_pubkey(pub, priv_be);
}

/* P2PKH mainnet address for a 32-byte BE private key. */
int wallet_address(char out[64], const unsigned char priv_be[32]) {
    unsigned char pub[33], h[20], payload[21];
    scalar_to_pubkey(pub, priv_be);
    hash160(h, pub, 33);
    payload[0] = 0x00;                       /* mainnet version */
    memcpy(payload + 1, h, 20);
    base58check_encode(out, payload, 21);    /* verified primitive */
    return 0;
}

/* Build the P2PKH prevout script (the signing script) for a compressed pubkey:
 *   OP_DUP 0xA9, OP_HASH160 0xA9, PUSH20 <h160>, OP_EQUALVERIFY 0x88, OP_CHECKSIG 0xAC
 * length = 25. */
static void wallet_p2pkh_script(unsigned char script[25], const unsigned char priv_be[32]) {
    unsigned char pub[33], h[20];
    scalar_to_pubkey(pub, priv_be);
    hash160(h, pub, 33);
    script[0] = 0x76; script[1] = 0xa9; script[2] = 0x14;
    memcpy(script + 3, h, 20);
    script[23] = 0x88; script[24] = 0xac;
}

/* Legacy SIGHASH_ALL message hash for a tx, its target input index, and the
 * signing (prevout) script. Returns 1 on success and fills out32 (BE bytes). */
int wallet_sighash(unsigned char out32[32], const unsigned char* tx, unsigned long txlen,
                   unsigned long input_index, const unsigned char* script,
                   unsigned long script_len) {
    static unsigned char preimg[4096];
    return sighash_all(out32, tx, txlen, input_index, script, script_len,
                       preimg, sizeof preimg);
}

/* ECDSA sign: deterministic nonce k = sha256d(z_be || priv_be), then
 *   R = k*G ; r = R.x mod n ; s = k^-1 (z + r*d) mod n  (low-S normalized).
 * On success sets *out_r and *out_s as 4 ascending LE limbs and returns 1. */
int wallet_ecdsa_sign(uint64_t out_r[4], uint64_t out_s[4],
                      const unsigned char z_be[32], const unsigned char priv_be[32]) {
    unsigned char seed[64], kbe[32];
    uint64_t k[4], d[4], z[4], R[12];
    uint64_t z2[4], zi[4], px[4], r[4], rd[4], zrd[4];

    /* deterministic nonce: k = sha256d(z || priv) */
    memcpy(seed, z_be, 32);
    memcpy(seed + 32, priv_be, 32);
    sha256d(kbe, seed, 64);
    be32_to_scalar(k, kbe);

    be32_to_limbs(d, priv_be);
    be32_to_limbs(z, z_be);

    /* R = k*G (Jacobian 12 limbs) */
    point_scalar_mul(R, G_AFF, k);

    /* affine x = X * (1/Z^2) mod p */
    fe_sqr(z2, R + 8);          /* Z^2 */
    fe_inv(zi, z2);             /* 1/Z^2 */
    fe_mul(px, R, zi);          /* X / Z^2 */

    /* r = px mod n */
    if (limb_cmp(px, N_LIMBS) >= 0) {
        uint64_t c = 0;
        for (int i = 0; i < 4; i++) {
            uint64_t s = px[i] - N_LIMBS[i] - c;
            c = (px[i] < N_LIMBS[i] + c) ? 1 : 0;
            r[i] = s;
        }
    } else memcpy(r, px, 32);

    /* rd = r*d mod n ; zrd = z + rd mod n ; s = k^-1 * zrd mod n */
    sc_mul(rd, r, d);
    sc_add(zrd, z, rd);
    sc_inv(k, k);               /* k^-1 */
    sc_mul(out_s, zrd, k);
    memcpy(out_r, r, 32);

    /* low-S normalization: if s > n/2 then s = n - s */
    if (limb_cmp(out_s, N_HALF) > 0) {
        uint64_t c = 0;
        for (int i = 0; i < 4; i++) {
            uint64_t s = N_LIMBS[i] - out_s[i] - c;
            c = (out_s[i] > N_LIMBS[i] - c) ? 1 : 0;
            out_s[i] = s;
        }
    }
    return 1;
}

/* --- DER + tx assembly helpers --- */

/* Encode an integer limb array as a minimal big-endian, canonical-DER integer
 * (prepend 0x00 if the high bit is set). Returns length written to out (>=1).
 * out must have room for 33 bytes. */
static int der_int(unsigned char* out, const uint64_t v[4]) {
    unsigned char be[32];
    int i, n;
    limbs_to_be32(be, v);
    i = 0;
    while (i < 31 && be[i] == 0) i++;      /* skip leading zeros */
    n = 0;
    if (be[i] & 0x80) out[n++] = 0x00;
    for (; i < 32; i++) out[n++] = be[i];
    return n;
}

/* DER-encode (r,s) into out (max 72 bytes). Returns length. */
static int der_signature(unsigned char* out, const uint64_t r[4], const uint64_t s[4]) {
    unsigned char rb[33], sb[33];
    int rl = der_int(rb, r), sl = der_int(sb, s);
    int body = 2 + rl + 2 + sl;
    out[0] = 0x30; out[1] = (unsigned char)body;
    out[2] = 0x02; out[3] = (unsigned char)rl; memcpy(out + 4, rb, rl);
    out[4 + rl] = 0x02; out[5 + rl] = (unsigned char)sl; memcpy(out + 6 + rl, sb, sl);
    return 2 + body;
}

/* Little varint writer (tx reconstruction). n < 0xfd in all our test cases but
 * handle the general forms to be safe. Returns bytes used. */
static int put_varint(unsigned char* p, unsigned long n) {
    if (n < 0xfd) { p[0] = (unsigned char)n; return 1; }
    else if (n <= 0xffff) { p[0] = 0xfd; p[1] = n & 0xff; p[2] = (n >> 8) & 0xff; return 3; }
    else if (n <= 0xffffffffUL) { p[0] = 0xfe; for (int i = 0; i < 4; i++) p[1+i] = (n >> (8*i)) & 0xff; return 5; }
    else { p[0] = 0xff; for (int i = 0; i < 8; i++) p[1+i] = (n >> (8*i)) & 0xff; return 9; }
}
static unsigned long get_varint(const unsigned char* p, unsigned long* consumed) {
    unsigned long n = p[0]; *consumed = 1;
    if (n < 0xfd) return n;
    if (n == 0xfd) { *consumed = 3; return (unsigned long)p[1] | ((unsigned long)p[2] << 8); }
    if (n == 0xfe) { *consumed = 5; unsigned long v = 0; for (int i = 0; i < 4; i++) v |= (unsigned long)p[1+i] << (8*i); return v; }
    *consumed = 9; 
    { unsigned long long v = 0; for (int i = 0; i < 8; i++) v |= (unsigned long long)p[1+i] << (8*i); return (unsigned long)v; }
}

/* Sign a P2PKH tx: replace the scriptSig of input `input_index` with
 *   <push> <DER sig> 0x01 <push> <33-byte pubkey>
 * and write the complete re-serialized tx to `out_tx` (caller sizes: cap).
 * Returns length, or -1 on error.
 */
long wallet_sign_tx(unsigned char* out_tx, long cap,
                    const unsigned char* tx, unsigned long txlen,
                    long input_index, const unsigned char priv_be[32]) {
    long pos = 0, i;
    unsigned long ncons, c;
    unsigned char* tmp0 = malloc(txlen * 2 + 512);
    unsigned char* tmp  = tmp0;
    if (!tmp0) return -1;

    /* ---- sign: z = sighash_all(prevout script) ---- */
    unsigned char script[25], z[32];
    uint64_t r[4], s[4];
    wallet_p2pkh_script(script, priv_be);
    if (!wallet_sighash(z, tx, txlen, (unsigned long)input_index, script, 25)) { free(tmp0); return -1; }
    wallet_ecdsa_sign(r, s, z, priv_be);

    /* DER sig + sighash type byte -> scriptSig body */
    unsigned char der[80], sbody[96];
    int dl = der_signature(der, r, s);
    memcpy(sbody, der, dl); sbody[dl] = 0x01;      /* SIGHASH_ALL */
    int sb_len = dl + 1;

    /* full replacement scriptSig:
     *   <push sb_len> <body> <push 33> <pubkey>   (single-byte pushes; sb_len<=75) */
    unsigned char newsig[160];
    int nsl = 0;
    newsig[nsl++] = (unsigned char)sb_len;
    memcpy(newsig + nsl, sbody, sb_len); nsl += sb_len;
    newsig[nsl++] = 0x21;
    scalar_to_pubkey(newsig + nsl, priv_be); nsl += 33;

    /* ---- reconstruct tx ----
     * version(4) | vin count | inputs | vout count | outputs | locktime(4) */
    pos = 0;
    memcpy(tmp + pos, tx, 4); pos += 4;                                   /* version */
    ncons = get_varint(tx + pos, &c); memcpy(tmp + pos, tx + pos, c); pos += (long)c; /* vin count */
    {
        unsigned long pos_in = 4 + c;
        for (i = 0; i < (long)ncons; i++) {
            unsigned long cc, slen;
            if (pos_in + 36 > txlen) { free(tmp0); return -1; }
            memcpy(tmp + pos, tx + pos_in, 36); pos += 36; pos_in += 36;   /* prev txid + vout */
            slen = get_varint(tx + pos_in, &cc);
            if (pos_in + cc + slen + 4 > txlen) { free(tmp0); return -1; }
            if (i == input_index) {
                /* write new scriptSig varint + bytes */
                unsigned char lenbf[9]; int ll = put_varint(lenbf, (unsigned long)nsl);
                memcpy(tmp + pos, lenbf, ll); pos += ll;
                memcpy(tmp + pos, newsig, nsl); pos += nsl;
            } else {
                memcpy(tmp + pos, tx + pos_in, cc); pos += (long)cc;       /* sig len varint */
                memcpy(tmp + pos, tx + pos_in + cc, slen); pos += (long)slen; /* sig */
            }
            pos_in += cc + slen;
            memcpy(tmp + pos, tx + pos_in, 4); pos += 4; pos_in += 4;      /* sequence */
        }
        /* vout count + outputs + locktime: copy verbatim */
        if (pos_in >= txlen) { free(tmp0); return -1; }
        memcpy(tmp + pos, tx + pos_in, txlen - pos_in);
        pos += (long)(txlen - pos_in);
    }

    if (pos > cap) { free(tmp0); return -1; }
    memcpy(out_tx, tmp, (size_t)pos);
    free(tmp0);
    return pos;
}
