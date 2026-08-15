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
/* BIP39 mnemonic <-> seed (bitcoin_bip39.asm) */
extern int  bip39_generate(char* out, const unsigned char* entropy, long ent_bits);
extern int  bip39_validate(const char* mnemonic);
extern int  bip39_mnemonic_to_seed(unsigned char seed[64], const char* mnemonic,
                                   const char* passphrase, long passlen);
/* BIP32 seeds/longest path (bitcoin_bip32.asm) for pairing with BIP39 */
extern int  bip32_master(unsigned char k[32], unsigned char c[32],
                         const unsigned char* seed, long seedlen);
extern int  bip32_derive_path(unsigned char k[32], unsigned char c[32],
                              const unsigned char* seed, long seedlen,
                              const unsigned* indexes, long n);
extern int  bip32_extkey_serialize(unsigned char ser[78], int is_priv,
                                   unsigned char depth,
                                   const unsigned char parent_fp[4],
                                   unsigned child, const unsigned char c[32],
                                   const unsigned char* key, long keylen);

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

/* ============================================================================
 * Wallet-core/RPC surface (address + raw-tx commands), building toward
 * bitcoin-cli parity. Kept in C over the verified asm crypto (wallet_ prefix).
 * ==========================================================================*/

/* base58 alphabet index lookup: returns 0..57 or -1 for an invalid char. */
static int b58_val(char c) {
    const char* A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    for (int i = 0; i < 58; i++) if (A[i] == c) return i;
    return -1;
}

/* base58check_decode(out, cap, &outlen, str): decode a base58check string to
 * its raw payload bytes (version||hash, e.g. 25 bytes for P2PKH). Verifies the
 * trailing 4-byte double-SHA256 checksum and leading '1' (zero) preservation.
 * Returns 1 on a valid, checksum-correct string (outlen = payload length);
 * 0 on any failure. out must hold at least cap bytes. */
int wallet_base58check_decode(unsigned char* out, long cap, long* outlen, const char* str) {
    long slen = (long)strlen(str);
    if (slen == 0 || slen > 128) return 0;
    /* count leading '1's */
    long zeros = 0;
    while (zeros < slen && str[zeros] == '1') zeros++;
    /* convert remainder base58->big-endian bytes: number = sum(digit_i * 58^i) */
    unsigned char buf[128];
    long blen = 0;                      /* number of significant bytes */
    for (long i = zeros; i < slen; i++) {
        int d = b58_val(str[i]);
        if (d < 0) return 0;
        unsigned carry = (unsigned)d;
        for (long j = 0; j < blen; j++) {
            unsigned t = (unsigned)buf[j] * 58u + carry;
            buf[j] = (unsigned char)(t & 0xff);
            carry = t >> 8;
        }
        while (carry) { buf[blen++] = (unsigned char)(carry & 0xff); carry >>= 8; }
    }
    /* total payload = zeros leading-zero bytes + blen significant bytes */
    long total = zeros + blen;
    if (total < 5 || total > cap) return 0;
    /* assemble payload bytes big-endian: [zeros zeros...][signif reversed] */
    unsigned char* pay = out;           /* caller's buffer is the payload dst */
    for (long i = 0; i < zeros; i++) pay[i] = 0;
    for (long i = 0; i < blen; i++) pay[zeros + i] = buf[blen - 1 - i];
    long paylen = total - 4;            /* payload = all but last 4 checksum bytes */
    /* verify checksum: sha256d(pay, paylen)[0..4] == last 4 bytes */
    unsigned char chk[32];
    sha256d(chk, pay, paylen);
    if (chk[0] != pay[paylen] || chk[1] != pay[paylen+1] ||
        chk[2] != pay[paylen+2] || chk[3] != pay[paylen+3]) return 0;
    *outlen = paylen;
    return 1;
}

/* bech32 externs (verified asm codec) */
extern void bech32_init(void);
extern long long bech32_encode(char* out, const char* hrp, long long hrplen,
                               const unsigned char* data5, long long datalen, long long spec);
extern long long bech32_convert_bits(unsigned char* out, const unsigned char* in,
                                     long long inlen, long long frombits,
                                     long long tobits, long long pad);
extern long long bech32_decode(unsigned char* out5, char* out_hrp,
                               long long hrp_cap, const char* in);
extern long long bech32_verify_checksum(const char* hrp, long long hrplen,
                                        const unsigned char* data5,
                                        long long datalen, long long spec);

/* Encode the bech32 (BIP173) witness-v0 P2WPKH address "bc1" + 20-byte h160.
 * Returns string length or -1. */
long wallet_p2wpkh_address(char* out, long cap, const unsigned char h160[20]) {
    unsigned char d5[40];
    long long n5 = bech32_convert_bits(d5, h160, 20, 8, 5, 1);
    if (n5 < 0) return -1;
    unsigned char data[40];
    long long dl = 0;
    data[dl++] = 0;                     /* witness version v0 */
    for (long long i = 0; i < n5; i++) data[dl++] = d5[i];
    bech32_init();
    long long sl = bech32_encode(out, "bc", 2, data, dl, 0);  /* spec 0 = bech32 */
    return (sl >= 0 && sl < cap) ? (long)sl : -1;
}

/* Encode the bech32m (BIP350) P2PKH-style ... unused here; keep P2WPKH only. */

/* Encode the bech32m (BIP350) witness-v1 P2TR address "bc1p" + 32-byte xonly key.
 * BIP341/350: hrp "bc", bech32m (spec=1), witness version 1, 32-byte program.
 * Returns string length or -1. */
long wallet_p2tr_address(char* out, long cap, const unsigned char xonly[32]) {
    unsigned char d5[64];
    long long n5 = bech32_convert_bits(d5, xonly, 32, 8, 5, 1);
    if (n5 < 0) return -1;
    unsigned char data[64];
    long long dl = 0;
    data[dl++] = 1;                     /* witness version v1 (taproot) */
    for (long long i = 0; i < n5; i++) data[dl++] = d5[i];
    bech32_init();
    long long sl = bech32_encode(out, "bc", 2, data, dl, 1);  /* spec 1 = bech32m */
    return (sl >= 0 && sl < cap) ? (long)sl : -1;
}

/* Build the 22-byte P2WPKH scriptPubKey: OP_0 PUSH20 <h160>. */
int wallet_p2wpkh_script_pubkey(unsigned char out[22], const unsigned char h160[20]) {
    out[0] = 0x00; out[1] = 0x14;
    memcpy(out + 2, h160, 20);
    return 22;
}

/* Derive the BIP84 native-segwit m/84'/0'/0'/index/0 receive keypath from a seed
 * and render its P2WPKH bech32 address. index >= 0. Returns string length or -1. */
long wallet_derive_p2wpkh_address(char* out, long cap, const unsigned char seed[64],
                                  unsigned index) {
    unsigned indexes[5] = {0x80000000u | 84u, 0x80000000u, 0x80000000u, index, 0};
    unsigned char k[32], c[32], pub[33], h[20];
    if (bip32_derive_path(k, c, seed, 64, indexes, 5) != 1) return -1;
    scalar_to_pubkey(pub, k);
    hash160(h, pub, 33);
    return wallet_p2wpkh_address(out, cap, h);
}

/* Derive the BIP84 change-keypath m/84'/0'/0'/index/1 P2WPKH address. */
long wallet_derive_p2wpkh_change(char* out, long cap, const unsigned char seed[64],
                                 unsigned index) {
    unsigned indexes[5] = {0x80000000u | 84u, 0x80000000u, 0x80000000u, index, 1};
    unsigned char k[32], c[32], pub[33], h[20];
    if (bip32_derive_path(k, c, seed, 64, indexes, 5) != 1) return -1;
    scalar_to_pubkey(pub, k);
    hash160(h, pub, 33);
    return wallet_p2wpkh_address(out, cap, h);
}

/* Reported address type from wallet_validate_address. */
enum wal_addr_type { WAL_ADDR_INVALID = 0, WAL_ADDR_P2PKH, WAL_ADDR_P2WPKH,
                     WAL_ADDR_P2SH, WAL_ADDR_P2WSH, WAL_ADDR_P2TR, WAL_ADDR_UNKNOWN };

/* Parse + validate an address string. Fills:
 *   *type_   - WAL_ADDR_P2PKH / WAL_ADDR_P2WPKH / WAL_ADDR_P2SH / WAL_ADDR_P2WSH
 *              / WAL_ADDR_P2TR / WAL_ADDR_UNKNOWN (valid but unclassified)
 *              / WAL_ADDR_INVALID (bad).
 *   version[1] - base58 version byte (P2PKH address->1) for base58 types.
 *   h160[20]   - the 20-byte hash (P2PKH h160 / P2WPKH h160 / P2SH redeem-hash).
 *   prog32[32] - (may be NULL) the 32-byte program/commitment for P2TR (and
 *                P2WSH script-hash) / key for P2TR. For P2TR this is the
 *                x-only output key (BIP341).
 * Returns 1 if the string is a CHECKSUM-VALID address (any recognized type), 0 if not. */
int wallet_validate_address(const char* str, int* type_, unsigned char* version,
                            unsigned char h160[20], unsigned char prog32[32]) {
    long plen;
    unsigned char pay[128];
    /* try base58check first */
    if (wallet_base58check_decode(pay, (long)sizeof pay, &plen, str)) {
        version[0] = pay[0];
        if (plen == 21) {                       /* version + 20 hash */
            memcpy(h160, pay + 1, 20);
            *type_ = (pay[0] == 0x00) ? WAL_ADDR_P2PKH
                   : (pay[0] == 0x05) ? WAL_ADDR_P2SH : WAL_ADDR_UNKNOWN;
            return 1;
        }
        *type_ = WAL_ADDR_UNKNOWN;
        return 1;                               /* checksum ok, odd payload size */
    }
    /* try bech32 (P2WPKH/P2WSH bech32; P2TR bech32m) -- bech32_decode gives
     * data5 WITHOUT verifying the checksum; accept only if it verifies. */
    bech32_init();
    unsigned char d5[256];
    char hrp[32];
    long long n5 = bech32_decode(d5, hrp, (long long)sizeof hrp, str);
    if (n5 >= 0) {
        /* normalize HRP to lowercase for the checksum + "bc" match */
        for (char* p = hrp; *p; p++) if (*p >= 'A' && *p <= 'Z') *p = (char)(*p + 32);
        long long hrplen = (long long)strlen(hrp);
        /* witness v0 uses bech32 (spec 0); witness v1 (taproot) uses bech32m (spec 1). */
        if (hrplen == 2 && hrp[0] == 'b' && hrp[1] == 'c' && n5 >= 8) {
            if (bech32_verify_checksum(hrp, hrplen, d5, n5, 1) == 1 && d5[0] == 1) {
                /* P2TR: witness version 1, 32-byte program, bech32m. */
                unsigned char bytes[64];
                long long bl = bech32_convert_bits(bytes, d5 + 1, n5 - 7, 5, 8, 0);
                if (bl == 32) {
                    if (prog32) memcpy(prog32, bytes, 32);
                    *type_ = WAL_ADDR_P2TR;
                    return 1;
                }
            }
            if (bech32_verify_checksum(hrp, hrplen, d5, n5, 0) == 1 && d5[0] == 0) {
                /* witness v0: the LAST SIX groups are the checksum, and the rest
                 * is the 5-bit program: 32 groups -> P2WPKH (20 byte), 52 -> P2WSH. */
                unsigned char bytes[64];
                long long bl = bech32_convert_bits(bytes, d5 + 1, n5 - 7, 5, 8, 0);
                if (bl == 20) {                         /* P2WPKH */
                    memcpy(h160, bytes, 20);
                    *type_ = WAL_ADDR_P2WPKH;
                    return 1;
                }
                if (bl == 32) {                         /* P2WSH */
                    if (prog32) memcpy(prog32, bytes, 32);
                    *type_ = WAL_ADDR_P2WSH;
                    return 1;
                }
            }
        }
    }
    *type_ = WAL_ADDR_INVALID;
    return 0;
}

/* ---- UTXO-query surface: gettxout / listunspent -------------------------- */

/* Render the ADDRESS for a scriptPubKey if it is a recognized P2PKH (25-byte
 * OP_DUP HASH160 PUSH20 h160 EQUALVERIFY CHECKSIG) or P2WPKH (22-byte
 * OP_0 PUSH20 h160) script. Fills out (>= 96 bytes) and returns the address
 * type (WAL_ADDR_P2PKH / WAL_ADDR_P2WPKH / WAL_ADDR_INVALID=0). */
int wallet_script_to_address(char* out, long cap, const unsigned char* script, long slen) {
    if (slen == 25 && script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 &&
        script[23] == 0x88 && script[24] == 0xac) {
        /* P2PKH: version 0x00 || h160 */
        unsigned char payload[21];
        payload[0] = 0x00;
        memcpy(payload + 1, script + 3, 20);
        base58check_encode(out, payload, 21);
        return WAL_ADDR_P2PKH;
    }
    if (slen == 22 && script[0] == 0x00 && script[1] == 0x14) {
        /* P2WPKH */
        if (wallet_p2wpkh_address(out, cap, script + 2) < 0) return WAL_ADDR_INVALID;
        return WAL_ADDR_P2WPKH;
    }
    if (slen == 34 && script[0] == 0x51 && script[1] == 0x20) {
        /* P2TR: OP_1 PUSH32 <xonly output key> (BIP341), bech32m */
        if (wallet_p2tr_address(out, cap, script + 2) < 0) return WAL_ADDR_INVALID;
        return WAL_ADDR_P2TR;
    }
    return WAL_ADDR_INVALID;
}

/* extern in-memory UTXO set primitives */
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_get(void* u, const unsigned char txid[32], unsigned long index,
                     unsigned long long* value, const unsigned char** script, unsigned long* slen);
extern long utxo_put(void* u, const unsigned char txid[32], unsigned long index,
                     unsigned long long value, const unsigned char* script, unsigned long slen);
extern long utxo_del(void* u, const unsigned char txid[32], unsigned long index);

/* gettxout: query the outpoint (txid, index) in the UTXO store. On a hit fills
 * value / script (points into the store) / slen, and (if addr != NULL and the
 * script classifies) the address string. Returns 1 on a live unspent outpoint,
 * 0 if absent/spent (like Core's gettxout null), -1 on error. */
int wallet_gettxout(void* u, const unsigned char txid[32], unsigned long index,
                    unsigned long long* value, const unsigned char** script, unsigned long* slen,
                    char* addr, long addr_cap) {
    unsigned long long v; const unsigned char* s; unsigned long sl;
    long r = utxo_get(u, txid, index, &v, &s, &sl);
    if (r != 1) return 0;
    if (value) *value = v;
    if (script) *script = s;
    if (slen)   *slen   = sl;
    if (addr) {
        int t = wallet_script_to_address(addr, addr_cap, s, (long)sl);
        if (t == WAL_ADDR_INVALID) addr[0] = 0;   /* unspendable/other script */
    }
    return 1;
}

/* One listunspent entry renderer: given an outpoint + resolved value + its
 * scriptPubKey, render a single line like Core's listunspent:
 *   <txid> <vout> <amount_sat> <scriptPubKey_hex> <address>
 * The caller enumerates the wallet's owned UTXOs (the wallet tracks its own
 * outputs; the in-memory store is an outpoint hash-map with no all-scan).
 * Returns bytes written to out (not incl. NUL). */
long wallet_listunspent_entry(char* out, long cap,
                              const unsigned char txid[32], unsigned long index,
                              unsigned long long value,
                              const unsigned char* script, unsigned long slen) {
    char addr[96];
    int t = (script && slen) ? wallet_script_to_address(addr, 96, script, (long)slen) : WAL_ADDR_INVALID;
    if (t == WAL_ADDR_INVALID) addr[0] = 0;
    long n = 0;
    for (int i = 0; i < 32; i++) n += snprintf(out + n, (size_t)(cap - n), "%02x", txid[i]);
    n += snprintf(out + n, (size_t)(cap - n), " %lu %llu ", index, value);
    for (unsigned long i = 0; i < slen && n < cap - 3; i++) n += snprintf(out + n, (size_t)(cap - n), "%02x", script[i]);
    n += snprintf(out + n, (size_t)(cap - n), " %s", addr);
    return n;
}

/* ---- decoderawtransaction ------------------------------------------------ */

/* Decode a raw serialized tx into a human-readable dump (bitcoin-cli
 * decoderawtransaction parity): version, every input (prev txid, prev vout,
 * scriptSig hex, sequence) with the input's address when the scriptSig is a
 * P2PKH spend, every output (value, scriptPubKey hex + address), and locktime.
 * Returns bytes written to out (not incl. NUL), or -1 if the tx is malformed.
 * The witness flag is left 0 for a plain legacy decode (segwit handled by
 * tx_parse in the wider validator; here we decode the legacy transaction
 * layout). */
long wallet_decoderawtx(char* out, long cap, const unsigned char* tx, unsigned long txlen) {
    unsigned long p = 0;
    long n = 0;
    unsigned long cc;
    /* version */
    if (txlen < 10) return -1;
    unsigned long v = (unsigned long)tx[0] | ((unsigned long)tx[1] << 8)
                    | ((unsigned long)tx[2] << 16) | ((unsigned long)tx[3] << 24);
    n += snprintf(out + n, (size_t)(cap - n), "version: %lu\n", v);
    p = 4;
    unsigned long n_in = get_varint(tx + p, &cc); p += cc; if (p > txlen) return -1;
    n += snprintf(out + n, (size_t)(cap - n), "num_inputs: %lu\n", n_in);
    for (unsigned long i = 0; i < n_in; i++) {
        if (p + 36 > txlen) return -1;
        /* prev txid (wire = little-endian display reverse; show as stored) */
        n += snprintf(out + n, (size_t)(cap - n), "  in[%lu]: prev_txid ", i);
        for (int j = 31; j >= 0; j--) n += snprintf(out + n, (size_t)(cap - n), "%02x", tx[p + j]);
        unsigned long pv = (unsigned long)tx[p+32] | ((unsigned long)tx[p+33] << 8)
                         | ((unsigned long)tx[p+34] << 16) | ((unsigned long)tx[p+35] << 24);
        n += snprintf(out + n, (size_t)(cap - n), " prev_vout %lu\n", pv);
        p += 36;
        unsigned long sl = get_varint(tx + p, &cc); p += cc; if (p + sl > txlen) return -1;
        n += snprintf(out + n, (size_t)(cap - n), "       scriptSig[%lu]: ", sl);
        for (unsigned long j = 0; j < sl; j++) n += snprintf(out + n, (size_t)(cap - n), "%02x", tx[p + j]);
        n += snprintf(out + n, (size_t)(cap - n), "\n");
        p += sl;
        if (p + 4 > txlen) return -1;
        unsigned long seq = (unsigned long)tx[p] | ((unsigned long)tx[p+1] << 8)
                          | ((unsigned long)tx[p+2] << 16) | ((unsigned long)tx[p+3] << 24);
        p += 4;
        n += snprintf(out + n, (size_t)(cap - n), "       sequence: %lu\n", seq);
    }
    if (p >= txlen) return -1;
    unsigned long n_out = get_varint(tx + p, &cc); p += cc; if (p > txlen) return -1;
    n += snprintf(out + n, (size_t)(cap - n), "num_outputs: %lu\n", n_out);
    for (unsigned long i = 0; i < n_out; i++) {
        if (p + 8 > txlen) return -1;
        unsigned long long val = 0;
        for (int j = 0; j < 8; j++) val |= (unsigned long long)tx[p + j] << (8 * j);
        p += 8;
        unsigned long sl = get_varint(tx + p, &cc); p += cc; if (p + sl > txlen) return -1;
        char addr[96]; addr[0] = 0;
        wallet_script_to_address(addr, 96, tx + p, (long)sl);
        n += snprintf(out + n, (size_t)(cap - n), "  out[%lu]: value %llu\n", i, val);
        n += snprintf(out + n, (size_t)(cap - n), "       scriptPubKey[%lu]: ", sl);
        for (unsigned long j = 0; j < sl; j++) n += snprintf(out + n, (size_t)(cap - n), "%02x", tx[p + j]);
        if (addr[0]) n += snprintf(out + n, (size_t)(cap - n), " (address %s)\n", addr);
        else         n += snprintf(out + n, (size_t)(cap - n), "\n");
        p += sl;
    }
    if (p + 4 > txlen) return -1;
    unsigned long lock = (unsigned long)tx[p] | ((unsigned long)tx[p+1] << 8)
                       | ((unsigned long)tx[p+2] << 16) | ((unsigned long)tx[p+3] << 24);
    n += snprintf(out + n, (size_t)(cap - n), "locktime: %lu\n", lock);
    return n;
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

/* ---- public "send" layer: createrawtx + sign-all-inputs ---- */

/* Public P2PKH prevout-script builder for a given compressed private key
 * (25-byte script): OP_DUP HASH160 PUSH20 <h160> EQUALVERIFY CHECKSIG. */
void wallet_make_p2pkh_script(unsigned char script[25], const unsigned char priv_be[32]) {
    wallet_p2pkh_script(script, priv_be);
}

/* Encode a P2PKH output script for a RAW destination pubkey hash:
 *   OP_DUP 0x76 OP_HASH160 0xa9 PUSH20 <h20> OP_EQUALVERIFY 0x88 OP_CHECKSIG 0xac
 * Returns 25 (the script length). */
int wallet_p2pkh_output_script(unsigned char out[25], const unsigned char h160[20]) {
    out[0] = 0x76; out[1] = 0xa9; out[2] = 0x14;
    memcpy(out + 3, h160, 20);
    out[23] = 0x88; out[24] = 0xac;
    return 25;
}

/* HASH160(pubkey) of a compressed private key (the P2PKH address hash). */
void wallet_key_h160(unsigned char h[20], const unsigned char priv_be[32]) {
    unsigned char pub[33];
    scalar_to_pubkey(pub, priv_be);
    hash160(h, pub, 33);
}

/* Sum a wallet's unspent prevout values (satoshis). The caller supplies the
 * wallet's UTXO set (the resolution of "which outputs are ours" lives in the
 * caller that owns the UTXO store). Returns the total. */
unsigned long long wallet_get_balance(const unsigned long long* tval, unsigned long n) {
    unsigned long long sum = 0;
    for (unsigned long i = 0; i < n; i++) sum += tval[i];
    return sum;
}

/* Build an UNSIGNED P2PKH transaction that spends `n` inputs, paying `amount`
 * to a destination P2PKH script (`to_script`, 25 bytes = wallet_p2pkh_output_script)
 * and returning change (sum(inputs) - amount - fee) to our own change script.
 *
 * Inputs  : toutid[i][32] == prevout txid, tidx[i] == prevout index,
 *           tval[i]       == prevout value (for the fee/change math)
 * Caller  : passes explicit prevout values; the wallet resolves them from its
 *           UTXO set (that resolution lives in the CLI, which owns the store).
 *          Each input's scriptSig is left EMPTY (to be filled by
 *          wallet_sign_all_inputs).
 *
 * Returns the unsigned tx length, or -1 on error (fee>0 required, and change
 * must be >= 0; coinbase-like zero outputs are allowed but discouraged).
 */
long wallet_createrawtx(unsigned char* out_tx, long cap,
                        const unsigned char toutid[][32], const unsigned long* tidx,
                        const unsigned long long* tval, unsigned long n,
                        const unsigned char to_script[25], unsigned long long amount,
                        const unsigned char change_script[25],
                        unsigned long long fee, unsigned long locktime) {
    unsigned long long total_in = 0;
    for (unsigned long i = 0; i < n; i++) total_in += tval[i];
    if (fee == 0 || total_in < amount + fee) return -1;      /* underfunded / no-fee */
    unsigned long long change = total_in - amount - fee;
    if (change > 0 && change == (unsigned long long)-1) return -1;

    unsigned char* t = out_tx;
    long pos = 0;
    /* version */
    t[pos++] = (unsigned char)(locktime & 0xff);
    t[pos++] = (unsigned char)((locktime >> 8) & 0xff);
    t[pos++] = (unsigned char)((locktime >> 16) & 0xff);
    t[pos++] = (unsigned char)((locktime >> 24) & 0xff);
    /* vin count */
    pos += put_varint(t + pos, n);
    for (unsigned long i = 0; i < n && pos + 41 < cap; i++) {
        memcpy(t + pos, toutid[i], 32); pos += 32;           /* prev txid */
        t[pos++] = (unsigned char)(tidx[i] & 0xff);          /* prev index LE */
        t[pos++] = (unsigned char)((tidx[i] >> 8) & 0xff);
        t[pos++] = (unsigned char)((tidx[i] >> 16) & 0xff);
        t[pos++] = (unsigned char)((tidx[i] >> 24) & 0xff);
        t[pos++] = 0;                                        /* scriptSig len = 0 */
        t[pos++] = 0xff; t[pos++] = 0xff; t[pos++] = 0xff; t[pos++] = 0xff; /* seq */
    }
    if (n && pos + 1 >= cap) return -1;
    /* vout count */
    pos += put_varint(t + pos, (change > 0) ? 2 : 1);
    /* output 0: destination */
    {
        for (int j = 0; j < 8; j++) t[pos++] = (unsigned char)((amount >> (8*j)) & 0xff);
        pos += put_varint(t + pos, 25);
        memcpy(t + pos, to_script, 25); pos += 25;
    }
    /* output 1: change (if any) */
    if (change > 0) {
        for (int j = 0; j < 8; j++) t[pos++] = (unsigned char)((change >> (8*j)) & 0xff);
        pos += put_varint(t + pos, 25);
        memcpy(t + pos, change_script, 25); pos += 25;
    }
    /* locktime */
    t[pos++] = (unsigned char)(locktime & 0xff);
    t[pos++] = (unsigned char)((locktime >> 8) & 0xff);
    t[pos++] = (unsigned char)((locktime >> 16) & 0xff);
    t[pos++] = (unsigned char)((locktime >> 24) & 0xff);
    if (pos > cap) return -1;
    return pos;
}

/* Sign EVERY input of an unsigned P2PKH tx in place, replacing each scriptSig
 * with <push><DER sig><sighash-all><push><pubkey>. All inputs are signed with
 * `priv_be` (same key owns all our inputs). Each input's SIGHASH_ALL digest is
 * built against the pure-unsigned tx (all other scriptSigs empty) with that
 * input's prevout script -- the standard legacy multi-input signing procedure.
 *
 * `prevout_script[i]` must be each input's 25-byte P2PKH script.
 *
 * Returns the final signed tx length, or -1 on error.
 */
long wallet_sign_all_inputs(unsigned char* tx, long txlen, long cap,
                            const unsigned char priv_be[32],
                            const unsigned char prevout_script[][25], unsigned long n) {
    /* parse the unsigned tx: version, vin count, per-input outpoint, then out */
    unsigned long pos = 4;
    unsigned long n_in = get_varint(tx + pos, &pos);
    if (n_in != n) return -1;
    /* We must rebuild the tx once per input. Sign every input against the
     * pure-unsigned form (all scriptSigs empty), stashing each resulting
     * scriptSig, then assemble the final signed tx.
     */
    unsigned char* signedtx = malloc(4096);
    long* sizes = malloc(sizeof(long) * (n + 1));
    unsigned char** bodies = malloc(sizeof(unsigned char*) * (n + 1));
    if (!signedtx || !sizes || !bodies) {
        free(signedtx); free(sizes); free(bodies); return -1;
    }
    /* First pass: produce and stash all scriptSigs (from the unsigned tx). */
    for (unsigned long i = 0; i < n; i++) {
        unsigned char* body = malloc(200);
        if (!body) { for (unsigned long j = 0; j < i; j++) free(bodies[j]); free(signedtx); free(sizes); free(bodies); return -1; }
        bodies[i] = body;
        /* z = sighash_all(unsigned tx, input i, prevout_script i) */
        unsigned char z[32];
        if (!wallet_sighash(z, tx, (unsigned long)txlen, i, prevout_script[i], 25)) {
            free(body); for (unsigned long j = 0; j < i; j++) free(bodies[j]); free(signedtx); free(sizes); free(bodies); return -1;
        }
        uint64_t r[4], sval[4];
        wallet_ecdsa_sign(r, sval, z, priv_be);
        int dl = der_signature(body, r, sval);
        /* body = <push dl+1> <DER><0x01> <push 33> <pubkey 33> */
        unsigned char tmp[200];
        int tl = 0;
        tmp[tl++] = (unsigned char)(dl + 1);
        memcpy(tmp + tl, body, dl); tl += dl;
        tmp[tl++] = 0x01;                          /* SIGHASH_ALL */
        tmp[tl++] = 0x21;
        scalar_to_pubkey(tmp + tl, priv_be); tl += 33;
        memcpy(body, tmp, tl);
        sizes[i] = tl;
    }

    /* Second pass: assemble the final tx. Copy input forward from the unsigned
     * tx; when reaching input i, write sizes[i] as the scriptSig len and the
     * body instead of the empty slot. */
    {
        unsigned long rp = 4;
        memcpy(signedtx, tx, 4); long slen = 4;   /* version */
        unsigned long cc;
        unsigned long vi = get_varint(tx + rp, &cc);
        rp += cc;                                  /* advance past vin-count varint */
        slen += put_varint(signedtx + slen, vi);  /* vin count */
        for (unsigned long i = 0; i < n; i++) {
            memcpy(signedtx + slen, tx + rp, 36); slen += 36; rp += 36; /* outpoint */
            unsigned long sl = get_varint(tx + rp, &cc); rp += cc;     /* sig len varint */
            /* write our sig length + body */
            slen += put_varint(signedtx + slen, (unsigned long)sizes[i]);
            memcpy(signedtx + slen, bodies[i], sizes[i]); slen += sizes[i];
            rp += sl;                              /* skip original sig (empty) */
            memcpy(signedtx + slen, tx + rp, 4); slen += 4; rp += 4;  /* seq */
        }
        /* outputs + locktime verbatim (up to the unsigned tx's true length) */
        memcpy(signedtx + slen, tx + rp, (unsigned long)txlen - rp);
        slen += (long)((unsigned long)txlen - rp);
        for (unsigned long j = 0; j < n; j++) free(bodies[j]);
        free(sizes); free(bodies);
        if (slen > cap) { free(signedtx); return -1; }
        memcpy(tx, signedtx, (size_t)slen);
        free(signedtx);
        return slen;
    }
}

/* One-call "send": build an unsigned P2PKH tx spending `n` of our UTXOs to a
 * destination and back to our change address (fee = total_in - amount), then
 * sign every input. `cap` bounds both the intermediate unsigned tx and the
 * final signed tx. Returns the signed tx length, or -1.
 *
 *   toutid[][32]/tidx[]/tval[]  -- the prevouts to spend (resolved by caller
 *                                  from its UTXO store).
 *   to_h160[20]                 -- destination P2PKH address hash.
 *   amount / fee                -- recipient amount and (exact) fee in sat.
 *   priv_be[32]                 -- the spending key (owns every prevout script
 *                                  = standard P2PKH pubkey-hash of priv_be).
 *   locktime                    -- 0 for a normal payment.
 */
long wallet_send_tx(unsigned char* out_tx, long cap,
                    const unsigned char toutid[][32], const unsigned long* tidx,
                    const unsigned long long* tval, unsigned long n,
                    const unsigned char to_h160[20],
                    unsigned long long amount, unsigned long long fee,
                    const unsigned char priv_be[32], unsigned long locktime) {
    /* our own change script (spending key's P2PKH) */
    unsigned char change_script[25];
    wallet_p2pkh_script(change_script, priv_be);
    /* destination output script */
    unsigned char to_script[25];
    wallet_p2pkh_output_script(to_script, to_h160);

    unsigned char* raw = malloc((size_t)cap + 1024);
    if (!raw) return -1;
    long rawlen = wallet_createrawtx(raw, cap, toutid, tidx, tval, n,
                                     to_script, amount, change_script, fee, locktime);
    if (rawlen < 0) { free(raw); return -1; }

    /* per-input prevout scripts: all are the spending key's P2PKH script */
    unsigned char (*prev)[25] = malloc((size_t)n * 25);
    if (!prev) { free(raw); return -1; }
    for (unsigned long i = 0; i < n; i++) wallet_p2pkh_script(prev[i], priv_be);

    unsigned char* signedtx = malloc((size_t)cap + 1024);
    if (!signedtx) { free(raw); free(prev); return -1; }
    memcpy(signedtx, raw, (size_t)rawlen);
    long slen = wallet_sign_all_inputs(signedtx, rawlen, cap + 1024, priv_be, prev, n);

    free(raw); free(prev);
    if (slen < 0) { free(signedtx); return -1; }
    if (slen > cap) { free(signedtx); return -1; }
    memcpy(out_tx, signedtx, (size_t)slen);
    free(signedtx);
    return slen;
}

/* ============================================================================
 * sendtoaddress -- pay `amount` to a destination from the wallet's own UTXOs,
 * doing greedy input selection (Core sendtoaddress within our wallet model).
 * Picks a subset of the wallet's UNSPENT P2PKH outputs (provided as a list of
 * caller-obtained UTXOs: outpoint txid/index + value) whose combined value
 * covers amount + fee, then builds + signs the send (wallet_send_tx) and
 * reports the change and the selected-input count/value.
 *
 *   our_txid[][32] / our_idx[] / our_val[] -- the wallet's own unspent prevouts
 *                                             (e.g. from gettxout/listunspent).
 *   n_ours -- count.
 *   to_h160[20] -- destination P2PKH address hash.
 *   amount / fee -- recipient amount and exact miner fee (sat).
 *   priv_be[32] -- the wallet spending key (owns every our P2PKH output).
 *   out_tx / cap -- destination for the signed tx.
 *   *out_change -- receives the change value (may be 0).
 *   *out_picked / *out_picked_val -- receives how many inputs / total value
 *                                    were selected (for reporting).
 *
 * Returns the signed tx length, or -1 if the wallet lacks enough UTXOs to cover
 * amount + fee (insufficient funds) or a rebuild fails.
 * ========================================================================== */
long wallet_sendtoaddress(unsigned char* out_tx, long cap,
                          const unsigned char our_txid[][32], const unsigned long* our_idx,
                          const unsigned long long* our_val, unsigned long n_ours,
                          const unsigned char to_h160[20],
                          unsigned long long amount, unsigned long long fee,
                          const unsigned char priv_be[32],
                          unsigned long long* out_change,
                          unsigned long* out_picked, unsigned long long* out_picked_val) {
    size_t maxin = (n_ours < 16) ? n_ours : 16;
    /* greedy: take the largest-value outputs first until they cover amount+fee */
    unsigned long pick[16];
    unsigned long np = 0;
    unsigned long long sum = 0;
    /* index sort desc by value */
    unsigned long order[16];
    for (unsigned long i = 0; i < n_ours && i < 16; i++) order[i] = i;
    for (unsigned long i = 0; i < n_ours && i < 16; i++)
        for (unsigned long j = i + 1; j < n_ours && j < 16; j++)
            if (our_val[order[j]] > our_val[order[i]]) { unsigned long t = order[i]; order[i] = order[j]; order[j] = t; }
    for (unsigned long k = 0; k < maxin && sum < amount + fee; k++) {
        unsigned long i = order[k];
        pick[np++] = i;
        sum += our_val[i];
    }
    if (sum < amount + fee) return -1;        /* insufficient funds */

    unsigned char (*tid)[32] = malloc(np * 32);
    unsigned long* tidx = malloc(np * sizeof(unsigned long));
    unsigned long long* tval = malloc(np * sizeof(unsigned long long));
    if (!tid || !tidx || !tval) { free(tid); free(tidx); free(tval); return -1; }
    for (unsigned long k = 0; k < np; k++) {
        memcpy(tid[k], our_txid[pick[k]], 32);
        tidx[k] = our_idx[pick[k]];
        tval[k] = our_val[pick[k]];
    }
    long sl = wallet_send_tx(out_tx, cap, tid, tidx, tval, np, to_h160, amount, fee, priv_be, 0);
    free(tid); free(tidx); free(tval);
    if (sl < 0) return -1;
    if (out_change) *out_change = sum - amount - fee;
    if (out_picked) *out_picked = np;
    if (out_picked_val) *out_picked_val = sum;
    return sl;
}

/* ============================================================================
 * signrawtransactionwithkey -- sign selected inputs of an arbitrary raw tx with
 * provided private keys (legacy SIGHASH_ALL, low-S). Mirrors Core's
 * signrawtransactionwithkey within our P2PKH scope.
 *
 *   tx / txlen            -- the raw tx (unsigned scriptSigs, or partially
 *                            signed; already-signed inputs are left untouched).
 *   keys[][32]            -- candidate private keys (big-endian bytes).
 *   nkeys                 -- number of keys.
 *   prevout[][25]         -- per-INPUT prevout P2PKH script (n_in entries); all
 *                            provided by the caller (the prevout script is what
 *                            SIGHASH_ALL is committed over). NULL entries mean
 *                            the input's prevout is not a P2PKH we can sign.
 *   out_tx / cap          -- destination for the signed tx.
 *   signed_mask_out       -- optional bitmask: bit i set if input i now carries
 *                            a (re)built signature; caller may use for detail.
 *
 * Returns the signed tx length, or -1 on error. Inputs whose scriptSig is
 * already non-empty are treated as already signed and left as-is. Keys are
 * tried in order for each blank input; the first key whose P2PKH h160 matches
 * is used (we sign with every matching key's signature, which for P2PKH is just
 * the one signature). Because SIGHASH_ALL commits over the whole tx, each
 * signature is built against the CURRENT tx (other inputs' existing scriptSigs
 * preserved, this input's slot = its prevout script) then re-serialized.
 * ========================================================================== */
long wallet_signrawtx_withkeys(unsigned char* out_tx, long cap,
                               const unsigned char* tx, unsigned long txlen,
                               const unsigned char keys[][32], unsigned long nkeys,
                               const unsigned char prevout[][25], unsigned long n_in,
                               unsigned char* signed_mask_out) {
    if (n_in == 0 || !prevout) return -1;
    /* working copy grows to <= cap + 1024 (sigs add ~108 B/input) */
    unsigned char* work = malloc((size_t)cap + 2048);
    unsigned char* next = malloc((size_t)cap + 2048);
    if (!work || !next) { free(work); free(next); return -1; }
    memcpy(work, tx, (size_t)txlen);
    long wlen = (long)txlen;
    unsigned long payload_msk = 0;

    for (unsigned long i = 0; i < n_in; i++) {
        /* locate input i scriptSig len offset in `work` */
        unsigned long p = 4, cc;
        unsigned long ni = get_varint(work + p, &cc); p += cc;
        if (ni != n_in) { free(work); free(next); return -1; }
        unsigned long sig_off = 0, sig_len = 0, siglen_pos = 0;
        for (unsigned long k = 0; k < n_in; k++) {
            if (p + 36 > (unsigned long)wlen) { free(work); free(next); return -1; }
            p += 36;
            siglen_pos = p;
            unsigned long sl = get_varint(work + p, &cc);
            if (k == i) { sig_off = p; sig_len = sl; }
            p += cc + sl + 4;
        }
        /* if already signed (non-empty scriptSig), skip */
        if (sig_len > 0) continue;
        /* find a key that owns this input's prevout P2PKH */
        const unsigned char* key = NULL;
        unsigned char want_h[20], kh[20];
        memcpy(want_h, prevout[i] + 3, 20);   /* P2PKH h160 in prevout script */
        for (unsigned long kk = 0; kk < nkeys; kk++) {
            wallet_key_h160(kh, keys[kk]);
            if (memcmp(kh, want_h, 20) == 0) { key = keys[kk]; break; }
        }
        if (!key) continue;                    /* no key owns this input */

        /* build SIGHASH_ALL sig over the CURRENT tx (this input's slot replaced
         * by its prevout script; others preserved) */
        unsigned char z[32];
        if (!wallet_sighash(z, work, (unsigned long)wlen, i, prevout[i], 25))
            { free(work); free(next); return -1; }
        uint64_t r[4], s[4];
        wallet_ecdsa_sign(r, s, z, key);
        unsigned char der[80];
        int dl = der_signature(der, r, s);
        unsigned char body[200];
        int bl = 0;
        body[bl++] = (unsigned char)(dl + 1);
        memcpy(body + bl, der, (unsigned long)dl); bl += dl;
        body[bl++] = 0x01;                     /* SIGHASH_ALL */
        body[bl++] = 0x21;
        scalar_to_pubkey(body + bl, key); bl += 33;

        /* rebuild tx with input i's scriptSig = <push bl> body */
        unsigned char* np = next;
        unsigned long rp = 4;
        long nn = 0;
        memcpy(np + nn, work, 4); nn += 4;
        unsigned long nv = get_varint(work + rp, &cc); rp += cc;
        nn += put_varint(np + nn, nv);
        for (unsigned long k = 0; k < n_in; k++) {
            memcpy(np + nn, work + rp, 36); nn += 36; rp += 36;
            unsigned long osl = get_varint(work + rp, &cc); rp += cc;
            if (k == i) {
                nn += put_varint(np + nn, (unsigned long)bl);
                memcpy(np + nn, body, (unsigned long)bl); nn += bl;
            } else {
                memcpy(np + nn, work + rp - cc, cc); nn += cc;
                memcpy(np + nn, work + rp, osl); nn += (long)osl;
            }
            rp += osl;
            memcpy(np + nn, work + rp, 4); nn += 4; rp += 4;
        }
        memcpy(np + nn, work + rp, (unsigned long)wlen - rp); nn += (long)((unsigned long)wlen - rp);
        /* swap work <-> next */
        unsigned char* t = work; work = next; next = t;
        wlen = nn;
        if (signed_mask_out) signed_mask_out[i] = 1;
        payload_msk |= (1UL << i);
    }

    if (wlen > cap) { free(work); free(next); return -1; }
    memcpy(out_tx, work, (size_t)wlen);
    free(work); free(next);
    return wlen;
}

/* ============================================================================
 * BIP39 mnemonic <-> seed, paired with BIP32 (recoverable wallets).
 * ==========================================================================*/

/* Generate a fresh 128-bit (12-word) BIP39 mnemonic from /dev/urandom.
 * Returns 1 on success (out receives the mnemonic string), 0 on error. */
int  wallet_mnemonic_generate(char out[256]) {
    unsigned char ent[16];
    FILE* f = fopen("/dev/urandom", "rb");
    if (!f || fread(ent, 1, 16, f) != 16) { if (f) fclose(f); return 0; }
    fclose(f);
    return bip39_generate(out, ent, 128);
}

/* Derive the 64-byte BIP39 seed from a mnemonic + optional passphrase. */
int  wallet_mnemonic_seed(unsigned char seed[64], const char* mn,
                          const char* pass, long passlen) {
    return bip39_mnemonic_to_seed(seed, mn, pass, passlen);
}

/* Validate a mnemonic (wordlist + checksum). Returns word count or -1. */
int  wallet_mnemonic_validate(const char* mn) {
    return bip39_validate(mn);
}

/* Derive the BIP32 master extended private key (xprv) from a seed. */
int  wallet_seed_master_xprv(char xprv[128], const unsigned char seed[64]) {
    unsigned char k[32], c[32], ser[78];
    unsigned char zero4[4] = {0, 0, 0, 0};
    if (bip32_master(k, c, seed, 64) != 1) return 0;
    bip32_extkey_serialize(ser, 1, 0, zero4, 0, c, k, 32);
    base58check_encode(xprv, ser, 78);
    return 1;
}

/* Derive the BIP44 m/44'/0'/0'/0/0 receive ADDRESS from a seed. */
int  wallet_seed_bip44_address(char addr[64], const unsigned char seed[64]) {
    unsigned indexes[5] = {0x80000000u | 44u, 0x80000000u, 0x80000000u, 0, 0};
    unsigned char k[32], c[32], pub[33], h[20], payload[21];
    char b58[128];
    if (bip32_derive_path(k, c, seed, 64, indexes, 5) != 1) return 0;
    scalar_to_pubkey(pub, k);
    hash160(h, pub, 33);
    payload[0] = 0x00; memcpy(payload + 1, h, 20);
    base58check_encode(b58, payload, 21);
    memcpy(addr, b58, 64);
    return 1;
}
