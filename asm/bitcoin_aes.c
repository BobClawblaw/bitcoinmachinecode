/* bitcoin_aes.c -- AES-256 (FIPS-197) + CBC mode, from scratch.
 *
 * WHY: Bitcoin Core's wallet encryption is AES-256-CBC of the wallet master
 * key, under a key derived from the passphrase by SHA512 rounds
 * (wallet/crypter.cpp). This node writes its own secp256k1, sha256 and
 * sha512; the wallet encryption path (daemon/wallet_crypter.c) needs the one
 * primitive it did not yet have. Byte-oriented, no T-tables (constant-shape
 * S-box lookups; not claimed constant-time against cache attacks, which is
 * out of scope for at-rest wallet encryption behind a passphrase). Verified
 * against the FIPS-197 Appendix C.3 known-answer vector in tests/test_aes.c.
 *
 * Exports:
 *   void aes256_encrypt_block(const u8 key[32], const u8 in[16], u8 out[16])
 *   void aes256_decrypt_block(const u8 key[32], const u8 in[16], u8 out[16])
 *   long aes256_cbc_encrypt(const u8 key[32], const u8 iv[16],
 *                           const u8* in, long inlen, u8* out, long cap)
 *   long aes256_cbc_decrypt(const u8 key[32], const u8 iv[16],
 *                           const u8* in, long inlen, u8* out, long cap)
 * CBC uses PKCS#7 padding, matching Core's EVP_aes_256_cbc default.
 */
#include <string.h>

typedef unsigned char u8;

static const u8 SBOX[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16 };

static u8 ISBOX[256];
static int g_isbox_ready;
static void build_isbox(void){
    for (int i = 0; i < 256; i++) ISBOX[SBOX[i]] = (u8)i;
    g_isbox_ready = 1;
}

static const u8 RCON[15] = {
0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d,0x9a };

/* GF(2^8) multiply by 2 (xtime) */
static u8 xt(u8 x){ return (u8)((x << 1) ^ ((x >> 7) * 0x1b)); }
static u8 mul(u8 a, u8 b){
    u8 r = 0;
    while (b){ if (b & 1) r ^= a; a = xt(a); b >>= 1; }
    return r;
}

#define NR 14                 /* AES-256 rounds */
#define NK 8                  /* key words */

static void key_expand(const u8 key[32], u8 rk[(NR+1)*16]){
    memcpy(rk, key, 32);
    int words = (NR + 1) * 4;
    u8 t[4];
    for (int i = NK; i < words; i++){
        memcpy(t, rk + (i-1)*4, 4);
        if (i % NK == 0){
            u8 tmp = t[0]; t[0]=t[1]; t[1]=t[2]; t[2]=t[3]; t[3]=tmp;    /* RotWord */
            for (int j = 0; j < 4; j++) t[j] = SBOX[t[j]];               /* SubWord */
            t[0] ^= RCON[i/NK - 1];
        } else if (i % NK == 4){
            for (int j = 0; j < 4; j++) t[j] = SBOX[t[j]];               /* AES-256 extra SubWord */
        }
        for (int j = 0; j < 4; j++) rk[i*4 + j] = rk[(i-NK)*4 + j] ^ t[j];
    }
}

void aes256_encrypt_block(const u8 key[32], const u8 in[16], u8 out[16]){
    u8 rk[(NR+1)*16]; key_expand(key, rk);
    u8 s[16]; memcpy(s, in, 16);
    for (int i = 0; i < 16; i++) s[i] ^= rk[i];                          /* AddRoundKey 0 */
    for (int r = 1; r <= NR; r++){
        u8 a[16];
        for (int i = 0; i < 16; i++) a[i] = SBOX[s[i]];                  /* SubBytes */
        /* ShiftRows (row = i%4, col = i/4; state is column-major) */
        u8 b[16];
        for (int c = 0; c < 4; c++) for (int row = 0; row < 4; row++)
            b[c*4 + row] = a[((c + row) % 4)*4 + row];
        if (r < NR){
            for (int c = 0; c < 4; c++){                                 /* MixColumns */
                u8* col = b + c*4;
                u8 c0=col[0],c1=col[1],c2=col[2],c3=col[3];
                col[0] = (u8)(mul(c0,2)^mul(c1,3)^c2^c3);
                col[1] = (u8)(c0^mul(c1,2)^mul(c2,3)^c3);
                col[2] = (u8)(c0^c1^mul(c2,2)^mul(c3,3));
                col[3] = (u8)(mul(c0,3)^c1^c2^mul(c3,2));
            }
        }
        for (int i = 0; i < 16; i++) s[i] = b[i] ^ rk[r*16 + i];         /* AddRoundKey r */
    }
    memcpy(out, s, 16);
}

void aes256_decrypt_block(const u8 key[32], const u8 in[16], u8 out[16]){
    if (!g_isbox_ready) build_isbox();
    u8 rk[(NR+1)*16]; key_expand(key, rk);
    u8 s[16]; memcpy(s, in, 16);
    for (int i = 0; i < 16; i++) s[i] ^= rk[NR*16 + i];                  /* AddRoundKey NR */
    for (int r = NR - 1; r >= 0; r--){
        /* InvShiftRows */
        u8 b[16];
        for (int c = 0; c < 4; c++) for (int row = 0; row < 4; row++)
            b[c*4 + row] = s[((c - row + 4) % 4)*4 + row];
        u8 a[16];
        for (int i = 0; i < 16; i++) a[i] = ISBOX[b[i]];                 /* InvSubBytes */
        for (int i = 0; i < 16; i++) a[i] ^= rk[r*16 + i];               /* AddRoundKey r */
        if (r > 0){
            for (int c = 0; c < 4; c++){                                 /* InvMixColumns */
                u8* col = a + c*4;
                u8 c0=col[0],c1=col[1],c2=col[2],c3=col[3];
                col[0] = (u8)(mul(c0,14)^mul(c1,11)^mul(c2,13)^mul(c3,9));
                col[1] = (u8)(mul(c0,9)^mul(c1,14)^mul(c2,11)^mul(c3,13));
                col[2] = (u8)(mul(c0,13)^mul(c1,9)^mul(c2,14)^mul(c3,11));
                col[3] = (u8)(mul(c0,11)^mul(c1,13)^mul(c2,9)^mul(c3,14));
            }
        }
        memcpy(s, a, 16);
    }
    memcpy(out, s, 16);
}

/* CBC + PKCS#7. Encrypt output = ceil((inlen+1)/16)*16. Returns length
 * written or -1 on capacity. */
long aes256_cbc_encrypt(const u8 key[32], const u8 iv[16],
                        const u8* in, long inlen, u8* out, long cap){
    long padded = ((inlen / 16) + 1) * 16;      /* always adds 1..16 pad bytes */
    if (cap < padded) return -1;
    u8 pad = (u8)(padded - inlen);
    u8 prev[16]; memcpy(prev, iv, 16);
    long o = 0;
    for (long off = 0; off < padded; off += 16){
        u8 blk[16];
        for (int i = 0; i < 16; i++){
            long idx = off + i;
            u8 b = idx < inlen ? in[idx] : pad;
            blk[i] = b ^ prev[i];
        }
        aes256_encrypt_block(key, blk, out + o);
        memcpy(prev, out + o, 16);
        o += 16;
    }
    return o;
}

/* Decrypt + strip PKCS#7. Returns plaintext length, or -1 on bad length /
 * bad padding. */
long aes256_cbc_decrypt(const u8 key[32], const u8 iv[16],
                        const u8* in, long inlen, u8* out, long cap){
    if (inlen <= 0 || inlen % 16 != 0 || cap < inlen) return -1;
    u8 prev[16]; memcpy(prev, iv, 16);
    for (long off = 0; off < inlen; off += 16){
        u8 blk[16];
        aes256_decrypt_block(key, in + off, blk);
        for (int i = 0; i < 16; i++) out[off + i] = blk[i] ^ prev[i];
        memcpy(prev, in + off, 16);
    }
    u8 pad = out[inlen - 1];
    if (pad < 1 || pad > 16) return -1;
    for (int i = 0; i < pad; i++) if (out[inlen - 1 - i] != pad) return -1;
    return inlen - pad;
}
