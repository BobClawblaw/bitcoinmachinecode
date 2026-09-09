/*
 * sha1_twin.c -- C twin for the SHA-1 module on the macOS port.
 *
 * Two AArch64 asm translations of asm/sha1.asm (scalar, unrolled-free)
 * both computed wrong W[0]/compression state; dynamic dumps showed W[0]
 * itself loaded/store incorrectly with everything static checking out.
 * Per the ripemd160 precedent (rule #2: prove the outcome, not a proxy)
 * the module ships as clang -O2 C with the identical public symbol.
 * Revisit hand-assembly after the daemon runs natively.
 *
 * Semantics match asm/sha1.asm exactly: FIPS 180-4 SHA-1, 80 rounds in
 * four phases (mux/xor/maj/xor; K 5A827999/6ED9EBA1/8F1BBCDC/CA62C1D6),
 * W extension ROTL1(W[i-3]^W[i-8]^W[i-14]^W[i-16]), padding identical to
 * SHA-256's, digest = 5 state words as BIG-ENDIAN bytes.
 */
#include <stdint.h>
#include <string.h>

static inline uint32_t rol32(uint32_t x, unsigned n)
{
    return (x << n) | (x >> (32 - n));
}

void sha1_init(uint32_t state[5])
{
    state[0] = 0x67452301u;
    state[1] = 0xefcdab89u;
    state[2] = 0x98badcfeu;
    state[3] = 0x10325476u;
    state[4] = 0xc3d2e1f0u;
}

void sha1_block(uint32_t state[5], const uint8_t block[64])
{
    uint32_t W[80];
    for (int i = 0; i < 16; i++) {
        W[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) | (uint32_t)block[i*4+3];
    }
    for (int i = 16; i < 80; i++) {
        W[i] = rol32(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
    for (int j = 0; j < 80; j++) {
        uint32_t f, k;
        switch (j / 20) {
        case 0: f = (b & c) | (~b & d);       k = 0x5a827999u; break;
        case 1: f = b ^ c ^ d;                k = 0x6ed9eba1u; break;
        case 2: f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdcu; break;
        default: f = b ^ c ^ d;               k = 0xca62c1d6u; break;
        }
        uint32_t temp = rol32(a, 5) + f + e + k + W[j];
        e = d; d = c; c = rol32(b, 30); b = a; a = temp;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

void sha1_full(unsigned char out[20], const void *msg, long long len)
{
    uint32_t st[5];
    const unsigned char *p = (const unsigned char *)msg;
    long long full = len >> 6;
    unsigned rem = (unsigned)(len & 63);
    unsigned char block[128];

    sha1_init(st);
    for (long long i = 0; i < full; i++, p += 64) {
        sha1_block(st, p);
    }
    memset(block, 0, sizeof block);
    memcpy(block, p, rem);
    block[rem] = 0x80;
    uint64_t bits = (uint64_t)len << 3;
    unsigned char lenbe[8];
    for (int i = 0; i < 8; i++) lenbe[i] = (unsigned char)(bits >> (56 - i*8));
    if (rem < 56) {
        memcpy(block + 56, lenbe, 8);
        sha1_block(st, block);
    } else {
        sha1_block(st, block);
        memcpy(block + 64 + 56, lenbe, 8);
        sha1_block(st, block + 64);
    }
    for (int i = 0; i < 5; i++) {
        out[i*4]   = (unsigned char)(st[i] >> 24);
        out[i*4+1] = (unsigned char)(st[i] >> 16);
        out[i*4+2] = (unsigned char)(st[i] >> 8);
        out[i*4+3] = (unsigned char)(st[i]);
    }
}
