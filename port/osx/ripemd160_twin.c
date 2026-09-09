/*
 * ripemd160_twin.c -- C twin for the RIPEMD-160 module on the macOS port.
 *
 * The bmc_osx port prefers hand-written AArch64 assembly with C twins as
 * oracles, mirroring the x86 tree. RIPEMD-160's x86 body is a fully
 * unrolled 2x80-round kernel with register renaming; two AArch64
 * translation attempts (mechanical 1:1, then generated loop-form) each
 * produced digests that diverged from the reference in ways three rounds
 * of static verification could not localize. Engineering rule #2 (prove
 * the outcome, not a proxy) beats rule "everything is assembly": this
 * module ships as compiler-generated AArch64 (clang -O2) with the SAME
 * public symbol and byte-identical semantics, differential-verified
 * against hashlib and the x86 tree's vectors. Revisit hand-assembly after
 * the daemon runs natively.
 *
 * Semantics match asm/ripemd160.asm exactly:
 *   - padding: 0x80, zeros, 64-bit LE bit-length
 *   - 16 LE message words per block
 *   - two parallel lines of 80 rounds (RL/RP/SL/SPROT/KCON tables)
 *   - final cross-mix; digest = 5 state words as LITTLE-ENDIAN bytes
 *     (the x86 .out stores raw host words -- no bswap).
 */
#include <stdint.h>
#include <string.h>

static const uint32_t KL[5] = { 0x00000000u, 0x5a827999u, 0x6ed9eba1u,
                                0x8f1bbcdcu, 0xa953fd4eu };
static const uint32_t KR[5] = { 0x50a28be6u, 0x5c4dd124u, 0x6d703ef3u,
                                0x7a6d76e9u, 0x00000000u };

static const uint8_t RL[80] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
    7, 4,13, 1,10, 6,15, 3,12, 0, 9, 5, 2,14,11, 8,
    3,10,14, 4, 9,15, 8, 1, 2, 7, 0, 6,13,11, 5,12,
    1, 9,11,10, 0, 8,12, 4,13, 3, 7,15,14, 5, 6, 2,
    4, 0, 5, 9, 7,12, 2,10,14, 1, 3, 8,11, 6,15,13 };
static const uint8_t RP[80] = {
    5,14, 7, 0, 9, 2,11, 4,13, 6,15, 8, 1,10, 3,12,
    6,11, 3, 7, 0,13, 5,10,14,15, 8,12, 4, 9, 1, 2,
   15, 5, 1, 3, 7,14, 6, 9,11, 8,12, 2,10, 0, 4,13,
    8, 6, 4, 1, 3,11,15, 0, 5,12, 2,13, 9, 7,10,14,
   12,15,10, 4, 1, 5, 8, 7, 6, 2,13,14, 0, 3, 9,11 };
static const uint8_t SL[80] = {
   11,14,15,12, 5, 8, 7, 9,11,13,14,15, 6, 7, 9, 8,
    7, 6, 8,13,11, 9, 7,15, 7,12,15, 9,11, 7,13,12,
   11,13, 6, 7,14, 9,13,15,14, 8,13, 6, 5,12, 7, 5,
   11,12,14,15,14,15, 9, 8, 9,14, 5, 6, 8, 6, 5,12,
    9,15, 5,11, 6, 8,13,12, 5,12,13,14,11, 8, 5, 6 };
static const uint8_t SP[80] = {
    8, 9, 9,11,13,15,15, 5, 7, 7, 8,11,14,14,12, 6,
    9,13,15, 7,12, 8, 9,11, 7, 7,12, 7, 6,15,13,11,
    9, 7,15,11, 8, 6, 6,14,12,13, 5,14,13,13, 7, 5,
   15, 5, 8,11,14,14, 6,14, 6, 9,12, 9,12, 5,15, 8,
    8, 5,12, 9,12, 5,14, 6, 8,13, 6, 5,15,13,11,11 };

static inline uint32_t rol32(uint32_t x, unsigned n)
{
    return (x << n) | (x >> (32 - n));
}

static void compress(uint32_t st[5], const uint32_t X[16])
{
    uint32_t A = st[0], B = st[1], C = st[2], D = st[3], E = st[4];
    uint32_t A2 = st[0], B2 = st[1], C2 = st[2], D2 = st[3], E2 = st[4];
    uint32_t Tl, Tr;
    for (int j = 0; j < 80; j++) {
        int fl = j / 16, fr = 4 - j / 16;
        uint32_t flv, frv;
        switch (fl) {
        case 0: flv = B ^ C ^ D; break;
        case 1: flv = (B & C) | (~B & D); break;
        case 2: flv = (B | ~C) ^ D; break;
        case 3: flv = (B & D) | (C & ~D); break;
        default: flv = B ^ (C | ~D); break;
        }
        switch (fr) {
        case 0: frv = B2 ^ C2 ^ D2; break;
        case 1: frv = (B2 & C2) | (~B2 & D2); break;
        case 2: frv = (B2 | ~C2) ^ D2; break;
        case 3: frv = (B2 & D2) | (C2 & ~D2); break;
        default: frv = B2 ^ (C2 | ~D2); break;
        }
        Tl = rol32(A + flv + X[RL[j]] + KL[j / 16], SL[j]) + E;
        A = E; E = D; D = rol32(C, 10); C = B; B = Tl;
        Tr = rol32(A2 + frv + X[RP[j]] + KR[j / 16], SP[j]) + E2;
        A2 = E2; E2 = D2; D2 = rol32(C2, 10); C2 = B2; B2 = Tr;
    }

    uint32_t T = st[1] + C + D2;
    st[1] = st[2] + D + E2;
    st[2] = st[3] + E + A2;
    st[3] = st[4] + A + B2;
    st[4] = st[0] + B + C2;
    st[0] = T;
}

void ripemd160(unsigned char out[20], const void *in, long long len)
{
    uint32_t st[5] = { 0x67452301u, 0xefcdab89u, 0x98badcfeu,
                       0x10325476u, 0xc3d2e1f0u };
    const unsigned char *p = (const unsigned char *)in;
    long long full = len >> 6;          /* full 64-byte blocks */
    unsigned rem = (unsigned)(len & 63);
    unsigned char block[128];
    uint32_t X[16];

    for (long long i = 0; i < full; i++, p += 64) {
        memcpy(X, p, 64);               /* LE words: plain copy */
        compress(st, X);
    }

    /* padded tail: rem + 0x80 + zeros + 64-bit LE bit length */
    memset(block, 0, sizeof block);
    memcpy(block, p, rem);
    block[rem] = 0x80;
    uint64_t bits = (uint64_t)len << 3;
    if (rem < 56) {
        memcpy(block + 56, &bits, 8);
        memcpy(X, block, 64);
        compress(st, X);
    } else {
        memcpy(block + 64 + 56, &bits, 8);
        memcpy(X, block, 64);
        compress(st, X);
        memcpy(X, block + 64, 64);
        compress(st, X);
    }

    /* digest: state words as little-endian bytes (no bswap, like x86) */
    memcpy(out, st, 20);
}
