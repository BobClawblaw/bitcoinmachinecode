/* crypto_chacha20.c -- RFC 8439 ChaCha20, with an arbitrary 96-bit nonce and
 * 32-bit block counter.
 *
 * WHY A SECOND CHACHA20. bitcoin_muhash.asm already has one
 * (chacha20_keystream_k0), but it is deliberately specialised: nonce fixed at
 * zero, counter fixed at 0, because that is exactly what MuHash needs to
 * expand a 32-byte SHA256 into a 384-byte Num3072. BIP324 needs a general
 * one -- every packet uses a different counter, and the FSChaCha20 wrappers
 * rekey with a nonce derived from a sequence number. Rather than widen a
 * verified primitive that one caller depends on, this is a separate,
 * separately-tested implementation of the full RFC contract.
 *
 * TWO PATHS (2026-09-28). The block function below is the plain-C reference,
 * kept readable against RFC 8439; it also serves every single-block call and
 * every tail. From two blocks up, chacha20_crypt hands the whole blocks to
 * chacha20_xor_avx2 (chacha20_avx2.asm: six blocks in flight, two per ymm
 * register), which the reference proves at test time. Why the split is at
 * two: one block is a chain of dependent operations whichever way it is
 * written, and the scalar form runs its four columns on four ALU ports (60
 * ns), while the vector form runs them in the lanes of one register (90 ns);
 * from the second block on the vector form wins by 1.6x, and from six on
 * by 4x (0.29 ns/byte against this file's 0.77). The probe runs once.
 * chacha20_force_path exists for the test, which drives both paths over the
 * same inputs.
 *
 * STATE LAYOUT (RFC 8439 section 2.3):
 *   x[0..3]   the constants "expand 32-byte k"
 *   x[4..11]  the 256-bit key, little-endian u32 words
 *   x[12]     the block counter
 *   x[13..15] the 96-bit nonce, little-endian u32 words
 */
#include <string.h>
#include "crypto_chacha20.h"

extern int  chacha20_cpu_has_avx2(void);
extern void chacha20_xor_avx2(unsigned char* out, const unsigned char* in,
                              const unsigned s[16], unsigned long nblocks);

/* -1 = not probed yet, 0 = the C block, 1 = AVX2 for two blocks and up */
static int chacha20_path = -1;
int chacha20_force_path(int p){ chacha20_path = p; return chacha20_path; }
static int chacha20_use_avx2(void){
    if (chacha20_path < 0) chacha20_path = chacha20_cpu_has_avx2() ? 1 : 0;
    return chacha20_path;
}

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

static unsigned rd32le(const unsigned char* p){
    return (unsigned)p[0] | ((unsigned)p[1] << 8) | ((unsigned)p[2] << 16) | ((unsigned)p[3] << 24);
}
static void wr32le(unsigned char* p, unsigned v){
    p[0] = (unsigned char)v; p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16); p[3] = (unsigned char)(v >> 24);
}

/* one quarter-round, RFC 8439 section 2.1 */
#define QR(a, b, c, d) \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d, 8);  \
    c += d; b ^= c; b = ROTL32(b, 7)

/* One 64-byte keystream block from the state. RFC 8439 section 2.3.1.
 * The sixteen words are locals and the ten double-rounds are written out,
 * so the compiler keeps the state in registers and schedules the four
 * independent columns side by side: 1.2 -> 0.92 ns/byte for the same
 * arithmetic (the earlier x[16] loop spilled). */
/* The 20 rounds on sixteen locals; the caller decides what to do with the
 * words. Always inlined: at -O2 a non-inlined block wrote 64 bytes to a
 * buffer that the caller then XORed into the output, and that round trip
 * was 11 ns of a 60 ns block (gcc -O3, which inlines it, reaches 49 -- the
 * scalar floor, and Core's C++). */
#define CHACHA20_ROUNDS(x_in) \
    unsigned x0 = x_in[0],  x1 = x_in[1],  x2 = x_in[2],   x3 = x_in[3];  \
    unsigned x4 = x_in[4],  x5 = x_in[5],  x6 = x_in[6],   x7 = x_in[7];  \
    unsigned x8 = x_in[8],  x9 = x_in[9],  x10 = x_in[10], x11 = x_in[11]; \
    unsigned x12 = x_in[12], x13 = x_in[13], x14 = x_in[14], x15 = x_in[15]; \
    DR(); DR(); DR(); DR(); DR(); DR(); DR(); DR(); DR(); DR();
#define DR() \
    QR(x0, x4, x8,  x12); QR(x1, x5, x9,  x13); QR(x2, x6, x10, x14); QR(x3, x7, x11, x15); \
    QR(x0, x5, x10, x15); QR(x1, x6, x11, x12); QR(x2, x7, x8,  x13); QR(x3, x4, x9,  x14)
/* one keystream block XORed straight into out (full blocks) */
static inline __attribute__((always_inline)) void chacha20_block_xor(const unsigned x_in[16], const unsigned char* in, unsigned char* out){
    CHACHA20_ROUNDS(x_in)
#define W(i, v) wr32le(out + (i) * 4, ((v) + x_in[i]) ^ rd32le(in + (i) * 4))
    W(0, x0); W(1, x1); W(2, x2); W(3, x3); W(4, x4); W(5, x5); W(6, x6); W(7, x7);
    W(8, x8); W(9, x9); W(10, x10); W(11, x11); W(12, x12); W(13, x13); W(14, x14); W(15, x15);
#undef W
}
/* one keystream block to a buffer (the raw-keystream and tail paths) */
static inline __attribute__((always_inline)) void chacha20_block(const unsigned x_in[16], unsigned char out[64]){
    CHACHA20_ROUNDS(x_in)
#define W(i, v) wr32le(out + (i) * 4, (v) + x_in[i])
    W(0, x0); W(1, x1); W(2, x2); W(3, x3); W(4, x4); W(5, x5); W(6, x6); W(7, x7);
    W(8, x8); W(9, x9); W(10, x10); W(11, x11); W(12, x12); W(13, x13); W(14, x14); W(15, x15);
#undef W
}

void chacha20_init(chacha20_ctx* c, const unsigned char key[32]){
    /* "expand 32-byte k" as four little-endian words */
    c->s[0] = 0x61707865u; c->s[1] = 0x3320646eu;
    c->s[2] = 0x79622d32u; c->s[3] = 0x6b206574u;
    for (int i = 0; i < 8; i++) c->s[4 + i] = rd32le(key + i * 4);
    c->s[12] = 0;
    c->s[13] = c->s[14] = c->s[15] = 0;
}

void chacha20_seek(chacha20_ctx* c, const unsigned char nonce[12], unsigned counter){
    c->s[12] = counter;
    c->s[13] = rd32le(nonce + 0);
    c->s[14] = rd32le(nonce + 4);
    c->s[15] = rd32le(nonce + 8);
}

/* XOR `len` keystream bytes into out. in == NULL produces raw keystream,
 * which is what the FSChaCha20 length cipher wants. */
void chacha20_crypt(chacha20_ctx* c, const unsigned char* in, unsigned char* out, unsigned long len){
    unsigned char block[64];
    if (len >= 128 && chacha20_use_avx2()){
        unsigned long nb = len / 64;
        chacha20_xor_avx2(out, in, c->s, nb);
        c->s[12] += (unsigned)nb;             /* wraps at 2^32, as the RFC says */
        out += nb * 64; len -= nb * 64;
        if (in) in += nb * 64;
    }
    while (len >= 64 && in){                /* whole blocks with input: XOR in place, no buffer */
        chacha20_block_xor(c->s, in, out);
        c->s[12]++;                        /* RFC 8439: counter is 32-bit, wraps */
        in += 64; out += 64; len -= 64;
    }
    while (len){                            /* raw keystream, and the tail */
        chacha20_block(c->s, block);
        c->s[12]++;
        unsigned long n = len < 64 ? len : 64;
        if (in){ for (unsigned long i = 0; i < n; i++) out[i] = (unsigned char)(in[i] ^ block[i]); in += n; }
        else     memcpy(out, block, n);
        out += n; len -= n;
    }
}

void chacha20_keystream(chacha20_ctx* c, unsigned char* out, unsigned long len){
    chacha20_crypt(c, NULL, out, len);
}
