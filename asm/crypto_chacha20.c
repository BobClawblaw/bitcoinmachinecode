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
 * It is plain C, not assembly. The assembly version exists because MuHash
 * calls it once per UTXO across a whole-chain replay; BIP324 calls this once
 * per network packet, where the socket dominates by orders of magnitude.
 * Auditability against RFC 8439 is worth more here than throughput.
 *
 * STATE LAYOUT (RFC 8439 section 2.3):
 *   x[0..3]   the constants "expand 32-byte k"
 *   x[4..11]  the 256-bit key, little-endian u32 words
 *   x[12]     the block counter
 *   x[13..15] the 96-bit nonce, little-endian u32 words
 */
#include <string.h>
#include "crypto_chacha20.h"

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

/* One 64-byte keystream block from the state. RFC 8439 section 2.3.1. */
static void chacha20_block(const unsigned x_in[16], unsigned char out[64]){
    unsigned x[16];
    memcpy(x, x_in, sizeof x);
    for (int i = 0; i < 10; i++){          /* 20 rounds = 10 double-rounds */
        QR(x[0], x[4], x[ 8], x[12]);      /* column rounds */
        QR(x[1], x[5], x[ 9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);      /* diagonal rounds */
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[ 8], x[13]);
        QR(x[3], x[4], x[ 9], x[14]);
    }
    for (int i = 0; i < 16; i++) wr32le(out + i * 4, x[i] + x_in[i]);
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
    while (len){
        chacha20_block(c->s, block);
        c->s[12]++;                        /* RFC 8439: counter is 32-bit, wraps */
        unsigned long n = len < 64 ? len : 64;
        if (in){ for (unsigned long i = 0; i < n; i++) out[i] = (unsigned char)(in[i] ^ block[i]); in += n; }
        else     memcpy(out, block, n);
        out += n; len -= n;
    }
}

void chacha20_keystream(chacha20_ctx* c, unsigned char* out, unsigned long len){
    chacha20_crypt(c, NULL, out, len);
}
