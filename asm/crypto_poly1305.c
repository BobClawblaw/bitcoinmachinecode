/* crypto_poly1305.c -- RFC 8439 Poly1305 one-time authenticator, and the
 * ChaCha20-Poly1305 AEAD built on it.
 *
 * Poly1305 evaluates a polynomial over GF(2^130 - 5). The 130-bit field is
 * carried here as five 26-bit limbs in u32s: a 64-bit product of two 26-bit
 * limbs cannot overflow, so the multiply needs no 128-bit type and stays
 * portable and auditable. This is the same limb layout the reference
 * implementations use, for the same reason.
 *
 * THE CLAMP MATTERS. RFC 8439 section 2.5 requires r's top four bits of each
 * 32-bit word cleared and the low two bits of the upper three words cleared.
 * Skipping it does not break arithmetic -- it breaks the SECURITY PROOF, and
 * the output still looks like a MAC. Only the published vectors catch it.
 *
 * VERIFICATION IS CONSTANT-TIME. A byte-by-byte early-exit compare on a MAC
 * leaks where the first difference is, which is enough to forge one byte at a
 * time. poly1305_verify accumulates the difference instead.
 */
#include <string.h>
#include "crypto_poly1305.h"
#include "crypto_chacha20.h"

static unsigned rd32le(const unsigned char* p){
    return (unsigned)p[0] | ((unsigned)p[1] << 8) | ((unsigned)p[2] << 16) | ((unsigned)p[3] << 24);
}
static void wr32le(unsigned char* p, unsigned v){
    p[0]=(unsigned char)v; p[1]=(unsigned char)(v>>8); p[2]=(unsigned char)(v>>16); p[3]=(unsigned char)(v>>24);
}

void poly1305_init(poly1305_ctx* st, const unsigned char key[32]){
    /* r, clamped per RFC 8439 section 2.5, split into 26-bit limbs */
    unsigned t0 = rd32le(key + 0), t1 = rd32le(key + 4);
    unsigned t2 = rd32le(key + 8), t3 = rd32le(key + 12);
    st->r[0] =  t0                         & 0x3ffffff;
    st->r[1] = ((t0 >> 26) | (t1 <<  6))   & 0x3ffff03;
    st->r[2] = ((t1 >> 20) | (t2 << 12))   & 0x3ffc0ff;
    st->r[3] = ((t2 >> 14) | (t3 << 18))   & 0x3f03fff;
    st->r[4] =  (t3 >>  8)                 & 0x00fffff;
    for (int i = 0; i < 5; i++) st->h[i] = 0;
    /* s: the second half of the key, added at the end */
    st->pad[0] = rd32le(key + 16); st->pad[1] = rd32le(key + 20);
    st->pad[2] = rd32le(key + 24); st->pad[3] = rd32le(key + 28);
    st->leftover = 0;
    st->final = 0;
}

static void poly1305_blocks(poly1305_ctx* st, const unsigned char* m, unsigned long bytes){
    const unsigned hibit = st->final ? 0 : (1u << 24);   /* the 2^128 pad bit */
    unsigned r0=st->r[0], r1=st->r[1], r2=st->r[2], r3=st->r[3], r4=st->r[4];
    unsigned s1=r1*5, s2=r2*5, s3=r3*5, s4=r4*5;
    unsigned h0=st->h[0], h1=st->h[1], h2=st->h[2], h3=st->h[3], h4=st->h[4];
    while (bytes >= 16){
        /* h += m */
        h0 += ( rd32le(m+ 0)                     ) & 0x3ffffff;
        h1 += ((rd32le(m+ 3) >> 2)               ) & 0x3ffffff;
        h2 += ((rd32le(m+ 6) >> 4)               ) & 0x3ffffff;
        h3 += ((rd32le(m+ 9) >> 6)               ) & 0x3ffffff;
        h4 += ((rd32le(m+12) >> 8)               ) | hibit;
        /* h *= r, reducing mod 2^130-5 as we go (the *5 terms) */
        unsigned long long d0 = (unsigned long long)h0*r0 + (unsigned long long)h1*s4 + (unsigned long long)h2*s3 + (unsigned long long)h3*s2 + (unsigned long long)h4*s1;
        unsigned long long d1 = (unsigned long long)h0*r1 + (unsigned long long)h1*r0 + (unsigned long long)h2*s4 + (unsigned long long)h3*s3 + (unsigned long long)h4*s2;
        unsigned long long d2 = (unsigned long long)h0*r2 + (unsigned long long)h1*r1 + (unsigned long long)h2*r0 + (unsigned long long)h3*s4 + (unsigned long long)h4*s3;
        unsigned long long d3 = (unsigned long long)h0*r3 + (unsigned long long)h1*r2 + (unsigned long long)h2*r1 + (unsigned long long)h3*r0 + (unsigned long long)h4*s4;
        unsigned long long d4 = (unsigned long long)h0*r4 + (unsigned long long)h1*r3 + (unsigned long long)h2*r2 + (unsigned long long)h3*r1 + (unsigned long long)h4*r0;
        /* carry propagate */
        unsigned c;
        c = (unsigned)(d0 >> 26); h0 = (unsigned)d0 & 0x3ffffff;
        d1 += c; c = (unsigned)(d1 >> 26); h1 = (unsigned)d1 & 0x3ffffff;
        d2 += c; c = (unsigned)(d2 >> 26); h2 = (unsigned)d2 & 0x3ffffff;
        d3 += c; c = (unsigned)(d3 >> 26); h3 = (unsigned)d3 & 0x3ffffff;
        d4 += c; c = (unsigned)(d4 >> 26); h4 = (unsigned)d4 & 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
        h1 += c;
        m += 16; bytes -= 16;
    }
    st->h[0]=h0; st->h[1]=h1; st->h[2]=h2; st->h[3]=h3; st->h[4]=h4;
}

void poly1305_update(poly1305_ctx* st, const unsigned char* m, unsigned long bytes){
    if (st->leftover){
        unsigned long want = 16 - st->leftover;
        if (want > bytes) want = bytes;
        memcpy(st->buffer + st->leftover, m, want);
        bytes -= want; m += want; st->leftover += want;
        if (st->leftover < 16) return;
        poly1305_blocks(st, st->buffer, 16);
        st->leftover = 0;
    }
    if (bytes >= 16){
        unsigned long want = bytes & ~(unsigned long)15;
        poly1305_blocks(st, m, want);
        m += want; bytes -= want;
    }
    if (bytes){ memcpy(st->buffer + st->leftover, m, bytes); st->leftover += bytes; }
}

void poly1305_finish(poly1305_ctx* st, unsigned char mac[16]){
    if (st->leftover){
        st->buffer[st->leftover++] = 1;                    /* the pad bit, explicitly */
        while (st->leftover < 16) st->buffer[st->leftover++] = 0;
        st->final = 1;
        poly1305_blocks(st, st->buffer, 16);
    }
    unsigned h0=st->h[0], h1=st->h[1], h2=st->h[2], h3=st->h[3], h4=st->h[4];
    unsigned c;
    c = h1 >> 26; h1 &= 0x3ffffff;
    h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
    h3 += c; c = h3 >> 26; h3 &= 0x3ffffff;
    h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
    h1 += c;
    /* compute h + -p, and select it if it did not borrow -- branchlessly */
    unsigned g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    unsigned g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    unsigned g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    unsigned g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    unsigned g4 = h4 + c - (1u << 26);
    unsigned mask = (g4 >> 31) - 1;          /* all-ones when g >= 0 */
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2; h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;
    /* back to 4 x 32-bit, then + s */
    unsigned f0 = ((h0      ) | (h1 << 26));
    unsigned f1 = ((h1 >>  6) | (h2 << 20));
    unsigned f2 = ((h2 >> 12) | (h3 << 14));
    unsigned f3 = ((h3 >> 18) | (h4 <<  8));
    unsigned long long t;
    t = (unsigned long long)f0 + st->pad[0]; f0 = (unsigned)t;
    t = (unsigned long long)f1 + st->pad[1] + (t >> 32); f1 = (unsigned)t;
    t = (unsigned long long)f2 + st->pad[2] + (t >> 32); f2 = (unsigned)t;
    t = (unsigned long long)f3 + st->pad[3] + (t >> 32); f3 = (unsigned)t;
    wr32le(mac + 0, f0); wr32le(mac + 4, f1); wr32le(mac + 8, f2); wr32le(mac + 12, f3);
    memset(st, 0, sizeof *st);
}

void poly1305_auth(unsigned char mac[16], const unsigned char* m, unsigned long bytes,
                   const unsigned char key[32]){
    poly1305_ctx st;
    poly1305_init(&st, key);
    poly1305_update(&st, m, bytes);
    poly1305_finish(&st, mac);
}

/* Constant time in WHERE the difference is -- an early-exit compare on a MAC
 * lets an attacker find the right tag one byte at a time. */
int poly1305_verify(const unsigned char a[16], const unsigned char b[16]){
    unsigned d = 0;
    for (int i = 0; i < 16; i++) d |= (unsigned)(a[i] ^ b[i]);
    return d == 0;
}

/* ---- RFC 8439 section 2.8 AEAD ------------------------------------------
 * The one-time Poly1305 key is the first 32 bytes of ChaCha20 keystream at
 * counter 0; the ciphertext starts at counter 1. Reusing counter 0 for data
 * would leak the authenticator key, so the split is not an optimisation. */
static void aead_pad16(poly1305_ctx* st, unsigned long len){
    static const unsigned char z[16] = {0};
    unsigned long r = len % 16;
    if (r) poly1305_update(st, z, 16 - r);
}
static void aead_len64(poly1305_ctx* st, unsigned long len){
    unsigned char b[8];
    for (int i = 0; i < 8; i++) b[i] = (unsigned char)((unsigned long long)len >> (8*i));
    poly1305_update(st, b, 8);
}

void chacha20poly1305_encrypt(unsigned char* out, unsigned char tag[16],
                              const unsigned char* plain, unsigned long plen,
                              const unsigned char* aad, unsigned long alen,
                              const unsigned char key[32], const unsigned char nonce[12]){
    chacha20_ctx c;
    unsigned char polykey[64];
    chacha20_init(&c, key);
    chacha20_seek(&c, nonce, 0);
    chacha20_keystream(&c, polykey, 64);          /* block 0 -> one-time key */
    chacha20_seek(&c, nonce, 1);                  /* data starts at block 1 */
    if (plen) chacha20_crypt(&c, plain, out, plen);

    poly1305_ctx st;
    poly1305_init(&st, polykey);
    if (alen){ poly1305_update(&st, aad, alen); aead_pad16(&st, alen); }
    if (plen){ poly1305_update(&st, out, plen);  aead_pad16(&st, plen); }
    aead_len64(&st, alen);
    aead_len64(&st, plen);
    poly1305_finish(&st, tag);
}

int chacha20poly1305_decrypt(unsigned char* out,
                             const unsigned char* cipher, unsigned long clen,
                             const unsigned char tag[16],
                             const unsigned char* aad, unsigned long alen,
                             const unsigned char key[32], const unsigned char nonce[12]){
    chacha20_ctx c;
    unsigned char polykey[64];
    chacha20_init(&c, key);
    chacha20_seek(&c, nonce, 0);
    chacha20_keystream(&c, polykey, 64);

    poly1305_ctx st;
    unsigned char want[16];
    poly1305_init(&st, polykey);
    if (alen){ poly1305_update(&st, aad, alen); aead_pad16(&st, alen); }
    if (clen){ poly1305_update(&st, cipher, clen); aead_pad16(&st, clen); }
    aead_len64(&st, alen);
    aead_len64(&st, clen);
    poly1305_finish(&st, want);
    /* AUTHENTICATE BEFORE DECRYPTING. Writing plaintext for a bad tag hands
     * an attacker a decryption oracle even if the caller checks the return. */
    if (!poly1305_verify(want, tag)) return 0;
    chacha20_seek(&c, nonce, 1);
    if (clen) chacha20_crypt(&c, cipher, out, clen);
    return 1;
}
