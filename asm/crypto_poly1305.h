/* crypto_poly1305.h -- RFC 8439 Poly1305 and the ChaCha20-Poly1305 AEAD. */
#ifndef BMC_CRYPTO_POLY1305_H
#define BMC_CRYPTO_POLY1305_H
typedef struct {
    unsigned r[5], h[5], pad[4];
    unsigned long leftover;
    unsigned char buffer[16];
    unsigned char final;
} poly1305_ctx;

void poly1305_init(poly1305_ctx* st, const unsigned char key[32]);
void poly1305_update(poly1305_ctx* st, const unsigned char* m, unsigned long bytes);
void poly1305_finish(poly1305_ctx* st, unsigned char mac[16]);
void poly1305_auth(unsigned char mac[16], const unsigned char* m, unsigned long bytes,
                   const unsigned char key[32]);
/* 1 if equal. Constant time in WHERE the difference is -- an early-exit
 * compare on a MAC lets an attacker find the tag a byte at a time. */
int  poly1305_verify(const unsigned char a[16], const unsigned char b[16]);

/* RFC 8439 section 2.8 AEAD. `out` may alias `plain`/`cipher`. */
void chacha20poly1305_encrypt(unsigned char* out, unsigned char tag[16],
                              const unsigned char* plain, unsigned long plen,
                              const unsigned char* aad, unsigned long alen,
                              const unsigned char key[32], const unsigned char nonce[12]);
/* 1 = authentic (and `out` written), 0 = tag mismatch (nothing written). */
int  chacha20poly1305_decrypt(unsigned char* out,
                              const unsigned char* cipher, unsigned long clen,
                              const unsigned char tag[16],
                              const unsigned char* aad, unsigned long alen,
                              const unsigned char key[32], const unsigned char nonce[12]);
#endif
