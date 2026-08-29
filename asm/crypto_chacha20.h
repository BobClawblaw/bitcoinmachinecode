/* crypto_chacha20.h -- RFC 8439 ChaCha20 with arbitrary nonce and counter.
 * Distinct from bitcoin_muhash.asm's chacha20_keystream_k0, which is fixed at
 * nonce 0 / counter 0 for MuHash. See crypto_chacha20.c for why both exist. */
#ifndef BMC_CRYPTO_CHACHA20_H
#define BMC_CRYPTO_CHACHA20_H
typedef struct { unsigned s[16]; } chacha20_ctx;

void chacha20_init(chacha20_ctx* c, const unsigned char key[32]);
/* 96-bit nonce + 32-bit block counter, RFC 8439 section 2.3 */
void chacha20_seek(chacha20_ctx* c, const unsigned char nonce[12], unsigned counter);
/* XOR the keystream over `in` into `out`; in == NULL emits raw keystream.
 * Advances the block counter, so successive calls continue the stream. */
void chacha20_crypt(chacha20_ctx* c, const unsigned char* in, unsigned char* out, unsigned long len);
void chacha20_keystream(chacha20_ctx* c, unsigned char* out, unsigned long len);
#endif
