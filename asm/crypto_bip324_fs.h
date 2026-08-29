/* crypto_bip324_fs.h -- BIP324's forward-secure ChaCha20 and AEAD wrappers.
 *
 * Both rekey every BIP324_REKEY_INTERVAL operations, so a key recovered from
 * a running node decrypts only the packets since the last rekey rather than
 * the whole session. */
#ifndef BMC_CRYPTO_BIP324_FS_H
#define BMC_CRYPTO_BIP324_FS_H
#include "crypto_chacha20.h"

#define BIP324_REKEY_INTERVAL 224
#define BIP324_AEAD_EXPANSION 16          /* the Poly1305 tag */

/* The length cipher: a continuous keystream chunked into 3-byte pieces.
 * The keystream position is carried across calls, which is why this keeps a
 * partial block rather than calling chacha20_crypt directly -- see the .c. */
typedef struct {
    chacha20_ctx c;
    unsigned char ks[64];
    unsigned pos;                          /* bytes of ks already used */
    unsigned rekey_interval;
    unsigned chunk_counter;
    unsigned long long rekey_counter;
} fschacha20_ctx;

void fschacha20_init(fschacha20_ctx* f, const unsigned char key[32], unsigned rekey_interval);
void fschacha20_crypt(fschacha20_ctx* f, const unsigned char* in, unsigned char* out, unsigned long len);

/* The packet cipher. */
typedef struct {
    unsigned char key[32];
    unsigned rekey_interval;
    unsigned packet_counter;
    unsigned long long rekey_counter;
} fsaead_ctx;

void fsaead_init(fsaead_ctx* a, const unsigned char key[32], unsigned rekey_interval);
/* out needs plen bytes; tag is separate. */
void fsaead_encrypt(fsaead_ctx* a, unsigned char* out, unsigned char tag[16],
                    const unsigned char* plain, unsigned long plen,
                    const unsigned char* aad, unsigned long alen);
/* 1 = authentic. The counters advance either way -- see the .c for why. */
int  fsaead_decrypt(fsaead_ctx* a, unsigned char* out,
                    const unsigned char* cipher, unsigned long clen,
                    const unsigned char tag[16],
                    const unsigned char* aad, unsigned long alen);
#endif
