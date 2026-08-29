/* crypto_bip324.h -- the BIP324 v2 transport cipher: key derivation from the
 * ElligatorSwift handshake, plus packet encryption and decryption. */
#ifndef BMC_CRYPTO_BIP324_H
#define BMC_CRYPTO_BIP324_H
#include "crypto_bip324_fs.h"

#define BIP324_LENGTH_LEN 3
#define BIP324_HEADER_LEN 1
/* what a packet costs over its contents: 3 length + 1 header + 16 tag */
#define BIP324_EXPANSION (BIP324_LENGTH_LEN + BIP324_HEADER_LEN + BIP324_AEAD_EXPANSION)
#define BIP324_GARBAGE_TERMINATOR_LEN 16
#define BIP324_MAX_GARBAGE_LEN 4095
#define BIP324_IGNORE_BIT 0x80

typedef struct {
    fschacha20_ctx send_l, recv_l;      /* the 3-byte length fields */
    fsaead_ctx     send_p, recv_p;      /* the packets themselves */
    unsigned char  send_garbage_terminator[BIP324_GARBAGE_TERMINATOR_LEN];
    unsigned char  recv_garbage_terminator[BIP324_GARBAGE_TERMINATOR_LEN];
    unsigned char  session_id[32];
    int            ready;
} bip324_cipher_t;

/* Derive the session from our key and both ellswift encodings.
 * `net_magic` is the 4-byte network start string, which is what keeps a
 * mainnet handshake from ever succeeding against a testnet peer.
 * `self_decrypt` swaps the send and receive directions so one cipher can
 * decrypt its own output; it is for tests, and normal callers pass 0.
 * Returns 1 on success, 0 if the key is unusable. */
int bip324_init(bip324_cipher_t* c,
                const unsigned char our_seckey32[32],
                const unsigned char our_ellswift64[64],
                const unsigned char their_ellswift64[64],
                const unsigned char net_magic[4],
                int initiator, int self_decrypt);

/* out needs contents_len + BIP324_EXPANSION bytes. */
void bip324_encrypt(bip324_cipher_t* c, unsigned char* out,
                    const unsigned char* contents, unsigned long clen,
                    const unsigned char* aad, unsigned long alen, int ignore);

/* Decrypt the 3-byte length prefix. This ADVANCES the length cipher, so it
 * must be called exactly once per packet, before bip324_decrypt. */
unsigned long bip324_decrypt_length(bip324_cipher_t* c, const unsigned char in[3]);

/* `in` is everything after the 3-byte length: header + contents + tag.
 * contents_out needs inlen - 1 - 16 bytes. 1 = authentic. */
int bip324_decrypt(bip324_cipher_t* c, unsigned char* contents_out,
                   const unsigned char* in, unsigned long inlen,
                   const unsigned char* aad, unsigned long alen, int* ignore_out);
#endif
