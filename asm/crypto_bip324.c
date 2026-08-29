/* crypto_bip324.c -- the BIP324 v2 transport cipher.
 *
 * After both peers exchange 64-byte ElligatorSwift encodings, everything else
 * falls out of one ECDH secret run through HKDF-SHA256. Four keys come out,
 * one per direction per purpose (lengths and packets), plus the two garbage
 * terminators and the session id.
 *
 * THE SALT CARRIES THE NETWORK MAGIC. That is not decoration: it is what
 * stops a mainnet node and a testnet node from completing a handshake with
 * each other. In v1 the network was checked per message header; in v2 there
 * are no plaintext headers to check, so the separation has to live in the key
 * derivation. Passing the wrong magic yields a session that fails on the
 * first packet with a tag mismatch, which looks exactly like a corrupted
 * connection.
 *
 * THE LABELS ARE BY ROLE, NOT BY DIRECTION. "initiator_L" is the key the
 * initiator SENDS lengths with and the responder RECEIVES them with. The
 * `side` flip below is the whole of that logic; getting it inverted gives a
 * cipher that talks fluently to itself and to nobody else.
 *
 * A packet is:  [3-byte length, stream-encrypted][AEAD(header || contents)]
 * The length is encrypted with a separate cipher because it must be readable
 * before the rest of the packet has arrived -- you cannot authenticate what
 * you have not yet received, so the length is confidential but not
 * authenticated. It is covered by the packet's own tag afterwards only in the
 * sense that a wrong length yields a wrong packet and a failed tag.
 */
#include <string.h>
#include <stdlib.h>
#include "crypto_bip324.h"
#include "crypto_hkdf.h"
#include "crypto_ellswift.h"

static void expand32(unsigned char out[32], const unsigned char prk[32], const char* label){
    hkdf_sha256_expand(out, 32, prk, (const unsigned char*)label, strlen(label));
}

int bip324_init(bip324_cipher_t* c,
                const unsigned char our_seckey32[32],
                const unsigned char our_ellswift64[64],
                const unsigned char their_ellswift64[64],
                const unsigned char net_magic[4],
                int initiator, int self_decrypt){
    unsigned char ecdh[32], prk[32], okm[32], salt[24 + 4];
    static const char SALT_PREFIX[] = "bitcoin_v2_shared_secret";

    memset(c, 0, sizeof *c);
    if (!ellswift_ecdh(ecdh, their_ellswift64, our_ellswift64, our_seckey32, initiator))
        return 0;

    memcpy(salt, SALT_PREFIX, 24);
    memcpy(salt + 24, net_magic, 4);
    hkdf_sha256_extract(prk, salt, sizeof salt, ecdh, sizeof ecdh);
    memset(ecdh, 0, sizeof ecdh);

    /* Which role's keys we send with. self_decrypt flips it so the same
     * object can read back what it wrote. */
    int side = (initiator != 0) != (self_decrypt != 0);

    expand32(okm, prk, "initiator_L");
    fschacha20_init(side ? &c->send_l : &c->recv_l, okm, BIP324_REKEY_INTERVAL);
    expand32(okm, prk, "initiator_P");
    fsaead_init(side ? &c->send_p : &c->recv_p, okm, BIP324_REKEY_INTERVAL);
    expand32(okm, prk, "responder_L");
    fschacha20_init(side ? &c->recv_l : &c->send_l, okm, BIP324_REKEY_INTERVAL);
    expand32(okm, prk, "responder_P");
    fsaead_init(side ? &c->recv_p : &c->send_p, okm, BIP324_REKEY_INTERVAL);

    /* One 32-byte draw holds both terminators: the initiator sends the first
     * half and expects the second, and the responder the reverse. Note this
     * keys off `initiator` alone, NOT `side` -- the terminators travel with
     * the real roles even when a test cipher is decrypting itself. */
    expand32(okm, prk, "garbage_terminators");
    memcpy(initiator ? c->send_garbage_terminator : c->recv_garbage_terminator, okm, 16);
    memcpy(initiator ? c->recv_garbage_terminator : c->send_garbage_terminator, okm + 16, 16);

    expand32(c->session_id, prk, "session_id");

    memset(okm, 0, sizeof okm);
    memset(prk, 0, sizeof prk);
    c->ready = 1;
    return 1;
}

void bip324_encrypt(bip324_cipher_t* c, unsigned char* out,
                    const unsigned char* contents, unsigned long clen,
                    const unsigned char* aad, unsigned long alen, int ignore){
    unsigned char len3[BIP324_LENGTH_LEN];
    len3[0] = (unsigned char)(clen);
    len3[1] = (unsigned char)(clen >> 8);
    len3[2] = (unsigned char)(clen >> 16);
    fschacha20_crypt(&c->send_l, len3, out, BIP324_LENGTH_LEN);

    /* The AEAD plaintext is the 1-byte header followed by the contents, as a
     * single message. Built in one buffer here rather than as Core's split
     * span pair; the tag covers the same bytes either way. */
    {
        unsigned char* p = out + BIP324_LENGTH_LEN;
        unsigned char* plain = p;                 /* encrypt in place */
        plain[0] = ignore ? BIP324_IGNORE_BIT : 0;
        if (clen) memcpy(plain + BIP324_HEADER_LEN, contents, clen);
        fsaead_encrypt(&c->send_p, p, p + BIP324_HEADER_LEN + clen,
                       plain, BIP324_HEADER_LEN + clen, aad, alen);
    }
}

unsigned long bip324_decrypt_length(bip324_cipher_t* c, const unsigned char in[3]){
    unsigned char buf[BIP324_LENGTH_LEN];
    fschacha20_crypt(&c->recv_l, in, buf, BIP324_LENGTH_LEN);
    return (unsigned long)buf[0] | ((unsigned long)buf[1] << 8) | ((unsigned long)buf[2] << 16);
}

int bip324_decrypt(bip324_cipher_t* c, unsigned char* contents_out,
                   const unsigned char* in, unsigned long inlen,
                   const unsigned char* aad, unsigned long alen, int* ignore_out){
    if (inlen < BIP324_HEADER_LEN + BIP324_AEAD_EXPANSION) return 0;
    unsigned long plen = inlen - BIP324_AEAD_EXPANSION;   /* header + contents */
    unsigned char header;

    /* Decrypt into a scratch that holds the header byte too. The caller's
     * buffer is one byte short of the AEAD plaintext, so the header is
     * recovered separately rather than by writing past the end of it. */
    {
        unsigned char stackbuf[256];
        unsigned char* plain = stackbuf;
        unsigned char* heap = 0;
        if (plen > sizeof stackbuf){
            heap = (unsigned char*)malloc(plen);
            if (!heap) return 0;
            plain = heap;
        }
        int ok = fsaead_decrypt(&c->recv_p, plain, in, plen,
                                in + plen, aad, alen);
        if (ok){
            header = plain[0];
            if (plen > BIP324_HEADER_LEN)
                memcpy(contents_out, plain + BIP324_HEADER_LEN, plen - BIP324_HEADER_LEN);
        }
        memset(plain, 0, plen);
        if (heap) free(heap);
        if (!ok) return 0;
    }
    if (ignore_out) *ignore_out = (header & BIP324_IGNORE_BIT) == BIP324_IGNORE_BIT;
    return 1;
}
