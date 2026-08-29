/* crypto_bip324_fs.c -- BIP324's forward-secure wrappers around ChaCha20 and
 * the ChaCha20-Poly1305 AEAD.
 *
 * Every BIP324_REKEY_INTERVAL operations both ciphers derive a fresh key from
 * their own keystream and forget the old one. An attacker who extracts the
 * live key from a node's memory therefore gets the current window and nothing
 * earlier.
 *
 * THE LENGTH CIPHER KEEPS A PARTIAL BLOCK. This is the detail that breaks
 * interop if missed. BIP324 encrypts each packet's 3-byte length field with
 * one fschacha20_crypt call, and those calls consume a SINGLE continuous
 * keystream: bytes 0-2, then 3-5, then 6-8, all from the same 64-byte block.
 * The bare chacha20_crypt underneath discards the rest of a block once a call
 * ends -- correct for RFC 8439, where every message starts fresh, and wrong
 * here. So the leftover lives in this struct. Getting it wrong desynchronises
 * lengths after the very first packet, and since lengths are what frame the
 * stream, the connection dies with no useful diagnostic.
 *
 * THE COUNTERS ADVANCE ON A FAILED DECRYPT. That looks like a bug and is not:
 * both peers must stay on the same packet number, and a peer that rejected a
 * forged packet has still consumed a packet slot. Core does the same. The
 * caller is expected to drop the connection on a failed tag anyway.
 */
#include <string.h>
#include "crypto_bip324_fs.h"
#include "crypto_poly1305.h"

/* nonce = LE32(a) || LE64(b), matching Core's Nonce96 */
static void nonce96(unsigned char n[12], unsigned a, unsigned long long b){
    n[0] = (unsigned char)a;        n[1] = (unsigned char)(a >> 8);
    n[2] = (unsigned char)(a >> 16);n[3] = (unsigned char)(a >> 24);
    for (int i = 0; i < 8; i++) n[4 + i] = (unsigned char)(b >> (8 * i));
}

/* ------------------------------- FSChaCha20 ------------------------------ */

void fschacha20_init(fschacha20_ctx* f, const unsigned char key[32], unsigned rekey_interval){
    unsigned char n[12];
    memset(f, 0, sizeof *f);
    chacha20_init(&f->c, key);
    nonce96(n, 0, 0);
    chacha20_seek(&f->c, n, 0);
    f->pos = sizeof f->ks;                 /* cache empty */
    f->rekey_interval = rekey_interval ? rekey_interval : BIP324_REKEY_INTERVAL;
}

/* pull `len` bytes of raw keystream, refilling the cached block as needed */
static void fs_keystream(fschacha20_ctx* f, unsigned char* out, unsigned long len){
    while (len){
        if (f->pos == sizeof f->ks){
            chacha20_crypt(&f->c, 0, f->ks, sizeof f->ks);
            f->pos = 0;
        }
        unsigned long n = sizeof f->ks - f->pos;
        if (n > len) n = len;
        memcpy(out, f->ks + f->pos, n);
        f->pos += (unsigned)n; out += n; len -= n;
    }
}

void fschacha20_crypt(fschacha20_ctx* f, const unsigned char* in, unsigned char* out, unsigned long len){
    while (len){
        unsigned char ks[64];
        unsigned long n = len < sizeof ks ? len : sizeof ks;
        fs_keystream(f, ks, n);
        for (unsigned long i = 0; i < n; i++) out[i] = (unsigned char)(in[i] ^ ks[i]);
        memset(ks, 0, sizeof ks);
        in += n; out += n; len -= n;
    }

    if (++f->chunk_counter == f->rekey_interval){
        unsigned char newkey[32], n[12];
        fs_keystream(f, newkey, sizeof newkey);   /* continues the same stream */
        chacha20_init(&f->c, newkey);
        memset(newkey, 0, sizeof newkey);
        nonce96(n, 0, ++f->rekey_counter);
        chacha20_seek(&f->c, n, 0);
        f->pos = sizeof f->ks;                    /* new key, cache is stale */
        memset(f->ks, 0, sizeof f->ks);
        f->chunk_counter = 0;
    }
}

/* --------------------------- FSChaCha20Poly1305 -------------------------- */

void fsaead_init(fsaead_ctx* a, const unsigned char key[32], unsigned rekey_interval){
    memset(a, 0, sizeof *a);
    memcpy(a->key, key, 32);
    a->rekey_interval = rekey_interval ? rekey_interval : BIP324_REKEY_INTERVAL;
}

/* Advance to the next packet, rekeying at the interval boundary. The new key
 * is keystream block 1 under nonce {0xFFFFFFFF, rekey_counter}: block 1, not
 * 0, because block 0 of every AEAD nonce is reserved for the Poly1305 key.
 * The 0xFFFFFFFF packet counter is unreachable by a real packet, so a rekey
 * draw can never collide with a packet's own keystream. */
static void fsaead_next(fsaead_ctx* a){
    if (++a->packet_counter == a->rekey_interval){
        unsigned char n[12], block[64];
        chacha20_ctx c;
        nonce96(n, 0xFFFFFFFFu, a->rekey_counter);
        chacha20_init(&c, a->key);
        chacha20_seek(&c, n, 1);
        chacha20_crypt(&c, 0, block, sizeof block);
        memcpy(a->key, block, 32);
        memset(block, 0, sizeof block);
        memset(&c, 0, sizeof c);
        a->packet_counter = 0;
        a->rekey_counter++;
    }
}

void fsaead_encrypt(fsaead_ctx* a, unsigned char* out, unsigned char tag[16],
                    const unsigned char* plain, unsigned long plen,
                    const unsigned char* aad, unsigned long alen){
    unsigned char n[12];
    nonce96(n, a->packet_counter, a->rekey_counter);
    chacha20poly1305_encrypt(out, tag, plain, plen, aad, alen, a->key, n);
    fsaead_next(a);
}

int fsaead_decrypt(fsaead_ctx* a, unsigned char* out,
                   const unsigned char* cipher, unsigned long clen,
                   const unsigned char tag[16],
                   const unsigned char* aad, unsigned long alen){
    unsigned char n[12];
    nonce96(n, a->packet_counter, a->rekey_counter);
    int ok = chacha20poly1305_decrypt(out, cipher, clen, tag, aad, alen, a->key, n);
    fsaead_next(a);          /* advances even on failure -- see the file header */
    return ok;
}
