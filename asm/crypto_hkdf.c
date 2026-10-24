/* crypto_hkdf.c -- HMAC-SHA256 (RFC 2104) and HKDF (RFC 5869).
 *
 * Built on sha256_full, the verified assembly primitive this project already
 * has, rather than a second SHA256.
 *
 * WHY BOTH HALVES ARE EXPOSED. HKDF is extract-then-expand, and BIP324
 * extracts ONCE from the ECDH secret and then expands it several times with
 * different `info` labels to get the session keys. Collapsing that into a
 * single hkdf_sha256() call would re-extract each time -- which still
 * produces keys, just not the ones every other node derives.
 */
#include <string.h>
#include <stdlib.h>
#include "crypto_hkdf.h"
#include "daemon/secure_zero.h"   /* CRY-4: key material is wiped with a barrier */

extern void sha256_full(unsigned char out[32], const void* msg, long long len);

void hmac_sha256(unsigned char out[32], const unsigned char* key, unsigned long keylen,
                 const unsigned char* msg, unsigned long msglen){
    unsigned char k[64]; memset(k, 0, sizeof k);
    if (keylen > 64) sha256_full(k, key, (long long)keylen);
    else if (keylen)  memcpy(k, key, keylen);
    unsigned char ipad[64], opad[64];
    for (int i = 0; i < 64; i++){ ipad[i] = (unsigned char)(k[i] ^ 0x36); opad[i] = (unsigned char)(k[i] ^ 0x5c); }

    /* inner = H(ipad || msg) -- built in a heap buffer so an arbitrarily long
     * message needs no streaming SHA256 API we do not have */
    unsigned char ih[32];
    {
        unsigned long n = 64 + msglen;
        unsigned char stackbuf[256];
        unsigned char* b = (n <= sizeof stackbuf) ? stackbuf : (unsigned char*)malloc(n);
        if (!b){ memset(out, 0, 32); secure_zero(k, sizeof k); secure_zero(ipad, sizeof ipad); secure_zero(opad, sizeof opad); return; }
        memcpy(b, ipad, 64);
        if (msglen) memcpy(b + 64, msg, msglen);
        sha256_full(ih, b, (long long)n);
        secure_zero(b, n);                 /* the keyed pad and the message (an ECDH secret in HKDF-Extract) */
        if (b != stackbuf) free(b);
    }
    unsigned char outer[96];
    memcpy(outer, opad, 64); memcpy(outer + 64, ih, 32);
    sha256_full(out, outer, 96);
    /* CRY-4 (audit 2026-10-23): the key, both pads, the inner hash and the
     * outer preimage were all left in the dead frame */
    secure_zero(k, sizeof k); secure_zero(ipad, sizeof ipad); secure_zero(opad, sizeof opad);
    secure_zero(ih, sizeof ih); secure_zero(outer, sizeof outer);
}

void hkdf_sha256_extract(unsigned char prk[32],
                         const unsigned char* salt, unsigned long saltlen,
                         const unsigned char* ikm,  unsigned long ikmlen){
    /* RFC 5869: an absent salt is 32 zero bytes, NOT an empty key */
    unsigned char zero[32] = {0};
    if (!salt || !saltlen){ salt = zero; saltlen = 32; }
    hmac_sha256(prk, salt, saltlen, ikm, ikmlen);
}

void hkdf_sha256_expand(unsigned char* out, unsigned long outlen,
                        const unsigned char prk[32],
                        const unsigned char* info, unsigned long infolen){
    unsigned char t[32];
    unsigned long tlen = 0, done = 0;
    unsigned char ctr = 1;
    while (done < outlen){
        /* T(n) = HMAC(prk, T(n-1) || info || n) */
        unsigned char buf[32 + 256 + 1];
        unsigned long n = 0;
        if (tlen){ memcpy(buf, t, tlen); n = tlen; }
        if (infolen){
            unsigned long take = infolen > 256 ? 256 : infolen;
            memcpy(buf + n, info, take); n += take;
        }
        buf[n++] = ctr;
        hmac_sha256(t, prk, 32, buf, n);
        tlen = 32;
        unsigned long take = (outlen - done) < 32 ? (outlen - done) : 32;
        memcpy(out + done, t, take);
        done += take;
        ctr++;
        secure_zero(buf, sizeof buf);      /* CRY-4: T(n-1) is derived key material */
    }
    secure_zero(t, sizeof t);
}

void hkdf_sha256(unsigned char* out, unsigned long outlen,
                 const unsigned char* ikm,  unsigned long ikmlen,
                 const unsigned char* salt, unsigned long saltlen,
                 const unsigned char* info, unsigned long infolen){
    unsigned char prk[32];
    hkdf_sha256_extract(prk, salt, saltlen, ikm, ikmlen);
    hkdf_sha256_expand(out, outlen, prk, info, infolen);
    secure_zero(prk, sizeof prk);
}
