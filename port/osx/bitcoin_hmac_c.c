
/*
 * bitcoin_hmac_c.c -- portable HMAC-SHA512 for the macOS/AArch64 port.
 * Bit-exact with asm/bitcoin_hmac.asm (same HMAC construction over the
 * native sha512.o).  CRY-4: kpad/tmp are locals in this frame, no .bss.
 * WAL-3: kpad + key-block prefix of tmp zeroised before return.
 */
#include <stdint.h>
#include <string.h>

extern void sha512_full(unsigned char out[64], const void *msg, long len);

void hmac_sha512(unsigned char out[64],
                 const unsigned char *key, long keylen,
                 const unsigned char *msg, long msglen)
{
    unsigned char kpad[128];
    unsigned char tmp[1160];            /* same budget as the x86 asm */

    /* effective key: if keylen > 128, replace with SHA512(key) */
    if (keylen > 128) {
        sha512_full(tmp, key, keylen);
        key = tmp;
        keylen = 64;
    }

    /* K' = key right-padded to 128 */
    memset(kpad, 0, 128);
    memcpy(kpad, key, keylen);

    /* inner = SHA512((K'^ipad) || msg) -- digest straight to tmp[192] */
    for (int i = 0; i < 128; i++) tmp[i] = kpad[i] ^ 0x36;
    memcpy(tmp + 128, msg, msglen);
    sha512_full(tmp + 192, tmp, 128 + msglen);

    /* out = SHA512((K'^opad) || inner) */
    for (int i = 0; i < 128; i++) tmp[i] = kpad[i] ^ 0x5c;
    memcpy(tmp + 128, tmp + 192, 64);
    sha512_full(out, tmp, 192);

    /* WAL-3: zeroise the key block and the stashed inner digest */
    memset(kpad, 0, 128);
    memset(tmp, 0, 256);
}
