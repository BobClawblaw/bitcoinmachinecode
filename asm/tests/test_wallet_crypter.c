/* tests/test_wallet_crypter.c -- wallet-at-rest encryption
 * (daemon/wallet_crypter.c).
 *
 *   1. wcrypt_derive MATCHES Core's BytesToKeySHA512AES for supplied
 *      (passphrase, salt, iterations) vectors -- computed independently by
 *      the OpenSSL kdf oracle and pasted here (regenerate with
 *      scratchpad/kdf_oracle);
 *   2. seal -> open round-trips the seed under the right passphrase;
 *   3. a WRONG passphrase returns 0 (pad-check failure), never garbage;
 *   4. wcrypt_rewrap re-encrypts under a new passphrase, the seed opens with
 *      the new one and not the old, and the seed CIPHERTEXT is untouched
 *      (only the wrap changed);
 *   5. a corrupted container fails the checksum (not "encrypted").
 */
#include <stdio.h>
#include <string.h>

typedef unsigned char u8;
typedef unsigned int u32;

extern void wcrypt_derive(const char* pass, long passlen, const u8 salt[8],
                          u32 iters, u8 key[32], u8 iv[16]);
extern long wcrypt_seal(const char* pass, long passlen, const u8* seed, long seedlen, u8* out, long cap);
extern long wcrypt_open(const char* pass, long passlen, const u8* blob, long len, u8* seed_out, long cap);
extern long wcrypt_rewrap(const char* oldp, long oldlen, const char* newp, long newlen,
                          const u8* blob, long len, u8* out, long cap);
extern int  wcrypt_is_encrypted(const u8* blob, long len);

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static void hx(u8* o, const char* h){ for (int i=0;h[2*i];i++){ unsigned b; sscanf(h+2*i,"%2x",&b); o[i]=(u8)b; } }

int main(void){
    printf("== 1: key derivation == Core's BytesToKeySHA512AES ==\n");
    /* oracle: /tmp/kdf_oracle "correct horse" 0011223344556677 1000 */
    { u8 salt[8]; hx(salt, "0011223344556677");
      u8 k[32], iv[16], wk[32], wiv[16];
      hx(wk,  "23ae8a72702ae93aed886f8822b18fa7e344eb2698c4b9844c6d0766a4278721");
      hx(wiv, "3a32d7d711621de316e88a6c4ec1860b");
      wcrypt_derive("correct horse", 13, salt, 1000, k, iv);
      ck("derived key == OpenSSL oracle", memcmp(k, wk, 32) == 0);
      ck("derived iv  == OpenSSL oracle", memcmp(iv, wiv, 16) == 0); }

    printf("\n== 2-4: seal / open / wrong-pass / rewrap ==\n");
    const char* seed = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    long seedlen = (long)strlen(seed);
    static u8 blob[8192]; u8 recovered[4096];
    long bl = wcrypt_seal("hunter2", 7, (const u8*)seed, seedlen, blob, sizeof blob);
    ck("seal produced a container", bl > 0);
    ck("container reads as encrypted", wcrypt_is_encrypted(blob, bl));

    long rl = wcrypt_open("hunter2", 7, blob, bl, recovered, sizeof recovered);
    ck("open with the right passphrase round-trips", rl == seedlen && memcmp(recovered, seed, seedlen) == 0);

    long wr = wcrypt_open("wrongpass", 9, blob, bl, recovered, sizeof recovered);
    ck("wrong passphrase -> 0 (not garbage, not the seed)", wr == 0);

    /* rewrap: locate the seed ciphertext region so we can prove it is
     * byte-identical across the re-encryption */
    static u8 blob2[8192];
    long b2 = wcrypt_rewrap("hunter2", 7, "newphrase!", 10, blob, bl, blob2, sizeof blob2);
    ck("rewrap produced a container", b2 > 0);
    ck("old passphrase no longer opens the rewrapped store",
       wcrypt_open("hunter2", 7, blob2, b2, recovered, sizeof recovered) == 0);
    long rl2 = wcrypt_open("newphrase!", 10, blob2, b2, recovered, sizeof recovered);
    ck("new passphrase opens it to the SAME seed", rl2 == seedlen && memcmp(recovered, seed, seedlen) == 0);
    /* seed ciphertext (the tail before the 32-byte checksum, after the
     * per-container wrap) must be identical -- the seal layout puts seed_iv
     * + seed_ct at the end; the seed_ct length is the same, so the last
     * (seedlen padded) bytes before the checksum match */
    { long padded = ((seedlen/16)+1)*16;
      ck("seed ciphertext untouched by rewrap",
         memcmp(blob + bl - 32 - padded, blob2 + b2 - 32 - padded, padded) == 0); }

    printf("\n== 5: corruption fails the checksum ==\n");
    blob[bl/2] ^= 0xff;
    ck("a corrupted container is not 'encrypted'", !wcrypt_is_encrypted(blob, bl));

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
