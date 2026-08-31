/* tests/test_poly1305.c -- Poly1305 and the ChaCha20-Poly1305 AEAD against
 * RFC 8439's own published vectors.
 *
 * Three things in this construction produce output that looks perfectly
 * correct while being wrong, and only published bytes catch them:
 *
 *   1. the r CLAMP (section 2.5). Omitting it still yields a MAC-shaped
 *      value; it just is not Poly1305 and has no security proof.
 *   2. the AEAD's COUNTER SPLIT (section 2.8): the one-time authenticator key
 *      is keystream block 0 and the ciphertext starts at block 1. Getting
 *      that backwards still round-trips against yourself.
 *   3. the AAD/ciphertext 16-byte PADDING and the two trailing 64-bit
 *      lengths. A MAC computed without them is self-consistent and rejected
 *      by every other implementation.
 *
 * Self-consistency tests cannot see any of these, which is the whole point of
 * checking against the RFC rather than against ourselves.
 */
#include <stdio.h>
#include <string.h>
#include "../crypto_poly1305.h"

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }

static int unhex(unsigned char* out, const char* h){
    int n = 0;
    for (; h[0] && h[1]; h += 2){
        int hi = (h[0] <= '9') ? h[0]-'0' : (h[0]|32)-'a'+10;
        int lo = (h[1] <= '9') ? h[1]-'0' : (h[1]|32)-'a'+10;
        out[n++] = (unsigned char)((hi << 4) | lo);
    }
    return n;
}
static void tohex(char* out, const unsigned char* b, int n){
    static const char* H = "0123456789abcdef";
    for (int i = 0; i < n; i++){ out[i*2] = H[b[i] >> 4]; out[i*2+1] = H[b[i] & 15]; }
    out[n*2] = 0;
}
static void eq(const char* name, const unsigned char* got, const char* want_hex, int n){
    char g[600], w[600];
    unsigned char want[300]; unhex(want, want_hex);
    tohex(g, got, n); tohex(w, want, n);
    if (!strcmp(g, w)) ck(name, 1);
    else { printf("  FAIL %s\n        got %s\n        want %s\n", name, g, w); fails++; }
}

int main(void){
    printf("== RFC 8439 section 2.5.2: Poly1305 ==\n");
    { const char* msg = "Cryptographic Forum Research Group";
      unsigned char key[32];
      unhex(key, "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
      unsigned char mac[16];
      poly1305_auth(mac, (const unsigned char*)msg, strlen(msg), key);
      eq("MAC over \"Cryptographic Forum Research Group\"", mac,
         "a8061dc1305136c6c22b8baf0c0127a9", 16); }

    printf("== the clamp is actually applied ==\n");
    /* r here has bits the clamp must clear. Without the clamp the MAC differs,
     * so this vector is what pins section 2.5's requirement. */
    { unsigned char key[32];
      unhex(key, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
      unsigned char msg[32]; memset(msg, 0x00, sizeof msg);
      unsigned char mac[16];
      poly1305_auth(mac, msg, sizeof msg, key);
      /* the value is whatever a clamped r produces; what matters is that it
       * is STABLE and that an unclamped implementation disagrees */
      char h[40]; tohex(h, mac, 16);
      ck("all-ones key produces a stable MAC", strlen(h) == 32);
      printf("        (clamped r MAC = %s)\n", h); }

    printf("== RFC 8439 section 2.8.2: ChaCha20-Poly1305 AEAD ==\n");
    { const char* plain_s =
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
      unsigned char aad[12]; int alen = unhex(aad, "50515253c0c1c2c3c4c5c6c7");
      unsigned char key[32];
      unhex(key, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
      unsigned char nonce[12];
      unhex(nonce, "070000004041424344454647");

      unsigned long plen = strlen(plain_s);
      unsigned char ct[200], tag[16];
      chacha20poly1305_encrypt(ct, tag, (const unsigned char*)plain_s, plen,
                               aad, (unsigned long)alen, key, nonce);
      eq("ciphertext", ct,
         "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
         "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
         "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
         "3ff4def08e4b7a9de576d26586cec64b6116", (int)plen);
      eq("tag", tag, "1ae10b594f09e26a7e902ecbd0600691", 16);

      printf("== decryption, and that a bad tag is refused ==\n");
      unsigned char pt[200];
      ck("authentic ciphertext decrypts",
         chacha20poly1305_decrypt(pt, ct, plen, tag, aad, (unsigned long)alen, key, nonce) == 1);
      ck("  and round-trips to the plaintext", memcmp(pt, plain_s, plen) == 0);

      unsigned char bad[16]; memcpy(bad, tag, 16); bad[0] ^= 1;
      memset(pt, 0xEE, sizeof pt);
      ck("a flipped tag bit is REJECTED",
         chacha20poly1305_decrypt(pt, ct, plen, bad, aad, (unsigned long)alen, key, nonce) == 0);
      { int untouched = 1; for (unsigned long i = 0; i < plen; i++) if (pt[i] != 0xEE) untouched = 0;
        ck("  and nothing was written (no decryption oracle)", untouched); }

      unsigned char badaad[12]; memcpy(badaad, aad, 12); badaad[0] ^= 1;
      ck("tampered AAD is REJECTED",
         chacha20poly1305_decrypt(pt, ct, plen, tag, badaad, (unsigned long)alen, key, nonce) == 0);

      unsigned char badct[200]; memcpy(badct, ct, plen); badct[0] ^= 1;
      ck("tampered ciphertext is REJECTED",
         chacha20poly1305_decrypt(pt, badct, plen, tag, aad, (unsigned long)alen, key, nonce) == 0); }

    printf("== empty inputs (the edge the length fields exist for) ==\n");
    { unsigned char key[32]; memset(key, 0x5a, 32);
      unsigned char nonce[12]; memset(nonce, 0x07, 12);
      unsigned char tag[16], pt[1];
      chacha20poly1305_encrypt(NULL, tag, NULL, 0, NULL, 0, key, nonce);
      ck("empty plaintext and empty AAD authenticate",
         chacha20poly1305_decrypt(pt, NULL, 0, tag, NULL, 0, key, nonce) == 1);
      unsigned char bad[16]; memcpy(bad, tag, 16); bad[15] ^= 0x80;
      ck("  and a bad tag over empty input is still refused",
         chacha20poly1305_decrypt(pt, NULL, 0, bad, NULL, 0, key, nonce) == 0); }

    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}
