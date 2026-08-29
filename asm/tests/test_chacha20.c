/* tests/test_chacha20.c -- our ChaCha20 against RFC 8439's own vectors.
 *
 * The vectors are the RFC's, taken via Core's crypto_tests.cpp so the nonce
 * and counter conventions match exactly what Core feeds its implementation --
 * that pairing is where a ChaCha20 usually goes wrong, not in the rounds.
 * RFC 8439 splits the 96-bit nonce as three little-endian u32 words, and Core
 * expresses the RFC's examples as {u32, u32} plus an implied leading zero
 * word for the section 2.3.2 case; the byte layouts below are written out in
 * full so there is no convention to misread.
 *
 * A wrong nonce split or a counter off by one still produces perfectly
 * random-looking output, which is exactly why this is checked against
 * published bytes rather than eyeballed.
 */
#include <stdio.h>
#include <string.h>
#include "../crypto_chacha20.h"

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }

static int unhex(unsigned char* out, const char* h){
    int n = 0;
    for (; h[0] && h[1]; h += 2){
        int hi, lo;
        hi = (h[0] <= '9') ? h[0]-'0' : (h[0]|32)-'a'+10;
        lo = (h[1] <= '9') ? h[1]-'0' : (h[1]|32)-'a'+10;
        out[n++] = (unsigned char)((hi << 4) | lo);
    }
    return n;
}
static void tohex(char* out, const unsigned char* b, int n){
    static const char* H = "0123456789abcdef";
    for (int i = 0; i < n; i++){ out[i*2] = H[b[i] >> 4]; out[i*2+1] = H[b[i] & 15]; }
    out[n*2] = 0;
}

/* plaintext "" means: check the raw KEYSTREAM against `expect` */
static void tv(const char* name, const char* plain_hex, const char* key_hex,
               const unsigned char nonce[12], unsigned counter, const char* expect_hex){
    unsigned char key[32]; unhex(key, key_hex);
    unsigned char expect[256]; int elen = unhex(expect, expect_hex);
    unsigned char got[256]; memset(got, 0, sizeof got);

    chacha20_ctx c;
    chacha20_init(&c, key);
    chacha20_seek(&c, nonce, counter);

    if (plain_hex && plain_hex[0]){
        unsigned char plain[256]; int plen = unhex(plain, plain_hex);
        chacha20_crypt(&c, plain, got, (unsigned long)plen);
        elen = plen < elen ? plen : elen;
    } else {
        chacha20_keystream(&c, got, (unsigned long)elen);
    }
    char g[520], e[520];
    tohex(g, got, elen); tohex(e, expect, elen);
    if (!strcmp(g, e)) ck(name, 1);
    else { printf("  FAIL %s\n        got %s\n        want %s\n", name, g, e); fails++; }
}

int main(void){
    printf("== RFC 8439 ChaCha20 ==\n");

    /* section 2.3.2: nonce 00:00:00:09 00:00:00:4a 00:00:00:00, counter 1 */
    { unsigned char n[12] = {0x00,0x00,0x00,0x09, 0x00,0x00,0x00,0x4a, 0x00,0x00,0x00,0x00};
      tv("2.3.2 keystream block",
         "", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", n, 1,
         "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
         "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"); }

    /* section 2.4.2: the "Ladies and Gentlemen" plaintext, counter 1 */
    { unsigned char n[12] = {0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x4a, 0x00,0x00,0x00,0x00};
      tv("2.4.2 encryption",
         "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
         "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
         "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
         "637265656e20776f756c642062652069742e",
         "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", n, 1,
         "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
         "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
         "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
         "5af90bbf74a35be6b40b8eedf2785e42874d"); }

    printf("== the properties a wrong implementation still satisfies ==\n");
    /* Each of these passes for random-looking-but-wrong output, so they are
     * NOT the real test -- they only pin behaviour the vectors do not cover. */
    { unsigned char key[32]; memset(key, 0x42, 32);
      unsigned char n[12]; memset(n, 0x24, 12);
      chacha20_ctx a, b;
      unsigned char ka[128], kb[128];
      chacha20_init(&a, key); chacha20_seek(&a, n, 0);
      chacha20_keystream(&a, ka, sizeof ka);
      chacha20_init(&b, key); chacha20_seek(&b, n, 0);
      chacha20_keystream(&b, kb, sizeof kb);
      ck("the same key/nonce/counter is deterministic", memcmp(ka, kb, sizeof ka) == 0);

      /* a stream produced in two calls must equal one produced in one --
       * this is what makes chacha20_crypt usable across packet boundaries */
      chacha20_init(&b, key); chacha20_seek(&b, n, 0);
      unsigned char part[128];
      chacha20_keystream(&b, part, 64);
      chacha20_keystream(&b, part + 64, 64);
      ck("split calls continue the stream (counter advances)", memcmp(ka, part, sizeof ka) == 0);

      /* seeking to block 1 must equal the second half of the block-0 stream */
      chacha20_init(&b, key); chacha20_seek(&b, n, 1);
      unsigned char blk1[64];
      chacha20_keystream(&b, blk1, 64);
      ck("seek(counter=1) lands on the second block", memcmp(ka + 64, blk1, 64) == 0);

      /* encrypt then decrypt round-trips */
      unsigned char msg[100], ct[100], pt[100];
      for (int i = 0; i < 100; i++) msg[i] = (unsigned char)i;
      chacha20_init(&a, key); chacha20_seek(&a, n, 7);
      chacha20_crypt(&a, msg, ct, 100);
      chacha20_init(&a, key); chacha20_seek(&a, n, 7);
      chacha20_crypt(&a, ct, pt, 100);
      ck("encrypt/decrypt round-trips", memcmp(msg, pt, 100) == 0);
      ck("  and the ciphertext is not the plaintext", memcmp(msg, ct, 100) != 0); }

    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}
