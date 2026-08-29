/* tests/test_hkdf.c -- HMAC-SHA256 and HKDF against RFC 4231 and RFC 5869.
 *
 * The two failure modes worth pinning, because both produce keys that look
 * fine and simply are not the ones anyone else derives:
 *
 *   1. An ABSENT SALT is 32 zero bytes, not an empty key (RFC 5869 s2.2).
 *      Treating it as empty gives a different PRK and therefore different
 *      session keys -- a handshake that fails with no diagnosable reason.
 *   2. EXTRACT must happen once. BIP324 extracts from the ECDH secret and
 *      expands several times with different labels; re-extracting per label
 *      also yields keys, just the wrong ones.
 */
#include <stdio.h>
#include <string.h>
#include "../crypto_hkdf.h"

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
    char g[600], w[600]; unsigned char want[300];
    unhex(want, want_hex); tohex(g, got, n); tohex(w, want, n);
    if (!strcmp(g, w)) ck(name, 1);
    else { printf("  FAIL %s\n        got %s\n        want %s\n", name, g, w); fails++; }
}

int main(void){
    printf("== RFC 4231: HMAC-SHA256 ==\n");
    /* test case 1 */
    { unsigned char key[20]; memset(key, 0x0b, sizeof key);
      unsigned char mac[32];
      hmac_sha256(mac, key, sizeof key, (const unsigned char*)"Hi There", 8);
      eq("case 1: 20-byte 0x0b key over \"Hi There\"", mac,
         "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", 32); }
    /* test case 2: key shorter than the block */
    { unsigned char mac[32];
      hmac_sha256(mac, (const unsigned char*)"Jefe", 4,
                  (const unsigned char*)"what do ya want for nothing?", 28);
      eq("case 2: \"Jefe\"", mac,
         "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", 32); }
    /* test case 6: key LONGER than the 64-byte block, so it is hashed first --
     * the branch a naive implementation gets wrong */
    { unsigned char key[131]; memset(key, 0xaa, sizeof key);
      const char* m = "Test Using Larger Than Block-Size Key - Hash Key First";
      unsigned char mac[32];
      hmac_sha256(mac, key, sizeof key, (const unsigned char*)m, strlen(m));
      eq("case 6: 131-byte key is hashed down first", mac,
         "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", 32); }

    printf("== RFC 5869: HKDF-SHA256 ==\n");
    /* A.1 basic */
    { unsigned char ikm[22]; memset(ikm, 0x0b, sizeof ikm);
      unsigned char salt[13]; unhex(salt, "000102030405060708090a0b0c");
      unsigned char info[10]; unhex(info, "f0f1f2f3f4f5f6f7f8f9");
      unsigned char prk[32];
      hkdf_sha256_extract(prk, salt, sizeof salt, ikm, sizeof ikm);
      eq("A.1 PRK", prk,
         "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", 32);
      unsigned char okm[42];
      hkdf_sha256(okm, sizeof okm, ikm, sizeof ikm, salt, sizeof salt, info, sizeof info);
      eq("A.1 OKM (42 bytes, spans two HMAC blocks)", okm,
         "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
         "34007208d5b887185865", 42); }

    /* A.3: zero-length salt and info -- the case that catches "absent salt
     * means empty key" */
    { unsigned char ikm[22]; memset(ikm, 0x0b, sizeof ikm);
      unsigned char prk[32];
      hkdf_sha256_extract(prk, NULL, 0, ikm, sizeof ikm);
      eq("A.3 PRK with NO salt (must be 32 zero bytes, not empty)", prk,
         "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04", 32);
      unsigned char okm[42];
      hkdf_sha256(okm, sizeof okm, ikm, sizeof ikm, NULL, 0, NULL, 0);
      eq("A.3 OKM", okm,
         "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
         "9d201395faa4b61a96c8", 42); }

    printf("== extract-once-expand-many, the way BIP324 uses it ==\n");
    { unsigned char ikm[32]; memset(ikm, 0x77, sizeof ikm);
      unsigned char prk[32];
      hkdf_sha256_extract(prk, (const unsigned char*)"salt", 4, ikm, sizeof ikm);
      unsigned char a[32], b[32];
      hkdf_sha256_expand(a, 32, prk, (const unsigned char*)"label-A", 7);
      hkdf_sha256_expand(b, 32, prk, (const unsigned char*)"label-B", 7);
      ck("different info labels give different keys", memcmp(a, b, 32) != 0);
      unsigned char a2[32];
      hkdf_sha256_expand(a2, 32, prk, (const unsigned char*)"label-A", 7);
      ck("  and the same label is reproducible", memcmp(a, a2, 32) == 0);
      /* re-extracting per label must NOT match expanding from one PRK --
       * this is the mistake that yields plausible but non-interoperable keys */
      unsigned char whole[32];
      hkdf_sha256(whole, 32, ikm, sizeof ikm, (const unsigned char*)"salt", 4,
                  (const unsigned char*)"label-A", 7);
      ck("one-shot hkdf equals extract-then-expand", memcmp(a, whole, 32) == 0); }

    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}
