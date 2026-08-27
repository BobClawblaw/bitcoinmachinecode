/* tests/test_aes.c -- AES-256 (bitcoin_aes.c) against the FIPS-197 known
 * answer, plus CBC round-trips and boundary padding cases. */
#include <stdio.h>
#include <string.h>

typedef unsigned char u8;
extern void aes256_encrypt_block(const u8 key[32], const u8 in[16], u8 out[16]);
extern void aes256_decrypt_block(const u8 key[32], const u8 in[16], u8 out[16]);
extern long aes256_cbc_encrypt(const u8 key[32], const u8 iv[16], const u8* in, long inlen, u8* out, long cap);
extern long aes256_cbc_decrypt(const u8 key[32], const u8 iv[16], const u8* in, long inlen, u8* out, long cap);

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }

static void hx(u8* out, const char* h){ for (int i=0;h[2*i];i++){ unsigned b; sscanf(h+2*i,"%2x",&b); out[i]=(u8)b; } }

int main(void){
    /* FIPS-197 C.3: AES-256 known-answer. */
    u8 key[32], in[16], want[16], out[16], back[16];
    hx(key, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    hx(in,  "00112233445566778899aabbccddeeff");
    hx(want,"8ea2b7ca516745bfeafc49904b496089");
    aes256_encrypt_block(key, in, out);
    ck("FIPS-197 C.3 encrypt", memcmp(out, want, 16) == 0);
    aes256_decrypt_block(key, want, back);
    ck("FIPS-197 C.3 decrypt", memcmp(back, in, 16) == 0);

    /* CBC round-trips at several lengths, including exact-block (forces a
     * full pad block) and empty. */
    u8 iv[16]; hx(iv, "000102030405060708090a0b0c0d0e0f");
    const char* msgs[] = { "", "a", "0123456789abcde", "0123456789abcdef",
                           "the wallet master key is exactly this long!!" };
    for (int m = 0; m < 5; m++){
        long il = (long)strlen(msgs[m]);
        u8 ct[128], pt[128];
        long cl = aes256_cbc_encrypt(key, iv, (const u8*)msgs[m], il, ct, sizeof ct);
        char lbl[64]; snprintf(lbl, sizeof lbl, "cbc encrypt len=%ld -> %ld (block-multiple)", il, cl);
        ck(lbl, cl > 0 && cl % 16 == 0 && cl >= il + 1);
        long pl = aes256_cbc_decrypt(key, iv, ct, cl, pt, sizeof pt);
        char lbl2[64]; snprintf(lbl2, sizeof lbl2, "cbc round-trip len=%ld", il);
        ck(lbl2, pl == il && memcmp(pt, msgs[m], il) == 0);
    }

    /* corrupt ciphertext -> bad padding (usually) or wrong plaintext */
    { u8 ct[64], pt[64];
      long cl = aes256_cbc_encrypt(key, iv, (const u8*)"secret", 6, ct, sizeof ct);
      ct[cl-1] ^= 0xff;
      long pl = aes256_cbc_decrypt(key, iv, ct, cl, pt, sizeof pt);
      ck("corrupted final block -> not the original 6-byte plaintext",
         !(pl == 6 && memcmp(pt, "secret", 6) == 0)); }

    /* non-block-multiple ciphertext is rejected */
    { u8 pt[64];
      ck("decrypt rejects a 15-byte ciphertext", aes256_cbc_decrypt(key, iv, (const u8*)"123456789012345", 15, pt, sizeof pt) == -1); }

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
