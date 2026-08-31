/* tests/test_bip324_fs.c -- BIP324's forward-secure ciphers.
 *
 * Vectors are Core's own (src/test/crypto_tests.cpp), since BIP324 specifies
 * the rekeying scheme without printing intermediates. Two properties are
 * being pinned:
 *
 *   1. Before the first rotation, FSChaCha20 must be byte-identical to a
 *      plain ChaCha20 run as ONE continuous stream. That is the check that
 *      catches a missing partial-block carry: chunked 1-byte calls that each
 *      restart at a block boundary still look fine on their own and diverge
 *      here immediately.
 *
 *   2. After the rotation it must STOP matching, and match Core's rotated
 *      output instead. A wrapper that forgot to rekey passes check 1 forever.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../crypto_bip324_fs.h"
#include "../crypto_chacha20.h"
#include "bip324_fs_vectors.h"

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static unsigned long unhex(unsigned char* out, const char* h){
    unsigned long n = 0;
    for (; h[0] && h[1]; h += 2){
        int hi = (h[0] <= '9') ? h[0]-'0' : (h[0]|32)-'a'+10;
        int lo = (h[1] <= '9') ? h[1]-'0' : (h[1]|32)-'a'+10;
        out[n++] = (unsigned char)((hi << 4) | lo);
    }
    return n;
}
static void tohex(char* out, const unsigned char* b, unsigned long n){
    static const char* H = "0123456789abcdef";
    for (unsigned long i = 0; i < n; i++){ out[i*2] = H[b[i] >> 4]; out[i*2+1] = H[b[i] & 15]; }
    out[n*2] = 0;
}

int main(void){
    printf("== FSChaCha20 vs a continuous ChaCha20, then across the rotation ==\n");
    for (int v = 0; v < FS20_NVEC; v++){
        unsigned char plain[256], key[32], want[256];
        unsigned long plen = unhex(plain, FS20_VEC[v].plain);
        unhex(key, FS20_VEC[v].key);
        unsigned long wlen = unhex(want, FS20_VEC[v].cipher_after_rotation);
        unsigned interval = FS20_VEC[v].interval;

        fschacha20_ctx f;
        fschacha20_init(&f, key, interval);
        chacha20_ctx c;
        unsigned char n12[12] = {0};
        chacha20_init(&c, key); chacha20_seek(&c, n12, 0);

        /* the plain cipher, driven as one continuous stream with its own
         * leftover carry so the comparison is apples to apples */
        unsigned char ks[64]; unsigned kspos = 64;
        unsigned char fo[256], co[256];
        int matched = 0;
        for (unsigned i = 0; i < interval; i++){
            fschacha20_crypt(&f, plain, fo, plen);
            for (unsigned long j = 0; j < plen; j++){
                if (kspos == 64){ chacha20_crypt(&c, 0, ks, 64); kspos = 0; }
                co[j] = (unsigned char)(plain[j] ^ ks[kspos++]);
            }
            if (!memcmp(fo, co, plen)) matched++;
        }
        char l[160];
        snprintf(l, sizeof l, "vector %d: all %u pre-rotation chunks match a continuous ChaCha20", v, interval);
        ck(l, matched == (int)interval);

        /* the very next call is the first after the rotation */
        fschacha20_crypt(&f, plain, fo, plen);
        snprintf(l, sizeof l, "vector %d: post-rotation output matches Core", v);
        if (plen != wlen){ printf("  FAIL %s (length %lu vs %lu)\n", l, plen, wlen); fails++; }
        else if (memcmp(fo, want, plen)){
            char g[520], w[520]; tohex(g, fo, plen); tohex(w, want, plen);
            printf("  FAIL %s\n        got  %s\n        want %s\n", l, g, w);
            fails++;
        } else printf("  ok  %s\n", l);

        /* and it must have actually rotated, i.e. differ from no-rekey */
        for (unsigned long j = 0; j < plen; j++){
            if (kspos == 64){ chacha20_crypt(&c, 0, ks, 64); kspos = 0; }
            co[j] = (unsigned char)(plain[j] ^ ks[kspos++]);
        }
        snprintf(l, sizeof l, "vector %d:   and differs from never rekeying", v);
        ck(l, memcmp(fo, co, plen) != 0);
    }

    printf("== FSChaCha20Poly1305 at packet indices past the rekey interval ==\n");
    for (int v = 0; v < FSAEAD_NVEC; v++){
        unsigned char *plain = malloc(4096), *aad = malloc(4096), *want = malloc(4096);
        unsigned char key[32], *out = malloc(4096), tag[16];
        unsigned long plen = unhex(plain, FSAEAD_VEC[v].plain);
        unsigned long alen = unhex(aad, FSAEAD_VEC[v].aad);
        unsigned long wlen = unhex(want, FSAEAD_VEC[v].cipher);
        unhex(key, FSAEAD_VEC[v].key);

        /* seek to the packet index with empty encryptions, as Core's harness does */
        fsaead_ctx a;
        fsaead_init(&a, key, BIP324_REKEY_INTERVAL);
        unsigned char dummy_tag[16];
        for (unsigned long long i = 0; i < FSAEAD_VEC[v].msg_idx; i++)
            fsaead_encrypt(&a, out, dummy_tag, 0, 0, 0, 0);
        fsaead_encrypt(&a, out, tag, plain, plen, aad, alen);

        char l[200];
        snprintf(l, sizeof l, "vector %d: ciphertext+tag matches Core at packet %llu",
                 v, FSAEAD_VEC[v].msg_idx);
        int ok = (wlen == plen + BIP324_AEAD_EXPANSION)
                 && !memcmp(out, want, plen)
                 && !memcmp(tag, want + plen, 16);
        ck(l, ok);
        if (!ok && plen < 200){
            char g[520], w[520]; tohex(g, out, plen); tohex(w, want, plen);
            printf("        got  %s\n        want %s\n", g, w);
        }

        /* and a matching decryptor recovers it */
        fsaead_ctx d;
        fsaead_init(&d, key, BIP324_REKEY_INTERVAL);
        for (unsigned long long i = 0; i < FSAEAD_VEC[v].msg_idx; i++)
            fsaead_encrypt(&d, out, dummy_tag, 0, 0, 0, 0);
        unsigned char* back = malloc(4096);
        int authentic = fsaead_decrypt(&d, back, want, plen, want + plen, aad, alen);
        snprintf(l, sizeof l, "vector %d:   decrypts back to the plaintext", v);
        ck(l, authentic && !memcmp(back, plain, plen));

        free(plain); free(aad); free(want); free(out); free(back);
    }

    printf("== a forged tag is rejected, and both sides stay in step ==\n");
    { unsigned char key[32], plain[64], out[64], tag[16], back[64];
      for (int i = 0; i < 32; i++) key[i] = (unsigned char)i;
      for (int i = 0; i < 64; i++) plain[i] = (unsigned char)(i * 3);
      fsaead_ctx e, d;
      fsaead_init(&e, key, 4);            /* short interval: rekey inside the loop */
      fsaead_init(&d, key, 4);
      int all_ok = 1;
      for (int i = 0; i < 12; i++){
          fsaead_encrypt(&e, out, tag, plain, 64, 0, 0);
          if (!fsaead_decrypt(&d, back, out, 64, tag, 0, 0)) all_ok = 0;
          if (memcmp(back, plain, 64)) all_ok = 0;
      }
      ck("12 packets across 3 rekeys round-trip", all_ok);

      /* a flipped tag bit must fail */
      fsaead_ctx e2, d2;
      fsaead_init(&e2, key, 4); fsaead_init(&d2, key, 4);
      fsaead_encrypt(&e2, out, tag, plain, 64, 0, 0);
      tag[0] ^= 1;
      ck("a corrupted tag is rejected", fsaead_decrypt(&d2, back, out, 64, tag, 0, 0) == 0);
      tag[0] ^= 1;
      /* the decryptor advanced past that packet, so replaying the same packet
       * now fails too -- confirming the counter moved, which is what keeps a
       * real peer in step */
      ck("  and the decryptor advanced past it (no silent replay)",
         fsaead_decrypt(&d2, back, out, 64, tag, 0, 0) == 0); }

    printf("== the AEAD is nonce-separated from the length cipher ==\n");
    /* Same key used for both must not produce the same keystream, or the
     * length field would leak packet contents. */
    { unsigned char key[32], p[32], a_out[32], f_out[32], tg[16];
      memset(key, 0x5a, 32); memset(p, 0, 32);
      fsaead_ctx a; fsaead_init(&a, key, BIP324_REKEY_INTERVAL);
      fsaead_encrypt(&a, a_out, tg, p, 32, 0, 0);
      fschacha20_ctx f; fschacha20_init(&f, key, BIP324_REKEY_INTERVAL);
      fschacha20_crypt(&f, p, f_out, 32);
      ck("the two ciphers' keystreams differ under the same key",
         memcmp(a_out, f_out, 32) != 0); }

    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}
