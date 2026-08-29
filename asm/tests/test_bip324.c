/* tests/test_bip324.c -- the official BIP324 packet vectors, end to end.
 *
 * These are the vectors that make the whole stack honest at once. Each one
 * supplies a private key, both ElligatorSwift encodings and a role, and
 * expects an exact session id, both garbage terminators, and the exact bytes
 * of a packet at a given index. Reaching that byte string requires the ECDH,
 * the HKDF salt (network magic included), the role-to-label mapping, the
 * rekeying schedule and the frame layout all to be simultaneously right.
 *
 * Two vectors repeat their contents ~70,000 and ~97,000 times, which pushes
 * a single packet past a megabyte and past several rekeys of the length
 * cipher; those give a ciphertext suffix instead of the whole thing.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../crypto_bip324.h"
#include "../crypto_ellswift.h"
#include "bip324_packet_vectors.h"

/* mainnet, which is what the vectors were generated under */
static const unsigned char MAINNET_MAGIC[4] = { 0xf9, 0xbe, 0xb4, 0xd9 };

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static unsigned long hexlen(const char* h){ return strlen(h) / 2; }
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
/* Compares and REPORTS. An empty expectation is treated as a failure, not as
 * a vacuous pass: a comparison against a zero-length string succeeds against
 * anything, so a vector field that failed to extract would otherwise show up
 * as a green line that checked nothing. */
static int cmp_hex(const char* label, const unsigned char* got, const char* want, unsigned long expect_len){
    unsigned long n = hexlen(want);
    char g[600];
    if (n != expect_len){
        printf("  FAIL %s: expectation is %lu bytes, should be %lu (bad vector extraction?)\n",
               label, n, expect_len);
        fails++; return 0;
    }
    tohex(g, got, n);
    if (!strncmp(g, want, n * 2)){ printf("  ok  %s\n", label); return 1; }
    printf("  FAIL %s\n        got  %s\n        want %.*s\n", label, g, (int)(n * 2), want);
    fails++;
    return 0;
}

int main(void){
    int n_full = 0, n_suffix = 0;
    printf("== official BIP324 packet vectors ==\n");
    for (int v = 0; v < PKT_NVEC; v++){
        const bip324_pkt_vec_t* V = &PKT_VEC[v];
        unsigned char priv[32], ours[64], theirs[64];
        unhex(priv, V->priv); unhex(ours, V->ours); unhex(theirs, V->theirs);

        bip324_cipher_t c;
        char l[160];
        snprintf(l, sizeof l, "vector %d (packet %u, %s): session established",
                 v, V->idx, V->initiating ? "initiator" : "responder");
        if (!bip324_init(&c, priv, ours, theirs, MAINNET_MAGIC, V->initiating, 0)){
            printf("  FAIL %s\n", l); fails++; continue;
        }
        printf("  ok  %s\n", l);

        snprintf(l, sizeof l, "vector %d:   session id", v);
        cmp_hex(l, c.session_id, V->session_id, 32);
        snprintf(l, sizeof l, "vector %d:   send garbage terminator", v);
        cmp_hex(l, c.send_garbage_terminator, V->send_garbage, 16);
        snprintf(l, sizeof l, "vector %d:   recv garbage terminator", v);
        cmp_hex(l, c.recv_garbage_terminator, V->recv_garbage, 16);

        /* seek to the packet index with empty ignored packets, as Core does */
        { unsigned char dummy[BIP324_EXPANSION];
          for (unsigned i = 0; i < V->idx; i++)
              bip324_encrypt(&c, dummy, 0, 0, 0, 0, 1); }

        unsigned long unit = hexlen(V->contents);
        unsigned long clen = unit * V->multiply;
        unsigned long alen = hexlen(V->aad);
        unsigned char* contents = clen ? malloc(clen) : malloc(1);
        unsigned char* aad = malloc(alen + 1);
        unsigned char* out = malloc(clen + BIP324_EXPANSION);
        if (!contents || !aad || !out){ printf("  FAIL vector %d: out of memory\n", v); fails++; continue; }
        { unsigned char one[512];
          if (unit) unhex(one, V->contents);
          for (unsigned m = 0; m < V->multiply; m++) memcpy(contents + m * unit, one, unit); }
        if (alen) unhex(aad, V->aad);

        bip324_encrypt(&c, out, contents, clen, aad, alen, V->ignore);
        unsigned long total = clen + BIP324_EXPANSION;

        if (V->ciphertext[0]){
            snprintf(l, sizeof l, "vector %d:   ciphertext (%lu bytes)", v, total);
            if (hexlen(V->ciphertext) != total){
                printf("  FAIL %s: length %lu, expected %lu\n", l, total, hexlen(V->ciphertext));
                fails++;
            } else { cmp_hex(l, out, V->ciphertext, total); n_full++; }
        } else {
            unsigned long n = hexlen(V->ciphertext_endswith);
            snprintf(l, sizeof l, "vector %d:   ciphertext suffix (of %lu bytes)", v, total);
            char g[600]; tohex(g, out + total - n, n);
            if (strcmp(g, V->ciphertext_endswith)){
                printf("  FAIL %s\n        got  %s\n        want %s\n", l, g, V->ciphertext_endswith);
                fails++;
            } else { printf("  ok  %s\n", l); n_suffix++; }
        }

        /* a self-decrypting cipher must read its own packet back */
        { bip324_cipher_t d;
          bip324_init(&d, priv, ours, theirs, MAINNET_MAGIC, V->initiating, 1);
          unsigned char dummy[BIP324_EXPANSION];
          for (unsigned i = 0; i < V->idx; i++){
              unsigned char scratch[1];
              bip324_encrypt(&d, dummy, 0, 0, 0, 0, 1);   /* keeps send side in step */
              unsigned long dl = bip324_decrypt_length(&d, dummy);
              int ign;
              (void)dl; (void)scratch;
              bip324_decrypt(&d, 0, dummy + BIP324_LENGTH_LEN,
                             BIP324_EXPANSION - BIP324_LENGTH_LEN, 0, 0, &ign);
          }
          unsigned long got_len = bip324_decrypt_length(&d, out);
          unsigned char* back = malloc(clen ? clen : 1);
          int ign = -1;
          int ok = bip324_decrypt(&d, back, out + BIP324_LENGTH_LEN,
                                  total - BIP324_LENGTH_LEN, aad, alen, &ign);
          snprintf(l, sizeof l, "vector %d:   round-trips through a self-decrypting cipher", v);
          ck(l, ok && got_len == clen && (clen == 0 || !memcmp(back, contents, clen))
                && ign == (V->ignore ? 1 : 0));
          free(back); }

        free(contents); free(aad); free(out);
    }

    { char l[140];
      snprintf(l, sizeof l, "every vector's ciphertext was checked (%d in full, %d by suffix)",
               n_full, n_suffix);
      ck(l, n_full + n_suffix == PKT_NVEC); }

    printf("== the network magic really separates chains ==\n");
    /* A mainnet node and a testnet node must not be able to complete a
     * session. Since v2 has no plaintext header to check, this separation
     * exists only in the HKDF salt -- so it is worth asserting directly. */
    { const bip324_pkt_vec_t* V = &PKT_VEC[0];
      unsigned char priv[32], ours[64], theirs[64];
      unhex(priv, V->priv); unhex(ours, V->ours); unhex(theirs, V->theirs);
      static const unsigned char TESTNET4_MAGIC[4] = { 0x1c, 0x16, 0x3f, 0x28 };
      bip324_cipher_t a, b;
      bip324_init(&a, priv, ours, theirs, MAINNET_MAGIC, V->initiating, 0);
      bip324_init(&b, priv, ours, theirs, TESTNET4_MAGIC, V->initiating, 0);
      ck("a different magic gives a different session id",
         memcmp(a.session_id, b.session_id, 32) != 0);
      ck("  and different garbage terminators",
         memcmp(a.send_garbage_terminator, b.send_garbage_terminator, 16) != 0); }

    printf("== two peers agree, and each direction has its own keys ==\n");
    { unsigned char ska[32], skb[32], ea[64], eb[64];
      for (int j = 0; j < 32; j++){ ska[j] = (unsigned char)(j + 1); skb[j] = (unsigned char)(200 - j); }
      ska[0] &= 0x7f; skb[0] &= 0x7f;
      ck("both keypairs encode", ellswift_create(ea, ska, 0, 0) && ellswift_create(eb, skb, 0, 0));
      bip324_cipher_t A, B;
      ck("initiator session", bip324_init(&A, ska, ea, eb, MAINNET_MAGIC, 1, 0) == 1);
      ck("responder session", bip324_init(&B, skb, eb, ea, MAINNET_MAGIC, 0, 0) == 1);
      ck("  same session id", memcmp(A.session_id, B.session_id, 32) == 0);
      ck("  terminators are mirrored",
         !memcmp(A.send_garbage_terminator, B.recv_garbage_terminator, 16) &&
         !memcmp(A.recv_garbage_terminator, B.send_garbage_terminator, 16));
      ck("  the two directions do NOT share a terminator",
         memcmp(A.send_garbage_terminator, A.recv_garbage_terminator, 16) != 0);

      /* talk both ways across a rekey boundary */
      int all = 1;
      for (int i = 0; i < 240; i++){
          unsigned char msg[40], pkt[40 + BIP324_EXPANSION], back[40];
          int ign = -1;
          for (int j = 0; j < 40; j++) msg[j] = (unsigned char)(i + j);
          bip324_encrypt(&A, pkt, msg, 40, 0, 0, 0);
          if (bip324_decrypt_length(&B, pkt) != 40) all = 0;
          if (!bip324_decrypt(&B, back, pkt + 3, 40 + BIP324_EXPANSION - 3, 0, 0, &ign)) all = 0;
          if (memcmp(back, msg, 40) || ign != 0) all = 0;
          bip324_encrypt(&B, pkt, msg, 40, 0, 0, 1);
          if (bip324_decrypt_length(&A, pkt) != 40) all = 0;
          if (!bip324_decrypt(&A, back, pkt + 3, 40 + BIP324_EXPANSION - 3, 0, 0, &ign)) all = 0;
          if (memcmp(back, msg, 40) || ign != 1) all = 0;
      }
      ck("240 packets each way survive the 224-packet rekey", all);

      /* tamper: any bit flip in the packet must fail the tag */
      { unsigned char msg[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
        unsigned char pkt[16 + BIP324_EXPANSION], back[16];
        int ign, rejected = 0, tried = 0;
        for (int bit = 0; bit < 8; bit++){
            bip324_cipher_t A2, B2;
            bip324_init(&A2, ska, ea, eb, MAINNET_MAGIC, 1, 0);
            bip324_init(&B2, skb, eb, ea, MAINNET_MAGIC, 0, 0);
            bip324_encrypt(&A2, pkt, msg, 16, 0, 0, 0);
            pkt[BIP324_LENGTH_LEN + bit] ^= 1;
            bip324_decrypt_length(&B2, pkt);
            tried++;
            if (!bip324_decrypt(&B2, back, pkt + 3, 16 + BIP324_EXPANSION - 3, 0, 0, &ign)) rejected++;
        }
        char l[120];
        snprintf(l, sizeof l, "%d/%d single-bit corruptions rejected", rejected, tried);
        ck(l, rejected == tried); }

      /* wrong aad must fail */
      { unsigned char msg[16] = {0}, pkt[16 + BIP324_EXPANSION], back[16];
        unsigned char aad1[4] = {1,2,3,4}, aad2[4] = {1,2,3,5};
        int ign;
        bip324_cipher_t A2, B2;
        bip324_init(&A2, ska, ea, eb, MAINNET_MAGIC, 1, 0);
        bip324_init(&B2, skb, eb, ea, MAINNET_MAGIC, 0, 0);
        bip324_encrypt(&A2, pkt, msg, 16, aad1, 4, 0);
        bip324_decrypt_length(&B2, pkt);
        ck("a different aad is rejected",
           bip324_decrypt(&B2, back, pkt + 3, 16 + BIP324_EXPANSION - 3, aad2, 4, &ign) == 0); } }

    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}
