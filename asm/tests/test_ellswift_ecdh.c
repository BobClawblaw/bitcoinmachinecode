/* tests/test_ellswift_ecdh.c -- the BIP324 handshake key agreement.
 *
 * Inputs come from Core's official BIP324 packet vectors; the expected secret
 * is computed by Core's own Python reference, because the published vectors
 * print the session id but not the intermediate ECDH secret. See
 * validation/gen_bip324_ecdh_vectors.py.
 *
 * The test that matters most is not the vectors, though -- it is the pair
 * agreement check at the bottom. Two peers with opposite roles must arrive at
 * the SAME secret from mirrored inputs. Getting the initiator-first hash
 * ordering backwards passes every single-sided vector where our role happens
 * to match, and then fails on the wire against a real peer.
 */
#include <stdio.h>
#include <string.h>
#include "../crypto_ellswift.h"
#include "bip324_ecdh_vectors.h"

extern void point_scalar_mul_ct(unsigned long long r[12], const unsigned long long xy[8],
                                const unsigned long long k[4]);

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static void unhex(unsigned char* out, const char* h){
    int n = 0;
    for (; h[0] && h[1]; h += 2){
        int hi = (h[0] <= '9') ? h[0]-'0' : (h[0]|32)-'a'+10;
        int lo = (h[1] <= '9') ? h[1]-'0' : (h[1]|32)-'a'+10;
        out[n++] = (unsigned char)((hi << 4) | lo);
    }
}
static void tohex(char* out, const unsigned char* b, int n){
    static const char* H = "0123456789abcdef";
    for (int i = 0; i < n; i++){ out[i*2] = H[b[i] >> 4]; out[i*2+1] = H[b[i] & 15]; }
    out[n*2] = 0;
}

int main(void){
    printf("== BIP324 ECDH against Core's official packet-vector inputs ==\n");
    int ok = 0, ninit = 0, nresp = 0;
    for (int i = 0; i < ECDH_NVEC; i++){
        unsigned char priv[32], ours[64], theirs[64], want[32], got[32];
        unhex(priv, ECDH_VEC[i].priv);
        unhex(ours, ECDH_VEC[i].ours);
        unhex(theirs, ECDH_VEC[i].theirs);
        unhex(want, ECDH_VEC[i].secret);
        if (!ellswift_ecdh(got, theirs, ours, priv, ECDH_VEC[i].initiating)){
            printf("  FAIL vector %d: ECDH refused a valid key\n", i); fails++; continue;
        }
        if (memcmp(got, want, 32)){
            char g[70], w[70]; tohex(g, got, 32); tohex(w, want, 32);
            printf("  FAIL vector %d\n        got  %s\n        want %s\n", i, g, w);
            fails++; continue;
        }
        ok++;
        if (ECDH_VEC[i].initiating) ninit++; else nresp++;
    }
    { char l[120];
      snprintf(l, sizeof l, "all %d vectors produce Core's secret exactly", ECDH_NVEC);
      ck(l, ok == ECDH_NVEC);
      snprintf(l, sizeof l, "  both roles covered (%d initiating, %d responding)", ninit, nresp);
      ck(l, ninit > 0 && nresp > 0); }

    printf("== the two sides of a handshake agree ==\n");
    /* Build a real pair: A's secret key with B's encoding, and B's secret key
     * with A's encoding. This is the property the wire depends on, and it is
     * checkable without any reference implementation at all. */
    { int agree = 0, trials = 0;
      for (int trial = 0; trial < 8; trial++){
          unsigned char ska[32], skb[32], ea[64], eb[64], sa[32], sb[32];
          for (int j = 0; j < 32; j++){
              ska[j] = (unsigned char)(trial * 71 + j * 13 + 1);
              skb[j] = (unsigned char)(trial * 29 + j * 47 + 2);
          }
          ska[0] &= 0x7f; skb[0] &= 0x7f;        /* keep both below the order */
          if (!ellswift_create(ea, ska, NULL, 0)) continue;
          if (!ellswift_create(eb, skb, NULL, 0)) continue;
          /* A initiates, B responds */
          if (!ellswift_ecdh(sa, eb, ea, ska, 1)) continue;
          if (!ellswift_ecdh(sb, ea, eb, skb, 0)) continue;
          trials++;
          if (!memcmp(sa, sb, 32)) agree++;
          else if (agree + 1 == trials){
              char x[70], y[70]; tohex(x, sa, 32); tohex(y, sb, 32);
              printf("        trial %d disagreed\n          initiator %s\n          responder %s\n", trial, x, y);
          }
      }
      char l[120];
      snprintf(l, sizeof l, "%d/%d handshake pairs derive an identical secret", agree, trials);
      ck(l, trials > 0 && agree == trials); }

    printf("== the role ordering is real, not cosmetic ==\n");
    /* If both peers wrongly used their own encoding first, they would still
     * agree with themselves but disagree with each other. Confirm that
     * swapping our declared role actually changes the answer, so the vectors
     * above are testing something. */
    { unsigned char priv[32], ours[64], theirs[64], as_init[32], as_resp[32];
      unhex(priv, ECDH_VEC[0].priv);
      unhex(ours, ECDH_VEC[0].ours);
      unhex(theirs, ECDH_VEC[0].theirs);
      ellswift_ecdh(as_init, theirs, ours, priv, 1);
      ellswift_ecdh(as_resp, theirs, ours, priv, 0);
      ck("flipping the role changes the secret", memcmp(as_init, as_resp, 32) != 0); }

    printf("== bad secret keys are refused ==\n");
    { unsigned char theirs[64], ours[64], out[32], k[32];
      unhex(theirs, ECDH_VEC[0].theirs); unhex(ours, ECDH_VEC[0].ours);
      memset(k, 0, 32);
      ck("zero secret key refused", ellswift_ecdh(out, theirs, ours, k, 1) == 0);
      /* n itself, the group order */
      static const unsigned char N[32] = {
          0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
          0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41 };
      memcpy(k, N, 32);
      ck("secret key == n refused", ellswift_ecdh(out, theirs, ours, k, 1) == 0);
      memset(k, 0xff, 32);
      ck("all-ones secret key refused (above n)", ellswift_ecdh(out, theirs, ours, k, 1) == 0);
      memcpy(k, N, 32); k[31] = 0x40;           /* n-1, the largest valid key */
      ck("n-1 accepted (the boundary is not off by one)",
         ellswift_ecdh(out, theirs, ours, k, 1) == 1); }

    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}
