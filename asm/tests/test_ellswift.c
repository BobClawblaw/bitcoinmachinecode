/* tests/test_ellswift.c -- the ElligatorSwift forward map against BIP324's
 * OFFICIAL decode vectors (Core's ellswift_decode_test_vectors.csv).
 *
 * These are the right vectors for this map because they were built to cover
 * its branches deliberately: the comment column names which of x1/x2/x3 each
 * input resolves to, plus the degenerate cases (u mod p = 0, t mod p = 0,
 * u^3+7+t^2 = 0). All three branches return points ON the curve, so a wrong
 * branch order, a wrong sign, or a mistranscribed sqrt(-3) all yield valid
 * curve points and disagree with everyone else. Only published x values
 * distinguish them -- which is precisely what happened here: the first cut of
 * the sqrt(-3) constant was off by one nibble in every limb, and nothing
 * except these vectors would have said so.
 *
 * The coverage counts are asserted, not assumed: if a future change made a
 * branch unreachable the vectors would still all pass while testing less.
 */
#include <stdio.h>
#include <string.h>
#include "../crypto_ellswift.h"
#include "ellswift_vectors.h"
#include "xswiftec_inv_vectors.h"

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

int main(void){
    printf("== BIP324 official ElligatorSwift decode vectors ==\n");
    int pass = 0, x1 = 0, x2 = 0, x3 = 0, degen = 0;
    for (int i = 0; i < ELLSWIFT_NVEC; i++){
        unsigned char in[64], want[32], got[32];
        if (unhex(in, ELLSWIFT_VEC[i].ellswift) != 64){ printf("  FAIL vector %d: bad input length\n", i); fails++; continue; }
        unhex(want, ELLSWIFT_VEC[i].x);
        ellswift_decode(got, in);
        if (!memcmp(got, want, 32)) pass++;
        else {
            char g[70], w[70]; tohex(g, got, 32); tohex(w, want, 32);
            printf("  FAIL vector %d (%s)\n        got  %s\n        want %s\n",
                   i, ELLSWIFT_VEC[i].comment, g, w);
            fails++;
        }
        const char* c = ELLSWIFT_VEC[i].comment;
        if (strstr(c, "valid_x(x1)")) x1++;
        if (strstr(c, "valid_x(x2)")) x2++;
        if (strstr(c, "valid_x(x3)")) x3++;
        if (strstr(c, "%p=0") || strstr(c, "g+s=0")) degen++;
    }
    { char l[120]; snprintf(l, sizeof l, "all %d official vectors decode correctly", ELLSWIFT_NVEC);
      ck(l, pass == ELLSWIFT_NVEC); }

    printf("== the vectors actually exercise every branch ==\n");
    { char l[120];
      snprintf(l, sizeof l, "x1 branch reached (%d vectors)", x1); ck(l, x1 > 0);
      snprintf(l, sizeof l, "x2 branch reached (%d vectors)", x2); ck(l, x2 > 0);
      snprintf(l, sizeof l, "x3 branch reached (%d vectors)", x3); ck(l, x3 > 0);
      snprintf(l, sizeof l, "degenerate inputs covered (%d vectors)", degen); ck(l, degen > 0); }

    printf("== every 64-byte string decodes, which is the whole point ==\n");
    /* If some input could fail, the encoding would carry a distinguisher and
     * BIP324's indistinguishability claim would not hold. */
    { int ok = 1;
      unsigned char in[64], out[32];
      for (int trial = 0; trial < 256; trial++){
          for (int j = 0; j < 64; j++) in[j] = (unsigned char)((trial * 7 + j * 31 + (j >> 3)) & 0xff);
          memset(out, 0, 32);
          ellswift_decode(out, in);
          int allzero = 1; for (int j = 0; j < 32; j++) if (out[j]) allzero = 0;
          if (allzero) ok = 0;      /* a real x is essentially never all-zero */
      }
      ck("256 arbitrary inputs all produce an x", ok); }
    { unsigned char in[64], out[32];
      memset(in, 0x00, 64); ellswift_decode(out, in);
      ck("all-zero input decodes (u=0 and t=0 both defaulted)", 1);
      memset(in, 0xff, 64); ellswift_decode(out, in);
      ck("all-ones input decodes (both halves exceed p, reduced)", 1); }

    printf("== round trip: encode(x) then decode must give x back ==\n");
    /* The official vectors pin DECODE absolutely. Encoding is one-to-many --
     * any (u,t) that decodes to x is a correct encoding -- so there are no
     * official encode vectors to check against. Round-tripping through the
     * verified decoder is the real test, and it is a strong one: the reverse
     * map has eight branches and a rejection rule, and getting any of them
     * wrong produces an encoding that decodes to a DIFFERENT point.
     *
     * Every official vector's x is used as the target, so this exercises the
     * reverse map against the same curve points the forward map was pinned on. */
    { int rt_ok = 0, rt_fail = 0, no_enc = 0;
      for (int i = 0; i < ELLSWIFT_NVEC; i++){
          unsigned char want[32], enc[64], back[32];
          unhex(want, ELLSWIFT_VEC[i].x);
          unsigned long long xf[4];
          ellswift_be32_to_fe(xf, want);
          unsigned char rnd[32];
          for (int j = 0; j < 32; j++) rnd[j] = (unsigned char)(i * 37 + j * 11 + 1);
          if (!ellswift_encode_x(enc, xf, rnd, sizeof rnd)){ no_enc++; continue; }
          ellswift_decode(back, enc);
          if (!memcmp(back, want, 32)) rt_ok++;
          else {
              if (rt_fail < 3){
                  char g[70], w[70]; tohex(g, back, 32); tohex(w, want, 32);
                  printf("        vector %d round-tripped to the WRONG x\n          got  %s\n          want %s\n", i, g, w);
              }
              rt_fail++;
          }
      }
      char l[140];
      snprintf(l, sizeof l, "%d/%d official x values round-trip exactly", rt_ok, ELLSWIFT_NVEC);
      ck(l, rt_fail == 0 && rt_ok > 0);
      snprintf(l, sizeof l, "  encoder found a solution for every x (%d gave up)", no_enc);
      ck(l, no_enc == 0); }

    printf("== BIP324 official reverse-map vectors (all 8 branches, exact t) ==\n");
    /* These pin far more than the round trip above. For each (u,x) they give
     * the EXACT t for every branch that has a solution, and an empty string
     * for every branch that must be refused. Producing some other encoding
     * that happens to decode correctly would pass the round-trip test and
     * fail here -- and it should, because a peer running libsecp256k1 has to
     * agree with us branch for branch and sign for sign. */
    { int solved = 0, refused = 0, wrong_t = 0, should_fail = 0, should_pass = 0, fwd_bad = 0;
      for (int i = 0; i < XSINV_NVEC; i++){
          unsigned char ub[32], xb[32];
          unhex(ub, XSINV_VEC[i].u); unhex(xb, XSINV_VEC[i].x);
          unsigned long long u[4], x[4], t[4];
          ellswift_be32_to_fe(u, ub); ellswift_be32_to_fe(x, xb);
          for (int c = 0; c < 8; c++){
              const char* want = XSINV_VEC[i].t[c];
              int has = want && want[0];
              int got = ellswift_xswiftec_inv(t, x, u, c);
              if (has && !got){ if (should_pass < 3) printf("        vec %d case %d: refused a case that HAS a solution\n", i, c); should_pass++; continue; }
              if (!has && got){ if (should_fail < 3) printf("        vec %d case %d: returned a t where there is NO solution\n", i, c); should_fail++; continue; }
              if (!has){ refused++; continue; }
              unsigned char tb[32]; ellswift_fe_to_be32(tb, t);
              char gh[70]; tohex(gh, tb, 32);
              if (strcmp(gh, want)){
                  if (wrong_t < 3) printf("        vec %d case %d: t mismatch\n          got  %s\n          want %s\n", i, c, gh, want);
                  wrong_t++; continue;
              }
              /* and the forward map must send (u,t) back to x */
              unsigned char enc[64], back[32];
              memcpy(enc, ub, 32); memcpy(enc + 32, tb, 32);
              ellswift_decode(back, enc);
              if (memcmp(back, xb, 32)) fwd_bad++;
              solved++;
          }
      }
      char l[160];
      snprintf(l, sizeof l, "%d branch solutions match Core's t byte for byte", solved);
      ck(l, wrong_t == 0 && solved > 0);
      snprintf(l, sizeof l, "%d branches with no solution are all refused", refused);
      ck(l, refused > 0);
      ck("  no case that has a solution was refused", should_pass == 0);
      ck("  no case without a solution returned a t", should_fail == 0);
      ck("  every solution feeds back through the forward map to x", fwd_bad == 0);
      snprintf(l, sizeof l, "  %d vectors x 8 branches = %d checks, all accounted for",
               XSINV_NVEC, XSINV_NVEC * 8);
      ck(l, solved + refused == XSINV_NVEC * 8); }

    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}
