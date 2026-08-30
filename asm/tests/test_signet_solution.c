/* tests/test_signet_solution.c -- BIP325: finding the signet solution inside
 * a coinbase witness commitment, and producing the script it is computed
 * over once removed.
 *
 * On signet the block SIGNATURE is the consensus rule, standing in for
 * meaningful proof of work. These bytes decide it: the solution is what gets
 * verified, and the stripped script is hashed into the modified merkle root
 * that the signature commits to. An encoding that differs from Core's by a
 * single byte yields a different root, and then every signature on the
 * network fails to verify -- the node would reject the whole chain while
 * looking, from the inside, like it was working correctly.
 *
 * So the stripped script is checked byte for byte, not merely for length.
 */
#include <stdio.h>
#include <string.h>
#include "../daemon/signet.h"
#include "signet_vectors.h"

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static void tohex(char* o, const unsigned char* b, unsigned long n){
    static const char* H = "0123456789abcdef";
    for (unsigned long i = 0; i < n; i++){ o[i*2] = H[b[i]>>4]; o[i*2+1] = H[b[i]&15]; }
    o[n*2] = 0;
}

/* a witness commitment: OP_RETURN <36: aa21a9ed || 32-byte hash> */
static unsigned long mk_commitment(unsigned char* o){
    unsigned long n = 0;
    o[n++] = 0x6a; o[n++] = 0x24;
    o[n++] = 0xaa; o[n++] = 0x21; o[n++] = 0xa9; o[n++] = 0xed;
    for (int i = 0; i < 32; i++) o[n++] = (unsigned char)(i + 1);
    return n;
}
/* append a push of <4-byte signet header || payload> */
static unsigned long add_solution(unsigned char* o, unsigned long n,
                                  const unsigned char* payload, unsigned long plen){
    unsigned long total = 4 + plen;
    o[n++] = (unsigned char)total;          /* minimal push, total < 76 here */
    o[n++] = SIGNET_HEADER_0; o[n++] = SIGNET_HEADER_1;
    o[n++] = SIGNET_HEADER_2; o[n++] = SIGNET_HEADER_3;
    memcpy(o + n, payload, plen);
    return n + plen;
}

int main(void){
    unsigned char sol[512], strip[512];
    unsigned long sl = 0, stl = 0;

    printf("== locating the witness commitment ==\n");
    { unsigned char c[64]; unsigned long cl = mk_commitment(c);
      unsigned char other[16]; memset(other, 0x51, sizeof other);
      const unsigned char* spks[3] = { other, c, other };
      unsigned long lens[3] = { sizeof other, cl, sizeof other };
      ck("a commitment output is found", signet_commitment_index(spks, lens, 3) == 1);
      const unsigned char* none[2] = { other, other };
      unsigned long nlens[2] = { sizeof other, sizeof other };
      ck("no commitment gives -1", signet_commitment_index(none, nlens, 2) == -1);
      /* Core takes the LAST match, not the first -- a block may carry more
       * than one and only the last is the commitment. */
      const unsigned char* two[3] = { c, other, c };
      unsigned long tlens[3] = { cl, sizeof other, cl };
      ck("with two commitments the LAST one wins", signet_commitment_index(two, tlens, 3) == 2);
      /* one byte short of the minimum must not match */
      const unsigned char* shortspk[1] = { c };
      unsigned long shortlen[1] = { 37 };
      ck("a 37-byte script is below the minimum and is ignored",
         signet_commitment_index(shortspk, shortlen, 1) == -1); }

    printf("== extracting the solution ==\n");
    { unsigned char c[256]; unsigned long cl = mk_commitment(c);
      unsigned char payload[9] = {0xde,0xad,0xbe,0xef,1,2,3,4,5};
      cl = add_solution(c, cl, payload, sizeof payload);

      int r = signet_extract_solution(c, cl, sol, &sl, strip, &stl, sizeof sol);
      ck("a solution is found", r == 1);
      ck("  its length is the push minus the 4-byte header", sl == sizeof payload);
      ck("  and its bytes are the payload", !memcmp(sol, payload, sizeof payload));

      /* the stripped script must be the commitment with the header push kept
       * but shortened to just the header -- byte for byte */
      unsigned char want[64]; unsigned long wl = mk_commitment(want);
      want[wl++] = 4;                       /* a 4-byte push ... */
      want[wl++] = SIGNET_HEADER_0; want[wl++] = SIGNET_HEADER_1;
      want[wl++] = SIGNET_HEADER_2; want[wl++] = SIGNET_HEADER_3;
      char g[600], w[600]; tohex(g, strip, stl); tohex(w, want, wl);
      if (stl != wl || memcmp(strip, want, wl)){
          printf("  FAIL stripped script differs\n        got  %s\n        want %s\n", g, w);
          fails++;
      } else printf("  ok  the stripped script keeps a SHORTENED header push, byte for byte\n"); }

    printf("== no solution is not an error ==\n");
    /* A trivial challenge such as OP_TRUE needs no signature at all, so a
     * commitment without a signet push is valid and must be reported as
     * "none", not as malformed. */
    { unsigned char c[64]; unsigned long cl = mk_commitment(c);
      int r = signet_extract_solution(c, cl, sol, &sl, strip, &stl, sizeof sol);
      ck("a commitment with no signet push reports 0", r == 0);
      ck("  and the script is returned unchanged", stl == cl && !memcmp(strip, c, cl)); }

    printf("== a bare header push is NOT a solution ==\n");
    /* Core requires the push to be LONGER than the header: header-only
     * carries no data and must not be treated as an empty solution. */
    { unsigned char c[64]; unsigned long cl = mk_commitment(c);
      c[cl++] = 4;
      c[cl++] = SIGNET_HEADER_0; c[cl++] = SIGNET_HEADER_1;
      c[cl++] = SIGNET_HEADER_2; c[cl++] = SIGNET_HEADER_3;
      int r = signet_extract_solution(c, cl, sol, &sl, strip, &stl, sizeof sol);
      ck("a header with no data is not a solution", r == 0); }

    printf("== only the FIRST signet push is taken ==\n");
    { unsigned char c[256]; unsigned long cl = mk_commitment(c);
      unsigned char p1[5] = {0xA1,0xA2,0xA3,0xA4,0xA5};
      unsigned char p2[5] = {0xB1,0xB2,0xB3,0xB4,0xB5};
      cl = add_solution(c, cl, p1, sizeof p1);
      cl = add_solution(c, cl, p2, sizeof p2);
      int r = signet_extract_solution(c, cl, sol, &sl, strip, &stl, sizeof sol);
      ck("the first push is the solution", r == 1 && sl == 5 && !memcmp(sol, p1, 5));
      /* and the second survives in the stripped script untouched, because
       * only the first is cleared */
      ck("  the second signet-looking push is left alone",
         memmem(strip, stl, p2, sizeof p2) != NULL); }

    printf("== malformed scripts are refused, not walked off the end ==\n");
    { unsigned char c[64]; unsigned long cl = mk_commitment(c);
      c[cl++] = 40;                          /* claims 40 bytes, none follow */
      ck("a truncated push is -1", signet_extract_solution(c, cl, sol, &sl, strip, &stl, sizeof sol) == -1); }
    { unsigned char c[64]; unsigned long cl = mk_commitment(c);
      c[cl++] = 0x4c;                        /* PUSHDATA1 with no length byte */
      ck("a truncated PUSHDATA1 is -1", signet_extract_solution(c, cl, sol, &sl, strip, &stl, sizeof sol) == -1); }

    printf("== a solution too large for the caller's buffer is refused ==\n");
    { unsigned char c[512]; unsigned long cl = mk_commitment(c);
      unsigned char big[60]; memset(big, 0x77, sizeof big);
      cl = add_solution(c, cl, big, sizeof big);
      unsigned char tiny[8];
      ck("a 60-byte solution into an 8-byte buffer is refused",
         signet_extract_solution(c, cl, tiny, &sl, strip, &stl, sizeof tiny) == -1); }

    printf("== REAL signet blocks from the live network ==\n");
    /* The fixtures above are mine; these are not. Each is a coinbase witness
     * commitment taken off the signet chain, with the expected solution and
     * stripped script recomputed by an independent Python implementation of
     * Core's FetchAndClearCommitmentSection. A shared misreading of the
     * format would have to happen twice, in two languages, to slip through. */
    { int ok = 0, bad = 0;
      for (int i = 0; i < SIGNET_NVEC; i++){
          unsigned char spk[1024], wsol[512], wstrip[1024];
          unsigned long spkl = 0, wsoll = 0, wstripl = 0;
          const char* h;
          for (h = SIGNET_VEC[i].spk; h[0] && h[1]; h += 2){
              int hi = (h[0] <= '9') ? h[0]-'0' : (h[0]|32)-'a'+10;
              int lo = (h[1] <= '9') ? h[1]-'0' : (h[1]|32)-'a'+10;
              spk[spkl++] = (unsigned char)((hi << 4) | lo);
          }
          for (h = SIGNET_VEC[i].solution; h[0] && h[1]; h += 2){
              int hi = (h[0] <= '9') ? h[0]-'0' : (h[0]|32)-'a'+10;
              int lo = (h[1] <= '9') ? h[1]-'0' : (h[1]|32)-'a'+10;
              wsol[wsoll++] = (unsigned char)((hi << 4) | lo);
          }
          for (h = SIGNET_VEC[i].stripped; h[0] && h[1]; h += 2){
              int hi = (h[0] <= '9') ? h[0]-'0' : (h[0]|32)-'a'+10;
              int lo = (h[1] <= '9') ? h[1]-'0' : (h[1]|32)-'a'+10;
              wstrip[wstripl++] = (unsigned char)((hi << 4) | lo);
          }
          unsigned char gsol[512], gstrip[1024];
          unsigned long gsoll = 0, gstripl = 0;
          int r = signet_extract_solution(spk, spkl, gsol, &gsoll, gstrip, &gstripl, sizeof gsol);
          if (r != 1 || gsoll != wsoll || memcmp(gsol, wsol, wsoll) ||
              gstripl != wstripl || memcmp(gstrip, wstrip, wstripl)){
              if (bad < 2)
                  printf("        block %d: r=%d sol %lu/%lu strip %lu/%lu\n",
                         SIGNET_VEC[i].height, r, gsoll, wsoll, gstripl, wstripl);
              bad++;
          } else ok++;
      }
      char l[130];
      snprintf(l, sizeof l, "%d/%d real signet commitments split exactly as Core would",
               ok, SIGNET_NVEC);
      ck(l, bad == 0 && ok == SIGNET_NVEC); }

    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}
