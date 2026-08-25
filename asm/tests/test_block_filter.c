/* test_block_filter.c -- BIP158 basic filters vs Bitcoin Core's own.
 *
 * Two real mainnet blocks, their filters frozen from the oracle
 * (2026-08-25), compared BYTE-FOR-BYTE:
 *
 *   501726  the degenerate case: coinbase-only, one non-OP_RETURN output,
 *           so N=1 -- filter "019170b8". Exercises the key derivation, one
 *           SipHash, the mapping and the Golomb tail with nothing else in
 *           the way: a wrong rotation in SipHash fails HERE, pinpointed.
 *   700038  91 transactions, 129 spent prevouts (frozen from the oracle's
 *           getblock verbosity 3), 827 filter bytes. Exercises collection,
 *           de-duplication, sorting and the full encoder at realistic size.
 *
 * The header chain link is verified against the oracle too: given block
 * 501725's real filter header, bf_header must reproduce 501726's.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../block_filter.h"
#include "test_tmpdir.h"

extern void sha256d(unsigned char out[32], const void* data, unsigned long len);

static int fails = 0, checks = 0;
static void ck(const char* w, int c){ checks++; if (c) printf("ok  : %s\n", w); else { printf("FAIL: %s\n", w); fails++; } }

static long slurp(const char* path, unsigned char* out, long cap){
    FILE* f = fopen(path, "rb");
    if (!f) return -1;
    long n = (long)fread(out, 1, (size_t)cap, f);
    fclose(f);
    return n;
}
static void hexify(char* out, const unsigned char* b, long n){
    static const char* H = "0123456789abcdef";
    for (long i = 0; i < n; i++){ out[i*2]=H[b[i]>>4]; out[i*2+1]=H[b[i]&15]; }
    out[n*2]=0;
}
static long unhex(unsigned char* out, const char* h, long maxn){
    long n = 0;
    while (h[0] && h[1] && n < maxn){
        int a = h[0], b = h[1];
        a = (a<='9')?a-'0':((a|32)-'a'+10);
        b = (b<='9')?b-'0':((b|32)-'a'+10);
        if (a < 0 || a > 15 || b < 0 || b > 15) break;
        out[n++] = (unsigned char)((a<<4)|b);
        h += 2;
    }
    return n;
}

/* Oracle values, frozen 2026-08-25 (Core v31.99, blockfilterindex=1). */
static const char* F_501726     = "019170b8";
static const char* HDR_501726   = "610391fe648865234f621b329b5ea03a732c5e8cdb93af5da4da58a6265f4c52";
static const char* HDR_501725   = "d89e5381d2ef7d33d4721a7b49b42a20239ae5f7d1e3546811c1048072bec36d";
static const char* HDR_700038   = "519c5132f3372797f6b0a40f6576b3b23d6c0803a217659c892345c450b4410f";
static const char* HDR_700037   = "35eb5045dd4b85fdb649c4130ecbafbaa5cc6daffcc2f819375daa78b2a07e1c";

int main(void){
    tt_isolate();
    static unsigned char blk[4 << 20];
    static unsigned char flt[1 << 20];
    char hex[1 << 20];

    /* ==== block 501726: the minimal real block ==== */
    long bl = slurp(tt_src("tests/fixtures/blk_501726.bin"), blk, sizeof blk);
    ck("fixture block 501726 loads (200 bytes)", bl == 200);
    unsigned char hash[32]; sha256d(hash, blk, 80);
    long fl = bf_basic_build(blk, (unsigned long)bl, hash, NULL, 0, flt, sizeof flt);
    ck("filter builds", fl > 0);
    hexify(hex, flt, fl);
    ck("filter is BYTE-IDENTICAL to Core's (019170b8)", fl == 4 && !strcmp(hex, F_501726));

    /* header chain link vs the oracle */
    { unsigned char prev[32], got[32]; char gh[65];
      /* headers are printed reversed (display order), so un-reverse */
      unsigned char tmp[32]; unhex(tmp, HDR_501725, 32);
      for (int i = 0; i < 32; i++) prev[i] = tmp[31-i];
      bf_header(flt, (unsigned long)fl, prev, got);
      unsigned char gr[32]; for (int i = 0; i < 32; i++) gr[i] = got[31-i];
      hexify(gh, gr, 32);
      ck("the header chain link reproduces Core's header for 501726",
         !strcmp(gh, HDR_501726)); }

    /* ==== block 700038: 91 txs, 129 spent prevouts ==== */
    bl = slurp(tt_src("tests/fixtures/blk_700038.bin"), blk, sizeof blk);
    ck("fixture block 700038 loads", bl == 29574);
    sha256d(hash, blk, 80);

    /* load the prevout scripts (one hex line each) */
    static bf_script prevs[512];
    static unsigned char prevbuf[512][128];
    int np = 0;
    { FILE* f = fopen(tt_src("tests/fixtures/prevouts_700038.txt"), "r");
      ck("prevout fixture opens", f != NULL);
      char line[300];
      while (f && fgets(line, sizeof line, f) && np < 512){
          size_t l = strlen(line);
          while (l && (line[l-1]=='\n' || line[l-1]=='\r')) line[--l] = 0;
          if (!l) continue;
          long n = unhex(prevbuf[np], line, sizeof prevbuf[np]);
          prevs[np].script = prevbuf[np]; prevs[np].len = (unsigned long)n;
          np++;
      }
      if (f) fclose(f); }
    ck("all 129 prevout scripts loaded", np == 129);

    fl = bf_basic_build(blk, (unsigned long)bl, hash, prevs, (unsigned long)np, flt, sizeof flt);
    ck("filter builds at realistic size", fl > 0);
    { static char want[8192];
      long wl = slurp(tt_src("tests/fixtures/filter_700038.txt"), (unsigned char*)want, sizeof want - 1);
      while (wl > 0 && (want[wl-1]=='\n' || want[wl-1]=='\r')) wl--;
      want[wl] = 0;
      hexify(hex, flt, fl);
      ck("827-byte filter is BYTE-IDENTICAL to Core's",
         fl == 827 && !strcmp(hex, want));
      if (strcmp(hex, want)) printf("      got %.60s...\n      want %.60s...\n", hex, want); }

    { unsigned char prev[32], got[32]; char gh[65];
      unsigned char tmp[32]; unhex(tmp, HDR_700037, 32);
      for (int i = 0; i < 32; i++) prev[i] = tmp[31-i];
      bf_header(flt, (unsigned long)fl, prev, got);
      unsigned char gr[32]; for (int i = 0; i < 32; i++) gr[i] = got[31-i];
      hexify(gh, gr, 32);
      ck("the 700038 header link matches Core too", !strcmp(gh, HDR_700038)); }

    /* prevout ORDER must not matter (the element set is hashed and sorted) */
    { bf_script rev[512];
      for (int i = 0; i < np; i++) rev[i] = prevs[np-1-i];
      static unsigned char flt2[1 << 20];
      long fl2 = bf_basic_build(blk, (unsigned long)bl, hash, rev, (unsigned long)np,
                                flt2, sizeof flt2);
      ck("prevout order does not change the filter",
         fl2 == fl && !memcmp(flt, flt2, (size_t)fl)); }

    /* a malformed block fails cleanly */
    ck("a truncated block returns -1, not garbage",
       bf_basic_build(blk, 100, hash, NULL, 0, flt, sizeof flt) == -1);

    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
