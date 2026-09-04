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

    /* ---------------------------------------------------------------- STO-2
     * A filter whose bitstream runs past 64 KiB must not depend on what was
     * in the output buffer beforehand.
     *
     * bf_basic_build used to zero only the first 65,536 bytes of the caller's
     * buffer and then OR the Golomb-Rice bits in, and every caller in the
     * tree passes a REUSED buffer. So a filter longer than that came out as
     * `previous_filter_bits | this_filter_bits` -- a permanent divergence
     * from Core in bfilters.dat and in every bf_header chained after it.
     *
     * The elements are supplied as PREVOUTS rather than as block outputs so
     * the fixture stays small: 40,000 distinct scripts at BIP158's ~2.6
     * bytes each is ~104 KB of bitstream, comfortably past the old window,
     * with a 100-byte block. The block still has to parse, so it carries one
     * transaction whose single output is an OP_RETURN (skipped as an element
     * by BIP158, so it contributes nothing and the element set stays exactly
     * the 40,000 prevouts).
     *
     * Both probes are differential -- clean buffer vs dirty buffer -- so they
     * need no frozen Core vector to have teeth. Against the pre-fix builder
     * the first probe fails on every byte past offset 65,536. */
    {
        enum { NEL = 40000 };
        static bf_script big[NEL];
        static unsigned char scripts[NEL][22];
        for (int i = 0; i < NEL; i++){
            /* distinct P2WPKH-shaped scripts: OP_0 PUSH20 <20 bytes> */
            scripts[i][0] = 0x00; scripts[i][1] = 0x14;
            for (int b = 0; b < 20; b++)
                scripts[i][2+b] = (unsigned char)((i * 2654435761u) >> ((b % 4) * 8));
            scripts[i][2] = (unsigned char)(i & 0xff);
            scripts[i][3] = (unsigned char)((i >> 8) & 0xff);
            scripts[i][4] = (unsigned char)((i >> 16) & 0xff);
            big[i].script = scripts[i];
            big[i].len = 22;
        }

        /* minimal parseable block: header, 1 tx, 1 input, 1 OP_RETURN output */
        unsigned char sb[200]; unsigned long sn = 0;
        memset(sb, 0x11, 80); sn = 80;
        sb[sn++] = 1;                                  /* ntx = 1 */
        sb[sn++] = 2; sb[sn++] = 0; sb[sn++] = 0; sb[sn++] = 0;   /* version */
        sb[sn++] = 1;                                  /* 1 input */
        memset(sb + sn, 0, 32); sn += 32;              /* prevout hash */
        sb[sn++] = 0xff; sb[sn++] = 0xff; sb[sn++] = 0xff; sb[sn++] = 0xff;
        sb[sn++] = 0;                                  /* empty scriptSig */
        sb[sn++] = 0xff; sb[sn++] = 0xff; sb[sn++] = 0xff; sb[sn++] = 0xff;
        sb[sn++] = 1;                                  /* 1 output */
        memset(sb + sn, 0, 8); sn += 8;                /* value */
        sb[sn++] = 1; sb[sn++] = 0x6a;                 /* OP_RETURN: not an element */
        sb[sn++] = 0; sb[sn++] = 0; sb[sn++] = 0; sb[sn++] = 0;   /* locktime */

        unsigned char bh[32];
        for (int i = 0; i < 32; i++) bh[i] = (unsigned char)(i * 7 + 3);

        static unsigned char clean[1 << 20], dirty[1 << 20];
        memset(clean, 0x00, sizeof clean);
        memset(dirty, 0xff, sizeof dirty);

        long lc = bf_basic_build(sb, sn, bh, big, NEL, clean, sizeof clean);
        long ld = bf_basic_build(sb, sn, bh, big, NEL, dirty, sizeof dirty);

        ck("STO-2 fixture really does exceed the old 64 KiB zeroing window",
           lc > 65536);
        ck("STO-2 a >64 KiB filter is identical from a dirty and a clean buffer",
           lc > 0 && lc == ld && !memcmp(clean, dirty, (size_t)lc));

        /* A third fill pattern, because 0xff and 0x00 alone cannot tell a
         * correct writer from one that happens to OR with all-ones. 0x5a
         * differs from the filter in both directions, bit by bit. */
        static unsigned char patt[1 << 20];
        memset(patt, 0x5a, sizeof patt);
        long lp = bf_basic_build(sb, sn, bh, big, NEL, patt, sizeof patt);
        ck("STO-2 a third fill pattern gives the same filter, to the last byte",
           lp == lc && !memcmp(clean, patt, (size_t)lc));

        /* The audit's own reproduction: two big filters through the SAME
         * buffer, back to back. The second must equal a fresh-buffer build. */
        for (int i = 0; i < NEL; i++) scripts[i][21] ^= 0xa5;   /* a different set */
        static unsigned char fresh[1 << 20];
        memset(fresh, 0x00, sizeof fresh);
        long l2reuse = bf_basic_build(sb, sn, bh, big, NEL, dirty, sizeof dirty);
        long l2fresh = bf_basic_build(sb, sn, bh, big, NEL, fresh, sizeof fresh);
        ck("STO-2 a reused buffer gives the same filter as a fresh one",
           l2reuse > 65536 && l2reuse == l2fresh &&
           !memcmp(dirty, fresh, (size_t)l2reuse));
    }

    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
