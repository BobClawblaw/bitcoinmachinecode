/* tests/test_hdr_tree.c -- the fork tree: headers off the best chain are
 * retained with their work, found by hash, the heaviest tip is the best,
 * pruning drops old entries, the file survives a reload, and a full table
 * evicts the lightest tip rather than refusing a heavier one. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "../daemon/hdr_tree.h"
#include "test_tmpdir.h"
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static void mk(unsigned char h[80], const unsigned char prev[32], unsigned nonce){ memset(h, 0, 80); h[0] = 1; if (prev) memcpy(h + 4, prev, 32); memcpy(h + 76, &nonce, 4); h[72] = 0xff; h[73] = 0xff; h[74] = 0x7f; h[75] = 0x20; }
static void work_n(unsigned char w[16], unsigned n){ memset(w, 0, 16); memcpy(w, &n, 4); }
int main(void){
    tt_isolate(); hdrtree_reset();
    unsigned char a[80], b[80], c[80], ha[32], hb[32], hc[32], w[16], prev[32]; long h;
    mk(a, 0, 1); block_hash(ha, a); mk(b, ha, 2); block_hash(hb, b); mk(c, ha, 3); block_hash(hc, c);
    work_n(w, 10); ck("add a (work 10)", hdrtree_add(a, 100, w) == 1);
    work_n(w, 25); ck("add b, a's child (work 25)", hdrtree_add(b, 101, w) == 1);
    work_n(w, 20); ck("add c, a's other child (work 20)", hdrtree_add(c, 101, w) == 1);
    ck("a duplicate is 0", hdrtree_add(b, 101, w) == 0 && hdrtree_count() == 3);
    ck("has/get: b is known with prev a, height 101, work 25", hdrtree_has(hb) && hdrtree_get(hb, prev, &h, w) && !memcmp(prev, ha, 32) && h == 101 && *(unsigned*)w == 25);
    unsigned char best[32]; ck("the best tip is b (25 > 20); a is not a tip", hdrtree_best(best, &h, w) && !memcmp(best, hb, 32) && h == 101);
    ck("prune below 101 drops a only", hdrtree_prune_below(101) == 1 && hdrtree_count() == 2 && !hdrtree_has(ha) && hdrtree_has(hb));
    ck("reload from the file keeps both", hdrtree_open() == 1 && hdrtree_count() == 2 && hdrtree_has(hc));
    /* fill to the cap with a chain of light tips, then a heavy one evicts the lightest tip */
    hdrtree_reset(); unsigned char p[32]; memset(p, 0x11, 32); int added = 0;
    for (long i = 0; i < HDRTREE_MAX; i++){ unsigned char x[80]; mk(x, p, (unsigned)(1000 + i)); work_n(w, (unsigned)(2 + i)); if (hdrtree_add(x, 500 + i, w) == 1) added++; block_hash(p, x); }
    ck("filled to the cap", added == HDRTREE_MAX && hdrtree_count() == HDRTREE_MAX);
    { unsigned char x[80]; memset(p, 0x22, 32); mk(x, p, 77); work_n(w, 1); ck("a lighter header than every tip is refused when full", hdrtree_add(x, 9, w) == -1); }
    { unsigned char x[80]; memset(p, 0x33, 32); mk(x, p, 78); work_n(w, 999999); ck("a heavier one evicts the lightest tip and lands", hdrtree_add(x, 9, w) == 1 && hdrtree_count() == HDRTREE_MAX && hdrtree_best(best, &h, w) && *(unsigned*)w == 999999); }
    { long before = hdrtree_count();
      hdrtree_open();
      ck("an eviction leaves the file too: a reload holds exactly the table, the evicted tip gone",
         hdrtree_count() == before && before == HDRTREE_MAX && hdrtree_best(best, &h, w) && *(unsigned*)w == 999999); }

    /* ---- 2026-11-04: the header itself, for getblockheader on a block reorged off ---- */
    hdrtree_reset();
    unsigned char d[80], hd[32], got[80], gw[16]; long gh; unsigned gn;
    mk(d, ha, 9); block_hash(hd, d); work_n(w, 41);
    ck("add with nTx 7", hdrtree_add_ntx(d, 120, w, 7) == 1);
    ck("the RPC process's file lookup returns the 80-byte header, height, work and nTx",
       hdrtree_file_lookup(hd, got, &gh, gw, &gn) == 1 && !memcmp(got, d, 80) && gh == 120 && *(unsigned*)gw == 41 && gn == 7);
    ck("an unknown hash is not found", hdrtree_file_lookup(ha, NULL, NULL, NULL, NULL) == 0);
    { FILE* f = fopen(HDRTREE_FILE, "ab"); unsigned char half[HDRTREE_REC / 2]; memcpy(half, hd, 32); memset(half + 32, 0, sizeof half - 32); fwrite(half, 1, sizeof half, f); fclose(f);
      ck("a half-written record at the end (an append in flight) is ignored, the whole one still found",
         hdrtree_file_lookup(hd, got, &gh, NULL, NULL) == 1 && !memcmp(got, d, 80) && gh == 120); }

    /* a version-1 file (96-byte records, no header) is read, rewritten as version 2 and kept aside */
    hdrtree_reset();
    { FILE* f = fopen(HDRTREE_FILE_V1, "wb"); unsigned char r[HDRTREE_REC_V1]; memset(r, 0, sizeof r);
      memcpy(r, hd, 32); memcpy(r + 32, ha, 32); long hh = 120; memcpy(r + 64, &hh, 8); memcpy(r + 72, d + 72, 4); work_n(w, 41); memcpy(r + 76, w, 16);
      fwrite(r, 1, sizeof r, f); fclose(f); }
    ck("open reads the version-1 entry", hdrtree_open() == 1 && hdrtree_count() == 1 && hdrtree_get(hd, prev, &h, w) && h == 120 && !memcmp(prev, ha, 32));
    ck("...moves the version-1 file aside", access(HDRTREE_FILE_V1, F_OK) != 0 && access(HDRTREE_FILE_V1 ".v1", F_OK) == 0);
    ck("...and a version-1 entry has no header to serve", hdrtree_file_lookup(hd, NULL, NULL, NULL, NULL) == 0);
    work_n(w, 41);
    ck("adding the same block again fills its header in (0: already known)", hdrtree_add_ntx(d, 120, w, 3) == 0 &&
       hdrtree_file_lookup(hd, got, &gh, NULL, &gn) == 1 && !memcmp(got, d, 80) && gn == 3 && hdrtree_count() == 1);
    unlink(HDRTREE_FILE_V1 ".v1");

    printf("%s (%d failure(s))\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
