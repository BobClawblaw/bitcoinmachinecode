/* tests/test_hdr_lowwork.c -- CC-5: full low-work header pages are held, not stored. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "hdr_lowwork.h"
extern void block_work(unsigned char work[16], unsigned bits);
extern void chainwork_add(unsigned char out[16], const unsigned char a[16], const unsigned char b[16]);
extern long chainwork_cmp(const unsigned char a[16], const unsigned char b[16]);
static int checks, fails; static void ok(int c, const char* m){ checks++; if(!c) fails++; printf("  %s %s\n", c?"ok  :":"FAIL:", m); }
static unsigned char FLOOR[16];
static int floor_fn(const unsigned char w[16]){ return chainwork_cmp(w, FLOOR) >= 0; }
static void mkpage(unsigned char* p, unsigned long cnt, unsigned bits){ memset(p, 0, cnt*81); for (unsigned long i = 0; i < cnt; i++){ unsigned char* h = p + i*81; h[72]=bits; h[73]=bits>>8; h[74]=bits>>16; h[75]=bits>>24; } }
static unsigned char fake_store[200][112];
static int fake_get(void* hst, unsigned long long h, void* out){ (void)hst; if (h >= 200) return 0; memcpy(out, fake_store[h], 112); return 1; }
int main(void){
    static lowwork_t L; static unsigned char page[LOWWORK_PAGE_MAX*81];
    const unsigned BITS = 0x1d00ffffu;                      /* genesis difficulty: work 2^32 per header */
    unsigned char one[16]; block_work(one, BITS);
    unsigned char zero[16]; memset(zero, 0, 16);
    unsigned char Z[32], H1[32], H2[32], H3[32]; memset(Z,0,32); memset(H1,1,32); memset(H2,2,32); memset(H3,3,32);
    /* floor = 5000 headers' worth of genesis work: 2.5 full pages */
    memset(FLOOR, 0, 16); for (int i = 0; i < 5000; i++) chainwork_add(FLOOR, FLOOR, one);
    lowwork_set_floor_fn(floor_fn);
    printf("== the finding: full pages below the floor are HELD, not stored ==\n");
    lowwork_begin(&L, zero, 1);
    mkpage(page, 2000, BITS); ok(lowwork_page(&L, page, 2000, 1, Z, H1) == LOWWORK_HOLD, "page 1 (2000 hdrs, 40%% of floor): HOLD");
    ok(lowwork_page(&L, page, 2000, 2001, H1, H2) == LOWWORK_HOLD && L.held == 2, "page 2 (80%%): HOLD, two pages held");
    ok(lowwork_page(&L, page, 2000, 4001, H2, H3) == LOWWORK_RELEASE, "page 3 crosses the floor: RELEASE the held pages, then append");
    { const unsigned char* h; unsigned long c; long p; const unsigned char* pv; ok(lowwork_held(&L, 0, &h, &c, &p, &pv) && c == 2000 && p == 1 && !memcmp(pv, Z, 32) && lowwork_held(&L, 1, &h, &c, &p, &pv) && p == 2001 && !memcmp(pv, H1, 32) && !lowwork_held(&L, 2, &h, &c, &p, &pv), "held pages come back in order with their heights and their prev hashes");
      unsigned char th[32]; long tht; ok(lowwork_tail(&L, th, &tht) && !memcmp(th, H2, 32) && tht == 4000, "the tail (last held header) is where the next getheaders starts: hash H2, height 4000"); }
    lowwork_clear(&L); ok(lowwork_page(&L, page, 2000, 6001, Z, Z) == LOWWORK_APPEND, "above the floor: plain APPEND from then on");
    printf("== a chain that never crosses the floor is abandoned, bounded ==\n");
    unsigned char low[16]; memset(low, 0, 16); lowwork_begin(&L, low, 1);
    unsigned char weak[LOWWORK_PAGE_MAX*81]; mkpage(weak, 2000, 0x1d00ffffu);
    /* raise the floor so 4 pages never reach it */
    memset(FLOOR, 0, 16); for (int i = 0; i < 20000; i++) chainwork_add(FLOOR, FLOOR, one);
    int r = 0; for (int i = 0; i < LOWWORK_HOLD_PAGES; i++) r = lowwork_page(&L, weak, 2000, 1 + i*2000, Z, Z);
    ok(r == LOWWORK_HOLD && L.held == LOWWORK_HOLD_PAGES, "four full low-work pages held (the scratch bound)");
    ok(lowwork_page(&L, weak, 2000, 8001, Z, Z) == LOWWORK_ABANDON, "the fifth: ABANDON -- 8000 junk headers cost 648 KB of scratch and nothing on disk");
    printf("== a short page is the end of its chain: appended, as Core does ==\n");
    lowwork_begin(&L, low, 1); ok(lowwork_page(&L, weak, 1500, 1, Z, Z) == LOWWORK_APPEND, "1500-header page below the floor: APPEND (bounded by one page)");
    printf("== cumulative work from a store ==\n");
    for (int h = 0; h < 200; h++){ memset(fake_store[h], 0, 112); fake_store[h][72]=0xff; fake_store[h][73]=0xff; fake_store[h][74]=0; fake_store[h][75]=0x1d; }
    unsigned char cum[16], expect[16]; memset(expect, 0, 16); for (int i = 0; i < 100; i++) chainwork_add(expect, expect, one);
    lowwork_cum_from_store(cum, NULL, 99, fake_get); ok(chainwork_cmp(cum, expect) == 0, "work of headers [0,99] = 100 x genesis work");
    printf("== a fork point already above the floor: nothing is ever held ==\n");
    memset(FLOOR, 0, 16); for (int i = 0; i < 5000; i++) chainwork_add(FLOOR, FLOOR, one);
    unsigned char high[16]; memset(high, 0, 16); for (int i = 0; i < 6000; i++) chainwork_add(high, high, one);
    lowwork_begin(&L, high, 1); ok(lowwork_page(&L, weak, 2000, 6001, Z, Z) == LOWWORK_APPEND, "a synced node extending its tip: APPEND (no cost added to the normal path)");
    printf("== negative control: the gate disarmed (the pre-CC-5 node) ==\n");
    lowwork_begin(&L, low, 0); r = 0; for (int i = 0; i < 6; i++) r = lowwork_page(&L, weak, 2000, 1 + i*2000, Z, Z);
    ok(r == LOWWORK_APPEND && L.held == 0, "control: six full low-work pages -> every one APPENDED to the store (the finding)");
    printf("\n%s (%d checks, %d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", checks, fails); return fails?1:0;
}
