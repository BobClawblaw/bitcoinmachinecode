/* test_tip_watch.c -- the tip-progress watch's rule (daemon/tip_watch.h,
 * 2026-11-07): a block announced on 3 legs and a tip that has not moved for
 * 15 minutes warns, for 30 ends the worker; one leg's noise, a moved tip, a
 * refused block and a flood of junk hashes do not. The wiring (the
 * announcement handler, the rotation, the shutdown) is checked in
 * tests/test_announce_claim.c. */
#include <stdio.h>
#include <string.h>
#include "tip_watch.h"

static int fails = 0, checks = 0;
static void ck(const char* w, int c){ checks++; if (c) printf("ok  : %s\n", w); else { printf("FAIL: %s\n", w); fails++; } }

static unsigned char bad[32];
static int is_bad(const unsigned char h[32]){ return !memcmp(h, bad, 32); }
static void mk(unsigned char h[32], int v){ memset(h, 0, 32); h[0] = (unsigned char)v; h[1] = (unsigned char)(v >> 8); h[31] = 0x5a; }

int main(void){
    setvbuf(stdout, NULL, _IONBF, 0);
    const long long M = 60 * 1000, T0 = 1000000;
    tipw_t w; memset(&w, 0, sizeof w);
    unsigned char a[32], b[32], j[32]; mk(a, 1); mk(b, 2);
    long long age; int legs;

    ck("the first check only records the tip", tipw_check(&w, 100, T0, 0, is_bad, &age, &legs) == TIPW_OK && w.have_tip && w.tip == 100);

    /* one leg, then two: noise, however long */
    tipw_announce(&w, a, 4, T0);
    for (int r = 0; r < 5; r++) tipw_announce(&w, a, 4, T0 + r);    /* the same leg again and again */
    ck("one leg announcing it five times is one leg", tipw_legs(w.legs[0]) == 1 && w.quorum_ms[0] == 0);
    tipw_announce(&w, a, 7, T0 + 1000);
    ck("two legs, three hours later: nothing", tipw_check(&w, 100, T0 + 180 * M, 0, is_bad, &age, &legs) == TIPW_OK);

    /* the third leg: the clock starts there */
    long long q = T0 + 180 * M;
    tipw_announce(&w, a, 9, q);
    ck("the third leg counts it", w.quorum_ms[0] == q);
    ck("just short of 15 min: nothing", tipw_check(&w, 100, q + 15 * M - 1, 0, is_bad, &age, &legs) == TIPW_OK);
    ck("at 15 min: one warning", tipw_check(&w, 100, q + 15 * M, 0, is_bad, &age, &legs) == TIPW_WARN && age == 15 * M && legs == 3);
    ck("...only one", tipw_check(&w, 100, q + 20 * M, 0, is_bad, &age, &legs) == TIPW_OK);
    ck("just short of 30 min: still nothing", tipw_check(&w, 100, q + 30 * M - 1, 0, is_bad, &age, &legs) == TIPW_OK);
    ck("at 30 min: fatal", tipw_check(&w, 100, q + 30 * M, 0, is_bad, &age, &legs) == TIPW_FATAL && age == 30 * M);
    ck("...and it stays fatal", tipw_check(&w, 100, q + 31 * M, 0, is_bad, &age, &legs) == TIPW_FATAL);

    /* the tip moves */
    ck("a tip that moved after a warning says so", tipw_check(&w, 101, q + 32 * M, 0, is_bad, &age, &legs) == TIPW_RECOVERED && age == 32 * M);
    ck("...and the record is cleared", w.n == 0 && w.warned == 0 && w.tip == 101);
    tipw_announce(&w, b, 1, q + 33 * M); tipw_announce(&w, b, 2, q + 33 * M); tipw_announce(&w, b, 3, q + 33 * M);
    ck("a tip that moves before the warning is just a block", tipw_check(&w, 102, q + 40 * M, 0, is_bad, &age, &legs) == TIPW_OK && w.n == 0);
    ck("a lower tip (a reorg's first step) is a change too", tipw_check(&w, 101, q + 41 * M, 0, is_bad, &age, &legs) == TIPW_OK && w.tip == 101);

    /* the oldest counted hash sets the clock */
    long long t = q + 50 * M;
    tipw_announce(&w, a, 1, t); tipw_announce(&w, a, 2, t); tipw_announce(&w, a, 3, t);
    tipw_announce(&w, b, 1, t + 10 * M); tipw_announce(&w, b, 2, t + 10 * M); tipw_announce(&w, b, 3, t + 10 * M);
    ck("two counted blocks: the older one's age", tipw_check(&w, 101, t + 30 * M, 0, is_bad, &age, &legs) == TIPW_FATAL && age == 30 * M);

    /* a counted hash that we then refused is dropped */
    memcpy(bad, a, 32);
    ck("a counted block in the invalid set is dropped; the next one's age stands (20 min: its warning)", tipw_check(&w, 101, t + 30 * M, 0, is_bad, &age, &legs) == TIPW_WARN && age == 20 * M && w.n == 1);
    memset(bad, 0, 32);

    /* the invalid set grew since the tip last moved: stand down */
    ck("a refused block since the tip moved: said once", tipw_check(&w, 101, t + 45 * M, 1, is_bad, &age, &legs) == TIPW_REFUSED);
    tipw_announce(&w, b, 1, t + 46 * M); tipw_announce(&w, b, 2, t + 46 * M); tipw_announce(&w, b, 3, t + 46 * M);
    ck("...then silent, however long its descendants are announced", tipw_check(&w, 101, t + 300 * M, 1, is_bad, &age, &legs) == TIPW_OK);
    ck("...until the tip moves (no 'recovered' line for it)", tipw_check(&w, 102, t + 301 * M, 1, is_bad, &age, &legs) == TIPW_OK && w.warned == 0 && w.invalid_n == 1);
    tipw_announce(&w, b, 1, t + 302 * M); tipw_announce(&w, b, 2, t + 302 * M); tipw_announce(&w, b, 3, t + 302 * M);
    ck("...after which the watch is back", tipw_check(&w, 102, t + 332 * M, 1, is_bad, &age, &legs) == TIPW_FATAL);

    /* a lone peer's junk cannot crowd out a real block */
    ck("(new episode)", tipw_check(&w, 103, t + 400 * M, 1, is_bad, &age, &legs) == TIPW_OK);
    for (int v = 100; v < 100 + 3 * TIPW_SLOTS; v++){ mk(j, v); tipw_announce(&w, j, 5, t + 400 * M); }
    ck("junk fills the table", w.n == TIPW_SLOTS);
    long long r0 = t + 401 * M;
    tipw_announce(&w, a, 1, r0); tipw_announce(&w, a, 2, r0); tipw_announce(&w, a, 3, r0);
    int found = 0; for (int i = 0; i < w.n; i++) if (!memcmp(w.hash[i], a, 32) && w.quorum_ms[i] == r0) found = 1;
    ck("a real block still gets in and counts", found);
    for (int v = 1000; v < 1000 + 3 * TIPW_SLOTS; v++){ mk(j, v); tipw_announce(&w, j, 6, r0 + M); }
    found = 0; for (int i = 0; i < w.n; i++) if (!memcmp(w.hash[i], a, 32)) found = 1;
    ck("...and more junk never evicts it", found);
    ck("...so the stall is still seen", tipw_check(&w, 103, r0 + 30 * M, 1, is_bad, &age, &legs) == TIPW_FATAL);

    /* every slot counted: a new hash is turned away, the oldest stays */
    tipw_t f; memset(&f, 0, sizeof f);
    ck("(full table)", tipw_check(&f, 200, T0, 0, is_bad, &age, &legs) == TIPW_OK);
    for (int v = 0; v < TIPW_SLOTS; v++){ mk(j, 2000 + v); for (int k = 0; k < 3; k++) tipw_announce(&f, j, k, T0 + v * M); }
    mk(j, 9999); tipw_announce(&f, j, 8, T0 + 20 * M);
    ck("with every slot counted, a new hash is not recorded", f.n == TIPW_SLOTS && f.quorum_ms[0] == T0);
    ck("...and the oldest still sets the clock", tipw_check(&f, 200, T0 + 30 * M, 0, is_bad, &age, &legs) == TIPW_FATAL && age == 30 * M);

    /* leg numbers outside the bit set are ignored */
    tipw_t z; memset(&z, 0, sizeof z);
    tipw_announce(&z, a, -1, T0); tipw_announce(&z, a, 64, T0);
    ck("legs outside 0..63 are ignored", z.n == 0);

    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
