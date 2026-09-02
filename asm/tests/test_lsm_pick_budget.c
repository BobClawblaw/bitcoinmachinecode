/* tests/test_lsm_pick_budget.c -- lsm_compact_pick_budget: above the byte
 * budget the leveled pick compacts at 2 runs regardless of the count
 * threshold; below it the count threshold rules (2026-09-01 cliff). */
#include <stdio.h>
#include <stdint.h>
#include "../daemon/lsm_manifest.h"
static int fails = 0;
static void ck(const char* w, int c){ if (c) printf("  ok  %s\n", w); else { printf("  FAIL %s\n", w); fails++; } }
int main(void){
    uint64_t sizes[8] = { 20ull<<30, 3ull<<30, 3ull<<30, 3ull<<30 };   /* one big run + three 3 GB runs */
    long lo = -1;
    ck("count threshold 8 with 4 runs, no budget -> no pick", lsm_compact_pick_budget(sizes, 4, 8, 64, 0, &lo) == 0);
    ck("budget 40 GB, total 29 GB -> still no pick", lsm_compact_pick_budget(sizes, 4, 8, 64, 40ull<<30, &lo) == 0);
    long k = lsm_compact_pick_budget(sizes, 4, 8, 64, 20ull<<30, &lo);
    ck("budget 20 GB, total 29 GB -> picks (ratio 4 folds the 20 GB run in too: 20 <= 4*9)", k == 4 && lo == 0);
    ck("threshold 2 alone gives the same pick (the budget rule is exactly 'threshold 2')", lsm_compact_pick(sizes, 4, 2, 64, &lo) == 4 && lo == 0);
    uint64_t one[1] = { 50ull<<30 };
    ck("a single run never picks, however large", lsm_compact_pick_budget(one, 1, 2, 64, 1ull<<30, &lo) == 0);
    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
