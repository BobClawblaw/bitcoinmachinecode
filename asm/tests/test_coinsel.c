/* tests/test_coinsel.c -- CC-10: SRD, knapsack and the waste metric beside BnB. */
#include <stdio.h>
#include <string.h>
#include "wallet_coinsel.h"
static int checks, fails; static void ok(int c, const char* m){ checks++; if(!c) fails++; printf("  %s %s\n", c?"ok  :":"FAIL:", m); }
static wcs_u64 sum(const wcs_u64* e, const int* p, long n){ wcs_u64 s = 0; for (long i = 0; i < n; i++) s += e[p[i]]; return s; }
int main(void){
    wcs_u64 e[] = { 5000, 3000, 2000, 1000, 500, 250 }; int n = 6; int pick[16]; long k;
    printf("== knapsack: exact single, exact subset, smallest overshoot, lowest-larger ==\n");
    k = wallet_knapsack_select(e, n, 3000, 0, pick, 16, 1); ok(k == 1 && e[pick[0]] == 3000, "exact single coin 3000");
    k = wallet_knapsack_select(e, n, 3750, 0, pick, 16, 1); ok(k > 0 && sum(e, pick, k) == 3750, "3750 = 3000+500+250 exactly");
    printf("      picked %ld coins, sum %llu\n", k, (unsigned long long)sum(e, pick, k));
    k = wallet_knapsack_select(e, n, 11751, 0, pick, 16, 1); ok(k == -1, "more than everything: no selection");
    k = wallet_knapsack_select(e, n, 4100, 0, pick, 16, 1); ok(k > 0 && sum(e, pick, k) >= 4100 && sum(e, pick, k) <= 4250, "4100: smallest overshoot (4250 or exact-ish), not the 5000 coin");
    printf("      sum %llu\n", (unsigned long long)sum(e, pick, k));
    k = wallet_knapsack_select(e, n, 4900, 100, pick, 16, 1); ok(k > 0 && sum(e, pick, k) >= 4900, "with min_change 100 the 5000 coin (lowest larger) is acceptable");
    printf("== SRD: covers target + change cost, random order ==\n");
    k = wallet_srd_select(e, n, 4000, 300, pick, 16, 7); ok(k > 0 && sum(e, pick, k) >= 4300, "selection covers 4000 + 300 change cost");
    int pick2[16]; long k2 = wallet_srd_select(e, n, 4000, 300, pick2, 16, 99);
    ok(k2 > 0 && (k2 != k || memcmp(pick, pick2, (size_t)(k < k2 ? k : k2) * sizeof(int)) != 0), "a different seed gives a different draw (it is random)");
    ok(wallet_srd_select(e, n, 20000, 0, pick, 16, 7) == -1, "unreachable target: -1");
    printf("== waste: change cost vs burned excess ==\n");
    int p1[] = {0}; long long w_change = wallet_selection_waste(e, NULL, p1, 1, 4000, 200);   /* 5000 for 4000 with change: waste = change cost */
    long long w_burn   = wallet_selection_waste(e, NULL, p1, 1, 4000, 0);                     /* no change: excess 1000 burned */
    ok(w_change == 200 && w_burn == 1000, "change costs 200; burning the 1000 excess costs 1000 -> making change is cheaper here");
    int p2[] = {1, 3}; long long w_exact = wallet_selection_waste(e, NULL, p2, 2, 4000, 0);
    ok(w_exact == 0, "an exact 3000+1000 match with no change wastes nothing");
    long long fd[] = { 50, 50, 50, 50, 50, 50 }; ok(wallet_selection_waste(e, fd, p2, 2, 4000, 0) == 100, "fee above long-term rate: 50 per input counts as waste");
    long long fd2[] = { -30, -30, -30, -30, -30, -30 }; ok(wallet_selection_waste(e, fd2, p2, 2, 4000, 0) == -60, "fee below long-term rate: negative waste (spending now is cheap)");
    printf("== negative control: BnB-only wallet had no answer when no exact match exists ==\n");
    extern long wallet_bnb_select(const wcs_u64*, const long long*, int, wcs_u64, wcs_u64, int*, int);
    long b = wallet_bnb_select(e, NULL, n, 4100, 0, pick, 16);
    k = wallet_knapsack_select(e, n, 4100, 0, pick, 16, 1);
    ok(b <= 0 && k > 0, "control: BnB finds nothing for 4100 (no changeless match); knapsack does -- the pre-CC-10 wallet fell to largest-first");
    printf("\n%s (%d checks, %d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", checks, fails); return fails?1:0;
}
