/* tests/test_coinselect_bnb.c -- Branch-and-Bound coin selection
 * (wallet_bnb.c). Core wallet/coinselection.cpp SelectCoinsBnB semantics:
 *
 *   1. an EXACT match is found and selected (waste 0, search stops);
 *   2. a within-window solution (target..target+cost_of_change) is accepted
 *      as changeless;
 *   3. a solution BELOW the window is never fabricated (returns 0: fallback);
 *   4. among multiple solutions the lower-waste (smaller excess) one wins;
 *   5. multi-coin combinations are explored (the classic 5+4 -> 9 case where
 *      no single coin works);
 *   6. unsorted input is rejected (-1), because a silently mis-sorted array
 *      would degrade the search rather than fail it;
 *   7. an unreachable target returns 0 immediately.
 */
#include <stdio.h>

typedef unsigned long long u64;
extern long wallet_bnb_select(const u64* eff, const long long* fee_delta, int n,
                              u64 target, u64 cost_of_change, int* pick, int pickcap);

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }

int main(void){
    int pick[16];

    /* 1: exact match on a single coin */
    { u64 eff[] = { 50000, 30000, 10000 };
      long n = wallet_bnb_select(eff, 0, 3, 30000, 500, pick, 16);
      ck("exact single-coin match", n == 1 && eff[pick[0]] == 30000); }

    /* 2: within-window (target 29800, window 500 -> 30000 qualifies) */
    { u64 eff[] = { 50000, 30000, 10000 };
      long n = wallet_bnb_select(eff, 0, 3, 29800, 500, pick, 16);
      ck("within-window changeless solution", n == 1 && eff[pick[0]] == 30000); }

    /* 3: nothing in window (target 29000, window 500; 30000 overshoots) */
    { u64 eff[] = { 50000, 30000, 10000 };
      long n = wallet_bnb_select(eff, 0, 3, 29000, 500, pick, 16);
      ck("no in-window set -> 0 (caller falls back)", n == 0); }

    /* 4: lower-excess solution wins (target 10000, window 2000:
     *    10500 (excess 500) must beat 11500 (excess 1500)) */
    { u64 eff[] = { 11500, 10500 };
      long n = wallet_bnb_select(eff, 0, 2, 10000, 2000, pick, 16);
      ck("lower waste preferred", n == 1 && eff[pick[0]] == 10500); }

    /* 5: multi-coin combination 5+4 = 9 exactly */
    { u64 eff[] = { 8000, 5000, 4000 };
      long n = wallet_bnb_select(eff, 0, 3, 9000, 0, pick, 16);
      u64 sum = 0; for (long k = 0; k < n; k++) sum += eff[pick[k]];
      ck("combination 5000+4000 == 9000", n == 2 && sum == 9000); }

    /* 6: unsorted input refused */
    { u64 eff[] = { 1000, 5000 };
      ck("ascending input -> -1", wallet_bnb_select(eff, 0, 2, 1000, 0, pick, 16) == -1); }

    /* 7: unreachable target */
    { u64 eff[] = { 100, 50 };
      ck("unreachable target -> 0", wallet_bnb_select(eff, 0, 2, 1000, 50, pick, 16) == 0); }

    /* 8: fee_delta contributes to waste: with equal excess, the coin with the
     *    smaller (fee_now - fee_long_term) sum must win */
    { u64 eff[] = { 10000, 10000 };
      long long fd[] = { 900, 100 };
      long n = wallet_bnb_select(eff, fd, 2, 10000, 5000, pick, 16);
      ck("fee_delta tie-break selects the cheaper input", n == 1 && pick[0] == 1); }

    printf("%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
