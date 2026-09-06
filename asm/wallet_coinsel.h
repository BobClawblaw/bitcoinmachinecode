/* wallet_coinsel.h -- CC-10 (2026-09-06): the two Core selectors this wallet
 * lacked beside BnB, and the waste metric that chooses among them.
 *   SRD      SelectCoinsSRD: shuffle, take until >= target + change cost
 *   knapsack KnapsackSolver / ApproximateBestSubset: exact hit if one exists,
 *            else the smallest overshoot, 1000 random passes with lower bound
 *   waste    GetSelectionWaste: sum(in_fee - long_term_in_fee) + change cost,
 *            or + excess when no change is made; the lowest waste wins.
 * All over effective values (value minus the input's own fee at the current
 * rate), as wallet_bnb.c is. */
#ifndef WALLET_COINSEL_H
#define WALLET_COINSEL_H
typedef unsigned long long wcs_u64;
long wallet_srd_select(const wcs_u64* eff, int n, wcs_u64 target, wcs_u64 change_cost, int* pick, int pickcap, unsigned long long seed);
long wallet_knapsack_select(const wcs_u64* eff, int n, wcs_u64 target, wcs_u64 min_change, int* pick, int pickcap, unsigned long long seed);
/* waste of a selection: fee_delta[i] = in_fee_now - in_fee_long_term per coin (may be negative);
 * change_cost = cost of creating + later spending the change output, 0 when no change is made */
long long wallet_selection_waste(const wcs_u64* eff, const long long* fee_delta, const int* pick, long npick, wcs_u64 target, wcs_u64 change_cost);
#endif
