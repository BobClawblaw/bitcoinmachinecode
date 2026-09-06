#include <string.h>
#include "wallet_coinsel.h"
static unsigned long long rng(unsigned long long* s){ *s ^= *s << 13; *s ^= *s >> 7; *s ^= *s << 17; return *s; }
long wallet_srd_select(const wcs_u64* eff, int n, wcs_u64 target, wcs_u64 change_cost, int* pick, int pickcap, unsigned long long seed){
    if (!eff || !pick || n <= 0) return -1;
    if (n > 4096) n = 4096;
    int idx[4096]; for (int i = 0; i < n; i++) idx[i] = i;
    unsigned long long s = seed ? seed : 0x9e3779b97f4a7c15ULL;
    for (int i = n - 1; i > 0; i--){ int j = (int)(rng(&s) % (unsigned long long)(i + 1)); int t = idx[i]; idx[i] = idx[j]; idx[j] = t; }
    wcs_u64 sum = 0; long k = 0;
    for (int i = 0; i < n && k < pickcap; i++){
        if (eff[idx[i]] == 0) continue;
        pick[k++] = idx[i]; sum += eff[idx[i]];
        if (sum >= target + change_cost) return k;            /* Core: SRD always makes change, so it must cover its cost */
    }
    return -1;
}
/* Core ApproximateBestSubset: 1000 passes; in each, walk the coins in
 * (already descending) order, include each with p=1/2 on the first sweep and
 * any not yet included on the second; keep the best (smallest) total >= target. */
static void approx_best(const wcs_u64* v, const int* ord, int n, wcs_u64 target, unsigned char* best_in, wcs_u64* best_total, unsigned long long* s){
    unsigned char inc[4096]; *best_total = (wcs_u64)-1; int found = 0;
    for (int pass = 0; pass < 1000 && *best_total != target; pass++){
        memset(inc, 0, (size_t)n); wcs_u64 total = 0; int reached = 0;
        for (int sweep = 0; sweep < 2 && !reached; sweep++)
            for (int i = 0; i < n; i++){
                int take = sweep == 0 ? (int)(rng(s) & 1) : !inc[i];
                if (!take) continue;
                total += v[ord[i]]; inc[i] = 1;
                if (total >= target){
                    reached = 1;
                    if (total < *best_total){ *best_total = total; memcpy(best_in, inc, (size_t)n); found = 1; }
                    total -= v[ord[i]]; inc[i] = 0;
                }
            }
    }
    if (!found) *best_total = 0;
}
long wallet_knapsack_select(const wcs_u64* eff, int n, wcs_u64 target, wcs_u64 min_change, int* pick, int pickcap, unsigned long long seed){
    if (!eff || !pick || n <= 0) return -1;
    if (n > 4096) n = 4096;
    /* Core KnapsackSolver: coins below target+min_change are "applicable"; the
     * smallest single coin >= target+min_change is the fallback (lowest larger). */
    int ord[4096]; int m = 0; long lowest_larger = -1; wcs_u64 total_lower = 0;
    for (int i = 0; i < n; i++){
        if (eff[i] == target){ pick[0] = i; return 1; }                          /* exact single */
        if (eff[i] < target + min_change){ ord[m++] = i; total_lower += eff[i]; }
        else if (lowest_larger < 0 || eff[i] < eff[lowest_larger]) lowest_larger = i;
    }
    if (total_lower == target){ long k = 0; for (int i = 0; i < m && k < pickcap; i++) pick[k++] = ord[i]; return k; }
    if (total_lower < target){
        if (lowest_larger < 0) return -1;
        pick[0] = (int)lowest_larger; return 1;
    }
    /* sort the applicable set descending, as Core does before the passes */
    for (int i = 1; i < m; i++){ int oi = ord[i]; int j = i - 1; while (j >= 0 && eff[ord[j]] < eff[oi]){ ord[j+1] = ord[j]; j--; } ord[j+1] = oi; }
    unsigned char best[4096]; wcs_u64 best_total; unsigned long long s = seed ? seed : 0x2545f4914f6cdd1dULL;
    approx_best(eff, ord, m, target, best, &best_total, &s);
    if (best_total != target && total_lower >= target + min_change){
        unsigned char best2[4096]; wcs_u64 best_total2; approx_best(eff, ord, m, target + min_change, best2, &best_total2, &s);
        if (best_total2 && best_total2 <= best_total){ memcpy(best, best2, (size_t)m); best_total = best_total2; }
    }
    if (lowest_larger >= 0 && (best_total != target && eff[lowest_larger] <= best_total)){ pick[0] = (int)lowest_larger; return 1; }
    if (!best_total) return -1;
    long k = 0; for (int i = 0; i < m && k < pickcap; i++) if (best[i]) pick[k++] = ord[i];
    return k;
}
long long wallet_selection_waste(const wcs_u64* eff, const long long* fee_delta, const int* pick, long npick, wcs_u64 target, wcs_u64 change_cost){
    long long waste = 0; wcs_u64 sum = 0;
    for (long k = 0; k < npick; k++){ sum += eff[pick[k]]; if (fee_delta) waste += fee_delta[pick[k]]; }
    if (change_cost) waste += (long long)change_cost;                       /* a change output is made */
    else if (sum > target) waste += (long long)(sum - target);              /* no change: the excess is burned as fee */
    return waste;
}
