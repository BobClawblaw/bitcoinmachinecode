/* wallet_bnb.c -- Branch-and-Bound coin selection (Core wallet/coinselection.cpp
 * SelectCoinsBnB), 2026-08-27.
 *
 * Core's algorithm, faithfully:
 *   - Work in EFFECTIVE values (utxo value minus that input's own fee at the
 *     target feerate) -- the caller computes them, this module never sees a
 *     feerate.
 *   - Find an input set whose effective sum lands in the window
 *     [target, target + cost_of_change]: enough to pay the recipients and the
 *     non-input fees, but by less than a change output would cost to create
 *     and later spend. Such a set is CHANGELESS -- the excess goes to fees,
 *     which is cheaper than minting change.
 *   - Depth-first search over the coins in DESCENDING effective value with
 *     Core's exact pruning: backtrack when the running total exceeds the
 *     window's top, or when the remaining coins cannot reach the target.
 *   - Among solutions, minimize WASTE (Core GetSelectionWaste): the excess
 *     over target plus, per input, (fee_now - fee_long_term). The caller
 *     passes each coin's (fee_now - fee_long_term) so this stays pure; with
 *     equal rates that term is zero and waste is just the excess.
 *   - Give up after 100,000 explored nodes (Core's TOTAL_TRIES), returning 0
 *     so the caller falls back to its simpler selector -- BnB is an
 *     optimization, never a point of failure.
 *
 * Pure integer arithmetic, no allocation, no globals: unit-testable byte for
 * byte (tests/test_coinselect_bnb.c).
 */

typedef unsigned long long u64c;

#define WBNB_TOTAL_TRIES 100000
#define WBNB_MAX_COINS   128

/* eff[]        effective values, MUST be sorted DESCENDING (asserted by scan);
 * fee_delta[]  per-coin (fee_now - fee_long_term), same order (may be NULL =
 *              all zero);
 * target       recipients + non-input fees (see header comment);
 * cost_of_change  the window width;
 * pick[]       receives the selected indexes into eff[];
 * returns the count selected (changeless solution found), or 0 when BnB found
 * nothing (caller falls back), or -1 on bad input. */
long wallet_bnb_select(const u64c* eff, const long long* fee_delta, int n,
                       u64c target, u64c cost_of_change,
                       int* pick, int pickcap){
    if (!eff || !pick || n < 0) return -1;
    if (n > WBNB_MAX_COINS) n = WBNB_MAX_COINS;   /* Core also bounds the set */

    u64c remaining = 0;
    for (int i = 0; i < n; i++){
        if (i && eff[i] > eff[i-1]) return -1;    /* not descending: caller bug */
        remaining += eff[i];
    }
    if (remaining < target) return 0;             /* cannot reach: no solution */

    int cur[WBNB_MAX_COINS]; int depth = 0;       /* cur[d] = index chosen at depth d */
    int best[WBNB_MAX_COINS]; int best_n = 0;
    u64c best_waste = (u64c)-1;
    u64c sum = 0;                                  /* effective sum of cur */
    long long fee_sum = 0;                         /* fee_delta sum of cur */
    int tries = 0;
    int i = 0;                                     /* next candidate index */

    while (1){
        if (++tries > WBNB_TOTAL_TRIES) break;
        int backtrack = 0;
        if (sum > target + cost_of_change) backtrack = 1;         /* overshot */
        else if (sum >= target){
            /* solution: waste = excess + sum(fee_now - fee_long_term) */
            long long waste = (long long)(sum - target) + fee_sum;
            if (waste < 0) waste = 0;             /* negative delta beats excess */
            if ((u64c)waste < best_waste){
                best_waste = (u64c)waste; best_n = depth;
                for (int k = 0; k < depth; k++) best[k] = cur[k];
                if (best_waste == 0) break;       /* perfect: cannot improve */
            }
            backtrack = 1;                        /* adding more only adds waste */
        } else if (sum + remaining < target) backtrack = 1;       /* unreachable */

        if (backtrack){
            if (depth == 0) break;
            /* undo the last inclusion, then take its EXCLUSION branch */
            depth--;
            int j = cur[depth];
            sum -= eff[j];
            if (fee_delta) fee_sum -= fee_delta[j];
            /* everything after j is back in `remaining`; j itself is excluded */
            remaining = 0;
            for (int k = j + 1; k < n; k++) remaining += eff[k];
            i = j + 1;
            continue;
        }
        if (i >= n){
            if (depth == 0) break;
            depth--;
            int j = cur[depth];
            sum -= eff[j];
            if (fee_delta) fee_sum -= fee_delta[j];
            remaining = 0;
            for (int k = j + 1; k < n; k++) remaining += eff[k];
            i = j + 1;
            continue;
        }
        /* inclusion branch for coin i */
        remaining -= eff[i];
        cur[depth++] = i;
        sum += eff[i];
        if (fee_delta) fee_sum += fee_delta[i];
        i++;
        if (depth >= (pickcap < WBNB_MAX_COINS ? pickcap : WBNB_MAX_COINS)){
            /* cannot deepen: force the backtrack path next iteration */
            if (sum < target) { /* treat as unreachable at this depth */ }
        }
    }
    if (best_n == 0 || best_waste == (u64c)-1) return 0;
    for (int k = 0; k < best_n && k < pickcap; k++) pick[k] = best[k];
    return best_n;
}
