/* daemon/dlc_rules.h -- the header phase's chain-selection rule, header-only
 * so main.c's static download code and a test share one definition.
 *
 * 2026-09-09: the parallel downloader took the first peer's header chain that
 * crossed -minimumchainwork. On the bench that peer was stuck on a real
 * 8-block stale branch 4,500 blocks below the tip; the whole branch was
 * downloaded and the run ended on it. Peers announce their heights in the
 * version handshake, so a fetched chain that ends far below what the pool
 * announces is a peer that is behind or stuck, and the fetch should try the
 * next candidate. The announced height is the MEDIAN of the pool's claims
 * (a few liars cannot move it), and a chain within DLC_HDR_BEHIND_MAX of it
 * is accepted: peers a few blocks apart are normal. */
#ifndef BMC_DLC_RULES_H
#define BMC_DLC_RULES_H
#include <stdlib.h>
#define DLC_HDR_BEHIND_MAX 144L
/* the pool's announced height: the MEDIAN of the positive claims (the lower
 * median for an even count). 2026-09-09 11:48Z, run 19: the rule was the
 * second-highest claim, "one liar cannot move it" -- and TWO peers claimed
 * 970,195 against a real tip of 966,200, so every honest chain fell short and
 * eight candidates were refused, a minute each. A median needs a lying
 * majority to move; honest peers a few blocks behind pull it down by at most
 * a few blocks, well inside DLC_HDR_BEHIND_MAX. */
static int dlc_cmp_long(const void* a, const void* b){
    long x = *(const long*)a, y = *(const long*)b; return x < y ? -1 : x > y;
}
static inline long dlc_announced_height(const long* hs, int n){
    long* v = (long*)malloc((size_t)(n > 0 ? n : 1) * sizeof(long));
    if (!v) return 0;
    int k = 0;
    for (int i = 0; i < n; i++) if (hs[i] > 0) v[k++] = hs[i];
    long r = 0;
    if (k > 0){ qsort(v, (size_t)k, sizeof(long), dlc_cmp_long); r = v[(k - 1) / 2]; }
    free(v);
    return r;
}
/* does a header chain ending at chain_tip fall short of what the pool announces? */
static inline int dlc_chain_falls_short(long chain_tip, long announced){
    return announced > 0 && chain_tip + DLC_HDR_BEHIND_MAX < announced;
}
#endif
