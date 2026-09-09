/* daemon/dlc_rules.h -- the header phase's chain-selection rule, header-only
 * so main.c's static download code and a test share one definition.
 *
 * 2026-09-09: the parallel downloader took the first peer's header chain that
 * crossed -minimumchainwork. On the bench that peer was stuck on a real
 * 8-block stale branch 4,500 blocks below the tip; the whole branch was
 * downloaded and the run ended on it. Peers announce their heights in the
 * version handshake, so a fetched chain that ends far below what the pool
 * announces is a peer that is behind or stuck, and the fetch should try the
 * next candidate. The announced height is the pool's SECOND-highest claim
 * (one liar cannot move it), and a chain within DLC_HDR_BEHIND_MAX of it is
 * accepted: peers a few blocks apart are normal. */
#ifndef BMC_DLC_RULES_H
#define BMC_DLC_RULES_H
#define DLC_HDR_BEHIND_MAX 144L
/* the pool's announced height: the second-highest of n claims (the highest
 * alone could be one peer lying), or the only one when there is one */
static inline long dlc_announced_height(const long* hs, int n){
    long top = 0, second = 0;
    for (int i = 0; i < n; i++){
        if (hs[i] <= 0) continue;
        if (hs[i] > top){ second = top; top = hs[i]; } else if (hs[i] > second) second = hs[i];
    }
    return second > 0 ? second : top;
}
/* does a header chain ending at chain_tip fall short of what the pool announces? */
static inline int dlc_chain_falls_short(long chain_tip, long announced){
    return announced > 0 && chain_tip + DLC_HDR_BEHIND_MAX < announced;
}
#endif
