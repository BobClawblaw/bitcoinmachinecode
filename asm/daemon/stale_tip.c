#include "stale_tip.h"
/* Pure so the rule is testable without a node. `enabled` is the feature
 * switch the negative control flips. IBD proxy: our tip trails the best
 * header we have seen by more than one block. */
int stale_tip_extra_outbound(long now, long tip_time, long tip_height, long best_header, int enabled){
    if (!enabled) return 0;
    if (tip_time <= 0) return 0;
    if (best_header >= 0 && tip_height < best_header - 1) return 0;   /* catching up: not stale, just behind */
    return (now - tip_time) > STALE_TIP_SECS ? 1 : 0;
}
