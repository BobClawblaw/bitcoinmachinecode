/* CC-6: Core CheckForStaleTipAndEvictPeers -> m_try_another_outbound_peer.
 * When the tip is older than STALE_TIP_SECS and we are NOT in initial block
 * download, want one extra full-relay outbound so a partition is noticed. */
#ifndef STALE_TIP_H
#define STALE_TIP_H
#define STALE_TIP_SECS (30L*60L)   /* Core: 3 x the 10-minute block interval */
int stale_tip_extra_outbound(long now, long tip_time, long tip_height, long best_header, int enabled);
#endif
