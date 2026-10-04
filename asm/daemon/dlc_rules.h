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
/* ---- Core's download shape (2026-09-10) ----------------------------------
 * Core: every usable peer downloads, up to 16 blocks in flight each; blocks
 * are requested only inside a 1,024-block window above the CONNECTED tip;
 * assignment follows completion; the one judge of slowness is the window's
 * tail -- the peer holding the oldest missing block while the window is
 * full has 2 s (doubling to 64 s when evictions come fast, easing back as
 * blocks land) before it is dropped. Ours had 16 workers of a fixed count
 * against 124 live peers, a window from the download's own frontier, an
 * EMA ranking and a rate floor. The rules below are the pure parts. */
#define DLC_WORKERS_HARD_MAX 64
#define DLC_BLOCK_DOWNLOAD_WINDOW 1024L    /* Core: BLOCK_DOWNLOAD_WINDOW, above the connected tip (2026-09-29) */
#define DLC_STALL_TIMEOUT_MIN_S 2L         /* BLOCK_STALLING_TIMEOUT_DEFAULT */
#define DLC_STALL_TIMEOUT_MAX_S 64L        /* BLOCK_STALLING_TIMEOUT_MAX */
/* every live peer downloads, up to the operator's cap and the arrays' 64 --
 * and no more than the span has chunks (2026-09-10, row 3: a reorg handoff
 * of forty blocks forked 64 helpers for one chunk) */
static inline int dlc_workers_for(int nlive, int cap, long span_blocks, long chunk){
    int n = nlive < cap ? nlive : cap;
    if (chunk < 1) chunk = 1;
    long chunks = (span_blocks + chunk - 1) / chunk;
    if (chunks >= 1 && n > chunks) n = (int)chunks;
    if (n < 1) n = 1;
    if (n > DLC_WORKERS_HARD_MAX) n = DLC_WORKERS_HARD_MAX;
    return n;
}
/* Core's window: 1,024 blocks above the connected tip, whatever the peer
 * count (2026-09-29; it was six times the claimed chunks, never under 4,096,
 * and run 30's download sat at that window's edge for the whole sync -- the
 * apply was the pace, and a 4,096 runway against Core's 1,024 was a setting
 * the A/B did not share). Never smaller than what the workers claim at once
 * (nw x chunk), or they could not all hold a chunk. */
static inline long dlc_window_blocks(int nw, long chunk){
    long claimed = (long)nw * chunk;
    return claimed > DLC_BLOCK_DOWNLOAD_WINDOW ? claimed : DLC_BLOCK_DOWNLOAD_WINDOW;
}
/* Cursor help (the committer asks a worker to fetch the chunk the apply is
 * waiting on) needs the pool to have moved on without that chunk: enough
 * chunks staged above the cursor. It was a fixed 32, which the window caps
 * at window/chunk -- 25 at 1,024 and 40 -- so from 2026-09-29 (the window
 * went to Core's 1,024) until 2026-09-30 it could never fire. A third of
 * the chunks the window holds, never under 2. */
static inline long dlc_cursor_help_min_staged(long window, long chunk){
    if (chunk < 1) chunk = 1;
    long t = window / chunk / 3;
    return t < 2 ? 2 : t;
}
/* the window is anchored to the CONNECTED tip when the engine is in this
 * process (applied_plus1 >= 0), else to the archive's first hole */
static inline long dlc_window_anchor(long applied_plus1, long first_hole){
    return applied_plus1 >= 0 && applied_plus1 < first_hole ? applied_plus1 : first_hole;
}
static inline int dlc_window_allows(long lo, long anchor, long window){ return lo - anchor <= window; }
/* the adaptive stall timeout: doubles on an eviction, eases 15% when the tail moves */
static inline long dlc_stall_timeout_after(long cur_s, int evicted){
    if (evicted){ long n = cur_s * 2; return n > DLC_STALL_TIMEOUT_MAX_S ? DLC_STALL_TIMEOUT_MAX_S : n; }
    long n = (cur_s * 85) / 100;
    return n < DLC_STALL_TIMEOUT_MIN_S ? DLC_STALL_TIMEOUT_MIN_S : n;
}
/* the holder of the oldest missing chunk is a staller only while the window is full */
static inline int dlc_tail_stalled(int window_full, long tail_age_ms, long timeout_s){
    return window_full && tail_age_ms >= timeout_s * 1000;
}
/* the stall clock restarts on every block the holder delivers. Core clears
 * m_stalling_since in RemoveBlockRequest, so its 2 s is a gap BETWEEN
 * blocks, not a budget for everything in flight. Ours timed the whole
 * 40-block chunk from the moment it became the tail (2026-09-24, m5ultra
 * at h=823,243): ~60 MB of recent blocks against 2-8 s, so a peer sending
 * 855 KB/s was dropped with "0 block(s)" and banned, three in a row, and
 * the tail never landed. */
static inline long long dlc_stall_clock(long long since_ms, long long last_block_ms){
    return last_block_ms > since_ms ? last_block_ms : since_ms;
}
/* a peer is replaced (rotation, the rate floor) only when a replacement exists;
 * otherwise the window's tail is the only judge, as in Core */
static inline int dlc_replace_allowed(int free_peers){ return free_peers > 0; }
/* bmc.dlshape=core (2026-10-04): Core's block download timeout. A peer whose
 * front in-flight block is older than BLOCK_DOWNLOAD_TIMEOUT_BASE (1) +
 * BLOCK_DOWNLOAD_TIMEOUT_PER_PEER (0.5) x the other peers downloading, in
 * units of the 600 s target spacing, is disconnected (net_processing.cpp:
 * 148-150, 6113-6122). With Core's 10 download peers: 600 x 5.5 = 3,300 s. */
static inline long dlc_core_block_timeout_s(int download_peers){
    int others = download_peers > 1 ? download_peers - 1 : 0;
    return (long)(600.0 * (1.0 + 0.5 * (double)others));
}
#endif
