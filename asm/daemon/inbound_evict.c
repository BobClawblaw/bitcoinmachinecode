#include <string.h>
#include "inbound_evict.h"
#include "netperm.h"
/* Core net.cpp SelectNodeToEvict, transcribed. Rounds, in order:
 *   1. protect the 4 with the lowest min ping           (ours: unmeasured, protects none)
 *   2. protect the 8 that most recently sent us a tx we accepted
 *   3. protect the 4 that most recently sent us a novel block
 *   4. protect half of the remainder by longest connection time
 *   5. of what is left, take the network group with the most members and
 *      evict its YOUNGEST connection (ties: the later slot)
 * Core additionally spreads round 4 across onion/localhost/i2p/cjdns so a
 * network with few peers keeps some; net_group already separates those
 * (NET-10 hashes them with the top bit set), which is what the grouping in
 * round 5 relies on. */
#define MAXC RPC_MAX_PEERS
typedef struct { int slot; long long conn, tx, blk, ping; unsigned grp; } cand_t;

static int protect_top(cand_t* c, int n, int k, long long (*key)(const cand_t*), int lowest_wins){
    /* mark the k best by key as protected (slot = -1); returns how many were marked */
    int marked = 0;
    for (int r = 0; r < k; r++){
        int best = -1;
        for (int i = 0; i < n; i++){
            if (c[i].slot < 0) continue;
            long long v = key(&c[i]);
            if (v == 0 && !lowest_wins) continue;                 /* "never" is not recent */
            if (best < 0 || (lowest_wins ? v < key(&c[best]) : v > key(&c[best]))) best = i;
        }
        if (best < 0) break;
        c[best].slot = -1; marked++;
    }
    return marked;
}
static long long k_tx  (const cand_t* c){ return c->tx; }
static long long k_blk (const cand_t* c){ return c->blk; }
static long long k_old (const cand_t* c){ return c->conn; }        /* longest connected = smallest conn_time (lowest wins) */

int inbound_select_victim(const node_status_t* st, long long now, int first_slot, int last_slot){
    (void)now;
    if (!st) return -1;
    cand_t c[MAXC]; int n = 0;
    for (int i = first_slot; i <= last_slot && i < MAXC; i++){
        const rpc_peer_t* q = &st->peers[i];
        if (!q->used || !q->inbound) continue;
        if (q->perms & NP_NOBAN) continue;                        /* never evict a NoBan peer */
        if (q->evict_requested) continue;                         /* already going */
        c[n].slot = i; c[n].conn = q->conn_time; c[n].tx = q->last_tx_time; c[n].blk = q->last_block_time;
        c[n].ping = q->min_ping_us > 0 ? q->min_ping_us : 0; c[n].grp = q->net_group; n++;
    }
    if (n == 0) return -1;
    /* round 1: lowest ping (only measured ones can win: ping 0 is skipped by the !lowest path... handle explicitly) */
    { cand_t* pc = c; int measured = 0; for (int i = 0; i < n; i++) if (pc[i].ping > 0) measured++;
      if (measured) { /* protect up to 4 lowest among measured */
          for (int r = 0; r < 4; r++){ int best = -1; for (int i = 0; i < n; i++){ if (c[i].slot < 0 || c[i].ping <= 0) continue; if (best < 0 || c[i].ping < c[best].ping) best = i; } if (best < 0) break; c[best].slot = -1; } } }
    protect_top(c, n, 8, k_tx, 0);                                /* round 2 */
    protect_top(c, n, 4, k_blk, 0);                               /* round 3 */
    { int left = 0; for (int i = 0; i < n; i++) if (c[i].slot >= 0) left++;
      protect_top(c, n, left / 2, k_old, 1); }                    /* round 4: half, longest connected */
    /* round 5: most populated group, evict its youngest */
    unsigned best_grp = 0; int best_cnt = 0; long long best_young = 0;
    for (int i = 0; i < n; i++){
        if (c[i].slot < 0) continue;
        int cnt = 0; long long young = 0;
        for (int j = 0; j < n; j++) if (c[j].slot >= 0 && c[j].grp == c[i].grp){ cnt++; if (c[j].conn > young) young = c[j].conn; }
        if (cnt > best_cnt || (cnt == best_cnt && young > best_young)){ best_cnt = cnt; best_grp = c[i].grp; best_young = young; }
    }
    if (best_cnt == 0) return -1;
    int victim = -1; long long vconn = -1;
    for (int i = 0; i < n; i++)
        if (c[i].slot >= 0 && c[i].grp == best_grp && c[i].conn >= vconn){ vconn = c[i].conn; victim = c[i].slot; }
    return victim;
}
