/* daemon/tip_watch.h -- the tip has stopped while the legs announce blocks
 * (2026-11-07).
 *
 * WHY. The systemd watchdog (sd_watchdog.c) is fed while the worker's loop
 * turns. The Mac mainnet node's stall of 2026-11-06 kept it turning: every
 * pass helper failed to start (EMFILE), announcements kept arriving and being
 * logged, the heartbeat and the tx relay ran on, and nothing fetched a block
 * for ten hours. #484 ends the worker for that one cause. This ends it for any
 * cause, from the outside view: the network says there is a new block and the
 * tip does not move.
 *
 * THE RULE. A block hash announced on a leg (leg_on_block_announce: not
 * stored, not a repeat on that leg, not in the invalid set) is recorded with
 * the set of legs that announced it. Once TIPW_QUORUM distinct legs have, it
 * counts. If the tip has not changed TIPW_WARN_MS after the oldest counted
 * hash reached its quorum, one warning; after TIPW_FATAL_MS the worker ends
 * and the unit restarts. Any change of the tip clears the record.
 *
 * WHY 3 LEGS AND 30 MINUTES. Production's log, 2026-10-05 .. 11-07 (1,957
 * tip advances that followed a 3-leg announcement): the tip moved a median
 * 1 s after the third leg announced, p99 437 s, max 610 s -- apart from the
 * two real stalls (10-19, the 15-hour ZMQ loop; 10-30, the memory
 * throttle). One leg alone is noise: a peer re-announced by inv, for an hour,
 * a block that was never stored (11-06 22:39-23:53Z) while the real ones came
 * from 16 legs at once. 30 minutes is three times the slowest healthy case.
 *
 * NOT A STALL. A block we refused (connect failure or invalidateblock adds it
 * to the invalid set) leaves the tip where it is and its descendants
 * announced, and a restart would change nothing; Core stays put too. So the
 * watch stands down for the episode when the invalid set grew since the tip
 * last moved, and drops counted hashes that are in it. A halted UTXO set
 * (utxo_live_halted) is the caller's to skip.
 *
 * Pure: no clock, no I/O. tests/test_tip_watch.c drives it directly. */
#ifndef TIP_WATCH_H
#define TIP_WATCH_H
#include <string.h>

#define TIPW_SLOTS    16
#define TIPW_QUORUM   3
#define TIPW_WARN_MS  (15LL * 60 * 1000)
#define TIPW_FATAL_MS (30LL * 60 * 1000)

typedef struct {
    long tip;                              /* the tip this episode started at */
    int have_tip;
    long invalid_n;                        /* the invalid set's size then */
    int n;
    unsigned char hash[TIPW_SLOTS][32];
    unsigned long long legs[TIPW_SLOTS];   /* bit k = leg k announced it */
    long long quorum_ms[TIPW_SLOTS];       /* when it reached TIPW_QUORUM legs; 0 = not yet */
    int warned;
} tipw_t;

enum { TIPW_OK = 0, TIPW_WARN = 1, TIPW_FATAL = 2, TIPW_RECOVERED = 3, TIPW_REFUSED = 4 };

static inline int tipw_legs(unsigned long long m){ return __builtin_popcountll(m); }

static inline void tipw_drop(tipw_t* w, int i){
    w->n--;
    if (i != w->n){
        memcpy(w->hash[i], w->hash[w->n], 32);
        w->legs[i] = w->legs[w->n]; w->quorum_ms[i] = w->quorum_ms[w->n];
    }
}

/* a novel block announced on leg k (0..63) */
static inline void tipw_announce(tipw_t* w, const unsigned char h[32], int leg, long long now_ms){
    if (leg < 0 || leg >= 64) return;
    int i;
    for (i = 0; i < w->n; i++) if (!memcmp(w->hash[i], h, 32)) break;
    if (i == w->n){
        if (w->n == TIPW_SLOTS){
            /* full: the hash on the fewest legs that has not counted yet
             * makes room (a lone peer's junk), never a counted one */
            int v = -1;
            for (int j = 0; j < w->n; j++)
                if (!w->quorum_ms[j] && (v < 0 || tipw_legs(w->legs[j]) < tipw_legs(w->legs[v]))) v = j;
            if (v < 0) return;
            tipw_drop(w, v);
            i = w->n;
        }
        memcpy(w->hash[i], h, 32); w->legs[i] = 0; w->quorum_ms[i] = 0; w->n++;
    }
    w->legs[i] |= 1ULL << leg;
    if (!w->quorum_ms[i] && tipw_legs(w->legs[i]) >= TIPW_QUORUM) w->quorum_ms[i] = now_ms > 0 ? now_ms : 1;
}

/* Once per rotation. tip: the public tip now; invalid_n: the invalid set's
 * size now; invalid(h): 1 if h is in it (may be NULL). Out: *age_ms, how long
 * the oldest counted hash has waited (for TIPW_RECOVERED: how long the
 * episode lasted); *legs_out, how many legs announced it.
 * -> TIPW_WARN once per episode, TIPW_FATAL while it lasts past the limit,
 *    TIPW_RECOVERED when the tip moves after a warning, TIPW_REFUSED once
 *    when a refused block explains the stall, else TIPW_OK. */
static inline int tipw_check(tipw_t* w, long tip, long long now_ms, long invalid_n,
                             int (*invalid)(const unsigned char[32]),
                             long long* age_ms, int* legs_out){
    long long oldest = 0; int legs = 0;
    for (int i = 0; i < w->n; i++)
        if (w->quorum_ms[i] && (!oldest || w->quorum_ms[i] < oldest)){ oldest = w->quorum_ms[i]; legs = tipw_legs(w->legs[i]); }
    if (!w->have_tip || tip != w->tip){
        int r = (w->have_tip && w->warned == 1) ? TIPW_RECOVERED : TIPW_OK;
        if (age_ms) *age_ms = oldest ? now_ms - oldest : 0;
        if (legs_out) *legs_out = legs;
        w->tip = tip; w->have_tip = 1; w->invalid_n = invalid_n; w->n = 0; w->warned = 0;
        return r;
    }
    if (invalid_n != w->invalid_n){
        /* we refused a block since the tip last moved: a restart would not
         * change that. Stand down until the tip moves. */
        w->n = 0;
        if (w->warned == 2) return TIPW_OK;
        w->warned = 2;
        return TIPW_REFUSED;
    }
    if (w->warned == 2) return TIPW_OK;
    oldest = 0; legs = 0;
    for (int i = 0; i < w->n;){
        if (invalid && invalid(w->hash[i])){ tipw_drop(w, i); continue; }
        if (w->quorum_ms[i] && (!oldest || w->quorum_ms[i] < oldest)){ oldest = w->quorum_ms[i]; legs = tipw_legs(w->legs[i]); }
        i++;
    }
    if (age_ms) *age_ms = oldest ? now_ms - oldest : 0;
    if (legs_out) *legs_out = legs;
    if (!oldest) return TIPW_OK;
    long long age = now_ms - oldest;
    if (age >= TIPW_FATAL_MS) return TIPW_FATAL;
    if (age >= TIPW_WARN_MS && !w->warned){ w->warned = 1; return TIPW_WARN; }
    return TIPW_OK;
}
#endif
