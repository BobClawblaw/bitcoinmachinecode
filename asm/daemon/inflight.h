/* daemon/inflight.h -- one request per block across the outbound legs.
 *
 * 2026-09-09: every leg's sync pass requested the block the node lacked, so a
 * new block at the tip cost eight requests from eight legs, and the compact-
 * block path did eight reconstructions of it. Core requests a block from one
 * peer and tracks it in flight by hash (up to 16 per peer, reassigned after a
 * stall). This table is the shared "who is fetching what": a leg claims a
 * hash before its getdata and every other leg's pass ends on it; the claim
 * dies with the pass (released by the leg) or after INFLIGHT_STALE_S if the
 * pass never returned. The caller passes the clock.
 *
 * 2026-11-07: SHARED ACROSS PROCESSES, and a stored block is remembered.
 * Since 2026-09-10 each leg's pass runs in a forked helper, and the helper's
 * claims went into its own copy-on-write copy of this table: no sibling pass
 * ever saw them, so the one-request rule held only for the claim the worker
 * takes itself (an announced block, at the pass's launch). Production's log
 * of 2026-11-06 12:12-23:10Z: of 58 compact blocks, 4 were reconstructed by
 * passes on 2 to 7 legs -- 14,878 KB of getblocktxn for blocks already
 * fetched, against 1,345 KB for the first reconstructions. Most of it came
 * AFTER a sibling had stored the block: its transactions had left the
 * mempool by then, so each late pass fetched all of them (1,692 KB each for
 * one 2,900-tx block, six times). The table now lives in a MAP_SHARED
 * mapping the worker creates before any pass forks (inflight_shared), behind
 * a lock any of the processes can take, and a pass that STORES a block marks
 * its hash (inflight_mark_stored), so a sibling that forked before the store
 * -- whose own index of stored blocks is a stale copy -- is refused the
 * fetch for INFLIGHT_DONE_S. */
#ifndef BMC_INFLIGHT_H
#define BMC_INFLIGHT_H
#define INFLIGHT_MAX 64
#define INFLIGHT_STALE_S 600L
/* how long a stored mark refuses the hash: longer than a pass can run (its
 * 60 s budget plus the parent's 15 s grace), so every pass that forked
 * before the store has ended, and the worker's own index has the block, by
 * the time the mark lapses */
#define INFLIGHT_DONE_S 120L
typedef struct { unsigned char hash[32]; int leg; long long since; int used; int stored; } inflight_ent_t;
typedef struct {
    inflight_ent_t e[INFLIGHT_MAX];
    unsigned long claims, refused, released, refused_stored;
    int lock;                     /* 0 free, else the holder's pid */
} inflight_t;
void inflight_init(inflight_t* t);
/* a zeroed table in a MAP_SHARED anonymous mapping, inherited by every child
 * forked after it; NULL if the mapping fails (the caller keeps its own) */
inflight_t* inflight_shared(void);
/* 1 = this leg may fetch the block (free, its own, or a stale claim taken
 * over); 0 = another leg has it, or it was stored under INFLIGHT_DONE_S ago */
int  inflight_claim(inflight_t* t, const unsigned char hash[32], int leg, long long now);
/* the same answer without claiming (the rotation picks an announced leg with it
 * and claims only when that leg's pass actually starts) */
int  inflight_would_allow(const inflight_t* t, const unsigned char hash[32], int leg, long long now);
/* the block is stored: whoever claimed it is done, and every fetch of it is
 * refused until INFLIGHT_DONE_S has passed */
void inflight_mark_stored(inflight_t* t, const unsigned char hash[32], long long now);
/* a rewind: the store may no longer hold a block marked stored */
void inflight_forget_stored(inflight_t* t);
void inflight_release(inflight_t* t, const unsigned char hash[32]);
void inflight_release_leg(inflight_t* t, int leg);
/* claims in flight (stored marks are not counted) */
int  inflight_count(const inflight_t* t);
#endif
