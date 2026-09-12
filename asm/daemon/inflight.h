/* daemon/inflight.h -- one request per block across the outbound legs.
 *
 * 2026-09-09: every leg's sync pass requested the block the node lacked, so a
 * new block at the tip cost eight requests from eight legs, and the compact-
 * block path did eight reconstructions of it. Core requests a block from one
 * peer and tracks it in flight by hash (up to 16 per peer, reassigned after a
 * stall). This table is the shared "who is fetching what": a leg claims a
 * hash before its getdata and every other leg's pass ends on it; the claim
 * dies with the pass (released by the leg) or after INFLIGHT_STALE_S if the
 * pass never returned. Pure; the caller passes the clock. */
#ifndef BMC_INFLIGHT_H
#define BMC_INFLIGHT_H
#define INFLIGHT_MAX 64
#define INFLIGHT_STALE_S 600L
typedef struct { unsigned char hash[32]; int leg; long long since; int used; } inflight_ent_t;
typedef struct { inflight_ent_t e[INFLIGHT_MAX]; unsigned long claims, refused, released; } inflight_t;
void inflight_init(inflight_t* t);
/* 1 = this leg may fetch the block (free, its own, or a stale claim taken over); 0 = another leg has it */
int  inflight_claim(inflight_t* t, const unsigned char hash[32], int leg, long long now);
void inflight_release(inflight_t* t, const unsigned char hash[32]);
void inflight_release_leg(inflight_t* t, int leg);
int  inflight_count(const inflight_t* t);
#endif
