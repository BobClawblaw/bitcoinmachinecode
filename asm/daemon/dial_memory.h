/* daemon/dial_memory.h -- what a dial attempt taught us about an address.
 *
 * 2026-09-09, production at the tip: 33 outbound connects an hour, 12 of
 * them hung up by the peer within a minute or two (revents 0x19), 27 refused
 * at the handshake, 100-200 connect timeouts, and one anchor re-dialled
 * forever. A Core-shaped client from a fresh socket got the same treatment
 * from the same peers, so the refusals are theirs -- popular nodes with
 * their inbound slots full accept and evict the newest connection -- and the
 * defect on our side is that nothing remembered it: every rotation offered
 * the same addresses again. Core's addrman keeps nLastTry/nAttempts and does
 * not retry a tried address for a while; this is that memory.
 *
 * A fixed-size table the download worker maps MAP_SHARED before it forks its
 * helpers, so every process that dials consults and updates one copy. Pure:
 * no clock, no I/O -- the caller passes `now` -- so tests pin the schedule.
 *
 * Keys are the address WITHOUT the port (an IPv6 literal keeps its colons):
 * the book can carry one host under two ports and the peer is the same. */
#ifndef BMC_DIAL_MEMORY_H
#define BMC_DIAL_MEMORY_H
#include <stddef.h>
enum { DM_CONNECT_FAIL = 1,   /* connect timed out, refused, unreachable */
       DM_REFUSED      = 2,   /* handshake failed, or hung up within DM_REFUSED_S of connecting */
       DM_EARLY_DROP   = 3,   /* hung up within DM_EARLY_S: an inbound-full node evicting its newest peer */
       DM_NO_WITNESS   = 4 }; /* lacks NODE_WITNESS: permanent for this run */
#define DM_REFUSED_S     5L
#define DM_EARLY_S     180L
#define DM_GOOD_S      600L    /* a leg that lived this long clears the address's streak */
#define DM_BASE_S      600L    /* first backoff: 10 minutes ... */
#define DM_MAX_S     21600L    /* ... doubling to 6 hours */
typedef struct { char host[64]; long long next_ok; long long last; int streak; unsigned char permanent; unsigned char used; } dm_ent_t;
typedef struct { volatile int n; int cap; volatile unsigned long long skips, notes; dm_ent_t e[]; } dm_table_t;
size_t dialmem_bytes(int cap);
void   dialmem_init(void* mem, int cap);
void   dialmem_key(char* out, size_t n, const char* host_port);
/* the backoff after `streak` consecutive failures: 10 min, 20, 40 ... 6 h */
long   dialmem_backoff_s(int streak);
/* 1 = may dial now (unknown, cleared, or the backoff has passed); 0 = wait.
 * A refusal is counted on the table's `skips` so the heartbeat can show it. */
int    dialmem_allowed(dm_table_t* t, const char* host_port, long long now);
/* record a failure; returns the seconds until the address may be dialled
 * again (-1 = permanent). An unknown address takes a free slot, else the
 * slot whose backoff ended longest ago. */
long   dialmem_note_failure(dm_table_t* t, const char* host_port, int kind, long long now);
/* a leg on this address lived DM_GOOD_S: forget its failures */
void   dialmem_note_success(dm_table_t* t, const char* host_port);
int    dialmem_count(const dm_table_t* t);
#endif
