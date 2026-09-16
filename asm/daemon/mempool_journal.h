/* daemon/mempool_journal.h -- the mempool departure journal's API.
 * Record layout and the reason codes live in mempool_journal_fmt.h. */
#ifndef MEMPOOL_JOURNAL_H
#define MEMPOOL_JOURNAL_H

#include <stdint.h>
#include "mempool_journal_fmt.h"

typedef struct {
    uint64_t capacity;          /* records the ring holds                     */
    uint64_t written;           /* departures ever recorded (monotonic)       */
    uint64_t held;              /* records still readable (min(written, cap)) */
    int64_t  oldest_departed;   /* unix seconds of the oldest held record     */
    int64_t  newest_departed;
    uint64_t by_reason[MPJ_REASON_MAX + 1];   /* indexed by MPJ_*             */
} mpj_stats_t;

/* Open (creating it at `capacity` records if absent) or adopt an existing
 * ring's capacity. Returns 1 on success, 0 if the journal stays disabled --
 * a refusal is never fatal: the node runs exactly as before without it. */
int  mpj_open(const char* path, uint64_t capacity);
void mpj_close(void);
int  mpj_is_open(void);
uint64_t mpj_capacity(void);
uint64_t mpj_next_seq(void);

/* Record one departure. A no-op when the journal is closed or the reason is
 * not an MPJ_* value, so callers never need to test first. */
void mpj_append(const mpj_rec* r);

/* Newest first. `cb` returning 0 stops the walk. Returns records delivered. */
long mpj_recent(long want, int (*cb)(void*, const mpj_rec*), void* ctx);

/* The most recent departure of `txid`, if the ring still holds one. */
int  mpj_lookup(const unsigned char txid[32], mpj_rec* out);

void mpj_stats(mpj_stats_t* st);

#endif
