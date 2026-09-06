/* daemon/hdr_lowwork.h -- CC-5 (2026-09-06): do not commit a headers chain to
 * the header store until it carries enough work.
 *
 * Core (24.0 "headers presync"): while the chain a peer is feeding us has
 * total work below nMinimumChainWork and the batches keep coming full, the
 * headers are not stored -- only commitments -- so a peer feeding a long
 * valid-PoW low-work chain costs us nothing. This node's boot header fetch
 * appended every PoW-valid header regardless of cumulative work; the
 * minimum-chain-work floor was only consulted at reorg time.
 *
 * Stage 1, this module: a bounded HOLD. Full pages (2000 headers) whose
 * running cumulative work is still below the floor are held in a small
 * scratch instead of appended; when the chain crosses the floor the held
 * pages are released in order; a chain that stays below the floor for more
 * than LOWWORK_HOLD_PAGES full pages is abandoned. A short (non-full) page is
 * appended as Core does: it is the last of its chain, so it is bounded. */
#ifndef HDR_LOWWORK_H
#define HDR_LOWWORK_H
#define LOWWORK_PAGE_MAX   2000
#define LOWWORK_HOLD_PAGES 4
enum { LOWWORK_APPEND = 1, LOWWORK_HOLD = 2, LOWWORK_RELEASE = 3, LOWWORK_ABANDON = 4 };
typedef struct {
    int armed;                       /* a floor is configured (mainnet); 0 = pass-through */
    unsigned char cum[16];           /* cumulative work of the chain so far (fork point + pages seen) */
    int held;                        /* pages in the hold */
    unsigned long held_cnt[LOWWORK_HOLD_PAGES];
    long held_pos[LOWWORK_HOLD_PAGES];
    unsigned char held_prev[LOWWORK_HOLD_PAGES][32];   /* hash of the header before each held page */
    unsigned char tail_hash[32]; long tail_height;        /* last held header: the next getheaders starts here */
    unsigned char hold[LOWWORK_HOLD_PAGES][LOWWORK_PAGE_MAX * 81];
} lowwork_t;
/* cumulative work of headers [0, upto] from a header store, via the caller's accessor (asm hst_get_at shape) */
void lowwork_cum_from_store(unsigned char out[16], void* hst, long upto, int (*get_at)(void*, unsigned long long, void*));
void lowwork_begin(lowwork_t* l, const unsigned char cum_at_fork[16], int armed);
/* One page of `cnt` 81-byte headers starting at height `pos`. Adds their work
 * to the running total and says what to do with the page:
 *   APPEND  -- append this page now (nothing held)
 *   HOLD    -- page copied into the hold; append nothing
 *   RELEASE -- the chain crossed the floor: append the held pages (lowwork_held) in order, then this page
 *   ABANDON -- too many full low-work pages: discard everything, drop the peer */
int  lowwork_page(lowwork_t* l, const unsigned char* hdrs, unsigned long cnt, long pos, const unsigned char prev[32], const unsigned char last_hash[32]);
int  lowwork_held(const lowwork_t* l, int i, const unsigned char** hdrs, unsigned long* cnt, long* pos, const unsigned char** prev);
int  lowwork_tail(const lowwork_t* l, unsigned char hash[32], long* height);   /* 1 if pages are held */
void lowwork_clear(lowwork_t* l);
/* test seam: the floor check (defaults to minchainwork.c's reorg_work_meets_minimum) */
void lowwork_set_floor_fn(int (*fn)(const unsigned char work[16]));
#endif
