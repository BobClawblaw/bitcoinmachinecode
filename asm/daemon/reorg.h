/* daemon/reorg.h -- Stage B fork choice / chain reorganisation.
 *
 * Public surface of daemon/reorg.c. Split out of the .c only so
 * tests/test_reorg.c can drive the individual phases (analyse / disconnect /
 * reconnect / mempool reconcile) directly instead of only through a socket.
 *
 * THE ONE INVARIANT THIS WHOLE MODULE EXISTS TO PROTECT:
 *   nothing destructive happens until the candidate chain has been fully
 *   validated AND fully downloaded. In order: headers validated (PoW +
 *   internal prevhash linkage) -> fork point located -> candidate proven
 *   strictly heavier by cumulative chainwork -> every replacement block
 *   downloaded and cons_verify'd into a staging file -> undo data proven
 *   sufficient for every height about to be disconnected -> ONLY THEN is
 *   anything unapplied, truncated or overwritten.
 */
#ifndef REORG_H
#define REORG_H

#include <stdint.h>

/* Header pages we are willing to accumulate for one candidate chain. 2048 is
 * ~1 getheaders page plus margin, and far beyond any reorg depth this node
 * will ever act on (see REORG_MAX_DEPTH). */
#define REORG_MAX_HEADERS   2048
/* Hard cap on how many blocks we will ever disconnect automatically. MUST
 * stay <= daemon/utxo_live.c's UTXO_UNDO_WINDOW (200), because a disconnect
 * deeper than the retained undo data physically cannot reconstruct the UTXO
 * set. A candidate that forks deeper than this is refused outright and
 * logged -- that situation is a human's decision, not a daemon's. */
#define REORG_MAX_DEPTH     100
/* Matches daemon/locator_build.c's own LOCATOR_MAX. */
#define REORG_LOCATOR_MAX   32

typedef struct {
    /* ---- candidate headers, in chain order ---- */
    long n;
    unsigned char hdr[REORG_MAX_HEADERS][80];
    unsigned char hash[REORG_MAX_HEADERS][32];   /* block_hash of hdr[i] */

    /* ---- the locator we sent, plus the height each hash came from. The
     * heights are what let us turn "the peer answered from hash X" into
     * "the peer answered from height H" in O(1) with no chain walk. ---- */
    long loc_n;
    unsigned char loc[REORG_LOCATOR_MAX][32];
    long loc_h[REORG_LOCATOR_MAX];

    /* ---- analysis output ---- */
    long base_height;    /* height of hdr[0]'s prevhash in OUR chain (-1 = not ours) */
    long fork_height;    /* last height common to both chains */
    long first_new;      /* index into hdr[] of the first header above fork_height */
    long our_tip;        /* our tip height at analysis time */
    unsigned char our_work[16];    /* cumulative work of OUR tip */
    unsigned char cand_work[16];   /* cumulative work of the candidate tip we know of */
} reorg_cand_t;

/* Block source for the reconnect phase. Returns the block's length in bytes,
 * or -1. `i` is 0-based over the blocks being connected, in chain order. */
typedef long (*reorg_block_src)(void* ctx, long i, unsigned char* out, uint64_t cap);

/* ---- chainwork maintenance (step 2 of the stage brief) ---- */
/* Open chainwork.dat on `st` and load the cumulative-work cache from it.
 * Returns 1 ok / -1. Idempotent-ish: safe to call once per process. */
long reorg_chainwork_open(void* st);
/* Bring chainwork.dat up to the store's current tip, appending one record per
 * missing height by reading that height's 80-byte header and running
 * block_work over its nBits. Returns the number of records appended (>=0), or
 * -1 on error. `max_blocks` <= 0 means "no limit" (used by the one-shot
 * backfill); a positive value bounds the work done in one call so the live
 * loop is never stalled by a huge gap. */
long reorg_chainwork_sync(void* st, long max_blocks);

/* ---- analysis (pure; touches nothing destructive) ---- */
/* Fill c->loc/loc_h/loc_n from our store, via daemon/locator_build.c. */
long reorg_build_locator(void* st, reorg_cand_t* c);
/* Append the headers in one `headers` payload to c. Returns headers added
 * (>=0) or -1 on a malformed payload. */
long reorg_headers_ingest(reorg_cand_t* c, const unsigned char* payload, long plen);
/* Classify the accumulated candidate against our chain.
 *   2  genuine fork AND strictly heavier -> a reorg is warranted
 *   1  genuine fork but NOT heavier      -> ignore (or fetch more headers)
 *   0  no fork (candidate extends us, duplicates us, or is behind us)
 *  -1  candidate REJECTED as invalid/unusable (bad PoW, broken prevhash
 *      linkage, unknown base, or forks deeper than REORG_MAX_DEPTH)
 * On 1/2 it fills fork_height, first_new, our_work and cand_work. */
long reorg_analyze(void* st, reorg_cand_t* c);

/* ---- execution (destructive) ---- */
/* Disconnect everything above fork_height, then connect `nblocks` blocks
 * supplied by `src` in chain order starting at fork_height+1.
 * Returns 1 on a completed reorg, 0 if it refused before touching anything,
 * -1 if it failed PART WAY THROUGH (the loud, must-not-happen case: the log
 * says exactly where). */
long reorg_execute(void* st, long fork_height, long nblocks,
                   reorg_block_src src, void* srcctx);

/* Called after the store has been truncated so the caller can rebuild its own
 * block-hash->height index using whatever construction it originally used.
 * (daemon/main.c and the test harness build that index differently; reorg.c
 * deliberately does not guess.) NULL disables the callback. */
void reorg_set_index_rebuild(void (*cb)(void));

/* Arm the nBits schedule check (Core's bad-diffbits) in reorg_analyze with
 * the selected chain's knobs. INJECTED and default-OFF: the hermetic suites
 * build synthetic chains with arbitrary bits, so only the daemon -- which
 * knows the chain -- arms it (main.c, right after chainparams_select).
 * The rule engine itself is bitcoin_pow_rules.c, shared with the apply path
 * and getblocktemplate. */
void reorg_set_pow_rules(int no_retarget, int allow_min_diff,
                         int enforce_bip94, unsigned int pow_limit_bits);

/* ---- mempool reconciliation (step 7) ---- */
typedef struct {
    void*    mp;         /* bitcoin_mempool.asm object */
    void*    pol;        /* mpol_cfg (bitcoin_mempool_policy.c) */
    void*    pol_state;  /* policy state buffer */
    unsigned pol_n;      /* capacity the state buffer was init'd with */
    void*    utxo_arg;   /* opaque pass-through for mpool_policy_add's `utxo` */
} reorg_mempool_t;

/* Rebuild the mempool against the CURRENT confirmed UTXO set, additionally
 * offering every non-coinbase transaction from the disconnected blocks for
 * re-entry. Returns the number of transactions in the mempool afterwards, or
 * -1 on allocation failure. See the .c for why a full rebuild is used rather
 * than a surgical unregister. */
/* STO-7: register the mempool that reorg_execute should reconcile once a
 * reorg has completed. INJECTED and default-OFF -- the hermetic suites drive
 * reorg_mempool_reconcile themselves and must not have reorg_execute reach
 * into a pool they never built. Pass NULL (or a struct with a NULL .mp) to
 * disarm. The struct is copied. */
void reorg_set_mempool(const reorg_mempool_t* m);

/* STO-7: fork height of the most recently completed reorg, or -1 if none has
 * run in this process. The daemon rewinds its new-block choke-point baseline
 * to this so the replacement blocks -- which may sit at or below the old tip
 * -- are still fed to the mempool's block-connect path. */
long reorg_last_fork_height(void);

long reorg_mempool_reconcile(reorg_mempool_t* m,
                             const unsigned char* const* disc_blocks,
                             const uint32_t* disc_lens, long ndisc);

/* ---- top-level network driver ---- */
/* One fork-detection pass against an already-handshaked peer fd.
 *   1  a reorg was detected, validated and completed
 *   0  nothing to do (no fork, or a fork that is not heavier)
 *  -1  the candidate was rejected, or an error occurred
 * `peer` is only used for logging. */
long reorg_probe_peer(int fd, void* st, const char* peer);

/* -minimumchainwork: the floor a candidate chain must clear. Set once at
 * boot from config or the chain default; all-zero means no floor. */
void reorg_set_min_chain_work(const unsigned char be32[32]);
int  reorg_work_meets_minimum(const unsigned char work[16]);
int  reorg_min_chain_work_set(void);
int  reorg_min_chain_work_unrepresentable(void);

/* -alertnotify: reorg raises an alert, main() decides how to deliver it. */
void reorg_set_alert_fn(void (*fn)(const char*));
void reorg_alert(const char* msg);

#endif /* REORG_H */
