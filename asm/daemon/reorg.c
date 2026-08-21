/* daemon/reorg.c -- Stage B: fork detection, fork-point location, block
 * disconnect, block reconnect, and mempool reconciliation. Plain C glue over
 * the Stage A assembly primitives (bitcoin_chainwork.asm's block_work /
 * chainwork_add / chainwork_cmp / store_chainwork_*, bitcoin_store.asm's
 * store_validates_prevhash / store_truncate_to, daemon/locator_build.c's
 * locator_build, daemon/undo_log.c's undo data) plus the pre-existing
 * cons_verify / block_hash / pow_check / tx_parse / mpool_* machinery.
 *
 * ===========================================================================
 * ORDER OF OPERATIONS -- this is the safety property of the whole stage.
 *
 * This module can delete real blocks and rewrite a real UTXO set. Every
 * expensive, fallible or attacker-influenced step therefore happens BEFORE
 * the first destructive one, and any failure at any point before that line
 * leaves the node exactly as it was:
 *
 *   1. getheaders with a REAL multi-hash locator (fork discovery).
 *   2. Validate the candidate headers standalone: PoW on every header, and
 *      hdr[i].prev == blockhash(hdr[i-1]) across the whole run.       [cheap]
 *   3. Locate the fork point by walking OUR chain forward from the ancestor
 *      the peer answered from, comparing hashes height by height.
 *   4. Refuse anything deeper than REORG_MAX_DEPTH (the undo window).
 *   5. Compare cumulative chainwork. Not strictly heavier -> stop, no action.
 *   6. Download and cons_verify EVERY replacement block into a staging file,
 *      checking each one hashes to the header we already validated.
 *   7. Pre-flight the disconnect: prove undo data exists and is complete for
 *      every height we are about to unapply.
 *   ------------------------- point of no return -------------------------
 *   8. Unapply those heights (undo replay + created-output removal).
 *   9. store_truncate_to + store_chainwork_truncate + index rebuild.
 *  10. Connect the staged blocks (store, chainwork, UTXO apply w/ undo).
 *  11. Reconcile the mempool.
 *
 * A crash between 8 and 10 leaves a SHORTER but internally consistent chain
 * (store tip, chainwork tip and applied UTXO height are all rewound
 * together), which the normal sync loop then re-extends from scratch. That
 * is the reason step 9 truncates chainwork and rewinds the applied height in
 * the same breath as the block store: a chain that is short in one of the
 * three and long in the others is the state that would actually corrupt.
 * ===========================================================================
 */
#include <stdio.h>
#include "log_ts.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/file.h>
#include <sys/stat.h>
#include "reorg.h"
#include "utxo_walk.h"

/* ---------------- externs: assembly + sibling C modules ------------------ */
extern long store_reload(void* st);
extern int  store_get_at(void* st, uint64_t height, uint64_t out_meta[3]);
extern long store_truncate_to(void* st, long target_height);
extern int  archive_truncate_safe(void* st, long target_height, int* out_used_index_only);
extern void store_rd_close(void* st);   /* bitcoin_store_fast.asm read-fd cache */
extern int  store_validates_prevhash(void* st, const unsigned char header[80]);
extern int  store_get_tip_hash(void* st, unsigned char out[32]);
extern long idxscan_append_locked(void* st, const unsigned char hash[32],
                                  const void* raw, long len);
/* Same append, minus the per-call flock/unflock pair -- for use only while
 * this module is already holding that lock across the whole reorg. See
 * bitcoin_idxscan.asm's header for why the plain variant cannot be used
 * here (its internal LOCK_UN would drop our outer hold after block one). */
extern long idxscan_append_nolocked(void* st, const unsigned char hash[32],
                                    const void* raw, long len);

extern void block_work(unsigned char work[16], unsigned bits);
extern void chainwork_add(unsigned char out[16], const unsigned char a[16], const unsigned char b[16]);
extern long chainwork_cmp(const unsigned char a[16], const unsigned char b[16]);
extern int  store_chainwork_init(void* st);
extern int  store_chainwork_append(void* st, long height, const unsigned char work[16]);
extern int  store_chainwork_get_at(void* st, long height, unsigned char out[16]);
extern int  store_chainwork_get_tip(void* st, unsigned char out[16]);
extern long store_chainwork_reload(void* st);
extern long store_chainwork_truncate(void* st, long target_height);

extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern int  pow_check(const unsigned char hdr[80]);
extern int  cons_verify(const void* block, long len, void* scratch, unsigned cap);
extern long locator_build(void* store_buf, unsigned char* out_hashes); /* [REORG_LOCATOR_MAX*32] */

extern long p2p_write(int fd, const char* cmd, unsigned cmdlen, const void* pl, unsigned plen);
extern int  p2p_read(int fd, char cmd[12], void* pl, unsigned cap, unsigned* len);
extern long p2p_getheaders(void* out, const void* locator, int count, const void* stop);
extern long p2p_getdata_block(void* out, const unsigned char hash[32]);
extern long p2p_headers_count(const void* payload, long plen);

extern int  tx_parse(void* info, const unsigned char* tx, unsigned long txlen);
extern void tx_txid(unsigned char out[32], const unsigned char* tx, unsigned long txlen,
                    unsigned char* buf, unsigned long buflen);

/* daemon/utxo_live.c */
extern int  utxo_live_can_unapply(const void* blockbuf, uint64_t blocklen, long height);
extern int  utxo_live_unapply_block(const void* blockbuf, uint64_t blocklen, long height);
extern int  utxo_live_apply_block(const void* blockbuf, uint64_t blocklen, long height);
extern int  utxo_live_rewind_to(long height);

/* bitcoin_mempool.asm / bitcoin_mempool_policy.c */
extern long mpool_del(void* mp, const unsigned char txid[32]);
extern long mpool_count(void* mp);
extern long mpool_policy_add(void* pol, void* st, void* mp,
                             const unsigned char* tx, unsigned long txlen,
                             const unsigned char txid[32], void* utxo);
extern void mpool_policy_state_init(void* st, unsigned n);

/* ---------------- tunables ---------------------------------------------- */
/* Distinct getheaders pages we will pull while trying to establish whether a
 * detected fork is heavier. Bounded so a hostile peer cannot make us spin. */
#define REORG_MAX_PAGES        6
/* Bounded retry budget for one p2p_read that must produce a specific message
 * type. Matches node_sync's own 20-timeout budget (see bitcoind.asm's
 * .hdr_drain comment for why a single -1 must not abandon the exchange). */
#define REORG_READ_TRIES       24
#define REORG_NET_BUF          (6<<20)
#define REORG_BLOCK_BUF        (8<<20)
#define REORG_STAGE_PATH       "reorg_stage.dat"

static void (*g_index_rebuild)(void) = 0;
void reorg_set_index_rebuild(void (*cb)(void)){ g_index_rebuild = cb; }

/* Has reorg_chainwork_open succeeded in THIS process? Every chainwork entry
 * point below refuses to act until it has, and this is not a nicety: the
 * chainwork fd lives at store_buf+144, and an unopened store_buf is all
 * zeroes -- so an ungated call would lseek/pwrite on FILE DESCRIPTOR 0,
 * i.e. stdin. daemon/main.c's do_outbound_sync is shared between the
 * download worker (which does open chainwork) and serve_mux's outbound legs
 * (which do not), so this is a reachable path, not a theoretical one.
 * The second thing it protects is fork choice itself: an unopened store
 * reports ZERO cumulative work for our own tip, which would make every
 * candidate chain compare as heavier. Refusing outright is the only safe
 * default for a function that can trigger a rewrite of real chain state. */
static int g_cw_open = 0;

/* ---------------- small helpers ----------------------------------------- */

/* Block hashes are printed the way explorers/RPC show them: byte-reversed,
 * first 8 display bytes. Identical convention (and identical helper shape) to
 * daemon/main.c's log_hash_short so reorg lines can be grep-correlated
 * against [block] stored lines. */
static void hash_short(char out[17], const unsigned char h[32]){
    static const char hexd[]="0123456789abcdef";
    for(int k=0;k<8;k++){ unsigned char b=h[31-k]; out[k*2]=hexd[b>>4]; out[k*2+1]=hexd[b&0xf]; }
    out[16]=0;
}
/* 128-bit cumulative work, printed as fixed-width hex (high limb then low).
 * Hex rather than decimal because there is no portable 128-bit printf. */
static void work_str(char out[40], const unsigned char w[16]){
    unsigned long long lo, hi;
    memcpy(&lo, w, 8); memcpy(&hi, w+8, 8);
    snprintf(out, 40, "0x%016llx%016llx", hi, lo);
}

static long store_tip(void* st){ return (long)*(int*)((char*)st + 24); }
static int  store_idx_fd(void* st){ return *(int*)((char*)st + 8); }
static int  store_flock_fd(void* st){ return *(int*)((char*)st + 40); }

/* Our stored block hash at `h`, straight out of index.dat's positional
 * record (bytes [0..31] of the 48-byte record at h*48). Same technique
 * daemon/main.c's anchor_locator and bitcoin_store.asm's store_get_tip_hash
 * use, and for the same reason: it is readable even immediately after an
 * append, unlike the block body. */
static int our_hash_at(void* st, long h, unsigned char out[32]){
    if (h < 0) return 0;
    return pread(store_idx_fd(st), out, 32, (off_t)h * 48) == 32;
}

/* ---- read a stored block's 80-byte header without disturbing `st` -------
 * Deliberately NOT via store_get_file_fd/store_read_at: store_get_file_fd
 * goes through open_file, which closes and reassigns st's cur_blk_fd (the
 * descriptor store_append is about to keep using), and store_read_at owns
 * the +56..+127 read-fd cache region of the same struct. A private one-slot
 * fd cache keeps this loop completely side-effect-free on `st`, which
 * matters because reorg_chainwork_sync runs on the live daemon's store_buf
 * while other code is using it. */
static int  g_hdr_fd = -1;
static unsigned g_hdr_fileno = 0xffffffffu;

static void hdr_fd_close(void){
    if (g_hdr_fd >= 0) close(g_hdr_fd);
    g_hdr_fd = -1; g_hdr_fileno = 0xffffffffu;
}
static int hdr_fd_for(unsigned file_no){
    if (g_hdr_fd >= 0 && g_hdr_fileno == file_no) return g_hdr_fd;
    if (g_hdr_fd >= 0) close(g_hdr_fd);
    char name[16];
    snprintf(name, sizeof name, "blk%05u.dat", file_no);
    g_hdr_fd = open(name, O_RDONLY);
    g_hdr_fileno = (g_hdr_fd >= 0) ? file_no : 0xffffffffu;
    return g_hdr_fd;
}

/* -> 1 ok / -3 pruned (block data deliberately deleted) / 0 unavailable.
 * Block frames are [u32 len][u32 magic][raw], so the header starts at
 * data_pos+8 (same +8 skip node_serve_block uses). */
static int read_stored_header(void* st, long h, unsigned char out[80]){
    uint64_t meta[3];
    int r = store_get_at(st, (uint64_t)h, meta);
    if (r == -3) return -3;                 /* pruned: distinguishable, see below */
    if (r != 1) return 0;
    int fd = hdr_fd_for((unsigned)meta[2]);
    if (fd < 0) return 0;
    return pread(fd, out, 80, (off_t)meta[0] + 8) == 80 ? 1 : 0;
}

/* Full block body, same framing skip. -> length or -1. */
static long read_stored_block(void* st, long h, unsigned char* out, uint64_t cap){
    uint64_t meta[3];
    if (store_get_at(st, (uint64_t)h, meta) != 1) return -1;
    if (meta[1] > cap) return -1;
    int fd = hdr_fd_for((unsigned)meta[2]);
    if (fd < 0) return -1;
    if (pread(fd, out, (size_t)meta[1], (off_t)meta[0] + 8) != (ssize_t)meta[1]) return -1;
    return (long)meta[1];
}

static unsigned hdr_bits(const unsigned char hdr[80]){
    unsigned b; memcpy(&b, hdr+72, 4); return b;
}

/* ===========================================================================
 * 1. CHAINWORK MAINTENANCE
 *
 * Design note (this differs from the literal wording of the stage brief, on
 * purpose). The brief suggests appending a chainwork record at each of the
 * two places a block gets stored -- node_sync's idxscan_append_locked call
 * and bitcoin_serve.asm's inbound .do_block. Instead this is a CATCH-UP
 * function that walks index.dat forward from wherever chainwork.dat ends and
 * fills the gap, called from the same loop that already calls
 * utxo_live_catchup. Reasons:
 *   - it covers BOTH writers (and any future one) with a single call site,
 *     in the one process that owns the reorg decision, instead of editing two
 *     real-time assembly paths -- one of which (.do_block) runs in a forked
 *     inbound child that has no business owning chainwork state;
 *   - it is inherently self-healing: a record missed for any reason (crash
 *     between the two writes, a block stored by a sibling process, a store
 *     restored from backup) is simply filled in on the next pass, whereas a
 *     write-time hook that misses once stays wrong forever;
 *   - the ~974k-block backfill the brief asks for as a separate one-time
 *     tool is then just this same function with max_blocks<=0, so the
 *     backfill path and the steady-state path are the same tested code.
 * The invariant it maintains is the one that actually matters: chainwork.dat
 * has exactly one cumulative record per index.dat height, always.
 * ======================================================================== */

long reorg_chainwork_open(void* st){
    g_cw_open = 0;
    if (store_chainwork_init(st) != 1) return -1;
    /* store_chainwork_init zeroes the cache even when the file already has
     * records. Without this reload our own tip would look weightless and
     * EVERY candidate chain would compare as heavier. */
    if (store_chainwork_reload(st) < 0) return -1;
    g_cw_open = 1;
    return 1;
}

long reorg_chainwork_sync(void* st, long max_blocks){
    if (!g_cw_open) return 0;                 /* see g_cw_open's comment */
    long have = store_chainwork_reload(st);   /* == number of records present */
    if (have < 0) return -1;
    long tip = store_tip(st);
    if (tip < 0) return 0;
    long appended = 0, pruned = 0;
    for (long h = have; h <= tip; h++){
        if (max_blocks > 0 && appended >= max_blocks) break;
        unsigned char hdr[80];
        unsigned char w[16];
        int rh = read_stored_header(st, h, hdr);
        if (rh == 1){
            block_work(w, hdr_bits(hdr));
        } else if (rh == -3){
            /* PRUNED HEIGHT: the block data is gone by design, so this
             * height's work is unknowable. Record ZERO work and keep going,
             * rather than stopping -- stopping would leave chainwork.dat
             * permanently short of the tip on any pruned node, which makes
             * store_chainwork_get_at fail at every fork height and disables
             * reorg handling outright.
             *
             * Zero is safe for fork choice specifically because fork choice
             * only ever compares two totals that share the SAME baseline:
             * ours = cumulative(fork) + work(our blocks above fork), theirs =
             * cumulative(fork) + work(their blocks above fork). Any error
             * baked into cumulative(fork) appears identically on both sides
             * and cancels. What it does mean is that the ABSOLUTE cumulative
             * figure printed in the [reorg] log lines understates reality on
             * a pruned node; the comparison it is used for is still exact. */
            memset(w, 0, 16);
            pruned++;
        } else {
            fprintf(stderr, "[chainwork] cannot read header at height %ld -- stopping sync short (tip=%ld)\n", h, tip);
            break;
        }
        if (store_chainwork_append(st, h, w) != 1){
            fprintf(stderr, "[chainwork] append failed at height %ld\n", h);
            hdr_fd_close();
            return -1;
        }
        appended++;
    }
    hdr_fd_close();
    if (pruned)
        fprintf(stderr, "[chainwork] %ld of %ld height(s) were pruned; their work is recorded as zero (see reorg_chainwork_sync -- fork COMPARISONS stay exact, absolute totals do not)\n",
                pruned, appended);
    return appended;
}

/* ===========================================================================
 * 2. LOCATOR + HEADER INGEST
 * ======================================================================== */

/* The height sequence below MUST stay identical to daemon/locator_build.c's
 * own walk (tip, tip-1, tip-2, tip-4, tip-8, ... capped at LOCATOR_MAX,
 * clamped at 0). locator_build returns only the hashes; we need the heights
 * too, so that "the peer replied from hash X" becomes "the peer replied from
 * height H" in O(1) instead of a chain scan. The two are cross-checked below
 * (same count, and each hash re-read from the height we derived), so a future
 * change to one without the other fails loudly instead of silently locating
 * the wrong fork point. */
long reorg_build_locator(void* st, reorg_cand_t* c){
    long n = locator_build(st, (unsigned char*)c->loc);
    if (n < 0) return -1;
    c->loc_n = n;
    if (n == 0) return 0;

    long height = store_tip(st), step = 1, transitions = 0, k = 0;
    while (k < n) {
        c->loc_h[k] = height;
        k++;
        if (height == 0) break;
        long next = height - step;
        transitions++;
        if (transitions >= 2) step *= 2;
        if (next < 0) next = 0;
        height = next;
    }
    if (k != n){
        fprintf(stderr, "[reorg] INTERNAL: locator height walk (%ld) disagrees with locator_build (%ld)\n", k, n);
        return -1;
    }
    for (long i = 0; i < n; i++){
        unsigned char h32[32];
        if (!our_hash_at(st, c->loc_h[i], h32) || memcmp(h32, c->loc[i], 32) != 0){
            fprintf(stderr, "[reorg] INTERNAL: locator entry %ld does not match index.dat height %ld\n", i, c->loc_h[i]);
            return -1;
        }
    }
    return n;
}

long reorg_headers_ingest(reorg_cand_t* c, const unsigned char* payload, long plen){
    long cnt = p2p_headers_count(payload, plen);
    if (cnt < 0) return -1;
    if (cnt == 0) return 0;
    /* p2p_headers_count already proved plen >= varintlen + cnt*81, so the
     * varint length is recoverable by subtraction -- the same derivation
     * node_sync does (and, as there, the RAW count must be used, never a
     * post-cap one). */
    long varlen = plen - cnt * 81;
    if (varlen < 1 || varlen > 9) return -1;
    long added = 0;
    for (long i = 0; i < cnt && c->n < REORG_MAX_HEADERS; i++){
        const unsigned char* e = payload + varlen + i*81;
        memcpy(c->hdr[c->n], e, 80);
        block_hash(c->hash[c->n], c->hdr[c->n]);
        c->n++; added++;
    }
    return added;
}

/* ===========================================================================
 * 3. ANALYSIS
 * ======================================================================== */

/* Standalone header-chain validation: every header must satisfy its own
 * claimed PoW target, and every header after the first must chain to its
 * predecessor. This runs BEFORE anything else looks at work or heights, so a
 * garbage or hostile headers page is discarded at the cheapest possible
 * point.
 *
 * What this deliberately does NOT check: that nBits follows Bitcoin's
 * difficulty-retarget rules. Neither does cons_verify (it calls pow_check
 * against whatever target the header itself claims). A peer is therefore free
 * to serve a long chain of trivially-mined low-difficulty headers -- which is
 * exactly why fork choice below is CUMULATIVE WORK and not height: such a
 * chain scores near zero and can never out-weigh ours. Retarget validation is
 * a real gap in this node's consensus rules; it is pre-existing, it is called
 * out in this stage's report, and chainwork comparison is what contains it. */
static int headers_chain_valid(const reorg_cand_t* c){
    for (long i = 0; i < c->n; i++){
        if (!pow_check(c->hdr[i])){
            fprintf(stderr, "[reorg] candidate REJECTED: header %ld fails proof-of-work\n", i);
            return 0;
        }
        if (i > 0 && memcmp(c->hdr[i]+4, c->hash[i-1], 32) != 0){
            fprintf(stderr, "[reorg] candidate REJECTED: header %ld prevhash does not chain to header %ld\n", i, i-1);
            return 0;
        }
    }
    return 1;
}

long reorg_analyze(void* st, reorg_cand_t* c){
    if (c->n <= 0) return 0;
    if (!g_cw_open){
        fprintf(stderr, "[reorg] refusing to evaluate a candidate chain: chainwork is not open in this process (our own tip would weigh zero, so EVERY chain would look heavier)\n");
        return -1;
    }
    if (!headers_chain_valid(c)) return -1;

    if (reorg_chainwork_sync(st, 0) < 0){
        fprintf(stderr, "[reorg] chainwork sync failed -- refusing to evaluate candidate\n");
        return -1;
    }
    long tip = store_tip(st);
    c->our_tip = tip;
    if (tip < 0) return 0;              /* empty store: plain IBD, not a reorg */

    /* ---- where does hdr[0] attach to OUR chain? The peer answers a
     * getheaders from the first locator hash it recognises, so hdr[0]'s
     * prevhash is normally one of the hashes we sent -- an O(loc_n) lookup
     * that yields the height directly. ---- */
    c->base_height = -1;
    for (long i = 0; i < c->loc_n; i++){
        if (memcmp(c->hdr[0]+4, c->loc[i], 32) == 0){ c->base_height = c->loc_h[i]; break; }
    }
    if (c->base_height < 0){
        /* Fall back to a bounded scan back from our tip, for a peer that
         * answered from something other than a locator entry (an unsolicited
         * headers announcement, say). Bounded by REORG_MAX_DEPTH because
         * anything older than that is unusable anyway -- we could not
         * disconnect that far even if we wanted to. */
        for (long h = tip; h >= 0 && h > tip - REORG_MAX_DEPTH - 1; h--){
            unsigned char h32[32];
            if (!our_hash_at(st, h, h32)) break;
            if (memcmp(c->hdr[0]+4, h32, 32) == 0){ c->base_height = h; break; }
        }
    }
    if (c->base_height < 0){
        fprintf(stderr, "[reorg] candidate REJECTED: its first header attaches to a block we do not have (within %d of our tip)\n",
                REORG_MAX_DEPTH);
        return -1;
    }

    /* ---- FORK-POINT WALK: advance along both chains together from
     * base_height while the hashes agree. The first disagreement is the
     * divergence; the height below it is the true common ancestor, which may
     * be well ABOVE base_height because the locator is sparse. ---- */
    long h = c->base_height, i = 0;
    while (i < c->n && h + 1 <= tip){
        unsigned char ours[32];
        if (!our_hash_at(st, h+1, ours)) break;
        if (memcmp(ours, c->hash[i], 32) != 0) break;
        h++; i++;
    }
    c->fork_height = h;
    c->first_new = i;

    if (i >= c->n){
        /* every candidate header is already on our chain -- peer is behind or level */
        return 0;
    }
    if (h >= tip){
        /* the candidate simply continues our tip: ordinary sync, not a reorg */
        return 0;
    }

    /* ---- depth gate, BEFORE any work is computed or any block fetched ---- */
    long depth = tip - c->fork_height;
    if (depth > REORG_MAX_DEPTH){
        fprintf(stderr, "[reorg] candidate REJECTED: fork at height %ld is %ld blocks deep (max %d -- deeper than the retained undo data). Human review required.\n",
                c->fork_height, depth, REORG_MAX_DEPTH);
        return -1;
    }

    /* ---- defensive re-assert: the first genuinely-new header must chain to
     * the fork point we just computed. Implied by the walk above, but this is
     * the hinge the entire disconnect depends on, so it is checked outright
     * rather than reasoned about. ---- */
    {
        unsigned char fh[32];
        if (!our_hash_at(st, c->fork_height, fh) ||
            memcmp(c->hdr[c->first_new]+4, fh, 32) != 0){
            fprintf(stderr, "[reorg] candidate REJECTED: first new header does not chain to fork point %ld\n", c->fork_height);
            return -1;
        }
    }

    /* ---- CUMULATIVE WORK. cand = work(fork_height) + sum of per-header work
     * over the replacement branch; ours = the cached cumulative tip work.
     * Computed from headers alone -- no block bodies needed to decide. ---- */
    unsigned char base[16];
    memset(base, 0, 16);
    if (c->fork_height >= 0 && store_chainwork_get_at(st, c->fork_height, base) != 1){
        fprintf(stderr, "[reorg] candidate REJECTED: no chainwork record at fork height %ld\n", c->fork_height);
        return -1;
    }
    unsigned char cand[16];
    memcpy(cand, base, 16);
    for (long k = c->first_new; k < c->n; k++){
        unsigned char w[16];
        block_work(w, hdr_bits(c->hdr[k]));
        chainwork_add(cand, cand, w);
    }
    memcpy(c->cand_work, cand, 16);
    store_chainwork_get_tip(st, c->our_work);

    char cw[40], ow[40];
    work_str(cw, c->cand_work); work_str(ow, c->our_work);
    fprintf(stderr, "[reorg] detected competing chain at height %ld, work=%s vs ours=%s (our tip=%ld, candidate adds %ld blocks)\n",
            c->fork_height, cw, ow, tip, c->n - c->first_new);

    return chainwork_cmp(c->cand_work, c->our_work) > 0 ? 2 : 1;
}

/* ===========================================================================
 * 4. EXECUTION (disconnect + reconnect)
 * ======================================================================== */

static double now_s(void){
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + ts.tv_nsec/1e9;
}

long reorg_execute(void* st, long fork_height, long nblocks,
                   reorg_block_src src, void* srcctx){
    double t0 = now_s();
    long tip = store_tip(st);
    if (fork_height > tip){
        fprintf(stderr, "[reorg] refusing: fork height %ld is above our tip %ld\n", fork_height, tip);
        return 0;
    }
    if (tip - fork_height > REORG_MAX_DEPTH){
        fprintf(stderr, "[reorg] refusing: disconnect depth %ld exceeds max %d\n", tip - fork_height, REORG_MAX_DEPTH);
        return 0;
    }
    if (nblocks <= 0){
        fprintf(stderr, "[reorg] refusing: no replacement blocks supplied\n");
        return 0;
    }

    static unsigned char blkbuf[REORG_BLOCK_BUF];

    /* ---------------- TAKE THE APPEND LOCK FOR THE WHOLE OPERATION ------
     * The other writer into this archive is an inbound serve child's
     * .do_block, which appends through store_append_shared and takes this
     * same flock (st+40, main.c's append.lock). A reorg must exclude it for
     * the ENTIRE window -- pre-flight, disconnect, truncate AND the whole
     * reconnect loop -- because a block appended by a sibling at any point
     * in that window lands on a chain that is mid-rewrite.
     *
     * This originally only covered disconnect+truncate, and even that hold
     * was illusory once reconnect started: idxscan_append_locked delegates to
     * store_append_shared, whose unconditional LOCK_UN on the way out would
     * have released OUR outer hold after the very first reconnected block.
     * The reconnect loop below therefore uses idxscan_append_nolocked, which
     * is the same append with the flock pair removed, so the hold taken here
     * survives to the single release at the end.
     *
     * If no flock fd is configured (st+40 unset -- standalone tools and some
     * tests), `locked` stays 0 and the reconnect loop falls back to the
     * self-locking append: strictly no worse than before, and correct in a
     * single-writer setting. */
    int lfd = store_flock_fd(st);
    int locked = 0;
    if (lfd > 0 && flock(lfd, LOCK_EX) == 0) locked = 1;
    else if (lfd > 0) fprintf(stderr, "[reorg] WARNING: could not take the append lock; proceeding with per-append locking only\n");

    /* ---------------- PRE-FLIGHT (non-destructive) ----------------------
     * Prove, for every height we intend to disconnect, that (a) the block is
     * readable and (b) its undo data is present and record-for-record
     * complete. Failing here costs nothing; failing halfway through step 8
     * would leave a corrupted UTXO set. */
    for (long h = tip; h > fork_height; h--){
        long len = read_stored_block(st, h, blkbuf, sizeof blkbuf);
        if (len < 81){
            fprintf(stderr, "[reorg] refusing: cannot read block at height %ld (len=%ld)\n", h, len);
            hdr_fd_close();
            if (locked) flock(lfd, LOCK_UN);
            return 0;
        }
        if (!utxo_live_can_unapply(blkbuf, (uint64_t)len, h)){
            fprintf(stderr, "[reorg] refusing: height %ld cannot be safely unapplied (see the pre-flight line above)\n", h);
            hdr_fd_close();
            if (locked) flock(lfd, LOCK_UN);
            return 0;
        }
    }

    /* ------------------------ point of no return ------------------------ */
    for (long h = tip; h > fork_height; h--){
        long len = read_stored_block(st, h, blkbuf, sizeof blkbuf);
        if (len < 81){
            fprintf(stderr, "[reorg] FATAL: block at height %ld became unreadable mid-disconnect\n", h);
            if (locked) flock(lfd, LOCK_UN);
            hdr_fd_close();
            return -1;
        }
        unsigned char bh[32]; block_hash(bh, blkbuf);
        char hs[17]; hash_short(hs, bh);
        fprintf(stderr, "[reorg] disconnecting height %ld hash=%s..\n", h, hs);
        if (!utxo_live_unapply_block(blkbuf, (uint64_t)len, h)){
            fprintf(stderr, "[reorg] FATAL: unapply failed at height %ld -- UTXO set is now PARTIALLY rewound and must be rebuilt from the archive\n", h);
            if (locked) flock(lfd, LOCK_UN);
            hdr_fd_close();
            return -1;
        }
    }
    hdr_fd_close();   /* the blk files may be about to be truncated/unlinked */

    /* Rewind all three tips together -- block store, chainwork, applied UTXO
     * height. Any one of them left ahead of the others is the state that
     * actually corrupts (see this file's header comment).
     *
     * archive_truncate_safe, not a bare store_truncate_to: on an archive
     * that isn't laid out in height order below fork_height (the parallel
     * chunked downloader can produce this -- see PLAN_SCRIPT_VERIFY.md's
     * "Related known issues"), a bare store_truncate_to safely refuses
     * (see store_layout_monotonic's header comment for why it must refuse
     * rather than guess) and this reorg would FATAL out here, leaving a
     * won reorg it cannot actually complete. archive_truncate_safe instead
     * falls back to the always-safe, index-only store_truncate_index_only
     * in that case -- disconnected heights' block bytes go unreclaimed on
     * disk rather than the reorg failing outright. */
    int used_index_only = 0;
    if (archive_truncate_safe(st, fork_height, &used_index_only) != 1){
        fprintf(stderr, "[reorg] FATAL: archive_truncate_safe(%ld) failed\n", fork_height);
        if (locked) flock(lfd, LOCK_UN);
        return -1;
    }
    if (used_index_only){
        fprintf(stderr, "[reorg] NOTE: archive below height %ld is not laid out in height order -- used the\n", fork_height);
        fprintf(stderr, "[reorg]   index-only truncate fallback; disconnected block bytes remain on disk, unreclaimed.\n");
    }
    if (store_chainwork_truncate(st, fork_height) != 1){
        fprintf(stderr, "[reorg] FATAL: store_chainwork_truncate(%ld) failed\n", fork_height);
        if (locked) flock(lfd, LOCK_UN);
        return -1;
    }
    /* Invalidate bitcoin_store_fast.asm's read-fd cache. store_truncate_to
     * ftruncates the boundary blk file and UNLINKS every later one, but a
     * descriptor cached in that region still refers to the old inode -- so a
     * subsequent store_read_at (which is how daemon/utxo_live.c reads every
     * block) could keep serving bytes out of a file that is no longer part of
     * the chain, or out of a deleted inode that a later rollover has since
     * replaced by a same-named new file. Same invalidation store_prune needs,
     * and the reason store_rd_close documents itself as "shutdown / post-prune
     * invalidation". */
    store_rd_close(st);
    if (!utxo_live_rewind_to(fork_height)){
        fprintf(stderr, "[reorg] WARNING: could not persist the rewound applied height %ld (next boot may re-apply from an older height, which is safe)\n", fork_height);
    }
    if (g_index_rebuild) g_index_rebuild();

    /* NOTE: the append lock is deliberately NOT released here -- it is held
     * through the reconnect loop below and dropped once at the very end. */

    /* ---------------- RECONNECT ---------------- */
    long connected = 0;
    for (long i = 0; i < nblocks; i++){
        long len = src(srcctx, i, blkbuf, sizeof blkbuf);
        if (len < 81){
            fprintf(stderr, "[reorg] FATAL: replacement block %ld unavailable (len=%ld) -- chain left at height %ld\n",
                    i, len, store_tip(st));
            if (locked) flock(lfd, LOCK_UN);
            return -1;
        }
        /* Re-verify at connect time even though the staging path already
         * did: staging and connecting are separated by every destructive
         * step above, and this is the last chance to refuse bad bytes before
         * they enter the archive. */
        static unsigned char scratch[1<<20];
        if (!cons_verify(blkbuf, len, scratch, sizeof scratch)){
            fprintf(stderr, "[reorg] FATAL: replacement block %ld failed cons_verify -- chain left at height %ld\n",
                    i, store_tip(st));
            if (locked) flock(lfd, LOCK_UN);
            return -1;
        }
        if (store_validates_prevhash(st, blkbuf) != 1){
            fprintf(stderr, "[reorg] FATAL: replacement block %ld does not chain to the current tip -- chain left at height %ld\n",
                    i, store_tip(st));
            if (locked) flock(lfd, LOCK_UN);
            return -1;
        }
        unsigned char bh[32]; block_hash(bh, blkbuf);
        long h = locked ? idxscan_append_nolocked(st, bh, blkbuf, len)
                        : idxscan_append_locked(st, bh, blkbuf, len);
        if (h < 0){
            fprintf(stderr, "[reorg] FATAL: store append failed for replacement block %ld\n", i);
            if (locked) flock(lfd, LOCK_UN);
            return -1;
        }
        unsigned char w[16];
        block_work(w, hdr_bits(blkbuf));
        if (store_chainwork_append(st, h, w) != 1){
            fprintf(stderr, "[reorg] FATAL: chainwork append failed at height %ld\n", h);
            if (locked) flock(lfd, LOCK_UN);
            return -1;
        }
        if (!utxo_live_apply_block(blkbuf, (uint64_t)len, h)){
            fprintf(stderr, "[reorg] FATAL: UTXO apply failed at height %ld\n", h);
            if (locked) flock(lfd, LOCK_UN);
            return -1;
        }
        if (!utxo_live_rewind_to(h)){
            fprintf(stderr, "[reorg] WARNING: could not persist applied height %ld\n", h);
        }
        char hs[17]; hash_short(hs, bh);
        fprintf(stderr, "[reorg] reconnecting height %ld hash=%s..\n", h, hs);
        connected++;
    }

    if (g_index_rebuild) g_index_rebuild();

    /* MEMPOOL RECONCILIATION IS NOT DONE HERE, AND THAT IS DELIBERATE.
     * bitcoin_serve.asm's mempool (mp_area) is a private BSS object that is
     * mpool_init'd once per node_serve_loop process -- i.e. it lives in each
     * forked INBOUND connection child, not in the download worker that owns
     * the reorg decision, and it is not even an exported symbol. There is
     * therefore no mempool in this process to reconcile. reorg_mempool_reconcile
     * is implemented and fully tested (tests/test_reorg.c drives eviction,
     * reinjection and survival against the real policy layer) and is ready for
     * whatever stage gives the node a shared, process-spanning mempool -- it
     * just has nothing to act on today. Say so out loud rather than let the
     * absence of a log line read as "reconciled successfully". */
    fprintf(stderr, "[reorg] mempool NOT reconciled: no mempool exists in this process (bitcoin_serve.asm's is per-inbound-connection). Any inbound child's mempool may briefly hold transactions that the new branch invalidates.\n");

    unsigned char tiph[32]; char hs[17] = "(none)";
    if (store_get_tip_hash(st, tiph) == 1) hash_short(hs, tiph);
    fprintf(stderr, "[reorg] complete: new tip height=%ld hash=%s.. (%.2fs, -%ld +%ld blocks)\n",
            store_tip(st), hs, now_s()-t0, tip - fork_height, connected);
    /* The single release for the whole operation. Everything above -- the
     * pre-flight, the disconnect, the truncate and every reconnect append --
     * ran under one continuous hold of this lock. */
    if (locked) flock(lfd, LOCK_UN);
    return 1;
}

/* ===========================================================================
 * 5. MEMPOOL RECONCILIATION
 *
 * Strategy: FULL REBUILD, not a surgical unregister.
 *
 * bitcoin_mempool_policy.c has no public way to remove one transaction from
 * its ancestor/descendant graph (daemon/tx_accept.c's own header comment
 * calls this out). Adding one would mean unwinding anc_cnt/anc_bytes/
 * desc_cnt/desc_bytes across a parent chain, plus compacting three parallel
 * arrays whose entries reference each other by INDEX -- every claim's
 * `claimer` and every node's `parent[]` would have to be renumbered. That is
 * a lot of new, subtly-order-dependent code on a path that runs at most a
 * few times a year.
 *
 * The policy state is a flat, zero-initialisable buffer, so a rebuild is
 * simply: snapshot the current mempool, add the disconnected blocks'
 * transactions to the candidate list, empty the structural mempool,
 * mpool_policy_state_init the policy state, and offer every candidate back
 * through the NORMAL mpool_policy_add path. That gets both required
 * behaviours out of one mechanism and with zero new policy code:
 *   - EVICTION: a transaction whose prevouts the winning branch already
 *     spent no longer resolves, so mpool_policy_add rejects it. This also
 *     covers transactions that are simply confirmed on the new branch --
 *     their inputs are spent there too.
 *   - REINJECTION: a transaction that was confirmed only on the losing
 *     branch is now unconfirmed again; if its inputs still resolve it is
 *     re-accepted, with fees/RBF/ancestor limits re-checked exactly as they
 *     would be for a freshly relayed transaction.
 *
 * Ordering: parents must be offered before children or the child is rejected
 * for an unresolvable input. Rather than topologically sorting, the offer
 * pass simply repeats while it keeps making progress (a child accepted on
 * pass 2 after its parent landed on pass 1), bounded by the candidate count.
 * ======================================================================== */

typedef struct { unsigned char txid[32]; const unsigned char* tx; unsigned long len; } rtx_t;

/* Enumerate the structural mempool directly. Layout per bitcoin_mempool.asm's
 * header comment: +0 n, +8 mask, +16 blob, +24 blob_cap, +32 fill, then
 * (mask+1) 48-byte slots at +40 -- [+0 len][+8 txid[32]][+40 blob_off], with
 * len == 0xFFFFFFFFFFFFFFFF marking an empty slot. mpool_del uses
 * backward-shift deletion (no tombstones), so "not EMPTY" is exactly "live". */
static long mempool_snapshot(void* mp, rtx_t* out, long max){
    unsigned char* m = (unsigned char*)mp;
    unsigned long long mask; memcpy(&mask, m+8, 8);
    unsigned char* blob; memcpy(&blob, m+16, 8);
    long n = 0;
    for (unsigned long long i = 0; i <= mask && n < max; i++){
        unsigned char* slot = m + 40 + i*48;
        unsigned long long len; memcpy(&len, slot, 8);
        if (len == 0xFFFFFFFFFFFFFFFFULL) continue;
        unsigned long long off; memcpy(&off, slot+40, 8);
        memcpy(out[n].txid, slot+8, 32);
        out[n].tx  = blob + off;
        out[n].len = (unsigned long)len;
        n++;
    }
    return n;
}

/* Collect every non-coinbase transaction of one block into `out`, copying the
 * bytes into `arena` (the block buffer the caller holds may be reused). */
static long collect_block_txs(const unsigned char* blk, uint64_t len,
                              rtx_t* out, long max, long nout,
                              unsigned char* arena, size_t arena_cap, size_t* arena_used){
    if (len < 81) return nout;
    const unsigned char* p = blk + 80;
    const unsigned char* end = blk + len;
    u64 consumed;
    u64 ntx = utxo_walk_read_varint(p, end, &consumed);
    if (!consumed) return nout;
    p += consumed;
    static unsigned char txid_scratch[4<<20];
    for (u64 t = 0; t < ntx && nout < max; t++){
        unsigned char info[64];
        if (!tx_parse(info, p, (unsigned long)(end - p))) break;
        u64 txlen; memcpy(&txlen, info, 8);
        if (t > 0){   /* index 0 is the coinbase; it can never re-enter a mempool */
            if (*arena_used + txlen > arena_cap) break;
            unsigned char* dst = arena + *arena_used;
            memcpy(dst, p, (size_t)txlen);
            *arena_used += (size_t)txlen;
            tx_txid(out[nout].txid, dst, (unsigned long)txlen, txid_scratch, sizeof txid_scratch);
            out[nout].tx = dst;
            out[nout].len = (unsigned long)txlen;
            nout++;
        }
        p += txlen;
    }
    return nout;
}

#define REORG_MEMPOOL_MAX_TX   8192
#define REORG_MEMPOOL_ARENA    (16u<<20)

long reorg_mempool_reconcile(reorg_mempool_t* m,
                             const unsigned char* const* disc_blocks,
                             const uint32_t* disc_lens, long ndisc){
    if (!m || !m->mp) return 0;

    rtx_t* cand = (rtx_t*)malloc(sizeof(rtx_t) * REORG_MEMPOOL_MAX_TX);
    unsigned char* arena = (unsigned char*)malloc(REORG_MEMPOOL_ARENA);
    /* The mempool's own blob is about to be logically emptied, and the policy
     * rebuild re-adds through mpool_put, which copies into that same blob at
     * a fresh `fill` offset. Snapshotted transaction bytes must therefore be
     * copied OUT first, not referenced in place. */
    unsigned char* snap_arena = (unsigned char*)malloc(REORG_MEMPOOL_ARENA);
    if (!cand || !arena || !snap_arena){
        free(cand); free(arena); free(snap_arena);
        fprintf(stderr, "[reorg] mempool reconcile: allocation failed\n");
        return -1;
    }
    size_t arena_used = 0;

    long ncand = mempool_snapshot(m->mp, cand, REORG_MEMPOOL_MAX_TX);
    size_t snap_used = 0;
    for (long i = 0; i < ncand; i++){
        if (snap_used + cand[i].len > REORG_MEMPOOL_ARENA){ ncand = i; break; }
        memcpy(snap_arena + snap_used, cand[i].tx, cand[i].len);
        cand[i].tx = snap_arena + snap_used;
        snap_used += cand[i].len;
    }
    long from_mempool = ncand;

    /* Disconnected blocks are offered oldest-first so an in-block parent is
     * naturally offered before its in-block child. */
    for (long b = 0; b < ndisc; b++){
        ncand = collect_block_txs(disc_blocks[b], disc_lens[b], cand,
                                  REORG_MEMPOOL_MAX_TX, ncand, arena,
                                  REORG_MEMPOOL_ARENA, &arena_used);
    }

    /* Empty the structural mempool and reset the policy graph. */
    for (long i = 0; i < from_mempool; i++) mpool_del(m->mp, cand[i].txid);
    if (m->pol_state && m->pol_n) mpool_policy_state_init(m->pol_state, m->pol_n);

    /* Offer everything back; repeat while progress is being made so a child
     * whose parent landed on an earlier pass still gets in. */
    char* done = (char*)calloc((size_t)ncand ? (size_t)ncand : 1, 1);
    long accepted = 0;
    if (done){
        for (long pass = 0; pass < ncand + 1; pass++){
            long progress = 0;
            for (long i = 0; i < ncand; i++){
                if (done[i]) continue;
                if (mpool_policy_add(m->pol, m->pol_state, m->mp,
                                     cand[i].tx, cand[i].len, cand[i].txid, m->utxo_arg) == 1){
                    done[i] = 1; accepted++; progress++;
                }
            }
            if (!progress) break;
        }
        free(done);
    }

    long final_n = mpool_count(m->mp);
    fprintf(stderr, "[reorg] mempool reconciled: %ld offered (%ld held + %ld from disconnected blocks), %ld accepted, %ld evicted, now %ld\n",
            ncand, from_mempool, ncand - from_mempool, accepted,
            ncand - accepted, final_n);

    free(cand); free(arena); free(snap_arena);
    return final_n;
}

/* ===========================================================================
 * 6. NETWORK DRIVER
 * ======================================================================== */

/* Read messages until one with command `want` arrives. Mirrors node_sync's
 * .hdr_drain/.blk_drain behaviour exactly: a -1 (SO_RCVTIMEO expiry) is a
 * transient gap in a busy peer's chatter and must be retried, not treated as
 * a dead connection; ping is answered with pong; everything else is ignored.
 * -> 1 got it / 0 gave up. */
static int read_until(int fd, const char* want, unsigned char* buf, unsigned cap, unsigned* plen){
    size_t wl = strlen(want);
    for (int i = 0; i < REORG_READ_TRIES; i++){
        char cmd[12];
        int r = p2p_read(fd, cmd, buf, cap, plen);
        if (r == -1) continue;
        if (r <= 0) return 0;
        if (strncmp(cmd, want, wl) == 0) return 1;
        if (strncmp(cmd, "ping", 4) == 0) p2p_write(fd, "pong", 4, buf, 8);
    }
    return 0;
}

/* One getheaders round trip. `loc` is loc_count*32 contiguous hashes. */
static int getheaders_once(int fd, const unsigned char* loc, int loc_count,
                           unsigned char* buf, unsigned cap, unsigned* plen){
    unsigned char gh[5 + REORG_LOCATOR_MAX*32 + 32];
    unsigned char stop[32]; memset(stop, 0, 32);
    long glen = p2p_getheaders(gh, loc, loc_count, stop);
    if (glen <= 0) return 0;
    if (p2p_write(fd, "getheaders", 10, gh, (unsigned)glen) < 24) return 0;
    return read_until(fd, "headers", buf, cap, plen);
}

/* Staging file: replacement blocks are downloaded and verified into
 * reorg_stage.dat BEFORE anything is disconnected, so a peer that stalls or
 * lies half way through costs us nothing. Framed [u32 len][bytes]. */
typedef struct { int fd; long n; long off[REORG_MAX_HEADERS]; uint32_t len[REORG_MAX_HEADERS]; } stage_t;

static long stage_read(void* ctx, long i, unsigned char* out, uint64_t cap){
    stage_t* s = (stage_t*)ctx;
    if (i < 0 || i >= s->n) return -1;
    if (s->len[i] > cap) return -1;
    if (pread(s->fd, out, s->len[i], s->off[i]) != (ssize_t)s->len[i]) return -1;
    return (long)s->len[i];
}

long reorg_probe_peer(int fd, void* st, const char* peer){
    if (!g_cw_open) return 0;
    static reorg_cand_t cand;
    static unsigned char netbuf[REORG_NET_BUF];
    memset(&cand, 0, sizeof cand);
    if (!peer) peer = "?";

    store_reload(st);
    if (reorg_build_locator(st, &cand) <= 0) return 0;   /* empty store: nothing to fork from */

    unsigned plen = 0;
    if (!getheaders_once(fd, (const unsigned char*)cand.loc, (int)cand.loc_n, netbuf, sizeof netbuf, &plen)) return 0;
    if (reorg_headers_ingest(&cand, netbuf, plen) < 0) return -1;

    long verdict = reorg_analyze(st, &cand);
    if (verdict <= 0) return verdict;   /* 0 = no fork, -1 = rejected */

    /* Fork found but not yet heavier: pull further pages of the candidate
     * chain (anchored on its own last header) before concluding. Bounded. */
    for (int page = 1; verdict == 1 && page < REORG_MAX_PAGES && cand.n < REORG_MAX_HEADERS; page++){
        long before = cand.n;
        if (!getheaders_once(fd, cand.hash[cand.n-1], 1, netbuf, sizeof netbuf, &plen)) break;
        long added = reorg_headers_ingest(&cand, netbuf, plen);
        if (added <= 0) break;
        verdict = reorg_analyze(st, &cand);
        if (verdict <= 0) return verdict;
        if (cand.n == before) break;
    }
    if (verdict != 2){
        fprintf(stderr, "[reorg] competing chain at height %ld from %s is NOT heavier -- ignoring (no action taken)\n",
                cand.fork_height, peer);
        return 0;
    }

    /* ---- download + verify every replacement block into the staging file
     * BEFORE touching anything. ---- */
    long nnew = cand.n - cand.first_new;
    stage_t stg; memset(&stg, 0, sizeof stg);
    stg.fd = open(REORG_STAGE_PATH, O_RDWR|O_CREAT|O_TRUNC, 0644);
    if (stg.fd < 0){
        fprintf(stderr, "[reorg] cannot open staging file %s: %s\n", REORG_STAGE_PATH, strerror(errno));
        return -1;
    }
    long stage_off = 0;
    int ok = 1;
    static unsigned char scratch[1<<20];
    for (long k = 0; k < nnew && ok; k++){
        long hi = cand.first_new + k;
        unsigned char gd[64];
        long gl = p2p_getdata_block(gd, cand.hash[hi]);
        if (gl <= 0 || p2p_write(fd, "getdata", 7, gd, (unsigned)gl) < 24){ ok = 0; break; }
        if (!read_until(fd, "block", netbuf, sizeof netbuf, &plen)){
            fprintf(stderr, "[reorg] peer %s did not deliver replacement block %ld -- aborting BEFORE any change\n", peer, hi);
            ok = 0; break;
        }
        unsigned char bh[32]; block_hash(bh, netbuf);
        if (memcmp(bh, cand.hash[hi], 32) != 0){
            fprintf(stderr, "[reorg] peer %s sent a block that is not the header it announced -- aborting BEFORE any change\n", peer);
            ok = 0; break;
        }
        if (!cons_verify(netbuf, (long)plen, scratch, sizeof scratch)){
            fprintf(stderr, "[reorg] replacement block at index %ld fails cons_verify -- aborting BEFORE any change\n", hi);
            ok = 0; break;
        }
        if (pwrite(stg.fd, netbuf, plen, stage_off) != (ssize_t)plen){ ok = 0; break; }
        stg.off[stg.n] = stage_off;
        stg.len[stg.n] = plen;
        stg.n++;
        stage_off += plen;
    }
    if (!ok || stg.n != nnew){
        close(stg.fd); unlink(REORG_STAGE_PATH);
        return -1;
    }

    long r = reorg_execute(st, cand.fork_height, stg.n, stage_read, &stg);
    close(stg.fd); unlink(REORG_STAGE_PATH);
    return r;
}
