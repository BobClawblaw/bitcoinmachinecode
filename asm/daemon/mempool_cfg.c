/* daemon/mempool_cfg.c -- Core -maxmempool and -mempoolexpiry.
 *
 * MAXMEMPOOL. bitcoin_serve.asm holds the relay mempool in STATIC buffers
 * (MP_SLOTS=1024, mp_blob = 2 MiB), so -maxmempool -- Core's default is 300 MB
 * -- could not be honoured at all: the setting would have parsed cleanly and
 * done nothing. mpool_init already takes (mp, slots, blob, blob_cap), so the
 * only thing missing was a right-sized region. We allocate one here and
 * publish it through mp_ext_* before node_serve_loop runs; the asm falls back
 * to its statics when mp_ext_area is null, so nothing that does not call this
 * changes behaviour.
 *
 * MEMPOOLEXPIRY. Mempool slots are [len][txid[32]][blob_off] -- there is no
 * timestamp, so the asm cannot expire anything on its own, and adding one
 * would change the slot layout and struct size for every consumer. Instead we
 * keep insertion times in a parallel C table keyed by txid and evict via the
 * exported mpool_del. That keeps the on-disk/in-memory mempool format
 * untouched while making expiry real.
 */
#include <stdio.h>
#include "log_ts.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <sys/mman.h>
#include "node_config.h"

extern unsigned long mpool_struct_size(unsigned long slots);
extern void mpool_init(void* mp, unsigned long slots, void* blob, unsigned long blob_cap);
extern long mpool_del(void* mp, const unsigned char txid[32]);
extern long mpool_count(void* mp);
extern unsigned long mpool_policy_state_size(unsigned long n);
extern void mpool_policy_state_init(void* st, unsigned long n);
extern void mpool_policy_set_poolcap(void* st, unsigned long long cap);
extern void mpool_policy_set_forget_cb(void (*fn)(const unsigned char*));
extern long mpool_policy_expire_one(void* st, void* mp, const unsigned char txid[32]);

/* Published to bitcoin_serve.asm, which declares these extern. Defined HERE
 * so the dependency runs C -> asm and not the reverse: when the asm owned
 * them, every target linking this file without bitcoin_serve.o failed to
 * link. A null area means "use the asm's static fallback".
 *
 * MEMPOOL COHERENCE (2026-08-25): the regions are MAP_SHARED and allocated
 * BEFORE the serve fork, so the download worker, every inbound serve child,
 * and the parent's RPC thread all see ONE mempool instead of divergent
 * copy-on-write copies (previously the parent's getrawmempool was always
 * empty). Three consequences, each handled here:
 *   1. mpool_init must run ONCE (here, pre-fork) -- the per-process lazy init
 *      in bitcoin_serve.asm would WIPE the shared pool on every new inbound
 *      connection. mp_ext_inited tells the asm to skip its init call.
 *   2. Writers now cross processes, so put/del/policy-add need a
 *      PTHREAD_PROCESS_SHARED mutex (mp_lock/mp_unlock; no-ops when the
 *      static per-process fallback is in use). NOT robust: a writer dying
 *      mid-critical-section (SIGKILL) leaves the lock held -- acceptable for
 *      now because writers are the worker (systemd-managed) and serve
 *      children (exit via normal paths), and a robust mutex would push
 *      EOWNERDEAD recovery onto every call site.
 *   3. The tx-accept POLICY state (fee/ancestor registry, previously a
 *      per-process malloc in tx_accept.c) moves into a shared region too --
 *      otherwise the structural pool is shared but the fee bookkeeping that
 *      getmempoolinfo/getmempoolentry report from is not. Same lock covers
 *      it: every mutation site (policy add via tx-accept, expiry, reorg
 *      reconcile) takes mp_lock.
 * The one remaining unlocked touch is bitcoin_serve.asm's mpool_get when
 * serving getdata(MSG_TX): a concurrent backward-shift delete or a reorg
 * blob rebuild can hand it stale bytes. Worst case is relaying a tx the pool
 * just dropped -- peers re-validate everything; documented, not load-bearing. */
void*         mp_ext_area    = 0;
void*         mp_ext_blob    = 0;
unsigned long mp_ext_slots   = 0;
unsigned long mp_ext_blobcap = 0;
unsigned long mp_ext_inited  = 0;   /* 1 => mpool_init already ran (skip in asm) */
void*         mp_ext_polstate = 0;  /* shared policy state (tx_accept.c) */
void*         mp_ext_feeest   = 0;  /* shared fee estimator (daemon/fee_estimator.c), NULL if absent */
/* fee-estimator glue, WEAK here (see daemon/fee_hooks.c) */
extern unsigned long fest_state_size(unsigned long) __attribute__((weak));
extern int  fest_init(void*, unsigned long) __attribute__((weak));
extern int  fest_read_file(void*, const char*, long) __attribute__((weak));
extern int  node_config_accept_stale_fee(void) __attribute__((weak));   /* -acceptstalefeeestimates */
__attribute__((weak)) void fest_on_forget(const unsigned char* txid){ (void)txid; }
unsigned long mp_ext_polstate_n = 0;

static pthread_mutex_t* g_mp_mutex = 0;   /* in its own shared page */

void mp_lock(void){   if (g_mp_mutex) pthread_mutex_lock(g_mp_mutex); }
void mp_unlock(void){ if (g_mp_mutex) pthread_mutex_unlock(g_mp_mutex); }

/* ---- expiry bookkeeping -------------------------------------------------
 * Open-addressed, same shape as the mempool itself so the two stay in step.
 * Sized to the mempool's slot count; a miss just means we cannot expire that
 * tx, never a wrong deletion. */
typedef struct { unsigned char txid[32]; long t; int used; } mp_seen_t;
static mp_seen_t*   g_seen = 0;
static unsigned long g_seen_mask = 0;
static void*        g_mp_area = 0;

static unsigned long tx_hash(const unsigned char* txid){
    unsigned long h = 1469598103934665603UL;
    for(int i=0;i<32;i++){ h ^= txid[i]; h *= 1099511628211UL; }
    return h;
}

static void mempool_forget(const unsigned char txid[32]);

/* Size the region from Core's -maxmempool (MB). Slots are derived from the
 * byte budget at a conservative ~512B per tx and rounded to a power of two,
 * because mpool indexes with a mask. Returns 1 if a region was published. */
int mempool_configure(void){
    long mb = g_cfg.maxmempool_mb;
    if(mb <= 0) return 0;                       /* 0 == keep the asm statics */

    unsigned long long blob_cap = (unsigned long long)mb << 20;
    unsigned long slots = 1024;
    while(slots < (blob_cap / 512UL) && slots < (1UL<<22)) slots <<= 1;

    unsigned long struct_sz = mpool_struct_size(slots);
    void* area = mmap(0, struct_sz, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    void* blob = mmap(0, (size_t)blob_cap, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if(area==MAP_FAILED || blob==MAP_FAILED){
        if(area!=MAP_FAILED) munmap(area, struct_sz);
        if(blob!=MAP_FAILED) munmap(blob, (size_t)blob_cap);
        fprintf(stderr,"[mempool] could not allocate %ldMB -- falling back to the built-in 2MiB mempool\n", mb);
        return 0;                                /* degrade, never fail boot */
    }
    mp_ext_area    = area;
    mp_ext_blob    = blob;
    mp_ext_slots   = slots;
    mp_ext_blobcap = (unsigned long)blob_cap;
    g_mp_area      = area;

    /* Init the pool ONCE, pre-fork (see coherence note above). */
    mpool_init(area, slots, blob, (unsigned long)blob_cap);
    mp_ext_inited = 1;

    /* Cross-process lock, in its own shared page. If it cannot be set up,
     * fall back to the per-process pools (unshare) rather than run a shared
     * pool without a lock. */
    { void* pg = mmap(0, sizeof(pthread_mutex_t), PROT_READ|PROT_WRITE,
                      MAP_SHARED|MAP_ANONYMOUS, -1, 0);
      pthread_mutexattr_t at;
      if (pg==MAP_FAILED || pthread_mutexattr_init(&at)!=0 ||
          pthread_mutexattr_setpshared(&at, PTHREAD_PROCESS_SHARED)!=0 ||
          pthread_mutex_init((pthread_mutex_t*)pg, &at)!=0){
          if (pg!=MAP_FAILED) munmap(pg, sizeof(pthread_mutex_t));
          munmap(area, struct_sz); munmap(blob, (size_t)blob_cap);
          mp_ext_area=0; mp_ext_blob=0; mp_ext_slots=0; mp_ext_blobcap=0;
          mp_ext_inited=0; g_mp_area=0;
          fprintf(stderr,"[mempool] process-shared lock unavailable -- falling back to the built-in 2MiB mempool\n");
          return 0;
      }
      g_mp_mutex = (pthread_mutex_t*)pg; }

    /* Shared tx-accept policy state (fee/ancestor registry), init'd once
     * pre-fork; tx_accept.c uses this instead of a per-process malloc.
     * SIZE == the pool's slot capacity: the policy graph needs one node per
     * mempool entry, so a smaller cap freezes acceptance the instant the
     * graph fills while the pool still has room -- which is exactly what a
     * fixed 4096 did in production (mempool stuck at exactly 4096, every
     * further tx rejected by mpool_policy_add having no node slot). Sizing
     * to `slots` makes the two limits coincide so it cannot recur. */
    { unsigned long pn = slots;
      unsigned long psz = mpool_policy_state_size(pn);
      void* ps = mmap(0, psz, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
      if (ps!=MAP_FAILED){ mpool_policy_state_init(ps, pn);
                           mpool_policy_set_poolcap(ps, blob_cap);   /* rolling-decay speed-up thresholds */
                           mp_ext_polstate = ps; mp_ext_polstate_n = pn; } }
    /* removals (eviction, RBF, expiry, block reconcile) clear their
     * arrival-time entry through this hook so the parallel table cannot
     * accumulate ghosts of txs the pool no longer holds. */
    mpool_policy_set_forget_cb(mempool_forget);

    /* Shared fee estimator (Core CBlockPolicyEstimator): sized for the pool's
     * slots, seeded from fee_estimates.dat when the file is younger than
     * Core's MAX_FILE_AGE (60 h). Only when the estimator is linked. */
    if (fest_state_size && fest_init){
        unsigned long fsz = fest_state_size(slots * 2);
        void* fe = mmap(0, fsz, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
        if (fe != MAP_FAILED && fest_init(fe, slots * 2)){
            mp_ext_feeest = fe;
            int rr = fest_read_file ? fest_read_file(fe, "fee_estimates.dat", (node_config_accept_stale_fee && node_config_accept_stale_fee()) ? -1 : 60) : 0;
            fprintf(stderr,"[feeest] estimator %s (%lu MB shared)%s\n",
                    rr == 1 ? "seeded from fee_estimates.dat" : rr == -1 ? "started fresh: fee_estimates.dat older than 60h, not used"
                    : rr == -2 ? "started fresh: fee_estimates.dat unreadable (non-fatal)" : "started fresh (no fee_estimates.dat)",
                    fsz >> 20, "");
        } else if (fe != MAP_FAILED) munmap(fe, fsz);
    }

    g_seen_mask = slots - 1;
    g_seen = (mp_seen_t*)mmap(0, sizeof(mp_seen_t)*slots, PROT_READ|PROT_WRITE,
                              MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if(g_seen==MAP_FAILED){ g_seen=0; g_seen_mask=0; }   /* expiry off, pool still sized */

    fprintf(stderr,"[mempool] maxmempool=%ldMB -> %lu slots, %lluMB tx storage (shared, locked%s%s)\n",
            mb, slots, blob_cap>>20,
            mp_ext_polstate?"":", policy state per-process",
            g_seen?"":", expiry tracking unavailable");
    return 1;
}

/* Arrival time of a pool tx (0 if unknown) -- for RPC "time" fields. */
long mempool_time_of(const unsigned char txid[32]){
    if(!g_seen) return 0;
    unsigned long i = tx_hash(txid) & g_seen_mask;
    for(unsigned long p=0; p<=g_seen_mask; p++){
        mp_seen_t* e = &g_seen[(i+p) & g_seen_mask];
        if(!e->used) return 0;
        if(!memcmp(e->txid, txid, 32)) return e->t;
    }
    return 0;
}

/* Record an accepted tx's arrival time. Called from the accept path. */
void mempool_note_accept(const unsigned char txid[32]){
    if(!g_seen) return;
    unsigned long i = tx_hash(txid) & g_seen_mask;
    for(unsigned long p=0; p<=g_seen_mask; p++){
        mp_seen_t* e = &g_seen[(i+p) & g_seen_mask];
        if(!e->used || !memcmp(e->txid, txid, 32)){
            memcpy(e->txid, txid, 32); e->t = (long)time(0); e->used = 1;
            return;
        }
    }
}

/* Clear one arrival-time entry (the policy layer's removal hook). */
static void mempool_forget(const unsigned char txid[32]){
    fest_on_forget(txid);              /* fee estimation: left the pool unconfirmed (or was booked as mined just before) */
    if(!g_seen) return;
    unsigned long i = tx_hash(txid) & g_seen_mask;
    for(unsigned long p=0; p<=g_seen_mask; p++){
        mp_seen_t* e = &g_seen[(i+p) & g_seen_mask];
        if(!e->used) return;
        if(!memcmp(e->txid, txid, 32)){ e->used = 0; return; }
    }
}

/* Evict anything older than -mempoolexpiry hours -- WITH its descendants
 * and its policy-graph bookkeeping (Core CTxMemPool::Expire; the previous
 * structural-only delete left descendant txs with phantom parents and
 * leaked graph slots). Safe to call often. */
long mempool_expire_now(void){
    if(!g_seen || !g_mp_area || !mp_ext_polstate) return 0;
    long hours = g_cfg.mempoolexpiry_h;
    if(hours <= 0) return 0;
    long cutoff = (long)time(0) - hours*3600;
    long removed = 0;
    mp_lock();
    for(unsigned long i=0;i<=g_seen_mask;i++){
        mp_seen_t* e = &g_seen[i];
        if(!e->used || e->t > cutoff) continue;
        unsigned char txid[32]; memcpy(txid, e->txid, 32);
        long r = mpool_policy_expire_one(mp_ext_polstate, g_mp_area, txid);
        if (r > 0) removed += r;
        else e->used = 0;   /* not in the graph (pre-policy legacy entry) */
    }
    mp_unlock();
    if(removed)
        fprintf(stderr,"[mempool] expired %ld tx older than %ldh incl. descendants (%ld remain)\n",
                removed, hours, mpool_count(g_mp_area));
    return removed;
}
