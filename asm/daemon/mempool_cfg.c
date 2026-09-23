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
#include <errno.h>
#include <sys/mman.h>
#include <signal.h>
#include <unistd.h>
#include "node_config.h"
#include "mempool_journal.h"
#include "mempool_seq.h"

extern unsigned long mpool_struct_size(unsigned long slots);
extern void mpool_init(void* mp, unsigned long slots, void* blob, unsigned long blob_cap);
extern long mpool_del(void* mp, const unsigned char txid[32]);
extern long mpool_count(void* mp);
extern unsigned long mpool_policy_state_size(unsigned long n);
extern void mpool_policy_state_init(void* st, unsigned long n);
extern void mpool_policy_set_poolcap(void* st, unsigned long long cap);
extern void mpool_policy_set_forget_cb(void (*fn)(const unsigned char*));
extern const unsigned char* mpool_get(const void*, const unsigned char*, unsigned long*);
extern void sha256d(unsigned char out[32], const void* data, unsigned long len);
extern void mpool_policy_set_depart_cb(void (*fn)(const unsigned char*, unsigned long long,
                                                  unsigned long long, int));
static void mempool_depart(const unsigned char* txid, unsigned long long vsize,
                           unsigned long long fee, int reason);   /* defined below */
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
static int g_mp_robust = 0;               /* MEM-20: PTHREAD_MUTEX_ROBUST armed */

/* ---------------------------------------------------------------- MEM-20
 * (audit 2026-09-03) A process-shared mutex that is not ROBUST turns any
 * crash inside its critical section into a permanent, node-wide outage.
 *
 * Every accept in every inbound serve child holds this across
 * mpool_policy_add, and the download worker holds it across block connect.
 * If ANY of those processes dies in there -- and they are separate processes
 * precisely so one can die without taking the node with it -- the lock stays
 * held forever: the mempool stops accepting in every process, and RPC readers
 * that take it (getblocktemplate's g_gbt_mph.lock) hang rather than answer.
 * MEM-12's longer critical sections widen that window.
 *
 * With ROBUST the kernel hands the next locker EOWNERDEAD instead. The state
 * the dead process was midway through IS rebuildable -- reorg_mempool_reconcile
 * already reconstructs the pool against the chain -- so the right move is to
 * take ownership, say so loudly, and let the node keep serving, rather than
 * wedge. It is NOT silent: a mempool that may have a half-applied entry in it
 * is a thing an operator must know about.
 *
 * Best-effort by design: a platform without robust process-shared mutexes
 * keeps exactly today's behaviour rather than failing mempool_configure and
 * dropping the node to the built-in 2 MiB pool.
 */
/* ---------------------------------------------------------------- 2026-09-19
 * Nothing on a NORMAL stop may die inside this critical section. EOWNERDEAD
 * is the crash path, yet all thirteen of these warnings in the production
 * logs (2026-09-08 through 2026-09-18) were printed during a STOP, by the
 * download worker's first lock after the serve parent's _exit. Two shapes
 * can do it; (1) is the one those logs show:
 *
 *   1. THE PARENT. Its RPC worker threads and the Esplora facade's
 *      connection threads take this lock (getrawmempool, /mempool/txids --
 *      a whole-pool walk that allocates one string per tx under it). The
 *      parent's shutdown ended in _exit(0) from the main thread, which kills
 *      every other thread wherever it is. On 2026-09-18 21:16:18.850 the
 *      mempool.space backend logged "socket hang up" on /mempool/txids at
 *      the same instant the worker logged the warning.
 *   2. AN INBOUND SERVE CHILD. It takes SIGTERM with the default action
 *      (main.c: so a stop does not wait for its peer), and it holds this
 *      lock across a whole accept. systemd's control-group stop signals it
 *      directly, at whatever point it has reached.
 *
 * (2) is closed per thread: SIGTERM and SIGINT are blocked from lock to
 * unlock, so a default-action termination lands just AFTER the unlock. (1) is
 * closed per process by mp_quiesce(), below, which the parent calls before
 * it exits: new entrants park, current holders finish.
 *
 * The gate is process-PRIVATE state (plain statics, copied at fork), which
 * is the point: the parent closing its gate must not close the worker's. A
 * child forked while a parent thread was inside inherits a count that no
 * thread of its own will ever decrement; mp_fork_child_reset() clears it. */
static volatile int g_mp_inflight = 0;      /* this process's threads entering or inside */
static volatile int g_mp_closed   = 0;      /* mp_quiesce ran: park, do not enter */
static unsigned long g_mp_owner_died = 0;   /* EOWNERDEAD recoveries seen by this process */
static __thread sigset_t g_mp_saved_mask;
static void mp_park(void){ for (;;) sleep(3600); }   /* until the process exits */
void mp_lock(void){
    if (!g_mp_mutex) return;
    if (g_mp_closed) mp_park();
    __atomic_add_fetch(&g_mp_inflight, 1, __ATOMIC_SEQ_CST);
    if (g_mp_closed){ __atomic_sub_fetch(&g_mp_inflight, 1, __ATOMIC_SEQ_CST); mp_park(); }
    { sigset_t term; sigemptyset(&term); sigaddset(&term, SIGTERM); sigaddset(&term, SIGINT);
      pthread_sigmask(SIG_BLOCK, &term, &g_mp_saved_mask); }
    int r = pthread_mutex_lock(g_mp_mutex);
    if (r == EOWNERDEAD){
        /* the previous holder died inside the critical section */
        pthread_mutex_consistent(g_mp_mutex);
        g_mp_owner_died++;
        fprintf(stderr,
            "[mempool] WARNING: a process died holding the mempool lock; the lock has\n"
            "[mempool]          been recovered and the node keeps running, but the pool\n"
            "[mempool]          may hold a partially-applied entry. It is rebuilt from\n"
            "[mempool]          the chain on the next reorg reconcile; restart if you\n"
            "[mempool]          want it rebuilt now.\n");
    }
}
void mp_unlock(void){
    if (!g_mp_mutex) return;
    pthread_mutex_unlock(g_mp_mutex);
    sigset_t m = g_mp_saved_mask;                /* copy first: a pending SIGTERM may end us in the call */
    __atomic_sub_fetch(&g_mp_inflight, 1, __ATOMIC_SEQ_CST);
    pthread_sigmask(SIG_SETMASK, &m, NULL);
}
/* Close this process's gate and wait (bounded) for its threads to leave the
 * critical section. Returns how many are still inside at the bound (0 = the
 * process may now exit without leaving the lock EOWNERDEAD). The calling
 * thread must not be inside, and must not take the lock afterwards. */
int mp_quiesce(long max_ms){
    __atomic_store_n(&g_mp_closed, 1, __ATOMIC_SEQ_CST);
    struct timespec t0, t; clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;){
        int n = __atomic_load_n(&g_mp_inflight, __ATOMIC_SEQ_CST);
        if (n <= 0) return 0;
        clock_gettime(CLOCK_MONOTONIC, &t);
        if ((t.tv_sec - t0.tv_sec) * 1000L + (t.tv_nsec - t0.tv_nsec) / 1000000L >= max_ms) return n;
        usleep(1000);
    }
}
void mp_fork_child_reset(void){ g_mp_inflight = 0; g_mp_closed = 0; }
unsigned long mp_lock_owner_died_count(void){ return g_mp_owner_died; }

/* for the test: 1 when the shared lock was created ROBUST */
int mp_lock_is_robust(void){ return g_mp_robust; }

/* ---- expiry bookkeeping -------------------------------------------------
 * Open-addressed, same shape as the mempool itself so the two stay in step.
 * Sized to the mempool's slot count; a miss just means we cannot expire that
 * tx, never a wrong deletion. */
/* The arrival-time table: open-addressed, linear probing, MAP_SHARED so every
 * forked process sees the same entries.
 *
 * `used` IS THREE-VALUED, and that is the whole point. It was a flag, and
 * deletion cleared it -- classic open addressing with no tombstone, which
 * breaks the probe: an entry that landed past a collision becomes unreachable
 * the moment something AHEAD of it in its chain is removed, because every
 * lookup stops at the first empty slot. mempool_time_of then returned 0
 * silently, which feeds getrawmempool's "time", the departure journal's
 * first_seen, and the mempool.dat arrival-time restore -- 50 of 16,457
 * restores failed on 2026-09-16 for exactly this reason. Worse,
 * mempool_note_accept would then insert a SECOND entry for the same txid at
 * the freed slot, and mempool_forget clears only the first.
 *
 * MPS_DEAD is a tombstone: lookups walk past it, inserts REUSE it. Reuse is
 * what bounds the table -- every accept can reclaim one departure's slot, so
 * a steady-state pool does not accumulate them. That reuse is NOT covered by
 * a test: the table is ~4M slots, so any fixture small enough to run finds an
 * empty slot whether or not tombstones are reused, and the assertion would
 * pass either way. It is stated here instead of claimed there. Compaction would be the other
 * answer and is deliberately NOT done here: it moves entries, and this table
 * is written by several processes with no lock (mempool_note_accept runs
 * after mp_unlock in daemon/tx_accept.c). A tombstone write is one word, the
 * same as the flag it replaces, so it is exactly as safe as what it replaces. */
enum { MPS_EMPTY = 0, MPS_LIVE = 1, MPS_DEAD = 2, MPS_CLAIMED = 3 };
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
unsigned long mp_ext_blob_cap = 0;   /* the published byte budget (tests; getmempoolinfo reads the pool's own) */
int mempool_configure(void){
    /* The sequence area first, and unconditionally: 'C'/'D' and the counter
     * getrawmempool reports exist whatever the pool is sized to. */
    mempool_seq_configure();
    long mb = g_cfg.maxmempool_mb;
    if(mb <= 0) return 0;                       /* 0 == keep the asm statics */

    /* Core's -maxmempool is in MB of 1,000,000 bytes (DEFAULT_MAX_MEMPOOL_SIZE_MB
     * * 1'000'000; getmempoolinfo reports 300000000 for the default). This
     * used MiB and reported 314572800 -- the REST differential against Core
     * caught it (2026-09-08). */
    unsigned long long blob_cap = (unsigned long long)mb * 1000000ULL;
    mp_ext_blob_cap = (unsigned long)blob_cap;
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
      /* MEM-20: ROBUST is requested but NOT required -- see mp_lock above. */
      int rb = 0;
      if (pg!=MAP_FAILED && pthread_mutexattr_init(&at)==0){
          if (pthread_mutexattr_setpshared(&at, PTHREAD_PROCESS_SHARED)==0 &&
              pthread_mutexattr_setrobust(&at, PTHREAD_MUTEX_ROBUST)==0)
              rb = 1;
          pthread_mutexattr_destroy(&at);
      }
      g_mp_robust = rb;
      if (pg==MAP_FAILED || pthread_mutexattr_init(&at)!=0 ||
          pthread_mutexattr_setpshared(&at, PTHREAD_PROCESS_SHARED)!=0 ||
          (rb && pthread_mutexattr_setrobust(&at, PTHREAD_MUTEX_ROBUST)!=0) ||
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
    /* the departure journal: opened below only when mempooljournal= is set, so
     * registering the hook unconditionally costs one branch per removal */
    mpool_policy_set_depart_cb(mempool_depart);
    /* Open the departure ring if the operator asked for one. A failure here is
     * NOT fatal and never touches an existing file it does not recognise: the
     * node runs exactly as it did before, minus the journal, and says so. */
    if (g_cfg.mempooljournal > 0){
        /* relative, like addrindex.tail: the daemon has already chdir'd into
         * the chain datadir by this point */
        if (mpj_open(MPJ_FILE, (uint64_t)g_cfg.mempooljournal))
            fprintf(stderr, "[mempool] departure journal: %llu records (%llu MB) in %s%s\n",
                    (unsigned long long)mpj_capacity(),
                    (unsigned long long)(MPJ_FILE_BYTES(mpj_capacity()) >> 20), MPJ_FILE,
                    (uint64_t)g_cfg.mempooljournal != mpj_capacity()
                        ? " (the EXISTING file's capacity, not the configured one)" : "");
        else
            fprintf(stderr, "[mempool] departure journal UNAVAILABLE (%s exists and is not one, "
                            "or could not be created) -- running without it\n", MPJ_FILE);
    }

    /* MEM-10: the shared "already refused" memory, allocated BEFORE the serve
     * children fork so a transaction one child refused is not re-fetched by
     * the next. Weakly referenced so the tools that link this file without
     * the serve path still build. */
    { extern unsigned long serve_rejects_size(void) __attribute__((weak));
      extern void serve_rejects_attach(void*) __attribute__((weak));
      if (serve_rejects_size && serve_rejects_attach){
          unsigned long rsz = serve_rejects_size();
          void* rj = mmap(0, rsz, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
          if (rj != MAP_FAILED){
              serve_rejects_attach(rj);
              fprintf(stderr,"[mempool] recent-rejects filter: %lu KB shared "
                             "(inbound announcements of an already-refused tx cost nothing)\n", rsz >> 10);
          }
      } }

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
        int st = __atomic_load_n(&e->used, __ATOMIC_ACQUIRE);
        if(st == MPS_EMPTY) return 0;                    /* the chain really ends */
        if(st == MPS_LIVE && !memcmp(e->txid, txid, 32)) return e->t;
        /* MPS_DEAD / MPS_CLAIMED: walk past -- the entry may live further along */
    }
    return 0;
}

/* Record an accepted tx's arrival time. Called from the accept path.
 *
 * THE SLOT IS CLAIMED WITH AN ATOMIC CAS, and that is not decoration. This
 * table is written by SEVERAL PROCESSES: the node forks per connection, the
 * mapping is MAP_SHARED, and mempool_note_accept runs AFTER mp_unlock in
 * daemon/tx_accept.c -- so the pool lock is not held and two accepts can probe
 * to the same free slot at the same moment. A plain write there loses one of
 * them, and a plain read of a half-written txid matches nothing, so an arrival
 * time simply disappears.
 *
 * A MUTEX IS NOT THE ANSWER HERE, and the reason is worth recording so nobody
 * "fixes" this by adding one: mempool_expire_now calls into the POLICY LAYER
 * while iterating this table, and that path comes back through
 * mempool_forget. A lock held across the iteration would meet itself, and
 * mp_lock's mutex has no settype, so it is non-recursive and would deadlock a
 * production node. Claiming a slot needs no lock, cannot deadlock, and needs
 * no ordering discipline against the pool lock.
 *
 * NOT COVERED BY A TEST, and kept on reasoning: the CAS itself, and lookups
 * skipping MPS_CLAIMED. Both need two processes at the same FREE slot in the
 * same instant, and tests/test_mempool_shared cannot produce that against ~4M
 * slots -- reverting either one does not fail it. Without the CAS, two
 * processes memcpy a txid into one slot and the result matches nothing: the
 * entry is unreachable AND unremovable (forget will not match it either)
 * until the expiry sweep. That is worse than the lost insert it also causes.
 *
 * MPS_CLAIMED is why lookups must treat it like a tombstone rather than like
 * an empty slot: an insert in flight sits in the middle of somebody else's
 * probe chain, and a lookup that stopped there would miss every entry behind
 * it -- the same class of bug the tombstone fixed.
 *
 * The same-txid duplicate that this creates is resolved after publishing, by
 * probe-order tie-break -- see the comment at that point. It was first written
 * off here as "a narrow window"; a contention test then produced 889 of them
 * out of 3,000, so it is handled rather than tolerated. */
void mempool_note_accept(const unsigned char txid[32]){
    if(!g_seen) return;
    unsigned long i = tx_hash(txid) & g_seen_mask;
    for(unsigned long p=0; p<=g_seen_mask; p++){
        mp_seen_t* e = &g_seen[(i+p) & g_seen_mask];
        int st = __atomic_load_n(&e->used, __ATOMIC_ACQUIRE);
        if(st == MPS_LIVE){
            if(!memcmp(e->txid, txid, 32)){
                __atomic_store_n(&e->t, (long)time(0), __ATOMIC_RELAXED);   /* already here: refresh */
                return; }
            continue;                                    /* a collision, keep probing */
        }
        if(st == MPS_CLAIMED) continue;                  /* somebody else is filling it */
        /* EMPTY or DEAD: try to take it. Losing the race means another process
         * got there first, so keep probing rather than overwrite its entry. */
        int want = st;
        if(!__atomic_compare_exchange_n(&e->used, &want, MPS_CLAIMED, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) continue;
        memcpy(e->txid, txid, 32);
        e->t = (long)time(0);
        __atomic_store_n(&e->used, MPS_LIVE, __ATOMIC_RELEASE);   /* publish last */

        /* INSERT, THEN VERIFY. Two processes accepting the same txid can both
         * pass the LIVE scan above before either publishes, and both then own
         * a slot: a duplicate. That is not the rare event it looks like -- six
         * processes inserting 3,000 shared ids produced 889 of them. It
         * matters because mempool_forget clears only the FIRST copy, so the
         * second survives as a ghost holding a stale arrival time for a
         * transaction the pool no longer has.
         *
         * The tie-break is the probe order, which every process computes
         * identically: walk the chain from the hash position, and whoever sits
         * EARLIEST keeps the entry. A later duplicate stands itself down. Both
         * cannot stand down -- the earliest one always finds itself first. */
        for(unsigned long q=0; q<=g_seen_mask; q++){
            mp_seen_t* o = &g_seen[(i+q) & g_seen_mask];
            if(o == e) break;                            /* we are the earliest: keep it */
            if(__atomic_load_n(&o->used, __ATOMIC_ACQUIRE) == MPS_LIVE &&
               !memcmp(o->txid, txid, 32)){
                int mine = MPS_LIVE;                     /* someone earlier has it: stand down */
                __atomic_compare_exchange_n(&e->used, &mine, MPS_DEAD, 0,
                                            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
                break;
            }
        }
        return;
    }
}

/* ---- the departure journal (2026-09-16) -----------------------------------
 * Called by the policy layer as a transaction leaves the pool, with the vsize,
 * fee and reason it holds at that moment. This is the LAST point at which the
 * arrival time still exists: mempool_forget clears it immediately after, and
 * once the pool has dropped the entry there is nowhere left to learn when the
 * transaction first arrived. That is exactly the fact an explorer needs and
 * Core cannot give -- "broadcast at T, evicted at T+6h, never mined".
 *
 * The journal being closed is the normal case (it is off unless configured),
 * and mpj_append is a no-op then, so this costs a call and a branch. */
static void mempool_depart(const unsigned char* txid, unsigned long long vsize,
                           unsigned long long fee, int reason){
    if (!mpj_is_open()) return;
    mpj_rec r;
    memset(&r, 0, sizeof r);
    memcpy(r.txid, txid, 32);
    /* wtxid. The structural pool caches one per slot but exposes it only BY
     * SLOT (mpool_wtxid_at_slot), and there is no by-txid getter -- adding one
     * means editing bitcoin_mempool.asm's probe, which carries the MEM-21
     * coherence rules and is not a file to touch for a display field.
     *
     * It does not need touching. The cached value is sha256d over the tx bytes
     * AS STORED (bitcoin_mempool.asm's own note; it equals the txid for a
     * non-witness transaction), and the departure hook fires BEFORE mpool_del
     * -- so the transaction is still in the pool here and the bytes are still
     * readable. Recomputing costs one hash per departure, and only when the
     * journal is enabled, so nothing is paid for a feature that is off.
     *
     * Leaving it zero was the honest placeholder; copying the TXID in would
     * not have been. That is right only for a non-witness transaction and
     * silently wrong for every segwit one, which is most of them. */
    { unsigned long rawlen = 0;
      const unsigned char* raw = g_mp_area ? mpool_get(g_mp_area, txid, &rawlen) : 0;
      if (raw && rawlen) sha256d(r.wtxid, raw, rawlen);
      /* else: still zero, and readers treat all-zero as "not recorded" */ }
    r.first_seen  = mempool_time_of(txid);
    r.departed_at = (long)time(0);
    r.vsize       = vsize;
    r.fee_sat     = fee;
    r.reason      = (uint32_t)reason;
    mpj_append(&r);
}

/* Restore a persisted arrival time (mempool.dat's per-transaction entry_time).
 *
 * WHY: mempool_note_accept stamps "now", which is right for a transaction
 * arriving off the wire and WRONG for one being re-admitted from mempool.dat
 * at startup -- that transaction may have been waiting for hours. Without
 * this, every restart resets the pool's sense of age: the departure journal
 * reported 2,189 rows with waited: 1 after the 2026-09-16 deploy, which was
 * an artifact of the restart rather than a fast-confirming mempool, and
 * -mempoolexpiry likewise started every transaction's 336-hour clock again.
 * Core restores the time (node/mempool_persist.cpp LoadMempool); this node
 * discarded it and said so in RPC_LIVE_NODE.md. Now it does not.
 *
 * THE TIME IS NOT TRUSTED BLINDLY. mempool.dat is a file on disk that a
 * restart reads before anything else has vetted it, and the arrival time is
 * an INPUT TO EXPIRY: a time far in the future would keep a transaction in
 * the pool forever, and one far in the past would evict it instantly. So a
 * value is applied only when it is in the past AND inside the expiry window;
 * anything else leaves the fresh stamp, which is the safe direction. Core
 * makes the same judgement differently -- it refuses to re-add a transaction
 * whose stored time is already past the window -- and this reaches the same
 * place from the other side, because the accept has already happened by the
 * time the sink sees the record.
 *
 * Returns 1 when the stored time was applied, 0 when it was rejected or the
 * transaction is not in the table. */
int mempool_restore_accept_time(const unsigned char txid[32], long t){
    if(!g_seen || t <= 0) return 0;
    long now = (long)time(0);
    if(t > now) return 0;                                  /* the future: refuse */
    long hours = g_cfg.mempoolexpiry_h > 0 ? g_cfg.mempoolexpiry_h : 336;
    if(t < now - hours*3600) return 0;                     /* already past expiry: refuse */
    unsigned long i = tx_hash(txid) & g_seen_mask;
    for(unsigned long p=0; p<=g_seen_mask; p++){
        mp_seen_t* e = &g_seen[(i+p) & g_seen_mask];
        int st = __atomic_load_n(&e->used, __ATOMIC_ACQUIRE);
        if(st == MPS_EMPTY) return 0;                      /* not in the pool: nothing to correct */
        if(st == MPS_LIVE && !memcmp(e->txid, txid, 32)){
            __atomic_store_n(&e->t, t, __ATOMIC_RELAXED); return 1; }
    }
    return 0;
}

/* Clear one arrival-time entry (the policy layer's removal hook). */
/* the removal hook, reachable by name so a test can drive the probe directly
 * (the policy layer reaches it through the callback) */
void mempool_forget_for_test(const unsigned char txid[32]){ mempool_forget(txid); }
static void mempool_forget(const unsigned char txid[32]){
    fest_on_forget(txid);              /* fee estimation: left the pool unconfirmed (or was booked as mined just before) */
    if(!g_seen) return;
    unsigned long i = tx_hash(txid) & g_seen_mask;
    for(unsigned long p=0; p<=g_seen_mask; p++){
        mp_seen_t* e = &g_seen[(i+p) & g_seen_mask];
        int st = __atomic_load_n(&e->used, __ATOMIC_ACQUIRE);
        if(st == MPS_EMPTY) return;                      /* the chain ends: done */
        if(st == MPS_LIVE && !memcmp(e->txid, txid, 32)){
            /* CAS so a slot being re-claimed underneath is not stamped DEAD */
            int want = MPS_LIVE;
            __atomic_compare_exchange_n(&e->used, &want, MPS_DEAD, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
            /* KEEP WALKING: there may be more than one copy. Two processes
             * accepting the same txid can both publish before either sees the
             * other -- the probe-order tie-break below closes the common case
             * but not the window where the loser scans before the winner
             * publishes. Clearing only the first copy left the second alive as
             * a GHOST: an arrival time for a transaction the pool no longer
             * holds, which mempool_time_of would keep answering. Clearing all
             * of them makes the duplicate cost a slot instead of a wrong
             * answer, and costs one extra walk of a chain we are already in. */
        }
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
        if(__atomic_load_n(&e->used, __ATOMIC_ACQUIRE) != MPS_LIVE || e->t > cutoff) continue;
        unsigned char txid[32]; memcpy(txid, e->txid, 32);
        long r = mpool_policy_expire_one(mp_ext_polstate, g_mp_area, txid);
        if (r > 0) removed += r;
        else e->used = MPS_DEAD;   /* not in the graph (pre-policy legacy entry) */
    }
    mp_unlock();
    if(removed)
        fprintf(stderr,"[mempool] expired %ld tx older than %ldh incl. descendants (%ld remain)\n",
                removed, hours, mpool_count(g_mp_area));
    return removed;
}

/* ---- the mempool sequence (Core m_sequence_number) and the ZMQ `sequence`
 * event ring. The why is in mempool_seq.h; what is here is the mechanics.
 *
 * WRITERS: mempool_seq_note (the policy layer's hook: every accept and every
 * removal, from whichever process mutated the pool, under mp_lock),
 * mempool_seq_emit (the reorg reconcile's net difference, under mp_lock),
 * mempool_seq_block[_locked] (block connect in tx_accept.c / main.c, block
 * disconnect in reorg.c). READERS: the download worker's zmqn_drain (the
 * ring) and getrawmempool's mempool_sequence through rpc_mempool_hooks (the
 * counter). */
extern void mpool_policy_set_seq_cb(void (*fn)(const unsigned char*, int));
static mpseq_area_t* g_seq = 0;
/* per PROCESS, and that is enough: only the worker's reorg reconcile sets it,
 * and it does so while holding mp_lock, so no other process can mutate the
 * pool -- and so reach the hook -- while it is set */
static int g_seq_hold = 0;

mpseq_area_t* mpseq_area(void){ return g_seq; }

int mempool_seq_configure(void){
    if (g_seq) return 1;
    void* a = mmap(0, sizeof(mpseq_area_t), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (a == MAP_FAILED){
        fprintf(stderr, "[mempool] sequence area unavailable (%zu bytes): the ZMQ sequence topic "
                        "and getrawmempool's mempool_sequence will not advance\n", sizeof(mpseq_area_t));
        return 0;
    }
    g_seq = (mpseq_area_t*)a;       /* anonymous mappings arrive zeroed */
    g_seq->next = 1;                /* Core: m_sequence_number{1} */
    mpool_policy_set_seq_cb(mempool_seq_note);
    return 1;
}

unsigned long long mempool_sequence(void){
    return g_seq ? __atomic_load_n(&g_seq->next, __ATOMIC_ACQUIRE) : 1;
}

void mempool_seq_hold(int on){ g_seq_hold = on ? 1 : 0; }

static void mpseq_push(const unsigned char hash[32], int label, unsigned long long mseq){
    unsigned long long slot = __atomic_fetch_add(&g_seq->head, 1ULL, __ATOMIC_ACQ_REL);
    mpseq_ev* e = &g_seq->ev[slot % MPSEQ_RING];
    /* a reader lapped onto this slot must not take it while it is refilled */
    __atomic_store_n(&e->ready, 0ULL, __ATOMIC_RELEASE);
    memcpy(e->hash, hash, 32);
    e->label = (unsigned char)label;
    e->mseq  = mseq;
    __atomic_store_n(&e->ready, slot + 1, __ATOMIC_RELEASE);   /* fill BEFORE announcing */
}

void mempool_seq_emit(const unsigned char txid[32], int kind){
    if (!g_seq || !txid) return;
    /* Every add and every removal takes a number -- a BLOCK removal ('M')
     * too, which is the one kind Core does not publish (removeUnchecked). */
    unsigned long long mseq = __atomic_fetch_add(&g_seq->next, 1ULL, __ATOMIC_ACQ_REL);
    if (kind == 'A' || kind == 'R') mpseq_push(txid, kind, mseq);
}

void mempool_seq_note(const unsigned char txid[32], int kind){
    if (g_seq_hold) return;
    mempool_seq_emit(txid, kind);
}

void mempool_seq_block_locked(const unsigned char hash[32], int label){
    if (!g_seq || !hash || (label != 'C' && label != 'D')) return;
    mpseq_push(hash, label, 0);
}

void mempool_seq_block(const unsigned char hash[32], int label){
    mp_lock();
    mempool_seq_block_locked(hash, label);
    mp_unlock();
}
