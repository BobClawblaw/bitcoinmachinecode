/* test_mempool_shared.c -- the shared-mempool coherence slice (2026-08-25).
 *
 * Proves the property the whole slice exists for: a tx put into the pool by
 * ONE process is visible to ANOTHER process through the same pre-fork
 * MAP_SHARED region -- exactly the daemon's shape, where inbound serve
 * children and the download worker write and the parent's RPC thread reads.
 * Before this slice the region was MAP_PRIVATE and every process had a
 * divergent copy-on-write pool (the parent's getrawmempool was always empty).
 *
 * Also pins the two load-bearing details:
 *   - mp_ext_inited: mpool_init ran ONCE at configure time; a second process
 *     must NOT re-init (bitcoin_serve.asm's per-process lazy init would have
 *     wiped the shared pool on every inbound connection).
 *   - the cross-process mutex actually works from the child (a
 *     PTHREAD_PROCESS_SHARED lock taken+released across fork()).
 */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../daemon/node_config.h"

extern int  mempool_configure(void);
extern void mp_lock(void);
extern void mp_unlock(void);
extern long mempool_time_of(const unsigned char* txid);
extern void mempool_note_accept(const unsigned char* txid);
extern int  mempool_restore_accept_time(const unsigned char* txid, long t);
extern void mempool_forget_for_test(const unsigned char* txid);
extern void* mp_ext_area;
extern unsigned long mp_ext_slots;
extern unsigned long mp_ext_inited;
extern void* mp_ext_polstate;
extern unsigned long mp_ext_blob_cap;
extern long mpool_put(void* mp, const unsigned char txid[32],
                      const unsigned char* tx, unsigned long txlen);
extern long mpool_count(void* mp);
extern const unsigned char* mpool_get(void* mp, const unsigned char txid[32],
                                      unsigned long* out_len);
extern long mpool_policy_entry(void*, const unsigned char*,
                               unsigned long long*, unsigned long long*);

static int fails=0, checks=0;
static void ck(const char* what, int cond){ checks++; if(cond) printf("ok  : %s\n",what); else { printf("FAIL: %s\n",what); fails++; } }

/* Link stub (same pattern as test_txv_cs_maxsize.c): bitcoin_mempool_policy.c
 * references the UTXO resolver, but this test exercises structural sharing
 * only -- mpool_policy_add is never called, so this can never be reached. */
long mempool_resolve_confirmed_utxo(void* u, const unsigned char* t, unsigned long i,
                                    unsigned long long* v, const unsigned char** sp,
                                    unsigned long* sl){
    (void)u;(void)t;(void)i;(void)v;(void)sp;(void)sl; return 0;
}

int main(void){
    /* Size the pool exactly the way the daemon does (-maxmempool). */
    g_cfg.maxmempool_mb = 8;
    ck("mempool_configure(8MB)", mempool_configure() == 1);
    ck("region published", mp_ext_area != NULL && mp_ext_slots >= 1024);
    ck("the budget is Core's MB: 8 -> 8,000,000 bytes (was MiB: 8,388,608; getmempoolinfo reported 314572800 for the default)", mp_ext_blob_cap == 8000000UL);
    ck("pool init'd ONCE at configure (mp_ext_inited)", mp_ext_inited == 1);
    ck("policy state shared region published", mp_ext_polstate != NULL);
    ck("pool starts empty", mpool_count(mp_ext_area) == 0);
    ck("policy_entry on empty state -> miss",
       mpool_policy_entry(mp_ext_polstate, (const unsigned char*)"0123456789abcdef0123456789abcdef", 0, 0) == 0);

    unsigned char txid1[32], txid2[32], tx1[64], tx2[80];
    memset(txid1, 0x11, 32); memset(tx1, 0xAA, sizeof tx1);
    memset(txid2, 0x22, 32); memset(tx2, 0xBB, sizeof tx2);

    /* ---- the point of the slice: child writes, parent sees ---- */
    pid_t pid = fork();
    if (pid == 0){
        /* CHILD: same flow as an inbound serve child's accept -- lock, put,
         * stamp arrival. Exit code carries its own view of the count. */
        mp_lock();
        long r1 = mpool_put(mp_ext_area, txid1, tx1, sizeof tx1);
        long r2 = mpool_put(mp_ext_area, txid2, tx2, sizeof tx2);
        mp_unlock();
        mempool_note_accept(txid1);
        _exit((r1==1 && r2==1 && mpool_count(mp_ext_area)==2) ? 0 : 1);
    }
    int st=-1; waitpid(pid, &st, 0);
    ck("child put 2 txs under the shared lock", WIFEXITED(st) && WEXITSTATUS(st)==0);
    ck("PARENT sees both txs (MAP_SHARED, not CoW)", mpool_count(mp_ext_area) == 2);
    unsigned long l1=0, l2=0;
    const unsigned char* p1 = mpool_get(mp_ext_area, txid1, &l1);
    const unsigned char* p2 = mpool_get(mp_ext_area, txid2, &l2);
    ck("parent reads tx1 bytes back", p1 && l1==sizeof tx1 && p1[0]==0xAA);
    ck("parent reads tx2 bytes back", p2 && l2==sizeof tx2 && p2[0]==0xBB);
    ck("arrival time visible cross-process", mempool_time_of(txid1) > 0);
    ck("no arrival record for un-stamped tx", mempool_time_of(txid2) == 0);

    /* ---- a second process must ADOPT, never re-init (serve.asm contract):
     * with mp_ext_inited set, the pool it inherits still holds both txs. ---- */
    pid = fork();
    if (pid == 0){
        _exit((mp_ext_inited==1 && mpool_count(mp_ext_area)==2) ? 0 : 1);
    }
    st=-1; waitpid(pid, &st, 0);
    ck("fresh child adopts (init-once survives fork)", WIFEXITED(st) && WEXITSTATUS(st)==0);

    /* lock sanity from the parent after all the cross-process traffic */
    mp_lock(); mp_unlock();
    ck("lock still usable in parent", 1);

    /* ---- MEM-20 (audit 2026-09-03): a holder that DIES must not wedge the
     * node.
     *
     * The shared mutex was PTHREAD_PROCESS_SHARED but not
     * PTHREAD_MUTEX_ROBUST. Every accept in every inbound serve child holds
     * it across mpool_policy_add and the worker holds it across block
     * connect, so a crash in any of those processes left it held forever:
     * the mempool stopped accepting in EVERY process and RPC readers that
     * take it hung. The processes are separate precisely so one can die
     * without taking the node down.
     *
     * The child below takes the lock and _exit()s still holding it -- the
     * exact shape of a crash in a critical section. The parent must then be
     * able to lock. An alarm is the assertion: without ROBUST this call
     * blocks forever and the alarm kills the test, which is what makes this
     * a control rather than a restatement. */
    {
        extern int mp_lock_is_robust(void);
        ck("MEM-20 the shared lock is ROBUST", mp_lock_is_robust() == 1);

        pid_t dp = fork();
        if (dp == 0){
            mp_lock();          /* take it and die still holding it */
            _exit(0);
        }
        int dst = -1; waitpid(dp, &dst, 0);
        ck("MEM-20 the child exited while holding the lock",
           WIFEXITED(dst) && WEXITSTATUS(dst) == 0);

        /* If the lock were not robust this blocks forever. */
        alarm(10);
        mp_lock();
        mp_unlock();
        alarm(0);
        ck("MEM-20 the parent still acquires the lock after the holder died", 1);

        /* and it is still usable afterwards, i.e. consistent() really ran --
         * a mutex left EOWNERDEAD-but-not-made-consistent goes
         * ENOTRECOVERABLE and every later lock fails for good. */
        alarm(10);
        mp_lock();
        mp_unlock();
        alarm(0);
        ck("MEM-20 and remains usable on the next acquisition", 1);
    }


    /* ---- deletion must not hide a colliding entry -------------------------
     * The table is open-addressed with linear probing, and deletion used to
     * clear the in-use flag outright. That breaks the probe: an entry that
     * landed PAST a collision becomes unreachable the moment something ahead
     * of it in its chain is removed, because every lookup stops at the first
     * empty slot. mempool_time_of then answered 0 with no error -- and that
     * value feeds getrawmempool's "time", the departure journal's first_seen,
     * and the mempool.dat arrival-time restore, where 50 of 16,457 restores
     * failed on 2026-09-16 for exactly this reason.
     *
     * Finding a real collision means inserting until two txids share a slot.
     * Rather than reverse the hash, insert a run of transactions, remove the
     * FIRST one inserted, and require every survivor to still be findable:
     * with enough entries some of them collide, and under the old behaviour
     * the ones behind the hole vanished. */
    {
        enum { N = 4096 };
        unsigned char ids[N][32];
        for (int i = 0; i < N; i++){
            memset(ids[i], 0, 32);
            ids[i][0] = (unsigned char)(i & 0xff);
            ids[i][1] = (unsigned char)((i >> 8) & 0xff);
            ids[i][2] = 0xC7;                 /* keep them clear of the other fixtures */
            mempool_note_accept(ids[i]);
        }
        int all_before = 1;
        for (int i = 0; i < N; i++) if (mempool_time_of(ids[i]) == 0) all_before = 0;
        ck("every entry is findable before any removal", all_before);

        /* remove a scattered quarter of them */
        for (int i = 0; i < N; i += 4) mempool_forget_for_test(ids[i]);

        int lost = 0;
        for (int i = 0; i < N; i++) if (i % 4 && mempool_time_of(ids[i]) == 0) lost++;
        ck("...and every SURVIVOR is still findable after the removals", lost == 0);
        if (lost) printf("      %d of %d survivors became unreachable\n", lost, N - N/4);

        int ghosts = 0;
        for (int i = 0; i < N; i += 4) if (mempool_time_of(ids[i]) != 0) ghosts++;
        ck("...and every removed entry really is gone", ghosts == 0);

        /* A removed entry can be re-added and found again. NOTE what this does
         * NOT prove: that the insert REUSED the tombstone. The table has ~4M
         * slots and this fixture uses 4,096, so an insert that skipped every
         * tombstone would still find an empty slot and still be findable --
         * reverting the reuse changes nothing here. Proving reuse needs the
         * table driven to exhaustion, which is not practical at this size, so
         * the property is stated in mempool_cfg.c and left uncovered rather
         * than claimed by an assertion that cannot fail. */
        for (int i = 0; i < N; i += 4) mempool_note_accept(ids[i]);
        int back = 0;
        for (int i = 0; i < N; i += 4) if (mempool_time_of(ids[i]) != 0) back++;
        ck("a removed entry can be re-added and found (reuse itself is untested)", back == N / 4);

        /* and re-accepting an entry that is already live must not duplicate it:
         * a duplicate survives the first forget and becomes a ghost */
        mempool_note_accept(ids[1]);
        mempool_note_accept(ids[1]);
        mempool_forget_for_test(ids[1]);
        ck("re-accepting a live entry does not create a duplicate",
           mempool_time_of(ids[1]) == 0);

        for (int i = 0; i < N; i++) mempool_forget_for_test(ids[i]);
    }

    /* ---- the persisted arrival time (mempool.dat entry_time) --------------
     * mempool_note_accept stamps "now", which is right off the wire and WRONG
     * for a transaction being re-admitted from mempool.dat at startup: it may
     * have been waiting for hours. Without the restore, every restart resets
     * the pool's sense of age -- the departure journal wrote 2,189 rows with
     * waited: 1 after the 2026-09-16 deploy, an artifact of the restart, and
     * -mempoolexpiry likewise began every transaction's 336-hour clock again.
     *
     * THE VALUE IS NOT TRUSTED. mempool.dat is read at startup before anything
     * has vetted it, and this field is an INPUT TO EXPIRY: a time in the
     * future would keep a transaction in the pool forever, one far in the past
     * would evict it instantly. Those two refusals are the checks that matter
     * here -- the happy path is the easy half. */
    {
        unsigned char tx_r[32]; memset(tx_r, 0xD1, 32);
        mempool_note_accept(tx_r);
        long fresh = mempool_time_of(tx_r);
        ck("a fresh accept is stamped now", fresh > 0);

        long now = (long)time(0);
        ck("a plausible past time IS restored",
           mempool_restore_accept_time(tx_r, now - 3600) == 1);
        ck("...and the table now reports it", mempool_time_of(tx_r) == now - 3600);

        /* a time in the FUTURE would defeat expiry entirely */
        ck("a FUTURE time is refused", mempool_restore_accept_time(tx_r, now + 86400) == 0);
        ck("...and the previous value stands", mempool_time_of(tx_r) == now - 3600);

        /* a time older than the expiry window would evict it on the next sweep */
        ck("a time PAST the expiry window is refused",
           mempool_restore_accept_time(tx_r, now - 400L*3600L) == 0);
        ck("...and the previous value still stands", mempool_time_of(tx_r) == now - 3600);

        ck("a zero time is refused", mempool_restore_accept_time(tx_r, 0) == 0);
        ck("a negative time is refused", mempool_restore_accept_time(tx_r, -5) == 0);

        /* a transaction that is not in the pool has nothing to correct */
        unsigned char absent[32]; memset(absent, 0xE7, 32);
        ck("restoring a time for an absent transaction is a no-op",
           mempool_restore_accept_time(absent, now - 60) == 0);
        ck("...and it is NOT inserted by the attempt", mempool_time_of(absent) == 0);
    }

    printf("\n%s (%d checks, %d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", checks, fails);
    return fails?1:0;
}
