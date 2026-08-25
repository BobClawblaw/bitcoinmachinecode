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
#include <sys/wait.h>
#include <unistd.h>
#include "../daemon/node_config.h"

extern int  mempool_configure(void);
extern void mp_lock(void);
extern void mp_unlock(void);
extern long mempool_time_of(const unsigned char* txid);
extern void mempool_note_accept(const unsigned char* txid);
extern void* mp_ext_area;
extern unsigned long mp_ext_slots;
extern unsigned long mp_ext_inited;
extern void* mp_ext_polstate;
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

    printf("\n%s (%d checks, %d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", checks, fails);
    return fails?1:0;
}
