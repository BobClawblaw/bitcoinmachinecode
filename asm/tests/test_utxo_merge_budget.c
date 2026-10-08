/* tests/test_utxo_merge_budget.c -- a merge deferred while the apply is
 * behind still starts when the run files are over the memory budget, at ANY
 * run count (2026-10-08, run 42).
 *
 * compact_start_async decided "over the budget" as (run count < count
 * threshold): true only when the byte rule, not the count, had picked the
 * merge. Once the count threshold was met the budget never overrode the
 * deferral, and the merge waited for twice the threshold. Run 42 (M2: half
 * the memtable, so half-size runs) reached 48 runs before 46.3 GB, then
 * waited to 96 runs and 72.7 GB; blocks 600k-700k took 2 h against run 41's
 * 30 min.
 *
 * Pinned, with the count threshold at 2 and two runs on disk (the count
 * has picked) and the apply 1,000 blocks behind:
 *   A. control: run files under the budget -- the merge is deferred (the
 *      deferral is live, so B's merge is the budget's doing);
 *   B. run files over the budget -- the merge starts, and every coin reads
 *      back from the merged run.
 *
 * Revert check: B FAILS with over_budget computed as (n < thr) again. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "test_tmpdir.h"
#include "../daemon/node_config.h"

typedef unsigned char u8;
typedef unsigned long long u64;

extern long store_init(void* st);
extern int  utxo_live_init(const char* dir);
extern void utxo_live_close(void);
extern void utxo_live_test_force_sizing(int);
extern void utxo_live_bg_poll(void);
extern long utxo_live_test_freeze_nowait(void);
extern int  utxo_live_test_writer_pid(void);
extern unsigned long utxo_live_test_fz_adopted(void);
extern int  utxo_live_test_seed(const u8 txid[32], unsigned int index, u64 value, const u8* spk, unsigned int spklen);
extern void* utxo_live_test_lst(void);
extern void* utxo_live_test_tbl(void);
extern int  utxo_live_test_compact_nowait(void);
extern int  utxo_live_test_compact_pid(void);
extern void utxo_live_test_set_apply_lag(long lag);
extern void utxo_live_set_run_budget(unsigned long long bytes);
extern unsigned long utxo_live_compactions_deferred(void);
extern long utxo_lsm_get(void* lst, void* u, const u8* txid, unsigned index, u64* value, unsigned long* height, unsigned long* cb, const u8** script, unsigned long* slen);

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u;(void)txid;(void)index;(void)value;(void)script;(void)slen;
    fprintf(stderr, "test_utxo_merge_budget: unexpected mempool_resolve_confirmed_utxo\n");
    abort();
}

static int failures = 0;
static void ck(const char* l, long got, long exp){
    if (got==exp) printf("PASS %s (got %ld)\n", l, got);
    else { printf("FAIL %s got=%ld exp=%ld\n", l, got, exp); failures++; }
}
static char proc_state(int pid){
    char p[64]; snprintf(p, sizeof p, "/proc/%d/stat", pid);
    FILE* f = fopen(p, "r"); if (!f) return 0;
    char buf[512]; size_t n = fread(buf, 1, sizeof buf - 1, f); fclose(f); buf[n] = 0;
    char* rp = strrchr(buf, ')');
    return (rp && rp[1] == ' ') ? rp[2] : '?';
}
static void wait_zombie(int pid){
    struct timespec ts = {0, 10 * 1000 * 1000};
    for (int i = 0; i < 1000 && pid > 0 && proc_state(pid) != 'Z'; i++) nanosleep(&ts, 0);
}
static void key(u8* t, unsigned i){ memset(t, 0x5a, 32); t[0] = (u8)i; t[1] = (u8)(i >> 8); }
static void seed(unsigned lo, unsigned n){
    u8 spk[25]; memset(spk, 0x76, sizeof spk);
    for (unsigned i = lo; i < lo + n; i++){ u8 t[32]; key(t, i); utxo_live_test_seed(t, 0, 1000ULL + i, spk, sizeof spk); }
}
static long found(unsigned lo, unsigned n){
    long c = 0;
    for (unsigned i = lo; i < lo + n; i++){
        u8 t[32]; key(t, i); u64 v = 0; unsigned long h, cb, sl; const u8* sp;
        if (utxo_lsm_get(utxo_live_test_lst(), utxo_live_test_tbl(), t, 0, &v, &h, &cb, &sp, &sl) == 1 && v == 1000ULL + i) c++;
    }
    return c;
}
/* one generation through the flush writer, awaited and adopted: one run */
static void flush_gen(unsigned lo, unsigned n){
    seed(lo, n);
    unsigned long a0 = utxo_live_test_fz_adopted();
    ck("the freeze forks a writer", utxo_live_test_freeze_nowait(), 1);
    wait_zombie(utxo_live_test_writer_pid());
    utxo_live_bg_poll();
    ck("the writer is adopted", (long)(utxo_live_test_fz_adopted() - a0), 1);
}

static u8 store_buf[4096];

int main(void){
    tt_isolate();
    utxo_live_test_force_sizing(0);
    g_cfg.async_flush = 1;
    g_cfg.utxo_compact_threshold = 2;               /* two runs: the count has picked */
    ck("store_init", store_init(store_buf), 1);
    ck("utxo_live_init", utxo_live_init("."), 1);
    flush_gen(0, 64);
    flush_gen(64, 64);
    utxo_live_test_set_apply_lag(1000);             /* the apply far behind the archive: merges wait */

    printf("-- A: control -- under the budget, the merge is deferred\n");
    utxo_live_set_run_budget(1ULL << 50);
    unsigned long d0 = utxo_live_compactions_deferred();
    ck("  no merge starts", utxo_live_test_compact_nowait(), 0);
    ck("  it was deferred", (long)(utxo_live_compactions_deferred() - d0), 1);
    ck("  no merge child", utxo_live_test_compact_pid(), 0);

    printf("\n-- B: over the budget at the count threshold, the merge starts\n");
    utxo_live_set_run_budget(1);
    d0 = utxo_live_compactions_deferred();
    ck("  a merge starts", utxo_live_test_compact_nowait(), 1);
    ck("  not deferred", (long)(utxo_live_compactions_deferred() - d0), 0);
    int mp = utxo_live_test_compact_pid();
    ck("  a merge child is outstanding", mp > 0, 1);
    wait_zombie(mp);
    utxo_live_bg_poll();
    ck("  the merge is adopted", utxo_live_test_compact_pid(), 0);
    ck("  every coin reads back from the merged run", found(0, 128), 128);

    utxo_live_close();
    printf("\n%s (%d failures)\n", failures==0 ? "ALL TESTS PASSED" : "TESTS FAILED", failures);
    return failures ? 1 : 0;
}
