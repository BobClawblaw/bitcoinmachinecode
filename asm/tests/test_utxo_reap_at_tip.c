/* tests/test_utxo_reap_at_tip.c -- plan B3 at the tip (2026-10-07): a flush
 * writer that has exited is adopted on the next idle rotation or catch-up
 * pass, not on the next block.
 *
 * Production, deploy-20261006d, 01:16:41Z: block 970267 crossed the memtable
 * threshold, the worker forked writer 1959235, the writer wrote
 * utxo_run_001417.dat in milliseconds and exited -- and sat as a zombie for
 * 22.5 minutes, until block 970268. fz_poll ran only at the end of a pass
 * that applied something (the pass that forked the writer, before it had
 * exited), so the manifest adopt, the WAL hole punch and the frozen copy's
 * release all waited for the next block.
 *
 * Pinned, with bmc.asyncflush=1 (the default), each arm against a writer
 * that is already a zombie when the poll runs:
 *   A. utxo_live_bg_poll() (the worker's idle rotation, main.c) adopts it:
 *      the zombie is gone, no writer is outstanding, the adopt count is +1,
 *      and the frozen coins read back from the adopted run.
 *   B. a catch-up pass with nothing to apply (the caught-up node between
 *      blocks) adopts it the same way.
 *
 * Revert checks: A FAILS with utxo_live_bg_poll's body emptied, B FAILS with
 * the two polls removed from catchup_run's nothing-to-apply return. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include "test_tmpdir.h"
#include "../daemon/node_config.h"

typedef unsigned char u8;
typedef unsigned long long u64;

extern long store_init(void* st);
extern int  utxo_live_init(const char* dir);
extern void utxo_live_close(void);
extern void utxo_live_test_force_sizing(int);
extern long utxo_live_catchup(void* store_buf);
extern void utxo_live_bg_poll(void);
extern long utxo_live_test_freeze_nowait(void);
extern int  utxo_live_test_writer_pid(void);
extern unsigned long utxo_live_test_fz_adopted(void);
extern int  utxo_live_test_seed(const u8 txid[32], unsigned int index, u64 value, const u8* spk, unsigned int spklen);
extern void* utxo_live_test_lst(void);
extern void* utxo_live_test_tbl(void);
extern long utxo_lsm_get(void* lst, void* u, const u8* txid, unsigned index, u64* value, unsigned long* height, unsigned long* cb, const u8** script, unsigned long* slen);

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u;(void)txid;(void)index;(void)value;(void)script;(void)slen;
    fprintf(stderr, "test_utxo_reap_at_tip: unexpected mempool_resolve_confirmed_utxo\n");
    abort();
}

static int failures = 0;
static void ck(const char* l, long got, long exp){
    if (got==exp) printf("PASS %s (got %ld)\n", l, got);
    else { printf("FAIL %s got=%ld exp=%ld\n", l, got, exp); failures++; }
}
static void ckm(const char* l, int cond){
    if (cond) printf("PASS %s\n", l); else { printf("FAIL %s\n", l); failures++; }
}
/* the state letter of /proc/<pid>/stat, or 0 when the pid is gone. Read, never
 * waitpid'd: a test that reaps the daemon's child steals the status it is testing. */
static char proc_state(int pid){
    char p[64]; snprintf(p, sizeof p, "/proc/%d/stat", pid);
    FILE* f = fopen(p, "r"); if (!f) return 0;
    char buf[512]; size_t n = fread(buf, 1, sizeof buf - 1, f); fclose(f); buf[n] = 0;
    char* rp = strrchr(buf, ')');                    /* comm may hold spaces: the state follows the last ')' */
    return (rp && rp[1] == ' ') ? rp[2] : '?';
}
static void key(u8* t, unsigned i){ memset(t, 0x3c, 32); t[0] = (u8)i; t[1] = (u8)(i >> 8); }
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
/* freeze, and wait (up to 10 s) until the writer has exited and nobody has
 * reaped it: the production state at 01:16:42Z. Returns the writer's pid. */
static int zombie_writer(unsigned lo, unsigned n){
    seed(lo, n);
    ck("the freeze forks a writer", utxo_live_test_freeze_nowait(), 1);
    int pid = utxo_live_test_writer_pid();
    ckm("a writer is outstanding", pid > 0);
    struct timespec ts = {0, 10 * 1000 * 1000};
    for (int i = 0; i < 1000 && pid > 0 && proc_state(pid) != 'Z'; i++) nanosleep(&ts, 0);
    ck("the writer has exited and is unreaped (state Z)", proc_state(pid), 'Z');
    return pid;
}
static void after(const char* how, int pid, unsigned long adopted0, unsigned lo, unsigned n){
    printf("     after %s:\n", how);
    ck("  the zombie is gone", proc_state(pid), 0);
    ck("  no writer is outstanding", utxo_live_test_writer_pid(), 0);
    ck("  the adopt count is +1", (long)(utxo_live_test_fz_adopted() - adopted0), 1);
    ck("  the frozen coins read back", found(lo, n), (long)n);
}

static u8 store_buf[4096];

int main(void){
    tt_isolate();
    utxo_live_test_force_sizing(0);                  /* the small steady-state memtable: quick, same code path */
    g_cfg.async_flush = 1;
    ck("store_init", store_init(store_buf), 1);
    ck("utxo_live_init", utxo_live_init("."), 1);

    printf("-- A: the worker's idle rotation (utxo_live_bg_poll) adopts an exited writer\n");
    unsigned long a0 = utxo_live_test_fz_adopted();
    int pa = zombie_writer(0, 64);
    utxo_live_bg_poll();
    after("utxo_live_bg_poll", pa, a0, 0, 64);

    printf("\n-- B: a catch-up pass with nothing to apply adopts an exited writer\n");
    unsigned long b0 = utxo_live_test_fz_adopted();
    int pb = zombie_writer(64, 64);
    ck("the catch-up pass applies nothing", utxo_live_catchup(store_buf), 0);
    after("utxo_live_catchup", pb, b0, 64, 64);

    utxo_live_close();
    printf("\n%s (%d failures)\n", failures==0 ? "ALL TESTS PASSED" : "TESTS FAILED", failures);
    return failures ? 1 : 0;
}
