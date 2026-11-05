/* tests/test_utxo_fork_trim.c -- plan M2 (2026-10-08): the merge child and
 * the flush writer are forked without the buffers they never read. The
 * frozen copy keeps its pages between flushes (2026-10-09): M2 released them
 * at the adopt, and every freeze then faulted ~3 GB of huge pages back in,
 * each behind a direct memory compaction on a box full of page cache
 * (run 45: 2.4 s a freeze where the copy is 0.2 s).
 *
 * Run 41's heap peaked at 32.2 GB against a steady 15.2: a merge child
 * forked at 15:20:32Z still shared the live memtable and the frozen copy
 * when a freeze rewrote the copy and the applier kept writing the memtable,
 * so the kernel copied every page the parent wrote (~17 GB) for a child
 * that reads none of them. And the frozen copy held its pages for the whole
 * generation though the writer needs it for ~17 s of ~123 s.
 *
 * Pinned (the children's views are their own /proc/self/maps, written by a
 * test hook that runs first in each child; the regions carry their M1 names):
 *   A. the flush writer's map has the frozen copy and not the live memtable;
 *      after its adopt the copy still holds its pages (mincore: the next
 *      freeze copies into resident memory) and the frozen coins read back
 *      from the run;
 *   B. a merge child's map has neither the memtable nor the frozen copy, and
 *      the merged store still reads every coin;
 *   C. a plain fork() afterwards inherits both again (the DOFORK is undone
 *      in the parent: every other fork in the worker sees what it did before);
 *   D. control: with the trim off (the pre-M2 fork) the writer's map DOES
 *      show the memtable -- the probe can see what A says is absent.
 *
 * Revert checks: A and B FAIL with the MADV_DONTFORK calls removed; C FAILS
 * with the parent's MADV_DOFORK removed; A's residency checks FAIL with
 * M2's release (MADV_DONTNEED on the copy's table and blob) put back in
 * fz_adopt. */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
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
extern void utxo_live_test_set_child_probe(void (*fn)(int who));
extern void utxo_live_test_set_fork_trim(int on);
extern int  utxo_live_test_compact_nowait(void);
extern int  utxo_live_test_compact_pid(void);
extern void* utxo_live_test_fz_table(void);
extern long utxo_lsm_get(void* lst, void* u, const u8* txid, unsigned index, u64* value, unsigned long* height, unsigned long* cb, const u8** script, unsigned long* slen);

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u;(void)txid;(void)index;(void)value;(void)script;(void)slen;
    fprintf(stderr, "test_utxo_fork_trim: unexpected mempool_resolve_confirmed_utxo\n");
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
/* the child's hook: its own map, copied to maps.<who> (raw syscalls only) */
static void copy_maps(const char* to){
    int in = open("/proc/self/maps", O_RDONLY), out = open(to, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    char b[8192]; long n;
    while (in >= 0 && out >= 0 && (n = read(in, b, sizeof b)) > 0) if (write(out, b, (size_t)n) != n) break;
    if (in >= 0) close(in);
    if (out >= 0) close(out);
}
static void probe(int who){ copy_maps(who == 1 ? "maps.merge" : "maps.writer"); }
static int has(const char* file, const char* name){
    FILE* f = fopen(file, "r"); if (!f) return -1;
    char line[1024], want[96]; int hit = 0;
    snprintf(want, sizeof want, "[anon:%s]", name);
    while (fgets(line, sizeof line, f)) if (strstr(line, want)){ hit = 1; break; }
    fclose(f);
    return hit;
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
/* resident pages of [p, p+len) */
static long resident(const void* p, size_t len){
    long pg = sysconf(_SC_PAGESIZE); size_t n = (len + (size_t)pg - 1) / (size_t)pg;
    unsigned char* v = malloc(n); if (!v) return -1;
    long r = 0;
    if (mincore((void*)p, len, v) == 0) for (size_t i = 0; i < n; i++) r += v[i] & 1; else r = -1;
    free(v);
    return r;
}
/* one generation through the writer, awaited and adopted */
static void flush_gen(unsigned lo, unsigned n){
    seed(lo, n);
    unlink("maps.writer");
    unsigned long a0 = utxo_live_test_fz_adopted();
    ck("the freeze forks a writer", utxo_live_test_freeze_nowait(), 1);
    wait_zombie(utxo_live_test_writer_pid());
    utxo_live_bg_poll();
    ck("the writer is adopted", (long)(utxo_live_test_fz_adopted() - a0), 1);
}

static u8 store_buf[4096];

int main(void){
    tt_isolate();
    utxo_live_test_force_sizing(0);                  /* the small steady-state memtable: quick, same code path */
    g_cfg.async_flush = 1;
    g_cfg.utxo_compact_threshold = 2;               /* two runs are a merge */
    ck("store_init", store_init(store_buf), 1);
    ck("utxo_live_init", utxo_live_init("."), 1);
    utxo_live_test_set_child_probe(probe);

    printf("-- A: the flush writer is forked with the frozen copy and without the live memtable\n");
    flush_gen(0, 64);
    ck("  the writer wrote its map", has("maps.writer", "utxo-frozen-table") >= 0, 1);
    ck("  it has the frozen table", has("maps.writer", "utxo-frozen-table"), 1);
    ck("  it has the frozen blob", has("maps.writer", "utxo-frozen-blob"), 1);
    ck("  it does NOT have the live table", has("maps.writer", "utxo-memtable-table"), 0);
    ck("  it does NOT have the live blob", has("maps.writer", "utxo-memtable-blob"), 0);
    { u8* fz = utxo_live_test_fz_table();
      u64 blob = ((u64*)fz)[2], cap = ((u64*)fz)[3];
      ckm("  the copy's header still names its blob", blob != 0 && cap != 0);
      size_t tb = (size_t)(((u64*)utxo_live_test_tbl())[1] + 1) * 48 + 40;   /* the copy is shaped like the live table (mask at +8) */
      long rt = resident(fz, tb), np = (long)((tb + 4095) / 4096);   /* the freeze filled all of it */
      ck("  the frozen table keeps every page after the adopt", rt, np);
      ckm("  the frozen blob keeps its first page", resident((void*)(uintptr_t)blob, 4096) == 1); }
    ck("  the frozen coins read back from the run", found(0, 64), 64);

    printf("\n-- B: a merge child is forked without the memtable and the frozen copy\n");
    flush_gen(64, 64);                                /* a second run */
    unlink("maps.merge");
    ck("  a background merge starts", utxo_live_test_compact_nowait(), 1);
    int mp = utxo_live_test_compact_pid();
    ckm("  a merge child is outstanding", mp > 0);
    wait_zombie(mp);
    utxo_live_bg_poll();
    ck("  the merge is adopted", utxo_live_test_compact_pid(), 0);
    ck("  the merge child wrote its map", has("maps.merge", "utxo-frozen-table") >= 0, 1);
    ck("  it does NOT have the live table", has("maps.merge", "utxo-memtable-table"), 0);
    ck("  it does NOT have the live blob", has("maps.merge", "utxo-memtable-blob"), 0);
    ck("  it does NOT have the frozen table", has("maps.merge", "utxo-frozen-table"), 0);
    ck("  it does NOT have the frozen blob", has("maps.merge", "utxo-frozen-blob"), 0);
    ck("  every coin reads back from the merged run", found(0, 128), 128);

    printf("\n-- C: any other fork inherits everything again\n");
    unlink("maps.plain");
    pid_t p = fork();
    if (p == 0){ copy_maps("maps.plain"); _exit(0); }
    int st; waitpid(p, &st, 0);
    ck("  a plain child has the live table", has("maps.plain", "utxo-memtable-table"), 1);
    ck("  a plain child has the live blob", has("maps.plain", "utxo-memtable-blob"), 1);
    ck("  a plain child has the frozen table", has("maps.plain", "utxo-frozen-table"), 1);

    printf("\n-- D: control -- with the trim off the writer's map shows the live memtable\n");
    utxo_live_test_set_fork_trim(0);
    flush_gen(128, 64);
    ck("  the untrimmed writer has the live table", has("maps.writer", "utxo-memtable-table"), 1);
    ck("  the untrimmed writer has the live blob", has("maps.writer", "utxo-memtable-blob"), 1);
    utxo_live_test_set_fork_trim(1);

    utxo_live_close();
    printf("\n%s (%d failures)\n", failures==0 ? "ALL TESTS PASSED" : "TESTS FAILED", failures);
    return failures ? 1 : 0;
}
