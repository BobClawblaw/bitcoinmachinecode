/* test_sto1_crash.c -- STO-1 (audit 2026-09-03) under real crashes: a SIGKILL
 * or a power loss at any step of a disconnect leaves a state boot repairs.
 *
 * reorg_execute's disconnect loop persists the applied height h-1 BEFORE it
 * unapplies h, and the unapply discards undo_h only after the reversal is on
 * disk (the STO-B discard hook). Between any two steps a crash must leave
 * either "applied h-1, the set with h, undo_h on disk" (boot rolls h back)
 * or "applied h-1, the set without h" -- never the set rewound under an
 * applied height that still claims the blocks, with their undo gone, which
 * no recovery can see (the audit's state). tests/test_reorg_crash_ordering
 * builds those states by hand; this one reaches them through the real
 * reorg_disconnect_to (the disconnect half of reorg_execute, invalidateblock's
 * path), with tests/durable_image.h placing the crash at a named sync: a
 * SIGKILL right after it returns, or a power loss at it (the ext4 image of
 * what was synced).
 *
 * The chain (tests/test_sto_crash.c's): blocks 0..149 coinbase-only, 150..153
 * each spend the previous one's output, so the disconnected blocks have undo
 * records. Process 1 applies 0..153 and closes. Process 2 disconnects to 151
 * (153, then 152) and dies at the crash point. Process 3 boots, recovers and
 * catches up. A crash before the archive is truncated must come back at 153
 * with 154 coins (the archive still holds 153, so catch-up re-applies what
 * the crash undid); one after it at 151 with 152. The control runs the
 * disconnect to the end and closes. */
#define _GNU_SOURCE
#include "durable_image.h"
#include "test_tmpdir.h"
#include <sys/wait.h>
#include <sys/file.h>

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

extern long store_init(void* st);
extern long store_reload(void* st);
extern long store_append(void* st, const u8 hash[32], const void* raw, long len);
extern void block_hash(u8 out[32], const u8 hdr[80]);
extern int  pow_check(const u8 hdr[80]);
extern int  tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* buf, unsigned long buflen);
extern void sha256d(u8 out[32], const void* msg, long len);
extern int  utxo_live_init(const char* dir);
extern long utxo_live_catchup(void* store_buf);
extern long utxo_live_count(void);
extern long utxo_live_applied_height(void);
extern void utxo_live_close(void);
extern long utxo_live_recover_at_boot(void* store_buf);
extern void utxo_live_test_force_sizing(int mode);
extern const char* utxo_live_last_reject(void);
extern long reorg_chainwork_open(void* st);
extern long reorg_chainwork_sync(void* st, long max_blocks);
extern long reorg_disconnect_to(void* st, long fork_height);

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u; (void)txid; (void)index; (void)value; (void)script; (void)slen;
    fprintf(stderr, "test_sto1_crash: unexpected mempool_resolve_confirmed_utxo\n");
    abort();
}

/* ---- the chain (tests/test_sto_crash.c's builders) ---- */
static void put32(u8* p, u32 v){ p[0]=(u8)v; p[1]=(u8)(v>>8); p[2]=(u8)(v>>16); p[3]=(u8)(v>>24); }
static void put64(u8* p, u64 v){ for(int i=0;i<8;i++) p[i]=(u8)(v>>(8*i)); }
static u8 g_scr[1<<14];
static long mk_coinbase(u8* q0, u32 tag){
    u8* q = q0;
    put32(q,1); q+=4; *q++ = 1; memset(q,0,32); q+=32; put32(q,0xffffffffu); q+=4;
    *q++ = 4; put32(q, tag); q+=4; put32(q,0xffffffffu); q+=4;
    *q++ = 1; put64(q, 50000000ULL); q+=8; *q++ = 1; *q++ = 0x51; put32(q,0); q+=4;
    return q - q0;
}
static long finish(u8* raw, u8 hash[32], const u8 prev[32], const u8 root[32], u32 ts, const u8* txs, long txlen, int ntx){
    u8* o = raw;
    put32(o,1); o+=4; memcpy(o, prev, 32); o+=32; memcpy(o, root, 32); o+=32;
    put32(o, ts); o+=4; put32(o, 0x207fffffu); o+=4; put32(o, 0); o+=4;
    *o++ = (u8)ntx; memcpy(o, txs, (size_t)txlen); o += txlen;
    u32 nonce = 0; while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
    block_hash(hash, raw);
    return o - raw;
}
#define NB 154
static u8  g_blk[NB][512]; static long g_len[NB]; static u8 g_hash[NB][32];
static u8  g_cb0[32], g_out[NB][32];
static void build_chain(void){
    u8 prev[32]; memset(prev, 0, 32);
    for (int h = 0; h < NB; h++){
        u8 cb[80], cbt[32]; long cbl = mk_coinbase(cb, (u32)h);
        tx_txid(cbt, cb, (unsigned long)cbl, g_scr, sizeof g_scr);
        if (h < 150){
            if (h == 0) memcpy(g_cb0, cbt, 32);
            g_len[h] = finish(g_blk[h], g_hash[h], prev, cbt, 1600000000u + (u32)h, cb, cbl, 1);
        } else {
            const u8* sp = h == 150 ? g_cb0 : g_out[h - 1];
            u8 tx[128]; u8* q = tx;
            put32(q,1); q+=4; *q++ = 1; memcpy(q, sp, 32); q+=32; put32(q,0); q+=4; *q++ = 0;
            put32(q,0xffffffffu); q+=4; *q++ = 1; put64(q, 40000000ULL); q+=8; *q++ = 1; *q++ = 0x51; put32(q,0); q+=4;
            long tl = q - tx; tx_txid(g_out[h], tx, (unsigned long)tl, g_scr, sizeof g_scr);
            u8 pair[64], root[32]; memcpy(pair, cbt, 32); memcpy(pair+32, g_out[h], 32); sha256d(root, pair, 64);
            u8 txs[256]; memcpy(txs, cb, (size_t)cbl); memcpy(txs + cbl, tx, (size_t)tl);
            g_len[h] = finish(g_blk[h], g_hash[h], prev, root, 1600000000u + (u32)h, txs, cbl + tl, 2);
        }
        memcpy(prev, g_hash[h], 32);
    }
}

/* ---- the processes ---- */
static u8 store_buf[4096];
static void boot(void){
    memset(store_buf, 0, sizeof store_buf);
    utxo_live_test_force_sizing(0);
    store_init(store_buf); store_reload(store_buf);
    int apfd = open("append.lock", O_RDWR | O_CREAT, 0644);       /* reorg_execute's append lock */
    if (apfd >= 0) *(int*)(store_buf + 40) = apfd;
    if (reorg_chainwork_open(store_buf) != 1){ printf("  reorg_chainwork_open failed\n"); _exit(9); }
    if (utxo_live_init(".") != 1){ printf("  utxo_live_init failed\n"); _exit(9); }
}
static int run(const char* dir, void (*fn)(void*), void* arg){
    fflush(stdout);
    pid_t p = fork();
    if (p == 0){ if (chdir(dir) != 0) _exit(8); fn(arg); fflush(stdout); _exit(0); }
    int st; while (waitpid(p, &st, 0) < 0 && errno == EINTR) {}
    return WIFSIGNALED(st) ? 1000 + WTERMSIG(st) : WEXITSTATUS(st);
}
static void p1_build(void* a){
    (void)a; boot();
    for (int h = 0; h < NB; h++)
        if (store_append(store_buf, g_hash[h], g_blk[h], g_len[h]) != h){ printf("  append %d failed\n", h); _exit(9); }
    long r = utxo_live_catchup(store_buf);
    if (reorg_chainwork_sync(store_buf, 0) < 0){ printf("  chainwork sync failed\n"); _exit(9); }
    printf("  p1: catch-up 0..153 -> %ld, applied %ld, count %ld; clean close\n", r, utxo_live_applied_height(), utxo_live_count());
    utxo_live_close();
}
/* the crash point: a SIGKILL right after, or a power loss at, the k-th sync
 * of `name` inside the disconnect; name 0 = no crash (trace / control) */
struct cp { const char* name; int k; int power; };
/* process 1's files are long written back by the time process 2 crashes:
 * record each as durable (a sync of every file and the directory) before the
 * trace starts, so the image holds exactly what process 2 did or did not sync */
static void settle(void){
    di_arm();
    DIR* d = opendir("."); struct dirent* e;
    while (d && (e = readdir(d))){
        if (e->d_type != DT_REG) continue;
        int fd = open(e->d_name, O_RDONLY); if (fd >= 0){ fsync(fd); close(fd); }
    }
    if (d) closedir(d);
    int dfd = open(".", O_RDONLY | O_DIRECTORY); if (dfd >= 0){ fsync(dfd); close(dfd); }
}
static void p2_disconnect(void* a){
    const struct cp* c = a;
    settle();
    boot();
    long rb = utxo_live_recover_at_boot(store_buf);
    if (rb < 0){ printf("  p2: recover_at_boot -> %ld\n", rb); _exit(9); }
    if (c->name){ if (c->power) di_freeze_after(c->name, c->k); else di_kill_after(c->name, c->k); }
    long r = reorg_disconnect_to(store_buf, 151);
    printf("  p2: reorg_disconnect_to(151) -> %ld; applied %ld, count %ld, archive tip %d; clean close\n",
           r, utxo_live_applied_height(), utxo_live_count(), *(int*)(store_buf + 24));
    utxo_live_close();
}
static void p3_recover(void* a){
    (void)a; boot();
    long rb = utxo_live_recover_at_boot(store_buf);
    long r = rb < 0 ? -9 : utxo_live_catchup(store_buf);
    long tip = *(int*)(store_buf + 24);
    printf("  p3: recover_at_boot -> %ld; catch-up -> %ld; applied %ld; count %ld; archive tip %ld%s%s\n",
           rb, r, utxo_live_applied_height(), utxo_live_count(), tip,
           utxo_live_last_reject()[0] ? "; reject: " : "", utxo_live_last_reject());
    FILE* f = fopen("result.txt", "w");
    if (f){ fprintf(f, "%ld %ld %ld %ld %ld\n", rb, r, utxo_live_applied_height(), utxo_live_count(), tip); fclose(f); }
}
static int read_res(const char* dir, long v[5]){
    char p[700]; snprintf(p, sizeof p, "%s/result.txt", dir);
    FILE* f = fopen(p, "r"); if (!f) return -1;
    int n = fscanf(f, "%ld %ld %ld %ld %ld", &v[0], &v[1], &v[2], &v[3], &v[4]); fclose(f); return n == 5 ? 0 : -1;
}

static char g_base[600];
static int failures;
/* one trace; `to` is the height the set must come back at (count to+1) */
static void scenario(const char* label, const struct cp* c, int to){
    char live[640], img[640], snap[640];
    static int seq; seq++;
    snprintf(live, sizeof live, "%s/s%d.live", g_base, seq);
    snprintf(img,  sizeof img,  "%s/s%d.img",  g_base, seq);
    snprintf(snap, sizeof snap, "%s/s%d.snap", g_base, seq);
    mkdir(live, 0755);
    printf("--- %s\n", label);
    fflush(stdout);
    pid_t p = fork();
    if (p == 0){
        if (di_install(snap) != 0){ printf("  seccomp install failed\n"); _exit(1); }
        if (run(live, p1_build, 0) != 0) _exit(1);
        int st = run(live, p2_disconnect, (void*)c);
        if (chdir(live) != 0) _exit(1);
        di_print_log();
        const char* where = live;
        if (c->name && c->power){
            if (!di->frozen){ printf("  the power-loss point was never reached\n"); _exit(1); }
            di->armed = 0;
            static const char* const none[] = { 0 };
            if (di_build_image(img, none) != 0) _exit(1);
            printf("  POWER LOSS -> image\n");
            where = img;
        } else if (c->name){
            printf("  p2 exit %d (1009 = SIGKILL)\n", st);
            if (st != 1009){ printf("  the kill point was never reached\n"); _exit(1); }
        }
        di->armed = 0;
        run(where, p3_recover, 0);
        long v[5]; if (read_res(where, v)) _exit(1);
        _exit(v[0] >= 0 && v[1] >= 0 && v[2] == to && v[3] == to + 1 && v[4] == to ? 0 : 1);
    }
    int st; while (waitpid(p, &st, 0) < 0 && errno == EINTR) {}
    int ok = WIFEXITED(st) && WEXITSTATUS(st) == 0;
    printf("%s %s: %s\n", ok ? "PASS" : "FAIL", label, ok ? "healed" : "NOT healed");
    if (!ok) failures++;
}

int main(int argc, char** argv){
    tt_isolate();
    setvbuf(stdout, 0, _IOLBF, 0);
    build_chain();
    if (snprintf(g_base, sizeof g_base, "%s", tt_workdir()) >= (int)sizeof g_base){ printf("FAIL work dir path too long\n"); return 1; }
    int trace = argc > 1 && !strcmp(argv[1], "trace");
    static const struct cp none = { 0, 0, 0 };
    if (trace){ scenario("trace: the disconnect to the end, its syncs in order", &none, 151); return 0; }
    scenario("control: the disconnect runs to the end", &none, 151);
    /* The disconnect's syncs, in order (`trace` prints them):
     *   rewind_to(152): undo.idx utxo.dat(1) height.tmp(1) <dir>
     *   unapply(153), the discard hook: utxo.dat(2), then undo_153 cleared
     *   rewind_to(151): undo.idx(2) utxo.dat(3) height.tmp(2) <dir>
     *   unapply(152), the discard hook: utxo.dat(4), then undo_152 cleared
     *   archive truncated to 151, then the final rewind_to(151): ... utxo.dat(5) */
    static const struct { struct cp c; int to; const char* what; } C[] = {
        { { "utxo.dat", 2, 0 }, 153, "SIGKILL in unapply(153): reversal on disk, undo_153 not yet cleared, applied 152" },
        { { "undo.idx", 2, 0 }, 153, "SIGKILL after unapply(153): undo_153 cleared, applied 152" },
        { { "utxo.dat", 4, 0 }, 153, "SIGKILL in unapply(152): reversal on disk, undo_152 not yet cleared, applied 151" },
        { { "utxo.dat", 5, 0 }, 151, "SIGKILL after the archive truncate (both blocks undone, applied 151)" },
        { { "utxo.dat", 2, 1 }, 153, "power loss in unapply(153), at the reversal's fsync" },
        { { "undo.idx", 2, 1 }, 153, "power loss after unapply(153), at the next height's prefix" },
        { { "utxo.dat", 4, 1 }, 153, "power loss in unapply(152), at the reversal's fsync" },
        { { "utxo.dat", 5, 1 }, 151, "power loss after the archive truncate, at the final confirm" } };
    for (unsigned i = 0; i < sizeof C / sizeof C[0]; i++) scenario(C[i].what, &C[i].c, C[i].to);
    printf("\n%s\n", failures ? "TESTS FAILED" : "ALL TESTS PASSED");
    return failures ? 1 : 0;
}
