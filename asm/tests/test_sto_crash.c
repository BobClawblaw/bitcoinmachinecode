/* test_sto_crash.c -- crash consistency of the UTXO store under SIGKILL and
 * power loss: STO-A, STO-B, STO-C, STO-E, STO-D and STO-W (formal/storage,
 * 2026-10-23).
 *
 * The formal model (formal/storage/tla/StorageCrash.tla) found four classes
 * of hole and its crash driver reproduced each on the real code. This test is
 * that driver turned around: every scenario must HEAL. Each runs the
 * processes of a trace as forked children of a runner that never touches the
 * store, so each starts with fresh utxo_live state like a restarted daemon. A
 * SIGKILL is a real SIGKILL; a power loss is the image tests/durable_image.h
 * records from the real fsync/fdatasync calls (ext4 namespace semantics:
 * every name as of the last sync, every file as of its own last sync).
 *
 *   B   ghostkill    boot recovery rolls the ghosts back, then dies: the
 *                    rollback must be on disk before the undo slots go
 *   A1  flushundo    a flush makes un-checkpointed spends durable: their
 *                    undo must be durable first
 *   A2  walwb        the WAL buffer lands and the kernel writes it back:
 *                    the undo must be durable before the write(2)
 *   A3  cbflush      a flush between a block's coinbase and its first spend:
 *                    the block's slot must exist before its first op
 *   A4  ghostchain   a SIGKILL, then a power loss in the middle of the boot
 *                    rollback: the dead process's undo durable before any
 *                    restore reaches the disk
 *   E   logoff       utxo.idx names a log_off past the WAL's durable end: the
 *                    records appended after the boot must stay readable
 *   C1  archive      the applied height is durable: so is the index.dat
 *                    record of every block it covers
 *   C2  archive-nosync  the same with the block store's per-block sync off
 *                    (the download committer): blocks before records
 *   F   fork         the WAL buffer now holds many blocks: a forked child
 *                    that drains (a reader's reload drains first) must not
 *                    land its parent's buffered records
 *
 * STO-D and STO-W hold only on a file system weaker than ext4, which orders
 * nothing between two name ops of a directory: these run durable_image.h's
 * weak mode (a name op durable only at a directory fsync, any subset of the
 * rest kept by the power loss), and inject a failed directory fsync (EIO) or
 * a failed open(".") (EMFILE) through the same seccomp trap.
 *   D1  dirpub       the manifest's directory fsync fails at an async adopt,
 *                    a power loss keeps the utxo.idx rename and not the
 *                    manifest's: no retire before a directory fsync works
 *   D2  dirretire    the directory fsync after the utxo.idx rename fails:
 *                    the WAL must not be punched under the old log_off
 *   D3  dirmerge     the directory fsync after a merge's manifest fails: its
 *                    inputs must stay on disk
 *   D4  opendot      the inline flush cannot open the directory: the WAL
 *                    reset must wait for a directory fsync that happened
 *   D5  dirckpt      the checkpoint's directory fsync fails: redo only (the
 *                    previous checkpoint, the blocks after it re-applied);
 *                    no fix, this pins the claim
 *   W1  runcreate    an async flush's run, the manifest rename kept and the
 *                    run's create lost: the create durable before the rename
 *   W2  runcreate-inline  the same in mac_flush
 *   W3  runcreate-merge   the same for the inline compaction's merged run
 *   W4  sweep        the boot sweep unlinks a merge's inputs on the strength
 *                    of a manifest whose rename is not durable: the rename
 *                    durable before the first unlink
 *
 * Every crash scenario has a control: the same trace with the one write its crash
 * loses kept (taken from the live directory, as if the kernel had written it
 * back), which heals with or without the fix -- so a failure is the lost
 * write's, not the harness's.
 *
 * The chain: blocks 0..149 coinbase-only, block 150 spends block 0's
 * coinbase creating A; 151 spends A creating B; 152 spends B creating C; 153
 * spends C creating D. After block h >= 150 the set holds h + 1 coins. */
#define _GNU_SOURCE
#include "durable_image.h"
#include "test_tmpdir.h"
#include "../daemon/node_config.h"
#include <sys/wait.h>

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

extern long store_init(void* st);
extern long store_reload(void* st);
extern long store_append(void* st, const u8 hash[32], const void* raw, long len);
extern long store_read_at(void* st, u64 height, void* buf, u64 cap);
extern void store_set_sync(int on);
extern void block_hash(u8 out[32], const u8 hdr[80]);
extern int  pow_check(const u8 hdr[80]);
extern int  tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* buf, unsigned long buflen);
extern void sha256d(u8 out[32], const void* msg, long len);
extern int  utxo_live_init(const char* dir);
extern long utxo_live_catchup(void* store_buf);
extern long utxo_live_count(void);
extern long utxo_live_applied_height(void);
extern void utxo_live_close(void);
extern int  utxo_live_apply_block(const void* blockbuf, u64 blocklen, long height);
extern long utxo_live_flush_now(void);
extern long utxo_live_recover_at_boot(void* store_buf);
extern void utxo_live_test_force_sizing(int mode);
extern void utxo_live_test_set_ckpt_batch(long n);
extern long utxo_live_test_wal_drain(void);
extern long utxo_store_wal_drain(void* st);
extern void utxo_live_test_set_after_tx0(void (*fn)(long h));
extern const char* utxo_live_last_reject(void);
extern void utxo_live_bg_poll(void);
extern void utxo_live_set_run_budget(unsigned long long bytes);
extern void utxo_live_test_set_apply_lag(long lag);
extern int  utxo_live_test_compact_nowait(void);
extern int  utxo_live_test_compact_pid(void);
extern void* utxo_live_test_lst(void);
extern long utxo_lsm_compact_range(void* lst, unsigned long lo, unsigned long k);
extern long utxo_live_lsm_get(const u8 txid_wire[32], unsigned int vout, u64* value, unsigned long* height,
                              unsigned long* is_coinbase, const u8** script, unsigned long* slen);

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u; (void)txid; (void)index; (void)value; (void)script; (void)slen;
    fprintf(stderr, "test_sto_crash: unexpected mempool_resolve_confirmed_utxo\n");
    abort();
}

/* ---- the chain (built once in the parent; pure data) ---- */
static void put32(u8* p, u32 v){ p[0]=(u8)v; p[1]=(u8)(v>>8); p[2]=(u8)(v>>16); p[3]=(u8)(v>>24); }
static void put64(u8* p, u64 v){ for(int i=0;i<8;i++) p[i]=(u8)(v>>(8*i)); }
static u8 g_scr[1<<12];
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
static u8  g_cb0[32], g_out[NB][32];          /* g_out[h]: the spend tx of block h (150..153) */
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

/* ---- the processes of a trace ---- */
static u8 store_buf[4096];
static int has(int h){ u64 v; unsigned long ht, cb, sl; const u8* s; return (int)utxo_live_lsm_get(g_out[h], 0, &v, &ht, &cb, &s, &sl); }
static void boot(void){
    memset(store_buf, 0, sizeof store_buf);
    utxo_live_test_force_sizing(0);
    store_init(store_buf); store_reload(store_buf);
    if (utxo_live_init(".") != 1){ printf("  utxo_live_init failed\n"); _exit(9); }
}
static void append(int lo, int hi){
    for (int h = lo; h <= hi; h++)
        if (store_append(store_buf, g_hash[h], g_blk[h], g_len[h]) != h){ printf("  append %d failed\n", h); _exit(9); }
}
/* 0..150 applied and checkpointed, then 151..to applied with no checkpoint (a batch) */
static void build_ghosts(int to){
    boot();
    append(0, 150);
    long r = utxo_live_catchup(store_buf);
    printf("  p1: catch-up 0..150 -> %ld, applied %ld\n", r, utxo_live_applied_height());
    append(151, to);
    for (int h = 151; h <= to; h++)
        if (utxo_live_apply_block(g_blk[h], (u64)g_len[h], h) != 1){ printf("  apply %d failed\n", h); _exit(9); }
    if (to >= 151) printf("  p1: applied 151..%d without a checkpoint\n", to);
}
typedef void (*proc_fn)(void* arg);
static int run(const char* dir, proc_fn fn, void* arg){
    fflush(stdout);
    pid_t p = fork();
    if (p == 0){ if (chdir(dir) != 0) _exit(8); fn(arg); fflush(stdout); _exit(0); }
    int st; while (waitpid(p, &st, 0) < 0 && errno == EINTR) {}
    return WIFSIGNALED(st) ? 1000 + WTERMSIG(st) : WEXITSTATUS(st);
}
/* recovery + catch-up, its verdict in result.txt: recover catchup applied count */
static void p_recover_catchup(void* a){
    (void)a; boot();
    long rb = utxo_live_recover_at_boot(store_buf);
    long r = rb < 0 ? -9 : utxo_live_catchup(store_buf);
    printf("  recover_at_boot -> %ld; catch-up -> %ld; applied %ld; count %ld%s%s\n", rb, r, utxo_live_applied_height(),
           utxo_live_count(), utxo_live_last_reject()[0] ? "; reject: " : "", utxo_live_last_reject());
    FILE* f = fopen("result.txt", "w"); if (f){ fprintf(f, "%ld %ld %ld %ld\n", rb, r, utxo_live_applied_height(), utxo_live_count()); fclose(f); }
}
static int read_res(const char* dir, long v[4]){
    char p[700]; snprintf(p, sizeof p, "%s/result.txt", dir);
    FILE* f = fopen(p, "r"); if (!f) return -1;
    int n = fscanf(f, "%ld %ld %ld %ld", &v[0], &v[1], &v[2], &v[3]); fclose(f); return n == 4 ? 0 : -1;
}
/* healed: recovery ran, the catch-up applied up to `to` and the set is the set at `to` */
static int healed_to(const char* dir, int to){
    long v[4]; if (read_res(dir, v)) return 0;
    return v[0] >= 0 && v[1] >= 0 && v[2] == to && v[3] == to + 1;
}

static char g_base[600];
static void paths(const char* name, int control, char* live, char* img, char* snap){
    snprintf(live, 640, "%s/%s%s.live", g_base, name, control ? "-ctl" : "");
    snprintf(img,  640, "%s/%s%s.img",  g_base, name, control ? "-ctl" : "");
    snprintf(snap, 640, "%s/%s%s.snap", g_base, name, control ? "-ctl" : "");
    mkdir(live, 0755);
}
/* the runner's half of a power-loss scenario: record, run the trace, image, recover */
static int image_then_recover(const char* live, const char* img, const char* const* cached, int to){
    if (chdir(live) != 0) return 0;
    di_print_log();
    di->armed = 0;
    if (di_build_image(img, cached) != 0) return 0;
    printf("  POWER LOSS -> image\n");
    run(img, p_recover_catchup, 0);
    return healed_to(img, to);
}

/* ===== B: a SIGKILL during boot recovery, after the ghost rollback ===== */
static void p1_ghosts152_armed(void* a){ (void)a; di_arm(); build_ghosts(152); }
static void p2_recover_then_kill(void* a){
    (void)a; boot();
    long rb = utxo_live_recover_at_boot(store_buf);
    printf("  p2: recover_at_boot -> %ld (152 and 151 rolled back, their slots cleared); SIGKILL\n", rb);
    fflush(stdout); raise(SIGKILL);
}
static void p2_recover_then_close(void* a){
    (void)a; boot();
    long rb = utxo_live_recover_at_boot(store_buf);
    printf("  p2: recover_at_boot -> %ld; clean close\n", rb);
    utxo_live_close();
}
/* p1 with its buffer landed (a full buffer, long before the batch's
 * checkpoint): the ghosts' ops are in the WAL, so their reversal is real */
static void p1_ghosts152_drained(void* a){
    (void)a; build_ghosts(152);
    printf("  p1: the WAL buffer lands (as a full buffer does) -> %ld; dies without a close\n", utxo_live_test_wal_drain());
}
static int sc_ghostkill(int control){
    char live[640], img[640], snap[640]; paths("ghostkill", control, live, img, snap);
    run(live, p1_ghosts152_drained, 0);
    int st = run(live, control ? p2_recover_then_close : p2_recover_then_kill, 0);
    if (!control) printf("  p2 exit %d (1009 = SIGKILL)\n", st);
    run(live, p_recover_catchup, 0);
    return healed_to(live, 152);
}

/* ===== A1: a flush makes un-checkpointed spends durable ===== */
static void p1_flush(void* a){
    (void)a; di_arm(); build_ghosts(152);
    printf("  p1: utxo_live_flush_now -> %ld (writer's run, manifest, utxo.idx retired)\n", utxo_live_flush_now());
}
static int sc_flushundo(int control){
    static const char* const arch[]  = { "blk", "index.dat", 0 };
    static const char* const archu[] = { "blk", "index.dat", "rev", "undo.idx", 0 };
    char live[640], img[640], snap[640]; paths("flushundo", control, live, img, snap);
    if (di_install(snap) != 0) return 0;
    if (run(live, p1_flush, 0) != 0) return 0;
    return image_then_recover(live, img, control ? archu : arch, 152);
}

/* ===== A2: the buffer lands, the kernel writes the WAL back ===== */
static void p1_drain(void* a){
    (void)a; di_arm(); build_ghosts(152);
    printf("  p1: the WAL buffer lands (as a full buffer does) -> %ld\n", utxo_live_test_wal_drain());
}
static int sc_walwb(int control){
    static const char* const c[]  = { "blk", "index.dat", "utxo.dat", 0 };
    static const char* const cu[] = { "blk", "index.dat", "utxo.dat", "rev", "undo.idx", 0 };
    char live[640], img[640], snap[640]; paths("walwb", control, live, img, snap);
    if (di_install(snap) != 0) return 0;
    if (run(live, p1_drain, 0) != 0) return 0;
    return image_then_recover(live, img, control ? cu : c, 152);
}

/* ===== A3: a flush between block 151's coinbase and its first spend ===== */
static void after_tx0(long h){
    if (h != 151) return;
    printf("  p1: flush after block 151's coinbase -> %ld; POWER LOSS here\n", utxo_live_flush_now());
    di_freeze_now();
}
static void p1_cbflush(void* a){
    (void)a; di_arm();
    boot(); append(0, 151);
    utxo_live_test_set_ckpt_batch(0);
    utxo_live_test_set_after_tx0(after_tx0);
    long r = utxo_live_catchup(store_buf);
    printf("  p1: catch-up 0..151 -> %ld\n", r);
}
static int sc_cbflush(int control){
    static const char* const c[]  = { "blk", "index.dat", 0 };
    static const char* const cu[] = { "blk", "index.dat", "rev", "undo.idx", 0 };
    char live[640], img[640], snap[640]; paths("cbflush", control, live, img, snap);
    if (di_install(snap) != 0) return 0;
    if (run(live, p1_cbflush, 0) != 0) return 0;
    return image_then_recover(live, img, control ? cu : c, 151);
}

/* ===== A4: SIGKILL, then a power loss in the middle of the boot rollback ===== */
static void p2_rollback_powerloss(void* a){
    (void)a; di_arm();
    di_freeze_after("utxo.dat", 1);       /* the first WAL fsync: 152's reversal, before 151's */
    boot();
    long rb = utxo_live_recover_at_boot(store_buf);
    printf("  p2: recover_at_boot -> %ld (the image is the power loss after its first WAL fsync)\n", rb);
}
/* copy the files of `from` whose names start with one of `pre` into `to` */
static void copy_named(const char* from, const char* to, const char* const* pre){
    DIR* d = opendir(from); struct dirent* e; char a[1400], b[1400];
    if (mkdir(to, 0755) != 0 && errno != EEXIST) return;
    while (d && (e = readdir(d))){
        if (e->d_type != DT_REG || !di_cached(e->d_name, pre)) continue;
        if (snprintf(a, sizeof a, "%s/%s", from, e->d_name) >= (int)sizeof a) continue;
        if (snprintf(b, sizeof b, "%s/%s", to, e->d_name) >= (int)sizeof b) continue;
        di_copy_path(a, b);
    }
    if (d) closedir(d);
}
static int sc_ghostchain(int control){
    static const char* const c[]    = { "blk", "index.dat", 0 };
    static const char* const undo[] = { "rev", "undo.idx", 0 };
    char live[640], img[640], snap[640]; paths("ghostchain", control, live, img, snap);
    char keep[700]; snprintf(keep, sizeof keep, "%s.p1undo", live);
    if (di_install(snap) != 0) return 0;
    run(live, p1_ghosts152_armed, 0);      /* dies without a close: its unsynced writes stay in the page cache */
    copy_named(live, keep, undo);          /* the control's kept write: p1's undo as the page cache held it */
    if (run(live, p2_rollback_powerloss, 0) != 0) return 0;
    if (chdir(live) != 0) return 0;
    di_print_log(); di->armed = 0;
    if (di_build_image(img, c) != 0) return 0;
    if (control) copy_named(keep, img, undo);
    printf("  POWER LOSS -> image%s\n", control ? " (with p1's undo as it wrote it)" : "");
    run(img, p_recover_catchup, 0);
    return healed_to(img, 152);
}

/* ===== E: utxo.idx's log_off past the WAL's durable end ===== */
static void p2_logoff(void* a){
    (void)a; boot();
    long rb = utxo_live_recover_at_boot(store_buf);
    long r = utxo_live_catchup(store_buf);
    printf("  p2: recover_at_boot -> %ld, catch-up -> %ld\n", rb, r);
    append(153, 153);
    r = utxo_live_catchup(store_buf);
    printf("  p2: block 153 (spends C, creates D) -> %ld; applied %ld; clean close\n", r, utxo_live_applied_height());
    utxo_live_close();
}
static void p3_check(void* a){
    (void)a; boot();
    int c = has(152), d = has(153);
    printf("  p3 (restart): applied %ld; C (spent by 153) present %d; D (created by 153) present %d; count %ld\n",
           utxo_live_applied_height(), c, d, utxo_live_count());
    FILE* f = fopen("result.txt", "w"); if (f){ fprintf(f, "%ld %d %d %ld\n", utxo_live_applied_height(), c, d, utxo_live_count()); fclose(f); }
}
static int sc_logoff(int control){
    static const char* const cu[]  = { "blk", "index.dat", "rev", "undo.idx", 0 };
    static const char* const cuw[] = { "blk", "index.dat", "rev", "undo.idx", "utxo.dat", 0 };
    char live[640], img[640], snap[640]; paths("logoff", control, live, img, snap);
    if (di_install(snap) != 0) return 0;
    if (run(live, p1_flush, 0) != 0) return 0;
    if (chdir(live) != 0) return 0;
    di_print_log(); di->armed = 0;
    if (di_build_image(img, control ? cuw : cu) != 0) return 0;
    { char p[700]; struct stat sb; snprintf(p, sizeof p, "%s/utxo.dat", img);
      long wal = stat(p, &sb) == 0 ? (long)sb.st_size : -1;
      snprintf(p, sizeof p, "%s/utxo.idx", img); FILE* f = fopen(p, "rb"); u8 h[20] = {0}; long lo = -1;
      if (f){ if (fread(h, 1, 20, f) == 20) memcpy(&lo, h + 4, 8); fclose(f); }
      printf("  POWER LOSS -> image: utxo.dat %ld bytes, utxo.idx log_off %ld\n", wal, lo); }
    run(img, p2_logoff, 0);
    run(img, p3_check, 0);
    long v[4]; if (read_res(img, v)) return 0;
    return v[0] == 153 && v[1] == 0 && v[2] == 1 && v[3] == 154;
}

/* ===== C: the applied height durable, the archive record not ===== */
static void p1_archive(void* a){
    int nosync = *(int*)a;
    di_arm();
    boot();
    if (nosync) store_set_sync(0);        /* the download committer: no per-block sync */
    append(0, 149);
    if (!nosync){                         /* an earlier durable point of the archive (a committer chunk) */
        int fd = open("index.dat", O_RDONLY); if (fd >= 0){ fdatasync(fd); close(fd); }
    }
    append(150, 150);
    utxo_live_test_set_ckpt_batch(0);
    long r = utxo_live_catchup(store_buf);
    printf("  p1: catch-up 0..150 -> %ld, applied %ld (per-block checkpoints)\n", r, utxo_live_applied_height());
}
static void p2_boot_read(void* a){
    (void)a; boot();
    long rb = utxo_live_recover_at_boot(store_buf);
    static u8 b[1024];
    long len = store_read_at(store_buf, 150, b, sizeof b);
    long tip = *(int*)(store_buf + 24);
    printf("  p2: archive tip %ld, applied %ld, recover_at_boot -> %ld, block 150 read -> %ld bytes\n",
           tip, utxo_live_applied_height(), rb, len);
    FILE* f = fopen("result.txt", "w");
    if (f){ fprintf(f, "%ld %ld %ld %ld\n", rb, tip, utxo_live_applied_height(), len == g_len[150] ? 1L : 0L); fclose(f); }
}
static int sc_archive(int nosync, int control){
    static const char* const none[] = { 0 };
    static const char* const ci[]   = { "index.dat", 0 };
    static const char* const cbi[]  = { "blk", "index.dat", 0 };
    char live[640], img[640], snap[640]; paths(nosync ? "archive-nosync" : "archive", control, live, img, snap);
    if (di_install(snap) != 0) return 0;
    if (run(live, p1_archive, &nosync) != 0) return 0;
    if (chdir(live) != 0) return 0;
    di_print_log(); di->armed = 0;
    if (di_build_image(img, control ? (nosync ? cbi : ci) : none) != 0) return 0;
    printf("  POWER LOSS -> image\n");
    run(img, p2_boot_read, 0);
    long v[4]; if (read_res(img, v)) return 0;
    return v[0] >= 0 && v[1] == 150 && v[2] == 150 && v[3] == 1;
}

/* ===== F: a forked child drains with its parent's bytes buffered ===== */
static long wal_size(void){ struct stat sb; return stat("utxo.dat", &sb) == 0 ? (long)sb.st_size : -1; }
static void p_fork(void* a){
    (void)a; build_ghosts(152);
    long s0 = wal_size();
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) _exit(utxo_store_wal_drain(0) == 0 ? 0 : 1);   /* the drain a child's own reload starts with */
    int st; while (waitpid(c, &st, 0) < 0 && errno == EINTR) {}
    long s1 = wal_size();
    long r = utxo_live_test_wal_drain();
    long s2 = wal_size();
    printf("  p1: utxo.dat %ld bytes with 151..152 buffered; after a child's drain %ld; after the parent's own drain (%ld) %ld\n", s0, s1, r, s2);
    FILE* f = fopen("result.txt", "w"); if (f){ fprintf(f, "%ld %ld %ld 0\n", s0, s1, s2); fclose(f); }
}
static int sc_fork(int control){
    char live[640], img[640], snap[640]; paths("fork", control, live, img, snap);
    run(live, p_fork, 0);
    long v[4]; if (read_res(live, v)) return 0;
    /* the scenario: the child landed nothing; the control: the bytes were pending, the parent lands them */
    return control ? v[2] > v[0] : v[1] == v[0];
}

/* ===== STO-D / STO-W: the weak file system ===== */
static const char* const g_arch[] = { "blk", "index.dat", 0 };
/* the runner's half of a weak power loss: the image with the `kept` name ops */
static int weak_image(const char* live, const char* img, const char* const* kept){
    if (chdir(live) != 0) return 0;
    di_print_log(); di->armed = 0;
    if (di_build_image_weak(img, g_arch, kept) != 0) return 0;
    printf("  POWER LOSS -> image (name ops kept beyond the last directory fsync:");
    for (int i = 0; kept[i]; i++) printf(" %s*", kept[i]);
    printf("%s)\n", kept[0] ? "" : " none");
    return 1;
}
static int weak_recover(const char* live, const char* img, const char* const* kept, int to){
    if (!weak_image(live, img, kept)) return 0;
    run(img, p_recover_catchup, 0);
    return healed_to(img, to);
}
/* recovery + catch-up, then which of C (spent by 153) and D (created by 153) is there */
static void p_recover_cd(void* a){
    (void)a; boot();
    long rb = utxo_live_recover_at_boot(store_buf);
    long r = rb < 0 ? -9 : utxo_live_catchup(store_buf);
    int c = has(152), d = has(153);
    printf("  recover_at_boot -> %ld; catch-up -> %ld; applied %ld; C present %d, D present %d; count %ld\n",
           rb, r, utxo_live_applied_height(), c, d, utxo_live_count());
    FILE* f = fopen("result.txt", "w"); if (f){ fprintf(f, "%ld %d %d %ld\n", utxo_live_applied_height(), c, d, utxo_live_count()); fclose(f); }
}
static void p1_weak(int to, int async){
    g_cfg.async_flush = async;
    di_arm(); build_ghosts(to);
}

/* D1: the publish's directory fsync fails; a later utxo.idx rename survives alone */
static void p1_dirpub(void* a){
    (void)a; p1_weak(152, 1);
    di_fail_dir_after("utxo_manifest.dat.pub", 1);   /* the directory fsync after the manifest's rename */
    di_lose_dir_after("utxo.idx.tmp", 1);            /* the power goes before the one after utxo.idx's */
    printf("  p1: utxo_live_flush_now -> %ld (the manifest's directory fsync answers EIO)\n", utxo_live_flush_now());
}
static int sc_dirpub(int control){
    static const char* const k[]  = { "utxo.idx", 0 };
    static const char* const kc[] = { "utxo.idx", "utxo_manifest.dat", "utxo_run_", 0 };
    char live[640], img[640], snap[640]; paths("dirpub", control, live, img, snap);
    if (di_install(snap) != 0) return 0;
    di_set_weak();
    if (run(live, p1_dirpub, 0) != 0) return 0;
    return weak_recover(live, img, control ? kc : k, 152);
}

/* D2: the directory fsync after the utxo.idx rename fails; the checkpoint's
 * height rename survives, the utxo.idx rename does not */
static void p1_dirretire(void* a){
    (void)a; p1_weak(152, 1);
    di_fail_dir_after("utxo.idx.tmp", 1);
    printf("  p1: utxo_live_flush_now -> %ld (the directory fsync after utxo.idx's rename answers EIO)\n", utxo_live_flush_now());
    append(153, 153);
    utxo_live_test_set_ckpt_batch(1000);              /* one checkpoint, at the catch-up's end */
    di_lose_dir_after("utxo_applied_height.dat.tmp", 1);
    long r = utxo_live_catchup(store_buf);
    printf("  p1: catch-up to 153 (spends C, creates D) -> %ld, checkpointed: the WAL fsynced, the power goes before the directory fsync\n", r);
}
static int sc_dirretire(int control){
    static const char* const k[]  = { "utxo_applied_height.dat", 0 };
    static const char* const kc[] = { "utxo_applied_height.dat", "utxo.idx", 0 };
    char live[640], img[640], snap[640]; paths("dirretire", control, live, img, snap);
    if (di_install(snap) != 0) return 0;
    di_set_weak();
    if (run(live, p1_dirretire, 0) != 0) return 0;
    if (!weak_image(live, img, control ? kc : k)) return 0;
    run(img, p_recover_cd, 0);
    long v[4]; if (read_res(img, v)) return 0;
    return v[0] == 153 && v[1] == 0 && v[2] == 1 && v[3] == 154;
}

static int count_runs(void){
    DIR* d = opendir("."); struct dirent* e; int n = 0;
    while (d && (e = readdir(d))) if (!strncmp(e->d_name, "utxo_run_", 9)) n++;
    if (d) closedir(d);
    return n;
}
/* two runs of a size (the leveled pick merges only those), blocks 151..152
 * applied without a checkpoint, then a background merge of both */
static void p1_tworuns(void){
    g_cfg.async_flush = 1;
    di_arm(); boot();
    append(0, 75);
    long r1 = utxo_live_catchup(store_buf), f1 = utxo_live_flush_now();
    append(76, 150);
    long r2 = utxo_live_catchup(store_buf), f2 = utxo_live_flush_now();
    printf("  p1: catch-up 0..75 -> %ld, flush -> %ld; catch-up 76..150 -> %ld, flush -> %ld; %d run files\n", r1, f1, r2, f2, count_runs());
    append(151, 152);
    for (int h = 151; h <= 152; h++)
        if (utxo_live_apply_block(g_blk[h], (u64)g_len[h], h) != 1){ printf("  apply %d failed\n", h); _exit(9); }
    printf("  p1: applied 151..152 without a checkpoint\n");
}
/* D3/W4: the merge's manifest renamed, the directory fsync after it fails */
static void p1_dirmerge(void* a){
    (void)a; p1_tworuns();
    utxo_live_set_run_budget(1); utxo_live_test_set_apply_lag(0);
    di_fail_dir_after("utxo_manifest.dat.pub", 1);
    int st = utxo_live_test_compact_nowait();
    while (utxo_live_test_compact_pid()){ utxo_live_bg_poll(); usleep(2000); }
    printf("  p1: background merge started (%d) and adopted, the directory fsync after its manifest answered EIO; %d run files\n", st, count_runs());
}
static int sc_dirmerge(int control){
    static const char* const k[]  = { "utxo_run_", 0 };
    static const char* const kc[] = { "utxo_run_", "utxo_manifest.dat", 0 };
    char live[640], img[640], snap[640]; paths("dirmerge", control, live, img, snap);
    if (di_install(snap) != 0) return 0;
    di_set_weak();
    if (run(live, p1_dirmerge, 0) != 0) return 0;
    return weak_recover(live, img, control ? kc : k, 152);
}
static void p2_boot_sweep(void* a){
    (void)a; boot();
    printf("  p2: boot (the orphan sweep ran); %d run files\n", count_runs());
}
static int sc_sweep(int control){
    static const char* const k[]  = { "utxo_run_", 0 };
    static const char* const kc[] = { "utxo_run_", "utxo_manifest.dat", 0 };
    char live[640], img[640], snap[640]; paths("sweep", control, live, img, snap);
    if (di_install(snap) != 0) return 0;
    di_set_weak();
    if (run(live, p1_dirmerge, 0) != 0) return 0;
    if (run(live, p2_boot_sweep, 0) != 0) return 0;
    return weak_recover(live, img, control ? kc : k, 152);
}

/* D4: mac_flush's open(".") after the manifest rename fails */
static void p1_opendot(void* a){
    (void)a; p1_weak(152, 0);
    append(153, 153);
    di_fail_open_dot_after("utxo_manifest.tmp", 1);
    printf("  p1: inline flush -> %ld (its open(\".\") after the manifest rename fails)\n", utxo_live_flush_now());
    di_lose_dir_after("utxo_applied_height.dat.tmp", 1);
    long r = utxo_live_catchup(store_buf);
    printf("  p1: catch-up to 153 -> %ld, checkpointed: the WAL fsynced, the power goes before the directory fsync\n", r);
}
static int sc_opendot(int control){
    static const char* const k[]  = { 0 };
    static const char* const kc[] = { "utxo_manifest.dat", 0 };
    char live[640], img[640], snap[640]; paths("opendot", control, live, img, snap);
    if (di_install(snap) != 0) return 0;
    di_set_weak();
    if (run(live, p1_opendot, 0) != 0) return 0;
    return weak_recover(live, img, control ? kc : k, 153);
}

/* D5: the checkpoint's directory fsync fails, the power goes later */
static void p1_dirckpt(void* a){
    (void)a; p1_weak(150, 1);
    append(151, 152);
    utxo_live_test_set_ckpt_batch(1000);              /* one checkpoint, at the catch-up's end */
    di_fail_dir_after("utxo_applied_height.dat.tmp", 1);
    long r = utxo_live_catchup(store_buf);
    printf("  p1: catch-up 151..152 -> %ld, applied %ld (its checkpoint's directory fsync answers EIO)\n", r, utxo_live_applied_height());
}
static int sc_dirckpt(int control){
    static const char* const k[]  = { 0 };
    static const char* const kc[] = { "utxo_applied_height.dat", 0 };
    char live[640], img[640], snap[640]; paths("dirckpt", control, live, img, snap);
    if (di_install(snap) != 0) return 0;
    di_set_weak();
    if (run(live, p1_dirckpt, 0) != 0) return 0;
    return weak_recover(live, img, control ? kc : k, 152);
}

/* W1/W2: a flush's manifest rename survives, its run's create does not */
static void p1_runcreate(void* a){
    int async = *(int*)a;
    p1_weak(152, async);
    di_lose_dir_after(async ? "utxo_manifest.dat.pub" : "utxo_manifest.tmp", 1);
    printf("  p1: %s flush -> %ld (the power goes at the directory fsync after the manifest's rename)\n", async ? "async" : "inline", utxo_live_flush_now());
}
static int sc_runcreate(int async, int control){
    static const char* const k[]  = { "utxo_manifest.dat", 0 };
    static const char* const kc[] = { "utxo_manifest.dat", "utxo_run_", 0 };
    char live[640], img[640], snap[640]; paths(async ? "runcreate" : "runcreate-inline", control, live, img, snap);
    if (di_install(snap) != 0) return 0;
    di_set_weak();
    if (run(live, p1_runcreate, &async) != 0) return 0;
    return weak_recover(live, img, control ? kc : k, 152);
}
/* W3: the inline compaction's merged run */
static void p1_runcreate_merge(void* a){
    (void)a; p1_tworuns();
    di_lose_dir_after("utxo_manifest.tmp", 1);
    printf("  p1: inline merge of both runs -> %ld (the power goes at the directory fsync after the manifest's rename)\n",
           utxo_lsm_compact_range(utxo_live_test_lst(), 0, 2));
}
static int sc_runcreate_merge(int control){
    static const char* const k[]  = { "utxo_manifest.dat", 0 };
    static const char* const kc[] = { "utxo_manifest.dat", "utxo_run_", 0 };
    char live[640], img[640], snap[640]; paths("runcreate-merge", control, live, img, snap);
    if (di_install(snap) != 0) return 0;
    di_set_weak();
    if (run(live, p1_runcreate_merge, 0) != 0) return 0;
    return weak_recover(live, img, control ? kc : k, 152);
}

/* ---- the runner: each scenario in its own process (the seccomp filter and
 * the recorder are per scenario) ---- */
static int g_which, g_ctl;
static int scenario(void){
    switch (g_which){
    case 0: return sc_ghostkill(g_ctl);
    case 1: return sc_flushundo(g_ctl);
    case 2: return sc_walwb(g_ctl);
    case 3: return sc_cbflush(g_ctl);
    case 4: return sc_ghostchain(g_ctl);
    case 5: return sc_logoff(g_ctl);
    case 6: return sc_archive(0, g_ctl);
    case 7: return sc_archive(1, g_ctl);
    case 8: return sc_fork(g_ctl);
    case 9: return sc_dirpub(g_ctl);
    case 10: return sc_dirretire(g_ctl);
    case 11: return sc_dirmerge(g_ctl);
    case 12: return sc_opendot(g_ctl);
    case 13: return sc_dirckpt(g_ctl);
    case 14: return sc_runcreate(1, g_ctl);
    case 15: return sc_runcreate(0, g_ctl);
    case 16: return sc_runcreate_merge(g_ctl);
    case 17: return sc_sweep(g_ctl);
    }
    return 0;
}
int main(int argc, char** argv){
    tt_isolate();
    setvbuf(stdout, 0, _IOLBF, 0);
    build_chain();
    if (snprintf(g_base, sizeof g_base, "%s", tt_workdir()) >= (int)sizeof g_base){ printf("FAIL work dir path too long\n"); return 1; }
    static const char* names[] = { "STO-B ghostkill", "STO-A1 flushundo", "STO-A2 walwb", "STO-A3 cbflush",
                                   "STO-A4 ghostchain", "STO-E logoff", "STO-C1 archive", "STO-C2 archive-nosync",
                                   "STO-A fork", "STO-D1 dirpub", "STO-D2 dirretire", "STO-D3 dirmerge",
                                   "STO-D4 opendot", "STO-D5 dirckpt", "STO-W1 runcreate", "STO-W2 runcreate-inline",
                                   "STO-W3 runcreate-merge", "STO-W4 sweep" };
    int only = argc > 1 ? atoi(argv[1]) : -1;
    int failures = 0;
    for (int w = 0; w < 18; w++){
        if (only >= 0 && w != only) continue;
        for (int c = 0; c <= 1; c++){
            printf("--- %s%s\n", names[w], c ? (w == 8 ? " (control: the bytes were pending)" : " (control: the lost write kept)") : "");
            g_which = w; g_ctl = c;
            fflush(stdout);
            pid_t p = fork();
            if (p == 0) _exit(scenario() ? 0 : 1);
            int st; while (waitpid(p, &st, 0) < 0 && errno == EINTR) {}
            int ok = WIFEXITED(st) && WEXITSTATUS(st) == 0;
            printf("%s %s%s: %s\n", ok ? "PASS" : "FAIL", names[w], c ? " control" : "", ok ? "healed" : "NOT healed");
            if (!ok) failures++;
        }
    }
    if (failures){ printf("\n%d FAILURE(S)\n", failures); return 1; }
    printf("\nALL TESTS PASSED\n");
    return 0;
}
