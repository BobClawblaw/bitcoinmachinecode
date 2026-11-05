/* formal/storage/crash/crash_storage.c -- crash-injection confirmation of the
 * TLC traces in formal/storage/README.md against the real write and recovery
 * paths (daemon/utxo_live.c, bitcoin_utxo_lsm.asm, undo_log.c, the archive).
 *
 *   crash_storage <scenario> <scratch-dir>
 *
 * Every scenario runs each "process" of the trace as a forked child of a
 * parent that never touches the store, so each child starts with a fresh
 * utxo_live state, exactly like a restarted daemon. A SIGKILL is a real
 * SIGKILL; a power loss is the durable image durable_image.h records from the
 * real fsync/fdatasync calls (ext4 namespace semantics). Each scenario prints
 * the expected and the observed result and exits 0 when it observed what the
 * scenario claims (the defect for a "bug" scenario, a clean recovery for its
 * control), 1 otherwise.
 *
 * The chain: blocks 0..149 coinbase-only, block 150 spends block 0's coinbase
 * creating A; 151 spends A creating B; 152 spends B creating C; 153 spends C
 * creating D (the shape of tests/test_utxo_ghost_resume.c, whose block
 * builders this copies). Steady-state memtable sizing in every process. */
#define _GNU_SOURCE
#include "durable_image.h"
#include <sys/wait.h>

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
extern int  utxo_live_apply_block(const void* blockbuf, u64 blocklen, long height);
extern long utxo_live_flush_now(void);
extern long utxo_live_recover_at_boot(void* store_buf);
extern void utxo_live_test_force_sizing(int mode);
extern void utxo_live_test_set_ckpt_batch(long n);
extern const char* utxo_live_last_reject(void);
extern long utxo_live_lsm_get(const u8 txid_wire[32], unsigned int vout, u64* value, unsigned long* height,
                              unsigned long* is_coinbase, const u8** script, unsigned long* slen);

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u; (void)txid; (void)index; (void)value; (void)script; (void)slen; abort();
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

static u8 store_buf[4096];
static int has(int h){ u64 v; unsigned long ht, cb, sl; const u8* s; return (int)utxo_live_lsm_get(g_out[h], 0, &v, &ht, &cb, &s, &sl); }
static void boot(void){
    memset(store_buf, 0, sizeof store_buf);
    utxo_live_test_force_sizing(0);
    store_init(store_buf); store_reload(store_buf);
    if (utxo_live_init(".") != 1){ printf("  utxo_live_init failed\n"); _exit(9); }
}
static void append(int lo, int hi){ for (int h = lo; h <= hi; h++) if (store_append(store_buf, g_hash[h], g_blk[h], g_len[h]) != h){ printf("  append %d failed\n", h); _exit(9); } }
/* process 1: 0..150 applied and checkpointed, then 151/152 applied with no checkpoint (a batch) */
static void p_build(int ghost_to){
    boot();
    append(0, 150);
    long r = utxo_live_catchup(store_buf);
    printf("  p1: catchup 0..150 -> %ld, applied %ld\n", r, utxo_live_applied_height());
    append(151, ghost_to);
    for (int h = 151; h <= ghost_to; h++)
        if (utxo_live_apply_block(g_blk[h], (u64)g_len[h], h) != 1){ printf("  apply %d failed\n", h); _exit(9); }
    printf("  p1: applied 151..%d without a checkpoint (applied height on disk stays %ld)\n", ghost_to, utxo_live_applied_height());
}
typedef void (*proc_fn)(void* arg);
static int run(const char* dir, proc_fn fn, void* arg){
    fflush(stdout);
    pid_t p = fork();
    if (p == 0){ if (chdir(dir) != 0) _exit(8); fn(arg); fflush(stdout); _exit(0); }
    int st; waitpid(p, &st, 0); fflush(stdout);
    return WIFSIGNALED(st) ? 1000 + WTERMSIG(st) : WEXITSTATUS(st);
}
/* recovery + catch-up; *out = { recover, catchup, applied, count } */
static long g_res[8];
static void p_recover_catchup(void* a){
    long* out = a ? (long*)a : g_res; (void)out;
    boot();
    long rb = utxo_live_recover_at_boot(store_buf);
    long r = rb < 0 ? -9 : utxo_live_catchup(store_buf);
    printf("  recover_at_boot -> %ld; catchup -> %ld; applied %ld; count %ld%s%s\n", rb, r, utxo_live_applied_height(),
           utxo_live_count(), utxo_live_last_reject()[0] ? "; reject: " : "", utxo_live_last_reject());
    FILE* f = fopen("result.txt", "w"); if (f){ fprintf(f, "%ld %ld %ld %ld\n", rb, r, utxo_live_applied_height(), utxo_live_count()); fclose(f); }
}
static int read_res(const char* dir, long v[4]){
    char p[600]; snprintf(p, sizeof p, "%s/result.txt", dir);
    FILE* f = fopen(p, "r"); if (!f) return -1;
    int n = fscanf(f, "%ld %ld %ld %ld", &v[0], &v[1], &v[2], &v[3]); fclose(f); return n == 4 ? 0 : -1;
}

/* ===== B: a SIGKILL during boot recovery (after the ghost rollback) ===== */
static void p1_ghost(void* a){ (void)a; p_build(152); /* dies: no close, the WAL buffer was drained at each block end */ }
static void p2_recover_then_kill(void* a){
    (void)a; boot();
    long rb = utxo_live_recover_at_boot(store_buf);
    printf("  p2: recover_at_boot -> %ld (rolled back 152, 151; their undo slots cleared); SIGKILL now\n", rb);
    fflush(stdout); raise(SIGKILL);
}
static void p2_recover_then_close(void* a){
    (void)a; boot();
    long rb = utxo_live_recover_at_boot(store_buf);
    printf("  p2: recover_at_boot -> %ld; clean close\n", rb);
    utxo_live_close();
}
static int sc_ghostkill(const char* base, int control){
    char d[512]; snprintf(d, sizeof d, "%s/ghostkill%s", base, control == 1 ? "-ctl-nokill" : control == 2 ? "-ctl-close" : "");
    mkdir(d, 0755);
    run(d, p1_ghost, 0);
    if (control == 0) printf("  p2 exit: %d (1009 = SIGKILL)\n", run(d, p2_recover_then_kill, 0));
    if (control == 2) run(d, p2_recover_then_close, 0);
    run(d, p_recover_catchup, 0);
    long v[4]; if (read_res(d, v)) return 1;
    int healed = v[0] >= 0 && v[1] == 2 && v[2] == 152 && v[3] == 153;
    printf("  expected: catchup re-applies 151..152 (2), applied 152, count 153; observed: %s\n", healed ? "healed" : "NOT healed");
    return healed;
}

/* ===== power-loss images ===== */
struct img { const char* const* cached; int ghost_to; int flush; int arm_ckpt; };
static char g_snap[600], g_img[600];
static void p1_image(void* a){
    struct img* m = a;
    if (di_install(g_snap, DI_EXT4) != 0){ printf("  seccomp install failed\n"); _exit(9); }
    if (m->arm_ckpt) utxo_live_test_set_ckpt_batch(0);
    p_build(m->ghost_to);
    if (m->flush){
        long fr = utxo_live_flush_now();
        printf("  p1: utxo_live_flush_now -> %ld (the async writer's run, the manifest, utxo.idx retired)\n", fr);
    }
    di_print_log("p1");
    printf("  p1: undo.idx synced: %s, rev00000.dat synced: %s, index.dat synced: %s\n",
           di_synced("undo.idx") ? "yes" : "no", di_synced("rev00000.dat") ? "yes" : "no", di_synced("index.dat") ? "yes" : "no");
    printf("  POWER LOSS: image %s\n", g_img);
    if (di_build_image(g_img, m->cached) != 0) _exit(9);
}

/* A: the flush makes un-checkpointed spends durable; their undo is not */
static int sc_flushundo(const char* base, int control){
    static const char* const arch[]  = { "blk", "index.dat", 0 };
    static const char* const archu[] = { "blk", "index.dat", "rev", "undo.idx", 0 };
    snprintf(g_snap, sizeof g_snap, "%s/flushundo%s.snap", base, control ? "-ctl" : "");
    char live[512]; snprintf(live, sizeof live, "%s/flushundo%s.live", base, control ? "-ctl" : "");
    snprintf(g_img, sizeof g_img, "%s/flushundo%s.img", base, control ? "-ctl" : "");
    mkdir(live, 0755);
    struct img m = { control ? archu : arch, 152, 1, 0 };
    if (run(live, p1_image, &m) != 0) return 1;
    run(g_img, p_recover_catchup, 0);
    long v[4]; if (read_res(g_img, v)) return 1;
    int healed = v[0] >= 0 && v[1] == 2 && v[2] == 152 && v[3] == 153;
    printf("  expected: recovery rolls 151..152 back and catch-up re-applies them; observed: %s\n", healed ? "healed" : "NOT healed");
    return healed;
}
/* A': no flush -- only the kernel writing the WAL back before the undo (the ST2-4 residual) */
static int sc_walwb(const char* base){
    static const char* const c[] = { "blk", "index.dat", "utxo.dat", 0 };
    snprintf(g_snap, sizeof g_snap, "%s/walwb.snap", base);
    char live[512]; snprintf(live, sizeof live, "%s/walwb.live", base);
    snprintf(g_img, sizeof g_img, "%s/walwb.img", base);
    mkdir(live, 0755);
    struct img m = { c, 152, 0, 0 };
    if (run(live, p1_image, &m) != 0) return 1;
    run(g_img, p_recover_catchup, 0);
    long v[4]; if (read_res(g_img, v)) return 1;
    int healed = v[0] >= 0 && v[1] == 2 && v[2] == 152 && v[3] == 153;
    printf("  expected: healed; observed: %s\n", healed ? "healed" : "NOT healed");
    return healed;
}

/* E: utxo.idx's log_off is durable past the WAL's durable end */
static void p2_logoff(void* a){
    (void)a; boot();
    long rb = utxo_live_recover_at_boot(store_buf);
    long r = utxo_live_catchup(store_buf);
    printf("  p2: recover_at_boot -> %ld, catchup -> %ld (151..152 re-applied)\n", rb, r);
    append(153, 153);
    r = utxo_live_catchup(store_buf);
    printf("  p2: block 153 (spends C, creates D) -> %ld; applied %ld; C present %d, D present %d; clean close\n",
           r, utxo_live_applied_height(), has(152), has(153));
    utxo_live_close();
}
static void p3_check(void* a){
    (void)a; boot();
    int c = has(152), d = has(153);
    printf("  p3 (restart): applied %ld; C (spent by 153) present %d; D (created by 153) present %d; count %ld\n",
           utxo_live_applied_height(), c, d, utxo_live_count());
    FILE* f = fopen("result.txt", "w"); if (f){ fprintf(f, "%ld %d %d %ld\n", utxo_live_applied_height(), c, d, utxo_live_count()); fclose(f); }
}
static int sc_logoff(const char* base, int control){
    static const char* const cu[]  = { "blk", "index.dat", "rev", "undo.idx", 0 };
    static const char* const cuw[] = { "blk", "index.dat", "rev", "undo.idx", "utxo.dat", 0 };
    snprintf(g_snap, sizeof g_snap, "%s/logoff%s.snap", base, control ? "-ctl" : "");
    char live[512]; snprintf(live, sizeof live, "%s/logoff%s.live", base, control ? "-ctl" : "");
    snprintf(g_img, sizeof g_img, "%s/logoff%s.img", base, control ? "-ctl" : "");
    mkdir(live, 0755);
    struct img m = { control ? cuw : cu, 152, 1, 0 };
    if (run(live, p1_image, &m) != 0) return 1;
    { char p[700]; struct stat sb; snprintf(p, sizeof p, "%s/utxo.dat", g_img);
      long wal = stat(p, &sb) == 0 ? (long)sb.st_size : -1;
      snprintf(p, sizeof p, "%s/utxo.idx", g_img); FILE* f = fopen(p, "rb"); u8 h[20] = {0}; long lo = -1;
      if (f){ if (fread(h, 1, 20, f) == 20) memcpy(&lo, h + 4, 8); fclose(f); }
      printf("  image: utxo.dat %ld bytes, utxo.idx log_off %ld\n", wal, lo); }
    run(g_img, p2_logoff, 0);
    run(g_img, p3_check, 0);
    long v[4]; if (read_res(g_img, v)) return 1;
    int ok = v[0] == 153 && v[1] == 0 && v[2] == 1;
    printf("  expected: applied 153, C absent, D present; observed: %s\n", ok ? "consistent" : "INCONSISTENT");
    return ok;
}

/* C: the archive's index.dat record is never synced; the applied height is */
static void p2_boot_only(void* a){
    (void)a; boot();
    long rb = utxo_live_recover_at_boot(store_buf);
    printf("  p2: archive tip %d, applied %ld, recover_at_boot -> %ld\n", *(int*)(store_buf + 24), utxo_live_applied_height(), rb);
    FILE* f = fopen("result.txt", "w"); if (f){ fprintf(f, "%ld 0 %ld 0\n", rb, utxo_live_applied_height()); fclose(f); }
}
static int sc_archive(const char* base, int control){
    static const char* const c[] = { "index.dat", 0 };
    snprintf(g_snap, sizeof g_snap, "%s/archive%s.snap", base, control ? "-ctl" : "");
    char live[512]; snprintf(live, sizeof live, "%s/archive%s.live", base, control ? "-ctl" : "");
    snprintf(g_img, sizeof g_img, "%s/archive%s.img", base, control ? "-ctl" : "");
    mkdir(live, 0755);
    struct img m = { c, 150, 0, 1 };
    if (run(live, p1_image, &m) != 0) return 1;
    if (!control){   /* the last record's write (block 150, after the last journal commit) did not reach the disk */
        char p[700]; struct stat sb; snprintf(p, sizeof p, "%s/index.dat", g_img);
        if (stat(p, &sb) == 0 && truncate(p, sb.st_size - 48) == 0) printf("  image: index.dat cut to %ld records (block 150's record lost)\n", (long)(sb.st_size / 48 - 1));
    }
    run(g_img, p2_boot_only, 0);
    long v[4]; if (read_res(g_img, v)) return 1;
    int ok = v[0] >= 0;
    printf("  expected: boot recovery succeeds; observed: %s\n", ok ? "boots" : "REFUSES TO START (STO-1 halt)");
    return ok;
}

int main(int argc, char** argv){
    if (argc != 3){ fprintf(stderr, "usage: %s ghostkill|ghostkill-ctl|ghostkill-close|flushundo|flushundo-ctl|walwb|logoff|logoff-ctl|archive|archive-ctl <scratch>\n", argv[0]); return 2; }
    setvbuf(stdout, 0, _IOLBF, 0);
    build_chain();
    const char* s = argv[1]; const char* b = argv[2];
    mkdir(b, 0755);
    int bug;   /* 1 = the scenario reproduces a defect (exit 0 if seen); 0 = a control (exit 0 if clean) */
    int clean;
    if      (!strcmp(s, "ghostkill"))       { bug = 1; clean = sc_ghostkill(b, 0); }
    else if (!strcmp(s, "ghostkill-ctl"))   { bug = 0; clean = sc_ghostkill(b, 1); }
    else if (!strcmp(s, "ghostkill-close")) { bug = 0; clean = sc_ghostkill(b, 2); }
    else if (!strcmp(s, "flushundo"))       { bug = 1; clean = sc_flushundo(b, 0); }
    else if (!strcmp(s, "flushundo-ctl"))   { bug = 0; clean = sc_flushundo(b, 1); }
    else if (!strcmp(s, "walwb"))           { bug = 1; clean = sc_walwb(b); }
    else if (!strcmp(s, "logoff"))          { bug = 1; clean = sc_logoff(b, 0); }
    else if (!strcmp(s, "logoff-ctl"))      { bug = 0; clean = sc_logoff(b, 1); }
    else if (!strcmp(s, "archive"))         { bug = 1; clean = sc_archive(b, 0); }
    else if (!strcmp(s, "archive-ctl"))     { bug = 0; clean = sc_archive(b, 1); }
    else return 2;
    int pass = bug ? !clean : clean;
    printf("%s: %s\n", s, bug ? (pass ? "DEFECT REPRODUCED" : "defect NOT reproduced")
                              : (pass ? "control clean" : "CONTROL FAILED"));
    return pass ? 0 : 1;
}
