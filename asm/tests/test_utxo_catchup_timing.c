/* tests/test_utxo_catchup_timing.c -- step 0 of
 * docs/audits/UTXO_INLINE_BUILD_PERF_SCOPE.md: the per-block phase timers
 * around utxo_live_catchup's connect loop.
 *
 * What is pinned: the timers are bookkeeping and nothing more. Their totals
 * are non-negative, sum to no more than the wall time of the call they
 * measured, the verify phase is non-zero for a chain with real spends (the
 * parallel script pass ran), the coinstats phase is non-zero when a fold
 * observer is registered (the MuHash callbacks were timed), and the two log
 * lines carry the breakdown. NEGATIVE CONTROL: utxo_live_set_timing(0)
 * leaves every total at exactly zero -- the same chain, the same call, no
 * clock reads. Then the setter is turned back on and the totals move again.
 *
 * Chain: 150 coinbase-only blocks, then 10 blocks each spending 5 of the
 * first 50 coinbases (all past the 100-block maturity) -- the same OP_1 spends
 * tests/test_utxo_crash_recovery.c uses, so every non-coinbase transaction
 * goes through tx_verify_block_connect_all's Phase 1 resolve and Phase 2
 * verify. The coinstats "fold" here is a stand-in callback that burns about
 * a microsecond, the real csi_on_add/csi_on_remove cost the scope measured.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include "test_tmpdir.h"

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

extern long store_init(void* st);
extern long store_append(void* st, const u8 hash[32], const void* raw, long len);
extern void block_hash(u8 out[32], const u8 hdr[80]);
extern int  pow_check(const u8 hdr[80]);
extern int  tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* buf, unsigned long buflen);
extern void merkle_root(u8 out[32], u8* hashes, long n);

extern int  utxo_live_init(const char* dir);
extern long utxo_live_catchup(void* store_buf);
extern long utxo_live_count(void);
extern long utxo_live_applied_height(void);
extern void utxo_live_close(void);

/* the instrumentation under test (daemon/utxo_live.c) */
extern void utxo_live_set_timing(int on);
extern void utxo_live_timing_reset(void);
extern unsigned long long utxo_live_timing_us(int phase);
/* phase indices, mirroring utxo_live.c's enum */
enum { TM_READ, TM_IDX, TM_VERIFY, TM_GET, TM_PUT, TM_CKPT, TM_FLUSH, TM_CSI, TM_WALL, TM_N };
static const char* PHASE_NAME[TM_N] = { "read", "idx", "verify", "get", "put", "ckpt", "flush", "csi", "wall" };

/* the coinstats observer seams (daemon/utxo_live.c, daemon/undo_log.c) */
typedef void (*coin_fn)(const u8 txid[32], u32 index, u64 value, u64 height,
                        u64 coinbase, const u8* script, unsigned long slen);
extern void utxo_live_set_coinstats(coin_fn add, coin_fn rm,
                                    void (*inval)(const char*), void (*commit)(long));
extern void undo_set_coin_observer(coin_fn fn);

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u; (void)txid; (void)index; (void)value; (void)script; (void)slen;
    fprintf(stderr, "test_utxo_catchup_timing: unexpected call to mempool_resolve_confirmed_utxo\n");
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

static void put32(u8* p, u32 v){ p[0]=(u8)v; p[1]=(u8)(v>>8); p[2]=(u8)(v>>16); p[3]=(u8)(v>>24); }
static void put64(u8* p, u64 v){ for(int i=0;i<8;i++) p[i]=(u8)(v>>(8*i)); }
static u8 g_txid_scratch[1<<12];

/* ---- the stand-in coinstats fold: ~1 us of work per coin, counted ---- */
static long g_fold_adds = 0, g_fold_rms = 0;
static volatile u64 g_fold_sink = 0;
static void fold_burn(void){ u64 x = g_fold_sink; for (int i = 0; i < 400; i++) x = x * 6364136223846793005ULL + 1442695040888963407ULL; g_fold_sink = x; }
static void fold_add(const u8 txid[32], u32 index, u64 value, u64 height, u64 cb, const u8* s, unsigned long sl){
    (void)txid; (void)index; (void)value; (void)height; (void)cb; (void)s; (void)sl;
    g_fold_adds++; fold_burn();
}
static void fold_rm(const u8 txid[32], u32 index, u64 value, u64 height, u64 cb, const u8* s, unsigned long sl){
    (void)txid; (void)index; (void)value; (void)height; (void)cb; (void)s; (void)sl;
    g_fold_rms++; fold_burn();
}
static void fold_inval(const char* why){ (void)why; }
static void fold_commit(long h){ (void)h; }

/* ---- chain builders (tests/test_utxo_crash_recovery.c's, verbatim) ---- */
#define CB_TX_LEN 65
static long mk_coinbase_tx(u8* tx, u32 tag){
    u8* q = tx;
    put32(q,1); q+=4; *q++ = 1; memset(q,0,32); q+=32; put32(q,0xffffffffu); q+=4;
    *q++ = 4; put32(q, tag); q+=4; put32(q,0xffffffffu); q+=4;
    *q++ = 1; put64(q, 50000000ULL); q+=8; *q++ = 1; *q++ = 0x51; put32(q,0); q+=4;
    if (q - tx != CB_TX_LEN){ printf("FAIL mk_coinbase_tx emitted %ld bytes\n", (long)(q - tx)); failures++; }
    return q - tx;
}
static long mk_and_mine(u8* raw, u8 hash[32], u8 cb_txid_out[32], const u8 prev[32], u32 tag, u32 tstamp){
    u8 tx[CB_TX_LEN], txid[32];
    long txlen = mk_coinbase_tx(tx, tag);
    tx_txid(txid, tx, (unsigned long)txlen, g_txid_scratch, sizeof g_txid_scratch);
    memcpy(cb_txid_out, txid, 32);
    u8* o = raw;
    put32(o,1); o+=4; memcpy(o, prev, 32); o+=32; memcpy(o, txid, 32); o+=32;
    put32(o, tstamp); o+=4; put32(o, 0x207fffffu); o+=4; put32(o, 0); o+=4;
    *o++ = 1; memcpy(o, tx, (size_t)txlen); o += txlen;
    long len = o - raw;
    u32 nonce = 0;
    while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
    block_hash(hash, raw);
    return len;
}
/* coinbase + nspend txs, tx_j spending spend_txids[j]:0 (empty scriptSig
 * against OP_1 -- valid) into one OP_1 output of 40,000,000 */
static long mk_and_mine_multispend(u8* raw, u8 hash[32], const u8 prev[32],
                                   const u8 (*spend_txids)[32], int nspend,
                                   u32 tag, u32 tstamp){
    u8 txbuf[8][128]; long txlen[8];
    u8 leaves[8*32];
    txlen[0] = mk_coinbase_tx(txbuf[0], tag);
    tx_txid(leaves, txbuf[0], (unsigned long)txlen[0], g_txid_scratch, sizeof g_txid_scratch);
    for (int j=0;j<nspend;j++){
        u8* q = txbuf[j+1];
        put32(q,1); q+=4;
        *q++ = 1;
        memcpy(q, spend_txids[j], 32); q+=32; put32(q,0); q+=4;
        *q++ = 0;
        put32(q,0xffffffffu); q+=4;
        *q++ = 1;
        put64(q, 40000000ULL); q+=8;
        *q++ = 1; *q++ = 0x51;
        put32(q,0); q+=4;
        txlen[j+1] = q - txbuf[j+1];
        tx_txid(leaves + 32*(j+1), txbuf[j+1], (unsigned long)txlen[j+1], g_txid_scratch, sizeof g_txid_scratch);
    }
    u8 root[32];
    merkle_root(root, leaves, nspend+1);
    u8* o = raw;
    put32(o,1); o+=4; memcpy(o, prev, 32); o+=32; memcpy(o, root, 32); o+=32;
    put32(o, tstamp); o+=4; put32(o, 0x207fffffu); o+=4; put32(o, 0); o+=4;
    *o++ = (u8)(nspend+1);
    for (int j=0;j<=nspend;j++){ memcpy(o, txbuf[j], (size_t)txlen[j]); o += txlen[j]; }
    long len = o - raw;
    u32 nonce = 0;
    while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
    block_hash(hash, raw);
    return len;
}

/* block NCB+j spends coinbases 5j..5j+4; the youngest, 5j+4, has
 * NCB+j-(5j+4) = 146-4j confirmations, >= 100 for every j < NSPENDBLK */
#define NCB      150
#define NSPENDBLK 10
#define PERBLK    5
#define NBLOCKS  (NCB + NSPENDBLK)
static u8 store_buf[4096];
static u8 cb_txids[NCB][32];

/* 150 coinbases, then 10 blocks spending 5 mature coinbases each. */
static void build_chain(u32 tagbase){
    u8 prev[32]; memset(prev,0,32);
    for (long h=0; h<NCB; h++){
        u8 raw[256], hash[32];
        long len = mk_and_mine(raw, hash, cb_txids[h], prev, tagbase+(u32)h, 1900000000u+(u32)h);
        if (store_append(store_buf, hash, raw, len) != h){ printf("FAIL store_append h=%ld\n", h); failures++; }
        memcpy(prev, hash, 32);
    }
    for (long j=0; j<NSPENDBLK; j++){
        u8 raw[1024], hash[32];
        long len = mk_and_mine_multispend(raw, hash, prev, &cb_txids[j*PERBLK], PERBLK,
                                          tagbase+0x1000u+(u32)j, 1900100000u+(u32)j);
        long h = NCB + j;
        if (store_append(store_buf, hash, raw, len) != h){ printf("FAIL store_append spend h=%ld\n", h); failures++; }
        memcpy(prev, hash, 32);
    }
}

static u64 now_us(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (u64)t.tv_sec*1000000ULL + (u64)t.tv_nsec/1000; }

/* stderr -> a file for the duration of one catch-up, so the log lines can be
 * asserted on (and echoed, so the gate log shows the breakdown) */
static int g_saved_stderr = -1;
static void capture_begin(const char* path){
    fflush(stderr);
    g_saved_stderr = dup(2);
    int fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd < 0){ perror("open capture"); exit(1); }
    dup2(fd, 2); close(fd);
}
static char* capture_end(const char* path){
    fflush(stderr);
    dup2(g_saved_stderr, 2); close(g_saved_stderr); g_saved_stderr = -1;
    FILE* f = fopen(path, "rb"); if (!f) return 0;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    char* buf = malloc((size_t)n + 1); if (!buf){ fclose(f); return 0; }
    size_t got = fread(buf, 1, (size_t)n, f); fclose(f); buf[got] = 0;
    return buf;
}
static void echo_lines_with(const char* text, const char* needle){
    const char* p = text;
    while (*p){
        const char* e = strchr(p, '\n'); size_t n = e ? (size_t)(e - p) : strlen(p);
        char line[512]; size_t m = n < sizeof line - 1 ? n : sizeof line - 1;
        memcpy(line, p, m); line[m] = 0;
        if (strstr(line, needle)) printf("     %s\n", line);
        if (!e) break;
        p = e + 1;
    }
}

static void dump_phases(const char* tag){
    printf("     %s:", tag);
    for (int k = 0; k < TM_N; k++) printf(" %s=%llu", PHASE_NAME[k], utxo_live_timing_us(k));
    printf(" blocks=%llu\n", utxo_live_timing_us(TM_N));
}

int main(void){
    tt_isolate();

    /* ---------------- A: timing on (the default) ---------------- */
    {
        tt_subdir("on");
        memset(store_buf,0,sizeof store_buf);
        ck("A store_init", store_init(store_buf), 1);
        ck("A utxo_live_init", utxo_live_init("."), 1);
        utxo_live_set_coinstats(fold_add, fold_rm, fold_inval, fold_commit);
        undo_set_coin_observer(fold_rm);
        build_chain(0x70000000u);

        utxo_live_timing_reset();
        for (int k = 0; k <= TM_N; k++) if (utxo_live_timing_us(k)) { printf("FAIL A reset left phase %d non-zero\n", k); failures++; }

        capture_begin("catchup_on.log");
        u64 t0 = now_us();
        long ar = utxo_live_catchup(store_buf);
        u64 wall_call = now_us() - t0;
        char* log = capture_end("catchup_on.log");

        ck("A catch-up applied the whole chain", ar, NBLOCKS);
        ck("A applied_height at tip", utxo_live_applied_height(), NBLOCKS - 1);
        ck("A fold observer saw every created output (coinbases + spend outputs)", g_fold_adds, NBLOCKS + NSPENDBLK * PERBLK);
        ck("A fold observer saw every spent input", g_fold_rms, NSPENDBLK * PERBLK);
        dump_phases("A phases (us)");
        printf("     A wall of the call as measured here: %llu us\n", wall_call);

        u64 sum = 0; int sane = 1;
        for (int k = 0; k < TM_WALL; k++){
            u64 v = utxo_live_timing_us(k);
            if (v > wall_call) sane = 0;
            sum += v;
        }
        ckm("A every phase total is non-negative and no larger than the call's wall", sane);
        ckm("A the phases sum to <= the instrumented wall", sum <= utxo_live_timing_us(TM_WALL));
        ckm("A the instrumented wall is <= the wall measured around the call", utxo_live_timing_us(TM_WALL) <= wall_call);
        ck("A blocks counted == blocks applied", (long)utxo_live_timing_us(TM_N), NBLOCKS);
        ckm("A verify phase is non-zero (10 blocks of real spends went through the script pass)", utxo_live_timing_us(TM_VERIFY) > 0);
        ckm("A csi phase is non-zero (the fold callbacks were timed on both sides)", utxo_live_timing_us(TM_CSI) > 0);
        ckm("A put phase is non-zero", utxo_live_timing_us(TM_PUT) > 0);
        ckm("A ckpt phase is non-zero (at least one checkpoint fsync landed)", utxo_live_timing_us(TM_CKPT) > 0);
        ckm("A the progress line carries the breakdown", log && strstr(log, "catchup progress:") && strstr(log, "| read ") && strstr(log, " csi "));
        ckm("A the call ends with a 'catchup timing' summary line", log && strstr(log, "[utxo_live] catchup timing: "));
        if (log){ echo_lines_with(log, "catchup progress:"); echo_lines_with(log, "catchup timing:"); free(log); }
        utxo_live_close();
    }

    /* ---------------- B: negative control, timing off ---------------- */
    {
        tt_subdir("off");
        memset(store_buf,0,sizeof store_buf);
        g_fold_adds = g_fold_rms = 0;
        utxo_live_set_timing(0);
        ck("B store_init", store_init(store_buf), 1);
        ck("B utxo_live_init", utxo_live_init("."), 1);
        utxo_live_set_coinstats(fold_add, fold_rm, fold_inval, fold_commit);
        undo_set_coin_observer(fold_rm);
        build_chain(0x71000000u);

        utxo_live_timing_reset();
        capture_begin("catchup_off.log");
        long ar = utxo_live_catchup(store_buf);
        char* log = capture_end("catchup_off.log");
        ck("B catch-up applied the whole chain (behaviour unchanged with timing off)", ar, NBLOCKS);
        ck("B fold observer still saw every created output (coinbases + spend outputs)", g_fold_adds, NBLOCKS + NSPENDBLK * PERBLK);
        ck("B fold observer still saw every spent input", g_fold_rms, NSPENDBLK * PERBLK);
        dump_phases("B phases (us)");
        int allzero = 1;
        for (int k = 0; k <= TM_N; k++) if (utxo_live_timing_us(k)) allzero = 0;
        ckm("B with timing off every total (phases, wall, blocks) stays exactly zero", allzero);
        ckm("B the progress line says 'timing off' instead of a breakdown", log && strstr(log, "| timing off") && !strstr(log, "| read "));
        if (log){ echo_lines_with(log, "catchup progress:"); echo_lines_with(log, "catchup timing:"); free(log); }

        /* ...and back on: the setter is reversible, the totals move again */
        utxo_live_set_timing(1);
        utxo_live_timing_reset();
        u8 prev[32]; long tip = utxo_live_applied_height();
        /* extend by 3 coinbase-only blocks off the current tip hash */
        {
            extern long store_read_at(void* st, u64 height, void* buf, u64 cap);
            static u8 tipraw[8<<10];
            long tl = store_read_at(store_buf, (u64)tip, tipraw, sizeof tipraw);
            ckm("B tip block readable for the extension", tl >= 81);
            block_hash(prev, tipraw);
        }
        for (long i = 0; i < 3; i++){
            u8 raw[256], hash[32], cbt[32];
            long len = mk_and_mine(raw, hash, cbt, prev, 0x72000000u+(u32)i, 1900200000u+(u32)i);
            ck("B extension store_append", store_append(store_buf, hash, raw, len), tip + 1 + i);
            memcpy(prev, hash, 32);
        }
        ck("B catch-up applied the 3 extension blocks", utxo_live_catchup(store_buf), 3);
        dump_phases("B-on phases (us)");
        ck("B timing back on: blocks counted again", (long)utxo_live_timing_us(TM_N), 3);
        ckm("B timing back on: wall is non-zero again", utxo_live_timing_us(TM_WALL) > 0);
        utxo_live_close();
    }

    printf("\n%s (%d failures)\n", failures==0 ? "ALL TESTS PASSED" : "TESTS FAILED", failures);
    return failures ? 1 : 0;
}
