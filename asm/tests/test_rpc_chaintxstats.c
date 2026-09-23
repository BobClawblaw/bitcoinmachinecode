/* test_rpc_chaintxstats.c -- getchaintxstats must cost O(new blocks), stay
 * right across a reorg, answer historical heights cheaply, and be safe to call
 * from several threads at once (2026-09-19).
 *
 * THE DEFECT. The cumulative `txcount` (Core's m_chain_tx_count) was cached
 * for exactly one height -- the last tip answered -- and re-walked from
 * genesis whenever the tip moved: 46,616 ms on production after a new block.
 * A historical blockhash re-walked from genesis on every call. And because the
 * cache was keyed on the HEIGHT alone, a reorg that replaced the tip at the
 * same height kept answering the old branch's total.
 *
 * THE MEASURE is implementation-independent: this binary is linked with
 * -Wl,--wrap=pread, and every pread the chain module issues against a
 * blk*.dat file is counted. getchaintxstats reads block PREFIXES (header +
 * tx-count varint) from those files; the median-time-past of the window ends
 * costs ~22 more. So "O(new blocks)" is: after the tip advances by K, one call
 * reads at most K + a small constant, where the old walk read the whole chain.
 *
 * The chain is synthetic but linked: each header carries the previous block's
 * hash, index.dat records sha256d(header), and block h holds 1 + h % 7
 * transactions (only the count varint is stored -- nothing here parses a
 * transaction). Growth and the reorgs happen in a CHILD process with its own
 * store handle, which is how the daemon's writer relates to the RPC reader. */
#define _GNU_SOURCE
#include "../rpc_json.h"
#include "../rpc_chain.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include "test_tmpdir.h"

extern int  store_init(void* st);
extern long store_append(void* st, const unsigned char* hash32, const void* blk, long len);
extern void store_reload(void* st);
extern int  store_truncate_to(void* st, long target_height);
extern void sha256d(unsigned char out[32], const void* data, unsigned long len);

long mempool_resolve_confirmed_utxo(void* u, const unsigned char txid[32], unsigned long index,
                     unsigned long long* value, const unsigned char** script,
                     unsigned long* slen);
long mempool_resolve_confirmed_utxo(void* u, const unsigned char txid[32], unsigned long index,
                     unsigned long long* value, const unsigned char** script,
                     unsigned long* slen){
    (void)u; (void)txid; (void)index; (void)value; (void)script; (void)slen;
    return 0;
}

/* ---- the instrument: preads against block files ---- */
ssize_t __real_pread(int fd, void* buf, size_t n, off_t off);
static volatile unsigned long g_blk_preads;
ssize_t __wrap_pread(int fd, void* buf, size_t n, off_t off);
ssize_t __wrap_pread(int fd, void* buf, size_t n, off_t off){
    char lp[64], tgt[512];
    snprintf(lp, sizeof lp, "/proc/self/fd/%d", fd);
    ssize_t k = readlink(lp, tgt, sizeof tgt - 1);
    if (k > 0){
        tgt[k] = 0;
        const char* b = strrchr(tgt, '/'); b = b ? b + 1 : tgt;
        if (!strncmp(b, "blk", 3)) __sync_fetch_and_add(&g_blk_preads, 1);
    }
    return __real_pread(fd, buf, n, off);
}

static int fails = 0;
static void ck(const char* l, int c){ printf("%s %s\n", c ? "ok  :" : "FAIL:", l); if (!c) fails++; }

/* ---- the synthetic chain ---- */
#define MAXH 8192
static unsigned char g_hash[MAXH][32];          /* wire order, per height, current branch */
static unsigned long long g_cum[MAXH];          /* expected cumulative count */
static unsigned g_ntx[MAXH];

static long mk_block(unsigned char* blk, const unsigned char prev[32], unsigned h, unsigned ntx, unsigned salt){
    memset(blk, 0, 96);
    blk[0] = 1;
    memcpy(blk + 4, prev, 32);
    for (int i = 0; i < 4; i++) blk[36 + i] = (unsigned char)(salt >> (8*i));   /* merkle area: makes a branch distinct */
    unsigned t = 1500000000u + 600u * h;
    for (int i = 0; i < 4; i++) blk[68 + i] = (unsigned char)(t >> (8*i));
    blk[72] = 0xff; blk[73] = 0xff; blk[74] = 0x00; blk[75] = 0x1d;              /* bits 0x1d00ffff */
    for (int i = 0; i < 4; i++) blk[76 + i] = (unsigned char)(h >> (8*i));
    if (ntx < 0xfd){ blk[80] = (unsigned char)ntx; return 81; }
    blk[80] = 0xfd; blk[81] = (unsigned char)ntx; blk[82] = (unsigned char)(ntx >> 8); return 83;
}
/* Append heights [from, to] on top of whatever the store holds, with tx counts
 * ntx_of(h) and a branch salt. Runs in a child with its own handle; the
 * parent mirrors the expected hashes/counts. `truncate_to` >= 0 first drops
 * everything above it (a reorg). */
static unsigned ntx_main(unsigned h){ return 1 + h % 7; }
static unsigned ntx_alt(unsigned h){ return 100 + h % 3; }
static void mirror(long from, long to, unsigned (*ntx_of)(unsigned), unsigned salt){
    for (long h = from; h <= to; h++){
        unsigned char blk[96];
        unsigned char z[32] = {0};
        const unsigned char* prev = h ? g_hash[h - 1] : z;
        g_ntx[h] = ntx_of((unsigned)h);
        mk_block(blk, prev, (unsigned)h, g_ntx[h], salt);
        sha256d(g_hash[h], blk, 80);
        g_cum[h] = (h ? g_cum[h - 1] : 0) + g_ntx[h];
    }
}
static int write_chain(long truncate_to, long from, long to, unsigned (*ntx_of)(unsigned), unsigned salt){
    /* the parent's mirror is computed first so the child sees the same hashes */
    mirror(from, to, ntx_of, salt);
    pid_t pid = fork();
    if (pid == 0){
        static unsigned char st[4096];
        memset(st, 0, sizeof st);
        if (store_init(st) != 1) _exit(2);
        store_reload(st);
        if (truncate_to >= 0 && store_truncate_to(st, truncate_to) != 1) _exit(4);
        for (long h = from; h <= to; h++){
            unsigned char blk[96];
            unsigned char z[32] = {0};
            long n = mk_block(blk, h ? g_hash[h - 1] : z, (unsigned)h, g_ntx[h], salt);
            if (store_append(st, g_hash[h], blk, n) < 0) _exit(3);
        }
        _exit(0);
    }
    int ws = 0; waitpid(pid, &ws, 0);
    return WIFEXITED(ws) && WEXITSTATUS(ws) == 0;
}

static void hexrev(char* out, const unsigned char* b){
    static const char* H = "0123456789abcdef";
    for (int i = 0; i < 32; i++){ unsigned char c = b[31 - i]; out[i*2] = H[c >> 4]; out[i*2+1] = H[c & 15]; }
    out[64] = 0;
}
static const char* S(rj_val* o, const char* k){ rj_val* v = o ? rj_obj_get(o, k) : NULL; return v && v->str ? v->str : NULL; }
static long long N(rj_val* o, const char* k){ const char* s = S(o, k); return s ? atoll(s) : -1; }

/* getchaintxstats [nblocks] [blockhash-of-height]; returns the result (caller frees) */
static rj_val* gcts(long nblocks, long at_h, long* ec_out){
    rj_val* p = rj_arr();
    if (nblocks >= 0) rj_arr_push(p, rj_numf("%ld", nblocks)); else rj_arr_push(p, rj_null());
    if (at_h >= 0){ char hx[65]; hexrev(hx, g_hash[at_h]); rj_arr_push(p, rj_str(hx)); }
    rj_val* res = NULL; long ec = 0; const char* em = NULL;
    int r = rpc_chain_dispatch("getchaintxstats", p, &res, &ec, &em);
    rj_free(p);
    if (ec_out) *ec_out = ec;
    if (r != 1){ if (res) rj_free(res); return NULL; }
    return res;
}

/* ---- concurrency ---- */
typedef struct { unsigned seed; long tip; int bad; int done; } thr_t;
static void* hammer(void* a){
    thr_t* t = a;
    for (int i = 0; i < 150; i++){
        t->seed = t->seed * 1103515245u + 12345u;
        long h = 1 + (long)((t->seed >> 8) % (unsigned)t->tip);
        long w = h > 1 ? 1 + (long)((t->seed >> 20) % (unsigned)(h - 1)) : 0;
        rj_val* r = gcts(w, h, NULL);
        if (!r || N(r, "txcount") != (long long)g_cum[h] ||
            (w > 0 && N(r, "window_tx_count") != (long long)(g_cum[h] - g_cum[h - w]))) t->bad++;
        if (r) rj_free(r);
        t->done++;
    }
    return NULL;
}

int main(void){
    tt_isolate();
    enum { TIP0 = 6000, K = 12 };   /* store_append fsyncs: 6k blocks is ~4 s; the old walk read all of them */

    ck("wrote the base chain (0..6000) in a writer process", write_chain(-1, 0, TIP0, ntx_main, 0));
    ck("rpc_chain_open", rpc_chain_open(NULL) == 1);

    /* ---- 1. the first call builds; its answer must be exact ---- */
    rj_val* r = gcts(-1, -1, NULL);
    ck("getchaintxstats at the tip answers", r != NULL);
    ck("txcount is the cumulative count through the tip", N(r, "txcount") == (long long)g_cum[TIP0]);
    ck("the default window is one month of blocks (4320)", N(r, "window_block_count") == 4320);
    ck("window_tx_count = count(tip) - count(tip - 4320)", N(r, "window_tx_count") == (long long)(g_cum[TIP0] - g_cum[TIP0 - 4320]));
    ck("window_interval is the MTP difference (4320 * 600 s)", N(r, "window_interval") == 4320L * 600);
    if (r) rj_free(r);

    /* ---- 2. the tip advances by K: the next call reads ~K prefixes ---- */
    ck("the writer appended K more blocks", write_chain(-1, TIP0 + 1, TIP0 + K, ntx_main, 0));
    g_blk_preads = 0;
    r = gcts(-1, -1, NULL);
    unsigned long cost = g_blk_preads;
    printf("      block-file preads for one call after a %d-block advance: %lu (chain height %d)\n", K, cost, TIP0 + K);
    ck("after the advance, txcount is exact", N(r, "txcount") == (long long)g_cum[TIP0 + K]);
    ck("the call cost O(new blocks): at most K + 64 block-file reads, not the chain", cost <= (unsigned long)K + 64);
    if (r) rj_free(r);

    /* ---- 3. a historical height is O(1) once the cache covers it ---- */
    g_blk_preads = 0;
    r = gcts(100, 3500, NULL);
    cost = g_blk_preads;
    printf("      block-file preads for a historical call (height 3500): %lu\n", cost);
    ck("historical: window_final_block_height", N(r, "window_final_block_height") == 3500);
    ck("historical: txcount through that height", N(r, "txcount") == (long long)g_cum[3500]);
    ck("historical: window_tx_count over its own window", N(r, "window_tx_count") == (long long)(g_cum[3500] - g_cum[3400]));
    ck("historical: a bounded number of block reads, not a walk from genesis", cost <= 64);
    if (r) rj_free(r);
    g_blk_preads = 0;
    r = gcts(0, 1500, NULL);
    ck("a second historical height is exact too", N(r, "txcount") == (long long)g_cum[1500]);
    ck("...and bounded", g_blk_preads <= 64);
    ck("window 0 emits no window_interval (Core)", r && rj_obj_get(r, "window_interval") == NULL);
    if (r) rj_free(r);

    /* ---- 4. a reorg that keeps the SAME height ----
     * The last 5 blocks are replaced by a branch with far more transactions.
     * A cache keyed on the height alone keeps answering the old branch. */
    long tip = TIP0 + K;
    r = gcts(-1, -1, NULL);                 /* the tip is the last thing answered */
    ck("before the reorg, the tip's count", N(r, "txcount") == (long long)g_cum[tip]);
    if (r) rj_free(r);
    ck("the writer reorged the last 5 blocks (same height)", write_chain(tip - 5, tip - 4, tip, ntx_alt, 0xa1));
    r = gcts(-1, -1, NULL);
    ck("after a same-height reorg, txcount is the NEW branch's", N(r, "txcount") == (long long)g_cum[tip]);
    { char hx[65]; hexrev(hx, g_hash[tip]);
      ck("...and the final block hash is the new tip's", S(r, "window_final_block_hash") && !strcmp(S(r, "window_final_block_hash"), hx)); }
    if (r) rj_free(r);
    r = gcts(3, tip - 2, NULL);
    ck("a reorged-IN block resolves by hash", r != NULL);
    ck("...with the new branch's count", N(r, "txcount") == (long long)g_cum[tip - 2]);
    if (r) rj_free(r);

    /* ---- 5. a deeper reorg onto a LONGER branch ---- */
    { unsigned char old_hash[32]; memcpy(old_hash, g_hash[tip - 50], 32);
      long fork = tip - 60;
      ck("the writer reorged 60 blocks deep onto a longer branch", write_chain(fork, fork + 1, tip + 7, ntx_alt, 0xb2));
      tip += 7;
      g_blk_preads = 0;
      r = gcts(-1, -1, NULL);
      printf("      block-file preads after a 60-deep reorg: %lu\n", (unsigned long)g_blk_preads);
      ck("after a deep reorg, txcount is exact", N(r, "txcount") == (long long)g_cum[tip]);
      ck("...and re-walking cost only the new branch, not the chain", g_blk_preads <= 67 + 64);
      if (r) rj_free(r);
      /* the reorged-OUT block is known but not on the active chain */
      rj_val* p = rj_arr(); rj_arr_push(p, rj_numf("%d", 1));
      char hx[65]; hexrev(hx, old_hash); rj_arr_push(p, rj_str(hx));
      rj_val* res = NULL; long ec = 0; const char* em = NULL;
      int rc = rpc_chain_dispatch("getchaintxstats", p, &res, &ec, &em);
      ck("a reorged-OUT block -> -8 Block is not in main chain (Core)", rc == 0 && ec == -8 && em && !strcmp(em, "Block is not in main chain"));
      if (res) rj_free(res);
      rj_free(p); }

    /* ---- 6. concurrent callers ----
     * The server now runs getchaintxstats without the execution lock, so
     * several threads can be in it at once. Each asks random historical
     * heights and windows and checks the answer. */
    { enum { T = 8 };
      pthread_t th[T]; thr_t ts[T];
      for (int i = 0; i < T; i++){ ts[i].seed = 0x9e3779b9u * (unsigned)(i + 1); ts[i].tip = tip; ts[i].bad = 0; ts[i].done = 0; pthread_create(&th[i], NULL, hammer, &ts[i]); }
      int bad = 0, done = 0;
      for (int i = 0; i < T; i++){ pthread_join(th[i], NULL); bad += ts[i].bad; done += ts[i].done; }
      printf("      %d concurrent calls from %d threads, %d wrong\n", done, T, bad);
      ck("concurrent getchaintxstats calls all answer exactly", bad == 0 && done == T * 150); }

    printf(fails ? "\nTESTS FAILED (%d failures)\n" : "\nALL TESTS PASSED (%d failures)\n", fails);
    return fails ? 1 : 0;
}
