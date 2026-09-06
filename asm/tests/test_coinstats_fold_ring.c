/* tests/test_coinstats_fold_ring.c -- the coinstats fold worker: the connect
 * thread pushes coin records onto the shared ring (rpc_node.h csi_ring), a
 * FORKED worker folds them, and the commit watermark gates the RPC.
 *
 * The finding (docs/audits/UTXO_INLINE_BUILD_PERF_SCOPE.md, lever 2):
 * steady state folded ~10k MuHash elements per heavy block on the connect
 * thread. Pinned here, against daemon/coinstats_index.c with a MAP_SHARED
 * node_status_t exactly as the daemon shares it across its fork:
 *
 *   1. records pushed by THIS process (adds, removes, scripts of 0, 124,
 *      125, 600 and 10000 bytes -- the inline boundary and the continuation
 *      path) are folded by the worker into the SAME digest and counters an
 *      independent full walk of the resulting set produces;
 *   2. the watermark gates commit: with the worker paused, a commit marker
 *      behind it makes csi_rpc_run refuse (-2, "still folding") and the
 *      file stays at the previous height; unpaused, the same call serves
 *      the new height;
 *   3. lapping is counted: the producer, its wait bound set to 0, overruns
 *      a paused worker by RING+50 records; the worker resyncs, counts the
 *      loss in csi_lapped, and INVALIDATES (coinstats.dat gone) -- a lost
 *      record is a wrong digest, never a silently wrong answer;
 *   4. negative control: no status block -> inline folding of the same
 *      records, same digest as the worker's; csi_worker_start refuses.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include "../rpc_node.h"
#include "test_tmpdir.h"

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

extern void utxo_stats_init(void* st, unsigned long want_muhash, unsigned long excl_genesis);
extern void utxo_stats_add(void* st, const u8 key36[36], unsigned long value,
                           unsigned long code, const u8* script, unsigned long slen);
extern void utxo_stats_finalize(void* st);
extern long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const u8 txid[32], u32 index, u64 value,
                         u64 height, u64 is_coinbase, const u8* script, u32 slen);
extern long utxo_lsm_walk(void* lst, void* u, void* cb, void* ctx);

extern int  csi_seed_from_walk(void* lst, void* u, long height);
extern void csi_on_add(const u8*, u32, u64, u64, u64, const u8*, unsigned long);
extern void csi_on_remove(const u8*, u32, u64, u64, u64, const u8*, unsigned long);
extern void csi_commit(long height);
extern int  csi_valid(void);
extern int  csi_read_live(long*, unsigned char[32], u64*, u64*, u64*);
extern int  csi_read_file(long*, unsigned char*, unsigned char[32], u64*, u64*, u64*);
extern long csi_rpc_run(int, void*, char*, unsigned long);
extern long csi_file_height(void);
extern void csi_set_status(void*);
extern int  csi_worker_start(void);
extern void csi_worker_stop(void);
extern int  csi_worker_pid(void);
extern int  csi_ring_on(void);
extern void csi_test_set_push_wait_ms(long);
extern void csi_test_set_rpc_wait_ms(long);
extern void csi_test_ring_pause(int);
extern u64  csi_test_fold_count(void);
extern u64  csi_test_push_overruns(void);

struct lsm_state {
    long log_fd, idx_fd;
    u64 log_len, ckpt_log_off, ckpt_n;
    u64 op_count, op_threshold, fill_threshold;
    void* tomb_buf; u64 tomb_cap, tomb_n, total_live, next_gen;
    void* manifest_buf; u64 manifest_cap, manifest_n;
    void* scratch_buf; u64 scratch_cap;
    u64 next_run_no;
    void* tomb_hash_buf; u64 tomb_hash_mask;
};
#define BLOOM_MAX_BYTES  (4*1024*1024)
#define SCRIPT_MAX_BYTES 65536

static int failures = 0;
static void ck(const char* l, int cond){
    if (cond) printf("  ok  %s\n", l);
    else { printf("  FAIL %s\n", l); failures++; }
}
static long long ms(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (long long)t.tv_sec*1000 + t.tv_nsec/1000000; }

/* ---- the coin set --------------------------------------------------------
 * N_ADD synthetic coins (script lengths cycling through the interesting
 * sizes) of which the first N_RM are removed again; the final set is
 * coins[N_RM..N_ADD). A: seeded by walk, then removed; B: seeded, kept. */
typedef struct { u8 txid[32]; u32 idx; u64 val, h, cb; u32 slen; u8 spk[10000]; } coin_t;
#define N_ADD 3000
#define N_RM  1000
static coin_t* coins;
static coin_t A, B;
static const u32 lens[] = { 25, 0, 124, 125, 600, 34, 10000, 67, 1, 300 };

static void mk_coin(coin_t* c, int tag, u32 slen){
    memset(c, 0, sizeof *c);
    for (int i = 0; i < 32; i++) c->txid[i] = (u8)(i * 13 + 1);
    for (int i = 0; i < 4; i++)  c->txid[i] = (u8)(tag >> (8 * i));   /* unique per tag */
    c->idx = (u32)(tag & 7); c->val = 1000000ULL + (u64)tag * 31; c->h = 100 + (u64)(tag % 500); c->cb = (u64)(tag % 3 == 0);
    c->slen = slen;
    for (u32 i = 0; i < slen; i++) c->spk[i] = (u8)(0x50 + ((tag + i) % 37));
    if (slen) c->spk[0] = 0x51;   /* never OP_RETURN: spendable, so a walk counts it */
}
static void mk_all(void){
    coins = calloc(N_ADD, sizeof(coin_t));
    if (!coins){ puts("calloc"); exit(2); }
    for (int i = 0; i < N_ADD; i++) mk_coin(&coins[i], 1000 + i, lens[i % 10]);
    mk_coin(&A, 1, 25); mk_coin(&B, 2, 34);
}

static void lsm_build(struct lsm_state* lst, void** table_out, const coin_t* const* cs, int n){
    unsigned long slots = 1UL<<14;
    void* table = malloc((size_t)utxo_struct_size(slots));
    void* blob = malloc(64UL<<20);
    utxo_init(table, slots, blob, 64UL<<20);
    memset(lst, 0, sizeof *lst);
    u64 op_th = slots*2, tomb_cap = op_th, desc_cap = slots*3;
    lst->op_threshold = op_th; lst->fill_threshold = slots*3/4;
    lst->tomb_buf = malloc(tomb_cap*36); lst->tomb_cap = tomb_cap;
    lst->manifest_buf = malloc(256*16); lst->manifest_cap = 256;
    lst->scratch_cap = desc_cap*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES;
    lst->scratch_buf = malloc(lst->scratch_cap);
    if (utxo_lsm_init(lst) != 1){ fprintf(stderr, "lsm init failed\n"); exit(1); }
    for (int i = 0; i < n; i++)
        if (utxo_lsm_put(lst, table, cs[i]->txid, cs[i]->idx, cs[i]->val, cs[i]->h, cs[i]->cb, cs[i]->spk, cs[i]->slen) != 1){
            fprintf(stderr, "seed put failed\n"); exit(1); }
    *table_out = table;
}

static void walk_digest(struct lsm_state* lst, void* table, unsigned char out[32], u64* txouts, u64* amount, u64* bogo){
    static u8 st[512] __attribute__((aligned(16)));
    utxo_stats_init(st, 1, 0);
    long n = utxo_lsm_walk(lst, table, (void*)utxo_stats_add, st);
    if (n < 0){ fprintf(stderr, "walk failed\n"); exit(1); }
    utxo_stats_finalize(st);
    memcpy(out, st + 64, 32); memcpy(txouts, st, 8); memcpy(amount, st + 8, 8); memcpy(bogo, st + 16, 8);
}

/* the event stream every variant replays: +coins[0..N_ADD), -coins[0..N_RM), -A */
static void push_events(void){
    for (int i = 0; i < N_ADD; i++) csi_on_add(coins[i].txid, coins[i].idx, coins[i].val, coins[i].h, coins[i].cb, coins[i].spk, coins[i].slen);
    for (int i = 0; i < N_RM; i++)  csi_on_remove(coins[i].txid, coins[i].idx, coins[i].val, coins[i].h, coins[i].cb, coins[i].spk, coins[i].slen);
    csi_on_remove(A.txid, A.idx, A.val, A.h, A.cb, A.spk, A.slen);
}
#define N_EVENTS (N_ADD + N_RM + 1)

static int wait_watermark(node_status_t* st, long long h, long timeout_ms){
    long long t0 = ms();
    while (st->csi_folded_height < h){ if (ms() - t0 > timeout_ms) return 0; usleep(1000); }
    return 1;
}
static int wait_drained(node_status_t* st, long timeout_ms){
    long long t0 = ms();
    while (st->csi_folded_seq != st->csi_seq){ if (ms() - t0 > timeout_ms) return 0; usleep(1000); }
    return 1;
}

typedef struct { long height; u64 txouts, bogosize, total_amount; unsigned char muhash[32]; int muhash_valid; } rpc_out_t;

int main(void){
    tt_isolate();
    mk_all();
    node_status_t* st = mmap(NULL, sizeof(node_status_t), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (st == MAP_FAILED){ perror("mmap"); return 2; }
    memset(st, 0, sizeof *st);

    printf("== 1: records pushed here, folded by the forked worker, equal the walk ==\n");
    mkdir("ring", 0755); mkdir("walk", 0755); mkdir("inline", 0755);
    if (chdir("ring")){ perror("chdir"); return 1; }
    struct lsm_state l1; void* t1;
    { const coin_t* s[2] = { &A, &B }; lsm_build(&l1, &t1, s, 2); }
    ck("seed {A,B} by walk (inline, before the worker exists)", csi_seed_from_walk(&l1, t1, 500) == 1);
    csi_set_status(st);
    ck("worker started", csi_worker_start() == 1 && csi_worker_pid() > 0 && csi_ring_on() == 1);
    ck("worker pid published in the block", st->csi_worker_pid == csi_worker_pid());
    u64 f0 = csi_test_fold_count();
    push_events();
    ck("this process folded NOTHING (the connect thread is off the fold)", csi_test_fold_count() == f0);
    ck("no overrun at the default wait bound", csi_test_push_overruns() == 0);
    csi_commit(501);
    ck("csi_pushed_height follows the commit", st->csi_pushed_height == 501);
    ck("watermark reaches 501 (the worker folded everything before the marker)", wait_watermark(st, 501, 10000));
    ck("the worker folded every event", st->csi_folds == N_EVENTS);
    ck("nothing lapped", st->csi_lapped == 0);
    ck("coinstats.dat at 501", csi_file_height() == 501);
    long h; unsigned char d_ring[32]; u64 tx, amt, bg;
    ck("file read", csi_read_file(&h, NULL, d_ring, &tx, &amt, &bg) == 1 && h == 501);
    ck("txouts = |{B} + coins[N_RM..N_ADD)|", tx == 1 + (N_ADD - N_RM));

    if (chdir("../walk")){ perror("chdir"); return 1; }
    struct lsm_state l2; void* t2;
    { const coin_t** s = malloc(sizeof(void*) * (N_ADD - N_RM + 1)); int n = 0;
      s[n++] = &B; for (int i = N_RM; i < N_ADD; i++) s[n++] = &coins[i];
      lsm_build(&l2, &t2, s, n); free(s); }
    unsigned char d_ref[32]; u64 rtx, ramt, rbg;
    walk_digest(&l2, t2, d_ref, &rtx, &ramt, &rbg);
    ck("DIGEST equals the independent walk of the resulting set", memcmp(d_ring, d_ref, 32) == 0);
    ck("counters equal the walk", tx == rtx && amt == ramt && bg == rbg);
    { rpc_out_t o; memset(&o, 0, sizeof o); char msg[256];
      if (chdir("../ring")){ perror("chdir"); return 1; }
      long r = csi_rpc_run(1, &o, msg, sizeof msg);
      unsigned char rev[32]; for (int i = 0; i < 32; i++) rev[i] = d_ring[31 - i];
      ck("csi_rpc_run serves 501 with the worker's digest", r == 1 && o.height == 501 && o.muhash_valid && memcmp(o.muhash, rev, 32) == 0); }

    printf("\n== 2: the watermark gates the RPC ==\n");
    csi_test_ring_pause(1);
    { coin_t E; mk_coin(&E, 77, 25);
      csi_on_add(E.txid, E.idx, E.val, E.h, E.cb, E.spk, E.slen); }
    csi_commit(502);
    ck("pushed 502, worker paused at 501", st->csi_pushed_height == 502 && st->csi_folded_height == 501);
    { rpc_out_t o; memset(&o, 0, sizeof o); char msg[256] = {0};
      csi_test_set_rpc_wait_ms(200);
      long long t0 = ms(); long r = csi_rpc_run(1, &o, msg, sizeof msg); long long dt = ms() - t0;
      ck("refused (-2) after the bounded wait, not served from the old file", r == -2 && dt >= 150 && dt < 2000);
      ck("...with the folding message", strstr(msg, "still folding") != NULL);
      printf("      msg: %s (%lld ms)\n", msg, dt);
      ck("file still at 501 (the marker is unfolded)", csi_file_height() == 501); }
    csi_test_ring_pause(0);
    { rpc_out_t o; memset(&o, 0, sizeof o); char msg[256] = {0};
      csi_test_set_rpc_wait_ms(5000);
      long r = csi_rpc_run(1, &o, msg, sizeof msg);
      ck("unpaused: the same call waits for the watermark and serves 502", r == 1 && o.height == 502 && st->csi_folded_height == 502);
      ck("txouts grew by the one add", o.txouts == tx + 1); }

    printf("\n== 3: lapping is counted and invalidates ==\n");
    csi_test_ring_pause(1);
    csi_test_set_push_wait_ms(0);
    { coin_t X; for (int i = 0; i < RPC_CSI_RING + 50; i++){ mk_coin(&X, 50000 + i, 25); csi_on_add(X.txid, X.idx, X.val, X.h, X.cb, X.spk, X.slen); } }
    ck("the producer gave up waiting and overran", csi_test_push_overruns() > 0 && st->csi_overrun == csi_test_push_overruns());
    csi_commit(503);
    csi_test_ring_pause(0);
    ck("worker drained the ring", wait_drained(st, 10000));
    ck("LAP COUNTED: csi_lapped > 0", st->csi_lapped > 0);
    printf("      lapped=%llu overruns=%llu\n", (unsigned long long)st->csi_lapped, (unsigned long long)csi_test_push_overruns());
    ck("watermark advanced past the marker anyway (the marker is final for 503)", st->csi_folded_height == 503);
    ck("INVALIDATED: coinstats.dat is gone (a lost record is a wrong digest)", csi_file_height() == -1);
    { rpc_out_t o; memset(&o, 0, sizeof o); char msg[256] = {0};
      ck("RPC: no index to serve (0), not a stale record", csi_rpc_run(1, &o, msg, sizeof msg) == 0); }
    csi_test_set_push_wait_ms(60000);
    int wp = csi_worker_pid();
    csi_worker_stop();
    ck("worker stopped and reaped", csi_worker_pid() == 0 && csi_ring_on() == 0 && (kill(wp, 0) != 0 || waitpid(wp, NULL, WNOHANG) != 0));
    ck("this process's stale accumulators are marked invalid, file NOT touched by the stop", csi_valid() == 0);

    printf("\n== 4: negative control -- no status block: inline folding, same digest ==\n");
    if (chdir("../inline")){ perror("chdir"); return 1; }
    csi_set_status(NULL);
    struct lsm_state l3; void* t3;
    { const coin_t* s[2] = { &A, &B }; lsm_build(&l3, &t3, s, 2); }
    ck("seed {A,B}", csi_seed_from_walk(&l3, t3, 500) == 1);
    ck("control: csi_worker_start refuses without a status block", csi_worker_start() == 0 && csi_ring_on() == 0);
    f0 = csi_test_fold_count();
    push_events();
    ck("control: every event folded IN THIS PROCESS (today's path)", csi_test_fold_count() - f0 == N_EVENTS);
    csi_commit(501);
    unsigned char d_inline[32];
    ck("live read", csi_read_live(&h, d_inline, &tx, &amt, &bg) == 1 && h == 501);
    ck("control: SAME digest as the worker produced", memcmp(d_inline, d_ring, 32) == 0);
    ck("control: same counters", tx == rtx && amt == ramt && bg == rbg);

    printf("\n%s (%d failures)\n", failures ? "TESTS FAILED" : "ALL TESTS PASSED", failures);
    return failures ? 1 : 0;
}
