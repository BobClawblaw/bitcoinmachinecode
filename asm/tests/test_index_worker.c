/* tests/test_index_worker.c -- the index worker (daemon/index_worker.c,
 * 2026-10-06, plan B4): the applier pushes heights and fold markers onto
 * the shared ring, a FORKED worker consumes them in order through the
 * writer hooks, and the published watermarks follow.
 *
 * Pinned, against the real module with a MAP_SHARED node_status_t exactly
 * as the daemon shares it across its fork, the hooks recording into shared
 * memory so the parent reads what the worker did:
 *
 *   1. order: 1,000 BLOCK records with ADV records between them reach the
 *      hooks in push order, every one, in the worker (not this process);
 *      the published covered height and filter count are the last block's;
 *   2. an unreadable block is retried after a reload and indexed;
 *   3. backpressure: with the worker paused, a producer that fills the
 *      ring blocks on the next push and proceeds once the worker moves;
 *   4. STOP drains everything pushed before it, then the worker exits and
 *      ixw_on() is 0;
 *   5. a worker that dies (SIGKILL) is noticed at the next push, which
 *      returns 0 so the caller indexes inline; ixw_on() is 0;
 *   6. a SIGTERM to the worker (systemd's group stop) does not end it;
 *   7. the revert-check this file carries: the hooks run in the WORKER's
 *      pid only -- with the fork removed, every record would be served in
 *      the test's own process and 1 would fail on the pid. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include "../daemon/index_worker.h"

static int fails = 0;
static void ck(const char* l, int c){ printf("%s %s\n", c ? "ok  :" : "FAIL:", l); if (!c) fails++; }
static void sleep_ms(long ms){ struct timespec t = { ms / 1000, (ms % 1000) * 1000000L }; nanosleep(&t, NULL); }
static long long mono_ms(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (long long)t.tv_sec * 1000LL + t.tv_nsec / 1000000LL; }

/* the shared record of what the hooks saw (written by the worker) */
#define LOG_MAX 4096
typedef struct {
    volatile long n;
    volatile int  kind[LOG_MAX];       /* 1 block, 2..4 adv */
    volatile long a[LOG_MAX];
    volatile int  pid[LOG_MAX];
    volatile long covered, bfi;
    volatile long reloads;
    volatile long fail_h;              /* read_block fails for this height until a reload */
    volatile int  in_child_calls;
} shlog_t;
static shlog_t* L;

static long h_read(long h, unsigned char* buf, long cap){
    (void)cap;
    if (h == L->fail_h) return -3;
    buf[0] = (unsigned char)h; return 100 + (h % 7);
}
static void h_reload(void){ L->reloads++; L->fail_h = -1; }
static void h_on_block(long h, const unsigned char* blk, long blen, unsigned long long ns[IXW_NS_N]){
    (void)blk; (void)blen;
    long i = L->n; if (i < LOG_MAX){ L->kind[i] = 1; L->a[i] = h; L->pid[i] = (int)getpid(); L->n = i + 1; }
    L->covered = h; L->bfi = h + 1; ns[0] = 1;
}
static void h_adv(int kind, long to){
    long i = L->n; if (i < LOG_MAX){ L->kind[i] = kind; L->a[i] = to; L->pid[i] = (int)getpid(); L->n = i + 1; }
}
static long h_covered(void){ return L->covered; }
static long h_bfi(void){ return L->bfi; }
static void h_in_child(void){ L->in_child_calls++; }

static node_status_t* st;
static ixw_hooks_t hooks;

static void wait_done(unsigned long long seq, long ms){
    long long t0 = mono_ms();
    while (st->ixw_done_seq < seq && mono_ms() - t0 < ms) sleep_ms(1);
}

int main(void){
    setvbuf(stdout, NULL, _IONBF, 0);
    st = mmap(NULL, sizeof *st, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    L  = mmap(NULL, sizeof *L,  PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (st == MAP_FAILED || L == MAP_FAILED){ printf("FAIL: mmap\n"); return 1; }
    memset(st, 0, sizeof *st); memset(L, 0, sizeof *L); L->fail_h = -1; L->covered = -1; L->bfi = -1;
    memset(&hooks, 0, sizeof hooks);
    hooks.read_block = h_read; hooks.reload = h_reload; hooks.on_block = h_on_block; hooks.runs_advanced = h_adv;
    hooks.covered = h_covered; hooks.bfi_count = h_bfi; hooks.in_child = h_in_child; hooks.block_cap = 4096;

    /* ---- 1. order, in the worker ---- */
    ck("ixw_on is 0 before a start", !ixw_on());
    ck("push with no worker is 0 (the caller indexes inline)", ixw_push(IXW_K_BLOCK, 1) == 0);
    ck("start forks a worker", ixw_start(st, &hooks) == 1 && ixw_on() && st->ixw_worker_pid > 0);
    int me = (int)getpid();
    long expect_n = 0;
    for (long h = 0; h < 1000; h++){

        if (!ixw_push(IXW_K_BLOCK, h)){ printf("FAIL: push %ld refused\n", h); fails++; goto ck_push_done; }
        expect_n++;
        if (h == 300){ ixw_push(IXW_K_ADV_TXI, 150); expect_n++; }
        if (h == 600){ ixw_push(IXW_K_ADV_AH, 400); expect_n++; }
    }
    ck_push_done:
    wait_done(st->ixw_seq, 10000);
    ck("every record consumed (done_seq == seq)", st->ixw_done_seq == st->ixw_seq);
    { int order = L->n == expect_n, inworker = 1; long bh = 0; long li = 0;
      for (long i = 0; order && i < L->n; i++){
          if (L->pid[i] == me) inworker = 0;
          if (L->kind[i] == 1){ if (L->a[i] != bh) order = 0; bh++; }
          else if (L->kind[i] == IXW_K_ADV_TXI){ if (bh != 301 || L->a[i] != 150) order = 0; li++; }
          else if (L->kind[i] == IXW_K_ADV_AH){ if (bh != 601 || L->a[i] != 400) order = 0; li++; }
          else order = 0;
      }
      ck("1,000 blocks and 2 fold markers reached the hooks in push order", order && bh == 1000 && li == 2);
      ck("...every one in the WORKER's process, none in this one (the fork is real)", inworker && L->n > 0 && L->pid[0] != me && L->pid[0] == st->ixw_worker_pid);
      ck("the published watermarks are the last block's (covered 999, filters 1000)", st->ixw_covered == 999 && st->ixw_bfi_count == 1000 && st->ixw_blocks == 1000);
      ck("the in_child hook ran once, in the worker", L->in_child_calls == 1); }

    /* ---- 2. an unreadable block: reload, retry ---- */
    L->fail_h = 1000;
    ixw_push(IXW_K_BLOCK, 1000); expect_n++;
    wait_done(st->ixw_seq, 5000);
    ck("an unreadable block is retried after a reload and indexed", L->reloads == 1 && L->n == expect_n && L->a[L->n - 1] == 1000 && st->ixw_covered == 1000);

    /* ---- 3. backpressure ---- */
    st->ixw_pause = 1;
    sleep_ms(5);
    long room = (long)(RPC_IXW_RING - (st->ixw_seq - st->ixw_done_seq));
    for (long i = 0; i < room; i++){ ixw_push(IXW_K_BLOCK, 2000 + i); expect_n++; }
    ck("the ring is full (seq - done == RING)", st->ixw_seq - st->ixw_done_seq == RPC_IXW_RING);
    volatile int* flag = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    *flag = 0;
    pid_t prod = fork();
    if (prod == 0){ ixw_push(IXW_K_BLOCK, 3000); *flag = 1; _exit(0); }
    sleep_ms(300);
    ck("a push on a full ring blocks while the worker is paused (300 ms)", *flag == 0);
    st->ixw_pause = 0;
    { long long t0 = mono_ms(); while (*flag == 0 && mono_ms() - t0 < 10000) sleep_ms(1); }
    int pst = 0; waitpid(prod, &pst, 0);
    ck("...and proceeds once the worker moves", *flag == 1);
    expect_n++;   /* the child's push (seq in shared memory; the child's own g_* are a copy) */
    wait_done(st->ixw_seq, 10000);
    ck("after the pause every pushed record is consumed", st->ixw_done_seq == st->ixw_seq && L->n == expect_n && L->a[L->n - 1] == 3000);

    /* ---- 6. SIGTERM does not end the worker ---- */
    { int wp = st->ixw_worker_pid; ck("the worker pid is still published after a sibling process pushed (it is not the worker's parent)", wp > 0); if (wp > 0) kill(wp, SIGTERM); sleep_ms(50);
      ck("a SIGTERM to the worker (a group stop) does not end it", !ixw_dead() && ixw_on());
      ixw_push(IXW_K_BLOCK, 4000); expect_n++; wait_done(st->ixw_seq, 5000);
      ck("...and it keeps serving", L->a[L->n - 1] == 4000); }

    /* ---- 4. STOP drains ---- */
    st->ixw_pause = 1;
    for (long i = 0; i < 10; i++){ ixw_push(IXW_K_BLOCK, 5000 + i); expect_n++; }
    { pid_t stopper = fork();   /* ixw_stop blocks until the worker is done: unpause from a sibling after 200 ms */
      if (stopper == 0){ sleep_ms(200); st->ixw_pause = 0; _exit(0); }
      int wp = st->ixw_worker_pid;
      ixw_stop();
      int sst = 0; waitpid(stopper, &sst, 0);
      ck("STOP: everything pushed before it was indexed first", L->n == expect_n && L->a[L->n - 1] == 5009 && st->ixw_covered == 5009);
      ck("STOP: the worker exited and ixw_on() is 0", !ixw_on() && kill(wp, 0) < 0 && st->ixw_worker_pid == 0); }
    ck("push after the stop is 0 (inline again)", ixw_push(IXW_K_BLOCK, 6000) == 0);

    /* ---- 5. a dead worker ---- */
    ck("a second start works after a stop", ixw_start(st, &hooks) == 1 && ixw_on());
    { int wp = st->ixw_worker_pid; kill(wp, SIGKILL); int w = 0; waitpid(wp, &w, 0); (void)w;
      ck("a killed worker: the next push returns 0 and ixw_on() is 0", ixw_push(IXW_K_BLOCK, 7000) == 0 && !ixw_on() && ixw_dead());
      ixw_stop();   /* a no-op on a dead worker */
      ck("stop on a dead worker is harmless", !ixw_on()); }

    printf("%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
