/* index_worker.c -- the index writers off the applier (plan B4). See the
 * header for the shape. */
#include "index_worker.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static node_status_t*     g_st;
static ixw_hooks_t        g_h;
static pid_t              g_pid;         /* the worker, in the parent */
static pid_t              g_owner;       /* the process that started it: the only one that reaps and records its death */
static int                g_in_child;
static long               g_cur_h = -1;  /* in the worker */
static int                g_reaped;

static void ixw_sleep_us(long us){ struct timespec t = { us / 1000000L, (us % 1000000L) * 1000L }; nanosleep(&t, NULL); }
static long long ixw_mono_ms(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (long long)t.tv_sec * 1000LL + t.tv_nsec / 1000000LL; }

long ixw_current_height(void){ return g_cur_h; }
long ixw_pid(void){ return (long)g_pid; }
int  ixw_on(void){ return g_pid > 0 && !g_reaped; }

/* reap without blocking; 1 when the worker is gone. Only the starting
 * process reaps: another process that inherited this state (a forked
 * helper pushing a record) sees ECHILD for a worker that is alive, and
 * must neither mark it dead nor zero the shared pid (2026-10-06: a test's
 * producer child did, and the next signal went to pid 0 -- the group). */
int ixw_dead(void){
    if (g_pid <= 0) return 1;
    if (g_reaped) return 1;
    if (getpid() != g_owner) return !(g_st && g_st->ixw_worker_pid > 0 && kill((pid_t)g_st->ixw_worker_pid, 0) == 0);
    int st = 0; pid_t r = waitpid(g_pid, &st, WNOHANG);
    if (r == g_pid){ g_reaped = 1; if (g_st) g_st->ixw_worker_pid = 0; return 1; }
    if (r < 0 && errno == ECHILD){ g_reaped = 1; if (g_st) g_st->ixw_worker_pid = 0; return 1; }   /* reaped elsewhere (a SIGCHLD reaper) */
    if (kill(g_pid, 0) < 0 && errno == ESRCH){ g_reaped = 1; if (g_st) g_st->ixw_worker_pid = 0; return 1; }
    return 0;
}

static void worker_run(pid_t parent){
    g_in_child = 1;
    signal(SIGTERM, SIG_IGN); signal(SIGINT, SIG_IGN); signal(SIGHUP, SIG_IGN);   /* the STOP record or the parent's death ends this process */
    if (g_h.in_child) g_h.in_child();
    long cap = g_h.block_cap > 0 ? g_h.block_cap : (8L << 20);
    unsigned char* buf = malloc((size_t)cap);
    if (!buf){ fprintf(stderr, "[ixw] no memory for the block buffer -- worker exiting\n"); _exit(1); }
    node_status_t* st = g_st;
    unsigned long long done = st->ixw_done_seq;
    for (;;){
        if (getppid() != parent) _exit(0);
        if (done >= st->ixw_seq || st->ixw_pause){ ixw_sleep_us(500); continue; }
        volatile typeof(st->ixw_ring[0])* e = &st->ixw_ring[done % RPC_IXW_RING];
        long long t0 = ixw_mono_ms();
        while (e->ready != done + 1){ if (ixw_mono_ms() - t0 > 2000){ fprintf(stderr, "[ixw] ring slot %llu not ready in 2 s -- worker exiting\n", (unsigned long long)done); _exit(2); } ixw_sleep_us(100); }
        int kind = e->kind; long a = (long)e->a;
        if (kind == IXW_K_STOP){ st->ixw_done_seq = done + 1; _exit(0); }
        if (kind == IXW_K_BLOCK){
            g_cur_h = a;
            long blen = g_h.read_block(a, buf, cap);
            if (blen <= 0 && g_h.reload){ g_h.reload(); blen = g_h.read_block(a, buf, cap); }
            if (blen <= 0){
                fprintf(stderr, "[ixw] block %ld unreadable (%ld) -- not indexed by the worker (the tails backfill the gap at the next height)\n", a, blen);
            } else {
                unsigned long long ns[IXW_NS_N]; memset(ns, 0, sizeof ns);
                g_h.on_block(a, buf, blen, ns);
                if (g_h.log_index) g_h.log_index(a, ns);
                st->ixw_blocks++;
            }
            if (g_h.covered)   st->ixw_covered   = g_h.covered();
            if (g_h.bfi_count) st->ixw_bfi_count = g_h.bfi_count();
        } else if (kind == IXW_K_ADV_TXI || kind == IXW_K_ADV_TSP || kind == IXW_K_ADV_AH){
            if (g_h.runs_advanced) g_h.runs_advanced(kind, a);
        }
        done++;
        st->ixw_done_seq = done;
    }
}

int ixw_start(node_status_t* st, const ixw_hooks_t* hooks){
    if (!st || !hooks || !hooks->read_block || !hooks->on_block) return 0;
    if (g_pid > 0 && !ixw_dead()) return 0;
    g_st = st; g_h = *hooks; g_reaped = 0;
    st->ixw_seq = 0; st->ixw_done_seq = 0; st->ixw_blocks = 0; st->ixw_pause = 0;
    st->ixw_covered = hooks->covered ? hooks->covered() : -1;
    st->ixw_bfi_count = hooks->bfi_count ? hooks->bfi_count() : -1;
    for (long i = 0; i < RPC_IXW_RING; i++) st->ixw_ring[i].ready = 0;
    pid_t parent = getpid();
    pid_t p = fork();
    if (p < 0){ fprintf(stderr, "[ixw] fork for the index worker failed (%s) -- indexing inline\n", strerror(errno)); g_pid = 0; return 0; }
    if (p == 0) worker_run(parent);   /* never returns */
    g_pid = p; g_owner = parent; st->ixw_worker_pid = (int)p;
    fprintf(stderr, "[ixw] index worker pid %d started: the applier pushes heights, the worker writes the txid tail, the txospender tail, the filter index and the address journal\n", (int)p);
    return 1;
}

/* the single producer: waits for room; a dead worker makes this 0 */
int ixw_push(int kind, long a){
    if (!ixw_on() || ixw_dead()) return 0;   /* a killed worker is noticed here, ring room or not */
    node_status_t* st = g_st;
    long long last_check = ixw_mono_ms();
    while (st->ixw_seq - st->ixw_done_seq >= RPC_IXW_RING){
        ixw_sleep_us(500);
        long long now = ixw_mono_ms();
        if (now - last_check >= 100){ last_check = now; if (ixw_dead()) return 0; }
    }
    unsigned long long seq = st->ixw_seq;
    volatile typeof(st->ixw_ring[0])* e = &st->ixw_ring[seq % RPC_IXW_RING];
    e->kind = kind; e->a = a;
    __sync_synchronize();
    e->ready = seq + 1;
    __sync_synchronize();
    st->ixw_seq = seq + 1;
    return 1;
}

void ixw_stop(void){
    if (g_pid <= 0) return;
    pid_t p = g_pid;
    if (!ixw_dead()){
        unsigned long long want = g_st->ixw_seq + 1;
        if (ixw_push(IXW_K_STOP, 0)){
            long long t0 = ixw_mono_ms();
            while (!ixw_dead()){
                if (g_st->ixw_done_seq >= want) break;   /* everything before the STOP is done (the exit follows) */
                if (ixw_mono_ms() - t0 > 60000){
                    fprintf(stderr, "[ixw] index worker pid %d did not stop in 60 s (%llu of %llu records done) -- killing it (the tails backfill what it missed)\n",
                            (int)p, (unsigned long long)g_st->ixw_done_seq, (unsigned long long)g_st->ixw_seq);
                    kill(p, SIGKILL);
                    break;
                }
                ixw_sleep_us(1000);
            }
        }
        long long t1 = ixw_mono_ms();
        while (!ixw_dead()){ if (ixw_mono_ms() - t1 > 5000){ kill(p, SIGKILL); } ixw_sleep_us(1000); if (ixw_mono_ms() - t1 > 10000) break; }
    }
    fprintf(stderr, "[ixw] index worker pid %d stopped: %llu block(s) indexed, covered %lld, filters %lld\n",
            (int)p, (unsigned long long)g_st->ixw_blocks, (long long)g_st->ixw_covered, (long long)g_st->ixw_bfi_count);
    g_reaped = 1; g_pid = 0; if (g_st) g_st->ixw_worker_pid = 0;
}
