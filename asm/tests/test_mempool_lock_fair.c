/* test_mempool_lock_fair.c -- a waiter is not starved by a holder that
 * releases and takes the lock again at once (2026-10-09).
 *
 * Production (the Mac's mainnet node, e9a44c97): a client polling
 * getmempoolentry in a loop held the pool lock 3-18 ms per call, and the
 * download worker's accepts waited 1-6 s behind it, with 97-216 takes going
 * by during each wait. mp_unlock frees the lock and wakes one waiter, but
 * the releasing thread's next take is a single CAS and wins the race
 * before the woken waiter is scheduled.
 *
 * Here a child process plays the poller (take, hold 3 ms, release, take
 * again at once) and the parent plays the worker: 20 takes, each timed.
 * A newcomer that finds others already waiting now sleeps behind them for
 * at most 1 ms, or until the next unlock wakes it, before it may take the
 * lock, so the woken waiter gets it. Watched to fail first: without the
 * deferral, the longest wait is 2.8-3.7 s.
 *
 * The deferral is in the Mac's lock (mp_rlock_lock). Linux takes a
 * process-shared pthread_mutex, which may barge the same way; until it
 * gets the same treatment the check is N/A there (x86 note, item 30). */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>
#include "../daemon/node_config.h"
#include "../daemon/mempool_lock.h"

extern int  mempool_configure(void);
extern void* mp_ext_area;

static int fails=0;
static void ck(const char* what, int cond){ if(cond) printf("ok  : %s\n",what); else { printf("FAIL: %s\n",what); fails++; } }
long mempool_resolve_confirmed_utxo(void* u, const unsigned char* t, unsigned long i,
                                    unsigned long long* v, const unsigned char** sp,
                                    unsigned long* sl){
    (void)u;(void)t;(void)i;(void)v;(void)sp;(void)sl; return 0;
}
static double now_ms(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6; }
static int cmp_d(const void* a, const void* b){ double x = *(const double*)a, y = *(const double*)b; return (x > y) - (x < y); }

int main(void){
#ifndef __APPLE__
    printf("N/A   lock fairness (the deferral is in the Mac's lock; x86 note item 30)\n");
    return 0;
#endif
    g_cfg.maxmempool_mb = 8;
    ck("mempool_configure(8MB)", mempool_configure() == 1 && mp_ext_area != NULL);
    mp_lock_set_log_ms(0);
    int pfd[2]; if (pipe(pfd) != 0) return 1;
    pid_t c = fork();
    if (c == 0){
        close(pfd[0]);
        int signalled = 0;
        double end = now_ms() + 8000;              /* the parent kills it sooner */
        while (now_ms() < end){
            mp_lock_at("poller");
            if (!signalled){ if (write(pfd[1], "L", 1) != 1) {} signalled = 1; }
            usleep(3000);
            mp_unlock();
        }
        _exit(0);
    }
    close(pfd[1]);
    char b; if (read(pfd[0], &b, 1) != 1) {}
    usleep(50000);
    enum { N = 20 };
    double w[N], total = now_ms();
    for (int i = 0; i < N; i++){
        double t0 = now_ms();
        mp_lock_at("worker");
        w[i] = now_ms() - t0;
        usleep(200);
        mp_unlock();
        usleep(2000);
    }
    total = now_ms() - total;
    kill(c, SIGKILL); waitpid(c, NULL, 0);
    double s[N]; memcpy(s, w, sizeof s); qsort(s, N, sizeof *s, cmp_d);
    printf("  %d takes against a 3 ms poller: median wait %.1f ms, longest %.1f ms, all %d in %.0f ms\n",
           N, s[N/2], s[N-1], N, total);
    char what[160];
    snprintf(what, sizeof what, "the longest wait is a few of the poller's holds, not a starvation (%.1f ms < 50)", s[N-1]);
    ck(what, s[N-1] < 50.0);
    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
