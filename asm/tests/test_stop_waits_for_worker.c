/* test_stop_waits_for_worker.c -- the main pid's exit MEANS the datadir is free.
 *
 * WHY THIS EXISTS
 *
 *   The datadir lock (DMN-1) is a flock on <datadir>/<chain>/.lock, and a
 *   flock belongs to the open file description: every process the serve
 *   parent forks -- the download worker, the inbound serve children, and
 *   what the worker forks in turn -- holds the same lock, and the kernel
 *   releases it when the last of them closes it. The parent forwarded SIGTERM
 *   to the worker and _exit(0)ed at once, so whenever the main pid had gone
 *   the worker was typically still flushing, still holding the lock. Anything
 *   that restarts on the main pid then booted into
 *       [boot] FATAL: cannot obtain a lock on data directory ...
 *   (2026-09-06 by hand -- DEPLOYMENT_HISTORY.md: "wait for the WORKER, not
 *   the parent"; and the bench/gate harnesses' `kill; wait; relaunch`).
 *
 * WHAT IT ASSERTS, per cycle, on a real regtest daemon (daemon/bmcbitcoind):
 *
 *   The worker is made SLOW to stop, deterministically: it is SIGSTOPped
 *   before the main pid gets its SIGTERM, and SIGCONTed a second later.
 *   (Production's worker took 1.3 s on 2026-09-18; a regtest worker takes
 *   milliseconds, which let the unfixed parent win the race only sometimes.)
 *
 *   1. While the worker cannot stop, the main pid does NOT exit.
 *   2. When it does exit, a fresh flock(LOCK_EX|LOCK_NB) on the lock file
 *      succeeds at that instant -- no process of that instance holds it.
 *   3. A new instance on the same datadir boots without the lock FATAL:
 *        odd cycles  -- started at the instant the main pid exits;
 *        even cycles -- started DURING the stop (the relaunch that does not
 *                       wait): it must see the stopping instance, wait for
 *                       it, and boot. The stopping parent, for its part,
 *                       must not mistake the newcomer's own open of .lock
 *                       for one of its holders.
 *   4. No process died holding the mempool lock, and the fold worker's stop
 *      is reported as a stop, not as "the index cannot be maintained".
 *
 *   With the parent's wait removed (the pre-2026-09-19 _exit), 1, 2 and 3
 *   fail on every cycle.
 *
 * SEAM NOTE. The test waitpid()s only the daemon's MAIN pid, which is its own
 * child. It never waits on the daemon's children -- that would steal the
 * statuses the daemon's own shutdown is waiting to collect.
 *
 * Usage: ./tests/test_stop_waits_for_worker   (from asm/, after make daemon/bmcbitcoind)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include "test_tmpdir.h"

#define CYCLES 4

static int fails = 0, checks = 0;
static void ck(const char* what, int cond){ checks++; if (cond) printf("ok  : %s\n", what); else { printf("FAIL: %s\n", what); fails++; } }
static long long ms(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec*1000LL + t.tv_nsec/1000000; }

static char g_dir[1024], g_conf[1200], g_lock[1200];

static pid_t spawn(const char* daemon, int n){
    char log[1300]; snprintf(log, sizeof log, "%s/run%d.log", g_dir, n);
    pid_t p = fork();
    if (p == 0){
        int fd = open(log, O_WRONLY|O_CREAT|O_TRUNC, 0600);
        if (fd >= 0){ dup2(fd, 1); dup2(fd, 2); close(fd); }
        char confarg[1300]; snprintf(confarg, sizeof confarg, "-conf=%s", g_conf);
        char* av[] = { (char*)daemon, confarg, "serve", g_dir, NULL };
        execv(daemon, av);
        _exit(127);
    }
    return p;
}
/* 1 = the log contains `needle`; reads the whole (small) log each call */
static int log_has(int n, const char* needle){
    char log[1300]; snprintf(log, sizeof log, "%s/run%d.log", g_dir, n);
    FILE* f = fopen(log, "r"); if (!f) return 0;
    static char buf[1 << 20]; size_t r = fread(buf, 1, sizeof buf - 1, f); fclose(f);
    buf[r] = 0;
    for (size_t i = 0; i < r; i++) if (!buf[i]) buf[i] = ' ';     /* the logs carry NULs */
    return strstr(buf, needle) != NULL;
}
/* wait for boot: 1 booted, 0 lock FATAL, -1 timeout or exited */
static int wait_boot(pid_t p, int n){
    long long t0 = ms();
    while (ms() - t0 < 60000){
        if (log_has(n, "boot phase complete")) return 1;
        if (log_has(n, "cannot obtain a lock")) return 0;
        int st; if (waitpid(p, &st, WNOHANG) == p) return log_has(n, "cannot obtain a lock") ? 0 : -1;
        usleep(20000);
    }
    return -1;
}
/* the download worker's pid, from "[serve] download worker pid N" */
static int worker_pid(int n){
    char log[1300]; snprintf(log, sizeof log, "%s/run%d.log", g_dir, n);
    FILE* f = fopen(log, "r"); if (!f) return -1;
    char line[4096]; int pid = -1;
    while (fgets(line, sizeof line, f)){
        char* p = strstr(line, "[serve] download worker pid ");
        if (p) pid = atoi(p + strlen("[serve] download worker pid "));
    }
    fclose(f);
    return pid;
}
static int lock_free_now(void){
    int fd = open(g_lock, O_RDWR);
    if (fd < 0) return 0;
    int ok = flock(fd, LOCK_EX|LOCK_NB) == 0;
    close(fd);                       /* releases it again */
    return ok;
}

int main(void){
    tt_isolate();
    const char* daemon = tt_src("daemon/bmcbitcoind");
    if (access(daemon, X_OK) != 0){ printf("FAIL: no daemon at %s (make daemon/bmcbitcoind)\n", daemon); return 1; }
    if (snprintf(g_dir, sizeof g_dir, "%.1000s/dd", tt_workdir()) >= (int)sizeof g_dir) return 2;
    mkdir(g_dir, 0700);
    snprintf(g_conf, sizeof g_conf, "%s/bitcoin.conf", g_dir);
    snprintf(g_lock, sizeof g_lock, "%s/regtest/.lock", g_dir);
    int base = 19000 + (int)(getpid() % 400) * 2;           /* 19000-19799: clear of 8331-8463 */
    FILE* c = fopen(g_conf, "w"); if (!c){ perror("conf"); return 2; }
    /* printtoconsole with the default debug.log: the log pump child is part
     * of the process tree under test. coinstatsindex: the fold worker too. */
    fprintf(c, "regtest=1\n[regtest]\nlisten=0\ndnsseed=0\nprinttoconsole=1\ncoinstatsindex=1\n"
               "port=%d\nrpcport=%d\n", base, base + 1);
    fclose(c);

    int n = 0;
    pid_t a = spawn(daemon, n);
    ck("instance 0 boots", wait_boot(a, n) == 1);
    for (int cyc = 1; cyc <= CYCLES; cyc++){
        char l[256];
        int during = (cyc % 2) == 0;
        printf("== cycle %d (relaunch %s) ==\n", cyc, during ? "DURING the stop" : "at the main pid's exit");
        int wpid = worker_pid(n);
        ck("the download worker's pid is in the log", wpid > 0);
        if (wpid <= 0) break;
        usleep(300000);                                     /* let the worker settle into its loop */
        kill(wpid, SIGSTOP);                                /* a worker that cannot stop yet */
        long long t0 = ms();
        kill(a, SIGTERM);
        usleep(1000000);
        int st = 0; pid_t w = waitpid(a, &st, WNOHANG);
        ck("the main pid is still there while its worker cannot stop", w == 0);
        pid_t b = -1;
        if (w == a){                                        /* exited early: the defect */
            ck("...(it exited with the worker still holding the lock: lock free?)", lock_free_now());
            b = spawn(daemon, n + 1);
        } else if (during) b = spawn(daemon, n + 1);        /* relaunch without waiting */
        usleep(during ? 500000 : 0);
        kill(wpid, SIGCONT);
        if (w == 0){
            alarm(700);                                     /* above the daemon's own 600 s bound */
            w = waitpid(a, &st, 0);
            alarm(0);
        }
        long long dt = ms() - t0;
        int freed = b < 0 ? lock_free_now() : -1;           /* THE assertion, at the instant of exit */
        if (b < 0) b = spawn(daemon, n + 1);                /* ...and the relaunch at that instant */
        snprintf(l, sizeof l, "main pid exited 0 on SIGTERM (%lld ms, 1000 of them with the worker stopped)", dt);
        ck(l, w == a && WIFEXITED(st) && WEXITSTATUS(st) == 0);
        if (freed >= 0) ck("the datadir lock is FREE the moment the main pid has exited", freed);
        ck("the parent logged that no other process held the lock", log_has(n, "held by no other process"));
        ck("no process died holding the mempool lock", !log_has(n, "died holding the mempool lock"));
        ck("the fold worker's stop is reported as a stop", log_has(n, "fold worker pid") && !log_has(n, "the index cannot be maintained"));
        int r = wait_boot(b, n + 1);
        ck("the new instance boots (no lock FATAL)", r == 1);
        if (during){
            ck("...having waited for the stopping instance", log_has(n + 1, "which is stopping; waiting"));
            ck("...and the stopping parent never counted it as a holder", !log_has(n, "(bmcbitcoind) -- SIGTERM"));
        }
        if (r != 1){ kill(b, SIGKILL); waitpid(b, NULL, 0); break; }
        a = b; n++;
    }
    kill(a, SIGTERM); waitpid(a, NULL, 0);
    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
