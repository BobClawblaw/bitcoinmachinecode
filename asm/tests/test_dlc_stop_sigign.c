/* test_dlc_stop_sigign.c -- the download worker's helper stop must not
 * block under SIGCHLD = SIG_IGN (the 2026-09-24 m5ultra wedge).
 *
 * The worker runs with SIGCHLD ignored, and there a blocking
 * waitpid(pid, .., 0) on a child that is still alive sleeps until EVERY
 * child has exited. dlc_stop_workers used to SIGTERM the helpers (advisory:
 * their handler only sets a flag), SIGKILL the first survivor and then block
 * on it -- so with the other helpers and any long-lived sibling (committer,
 * fold worker, index builder) alive, it never returned: the worker sat in
 * wait4 for 2.5 h after the h=274443 reject and ignored the parent's SIGTERM.
 *
 * Shape reproduced here: SIGCHLD ignored, a long-lived sibling that is not a
 * helper, N helpers that ignore SIGTERM, a committer that ignores SIGTERM.
 * The real dlc_stop_workers and dlc_stop_committer (main.c as a TU) must
 * return within the SIGTERM grace plus slack, kill every helper and zero the
 * bookkeeping. An alarm() watchdog turns the old hang into a FAIL. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define main daemon_main_disabled
#include "../daemon/main.c"
#undef main

static void watchdog(int s){ (void)s; static const char m[] = "FAIL: stop blocked (watchdog)\n"; ssize_t w = write(2, m, sizeof m - 1); (void)w; _exit(1); }
static pid_t spawn_term_ignorer(void){
    pid_t p = fork();
    if (p == 0){ signal(SIGTERM, SIG_IGN); signal(SIGALRM, SIG_DFL); alarm(60); for(;;) pause(); }
    return p;
}
static double now_s(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec / 1e9; }

int main(void){
    int fails = 0;
    signal(SIGCHLD, SIG_IGN);                           /* serve_download_worker's disposition */
    signal(SIGALRM, watchdog);
    pid_t sibling = spawn_term_ignorer();               /* a long-lived child that is not a helper */

    enum { NW = 8 };
    pid_t kids[NW], orig[NW];
    for (int w = 0; w < NW; w++) orig[w] = kids[w] = spawn_term_ignorer();
    usleep(100000);

    alarm(15);
    double t0 = now_s();
    dlc_stop_workers(kids, NW, "test reject");
    double dt = now_s() - t0;
    alarm(0);
    int zeroed = 1, dead = 1;
    for (int w = 0; w < NW; w++){ if (kids[w]) zeroed = 0; if (kill(orig[w], 0) == 0) dead = 0; }
    printf("dlc_stop_workers: %d helpers, returned in %.2fs, zeroed=%d all_dead=%d\n", NW, dt, zeroed, dead);
    if (dt > 3.0 || !zeroed || !dead){ printf("FAIL: dlc_stop_workers\n"); fails++; }

    g_dlc_committer = spawn_term_ignorer();
    pid_t c = g_dlc_committer;
    usleep(100000);
    alarm(15);
    t0 = now_s();
    dlc_stop_committer();
    dt = now_s() - t0;
    alarm(0);
    printf("dlc_stop_committer: returned in %.2fs, cleared=%d dead=%d\n", dt, g_dlc_committer == 0, kill(c, 0) != 0);
    if (dt > 3.0 || g_dlc_committer != 0 || kill(c, 0) == 0){ printf("FAIL: dlc_stop_committer\n"); fails++; }

    /* a helper that exits on SIGTERM is reaped inside the grace, early */
    pid_t quick[2];
    for (int w = 0; w < 2; w++){ quick[w] = fork(); if (quick[w] == 0){ signal(SIGALRM, SIG_DFL); alarm(60); for(;;) pause(); } }
    usleep(100000);
    alarm(15);
    t0 = now_s();
    dlc_stop_workers(quick, 2, "test clean stop");
    dt = now_s() - t0;
    alarm(0);
    printf("dlc_stop_workers (SIGTERM-honouring helpers): returned in %.2fs\n", dt);
    if (dt > 0.9){ printf("FAIL: the grace did not end early\n"); fails++; }

    printf("sibling untouched: %d\n", kill(sibling, 0) == 0);
    if (kill(sibling, 0) != 0){ printf("FAIL: the non-helper sibling was killed\n"); fails++; }
    kill(sibling, SIGKILL);

    printf("%s\n", fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
