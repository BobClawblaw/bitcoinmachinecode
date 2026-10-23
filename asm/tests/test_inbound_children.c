/* tests/test_inbound_children.c -- the serve parent's inbound child count
 * (daemon/inbound_children.h, HST-1 and HST-2 of the 2026-10-23 audit).
 *
 * The count bounds inbound peers (CFG_INBOUND_LIMIT). It used to be a plain
 * counter: ++ after each inbound fork in the mux loop, -- in the SIGCHLD
 * handler for EVERY reaped child but the download worker. So
 *   1. a non-inbound child (a notify hook's intermediate, an RPC helper)
 *      took a slot's worth off the count -- the cap admitted extra peers;
 *   2. a child that exited before the parent counted it was decremented
 *      first (clamped at 0) and incremented after: a slot leaked for good;
 *   3. ++ and -- were not atomic, and the handler may run on another thread.
 * Each is driven here through the daemon's own functions, with the
 * daemon's reaper shape (waitpid(-1) in a SIGCHLD handler). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/wait.h>
#include "../daemon/inbound_children.h"

static int fails = 0;
static void ck(const char* w, int c){ printf("%s %s\n", c ? "ok  :" : "FAIL:", w); if (!c) fails++; }

static void reaper(int sig){            /* main.c reap_children, minus the worker */
    (void)sig; int e = errno, st; pid_t p;
    while ((p = waitpid(-1, &st, WNOHANG)) > 0) inb_reaped(p);
    errno = e;
}
static void msleep(int ms){ struct timespec t = { ms / 1000, (ms % 1000) * 1000000L }; while (nanosleep(&t, &t) != 0 && errno == EINTR) {} }
static void settle(void){                 /* every exited child reaped by the handler */
    for (int i = 0; i < 200; i++){ msleep(10); if (waitpid(-1, NULL, WNOHANG | WNOWAIT) < 0 && errno == ECHILD) return; }
}

/* HST-2 stress: one thread registers pids, another "reaps" them, as the mux
 * loop and a handler on another thread do; the reaper may run a few pids
 * AHEAD of the registration (a child that exited before it was counted). */
#define STRESS_N 200000
static volatile long g_reg_done, g_reap_done;
static void* reg_thread(void* a){
    (void)a;
    for (long i = 1; i <= STRESS_N; i++){
        while (i - __atomic_load_n(&g_reap_done, __ATOMIC_SEQ_CST) > 2000) {}   /* bound the live table */
        inb_register((pid_t)(1000000 + i));
        __atomic_store_n(&g_reg_done, i, __ATOMIC_SEQ_CST);
    }
    return NULL;
}
static void* reap_thread(void* a){
    (void)a;
    for (long i = 1; i <= STRESS_N; i++){
        while (i - __atomic_load_n(&g_reg_done, __ATOMIC_SEQ_CST) > 8) {}       /* at most 8 ahead */
        inb_reaped((pid_t)(1000000 + i));
        __atomic_store_n(&g_reap_done, i, __ATOMIC_SEQ_CST);
    }
    return NULL;
}

int main(void){
    struct sigaction sc; memset(&sc, 0, sizeof sc); sc.sa_handler = reaper;
    sigemptyset(&sc.sa_mask); sc.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sc, NULL);

    printf("== HST-1: only inbound children count ==\n");
    pid_t live[5];
    for (int i = 0; i < 5; i++){
        live[i] = fork();
        if (live[i] == 0){ pause(); _exit(0); }
        inb_register(live[i]);
    }
    ck("five inbound children counted", inb_count() == 5);
    for (int i = 0; i < 20; i++){ pid_t p = fork(); if (p == 0) _exit(0); }   /* hooks, helpers: not inbound */
    msleep(300);
    ck("HST-1: twenty other children exiting leave the count at 5", inb_count() == 5);
    if (inb_count() != 5) printf("      count is %d\n", inb_count());
    for (int i = 0; i < 5; i++) kill(live[i], SIGTERM);
    settle();
    ck("the five leaving brings it to 0", inb_count() == 0);
    if (inb_count() != 0) printf("      count is %d\n", inb_count());

    printf("== HST-1: a child that exits before it is counted ==\n");
    for (int r = 0; r < 10; r++){
        pid_t p = fork();
        if (p == 0) _exit(0);
        msleep(30);                       /* reaped by the handler before the parent registers it */
        inb_register(p);
    }
    ck("HST-1: ten early exits leak no slot (count 0)", inb_count() == 0);
    if (inb_count() != 0) printf("      count is %d\n", inb_count());

    printf("== HST-2: concurrent register and reap ==\n");
    sigaction(SIGCHLD, &(struct sigaction){ .sa_handler = SIG_DFL }, NULL);
    pthread_t a, b;
    pthread_create(&a, NULL, reg_thread, NULL);
    pthread_create(&b, NULL, reap_thread, NULL);
    pthread_join(a, NULL); pthread_join(b, NULL);
    ck("HST-2: 200000 registrations and reaps on two threads net to 0", inb_count() == 0);
    if (inb_count() != 0) printf("      count is %d\n", inb_count());

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
