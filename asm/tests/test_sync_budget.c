/* Regression test: the per-leg sync budget must END the pass, not just flag it.
 *
 * 2026-08-31, live signet worker: 47 minutes inside ONE leg's node_sync,
 * downloading at 500 KB/s, while UTXO catch-up, the heartbeat and every other
 * leg starved. In the live process mux_sync_budget_fired was already 1 -- the
 * 60s alarm HAD fired. Its only effect was EINTR on the blocked read, which
 * fd_read_full reports as -1, and node_sync_multi retries -1 (it also means a
 * 3s SO_RCVTIMEO tick, incident #33). alarm() is one-shot, so after that one
 * swallowed EINTR nothing interrupted the pass again.
 *
 * The handler now shuts the socket down, so the read returns EOF -- which
 * every layer already treats as "connection done". This test drives the real
 * asm fd_read_full against a peer that never stops sending, exactly the shape
 * that defeated the flag, and pins BOTH behaviours: with the fd registered the
 * read ends at the budget as EOF; without it the read merely returns -1 at the
 * alarm and the peer is still very much alive -- the retryable outcome that
 * wedged production.
 *
 * mux_budget_alarm and mux_budget_fd are static in daemon/main.c, so this
 * includes that TU directly (the test_dial_budget pattern). */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>

#define main daemon_main_disabled
#include "../daemon/main.c"
#undef main

extern long fd_read_full(int fd, void* buf, long n);   /* bitcoin_net.asm */

static int fails = 0;
static void ok(int c, const char* w){ printf("  %s %s\n", c?"ok ":"FAIL", w); if(!c) fails++; }
static double now(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec + t.tv_nsec/1e9; }

/* A peer that sends 100 bytes every 100ms forever: every read succeeds, so
 * nothing but the alarm can end a read of a large frame. */
static pid_t start_trickler(int fd){
    pid_t p = fork();
    if(p == 0){
        char buf[100]; memset(buf, 0x42, sizeof buf);
        for(;;){ if(send(fd, buf, sizeof buf, MSG_NOSIGNAL) != (ssize_t)sizeof buf) _exit(0); usleep(100000); }
    }
    return p;
}

int main(void){
    static unsigned char big[1<<20];
    struct sigaction sa, old; memset(&sa,0,sizeof sa);
    sa.sa_handler = mux_budget_alarm; sigemptyset(&sa.sa_mask);   /* no SA_RESTART, as production */

    printf("== OLD behaviour: alarm without the fd only yields a retryable -1 ==\n");
    {
        int sp[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
        pid_t peer = start_trickler(sp[1]); close(sp[1]);
        sigaction(SIGALRM,&sa,&old);
        mux_sync_budget_fired = 0; mux_budget_fd = -1;
        double t0 = now(); alarm(1);
        long r = fd_read_full(sp[0], big, sizeof big);
        alarm(0); sigaction(SIGALRM,&old,NULL);
        double dt = now() - t0;
        ok(mux_sync_budget_fired == 1, "the alarm fired");
        ok(r == -1, "fd_read_full reported -1 (EINTR), which node_sync_multi treats as a retryable timeout");
        /* the peer is still sending: a retry would simply carry on */
        char probe[4]; ssize_t pr = recv(sp[0], probe, sizeof probe, 0);
        ok(pr > 0, "and the connection is still alive -- a retry continues the pass (the wedge)");
        ok(dt < 3.0, "within a few seconds");
        kill(peer, SIGKILL); waitpid(peer, NULL, 0); close(sp[0]);
    }

    printf("== NEW behaviour: with the fd registered, the budget ENDS the pass ==\n");
    {
        int sp[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
        pid_t peer = start_trickler(sp[1]); close(sp[1]);
        sigaction(SIGALRM,&sa,&old);
        mux_sync_budget_fired = 0; mux_budget_fd = sp[0];
        double t0 = now(); alarm(1);
        long r = fd_read_full(sp[0], big, sizeof big);
        alarm(0); mux_budget_fd = -1; sigaction(SIGALRM,&old,NULL);
        double dt = now() - t0;
        ok(mux_sync_budget_fired == 1, "the alarm fired");
        /* The read IN FLIGHT when the alarm lands still sees EINTR (-1): the
         * signal interrupts it before shutdown()'s wake-up reaches it. That is
         * fine and exactly the production sequence -- node_sync_multi retries
         * the -1, and the retry is what must now end. */
        double t1 = now();
        long r2 = (r == -1) ? fd_read_full(sp[0], big, sizeof big) : r;
        ok(r2 >= 0 && r2 < (long)sizeof big,
           "the retry node_sync_multi would make returns SHORT/EOF at once, not another block");
        ok(now() - t1 < 0.5, "and returns immediately -- the pass is over");
        char probe[4]; ssize_t pr = recv(sp[0], probe, sizeof probe, 0);
        ok(pr == 0, "and the socket now reads EOF -- the pass cannot be retried into");
        ok(dt >= 0.9 && dt < 3.0, "at the budget, not before and not much after");
        kill(peer, SIGKILL); waitpid(peer, NULL, 0); close(sp[0]);
    }

    printf("== a pass that finishes inside the budget is untouched ==\n");
    {
        int sp[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
        unsigned char small[64]; memset(small, 7, sizeof small);
        send(sp[1], small, sizeof small, 0);
        sigaction(SIGALRM,&sa,&old);
        mux_sync_budget_fired = 0; mux_budget_fd = sp[0];
        alarm(2);
        long r = fd_read_full(sp[0], big, sizeof small);
        alarm(0); mux_budget_fd = -1; sigaction(SIGALRM,&old,NULL);
        ok(r == (long)sizeof small && mux_sync_budget_fired == 0, "full read, no alarm, socket left alone");
        char probe[4]; send(sp[1], "ab", 2, 0);
        ok(recv(sp[0], probe, 2, 0) == 2, "and it is still usable afterwards");
        close(sp[0]); close(sp[1]);
    }

    printf("\n%s (%d failure%s)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", fails, fails==1?"":"s");
    return fails ? 1 : 0;
}
