/* tests/test_inbound_idle_timeout.c -- NET-3 (audit 2026-09-03): an idle
 * inbound peer must not hold its slot forever.
 *
 * THE DEFECT. An accepted socket got no SO_RCVTIMEO, no alarm and no
 * per-child deadline, and fd_read_full (bitcoin_net.asm) blocks in read(2)
 * with no poll. A peer that completed the version handshake and then went
 * silent held its inbound slot and its forked child indefinitely. An attacker
 * opening CFG_INBOUND_LIMIT (189) such connections makes the parent log
 * "inbound at capacity" and refuse every honest peer, for the price of 189
 * idle sockets.
 *
 * WHAT THIS PINS, and why it is at this level. The fix is a setsockopt in the
 * parent, but the property that actually matters is further down: that a
 * receive timeout PROPAGATES through the assembly reader as a failure rather
 * than being retried. fd_read_full returns -1 on any read error and does not
 * loop on EAGAIN -- so the timeout ends the child's serve loop. A test of the
 * setsockopt alone would pass even if fd_read_full spun on EAGAIN forever,
 * which is the failure mode that would leave the DoS fully intact.
 *
 * So this drives the REAL fd_read_full over a real socket:
 *   1. with no timeout set, it blocks (checked with a short alarm, so a
 *      regression that quietly stops blocking is also visible);
 *   2. with SO_RCVTIMEO set, it returns < 0 promptly;
 *   3. and it does so at roughly the configured deadline, not instantly --
 *      an implementation that returned -1 immediately would pass a
 *      "returns < 0" check while breaking every real peer.
 *
 * Usage: ./test_inbound_idle_timeout
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/socket.h>
#include <sys/time.h>

extern long fd_read_full(int fd, void* buf, long n);

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("ok  : %s\n", l); else { printf("FAIL: %s\n", l); fails++; } }

static sigjmp_buf jb;
static void on_alarm(int s){ (void)s; siglongjmp(jb, 1); }

static double now_s(void){
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + 1e-9*(double)t.tv_nsec;
}

int main(void){
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0){ printf("FAIL: socketpair\n"); return 1; }

    unsigned char buf[64];

    /* ---- 1. no timeout: fd_read_full blocks (the defect's precondition) -- */
    signal(SIGALRM, on_alarm);
    int blocked = 0;
    if (sigsetjmp(jb, 1) == 0){
        alarm(2);
        (void)fd_read_full(sv[0], buf, 16);   /* peer never writes */
        alarm(0);
    } else {
        blocked = 1;                          /* alarm fired: it was blocking */
    }
    alarm(0);
    ck("without a timeout fd_read_full blocks on a silent peer", blocked);

    /* ---- 2/3. with SO_RCVTIMEO it returns, and at the deadline ---------- */
    int sv2[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) != 0){ printf("FAIL: socketpair 2\n"); return 1; }
    struct timeval tv = { 1, 0 };             /* 1 second, as the daemon sets 1200 */
    if (setsockopt(sv2[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) != 0){
        printf("FAIL: setsockopt SO_RCVTIMEO\n"); return 1;
    }

    double t0 = now_s();
    long r = fd_read_full(sv2[0], buf, 16);
    double dt = now_s() - t0;
    printf("      fd_read_full returned %ld after %.2fs\n", r, dt);

    ck("NET-3 a receive timeout ends fd_read_full instead of being retried", r < 0);
    ck("NET-3 it waits for the deadline rather than failing instantly", dt > 0.5);
    ck("NET-3 and it does not overshoot it", dt < 5.0);

    close(sv[0]); close(sv[1]); close(sv2[0]); close(sv2[1]);
    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
