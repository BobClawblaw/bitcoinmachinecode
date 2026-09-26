/* test_pass_silence_strike.c -- a failing sync pass is not a strike against
 * the peer when the whole host heard nothing during it.
 *
 * 2026-09-26 06:24 UTC: a 3-minute outage (no packet of any kind in or out,
 * LAN included) made every leg's pass fail "where=3 in 24.1s", and after
 * three such passes pass_fail_bookkeeping closed five legs that had been up
 * for over an hour as sync-failed-3x -- and noted each in the dial memory as
 * an early drop. 21% of the sync-failed-3x closes since 09-11 came in such
 * clusters. Core keeps a peer through that (a 20-minute ping timeout).
 *
 * The rule: a failure counts only if some leg -- the failing one included --
 * received data during the pass, or if the failing leg is the only leg.
 * "Received" is the kernel's tcpi_last_data_recv, so the legs here are real
 * loopback TCP connections; PASS_SILENCE_SLACK_MS is 0 so the window is the
 * pass's own duration.
 *
 * pass_fail_bookkeeping lives beside main(), so this includes that TU
 * (renaming its main), as tests/test_dial_budget.c does.
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define PASS_SILENCE_SLACK_MS 0
#define main daemon_main_disabled
#include "../daemon/main.c"
#undef main
#include "test_tmpdir.h"

static int fails = 0, checks = 0;
static void ck(const char* w, int c){ checks++; if (c) printf("ok  : %s\n", w); else { printf("FAIL: %s\n", w); fails++; } }

static int g_lfd;
static unsigned short g_port;
/* one loopback TCP connection: *cli is the leg's socket, *srv the "peer" */
static void tcp_pair(int* cli, int* srv){
    *cli = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = htons(g_port);
    if (connect(*cli, (struct sockaddr*)&a, sizeof a) != 0){ perror("connect"); exit(2); }
    *srv = accept(g_lfd, NULL, NULL);
    if (*srv < 0){ perror("accept"); exit(2); }
}
static void nap_ms(long ms){ struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L }; nanosleep(&ts, NULL); }

static int srv_fd[MUX_MAX_OUT];
static void leg_open(int k, const char* host){
    int c, s; tcp_pair(&c, &s);
    mux_out_fd[k] = c; srv_fd[k] = s;
    snprintf(mux_out_host[k], sizeof mux_out_host[k], "%s", host);
    mux_out_since[k] = (long long)time(NULL) - 4000;   /* up for over an hour */
    g_sync_fail_streak[k] = 0;
}
static void leg_shut(int k){
    if (mux_out_fd[k] >= 0) close(mux_out_fd[k]);
    if (srv_fd[k] >= 0) close(srv_fd[k]);
    mux_out_fd[k] = -1; srv_fd[k] = -1;
}
/* three failing passes of 0.3 s each on leg 0 ("where=3") */
static void three_failing_passes(void){
    for (int n = 0; n < 3; n++) pass_fail_bookkeeping(0, 0, 3, 0.3);
}

int main(void){
    setvbuf(stdout, NULL, _IONBF, 0);
    tt_isolate();
    for (int k = 0; k < MUX_MAX_OUT; k++){ mux_out_fd[k] = -1; srv_fd[k] = -1; }
    g_lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
    if (bind(g_lfd, (struct sockaddr*)&a, sizeof a) != 0 || listen(g_lfd, 16) != 0){ perror("listen"); return 2; }
    socklen_t al = sizeof a; getsockname(g_lfd, (struct sockaddr*)&a, &al); g_port = ntohs(a.sin_port);

    /* ---- 1. the host heard nothing: three failing passes are not strikes ---- */
    mux_n_out = 3;
    leg_open(0, "198.51.100.10:8333"); leg_open(1, "198.51.100.11:8333"); leg_open(2, "198.51.100.12:8333");
    nap_ms(800);                                    /* nothing received on any leg for 0.8 s > the 0.3 s pass */
    three_failing_passes();
    ck("host-wide silence: the leg is kept after three failing passes", mux_out_fd[0] >= 0);
    ck("...and none of them was counted", g_sync_fail_streak[0] == 0);

    /* ---- 2. another leg heard data: the silence is this peer's, strikes count ---- */
    if (write(srv_fd[1], "x", 1) != 1){ perror("write"); return 2; }
    nap_ms(20);
    three_failing_passes();
    ck("another leg received data during the passes: three strikes close the leg", mux_out_fd[0] < 0);
    leg_shut(0);

    /* ---- 3. the failing leg itself received chatter: the network is up, strikes count ---- */
    leg_open(0, "198.51.100.13:8333");
    nap_ms(800);                                    /* legs 1 and 2 silent again */
    for (int n = 0; n < 3; n++){
        if (write(srv_fd[0], "y", 1) != 1){ perror("write"); return 2; }
        nap_ms(20);
        pass_fail_bookkeeping(0, 0, 3, 0.3);
    }
    ck("the failing leg's own chatter proves the network: three strikes close it", mux_out_fd[0] < 0);
    leg_shut(0);

    /* ---- 4. the only leg: silence proves nothing, strikes count as before ---- */
    leg_shut(1); leg_shut(2);
    leg_open(0, "198.51.100.14:8333");
    nap_ms(800);
    three_failing_passes();
    ck("a lone leg: three failing passes close it, as before", mux_out_fd[0] < 0);
    leg_shut(0);

    /* ---- 5. a pass that succeeds still clears the streak ---- */
    mux_n_out = 2;
    leg_open(0, "198.51.100.15:8333"); leg_open(1, "198.51.100.16:8333");
    if (write(srv_fd[1], "z", 1) != 1){ perror("write"); return 2; }
    nap_ms(20);
    pass_fail_bookkeeping(0, 0, 3, 0.3); pass_fail_bookkeeping(0, 0, 3, 0.3);
    ck("two counted failures", g_sync_fail_streak[0] == 2);
    pass_fail_bookkeeping(0, 1, 0, 0.3);
    ck("a good pass resets the streak", g_sync_fail_streak[0] == 0);
    leg_shut(0); leg_shut(1);

    close(g_lfd);
    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
