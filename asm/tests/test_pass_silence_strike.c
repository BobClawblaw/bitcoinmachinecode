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
 * The reorg probe (6.): the same outage closed three more long-lived legs as
 * probe-budget -- a probe's timeout always costs its leg (the alarm shuts the
 * socket down) -- so a probe does not start while no leg has heard anything
 * for PROBE_SILENCE_MS (300 ms here). reorg_probe_host_silent is the gate.
 *
 * 7./8. (P2P-1/2/3, audit 2026-10-23): a pass that failed on the peer's
 * misbehaviour (where=12 an invalid header, where=14 bogus compact-block
 * indexes) scores it and closes the leg at once, and a pushed cmpctblock
 * whose header has no PoW is refused, and scored, before any reconstruction.
 *
 * pass_fail_bookkeeping lives beside main(), so this includes that TU
 * (renaming its main), as tests/test_dial_budget.c does.
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define PASS_SILENCE_SLACK_MS 0
#define PROBE_SILENCE_MS 300
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

    /* ---- 6. the reorg probe's gate: no probe while the host hears nothing ---- */
    mux_n_out = 3;
    leg_open(0, "198.51.100.17:8333"); leg_open(1, "198.51.100.18:8333"); leg_open(2, "198.51.100.19:8333");
    nap_ms(800);
    ck("probe gate: every leg silent past the window -> the host is silent, no probe", reorg_probe_host_silent() == 1);
    if (write(srv_fd[2], "p", 1) != 1){ perror("write"); return 2; }
    nap_ms(20);
    ck("probe gate: one leg just received data -> the probe may run", reorg_probe_host_silent() == 0);
    leg_shut(0); leg_shut(1); leg_shut(2);
    ck("probe gate: no legs at all -> not 'silent' (nothing to judge by)", reorg_probe_host_silent() == 0);

    /* ---- 7. P2P-1/P2P-3 (2026-10-23): a pass that failed on the peer's
     * misbehaviour -- a header Core refuses (where=12) or bogus compact-block
     * indexes (where=14) -- scores the peer and closes the leg at once, as
     * Core's Misbehaving disconnects; not a strike out of three ---- */
    g_node_status = calloc(1, sizeof *g_node_status);
    if (!g_node_status){ perror("calloc"); return 2; }
    mux_n_out = 2;
    leg_open(0, "198.51.100.20:8333"); leg_open(1, "198.51.100.21:8333");
    pass_fail_bookkeeping(0, 0, 12, 0.3);
    ck("where=12 (an invalid header): ONE pass closes the leg", mux_out_fd[0] < 0);
    ck("...and the peer is scored to a ban (Core: Misbehaving)", ctl_is_banned("198.51.100.20") == 1);
    leg_shut(0);
    leg_open(0, "198.51.100.22:8333");
    pass_fail_bookkeeping(0, 0, 14, 0.3);
    ck("where=14 (an invalid compact block): ONE pass closes the leg", mux_out_fd[0] < 0);
    ck("...and the peer is scored to a ban", ctl_is_banned("198.51.100.22") == 1);
    leg_shut(0);
    /* where=11 (only blocks we did not ask for) and 13 (time-too-new) are not
     * misbehaviour: an ordinary strike, nobody scored */
    leg_open(0, "198.51.100.23:8333");
    if (write(srv_fd[1], "q", 1) != 1){ perror("write"); return 2; }
    nap_ms(20);
    pass_fail_bookkeeping(0, 0, 11, 0.3); pass_fail_bookkeeping(0, 0, 13, 0.3);
    ck("where=11 and where=13: the leg stays, two strikes", mux_out_fd[0] >= 0 && g_sync_fail_streak[0] == 2);
    ck("...and nobody is banned", ctl_is_banned("198.51.100.23") == 0);
    leg_shut(0); leg_shut(1);

    /* ---- 8. P2P-2: an unsolicited cmpctblock whose header has no PoW is
     * refused before any reconstruction, and the peer scored (Core:
     * CheckBlockHeader high-hash -> BLOCK_INVALID_HEADER -> Misbehaving) ---- */
    mux_n_out = 1;
    leg_open(0, "198.51.100.24:8333");
    { unsigned char pl[90]; memset(pl, 0, sizeof pl);
      pl[0] = 0x20;                                                  /* version */
      pl[72] = 0xff; pl[73] = 0xff; pl[74] = 0x00; pl[75] = 0x1d;    /* nBits 0x1d00ffff: difficulty 1 */
      unsigned nonce = 0;                                            /* a nonce that misses the target */
      for (;; nonce++){ memcpy(pl + 76, &nonce, 4); if (!pow_check(pl)) break; }
      unsigned long r0, n0, f0; cmpct_recv_stats(&r0, &n0, &f0);
      long rc = leg_on_cmpctblock(mux_out_fd[0], pl, sizeof pl);
      unsigned long r1, n1, f1; cmpct_recv_stats(&r1, &n1, &f1);
      ck("a high-hash compact block header: refused (-1)", rc == -1);
      ck("...before the reconstruction (nothing assembled, requested or fallen back)", r1 == r0 && n1 == n0 && f1 == f0 && !g_push_pending);
      ck("...and the peer is scored to a ban", ctl_is_banned("198.51.100.24") == 1); }
    leg_shut(0);
    free(g_node_status); g_node_status = NULL;

    close(g_lfd);
    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
