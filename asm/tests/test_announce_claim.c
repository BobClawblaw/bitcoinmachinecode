/* test_announce_claim.c -- an announced block's in-flight claim is taken when
 * its pass starts, never left held by a leg that was skipped.
 *
 * 2026-09-26: blocks 968,680 and 968,681 were stored 552 s and 605 s after
 * Core had them. leg_announced_pick cleared the leg's mark and claimed the
 * block the moment it picked the leg; any later check that skipped the leg
 * (the relay deferral, apply-first, a gone socket) left the claim held with no
 * pass behind it, and the claim refused the block to every other leg until
 * INFLIGHT_STALE_S (600 s). A gdb read of the stalled worker showed leg 5
 * holding 968,680's claim for 368 s with no pass running. And the relay
 * deferral came after the 30 s pass stamp, so a leg mid-relay at each of its
 * turns got no pass for minutes.
 *
 * Covered here: the pick neither claims nor clears a leg it hands back; a
 * skipped pick leaves the block free for another leg; one offer per leg per
 * rotation; an announced leg is never deferred for relay replies; a deferred
 * leg is not held to the 30 s spacing; the claim is taken at launch and
 * released when no helper starts.
 *
 * 2026-11-06: a helper that cannot start (EMFILE at its pipe) is named, not
 * only counted, and five minutes of it end the worker so the node restarts
 * (pass_start_note); the real leg_pass_start is run with the descriptor table
 * full and must fail without forking and report EMFILE.
 *
 * The relay check and the helper fork are seams (TXRELAY_REPLIES_PENDING,
 * LEG_PASS_START). These functions live beside main(), so this includes that
 * TU (renaming its main), as tests/test_dial_budget.c does.
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static int g_pending[64];                 /* relay replies pending, by fd */
static int g_start_ok = 1, g_starts, g_start_err;
static int test_pending(int fd){ return fd >= 0 && fd < 64 ? g_pending[fd] : 0; }
static int test_start(int i, unsigned b){ (void)i; (void)b; g_starts++; return g_start_ok; }
#define TXRELAY_REPLIES_PENDING(fd) test_pending(fd)
/* the stub also says why it "failed", as leg_pass_start does (0 = declined) */
#define LEG_PASS_START(i, b) (g_pass_start_errno = g_start_ok ? 0 : g_start_err, test_start(i, b))
/* With LEG_PASS_START stubbed, gcc inlines this TU differently and reports a
 * format truncation in blk_src_note (a bounded snprintf into a 64-byte field)
 * that the daemon build does not; it is silenced for this test only. */
#pragma GCC diagnostic ignored "-Wformat-truncation"
#define main daemon_main_disabled
#include "../daemon/main.c"
#undef main
/* the seam replaced the only call; keep the real one referenced */
static int (*keep_leg_pass_start)(int, unsigned) __attribute__((unused)) = leg_pass_start;
#include "test_tmpdir.h"

static int fails = 0, checks = 0;
static void ck(const char* w, int c){ checks++; if (c) printf("ok  : %s\n", w); else { printf("FAIL: %s\n", w); fails++; } }

static unsigned char H[32];
static void announce(int k){ mux_out_announced[k] = 1; memcpy(mux_out_announced_hash[k], H, 32); }
static void new_rotation(void){ memset(g_pick_tried, 0, sizeof g_pick_tried); }
static void reset(void){
    inflight_init(&g_inflight);
    memset(mux_out_announced, 0, sizeof mux_out_announced);
    memset(mux_out_lastpass_ms, 0, sizeof mux_out_lastpass_ms);
    memset(g_pending, 0, sizeof g_pending);
    new_rotation(); g_start_ok = 1; g_starts = 0; g_start_err = 0;
}
static void reset_fail_state(void){
    g_pass_fail_since_ms = 0; g_pass_fail_n = 0; g_pass_fail_logged_errno = 0;
    g_worker_fatal = 0; g_shutdown_requested = 0;
}

int main(void){
    setvbuf(stdout, NULL, _IONBF, 0);
    tt_isolate();
    for (int i = 0; i < 32; i++) H[i] = (unsigned char)(0xb0 + i);
    mux_n_out = 3;
    for (int k = 0; k < MUX_MAX_OUT; k++) mux_out_fd[k] = -1;
    mux_out_fd[0] = 10; mux_out_fd[1] = 11; mux_out_fd[2] = 12;   /* only compared, never read */

    /* ---- 1. the pick only looks ---- */
    reset(); announce(1);
    ck("the pick hands back the announced leg", leg_announced_pick(-1) == 1);
    ck("...without claiming its block", inflight_count(&g_inflight) == 0);
    ck("...and without clearing its mark", mux_out_announced[1] == 1);

    /* ---- 2. a picked leg the rotation then skips leaves the block free ---- */
    /* (leg 1 was picked above and no pass started -- the 12:33 case) */
    announce(2);
    ck("another leg that announced the same block is not refused", leg_announced_pick(-1) == 2);
    ck("...and could claim it", inflight_would_allow(&g_inflight, H, 2, (long long)time(NULL)) == 1);

    /* ---- 3. one offer per leg per rotation; the next rotation offers it again ---- */
    ck("within the rotation, no leg is offered twice", leg_announced_pick(-1) == -1);
    new_rotation();
    ck("the next rotation offers the skipped leg again", leg_announced_pick(-1) == 1);

    /* ---- 4. the gate ---- */
    reset();
    long long now = 1000000;
    g_pending[11] = 1;
    ck("an announced leg is not deferred for relay replies", leg_pass_gate(1, 1, now) == 1);
    mux_out_lastpass_ms[1] = 0;
    ck("an unannounced leg with replies pending is deferred", leg_pass_gate(1, 0, now) == 0);
    ck("...and the deferral does not stamp its 30 s spacing", mux_out_lastpass_ms[1] == 0);
    g_pending[11] = 0;
    ck("...so it passes as soon as the replies are in, not 30 s later", leg_pass_gate(1, 0, now + 500) == 1);
    ck("a pass that goes ahead stamps the spacing", mux_out_lastpass_ms[1] == now + 500);
    ck("the 30 s spacing still holds between routine passes", leg_pass_gate(1, 0, now + 1000) == 0);

    /* ---- 5. launch: the claim comes with the pass ---- */
    reset(); announce(1);
    ck("launch starts the pass", leg_pass_launch(1, 1, 60) == 1 && g_starts == 1);
    ck("...claims the announced block for that leg", inflight_count(&g_inflight) == 1 &&
                                                        inflight_would_allow(&g_inflight, H, 2, (long long)time(NULL)) == 0);
    ck("...and clears the mark", mux_out_announced[1] == 0);
    announce(2); new_rotation();
    ck("another leg announcing the block while that pass runs is refused", leg_pass_busy(2) == 0 && leg_announced_pick(-1) == -1);
    ck("...and its mark is cleared (the running pass will store it)", mux_out_announced[2] == 0);

    reset(); announce(1); g_start_ok = 0;
    long fb = g_pass_fallback;
    ck("no helper: launch reports failure", leg_pass_launch(1, 1, 60) == 0);
    ck("...and releases the claim at once", inflight_count(&g_inflight) == 0);
    ck("...keeps the mark for the next rotation", mux_out_announced[1] == 1);
    ck("...and counts the fallback", g_pass_fallback == fb + 1);
    ck("...a helper that only declined (busy, cap) is not a failure", g_pass_fail_since_ms == 0 && g_pass_fail_n == 0);

    /* ---- 6. a helper that cannot start (2026-11-06: 974,810 and ten silent hours) ---- */
    reset_fail_state();
    long long t0 = 5000000;
    ck("a declined start is not counted", pass_start_note(0, 0, t0) == 0 && g_pass_fail_since_ms == 0);
    ck("the first EMFILE starts the clock", pass_start_note(0, EMFILE, t0) == 0 && g_pass_fail_since_ms == t0 && g_pass_fail_n == 1);
    ck("...and is named", g_pass_fail_logged_errno == EMFILE);
    ck("the same errno is not named again", pass_start_note(0, EMFILE, t0 + 1000) == 0 && g_pass_fail_logged_errno == EMFILE && g_pass_fail_n == 2);
    ck("a different errno is named", pass_start_note(0, EAGAIN, t0 + 2000) == 0 && g_pass_fail_logged_errno == EAGAIN);
    ck("just short of the limit the worker carries on", pass_start_note(0, EMFILE, t0 + PASS_START_FAIL_EXIT_MS - 1) == 0);
    ck("at the limit the worker must end", pass_start_note(0, EMFILE, t0 + PASS_START_FAIL_EXIT_MS) == 1);
    ck("a start that succeeds clears the record", pass_start_note(1, 0, t0 + PASS_START_FAIL_EXIT_MS + 1) == 0 &&
                                                    g_pass_fail_since_ms == 0 && g_pass_fail_n == 0 && g_pass_fail_logged_errno == 0);
    ck("...so a later failure starts a fresh clock", pass_start_note(0, EMFILE, t0 + 2 * PASS_START_FAIL_EXIT_MS) == 0);

    /* ---- 7. launch wires the rule to the worker's shutdown ---- */
    reset(); reset_fail_state(); announce(1); g_start_ok = 0; g_start_err = EMFILE;
    ck("a failed start through launch is counted", leg_pass_launch(1, 1, 60) == 0 && g_pass_fail_n == 1 && g_pass_fail_since_ms > 0);
    ck("...and does not end the worker yet", g_worker_fatal == 0 && g_shutdown_requested == 0);
    g_pass_fail_since_ms = dh_now_ms() - PASS_START_FAIL_EXIT_MS - 1;
    ck("failures past the limit through launch", leg_pass_launch(1, 1, 60) == 0);
    ck("...request the worker's shutdown with status 1", g_worker_fatal == 1 && g_shutdown_requested == SIGTERM);
    reset(); reset_fail_state(); announce(1); g_start_ok = 0; g_start_err = EMFILE;
    (void)leg_pass_launch(1, 1, 60);
    g_start_ok = 1; g_start_err = 0;
    ck("a launch that starts clears the failure record", leg_pass_launch(1, 1, 60) == 1 && g_pass_fail_since_ms == 0 && g_worker_fatal == 0);
    reset_fail_state();

    /* ---- 8. the real leg_pass_start with the descriptor table full ---- */
    {
        struct rlimit rl; getrlimit(RLIMIT_NOFILE, &rl);
        struct rlimit low = rl; if (low.rlim_cur > 256) low.rlim_cur = 256;
        setrlimit(RLIMIT_NOFILE, &low);
        int held[300]; int nheld = 0, last_err = 0;
        while (nheld < 300){ int fd = open("/dev/null", O_RDONLY); if (fd < 0){ last_err = errno; break; } held[nheld++] = fd; }
        int ret = (last_err == EMFILE) ? leg_pass_start(0, 1) : -1;
        int err = g_pass_start_errno;
        for (int k = 0; k < nheld; k++) close(held[k]);
        setrlimit(RLIMIT_NOFILE, &rl);
        ck("the table really is full (open says EMFILE)", last_err == EMFILE);
        ck("leg_pass_start fails without forking", ret == 0 && g_pass[0].pid == 0);
        ck("...and says why: EMFILE", err == EMFILE);
    }

    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
