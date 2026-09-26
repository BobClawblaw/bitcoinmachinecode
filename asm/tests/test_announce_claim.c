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
 * The relay check and the helper fork are seams (TXRELAY_REPLIES_PENDING,
 * LEG_PASS_START). These functions live beside main(), so this includes that
 * TU (renaming its main), as tests/test_dial_budget.c does.
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static int g_pending[64];                 /* relay replies pending, by fd */
static int g_start_ok = 1, g_starts;
static int test_pending(int fd){ return fd >= 0 && fd < 64 ? g_pending[fd] : 0; }
static int test_start(int i, unsigned b){ (void)i; (void)b; g_starts++; return g_start_ok; }
#define TXRELAY_REPLIES_PENDING(fd) test_pending(fd)
#define LEG_PASS_START(i, b) test_start(i, b)
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
    new_rotation(); g_start_ok = 1; g_starts = 0;
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

    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
