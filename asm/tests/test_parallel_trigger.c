/* When does the running download worker hand a far-behind archive to the
 * parallel downloader instead of its serial legs? The decision is pure, so it
 * is pinned here without a network. (dl_should_parallel_fetch is static in
 * daemon/main.c; include the TU, as test_dial_budget does.) */
#include <stdio.h>
#define main daemon_main_disabled
#include "../daemon/main.c"
#undef main
static int fails = 0;
static void ok(int c, const char* w){ printf("  %s %s\n", c?"ok ":"FAIL", w); if(!c) fails++; }
int main(void){
    printf("== fires when far behind and not apply-bound ==\n");
    ok( dl_should_parallel_fetch(1000, 320000, 0, 5000, 0),      "300k behind, no backlog, never run: fires");
    ok( dl_should_parallel_fetch(1000, 1000+DL_PARALLEL_GAP, 0, 5000, 0), "exactly DL_PARALLEL_GAP behind: fires");
    /* 2026-09-08, the first continuity test: the backlog is what the connect
     * can apply, up to the first hole -- not archive tip minus applied */
    ok( dl_apply_backlog(136161, 135639, 135638) == 0,   "applied 135,638, hole at 135,639, archive to 136,161: backlog 0 (the connect is stuck on the hole)");
    ok( dl_apply_backlog(136161, -1, 135638) == 523,     "same, no hole: backlog 523 (the whole prefix is applicable)");
    ok( dl_apply_backlog(1000, 900, 100) == 799,         "hole at 900: backlog counts 101..899 only");
    ok( dl_should_parallel_fetch(136161, 966009, dl_apply_backlog(136161, 135639, 135638), 5000, 0), "...so the trigger FIRES on the restart that deadlocked (run 17b)");
    ok(!dl_should_parallel_fetch(1000, 1000+DL_PARALLEL_GAP-1, 0, 5000, 0), "one block under the gap: does not");
    printf("== stays out of the way ==\n");
    ok(!dl_should_parallel_fetch(1000, 320000, DL_APPLY_FIRST_BACKLOG+1, 5000, 0), "apply-bound (backlog over the apply-first line): downloading more is pointless");
    ok(!dl_should_parallel_fetch(319990, 320000, 0, 5000, 0),   "at the tip: never");
    ok(!dl_should_parallel_fetch(1000, 0, 0, 5000, 0),          "no peer has announced a height yet");
    ok(!dl_should_parallel_fetch(-1, 320000, 0, 5000, 0),       "no archive tip yet");
    printf("== re-arm ==\n");
    ok(!dl_should_parallel_fetch(1000, 320000, 0, 5000, 5000-DL_PARALLEL_REARM_S+1), "ran just under the re-arm interval ago: waits");
    ok( dl_should_parallel_fetch(1000, 320000, 0, 5000, 5000-DL_PARALLEL_REARM_S),   "ran exactly the interval ago: fires again");
    printf("\n%s (%d failure%s)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", fails, fails==1?"":"s");
    return fails ? 1 : 0;
}
