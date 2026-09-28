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
    /* 2026-09-24: a hole BELOW the archive tip holding the apply (testnet4 node
     * B: applied 153,876, heights 153,877-8 blanked by a boot repair, archive
     * to 153,885, peers announcing 153,885). The far-behind rule alone never
     * fires there; the worker treats this as a trigger. */
    ok( dl_hole_blocks_apply(153885, 153877, 153876),    "applied 153,876, hole at 153,877 under a 153,885 tip: the hole holds the apply");
    ok(!dl_should_parallel_fetch(153885, 153885, dl_apply_backlog(153885, 153877, 153876), 5000, 0), "...and the far-behind rule alone does NOT fire (the node sat there an hour)");
    ok( dl_should_parallel_fetch(153885, 153885+DL_PARALLEL_GAP, dl_apply_backlog(153885, 153877, 153876), 5000, 0), "...the worker's hole trigger (best = tip + gap) does");
    ok(!dl_hole_blocks_apply(153885, 153880, 153876),    "the apply is below the hole (still connecting): not held by it");
    ok(!dl_hole_blocks_apply(153885, -1, 153885),        "no hole: nothing");
    ok(!dl_hole_blocks_apply(153885, 153886, 153885),    "the first 'hole' is just past the tip: the ordinary tip, not a hole below it");
    ok(!dl_hole_blocks_apply(153885, 153877, -1),        "no engine (applied -1): nothing");
    printf("== #304: who is believed (2026-09-28) ==\n");
    /* the cluster: two Knots peers claiming 974,088 on a 968,553 chain; the
     * honest peers claim the tip. The second-highest rule alone fires. */
    { long hs[4] = { 974088, 974088, 968553, 968554 };
      ok( dl_trigger_height(hs, 4) == 974088, "two agreeing false claims pass the second-highest rule (the #304 runs)"); }
    ok(!dl_claim_memo_active("203.0.113.7:8333", 1000), "an unknown host is believed");
    dl_claim_memo_note("203.0.113.7:8333", 974088, 1000);
    ok( dl_claim_memo_active("203.0.113.7:8333", 1001), "a host whose claim came to nothing is remembered");
    ok( dl_claim_memo_active("203.0.113.7:8333", 1000 + DL_CLAIM_MEMO_S - 1), "...for DL_CLAIM_MEMO_S");
    ok(!dl_claim_memo_active("203.0.113.7:8333", 1000 + DL_CLAIM_MEMO_S), "...and then believed again");
    ok(!dl_claim_memo_active("203.0.113.8:8333", 1001), "another host is unaffected");
    dl_claim_memo_note("203.0.113.7:8333", 974120, 5000);
    ok( dl_claim_memo_active("203.0.113.7:8333", 5000 + DL_CLAIM_MEMO_S - 1), "a repeat note extends the same entry");
    for(int k = 0; k < DL_CLAIM_MEMO + 5; k++){ char h[64]; snprintf(h, sizeof h, "198.51.100.%d:8333", k); dl_claim_memo_note(h, 974000 + k, 6000); }
    ok( dl_claim_memo_active("198.51.100.36:8333", 6001), "the table wraps: the newest entries are kept");
    ok(!dl_claim_memo_active("203.0.113.7:8333", 6001), "...and the oldest was evicted");
    /* the leg-level rule: a failing pass or a remembered host takes the vote away */
    mux_n_out = 2;
    snprintf(mux_out_host[0], sizeof mux_out_host[0], "%s", "198.51.100.36:8333"); g_sync_fail_streak[0] = 0;
    snprintf(mux_out_host[1], sizeof mux_out_host[1], "%s", "192.0.2.1:8333");     g_sync_fail_streak[1] = 0;
    ok(!dl_claim_believed(0, 6001), "a remembered host's leg does not vote");
    ok( dl_claim_believed(1, 6001), "a clean leg votes");
    g_sync_fail_streak[1] = 1;
    ok(!dl_claim_believed(1, 6001), "a leg whose sync pass is failing does not vote (its headers do not connect)");
    g_sync_fail_streak[1] = 0;
    ok( dl_claim_believed(1, 6001), "...and votes again once a pass succeeds");
    printf("== the reorg probe's rejection memo (2026-09-28) ==\n");
    ok(!probe_memo_active("108.233.254.177:8333", 7000), "a host never probed is due");
    probe_memo_note("108.233.254.177:8333", 7000);
    ok( probe_memo_active("108.233.254.177:8333", 7001), "a host whose probe rejected a candidate is not probed again");
    ok( probe_memo_active("108.233.254.177:8333", 7000 + PROBE_REJECT_MEMO_S - 1), "...for PROBE_REJECT_MEMO_S");
    ok(!probe_memo_active("108.233.254.177:8333", 7000 + PROBE_REJECT_MEMO_S), "...and is due again after it");
    ok(!probe_memo_active("108.53.180.124:8333", 7001), "another host is due meanwhile");
    ok(!dl_claim_memo_active("108.233.254.177:8333", 7001), "the probe memo and the claim memo are separate tables");
    printf("\n%s (%d failure%s)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", fails, fails==1?"":"s");
    return fails ? 1 : 0;
}
