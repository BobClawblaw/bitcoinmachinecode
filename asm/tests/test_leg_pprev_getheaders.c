/* tests/test_leg_pprev_getheaders.c -- a new leg is asked for headers from our
 * tip's parent, as Core does, so getpeerinfo's synced_headers/synced_blocks
 * know an up-to-date peer's best block without waiting for an announcement
 * (bmc_osx ad11ac5a + 61eaa0f9, ported 2026-09-25).
 *
 * Core, once its best header is recent, sends every new peer a getheaders
 * from m_best_header->pprev "so that we get at least one header back". Ours
 * asked only from the tip, which an up-to-date peer answers with nothing:
 * production after #302 had 7 of 7 peers at -1 for 22 minutes.
 *
 * The real leg_note_installed / leg_on_headers / block_fetch_gate (main.c
 * as a TU) against a socketpair standing in for leg 0:
 *   1  tip older than maxtipage (IBD): sendheaders only, no getheaders
 *   2  recent tip: sendheaders, then getheaders with locator [block 1, block 0]
 *      -- the tip's parent first, the tip left out
 *   3  the reply read by the sweep: best_known_height = our tip (2)
 *   4  the reply read by the leg's pass instead: the fetch gate refuses the
 *      block we have and records it for g_sync_leg
 *   5  no receive side installed: nothing is sent
 * (bmc_osx carried the fix with no test of its own.) */
#include <stdio.h>
#include "test_tmpdir.h"
#define main daemon_main_disabled
#include "../daemon/main.c"
#undef main

static int fails = 0;
static void ok(int c, const char* w){ printf("  %s %s\n", c ? "ok  " : "FAIL", w); if(!c) fails++; }
static void dummy_hook(void){}

static int read_msg(int fd, char cmd[12], unsigned char* pl, unsigned cap, unsigned* plen, int ms){
    struct pollfd pf = { fd, POLLIN, 0 };
    if(poll(&pf, 1, ms) <= 0) return 0;
    return p2p_read(fd, cmd, pl, cap, plen) > 0;
}
static unsigned char blk[3][81], bh[3][32];
/* a fresh store holding three linked synthetic blocks stamped `t0`, `t0+1`, `t0+2` */
static int make_store(const char* dir, unsigned t0){
    tt_subdir(dir);
    memset(store_buf, 0, sizeof store_buf);
    if(store_init(store_buf) != 1) return 0;
    for(int h = 0; h < 3; h++){
        memset(blk[h], 0, sizeof blk[h]);
        blk[h][0] = 1;
        if(h) memcpy(blk[h] + 4, bh[h-1], 32);
        unsigned t = t0 + (unsigned)h; memcpy(blk[h] + 68, &t, 4);
        sha256d(bh[h], blk[h], 80);
        if(store_append(store_buf, bh[h], blk[h], 81) < 0) return 0;
    }
    store_reload(store_buf);
    idx_init(ht_idx, HT_SLOTS);
    for(int h = 0; h < 3; h++) idx_put(ht_idx, bh[h], h);
    return *(int*)(store_buf + 24) == 2;
}

int main(void){
    tt_isolate();
    signal(SIGPIPE, SIG_IGN);
    ht_idx = malloc(24 + (size_t)HT_SLOTS * 48 + 64);
    g_node_status = mmap(NULL, sizeof *g_node_status, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if(g_node_status == MAP_FAILED){ perror("mmap"); return 1; }
    memset((void*)g_node_status, 0, sizeof *g_node_status);
    for(int k = 0; k < MUX_MAX_OUT; k++){ mux_out_fd[k] = -1; g_node_status->peers[k].best_known_height = -1; }
    int sv[2]; if(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0){ perror("socketpair"); return 1; }
    mux_out_fd[0] = sv[0]; mux_n_out = 1; snprintf(mux_out_host[0], sizeof mux_out_host[0], "127.0.0.1:8333");
    g_cmpct_hook_cmpct = (void*)dummy_hook;              /* the receive side is installed */
    char cmd[12]; static unsigned char pl[1 << 16]; unsigned plen = 0;
    unsigned now = (unsigned)time(NULL);

    printf("== 1. tip older than maxtipage (IBD): no getheaders ==\n");
    ok(make_store("stale", 1600000000u), "fixture: a 3-block store stamped 2020");
    leg_note_installed(0);
    ok(read_msg(sv[1], cmd, pl, sizeof pl, &plen, 500) && !strcmp(cmd, "sendheaders"), "sendheaders");
    ok(!read_msg(sv[1], cmd, pl, sizeof pl, &plen, 300), "...and nothing else");

    printf("== 2. recent tip: getheaders from the tip's parent ==\n");
    ok(make_store("recent", now - 2), "fixture: a 3-block store stamped now");
    leg_note_installed(0);
    ok(read_msg(sv[1], cmd, pl, sizeof pl, &plen, 500) && !strcmp(cmd, "sendheaders"), "sendheaders first");
    int got = read_msg(sv[1], cmd, pl, sizeof pl, &plen, 500);
    ok(got && !strcmp(cmd, "getheaders"), "then a getheaders");
    ok(got && plen >= 4 + 1 + 64 + 32 && pl[4] == 2, "locator carries 2 hashes (the tip is left out)");
    ok(got && !memcmp(pl + 5, bh[1], 32), "...the first is the tip's parent, block 1");
    ok(got && !memcmp(pl + 37, bh[0], 32), "...then block 0");

    printf("== 3. the reply, read by the sweep, records the peer's best block ==\n");
    g_node_status->peers[0].best_known_height = -1;
    leg_on_headers(sv[0], blk[2], 1);                   /* headers: [block 2] -- our tip */
    ok(g_node_status->peers[0].best_known_height == 2, "best_known_height = 2 (synced_headers)");

    printf("== 4. the reply, read by the leg's pass: the fetch gate records it ==\n");
    g_node_status->peers[0].best_known_height = -1; g_sync_leg = 0;
    long fg = block_fetch_gate(bh[2]);
    ok(fg == 0, "the gate refuses a block we already have (the pass ends ok)");
    ok(g_node_status->peers[0].best_known_height == 2, "...and records it as this peer's best block");
    g_sync_leg = -1;

    printf("== 5. no receive side installed: nothing is sent ==\n");
    g_cmpct_hook_cmpct = 0;
    leg_note_installed(0);
    ok(!read_msg(sv[1], cmd, pl, sizeof pl, &plen, 300), "no sendheaders, no getheaders");

    printf("%s (%d failure(s))\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
