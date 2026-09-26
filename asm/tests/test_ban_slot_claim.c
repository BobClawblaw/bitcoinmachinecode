/* test_ban_slot_claim.c -- two processes banning at once must not claim the
 * same ban slot.
 *
 * The ban table lives in MAP_SHARED node status. Its writers -- ctl_ban_add,
 * reached from misbehaving() in any process, and the worker's setban --
 * scanned for a free slot (until == 0) and then wrote it, with no lock. Two
 * writers between the scan and the publish picked the SAME slot: one ban was
 * lost, or published under the other's subnet (bmc_osx note-for-x86-2 item 6,
 * unfixed on both sides). The fix takes mis_lock, the table's existing
 * cross-process lock, around the claim (ban_table_add).
 *
 * BAN_SLOT_CHOSEN is main.c's seam between the choice of a slot and its
 * write. Here it forks a second process that bans another subnet and waits
 * (up to 2 s) for it: without the lock the child claims the same free slot
 * and publishes first, and the parent then overwrites it; with the lock the
 * child waits for the parent's release and takes the next slot.
 *
 * ctl_ban_add lives beside main(), so this includes that TU (renaming its
 * main), as tests/test_dial_budget.c does.
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static void slot_hook(int slot);
#define BAN_SLOT_CHOSEN(slot) slot_hook(slot)
#define main daemon_main_disabled
#include "../daemon/main.c"
#undef main
#include "test_tmpdir.h"

static int fails = 0, checks = 0;
static void ck(const char* w, int c){ checks++; if (c) printf("ok  : %s\n", w); else { printf("FAIL: %s\n", w); fails++; } }

static int   g_armed;
static pid_t g_child;
static int   g_child_done_in_seam, g_child_status;
static long long g_until;

static void slot_hook(int slot){
    (void)slot;
    if (!g_armed) return;
    g_armed = 0;                                   /* the child inherits it disarmed */
    fflush(stdout);
    g_child = fork();
    if (g_child == 0)
        _exit(ctl_ban_add("198.51.100.0/24", g_until) == 1 ? 0 : 1);
    /* give the second writer every chance to finish inside our window */
    for (int i = 0; i < 200; i++){
        if (waitpid(g_child, &g_child_status, WNOHANG) == g_child){ g_child_done_in_seam = 1; return; }
        struct timespec ts = { 0, 10 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
}

static int count_subnet(const char* s){
    int n = 0;
    for (int i = 0; i < RPC_MAX_BANS; i++)
        if (g_node_status->bans[i].until && !strcmp((const char*)g_node_status->bans[i].subnet, s)) n++;
    return n;
}

int main(void){
    setvbuf(stdout, NULL, _IONBF, 0);
    tt_isolate();                                  /* banlist_persist writes banlist.json into the cwd */
    node_status_t* st = mmap(NULL, sizeof(node_status_t), PROT_READ|PROT_WRITE,
                             MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (st == MAP_FAILED){ printf("FAIL: mmap\n"); return 1; }
    memset(st, 0, sizeof *st);
    g_node_status = st;
    g_until = (long long)time(NULL) + 3600;

    g_armed = 1;
    ck("the first writer bans 192.0.2.0/24", ctl_ban_add("192.0.2.0/24", g_until) == 1);
    if (!g_child_done_in_seam) waitpid(g_child, &g_child_status, 0);
    ck("the second writer (another process) bans 198.51.100.0/24",
       WIFEXITED(g_child_status) && WEXITSTATUS(g_child_status) == 0);
    ck("the second writer waited for the first's claim to finish", !g_child_done_in_seam);

    ck("192.0.2.0/24 is in the table exactly once", count_subnet("192.0.2.0/24") == 1);
    ck("198.51.100.0/24 is in the table exactly once", count_subnet("198.51.100.0/24") == 1);
    ck("192.0.2.9 is banned", ctl_is_banned("192.0.2.9") == 1);
    ck("198.51.100.9 is banned", ctl_is_banned("198.51.100.9") == 1);
    ck("the lock is free afterwards", st->mis_lock == 0);

    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
