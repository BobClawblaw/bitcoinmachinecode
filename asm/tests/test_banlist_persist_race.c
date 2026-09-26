/* test_banlist_persist_race.c -- banlist.json holds every ban, whoever
 * wrote it and however the saves interleaved.
 *
 * Two defects, both found while testing the ban slot claim (#314):
 *
 *   1. Concurrent saves. banlist_persist runs in any process (misbehaving()
 *      in a serve child, the worker's setban) and every process wrote
 *      through the one temp file, BANLIST_TMP, with no lock. Two saves could
 *      fail a rename, rename a torn file into place, or -- the case driven
 *      here -- rename an OLDER snapshot last, so the newer ban was in memory
 *      but not on disk and a restart forgot it. The fix holds an flock on
 *      banlist.json.lock across the snapshot, the write and the rename.
 *
 *   2. setban never persisted. The worker's setban add path published the
 *      ban and returned; only ctl_ban_add, setban remove and clearbanned
 *      wrote the file. Core's setban writes banlist.json (banman.cpp Ban ->
 *      DumpBanlist).
 *
 * BANLIST_SNAPSHOT_TAKEN is main.c's seam between the snapshot and the save.
 * For (1) it forks a second process that bans another subnet and waits up
 * to 2 s for it: without the lock the child saves both bans and the parent
 * then renames its one-ban snapshot over them; with the lock the child waits
 * and saves last. The child closes the fds it inherited, as an unrelated
 * process would not hold the parent's lock description.
 *
 * ctl_ban_add and ctl_setban live beside main(), so this includes that TU
 * (renaming its main), as tests/test_dial_budget.c does.
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static void snapshot_hook(void);
#define BANLIST_SNAPSHOT_TAKEN() snapshot_hook()
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

static void snapshot_hook(void){
    if (!g_armed) return;
    g_armed = 0;                                   /* the child inherits it disarmed */
    fflush(stdout);
    g_child = fork();
    if (g_child == 0){
        for (int fd = 3; fd < 1024; fd++) close(fd);   /* not the parent's lock description */
        _exit(ctl_ban_add("198.51.100.0/24", g_until) == 1 ? 0 : 1);
    }
    for (int i = 0; i < 200; i++){
        if (waitpid(g_child, &g_child_status, WNOHANG) == g_child){ g_child_done_in_seam = 1; return; }
        struct timespec ts = { 0, 10 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
}

/* ---- what the file says ---- */
static char g_seen[8][64];
static int  g_nseen;
static int collect(const char* subnet, long long until, long long created){
    (void)until; (void)created;
    if (g_nseen < 8) snprintf(g_seen[g_nseen++], 64, "%s", subnet);
    return 1;
}
static int on_disk(const char* subnet){
    g_nseen = 0;
    if (banlist_load((long long)time(NULL), collect) < 0) return 0;
    for (int i = 0; i < g_nseen; i++) if (!strcmp(g_seen[i], subnet)) return 1;
    return 0;
}

int main(void){
    setvbuf(stdout, NULL, _IONBF, 0);
    tt_isolate();                                  /* banlist.json and its lock live in the cwd */
    node_status_t* st = mmap(NULL, sizeof(node_status_t), PROT_READ|PROT_WRITE,
                             MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (st == MAP_FAILED){ printf("FAIL: mmap\n"); return 1; }
    memset(st, 0, sizeof *st);
    g_node_status = st;
    g_until = (long long)time(NULL) + 3600;

    /* ---- 1. two processes saving at once ---- */
    g_armed = 1;
    ck("the first writer bans 192.0.2.0/24", ctl_ban_add("192.0.2.0/24", g_until) == 1);
    if (!g_child_done_in_seam) waitpid(g_child, &g_child_status, 0);
    ck("the second writer (another process) bans 198.51.100.0/24",
       WIFEXITED(g_child_status) && WEXITSTATUS(g_child_status) == 0);
    ck("the second writer's save waited for the first's", !g_child_done_in_seam);
    ck("both bans are in memory",
       st->bans[0].until == g_until && st->bans[1].until == g_until);
    ck("banlist.json has 192.0.2.0/24", on_disk("192.0.2.0/24"));
    ck("banlist.json has 198.51.100.0/24 (the newer snapshot was renamed last)", on_disk("198.51.100.0/24"));
    ck("no temp file is left behind", access("banlist.json.tmp", F_OK) != 0);

    /* ---- 2. setban writes the file ---- */
    char reason[128]; reason[0] = 0;
    ck("setban 203.0.113.0/24 succeeds", ctl_setban("203.0.113.0/24", g_until, reason, sizeof reason) == 1);
    ck("banlist.json has the setban", on_disk("203.0.113.0/24"));
    ck("setban remove succeeds", ctl_setban("203.0.113.0/24", 0, reason, sizeof reason) == 1);
    ck("...and banlist.json no longer has it", !on_disk("203.0.113.0/24"));

    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
