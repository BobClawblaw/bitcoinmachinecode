/* test_ban_expiry_race.c -- ctl_is_banned's lazy expiry must not wipe a ban
 * another process published into the same slot.
 *
 * The ban table lives in MAP_SHARED node status and every process checks it
 * (the worker before each dial and inbound accept, connection children,
 * the parent). A checker that finds an expired ban clears the slot. It used
 * to do that with a plain `until = 0` after its load, so this interleaving
 * lost a ban:
 *
 *   checker A: loads until = T0 (expired)
 *   checker B: expires the slot       -> until = 0 (the slot is free)
 *   setban:    claims the free slot, writes the subnet, publishes until = T1
 *   checker A: until = 0               -> the new ban is gone
 *
 * Not an ordering subtlety: it happens on x86 (bmc_osx 0e916bca; the osx note
 * worklog/2026-09-25-note-for-x86-2.md item 2). The fix expires by CAS from
 * the value observed. BAN_EXPIRY_OBSERVED is main.c's seam between checker
 * A's load and its store; here it runs checker B and the setban there.
 *
 * ctl_is_banned and ctl_ban_add live beside main(), so this includes that TU
 * (renaming its main), as tests/test_dial_budget.c does.
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static void ban_hook(int i);
#define BAN_EXPIRY_OBSERVED(i) ban_hook(i)
#define main daemon_main_disabled
#include "../daemon/main.c"
#undef main
#include "test_tmpdir.h"

static int fails = 0, checks = 0;
static void ck(const char* w, int c){ checks++; if (c) printf("ok  : %s\n", w); else { printf("FAIL: %s\n", w); fails++; } }

static int g_armed, g_hook_ran;
static long long g_new_until;

static void ban_hook(int i){
    if (!g_armed || i != 0) return;
    g_armed = 0;
    g_hook_ran = 1;
    g_node_status->bans[0].until = 0;                         /* checker B expires it */
    g_hook_ran += ctl_ban_add("192.0.2.0/24", g_new_until);   /* setban claims slot 0 */
}

int main(void){
    tt_isolate();                             /* banlist_persist writes banlist.json into the cwd */
    static node_status_t st;
    g_node_status = &st;
    long long now = (long long)time(NULL);

    /* ---- the plain case: an expired ban is cleared, a live one bans ---- */
    snprintf(st.bans[0].subnet, 64, "%s", "10.1.0.0/16");
    st.bans[0].until = now - 10;
    snprintf(st.bans[1].subnet, 64, "%s", "203.0.113.0/24");
    st.bans[1].until = now + 3600;
    ck("an expired ban does not ban", ctl_is_banned("10.1.2.3") == 0);
    ck("...and its slot is cleared", st.bans[0].until == 0);
    ck("a live ban bans", ctl_is_banned("203.0.113.9") == 1);

    /* ---- the race: slot 0 is re-banned between the load and the expiry ---- */
    snprintf(st.bans[0].subnet, 64, "%s", "10.1.0.0/16");
    st.bans[0].until = now - 10;
    g_new_until = now + 7200;
    g_armed = 1; g_hook_ran = 0;
    ctl_is_banned("198.51.100.1");
    ck("the seam ran, and setban took the slot checker B freed", g_hook_ran == 2);
    ck("the ban published mid-check survives the lazy expiry", st.bans[0].until == g_new_until);
    ck("...with its own subnet", strcmp(st.bans[0].subnet, "192.0.2.0/24") == 0);
    ck("...and it bans", ctl_is_banned("192.0.2.77") == 1);
    ck("the unrelated live ban is untouched", st.bans[1].until == now + 3600);

    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
