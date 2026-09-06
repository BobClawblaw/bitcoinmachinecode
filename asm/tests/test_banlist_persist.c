/* tests/test_banlist_persist.c -- the ban list survives a restart.
 *
 * The finding: this node scored misbehaviour and banned, but only in memory.
 * Every restart forgave every ban, so a peer banned for a consensus violation
 * came back the moment the node did. The behavioural-compatibility register
 * carried it as PARTIAL -- "scored ... not persisted across restart".
 *
 * Core writes <datadir>/banlist.json on every change and at shutdown, loads
 * it at startup, and sweeps entries whose ban has expired (banman.cpp). The
 * file's shape is fixed by net_types.cpp / addrdb.cpp:
 *   { "_warning_": "...", "banned_nets":
 *       [ {"address": ..., "version": 1, "ban_created": ..., "banned_until": ...} ] }
 *
 * Watched to fail first: with banlist_save() stubbed to return 0 without
 * writing, every check below that reads the file back fails.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include "banlist.h"
#include "test_tmpdir.h"

static int checks, fails;
static void ok(int c, const char* m){ checks++; if(!c) fails++; printf("  %s %s\n", c?"ok  :":"FAIL:", m); }

static char g_seen[8][64];
static long long g_until[8], g_created[8];
static int g_n;
static int sink(const char* subnet, long long until, long long created){
    if (g_n >= 8) return 0;
    snprintf(g_seen[g_n], sizeof g_seen[g_n], "%s", subnet);
    g_until[g_n] = until; g_created[g_n] = created; g_n++;
    return 1;
}
static char* slurp(const char* p, long* n){
    FILE* f = fopen(p, "rb"); if (!f) return NULL;
    static char b[1<<16]; *n = (long)fread(b, 1, sizeof b - 1, f); fclose(f); b[*n]=0; return b;
}

int main(void){
    tt_isolate();
    long long now = (long long)time(NULL);

    printf("== the finding: a ban outlives the process that made it ==\n");
    ban_entry_t e[3];
    snprintf(e[0].subnet, sizeof e[0].subnet, "1.2.3.4");        e[0].until = now + 3600; e[0].created = now;
    snprintf(e[1].subnet, sizeof e[1].subnet, "10.0.0.0/24");     e[1].until = now + 7200; e[1].created = now - 10;
    snprintf(e[2].subnet, sizeof e[2].subnet, "2001:db8::/32");   e[2].until = now + 60;   e[2].created = now - 20;
    ok(banlist_save(e, 3) == 0, "three bans are written");
    ok(access("banlist.json", F_OK) == 0, "banlist.json exists (Core's filename, in the datadir)");

    g_n = 0;
    int n = banlist_load(now, sink);
    ok(n == 3 && g_n == 3, "a fresh process loads all three back");
    { int found = 0;
      for (int i = 0; i < g_n; i++) if (!strcmp(g_seen[i], "10.0.0.0/24") && g_until[i] == now + 7200 && g_created[i] == now - 10) found = 1;
      ok(found, "the subnet, the expiry AND ban_created all round-trip"); }
    { int v6 = 0; for (int i = 0; i < g_n; i++) if (!strcmp(g_seen[i], "2001:db8::/32")) v6 = 1;
      ok(v6, "an IPv6 subnet survives too"); }

    printf("== Core's file format, key for key ==\n");
    { long len = 0; char* t = slurp("banlist.json", &len);
      ok(t && strstr(t, "\"banned_nets\""),  "the array is named banned_nets, as Core names it");
      ok(t && strstr(t, "\"address\""),      "each entry has address");
      ok(t && strstr(t, "\"banned_until\""), "each entry has banned_until");
      ok(t && strstr(t, "\"ban_created\""),  "each entry has ban_created");
      ok(t && strstr(t, "\"version\""),      "each entry carries the entry version");
      ok(t && strstr(t, "_warning_"),        "the _warning_ header Core writes is there"); }

    printf("== an expired ban is swept on load, not resurrected ==\n");
    snprintf(e[0].subnet, sizeof e[0].subnet, "5.5.5.5"); e[0].until = now - 1; e[0].created = now - 100;
    snprintf(e[1].subnet, sizeof e[1].subnet, "6.6.6.6"); e[1].until = now + 50; e[1].created = now;
    ok(banlist_save(e, 2) == 0, "one live ban and one already expired are written");
    g_n = 0; n = banlist_load(now, sink);
    ok(n == 1 && g_n == 1 && !strcmp(g_seen[0], "6.6.6.6"), "only the live one comes back");

    printf("== the empty and the missing cases ==\n");
    ok(banlist_save(e, 0) == 0, "an empty list writes cleanly");
    g_n = 0; ok(banlist_load(now, sink) == 0 && g_n == 0, "and loads as zero bans, not an error");
    unlink("banlist.json");
    g_n = 0; ok(banlist_load(now, sink) == 0, "a missing file is zero bans, NOT a failure (first boot)");

    printf("== a truncated file is refused, not half-applied ==\n");
    { FILE* f = fopen("banlist.json", "w"); fputs("{ \"banned_nets\": [ { \"address\": \"7.7.7", f); fclose(f); }
    g_n = 0; ok(banlist_load(now, sink) == -1 && g_n == 0, "a truncated banlist.json loads nothing and says so");

    printf("\n%s (%d checks, %d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", checks, fails);
    return fails?1:0;
}
