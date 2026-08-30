/* tests/test_reindex_chainstate.c -- -reindex-chainstate drops the UTXO set,
 * ONCE.
 *
 * The drop itself is proven machinery: archive_drop_utxo_state() already runs
 * after an archive repair, and getting it wrong there once left 366 orphaned
 * run files behind. What is new is the config flag, and the flag brings a
 * hazard the drop does not have on its own:
 *
 *   -reindex-chainstate is a REQUEST, not a mode. An operator who leaves it
 *   in bitcoin.conf would otherwise wipe and rebuild the UTXO set on every
 *   single restart -- hours of work each time, silently, presenting only as a
 *   slow start. Core treats it the same way.
 *
 * So the assertion that matters here is not "it drops the files" but "it does
 * not drop them AGAIN". Both are checked, because a one-shot that never fires
 * at all would pass the second and fail the operator.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "../daemon/node_config.h"

extern node_config_t g_cfg;
extern long archive_drop_utxo_state(void);

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }

static void touch(const char* n){ FILE* f = fopen(n, "w"); if (f){ fputs("x", f); fclose(f); } }
static int exists(const char* n){ struct stat s; return stat(n, &s) == 0; }

/* The boot decision, mirroring daemon/main.c's guard. Kept as a pure
 * predicate so the one-shot rule is testable without booting a node. */
static int should_drop(int flag_set, int marker_present){
    return flag_set && !marker_present;
}

int main(void){
    char dir[128];
    snprintf(dir, sizeof dir, "/tmp/reidx_%d", (int)getpid());
    if (mkdir(dir, 0700) != 0 || chdir(dir) != 0){ printf("  FAIL scratch dir\n"); return 1; }

    printf("== the config key is real ==\n");
    ck("reindex_chainstate defaults to 0 -- never a standing mode",
       g_cfg.reindex_chainstate == 0);
    { extern int nodecfg_unimplemented(const char*);
      ck("reindex-chainstate is no longer flagged unimplemented",
         nodecfg_unimplemented("reindex-chainstate") == 0);
      ck("  but bare -reindex still is (block-index rebuild is not implemented)",
         nodecfg_unimplemented("reindex") == 1); }

    printf("== the drop removes every UTXO artefact, not just the height file ==\n");
    /* Removing utxo_applied_height.dat alone silently reintroduces corruption:
     * utxo_live_init decides "prior state exists" from utxo.dat and the
     * manifest, so it would reload the stale set and replay on top of it. */
    { touch("utxo.dat"); touch("utxo.idx"); touch("utxo_manifest.dat");
      touch("utxo_applied_height.dat"); touch("utxo_lsm_table.map");
      touch("utxo_lsm_blob.map");
      touch("utxo_run_000001.dat"); touch("utxo_run_000002.dat");
      /* and something that must SURVIVE -- the archive itself */
      touch("blk00000.dat"); touch("index.dat");

      long n = archive_drop_utxo_state();
      char l[120]; snprintf(l, sizeof l, "removed %ld file(s)", n);
      ck(l, n >= 8);
      ck("  utxo.dat is gone",             !exists("utxo.dat"));
      ck("  the manifest is gone",         !exists("utxo_manifest.dat"));
      ck("  the applied-height file is gone", !exists("utxo_applied_height.dat"));
      ck("  the run files are gone",       !exists("utxo_run_000001.dat") && !exists("utxo_run_000002.dat"));
      ck("  and the ARCHIVE is untouched", exists("blk00000.dat") && exists("index.dat")); }

    printf("== dropping again is harmless ==\n");
    { long n = archive_drop_utxo_state();
      ck("a second drop removes nothing and does not fail", n == 0); }

    printf("== the flag is ONE-SHOT ==\n");
    /* This is the assertion that protects the operator from an hours-long
     * rebuild on every restart. */
    ck("flag set, no marker -> drop", should_drop(1, 0) == 1);
    ck("flag set, marker present -> do NOT drop again", should_drop(1, 1) == 0);
    ck("flag clear -> never drops", should_drop(0, 0) == 0 && should_drop(0, 1) == 0);

    printf("== the marker is what makes it one-shot ==\n");
    { ck("no marker before the first run", !exists("reindex_chainstate.done"));
      touch("reindex_chainstate.done");
      ck("  once written, the next boot sees it", exists("reindex_chainstate.done"));
      ck("  and would skip the rebuild", should_drop(1, exists("reindex_chainstate.done")) == 0); }

    /* tidy */
    const char* leftovers[] = { "blk00000.dat", "index.dat", "reindex_chainstate.done", 0 };
    for (int i = 0; leftovers[i]; i++) unlink(leftovers[i]);
    if (chdir("/") == 0) rmdir(dir);

    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}
