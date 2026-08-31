/* bmc.utxocompactthreshold was parsed and printed at boot ("compact_at=N") and
 * READ BY NOTHING; the compaction cadence came from a hardcoded macro. This
 * pins that the option is honoured, that bulk mode compacts 4x less often
 * (each compaction rewrites the whole live set -- 44% of wall-clock on a
 * signet bulk catch-up), and that the result stays inside the manifest cap. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "test_tmpdir.h"
#include "../daemon/node_config.h"
extern long node_config_load(const char* path);
extern long utxo_live_compact_threshold(void);
extern void utxo_live_test_set_bulk_mode(int on);

/* utxo_live.c's link set wants these; nothing here touches the mempool. */
long mempool_resolve_confirmed_utxo(void* u, const unsigned char t[32], unsigned long i,
                                    unsigned long long* v, const unsigned char** s, unsigned long* l){
    (void)u;(void)t;(void)i;(void)v;(void)s;(void)l; abort();
}

static int fails = 0;
static void ok(int c, const char* w){ printf("  %s %s\n", c?"ok ":"FAIL", w); if(!c) fails++; }
static void wr(const char* p, const char* b){ FILE* f=fopen(p,"w"); fputs(b,f); fclose(f); }

int main(void){
    tt_isolate();
    printf("== default ==\n");
    node_config_load("/nonexistent.conf");
    utxo_live_test_set_bulk_mode(0);
    ok(utxo_live_compact_threshold() == 12, "steady-state default is 12 (the old macro's value)");
    utxo_live_test_set_bulk_mode(1);
    ok(utxo_live_compact_threshold() == 48, "bulk mode compacts 4x less often: 48");

    printf("== the option is honoured (it used to be inert) ==\n");
    wr("t.conf", "bmc.utxocompactthreshold=20\n");
    node_config_load("t.conf");
    utxo_live_test_set_bulk_mode(0);
    ok(g_cfg.utxo_compact_threshold == 20, "parsed as 20");
    ok(utxo_live_compact_threshold() == 20, "and the threshold actually used is 20");
    utxo_live_test_set_bulk_mode(1);
    ok(utxo_live_compact_threshold() == 64, "20 x4 would be 80; capped at 64 in bulk (COMPACT_MAX_RUNS)");

    printf("== bounds ==\n");
    wr("t.conf", "bmc.utxocompactthreshold=100\n");
    node_config_load("t.conf");
    utxo_live_test_set_bulk_mode(1);
    ok(utxo_live_compact_threshold() == 64, "bulk x4 is capped at COMPACT_MAX_RUNS (64), the most one merge folds");
    utxo_live_test_set_bulk_mode(0);
    ok(utxo_live_compact_threshold() == 64, "and steady-state 100 is capped the same way");
    printf("\n%s (%d failure%s)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", fails, fails==1?"":"s");
    return fails ? 1 : 0;
}
