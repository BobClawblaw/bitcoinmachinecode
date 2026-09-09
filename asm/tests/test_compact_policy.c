/* tests/test_compact_policy.c -- a background merge waits while the apply is behind the download (daemon/utxo_live_compact_policy.h) */
#include <stdio.h>
#include "../daemon/utxo_live_compact_policy.h"
static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
int main(void){
    ck("the apply keeping up (lag 0): merge now", compact_should_defer(0, 48, 48, 0) == 0);
    ck("lag 255: merge now", compact_should_defer(255, 48, 48, 0) == 0);
    ck("lag 256 with the run count at the threshold: wait", compact_should_defer(256, 48, 48, 0) == 1);
    ck("lag 969 (run 19's worst hour) with 60 runs: wait", compact_should_defer(969, 60, 48, 0) == 1);
    ck("lag 969 but the run count at twice the threshold: merge (lookups scan every run; the manifest has a cap)", compact_should_defer(969, 96, 48, 0) == 0);
    ck("lag 969 but the run files over the memory budget: merge", compact_should_defer(969, 48, 48, 1) == 0);
    ck("steady-state threshold 12: wait at 12, merge at 24", compact_should_defer(500, 12, 12, 0) == 1 && compact_should_defer(500, 24, 12, 0) == 0);
    printf("%s (%d failure(s))\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
