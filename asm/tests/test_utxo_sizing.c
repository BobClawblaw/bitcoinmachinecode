/* tests/test_utxo_sizing.c -- the memtable sizing decision (daemon/utxo_live_sizing.h):
 * a fresh datadir takes the dbcache-sized bulk memtable; a far-behind restart
 * too; a steady-state restart at the tip does not. */
#include <stdio.h>
#include "../daemon/utxo_live_sizing.h"
static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
int main(void){
    ck("a fresh datadir (applied -1, tip 0, gap 1) is BULK -- run 19's case", utxo_live_pick_bulk(-1, 0, 50000) == 1);
    ck("a fresh datadir with an archive already downloaded is bulk too", utxo_live_pick_bulk(-1, 966181, 50000) == 1);
    ck("a restart at the tip is steady-state", utxo_live_pick_bulk(966118, 966118, 50000) == 0);
    ck("a restart 750 behind is steady-state (the WAL-tail rule covers a big tail)", utxo_live_pick_bulk(965368, 966118, 50000) == 0);
    ck("a restart 50,000 behind is bulk", utxo_live_pick_bulk(900000, 950000, 50000) == 1);
    ck("a restart 49,999 behind is not", utxo_live_pick_bulk(900001, 950000, 50000) == 0);
    ck("a reindex-chainstate boot (applied -1, tip at the chain) is bulk", utxo_live_pick_bulk(-1, 966181, 50000) == 1);
    /* issue #294 (2026-09-28): the store's shape. 17 runs of 42 GB against
     * threshold 12 and a 22 GB budget (35% of 63 GB) is bulk twice over; the
     * gap (3,345) and the WAL (0.25 GB) said steady-state on that restart. */
    unsigned long long GB = 1000000000ULL;
    ck("17 runs, 42 GB, threshold 12: bulk (the #294 restart)", utxo_live_pick_bulk_shape(17, 42*GB, 12, 22*GB) == 1);
    ck("12 runs at the threshold: bulk (a merge is due)", utxo_live_pick_bulk_shape(12, 3*GB, 12, 22*GB) == 1);
    ck("11 runs under the threshold, 3 GB: steady-state", utxo_live_pick_bulk_shape(11, 3*GB, 12, 22*GB) == 0);
    ck("4 runs but 25.7 GB over a 22 GB budget: bulk (lookups fault from disk)", utxo_live_pick_bulk_shape(4, 25700000000ULL, 12, 22*GB) == 1);
    ck("no runs: steady-state", utxo_live_pick_bulk_shape(0, 0, 12, 22*GB) == 0);
    ck("no budget known (0): only the count rule applies", utxo_live_pick_bulk_shape(3, 100*GB, 12, 0) == 0);
    ck("no threshold (0): only the bytes rule applies", utxo_live_pick_bulk_shape(30, 1*GB, 0, 22*GB) == 0);
    ck("...and the gap rule is unchanged beside it", utxo_live_pick_bulk(894135, 897480, 50000) == 0);
    printf("%s (%d failure(s))\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
