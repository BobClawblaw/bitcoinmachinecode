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
    printf("%s (%d failure(s))\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
