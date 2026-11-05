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
    /* plan M2 (2026-10-08): dbcache is the total. node_config maps
     * dbcache=8192 to 2^25 slots and a 6,144 MB blob; with the async flush
     * the frozen copy is a second buffer of that shape, so each gets half. */
    { int lg; unsigned long mb;
      utxo_live_bulk_split(25, 6144, 1, &lg, &mb);
      ck("dbcache=8192, async flush: 2^24 slots, 3,072 MB blob", lg == 24 && mb == 3072);
      unsigned long long one = (1ULL << lg) * 48 + 40 + ((unsigned long long)mb << 20);   /* 48-byte slots + header + blob */
      ck("...and live + frozen fit in 8,192 MB (run 41: 2 x 7.6 GB)", 2 * one <= 8192ULL << 20);
      utxo_live_bulk_split(25, 6144, 0, &lg, &mb);
      ck("inline flush (one copy): the whole dbcache, unchanged", lg == 25 && mb == 6144);
      utxo_live_bulk_split(16, 16, 1, &lg, &mb);
      ck("the floors hold: 2^16 slots and 16 MB stay", lg == 16 && mb == 16);
      utxo_live_bulk_split(17, 20, 1, &lg, &mb);
      ck("a blob halving under 16 MB stops at 16", lg == 16 && mb == 16);
      utxo_live_bulk_split(16, 8, 1, &lg, &mb);
      ck("a blob already under the floor is left alone", mb == 8); }
    printf("%s (%d failure(s))\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
