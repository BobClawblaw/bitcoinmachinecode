/* tests/test_bip68_locks.c -- VAL-4's BIP68 arithmetic, pinned against
 * hand-computed values from Core's own formulas.
 *
 * WHY A UNIT TEST AND NOT AN END-TO-END ONE. BIP68 only applies at or after
 * CSVHeight, which on mainnet is 419,328. The block-level fixtures in this
 * suite run at height ~150, so they cannot reach the rule at all -- and
 * building a 419k-block fixture to exercise three lines of arithmetic would
 * be theatre. test_blk_dryrun pins the ACTIVATION GATE instead (below
 * CSVHeight nothing is enforced, which is the false-reject direction that
 * matters there); this file pins the arithmetic those lines perform.
 *
 * That arithmetic is the whole risk. From consensus/tx_verify.cpp:
 *     height-based  minHeight = coinHeight + (seq & 0xffff) - 1
 *     time-based    minTime   = coinMTP    + ((seq & 0xffff) << 9) - 1
 *     satisfied iff minHeight <  nBlockHeight  AND  minTime < MTP(prev)
 * The `<< 9` is BIP68's 512-second granularity; the `- 1` makes the lock
 * satisfied AT the boundary rather than one past it. Get either wrong by one
 * and the node accepts a transaction Core rejects, or rejects one Core
 * accepts -- a chain split, not a failing assertion. So the expected values
 * below are computed by hand from the BIP, not from this implementation.
 *
 * Usage: ./test_bip68_locks
 */
#include <stdio.h>

/* The arithmetic under test is header-only (static inline) so the block path
 * and the mempool path share ONE definition without a common link island --
 * see daemon/seqlocks.h. Including it is therefore the only way to reach it,
 * and it also means this test compiles standalone: no daemon objects, no
 * stub symbols, nothing that can drift from what the daemon actually runs. */
#include "../daemon/seqlocks.h"

static int fails = 0, checks = 0;
static void ck(const char* w, long long got, long long want){
    checks++;
    if (got == want) printf("ok  : %-62s (%lld)\n", w, got);
    else { printf("FAIL: %-62s got %lld want %lld\n", w, got, want); fails++; }
}

int main(void){
    /* ---- height-based: minHeight = coinHeight + n - 1 ------------------- */
    ck("relative 1 block from height 100 locks until 100",
       val_seq_min_height(100, 1), 100);
    ck("relative 10 blocks from height 100 locks until 109",
       val_seq_min_height(100, 10), 109);
    ck("relative 0 blocks is already satisfied at 99",
       val_seq_min_height(100, 0), 99);
    ck("the mask keeps only the low 16 bits (0x10000 reads as 0)",
       val_seq_min_height(100, 0x10000u), 99);
    ck("the maximum relative height, 65535, from 100",
       val_seq_min_height(100, 0xffffu), 100 + 65535 - 1);
    ck("the TYPE bit is not part of the count",
       val_seq_min_height(100, (1u<<22) | 10u), 109);

    /* ---- time-based: minTime = coinMTP + (n << 9) - 1 ------------------- */
    ck("one 512-second unit from MTP 1000000",
       val_seq_min_time(1000000, 1), 1000000 + 512 - 1);
    ck("two units is 1024 seconds",
       val_seq_min_time(1000000, 2), 1000000 + 1024 - 1);
    ck("zero units is already satisfied one second before",
       val_seq_min_time(1000000, 0), 999999);
    ck("the maximum, 65535 units = 33553920 seconds (~388 days)",
       val_seq_min_time(1000000, 0xffffu), 1000000 + 33553920 - 1);

    /* ---- the predicate: strictly less than, in BOTH dimensions ---------- */
    ck("a height lock is satisfied one block after its minimum",
       val_seq_locks_ok(149, -1, 150, 2000000), 1);
    ck("a height lock is NOT satisfied at exactly its minimum",
       val_seq_locks_ok(150, -1, 150, 2000000), 0);
    ck("nor above it",
       val_seq_locks_ok(151, -1, 150, 2000000), 0);
    ck("a time lock is satisfied one second after its minimum",
       val_seq_locks_ok(-1, 1999999, 150, 2000000), 1);
    ck("a time lock is NOT satisfied at exactly its minimum",
       val_seq_locks_ok(-1, 2000000, 150, 2000000), 0);
    ck("no locks at all (-1/-1) is always satisfied",
       val_seq_locks_ok(-1, -1, 0, 0), 1);
    ck("BOTH must hold: a satisfied height with an unsatisfied time fails",
       val_seq_locks_ok(100, 2000000, 150, 2000000), 0);
    ck("and the reverse",
       val_seq_locks_ok(150, 1000, 150, 2000000), 0);

    /* ---- the worked example from the phase's own comment ---------------- */
    /* a coinbase from height 1 spent at tip 150: 149 confirmations.
     * A 1000-block relative lock is NOT satisfied; a 10-block one is. */
    ck("v2 spend of a height-1 coin at tip 150, relative 1000: refused",
       val_seq_locks_ok(val_seq_min_height(1, 1000), -1, 150, 2000000), 0);
    ck("...and relative 10: allowed",
       val_seq_locks_ok(val_seq_min_height(1, 10), -1, 150, 2000000), 1);
    ck("...the boundary, relative 150, is exactly refused",
       val_seq_locks_ok(val_seq_min_height(1, 150), -1, 150, 2000000), 0);
    ck("...and relative 149 is exactly allowed",
       val_seq_locks_ok(val_seq_min_height(1, 149), -1, 150, 2000000), 1);

    printf("\n%s (%d checks, %d failures)\n",
           fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
