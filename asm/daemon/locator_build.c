/* daemon/locator_build.c -- Stage A reorg/fork-choice primitive #2 (real
 * multi-hash block locator). 100% AI-generated, plain C, no libc surprises.
 *
 * STANDALONE / ADDITIVE: nothing in the live daemon calls this yet. It is
 * exercised only by tests/test_locator.c. daemon/main.c's own
 * anchor_locator/mux_locator (single-hash-only locator, the one the live
 * sync loop actually uses today) are left completely untouched -- wiring a
 * real multi-hash locator into that loop is a later, separately reviewed
 * stage. This file only borrows their read-the-hash-straight-from-
 * index.dat technique (see anchor_locator's own header comment for why:
 * node_serve_block on a just-appended tip can transiently return a short
 * read, whereas index.dat's positional record is always consistently
 * readable once store_append's single 48-byte write has landed).
 *
 * locator_build walks ancestor heights tip, tip-1, tip-2, tip-4, tip-8,
 * tip-16, ... (gap sequence 1,1,2,4,8,16,32,... -- the gap stays 1 for the
 * first two steps, then doubles every step after that) down to height 0,
 * reading each ancestor's block hash directly out of index.dat by
 * position (height*48, first 32 bytes) -- O(1) per hash, no tree walk,
 * since height is positional in this store's index.
 *
 * store_buf layout assumed here (mirrors bitcoin_store.asm's own header
 * comment and daemon/main.c's anchor_locator, which reads the identical
 * two fields the identical way):
 *   +8  idx_fd       (open fd of index.dat)
 *   +24 tip_height   (int, -1 when the store is empty)
 * Each index.dat record is 48 bytes; the block hash is its first 32 bytes,
 * in the same byte order block_hash()/store_append use internally (no
 * reversal anywhere in this file).
 */
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>

typedef unsigned char u8;

/* Bitcoin Core's own real locator caps around this size; the doubling-gap
 * construction below reaches genesis from any realistic chain height (even
 * billions of blocks) in well under 32 steps, so this is a generous, safe
 * ceiling rather than a tight one. */
#define LOCATOR_MAX 32

/* locator_build(store_buf, out_hashes[LOCATOR_MAX*32])
 *   -> number of hashes written (>=1 for any non-empty store; a
 *      single-block/genesis-only store still yields exactly 1: height 0),
 *      0 for a completely empty store (tip_height==-1), or -1 on a read
 *      error (a hole in index.dat -- should not happen for a consistent
 *      store, surfaced rather than silently truncating the locator). */
long locator_build(void* store_buf, u8 out_hashes[LOCATOR_MAX*32]) {
    int idx_fd = *(int*)((char*)store_buf + 8);
    int tip    = *(int*)((char*)store_buf + 24);
    if (tip < 0) return 0;

    long n = 0;
    long height = (long)tip;
    long step = 1;
    long transitions = 0;

    while (n < LOCATOR_MAX) {
        off_t off = (off_t)height * 48;
        long r = pread(idx_fd, out_hashes + n*32, 32, off);
        if (r != 32) return -1;
        n++;
        if (height == 0) break;

        long gap = step;
        long next = height - gap;
        transitions++;
        if (transitions >= 2) step *= 2;
        if (next < 0) next = 0;
        height = next;
    }
    return n;
}
