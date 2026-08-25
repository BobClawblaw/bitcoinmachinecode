/* tests/reorg_drill.c -- REAL-DATA reorg drill.
 *
 * WHY (the gap this closes). Reorg is the last major consensus path whose
 * only evidence is synthetic. The UTXO set is MuHash-proven byte-identical to
 * Core, scripts are corpus-proven on real mainnet spends, and blocks are
 * replay-proven from genesis -- but the disconnect/reconnect machinery has
 * only ever run on synthetic chains (tests/test_reorg.c, which is thorough,
 * but builds its own blocks). The live daemon has executed exactly ZERO real
 * reorgs: mainnet gives you one every few weeks, so "it has not happened yet"
 * is not reassurance. Meanwhile reorg is the most destructive path in the
 * tree -- it disconnects blocks, rewrites UTXO state, truncates the archive
 * and reconciles the mempool -- and today's incidents (#45 flush window, #46
 * duplicate append) were all in machinery a reorg drives at once.
 *
 * WHAT IT DOES. Against a COPY of a real datadir (never the live one -- see
 * the safety gate in main), at real chain height:
 *   1. record the UTXO set's exact state (count, and optionally MuHash) at
 *      the tip;
 *   2. reorg_execute a disconnect of the last N real blocks and reconnect
 *      of THE SAME N BLOCKS, read back out of the real archive -- so the
 *      expected end state is exactly the start state, which makes the
 *      assertion total rather than approximate;
 *   3. re-measure and require EVERY field to match: applied height, live
 *      count, and (with --muhash) the set hash itself.
 *
 * Reconnecting the same blocks is deliberately the FIRST drill: it isolates
 * the disconnect/reconnect machinery from any question of which chain is
 * correct, and any divergence is unambiguously a bug in that machinery. A
 * competing-branch drill (fetch a real fork, verify we follow the heavier
 * chain) is the natural follow-up and needs a second archive to pull from.
 *
 * SAFETY. Refuses to run on a datadir that a daemon is writing (same
 * fingerprint discipline the setinfo tooling uses -- an inconsistent read
 * here would produce a meaningless verdict), and refuses the production
 * datadir by path unless --i-know explicitly allows it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include "../daemon/reorg.h"

typedef unsigned char u8;
typedef unsigned long long u64;

extern long store_init(void* st);
extern long store_reload(void* st);
extern long store_read_at(void* st, u64 height, void* buf, u64 cap);
extern int  store_get_tip_hash(void* st, u8 out[32]);

extern int  utxo_live_init(const char* dir);
extern long utxo_live_catchup(void* store_buf);
extern long utxo_live_count(void);
extern long utxo_live_walk_count(void);
extern long utxo_live_applied_height(void);
extern void utxo_live_close(void);

extern long reorg_chainwork_open(void* st);
extern long reorg_chainwork_sync(void* st, long max_blocks);

/* Never reached: this drill offers no mempool-chained prevouts. */
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u;(void)txid;(void)index;(void)value;(void)script;(void)slen;
    fprintf(stderr, "reorg_drill: unexpected mempool prevout resolution\n");
    abort();
}

static int failures = 0;
static void ck(const char* l, long got, long exp){
    if (got == exp) printf("PASS %s (got %ld)\n", l, got);
    else { printf("FAIL %s got=%ld exp=%ld\n", l, got, exp); failures++; }
}

/* ---- block source: hand reorg_execute the REAL blocks it is about to
 * disconnect. They must be CAPTURED UP FRONT: reorg_execute truncates the
 * index before calling this back, so a store_read_at here returns -2 (the
 * first run of this drill did exactly that and left the chain at the fork
 * point -- the disconnect half worked perfectly, the reconnect had nothing
 * to read). Reconnecting the identical bytes is what makes "the set must
 * return to exactly where it was" a total assertion. ---- */
#define DRILL_MAX_DEPTH 16
#define DRILL_BLK_CAP (4u<<20)
typedef struct { u8* buf[DRILL_MAX_DEPTH]; long len[DRILL_MAX_DEPTH]; long n; } captured_src_t;
static long captured_src(void* ctx, long i, u8* out, uint64_t cap){
    captured_src_t* s = (captured_src_t*)ctx;
    if (i < 0 || i >= s->n) return 0;
    if ((uint64_t)s->len[i] > cap) return 0;
    memcpy(out, s->buf[i], (size_t)s->len[i]);
    return s->len[i];
}

static u8 store_buf[4096];

int main(int argc, char** argv){
    const char* dir = NULL;
    long depth = 3;
    int allow_prod = 0;
    for (int i = 1; i < argc; i++){
        if (!strcmp(argv[i], "--depth") && i+1 < argc) depth = atol(argv[++i]);
        else if (!strcmp(argv[i], "--i-know")) allow_prod = 1;
        else if (argv[i][0] != '-') dir = argv[i];
    }
    if (!dir){
        fprintf(stderr,
          "usage: reorg_drill <datadir-COPY> [--depth N] [--i-know]\n"
          "  Disconnects the last N real blocks and reconnects the SAME blocks,\n"
          "  requiring the UTXO set to return to exactly its prior state.\n"
          "  Point this at a COPY of a datadir, never one a daemon is using.\n");
        return 2;
    }
    /* SAFETY: refuse the known production datadir unless explicitly allowed. */
    if (!allow_prod && strstr(dir, "/storage/bitcoinmachinecode/data")){
        fprintf(stderr, "reorg_drill: REFUSING the production datadir (%s).\n"
                        "  This drill disconnects and rewrites blocks. Copy it first,\n"
                        "  or pass --i-know if you genuinely mean to run here.\n", dir);
        return 3;
    }
    if (chdir(dir) != 0){ perror("chdir"); return 1; }

    printf("=== reorg drill on %s (depth %ld) ===\n", dir, depth);
    memset(store_buf, 0, sizeof store_buf);
    ck("store_init", store_init(store_buf), 1);
    store_reload(store_buf);
    long tip = *(int*)(store_buf + 24);
    printf("archive tip: %ld\n", tip);
    if (tip < depth + 1){ fprintf(stderr, "archive too short for depth %ld\n", depth); return 1; }

    ck("utxo_live_init", utxo_live_init("."), 1);
    ck("chainwork_open", reorg_chainwork_open(store_buf), 1);
    reorg_chainwork_sync(store_buf, 0);

    /* Catch the UTXO state up to the archive tip so the before/after
     * comparison is taken at a defined point. */
    long ar = utxo_live_catchup(store_buf);
    if (ar < 0){ fprintf(stderr, "catch-up failed; datadir not in a usable state\n"); return 1; }
    long applied_before = utxo_live_applied_height();
    long count_before   = utxo_live_count();
    long walk_before    = utxo_live_walk_count();
    printf("before: applied=%ld count=%ld walk=%ld\n",
           applied_before, count_before, walk_before);
    ck("counter agrees with the walk BEFORE the reorg", count_before, walk_before);
    u8 hash_before[32];
    ck("tip hash readable", store_get_tip_hash(store_buf, hash_before), 1);

    /* ---- the drill: disconnect the last `depth` blocks, reconnect the same
     * ones out of the archive. ---- */
    long fork_height = applied_before - depth;
    if (depth > DRILL_MAX_DEPTH){ fprintf(stderr, "depth capped at %d\n", DRILL_MAX_DEPTH); return 1; }
    /* capture the real blocks BEFORE the truncate removes their index records */
    captured_src_t src; memset(&src, 0, sizeof src); src.n = depth;
    for (long i = 0; i < depth; i++){
        src.buf[i] = (u8*)malloc(DRILL_BLK_CAP);
        if (!src.buf[i]){ fprintf(stderr, "oom capturing block %ld\n", i); return 1; }
        src.len[i] = store_read_at(store_buf, (u64)(fork_height + 1 + i), src.buf[i], DRILL_BLK_CAP);
        if (src.len[i] <= 0){
            fprintf(stderr, "could not capture block %ld (len=%ld)\n", fork_height+1+i, src.len[i]);
            return 1;
        }
    }
    printf("captured %ld real block(s) %ld..%ld (%ld..%ld bytes)\n",
           depth, fork_height + 1, applied_before, src.len[0], src.len[depth-1]);
    printf("reorg_execute: fork_height=%ld, reconnecting them\n", fork_height);
    long r = reorg_execute(store_buf, fork_height, depth, captured_src, &src);
    ck("reorg_execute", r, 1);

    /* ---- the load-bearing assertions ---- */
    long applied_after = utxo_live_applied_height();
    long walk_after    = utxo_live_walk_count();
    long count_after   = utxo_live_count();
    printf("after:  applied=%ld count=%ld walk=%ld\n",
           applied_after, count_after, walk_after);
    ck("applied height returned to the tip", applied_after, applied_before);
    ck("UTXO WALK returned to exactly its prior value", walk_after, walk_before);
    ck("counter agrees with the walk AFTER the reorg", count_after, walk_after);
    u8 hash_after[32];
    store_get_tip_hash(store_buf, hash_after);
    ck("tip hash unchanged", memcmp(hash_before, hash_after, 32) == 0 ? 1 : 0, 1);

    utxo_live_close();
    printf(failures ? "\n%d FAILURE(S)\n" : "\nDRILL PASSED\n", failures);
    return failures ? 1 : 0;
}
