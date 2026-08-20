/* tests/test_compact_manifest_order.c -- regression test for a real
 * production incident (2026-08-20): utxo_lsm_compact wrote the newly-merged
 * (OLDEST-generation) manifest entry at the HIGHEST array index instead of
 * the lowest, inverting the priority order utxo_lsm_get's scan relies on
 * (it walks the manifest from its highest index down to 0, treating the
 * highest index as "newest, check first"). A key that was live in an old,
 * now-merged run and genuinely spent afterward in a surviving newer run
 * would resolve to its STALE pre-spend value once compaction ran -- which
 * is exactly what happened live: a real historical block's signature check
 * failed against wrong (stale) prevout data.
 *
 * The bug only manifests when a compaction call has manifest_n strictly
 * greater than COMPACT_MAX_RUNS (64, bitcoin_utxo_lsm.asm's own constant)
 * at the moment it runs -- a compaction that merges EVERY existing run
 * leaves zero survivors and thus no ordering to get wrong. No other test in
 * this suite ever grows manifest_n past 64 before compacting, which is
 * exactly why this went uncaught until a real bulk replay finally ran long
 * enough (after tonight's throughput fixes) to accumulate that many runs
 * for the first time.
 *
 * Reproduction: force fill_threshold=1 so every single put/del flushes its
 * own run. PUT key A (run 1) -> 63 unrelated dummy PUTs (runs 2..64) -> DEL
 * key A (run 65, its tombstone -- deliberately OUTSIDE the first-64 batch).
 * Compact: batch_size = min(65,64) = 64, merging runs 1..64 (A's stale PUT
 * included) and leaving run 65 (A's real tombstone) as the sole survivor.
 * utxo_lsm_get(A) after compaction MUST report "not found" -- under the
 * bug it incorrectly reports A still live with its stale pre-spend value.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const unsigned char txid[32],
                          unsigned index, unsigned long long value,
                          unsigned long height, unsigned long is_coinbase,
                          const unsigned char* script, unsigned slen);
extern long utxo_lsm_del(void* lst, void* u, const unsigned char txid[32], unsigned index);
extern long utxo_lsm_get(void* lst, void* u, const unsigned char txid[32], unsigned index,
                          unsigned long long* value, unsigned long* height,
                          unsigned long* is_coinbase,
                          const unsigned char** script, unsigned* slen);
extern long utxo_lsm_compact(void* lst);
extern void utxo_lsm_close(void* lst);

/* Must mirror bitcoin_utxo_lsm.asm's state struct exactly (168 bytes) --
 * same layout tests/test_utxo_lsm.c mirrors. */
struct LST {
    long log_fd, idx_fd;
    unsigned long long log_len, ckpt_log_off, ckpt_n;
    unsigned long long op_count, op_threshold, fill_threshold;
    void* tomb_buf; unsigned long long tomb_cap, tomb_n, total_live, next_gen;
    void* manifest_buf; unsigned long long manifest_cap, manifest_n;
    void* scratch_buf; unsigned long long scratch_cap;
    unsigned long long next_run_no;
    void* tomb_hash_buf; unsigned long long tomb_hash_mask;
};

#define BLOOM_MAX_BYTES  (4*1024*1024)
#define SCRIPT_MAX_BYTES 65536

static int fails = 0;
static void ck(const char* l, long g, long e) {
    if (g == e) printf("ok  : %-52s (got %ld)\n", l, g);
    else { printf("FAIL: %-52s (got %ld exp %ld)\n", l, g, e); fails++; }
}
static void ckm(const char* l, int cond) { ck(l, cond, 1); }

static void make_txid(unsigned char* t, int seed, unsigned int i) {
    for (int j = 0; j < 32; j++) t[j] = (unsigned char)(seed + j);
    t[0] = (unsigned char)(i & 0xff);
    t[1] = (unsigned char)((i >> 8) & 0xff);
    t[2] = (unsigned char)((i >> 16) & 0xff);
}

/* fill_threshold=1: every single put/del flushes its own dedicated run,
 * giving exact, deterministic control over manifest_n. COMPACT_MAX_RUNS=64
 * (bitcoin_utxo_lsm.asm) is the number that matters here -- N_DUMMY chosen
 * so manifest_n reaches exactly 65 (one more than COMPACT_MAX_RUNS) right
 * before compaction: run 1 (key A) + N_DUMMY runs + run 65 (A's tombstone). */
#define SLOTS          64
#define BLOB           (1<<16)
#define FILL_THRESHOLD 1
#define OP_THRESHOLD   2
#define TOMB_CAP       8
#define MANIFEST_CAP   128
#define DESC_CAP       16
#define SCRATCH_CAP    ((unsigned long long)DESC_CAP*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES)
#define N_DUMMY        63   /* runs 2..64 */

int main(void) {
    char tmpl[] = "/tmp/compactorderXXXXXX";
    char* dir = mkdtemp(tmpl);
    if (!dir) { printf("FAIL mkdtemp\n"); return 1; }
    chdir(dir);

    void* tomb = malloc(TOMB_CAP*36);
    void* manifest = malloc(MANIFEST_CAP*16);
    void* scratch = malloc(SCRATCH_CAP);
    if (!tomb || !manifest || !scratch) { printf("FAIL alloc\n"); return 1; }

    struct LST lst;
    memset(&lst, 0, sizeof lst);
    lst.op_threshold = OP_THRESHOLD;
    lst.fill_threshold = FILL_THRESHOLD;
    lst.tomb_buf = tomb; lst.tomb_cap = TOMB_CAP;
    lst.manifest_buf = manifest; lst.manifest_cap = MANIFEST_CAP;
    lst.scratch_buf = scratch; lst.scratch_cap = SCRATCH_CAP;
    ck("lsm_init", utxo_lsm_init(&lst), 1);

    static unsigned char g_ux[ 40 + SLOTS*48 + 8 ];
    static unsigned char g_blob[BLOB];
    utxo_init(g_ux, SLOTS, g_blob, sizeof g_blob);

    /* run 1: key A, live, with a distinctive value we can recognize if the
     * bug resurrects it. */
    unsigned char txidA[32]; make_txid(txidA, 0xAA, 0);
    unsigned char scrA[4] = {0xAA,0xAA,0xAA,0xAA};
    ck("put A (run 1)", utxo_lsm_put(&lst, g_ux, txidA, 0, 999999ULL, 100, 0, scrA, 4), 1);
    ck("manifest_n after A's flush", (long)lst.manifest_n, 1);

    /* runs 2..64: unrelated dummy keys, each its own flush. The LAST dummy
     * (still live after compaction) doubles as a positive control -- proves
     * the merge itself preserves genuinely-live survivors, not just that it
     * happens to drop A. */
    unsigned char txidLastDummy[32]; unsigned char scrLastDummy[4];
    for (int i = 0; i < N_DUMMY; i++) {
        unsigned char txidD[32]; make_txid(txidD, 0xBB, (unsigned)i);
        unsigned char scrD[4] = { (unsigned char)i, 0xBB, 0xBB, 0xBB };
        long r = utxo_lsm_put(&lst, g_ux, txidD, 0, 1000ULL + (unsigned)i, 101, 0, scrD, 4);
        if (r != 1) { printf("FAIL: dummy put %d returned %ld\n", i, r); fails++; }
        if (i == N_DUMMY - 1) { memcpy(txidLastDummy, txidD, 32); memcpy(scrLastDummy, scrD, 4); }
    }
    ck("manifest_n after all dummy flushes", (long)lst.manifest_n, 1 + N_DUMMY);

    /* run 65: A's real spend, deliberately the run compaction will NOT
     * include in its batch (batch_size = min(65,64) = 64). del() alone
     * does NOT flush -- fill_threshold only fires on a GROWING live count,
     * and op_threshold isn't crossed by one op either, so A's tombstone
     * would otherwise just sit in the current (unflushed) generation's
     * tomb_buf -- which utxo_lsm_get's own current-generation tombstone
     * check (checked BEFORE ever reaching the disk-run scan the bug lives
     * in) would shadow correctly regardless of whether the fix is applied,
     * making the test pass for the wrong reason. One more dummy PUT right
     * after forces that flush (fill_threshold=1 fires on its own insert),
     * landing A's tombstone in an actual ON-DISK run outside the batch --
     * the real scenario the bug needs to manifest. */
    ck("del A (still just in-memory tombstone so far)", utxo_lsm_del(&lst, g_ux, txidA, 0), 1);
    unsigned char txidTrigger[32]; make_txid(txidTrigger, 0xCC, 0);
    unsigned char scrTrigger[4] = {0xCC,0xCC,0xCC,0xCC};
    ck("trigger put (forces run 65's flush, carrying A's tombstone)",
       utxo_lsm_put(&lst, g_ux, txidTrigger, 0, 42ULL, 102, 0, scrTrigger, 4), 1);
    ck("manifest_n before compact (65 > COMPACT_MAX_RUNS=64)", (long)lst.manifest_n, 2 + N_DUMMY);

    long rc = utxo_lsm_compact(&lst);
    ck("compact succeeded", rc, 1);
    printf("info: manifest_n after partial compact = %llu (batch_size=64 merged, 1 survivor expected -> 2)\n",
           (unsigned long long)lst.manifest_n);

    /* the actual regression check: A must resolve as deleted, not as its
     * stale pre-spend value from the now-merged old run. */
    unsigned long long v; unsigned long h, cb; const unsigned char* s; unsigned sl;
    long rA = utxo_lsm_get(&lst, g_ux, txidA, 0, &v, &h, &cb, &s, &sl);
    if (rA == 1) {
        printf("FAIL: key A resolved LIVE after compaction (value=%llu) -- this IS the bug: "
               "the merged (oldest) run's stale pre-spend data shadowed its real, newer tombstone\n",
               (unsigned long long)v);
        fails++;
    } else {
        ck("A correctly resolves as deleted after compaction", rA, 0);
    }

    /* positive control: a genuinely-still-live key that WAS part of the
     * merged batch must still resolve correctly. */
    unsigned long long v2; unsigned long h2, cb2; const unsigned char* s2; unsigned sl2;
    long rD = utxo_lsm_get(&lst, g_ux, txidLastDummy, 0, &v2, &h2, &cb2, &s2, &sl2);
    ck("last dummy (genuinely live, in the merged batch) still resolves", rD, 1);
    if (rD == 1) {
        ck("last dummy value intact after compaction", (long)v2, (long)(1000ULL + N_DUMMY - 1));
        ckm("last dummy script intact after compaction", sl2 == 4 && memcmp(s2, scrLastDummy, 4) == 0);
    }

    utxo_lsm_close(&lst);
    printf("\n%s (%d failures)\n", fails == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", fails);
    return fails ? 1 : 0;
}
