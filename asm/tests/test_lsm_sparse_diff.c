/* tests/test_lsm_sparse_diff.c -- PERF_SCOPE.md 4.1, sparse-index coverage.
 *
 * tests/test_lsm_mmap_diff.c uses fill_threshold=1 so it can control
 * manifest_n exactly. That gives runs of ONE record each -- and SPARSE_STRIDE
 * is 256, so those runs carry no sparse index at all. The C fast path's
 * sparse binary search (asm/utxo_lsm_mm.c) was therefore never executed by
 * that test, while every production run holds millions of records and always
 * has one.
 *
 * This test closes that hole: fill_threshold is large enough that each run
 * holds thousands of records and sparse_n is comfortably > 1, then every
 * lookup is answered twice -- once through the mmap fast path, once forced
 * through the assembly -- and the full result tuple must match.
 *
 * Capacity invariant (bitcoin_utxo_lsm.asm:114):
 *     desc_cap = (scratch_cap - BLOOM_MAX_BYTES - SCRIPT_MAX_BYTES) / 128
 *     desc_cap >= fill_threshold + tomb_cap
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "test_tmpdir.h"

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
                          const unsigned char** script, unsigned long* slen);
extern void utxo_lsm_close(void* lst);
extern long utxo_lsm_compact(void* lst);
extern long utxo_lsm_reload(void* lst, void* u);
extern void lsm_mm_set_enabled(int on);

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
#define SLOTS          16384
#define BLOB           (16u<<20)
#define TOMB_CAP       512
#define MANIFEST_CAP   512
#define DESC_CAP       8192                      /* >= FILL + TOMB_CAP */
#define SCRATCH_CAP    ((unsigned long long)DESC_CAP*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES)

#define FILL           3000u                     /* records per run -> sparse_n ~ 11 */
#define NKEYS          12000u                    /* -> ~4 runs */

static int fails = 0;
static void ck(const char* l, long g, long e) {
    if (g == e) printf("ok  : %-46s (got %ld)\n", l, g);
    else { printf("FAIL: %-46s (got %ld exp %ld)\n", l, g, e); fails++; }
}

static void make_txid(unsigned char* t, unsigned i) {
    for (int j = 0; j < 32; j++) t[j] = (unsigned char)(0x40 + j);
    t[0] = (unsigned char)(i & 0xff);
    t[1] = (unsigned char)((i >> 8) & 0xff);
    t[2] = (unsigned char)((i >> 16) & 0xff);
}

typedef struct {
    long r; unsigned long long v; unsigned long h, cb; unsigned slen;
    unsigned char script[80];
} res_t;

static void do_get(struct LST* lst, void* u, unsigned i, res_t* out) {
    unsigned char t[32]; make_txid(t, i);
    const unsigned char* sp = NULL; unsigned long sl = 0;
    unsigned long long v = 0; unsigned long h = 0, cb = 0;
    memset(out, 0, sizeof *out);
    out->r = utxo_lsm_get(lst, u, t, i & 3, &v, &h, &cb, &sp, &sl);
    out->v = v; out->h = h; out->cb = cb; out->slen = sl;
    if (out->r == 1 && sl && sl <= sizeof out->script) memcpy(out->script, sp, sl);
}

static int res_eq(const res_t* a, const res_t* b) {
    if (a->r != b->r || a->v != b->v || a->h != b->h || a->cb != b->cb || a->slen != b->slen)
        return 0;
    if (a->r == 1 && a->slen && a->slen <= sizeof a->script)
        return memcmp(a->script, b->script, a->slen) == 0;
    return 1;
}

int main(void) {
    tt_isolate();
    void* tomb     = malloc((size_t)TOMB_CAP*36);
    void* manifest = malloc((size_t)MANIFEST_CAP*16);
    void* scratch  = malloc(SCRATCH_CAP);
    void* ublob    = malloc(BLOB);
    void* u        = malloc(utxo_struct_size(SLOTS));
    if (!tomb || !manifest || !scratch || !ublob || !u) { printf("FAIL alloc\n"); return 1; }
    utxo_init(u, SLOTS, ublob, BLOB);

    struct LST lst;
    memset(&lst, 0, sizeof lst);
    lst.op_threshold   = 100000000ULL;     /* let fill_threshold drive flushes */
    lst.fill_threshold = FILL;
    lst.tomb_buf = tomb; lst.tomb_cap = TOMB_CAP;
    lst.manifest_buf = manifest; lst.manifest_cap = MANIFEST_CAP;
    lst.scratch_buf = scratch; lst.scratch_cap = SCRATCH_CAP;
    ck("lsm_init", utxo_lsm_init(&lst), 1);

    unsigned char script[48];
    for (int j = 0; j < 48; j++) script[j] = (unsigned char)(0x80 + j);

    /* Phase 1: NKEYS puts -> several large runs, each with a sparse index. */
    for (unsigned i = 0; i < NKEYS; i++) {
        unsigned char t[32]; make_txid(t, i);
        if (utxo_lsm_put(&lst, u, t, i & 3, 1000ULL + i, 10 + i, i & 1, script, 20 + (i % 20)) < 0) {
            printf("FAIL put %u\n", i); return 1;
        }
    }
    /* Phase 2: overwrite the first quarter -- stale copies stay in older runs. */
    for (unsigned i = 0; i < NKEYS/4; i++) {
        unsigned char t[32]; make_txid(t, i);
        if (utxo_lsm_put(&lst, u, t, i & 3, 999000ULL + i, 900 + i, (i+1) & 1, script, 33) < 0) {
            printf("FAIL overwrite %u\n", i); return 1;
        }
    }
    /* Phase 3: tombstone a band. */
    for (unsigned i = NKEYS/2; i < NKEYS/2 + 300; i++) {
        unsigned char t[32]; make_txid(t, i);
        if (utxo_lsm_del(&lst, u, t, i & 3) < 0) { printf("FAIL del %u\n", i); return 1; }
    }

    printf("      manifest_n=%llu next_run_no=%llu (runs of ~%u recs -> sparse index populated)\n",
           (unsigned long long)lst.manifest_n, (unsigned long long)lst.next_run_no, FILL);
    ck("manifest_n > 0 (runs on disk)", lst.manifest_n > 0, 1);

    /* ---- differential: every key, fast path vs asm path ---- */
    unsigned mismatch = 0, checked = 0, first_bad = 0;
    res_t a, b;
    for (unsigned i = 0; i < NKEYS + 500; i++) {   /* +500 -> absent keys too */
        lsm_mm_set_enabled(1); do_get(&lst, u, i, &a);
        lsm_mm_set_enabled(0); do_get(&lst, u, i, &b);
        checked++;
        if (!res_eq(&a, &b)) {
            if (!mismatch) {
                first_bad = i;
                printf("  MISMATCH key=%u  mmap{r=%ld v=%llu h=%lu cb=%lu sl=%u}  asm{r=%ld v=%llu h=%lu cb=%lu sl=%u}\n",
                       i, a.r, a.v, a.h, a.cb, a.slen, b.r, b.v, b.h, b.cb, b.slen);
            }
            mismatch++;
        }
    }
    lsm_mm_set_enabled(1);
    printf("      compared %u keys, %u mismatches%s\n", checked, mismatch,
           mismatch ? "" : " (fast path == asm path)");
    ck("mmap fast path matches asm on large/sparse runs", mismatch, 0);
    (void)first_bad;

    /* ---- Phase 4: COMPACTION-created runs.
     * Everything above was written by mac_flush. Production is dominated by
     * runs written by utxo_lsm_compact, which is a different writer -- and
     * nothing had ever diffed the fast path against one. */
    ck("compact", utxo_lsm_compact(&lst) >= 0, 1);
    printf("      after compact: manifest_n=%llu next_run_no=%llu\n",
           (unsigned long long)lst.manifest_n, (unsigned long long)lst.next_run_no);
    mismatch = checked = 0;
    for (unsigned i = 0; i < NKEYS + 500; i++) {
        lsm_mm_set_enabled(1); do_get(&lst, u, i, &a);
        lsm_mm_set_enabled(0); do_get(&lst, u, i, &b);
        checked++;
        if (!res_eq(&a, &b)) {
            if (!mismatch)
                printf("  MISMATCH(compacted) key=%u  mmap{r=%ld v=%llu h=%lu cb=%lu sl=%u}  asm{r=%ld v=%llu h=%lu cb=%lu sl=%u}\n",
                       i, a.r, a.v, a.h, a.cb, a.slen, b.r, b.v, b.h, b.cb, b.slen);
            mismatch++;
        }
    }
    lsm_mm_set_enabled(1);
    printf("      compared %u keys after compaction, %u mismatches\n", checked, mismatch);
    ck("mmap fast path matches asm on COMPACTED runs", mismatch, 0);

    /* ---- Phase 5: RELOAD -- the exact production trigger.
     * The live failure happened on a fresh process resuming from a checkpoint:
     * utxo_lsm_reload() over run files written by an earlier process, then a
     * lookup on the very next block. Nothing had diffed the fast path across
     * a reload of LARGE runs. */
    utxo_lsm_close(&lst);
    memset(&lst, 0, sizeof lst);
    lst.op_threshold   = 100000000ULL;
    lst.fill_threshold = FILL;
    lst.tomb_buf = tomb; lst.tomb_cap = TOMB_CAP;
    lst.manifest_buf = manifest; lst.manifest_cap = MANIFEST_CAP;
    lst.scratch_buf = scratch; lst.scratch_cap = SCRATCH_CAP;
    utxo_init(u, SLOTS, ublob, BLOB);
    long rr = utxo_lsm_reload(&lst, u);
    printf("      reload -> %ld  manifest_n=%llu next_run_no=%llu\n",
           rr, (unsigned long long)lst.manifest_n, (unsigned long long)lst.next_run_no);
    ck("reload succeeded", rr != -1, 1);

    mismatch = checked = 0;
    for (unsigned i = 0; i < NKEYS + 500; i++) {
        lsm_mm_set_enabled(1); do_get(&lst, u, i, &a);
        lsm_mm_set_enabled(0); do_get(&lst, u, i, &b);
        checked++;
        if (!res_eq(&a, &b)) {
            if (!mismatch)
                printf("  MISMATCH(reloaded) key=%u  mmap{r=%ld v=%llu h=%lu cb=%lu sl=%u}  asm{r=%ld v=%llu h=%lu cb=%lu sl=%u}\n",
                       i, a.r, a.v, a.h, a.cb, a.slen, b.r, b.v, b.h, b.cb, b.slen);
            mismatch++;
        }
    }
    lsm_mm_set_enabled(1);
    printf("      compared %u keys after reload, %u mismatches\n", checked, mismatch);
    ck("mmap fast path matches asm after RELOAD", mismatch, 0);

    utxo_lsm_close(&lst);
    if (fails) { printf("\nTESTS FAILED (%d failures)\n", fails); return 1; }
    printf("\nALL TESTS PASSED (0 failures)\n");
    return 0;
}
