/* tests/test_lsm_mmap_diff.c -- PERF_SCOPE.md 4.1.
 *
 * The mmap-cached fast path (asm/utxo_lsm_mm.c) must be indistinguishable
 * from the assembly path it short-circuits. This is the UTXO set: a wrong
 * answer here is a consensus bug, not a performance bug.
 *
 * Every lookup below is run TWICE against the same on-disk LSM -- once with
 * the fast path enabled, once forced through the asm -- and the full result
 * tuple (return code, value, height, is_coinbase, slen, script bytes) must
 * match exactly. Coverage:
 *
 *   - present keys              (fresh and repeatedly overwritten)
 *   - absent keys               (never inserted)
 *   - tombstoned keys           (inserted then deleted)
 *   - STALE-VALUE keys          -- a key whose old value still sits in an
 *     older run while a newer run holds the current one. This is the shape
 *     that caught the 2026-08-20 manifest-order bug (e12dcbb): get the run
 *     ordering wrong and you return the stale value instead of the live one.
 *     Built here deliberately, with manifest_n driven past COMPACT_MAX_RUNS
 *     (64) so compaction leaves SURVIVORS -- the only configuration in which
 *     that class of bug is observable at all.
 *   - a concurrency pass       -- many threads hammering utxo_lsm_get while
 *     each thread's mapping cache fills from cold, every answer compared to
 *     a single-threaded reference captured beforehand.
 *
 * fill_threshold=1 (as in tests/test_compact_manifest_order.c) makes every
 * put/del flush its own run, giving exact control over manifest_n.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
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
                          const unsigned char** script, unsigned* slen);
extern long utxo_lsm_compact(void* lst);
extern void utxo_lsm_close(void* lst);
extern void lsm_mm_set_enabled(int on);
extern void lsm_mm_stats(unsigned long long*, unsigned long long*, unsigned long long*);

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
#define SLOTS          256
#define BLOB           (1<<20)
#define TOMB_CAP       512
#define MANIFEST_CAP   512
#define DESC_CAP       64
#define SCRATCH_CAP    ((unsigned long long)DESC_CAP*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES)

static int fails = 0;
static void ck(const char* l, long g, long e) {
    if (g == e) printf("ok  : %-52s (got %ld)\n", l, g);
    else { printf("FAIL: %-52s (got %ld exp %ld)\n", l, g, e); fails++; }
}

static void make_txid(unsigned char* t, unsigned i) {
    for (int j = 0; j < 32; j++) t[j] = (unsigned char)(0x40 + j);
    t[0] = (unsigned char)(i & 0xff);
    t[1] = (unsigned char)((i >> 8) & 0xff);
    t[2] = (unsigned char)((i >> 16) & 0xff);
}

typedef struct {
    long r; unsigned long long v; unsigned long h, cb; unsigned slen;
    unsigned char script[64];
} res_t;

static void do_get(struct LST* lst, void* u, unsigned i, res_t* out) {
    unsigned char t[32]; make_txid(t, i);
    const unsigned char* sp = NULL; unsigned sl = 0;
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

/* ---- concurrency pass ---- */
#define NTHREADS 8
#define NKEYS    400
static struct LST* c_lst; static void* c_u;
static res_t c_ref[NKEYS];
static int c_mismatch;

static void* hammer(void* arg) {
    long tid = (long)arg;
    for (int pass = 0; pass < 12; pass++) {
        for (int i = 0; i < NKEYS; i++) {
            int k = (i * 7 + (int)tid * 13 + pass) % NKEYS;
            res_t got; do_get(c_lst, c_u, (unsigned)k, &got);
            if (!res_eq(&got, &c_ref[k])) __atomic_fetch_add(&c_mismatch, 1, __ATOMIC_RELAXED);
        }
    }
    return NULL;
}

int main(void) {
    tt_isolate();
    void* tomb = malloc(TOMB_CAP*36);
    void* manifest = malloc(MANIFEST_CAP*16);
    void* scratch = malloc(SCRATCH_CAP);
    void* ublob = malloc(BLOB);
    void* u = malloc(utxo_struct_size(SLOTS));
    if (!tomb || !manifest || !scratch || !ublob || !u) { printf("FAIL alloc\n"); return 1; }
    utxo_init(u, SLOTS, ublob, BLOB);

    struct LST lst;
    memset(&lst, 0, sizeof lst);
    lst.op_threshold = 2;
    lst.fill_threshold = 1;          /* one run per op -- deterministic manifest_n */
    lst.tomb_buf = tomb; lst.tomb_cap = TOMB_CAP;
    lst.manifest_buf = manifest; lst.manifest_cap = MANIFEST_CAP;
    lst.scratch_buf = scratch; lst.scratch_cap = SCRATCH_CAP;
    ck("lsm_init", utxo_lsm_init(&lst), 1);

    unsigned char script[40];
    for (int j = 0; j < 40; j++) script[j] = (unsigned char)(0x80 + j);

    /* Phase 1: 200 keys, each written once. */
    for (unsigned i = 0; i < 200; i++) {
        unsigned char t[32]; make_txid(t, i);
        if (utxo_lsm_put(&lst, u, t, i & 3, 1000ULL + i, 10 + i, i & 1, script, 20) < 0)
            { printf("FAIL put %u\n", i); return 1; }
    }
    /* Phase 2: OVERWRITE the first 100 with new values. The originals stay
     * behind in older runs -- these are the stale-value keys. */
    for (unsigned i = 0; i < 100; i++) {
        unsigned char t[32]; make_txid(t, i);
        if (utxo_lsm_put(&lst, u, t, i & 3, 999000ULL + i, 900 + i, (i+1) & 1, script, 33) < 0)
            { printf("FAIL overwrite %u\n", i); return 1; }
    }
    /* Phase 3: tombstone 50 of the untouched ones. */
    for (unsigned i = 200; i < 250; i++) {
        unsigned char t[32]; make_txid(t, i);
        utxo_lsm_put(&lst, u, t, i & 3, 5000ULL + i, 50 + i, 0, script, 12);
    }
    for (unsigned i = 200; i < 250; i++) {
        unsigned char t[32]; make_txid(t, i);
        if (utxo_lsm_del(&lst, u, t, i & 3) < 0) { printf("FAIL del %u\n", i); return 1; }
    }

    ck("manifest_n > COMPACT_MAX_RUNS(64) before compact",
       lst.manifest_n > 64, 1);
    long cr = utxo_lsm_compact(&lst);
    ck("compact ok", cr >= 0, 1);
    ck("compaction left SURVIVORS (the e12dcbb shape)", lst.manifest_n > 1, 1);

    /* ---- differential: fast path vs asm, every key ---- */
    int diff = 0, n_found = 0, n_absent = 0;
    for (unsigned i = 0; i < 400; i++) {
        res_t fast, slow;
        lsm_mm_set_enabled(1); do_get(&lst, u, i, &fast);
        lsm_mm_set_enabled(0); do_get(&lst, u, i, &slow);
        if (!res_eq(&fast, &slow)) {
            if (diff < 5)
                printf("FAIL: key %u mmap{r=%ld v=%llu h=%lu cb=%lu sl=%u} "
                       "asm{r=%ld v=%llu h=%lu cb=%lu sl=%u}\n", i,
                       fast.r, fast.v, fast.h, fast.cb, fast.slen,
                       slow.r, slow.v, slow.h, slow.cb, slow.slen);
            diff++;
        }
        if (slow.r == 1) n_found++; else n_absent++;
    }
    lsm_mm_set_enabled(1);
    ck("differential over 400 keys: mismatches", diff, 0);
    ck("  ...of which present", n_found > 100, 1);
    ck("  ...of which absent/tombstoned", n_absent > 50, 1);

    /* Overwritten keys must report the NEW value, not the stale older run. */
    int stale = 0;
    for (unsigned i = 0; i < 100; i++) {
        res_t r; do_get(&lst, u, i, &r);
        if (r.r != 1 || r.v != 999000ULL + i || r.h != 900 + i || r.slen != 33) stale++;
    }
    ck("stale-value keys resolve to the NEWER run", stale, 0);

    /* Tombstoned keys must be absent. */
    int tomb_bad = 0;
    for (unsigned i = 200; i < 250; i++) {
        res_t r; do_get(&lst, u, i, &r);
        if (r.r == 1) tomb_bad++;
    }
    ck("tombstoned keys absent", tomb_bad, 0);

    /* Never-inserted keys must be absent. */
    int ghost = 0;
    for (unsigned i = 300; i < 400; i++) {
        res_t r; do_get(&lst, u, i, &r);
        if (r.r == 1) ghost++;
    }
    ck("never-inserted keys absent", ghost, 0);

    /* ---- concurrency: cold caches in 8 threads vs a single-threaded ref ---- */
    c_lst = &lst; c_u = u; c_mismatch = 0;
    for (int i = 0; i < NKEYS; i++) do_get(&lst, u, (unsigned)i, &c_ref[i]);
    pthread_t th[NTHREADS];
    for (long t = 0; t < NTHREADS; t++) pthread_create(&th[t], NULL, hammer, (void*)t);
    for (int t = 0; t < NTHREADS; t++) pthread_join(th[t], NULL);
    ck("concurrent gets (8 threads x 12 passes x 400 keys)", c_mismatch, 0);

    utxo_lsm_close(&lst);
    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
