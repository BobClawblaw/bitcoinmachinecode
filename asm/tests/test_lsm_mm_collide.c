/* tests/test_lsm_mm_collide.c -- two live runs whose run_no collide in the
 * mm cache must not thrash it (2026-09-24, m5ultra).
 *
 * utxo_lsm_mm.c's per-thread cache was direct-mapped, slot = run_no % 64, on
 * the premise that ~12 live runs make collisions "essentially absent". A
 * mid-catchup manifest holds up to 24 runs with scattered numbers, and on
 * the m5ultra the 15 GB base run (9040) shared slot 16 with a fresh 6.7 MB
 * run (9232): a lookup checks the newer run first and finds an old coin in
 * the base, so every lookup unmapped and re-mapped both. Sampled, the apply
 * thread spent about half its time in munmap/open/mmap under
 * lsm_run_lookup_mm.
 *
 * Shape: fill_threshold=1, so each put flushes its own run; next_run_no is
 * set to 64 between the two puts, so the live runs are 0 and 64 (same slot
 * under % 64). 1,000 lookups of each key through utxo_lsm_get; the answers
 * must be right and the cache must map each run once (lsm_mm_stats maps ==
 * 2), not once per lookup. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "test_tmpdir.h"

extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const unsigned char txid[32],
                          unsigned index, unsigned long long value,
                          unsigned long height, unsigned long is_coinbase,
                          const unsigned char* script, unsigned slen);
extern long utxo_lsm_get(void* lst, void* u, const unsigned char txid[32], unsigned index,
                          unsigned long long* value, unsigned long* height,
                          unsigned long* is_coinbase,
                          const unsigned char** script, unsigned long* slen);
extern void utxo_lsm_close(void* lst);
extern void lsm_mm_set_enabled(int on);
extern void lsm_mm_stats(unsigned long long*, unsigned long long*, unsigned long long*);
extern void lsm_mm_stats_reset(void);

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
#define SCRATCH_CAP    ((unsigned long long)64*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES)

static int fails = 0;
static void ck(const char* l, long long g, long long e) {
    if (g == e) printf("ok  : %-58s (got %lld)\n", l, g);
    else { printf("FAIL: %-58s (got %lld exp %lld)\n", l, g, e); fails++; }
}
static void make_txid(unsigned char* t, unsigned i) {
    for (int j = 0; j < 32; j++) t[j] = (unsigned char)(0x11 * (j + 1) + i);
}

int main(void) {
    tt_isolate();
    void* u = malloc(utxo_struct_size(SLOTS)); void* ublob = malloc(BLOB);
    struct LST lst; memset(&lst, 0, sizeof lst);
    lst.op_threshold = 2; lst.fill_threshold = 1;
    lst.tomb_buf = malloc(TOMB_CAP*36); lst.tomb_cap = TOMB_CAP;
    lst.manifest_buf = malloc(MANIFEST_CAP*16); lst.manifest_cap = MANIFEST_CAP;
    lst.scratch_buf = malloc(SCRATCH_CAP); lst.scratch_cap = SCRATCH_CAP;
    utxo_init(u, SLOTS, ublob, BLOB);
    ck("lsm_init", utxo_lsm_init(&lst), 1);
    lsm_mm_set_enabled(1);

    unsigned char script[20]; memset(script, 0x51, sizeof script);
    unsigned char a[32], b[32]; make_txid(a, 1); make_txid(b, 2);
    if (utxo_lsm_put(&lst, u, a, 0, 1111, 100, 0, script, 20) < 0) { printf("FAIL put a\n"); return 1; }
    lst.next_run_no = 64;                          /* the next flush lands in run 64: slot 0 again */
    if (utxo_lsm_put(&lst, u, b, 0, 2222, 200, 0, script, 20) < 0) { printf("FAIL put b\n"); return 1; }
    ck("two live runs", (long long)lst.manifest_n, 2);

    lsm_mm_stats_reset();
    long bad = 0;
    for (int i = 0; i < 1000; i++) {
        const unsigned char* sp; unsigned long sl, h, cb; unsigned long long v;
        if (utxo_lsm_get(&lst, u, a, 0, &v, &h, &cb, &sp, &sl) != 1 || v != 1111 || h != 100) bad++;
        if (utxo_lsm_get(&lst, u, b, 0, &v, &h, &cb, &sp, &sl) != 1 || v != 2222 || h != 200) bad++;
    }
    ck("2,000 lookups answered correctly", bad, 0);
    unsigned long long maps = 0, hits = 0, fb = 0; lsm_mm_stats(&maps, &hits, &fb);
    printf("      mm stats: maps %llu, hits %llu, fallbacks %llu\n", maps, hits, fb);
    ck("each colliding run mapped once, not once per lookup", (long long)maps, 2);
    ck("no fallbacks", (long long)fb, 0);

    utxo_lsm_close(&lst);
    printf("%s\n", fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
