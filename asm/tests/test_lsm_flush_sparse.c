/* tests/test_lsm_flush_sparse.c -- one flush of many more records than two
 * sparse-index strides (SPARSE_STRIDE = 256), every record small enough that
 * the whole run still sits in mac_flush's 1 MB write buffer while the sparse
 * index samples its offsets.
 *
 * 2026-09-01 (deploy y): the samples took lseek(SEEK_CUR), which excludes the
 * buffered bytes, so every sample after the first pointed short of its record;
 * every lookup through such a run missed and the live UTXO replay hit
 * "input references a missing/already-spent UTXO" at each flush (recovered
 * each time by a full compaction, whose sequential rewrite has correct
 * offsets). The sample must be the LOGICAL offset: written + buffered.
 * Every key must be found through the run, before and after a reload. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
typedef unsigned long long u64;
struct lsm_state { long log_fd, idx_fd; u64 log_len, ckpt_log_off, ckpt_n; u64 op_count, op_threshold, fill_threshold;
    void* tomb_buf; u64 tomb_cap, tomb_n, total_live, next_gen; void* manifest_buf; u64 manifest_cap, manifest_n;
    void* scratch_buf; u64 scratch_cap; u64 next_run_no; void* tomb_hash_buf; u64 tomb_hash_mask; };
extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const unsigned char* txid, unsigned index, u64 value, unsigned long height, unsigned long cb, const unsigned char* script, unsigned slen);
extern long utxo_lsm_get(void* lst, void* u, const unsigned char* txid, unsigned index, u64* value, unsigned long* height, unsigned long* cb, const unsigned char** script, unsigned long* slen);
extern long utxo_lsm_flush(void* lst, void* u);
extern long utxo_lsm_reload(void* lst, void* u);
extern void utxo_lsm_close(void* lst);
extern void lsm_mm_set_enabled(int on);

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static void make_txid(unsigned char* t, unsigned i){ for (int j = 0; j < 32; j++) t[j] = (unsigned char)(0x40 + j); t[0] = (unsigned char)i; t[1] = (unsigned char)(i >> 8); t[2] = (unsigned char)(i >> 16); }
#ifndef NREC
#define NREC 40000   /* ~2.8 MB of records: several 1 MB buffer drains, so the lag shows */
#endif
static int count_misses(struct lsm_state* lst, void* u){
    int bad = 0;
    for (unsigned i = 0; i < NREC; i++) {
        unsigned char t[32]; make_txid(t, i);
        u64 v = 0; unsigned long h = 0, cb = 0, sl = 0; const unsigned char* sp = 0;
        long r = utxo_lsm_get(lst, u, t, i & 3, &v, &h, &cb, &sp, &sl);
        if (r != 1 || v != 1000ULL + i || h != 10 + i || sl != 20 + (i % 20)) { if (bad < 3) printf("    miss/mismatch at %u: r=%ld v=%llu h=%lu sl=%lu\n", i, r, v, h, sl); bad++; }
    }
    return bad;
}
int main(void){
    char tmpl[] = "/tmp/lsmsparseXXXXXX"; char* dir = mkdtemp(tmpl);
    if (!dir || chdir(dir) != 0) { printf("FAIL tmpdir\n"); return 1; }
    enum { SLOTS = 65536 };
    void* blob = malloc(16u << 20); void* u = malloc(utxo_struct_size(SLOTS)); utxo_init(u, SLOTS, blob, 16u << 20);
    struct lsm_state lst; memset(&lst, 0, sizeof lst);
    lst.op_threshold = 100000000ULL; lst.fill_threshold = SLOTS;   /* only the explicit flush below flushes */
    lst.tomb_buf = malloc(512 * 36); lst.tomb_cap = 512; lst.manifest_buf = malloc(512 * 16); lst.manifest_cap = 512;
    lst.scratch_cap = (u64)(SLOTS + 512) * 128 + 4 * 1024 * 1024 + 65536; lst.scratch_buf = malloc(lst.scratch_cap);
    ck("lsm_init", utxo_lsm_init(&lst) == 1);
    unsigned char script[48]; for (int j = 0; j < 48; j++) script[j] = (unsigned char)(0x80 + j);
    printf("== %d records (%d sparse strides), one flush, every key looked up through the run ==\n", NREC, NREC / 256);
    for (unsigned i = 0; i < NREC; i++) {
        unsigned char t[32]; make_txid(t, i);
        if (utxo_lsm_put(&lst, u, t, i & 3, 1000ULL + i, 10 + i, i & 1, script, 20 + (i % 20)) != 1) { printf("FAIL put %u\n", i); return 1; }
    }
    ck("all records found in the memtable before the flush", count_misses(&lst, u) == 0);
    ck("explicit flush", utxo_lsm_flush(&lst, u) != -1);
    ck("one run on disk", lst.manifest_n == 1);
    lsm_mm_set_enabled(0); int bad_asm = count_misses(&lst, u); lsm_mm_set_enabled(1); int bad = count_misses(&lst, u);
    printf("  (misses via the asm run path: %d)\n", bad_asm); ck("every record found via the asm (non-mmap) run path too", bad_asm == 0);
    printf("  (misses through the flushed run: %d of %d)\n", bad, NREC);
    ck("every record found through the flushed run's sparse index", bad == 0);
    ck("reload from disk (WAL empty after the flush)", utxo_lsm_reload(&lst, u) >= 0);
    ck("...and every record still found after the reload", count_misses(&lst, u) == 0);
    utxo_lsm_close(&lst);
    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
