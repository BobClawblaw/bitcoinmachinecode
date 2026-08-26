/* tests/bench_lsm_get.c -- PERF_SCOPE.md 4.1 measurement.
 *
 * Builds a multi-run LSM, then times N utxo_lsm_get calls. Run it under
 * `strace -c -f` to count syscalls, and with BMC_LSM_MMAP=0 to get the
 * pre-change (assembly read/lseek) baseline for comparison.
 *
 * Usage: bench_lsm_get [n_lookups]
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

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
#define SLOTS          1024
#define BLOB           (1<<22)
#define TOMB_CAP       1024
#define MANIFEST_CAP   512
#define DESC_CAP       2048   /* must be >= fill_threshold + tomb_cap (see lst->scratch_buf docs) */
#define SCRATCH_CAP    ((unsigned long long)DESC_CAP*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES)
#define NKEYS          4000

static void make_txid(unsigned char* t, unsigned i) {
    for (int j = 0; j < 32; j++) t[j] = (unsigned char)(0x40 + j);
    t[0] = (unsigned char)(i & 0xff);
    t[1] = (unsigned char)((i >> 8) & 0xff);
    t[2] = (unsigned char)((i >> 16) & 0xff);
}

int main(int argc, char** argv) {
    long n = (argc > 1) ? atol(argv[1]) : 200000;
    char tmpl[] = "/tmp/benchlsmXXXXXX";
    char* dir = mkdtemp(tmpl);
    if (!dir || chdir(dir) != 0) { printf("mkdtemp/chdir failed\n"); return 1; }

    void* tomb = malloc(TOMB_CAP*36);
    void* manifest = malloc(MANIFEST_CAP*16);
    void* scratch = malloc(SCRATCH_CAP);
    void* ublob = malloc(BLOB);
    void* u = malloc(utxo_struct_size(SLOTS));
    utxo_init(u, SLOTS, ublob, BLOB);

    struct LST lst;
    memset(&lst, 0, sizeof lst);
    lst.op_threshold = 400;
    lst.fill_threshold = 400;      /* ~10 runs over NKEYS puts */
    lst.tomb_buf = tomb; lst.tomb_cap = TOMB_CAP;
    lst.manifest_buf = manifest; lst.manifest_cap = MANIFEST_CAP;
    lst.scratch_buf = scratch; lst.scratch_cap = SCRATCH_CAP;
    if (utxo_lsm_init(&lst) != 1) { printf("lsm_init failed\n"); return 1; }

    unsigned char script[25];
    for (int j = 0; j < 25; j++) script[j] = (unsigned char)j;
    for (unsigned i = 0; i < NKEYS; i++) {
        unsigned char t[32]; make_txid(t, i);
        utxo_lsm_put(&lst, u, t, i & 3, 1000ULL + i, 10 + i, i & 1, script, 25);
    }
    printf("built LSM: manifest_n=%llu, %d keys\n",
           (unsigned long long)lst.manifest_n, NKEYS);

    /* Lookups skewed to MISSING keys: the bloom-reject path, which is where
     * the old code paid a full bloom read per run for a 3-bit test. */
    struct timespec a, b;
    unsigned long long found = 0;
    clock_gettime(CLOCK_MONOTONIC, &a);
    for (long i = 0; i < n; i++) {
        unsigned k = (unsigned)((i * 2654435761u) % (NKEYS * 4));
        unsigned char t[32]; make_txid(t, k);
        unsigned long long v; unsigned long h, cb; const unsigned char* sp; unsigned long sl;
        if (utxo_lsm_get(&lst, u, t, k & 3, &v, &h, &cb, &sp, &sl) == 1) found++;
    }
    clock_gettime(CLOCK_MONOTONIC, &b);
    double sec = (b.tv_sec - a.tv_sec) + (b.tv_nsec - a.tv_nsec) / 1e9;

    unsigned long long maps = 0, hits = 0, fb = 0;
    lsm_mm_stats(&maps, &hits, &fb);
    printf("%ld lookups in %.3fs -> %.0f lookups/s (found=%llu)\n",
           n, sec, n / sec, found);
    printf("mmap-cache: maps=%llu hits=%llu fallbacks=%llu\n", maps, hits, fb);

    utxo_lsm_close(&lst);
    return 0;
}
