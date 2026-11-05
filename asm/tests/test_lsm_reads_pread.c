/* tests/test_lsm_reads_pread.c -- bmc.lsmreads=pread (2026-10-11): the UTXO
 * run lookups read RECORDS with pread() into a per-thread window instead of
 * through the mapping (utxo_lsm_mm.c rec_at), so a run file's records pages
 * never enter the process's page tables: they stay page cache and leave the
 * resident set. The release report's memory row: run 46's worker held ~49 GB
 * of mapped, touched run pages the minute before a full compaction.
 *
 * Pinned:
 *   1. the answers are identical across the three paths -- pread, the mapped
 *      fast path, the asm -- over every present key, 2,000 absent keys and
 *      the tombstoned keys, scripts of 100 bytes and of 5,000 bytes (a record
 *      that does not fit the first 4 KB window and makes rec_at re-read);
 *   2. pread mode makes pread() calls, mmap mode makes none;
 *   3. the resident set: a thread that looked up 2,000 random present keys
 *      in pread mode has at most a quarter of its run mappings' bytes
 *      resident (the header, the Bloom filter and the sparse index, read
 *      through the mapping); a thread that did the same in mmap mode has at
 *      least half of them (the records pages it touched).
 *
 * Watched to FAIL with rec_at's pread branch returning the mapping (the
 * residency check) and with the pread path's window re-read removed (the
 * 5,000-byte scripts fall back or differ). */
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
                          const unsigned char** script, unsigned long* slen);
extern void utxo_lsm_close(void* lst);
extern void lsm_mm_set_enabled(int on);
extern void lsm_mm_set_reads(int pread_mode);
extern unsigned long long lsm_mm_pread_count(void);
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
#define SLOTS          65536
#define BLOB           (64u<<20)
#define TOMB_CAP       4096
#define MANIFEST_CAP   512
#define FILL           4000                 /* records per run: 5 runs of 4,000 */
#define DESC_CAP       (FILL + TOMB_CAP)
#define SCRATCH_CAP    ((unsigned long long)DESC_CAP*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES)
#define NKEYS          20000
#define NBIG           200                  /* keys 0..199 carry a 5,000-byte script */
#define NTOMB          300                  /* keys 1000..1299 are tombstoned */
#define NABSENT        2000

static int fails = 0;
static void ck(const char* l, long g, long e){
    if (g == e) printf("ok  : %-60s (got %ld)\n", l, g);
    else { printf("FAIL: %-60s (got %ld exp %ld)\n", l, g, e); fails++; }
}
static void make_txid(unsigned char* t, unsigned i){
    for (int j = 0; j < 32; j++) t[j] = (unsigned char)(0x40 + j);
    t[0] = (unsigned char)(i & 0xff); t[1] = (unsigned char)((i >> 8) & 0xff); t[2] = (unsigned char)((i >> 16) & 0xff);
}
static unsigned script_len(unsigned i){ return i < NBIG ? 5000 : 100; }
static void make_script(unsigned char* s, unsigned i){ unsigned n = script_len(i); for (unsigned j = 0; j < n; j++) s[j] = (unsigned char)(0x80 + ((i + j) & 0x3f)); }

typedef struct { long r; unsigned long long v; unsigned long h, cb, slen; unsigned char script[5000]; } res_t;
static void do_get(struct LST* lst, void* u, unsigned i, res_t* out){
    unsigned char t[32]; make_txid(t, i);
    const unsigned char* sp = NULL; unsigned long sl = 0; unsigned long long v = 0; unsigned long h = 0, cb = 0;
    memset(out, 0, sizeof *out);
    out->r = utxo_lsm_get(lst, u, t, i & 3, &v, &h, &cb, &sp, &sl);
    out->v = v; out->h = h; out->cb = cb; out->slen = sl;
    if (out->r == 1 && sl && sl <= sizeof out->script) memcpy(out->script, sp, sl);
}
static int res_eq(const res_t* a, const res_t* b){
    if (a->r != b->r || a->v != b->v || a->h != b->h || a->cb != b->cb || a->slen != b->slen) return 0;
    if (a->r == 1 && a->slen && a->slen <= sizeof a->script) return memcmp(a->script, b->script, a->slen) == 0;
    return 1;
}

/* /proc/self/smaps: Rss and size summed over every mapping of a utxo_run file */
static void run_mappings(unsigned long* rss_kb, unsigned long* size_kb, int* nmaps){
    *rss_kb = *size_kb = 0; *nmaps = 0;
    FILE* f = fopen("/proc/self/smaps", "r"); if (!f) return;
    char line[512]; int in = 0;
    while (fgets(line, sizeof line, f)){
        unsigned long lo, hi; char perms[8];
        if (sscanf(line, "%lx-%lx %7s", &lo, &hi, perms) == 3){ in = strstr(line, "utxo_run_") != NULL; if (in){ *size_kb += (hi - lo) / 1024; (*nmaps)++; } continue; }
        if (in && !strncmp(line, "Rss:", 4)) *rss_kb += strtoul(line + 4, NULL, 10);
    }
    fclose(f);
}

static struct LST* t_lst; static void* t_u;
static unsigned long t_rss, t_size; static int t_maps; static long t_found;
/* 2,000 random present keys in the mode the caller set, on cold mappings */
static void* lookup_thread(void* arg){
    (void)arg;
    unsigned x = 12345; t_found = 0;
    for (int n = 0; n < 2000; n++){
        x = x * 1103515245u + 12345u; unsigned i = (x >> 8) % NKEYS;
        if (i >= 1000 && i < 1000 + NTOMB) i += NTOMB;
        res_t r; do_get(t_lst, t_u, i, &r); if (r.r == 1) t_found++;
    }
    run_mappings(&t_rss, &t_size, &t_maps);
    return NULL;
}

int main(void){
    tt_isolate();
    void* tomb = malloc(TOMB_CAP*36); void* manifest = malloc(MANIFEST_CAP*16); void* scratch = malloc(SCRATCH_CAP);
    void* ublob = malloc(BLOB); void* u = malloc(utxo_struct_size(SLOTS));
    if (!tomb || !manifest || !scratch || !ublob || !u){ printf("FAIL alloc\n"); return 1; }
    utxo_init(u, SLOTS, ublob, BLOB);
    struct LST lst; memset(&lst, 0, sizeof lst);
    lst.op_threshold = 1u << 30; lst.fill_threshold = FILL;
    lst.tomb_buf = tomb; lst.tomb_cap = TOMB_CAP; lst.manifest_buf = manifest; lst.manifest_cap = MANIFEST_CAP;
    lst.scratch_buf = scratch; lst.scratch_cap = SCRATCH_CAP;
    ck("lsm_init", utxo_lsm_init(&lst), 1);

    static unsigned char script[5000];
    for (unsigned i = 0; i < NKEYS; i++){
        unsigned char t[32]; make_txid(t, i); make_script(script, i);
        if (utxo_lsm_put(&lst, u, t, i & 3, 1000ULL + i, 10 + i, i & 1, script, script_len(i)) < 0){ printf("FAIL put %u\n", i); return 1; }
    }
    for (unsigned i = 1000; i < 1000 + NTOMB; i++){ unsigned char t[32]; make_txid(t, i); if (utxo_lsm_del(&lst, u, t, i & 3) < 0){ printf("FAIL del %u\n", i); return 1; } }
    /* the tombstones and the last keys are still in the memtable: push one more
     * run out so every key and every tombstone is on disk */
    for (unsigned i = NKEYS; i < NKEYS + FILL; i++){
        unsigned char t[32]; make_txid(t, i); make_script(script, i);
        if (utxo_lsm_put(&lst, u, t, i & 3, 7ULL, 1, 0, script, 100) < 0){ printf("FAIL pad %u\n", i); return 1; }
    }
    printf("     manifest_n=%llu (runs on disk)\n", lst.manifest_n);
    ck("at least 5 runs on disk", lst.manifest_n >= 5, 1);

    /* ---- 1. the three paths agree on every key ---- */
    long diff = 0, nfound = 0, ntomb = 0, nabsent = 0;
    unsigned long long pr0 = lsm_mm_pread_count();
    for (unsigned i = 0; i < NKEYS + NABSENT; i++){
        unsigned k = i < NKEYS ? i : 0x100000u + (i - NKEYS);
        res_t a, b, c;
        lsm_mm_set_enabled(1); lsm_mm_set_reads(1); do_get(&lst, u, k, &a);
        lsm_mm_set_reads(0);                         do_get(&lst, u, k, &b);
        lsm_mm_set_enabled(0);                       do_get(&lst, u, k, &c);
        lsm_mm_set_enabled(1);
        if (!res_eq(&a, &b) || !res_eq(&a, &c)){
            if (diff < 5) printf("FAIL: key %u pread{r=%ld v=%llu sl=%lu} mmap{r=%ld v=%llu sl=%lu} asm{r=%ld v=%llu sl=%lu}\n",
                                 k, a.r, a.v, a.slen, b.r, b.v, b.slen, c.r, c.v, c.slen);
            diff++;
        }
        if (c.r == 1) nfound++; else if (c.r == 2 || (k >= 1000 && k < 1000 + NTOMB)) ntomb++; else nabsent++;
    }
    unsigned long long pr1 = lsm_mm_pread_count();
    /* the 5,000-byte records do not fit the first window: rec_at re-reads
     * the window at the record, never hands the lookup to the asm */
    unsigned long long fb0, fb1, mm_, hh_; lsm_mm_stats(&mm_, &hh_, &fb0);
    { res_t r; lsm_mm_set_reads(1); for (unsigned i = 0; i < NBIG; i++) do_get(&lst, u, i, &r); lsm_mm_set_reads(0); }
    lsm_mm_stats(&mm_, &hh_, &fb1);
    ck("pread: the big records are read in the window, no fallback to the asm", (long)(fb1 - fb0), 0);
    ck("differential pread / mmap / asm: mismatches", diff, 0);
    ck("  ...present keys found", nfound, NKEYS - NTOMB);
    ck("  ...absent keys (never put)", nabsent >= NABSENT, 1);
    ck("  ...5,000-byte scripts came back whole (key 0)", ({ res_t r; lsm_mm_set_reads(1); do_get(&lst, u, 0, &r); lsm_mm_set_reads(0); (long)r.slen; }), 5000);
    ck("pread mode made pread() calls", pr1 - pr0 > 0, 1);
    unsigned long long pr2 = lsm_mm_pread_count();
    { res_t r; lsm_mm_set_reads(0); for (unsigned i = 0; i < 500; i++) do_get(&lst, u, i, &r); }
    ck("mmap mode makes none", (long)(lsm_mm_pread_count() - pr2), 0);

    /* ---- 3. the resident set, each mode on a thread of its own (cold mappings) ---- */
    t_lst = &lst; t_u = u;
    pthread_t th;
    /* the main thread's own mappings (fully resident after the mmap-mode
     * lookups above) are subtracted: each thread's figure is what it added */
    unsigned long rss0, size0; int maps0; run_mappings(&rss0, &size0, &maps0);
    lsm_mm_set_reads(1);
    pthread_create(&th, NULL, lookup_thread, NULL); pthread_join(th, NULL);
    unsigned long rss_pread = t_rss - rss0, size_pread = t_size - size0; int maps_pread = t_maps - maps0; long found_pread = t_found;
    unsigned long rss1 = t_rss, size1 = t_size; int maps1 = t_maps;
    printf("     pread: %d run mapping(s), %lu KB mapped, %lu KB resident (%.0f%%), %ld found\n",
           maps_pread, size_pread, rss_pread, size_pread ? 100.0 * rss_pread / size_pread : 0, found_pread);
    lsm_mm_set_reads(0);
    pthread_create(&th, NULL, lookup_thread, NULL); pthread_join(th, NULL);
    unsigned long rss_mmap = t_rss - rss1, size_mmap = t_size - size1;
    printf("     mmap : %d run mapping(s), %lu KB mapped, %lu KB resident (%.0f%%), %ld found\n",
           t_maps - maps1, size_mmap, rss_mmap, size_mmap ? 100.0 * rss_mmap / size_mmap : 0, t_found);
    ck("pread thread found its keys", found_pread > 1500, 1);
    ck("pread: at most a quarter of the run files resident (header, Bloom, sparse)", rss_pread * 4 <= size_pread, 1);
    ck("mmap : at least half of the run files resident (the records it touched)", rss_mmap * 2 >= size_mmap, 1);

    utxo_lsm_close(&lst);
    printf("\n%s (%d failures)\n", fails == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", fails);
    return fails ? 1 : 0;
}
