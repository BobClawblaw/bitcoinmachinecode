/* tests/test_lsm_bloom_sized.c -- a run's Bloom filter is sized to its
 * records, past the old 4 MiB cap (2026-10-09).
 *
 * The writer sized the filter at 10 bits per record but capped it at
 * BLOOM_MAX_BYTES (4 MiB, 2^25 bits, ~3.35M records). A bulk flush run in
 * run 45 held ~19M records: 1.76 bits per key, and 55% of the keys a run did
 * not hold passed its filter into a ~500 ns sparse search + scan, on every
 * lookup that reached the runs (26 of them mid-chain).
 *
 * Shape: one flush of 3,400,000 records (34M bits wanted: 2^26 with the fix,
 * the cap's 2^25 without), then a second small run and a merge of the two.
 *   A. the flushed run's header says 2^26 bits;
 *   B. its filter, read from the file and tested with the writer's own hash,
 *      passes under 1% of 200,000 absent keys (at the cap: ~1.7%);
 *   C. sampled keys read back and absent keys miss, through the mmap path
 *      (lsm_run_lookup_mm, hashes computed once per key across the runs) and
 *      through the asm fallback with the mmap path off -- whose 4 MiB TLS
 *      copy cannot hold this filter, so it searches without it;
 *   D. the merged run's header says 2^26 bits and every sampled key reads
 *      back from it on both paths.
 *
 * Revert checks: A and D FAIL with RUN_BLOOM_MAX_BYTES set back to
 * BLOOM_MAX_BYTES in the writer and the merge; B FAILS with the cap back in
 * the writer; C's fallback half fails (reads past the TLS copy) with the
 * .ml_nobloom skip removed. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
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
extern long utxo_lsm_flush(void* lst, void* u);
extern long utxo_lsm_compact(void* lst);
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
#define N              3400000ULL
#define SLOTS          (1UL << 22)
#define BLOB           ((unsigned long)N * 32 + (1UL << 20))
#define TOMB_CAP       1024
#define MANIFEST_CAP   64
#define DESC_CAP       (N + 4096)
#define SCRATCH_CAP    ((unsigned long long)DESC_CAP*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES)

static int fails = 0;
static void ck(const char* l, long long g, long long e) {
    if (g == e) printf("ok  : %-62s (got %lld)\n", l, g);
    else { printf("FAIL: %-62s (got %lld exp %lld)\n", l, g, e); fails++; }
}
static void ckm(const char* l, int ok) {
    if (ok) printf("ok  : %s\n", l); else { printf("FAIL: %s\n", l); fails++; }
}
/* distinct, well-spread txids: i in the first 8 bytes, a mix after */
static void make_txid(unsigned char* t, unsigned long long i) {
    unsigned long long x = i * 0x9E3779B97F4A7C15ULL;
    for (int j = 0; j < 32; j++) { t[j] = (unsigned char)(x >> ((j & 7) * 8)) ^ (unsigned char)(j * 29); if ((j & 7) == 7) x = x * 6364136223846793005ULL + 1442695040888963407ULL; }
    memcpy(t, &i, 8);
}
/* the writer's hash (mac_bloom_h): FNV-1a over the 36-byte key */
static uint32_t fnv(const unsigned char* k, uint32_t h) { for (int i = 0; i < 36; i++) { h ^= k[i]; h *= 16777619u; } return h; }

struct hdr { unsigned long long gen, nrec, bits, spo, spn; };
static int read_hdr(unsigned long long run_no, struct hdr* h, unsigned char** bloom) {
    char nm[64]; snprintf(nm, sizeof nm, "utxo_run_%06llu.dat", run_no);
    FILE* f = fopen(nm, "rb"); if (!f) return -1;
    unsigned char b[44]; if (fread(b, 1, 44, f) != 44) { fclose(f); return -1; }
    memcpy(&h->gen, b + 4, 8); memcpy(&h->nrec, b + 12, 8); memcpy(&h->bits, b + 20, 8);
    memcpy(&h->spo, b + 28, 8); memcpy(&h->spn, b + 36, 8);
    if (bloom) { *bloom = malloc(h->bits / 8); if (fread(*bloom, 1, h->bits / 8, f) != h->bits / 8) { fclose(f); return -1; } }
    fclose(f); return 0;
}
static unsigned long long run_no_at(struct LST* l, unsigned long long i) {
    unsigned long long r; memcpy(&r, (unsigned char*)l->manifest_buf + i * 16 + 8, 8); return r;
}
/* sampled present keys read back with their values; absent keys miss */
static long check_reads(struct LST* l, void* u, unsigned long long upto, const char* what) {
    long bad = 0;
    for (unsigned long long i = 0; i < upto; i += 997) {
        unsigned char t[32]; make_txid(t, i);
        const unsigned char* sp; unsigned long sl, h, cb; unsigned long long v;
        if (utxo_lsm_get(l, u, t, (unsigned)(i & 3), &v, &h, &cb, &sp, &sl) != 1 || v != i + 1 || h != (i % 900000)) bad++;
        make_txid(t, i + 50000000ULL);                      /* never put */
        if (utxo_lsm_get(l, u, t, 0, &v, &h, &cb, &sp, &sl) != 0) bad++;
    }
    printf("      %s: %ld wrong of %llu lookups\n", what, bad, 2 * ((upto + 996) / 997));
    return bad;
}

int main(void) {
    tt_isolate();
    void* u = malloc(utxo_struct_size(SLOTS)); void* ublob = malloc(BLOB);
    struct LST lst; memset(&lst, 0, sizeof lst);
    lst.op_threshold = ~0ULL >> 1; lst.fill_threshold = ~0ULL >> 1;   /* flushes are explicit */
    lst.tomb_buf = malloc(TOMB_CAP*36); lst.tomb_cap = TOMB_CAP;
    lst.manifest_buf = malloc(MANIFEST_CAP*16); lst.manifest_cap = MANIFEST_CAP;
    lst.scratch_buf = malloc(SCRATCH_CAP); lst.scratch_cap = SCRATCH_CAP;
    if (!u || !ublob || !lst.scratch_buf) { printf("FAIL: no memory\n"); return 1; }
    utxo_init(u, SLOTS, ublob, BLOB);
    ck("lsm_init", utxo_lsm_init(&lst), 1);
    lsm_mm_set_enabled(1);

    unsigned char script[1] = { 0x51 };
    for (unsigned long long i = 0; i < N; i++) {
        unsigned char t[32]; make_txid(t, i);
        if (utxo_lsm_put(&lst, u, t, (unsigned)(i & 3), i + 1, i % 900000, 0, script, 1) < 0) { printf("FAIL: put %llu\n", i); return 1; }
    }
    ck("the flush of 3,400,000 records", utxo_lsm_flush(&lst, u), 1);
    ck("one run", (long long)lst.manifest_n, 1);

    printf("-- A/B: the flushed run's filter\n");
    struct hdr h; unsigned char* bloom = NULL;
    ck("  header read", read_hdr(run_no_at(&lst, 0), &h, &bloom), 0);
    ck("  records", (long long)h.nrec, (long long)N);
    ck("  bloom bits (10 per record, next power of two: 2^26)", (long long)h.bits, 1LL << 26);
    {   uint32_t m = (uint32_t)(h.bits - 1); long pass = 0, present_miss = 0;
        for (unsigned long long i = 0; i < 200000; i++) {
            unsigned char k[36]; make_txid(k, i + 70000000ULL); memset(k + 32, 0, 4);
            int ok = 1; uint32_t seeds[3] = { 0x811c9dc5u, 0xa1b2c3d4u, 0x5bd1e995u };
            for (int s = 0; s < 3 && ok; s++) { uint32_t b = fnv(k, seeds[s]) & m; ok = (bloom[b >> 3] >> (b & 7)) & 1; }
            pass += ok;
            make_txid(k, i * 17); { unsigned idx = (unsigned)((i * 17) & 3); memcpy(k + 32, &idx, 4); }
            ok = 1; for (int s = 0; s < 3 && ok; s++) { uint32_t b = fnv(k, seeds[s]) & m; ok = (bloom[b >> 3] >> (b & 7)) & 1; }
            if (!ok) present_miss++;
        }
        printf("      %ld of 200,000 absent keys pass the filter (%.3f%%)\n", pass, pass / 2000.0);
        ckm("  under 1% of absent keys pass (the 4 MiB cap: ~1.7%)", pass < 2000);
        ck("  every present key passes", present_miss, 0);
    }
    free(bloom);

    printf("-- C: reads through both lookup paths\n");
    lsm_mm_stats_reset();
    ck("  mmap path", check_reads(&lst, u, N, "mmap path"), 0);
    { unsigned long long maps = 0, hits = 0, fb = 0; lsm_mm_stats(&maps, &hits, &fb); ck("  ...with no fallback", (long long)fb, 0); }
    lsm_mm_set_enabled(0);
    ck("  asm fallback (filter larger than its TLS copy)", check_reads(&lst, u, N, "asm fallback"), 0);
    lsm_mm_set_enabled(1);

    printf("-- D: a merge sizes the merged run's filter the same way\n");
    for (unsigned long long i = N; i < N + 1000; i++) {
        unsigned char t[32]; make_txid(t, i);
        if (utxo_lsm_put(&lst, u, t, (unsigned)(i & 3), i + 1, i % 900000, 0, script, 1) < 0) { printf("FAIL: put %llu\n", i); return 1; }
    }
    ck("  a second run", utxo_lsm_flush(&lst, u), 1);
    ck("  two runs", (long long)lst.manifest_n, 2);
    ck("  reads across two runs (one hash set per key)", check_reads(&lst, u, N + 1000, "two runs, mmap"), 0);
    ck("  the merge", utxo_lsm_compact(&lst) >= 0, 1);
    ck("  one run after the merge", (long long)lst.manifest_n, 1);
    ck("  merged header read", read_hdr(run_no_at(&lst, 0), &h, NULL), 0);
    ck("  merged bloom bits (2^26)", (long long)h.bits, 1LL << 26);
    ck("  merged run, mmap path", check_reads(&lst, u, N + 1000, "merged, mmap"), 0);
    lsm_mm_set_enabled(0);
    ck("  merged run, asm fallback", check_reads(&lst, u, N + 1000, "merged, asm fallback"), 0);

    utxo_lsm_close(&lst);
    printf("%s\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED (0 failures)");
    return fails ? 1 : 0;
}
