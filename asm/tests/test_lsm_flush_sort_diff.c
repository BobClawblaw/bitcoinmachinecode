/* tests/test_lsm_flush_sort_diff.c -- the flush's radix sort (mac_rsort_desc,
 * the default since 2026-09-06) writes EXACTLY the run the merge sort
 * (mac_sort_desc, today's behaviour, the negative control) wrote.
 *
 * For memtables of 1, 2, 255, 256, 4097 and 100,000 descriptors -- random
 * keys, one txid with 200 outputs (shares 32 key bytes: past the insertion
 * threshold and the sort's 96 compact bits), txids with 2..5 outputs, a family
 * sharing a 30-byte prefix and one sharing 31, tombstones for absent keys
 * (some twice: equal keys, the stability case), tombstones for keys that were
 * live, and delete-then-re-put keys whose tombstone the flush must skip --
 * the same operation sequence is applied in two datadirs, one flushed with
 * utxo_lsm_set_sort_mode(0) (merge) and one with mode 1 (radix), and the two
 * utxo_run_000000.dat files must be byte-identical: header, Bloom filter,
 * records, sparse index.
 *
 * In BOTH datadirs the existing run readers then resolve every key through
 * the flushed run: utxo_lsm_get with the mmap cache on and off finds every
 * live key with its value and misses every tombstoned one, and utxo_lsm_walk
 * (the walk under gettxoutsetinfo: utxo_setinfo.c hands it utxo_stats_add)
 * visits exactly the live set. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include "test_tmpdir.h"

typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;
struct lsm_state { long log_fd, idx_fd; u64 log_len, ckpt_log_off, ckpt_n; u64 op_count, op_threshold, fill_threshold;
    void* tomb_buf; u64 tomb_cap, tomb_n, total_live, next_gen; void* manifest_buf; u64 manifest_cap, manifest_n;
    void* scratch_buf; u64 scratch_cap; u64 next_run_no; void* tomb_hash_buf; u64 tomb_hash_mask; };
extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const u8* txid, unsigned index, u64 value, unsigned long height, unsigned long cb, const u8* script, unsigned slen);
extern long utxo_lsm_del(void* lst, void* u, const u8* txid, unsigned index);
extern long utxo_lsm_get(void* lst, void* u, const u8* txid, unsigned index, u64* value, unsigned long* height, unsigned long* cb, const u8** script, unsigned long* slen);
extern long utxo_lsm_flush(void* lst, void* u);
extern long utxo_lsm_walk(void* lst, void* u, void* cb, void* ctx);
extern void utxo_lsm_close(void* lst);
extern void utxo_lsm_set_sort_mode(long mode);
extern void lsm_mm_set_enabled(int on);
extern void lsm_mm_invalidate_all(void);

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }

static u64 rs;
static u64 rnd(void){ u64 z = (rs += 0x9E3779B97F4A7C15ULL); z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL; z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL; return z ^ (z >> 31); }
static void rnd_bytes(u8* p, int n){ for (int i = 0; i < n; i++) p[i] = (u8)rnd(); }

/* one operation sequence, replayed identically per mode */
struct key { u8 txid[32]; u32 index; u64 value; int live; };
struct ops { struct key* live; unsigned long nlive; struct key* tomb; unsigned long ntomb; unsigned long expect_live, expect_desc; };

static struct ops gen(unsigned long N){
    struct ops o; memset(&o, 0, sizeof o);
    unsigned long T = N >= 2 ? (N / 8 ? N / 8 : 1) : 0, L = N - T;
    o.live = calloc(L ? L : 1, sizeof *o.live); o.nlive = L;
    o.tomb = calloc(T ? T : 1, sizeof *o.tomb); o.ntomb = T;
    unsigned long i = 0;
    /* one txid with many outputs, inserted in shuffled index order */
    if (L >= 8){ unsigned long G = L / 2 < 200 ? L / 2 : 200; u8 t[32]; rnd_bytes(t, 32);
        u32* idx = malloc(G * sizeof *idx); for (u32 k = 0; k < G; k++) idx[k] = k;
        for (u32 k = G - 1; k > 0; k--){ u32 j = (u32)(rnd() % (k + 1)); u32 x = idx[k]; idx[k] = idx[j]; idx[j] = x; }
        for (u32 k = 0; k < G; k++, i++){ memcpy(o.live[i].txid, t, 32); o.live[i].index = idx[k]; }
        free(idx); }
    /* txids with 2..5 outputs */
    while (i + 5 < L && i < L / 2){ u8 t[32]; rnd_bytes(t, 32); unsigned long g = 2 + rnd() % 4; for (unsigned long k = 0; k < g && i < L; k++, i++){ memcpy(o.live[i].txid, t, 32); o.live[i].index = (u32)k; } }
    /* a family sharing a 30-byte txid prefix (bytes 30..31 = k, index = k & 7) and one sharing
     * 31 bytes (byte 31 = k & 0xFF, index = k >> 8: 256 txids of up to fam/512 outputs each);
     * k-derived rather than random so no two live keys collide */
    if (L >= 40){ u8 p[32]; rnd_bytes(p, 32); unsigned long fam = L / 4;
        for (unsigned long k = 0; k < fam && i < L; k++, i++){ memcpy(o.live[i].txid, p, 32); o.live[i].txid[30] = (u8)k; o.live[i].txid[31] = (u8)(k >> 8); o.live[i].index = (u32)(k & 7); }
        rnd_bytes(p, 32);
        for (unsigned long k = 0; k < fam / 2 && i < L; k++, i++){ memcpy(o.live[i].txid, p, 32); o.live[i].txid[31] = (u8)k; o.live[i].index = (u32)(k >> 8); } }
    /* the rest: unique random keys */
    for (; i < L; i++){ rnd_bytes(o.live[i].txid, 32); o.live[i].index = (u32)(rnd() & 3); }
    for (i = 0; i < L; i++){ o.live[i].value = 1000 + i; o.live[i].live = 1; }
    /* tombstones */
    for (unsigned long t = 0; t < T; t++){
        struct key* k = &o.tomb[t]; k->live = 0;   /* .live here = "was a live key" */
        switch (t % 5){
        case 0: rnd_bytes(k->txid, 32); k->index = (u32)(rnd() & 3); break;                       /* absent key */
        case 1: if (t > 0 && (t % 10) == 1){ *k = o.tomb[t - 1]; k->live = 0; break; }              /* the SAME absent key again: duplicate tombstone */
                rnd_bytes(k->txid, 32); k->index = (u32)(rnd() & 3); break;
        case 2: memcpy(k->txid, o.live[L > 40 ? L - 1 - (t % 8) : 0].txid, 32); k->txid[31] ^= 0x5A; k->index = 9; break; /* absent, shares a prefix with a live key */
        case 3: if (t < L){ *k = o.live[t]; k->live = 1; o.live[t].live = 0; break; }             /* delete a live key */
                rnd_bytes(k->txid, 32); k->index = (u32)(rnd() & 3); break;
        case 4: if (t < L){ *k = o.live[t]; k->live = 2; break; }                                   /* delete then re-put: stays live, tombstone skipped */
                rnd_bytes(k->txid, 32); k->index = (u32)(rnd() & 3); break;
        }
    }
    for (i = 0; i < L; i++) o.expect_live += o.live[i].live;
    o.expect_desc = o.expect_live; for (unsigned long t = 0; t < T; t++) o.expect_desc += o.tomb[t].live != 2;
    return o;
}

struct walkacc { unsigned long n; u64 sum; };
static u64 fold(const u8* key36, u64 value){ u64 h = 0xcbf29ce484222325ULL; for (int i = 0; i < 36; i++){ h ^= key36[i]; h *= 0x100000001b3ULL; } h ^= value; h *= 0x100000001b3ULL; return h; }
static void walk_cb(void* ctx, const u8* key36, unsigned long value, unsigned long code, const u8* script, unsigned long slen){
    struct walkacc* w = ctx; w->n++; w->sum += fold(key36, value); (void)code; (void)script; (void)slen; }

static u8 script[40];

/* returns the run file's bytes (caller frees), *len = size; runs every reader check in this datadir */
static u8* run_one(const char* dir, long mode, unsigned long N, struct ops* o, size_t* len){
    char lbl[128];
    if (mkdir(dir, 0755) != 0 || chdir(dir) != 0){ printf("  FAIL mkdir/chdir %s\n", dir); fails++; return 0; }
    lsm_mm_invalidate_all();
    unsigned long slots = 1024; while (slots < N * 2) slots <<= 1;
    unsigned long blob_cap = N * 96 + (1u << 20);
    void* blob = malloc(blob_cap); void* u = malloc(utxo_struct_size(slots)); utxo_init(u, slots, blob, blob_cap);
    struct lsm_state lst; memset(&lst, 0, sizeof lst);
    lst.op_threshold = ~0ULL >> 1; lst.fill_threshold = slots;                 /* only the explicit flush below flushes */
    lst.tomb_cap = N + 16; lst.tomb_buf = malloc(lst.tomb_cap * 36);
    lst.manifest_cap = 16; lst.manifest_buf = malloc(lst.manifest_cap * 16);
    lst.scratch_cap = (u64)(slots + lst.tomb_cap) * 128 + 4 * 1024 * 1024 + 65536; lst.scratch_buf = malloc(lst.scratch_cap);
    snprintf(lbl, sizeof lbl, "[%s] lsm_init", dir); ck(lbl, utxo_lsm_init(&lst) == 1);
    for (unsigned long i = 0; i < o->nlive; i++){ struct key* k = &o->live[i];
        if (utxo_lsm_put(&lst, u, k->txid, k->index, k->value, 10 + (i % 7), i & 1, script, 20 + (i % 20)) != 1){ printf("  FAIL put %lu\n", i); fails++; } }
    for (unsigned long t = 0; t < o->ntomb; t++){ struct key* k = &o->tomb[t];
        if (utxo_lsm_del(&lst, u, k->txid, k->index) != 1){ printf("  FAIL del %lu\n", t); fails++; }
        if (k->live == 2 && utxo_lsm_put(&lst, u, k->txid, k->index, k->value, 10 + (t % 7), t & 1, script, 20 + (t % 20)) != 1){ printf("  FAIL re-put %lu\n", t); fails++; } }   /* t == its index in o->live */
    utxo_lsm_set_sort_mode(mode);
    snprintf(lbl, sizeof lbl, "[%s] flush (sort mode %ld)", dir, mode); ck(lbl, utxo_lsm_flush(&lst, u) == 1 && lst.manifest_n == 1);
    utxo_lsm_set_sort_mode(1);
    /* the run file */
    FILE* f = fopen("utxo_run_000000.dat", "rb"); u8* buf = 0; *len = 0;
    if (f){ fseek(f, 0, SEEK_END); *len = (size_t)ftell(f); fseek(f, 0, SEEK_SET); buf = malloc(*len + 1); if (fread(buf, 1, *len, f) != *len){ free(buf); buf = 0; } fclose(f); }
    snprintf(lbl, sizeof lbl, "[%s] run file readable, nrec == %lu", dir, o->expect_desc);
    ck(lbl, buf && *len >= 44 && *(u32*)buf == 0x33555255u && *(u64*)(buf + 12) == o->expect_desc);
    /* readers: utxo_lsm_get through the mmap path and the asm path */
    for (int mm = 1; mm >= 0; mm--){
        lsm_mm_set_enabled(mm); unsigned long bad = 0;
        for (unsigned long i = 0; i < o->nlive; i++){ struct key* k = &o->live[i]; u64 v = 0; unsigned long h = 0, cb = 0, sl = 0; const u8* sp = 0;
            long r = utxo_lsm_get(&lst, u, k->txid, k->index, &v, &h, &cb, &sp, &sl);
            if (k->live ? (r != 1 || v != k->value || sl != 20 + (i % 20)) : r != 0){ if (bad < 3) printf("    key %lu: live=%d r=%ld v=%llu\n", i, k->live, r, (unsigned long long)v); bad++; } }
        for (unsigned long t = 0; t < o->ntomb; t++){ struct key* k = &o->tomb[t]; if (k->live == 2) continue; u64 v = 0; unsigned long h = 0, cb = 0, sl = 0; const u8* sp = 0;
            if (utxo_lsm_get(&lst, u, k->txid, k->index, &v, &h, &cb, &sp, &sl) != 0) bad++; }
        snprintf(lbl, sizeof lbl, "[%s] utxo_lsm_get (%s) resolves every live key and misses every tombstoned one", dir, mm ? "mmap path" : "asm path"); ck(lbl, bad == 0);
    }
    lsm_mm_set_enabled(1);
    /* the walk under gettxoutsetinfo */
    struct walkacc w = { 0, 0 }; u64 want = 0;
    for (unsigned long i = 0; i < o->nlive; i++) if (o->live[i].live){ u8 k36[36]; memcpy(k36, o->live[i].txid, 32); memcpy(k36 + 32, &o->live[i].index, 4); want += fold(k36, o->live[i].value); }
    long walked = utxo_lsm_walk(&lst, u, (void*)walk_cb, &w);
    snprintf(lbl, sizeof lbl, "[%s] utxo_lsm_walk visits exactly the %lu live keys", dir, o->expect_live);
    ck(lbl, walked == (long)o->expect_live && w.n == o->expect_live && w.sum == want);
    utxo_lsm_close(&lst); free(u); free(blob); free(lst.tomb_buf); free(lst.manifest_buf); free(lst.scratch_buf);
    if (chdir("..") != 0){ printf("  FAIL chdir ..\n"); fails++; }
    return buf;
}

int main(void){
    tt_isolate();
    for (int i = 0; i < 40; i++) script[i] = (u8)(0x80 + i);
    static const unsigned long sizes[] = { 1, 2, 255, 256, 4097, 100000 };
    for (unsigned s = 0; s < sizeof sizes / sizeof *sizes; s++){
        unsigned long N = sizes[s]; rs = 0x5EED0000 + N; struct ops o = gen(N);
        printf("== %lu descriptors: %lu live (%lu after deletes) + %lu tombstones ==\n", N, o.nlive, o.expect_live, o.ntomb);
        char dm[32], dr[32]; snprintf(dm, sizeof dm, "merge_%lu", N); snprintf(dr, sizeof dr, "radix_%lu", N);
        size_t lm = 0, lr = 0; u8* bm = run_one(dm, 0, N, &o, &lm); u8* br = run_one(dr, 1, N, &o, &lr);
        char lbl[128]; snprintf(lbl, sizeof lbl, "radix run == merge run, byte for byte (%zu bytes)", lm);
        int same = bm && br && lm == lr && memcmp(bm, br, lm) == 0; ck(lbl, same);
        if (bm && br && !same){ size_t k = 0; while (k < lm && k < lr && bm[k] == br[k]) k++; printf("    sizes %zu vs %zu, first difference at byte %zu\n", lm, lr, k); }
        free(bm); free(br); free(o.live); free(o.tomb);
    }
    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
