/* tests/test_utxo_probe_diff.c -- the memtable's put/get/del answers, with
 * the prefetch that walks the probe sequence ahead of them, are exactly a
 * reference hash map's answers, and the table's bytes do not depend on
 * which prefetch (if any) ran.
 *
 * WHY THIS EXISTS
 *   bench_utxo_probe (2026-09-06) showed a utxo_get at 2^26 slots is bound
 *   by the lines the probe walks, and that warming them a phase ahead --
 *   utxo_prefetch now covers UTXO_PREFETCH_LINES lines instead of two --
 *   takes a 75%-load miss from ~105 ns to ~60-75 (16 keys ahead) and
 *   ~104 to ~91 (4,096 keys ahead, a block). A prefetch is a hint with
 *   no architectural effect, so this cannot change an answer; a test that
 *   only asserts that would pass against anything. What this test pins is
 *   the whole probe contract the prefetch sits in front of, against an
 *   independent reference, on workloads that exercise the parts a probe
 *   change would break first:
 *     - keys that collide, get deleted (backward-shift, no tombstones),
 *       get re-inserted, and get looked up while the gap moves;
 *     - a FULL table: put reports 2, an absent get/del reports 0 rather
 *       than spinning (test_utxo_probe_bound's finding), then deletes
 *       reopen it and everything still resolves;
 *     - duplicate puts (0), double deletes (0), value/height/coinbase/
 *       script bytes read back exactly.
 *   Three arms run the same seeded workload: no prefetch, the legacy
 *   two-line prefetch (utxo_prefetch_n(...,2), the 2026-08-23 body, kept
 *   as the seam), and utxo_prefetch. Every arm's answer stream must match
 *   the reference, and the three tables' bytes must be identical at the
 *   end. The negative control is the legacy seam: if the new prefetch
 *   ever diverged from a pure hint, the arms would disagree.
 *
 *   Watched to fail first (2026-09-06) against three scratch builds of
 *   bitcoin_utxo.asm: utxo_prefetch_n storing one byte into the home slot's
 *   pad (the arms' tables diverged: 3 FAILs); utxo_get comparing only the
 *   first 8 txid bytes, a tag-only compare (the colliding 2k/2k+1 pairs
 *   resolved to each other's records: 4,171-73,984 mismatches per size);
 *   utxo_del opening the gap without the backward shift (23,587-421,714
 *   mismatches and the live counts disagreed). A fourth, `jae`->`ja` on
 *   the shift's distance test, was NOT caught -- and is not a bug: the two
 *   distances can only be equal when i == j, which the loop never visits.
 *
 * Usage: ./test_utxo_probe_diff [--big]   (--big adds 2^22 slots; manual) */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;

extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_put(void* u, const u8 txid[32], unsigned long index, u64 value,
                     unsigned long height, unsigned long is_coinbase,
                     const u8* script, unsigned long slen);
extern long utxo_get(void* u, const u8 txid[32], unsigned long index, u64* value,
                     unsigned long* height, unsigned long* is_coinbase,
                     const u8** script, unsigned long* slen);
extern long utxo_del(void* u, const u8 txid[32], unsigned long index);
extern long utxo_count(void* u);
extern void utxo_prefetch(void* u, const u8 txid[32], unsigned long index);
extern void utxo_prefetch_n(void* u, const u8 txid[32], unsigned long index, unsigned long lines);

static int checks, fails;
static void ok(int c, const char* m){ checks++; if (!c) fails++; printf("  %s %s\n", c ? "ok  :" : "FAIL:", m); }

/* ---- reference: chained hash map over the 36-byte key ---- */
struct rnode { struct rnode* next; u8 key[36]; u64 value; u32 height; u8 cb; u8 slen; u8 script[40]; };
struct ref { struct rnode** b; u64 nb, n; };
static u64 rhash(const u8* k){ u64 h = 1469598103934665603ULL; for (int i = 0; i < 36; i++){ h ^= k[i]; h *= 1099511628211ULL; } return h; }
static void ref_init(struct ref* r, u64 nb){ r->b = calloc(nb, sizeof *r->b); r->nb = nb; r->n = 0; }
static struct rnode* ref_find(struct ref* r, const u8* k){ for (struct rnode* p = r->b[rhash(k) % r->nb]; p; p = p->next) if (!memcmp(p->key, k, 36)) return p; return 0; }
static int ref_put(struct ref* r, const u8* k, u64 v, u32 h, u8 cb, const u8* s, u8 sl){
    if (ref_find(r, k)) return 0;
    struct rnode* p = calloc(1, sizeof *p); memcpy(p->key, k, 36); p->value = v; p->height = h; p->cb = cb; p->slen = sl; memcpy(p->script, s, sl);
    u64 i = rhash(k) % r->nb; p->next = r->b[i]; r->b[i] = p; r->n++; return 1;
}
static int ref_del(struct ref* r, const u8* k){
    struct rnode** pp = &r->b[rhash(k) % r->nb];
    for (; *pp; pp = &(*pp)->next) if (!memcmp((*pp)->key, k, 36)){ struct rnode* d = *pp; *pp = d->next; free(d); r->n--; return 1; }
    return 0;
}
static void ref_free(struct ref* r){ for (u64 i = 0; i < r->nb; i++){ struct rnode* p = r->b[i]; while (p){ struct rnode* n = p->next; free(p); p = n; } } free(r->b); }

/* ---- keys: a small universe so collisions, re-inserts and double
 * deletes are frequent; key i is deterministic ---- */
static u64 splitmix64(u64* s){ u64 z = (*s += 0x9E3779B97F4A7C15ULL); z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL; z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL; return z ^ (z >> 31); }
static void key_of(u64 i, u8 key[36]){
    /* keys 2k and 2k+1 share txid[0..7] AND index, so they hash to the same
     * home slot and only the txid tail tells them apart: the 32-byte compare
     * after the index match is exercised on every such pair */
    u64 s = (i & ~1ULL) * 0x9E3779B97F4A7C15ULL + 12345; u64 w;
    for (int k = 0; k < 4; k++){ w = splitmix64(&s); memcpy(key + 8*k, &w, 8); }
    w = splitmix64(&s); u32 index = (u32)__builtin_ctzll(w | (1ULL << 20)); memcpy(key + 32, &index, 4);
    if (i & 1) key[31] ^= 0x5A;
}
static u32 key_index(const u8* key){ u32 i; memcpy(&i, key + 32, 4); return i; }

/* ---- one arm: the seeded workload against one table, answers folded into
 * a running hash; every answer also checked against the reference ---- */
struct arm { void* u; u8* blob; u64 tsz, bsz; };
static void arm_init(struct arm* a, u64 slots, u64 bsz){
    a->tsz = utxo_struct_size(slots); a->bsz = bsz;
    a->u = calloc(1, a->tsz); a->blob = calloc(1, bsz);
    utxo_init(a->u, slots, a->blob, bsz);
}
static u64 fold(u64 h, u64 v){ h ^= v; h *= 0x100000001B3ULL; return h; }

/* mode 0: no prefetch; 1: legacy two-line seam; 2: utxo_prefetch */
static u64 run_arm(struct arm* a, struct ref* r, int mode, u64 slots, u64 universe, u64 ops, u64 seed, int fill_full, u64* mism){
    u64 s = seed, h = 0xC0FFEEULL; u8 key[36]; u8 script[40]; for (int i = 0; i < 40; i++) script[i] = (u8)(0xA0 + i);
    u64 v; unsigned long ht, cb, sl; const u8* sp;
#define PF(k) do { if (mode == 1) utxo_prefetch_n(a->u, k, key_index(k), 2); else if (mode == 2) utxo_prefetch(a->u, k, key_index(k)); } while (0)
#define CHECK_GET(k) do { PF(k); long g = utxo_get(a->u, k, key_index(k), &v, &ht, &cb, &sp, &sl); struct rnode* p = ref_find(r, k); \
        int good = p ? (g == 1 && v == p->value && ht == p->height && cb == p->cb && sl == p->slen && !memcmp(sp, p->script, sl)) : (g == 0); \
        if (!good){ (*mism)++; } h = fold(h, (u64)g); if (g){ h = fold(fold(h, v), sl); } } while (0)
    for (u64 op = 0; op < ops; op++){
        u64 w = splitmix64(&s); u64 i = (w >> 8) % universe; key_of(i, key);
        int kind = (int)(w & 7);   /* 0-2 put, 3-5 get, 6-7 del */
        if (kind <= 2){
            u64 val = w ^ i; u32 hgt = (u32)(w >> 20) & 0xFFFFF; u8 c = (u8)((w >> 41) & 1); u8 sln = (u8)(1 + ((w >> 44) % 40));
            long rr = utxo_put(a->u, key, key_index(key), val, hgt, c, script, sln);
            int ex = ref_find(r, key) ? 0 : 1;
            if (rr == 2){ if (r->n != slots){ (*mism)++; } h = fold(h, 2); }           /* full: only legal when every slot is live */
            else { if (rr != ex){ (*mism)++; } if (rr == 1){ ref_put(r, key, val, hgt, c, script, sln); } h = fold(h, (u64)rr); }
        } else if (kind <= 5){
            CHECK_GET(key);
        } else {
            PF(key); long rr = utxo_del(a->u, key, key_index(key)); int ex = ref_del(r, key);
            if (rr != ex){ (*mism)++; } h = fold(h, (u64)rr + 4);
        }
        if ((u64)utxo_count(a->u) != r->n) (*mism)++;
    }
    if (fill_full){
        /* drive the table to FULL with keys outside the workload's universe,
         * then probe absent keys (must terminate: 0), then reopen it */
        u64 extra = 0, kf;
        for (kf = universe; r->n < slots; kf++){ key_of(kf, key); if (ref_find(r, key)) continue;
            long rr = utxo_put(a->u, key, key_index(key), kf, 7, 0, script, 3); if (rr != 1){ (*mism)++; break; } ref_put(r, key, kf, 7, 0, script, 3); extra++; }
        h = fold(h, extra);
        key_of(kf + 1, key); long rr = utxo_put(a->u, key, key_index(key), 1, 1, 0, script, 1); if (rr != 2){ (*mism)++; } h = fold(h, (u64)rr);
        for (int t = 0; t < 8; t++){ key_of(kf + 2 + t, key); if (ref_find(r, key)) continue; CHECK_GET(key); PF(key); if (utxo_del(a->u, key, key_index(key)) != 0) (*mism)++; }
        for (u64 j = 0; j < universe; j++){ key_of(j, key); CHECK_GET(key); }       /* every live key still resolves on the full table */
        for (u64 j = universe; j < kf; j += 3){ key_of(j, key); PF(key); long d = utxo_del(a->u, key, key_index(key)); if (d != ref_del(r, key)){ (*mism)++; } h = fold(h, (u64)d); }
        for (u64 j = 0; j < kf + 16; j++){ key_of(j, key); CHECK_GET(key); }        /* after the gaps moved: everything, present or not */
    }
    /* final sweep over the whole universe: present and absent alike */
    for (u64 j = 0; j < universe; j++){ key_of(j, key); CHECK_GET(key); }
#undef CHECK_GET
#undef PF
    return h;
}

static int run_size(int log2slots, u64 ops, int fill_full){
    u64 slots = 1ULL << log2slots, universe = slots * 3 / 4, bsz = (ops + slots) * 64 + 4096;
    printf("== 2^%d slots, universe %lu keys, %lu ops%s ==\n", log2slots, universe, ops, fill_full ? ", then FULL" : "");
    struct arm a[3]; struct ref r[3]; u64 h[3], mism[3] = {0, 0, 0};
    for (int m = 0; m < 3; m++){ arm_init(&a[m], slots, bsz); ref_init(&r[m], slots * 2 + 17); h[m] = run_arm(&a[m], &r[m], m, slots, universe, ops, 0x5EED + log2slots, fill_full, &mism[m]); }
    static const char* nm[3] = {"no prefetch", "legacy 2-line seam", "utxo_prefetch"};
    for (int m = 0; m < 3; m++){ char b[96]; snprintf(b, sizeof b, "%s: every answer matches the reference (%lu mismatches)", nm[m], mism[m]); ok(mism[m] == 0, b); }
    ok(h[0] == h[1] && h[1] == h[2], "the three arms' answer streams are identical");
    /* the table header's +16 is the blob POINTER, different per arm by
     * construction; everything else -- n, mask, cap, fill, every slot -- must match */
    ok(!memcmp(a[0].u, a[1].u, 16) && !memcmp(a[1].u, a[2].u, 16)
       && !memcmp((u8*)a[0].u + 24, (u8*)a[1].u + 24, a[0].tsz - 24) && !memcmp((u8*)a[1].u + 24, (u8*)a[2].u + 24, a[0].tsz - 24),
       "the three tables are byte-identical (slots, fill, count)");
    ok(!memcmp(a[0].blob, a[1].blob, bsz) && !memcmp(a[1].blob, a[2].blob, bsz), "the three blobs are byte-identical");
    ok(r[0].n == r[1].n && r[1].n == r[2].n && (u64)utxo_count(a[2].u) == r[2].n, "live counts agree");
    for (int m = 0; m < 3; m++){ free(a[m].u); free(a[m].blob); ref_free(&r[m]); }
    return 0;
}

int main(int argc, char** argv){
    int big = argc > 1 && !strcmp(argv[1], "--big");
    run_size(10, 20000, 1);
    run_size(14, 200000, 1);
    run_size(16, 400000, 0);
    if (big) run_size(22, 4000000, 0);
    printf("%s: %d checks, %d failed\n", fails ? "FAIL" : "PASS", checks, fails);
    return fails ? 1 : 0;
}
