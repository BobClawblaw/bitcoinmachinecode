/* tests/test_utxo_tiered_compact.c -- UTXO_CACHE_MODEL_SCOPE.md section 4.2:
 * a compaction rewrites O(recent), not O(set).
 *
 * The all-runs-to-one merge (utxo_lsm_compact) rewrites the entire live set
 * every time the run count trips the threshold, so on a growing set the
 * bytes written per compaction grow with the set while the cadence stays
 * fixed. The size-tiered policy (lsm_compact_pick + utxo_lsm_compact_range,
 * 2026-08-31) merges only the newest runs -- a run joins the batch while it
 * is at most LSM_COMPACT_RATIO times everything newer than it -- and leaves
 * the oldest, largest run alone until the merged younger tier has grown to
 * a quarter of it. A tail merge has runs BELOW it, so its tombstones must
 * survive into the output: a DEL in the batch may be the only thing standing
 * between a lookup and a stale PUSH in the base.
 *
 * This test builds a GROWING set through the real flush path (mac_flush,
 * via utxo_lsm_flush) with runs of known size, applies the same policy the
 * daemon applies (compact_pick_now in daemon/utxo_live.c is
 * lsm_compact_pick_budget over the run files' sizes), and checks, at every
 * compaction:
 *   - the batch is exactly the tier the policy names: it ends at the newest
 *     run, the runs below it keep their identity (run_no) and their bytes,
 *     and the run just below the batch dwarfs the batch (ratio rule); when
 *     the base IS rewritten, the young tier had reached a quarter of it;
 *   - bytes written (the output run's size) are bounded by the batch's own
 *     input bytes (plus the bloom rounding), never by the total on disk;
 *   - the whole live set is still exact: utxo_lsm_walk visits precisely the
 *     model's live keys with their current values, and utxo_lsm_get finds
 *     every live key and NONE of the deleted ones -- through every tier.
 * The deletions are the tombstone cases of test_lsm_lost_tombstones /
 * test_utxo_lost_tombstones extended across tiers: spends of base-resident
 * coins, of coins in every middle tier, of coins created in the same
 * generation; reorg-shaped keys (PUT, DEL, PUT again, DEL again in four
 * different generations); and BIP30-shaped keys (PUT, PUT again with a new
 * value in a later generation, DEL later still) -- the shape where dropping
 * a tombstone that cancels a put INSIDE the batch would resurrect the older
 * copy below it.
 *
 * NEGATIVE CONTROL: the same workload, same seeds, in a second directory
 * under the all-runs-to-one policy. Every compaction there merges the whole
 * manifest and writes the whole set; it must end with the SAME live set
 * (walk count and an order-independent digest of every entry), and its
 * total bytes written must exceed the tiered policy's by a wide margin. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include "test_tmpdir.h"
#include "lsm_state.h"
#include "lsm_manifest.h"

typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;
extern long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long long blob_cap);
extern int  utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const u8 txid[32], u32 index, unsigned long long value,
                         unsigned long long height, unsigned long long is_cb, const u8* script, unsigned long slen);
extern long utxo_lsm_del(void* lst, void* u, const u8 txid[32], u32 index);
extern long utxo_lsm_get(void* lst, void* u, const u8 txid[32], u32 index, unsigned long long* value,
                         unsigned long* height, unsigned long* is_coinbase, const u8** script, unsigned long* slen);
extern long utxo_lsm_flush(void* lst, void* u);
extern long utxo_lsm_walk(void* lst, void* u, void* cb, void* ctx);
extern long utxo_lsm_compact(void* lst);
extern long utxo_lsm_compact_range(void* lst, unsigned long lo, unsigned long k);
extern void utxo_lsm_close(void* lst);
#define BLOOM_MAX_BYTES (4*1024*1024)
#define SCRIPT_MAX_BYTES 65536

/* ---- workload shape ------------------------------------------------------ */
enum { GENS = 160,            /* flushes = runs built */
       PUTS = 4000,           /* fresh coins per generation: ~350 KB runs */
       DELS = 200,            /* spends per generation, aimed at every tier */
       REORG = 8,             /* PUT/DEL/PUT/DEL keys started per generation */
       OVERW = 8,             /* PUT/PUT(new value)/DEL keys started per generation */
       THRESHOLD = 4,         /* compact when the run count reaches this */
       NKEYS = GENS * PUTS };
enum { KEY_TAG = 0x7a };
static u8  alive[NKEYS];
static u64 model_val[NKEYS];
static long dead_list[NKEYS]; static long ndead = 0;   /* every key ever deleted (some re-created later) */
static u32 touched[NKEYS]; static u32 cur_gen_stamp = 0;   /* keys already picked in the current generation */
static u32 rng_state = 12345;
static u32 rnd(void){ rng_state = rng_state * 1664525u + 1013904223u; return rng_state >> 8; }
static void mk_txid(u8 txid[32], long i){ memset(txid, 0, 32); memcpy(txid, &i, sizeof i); txid[31] = KEY_TAG; }
static u32 key_index(long i){ return (u32)(i & 3); }
static u8 g_spk[34];

static int fails = 0;
static void ok(int c, const char* w){ printf("  %s %s\n", c ? "ok " : "FAIL", w); if (!c) fails++; }

/* ---- run-file arithmetic ------------------------------------------------- */
static u64 entry_run(struct lsm_state* l, u64 i){ u64 r; memcpy(&r, (char*)l->manifest_buf + i*16 + 8, 8); return r; }
static u64 fsize(u64 run_no){ char n[64]; snprintf(n, sizeof n, "utxo_run_%06u.dat", (unsigned)run_no); struct stat sb; return stat(n, &sb) == 0 ? (u64)sb.st_size : 0; }
/* bloom bytes of a run (header: magic 4, gen 8, nrec 8, bloom_bits 8, sparse_off 8, sparse_n 8) */
static u64 bloom_bytes(u64 run_no){
    char n[64]; snprintf(n, sizeof n, "utxo_run_%06u.dat", (unsigned)run_no);
    FILE* f = fopen(n, "rb"); if (!f) return 0;
    unsigned char h[44]; size_t got = fread(h, 1, 44, f); fclose(f);
    if (got != 44) return 0;
    u64 bits; memcpy(&bits, h + 20, 8); return bits / 8;
}
static void sizes_now(struct lsm_state* l, u64* sizes){ for (u64 i = 0; i < l->manifest_n; i++) sizes[i] = fsize(entry_run(l, i)); }

/* ---- the store -------------------------------------------------------------- */
typedef struct { struct lsm_state lst; void* table; } store_t;
static void store_open(store_t* s){
    unsigned long slots = 1UL << 14;
    s->table = malloc((size_t)utxo_struct_size(slots)); void* blob = malloc(64UL << 20);
    utxo_init(s->table, slots, blob, 64UL << 20);
    memset(&s->lst, 0, sizeof s->lst);
    unsigned long long tomb_cap = slots * 2, desc_cap = slots * 3;
    /* the flush is ours to call (utxo_lsm_flush == mac_flush): thresholds
     * far above a generation's ops, so a run is exactly one generation */
    s->lst.op_threshold = 1ULL << 30; s->lst.fill_threshold = slots * 3 / 4;
    s->lst.tomb_buf = malloc(tomb_cap * 36); s->lst.tomb_cap = tomb_cap;
    s->lst.manifest_buf = malloc(256 * 16); s->lst.manifest_cap = 256;
    s->lst.scratch_cap = desc_cap * 128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES; s->lst.scratch_buf = malloc(s->lst.scratch_cap);
    if (utxo_lsm_init(&s->lst) != 1){ fprintf(stderr, "lsm init failed\n"); exit(1); }
}
static void put_key(store_t* s, long i, u64 value){
    u8 t[32]; mk_txid(t, i);
    if (utxo_lsm_put(&s->lst, s->table, t, key_index(i), value, 100 + (i % 50), 0, g_spk, 34) != 1){ fprintf(stderr, "put %ld failed\n", i); exit(1); }
}
static void del_key(store_t* s, long i){
    u8 t[32]; mk_txid(t, i);
    if (utxo_lsm_del(&s->lst, s->table, t, key_index(i)) != 1){ fprintf(stderr, "del %ld failed\n", i); exit(1); }
}
static int get_key(store_t* s, long i, u64* v){
    u8 t[32]; mk_txid(t, i); unsigned long h, cb, sl; const u8* sp; unsigned long long vv;
    long r = utxo_lsm_get(&s->lst, s->table, t, key_index(i), &vv, &h, &cb, &sp, &sl);
    if (r == 1){ *v = vv; if (sl != 34 || memcmp(sp, g_spk, 34) != 0) return -1; }
    return (int)r;
}

/* ---- the model: one deterministic script of operations ----------------------
 * Replayed identically for both stores; the model arrays are rebuilt each time. */
static long reorg_reput[GENS][REORG], reorg_redel[GENS][REORG], overw_del[GENS][OVERW];
static int  n_reput[GENS], n_redel[GENS], n_odel[GENS];
static void model_reset(void){
    memset(alive, 0, sizeof alive); memset(model_val, 0, sizeof model_val); memset(touched, 0, sizeof touched); ndead = 0; rng_state = 12345;
    memset(n_reput, 0, sizeof n_reput); memset(n_redel, 0, sizeof n_redel); memset(n_odel, 0, sizeof n_odel);
}
/* pick a live key from generation g (its PUTS keys) not yet touched in the
 * current generation (a second PUT of a memtable-resident key is a duplicate,
 * not a shadowing copy), or -1 */
static long pick_live_in_gen(long g){
    for (int tries = 0; tries < 16; tries++){
        long i = g * PUTS + (long)(rnd() % PUTS);
        if (alive[i] && touched[i] != cur_gen_stamp){ touched[i] = cur_gen_stamp; return i; }
    }
    return -1;
}
static void model_put(store_t* s, long i, u64 v){ put_key(s, i, v); alive[i] = 1; model_val[i] = v; }
static void model_del(store_t* s, long i){ del_key(s, i); alive[i] = 0; dead_list[ndead++] = i; }
/* one generation of operations, then the flush */
static long generation(store_t* s, long g){
    cur_gen_stamp = (u32)g + 1;
    for (long i = g * PUTS; i < (g + 1) * PUTS; i++) model_put(s, i, 1000 + (u64)i);
    /* spends aimed at every tier: the base (gen 0), the newest older runs, the middle, and this generation */
    for (int j = 0; j < DELS; j++){
        long tg; switch (j & 3){ case 0: tg = 0; break; case 1: tg = g - 1; break; case 2: tg = g / 2; break; default: tg = g; break; }
        if (tg < 0) tg = g;
        long i = pick_live_in_gen(tg); if (i >= 0) model_del(s, i);
    }
    /* reorg shape: coins from ~6 generations back die now, come back in g+2, die again in g+4 */
    if (g >= 6 && g + 4 < GENS) for (int j = 0; j < REORG; j++){
        long i = pick_live_in_gen(g - 6 + (long)(rnd() % 3)); if (i < 0) continue;
        model_del(s, i);
        reorg_reput[g + 2][n_reput[g + 2]++] = i;
    }
    for (int j = 0; j < n_reput[g]; j++){ long i = reorg_reput[g][j]; model_put(s, i, 5000 + (u64)i); reorg_redel[g + 2][n_redel[g + 2]++] = i; }
    for (int j = 0; j < n_redel[g]; j++) model_del(s, reorg_redel[g][j]);
    /* BIP30 shape: a live coin from 3 generations back is PUT again with a new
     * value (memtable miss -> a fresh PUSH that shadows the run below), then
     * deleted in g+2: the DEL must cancel BOTH copies */
    if (g >= 3 && g + 2 < GENS) for (int j = 0; j < OVERW; j++){
        long i = pick_live_in_gen(g - 3); if (i < 0) continue;
        model_put(s, i, 9000 + (u64)i);
        overw_del[g + 2][n_odel[g + 2]++] = i;
    }
    for (int j = 0; j < n_odel[g]; j++) if (alive[overw_del[g][j]]) model_del(s, overw_del[g][j]);
    u64 before = s->lst.manifest_n;
    if (utxo_lsm_flush(&s->lst, s->table) != 1){ fprintf(stderr, "flush %ld failed\n", g); exit(1); }
    return (long)(s->lst.manifest_n - before);
}

/* ---- checking the set --------------------------------------------------- */
typedef struct { long n, bad_key, bad_val, dup; u64 dsum, dxor; } walk_t;
static u8 seen[NKEYS];
static u64 mix(u64 h, u64 x){ h ^= x; h *= 0x9E3779B97F4A7C15ULL; h ^= h >> 29; return h; }
static void walk_cb(void* ctx, const u8 key36[36], u64 value, u64 code, const u8* script, u64 slen){
    walk_t* w = (walk_t*)ctx; w->n++;
    long i; memcpy(&i, key36, sizeof i); u32 idx; memcpy(&idx, key36 + 32, 4);
    u64 h = 0x1234567ULL; for (int k = 0; k < 36; k++) h = mix(h, key36[k]); h = mix(h, value); h = mix(h, code); h = mix(h, slen);
    for (u64 k = 0; k < slen; k++) h = mix(h, script[k]);
    w->dsum += h; w->dxor ^= h;
    if (i < 0 || i >= NKEYS || key36[31] != KEY_TAG || idx != key_index(i) || !alive[i]){ w->bad_key++; return; }
    if (value != model_val[i] || slen != 34) w->bad_val++;
    if (seen[i]) w->dup++;
    seen[i] = 1;
}
/* one key, whatever its state now: live keys must resolve to the model's value, dead keys must be dead */
static void tally_key(store_t* s, long i, long* missing, long* resurrected){
    u64 v; int r = get_key(s, i, &v);
    if (alive[i]){
        if (r != 1 || v != model_val[i]) (*missing)++;
    } else {
        if (r != 0) (*resurrected)++;
    }
}
/* full check: the walk is exactly the model, every dead key is dead through get, every live key resolves (sampled) */
static int check_set(store_t* s, const char* when, walk_t* out){
    walk_t w; memset(&w, 0, sizeof w); memset(seen, 0, sizeof seen);
    long r = utxo_lsm_walk(&s->lst, s->table, (void*)walk_cb, &w);
    long expected = 0; for (long i = 0; i < NKEYS; i++) expected += alive[i];
    long unseen = 0; for (long i = 0; i < NKEYS; i++) if (alive[i] && !seen[i]) unseen++;
    long resurrected = 0, missing = 0, wrong = 0;
    for (long d = 0; d < ndead; d++){ long i = dead_list[d]; if (alive[i]) continue; u64 v; if (get_key(s, i, &v) != 0) resurrected++; }
    for (long i = 0; i < NKEYS; i += 97){ if (!alive[i]) continue; u64 v; int g = get_key(s, i, &v); if (g != 1) missing++; else if (v != model_val[i]) wrong++; }
    /* the reorg and overwrite keys, every one of them, whatever their state now */
    for (long g = 0; g < GENS; g++){
        for (int j = 0; j < n_reput[g]; j++) tally_key(s, reorg_reput[g][j], &missing, &resurrected);
        for (int j = 0; j < n_odel[g]; j++)  tally_key(s, overw_del[g][j],  &missing, &resurrected);
    }
    int good = r == expected && w.n == expected && w.bad_key == 0 && w.bad_val == 0 && w.dup == 0 && unseen == 0 && resurrected == 0 && missing == 0 && wrong == 0;
    if (!good) printf("      %s: walk=%ld expected=%ld visited=%ld bad_key=%ld bad_val=%ld dup=%ld unseen=%ld resurrected=%ld missing=%ld wrong=%ld\n",
                      when, r, expected, w.n, w.bad_key, w.bad_val, w.dup, unseen, resurrected, missing, wrong);
    if (out) *out = w;
    return good;
}

/* ---- one policy over the whole workload ------------------------------------- */
typedef struct {
    long compactions, tail_merges, base_rewrites;
    u64  written, max_tail_out, max_tail_young, max_total_at_tail, final_bytes;
    long bad_range, bad_identity, bad_ratio, bad_bytes, bad_set, bad_count, bad_flush;
    long checks;
    walk_t final_walk;
} result_t;

static void run_policy(const char* dir, int tiered, result_t* R){
    memset(R, 0, sizeof *R);
    mkdir(dir, 0755); if (chdir(dir) != 0){ perror("chdir"); exit(1); }
    model_reset();
    store_t s; store_open(&s);
    static u64 sizes[256], bsizes[256], bruns[256];
    for (long g = 0; g < GENS; g++){
        if (generation(&s, g) != 1) R->bad_flush++;      /* exactly one run per generation */
        long n = (long)s.lst.manifest_n;
        if (n < THRESHOLD) continue;
        sizes_now(&s.lst, sizes);
        long lo = 0, k;
        if (tiered){ k = lsm_compact_pick_budget(sizes, n, THRESHOLD, 64, 0, &lo); if (k == 0) continue; }
        else { lo = 0; k = n; }
        /* snapshot before */
        u64 nb = s.lst.manifest_n; for (u64 i = 0; i < nb; i++){ bruns[i] = entry_run(&s.lst, i); bsizes[i] = sizes[i]; }
        u64 in_bytes = 0, in_bloom = 0, total = 0, young = 0;
        for (long i = 0; i < n; i++) total += sizes[i];
        for (long i = lo; i < n; i++){ in_bytes += sizes[i]; in_bloom += bloom_bytes(bruns[i]); }
        young = in_bytes;
        long cr = tiered ? utxo_lsm_compact_range(&s.lst, (unsigned long)lo, (unsigned long)k) : utxo_lsm_compact(&s.lst);
        if (cr <= 0){ fprintf(stderr, "compaction failed (%ld)\n", cr); exit(1); }
        R->compactions++;
        /* the batch ended at the newest run and left exactly lo+1 entries */
        if (lo + k != n || (long)s.lst.manifest_n != lo + 1) R->bad_range++;
        /* identity: entries below lo are the same files with the same bytes; entry lo is a new run */
        int same = 1; for (long i = 0; i < lo; i++) if (entry_run(&s.lst, (u64)i) != bruns[i] || fsize(bruns[i]) != bsizes[i]) same = 0;
        u64 out_run = entry_run(&s.lst, (u64)lo); for (long i = 0; i < n; i++) if (out_run == bruns[i]) same = 0;
        if (!same) R->bad_identity++;
        u64 out = fsize(out_run); R->written += out;
        /* bytes rewritten: bounded by the batch's own inputs (bloom rounding aside), not by the total */
        if (out > in_bytes + in_bloom) R->bad_bytes++;
        if (lo > 0){
            R->tail_merges++;
            if (out > R->max_tail_out) R->max_tail_out = out;
            if (young > R->max_tail_young) R->max_tail_young = young;
            if (total > R->max_total_at_tail) R->max_total_at_tail = total;
            /* the ratio rule: the run just below the batch dwarfs the batch */
            if (!(sizes[lo - 1] > (u64)LSM_COMPACT_RATIO * young)) R->bad_ratio++;
        } else {
            R->base_rewrites++;
            /* a base rewrite is only justified once the young tier reached a quarter of the base */
            if (tiered && n > 1 && !((u64)LSM_COMPACT_RATIO * (young - sizes[0]) >= sizes[0])) R->bad_ratio++;
        }
        if (!check_set(&s, tiered ? "tiered" : "classic", 0)) R->bad_set++;
        R->checks++;
        if (tiered) printf("      gen %3ld: %s [%ld..%ld) of %ld  in %6.2f MB -> out %6.2f MB  total on disk %6.2f MB\n",
                           g, lo ? "tail" : "base", lo, lo + k, n, in_bytes / 1048576.0, out / 1048576.0, total / 1048576.0);
    }
    if (!check_set(&s, "final", &R->final_walk)) R->bad_set++;
    R->checks++;
    for (u64 i = 0; i < s.lst.manifest_n; i++) R->final_bytes += fsize(entry_run(&s.lst, i));
    long expected = 0; for (long i = 0; i < NKEYS; i++) expected += alive[i];
    if (R->final_walk.n != expected) R->bad_count++;
    printf("      %s: %ld compactions (%ld tail, %ld base), %.1f MB written, final set %.1f MB in %lu run(s), %ld live keys, %ld checks\n",
           tiered ? "tiered " : "classic", R->compactions, R->tail_merges, R->base_rewrites, R->written / 1048576.0, R->final_bytes / 1048576.0,
           (unsigned long)s.lst.manifest_n, R->final_walk.n, R->checks);
    utxo_lsm_close(&s.lst);
    if (chdir("..") != 0) exit(1);
}

int main(void){
    tt_isolate();
    memset(g_spk, 0x61, 34); g_spk[0] = 0x51;
    result_t T, C;
    printf("== tiered: the newest runs by size ratio, tombstones kept ==\n");
    run_policy("tiered", 1, &T);
    ok(T.bad_flush == 0, "every generation flushed exactly one run (known sizes)");
    ok(T.compactions >= 20, "the growing set tripped the threshold many times");
    ok(T.bad_range == 0, "every batch ended at the newest run and collapsed to one entry");
    ok(T.bad_identity == 0, "the runs below every batch kept their identity and their bytes; the output is a new run");
    ok(T.tail_merges > T.base_rewrites, "most compactions were tail merges (the base was left alone)");
    ok(T.bad_ratio == 0, "the ratio rule held: a tail's neighbour below dwarfs it; the base is rewritten only once the young tier reaches a quarter of it");
    ok(T.bad_bytes == 0, "bytes written per compaction <= the batch's own input bytes (+ bloom rounding)");
    ok(T.max_tail_out * 4 <= T.max_total_at_tail, "a tail merge's output is under a quarter of what was on disk -- O(recent), not O(set)");
    ok(T.written <= 8 * T.final_bytes, "total bytes written by compaction stayed within 8x the final set");
    ok(T.bad_set == 0, "after every compaction the live set was exact: walk == model, every deleted key dead through every tier, every live key resolved");
    ok(T.bad_count == 0, "final walk count == the model's live count");
    printf("      tiered: max tail output %.2f MB (young tier %.2f MB) with %.1f MB on disk; %.2fx the final set written in all\n",
           T.max_tail_out / 1048576.0, T.max_tail_young / 1048576.0, T.max_total_at_tail / 1048576.0, (double)T.written / (double)T.final_bytes);

    printf("== negative control: all runs to one ==\n");
    run_policy("classic", 0, &C);
    ok(C.bad_flush == 0, "same generations, same runs");
    ok(C.compactions >= 20 && C.tail_merges == 0 && C.base_rewrites == C.compactions, "every compaction rewrote the base");
    ok(C.bad_range == 0 && C.bad_identity == 0 && C.bad_bytes == 0, "each merged the whole manifest into one new run");
    ok(C.bad_set == 0 && C.bad_count == 0, "and the set was exact there too (tombstones dropped only because nothing is below)");
    ok(C.final_walk.n == T.final_walk.n && C.final_walk.dsum == T.final_walk.dsum && C.final_walk.dxor == T.final_walk.dxor,
       "both policies end with the SAME live set (count and order-independent digest of every entry)");
    ok(C.written >= 3 * T.written, "the control wrote at least 3x the bytes the tiered policy wrote");
    printf("      classic: %.1f MB written (%.2fx the final set) vs tiered %.1f MB (%.2fx): ratio %.2f\n",
           C.written / 1048576.0, (double)C.written / (double)C.final_bytes, T.written / 1048576.0, (double)T.written / (double)T.final_bytes,
           (double)C.written / (double)(T.written ? T.written : 1));
    printf("\n%s (%d failure%s)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
