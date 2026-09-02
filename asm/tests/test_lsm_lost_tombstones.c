/* tests/test_lsm_lost_tombstones.c -- incident 2026-09-01: 2,596 spent coins
 * resurrected during the mainnet rebuild.
 *
 * What production did, eight times between 13:37 and 14:23 UTC:
 *   1. a memtable window of ~15k blocks flushed to a run under b3d47a9 (the
 *      1 MB write buffer), whose sparse-index samples were short by the
 *      buffered bytes, so lookups through that run missed;
 *   2. the next block's verification looked a prevout up through that run,
 *      missed, and REJECTed ("input references a missing/already-spent UTXO");
 *   3. daemon/main.c called utxo_live_recover() -- a full compaction -- and
 *      retried; the retry passed;
 *   4. afterwards the spends recorded by the block applied just before the
 *      flush were gone from the set: 471 at 539016, 491 at 428470, ...
 *
 * This test replays 1-3 at the store level and COUNTS the set after every
 * step, so it answers where the tombstones go. Two builds of the same file:
 *   - tests/test_lsm_lost_tombstones      shipped object (bc098fd+): every
 *                                          stage must be exact -- a regression gate;
 *   - tests/test_lsm_lost_tombstones_bad   tests/bitcoin_utxo_lsm_badsparse.o
 *                                          (the fix compiled out) with
 *                                          -DEXPECT_INCIDENT: must reproduce the
 *                                          trigger AND the loss, and reports the
 *                                          stage. A repro that stops reproducing
 *                                          is news, so it is gated too.
 *
 * Sets:  A = "old coins" flushed first (their own run)
 *        B = coins created in the window (in the flushed memtable)
 *        D ⊂ A = spends of old coins in the window (tombstones: DEL descriptors
 *                in the flushed run) -- the 471 of block 539016
 *        E ⊂ B = spends of window-created coins (memtable removals) */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
typedef unsigned long long u64;
typedef unsigned char u8;
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
extern long utxo_lsm_compact(void* lst);
extern long utxo_lsm_reload(void* lst, void* u);
extern long utxo_lsm_count(void* lst);
extern long utxo_lsm_walk(void* lst, void* u, void* cb, void* ctx);
extern void utxo_lsm_close(void* lst);
extern void lsm_mm_set_enabled(int on);

enum { NA = 40000, NB = 30000, ND = 3000, NE = 1000 };   /* A: ~3 MB run (several drains); B+D: ~2.3 MB run */
static int fails = 0;
static long g_expected = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static void make_txid(u8* t, unsigned i, u8 tag){ for (int j = 0; j < 32; j++) t[j] = (u8)(0x40 + j); t[0] = (u8)i; t[1] = (u8)(i >> 8); t[2] = (u8)(i >> 16); t[3] = tag; }
static long get1(struct lsm_state* lst, void* u, unsigned i, u8 tag){
    u8 t[32]; make_txid(t, i, tag);
    u64 v = 0; unsigned long h = 0, cb = 0, sl = 0; const u8* sp = 0;
    return utxo_lsm_get(lst, u, t, i & 3, &v, &h, &cb, &sp, &sl);
}
/* D = A[i] for i % 13 == 0 (i < ND*13); E = B[i] for i % 29 == 0 (i < NE*29) */
static int in_D(unsigned i){ return i % 13 == 0 && i < ND * 13; }
static int in_E(unsigned i){ return i % 29 == 0 && i < NE * 29; }
static void walk_cb(void* ctx, const u8 key36[36], u64 value, u64 code, const u8* script, u64 slen){
    (void)value; (void)code; (void)script; (void)slen; (void)key36; (*(long*)ctx)++;
}
typedef struct { long missB, resD, missA, foundE, walk, count; } probe_t;
static int g_stage4 = 0;   /* once the stage-4 dels are in, F/G coins are legitimately gone */
static int in_F(unsigned i){ return g_stage4 && i % 31 == 1 && !in_E(i); }
static int in_G(unsigned i){ return g_stage4 && i % 37 == 1 && !in_D(i); }
static probe_t probe(struct lsm_state* lst, void* u, const char* stage, int mm){
    probe_t p; memset(&p, 0, sizeof p);
    lsm_mm_set_enabled(mm);
    for (unsigned i = 0; i < NB; i++) if (!in_E(i) && !in_F(i) && get1(lst, u, i, 'B') != 1) p.missB++;
    for (unsigned i = 0; i < NB; i++) if (in_E(i) && get1(lst, u, i, 'B') == 1) p.foundE++;
    for (unsigned i = 0; i < NA; i++){ long r = get1(lst, u, i, 'A'); if (in_D(i)) { if (r == 1) p.resD++; } else if (!in_G(i) && r != 1) p.missA++; }
    lsm_mm_set_enabled(1);
    long n = 0; if (utxo_lsm_walk(lst, u, (void*)walk_cb, &n) < 0) n = -1; p.walk = n;
    p.count = utxo_lsm_count(lst);
    printf("  [%s%s] B missing=%ld (of %d)  D resurrected=%ld (of %d)  E found=%ld (of %d)  A(other) missing=%ld  walk=%ld count=%ld expected=%ld\n",
           stage, mm ? "" : ",asm-path", p.missB, NB - NE, p.resD, ND, p.foundE, NE, p.missA, p.walk, p.count, g_expected);
    return p;
}
int main(void){
    char tmpl[] = "/tmp/lsmtombXXXXXX"; char* dir = mkdtemp(tmpl);
    if (!dir || chdir(dir) != 0) { printf("FAIL tmpdir\n"); return 1; }
    enum { SLOTS = 131072, TOMBS = 8192 };
    void* blob = malloc(32u << 20); void* u = malloc(utxo_struct_size(SLOTS)); utxo_init(u, SLOTS, blob, 32u << 20);
    struct lsm_state lst; memset(&lst, 0, sizeof lst);
    lst.op_threshold = 100000000ULL; lst.fill_threshold = SLOTS;   /* explicit flushes only, like a bulk window */
    lst.tomb_buf = malloc(TOMBS * 36); lst.tomb_cap = TOMBS; lst.manifest_buf = malloc(512 * 16); lst.manifest_cap = 512;
    lst.scratch_cap = (u64)(SLOTS + TOMBS) * 128 + 8 * 1024 * 1024 + 65536; lst.scratch_buf = malloc(lst.scratch_cap);
    ck("lsm_init", utxo_lsm_init(&lst) == 1);
    u8 script[48]; for (int j = 0; j < 48; j++) script[j] = (u8)(0x80 + j);
    const char* slenv = getenv("SCRIPTLEN"); int fixed_slen = slenv ? atoi(slenv) : 0;   /* 0 = 20..39 varied (default) */
#define SLEN(i) (fixed_slen ? (unsigned)fixed_slen : 20 + ((i) % 20))
    const int expected = NA - ND + NB - NE; g_expected = expected;
#ifdef EXPECT_INCIDENT
    printf("== object: tests/bitcoin_utxo_lsm_badsparse.o (b3d47a9's sparse samples) -- expecting the incident ==\n");
#else
    printf("== object: shipped bitcoin_utxo_lsm.o -- expecting exactness at every stage ==\n");
#endif
    /* ---- the old runs: A, flushed cleanly-shaped (this flush is also buggy under _bad,
     * which is faithful: every run of the rebuild was written by the same object) ---- */
    for (unsigned i = 0; i < NA; i++){ u8 t[32]; make_txid(t, i, 'A');
        if (utxo_lsm_put(&lst, u, t, i & 3, 1000ULL + i, 100 + i, 0, script, SLEN(i)) != 1) { printf("FAIL put A %u\n", i); return 1; } }
    ck("flush A -> run 1", utxo_lsm_flush(&lst, u) != -1 && lst.manifest_n == 1);
    /* ---- the window: B created, D (old coins) spent, E (window coins) spent ---- */
    for (unsigned i = 0; i < NB; i++){ u8 t[32]; make_txid(t, i, 'B');
        if (utxo_lsm_put(&lst, u, t, i & 3, 5000ULL + i, 50000 + i, 0, script, SLEN(i)) != 1) { printf("FAIL put B %u\n", i); return 1; } }
    long dels = 0;
    for (unsigned i = 0; i < NA; i++) if (in_D(i)){ u8 t[32]; make_txid(t, i, 'A'); if (utxo_lsm_del(&lst, u, t, i & 3) != 1) { printf("FAIL del D %u\n", i); return 1; } dels++; }
    for (unsigned i = 0; i < NB; i++) if (in_E(i)){ u8 t[32]; make_txid(t, i, 'B'); if (utxo_lsm_del(&lst, u, t, i & 3) != 1) { printf("FAIL del E %u\n", i); return 1; } dels++; }
    ck("window applied: 3000 old-coin spends + 1000 window-coin spends", dels == ND + NE);
    probe_t s0 = probe(&lst, u, "before flush (memtable)", 1);
#ifdef EXPECT_INCIDENT
    ck("before the flush the walk and counter are exact (run 1 was written by the bad object too, so its point lookups already miss)", s0.walk == expected && s0.count == expected);
#else
    ck("before the flush the set is exact", s0.missB == 0 && s0.resD == 0 && s0.foundE == 0 && s0.missA == 0 && s0.walk == expected && s0.count == expected);
#endif
    /* ---- step 1: the flush that ends the window ---- */
    ck("flush window -> run 2", utxo_lsm_flush(&lst, u) != -1 && lst.manifest_n == 2);
    probe_t s1 = probe(&lst, u, "after flush", 1);
    probe_t s1a = probe(&lst, u, "after flush", 0);
    /* ---- stage 4 (moved): what block 539016 did AFTER the flush point, BEFORE the recovery compaction -- spend coins that
     * already live in a run (memtable miss on del: the tombstone is the only record).
     * F = B[i] for i % 31 == 1 (window coins, in the merged run), G = A[i] for i % 37 == 1.
     * Then the two things production did next: a full compaction, and a reload. ---- */
    long nF = 0, nG = 0;
    for (unsigned i = 0; i < NB; i++) if (i % 31 == 1 && !in_E(i)){ u8 t[32]; make_txid(t, i, 'B'); if (utxo_lsm_del(&lst, u, t, i & 3) != 1){ printf("FAIL del F %u\n", i); return 1; } nF++; }
    for (unsigned i = 0; i < NA; i++) if (i % 37 == 1 && !in_D(i)){ u8 t[32]; make_txid(t, i, 'A'); if (utxo_lsm_del(&lst, u, t, i & 3) != 1){ printf("FAIL del G %u\n", i); return 1; } nG++; }
    printf("  stage 4: %ld post-flush spends of run-resident coins recorded (tomb_n=%lu, WAL log_len=%llu)\n", nF + nG, (unsigned long)lst.tomb_n, (unsigned long long)lst.log_len);
    g_stage4 = 1; g_expected = expected - nF - nG;
    #define COUNT_FG(label) do { long fF = 0, fG = 0; \
        for (unsigned i = 0; i < NB; i++) if (i % 31 == 1 && !in_E(i) && get1(&lst, u, i, 'B') == 1) fF++; \
        for (unsigned i = 0; i < NA; i++) if (i % 37 == 1 && !in_D(i) && get1(&lst, u, i, 'A') == 1) fG++; \
        long n = 0; utxo_lsm_walk(&lst, u, (void*)walk_cb, &n); \
        printf("  [%s] F resurrected=%ld of %ld  G resurrected=%ld of %ld  walk=%ld count=%ld expected=%ld\n", label, fF, nF, fG, nG, n, utxo_lsm_count(&lst), (long)expected - nF - nG); \
        s4_res += fF + fG; s4_walk_bad += (n != (long)expected - nF - nG); } while (0)
    long s4_res = 0, s4_walk_bad = 0;
    COUNT_FG("stage4 dels done, run 2 still bad");
    /* ---- step 2: what the next block's verification saw (B lookups) is s1.missB ---- */
    /* ---- step 3: utxo_live_recover() == compaction, then the retry ---- */
    long cr = utxo_lsm_compact(&lst);
    printf("  compact -> result=%ld manifest_n=%lu\n", cr, (unsigned long)lst.manifest_n);
    ck("compaction merged 2 -> 1", cr == 1 && lst.manifest_n == 1);
    probe_t s2 = probe(&lst, u, "after compaction", 1);
    /* ---- the 14:23 restart: reload from disk ---- */
    ck("reload", utxo_lsm_reload(&lst, u) >= 0);
    probe_t s3 = probe(&lst, u, "after reload", 1);
    COUNT_FG("stage4 after the recovery compaction + retry window");
    ck("stage 4: compaction (nothing to merge with one run is fine)", utxo_lsm_compact(&lst) >= 0);
    COUNT_FG("stage4 after compaction");
    ck("stage 4: flush (tombstones -> DEL descriptors)", utxo_lsm_flush(&lst, u) != -1);
    COUNT_FG("stage4 after flush");
    ck("stage 4: compaction 2 -> 1", utxo_lsm_compact(&lst) == 1);
    COUNT_FG("stage4 after 2nd compaction");
    ck("stage 4: reload", utxo_lsm_reload(&lst, u) >= 0);
    COUNT_FG("stage4 after reload");
    ck("stage 4: no post-flush spend of a run-resident coin ever came back", s4_res == 0);
    ck("stage 4: walk exact at every step", s4_walk_bad == 0);
#ifdef EXPECT_INCIDENT
    ck("TRIGGER reproduced: lookups through the freshly flushed run miss (the REJECT)", s1.missB > 0 || s1a.missB > 0);
    long lost = s2.resD > s3.resD ? s2.resD : s3.resD;
    ck("lookups through the bad run resurrect tombstoned coins (the lie the daemon acted on)", s1.resD > 0 || s1a.resD > 0);
    ck("the set on disk is nevertheless exact after compaction and reload (the store never lost a record)", s2.walk == expected - nF - nG && s3.walk == expected - nF - nG && lost == 0);
    printf("  FINDING: through the bad run, %ld of %d tombstoned coins READ BACK AS LIVE (the DEL in run 2 is missed, run 1's PUSH shows through) and %ld of %d window coins are MISSING; the walk stays exact (%ld/%ld/%ld) -- the store never loses a record, only point lookups lie. The daemon-level test shows what a lying lookup does to a spend.\n",
           s1.resD, ND, s1.missB, NB - NE, s1.walk, s2.walk, s3.walk);
#else
    ck("shipped object: no misses through the flushed run (mmap path)", s1.missB == 0 && s1.missA == 0);
    ck("shipped object: no misses through the flushed run (asm path)", s1a.missB == 0 && s1a.missA == 0);
    ck("shipped object: no spend resurrected at any stage", s1.resD == 0 && s1a.resD == 0 && s2.resD == 0 && s3.resD == 0);
    ck("shipped object: walk exact at every stage", s1.walk == expected && s2.walk == expected - nF - nG && s3.walk == expected - nF - nG);
    ck("shipped object: counter exact at every stage", s1.count == expected && s2.count == expected - nF - nG && s3.count == expected - nF - nG);
#endif
    utxo_lsm_close(&lst);
    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
