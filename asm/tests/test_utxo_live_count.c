/* test_utxo_live_count.c -- utxo_lsm_count() must return the EXACT number of
 * live UTXOs and survive restarts, the fix for the telemetry bug where
 * live_utxo went negative (live_utxo=-2610837) in production.
 *
 * Root cause (see bitcoin_utxo_lsm.asm): on reload total_live was re-derived
 * as u->n -- the current unflushed generation's memtable live count ONLY --
 * ignoring the tens of millions of UTXOs sitting in older flushed/compacted
 * runs. Seeded ~51M too low, every subsequent del of a pre-existing (older-
 * run) UTXO decremented past zero into the negatives.
 *
 * The fix persists an accurate total_live in the manifest (MAGIC_MANIFEST2)
 * and, on reload, either restores base+WAL-tail-delta (new format) or does a
 * one-time full dedup recount (old format / no persisted count).
 *
 * This test proves, against a reference model, that:
 *   (A) reload restores an EXACT count (this is the assertion that fails on
 *       the pre-fix code -- it undercounts to the memtable tail);
 *   (B) spending UTXOs that live only in older flushed runs decrements the
 *       count correctly and it NEVER goes negative;
 *   (C) a compaction cycle preserves the exact count;
 *   (D) an OLD-format manifest (no persisted count) reloads and RECOMPUTES
 *       the correct count, including an unflushed WAL tail (live memtable
 *       entries + tombstones shadowing older-run keys).
 *
 * Run in a throwaway temp dir (relative filenames, per build_utxo.c's chdir
 * convention).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "test_tmpdir.h"

extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_count(void* u);

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
extern long utxo_lsm_count(void* lst);
extern long utxo_lsm_reload(void* lst, void* u);
extern long utxo_lsm_compact(void* lst);
extern void utxo_lsm_close(void* lst);

/* Must mirror bitcoin_utxo_lsm.asm's state struct exactly (168 bytes). */
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

#define BLOOM_MAX_BYTES   (4*1024*1024)
#define SCRIPT_MAX_BYTES  65536

/* Small thresholds -> many flushes -> many runs, so most live UTXOs live in
 * OLDER runs, not the memtable tail. This is exactly the shape that made the
 * old reload seed (u->n) wildly wrong. */
#define SLOTS          1024
#define BLOB           (1<<20)
#define FILL_THRESHOLD 8
#define OP_THRESHOLD   16
#define TOMB_CAP       64
#define MANIFEST_CAP   4096
#define DESC_CAP       128
#define SCRATCH_CAP    ((unsigned long long)DESC_CAP*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES)

#define N 205

static int fails = 0;
static void ck(const char* l, long g, long e) {
    if (g == e) printf("ok  : %-52s (got %ld)\n", l, g);
    else { printf("FAIL: %-52s (got %ld exp %ld)\n", l, g, e); fails++; }
}
static void ckm(const char* l, int cond) { ck(l, cond, 1); }

static void make_txid(unsigned char* t, unsigned int i) {
    for (int j = 0; j < 32; j++) t[j] = (unsigned char)(0x11 + j);
    t[0] = (unsigned char)(i & 0xff);
    t[1] = (unsigned char)((i >> 8) & 0xff);
    t[2] = (unsigned char)((i >> 16) & 0xff);
}

static void setup_lst(struct LST* lst, void* tomb, void* manifest, void* scratch) {
    memset(lst, 0, sizeof *lst);
    lst->op_threshold = OP_THRESHOLD;
    lst->fill_threshold = FILL_THRESHOLD;
    lst->tomb_buf = tomb;   lst->tomb_cap = TOMB_CAP;
    lst->manifest_buf = manifest; lst->manifest_cap = MANIFEST_CAP;
    lst->scratch_buf = scratch;  lst->scratch_cap = SCRATCH_CAP;
}

/* reference model of the live set */
static unsigned char refl[N];
static long ref_count(void) { long c = 0; for (int i = 0; i < N; i++) c += refl[i]; return c; }

/* current live struct handles, swapped on each simulated restart */
static struct LST L;
static unsigned char UX[ 40 + SLOTS*48 + 8 ];
static unsigned char BLOBBUF[BLOB];
static void* g_tomb; static void* g_manifest; static void* g_scratch;

static long do_put(int k) {
    unsigned char t[32]; make_txid(t, (unsigned)k);
    unsigned char scr[6] = { (unsigned char)k, (unsigned char)(k>>8), 3,4,5,6 };
    long r = utxo_lsm_put(&L, UX, t, 0, 1000ULL + k, (unsigned long)k, 0, scr, 6);
    if (r == 1) refl[k] = 1;
    return r;
}
static long do_del(int k) {
    unsigned char t[32]; make_txid(t, (unsigned)k);
    long r = utxo_lsm_del(&L, UX, t, 0);
    if (r != -1) refl[k] = 0;
    return r;
}

/* simulate a crash+restart: fresh struct + fresh memtable, then reload */
static long restart_reload(void) {
    setup_lst(&L, g_tomb, g_manifest, g_scratch);
    utxo_init(UX, SLOTS, BLOBBUF, sizeof BLOBBUF);
    return utxo_lsm_reload(&L, UX);
}

/* rewrite utxo_manifest.dat from the new MAGIC_MANIFEST2 (20-byte header,
 * carries total_live) down to the OLD MAGIC_MANIFEST (12-byte header, no
 * count) so we can exercise the recount fallback the production manifest
 * needs on the first boot after this fix ships. */
static int downgrade_manifest_to_oldformat(void) {
    FILE* f = fopen("utxo_manifest.dat", "rb");
    if (!f) return 0;
    unsigned magic; unsigned long long n;
    if (fread(&magic, 4, 1, f) != 1 || fread(&n, 8, 1, f) != 1) { fclose(f); return 0; }
    if (magic != 0x324E4D55u /* "UMN2" */) { fclose(f); return 0; }
    unsigned long long skip; /* the persisted total_live we are stripping */
    if (fread(&skip, 8, 1, f) != 1) { fclose(f); return 0; }
    unsigned long long* ents = malloc(n * 16);
    if (n && fread(ents, 16, n, f) != n) { free(ents); fclose(f); return 0; }
    fclose(f);
    FILE* o = fopen("utxo_manifest.dat", "wb");
    if (!o) { free(ents); return 0; }
    unsigned oldmagic = 0x4E414D55u; /* "UMAN" */
    fwrite(&oldmagic, 4, 1, o);
    fwrite(&n, 8, 1, o);
    if (n) fwrite(ents, 16, n, o);
    fclose(o);
    free(ents);
    return 1;
}

int main(void) {
    tt_isolate();
    g_tomb = malloc(TOMB_CAP*36);
    g_manifest = malloc(MANIFEST_CAP*16);
    g_scratch = malloc(SCRATCH_CAP);
    if (!g_tomb || !g_manifest || !g_scratch) { printf("FAIL alloc\n"); return 1; }
    memset(refl, 0, sizeof refl);

    /* ---------- Part A: build N live UTXOs across many runs ---------- */
    setup_lst(&L, g_tomb, g_manifest, g_scratch);
    ck("lsm_init", utxo_lsm_init(&L), 1);
    utxo_init(UX, SLOTS, BLOBBUF, sizeof BLOBBUF);

    int all_new = 1;
    for (int k = 0; k < N; k++) if (do_put(k) != 1) all_new = 0;
    ckm("Part A: all N puts were genuinely new", all_new);
    ckm("Part A: many runs exist (not just the memtable tail)", L.manifest_n >= 5);
    ck("Part A: in-memory count == N", utxo_lsm_count(&L), N);
    ck("Part A: reference count == N", ref_count(), N);
    utxo_lsm_close(&L);

    /* THE assertion that fails on the pre-fix code: reload must restore the
     * exact count, not the handful of entries left in the unflushed tail. */
    long rep = restart_reload();
    ckm("Part A: reload ok (>=0)", rep >= 0);
    ck("Part A: reload count EXACT == N (undercounts on old code)",
       utxo_lsm_count(&L), N);

    /* ---------- Part B: spend UTXOs that live only in older runs -------- */
    /* Spend the first 60 keys -- long since flushed, so every del is a
     * memtable MISS against an older run: precisely the path that drove the
     * counter negative when the base was seeded too low. */
    int spent = 0;
    for (int k = 0; k < 60; k++) { if (do_del(k) != -1) spent++; }
    ck("Part B: 60 older-run spends recorded", spent, 60);
    ck("Part B: in-memory count == N-60", utxo_lsm_count(&L), N - 60);
    ckm("Part B: count never negative", utxo_lsm_count(&L) >= 0);
    ck("Part B: reference count == N-60", ref_count(), N - 60);

    long repB = restart_reload();
    ckm("Part B: reload ok", repB >= 0);
    ck("Part B: reload count EXACT == N-60", utxo_lsm_count(&L), ref_count());
    ckm("Part B: reload count never negative", utxo_lsm_count(&L) >= 0);

    /* ---------- Part C: a compaction cycle preserves the count ---------- */
    long before_compact = utxo_lsm_count(&L);
    long cr = utxo_lsm_compact(&L);
    ckm("Part C: compact ran (1) or was a no-op (0)", cr == 1 || cr == 0);
    ck("Part C: count unchanged by compaction", utxo_lsm_count(&L), before_compact);
    ck("Part C: count still == reference", utxo_lsm_count(&L), ref_count());

    long repC = restart_reload();
    ckm("Part C: reload-after-compact ok", repC >= 0);
    ck("Part C: reload count EXACT == reference", utxo_lsm_count(&L), ref_count());

    /* ---------- Part D: OLD-format manifest -> one-time recount --------- */
    /* Leave an UNFLUSHED tail: 4 brand-new keys live in the memtable, plus 3
     * spends of older-run keys (tombstones shadowing runs). Then strip the
     * persisted count from the manifest and reload: the recount must scan
     * runs + memtable + tombstones and land on the exact reference. */
    /* revive 4 previously-spent keys (0..3 were spent in Part B) as new puts */
    for (int k = 0; k < 4; k++) if (!refl[k]) do_put(k);
    /* spend 3 keys that are currently live and sitting in older runs (100..102) */
    for (int k = 100; k < 103; k++) if (refl[k]) do_del(k);

    long tail_expected = ref_count();
    printf("info: Part D WAL tail log_len=%llu (recount exercises the memtable"
           "+tombstone path when >0)\n", (unsigned long long)L.log_len);
    utxo_lsm_close(&L);

    ckm("Part D: manifest downgraded to old format", downgrade_manifest_to_oldformat());
    long repD = restart_reload();
    ckm("Part D: reload (old-format -> recount) ok", repD >= 0);
    ck("Part D: recount EXACT == reference (runs + memtable + tombstones)",
       utxo_lsm_count(&L), tail_expected);
    ckm("Part D: recount never negative", utxo_lsm_count(&L) >= 0);

    /* a subsequent flush must re-persist a NEW-format count, and the next
     * reload must restore it WITHOUT recounting (base+delta) and still match */
    for (int k = 0; k < N; k++) {
        if (!refl[k]) { if (do_put(k) != 1) {} }  /* repopulate to force flushes */
    }
    long after = ref_count();
    ck("Part D: post-recount in-memory count == reference", utxo_lsm_count(&L), after);
    utxo_lsm_close(&L);
    long repE = restart_reload();
    ckm("Part D: reload-after-repersist ok", repE >= 0);
    ck("Part D: base+delta reload EXACT == reference", utxo_lsm_count(&L), after);
    utxo_lsm_close(&L);

    free(g_tomb); free(g_manifest); free(g_scratch);
    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
