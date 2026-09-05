/* test_utxo_lsm.c -- verify the LSM-tree UTXO store (bitcoin_utxo_lsm.asm):
 * bounded memtable + per-generation WAL + sorted immutable run flush +
 * multi-run Bloom-filtered lookup + tombstone-shadowing + crash recovery,
 * and (2026-08-19, Stage D) that height/is_coinbase survive every one of
 * those paths -- memtable, flush-to-disk-run, the sparse-index-accelerated
 * disk lookup, crash recovery, compaction, and reading an OLD-format run
 * file that never captured them at all (must report 0/0, not garbage).
 *
 * Run in a throwaway temp dir (utxo_lsm_init/reload's fds are relative
 * filenames, matching the convention build_utxo.c's chdir already uses).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "test_tmpdir.h"

extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_count(void* u);

extern long utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const unsigned char txid[32],
                          unsigned index, unsigned long long value,
                          unsigned long height, unsigned long is_coinbase,
                          const unsigned char* script, unsigned slen);
extern long utxo_lsm_del(void* lst, void* u, const unsigned char txid[32], unsigned index);
extern long utxo_lsm_flush(void* lst, void* u);
extern long utxo_lsm_get(void* lst, void* u, const unsigned char txid[32], unsigned index,
                          unsigned long long* value, unsigned long* height,
                          unsigned long* is_coinbase,
                          const unsigned char** script, unsigned long* slen);
extern long utxo_lsm_count(void* lst);
extern long utxo_lsm_reload(void* lst, void* u);
extern long utxo_lsm_compact(void* lst);
extern void utxo_lsm_close(void* lst);

/* Must mirror bitcoin_utxo_lsm.asm's state struct exactly (168 bytes). */
struct LST {
    long log_fd;                      /* +0   */
    long idx_fd;                      /* +8   */
    unsigned long long log_len;       /* +16  */
    unsigned long long ckpt_log_off;  /* +24  */
    unsigned long long ckpt_n;        /* +32  */
    unsigned long long op_count;      /* +40  */
    unsigned long long op_threshold;  /* +48  */
    unsigned long long fill_threshold;/* +56  */
    void*              tomb_buf;      /* +64  */
    unsigned long long tomb_cap;      /* +72  */
    unsigned long long tomb_n;        /* +80  */
    unsigned long long total_live;    /* +88  */
    unsigned long long next_gen;      /* +96  */
    void*              manifest_buf;  /* +104 */
    unsigned long long manifest_cap;  /* +112 */
    unsigned long long manifest_n;    /* +120 */
    void*              scratch_buf;   /* +128 */
    unsigned long long scratch_cap;   /* +136 */
    unsigned long long next_run_no;   /* +144 */
    void*              tomb_hash_buf;   /* +152, LSM-owned, see bitcoin_utxo_lsm.asm */
    unsigned long long tomb_hash_mask;  /* +160, LSM-owned */
};

#define BLOOM_MAX_BYTES   (4*1024*1024)
#define SCRIPT_MAX_BYTES  65536

static int fails = 0;
static void ck(const char* l, long g, long e) {
    if (g == e) printf("ok  : %-42s (got %ld)\n", l, g);
    else { printf("FAIL: %-42s (got %ld exp %ld)\n", l, g, e); fails++; }
}
static void ckm(const char* l, int cond) { ck(l, cond, 1); }

static void make_txid(unsigned char* t, int seed, unsigned int i) {
    for (int j = 0; j < 32; j++) t[j] = (unsigned char)(seed + j);
    t[0] = (unsigned char)(i & 0xff);
    t[1] = (unsigned char)((i >> 8) & 0xff);
    t[2] = (unsigned char)((i >> 16) & 0xff);
}

/* Sizes chosen small so flush triggers are easy to hit deterministically
 * in a test: memtable capacity SLOTS=256, fill_threshold=8, op_threshold=16.
 * desc_cap must be >= fill_threshold+tomb_cap; tomb_cap=64 -> desc_cap>=72,
 * we use 128 for margin. */
#define SLOTS          256
#define BLOB           (1<<20)
#define FILL_THRESHOLD 8
#define OP_THRESHOLD   16
#define TOMB_CAP       64
#define MANIFEST_CAP   4096
#define DESC_CAP       128
#define SCRATCH_CAP    ((unsigned long long)DESC_CAP*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES)

static void setup_lst(struct LST* lst, void* tomb, void* manifest, void* scratch) {
    memset(lst, 0, sizeof *lst);
    lst->op_threshold = OP_THRESHOLD;
    lst->fill_threshold = FILL_THRESHOLD;
    lst->tomb_buf = tomb;
    lst->tomb_cap = TOMB_CAP;
    lst->manifest_buf = manifest;
    lst->manifest_cap = MANIFEST_CAP;
    lst->scratch_buf = scratch;
    lst->scratch_cap = SCRATCH_CAP;
}

int main(void) {
    tt_isolate();
    void* tomb = malloc(TOMB_CAP*36);
    void* manifest = malloc(MANIFEST_CAP*16);
    void* scratch = malloc(SCRATCH_CAP);
    if (!tomb || !manifest || !scratch) { printf("FAIL alloc\n"); return 1; }

    static unsigned char g_ux[ 40 + SLOTS*48 + 8 ];
    static unsigned char g_blob[BLOB];

    /* ---------- phase 1: fresh, small puts (no flush yet) ---------- */
    struct LST lst;
    setup_lst(&lst, tomb, manifest, scratch);
    ck("lsm_init", utxo_lsm_init(&lst), 1);
    utxo_init(g_ux, SLOTS, g_blob, sizeof g_blob);

    unsigned char tA[32], tB[32], tC[32];
    make_txid(tA, 0x10, 1); make_txid(tB, 0x20, 2); make_txid(tC, 0x30, 3);
    unsigned char scrA[25], scrB[22], scrC[5];
    for (int i=0;i<25;i++) scrA[i]=0x40+i;
    for (int i=0;i<22;i++) scrB[i]=0x90+i;
    for (int i=0;i<5;i++)  scrC[i]=0x51;

    /* A0 is a coinbase output at height 100; B7/C0 are normal spends. */
    ck("lsm_put A0 new (coinbase h=100)", utxo_lsm_put(&lst, g_ux, tA, 0, 50000ULL, 100, 1, scrA, 25), 1);
    ck("lsm_put B7 new (h=200)", utxo_lsm_put(&lst, g_ux, tB, 7, 1234567ULL, 200, 0, scrB, 22), 1);
    ck("lsm_put C0 new (h=201)", utxo_lsm_put(&lst, g_ux, tC, 0, 999ULL, 201, 0, scrC, 5), 1);
    ck("lsm_count 3", utxo_lsm_count(&lst), 3);
    ck("manifest_n still 0 (no flush)", lst.manifest_n, 0);

    unsigned long long v; const unsigned char* s; unsigned long sl; unsigned long h, cb;
    ck("get A0 (memtable)", utxo_lsm_get(&lst, g_ux, tA, 0, &v, &h, &cb, &s, &sl), 1);
    ck("get A0 value", v, 50000ULL);
    ck("get A0 height (memtable)", h, 100);
    ck("get A0 is_coinbase (memtable)", cb, 1);
    ck("get A0 slen", sl, 25);
    ckm("get A0 script", memcmp(s, scrA, 25) == 0);

    ck("lsm_del B7", utxo_lsm_del(&lst, g_ux, tB, 7), 1);
    ck("lsm_count 2 after spend", utxo_lsm_count(&lst), 2);
    ck("get B7 miss (spent)", utxo_lsm_get(&lst, g_ux, tB, 7, &v, &h, &cb, &s, &sl), 0);
    ck("tomb_n 1 after spend", lst.tomb_n, 1);

    /* ---------- phase 2: force a flush by crossing op_threshold ---------- */
    unsigned char tD[32], tE[32];
    make_txid(tD, 0x40, 4); make_txid(tE, 0x50, 5);
    unsigned char scrD[8]; for (int i=0;i<8;i++) scrD[i]=0x77;
    unsigned char scrE[10]; for (int i=0;i<10;i++) scrE[i]=0x33;
    /* D0 is a coinbase output at height 300; E0 is a normal spend at 301. */
    ck("lsm_put D0 (coinbase h=300)", utxo_lsm_put(&lst, g_ux, tD, 0, 7777ULL, 300, 1, scrD, 8), 1);
    ck("lsm_put E0 (h=301)", utxo_lsm_put(&lst, g_ux, tE, 0, 5555ULL, 301, 0, scrE, 10), 1);
    /* op_count so far: put A,put B,del B,put D,put E = 6; push exactly 10
     * more no-op dup puts (duplicates of C0, each still counts as an op but
     * never changes memtable live-count) so op_count hits OP_THRESHOLD=16
     * on precisely the LAST iteration -- flush fires there and nothing
     * else runs afterward, so the post-flush reset checks below are exact. */
    for (int i = 0; i < 10; i++) {
        utxo_lsm_put(&lst, g_ux, tC, 0, 999ULL, 201, 0, scrC, 5); /* dup */
    }
    ckm("flush happened (manifest_n>=1)", lst.manifest_n >= 1);
    ck("memtable cleared after flush", utxo_count(g_ux), 0);
    ck("op_count reset after flush", lst.op_count, 0);
    ck("tomb_n reset after flush", lst.tomb_n, 0);
    ck("log_len reset after flush", (long)lst.log_len, 0);

    /* live keys now only findable via the flushed run (memtable is empty).
     * Checking height/is_coinbase here proves mac_flush's write and
     * mac_run_lookup's read agree on the new 15-byte record shape. */
    /* incident #49 regression: the run-hit path once stored slen as 4 bytes
     * while every daemon caller declares unsigned long* -- the upper half of
     * the caller's variable kept stale stack garbage, and mempool prevout
     * resolution nondeterministically failed "prevout script too large".
     * POISON the upper half first: with the old 4-byte store this check
     * reads back 0xDEADBEEF00000019 and fails loudly. */
    sl = 0xDEADBEEF00000000UL;
    ck("get A0 (from run)", utxo_lsm_get(&lst, g_ux, tA, 0, &v, &h, &cb, &s, &sl), 1);
    ck("get A0 slen FULL-WIDTH (poisoned high half cleared)", (long long)sl, 25);
    ck("get A0 value (from run)", v, 50000ULL);
    ck("get A0 height (from run)", h, 100);
    ck("get A0 is_coinbase (from run)", cb, 1);
    ckm("get A0 script (from run)", memcmp(s, scrA, 25) == 0);
    ck("get C0 (from run)", utxo_lsm_get(&lst, g_ux, tC, 0, &v, &h, &cb, &s, &sl), 1);
    ck("get C0 value (from run)", v, 999ULL);
    ck("get C0 height (from run)", h, 201);
    ck("get C0 is_coinbase (from run)", cb, 0);
    ck("get D0 (from run)", utxo_lsm_get(&lst, g_ux, tD, 0, &v, &h, &cb, &s, &sl), 1);
    ck("get D0 value (from run)", v, 7777ULL);
    ck("get D0 height (from run)", h, 300);
    ck("get D0 is_coinbase (from run)", cb, 1);
    ckm("get D0 script (from run)", memcmp(s, scrD, 8) == 0);
    ck("get E0 (from run)", utxo_lsm_get(&lst, g_ux, tE, 0, &v, &h, &cb, &s, &sl), 1);
    ck("get E0 height (from run)", h, 301);
    ck("get E0 is_coinbase (from run)", cb, 0);
    ck("get B7 absent (spent before flush)", utxo_lsm_get(&lst, g_ux, tB, 7, &v, &h, &cb, &s, &sl), 0);
    unsigned char tZ[32]; make_txid(tZ, 0x99, 9);
    ck("get tZ absent (never existed)", utxo_lsm_get(&lst, g_ux, tZ, 0, &v, &h, &cb, &s, &sl), 0);

    /* ---- UTX-9 (audit 2026-09-03): the run scan stops at the records end
     *
     * The linear scan was bounded by the whole MAPPING rather than by
     * sparse_off, so a lookup for a key past every record in the run walked
     * on into the sparse-index trailer and parsed 44-byte index entries as
     * records, skipping by whatever their bytes said `slen` was. It stayed
     * inside the mapping (no OOB) and still answered ABSENT, so the cost was
     * wasted I/O and a fragile invariant -- which is why the assertion that
     * matters here is the OTHER direction.
     *
     * Tightening a bound risks cutting off the LAST record, and a
     * highest-sorting key that stopped being found would be silent data loss.
     * make_txid puts the low byte of `i` first, so 0xff sorts above every key
     * written above; storing and reading it back proves the new bound admits
     * the final record rather than excluding it. (tZ above is the past-the-end
     * case, and it must stay absent.) */
    { unsigned char tMax[32]; make_txid(tMax, 0x11, 0xff);
      unsigned char scrMax[6] = {9,8,7,6,5,4};
      ck("UTX-9 store a key that sorts LAST",
         utxo_lsm_put(&lst, g_ux, tMax, 0, 4242ULL, 777, 0, scrMax, 6) >= 0, 1);
      ck("UTX-9 flush it into a run", utxo_lsm_flush(&lst, g_ux), 1);
      sl = 0;
      ck("UTX-9 the last record in the run is still FOUND (bound not too tight)",
         utxo_lsm_get(&lst, g_ux, tMax, 0, &v, &h, &cb, &s, &sl), 1);
      ck("UTX-9   with its value intact", v, 4242ULL);
      ck("UTX-9   and its script length", (long long)sl, 6);
      ckm("UTX-9   and its script bytes", memcmp(s, scrMax, 6) == 0);
      ck("UTX-9 a key past the last record is still absent",
         utxo_lsm_get(&lst, g_ux, tZ, 0, &v, &h, &cb, &s, &sl), 0); }

    /* ---------- phase 3: tombstone-shadowing across generations ---------- */
    /* A0 currently lives in run 0. Spend it now (memtable miss -> tombstone
     * recorded per the documented contract change), then force a second
     * flush -> run 1 should carry a DEL tombstone for A0's key, which must
     * shadow run 0's PUSH so get(A0) is authoritatively absent afterward. */
    long manifest_before = lst.manifest_n;
    unsigned long long total_live_before_del = lst.total_live;
    ck("lsm_del A0 (memtable miss, still recorded)", utxo_lsm_del(&lst, g_ux, tA, 0), 1);
    ck("total_live decremented on assumed-older-run spend",
       (long)lst.total_live, (long)(total_live_before_del - 1));
    for (int i = 0; i < 16; i++) {
        unsigned char tF[32]; make_txid(tF, 0x60, 100+i);
        unsigned char scrF[4] = {1,2,3,4};
        utxo_lsm_put(&lst, g_ux, tF, 0, (unsigned long long)i, (unsigned long)i, 0, scrF, 4);
    }
    ckm("second flush happened", lst.manifest_n > manifest_before);
    ck("get A0 absent after tombstone flush (shadowed)", utxo_lsm_get(&lst, g_ux, tA, 0, &v, &h, &cb, &s, &sl), 0);
    ck("get C0 still present (unaffected)", utxo_lsm_get(&lst, g_ux, tC, 0, &v, &h, &cb, &s, &sl), 1);
    ck("get D0 still present (unaffected)", utxo_lsm_get(&lst, g_ux, tD, 0, &v, &h, &cb, &s, &sl), 1);

    /* ---------- phase 4: crash recovery ---------- */
    /* Do a handful of puts/dels that stay BELOW both thresholds (so they
     * remain unflushed, living only in the WAL), then reload into a FRESH
     * state+memtable without calling close first -- simulates a crash. */
    unsigned char tG[32], tH[32];
    make_txid(tG, 0x70, 200); make_txid(tH, 0x80, 201);
    unsigned char scrG[3] = {9,9,9};
    ck("lsm_put G0 (unflushed, pre-crash)", utxo_lsm_put(&lst, g_ux, tG, 0, 42ULL, 400, 0, scrG, 3), 1);
    ck("lsm_del D0 (unflushed, pre-crash spend of a run0 key)", utxo_lsm_del(&lst, g_ux, tD, 0), 1);
    unsigned long long pre_total_live = lst.total_live;
    long pre_manifest_n = lst.manifest_n;

    {
        struct LST lst2;
        void* tomb2 = malloc(TOMB_CAP*36);
        void* manifest2 = malloc(MANIFEST_CAP*16);
        void* scratch2 = malloc(SCRATCH_CAP);
        setup_lst(&lst2, tomb2, manifest2, scratch2);
        static unsigned char ux2[ 40 + SLOTS*48 + 8 ];
        static unsigned char blob2[BLOB];
        utxo_init(ux2, SLOTS, blob2, sizeof blob2);
        long replayed = utxo_lsm_reload(&lst2, ux2);
        ckm("reload ok (>=0)", replayed >= 0);
        ck("reload manifest_n matches pre-crash", lst2.manifest_n, pre_manifest_n);
        ck("reload get G0 (from replayed WAL)", utxo_lsm_get(&lst2, ux2, tG, 0, &v, &h, &cb, &s, &sl), 1);
        ck("reload get G0 value", v, 42ULL);
        ck("reload get D0 absent (spent in lost tail, tombstone rebuilt)",
           utxo_lsm_get(&lst2, ux2, tD, 0, &v, &h, &cb, &s, &sl), 0);
        ck("reload get C0 still present (older run)", utxo_lsm_get(&lst2, ux2, tC, 0, &v, &h, &cb, &s, &sl), 1);
        ck("reload get A0 still absent (tombstone run survives)",
           utxo_lsm_get(&lst2, ux2, tA, 0, &v, &h, &cb, &s, &sl), 0);
        /* tomb_n after reload must reflect the one DEL (D0) replayed from
         * the WAL tail, so a THIRD flush would still correctly shadow it */
        ck("reload tomb_n rebuilt to 1", lst2.tomb_n, 1);
        utxo_lsm_close(&lst2);
        free(tomb2); free(manifest2); free(scratch2);
    }
    (void)pre_total_live;
    (void)tH;

    /* ---------- phase 5: randomized stress vs a reference model ---------- */
    {
        struct LST lst3;
        void* tomb3 = malloc(TOMB_CAP*36);
        void* manifest3 = malloc(MANIFEST_CAP*16);
        void* scratch3 = malloc(SCRATCH_CAP);
        setup_lst(&lst3, tomb3, manifest3, scratch3);
        ckm("stress lsm_init", utxo_lsm_init(&lst3) == 1);
        static unsigned char ux3[ 40 + SLOTS*48 + 8 ];
        static unsigned char blob3[BLOB];
        utxo_init(ux3, SLOTS, blob3, sizeof blob3);

        #define NKEYS 400
        static unsigned char live[NKEYS];
        static unsigned long long refval[NKEYS];
        static unsigned long refheight[NKEYS];
        static unsigned char refcb[NKEYS];
        memset(live, 0, sizeof live);

        srand(12345);
        int stress_fails = 0;
        for (int round = 0; round < 6000; round++) {
            int k = rand() % NKEYS;
            unsigned char tk[32];
            make_txid(tk, 0x11, (unsigned)k);
            unsigned char scrk[4] = { (unsigned char)k, (unsigned char)(k>>8), 7, 7 };
            int do_put = (rand() % 2) == 0;
            if (do_put) {
                unsigned long long val = (unsigned long long)round*1000ULL + k;
                unsigned long height = (unsigned long)round;
                unsigned long is_cb = (k % 3 == 0) ? 1 : 0;
                /* utxo_put's real contract (matching real UTXO semantics --
                 * a given outpoint is created exactly once): a put against
                 * an ALREADY-LIVE key is a no-op dup (r==0) that does NOT
                 * update the stored value/height/is_coinbase, so the
                 * reference model must only adopt the new fields when
                 * r==1 (genuinely new insert). */
                long r = utxo_lsm_put(&lst3, ux3, tk, 0, val, height, is_cb, scrk, 4);
                if (r == 1) { live[k] = 1; refval[k] = val; refheight[k] = height; refcb[k] = (unsigned char)is_cb; }
                else if (r == -1) { stress_fails++; printf("FAIL: stress put returned -1 at round %d\n", round); }
            } else {
                long r = utxo_lsm_del(&lst3, ux3, tk, 0);
                if (r == -1) { stress_fails++; printf("FAIL: stress del returned -1 at round %d\n", round); }
                else live[k] = 0;
            }
            if ((round % 37) == 0) {
                /* spot-check a handful of keys against the reference,
                 * including height/is_coinbase */
                for (int c = 0; c < 20; c++) {
                    int ck_i = (round + c*13) % NKEYS;
                    unsigned char tc[32];
                    make_txid(tc, 0x11, (unsigned)ck_i);
                    unsigned long long gv; unsigned long gh, gcb; const unsigned char* gs; unsigned long gsl;
                    long r = utxo_lsm_get(&lst3, ux3, tc, 0, &gv, &gh, &gcb, &gs, &gsl);
                    if (live[ck_i]) {
                        if (r != 1 || gv != refval[ck_i] || gh != refheight[ck_i] || gcb != refcb[ck_i]) {
                            stress_fails++;
                            printf("FAIL: stress key %d expected live=%llu h=%lu cb=%u got r=%ld v=%llu h=%lu cb=%lu (round %d)\n",
                                   ck_i, refval[ck_i], refheight[ck_i], (unsigned)refcb[ck_i], r, gv, gh, gcb, round);
                        }
                    } else {
                        if (r != 0) {
                            stress_fails++;
                            printf("FAIL: stress key %d expected absent got r=%ld (round %d)\n", ck_i, r, round);
                        }
                    }
                }
            }
            if ((round % 211) == 0) {
                /* interleave compaction into the same live workload -- the
                 * strongest test of compaction's correctness: it must not
                 * disturb any in-flight get() result, whether the key ends
                 * up in the merged run, an untouched newer run, or the
                 * still-open memtable. */
                long r = utxo_lsm_compact(&lst3);
                if (r == -1) { stress_fails++; printf("FAIL: stress compact returned -1 at round %d\n", round); }
            }
        }
        /* one more compaction right before the final full sweep, plus a
         * fresh reload afterward -- exercises "did compaction's on-disk
         * state survive being closed and reopened" on top of everything
         * the interleaved compactions during the loop already covered. */
        long manifest_before_final_compact = lst3.manifest_n;
        long rc = utxo_lsm_compact(&lst3);
        if (rc == -1) { stress_fails++; printf("FAIL: final compact returned -1\n"); }
        printf("info: final compact manifest_n %ld -> %llu\n", manifest_before_final_compact, lst3.manifest_n);
        utxo_lsm_close(&lst3);

        struct LST lst3b;
        void* tomb3b = malloc(TOMB_CAP*36);
        void* manifest3b = malloc(MANIFEST_CAP*16);
        void* scratch3b = malloc(SCRATCH_CAP);
        setup_lst(&lst3b, tomb3b, manifest3b, scratch3b);
        static unsigned char ux3b[ 40 + SLOTS*48 + 8 ];
        static unsigned char blob3b[BLOB];
        utxo_init(ux3b, SLOTS, blob3b, sizeof blob3b);
        long replayed3b = utxo_lsm_reload(&lst3b, ux3b);
        ckm("stress reload after compact ok (>=0)", replayed3b >= 0);
        ck("stress reload manifest_n matches", lst3b.manifest_n, lst3.manifest_n);

        /* final full sweep -- against the FRESH, reloaded state */
        for (int k = 0; k < NKEYS; k++) {
            unsigned char tk[32];
            make_txid(tk, 0x11, (unsigned)k);
            unsigned long long gv; unsigned long gh, gcb; const unsigned char* gs; unsigned long gsl;
            long r = utxo_lsm_get(&lst3b, ux3b, tk, 0, &gv, &gh, &gcb, &gs, &gsl);
            if (live[k]) {
                if (r != 1 || gv != refval[k] || gh != refheight[k] || gcb != refcb[k]) {
                    stress_fails++;
                    printf("FAIL: final sweep key %d expected live=%llu h=%lu cb=%u got r=%ld v=%llu h=%lu cb=%lu\n",
                           k, refval[k], refheight[k], (unsigned)refcb[k], r, gv, gh, gcb);
                }
            } else {
                if (r != 0) {
                    stress_fails++;
                    printf("FAIL: final sweep key %d expected absent got r=%ld\n", k, r);
                }
            }
        }
        ck("stress test (0 mismatches)", stress_fails, 0);
        printf("info: stress final manifest_n=%llu (runs after compaction)\n", lst3b.manifest_n);
        fails += stress_fails;
        utxo_lsm_close(&lst3b);
        free(tomb3); free(manifest3); free(scratch3);
        free(tomb3b); free(manifest3b); free(scratch3b);
    }

    /* ---------- phase 6: sparse index acceleration on a large run ---------- */
    /* A single flush this large forces many SPARSE_STRIDE(256)-record
     * strides into one run, so utxo_lsm_get must actually exercise the
     * on-disk binary search (not just land at records_start by luck). */
    {
        #define SP_SLOTS    4096
        #define SP_FILL     3000
        #define SP_OP       999999
        #define SP_TOMB     64
        #define SP_MANIFEST 64
        #define SP_DESC     3200
        #define SP_SCRATCH  ((unsigned long long)SP_DESC*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES)
        #define SP_N        3000

        struct LST lst4;
        void* tomb4 = malloc(SP_TOMB*36);
        void* manifest4 = malloc(SP_MANIFEST*16);
        void* scratch4 = malloc(SP_SCRATCH);
        if (!tomb4 || !manifest4 || !scratch4) { printf("FAIL alloc (sparse)\n"); return 1; }
        memset(&lst4, 0, sizeof lst4);
        lst4.op_threshold = SP_OP;
        lst4.fill_threshold = SP_FILL;
        lst4.tomb_buf = tomb4; lst4.tomb_cap = SP_TOMB;
        lst4.manifest_buf = manifest4; lst4.manifest_cap = SP_MANIFEST;
        lst4.scratch_buf = scratch4; lst4.scratch_cap = SP_SCRATCH;
        ckm("sparse: lsm_init", utxo_lsm_init(&lst4) == 1);

        static unsigned char ux4[ 40 + SP_SLOTS*48 + 8 ];
        static unsigned char blob4[BLOB];
        utxo_init(ux4, SP_SLOTS, blob4, sizeof blob4);

        static unsigned long long sp_val[SP_N];
        static unsigned long sp_height[SP_N];
        static unsigned char sp_cb[SP_N];
        int sp_setup_fails = 0;
        for (int i = 0; i < SP_N; i++) {
            unsigned char tk[32];
            make_txid(tk, 0x22, (unsigned)i);
            unsigned char scrk[6] = {1,2,3,4,5,(unsigned char)i};
            sp_val[i] = 900000ULL + (unsigned long long)i;
            sp_height[i] = 900000UL + (unsigned long)i;
            sp_cb[i] = (i % 5 == 0) ? 1 : 0;
            long r = utxo_lsm_put(&lst4, ux4, tk, 0, sp_val[i], sp_height[i], sp_cb[i], scrk, 6);
            if (r != 1) { sp_setup_fails++; printf("FAIL: sparse setup put %d returned %ld\n", i, r); }
        }
        ck("sparse: setup puts all new (0 failures)", sp_setup_fails, 0);
        fails += sp_setup_fails;
        ckm("sparse: flush happened after N puts", lst4.manifest_n >= 1);
        ck("sparse: memtable cleared", utxo_count(ux4), 0);
        printf("info: sparse run manifest_n=%llu (nrec=%d, SPARSE_STRIDE=256 -> ~%d strides)\n",
               lst4.manifest_n, SP_N, SP_N/256);

        int sp_fails = 0;
        for (int i = 0; i < SP_N; i += 7) {
            unsigned char tk[32];
            make_txid(tk, 0x22, (unsigned)i);
            unsigned long long gv; unsigned long gh, gcb; const unsigned char* gs; unsigned long gsl;
            long r = utxo_lsm_get(&lst4, ux4, tk, 0, &gv, &gh, &gcb, &gs, &gsl);
            if (r != 1 || gv != sp_val[i] || gsl != 6 || gs[5] != (unsigned char)i
                || gh != sp_height[i] || gcb != sp_cb[i]) {
                sp_fails++;
                printf("FAIL: sparse get key %d r=%ld v=%llu exp=%llu h=%lu exph=%lu cb=%lu expcb=%u\n",
                       i, r, gv, sp_val[i], gh, sp_height[i], gcb, sp_cb[i]);
            }
        }
        {
            unsigned char tk[32]; unsigned long long gv; unsigned long gh, gcb; const unsigned char* gs; unsigned long gsl;
            make_txid(tk, 0x22, 0);
            if (utxo_lsm_get(&lst4, ux4, tk, 0, &gv, &gh, &gcb, &gs, &gsl) != 1) { sp_fails++; printf("FAIL: sparse first key absent\n"); }
            make_txid(tk, 0x22, SP_N-1);
            if (utxo_lsm_get(&lst4, ux4, tk, 0, &gv, &gh, &gcb, &gs, &gsl) != 1) { sp_fails++; printf("FAIL: sparse last key absent\n"); }
            make_txid(tk, 0x22, SP_N);
            if (utxo_lsm_get(&lst4, ux4, tk, 0, &gv, &gh, &gcb, &gs, &gsl) != 0) { sp_fails++; printf("FAIL: sparse absent key found\n"); }
        }
        ck("sparse: spot-check across large run (0 mismatches, incl height/is_coinbase)", sp_fails, 0);
        fails += sp_fails;

        utxo_lsm_close(&lst4);
        free(tomb4); free(manifest4); free(scratch4);
        #undef SP_SLOTS
        #undef SP_FILL
        #undef SP_OP
        #undef SP_TOMB
        #undef SP_MANIFEST
        #undef SP_DESC
        #undef SP_SCRATCH
        #undef SP_N
    }

    /* ---------- phase 7: old-format (MAGIC_RUN) run readable via fallback,
     * reporting height=0/is_coinbase=0 (never garbage) since that data was
     * never captured by the pre-Stage-D format; and phase 8: compacting
     * TWO such old-format runs together, alongside a genuine new-format
     * key, mid-migration -- exactly what a long-running node hits before
     * every run has been rewritten in the new MAGIC_RUN3 shape. Kept in
     * ONE scope (not two) so phase 8 can reuse phase 7's lst5/ux5/run. ---- */
    {
        struct LST lst5;
        void* tomb5 = malloc(TOMB_CAP*36);
        void* manifest5 = malloc(MANIFEST_CAP*16);
        void* scratch5 = malloc(SCRATCH_CAP);
        if (!tomb5 || !manifest5 || !scratch5) { printf("FAIL alloc (oldfmt)\n"); return 1; }
        setup_lst(&lst5, tomb5, manifest5, scratch5);
        ckm("oldfmt: lsm_init", utxo_lsm_init(&lst5) == 1);
        static unsigned char ux5[ 40 + SLOTS*48 + 8 ];
        static unsigned char blob5[BLOB];
        utxo_init(ux5, SLOTS, blob5, sizeof blob5);

        unsigned run_no = 777;
        char fname[64];
        snprintf(fname, sizeof fname, "utxo_run_%06u.dat", run_no);
        FILE* f = fopen(fname, "wb");
        ckm("oldfmt: fixture file opened", f != NULL);

        unsigned char tX[32], tY[32];
        make_txid(tX, 0x01, 1);   /* key sorts first (txid[0]=1) */
        make_txid(tY, 0x01, 2);   /* key sorts second (txid[0]=2) */
        unsigned char scrX[4] = {11,22,33,44};
        unsigned char scrY[3] = {5,6,7};
        unsigned long long valX = 111111ULL, valY = 222222ULL;

        unsigned magic = 0x4E555255; /* MAGIC_RUN ("URUN") */
        unsigned long long gen = 1, nrec = 2, bloom_bits = 64; /* 8 bloom bytes */
        unsigned char bloom_all_ones[8]; memset(bloom_all_ones, 0xFF, 8);
        fwrite(&magic, 4, 1, f);
        fwrite(&gen, 8, 1, f);
        fwrite(&nrec, 8, 1, f);
        fwrite(&bloom_bits, 8, 1, f);
        fwrite(bloom_all_ones, 1, 8, f);
        {
            unsigned zero32 = 0; unsigned char type_push = 1; unsigned short slen;
            fwrite(tX, 32, 1, f); fwrite(&zero32, 4, 1, f); fwrite(&type_push, 1, 1, f);
            fwrite(&valX, 8, 1, f); slen = 4; fwrite(&slen, 2, 1, f); fwrite(scrX, 1, 4, f);
            fwrite(tY, 32, 1, f); fwrite(&zero32, 4, 1, f); fwrite(&type_push, 1, 1, f);
            fwrite(&valY, 8, 1, f); slen = 3; fwrite(&slen, 2, 1, f); fwrite(scrY, 1, 3, f);
        }
        fclose(f);

        /* inject a single manifest entry pointing at the hand-written run,
         * bypassing utxo_lsm_put/flush entirely */
        unsigned long long* mbuf = (unsigned long long*)manifest5;
        mbuf[0] = gen; mbuf[1] = run_no;
        lst5.manifest_n = 1;

        unsigned long long v5; unsigned long h5, cb5; const unsigned char* s5; unsigned long sl5;
        ck("oldfmt: get X (fallback linear scan)", utxo_lsm_get(&lst5, ux5, tX, 0, &v5, &h5, &cb5, &s5, &sl5), 1);
        ck("oldfmt: get X value", v5, valX);
        ck("oldfmt: get X height (unavailable -> 0, not garbage)", h5, 0);
        ck("oldfmt: get X is_coinbase (unavailable -> 0, not garbage)", cb5, 0);
        ck("oldfmt: get X slen", sl5, 4);
        ckm("oldfmt: get X script", memcmp(s5, scrX, 4) == 0);
        ck("oldfmt: get Y (fallback linear scan)", utxo_lsm_get(&lst5, ux5, tY, 0, &v5, &h5, &cb5, &s5, &sl5), 1);
        ck("oldfmt: get Y value", v5, valY);
        ck("oldfmt: get Y height (unavailable -> 0, not garbage)", h5, 0);
        ck("oldfmt: get Y is_coinbase (unavailable -> 0, not garbage)", cb5, 0);
        ckm("oldfmt: get Y script", memcmp(s5, scrY, 3) == 0);
        unsigned char tZ3[32]; make_txid(tZ3, 0x01, 3); /* sorts after both -> EOF miss */
        ck("oldfmt: get absent key past end", utxo_lsm_get(&lst5, ux5, tZ3, 0, &v5, &h5, &cb5, &s5, &sl5), 0);

        /* ---------- phase 8: compact TWO old-format runs together, with a
         * genuine new-format key live in the memtable at the same time. ---- */
        unsigned run_no2 = 778;
        char fname2[64];
        snprintf(fname2, sizeof fname2, "utxo_run_%06u.dat", run_no2);
        FILE* f2 = fopen(fname2, "wb");
        ckm("phase8: fixture2 file opened", f2 != NULL);

        unsigned char tW[32];
        make_txid(tW, 0x02, 1);
        unsigned char scrW[2] = {77, 88};
        unsigned long long valW = 333333ULL;

        unsigned magic2 = 0x4E555255; /* MAGIC_RUN, same old format as run 777 */
        unsigned long long gen2 = 1, nrec2 = 1, bloom_bits2 = 64;
        unsigned char bloom_all_ones2[8]; memset(bloom_all_ones2, 0xFF, 8);
        fwrite(&magic2, 4, 1, f2);
        fwrite(&gen2, 8, 1, f2);
        fwrite(&nrec2, 8, 1, f2);
        fwrite(&bloom_bits2, 8, 1, f2);
        fwrite(bloom_all_ones2, 1, 8, f2);
        {
            unsigned zero32 = 0; unsigned char type_push = 1; unsigned short slen2;
            fwrite(tW, 32, 1, f2); fwrite(&zero32, 4, 1, f2); fwrite(&type_push, 1, 1, f2);
            fwrite(&valW, 8, 1, f2); slen2 = 2; fwrite(&slen2, 2, 1, f2); fwrite(scrW, 1, 2, f2);
        }
        fclose(f2);

        unsigned long long* mbuf5b = (unsigned long long*)manifest5;
        mbuf5b[2] = gen2; mbuf5b[3] = run_no2;
        lst5.manifest_n = 2;

        /* a genuine new-format key, left live in the memtable (not
         * flushed) -- proves compacting the two old-format runs doesn't
         * disturb an unrelated live memtable entry. The compaction path
         * for a REAL MAGIC_RUN3 run is already covered by phase 5's
         * interleaved compactions (all its runs are new-format); phase 8's
         * unique value is old-format-only compaction plus a coexisting
         * live memtable, which phase 5 doesn't specifically isolate. */
        unsigned char tI[32]; make_txid(tI, 0x03, 1);
        unsigned char scrI[3] = {1, 2, 3};
        ck("phase8: put I0 (new-format, memtable-resident)",
           utxo_lsm_put(&lst5, ux5, tI, 0, 444444ULL, 500, 1, scrI, 3), 1);

        long rc8 = utxo_lsm_compact(&lst5);
        ck("phase8: compact of 2 old-format runs succeeds", rc8, 1);

        unsigned long long v8; unsigned long h8, cb8; const unsigned char* s8; unsigned long sl8;
        ck("phase8: get X after compact", utxo_lsm_get(&lst5, ux5, tX, 0, &v8, &h8, &cb8, &s8, &sl8), 1);
        ck("phase8: X value after compact", v8, valX);
        ck("phase8: X height still 0 after compact (never captured)", h8, 0);
        ck("phase8: X is_coinbase still 0 after compact (never captured)", cb8, 0);
        ck("phase8: get Y after compact", utxo_lsm_get(&lst5, ux5, tY, 0, &v8, &h8, &cb8, &s8, &sl8), 1);
        ck("phase8: Y value after compact", v8, valY);
        ck("phase8: Y height still 0 after compact (never captured)", h8, 0);
        ck("phase8: get W after compact", utxo_lsm_get(&lst5, ux5, tW, 0, &v8, &h8, &cb8, &s8, &sl8), 1);
        ck("phase8: W value after compact", v8, valW);
        ck("phase8: W height still 0 after compact (never captured)", h8, 0);
        ck("phase8: W is_coinbase still 0 after compact (never captured)", cb8, 0);
        ck("phase8: get I0 (memtable, unaffected by compact)", utxo_lsm_get(&lst5, ux5, tI, 0, &v8, &h8, &cb8, &s8, &sl8), 1);
        ck("phase8: I0 value", v8, 444444ULL);
        ck("phase8: I0 height (real, new-format, survives)", h8, 500);
        ck("phase8: I0 is_coinbase (real, new-format, survives)", cb8, 1);

        utxo_lsm_close(&lst5);
        free(tomb5); free(manifest5); free(scratch5);
    }

    utxo_lsm_close(&lst);
    free(tomb); free(manifest); free(scratch);

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
