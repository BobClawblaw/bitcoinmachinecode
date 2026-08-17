/* test_utxo_lsm.c -- verify the LSM-tree UTXO store (bitcoin_utxo_lsm.asm):
 * bounded memtable + per-generation WAL + sorted immutable run flush +
 * multi-run Bloom-filtered lookup + tombstone-shadowing + crash recovery.
 *
 * Run in a throwaway temp dir (utxo_lsm_init/reload's fds are relative
 * filenames, matching the convention build_utxo.c's chdir already uses).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_count(void* u);

extern long utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const unsigned char txid[32],
                          unsigned index, unsigned long long value,
                          const unsigned char* script, unsigned slen);
extern long utxo_lsm_del(void* lst, void* u, const unsigned char txid[32], unsigned index);
extern long utxo_lsm_get(void* lst, void* u, const unsigned char txid[32], unsigned index,
                          unsigned long long* value, const unsigned char** script, unsigned* slen);
extern long utxo_lsm_count(void* lst);
extern long utxo_lsm_reload(void* lst, void* u);
extern void utxo_lsm_close(void* lst);

/* Must mirror bitcoin_utxo_lsm.asm's state struct exactly (144 bytes). */
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
    char tmpl[] = "/tmp/btclsmXXXXXX";
    char* dir = mkdtemp(tmpl);
    if (!dir) { printf("FAIL mkdtemp\n"); return 1; }
    chdir(dir);

    void* tomb = malloc(TOMB_CAP*36);
    void* manifest = malloc(MANIFEST_CAP*8);
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

    ck("lsm_put A0 new", utxo_lsm_put(&lst, g_ux, tA, 0, 50000ULL, scrA, 25), 1);
    ck("lsm_put B7 new", utxo_lsm_put(&lst, g_ux, tB, 7, 1234567ULL, scrB, 22), 1);
    ck("lsm_put C0 new", utxo_lsm_put(&lst, g_ux, tC, 0, 999ULL, scrC, 5), 1);
    ck("lsm_count 3", utxo_lsm_count(&lst), 3);
    ck("manifest_n still 0 (no flush)", lst.manifest_n, 0);

    unsigned long long v; const unsigned char* s; unsigned sl;
    ck("get A0 (memtable)", utxo_lsm_get(&lst, g_ux, tA, 0, &v, &s, &sl), 1);
    ck("get A0 value", v, 50000ULL);
    ck("get A0 slen", sl, 25);
    ckm("get A0 script", memcmp(s, scrA, 25) == 0);

    ck("lsm_del B7", utxo_lsm_del(&lst, g_ux, tB, 7), 1);
    ck("lsm_count 2 after spend", utxo_lsm_count(&lst), 2);
    ck("get B7 miss (spent)", utxo_lsm_get(&lst, g_ux, tB, 7, &v, &s, &sl), 0);
    ck("tomb_n 1 after spend", lst.tomb_n, 1);

    /* ---------- phase 2: force a flush by crossing op_threshold ---------- */
    unsigned char tD[32], tE[32];
    make_txid(tD, 0x40, 4); make_txid(tE, 0x50, 5);
    unsigned char scrD[8]; for (int i=0;i<8;i++) scrD[i]=0x77;
    unsigned char scrE[10]; for (int i=0;i<10;i++) scrE[i]=0x33;
    ck("lsm_put D0", utxo_lsm_put(&lst, g_ux, tD, 0, 7777ULL, scrD, 8), 1);
    ck("lsm_put E0", utxo_lsm_put(&lst, g_ux, tE, 0, 5555ULL, scrE, 10), 1);
    /* op_count so far: put A,put B,del B,put D,put E = 6; push exactly 10
     * more no-op dup puts (duplicates of C0, each still counts as an op but
     * never changes memtable live-count) so op_count hits OP_THRESHOLD=16
     * on precisely the LAST iteration -- flush fires there and nothing
     * else runs afterward, so the post-flush reset checks below are exact. */
    for (int i = 0; i < 10; i++) {
        utxo_lsm_put(&lst, g_ux, tC, 0, 999ULL, scrC, 5); /* dup, still counts as an op */
    }
    ckm("flush happened (manifest_n>=1)", lst.manifest_n >= 1);
    ck("memtable cleared after flush", utxo_count(g_ux), 0);
    ck("op_count reset after flush", lst.op_count, 0);
    ck("tomb_n reset after flush", lst.tomb_n, 0);
    ck("log_len reset after flush", (long)lst.log_len, 0);

    /* live keys now only findable via the flushed run (memtable is empty) */
    ck("get A0 (from run)", utxo_lsm_get(&lst, g_ux, tA, 0, &v, &s, &sl), 1);
    ck("get A0 value (from run)", v, 50000ULL);
    ckm("get A0 script (from run)", memcmp(s, scrA, 25) == 0);
    ck("get C0 (from run)", utxo_lsm_get(&lst, g_ux, tC, 0, &v, &s, &sl), 1);
    ck("get C0 value (from run)", v, 999ULL);
    ck("get D0 (from run)", utxo_lsm_get(&lst, g_ux, tD, 0, &v, &s, &sl), 1);
    ck("get D0 value (from run)", v, 7777ULL);
    ckm("get D0 script (from run)", memcmp(s, scrD, 8) == 0);
    ck("get E0 (from run)", utxo_lsm_get(&lst, g_ux, tE, 0, &v, &s, &sl), 1);
    ck("get B7 absent (spent before flush)", utxo_lsm_get(&lst, g_ux, tB, 7, &v, &s, &sl), 0);
    unsigned char tZ[32]; make_txid(tZ, 0x99, 9);
    ck("get tZ absent (never existed)", utxo_lsm_get(&lst, g_ux, tZ, 0, &v, &s, &sl), 0);

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
        utxo_lsm_put(&lst, g_ux, tF, 0, (unsigned long long)i, scrF, 4);
    }
    ckm("second flush happened", lst.manifest_n > manifest_before);
    ck("get A0 absent after tombstone flush (shadowed)", utxo_lsm_get(&lst, g_ux, tA, 0, &v, &s, &sl), 0);
    ck("get C0 still present (unaffected)", utxo_lsm_get(&lst, g_ux, tC, 0, &v, &s, &sl), 1);
    ck("get D0 still present (unaffected)", utxo_lsm_get(&lst, g_ux, tD, 0, &v, &s, &sl), 1);

    /* ---------- phase 4: crash recovery ---------- */
    /* Do a handful of puts/dels that stay BELOW both thresholds (so they
     * remain unflushed, living only in the WAL), then reload into a FRESH
     * state+memtable without calling close first -- simulates a crash. */
    unsigned char tG[32], tH[32];
    make_txid(tG, 0x70, 200); make_txid(tH, 0x80, 201);
    unsigned char scrG[3] = {9,9,9};
    ck("lsm_put G0 (unflushed, pre-crash)", utxo_lsm_put(&lst, g_ux, tG, 0, 42ULL, scrG, 3), 1);
    ck("lsm_del D0 (unflushed, pre-crash spend of a run0 key)", utxo_lsm_del(&lst, g_ux, tD, 0), 1);
    unsigned long long pre_total_live = lst.total_live;
    long pre_manifest_n = lst.manifest_n;

    {
        struct LST lst2;
        void* tomb2 = malloc(TOMB_CAP*36);
        void* manifest2 = malloc(MANIFEST_CAP*8);
        void* scratch2 = malloc(SCRATCH_CAP);
        setup_lst(&lst2, tomb2, manifest2, scratch2);
        static unsigned char ux2[ 40 + SLOTS*48 + 8 ];
        static unsigned char blob2[BLOB];
        utxo_init(ux2, SLOTS, blob2, sizeof blob2);
        long replayed = utxo_lsm_reload(&lst2, ux2);
        ckm("reload ok (>=0)", replayed >= 0);
        ck("reload manifest_n matches pre-crash", lst2.manifest_n, pre_manifest_n);
        ck("reload get G0 (from replayed WAL)", utxo_lsm_get(&lst2, ux2, tG, 0, &v, &s, &sl), 1);
        ck("reload get G0 value", v, 42ULL);
        ck("reload get D0 absent (spent in lost tail, tombstone rebuilt)",
           utxo_lsm_get(&lst2, ux2, tD, 0, &v, &s, &sl), 0);
        ck("reload get C0 still present (older run)", utxo_lsm_get(&lst2, ux2, tC, 0, &v, &s, &sl), 1);
        ck("reload get A0 still absent (tombstone run survives)",
           utxo_lsm_get(&lst2, ux2, tA, 0, &v, &s, &sl), 0);
        /* tomb_n after reload must reflect the one DEL (D0) replayed from
         * the WAL tail, so a THIRD flush would still correctly shadow it */
        ck("reload tomb_n rebuilt to 1", lst2.tomb_n, 1);
        utxo_lsm_close(&lst2);
        free(tomb2); free(manifest2); free(scratch2);
    }
    (void)pre_total_live;

    /* ---------- phase 5: randomized stress vs a reference model ---------- */
    {
        struct LST lst3;
        void* tomb3 = malloc(TOMB_CAP*36);
        void* manifest3 = malloc(MANIFEST_CAP*8);
        void* scratch3 = malloc(SCRATCH_CAP);
        setup_lst(&lst3, tomb3, manifest3, scratch3);
        ckm("stress lsm_init", utxo_lsm_init(&lst3) == 1);
        static unsigned char ux3[ 40 + SLOTS*48 + 8 ];
        static unsigned char blob3[BLOB];
        utxo_init(ux3, SLOTS, blob3, sizeof blob3);

        #define NKEYS 400
        static unsigned char live[NKEYS];
        static unsigned long long refval[NKEYS];
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
                long r = utxo_lsm_put(&lst3, ux3, tk, 0, val, scrk, 4);
                /* utxo_put's real contract (matching real UTXO semantics --
                 * a given outpoint is created exactly once): a put against
                 * an ALREADY-LIVE key is a no-op dup (r==0) that does NOT
                 * update the stored value, so the reference model must only
                 * adopt the new value when r==1 (genuinely new insert). */
                if (r == 1) { live[k] = 1; refval[k] = val; }
                else if (r == -1) { stress_fails++; printf("FAIL: stress put returned -1 at round %d\n", round); }
            } else {
                long r = utxo_lsm_del(&lst3, ux3, tk, 0);
                if (r == -1) { stress_fails++; printf("FAIL: stress del returned -1 at round %d\n", round); }
                else live[k] = 0;
            }
            if ((round % 37) == 0) {
                /* spot-check a handful of keys against the reference */
                for (int c = 0; c < 20; c++) {
                    int ck_i = (round + c*13) % NKEYS;
                    unsigned char tc[32];
                    make_txid(tc, 0x11, (unsigned)ck_i);
                    unsigned long long gv; const unsigned char* gs; unsigned gsl;
                    long r = utxo_lsm_get(&lst3, ux3, tc, 0, &gv, &gs, &gsl);
                    if (live[ck_i]) {
                        if (r != 1 || gv != refval[ck_i]) {
                            stress_fails++;
                            printf("FAIL: stress key %d expected live=%llu got r=%ld v=%llu (round %d)\n",
                                   ck_i, refval[ck_i], r, gv, round);
                        }
                    } else {
                        if (r != 0) {
                            stress_fails++;
                            printf("FAIL: stress key %d expected absent got r=%ld (round %d)\n", ck_i, r, round);
                        }
                    }
                }
            }
        }
        /* final full sweep */
        for (int k = 0; k < NKEYS; k++) {
            unsigned char tk[32];
            make_txid(tk, 0x11, (unsigned)k);
            unsigned long long gv; const unsigned char* gs; unsigned gsl;
            long r = utxo_lsm_get(&lst3, ux3, tk, 0, &gv, &gs, &gsl);
            if (live[k]) {
                if (r != 1 || gv != refval[k]) {
                    stress_fails++;
                    printf("FAIL: final sweep key %d expected live=%llu got r=%ld v=%llu\n",
                           k, refval[k], r, gv);
                }
            } else {
                if (r != 0) {
                    stress_fails++;
                    printf("FAIL: final sweep key %d expected absent got r=%ld\n", k, r);
                }
            }
        }
        ck("stress test (0 mismatches)", stress_fails, 0);
        printf("info: stress final manifest_n=%llu (runs created)\n", lst3.manifest_n);
        fails += stress_fails;
        utxo_lsm_close(&lst3);
        free(tomb3); free(manifest3); free(scratch3);
    }

    utxo_lsm_close(&lst);
    free(tomb); free(manifest); free(scratch);

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
