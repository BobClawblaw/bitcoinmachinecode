/* test_undo_log.c -- 100% AI-generated harness for Stage A reorg/fork-choice
 * primitive #5: the per-block undo-data structure (daemon/undo_log.c).
 *
 * Exercises undo_capture_and_del against the REAL LSM UTXO store
 * (bitcoin_utxo_lsm.asm) -- put a UTXO, spend it through the capture path,
 * verify the undo record holds the exact original value+script and that
 * the spend actually happened (utxo_lsm_get now misses). Also verifies
 * undo_prune's retention-window boundary precisely.
 *
 * See daemon/undo_log.c's own header comment for why this exercises a
 * standalone capture function rather than daemon/utxo_live.c's real
 * live_on_input, which is intentionally left untouched in this stage.
 *
 * LSM setup mirrors tests/test_utxo_lsm.c's own init pattern.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned long long u64;

extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);

extern long utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const u8 txid[32], unsigned index,
                          unsigned long long value, unsigned long height, unsigned long is_coinbase,
                          const u8* script, unsigned slen);
extern long utxo_lsm_get(void* lst, void* u, const u8 txid[32], unsigned index,
                          unsigned long long* value, unsigned long* height, unsigned long* is_coinbase,
                          const u8** script, unsigned* slen);

#define UNDO_MAX_SCRIPT 10000
typedef struct {
    u8  txid[32];
    u32 index;
    u64 value;
    u32 height;
    u8  is_coinbase;
    u16 slen;
    u8  script[UNDO_MAX_SCRIPT];
} undo_rec_t;

extern long undo_append_record(long height, const u8 txid[32], u32 index, u64 value,
                                u32 utxo_height, u8 is_coinbase, const u8* script, u16 slen);
extern long undo_load(long height, undo_rec_t* out, long max_recs);
extern long undo_prune(long tip_height, long window);
extern long undo_capture_and_del(void* lst, void* u, long height, const u8 txid[32], u32 index);

/* Must mirror bitcoin_utxo_lsm.asm's state struct exactly (152 bytes) --
 * same layout tests/test_utxo_lsm.c / daemon/utxo_live.c / daemon/tx_accept.c mirror. */
struct LST {
    long log_fd, idx_fd;
    unsigned long long log_len, ckpt_log_off, ckpt_n;
    unsigned long long op_count, op_threshold, fill_threshold;
    void* tomb_buf; unsigned long long tomb_cap, tomb_n, total_live, next_gen;
    void* manifest_buf; unsigned long long manifest_cap, manifest_n;
    void* scratch_buf; unsigned long long scratch_cap;
    unsigned long long next_run_no;
};
#define BLOOM_MAX_BYTES  (4*1024*1024)
#define SCRIPT_MAX_BYTES 65536
#define SLOTS          64
#define BLOB           (1<<18)
#define FILL_THRESHOLD 8
#define OP_THRESHOLD   1000000ULL /* huge: never trigger a flush in this test */
#define TOMB_CAP       64
#define MANIFEST_CAP   64
#define DESC_CAP       128
#define SCRATCH_CAP    ((unsigned long long)DESC_CAP*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES)

static int failures = 0;
static void cki(const char* l, long long g, long long e){ if(g==e)printf("PASS %s (got %lld)\n",l,g); else{printf("FAIL %s got=%lld exp=%lld\n",l,g,e);failures++;} }
static void ckm(const char* l, int cond){ cki(l, cond, 1); }

static void setup_lst(struct LST* lst, void* tomb, void* manifest, void* scratch){
    memset(lst, 0, sizeof *lst);
    lst->op_threshold = OP_THRESHOLD;
    lst->fill_threshold = FILL_THRESHOLD;
    lst->tomb_buf = tomb; lst->tomb_cap = TOMB_CAP;
    lst->manifest_buf = manifest; lst->manifest_cap = MANIFEST_CAP;
    lst->scratch_buf = scratch; lst->scratch_cap = SCRATCH_CAP;
}

static int file_exists(const char* path){
    struct stat sb;
    return stat(path, &sb) == 0;
}

int main(void){
    char tmpl[]="/tmp/btcundoXXXXXX";
    char* dir = mkdtemp(tmpl);
    if(!dir){ printf("FAIL mkdtemp\n"); return 1; }
    chdir(dir);

    void* tomb = malloc(TOMB_CAP*36);
    void* manifest = malloc(MANIFEST_CAP*16);
    void* scratch = malloc(SCRATCH_CAP);
    static unsigned char g_ux[40 + SLOTS*48 + 8];
    static unsigned char g_blob[BLOB];
    if (!tomb || !manifest || !scratch){ printf("FAIL alloc\n"); return 1; }

    struct LST lst;
    setup_lst(&lst, tomb, manifest, scratch);
    cki("lsm_init", utxo_lsm_init(&lst), 1);
    utxo_init(g_ux, SLOTS, g_blob, sizeof g_blob);

    /* ============================================================
     * Part 1: capture + del against a real UTXO, verify the undo record
     * holds the exact original value+script, and the spend actually
     * removed it from the live set.
     * ============================================================ */
    /* Uses height 200 (not 0/5/etc.) deliberately: Part 2 below prunes with
     * tip=250,window=200, which retains only heights [51..250] -- picking a
     * real-data height inside that retained range means Part 2 can assert
     * these records BOTH survive pruning AND that the boundary itself is
     * exactly where it should be, in the same test. */
    const long REAL_HEIGHT = 200;
    /* A0 is a COINBASE output created at height 150 -- spent (captured) in
     * the block at REAL_HEIGHT=200. The undo record must carry A0's OWN
     * creation height (150) and is_coinbase=1, NOT the spending block's
     * height (200) -- these are two genuinely different numbers, and
     * conflating them is exactly the bug daemon/undo_log.c's header comment
     * warns about (see "CAREFUL" there). */
    const unsigned long A0_CREATION_HEIGHT = 150;
    unsigned char txidA[32]; for (int i=0;i<32;i++) txidA[i]=(unsigned char)(0xA0+i);
    unsigned char scrA[37]; for (int i=0;i<37;i++) scrA[i]=(unsigned char)(0x51+i);
    cki("put A0 (simulated prior-block coinbase output)",
        utxo_lsm_put(&lst, g_ux, txidA, 0, 123456789ULL, A0_CREATION_HEIGHT, 1, scrA, sizeof scrA), 1);

    long r = undo_capture_and_del(&lst, g_ux, REAL_HEIGHT, txidA, 0);
    cki("undo_capture_and_del A0", r, 1);

    {
        unsigned long long v; unsigned long h, cb; const unsigned char* s; unsigned sl;
        cki("A0 now missing from live set (spent)", utxo_lsm_get(&lst, g_ux, txidA, 0, &v, &h, &cb, &s, &sl), 0);
    }

    {
        static undo_rec_t recs[8];
        long n = undo_load(REAL_HEIGHT, recs, 8);
        cki("undo_load height record count", n, 1);
        ckm("undo record txid matches", memcmp(recs[0].txid, txidA, 32) == 0);
        cki("undo record index matches", recs[0].index, 0);
        cki("undo record value matches", (long long)recs[0].value, 123456789LL);
        cki("undo record height is A0's OWN creation height (150), not the spending height (200)",
            (long long)recs[0].height, (long long)A0_CREATION_HEIGHT);
        cki("undo record is_coinbase preserved", recs[0].is_coinbase, 1);
        cki("undo record slen matches", recs[0].slen, sizeof scrA);
        ckm("undo record script bytes match", memcmp(recs[0].script, scrA, sizeof scrA) == 0);
    }

    /* capturing a nonexistent UTXO is a clean no-op (0), not an error */
    {
        unsigned char txidZ[32]; memset(txidZ, 0xEE, 32);
        long rz = undo_capture_and_del(&lst, g_ux, REAL_HEIGHT, txidZ, 3);
        cki("undo_capture_and_del on nonexistent UTXO", rz, 0);
        static undo_rec_t recs[8];
        long n = undo_load(REAL_HEIGHT, recs, 8);
        cki("no extra undo record appended for a miss", n, 1);
    }

    /* a second real spend in the SAME height appends a second record,
     * doesn't clobber the first */
    unsigned char txidB[32]; for (int i=0;i<32;i++) txidB[i]=(unsigned char)(0xB0+i);
    unsigned char scrB[9]; for (int i=0;i<9;i++) scrB[i]=(unsigned char)(0x22+i);
    cki("put B0 (normal, not coinbase)", utxo_lsm_put(&lst, g_ux, txidB, 0, 42ULL, 180, 0, scrB, sizeof scrB), 1);
    cki("undo_capture_and_del B0", undo_capture_and_del(&lst, g_ux, REAL_HEIGHT, txidB, 0), 1);
    {
        static undo_rec_t recs[8];
        long n = undo_load(REAL_HEIGHT, recs, 8);
        cki("undo_load height now has 2 records", n, 2);
        ckm("record0 still txidA", memcmp(recs[0].txid, txidA, 32)==0);
        ckm("record1 is txidB", memcmp(recs[1].txid, txidB, 32)==0);
        cki("record1 value", (long long)recs[1].value, 42LL);
        cki("record1 height", (long long)recs[1].height, 180LL);
        cki("record1 is_coinbase false", recs[1].is_coinbase, 0);
    }

    /* ============================================================
     * Part 2: undo_prune retention-window boundary.
     *   tip=250, window=200 -> retain heights [51..250] (200 files),
     *   remove heights [0..50] (51 files). REAL_HEIGHT=200 sits inside the
     *   retained range, so its records (seeded above, not re-seeded here)
     *   must survive intact.
     * ============================================================ */
    {
        unsigned char dummy_txid[32]; memset(dummy_txid, 0x01, 32);
        unsigned char dummy_script[3] = {1,2,3};
        for (long h = 0; h <= 250; h++){
            if (h == REAL_HEIGHT) continue; /* already has real records from Part 1 */
            cki("seed dummy undo record", undo_append_record(h, dummy_txid, 0, 1, 0, 0, dummy_script, 3), 1);
        }
        char path_real[64]; snprintf(path_real, sizeof path_real, "undo_%ld.dat", REAL_HEIGHT);
        ckm("real-height undo file exists before prune", file_exists(path_real));

        long removed = undo_prune(250, 200);
        cki("undo_prune removed count", removed, 51);

        for (long h = 0; h <= 50; h++){
            char p[64]; snprintf(p, sizeof p, "undo_%ld.dat", h);
            char lbl[80]; snprintf(lbl, sizeof lbl, "undo_%ld.dat removed (h<=50)", h);
            ckm(lbl, !file_exists(p));
        }
        for (long h = 51; h <= 250; h += 37){ /* spot-check the retained range */
            char p[64]; snprintf(p, sizeof p, "undo_%ld.dat", h);
            char lbl[80]; snprintf(lbl, sizeof lbl, "undo_%ld.dat retained (h>=51)", h);
            ckm(lbl, file_exists(p));
        }
        ckm("real-height undo file survived pruning (h=200 is inside the window)", file_exists(path_real));
        {
            static undo_rec_t recs[8];
            long n = undo_load(REAL_HEIGHT, recs, 8);
            cki("real-height undo file still has both real records after prune", n, 2);
        }

        /* second prune call with the same window is a clean no-op (nothing
         * left below the boundary to remove) */
        long removed2 = undo_prune(250, 200);
        cki("re-pruning the same window removes nothing more", removed2, 0);
    }

    /* cleanup */
    for (long h = 0; h <= 250; h++){
        char p[64]; snprintf(p, sizeof p, "undo_%ld.dat", h);
        unlink(p);
    }
    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    rmdir(dir);
    return failures?1:0;
}
