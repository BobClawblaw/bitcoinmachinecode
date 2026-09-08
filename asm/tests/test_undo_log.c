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
#include "../daemon/undo_store.h"
/* 2026-09-08: the store's API used by the new checks (undo_log.c has no header) */
typedef int (*undo_replay_cb)(void* ctx, const unsigned char txid[32], unsigned index, unsigned long long value, unsigned height, unsigned char is_coinbase, const unsigned char* script, unsigned short slen);
extern long undo_replay_tolerant(long height, undo_replay_cb cb, void* ctx, int* torn);
extern long undo_discard(long height);
extern long undo_commit(long height);
extern int  undo_exists(long height);
extern long undo_prune_below(long keep_from);
extern long undo_prune_from(long from_height, long tip_height, long window, long max_scan);
extern long undo_migrate_legacy(void);
extern long undo_wipe(void);
extern void undo_close_current(void);
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "test_tmpdir.h"

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
                          const u8** script, unsigned long* slen);

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

/* Must mirror bitcoin_utxo_lsm.asm's state struct exactly (168 bytes) --
 * same layout tests/test_utxo_lsm.c / daemon/utxo_live.c / daemon/tx_accept.c mirror. */
struct LST {
    long log_fd, idx_fd;
    unsigned long long log_len, ckpt_log_off, ckpt_n;
    unsigned long long op_count, op_threshold, fill_threshold;
    void* tomb_buf; unsigned long long tomb_cap, tomb_n, total_live, next_gen;
    void* manifest_buf; unsigned long long manifest_cap, manifest_n;
    void* scratch_buf; unsigned long long scratch_cap;
    unsigned long long next_run_no;
    void* tomb_hash_buf; unsigned long long tomb_hash_mask; /* LSM-owned, see bitcoin_utxo_lsm.asm */
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


int main(void){
    tt_isolate();
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
        unsigned long long v; unsigned long h, cb; const unsigned char* s; unsigned long sl;
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
        undo_close_current();
        ckm("real-height undo run exists before any prune", undo_exists(REAL_HEIGHT));

        /* 2026-09-08: undo is kept for EVERY block, like Core's rev files. The
         * old 200-block window (undo_prune / undo_prune_from) is a no-op. */
        long removed = undo_prune(250, 200);
        cki("undo_prune is a no-op now (retention follows the block store)", removed, 0);
        cki("undo_prune_from is a no-op too (cursor unchanged)", undo_prune_from(7, 250, 200, 20000), 7);
        int all_kept = 1; for (long h = 0; h <= 250; h++) if (!undo_exists(h)) all_kept = 0;
        ckm("every height 0..250 still has its undo run after the old window's prune", all_kept);
        { static undo_rec_t r10[2]; cki("undo_load(10) after undo_prune(250,200) still returns its record (retention, not a window)", undo_load(10, r10, 2), 1); }

        /* the block store pruned below 51: entries below go, the rev file
         * stays while it still holds a kept height (whole files, like Core) */
        long files = undo_prune_below(51);
        cki("undo_prune_below(51) removed no rev file (the one file also holds kept heights)", files, 0);
        int low_gone = 1; for (long h = 0; h <= 50; h++) if (undo_exists(h)) low_gone = 0;
        ckm("heights 0..50 have no undo entry after the store prune", low_gone);
        int high_kept = 1; for (long h = 51; h <= 250; h += 37) if (!undo_exists(h)) high_kept = 0;
        ckm("heights 51..250 keep their entries", high_kept);
        ckm("real-height undo run survived (h=200 is kept)", undo_exists(REAL_HEIGHT));
        {
            static undo_rec_t recs[8];
            long n = undo_load(REAL_HEIGHT, recs, 8);
            cki("real-height run still has both real records after the prune", n, 2);
        }
        cki("pruning below the same height again removes nothing more", undo_prune_below(51), 0);
    }

    /* 2026-09-08: the packed store's run semantics -- open, closed, torn */
    {
        u8 tx[32]; memset(tx, 0xB1, 32); u8 sc[3] = {1,2,3};
        cki("append h=880 (run open, no END yet)", undo_append_record(880, tx, 1, 10, 0, 0, sc, 3), 1);
        cki("append h=880 again", undo_append_record(880, tx, 2, 20, 0, 0, sc, 3), 1);
        undo_close_current();
        { undo_rec_t recs[4]; cki("an OPEN run loads its whole records (as the old file read to its end)", undo_load(880, recs, 4), 2); }
        cki("commit h=880 (END written)", undo_commit(880), 1);
        { undo_rec_t recs[4]; cki("a closed run loads the same two records", undo_load(880, recs, 4), 2); }
        cki("commit of a height that spent nothing creates an empty run", undo_commit(881), 1);
        ckm("...so undo_exists(881) is true: 881 was applied", undo_exists(881));
        { undo_rec_t recs[4]; cki("...and it loads zero records", undo_load(881, recs, 4), 0); }
        /* a torn tail: a partial record appended raw to the current rev file after a new open run */
        cki("append h=882 (open)", undo_append_record(882, tx, 3, 30, 0, 0, sc, 3), 1);
        undo_close_current();
        { undo_slot_t sl = {0, 0}; ckm("882 has an index entry", us_slot_get(882, &sl) == 1);
          char name[32]; us_rev_name(name, sl.file); int fd = open(name, O_WRONLY | O_APPEND);
          u8 partial[20]; memset(partial, 0x77, 20); ckm("write a partial record at the tail", fd >= 0 && write(fd, partial, 20) == 20); if (fd >= 0) close(fd); }
        { undo_rec_t recs[4]; cki("strict load of a torn run is -1", undo_load(882, recs, 4), -1); }
        { int torn = -1; long n = undo_replay_tolerant(882, 0, 0, &torn); cki("tolerant replay returns the whole record before the tear", n, 1); cki("...and reports torn", torn, 1); }
        cki("discard 882 clears the entry", undo_discard(882), 1);
        ckm("...undo_exists(882) is false", !undo_exists(882));
        cki("re-append h=882 starts a fresh run after the orphan bytes", undo_append_record(882, tx, 9, 90, 0, 0, sc, 3), 1);
        undo_close_current();
        { undo_rec_t recs[4]; long n = undo_load(882, recs, 4); cki("the fresh run holds only the new record", n, 1); cki("...index 9", n == 1 ? (long)recs[0].index : -1, 9); }
        undo_discard(880); undo_discard(881); undo_discard(882);
    }

    /* 2026-09-08: legacy per-height files fold into the store once */
    {
        u8 tx[32]; memset(tx, 0xC1, 32); u8 rec[2][54];
        for (int i = 0; i < 2; i++){ memset(rec[i], 0, 54); memcpy(rec[i], tx, 32); unsigned idx = (unsigned)i; memcpy(rec[i] + 32, &idx, 4);
            unsigned long long v = 1000 + (unsigned long long)i; memcpy(rec[i] + 36, &v, 8); rec[i][49] = 3; memcpy(rec[i] + 51, "\x01\x02\x03", 3); }
        FILE* lf = fopen("undo_900.dat", "wb"); ckm("legacy undo_900.dat written", lf != 0); if (lf){ fwrite(rec, 1, sizeof rec, lf); fclose(lf); }
        cki("migration folded one legacy file", undo_migrate_legacy(), 1);
        ckm("the legacy file is gone", access("undo_900.dat", F_OK) != 0);
        ckm("height 900 exists in the store", undo_exists(900));
        { undo_rec_t recs[4]; long n = undo_load(900, recs, 4); cki("its two records load", n, 2); cki("...second value 1001", n == 2 ? (long)recs[1].value : -1, 1001); }
        cki("a second migration finds nothing", undo_migrate_legacy(), 0);
        undo_discard(900);
    }

    /* 2026-09-01: the undo file of a height stays open across its appends;
     * a discard of that same height must close it, so a later re-append
     * (a rolled-back block applied again) writes a NEW file, not the
     * unlinked inode. */
    {
        extern long undo_discard(long height);
        extern void undo_close_current(void);
        u8 tx1[32], tx2[32]; memset(tx1, 0xA1, 32); memset(tx2, 0xA2, 32);
        u8 sc[3] = { 0x51, 0x52, 0x53 };
        cki("append h=777 (fd stays open)", undo_append_record(777, tx1, 0, 1, 0, 0, sc, 3), 1);
        cki("discard h=777 while its fd is cached", undo_discard(777), 1);
        cki("re-append h=777 after the discard", undo_append_record(777, tx2, 5, 2, 0, 0, sc, 3), 1);
        undo_close_current();
        undo_rec_t recs[4]; long n = undo_load(777, recs, 4);
        cki("the re-created file holds only the new record", n, 1);
        cki("...and it is the second one", n == 1 && memcmp(recs[0].txid, tx2, 32) == 0 && recs[0].index == 5, 1);
        undo_discard(777);
    }

    /* cleanup: the packed store */
    undo_wipe();
    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
