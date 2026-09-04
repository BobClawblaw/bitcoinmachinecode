/* tests/test_utxo_compact_gen_tiebreak.c -- UTX-1 (audit 2026-09-03): the
 * k-way merges must break equal-key ties by MANIFEST INDEX, as utxo_lsm_get
 * does, not by generation.
 *
 * BACKGROUND. utxo_lsm_get resolves duplicates by manifest index -- it scans
 * from the highest index down and takes the first hit -- a rule fixed on
 * 2026-08-20 after a production incident and pinned by
 * tests/test_compact_manifest_order.c. But the two k-way merges,
 * utxo_lsm_compact's .cc_find_loop and mac_lsm_recount's .rc_find, broke ties
 * by GENERATION instead.
 *
 * Those two orderings disagree after a PARTIAL compaction. When manifest_n >
 * COMPACT_MAX_RUNS (64), compaction merges the oldest 64 runs and leaves the
 * rest as survivors. The merged run M is placed at index 0 -- correct, it is
 * the oldest -- but it is assigned a FRESH generation, higher than every
 * survivor's. So for a key with a PUSH in M and a DEL in a survivor:
 *   * utxo_lsm_get  -> survivor wins (higher index): correct, deleted.
 *   * the merges    -> M wins (higher gen):          wrong, resurrected.
 *
 * The lookup path is right, which is why test_compact_manifest_order passes.
 * The WALK and the NEXT COMPACTION are wrong, and the next compaction is the
 * one that matters: it writes M's stale PUSH into the new merged run, and the
 * survivor's tombstone is gone. The spent coin is then genuinely back on
 * disk, and utxo_lsm_get agrees with it.
 *
 * THE FIXTURE is test_compact_manifest_order's, which already builds exactly
 * this shape: PUT A (run 1), 63 dummy runs, DEL A flushed into run 65 --
 * deliberately outside the 64-run batch -- then compact. This test adds the
 * two probes that fixture never made:
 *
 *   1. utxo_lsm_walk must visit 64 entries, not 65. Under the bug it visits
 *      A as live. The walk is also what utxo_live_verify_after_recovery
 *      trusts, so a wrong walk means recovery validates itself against a
 *      mis-count.
 *   2. after a SECOND compaction, A must still resolve as deleted. This is
 *      the destructive step: it is where the resurrection becomes durable.
 *
 * Reachability is not theoretical: utxo_live_recover() loops the classic
 * utxo_lsm_compact when the manifest is full, and build_migrate_compact.c
 * loops it over an 8192-entry manifest.
 *
 * Usage: ./test_utxo_compact_gen_tiebreak
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "test_tmpdir.h"

typedef unsigned char u8;
typedef unsigned long long u64;

extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const u8 txid[32], unsigned index, u64 value,
                         unsigned long height, unsigned long cb, const u8* script, unsigned slen);
extern long utxo_lsm_del(void* lst, void* u, const u8 txid[32], unsigned index);
extern long utxo_lsm_get(void* lst, void* u, const u8 txid[32], unsigned index, u64* value,
                         unsigned long* height, unsigned long* cb, const u8** script, unsigned long* slen);
extern long utxo_lsm_compact(void* lst);
extern long utxo_lsm_count(void* lst);
extern long utxo_lsm_walk(void* lst, void* u, void* cb, void* ctx);
extern void utxo_lsm_close(void* lst);

struct LST {
    long log_fd, idx_fd;
    u64 log_len, ckpt_log_off, ckpt_n;
    u64 op_count, op_threshold, fill_threshold;
    void* tomb_buf; u64 tomb_cap, tomb_n, total_live, next_gen;
    void* manifest_buf; u64 manifest_cap, manifest_n;
    void* scratch_buf; u64 scratch_cap;
    u64 next_run_no;
    void* tomb_hash_buf; u64 tomb_hash_mask;
};

#define BLOOM_MAX_BYTES  (4*1024*1024)
#define SCRIPT_MAX_BYTES 65536
#define SLOTS          64
#define BLOB           (1<<16)
#define TOMB_CAP       8
#define MANIFEST_CAP   128
#define DESC_CAP       16
#define SCRATCH_CAP    ((u64)DESC_CAP*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES)
#define N_DUMMY        63

static int fails = 0;
static void ck(const char* l, long g, long e){
    if (g == e) printf("ok  : %-58s (got %ld)\n", l, g);
    else { printf("FAIL: %-58s (got %ld exp %ld)\n", l, g, e); fails++; }
}
static void make_txid(u8* t, int seed, unsigned i){
    for (int j=0;j<32;j++) t[j]=(u8)(seed+j);
    t[0]=(u8)(i&0xff); t[1]=(u8)((i>>8)&0xff); t[2]=(u8)((i>>16)&0xff);
}
static void walk_cb(void* ctx, const u8 k[36], u64 v, u64 code, const u8* s, u64 sl){
    (void)k;(void)v;(void)code;(void)s;(void)sl; (*(long*)ctx)++;
}

int main(void){
    tt_isolate();
    void* tomb = malloc(TOMB_CAP*36);
    void* manifest = malloc(MANIFEST_CAP*16);
    void* scratch = malloc(SCRATCH_CAP);
    if (!tomb || !manifest || !scratch){ printf("FAIL alloc\n"); return 1; }

    struct LST lst; memset(&lst,0,sizeof lst);
    lst.op_threshold = 2; lst.fill_threshold = 1;
    lst.tomb_buf = tomb; lst.tomb_cap = TOMB_CAP;
    lst.manifest_buf = manifest; lst.manifest_cap = MANIFEST_CAP;
    lst.scratch_buf = scratch; lst.scratch_cap = SCRATCH_CAP;
    ck("lsm_init", utxo_lsm_init(&lst), 1);

    static u8 g_ux[ 40 + SLOTS*48 + 8 ];
    static u8 g_blob[BLOB];
    utxo_init(g_ux, SLOTS, g_blob, sizeof g_blob);

    u8 txidA[32]; make_txid(txidA, 0xAA, 0);
    u8 scrA[4] = {0xAA,0xAA,0xAA,0xAA};
    ck("put A (run 1)", utxo_lsm_put(&lst,g_ux,txidA,0,999999ULL,100,0,scrA,4), 1);

    for (int i=0;i<N_DUMMY;i++){
        u8 t[32]; make_txid(t, 0xBB, (unsigned)i);
        u8 s[4] = {(u8)i,0xBB,0xBB,0xBB};
        if (utxo_lsm_put(&lst,g_ux,t,0,1000ULL+(unsigned)i,101,0,s,4) != 1){
            printf("FAIL dummy put %d\n", i); fails++; }
    }
    ck("del A", utxo_lsm_del(&lst,g_ux,txidA,0), 1);
    u8 txidT[32]; make_txid(txidT, 0xCC, 0);
    u8 scrT[4] = {0xCC,0xCC,0xCC,0xCC};
    ck("trigger put flushes run 65 with A's tombstone",
       utxo_lsm_put(&lst,g_ux,txidT,0,42ULL,102,0,scrT,4), 1);
    ck("manifest_n is 65 (> COMPACT_MAX_RUNS)", (long)lst.manifest_n, 65);

    ck("first compact", utxo_lsm_compact(&lst), 1);
    printf("info: manifest_n after partial compact = %llu\n", (u64)lst.manifest_n);

    /* the lookup path is CORRECT even under the bug -- stated so a reader
     * does not mistake this for the property under test */
    u64 v; unsigned long h,cb,sl; const u8* s;
    ck("utxo_lsm_get(A) is deleted (the lookup path was never wrong)",
       utxo_lsm_get(&lst,g_ux,txidA,0,&v,&h,&cb,&s,&sl), 0);

    /* PROBE 1: the walk. 64 live keys expected -- 63 dummies + the trigger. */
    long visited = 0;
    long wr = utxo_lsm_walk(&lst, g_ux, (void*)walk_cb, &visited);
    printf("info: walk returned %ld, visited %ld, count says %ld\n",
           wr, visited, utxo_lsm_count(&lst));
    ck("UTX-1 the walk visits 64 live entries, not 65", visited, 64);

    /* PROBE 2: the second compaction is where resurrection becomes durable */
    ck("second compact", utxo_lsm_compact(&lst), 1);
    long rA2 = utxo_lsm_get(&lst,g_ux,txidA,0,&v,&h,&cb,&s,&sl);
    if (rA2 == 1)
        printf("      A came back LIVE with value %llu -- the spent coin is on disk\n", (u64)v);
    ck("UTX-1 A is STILL deleted after a second compaction", rA2, 0);

    /* positive control: a genuinely live key must survive both compactions,
     * so the fix cannot be "drop everything on a tie" */
    u8 tD[32]; make_txid(tD, 0xBB, (unsigned)(N_DUMMY-1));
    ck("a genuinely live key survives both compactions",
       utxo_lsm_get(&lst,g_ux,tD,0,&v,&h,&cb,&s,&sl), 1);

    utxo_lsm_close(&lst);
    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
