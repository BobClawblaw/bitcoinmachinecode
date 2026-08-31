/* Regression test: the tx-validation snapshot must be sized to the WAL it
 * replays, and must refuse to serve a snapshot that does not match the writer.
 *
 * 2026-08-31, signet: the writer had been in BULK mode and died mid-catch-up,
 * leaving an 81.5 MB WAL (~497k live entries). tx_dispatch_init allocated its
 * fixed 2^16-slot table, the replay jammed it after 65,536 puts and returned
 * -2 -- which `r != -1` treated as READY -- and the recount that follows then
 * probed ~8.7M absent keys at 65,536 slots each. The node sat at "[boot]
 * tx-validation snapshot" at 99.9% CPU indefinitely; had it finished, the
 * snapshot would have been missing 7/8 of the set.
 *
 * Seeds a WAL with more entries than 2^16 can hold and asserts the snapshot
 * (a) comes up, (b) holds every entry, and (c) refuses when the writer's own
 * persisted count disagrees with what it replayed. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include "test_tmpdir.h"
typedef uint8_t u8; typedef uint32_t u32;

extern long   utxo_struct_size(unsigned long slots);
extern void   utxo_init(void* u, unsigned long slots, void* blob, unsigned long long blob_cap);
extern int    utxo_lsm_init(void* lst);
extern long   utxo_lsm_put(void* lst, void* u, const u8 txid[32], u32 index, unsigned long long value,
                           unsigned long long height, unsigned long long is_cb, const u8* script, unsigned long slen);
extern void   utxo_lsm_close(void* lst);
extern int    tx_dispatch_init(void);
extern long   txacc_snapshot_count(void);

struct lsm_state {
    long log_fd, idx_fd;
    unsigned long long log_len, ckpt_log_off, ckpt_n;
    unsigned long long op_count, op_threshold, fill_threshold;
    void* tomb_buf; unsigned long long tomb_cap, tomb_n, total_live, next_gen;
    void* manifest_buf; unsigned long long manifest_cap, manifest_n;
    void* scratch_buf; unsigned long long scratch_cap;
    unsigned long long next_run_no;
    void* tomb_hash_buf; unsigned long long tomb_hash_mask;
};
#define BLOOM_MAX_BYTES  (4*1024*1024)
#define SCRIPT_MAX_BYTES 65536

static int fails = 0;
static void ok(int c, const char* w){ printf("  %s %s\n", c?"ok ":"FAIL", w); if(!c) fails++; }

/* A writer sized like BULK mode (2^18 slots here: enough that IT never
 * flushes, so every entry stays in the WAL generation the snapshot replays). */
static void seed(long n){
    unsigned long slots = 1UL<<18;
    void* table = malloc((size_t)utxo_struct_size(slots));
    void* blob = malloc(64UL<<20);
    utxo_init(table, slots, blob, 64UL<<20);
    struct lsm_state lst; memset(&lst, 0, sizeof lst);
    unsigned long long op_th = slots*2, tomb_cap = op_th, desc_cap = slots*3;
    lst.op_threshold = op_th; lst.fill_threshold = slots*3/4;
    lst.tomb_buf = malloc(tomb_cap*36); lst.tomb_cap = tomb_cap;
    lst.manifest_buf = malloc(256*16); lst.manifest_cap = 256;
    lst.scratch_cap = desc_cap*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES;
    lst.scratch_buf = malloc(lst.scratch_cap);
    if (utxo_lsm_init(&lst) != 1){ fprintf(stderr, "lsm init failed\n"); exit(1); }
    u8 spk[25]; memset(spk, 0x76, sizeof spk);
    for (long i = 0; i < n; i++){
        u8 txid[32]; memset(txid, 0, 32); memcpy(txid, &i, sizeof i); txid[31] = 0x5a;
        if (utxo_lsm_put(&lst, table, txid, 0, 1000ULL + i, 100 + (i % 7), 0, spk, 25) != 1){
            fprintf(stderr, "seed put %ld failed\n", i); exit(1); }
    }
    utxo_lsm_close(&lst);
    free(table); free(blob); free(lst.tomb_buf); free(lst.manifest_buf); free(lst.scratch_buf);
}

int main(void){
    tt_isolate();
    const long N = 100000;                 /* > 2^16 = 65,536 */

    printf("== a WAL generation larger than the steady-state table ==\n");
    seed(N);
    { struct stat st; ok(stat("utxo.dat", &st) == 0 && st.st_size > 65536L*44,
         "the seeded WAL is bigger than 65,536 records could ever be"); }
    int r = tx_dispatch_init();
    ok(r == 1, "tx_dispatch_init comes up (old code: -2 from the replay, counted as ready)");
    long cnt = txacc_snapshot_count();
    printf("      snapshot holds %ld entries, WAL holds %ld\n", cnt, N);
    ok(cnt == N, "and the snapshot holds EVERY entry, not the first 65,536");

    printf("== the writer-count cross-check refuses a snapshot that disagrees ==\n");
    { FILE* f = fopen("utxo_lsm_table.map", "wb");
      unsigned long long bogus_n = 42, mask = (1ULL<<18) - 1;
      fwrite(&bogus_n, 8, 1, f); fwrite(&mask, 8, 1, f); fclose(f); }
    r = tx_dispatch_init();
    ok(r == 0, "with the writer claiming 42 live entries, the snapshot REFUSES rather than serve");
    { FILE* f = fopen("utxo_lsm_table.map", "wb");
      unsigned long long good_n = (unsigned long long)N, mask = (1ULL<<18) - 1;
      fwrite(&good_n, 8, 1, f); fwrite(&mask, 8, 1, f); fclose(f); }
    r = tx_dispatch_init();
    ok(r == 1, "with the writer's count matching, it comes up again");
    unlink("utxo_lsm_table.map");

    printf("\n%s (%d failure%s)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", fails, fails==1?"":"s");
    return fails ? 1 : 0;
}
