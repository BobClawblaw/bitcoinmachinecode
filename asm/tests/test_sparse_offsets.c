/* Every sparse-index entry in a run must point at its own key.
 *
 * The sparse index is (key, file_offset) sampled every SPARSE_STRIDE records;
 * lookups binary-search it and seek to file_offset. When compaction output
 * became buffered (2026-08-31), the offset was still taken from
 * lseek(SEEK_CUR) on the output fd -- which reports bytes FLUSHED, not bytes
 * emitted -- so every entry pointed up to 1 MB too early. All the LSM tests
 * passed. A byte comparison of old vs new output caught it: 35,675 differing
 * bytes, all in the sparse index. This test makes that invariant explicit,
 * for runs produced by flush AND by compaction. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include "test_tmpdir.h"
typedef uint8_t u8; typedef uint32_t u32;
extern long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long long blob_cap);
extern int  utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const u8 txid[32], u32 index, unsigned long long value,
                         unsigned long long height, unsigned long long is_cb, const u8* script, unsigned long slen);
extern long utxo_lsm_compact(void* lst);
extern void utxo_lsm_close(void* lst);
struct lsm_state {
    long log_fd, idx_fd; unsigned long long log_len, ckpt_log_off, ckpt_n;
    unsigned long long op_count, op_threshold, fill_threshold;
    void* tomb_buf; unsigned long long tomb_cap, tomb_n, total_live, next_gen;
    void* manifest_buf; unsigned long long manifest_cap, manifest_n;
    void* scratch_buf; unsigned long long scratch_cap; unsigned long long next_run_no;
    void* tomb_hash_buf; unsigned long long tomb_hash_mask;
};
#define BLOOM_MAX_BYTES (4*1024*1024)
#define SCRIPT_MAX_BYTES 65536
static int fails = 0;
static void ok(int c, const char* w){ printf("  %s %s\n", c?"ok ":"FAIL", w); if(!c) fails++; }

/* Run header (44 bytes): magic(4) gen(8) nrec(8) x(8) sparse_off(8) sparse_n(8). */
static long check_run(const char* name, long* entries){
    int fd = open(name, O_RDONLY); if (fd < 0) return -1;
    unsigned char h[44]; if (pread(fd, h, 44, 0) != 44){ close(fd); return -1; }
    uint64_t sparse_off, sparse_n; memcpy(&sparse_off, h+28, 8); memcpy(&sparse_n, h+36, 8);
    long bad = 0;
    for (uint64_t i = 0; i < sparse_n; i++){
        unsigned char e[44]; if (pread(fd, e, 44, (off_t)(sparse_off + i*44)) != 44){ bad++; continue; }
        uint64_t off; memcpy(&off, e+36, 8);
        unsigned char rec[37]; if (pread(fd, rec, 37, (off_t)off) != 37){ bad++; continue; }
        if (memcmp(rec, e, 36) != 0) bad++;      /* the key at the offset must be the entry's key */
    }
    close(fd); *entries += (long)sparse_n; return bad;
}
static long check_all(long* entries, long* runs){
    long bad = 0; *entries = 0; *runs = 0;
    DIR* d = opendir("."); struct dirent* de;
    while ((de = readdir(d))){
        if (strncmp(de->d_name, "utxo_run_", 9)) continue;
        long b = check_run(de->d_name, entries); if (b < 0) b = 1;
        bad += b; (*runs)++;
    }
    closedir(d); return bad;
}

int main(void){
    tt_isolate();
    unsigned long slots = 1UL<<16;
    void* table = malloc((size_t)utxo_struct_size(slots)); void* blob = malloc(64UL<<20);
    utxo_init(table, slots, blob, 64UL<<20);
    struct lsm_state lst; memset(&lst,0,sizeof lst);
    unsigned long long op_th = slots*2, tomb_cap = op_th, desc_cap = slots*3;
    lst.op_threshold = op_th; lst.fill_threshold = slots*3/4;
    lst.tomb_buf = malloc(tomb_cap*36); lst.tomb_cap = tomb_cap;
    lst.manifest_buf = malloc(256*16); lst.manifest_cap = 256;
    lst.scratch_cap = desc_cap*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES; lst.scratch_buf = malloc(lst.scratch_cap);
    if (utxo_lsm_init(&lst) != 1){ fprintf(stderr,"lsm init failed\n"); return 1; }
    u8 spk[34]; memset(spk, 0x51, 34); spk[1]=0x20;
    /* enough puts for several flushes (> 2 MB of output, i.e. past the 1 MB
     * write buffer, so a flushed/unflushed offset mismatch is exposed) */
    const long N = 400000;
    for (long i = 0; i < N; i++){
        u8 txid[32]; memset(txid,0,32); memcpy(txid,&i,sizeof i); txid[31]=0x33;
        if (utxo_lsm_put(&lst, table, txid, (u32)(i&3), 1000+i, 100+(i%50), 0, spk, 34) != 1){ fprintf(stderr,"put failed\n"); return 1; }
    }
    long entries, runs;
    printf("== runs written by FLUSH ==\n");
    long bad = check_all(&entries, &runs);
    printf("      %ld run(s), %ld sparse entries\n", runs, entries);
    ok(runs >= 2 && entries > 100, "several runs, with real sparse indexes to check");
    ok(bad == 0, "every sparse entry points at its own key");

    printf("== runs written by COMPACTION (buffered output) ==\n");
    while (lst.manifest_n > 1){ if (utxo_lsm_compact(&lst) <= 0) break; }
    bad = check_all(&entries, &runs);
    printf("      %ld run(s), %ld sparse entries\n", runs, entries);
    ok(runs == 1, "compacted down to one run");
    ok(entries > 1000, "whose sparse index is large (output well past the 1 MB buffer)");
    ok(bad == 0, "every sparse entry points at its own key -- the offset counted buffered bytes");
    utxo_lsm_close(&lst);
    printf("\n%s (%d failure%s)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", fails, fails==1?"":"s");
    return fails ? 1 : 0;
}
