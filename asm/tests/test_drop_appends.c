/* tests/test_drop_appends.c -- plan B16 (2026-10-11): the undo append stream
 * is dropped from the page cache behind the writer (bmc.dropappends).
 *
 * WHY
 * ---
 * Run 49 read the UTXO run records with pread (bmc.lsmreads=pread) so the
 * run files would stay page cache and leave the PSS. They left the PSS and
 * then left the page cache too: the blk and rev append streams (400 GB by
 * block 650,000) sit on the same inactive list, and the kernel evicted the
 * run pages behind them -- 76% of the run bytes resident at block 650,000,
 * 212 GB of run-file re-reads from disk, the get column 4x run 46's. A
 * mapped page wins that eviction, which is why the mmap path never showed
 * it. The fix drops each append stream behind its writer so it never
 * competes.
 *
 * WHAT THIS CHECKS (undo_log.c's side; the blk side is the same two calls
 * once per file behind the applier in utxo_live.c)
 *   1. drop off: a 40 MB rev stream is fully resident after it is written
 *      (the control -- the page cache keeps what the kernel is left to keep).
 *   2. drop on: writing on to 100 MB leaves the first 64 MB with (nearly) no
 *      resident page: every 16 MB step writes back and drops the step before
 *      it. Reverting the fix (no sync_file_range/fadvise) leaves the file
 *      resident and this FAILS.
 *   3. the roll: past UNDO_REV_MAX the old file is dropped whole, tail
 *      included.
 *   4. the records read back intact through undo_load at every phase -- the
 *      drop is a cache hint, never a change to the bytes.
 * Residency is measured with mincore(2) on a private read-only mapping of the
 * file, which touches no page.
 */
#include "test_tmpdir.h"
#include "../daemon/undo_store.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

typedef unsigned char u8; typedef unsigned int u32; typedef unsigned short u16; typedef unsigned long long u64;
typedef struct { u8 txid[32]; u32 index; u64 value; u32 height; u8 is_coinbase; u16 slen; u8 script[10000]; } undo_rec_t;
extern long undo_append_record(long height, const u8 txid[32], u32 index, u64 value, u32 utxo_height, u8 is_coinbase, const u8* script, u16 slen);
extern long undo_commit(long height);
extern long undo_load(long height, undo_rec_t* out, long max_recs);
extern void undo_set_drop_appends(int on);
extern unsigned long long undo_drop_count(void);

static int fails;
#define CHECK(c, ...) do{ if(!(c)){ fails++; printf("FAIL: " __VA_ARGS__); printf("\n"); } }while(0)

/* resident fraction (0..1) of bytes [off, off+len) of `path` */
static double resident(const char* path, u64 off, u64 len){
    int fd = open(path, O_RDONLY); if (fd < 0) return -1;
    struct stat sb; if (fstat(fd, &sb) != 0){ close(fd); return -1; }
    if (len == 0 || off + len > (u64)sb.st_size) len = (u64)sb.st_size - off;
    long ps = sysconf(_SC_PAGESIZE);
    u64 n = (len + ps - 1) / ps;
    void* m = mmap(0, (size_t)len, PROT_READ, MAP_PRIVATE, fd, (off_t)off);
    close(fd);
    if (m == MAP_FAILED) return -1;
    u8* vec = calloc(n, 1);
    if (mincore(m, (size_t)len, vec) != 0){ munmap(m, (size_t)len); free(vec); return -1; }
    u64 r = 0; for (u64 i = 0; i < n; i++) r += vec[i] & 1;
    munmap(m, (size_t)len); free(vec);
    return (double)r / (double)n;
}
static u64 fsize(const char* path){ struct stat sb; return stat(path, &sb) == 0 ? (u64)sb.st_size : 0; }

#define RECS 64
#define SLEN 1000
static long g_next_h;
/* append heights until rev file `name` is at least `target` bytes */
static void fill_to(const char* name, u64 target){
    u8 script[SLEN]; u8 txid[32];
    while (fsize(name) < target){
        long h = g_next_h++;
        for (int i = 0; i < RECS; i++){
            memset(txid, (int)(h & 0xff), 32); txid[0] = (u8)i; memcpy(txid + 1, &h, sizeof h);
            memset(script, (int)((h + i) & 0xff), SLEN);
            if (undo_append_record(h, txid, (u32)i, (u64)h * 1000 + i, (u32)h, 0, script, SLEN) != 1){ printf("FAIL: append h=%ld i=%d\n", h, i); exit(1); }
        }
        if (undo_commit(h) != 1){ printf("FAIL: commit h=%ld\n", h); exit(1); }
    }
}
static void verify_height(long h){
    static undo_rec_t recs[RECS];
    long n = undo_load(h, recs, RECS);
    CHECK(n == RECS, "undo_load(%ld) = %ld, want %d", h, n, RECS);
    if (n != RECS) return;
    for (int i = 0; i < RECS; i++){
        long hh; memcpy(&hh, recs[i].txid + 1, sizeof hh);
        CHECK(recs[i].txid[0] == (u8)i && hh == h && recs[i].index == (u32)i && recs[i].value == (u64)h * 1000 + i && recs[i].slen == SLEN && recs[i].script[7] == (u8)((h + i) & 0xff),
              "record h=%ld i=%d read back wrong", h, i);
    }
}

int main(void){
    tt_isolate();
    const u64 MB = 1u << 20;
    const char* f0 = "rev00000.dat"; const char* f1 = "rev00001.dat";

    /* 1. control: drop off, the stream stays resident */
    undo_set_drop_appends(0);
    fill_to(f0, 40 * MB);
    double r = resident(f0, 0, 32 * MB);
    printf("phase 1 (drop off): %llu MB written, [0,32MB) resident %.1f%%\n", fsize(f0) / MB, 100 * r);
    CHECK(r >= 0.90, "control: the undo stream should be resident when nothing drops it (%.1f%%)", 100 * r);
    CHECK(undo_drop_count() == 0, "drop count %llu with the knob off", undo_drop_count());
    verify_height(0); verify_height(g_next_h - 1);

    /* 2. drop on: the first 64 MB go, the last two steps may stay */
    undo_set_drop_appends(1);
    fill_to(f0, 100 * MB);
    r = resident(f0, 0, 64 * MB);
    double rt = resident(f0, 64 * MB, 0);
    printf("phase 2 (drop on): %llu MB written, [0,64MB) resident %.1f%%, [64MB,end) %.1f%%, drops %llu\n", fsize(f0) / MB, 100 * r, 100 * rt, undo_drop_count());
    CHECK(r <= 0.02, "the dropped steps are still resident (%.1f%%)", 100 * r);
    CHECK(undo_drop_count() >= 4, "drop count %llu, want >= 4 for 100 MB", undo_drop_count());
    verify_height(0); verify_height(g_next_h / 2); verify_height(g_next_h - 1);

    /* 3. the roll: past UNDO_REV_MAX the old file is dropped whole */
    fill_to(f1, 4 * MB);
    r = resident(f0, 0, 0);
    printf("phase 3 (roll): %s %llu MB resident %.1f%%, %s %llu MB, drops %llu\n", f0, fsize(f0) / MB, 100 * r, f1, fsize(f1) / MB, undo_drop_count());
    CHECK(fsize(f0) >= UNDO_REV_MAX, "the roll did not happen (%llu bytes)", fsize(f0));
    CHECK(r <= 0.02, "the rolled file is still resident (%.1f%%)", 100 * r);
    verify_height(0); verify_height(g_next_h - 1);

    if (fails){ printf("%d FAILURE(S)\n", fails); return 1; }
    printf("ALL TESTS PASSED (test_drop_appends)\n");
    return 0;
}
