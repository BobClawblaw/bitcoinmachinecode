/* test_frontier_append.c -- THE GATE for the .frontier guard in
 * store_append_shared_x (bitcoin_store.asm).
 *
 * WHAT IS BEING GATED. store_append_shared self-heals its POSITION (it lseeks
 * to SEEK_END of whatever file it opens) but NOT its FILE NUMBER, and its
 * rollover walks forward one file at a time until one has room. So a cursor
 * that is behind does not fail loudly: it fills the leftover TAIL GAP of every
 * older blk file on the way up, and each of those writes puts a LOWER offset
 * at a HIGHER height. Run 26 accumulated six such breaks -- each the first
 * block after a restart -- and was still walking 2,300 files later.
 *
 * WHY A REAL APPEND. The branch was previously only dry-run assembled with 18
 * suites passing; none of them exercised an append LANDING at a frontier,
 * which is the one thing the guard exists to do. This test creates the exact
 * condition (cursor at N, a newer blk file already on disk) and appends for
 * real, then reads the bytes back through the index.
 *
 * WITHOUT THE GUARD this test FAILS at "h1 lands in blk00001, not the tail gap
 * of blk00000": the append goes to file 0, which is a lower file at a higher
 * height -- the defect itself. That failure has been observed by reverting the
 * guard; a gate nobody has watched fail is not a gate. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "test_tmpdir.h"

extern int  store_init(void* st);
extern long store_append_shared(void* st, long height, const void* hash,
                                const void* raw, unsigned long long len);
/* NOTE: we do NOT use store_get_at here. It answers from the IN-MEMORY
 * idx_len, which store_append_shared deliberately does not update -- the
 * shared design has each process re-read index.dat. test_shared verifies the
 * same way: parse the 48-byte record straight off disk.
 *   [0..31] hash   [32..35] file_no u32   [36..43] data_pos u64   [44..47] size u32 */
static int rec_get(unsigned long long height, unsigned long long out[3],
                   unsigned char out_hash[32]){
    unsigned char rec[48];
    int fd = open("index.dat", O_RDONLY); if(fd < 0) return -1;
    ssize_t r = pread(fd, rec, 48, (off_t)height*48);
    close(fd);
    if(r != 48) return -1;
    uint32_t fno, sz; uint64_t pos;
    memcpy(&fno, rec+32, 4); memcpy(&pos, rec+36, 8); memcpy(&sz, rec+44, 4);
    out[0] = pos; out[1] = sz; out[2] = fno;
    if(out_hash) memcpy(out_hash, rec, 32);
    return 1;
}

static int failures = 0;
static void ck(const char* l, long long g, long long e){
    if (g==e) printf("PASS %s (got %lld)\n", l, g);
    else { printf("FAIL %s got=%lld exp=%lld\n", l, g, e); failures++; }
}
static void ck_ge(const char* l, long long g, long long e){
    if (g>=e) printf("PASS %s (got %lld >= %lld)\n", l, g, e);
    else { printf("FAIL %s got=%lld exp>=%lld\n", l, g, e); failures++; }
}

static unsigned char st[4096];

/* create blkNNNNN.dat with `n` filler bytes; this is how we place a file
 * NEWER than the cursor, which is what run_26's reload-from-tip produced. */
static void mk_blk(unsigned file_no, long n){
    char nm[32]; snprintf(nm, sizeof nm, "blk%05u.dat", file_no);
    int fd = open(nm, O_RDWR|O_CREAT|O_TRUNC, 0644);
    if(fd < 0){ perror(nm); exit(2); }
    if(n > 0){
        unsigned char* b = malloc(n); memset(b, 0x7E, n);
        if(write(fd, b, n) != n){ perror("write filler"); exit(2); }
        free(b);
    }
    close(fd);
}
static long fsize(const char* nm){
    struct stat s; if(stat(nm, &s)) return -1; return (long)s.st_size;
}

/* read the payload back through the index record and compare */
static int readback_ok(unsigned long long meta[3], const unsigned char* want, unsigned len){
    char nm[32]; snprintf(nm, sizeof nm, "blk%05u.dat", (unsigned)meta[2]);
    int fd = open(nm, O_RDONLY); if(fd < 0) return 0;
    unsigned char got[256]; memset(got, 0, sizeof got);
    /* frame is [u32 len][u32 magic][payload]; data_pos points at the frame */
    ssize_t r = pread(fd, got, len, (off_t)meta[0] + 8);
    close(fd);
    return r == (ssize_t)len && memcmp(got, want, len) == 0;
}

int main(void){
    tt_isolate();

    /* pre-size index.dat for 8 records, like test_shared does */
    int ix = open("index.dat", O_RDWR|O_CREAT|O_TRUNC, 0644);
    if(ftruncate(ix, 8*48)){ perror("ftruncate"); return 1; }
    close(ix);
    int lockfd = open("append.lock", O_RDWR|O_CREAT, 0644);

    memset(st, 0, sizeof st);
    ck("store_init", store_init(st), 1);
    *(int*)((char*)st+40) = lockfd;          /* flock fd */
    *(int*)((char*)st+36) = 0xd9b4bef9;      /* mainnet magic */
    *(int*)((char*)st+28) = 0;               /* cur_file_no = 0 */
    *(int*)((char*)st+0)  = -1;              /* force lazy blk open */

    unsigned char h0[32], h1[32], h2[32];
    memset(h0, 0xA0, 32); memset(h1, 0xA1, 32); memset(h2, 0xA2, 32);
    unsigned char b0[64], b1[64], b2[64];
    memset(b0, 0x10, 64); memset(b1, 0x11, 64); memset(b2, 0x12, 64);

    unsigned long long m0[3], m1[3], m2[3];
    unsigned char gh[32];

    /* ---- h0: ordinary append, nothing newer exists. Cursor IS the frontier. */
    ck("append h0", store_append_shared(st, 0, h0, b0, 64), 0);
    ck("get h0 record", rec_get(0, m0, gh), 1);
    ck("h0 record carries h0's hash", memcmp(gh, h0, 32)==0, 1);
    ck("h0 file_no == 0", (long long)m0[2], 0);
    long f0_after_h0 = fsize("blk00000.dat");
    ck_ge("blk00000 grew for h0", f0_after_h0, 64);

    /* ---- THE CONDITION. A newer file exists while the cursor still says 0.
     * This is run 26 after store_reload set the cursor from a tip that lived
     * in an old file. Nothing here is corrupt -- the cursor is merely behind. */
    mk_blk(1, 1000);
    ck("cur_file_no still 0 before the append", *(int*)((char*)st+28), 0);

    /* ---- h1: the append that must land AT THE FRONTIER, not in the tail gap. */
    ck("append h1", store_append_shared(st, 1, h1, b1, 64), 1);
    ck("get h1 record", rec_get(1, m1, gh), 1);
    ck("h1 record carries h1's hash", memcmp(gh, h1, 32)==0, 1);
    ck("h1 lands in blk00001, not the tail gap of blk00000", (long long)m1[2], 1);
    ck_ge("h1 landed past the pre-existing bytes of blk00001", (long long)m1[0], 1000);
    ck("blk00000 was NOT extended by h1", fsize("blk00000.dat"), f0_after_h0);
    ck("h1 payload reads back through its index record", readback_ok(m1, b1, 64), 1);

    /* ---- the guard LOOPS: two newer files at once must skip to the newest. */
    mk_blk(2, 500);
    mk_blk(3, 0);          /* exists but empty -- access(F_OK) still finds it */
    ck("append h2", store_append_shared(st, 2, h2, b2, 64), 2);
    ck("get h2 record", rec_get(2, m2, gh), 1);
    ck("h2 record carries h2's hash", memcmp(gh, h2, 32)==0, 1);
    ck("h2 skips 2 and lands in blk00003 (the frontier)", (long long)m2[2], 3);
    ck("blk00002 was NOT filled", fsize("blk00002.dat"), 500);
    ck("h2 payload reads back", readback_ok(m2, b2, 64), 1);


    /* ---- RUN 26'S ACTUAL SHAPE, and the only way the monotonic check below
     * means anything. Above, the newer blk files held no INDEXED blocks, so
     * h0..h2 were monotonic among themselves even with the guard reverted.
     * The real defect needs a block already indexed in a HIGHER file, and then
     * a cursor that has fallen behind it -- which is what store_reload does
     * when the tip record points into an old file.
     *
     * Two handles on one store, as the daemon really has: st2 sits at the
     * frontier, st is the one whose cursor goes stale. */
    static unsigned char st2[4096];
    unsigned char h3[32], h4[32], b3[64], b4[64];
    unsigned long long m3[3], m4[3];
    memset(h3, 0xA3, 32); memset(h4, 0xA4, 32);
    memset(b3, 0x13, 64); memset(b4, 0x14, 64);

    memset(st2, 0, sizeof st2);
    ck("store_init st2 (frontier handle)", store_init(st2), 1);
    *(int*)((char*)st2+40) = lockfd;
    *(int*)((char*)st2+36) = 0xd9b4bef9;
    *(int*)((char*)st2+28) = 3;            /* this handle is AT the frontier */
    *(int*)((char*)st2+0)  = -1;
    ck("append h3 through the frontier handle", store_append_shared(st2, 3, h3, b3, 64), 3);
    ck("get h3 record", rec_get(3, m3, gh), 1);
    ck_ge("h3 is indexed in blk00003 or newer", (long long)m3[2], 3);

    /* the cursor falls behind -- exactly what store_reload produces when the
     * tip record lives in an old file. Nothing is corrupt; it is just stale. */
    *(int*)((char*)st+28) = 0;
    *(int*)((char*)st+0)  = -1;
    ck("append h4 with the cursor behind h3's file",
       store_append_shared(st, 4, h4, b4, 64), 4);
    ck("get h4 record", rec_get(4, m4, gh), 1);
    ck_ge("h4 does NOT land in a lower file than h3", (long long)m4[2], (long long)m3[2]);
    ck("h4 payload reads back", readback_ok(m4, b4, 64), 1);

    /* ---- the property the whole thing exists for: file_no never decreases
     * as height increases (what archive_layout_monotonic checks). */
    int mono = 1;
    unsigned long long prev_file = 0, prev_pos = 0;
    for(int h=0; h<=4; h++){
        unsigned long long m[3];
        if(rec_get(h, m, NULL) != 1){ mono = 0; break; }
        if(h){
            if(m[2] < prev_file) mono = 0;
            else if(m[2] == prev_file && m[0] <= prev_pos) mono = 0;
        }
        prev_file = m[2]; prev_pos = m[0];
    }
    ck("layout is monotonic across h0..h4", mono, 1);

    /* ---- h0 must still be readable; the guard must not disturb old records */
    ck("h0 payload still reads back", readback_ok(m0, b0, 64), 1);

    printf(failures ? "\nFAILURES: %d\n" : "\nALL FRONTIER GATE CHECKS PASSED\n", failures);
    return failures ? 1 : 0;
}
