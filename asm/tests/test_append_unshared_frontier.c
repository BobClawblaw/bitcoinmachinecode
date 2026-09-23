/* test_append_unshared_frontier.c -- store_append (the NON-shared path).
 *
 * store_append_shared got .frontier on 2026-09-17. This function did not, and
 * the two failure modes are not the same. The shared one lseeks to SEEK_END, so
 * it self-heals its POSITION and only ever needed its FILE NUMBER guarded. This
 * one TRUSTS cur_file_pos -- for the rollover check and for the lseek it writes
 * at -- and that is what actually destroyed a block:
 *
 *   2026-09-17: a C-side archive_store_frontier() advanced cur_file_no to 5762
 *   and left cur_file_pos at 0. The genesis seed uses store_append. It wrote
 *   293 bytes at offset 0 of blk05762.dat, over the start of height 967422,
 *   which the node then served as a 1-transaction block under the correct hash.
 *
 * So the position resync is the safety-critical half and the frontier walk is
 * the monotonicity half. This test covers both, and CASE A is the incident
 * itself, reduced. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "test_tmpdir.h"

extern int  store_init(void* st);
extern int  store_append(void* st, const void* hash, const void* raw, unsigned long long len);
extern int  store_get_at(void* st, unsigned long long height, unsigned long long* out_meta);

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
#define CUR_FILE_NO(s)  (*(int*)((char*)(s)+28))
#define CUR_FILE_POS(s) (*(int*)((char*)(s)+32))

static void mk_blk(unsigned n, long len, unsigned char fill){
    char nm[32]; snprintf(nm, sizeof nm, "blk%05u.dat", n);
    int fd = open(nm, O_RDWR|O_CREAT|O_TRUNC, 0644);
    if (fd < 0){ perror(nm); exit(2); }
    unsigned char* b = malloc((size_t)len); memset(b, fill, (size_t)len);
    if (write(fd, b, (size_t)len) != len){ perror("write"); exit(2); }
    free(b); close(fd);
}
static long fsize(const char* nm){ struct stat s; return stat(nm,&s) ? -1 : (long)s.st_size; }
/* every byte in [0,len) of the file still equals `fill` */
static int intact(const char* nm, long len, unsigned char fill){
    int fd = open(nm, O_RDONLY); if (fd < 0) return 0;
    unsigned char* b = malloc((size_t)len);
    ssize_t r = pread(fd, b, (size_t)len, 0); close(fd);
    int ok = (r == (ssize_t)len);
    for (long i = 0; ok && i < len; i++) if (b[i] != fill) ok = 0;
    free(b); return ok;
}

int main(void){
    tt_isolate();
    memset(st, 0, sizeof st);
    ck("store_init", store_init(st), 1);

    unsigned char h[8][32], raw[8][64];
    for (int i = 0; i < 8; i++){ memset(h[i], 0xB0+i, 32); memset(raw[i], 0x20+i, 64); }
    unsigned long long m[3];

    /* two ordinary appends -- both land in blk00000 */
    ck("append h0", store_append(st, h[0], raw[0], 64), 0);
    ck("append h1", store_append(st, h[1], raw[1], 64), 1);
    ck("h1 is in blk00000", (store_get_at(st,1,m), (long long)m[2]), 0);

    /* ---- CASE A: the incident's monotonicity half. The cursor is behind and
     * a newer file exists. Unguarded, store_append writes into the OLD file at
     * the old position -- a lower offset at a higher height, and on 2026-09-17
     * that landed 293 bytes over the start of a live block. Guarded, the walk
     * moves the cursor to the frontier and RETAKES cur_file_pos from the new
     * file, because a position measured in one file means nothing in another. */
    mk_blk(1, 5000, 0x5A);
    CUR_FILE_NO(st)  = 0;      /* behind ... */
    CUR_FILE_POS(st) = 0;      /* ... with a position belonging to file 0 */
    ck("append h2 with the cursor behind a newer file", store_append(st, h[2], raw[2], 64), 2);
    ck("get h2", store_get_at(st, 2, m), 1);
    ck("h2 lands in the frontier blk00001, not blk00000's tail gap", (long long)m[2], 1);
    ck_ge("h2 was written PAST blk00001's bytes, not over them", (long long)m[0], 5000);
    ck("blk00001's original 5000 bytes are INTACT", intact("blk00001.dat", 5000, 0x5A), 1);
    ck_ge("blk00001 grew rather than being overwritten", fsize("blk00001.dat"), 5000 + 8 + 64);
    { unsigned long long m0[3]; store_get_at(st, 0, m0);
      char nm[32]; snprintf(nm, sizeof nm, "blk%05u.dat", (unsigned)m0[2]);
      int fd = open(nm, O_RDONLY); unsigned char got[64]; memset(got, 0, 64);
      if (fd >= 0){ (void)!pread(fd, got, 64, (off_t)m0[0] + 8); close(fd); }
      ck("h0's block was not disturbed", memcmp(got, raw[0], 64) == 0, 1); }

    /* ---- CASE B: the walk crosses MORE than one file. */
    mk_blk(2, 300, 0x6B);
    mk_blk(3, 400, 0x7C);
    CUR_FILE_NO(st)  = 0;
    CUR_FILE_POS(st) = 0;
    ck("append h3 with the cursor at 0 and the frontier at 3", store_append(st, h[3], raw[3], 64), 3);
    ck("get h3", store_get_at(st, 3, m), 1);
    ck("h3 lands at the frontier blk00003", (long long)m[2], 3);
    ck_ge("h3 is past blk00003's existing bytes", (long long)m[0], 400);
    ck("blk00003's original bytes are intact", intact("blk00003.dat", 400, 0x7C), 1);
    ck("blk00002 was NOT filled on the way", fsize("blk00002.dat"), 300);

    /* ---- CASE C: the 2026-09-17 incident in its exact shape, and the reason
     * the struct now carries +44 pos_file_no.
     *
     * Something sets cur_file_no to a file that has NO successor, and leaves
     * cur_file_pos belonging to a different file. The frontier walk cannot help
     * -- there is no blk(cur+1) to find -- so before 2026-09-18 the stale
     * position was trusted and the write landed at that offset in the wrong
     * file. That is precisely how 293 bytes went over the start of height
     * 967422.
     *
     * cur_file_pos is a POSITION, and a position only means anything relative
     * to a file. +44 records which file it was measured in; store_append
     * compares the two and retakes the position when they disagree. */
    {
        /* h3's append left cur_file_pos measured in file 3. Now two newer files
         * appear and an outside party advances cur_file_no to the newest of
         * them WITHOUT retaking the position -- exactly what
         * archive_store_frontier() did on 2026-09-17. blk00006 does not exist,
         * so the frontier walk has nowhere to go and cannot rescue this; only
         * the +44 mismatch can. */
        mk_blk(4, 200, 0x8D);
        mk_blk(5, 600, 0x9E);
        CUR_FILE_NO(st) = 5;       /* advanced ... */
        /* cur_file_pos deliberately NOT touched: it still describes file 3 */
        ck("append h4: file_no advanced to 5, position still file 3's",
           store_append(st, h[4], raw[4], 64), 4);
        ck("get h4", store_get_at(st, 4, m), 1);
        ck("h4 is in blk00005", (long long)m[2], 5);
        ck_ge("the stale position was REJECTED and retaken from blk00005",
              (long long)m[0], 600);
        ck("blk00005's 600 existing bytes are intact", intact("blk00005.dat", 600, 0x9E), 1);
        ck_ge("blk00005 grew rather than being overwritten", fsize("blk00005.dat"), 600 + 8 + 64);
        ck("blk00004 was not touched", fsize("blk00004.dat"), 200);
        /* the block sitting where the stale position pointed survives */
        { unsigned long long m3[3]; store_get_at(st, 3, m3);
          char nm[32]; snprintf(nm, sizeof nm, "blk%05u.dat", (unsigned)m3[2]);
          int fd = open(nm, O_RDONLY); unsigned char got[64]; memset(got, 0, 64);
          if (fd >= 0){ (void)!pread(fd, got, 64, (off_t)m3[0] + 8); close(fd); }
          ck("h3's block was not clobbered by the stale write", memcmp(got, raw[3], 64) == 0, 1); }
    }

    /* ---- the property both halves exist for */
    int mono = 1; unsigned long long pf = 0, pp = 0;
    for (int i = 0; i <= 4; i++){
        unsigned long long mm[3];
        if (store_get_at(st, i, mm) != 1){ mono = 0; break; }
        if (i && (mm[2] < pf || (mm[2] == pf && mm[0] <= pp))) mono = 0;
        pf = mm[2]; pp = mm[0];
    }
    ck("layout is monotonic across h0..h4", mono, 1);

    printf(failures ? "\nFAILURES: %d\n" : "\nALL UNSHARED-APPEND CHECKS PASSED\n", failures);
    return failures ? 1 : 0;
}
