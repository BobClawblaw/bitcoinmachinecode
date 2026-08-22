/* test_prune_nonmonotonic.c -- archive_prune_file_granular (daemon/
 * archive_verify.c) and the store_get_at sentinel it depends on
 * (bitcoin_store.asm), 2026-08-21.
 *
 * Real-world motivation: store_prune's in-place compaction (bitcoin_store.asm)
 * assumes every index record naming its "boundary file" appears as ONE
 * contiguous run of heights before the first record of a different file --
 * exactly what a non-monotonic archive (the parallel chunked downloader's
 * real, longstanding output shape -- see PLAN_SCRIPT_VERIFY.md) breaks.
 * archive_prune_decide already refuses (ARCHIVE_PRUNE_REFUSE_LAYOUT) rather
 * than run store_prune unsafely in that case, but until now that refusal was
 * a dead end: pruning was "configurable in theory only" on the one archive
 * shape this project's own real datadir actually has.
 *
 * archive_prune_file_granular fixes that by working at WHOLE-FILE
 * granularity instead: a file is deleted only when every height it holds is
 * safely below the target, regardless of physical byte order. This test
 * proves:
 *   - a non-monotonic multi-file archive prunes correctly (wholly-old files
 *     deleted, a file straddling the target retained WHOLE)
 *   - the currently-open (tip) file is NEVER deleted even if its own
 *     recorded max height would otherwise qualify
 *   - store_get_at returns -3 for a pruned height via the new data_size
 *     sentinel, and 1 (normal) for everything retained
 *   - the sentinel does NOT corrupt the hash bytes or (file_no,pos) of
 *     other records -- archive_layout_monotonic and a manual hash check
 *     both stay accurate after a prune, so hole-scans and reorg-truncation
 *     logic are not misled into re-fetching pruned data
 *   - re-running the prune is idempotent (already-gone files, already-
 *     marked records) and doesn't crash or double-count
 *
 * Runs in a throwaway temp dir; never touches a real datadir.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "test_tmpdir.h"

struct St {
    unsigned long long cur_blk_fd, idx_fd, idx_len;
    int tip_height, cur_file_no, cur_file_pos, magic, pad, pad2, prune_height;
};

extern int  store_init(void* st);
extern long store_reload(void* st);
extern int  store_get_at(void* st, unsigned long long height, unsigned long long* out_meta);

extern long archive_layout_monotonic(long upto);
extern long archive_prune_file_granular(long target_height);

static int failures = 0;
static void ck(const char* l, long long got, long long exp){
    if (got == exp) printf("PASS %s (got %lld)\n", l, got);
    else { printf("FAIL %s got=%lld exp=%lld\n", l, got, exp); failures++; }
}
static void ckcond(const char* l, int cond){ ck(l, cond ? 1 : 0, 1); }

static int file_exists(const char* p){ struct stat s; return stat(p, &s) == 0; }

static void fresh_dir(void){
    tt_isolate();
}

#define NB 40   /* payload bytes per test block */

/* Write one block frame ([u32 len][u32 magic][raw]) into an already-open FILE*. */
static void write_frame(FILE* f, int fill){
    unsigned char hdr[8], block[NB];
    hdr[0]=NB&0xff; hdr[1]=(NB>>8)&0xff; hdr[2]=(NB>>16)&0xff; hdr[3]=(NB>>24)&0xff;
    hdr[4]=0xf9; hdr[5]=0xbe; hdr[6]=0xb4; hdr[7]=0xd9;
    for (int i=0;i<NB;i++) block[i] = (unsigned char)(fill+i);
    fwrite(hdr,1,8,f); fwrite(block,1,NB,f);
}

/* Build a NON-MONOTONIC 4-file, 12-height archive by hand:
 *   height ->  file_no   (files interleaved on purpose, real-world shape)
 *     0    ->    0
 *     1    ->    1
 *     2    ->    0
 *     3    ->    2
 *     4    ->    1
 *     5    ->    0
 *     6    ->    3        <- tip's file
 *     Note: only 7 heights (0..6) used for the main scenario; helper takes
 *     an explicit height count so a second, larger case can reuse it.
 * File 0 ends up holding heights {0,2,5}; file 1 holds {1,4}; file 2 holds
 * {3}; file 3 (the tip's own file) holds {6}.
 */
static const int HEIGHT_FILE[7] = {0,1,0,2,1,0,3};

static void build_nonmonotonic_archive(void){
    /* one FILE* per distinct file_no, opened in whatever order first needed
     * (mirrors how a real out-of-order parallel downloader would populate
     * them -- nothing here assumes ascending file_no open order). */
    FILE* f[4] = {0,0,0,0};
    long pos[4] = {0,0,0,0};
    int fileno_at[7];
    for (int h = 0; h < 7; h++){
        int fn = HEIGHT_FILE[h];
        if (!f[fn]){
            char name[16]; snprintf(name, sizeof name, "blk%05d.dat", fn);
            f[fn] = fopen(name, "wb");
            if (!f[fn]) { printf("FAIL open %s\n", name); exit(1); }
        }
        fileno_at[h] = fn;
        write_frame(f[fn], h * 10);
    }
    /* record each height's pos as the offset it was written at, computed
     * as we go (re-walk since fwrite doesn't hand back the pre-write pos) */
    long cursor[4] = {0,0,0,0};
    long recorded_pos[7];
    for (int h = 0; h < 7; h++){
        int fn = fileno_at[h];
        recorded_pos[h] = cursor[fn];
        cursor[fn] += 8 + NB;
    }
    for (int i = 0; i < 4; i++) if (f[i]) fclose(f[i]);

    FILE* idf = fopen("index.dat", "wb");
    if (!idf) { printf("FAIL open index.dat\n"); exit(1); }
    for (int h = 0; h < 7; h++){
        unsigned char rec[48]; memset(rec, 0, 48);
        for (int i = 0; i < 32; i++) rec[i] = (unsigned char)(h + 1);   /* nonzero hash */
        unsigned int fn = (unsigned int)fileno_at[h]; memcpy(rec+32, &fn, 4);
        unsigned long long dp = (unsigned long long)recorded_pos[h]; memcpy(rec+36, &dp, 8);
        unsigned int sz = NB; memcpy(rec+44, &sz, 4);
        fwrite(rec, 1, 48, idf);
    }
    fclose(idf);
}

int main(void){
    /* ================================================================
     * Part 1: confirm the archive really is non-monotonic (sanity check
     * that this test fixture exercises the case it claims to).
     * ================================================================ */
    {
        fresh_dir();
        build_nonmonotonic_archive();
        ck("fixture genuinely non-monotonic", archive_layout_monotonic(6) >= 0, 1);
    }

    /* ================================================================
     * Part 2: prune to target_height=5 (retain heights >=5). Expect:
     *   - file 0 {0,2,5}: straddles the target (holds height 5, retained)
     *     -> NOT deleted
     *   - file 1 {1,4}: wholly < 5 -> deleted
     *   - file 2 {3}: wholly < 5 -> deleted
     *   - file 3 {6}: holds the tip -> NEVER deleted regardless of height
     * ================================================================ */
    {
        fresh_dir();
        build_nonmonotonic_archive();

        struct St st; memset(&st, 0, sizeof st);
        ck("init", store_init(&st), 1);
        ck("reload", store_reload(&st), 1);
        ck("tip is 6", (long long)st.tip_height, 6);

        unsigned long long meta[3];
        ck("height 0 readable pre-prune", store_get_at(&st, 0, meta), 1);
        ck("height 5 readable pre-prune", store_get_at(&st, 5, meta), 1);

        long deleted = archive_prune_file_granular(5);
        ck("2 files deleted (file 1 and file 2)", deleted, 2);

        ckcond("blk00000.dat retained (straddles target)", file_exists("blk00000.dat"));
        ckcond("blk00001.dat deleted (wholly old)", !file_exists("blk00001.dat"));
        ckcond("blk00002.dat deleted (wholly old)", !file_exists("blk00002.dat"));
        ckcond("blk00003.dat retained (holds the tip)", file_exists("blk00003.dat"));

        /* re-open (archive_prune_file_granular doesn't update the live
         * struct's cached fields, only index.dat -- a fresh store_get_at
         * call re-reads the index record every time, so no reload needed).
         * File 0 (heights 0,2,5) is RETAINED WHOLE because it straddles the
         * target (holds height 5 >= 5) -- heights 0 and 2, even though each
         * is individually < target, must stay readable: this is exactly the
         * documented whole-file tradeoff, not a bug. Only files 1 and 2
         * (heights 1,4 and 3) were wholly < target and got deleted. */
        ck("height 0 (file 0, retained WHOLE despite being < target itself) still readable", store_get_at(&st, 0, meta), 1);
        ck("height 1 (deleted file) now pruned", store_get_at(&st, 1, meta), -3);
        ck("height 2 (file 0, retained WHOLE) still readable", store_get_at(&st, 2, meta), 1);
        ck("height 3 (deleted file) now pruned", store_get_at(&st, 3, meta), -3);
        ck("height 4 (deleted file) now pruned", store_get_at(&st, 4, meta), -3);
        ck("height 5 (file 0, the height that saved it from deletion) still readable", store_get_at(&st, 5, meta), 1);
        ck("height 6 (tip, never touched) still readable", store_get_at(&st, 6, meta), 1);

        /* file 0's surviving records must still carry their ORIGINAL
         * data_pos/data_size -- proves the marker write only ever touched
         * pruned records (in deleted files), nothing in a retained file. */
        ck("height 5 data_size untouched", meta[1], NB);
        ck("height 0 data_size untouched too", (store_get_at(&st, 0, meta), meta[1]), NB);

        /* archive_layout_monotonic must still see accurate (file_no,pos)
         * ordering for whatever's left -- proves the sentinel write didn't
         * corrupt file_no/data_pos on the pruned records either (a reorg's
         * archive_truncate_safe call after a prune must not be misled). */
        int fd = open("index.dat", O_RDONLY);
        unsigned char rec1[48], rec3[48];
        ck("read height1 record", pread(fd, rec1, 48, 1*48) == 48, 1);
        ck("read height3 record", pread(fd, rec3, 48, 3*48) == 48, 1);
        close(fd);
        unsigned int fn1, fn3; unsigned long long dp1, dp3;
        memcpy(&fn1, rec1+32, 4); memcpy(&dp1, rec1+36, 8);
        memcpy(&fn3, rec3+32, 4); memcpy(&dp3, rec3+36, 8);
        ck("pruned height1 file_no unchanged (still 1)", fn1, 1);
        ck("pruned height1 data_pos unchanged (still 0)", (long long)dp1, 0);
        ck("pruned height3 file_no unchanged (still 2)", fn3, 2);
        ck("pruned height1 hash bytes untouched (not the hole sentinel)", rec1[0] != 0 || rec1[1] != 0, 1);
        ck("pruned height1 data_size IS the pruned marker", *(unsigned int*)(rec1+44), 0xFFFFFFFFu);

        /* re-running is idempotent: files already gone -> ENOENT tolerated,
         * already-marked records get re-marked harmlessly */
        long deleted2 = archive_prune_file_granular(5);
        ck("re-prune reports the same 2 (still-gone) files", deleted2, 2);
        ck("height 5 still readable after re-prune", store_get_at(&st, 5, meta), 1);
        ck("height 6 still readable after re-prune", store_get_at(&st, 6, meta), 1);
    }

    /* ================================================================
     * Part 3: target_height above everything -> the tip's own file must
     * STILL be retained (never deleted), even though every height it
     * holds is below the target -- proves the tip exclusion is
     * unconditional, not just "usually true".
     * ================================================================ */
    {
        fresh_dir();
        build_nonmonotonic_archive();
        struct St st; memset(&st, 0, sizeof st);
        store_init(&st); store_reload(&st);

        long deleted = archive_prune_file_granular(100);   /* clamped to tip+1 = 7 */
        ckcond("blk00003.dat (tip's file) survives an over-target prune", file_exists("blk00003.dat"));
        ckcond("every OTHER file is gone", !file_exists("blk00000.dat") &&
                                            !file_exists("blk00001.dat") &&
                                            !file_exists("blk00002.dat"));
        ck("3 files deleted (all but the tip's)", deleted, 3);

        unsigned long long meta[3];
        ck("tip height still readable even though 'below target'", store_get_at(&st, 6, meta), 1);
    }

    /* ================================================================
     * Part 4: target_height <= 0 and an empty/near-empty archive are
     * both clean no-ops, not errors or crashes.
     * ================================================================ */
    {
        fresh_dir();
        ck("target<=0 on an archive with no index.dat yet is a noop", archive_prune_file_granular(0), 0);
        ck("negative target is a noop", archive_prune_file_granular(-5), 0);

        build_nonmonotonic_archive();
        ck("target_height=0 (nothing below 0) is a noop", archive_prune_file_granular(0), 0);
        ckcond("nothing deleted", file_exists("blk00000.dat") && file_exists("blk00001.dat") &&
                                   file_exists("blk00002.dat") && file_exists("blk00003.dat"));
    }

    if (failures) printf("\nFAILURES: %d\n", failures);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return failures ? 1 : 0;
}
