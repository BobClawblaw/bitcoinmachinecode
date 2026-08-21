/* test_archive_truncate_nonmonotonic.c -- store_truncate_index_only
 * (bitcoin_store.asm) and archive_truncate_safe (daemon/archive_verify.c),
 * 2026-08-21.
 *
 * Real-world motivation: the parallel chunked downloader can leave the
 * block archive laid out out of height order (see PLAN_SCRIPT_VERIFY.md's
 * "Related known issues"), which is exactly the shape of archive that once
 * made a bare store_truncate_to destroy ~600GB of real block data (see
 * store_layout_monotonic's header comment in bitcoin_store.asm). Every
 * truncating caller -- reorg's disconnect path (daemon/reorg.c) and this
 * project's own corruption self-repair (archive_verify_and_repair) -- used
 * to either safely refuse outright on such an archive, or (before the
 * guard existed) destroy it. Neither reorg nor repair could actually make
 * progress on a non-monotonic archive.
 *
 * store_truncate_index_only fixes that for the TRUNCATE-FROM-THE-TIP case
 * (reorg disconnect, corruption repair -- NOT pruning, which removes from
 * the bottom and genuinely needs the physical bytes reclaimed, so it is
 * intentionally NOT touched by this fix and still refuses on non-monotonic
 * layout): index.dat is positional-by-height by construction, so shrinking
 * it never needs to trust where the block DATA it points to physically
 * lives. archive_truncate_safe is the dispatcher every real caller should
 * use: physical (space-reclaiming) store_truncate_to when the archive is
 * genuinely monotonic below the target, else this always-safe fallback.
 *
 * Runs in a throwaway temp dir; never touches a real datadir.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* state struct layout must mirror bitcoin_store.asm (see tests/test_truncate.c) */
struct St {
    unsigned long long cur_blk_fd, idx_fd, idx_len;
    int tip_height, cur_file_no, cur_file_pos, magic, pad, pad2, prune_height;
};

extern int  store_init(void* st);
extern int  store_append(void* st, const void* hash, const void* raw, unsigned long long len);
extern int  store_get_at(void* st, unsigned long long height, unsigned long long* out_meta);
extern long store_reload(void* st);
extern long long store_truncate_to(void* st, long long target_height);
extern long long store_truncate_index_only(void* st, long long target_height);

extern long archive_layout_monotonic(long upto);
extern int  archive_truncate_safe(void* st, long target_height, int* out_used_index_only);

static int failures = 0;
static void ck(const char* l, long long got, long long exp){
    if (got == exp) printf("PASS %s (got %lld)\n", l, got);
    else { printf("FAIL %s got=%lld exp=%lld\n", l, got, exp); failures++; }
}
static void ckcond(const char* l, int cond){ ck(l, cond ? 1 : 0, 1); }

static long filesize(const char* path){
    struct stat sb;
    if (stat(path, &sb) != 0) return -1;
    return (long)sb.st_size;
}

#define NBLK 8
static unsigned char g_hashes[NBLK][32];
static unsigned char g_raw[NBLK][96];   /* max used size is 40+7*4=68; margin */
static int g_sizes[NBLK];

static void build_archive(struct St* st){
    memset(st, 0, sizeof *st);
    if (store_init(st) != 1) { printf("FAIL store_init\n"); exit(1); }
    for (int h = 0; h < NBLK; h++){
        memset(g_hashes[h], 0, 32);
        g_hashes[h][0] = (unsigned char)(h + 1);
        g_hashes[h][31] = (unsigned char)(0x40 + h);
        g_sizes[h] = 40 + h * 4;
        memset(g_raw[h], (unsigned char)(0xA0 + h), (size_t)g_sizes[h]);
        if (store_append(st, g_hashes[h], g_raw[h], (unsigned long long)g_sizes[h]) < 0){
            printf("FAIL append %d\n", h); exit(1);
        }
    }
}

/* Corrupt the layout the way the real incident did: make a late height's
 * index record point BACKWARDS into file 0 at a low offset (real case:
 * height 479,658 held the block belonging at height 43, at offset ~9,597).
 * Content is untouched -- only the (file_no, data_pos) fields lie. */
static void make_nonmonotonic(long at_height){
    int fd = open("index.dat", O_RDWR);
    if (fd < 0) { printf("FAIL open index.dat for corruption\n"); exit(1); }
    unsigned char rec[48];
    if (pread(fd, rec, 48, (off_t)at_height * 48) != 48) { printf("FAIL read rec\n"); exit(1); }
    unsigned int fno = 0; unsigned long long pos = 4;   /* backwards, into file 0 near the start */
    memcpy(rec + 32, &fno, 4);
    memcpy(rec + 36, &pos, 8);
    if (pwrite(fd, rec, 48, (off_t)at_height * 48) != 48) { printf("FAIL write rec\n"); exit(1); }
    close(fd);
}

/* Each Part gets its OWN fresh directory: several Parts truncate/wipe the
 * same filenames (index.dat, blk00000.dat), and reusing one directory made
 * an earlier Part's leftover bytes silently contaminate a later Part's
 * "fresh archive" assumptions (caught by this test's own first draft). */
static void fresh_dir(void){
    char tmpl[] = "/tmp/btcnonmonoXXXXXX";
    char* dir = mkdtemp(tmpl);
    if (!dir) { printf("FAIL mkdtemp\n"); exit(1); }
    chdir(dir);
}

int main(void){
    /* ================================================================
     * Part 1: store_truncate_index_only primitive, on a NON-MONOTONIC
     * archive -- the case store_truncate_to must refuse.
     * ================================================================ */
    {
        fresh_dir();
        struct St st;
        build_archive(&st);
        long before_blk = filesize("blk00000.dat");
        /* store_truncate_to(st,4) only checks layout up through height 5
         * (target+1, the boundary record it would read) -- corrupt WITHIN
         * that range, not beyond it, or the refusal this test exists to
         * prove never actually triggers. */
        make_nonmonotonic(5);

        ck("layout genuinely non-monotonic (0=no)", archive_layout_monotonic(7) >= 0, 1);

        long long r = store_truncate_to(&st, 4);
        ck("store_truncate_to REFUSES on non-monotonic archive", r, -1);
        ck("...and leaves blk00000.dat untouched after refusal", filesize("blk00000.dat"), before_blk);

        r = store_truncate_index_only(&st, 4);
        ck("store_truncate_index_only SUCCEEDS on the same archive", r, 1);
        ck("blk00000.dat is untouched (bytes never reclaimed)", filesize("blk00000.dat"), before_blk);
        ck("index.dat shrunk to 5 records", filesize("index.dat"), 5 * 48);
        ck("in-memory tip_height now 4", (long long)st.tip_height, 4);

        unsigned long long meta[3];
        ck("height 4 still readable", store_get_at(&st, 4, meta), 1);
        ck("height 5 (above target, the corrupted one) now out of range", store_get_at(&st, 5, meta), -2);

        /* A restart (store_reload from the on-disk index alone) must see
         * exactly the same truncated tip, not just the in-memory struct. */
        ck("store_reload after index-only truncate", store_reload(&st), 1);
        ck("tip_height survives reload", (long long)st.tip_height, 4);
        ck("height 4 still readable after reload", store_get_at(&st, 4, meta), 1);
        ck("height 5 still out of range after reload", store_get_at(&st, 5, meta), -2);
    }

    /* ================================================================
     * Part 2: store_truncate_index_only edge cases (still on a
     * non-monotonic archive, to prove they don't depend on layout).
     * ================================================================ */
    {
        fresh_dir();
        struct St st;
        build_archive(&st);
        make_nonmonotonic(6);

        long long r = store_truncate_index_only(&st, 100);  /* target >= tip -> noop */
        ck("target >= tip is a noop", r, 1);
        ck("tip_height unchanged by noop", (long long)st.tip_height, NBLK - 1);

        long before_blk = filesize("blk00000.dat");
        r = store_truncate_index_only(&st, -1);   /* wipe entire index */
        ck("target==-1 wipes the whole index", r, 1);
        ck("index.dat now empty", filesize("index.dat"), 0);
        ck("tip_height now -1", (long long)st.tip_height, -1);
        ck("blk00000.dat bytes still untouched even on full wipe", filesize("blk00000.dat"), before_blk);
    }

    /* ================================================================
     * Part 3: archive_truncate_safe dispatcher -- non-monotonic archive
     * routes to the fallback, and it actually succeeds where a bare
     * store_truncate_to would have failed the whole reorg/repair.
     * ================================================================ */
    {
        fresh_dir();
        struct St st;
        build_archive(&st);
        long before_blk = filesize("blk00000.dat");
        make_nonmonotonic(5);   /* within archive_truncate_safe's checked range for target=4 */

        int used_index_only = -1;
        long long r = archive_truncate_safe(&st, 4, &used_index_only);
        ck("archive_truncate_safe succeeds on non-monotonic archive", r, 1);
        ck("...and reports it used the index-only fallback", used_index_only, 1);
        ck("blk00000.dat untouched via the dispatcher too", filesize("blk00000.dat"), before_blk);
        ck("tip_height correct via the dispatcher", (long long)st.tip_height, 4);
    }

    /* ================================================================
     * Part 4: archive_truncate_safe on a NORMAL monotonic archive must
     * behave exactly like the existing physical store_truncate_to --
     * no regression for the common (space-reclaiming) case.
     * ================================================================ */
    {
        fresh_dir();
        struct St st;
        build_archive(&st);
        ck("freshly-appended archive is monotonic", archive_layout_monotonic(NBLK - 1), -1);

        int used_index_only = -1;
        long long r = archive_truncate_safe(&st, 4, &used_index_only);
        ck("archive_truncate_safe succeeds on monotonic archive", r, 1);
        ck("...and reports it used the PHYSICAL path", used_index_only, 0);
        ck("index.dat shrunk to 5 records", filesize("index.dat"), 5 * 48);

        /* Physical path reclaims space: blk00000.dat must be SHORTER than
         * the full 8-block archive (unlike the index-only path in Part 1/3,
         * which always leaves it exactly as long as before truncation). */
        long full_size = 0;
        for (int h = 0; h < NBLK; h++) full_size += 8 + g_sizes[h];
        long after_blk = filesize("blk00000.dat");
        ckcond("physical path DID reclaim space", after_blk < full_size);

        unsigned long long meta[3];
        ck("height 4 still readable", store_get_at(&st, 4, meta), 1);
        ck("height 5 now out of range", store_get_at(&st, 5, meta), -2);
    }

    if (failures) printf("\nFAILURES: %d\n", failures);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return failures ? 1 : 0;
}
