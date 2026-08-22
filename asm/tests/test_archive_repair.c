/* test_archive_repair.c -- daemon/archive_verify.c's duplicate-hash boot
 * repair (archive_scan_duplicates / archive_repair_duplicates), 2026-08-19.
 *
 * Real-world motivation: a locator collapse mid-sync (a peer re-serves from
 * genesis onto the tail) left a real archive with 1,336 consecutive heights
 * holding duplicate content from heights 1..1336. The existing repair
 * (archive_verify_and_repair) truncates back to the last good height, but
 * REFUSES when the archive isn't laid out monotonically on disk -- which
 * this one wasn't (an unrelated, older ordering quirk). This repair takes a
 * different, truncation-free path: mark each duplicate height as an
 * ordinary HOLE (zero its index.dat record, the same representation an
 * unfetched height already has), and let the existing catch-up/hole-filler
 * (dl_catchup) do the actual re-download with zero new fetch logic. Wired
 * into the main serve-mode boot sequence, unconditionally, right before
 * that catch-up call -- so a corrupted archive self-heals on every boot,
 * before the node opens for service, with no manual/one-off tooling.
 *
 * Uses a small synthetic index.dat mirroring the real corruption's exact
 * shape (an early unique range, then a range that duplicates part of it,
 * then more unique) so this runs in milliseconds and never touches a real
 * archive.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "test_tmpdir.h"

extern long archive_scan_duplicates(long* out_heights, long max_out);
extern long archive_repair_duplicates(void);

static int failures = 0;
static void ck(const char* l, long got, long exp){
    if (got==exp) printf("PASS %s (got %ld)\n", l, got);
    else { printf("FAIL %s got=%ld exp=%ld\n", l, got, exp); failures++; }
}
static void ckm(const char* l, int cond){ ck(l, cond, 1); }

static void write_rec(int fd, long h, unsigned char hashbyte, int is_hole){
    unsigned char rec[48]; memset(rec, 0, 48);
    if (!is_hole){
        memset(rec, hashbyte, 32);   /* fake "hash": constant byte per logical block */
        /* file_no/data_pos/data_size don't matter for duplicate detection */
    }
    pwrite(fd, rec, 48, (off_t)h*48);
}

int main(void){
    tt_isolate();
    /* Build a synthetic 20-height archive mirroring the REAL corruption
     * shape: heights 0..9 unique; heights 10..14 duplicate heights 1..5
     * (a "locator collapse" pattern); heights 15..19 unique again. */
    int fd = open("index.dat", O_RDWR|O_CREAT, 0644);
    if (fd < 0) { printf("FAIL open\n"); return 1; }
    for (long h=0; h<10; h++) write_rec(fd, h, (unsigned char)(0x10+h), 0);
    /* dup block: heights 10..14 get the SAME hash bytes as heights 1..5 */
    write_rec(fd, 10, 0x11, 0); /* == height 1 */
    write_rec(fd, 11, 0x12, 0); /* == height 2 */
    write_rec(fd, 12, 0x13, 0); /* == height 3 */
    write_rec(fd, 13, 0x14, 0); /* == height 4 */
    write_rec(fd, 14, 0x15, 0); /* == height 5 */
    for (long h=15; h<20; h++) write_rec(fd, h, (unsigned char)(0x30+h), 0);
    close(fd);

    /* ---- 1. archive_scan_duplicates finds exactly the right heights ---- */
    long heights[64];
    long n = archive_scan_duplicates(heights, 64);
    ck("duplicate count found", n, 5);
    if (n == 5){
        ck("dup[0]", heights[0], 10);
        ck("dup[1]", heights[1], 11);
        ck("dup[2]", heights[2], 12);
        ck("dup[3]", heights[3], 13);
        ck("dup[4]", heights[4], 14);
    }

    /* ---- 2. archive_repair_duplicates zeroes exactly those, nothing else ---- */
    long fixed = archive_repair_duplicates();
    ck("repaired count", fixed, 5);

    fd = open("index.dat", O_RDONLY);
    unsigned char rec[48];
    int all_good = 1;
    for (long h=0; h<20; h++){
        pread(fd, rec, 48, (off_t)h*48);
        int is_zero = 1;
        for (int i=0;i<48;i++) if (rec[i]) { is_zero=0; break; }
        int should_be_zero = (h>=10 && h<=14);
        if (is_zero != should_be_zero){
            printf("FAIL height %ld: is_zero=%d expected=%d\n", h, is_zero, should_be_zero);
            all_good = 0;
        }
    }
    close(fd);
    ckm("every height matches expected hole/present state after repair", all_good);

    /* ---- 3. a second repair pass on the now-holed archive is a clean no-op ---- */
    long n2 = archive_scan_duplicates(heights, 64);
    ck("no duplicates left after repair", n2, 0);
    long fixed2 = archive_repair_duplicates();
    ck("second repair pass is a no-op", fixed2, 0);

    /* ---- 4. a genuinely clean archive (no dups at all) reports 0, not -1 ---- */
    unlink("index.dat");
    fd = open("index.dat", O_RDWR|O_CREAT, 0644);
    for (long h=0; h<10; h++) write_rec(fd, h, (unsigned char)(0x50+h), 0);
    close(fd);
    long n3 = archive_scan_duplicates(heights, 64);
    ck("clean archive: 0 duplicates", n3, 0);
    long fixed3 = archive_repair_duplicates();
    ck("clean archive: repair is a no-op", fixed3, 0);

    /* cleanup */
    unlink("index.dat");
    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
