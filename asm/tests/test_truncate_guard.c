/* Proves the truncation safety gate refuses a non-monotonic archive.
 *
 * Uses a SYNTHETIC index built here -- never symlinks to a real datadir. The
 * previous version of this test symlinked live production blk files into a
 * scratch dir and called a destructive primitive on them; ftruncate follows
 * symlinks, and the test asserted only on index.dat entry counts, so it
 * reported all-green while the repair it was "verifying" annihilated a ~50GB
 * archive. Destructive tests get their own fixtures, and assert on the data. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

extern long archive_layout_monotonic(long upto);

static void put_rec(int fd, long h, unsigned char tag,
                    unsigned int file_no, unsigned long long pos){
    unsigned char rec[48];
    memset(rec, 0, sizeof rec);
    rec[0] = tag; rec[1] = (unsigned char)(h & 0xff); rec[2] = (unsigned char)(h >> 8); rec[3] = 1;
    memcpy(rec + 32, &file_no, 4);
    memcpy(rec + 36, &pos, 8);
    pwrite(fd, rec, 48, (off_t)h * 48);
}

int main(void){
    int failures = 0;
    printf("---- truncate safety gate ----\n");

    if (chdir("/tmp")) return 2;
    mkdir("av_guard_fixture", 0755);
    if (chdir("/tmp/av_guard_fixture")) return 2;

    /* 1. well-formed archive: strictly increasing (file_no, data_pos) */
    unlink("index.dat");
    int fd = open("index.dat", O_RDWR | O_CREAT | O_TRUNC, 0644);
    for (long h = 0; h < 200; h++) put_rec(fd, h, 0xAA, (unsigned)(h / 50), (unsigned long long)(h % 50) * 1000ULL);
    close(fd);
    long r = archive_layout_monotonic(199);
    if (r < 0) printf("PASS: monotonic archive accepted (safe to truncate)\n");
    else { printf("FAIL: monotonic archive flagged at height %ld\n", r); failures++; }

    /* 2. the real damage shape: a late height pointing back at file 0, low
     *    offset -- exactly what height 479,658 did (it held block 43's data) */
    unlink("index.dat");
    fd = open("index.dat", O_RDWR | O_CREAT | O_TRUNC, 0644);
    for (long h = 0; h < 200; h++) put_rec(fd, h, 0xAA, (unsigned)(h / 50), (unsigned long long)(h % 50) * 1000ULL);
    put_rec(fd, 150, 0xBB, 0, 9597ULL);          /* points BACKWARDS into file 0 */
    close(fd);
    r = archive_layout_monotonic(199);
    if (r == 150) printf("PASS: backwards-pointing height 150 detected -- truncation refused\n");
    else { printf("FAIL: expected height 150 flagged, got %ld -- ARCHIVE WOULD BE DESTROYED\n", r); failures++; }

    /* 3. backwards within the same file (offset regression only) */
    unlink("index.dat");
    fd = open("index.dat", O_RDWR | O_CREAT | O_TRUNC, 0644);
    for (long h = 0; h < 100; h++) put_rec(fd, h, 0xAA, 0, (unsigned long long)h * 1000ULL);
    put_rec(fd, 80, 0xBB, 0, 5ULL);
    close(fd);
    r = archive_layout_monotonic(99);
    if (r == 80) printf("PASS: same-file offset regression detected at height 80\n");
    else { printf("FAIL: expected height 80, got %ld\n", r); failures++; }

    unlink("index.dat");
    if (failures) printf("\nFAILURES: %d\n", failures);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return failures ? 1 : 0;
}
