/* store_truncate_to must REFUSE an out-of-order archive, and must leave every
 * byte of block data intact when it does.
 *
 * This is the case that destroyed a ~600GB archive: the caller had proven the
 * archive was out of order, then handed it to a primitive that assumes order.
 * The guard now lives in the primitive, so this asserts at that level -- and
 * critically it asserts on the BLOCK FILES, not just index.dat. The test that
 * missed the original incident checked only index counts and never opened a
 * block, so it passed while the data was being deleted. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

extern long store_init(void* st);
extern int  store_append(void* st, const void* hash, const void* raw, unsigned long long len);
extern int  store_truncate_to(void* st, long target_height);
extern long store_layout_monotonic(void* st, long upto);

static unsigned char st[4096];

static long fsize(const char* p){ struct stat s; return stat(p,&s)==0 ? (long)s.st_size : -1; }

int main(void){
    int failures = 0;
    printf("---- store_truncate_to safety gate (primitive level) ----\n");
    if (chdir("/storage/bitcoinmachinecode/scratch_guard")) { perror("chdir"); return 2; }

    if (store_init(st) != 1) { printf("FAIL: store_init\n"); return 1; }
    unsigned char blk[256], hash[32];
    for (int i=0;i<8;i++){
        memset(blk,0xA0+i,sizeof blk); blk[0]=(unsigned char)(i+1);
        memset(hash,0,32); hash[0]=(unsigned char)(i+1); hash[31]=(unsigned char)(0x40+i);
        if (store_append(st, hash, blk, sizeof blk) < 0) { printf("FAIL: append %d\n", i); return 1; } }

    long before = fsize("blk00000.dat");
    printf("blk00000.dat is %ld bytes with 8 blocks stored\n", before);

    if (store_layout_monotonic(st, 7) == 1) printf("PASS: freshly-appended archive reads as monotonic\n");
    else { printf("FAIL: normal archive flagged non-monotonic\n"); failures++; }

    /* Corrupt the layout the way the real incident did: make a LATE height
     * point back into file 0 at a low offset (real case: height 479,658 held
     * the block belonging at height 43, at offset ~9,597). */
    int fd = open("index.dat", O_RDWR);
    if (fd < 0) { printf("FAIL: open index.dat\n"); return 1; }
    unsigned char rec[48];
    if (pread(fd, rec, 48, 6*48) != 48) { printf("FAIL: read rec 6\n"); return 1; }
    unsigned int fno = 0; unsigned long long pos = 16;      /* backwards */
    memcpy(rec+32, &fno, 4);
    memcpy(rec+36, &pos, 8);
    if (pwrite(fd, rec, 48, 6*48) != 48) { printf("FAIL: write rec 6\n"); return 1; }
    close(fd);

    if (store_layout_monotonic(st, 7) == 0) printf("PASS: backwards-pointing height 6 detected\n");
    else { printf("FAIL: guard did not detect the backwards height -- ARCHIVE AT RISK\n"); failures++; }

    /* The whole point: truncation must refuse, and must not touch the data. */
    int r = store_truncate_to(st, 5);
    if (r != 1) printf("PASS: store_truncate_to REFUSED (returned %d)\n", r);
    else { printf("FAIL: store_truncate_to proceeded on an out-of-order archive\n"); failures++; }

    long after = fsize("blk00000.dat");
    if (after == before) printf("PASS: block data untouched (%ld bytes, unchanged)\n", after);
    else { printf("FAIL: blk00000.dat %ld -> %ld -- DATA WAS DESTROYED\n", before, after); failures++; }

    if (fsize("index.dat") == 8*48) printf("PASS: index.dat untouched (8 records)\n");
    else { printf("FAIL: index.dat truncated to %ld bytes\n", fsize("index.dat")); failures++; }

    if (failures) printf("\nFAILURES: %d\n", failures);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return failures ? 1 : 0;
}
