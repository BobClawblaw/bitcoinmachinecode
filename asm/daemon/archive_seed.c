#include "archive_seed.h"
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "log_ts.h"
extern void block_hash(unsigned char out[32], const unsigned char* hdr80);
extern long store_append(void* st, const unsigned char hash[32], const unsigned char* blk, unsigned long len);
extern long store_reload(void* st);

#define FRAME 8   /* [u32 len][u32 magic] before each block in a blk file */

/* Is genesis stored, byte for byte, in the frame that ends where block 1's
 * frame begins? That is where the first seed of a fresh archive put it. */
static int original_before(const unsigned char rec1[48], const unsigned char* st,
                           const unsigned char* genesis, unsigned long len,
                           unsigned int* fno, unsigned long long* pos)
{
    unsigned int f1; unsigned long long p1;
    memcpy(&f1, rec1 + 32, 4); memcpy(&p1, rec1 + 36, 8);
    if (len > 4096 || p1 < FRAME + len) return 0;
    char fn[32]; snprintf(fn, sizeof fn, "blk%05u.dat", f1);
    int fd = open(fn, O_RDONLY);
    if (fd < 0) return 0;
    unsigned char buf[FRAME + 4096];
    unsigned long long p = p1 - FRAME - len;
    int ok = pread(fd, buf, FRAME + len, (off_t)p) == (ssize_t)(FRAME + len);
    close(fd);
    unsigned int flen, magic, want;
    memcpy(&flen, buf, 4); memcpy(&magic, buf + 4, 4); memcpy(&want, st + 36, 4);
    if (!ok || flen != len || magic != want || memcmp(buf + FRAME, genesis, len) != 0) return 0;
    *fno = f1; *pos = p;
    return 1;
}

/* Whether the archive is empty is read from index.dat, never from the
 * handle's tip: store_init always leaves the tip at -1 without reading the
 * index, so a check on the tip passed on EVERY boot and appended another
 * copy of genesis to the newest blk file each time, pointing record 0 at it.
 * Record 0 then lay after record 1, and archive_layout_monotonic() reported
 * "first break at height 1" on every boot, which keeps truncation and
 * pruning from running.
 *
 * The store sits in its directory (it opens index.dat and blk*.dat by name),
 * and the handle holds the index fd at +8 and the magic at +36. */
int archive_seed_genesis_if_empty(void* store_buf, const unsigned char* genesis,
                                  unsigned long genesis_len)
{
    unsigned char* st = (unsigned char*)store_buf;
    long long ifd; memcpy(&ifd, st + 8, 8);
    unsigned char rec[96];
    ssize_t n = pread((int)ifd, rec, sizeof rec, 0);
    if (n < 0) return -1;
    unsigned char gh[32];
    block_hash(gh, genesis);

    static const unsigned char z32[32];
    int hole = n >= 48 && memcmp(rec, z32, 32) == 0;   /* record 0 cleared by archive_trim_derived_tails */
    unsigned int ofno = 0; unsigned long long opos = 0;
    int orig = n >= 96 && memcmp(rec + 48, z32, 32) != 0
               && original_before(rec + 48, st, genesis, genesis_len, &ofno, &opos);

    /* Record 0 belongs at the original copy when there is one: a cleared
     * slot, or one naming a later copy that an earlier boot's re-seed wrote. */
    if (orig && (hole || memcmp(rec, gh, 32) == 0)){
        unsigned int fno; unsigned long long pos;
        memcpy(&fno, rec + 32, 4); memcpy(&pos, rec + 36, 8);
        if (hole || fno != ofno || pos != opos){
            unsigned char r0[48]; unsigned int sz = (unsigned int)genesis_len;
            memcpy(r0, gh, 32); memcpy(r0 + 32, &ofno, 4); memcpy(r0 + 36, &opos, 8); memcpy(r0 + 44, &sz, 4);
            if (pwrite((int)ifd, r0, 48, 0) != 48 || fdatasync((int)ifd) != 0) return -1;
            if (hole)
                fprintf(stderr, "[boot] index.dat record 0 was cleared -- pointed at genesis in blk%05u.dat at %llu\n", ofno, opos);
            else
                fprintf(stderr, "[boot] index.dat record 0 named a later copy of genesis (blk%05u.dat at %llu) -- "
                                "pointed back at the original in blk%05u.dat at %llu\n", fno, pos, ofno, opos);
        }
        return store_reload(store_buf) == 1 ? 0 : -1;
    }
    if (n >= 48 && !hole) return store_reload(store_buf) == 1 ? 0 : -1;

    /* An empty index, or a cleared record 0 with no original to point at:
     * the handle's index length is still 0 from store_init, so the append
     * writes record 0 whatever the file's length. */
    if (store_append(store_buf, gh, genesis, genesis_len) < 0) return -1;
    return 1;
}
