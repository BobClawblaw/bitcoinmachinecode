/* ============================================================================
 * store_twin.c -- block-file storage layer for the macOS/AArch64 port.
 * Functional twin of asm/bitcoin_store.asm (branch bmc_osx).
 *
 * Struct layout (offsets from the x86 listing):
 *   +0  cur_blk_fd (i64, -1 none)   +8  idx_fd
 *   +16 idx_len (u64)               +24 tip_height (i32, -1 empty)
 *   +28 cur_file_no (u32)           +32 cur_file_pos (u32)
 *   +36 magic (0xd9b4bef9)          +40 flock fd
 *   +48 prune_height (i32)
 *
 * Index record (48 B): hash[32], file_no u32 @32, data_pos u64 @36,
 *                      data_size u32 @44 (0xFFFFFFFF = pruned).
 * Block file record:   len u32 LE, magic u32, raw[len].
 *
 * Files: blkNNNNN.dat (5-digit zero-padded), index.dat, prune.dat.  MAX_FILE = 128 MiB roll.
 * -------------------------------------------------------------------------- */
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef int32_t  i32;
typedef int64_t  i64;
typedef unsigned char u8;

#define MAX_FILE 0x08000000u        /* 128 MiB */
#define MAGIC    0xd9b4bef9u

static void fmt_blkname(char buf[13], u32 file_no)
{
    snprintf(buf, 13, "blk%05u.dat", file_no);
}

static long open_file(void *st, u32 file_no)
{
    u8 *S = (u8 *)st;
    char name[13];
    fmt_blkname(name, file_no);
    /* x86 open_file closes the cached cur_blk_fd first (1-slot cache) and
     * stores the new fd back into st+0 */
    if (*(i64 *)(S + 0) >= 0) { close((int)*(i64 *)(S + 0)); *(i64 *)(S + 0) = -1; }
    int fd = open(name, O_RDWR | O_CREAT, 0644);
    if (fd < 0) return -1;
    *(i64 *)(S + 0) = fd;
    return fd;
}

long store_init(void *st)
{
    u8 *S = (u8 *)st;
    int fd = open("index.dat", O_RDWR | O_CREAT, 0644);
    if (fd < 0) return -1;
    *(i32 *)(S + 8) = fd;
    *(i64 *)(S + 0) = -1;                       /* cur_blk_fd: none yet */
    *(u64 *)(S + 16) = 0;                       /* idx_len */
    *(i32 *)(S + 24) = -1;                      /* tip_height: empty */
    *(u32 *)(S + 28) = 0;                       /* cur_file_no */
    *(u32 *)(S + 32) = 0;                       /* cur_file_pos */
    *(u32 *)(S + 36) = MAGIC;
    *(u32 *)(S + 40) = 0;
    *(i32 *)(S + 48) = 0;                       /* prune_height */
    /* optional prune.dat: read the persisted prune_height */
    int pfd = open("prune.dat", O_RDONLY);
    if (pfd >= 0) {
        u8 b[4];
        if (read(pfd, b, 4) == 4) {
            i32 v;
            memcpy(&v, b, 4);
            *(i32 *)(S + 48) = v;
        }
        close(pfd);
    }
    return 1;
}

/* x86: opens blk<file_no>.dat fresh each call (no cache) */
long store_get_file_fd(void *st, u32 file_no)
{
    return open_file(st, file_no);
}

long store_reload(void *st)
{
    u8 *S = (u8 *)st;
    int idx_fd = *(i32 *)(S + 8);
    off_t sz = lseek(idx_fd, 0, SEEK_END);
    if (sz < 0) return -1;
    *(u64 *)(S + 16) = (u64)sz;
    if ((u64)sz < 48) return 0;                 /* empty */
    u64 tip = (u64)sz / 48 - 1;
    u8 rec[48];
    if (pread(idx_fd, rec, 48, (off_t)(sz - 48)) != 48) return -1;
    u32 file_no;
    memcpy(&file_no, rec + 32, 4);
    u64 data_pos;
    memcpy(&data_pos, rec + 36, 8);
    u32 data_size;
    memcpy(&data_size, rec + 44, 4);
    *(u32 *)(S + 28) = file_no;
    *(u32 *)(S + 32) = (u32)(data_pos + 8 + data_size);
    *(i32 *)(S + 24) = (i32)tip;
    /* reopen the last block file */
    if (*(i64 *)(S + 0) >= 0) close(*(i64 *)(S + 0));
    *(i64 *)(S + 0) = open_file(st, file_no);
    if (*(i64 *)(S + 0) < 0) return -1;
    return 1;
}

long store_get_at(void *st, long height, u8 out_meta[16])
{
    u8 *S = (u8 *)st;
    u64 n = *(u64 *)(S + 16) / 48;
    if (n == 0) return -2;
    if ((u64)height > n - 1) return -2;
    if (height < *(i32 *)(S + 48)) return -3;   /* pruned */
    u8 rec[48];
    if (pread(*(i32 *)(S + 8), rec, 48, (off_t)height * 48) != 48)
        return -1;
    u32 size_flag;
    memcpy(&size_flag, rec + 44, 4);
    if (size_flag == 0xFFFFFFFFu) return -3;    /* pruned record */
    u64 data_pos; memcpy(&data_pos, rec + 36, 8);
    u32 data_size; memcpy(&data_size, rec + 44, 4);
    u32 file_no;   memcpy(&file_no, rec + 32, 4);
    u64 sz64 = data_size;                    /* zero-extend: the test reads
                                                meta[1] as a full u64 */
    u64 fn64 = file_no;
    memcpy(out_meta + 0, &data_pos, 8);
    memcpy(out_meta + 8, &sz64, 8);
    memcpy(out_meta + 16, &fn64, 8);
    return 1;
}

long store_get_tip(void *st, u8 out_meta[16])
{
    u8 *S = (u8 *)st;
    if (*(i32 *)(S + 24) < 0) return -1;
    return store_get_at(st, *(i32 *)(S + 24), out_meta);
}

static long store_sync_enabled_ = 1;
void store_set_sync(void *st, long v) { (void)st; store_sync_enabled_ = v; }
long store_get_sync(void *st) { (void)st; return store_sync_enabled_; }
long store_sync_enabled(void) { return store_sync_enabled_; }

long store_append(void *st, const u8 hash[32], const u8 *raw, u64 len)
{
    u8 *S = (u8 *)st;
    if (*(i64 *)(S + 0) < 0) {
        *(i64 *)(S + 0) = open_file(st, *(u32 *)(S + 28));
        if (*(i64 *)(S + 0) < 0) return -1;
    }
    u32 pos_after = *(u32 *)(S + 32) + 8 + (u32)len;
    if (pos_after > MAX_FILE) {
        close(*(i64 *)(S + 0));
        *(i64 *)(S + 0) = -1;
        (*(u32 *)(S + 28))++;
        *(u32 *)(S + 32) = 0;
        *(i64 *)(S + 0) = open_file(st, *(u32 *)(S + 28));
        if (*(i64 *)(S + 0) < 0) return -1;
    }
    u32 data_pos = *(u32 *)(S + 32);
    u32 file_no = *(u32 *)(S + 28);
    u8 hdr[8];
    u32 l = (u32)len;
    memcpy(hdr + 0, &l, 4);
    u32 magic = *(u32 *)(S + 36);
    memcpy(hdr + 4, &magic, 4);
    int bfd = (int)*(i64 *)(S + 0);
    if (lseek(bfd, (off_t)data_pos, SEEK_SET) < 0) return -1;
    if (write(bfd, hdr, 8) != 8) return -1;
    if (write(bfd, raw, len) != (ssize_t)len) return -1;
    *(u32 *)(S + 32) = data_pos + 8 + (u32)len;
    if (store_sync_enabled_) {
        if (fdatasync(bfd) != 0) return -1;    /* failed sync = failed append */
    }
    /* index record */
    u64 new_height = (*(u64 *)(S + 16)) / 48;
    u8 rec[48];
    memcpy(rec + 0, hash, 32);
    memcpy(rec + 32, &file_no, 4);
    u64 pos64 = data_pos;
    memcpy(rec + 36, &pos64, 8);
    memcpy(rec + 44, &l, 4);
    off_t woff = (off_t)new_height * 48;
    if (pwrite(*(i32 *)(S + 8), rec, 48, woff) != 48) return -1;
    *(u64 *)(S + 16) = (new_height + 1) * 48;
    *(i32 *)(S + 24) = (i32)new_height;
    return (long)new_height;                /* x86 returns the new height */
}

long store_get_tip_hash(void *st, u8 out_hash[32])
{
    u8 *S = (u8 *)st;
    i32 tip = *(i32 *)(S + 24);
    if (tip < 0) return -1;
    if (pread(*(i32 *)(S + 8), out_hash, 32, (off_t)tip * 48) != 32)
        return -1;
    return 1;
}

long store_validates_prevhash(void *st, const u8 header[80])
{
    u8 tip_hash[32];
    if (store_get_tip_hash(st, tip_hash) != 1) return -1;
    /* header+32..64 = prevhash */
    if (memcmp(header + 32, tip_hash, 32) == 0) return 1;
    return 0;
}

long store_set_prune(void *st, long prune_height)
{
    u8 *S = (u8 *)st;
    *(i32 *)(S + 48) = (i32)prune_height;
    int fd = open("prune.dat", O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    u8 b[4];
    i32 v = (i32)prune_height;
    memcpy(b, &v, 4);
    if (write(fd, b, 4) != 4) { close(fd); return -1; }
    close(fd);
    return 1;
}

long store_layout_monotonic(void *st, long tip)
{
    /* verify heights 0..tip are laid out monotonically in the index */
    u8 *S = (u8 *)st;
    u64 prev_pos = 0;
    u32 prev_file = 0;
    for (long h = 0; h <= tip; h++) {
        u8 rec[48];
        if (pread(*(i32 *)(S + 8), rec, 48, (off_t)h * 48) != 48) return 0;
        u32 file_no; memcpy(&file_no, rec + 32, 4);
        u64 data_pos; memcpy(&data_pos, rec + 36, 8);
        if (h > 0) {
            if (file_no < prev_file) return 0;
            if (file_no == prev_file && data_pos <= prev_pos) return 0;
        }
        prev_file = file_no;
        prev_pos = data_pos;
    }
    return 1;
}

long store_truncate_to(void *st, long target_height)
{
    u8 *S = (u8 *)st;
    i32 tip = *(i32 *)(S + 24);
    if (tip < 0) return 1;                       /* already empty */
    if (target_height >= tip) return 1;          /* nothing to drop */
    if (target_height < -1) return -1;
    if (target_height == -1) {
        /* wipe: index to zero length; close the block file */
        if (ftruncate(*(i32 *)(S + 8), 0) < 0) return -1;
        if (*(i64 *)(S + 0) >= 0) { close(*(i64 *)(S + 0)); *(i64 *)(S + 0) = -1; }
        *(u64 *)(S + 16) = 0;
        *(i32 *)(S + 24) = -1;
        *(u32 *)(S + 28) = 0;
        *(u32 *)(S + 32) = 0;
        return 1;
    }
    if (!store_layout_monotonic(st, tip)) return -1;
    /* boundary record = target_height+1: everything from its data_pos
     * onwards is dropped; the blk file is truncated to that point. */
    u8 rec[48];
    if (pread(*(i32 *)(S + 8), rec, 48, (off_t)(target_height + 1) * 48) != 48)
        return -1;
    u32 b_file; memcpy(&b_file, rec + 32, 4);
    u64 b_pos;  memcpy(&b_pos, rec + 36, 8);
    /* drop index entries above target */
    if (ftruncate(*(i32 *)(S + 8), (off_t)(target_height + 1) * 48) < 0)
        return -1;
    *(u64 *)(S + 16) = (u64)(target_height + 1) * 48;
    *(i32 *)(S + 24) = (i32)target_height;
    /* truncate the block file holding the boundary (if it exists) */
    if (*(i64 *)(S + 0) >= 0) { close(*(i64 *)(S + 0)); *(i64 *)(S + 0) = -1; }
    char name[13];
    fmt_blkname(name, b_file);
    int bfd = open(name, O_RDWR);
    if (bfd >= 0) {
        ftruncate(bfd, (off_t)b_pos);
        close(bfd);
    }
    *(u32 *)(S + 28) = b_file;
    *(u32 *)(S + 32) = (u32)b_pos;
    *(i64 *)(S + 0) = open_file(st, b_file);
    if (*(i64 *)(S + 0) < 0) return -1;
    return 1;
}

long store_truncate_index_only(void *st, long target_height)
{
    u8 *S = (u8 *)st;
    i32 tip = *(i32 *)(S + 24);
    if (tip < 0 || target_height >= tip) return 1;
    if (target_height < -1) return -1;
    if (ftruncate(*(i32 *)(S + 8), (off_t)(target_height + 1) * 48) < 0)
        return -1;
    *(u64 *)(S + 16) = (u64)(target_height + 1) * 48;
    *(i32 *)(S + 24) = (i32)target_height;
    return 1;
}
