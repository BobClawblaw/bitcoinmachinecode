/* ============================================================================
 * store_fast_twin.c -- read-cache layer for the macOS/AArch64 port.
 * Functional twin of asm/bitcoin_store_fast.asm (branch bmc_osx).
 *
 * Layout additions to the store struct:
 *   +56 FDC magic 0x5244464300000001 ("RDFC"+version)
 *   +64 fd cache: 8 slots x {file_no u32, fd i32} (LRU-by-slot, direct map)
 *
 *   void store_rd_init(void *st);
 *   void store_rd_close(void *st);
 *   long store_rd_fd(void *st, u32 file_no);      -> fd or -1
 *   long store_read_meta(void *st, u64 height, u64 meta[3], u8 *buf, u64 cap);
 *   long store_read_at(void *st, u64 height, void *buf, u64 cap);
 *   void store_rd_advise(void *st, u64 height, u64 nblocks);
 *   void store_map_init/close/at (random-access pread cache, advisory)
 * -------------------------------------------------------------------------- */
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef int32_t i32_;
typedef unsigned char u8;

#define FDC_OFF    64
#define FDC_SLOTS  8
#define FDC_MAGIC  0x5244464300000001ULL
#define FDC_MASK   (FDC_SLOTS - 1)

extern long store_get_at(void *st, long height, u8 out_meta[24]);

void store_rd_init(void *st)
{
    u8 *S = (u8 *)st;
    if (*(u64 *)(S + 56) == FDC_MAGIC) {
        for (u32 slot = 0; slot < FDC_SLOTS; slot++) {
            u8 *e = S + FDC_OFF + slot * 8;
            i32_ fd;
            memcpy(&fd, e + 4, 4);
            if (fd >= 0) close(fd);
        }
    }
    for (u32 slot = 0; slot < FDC_SLOTS; slot++) {
        u8 *e = S + FDC_OFF + slot * 8;
        *(u32 *)(e + 0) = 0;
        *(int *)(e + 4) = -1;
    }
    *(u64 *)(S + 56) = FDC_MAGIC;
}

void store_rd_close(void *st) { store_rd_init(st); }

long store_rd_fd(void *st, u32 file_no)
{
    u8 *S = (u8 *)st;
    if (*(u64 *)(S + 56) != FDC_MAGIC) store_rd_init(st);
    u8 *e = S + FDC_OFF + (u64)(file_no & FDC_MASK) * 8;
    int fd;
    memcpy(&fd, e + 4, 4);
    u32 cached_no;
    memcpy(&cached_no, e + 0, 4);
    if (fd >= 0) {
        if (cached_no == file_no) return fd;
        close(fd);                          /* evict */
    }
    char name[13];
    snprintf(name, sizeof name, "blk%05u.dat", file_no);
    fd = open(name, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    memcpy(e + 0, &file_no, 4);
    memcpy(e + 4, &fd, 4);
    return fd;
}

/* meta[3] = {data_pos u64, data_size u64, file_no u64} */
long store_read_meta(void *st, u64 height, u64 meta[3], u8 *buf, u64 cap)
{
    long rc = store_get_at(st, (long)height, (u8 *)meta);
    if (rc != 1) return rc;                 /* propagate -1/-2/-3 */
    if (meta[1] > cap) return -4;           /* toobig */
    long fd = store_rd_fd(st, (u32)meta[2]);
    if (fd < 0) return -1;
    ssize_t n = pread(fd, buf, meta[1], (off_t)(meta[0] + 8));
    if (n != (ssize_t)meta[1]) return -1;
    return (long)n;
}

long store_read_at(void *st, u64 height, void *buf, u64 cap)
{
    u64 meta[3] = { 0, 0, 0 };
    return store_read_meta(st, height, meta, (u8 *)buf, cap);
}

/* Advise: warm the fd cache for the files a sequential read of nblocks
 * starting at height will touch.  Darwin has no readahead(2); opening the
 * files is the useful part (fills the cache slots). */
void store_rd_advise(void *st, u64 height, u64 nblocks)
{
    if (nblocks == 0) return;
    u64 meta_first[3], meta_last[3];
    if (store_get_at(st, (long)height, (u8 *)meta_first) != 1) return;
    if (store_get_at(st, (long)(height + nblocks - 1), (u8 *)meta_last) != 1)
        return;
    if (meta_first[2] == meta_last[2]) {
        store_rd_fd(st, (u32)meta_first[2]);
        return;
    }
    for (u32 f = (u32)meta_first[2]; f <= (u32)meta_last[2]; f++)
        store_rd_fd(st, f);
}

/* ---- random-map cache: 8 slots of {file_no, map, size} at st+128 ------- */
#define MAP_OFF    128
#define MAP_SLOTS  8
#define MAP_MAGIC  0x4D41504300000001ULL   /* "MAPC" + version */
#define MAP_MASK   (MAP_SLOTS - 1)

extern long store_rd_fd(void *st, u32 file_no);

#include <sys/mman.h>
#include <sys/stat.h>

static void map_file(void *st, u32 file_no, u64 need_end, u8 **out_map, u64 *out_size)
{
    u8 *S = (u8 *)st;
    if (*(u64 *)(S + 120) != MAP_MAGIC) {
        for (u32 i = 0; i < MAP_SLOTS; i++) {
            u8 *e = S + MAP_OFF + i * 32;
            *(u32 *)(e + 0) = 0;
            *(u64 *)(e + 8) = 0;
            *(u64 *)(e + 16) = 0;
        }
        *(u64 *)(S + 120) = MAP_MAGIC;
    }
    u8 *e = S + MAP_OFF + (u64)(file_no & MAP_MASK) * 32;
    u32 cached_no;
    memcpy(&cached_no, e + 0, 4);
    u64 map = 0, size = 0;
    memcpy(&map, e + 8, 8);
    memcpy(&size, e + 16, 8);
    if (cached_no == file_no && map != 0 && size >= need_end) {
        *out_map = (u8 *)(uintptr_t)map;
        *out_size = size;
        return;
    }
    /* replace */
    if (map) munmap((void *)(uintptr_t)map, size);
    *(u64 *)(e + 8) = 0;
    char name[13];
    snprintf(name, sizeof name, "blk%05u.dat", file_no);
    int fd = open(name, O_RDONLY);
    if (fd < 0) { *out_map = 0; *out_size = 0; return; }
    struct stat sb;
    if (fstat(fd, &sb) < 0 || (u64)sb.st_size < need_end) {
        close(fd);
        *out_map = 0; *out_size = 0;
        return;
    }
    void *m = mmap(NULL, (size_t)sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (m == MAP_FAILED) { *out_map = 0; *out_size = 0; return; }
    memcpy(e + 0, &file_no, 4);
    u64 m64 = (u64)(uintptr_t)m, s64 = (u64)sb.st_size;
    memcpy(e + 8, &m64, 8);
    memcpy(e + 16, &s64, 8);
    *out_map = (u8 *)m;
    *out_size = s64;
}

void store_map_init(void *st)
{
    u8 *S = (u8 *)st;
    for (u32 i = 0; i < MAP_SLOTS; i++) {
        u8 *e = S + MAP_OFF + i * 32;
        u64 map = 0;
        memcpy(&map, e + 8, 8);
        if (map) {
            u64 size = 0;
            memcpy(&size, e + 16, 8);
            munmap((void *)(uintptr_t)map, size);
        }
        *(u32 *)(e + 0) = 0;
        *(u64 *)(e + 8) = 0;
        *(u64 *)(e + 16) = 0;
    }
    *(u64 *)(S + 120) = MAP_MAGIC;
}

void store_map_close(void *st) { store_map_init(st); }

const u8 *store_map_at(void *st, u64 height, u64 out[2])
{
    u64 meta[3] = { 0, 0, 0 };
    if (store_get_at(st, (long)height, (u8 *)meta) != 1) {
        if (out) { out[0] = 0; out[1] = 0; }
        return 0;
    }
    u64 need = meta[0] + 8 + meta[1];
    u8 *map = 0; u64 size = 0;
    map_file(st, (u32)meta[2], need, &map, &size);
    if (!map) {
        if (out) { out[0] = 0; out[1] = 0; }
        return 0;
    }
    if (out) { out[0] = meta[1]; out[1] = meta[2]; }
    return map + meta[0] + 8;              /* skip [len][magic] header */
}
