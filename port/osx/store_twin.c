/* ============================================================================
 * store_twin.c -- persistent multi-file block storage + block index,
 * macOS/AArch64. Functional twin of asm/bitcoin_store.asm (branch bmc_osx).
 *
 * Modeled on Bitcoin Core's layout: rolling 128 MiB blk%05u.dat files, each
 * block framed as [u32 len LE][u32 magic f9beb4d9][raw block bytes] at a
 * file-LOCAL offset, plus a positional index.dat with one 48-byte record per
 * block: [0..31] block hash, [32..35] file_no u32, [36..43] data_pos u64,
 * [44..47] data_size u32.
 *
 * State struct offsets (MUST match the x86; callers allocate + memset it):
 *   +0   u64 cur_blk_fd   (open fd of CURRENT blk file; -1 = none)
 *   +8   u64 idx_fd       (open fd of index.dat)
 *   +16  u64 idx_len      (bytes in index.dat; tip = idx_len/48 - 1)
 *   +24  i32 tip_height   (-1 when empty)
 *   +28  i32 cur_file_no
 *   +32  i32 cur_file_pos (bytes written in current blk file)
 *   +36  i32 magic        (0xd9b4bef9)
 *   +40  i32 pad          (shared-append flock fd, set by caller)
 *   +44  i32 pad2
 *   +48  i32 prune_height (first retained height; persisted in prune.dat)
 *
 * Exports (semantics byte-matched to the asm):
 *   int   store_init(void *st);                       -> 1 ok / -1
 *   int   store_reload(void *st);                     -> 1 ok / -1
 *   int   store_append(void *st, const u8 hash[32], const void *raw, u64 len);
 *                                                     -> new height / -1
 *   int   store_get_at(void *st, u64 height, u64 out_meta[3]);
 *          out_meta = {data_pos, data_size, file_no}  -> 1 / -2 oor / -3 pruned / -1
 *   int   store_get_tip(void *st, u64 out_meta[3]);   -> 1 ok / -1 empty
 *   int   store_get_file_fd(void *st, u32 file_no);   -> fd / -1
 *   int   store_set_prune(void *st, int h);           -> 1 ok / -1
 *   int   store_prune(void *st, int h);               -> 1 ok / -1
 *   int   store_get_tip_hash(void *st, u8 out[32]);   -> 1 ok / -1 empty
 *   int   store_validates_prevhash(void *st, const u8 hdr[80]); -> 1/0/-1
 *   int   store_layout_monotonic(void *st, long upto);-> 1 / 0
 *   long long store_truncate_to(void *st, i64 target);-> 1 ok / -1 err
 *   int   store_truncate_index_only(void *st, i64 t); -> 1 ok / -1 err
 *   void  store_set_sync(int on);   int store_get_sync(void);
 *   int   store_append_shared(void*, long, const u8[32], const void*, u64);
 *   int   store_append_shared_nolock(void*, long, const u8[32], const void*, u64);
 *
 * Darwin deltas: the x86 raw syscalls (open/lseek/read/write/pread64/
 * ftruncate/flock/unlink) collapse to libc calls with identical semantics.
 * flock(LOCK_EX/LOCK_UN) exists on Darwin with the same per-open-file-
 * description accounting the asm comment relies on.
 * -------------------------------------------------------------------------- */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>

typedef uint64_t u64;
typedef int64_t i64;
typedef uint32_t u32;
typedef int32_t i32;
typedef unsigned char u8;

#define MAX_FILE 0x08000000u          /* 128 MiB (Bitcoin MAX_BLOCKFILE_SIZE) */

static const char idxname[]   = "index.dat";
static const char prunename[] = "prune.dat";

/* ---- fmt_blkname(buf(>=13), file_no): "blk%05u.dat" + NUL ---------------- */
void fmt_blkname(char *buf, u32 file_no)
{
    memcpy(buf, "blk", 3);
    buf[3] = (char)('0' + (file_no / 10000) % 10);
    buf[4] = (char)('0' + (file_no / 1000) % 10);
    buf[5] = (char)('0' + (file_no / 100) % 10);
    buf[6] = (char)('0' + (file_no / 10) % 10);
    buf[7] = (char)('0' + (file_no) % 10);
    memcpy(buf + 8, ".dat", 4);
    buf[12] = 0;
}

/* STO-11 durability switch (default ON, like the x86 .data dq 1). */
static u64 store_sync_enabled = 1;
void store_set_sync(int on) { store_sync_enabled = on ? 1 : 0; }
int  store_get_sync(void)   { return (int)store_sync_enabled; }

/* ---- open_file(st, file_no) -> fd; closes any previous blk fd first ----- */
static long open_file(void *st, u32 file_no)
{
    u8 *S = (u8 *)st;
    long cur = (long)*(u64 *)(S + 0);
    if (cur >= 0) close(cur);                       /* fd-leak fix parity */
    char name[16];
    fmt_blkname(name, file_no);
    int fd = open(name, O_RDWR | O_CREAT, 0644);
    if (fd < 0) return fd;
    *(u64 *)(S + 0) = (u64)fd;
    return fd;
}

int store_init(void *st)
{
    u8 *S = (u8 *)st;
    int fd = open(idxname, O_RDWR | O_CREAT, 0644);
    if (fd < 0) return -1;
    *(u64 *)(S + 8)  = (u64)fd;                     /* idx_fd */
    *(u64 *)(S + 0)  = (u64)-1;                     /* cur_blk_fd = none */
    *(u64 *)(S + 16) = 0;                           /* idx_len = 0 */
    *(i32 *)(S + 24) = -1;                          /* tip_height = -1 */
    *(i32 *)(S + 28) = 0;                           /* cur_file_no */
    *(i32 *)(S + 32) = 0;                           /* cur_file_pos */
    *(i32 *)(S + 36) = (i32)0xd9b4bef9;             /* magic */
    *(i32 *)(S + 40) = 0;                           /* pad / flock fd */
    *(i32 *)(S + 48) = 0;                           /* prune_height */
    /* restore persisted prune gate */
    int pfd = open(prunename, O_RDONLY);
    if (pfd >= 0) {
        u8 b4[4];
        if (read(pfd, b4, 4) == 4) {
            i32 ph;
            memcpy(&ph, b4, 4);
            *(i32 *)(S + 48) = ph;
        }
        close(pfd);
    }
    return 1;
}

int store_reload(void *st)
{
    u8 *S = (u8 *)st;
    int idx_fd = (int)*(u64 *)(S + 8);
    off_t sz = lseek(idx_fd, 0, SEEK_END);
    if (sz < 0) return -1;
    *(u64 *)(S + 16) = (u64)sz;
    if (sz < 48) {
        *(i32 *)(S + 24) = -1;                      /* empty */
        *(i32 *)(S + 28) = 0;
        *(i32 *)(S + 32) = 0;
        *(u64 *)(S + 0)  = (u64)-1;
        return 1;
    }
    i64 tip = (i64)(sz / 48) - 1;
    u8 rec[48];
    if (pread(idx_fd, rec, 48, sz - 48) != 48) return -1;
    i32 fno;
    memcpy(&fno, rec + 32, 4);
    u64 pos;
    memcpy(&pos, rec + 36, 8);
    u32 size;
    memcpy(&size, rec + 44, 4);
    *(i32 *)(S + 28) = fno;
    *(i32 *)(S + 32) = (i32)(pos + 8 + size);
    *(i32 *)(S + 24) = (i32)tip;
    if (open_file(st, (u32)fno) < 0) return -1;
    return 1;
}

int store_get_file_fd(void *st, u32 file_no)
{
    return (int)open_file(st, file_no);
}

/* ---- read_idx_rec(st, height, buf) -> file_no / -1 ---------------------- */
static long read_idx_rec(void *st, i64 height, u8 *buf)
{
    u8 *S = (u8 *)st;
    int idx_fd = (int)*(u64 *)(S + 8);
    if (pread(idx_fd, buf, 48, (off_t)height * 48) != 48) return -1;
    i32 fno;
    memcpy(&fno, buf + 32, 4);
    return fno;
}

/* ---- write_idx_rec(st, height, buf) -> 1 / -1 --------------------------- */
static long write_idx_rec(void *st, i64 height, const u8 *buf)
{
    u8 *S = (u8 *)st;
    int idx_fd = (int)*(u64 *)(S + 8);
    if (pwrite(idx_fd, buf, 48, (off_t)height * 48) != 48) return -1;
    return 1;
}

int store_get_at(void *st, u64 height, u64 out_meta[3])
{
    u8 *S = (u8 *)st;
    i64 tip = (i64)(*(u64 *)(S + 16) / 48) - 1;
    if (tip < 0 || (i64)height > tip) return -2;
    if ((i64)height < *(i32 *)(S + 48)) return -3;  /* below prune gate */
    u8 rec[48];
    int idx_fd = (int)*(u64 *)(S + 8);
    if (pread(idx_fd, rec, 48, (off_t)height * 48) != 48) return -1;
    u32 size;
    memcpy(&size, rec + 44, 4);
    if (size == 0xFFFFFFFFu) return -3;             /* sparse-prune marker */
    memcpy(&out_meta[0], rec + 36, 8);              /* data_pos */
    memcpy(&out_meta[1], rec + 44, 4);              /* data_size (u32) */
    out_meta[1] &= 0xFFFFFFFFu;
    memcpy(&out_meta[2], rec + 32, 4);              /* file_no */
    return 1;
}

int store_get_tip(void *st, u64 out_meta[3])
{
    u8 *S = (u8 *)st;
    i64 tip = (i64)(*(u64 *)(S + 16) / 48) - 1;
    if (tip < 0) return -1;
    if (store_get_at(st, (u64)tip, out_meta) != 1) return -1;
    return 1;
}

/* ---- unlink_blk(st, file_no): remove blk%05d.dat (ENOENT tolerated) ----- */
static void unlink_blk(void *st, u32 file_no)
{
    (void)st;
    char name[16];
    fmt_blkname(name, file_no);
    unlink(name);
}

int store_set_prune(void *st, int h)
{
    u8 *S = (u8 *)st;
    *(i32 *)(S + 48) = h;
    int fd = open(prunename, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    u8 b4[4];
    memcpy(b4, &h, 4);
    if (write(fd, b4, 4) != 4) { close(fd); return -1; }
    close(fd);
    return 1;
}

int store_prune(void *st, int prune_height)
{
    u8 *S = (u8 *)st;
    i32 tip = *(i32 *)(S + 24);
    if (tip == -1) {                                /* empty store */
        *(i32 *)(S + 48) = 0;
        store_set_prune(st, 0);
        return 1;
    }
    i32 eff = prune_height < 0 ? 0 : prune_height;  /* clamp negatives to 0 */
    if ((u32)eff > (u32)tip + 1) eff = tip + 1;     /* clamp to tip+1 */
    *(i32 *)(S + 48) = eff;
    if (eff == 0) {                                 /* nothing deleted */
        store_set_prune(st, 0);
        return 1;
    }
    store_set_prune(st, eff);
    if (eff == tip + 1) {                           /* retain nothing */
        for (i32 f = 0; f <= *(i32 *)(S + 28); f++)
            unlink_blk(st, (u32)f);
        return 1;
    }
    /* first retained file */
    u8 recA[48], recB[48];
    long first_ret = read_idx_rec(st, eff, recA);
    if (first_ret < 0) return -1;
    for (i32 f = 0; f < first_ret; f++)
        unlink_blk(st, (u32)f);
    /* compact the boundary file in place */
    long fd = open_file(st, (u32)first_ret);
    if (fd < 0) return -1;
    u64 new_off = 0;
    for (i64 h = eff; h <= tip; h++) {
        if (read_idx_rec(st, h, recA) < 0) return -1;
        i32 fno;
        memcpy(&fno, recA + 32, 4);
        if (fno != first_ret) break;
        u64 old_off;
        memcpy(&old_off, recA + 36, 8);
        u32 size;
        memcpy(&size, recA + 44, 4);
        u64 remaining = (u64)size + 8;
        u8 buf[0x10000];
        u64 old_ptr = old_off, new_ptr = new_off;
        while (remaining) {
            u64 chunk = remaining < sizeof buf ? remaining : sizeof buf;
            if (pread(fd, buf, chunk, (off_t)old_ptr) != (ssize_t)chunk) return -1;
            if (pwrite(fd, buf, chunk, (off_t)new_ptr) != (ssize_t)chunk) return -1;
            old_ptr += chunk; new_ptr += chunk; remaining -= chunk;
        }
        /* record with data_pos := new_off */
        memcpy(recB, recA, 48);
        memcpy(recB + 36, &new_off, 8);
        if (write_idx_rec(st, h, recB) < 0) return -1;
        new_off += (u64)size + 8;
    }
    if (ftruncate(fd, (off_t)new_off) < 0) return -1;
    return 1;
}

/* ---- STO-5: single-writer append (batch tools/tests only on x86 too) ---- */
int store_append(void *st, const u8 hash[32], const void *raw, u64 len)
{
    u8 *S = (u8 *)st;
    if (*(u64 *)(S + 0) == (u64)-1 || (long)*(u64 *)(S + 0) < 0) {
        if (open_file(st, (u32)*(i32 *)(S + 28)) < 0) return -1;
    }
    /* rollover: cur_file_pos + 8 + len > MAX_FILE -> next file */
    if ((u64)(u32)*(i32 *)(S + 32) + 8 + len > MAX_FILE) {
        close((long)*(u64 *)(S + 0));
        *(u64 *)(S + 0) = (u64)-1;
        *(i32 *)(S + 28) += 1;
        *(i32 *)(S + 32) = 0;
        if (open_file(st, (u32)*(i32 *)(S + 28)) < 0) return -1;
    }
    u64 pos    = (u64)(u32)*(i32 *)(S + 32);        /* data_pos */
    u32 file_no = (u32)*(i32 *)(S + 28);
    int blk_fd = (int)*(u64 *)(S + 0);
    /* frame header [len][magic] at cur_file_pos */
    u8 hdr[8];
    u32 l32 = (u32)len;
    memcpy(hdr + 0, &l32, 4);
    memcpy(hdr + 4, S + 36, 4);                     /* magic */
    if (pwrite(blk_fd, hdr, 8, (off_t)pos) != 8) return -1;
    if (pwrite(blk_fd, raw, len, (off_t)pos + 8) != (ssize_t)len) return -1;
    *(i32 *)(S + 32) = (i32)(pos + 8 + len);
    /* STO-11: block bytes durable before the index record */
    if (store_sync_enabled) {
        if (fdatasync(blk_fd) < 0) return -1;
    }
    /* index record at height = idx_len/48 */
    i64 height = (i64)(*(u64 *)(S + 16) / 48);
    u8 rec[48];
    memcpy(rec + 0, hash, 32);
    memcpy(rec + 32, &file_no, 4);
    memcpy(rec + 36, &pos, 8);
    memcpy(rec + 44, &l32, 4);
    int idx_fd = (int)*(u64 *)(S + 8);
    if (pwrite(idx_fd, rec, 48, (off_t)height * 48) != 48) return -1;
    *(u64 *)(S + 16) += 48;
    *(i32 *)(S + 24) = (i32)height;
    return (int)height;
}

/* ---- STAGE B: shared body, flock optional (r9 'dolock' on x86) ---------- */
static long store_append_shared_x(void *st, long height, const u8 hash[32],
                                  const void *raw, u64 len, int dolock)
{
    u8 *S = (u8 *)st;
    int lock_fd = (int)*(i32 *)(S + 40);
    if (dolock && lock_fd >= 0)
        flock(lock_fd, LOCK_EX);
    long ret = -1;
    for (;;) {                                      /* single-pass body */
        if ((int)*(u64 *)(S + 8) < 0) {             /* stale idx_fd: reopen */
            int fd = open(idxname, O_RDWR | O_CREAT, 0644);
            if (fd >= 0) *(u64 *)(S + 8) = (u64)fd;
        }
        if ((long)*(u64 *)(S + 0) < 0) {
            if (open_file(st, (u32)*(i32 *)(S + 28)) < 0) break;
        }
        /* TRUE end of current blk file (self-healing position) */
        off_t true_len;
        for (;;) {
            int blk_fd = (int)*(u64 *)(S + 0);
            off_t sz = lseek(blk_fd, 0, SEEK_END);
            if (sz < 0) break;
            if ((u64)sz + 8 + len > MAX_FILE) {
                close(blk_fd);
                *(u64 *)(S + 0) = (u64)-1;
                *(i32 *)(S + 28) += 1;
                if (open_file(st, (u32)*(i32 *)(S + 28)) < 0) break;
                continue;                           /* re-lseek the new file */
            }
            true_len = sz;
            goto sized;
        }
        break;
    sized:;
        u64 pos = (u64)true_len;                    /* data_pos = true end */
        u32 file_no = (u32)*(i32 *)(S + 28);
        int blk_fd = (int)*(u64 *)(S + 0);
        u8 hdr[8];
        u32 l32 = (u32)len;
        memcpy(hdr + 0, &l32, 4);
        memcpy(hdr + 4, S + 36, 4);
        if (pwrite(blk_fd, hdr, 8, (off_t)pos) != 8) break;
        if (pwrite(blk_fd, raw, len, (off_t)pos + 8) != (ssize_t)len) break;
        if (store_sync_enabled && fdatasync(blk_fd) < 0) break;
        u8 rec[48];
        memcpy(rec + 0, hash, 32);
        memcpy(rec + 32, &file_no, 4);
        memcpy(rec + 36, &pos, 8);
        memcpy(rec + 44, &l32, 4);
        int idx_fd = (int)*(u64 *)(S + 8);
        if (pwrite(idx_fd, rec, 48, (off_t)height * 48) != 48) break;
        ret = height;
        break;
    }
    if (dolock && lock_fd >= 0)
        flock(lock_fd, LOCK_UN);
    return ret;
}

long store_append_shared(void *st, long height, const u8 hash[32],
                         const void *raw, u64 len)
{
    return store_append_shared_x(st, height, hash, raw, len, 1);
}

long store_append_shared_nolock(void *st, long height, const u8 hash[32],
                                const void *raw, u64 len)
{
    return store_append_shared_x(st, height, hash, raw, len, 0);
}

/* ---- Stage A reorg primitives ------------------------------------------ */
int store_get_tip_hash(void *st, u8 out_hash[32])
{
    u8 *S = (u8 *)st;
    i32 tip = *(i32 *)(S + 24);
    if (tip == -1) return -1;
    int idx_fd = (int)*(u64 *)(S + 8);
    if (pread(idx_fd, out_hash, 32, (off_t)tip * 48) != 32) return -1;
    return 1;
}

int store_validates_prevhash(void *st, const u8 block_header[80])
{
    u8 tip_hash[32];
    if (store_get_tip_hash(st, tip_hash) != 1) return -1;
    return memcmp(block_header + 4, tip_hash, 32) == 0 ? 1 : 0;
}

int store_layout_monotonic(void *st, long upto_height)
{
    u8 *S = (u8 *)st;
    int idx_fd = (int)*(u64 *)(S + 8);
    u32 prev_file = 0;
    u64 prev_pos = 0;
    int seen = 0;
    for (long h = 0; h <= upto_height; h++) {
        u8 rec[48];
        if (pread(idx_fd, rec, 48, (off_t)h * 48) != 48)
            break;                                  /* short read == end */
        u32 hash_prefix;
        memcpy(&hash_prefix, rec, 4);
        if (hash_prefix == 0) continue;             /* hole, not a block */
        u32 fno;
        memcpy(&fno, rec + 32, 4);
        u64 pos;
        memcpy(&pos, rec + 36, 8);
        if (seen) {
            if (fno < prev_file) return 0;          /* file went backwards */
            if (fno == prev_file && pos < prev_pos) return 0;
        }
        prev_file = fno;
        prev_pos = pos;
        seen = 1;
    }
    return 1;
}

long long store_truncate_to(void *st, long long target_height)
{
    u8 *S = (u8 *)st;
    i32 tip = *(i32 *)(S + 24);
    if (tip == -1) return 1;                        /* already empty */
    if (target_height >= (long long)tip) return 1;  /* nothing to drop */
    if (target_height == -1) {                      /* wipe everything */
        int idx_fd = (int)*(u64 *)(S + 8);
        if (ftruncate(idx_fd, 0) < 0) return -1;
        for (i32 f = 0; f <= *(i32 *)(S + 28); f++)
            unlink_blk(st, (u32)f);
        *(u64 *)(S + 16) = 0;
        *(i32 *)(S + 24) = -1;
        *(i32 *)(S + 28) = 0;
        *(i32 *)(S + 32) = 0;
        *(u64 *)(S + 0)  = (u64)-1;
        return 1;
    }
    /* SAFETY GATE: refuse an out-of-order archive */
    if (!store_layout_monotonic(st, (long)target_height + 1)) return -1;
    /* boundary record at (target+1)*48 -> new end-of-data */
    u8 rec[48];
    int idx_fd = (int)*(u64 *)(S + 8);
    if (pread(idx_fd, rec, 48, ((off_t)target_height + 1) * 48) != 48) return -1;
    u32 bfile;
    memcpy(&bfile, rec + 32, 4);
    u64 bpos;
    memcpy(&bpos, rec + 36, 8);
    /* ftruncate index.dat */
    if (ftruncate(idx_fd, ((off_t)target_height + 1) * 48) < 0) return -1;
    /* ftruncate the boundary blk file (also makes it the current file) */
    long fd = open_file(st, bfile);
    if (fd < 0) return -1;
    if (ftruncate(fd, (off_t)bpos) < 0) return -1;
    /* delete later blk files */
    i32 orig_cur = *(i32 *)(S + 28);
    for (i32 f = (i32)bfile + 1; f <= orig_cur; f++)
        unlink_blk(st, (u32)f);
    /* in-memory state */
    *(i32 *)(S + 28) = (i32)bfile;
    *(i32 *)(S + 32) = (i32)bpos;
    *(u64 *)(S + 16) = ((u64)target_height + 1) * 48;
    *(i32 *)(S + 24) = (i32)target_height;
    return 1;
}

int store_truncate_index_only(void *st, long long target_height)
{
    u8 *S = (u8 *)st;
    i32 tip = *(i32 *)(S + 24);
    if (tip == -1) return 1;
    if (target_height >= (long long)tip) return 1;
    int idx_fd = (int)*(u64 *)(S + 8);
    if (target_height == -1) {                      /* drop entire index */
        if (ftruncate(idx_fd, 0) < 0) return -1;
        *(u64 *)(S + 16) = 0;
        *(i32 *)(S + 24) = -1;
        return 1;
    }
    u64 new_len = ((u64)target_height + 1) * 48;
    if (ftruncate(idx_fd, (off_t)new_len) < 0) return -1;
    *(u64 *)(S + 16) = new_len;
    *(i32 *)(S + 24) = (i32)target_height;
    return 1;
}
