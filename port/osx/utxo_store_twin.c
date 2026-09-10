/* ============================================================================
 * utxo_store_twin.c -- persistent UTXO store (WAL + checkpoint) for the
 * macOS/AArch64 port. Functional twin of asm/bitcoin_utxo_store.asm.
 *
 * Files (bare relative names, CWD):
 *   utxo.dat  -- append-only WAL. PUSH: [u32 magic "UTXO"][u8 op=1][3 pad]
 *                [txid32][u32 index][u64 value][u32 height][u8 is_coinbase]
 *                [u16 slen][script]  (8+51=59B header + script).
 *                DEL: [magic][op=2][3 pad][txid32][u32 index] (44B).
 *   utxo.idx  -- checkpoint: [u32 magic "UTXI"][u64 log_off][u64 n] then n
 *                records [txid32][u32 index][u64 value][u32 height]
 *                [u8 is_coinbase][u16 slen][script]. Written via
 *                utxo.idx.tmp + rename (atomic publish).
 *
 * State struct offsets (caller supplies zeroed):
 *   +0  u64 log_fd   +8 u64 idx_fd   +16 u64 log_len (LOGICAL length:
 *   file + buffered WAL bytes)   +24 u64 ckpt_log_off   +32 u64 ckpt_n
 *
 * 1 MB process-wide WAL buffer shared across stores keyed by fd, exactly
 * like the x86 .bss (wal_buf/wal_fill/wal_fd): appends buffer, drains happen
 * on sync/reload/close/wal_drain/owner-switch/overflow; oversize writes go
 * straight through. log_len advances on BUFFER, not on file write.
 *
 * The in-memory table (utxo_twin.c, layout-compatible with bitcoin_utxo.asm)
 * is delegated to: put/del write the WAL record first, then apply in memory;
 * get/count are pass-throughs.
 *
 * Exports:
 *   long utxo_store_init(void *st);                     -> 1 / -1
 *   long utxo_store_init_ro(void *st);                  -> 1 / -1
 *   long utxo_store_put(void *st, void *u, const u8 txid[32], u32 index,
 *                       u64 value, u32 height, u32 is_coinbase,
 *                       const void *script, u32 slen);  -> utxo_put result / -1
 *   long utxo_store_del(void *st, void *u, const u8 txid[32], u32 index);
 *                                                       -> utxo_del result / -1
 *   long utxo_store_count(void *st, void *u);
 *   long utxo_store_get(void *st, void *u, const u8 txid[32], u32 index,
 *                       u64 *value, u32 *height, u32 *is_coinbase,
 *                       const void **script, u32 *slen);
 *   long utxo_store_sync(void *st, void *u);            -> 1 / -1
 *   long utxo_store_reload(void *st, void *u);          -> replayed / -1 / -2 full
 *   long utxo_store_wal_drain(void *st);                -> 0 / -1
 *   void utxo_store_close(void *st);
 * -------------------------------------------------------------------------- */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef unsigned char u8;

#define MAGIC_LOG  0x5554584Fu   /* "UTXO" LE */
#define MAGIC_IDX  0x55545849u   /* "UTXI" LE */
#define OP_PUSH    1
#define OP_DEL     2
#define CKPT_REC   51            /* txid32+index4+value8+height4+cb1+slen2 */
#define PUSH_HDR   8 + CKPT_REC  /* 59 */
#define DEL_SIZE   44
#define IDX_HDR    20            /* magic4+log_off8+n8 */
#define WALBUF_CAP 1048576

static const char logname[]  = "utxo.dat";
static const char idxname[]  = "utxo.idx";
static const char idxtmp[]   = "utxo.idx.tmp";

/* process-wide WAL buffer (mirrors the x86 .bss triple) */
static u8   wal_buf[WALBUF_CAP];
static u64  wal_fill;
static u64  wal_fd;

/* in-memory table primitives (utxo_twin.c; same layout as bitcoin_utxo.asm) */
extern long utxo_put(void *u, const u8 txid[32], unsigned long index,
                     u64 value, unsigned height, unsigned is_coinbase,
                     const void *script, unsigned long slen);
extern long utxo_del(void *u, const u8 txid[32], unsigned long index);
extern long utxo_get(void *u, const u8 txid[32], unsigned long index,
                     u64 *value, unsigned long *height,
                     unsigned long *is_coinbase, const void **script,
                     unsigned long *slen);
extern void utxo_store_clear(void *u);   /* local static below (x86: file-local) */

/* ---- drain: write every buffered byte to fd; short-write tail moved front */
static long mac_wal_drain_fd(u64 fd)
{
    const u8 *p = wal_buf;
    u64 remain = wal_fill;
    while (remain) {
        ssize_t w = write((int)fd, p, remain);
        if (w <= 0) {
            memmove(wal_buf, p, remain);        /* dst < src: forward-safe */
            wal_fill = remain;
            return -1;
        }
        p += w;
        remain -= (u64)w;
    }
    wal_fill = 0;
    return 0;
}

static long mac_wal_drain_pending(void)
{
    return mac_wal_drain_fd(wal_fd);
}

long utxo_store_wal_drain(void *st)
{
    (void)st;
    if (wal_fill == 0) return 0;
    return mac_wal_drain_fd(wal_fd);
}

/* ---- mac_wr_log: buffer/drain/append; advances st->log_len by len -------- */
static long mac_wr_log(void *st, const u8 *buf, u64 len)
{
    u8 *S = (u8 *)st;
    u64 log_fd = *(u64 *)(S + 0);
    if (wal_fill && log_fd != wal_fd) {
        if (mac_wal_drain_pending()) return -1;  /* land other store's bytes */
    }
    wal_fd = log_fd;
    if (len > WALBUF_CAP) {                      /* oversize: straight through */
        if (wal_fill && mac_wal_drain_fd(log_fd)) return -1;
        const u8 *p = buf;
        u64 remain = len;
        while (remain) {
            ssize_t w = write((int)log_fd, p, remain);
            if (w <= 0) return -1;
            p += w;
            remain -= (u64)w;
        }
        *(u64 *)(S + 16) += len;
        return 0;
    }
    if (wal_fill + len > WALBUF_CAP) {
        if (mac_wal_drain_fd(log_fd)) return -1;
    }
    memcpy(wal_buf + wal_fill, buf, len);
    wal_fill += len;
    *(u64 *)(S + 16) += len;                     /* LOGICAL length advances now */
    return 0;
}

long utxo_store_init(void *st)
{
    u8 *S = (u8 *)st;
    int fd = open(logname, O_RDWR | O_CREAT, 0644);
    if (fd < 0) return -1;
    *(u64 *)(S + 0) = (u64)fd;
    fd = open(idxname, O_RDWR | O_CREAT, 0644);
    if (fd < 0) { close((int)*(u64 *)(S + 0)); return -1; }
    *(u64 *)(S + 8) = (u64)fd;
    *(u64 *)(S + 16) = 0;                        /* log_len */
    *(u64 *)(S + 24) = 0;                        /* ckpt_log_off */
    *(u64 *)(S + 32) = 0;                        /* ckpt_n */
    return 1;
}

long utxo_store_init_ro(void *st)
{
    u8 *S = (u8 *)st;
    int fd = open(logname, O_RDONLY);            /* no O_CREAT: missing = error */
    if (fd < 0) return -1;
    *(u64 *)(S + 0) = (u64)fd;
    *(u64 *)(S + 8) = (u64)-1;                   /* idx never opened (reload
                                                    opens utxo.idx itself) */
    *(u64 *)(S + 16) = 0;
    *(u64 *)(S + 24) = 0;
    *(u64 *)(S + 32) = 0;
    return 1;
}

long utxo_store_put(void *st, void *u, const u8 txid[32], u32 index,
                    u64 value, u32 height, u32 is_coinbase,
                    const void *script, u32 slen)
{
    u8 hdr[PUSH_HDR];
    u32 m = MAGIC_LOG;
    memcpy(hdr + 0, &m, 4);
    hdr[4] = OP_PUSH;
    memset(hdr + 5, 0, 3);
    memcpy(hdr + 8, txid, 32);
    memcpy(hdr + 40, &index, 4);
    memcpy(hdr + 44, &value, 8);
    memcpy(hdr + 52, &height, 4);
    hdr[56] = (u8)is_coinbase;
    u16 s16 = (u16)slen;
    memcpy(hdr + 57, &s16, 2);
    if (mac_wr_log(st, hdr, PUSH_HDR)) return -1;
    if (slen && mac_wr_log(st, script, slen)) return -1;
    return utxo_put(u, txid, index, value, height, is_coinbase, script, slen);
}

long utxo_store_del(void *st, void *u, const u8 txid[32], u32 index)
{
    u8 rec[DEL_SIZE];
    u32 m = MAGIC_LOG;
    memcpy(rec + 0, &m, 4);
    rec[4] = OP_DEL;
    memset(rec + 5, 0, 3);
    memcpy(rec + 8, txid, 32);
    memcpy(rec + 40, &index, 4);
    if (mac_wr_log(st, rec, DEL_SIZE)) return -1;
    return utxo_del(u, txid, index);
}

long utxo_store_count(void *st, void *u)
{
    (void)st;
    return *(long *)u;
}

long utxo_store_get(void *st, void *u, const u8 txid[32], u32 index,
                    u64 *value, unsigned long *height,
                    unsigned long *is_coinbase, const void **script,
                    unsigned long *slen)
{
    /* out-pointer widths match the x86 asm + upstream harness ABI exactly:
     * utxo_get writes 8-byte unsigned longs into height/is_coinbase/slen --
     * a 4-byte out pointer gets its neighbor smashed. */
    (void)st;
    return utxo_get(u, txid, index, value, height, is_coinbase, script, slen);
}

/* ---- utxo_store_clear: reset the in-memory table to empty, reusing its ----
 * existing mask/blob/blob_cap pointers (mirrors the x86 file-local helper). */
void utxo_store_clear(void *u)
{
    u8 *U = (u8 *)u;
    *(u64 *)(U + 0) = 0;                         /* n = 0 */
    *(u64 *)(U + 32) = 0;                        /* blob fill = 0 */
    u64 mask = *(u64 *)(U + 8);
    u8 *slot = U + 40;
    for (u64 s = 0; s <= mask; s++, slot += 48)
        *(u32 *)(slot + 40) = 0xFFFFFFFFu;       /* empty */
}

/* ---- sync: drain, write checkpoint to utxo.idx.tmp, fsync, rename -------- */
long utxo_store_sync(void *st, void *u)
{
    u8 *S = (u8 *)st;
    if (utxo_store_wal_drain(st) == -1) return -1;
    int tfd = open(idxtmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (tfd < 0) return -1;
    u8 hdr[IDX_HDR];
    u32 m = MAGIC_IDX;
    memcpy(hdr + 0, &m, 4);
    u64 log_off = *(u64 *)(S + 16);
    u64 n = *(u64 *)u;
    memcpy(hdr + 4, &log_off, 8);
    memcpy(hdr + 12, &n, 8);
    if (write(tfd, hdr, IDX_HDR) != IDX_HDR) goto fail;
    /* walk every live slot: [txid32][index4][value8][height4][cb1][slen2][script] */
    u8 *U = (u8 *)u;
    u64 mask = *(u64 *)(U + 8);
    u8 *blob = (u8 *)(uintptr_t)*(u64 *)(U + 16);
    for (u64 s = 0; s <= mask; s++) {
        u8 *slot = U + 40 + s * 48;
        u32 idx;
        memcpy(&idx, slot + 40, 4);
        if (idx == 0xFFFFFFFFu) continue;
        u64 rec_off = *(u64 *)slot;
        const u8 *rec = blob + rec_off;
        u64 value;
        memcpy(&value, rec, 8);
        u64 hc;
        memcpy(&hc, rec + 8, 8);                 /* height low32, cb in byte32 */
        u64 slen;
        memcpy(&slen, rec + 16, 8);
        u8 txid[32];
        memcpy(txid, slot + 8, 32);
        u32 height = (u32)(hc & 0xFFFFFFFFu);
        u8 cb = (u8)((hc >> 32) & 0xFF);
        u16 s16 = (u16)slen;
        if (write(tfd, txid, 32) != 32) goto fail;
        if (write(tfd, &idx, 4) != 4) goto fail;
        if (write(tfd, &value, 8) != 8) goto fail;
        if (write(tfd, &height, 4) != 4) goto fail;
        if (write(tfd, &cb, 1) != 1) goto fail;
        if (write(tfd, &s16, 2) != 2) goto fail;
        if (slen && write(tfd, rec + 24, slen) != (ssize_t)slen) goto fail;
    }
    *(u64 *)(S + 24) = log_off;                  /* ckpt_log_off */
    *(u64 *)(S + 32) = n;                        /* ckpt_n */
    fsync(tfd);
    fsync((int)*(u64 *)(S + 0));                 /* the log too */
    if (rename(idxtmp, idxname) < 0) goto fail;
    close(tfd);
    return 1;
fail:
    close(tfd);
    unlink(idxtmp);                              /* no torn tmp left behind */
    return -1;
}

/* ---- reload: clear table, load checkpoint snapshot, replay WAL tail ------ */
long utxo_store_reload(void *st, void *u)
{
    u8 *S = (u8 *)st;
    if (utxo_store_wal_drain(st) == -1) return -1;
    utxo_store_clear(u);
    int log_fd = (int)*(u64 *)(S + 0);
    off_t sz = lseek(log_fd, 0, SEEK_END);
    if (sz < 0) return -1;
    *(u64 *)(S + 16) = (u64)sz;
    u64 log_end = (u64)sz;
    *(u64 *)(S + 24) = 0;
    *(u64 *)(S + 32) = 0;
    /* checkpoint (opened here even for init_ro stores, per the x86 contract) */
    int cfd = open(idxname, O_RDONLY);
    if (cfd >= 0) {
        u8 hdr[IDX_HDR];
        if (pread(cfd, hdr, IDX_HDR, 0) == IDX_HDR) {
            u32 m;
            memcpy(&m, hdr, 4);
            if (m == MAGIC_IDX) {
                u64 off, n;
                memcpy(&off, hdr + 4, 8);
                memcpy(&n, hdr + 12, 8);
                *(u64 *)(S + 24) = off;
                *(u64 *)(S + 32) = n;
                off_t cur = IDX_HDR;
                for (u64 i = 0; i < n; i++) {
                    u8 fixed[CKPT_REC];
                    if (pread(cfd, fixed, CKPT_REC, cur) != CKPT_REC) break;
                    cur += CKPT_REC;
                    u32 index;
                    memcpy(&index, fixed + 32, 4);
                    u64 value;
                    memcpy(&value, fixed + 36, 8);
                    u32 height;
                    memcpy(&height, fixed + 44, 4);
                    u8 cb = fixed[48];
                    u16 s16;
                    memcpy(&s16, fixed + 49, 2);
                    u8 script[65536];
                    if (s16 && pread(cfd, script, s16, cur) != s16) break;
                    cur += s16;
                    long pr = utxo_put(u, fixed, index, value, height, cb,
                                       s16 ? script : NULL, s16);
                    if (pr == 2) { close(cfd); return -2; }  /* memtable full */
                }
            }
        }
        close(cfd);
    }
    /* replay WAL tail from ckpt_log_off */
    int rfd = open(logname, O_RDONLY);
    if (rfd < 0) return -1;
    u64 consumed = *(u64 *)(S + 24);
    u64 rec_start = consumed;
    int torn = 0;                                /* UTX-4: set on failing exits */
    long replayed = 0;
    for (;;) {
        if (consumed >= log_end) break;          /* clean end: no truncate */
        rec_start = consumed;
        u8 prefix[8];
        if (pread(rfd, prefix, 8, (off_t)consumed) != 8) { torn = 1; break; }
        consumed += 8;
        u32 m;
        memcpy(&m, prefix, 4);
        u8 op = prefix[4];
        if (m != MAGIC_LOG) { torn = 1; break; } /* corrupt/torn */
        if (op == OP_PUSH) {
            u8 fixed[CKPT_REC];
            if (pread(rfd, fixed, CKPT_REC, (off_t)consumed) != CKPT_REC) { torn = 1; break; }
            consumed += CKPT_REC;
            u32 index;
            memcpy(&index, fixed + 32, 4);
            u64 value;
            memcpy(&value, fixed + 36, 8);
            u32 height;
            memcpy(&height, fixed + 44, 4);
            u8 cb = fixed[48];
            u16 s16;
            memcpy(&s16, fixed + 49, 2);
            u8 script[65536];
            if (s16) {
                if (pread(rfd, script, s16, (off_t)consumed) != s16) { torn = 1; break; }
                consumed += s16;
            }
            long pr = utxo_put(u, fixed, index, value, height, cb,
                               s16 ? script : NULL, s16);
            if (pr == 2) { close(rfd); return -2; }
            replayed++;
        } else if (op == OP_DEL) {
            u8 body[36];
            if (pread(rfd, body, 36, (off_t)consumed) != 36) { torn = 1; break; }
            consumed += 36;
            u32 index;
            memcpy(&index, body + 32, 4);
            utxo_del(u, body, index);
            replayed++;
        } else {
            torn = 1;                            /* unknown op */
            break;
        }
    }
    /* UTX-4: torn tail -> log_len = last good record start; truncate there.
     * ONLY on a torn exit (the x86 has two exits: .rep_close truncates,
     * .rep_done skips). rec_start is where the failing record begins --
     * consumed has already advanced past its prefix, so gating on consumed
     * misses unknown-op records; gating without `torn` truncates a CLEAN
     * WAL's last record (both mistakes caught by test_utxo_torn_tail). */
    if (torn && rec_start < log_end && rec_start < (u64)sz) {
        *(u64 *)(S + 16) = rec_start;
        if (log_fd >= 0)
            ftruncate(log_fd, (off_t)rec_start); /* best-effort, like x86 */
    }
    close(rfd);
    return replayed;
}

void utxo_store_close(void *st)
{
    u8 *S = (u8 *)st;
    u64 log_fd = *(u64 *)(S + 0);
    if (log_fd != (u64)-1) {
        utxo_store_wal_drain(st);
        fsync((int)log_fd);
        close((int)log_fd);
    }
    u64 idx_fd = *(u64 *)(S + 8);
    if (idx_fd != (u64)-1) {
        fsync((int)idx_fd);
        close((int)idx_fd);
    }
}
