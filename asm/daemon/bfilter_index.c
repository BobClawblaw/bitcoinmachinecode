/* daemon/bfilter_index.c -- the persistent BIP157/158 block filter index.
 *
 * WHY: the filter BUILDER has been byte-identical to Core since 2026-08-26
 * (KAT-pinned), but getblockfilter could only serve the ~200-block undo
 * window -- a filter needs the block's SPENT-PREVOUT scripts, and undo data
 * was the only source -- and could never serve the HEADER at all, because
 * BIP157 headers chain from genesis through every prior filter. This index
 * stores every filter and its chained header, whole-chain, tip-following.
 *
 * FILES (datadir):
 *   bfilters.dat  append-only concatenated filter bytes.
 *   bfilters.idx  48-byte file header:  "BMCBFIX1" | u64 n_records | rsvd
 *                 then one 48-byte record per height:
 *                 u64 data_offset | u32 filter_len | u32 zero | u8 header[32]
 *                 (header = BIP157: sha256d(sha256d(filter) || prev_header),
 *                  prev_header = zeros for height 0.)
 *
 * WRITERS, in strict sequence, never concurrent:
 *   1. daemon/build_block_filters.c backfills history offline, resolving
 *      each input's prevout script through the TXID INDEX (the reason this
 *      index became feasible today). Resumable: it continues from the
 *      record count it finds.
 *   2. The DAEMON's tail appends per applied block at the new-block choke
 *      point, prevouts from that block's own undo records. It ADOPTS the
 *      files lazily: while the backfill is still far behind the tip the
 *      daemon leaves them alone; once the remaining gap is small enough to
 *      close from the undo retention window it reconciles, backfills the
 *      gap from undo data, and owns the files from then on -- no restart
 *      between "backfill finished" and "index live". Never run the
 *      offline builder against files the daemon has adopted.
 *
 * CRASH DISCIPLINE: data bytes are written before their idx record, no
 * per-block fsync (the choke point must never stall on filter IO); boot
 * reconciliation truncates a torn idx tail to the 48-byte grid, truncates
 * orphan data bytes past the last complete record, and re-verifies the
 * LAST record's header against the chain before trusting it.
 */
#include <stdio.h>
#include "log_ts.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

#include "../block_filter.h"
extern void sha256d(u8 out[32], const void* msg, long long len);

#define BFI_DATA "bfilters.dat"
#define BFI_IDX  "bfilters.idx"
#define BFI_MAGIC "BMCBFIX1"
#define BFI_HDR   48
#define BFI_REC   48
#define BFI_MAX_FILTER (1u << 20)

static int  g_dfd = -1, g_ifd = -1;
static long g_n = -1;                  /* records (== next height to append) */
static u8   g_prev_header[32];         /* header of record g_n-1; zeros at 0 */

void bfi_close(void);

long bfi_count(void){ return g_n; }
int  bfi_active(void){ return g_dfd >= 0; }

static int bfi_read_rec(long h, u64* off, u32* len, u8 hdr[32]){
    u8 r[BFI_REC];
    if (pread(g_ifd, r, BFI_REC, BFI_HDR + (long)h * BFI_REC) != BFI_REC) return 0;
    u64 o = 0; u32 l = 0;
    for (int i = 0; i < 8; i++) o |= (u64)r[i] << (8*i);
    for (int i = 0; i < 4; i++) l |= (u32)r[8+i] << (8*i);
    *off = o; *len = l;
    if (hdr) memcpy(hdr, r + 16, 32);
    return 1;
}

/* Open + reconcile. Returns the record count, or -1 when the files are
 * absent/unusable (index inactive). `rw` distinguishes the daemon/builder
 * (which repair) from a read-only probe. */
long bfi_open(int rw){
    int fl = rw ? O_RDWR : O_RDONLY;
    int ifd = open(BFI_IDX, fl);
    if (ifd < 0) return -1;
    int dfd = open(BFI_DATA, fl | (rw ? O_APPEND : 0));
    if (dfd < 0){ close(ifd); return -1; }
    u8 h[BFI_HDR];
    struct stat is, ds;
    if (fstat(ifd, &is) != 0 || fstat(dfd, &ds) != 0 ||
        is.st_size < BFI_HDR || pread(ifd, h, BFI_HDR, 0) != BFI_HDR ||
        memcmp(h, BFI_MAGIC, 8) != 0){
        close(ifd); close(dfd); return -1;
    }
    u64 n = 0;
    for (int i = 0; i < 8; i++) n |= (u64)h[8+i] << (8*i);
    long by_size = (long)((is.st_size - BFI_HDR) / BFI_REC);
    long nn = (long)n < by_size ? (long)n : by_size;   /* trust the SMALLER: a
                                                        * torn header or tail
                                                        * shrinks, never grows */
    g_ifd = ifd; g_dfd = dfd;
    if (rw){
        /* truncate a torn idx tail to the record grid */
        if (is.st_size != BFI_HDR + nn * BFI_REC)
            if (ftruncate(ifd, BFI_HDR + nn * BFI_REC) != 0){ bfi_close(); return -1; }
        /* orphan data past the last complete record: truncate */
        if (nn > 0){
            u64 off; u32 len;
            if (!bfi_read_rec(nn - 1, &off, &len, g_prev_header)){ bfi_close(); return -1; }
            if ((u64)ds.st_size != off + len)
                if ((u64)ds.st_size < off + len || ftruncate(dfd, (long)(off + len)) != 0){
                    bfi_close(); return -1;
                }
        } else memset(g_prev_header, 0, 32);
    } else if (nn > 0){
        u64 off; u32 len;
        if (!bfi_read_rec(nn - 1, &off, &len, g_prev_header)){ bfi_close(); return -1; }
    } else memset(g_prev_header, 0, 32);
    g_n = nn;
    return nn;
}

void bfi_close(void){
    if (g_ifd >= 0) close(g_ifd);
    if (g_dfd >= 0) close(g_dfd);
    g_ifd = g_dfd = -1; g_n = -1;
}

/* create empty files (the offline builder's first run) */
int bfi_create(void){
    int ifd = open(BFI_IDX, O_RDWR | O_CREAT | O_EXCL, 0644);
    if (ifd < 0) return 0;
    int dfd = open(BFI_DATA, O_RDWR | O_CREAT | O_APPEND, 0644);
    if (dfd < 0){ close(ifd); unlink(BFI_IDX); return 0; }
    u8 h[BFI_HDR]; memset(h, 0, sizeof h);
    memcpy(h, BFI_MAGIC, 8);
    if (write(ifd, h, BFI_HDR) != BFI_HDR){ close(ifd); close(dfd); unlink(BFI_IDX); return 0; }
    g_ifd = ifd; g_dfd = dfd; g_n = 0;
    memset(g_prev_header, 0, 32);
    return 1;
}

/* Append the NEXT height's filter: data first, then the idx record, then
 * the count in the file header -- so every prefix of the write sequence
 * reconciles to a consistent state. */
int bfi_append(const u8* filter, unsigned long flen){
    if (g_dfd < 0 || flen == 0 || flen > BFI_MAX_FILTER) return 0;
    struct stat ds;
    if (fstat(g_dfd, &ds) != 0) return 0;
    if (write(g_dfd, filter, flen) != (long)flen) return 0;
    u8 hdr[32];
    bf_header(filter, flen, g_prev_header, hdr);
    u8 r[BFI_REC]; memset(r, 0, sizeof r);
    u64 off = (u64)ds.st_size;
    for (int i = 0; i < 8; i++) r[i]   = (u8)(off >> (8*i));
    for (int i = 0; i < 4; i++) r[8+i] = (u8)(flen >> (8*i));
    memcpy(r + 16, hdr, 32);
    if (pwrite(g_ifd, r, BFI_REC, BFI_HDR + g_n * BFI_REC) != BFI_REC) return 0;
    g_n++;
    memcpy(g_prev_header, hdr, 32);
    u8 cnt[8];
    for (int i = 0; i < 8; i++) cnt[i] = (u8)((u64)g_n >> (8*i));
    if (pwrite(g_ifd, cnt, 8, 8) != 8) return 0;
    return 1;
}

/* Read one height's filter + chained header. 1 ok / 0 not covered. */
int bfi_get(long h, u8* out, unsigned long cap, unsigned long* flen, u8 header[32]){
    if (g_dfd < 0 || h < 0 || h >= g_n) return 0;
    u64 off; u32 len;
    if (!bfi_read_rec(h, &off, &len, header)) return 0;
    if (len > cap) return 0;
    if (pread(g_dfd, out, len, (long)off) != (long)len) return 0;
    *flen = len;
    return 1;
}

/* Out-of-process probe (the parent's RPC/getindexinfo): fresh open,
 * read, close. Single writer + ordered appends make a read of record
 * i < count always consistent. */
long bfi_probe_count(void){
    int ifd = open(BFI_IDX, O_RDONLY);
    if (ifd < 0) return -1;
    u8 h[BFI_HDR];
    struct stat is;
    long n = -1;
    if (fstat(ifd, &is) == 0 && is.st_size >= BFI_HDR &&
        pread(ifd, h, BFI_HDR, 0) == BFI_HDR && memcmp(h, BFI_MAGIC, 8) == 0){
        u64 v = 0;
        for (int i = 0; i < 8; i++) v |= (u64)h[8+i] << (8*i);
        long by_size = (long)((is.st_size - BFI_HDR) / BFI_REC);
        n = (long)v < by_size ? (long)v : by_size;
    }
    close(ifd);
    return n;
}

/* ---- the daemon's live tail ---------------------------------------------
 * bfi_on_block: append the filter for a freshly-applied block, prevouts
 * from that block's OWN undo records. Lazy adoption: while the offline
 * backfill is still far behind the tip, the daemon leaves the files alone
 * (adopting mid-build would race the builder); once the remaining gap fits
 * inside the undo retention window it reconciles, closes the gap from undo
 * data, and owns the files from then on. */
/* undo access is REGISTERED, not linked: the tail runs only in the daemon
 * worker; the standalone rpcd links this file for the read side alone and
 * must not drag undo_log in. */
typedef int (*bfi_undo_cb)(void*, const u8*, u32, u64, u32, u8, const u8*, unsigned short);
static long (*g_undo_replay_fn)(long, bfi_undo_cb, void*);
void bfi_set_undo_replay(long (*fn)(long, bfi_undo_cb, void*)){ g_undo_replay_fn = fn; }
extern long store_read_at(void* st, unsigned long h, void* out, long cap);

#define BFI_ADOPT_GAP 144              /* adopt only when closable from undo */
#define BFI_MAX_PREV_LIVE 65536

typedef struct {
    bf_script* v; u8* buf; unsigned long n, bufoff; int overflow;
} bfi_prev_ctx;

static int bfi_prev_cb(void* ctxv, const u8* txid, u32 index, u64 value,
                       u32 height, u8 coinbase, const u8* script, unsigned short slen){
    (void)txid; (void)index; (void)value; (void)height; (void)coinbase;
    bfi_prev_ctx* c = ctxv;
    if (c->n >= BFI_MAX_PREV_LIVE || c->bufoff + slen > (unsigned long)BFI_MAX_PREV_LIVE * 128){
        c->overflow = 1; return 0;
    }
    memcpy(c->buf + c->bufoff, script, slen);
    c->v[c->n].script = c->buf + c->bufoff;
    c->v[c->n].len = slen;
    c->bufoff += slen;
    c->n++;
    return 1;
}

/* CompactSize reader for the walk below. Sets *consumed to 0 on a truncated
 * or out-of-range field so every caller can treat that as "malformed". */
static u64 bfi_rd_varint(const u8* p, const u8* end, unsigned long* consumed){
    *consumed = 0;
    if (p >= end) return 0;
    u8 c = *p;
    if (c < 0xfd){ *consumed = 1; return c; }
    if (c == 0xfd){ if (p + 3 > end) return 0; *consumed = 3;
                    return (u64)p[1] | ((u64)p[2] << 8); }
    if (c == 0xfe){ if (p + 5 > end) return 0; *consumed = 5;
                    u64 v = 0; for (int i=0;i<4;i++) v |= (u64)p[1+i] << (8*i); return v; }
    if (p + 9 > end) return 0;
    *consumed = 9;
    { u64 v = 0; for (int i=0;i<8;i++) v |= (u64)p[1+i] << (8*i); return v; }
}

/* STO-3: how many prevouts this block spends, i.e. how many undo records the
 * filter needs. Local varint walk rather than a shared helper, because
 * tests/test_bfilter_index does not link daemon/undo_log.c and adding that
 * dependency to read one number would be the wrong trade. Returns -1 on a
 * malformed block, which the caller treats as "cannot build". */
static long bfi_count_spends(const u8* blk, unsigned long blen){
    const u8* p = blk + 80; const u8* end = blk + blen;
    unsigned long cc;
    u64 ntx = bfi_rd_varint(p, end, &cc); if (!cc) return -1;
    p += cc;
    long spends = 0;
    for (u64 t = 0; t < ntx; t++){
        if (p + 4 > end) return -1;
        p += 4;
        int sw = (p + 2 <= end && p[0] == 0x00 && p[1] == 0x01);
        if (sw) p += 2;
        u64 nin = bfi_rd_varint(p, end, &cc); if (!cc) return -1;
        p += cc;
        for (u64 i = 0; i < nin; i++){
            if (p + 36 > end) return -1;
            if (t != 0) spends++;                 /* the coinbase spends nothing */
            p += 36;
            u64 sl = bfi_rd_varint(p, end, &cc); if (!cc) return -1;
            p += cc + sl + 4;
            if (p > end) return -1;
        }
        u64 nout = bfi_rd_varint(p, end, &cc); if (!cc) return -1;
        p += cc;
        for (u64 i = 0; i < nout; i++){
            if (p + 8 > end) return -1;
            p += 8;
            u64 sl = bfi_rd_varint(p, end, &cc); if (!cc) return -1;
            p += cc;
            if (p + sl > end) return -1;
            p += sl;
        }
        if (sw){
            for (u64 i = 0; i < nin; i++){
                u64 items = bfi_rd_varint(p, end, &cc); if (!cc) return -1;
                p += cc;
                for (u64 k = 0; k < items; k++){
                    u64 il = bfi_rd_varint(p, end, &cc); if (!cc) return -1;
                    p += cc + il;
                    if (p > end) return -1;
                }
            }
        }
        if (p + 4 > end) return -1;
        p += 4;
    }
    return spends;
}

/* build + append the filter for height h from block bytes + undo records.
 * 1 ok / 0 failed (the index closes rather than storing a wrong filter). */
static int bfi_append_from_undo(long h, const u8* blk, unsigned long blen){
    static bf_script* v; static u8* pbuf; static u8* filter;
    if (!v)      v = malloc(BFI_MAX_PREV_LIVE * sizeof *v);
    if (!pbuf)   pbuf = malloc((unsigned long)BFI_MAX_PREV_LIVE * 128);
    if (!filter) filter = malloc(BFI_MAX_FILTER);
    if (!v || !pbuf || !filter) return 0;
    if (!g_undo_replay_fn) return 0;
    bfi_prev_ctx c = { v, pbuf, 0, 0, 0 };
    long ur = g_undo_replay_fn(h, bfi_prev_cb, &c);
    if ((ur < 0 && h != 0) || c.overflow) return 0;   /* undo torn: cannot build */
    /* STO-3 (audit 2026-09-03): an ABSENT undo file returns 0, exactly like a
     * block that genuinely spends nothing -- undo_replay cannot tell "pruned"
     * from "empty", and chose to proceed. A block whose undo file had been
     * pruned then produced a filter built from OUTPUT scripts only, missing
     * every spent-prevout element. Core's BlockFilterIndex::CustomAppend
     * FAILS the index when undo is unavailable; it never emits a partial
     * filter. A partial one is worse than none: its sha256d and every
     * bf_header chained after it diverge from Core permanently, and a light
     * client is told those blocks do not touch its coins.
     *
     * The block is the authority on how many prevouts to expect. Fewer undo
     * records than spends means the data is missing or short, whatever the
     * reason -- which also covers a truncated-but-not-torn file that the
     * ur < 0 check cannot see.
     *
     * Reachable without operator error: utxo_live_catchup applies to the
     * archive tip in one call and prunes undo below applied-199, before the
     * choke point that feeds this tail runs. */
    { long want = bfi_count_spends(blk, blen);
      if (want < 0) return 0;
      if (ur < want){
          fprintf(stderr, "[bfi] h=%ld: undo has %ld records but the block spends %ld "
                          "-- refusing to store a filter missing its prevout elements\n",
                  h, ur, want);
          return 0;
      } }
    u8 hash[32];
    sha256d(hash, blk, 80);
    long fl = bf_basic_build(blk, blen, hash, v, c.n, filter, BFI_MAX_FILTER);
    if (fl <= 0) return 0;
    return bfi_append(filter, (unsigned long)fl);
}

/* called at the new-block choke point for every applied height, in order */
void bfi_on_block(void* store_buf, long h, const u8* blk, unsigned long blen){
    static int adopt_denied_logged;
    if (g_dfd < 0){
        /* not adopted yet: probe cheaply; adopt only when the gap is
         * closable from the undo window */
        long n = bfi_probe_count();
        if (n < 0) return;                           /* no files: builder not run */
        /* Judge the gap against the CHAIN TIP, not h. The daemon connects a
         * catch-up burst by looping h from last_seen_tip+1, so early in a
         * burst h is small while the tip is already far ahead -- h - n then
         * goes NEGATIVE and this adopts at an arbitrarily large REAL gap.
         * Not corrupting (the append below is guarded by g_n == h, and a gap
         * close that outruns the undo window closes the index rather than
         * storing a wrong filter) but it takes the index DOWN until
         * build_block_filters is re-run -- the worst possible outcome for an
         * unattended overnight backfill. The sibling tails read the tip the
         * same way: addr_index_tail.c, tx_index_tail.c. Caught 2026-08-28 by
         * validation/bfi_adopt_regtest_e2e.sh, whose builder happened to
         * finish mid-burst and got "ADOPTED at 73 records (tip 1)". */
        long tip = *(int*)((u8*)store_buf + 24);
        if (tip < h) tip = h;                        /* h wins if the store header lags */
        if (tip - n > BFI_ADOPT_GAP){
            if (!adopt_denied_logged){
                fprintf(stderr, "[bfilter] index at %ld, tip %ld -- waiting for the backfill to close in\n", n, tip);
                adopt_denied_logged = 1;
            }
            return;
        }
        if (bfi_open(1) < 0) return;
        fprintf(stderr, "[bfilter] ADOPTED at %ld records (tip %ld) -- closing the gap from undo data\n",
                bfi_count(), tip);
    }
    /* close any gap below h from the archive + undo, then append h */
    static u8* gapbuf;
    while (g_n < h){
        if (!gapbuf && !(gapbuf = malloc(8u << 20))) { bfi_close(); return; }
        long gl = store_read_at(store_buf, (unsigned long)g_n, gapbuf, 8u << 20);
        if (gl < 81 || !bfi_append_from_undo(g_n, gapbuf, (unsigned long)gl)){
            fprintf(stderr, "[bfilter] gap close FAILED at %ld (undo pruned?) -- index closed; "
                            "re-run build_block_filters\n", g_n);
            bfi_close();
            return;
        }
    }
    if (g_n == h && !bfi_append_from_undo(h, blk, blen)){
        fprintf(stderr, "[bfilter] append failed at %ld -- index closed\n", h);
        bfi_close();
    }
}

/* reorg: drop records above the new tip; the reconnected blocks re-append
 * through the choke point (bfi_on_block's gap close). */
void bfi_on_truncate(long new_tip){
    if (g_dfd < 0 || g_n <= new_tip + 1) return;
    long keep = new_tip + 1;
    u64 off; u32 len;
    if (keep > 0 && bfi_read_rec(keep - 1, &off, &len, g_prev_header)){
        if (ftruncate(g_ifd, BFI_HDR + keep * BFI_REC) == 0 &&
            ftruncate(g_dfd, (long)(off + len)) == 0){
            g_n = keep;
            u8 cnt[8];
            for (int i = 0; i < 8; i++) cnt[i] = (u8)((u64)g_n >> (8*i));
            if (pwrite(g_ifd, cnt, 8, 8) == 8){
                fprintf(stderr, "[bfilter] truncated to %ld records (reorg)\n", g_n);
                return;
            }
        }
    }
    fprintf(stderr, "[bfilter] reorg truncate failed -- index closed\n");
    bfi_close();
}

int bfi_get_file(long h, u8* out, unsigned long cap, unsigned long* flen, u8 header[32]){
    long n = bfi_probe_count();
    if (n < 0 || h < 0 || h >= n) return 0;
    int ifd = open(BFI_IDX, O_RDONLY), dfd = open(BFI_DATA, O_RDONLY);
    int ok = 0;
    if (ifd >= 0 && dfd >= 0){
        u8 r[BFI_REC];
        if (pread(ifd, r, BFI_REC, BFI_HDR + h * BFI_REC) == BFI_REC){
            u64 off = 0; u32 len = 0;
            for (int i = 0; i < 8; i++) off |= (u64)r[i] << (8*i);
            for (int i = 0; i < 4; i++) len |= (u32)r[8+i] << (8*i);
            if (header) memcpy(header, r + 16, 32);
            if (len <= cap && pread(dfd, out, len, (long)off) == (long)len){
                *flen = len; ok = 1;
            }
        }
    }
    if (ifd >= 0) close(ifd);
    if (dfd >= 0) close(dfd);
    return ok;
}
