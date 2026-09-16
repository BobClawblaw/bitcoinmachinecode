/* daemon/tx_index_tail.c -- incremental maintenance of the txid index.
 *
 * WHY: build_tx_index.c writes a sorted, immutable txindex.dat and the
 * daemon never touched it again, so the index stopped at whatever height it
 * was built at and `getrawtransaction <txid>` went blind for every block
 * after that. This module keeps a TAIL: an append-only file of the same
 * 20-byte records, unsorted, covering the heights after the base index's
 * to_height. The reader (rpc_chain.c) scans it linearly after a base-index
 * miss.
 *
 * WHY UNSORTED-APPEND IS SAFE HERE, when everything else in this project
 * fsyncs and orders its writes so carefully: the reader VERIFIES every
 * candidate record by reading the transaction out of the archive and
 * recomputing its full txid. A torn record from a crash mid-write, or a
 * duplicate from a re-appended block, is either rejected by that check or
 * yields the identical (height, offset, len) answer. There is no state a
 * partial tail write can corrupt -- the worst case is a missing record,
 * and boot-time backfill (below) closes exactly that.
 *
 * COVERAGE IS KEPT CONTIGUOUS: records are appended in strictly ascending
 * height order, one write(2) per block (O_APPEND, so concurrent readers see
 * whole-block extents). txit_boot backfills from the archive any gap
 * between max(base.to_height, tail's last height) and the current tip --
 * which also covers blocks that arrived while the daemon was down, and the
 * gap between an offline base build and the deploy that follows it. A UTXO
 * drop-and-rebuild replaying the whole chain appends nothing: every height
 * it revisits is <= the covered height.
 *
 * If the base index is later REBUILT past the tail, the tail's heights are
 * folded into it; boot detects that (base.to >= tail max) and truncates the
 * tail to zero rather than letting dead records accumulate.
 *
 * No base index at all => disabled, loudly. Backfilling from genesis into
 * an unsorted file would build a 29 GB linear scan; the offline builder is
 * the right tool for the base and this module is the right tool for the
 * tip.
 */
#include <stdio.h>
#include "log_ts.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "txi_format.h"

extern long store_read_at(void* st, unsigned long h, void* out, long cap);
extern int  tx_txid(void* out, const void* tx, unsigned long txlen, void* buf, unsigned long buflen);

#define TXIT_BLOCKBUF (8u << 20)

static int  g_fd = -1;        /* txindex.tail, O_APPEND; -1 = disabled */
static long g_covered = -1;   /* highest height whose records are durable */

typedef struct { uint8_t* out; long n; uint32_t height; uint8_t* scratch; int ok; } emit_ctx;

static void txit_emit(void* ctxv, const uint8_t* tx, uint32_t off, uint32_t len){
    emit_ctx* c = ctxv;
    uint8_t txid[32];
    if (tx_txid(txid, tx, len, c->scratch, TXIT_BLOCKBUF) != 1){ c->ok = 0; return; }
    uint8_t* r = c->out + c->n * TXI_REC;
    memcpy(r, txid, 8);
    for (int b = 0; b < 4; b++) r[8+b]  = (uint8_t)(c->height >> (8*b));
    for (int b = 0; b < 4; b++) r[12+b] = (uint8_t)(off >> (8*b));
    for (int b = 0; b < 4; b++) r[16+b] = (uint8_t)(len >> (8*b));
    c->n++;
}

/* Append one block's records as ONE write. Returns 1 on success. */
static int txit_append_block(long h, const uint8_t* blk, long blen){
    uint64_t cc, ntx;
    if (blen < 81) return 0;
    ntx = txi_rd_varint(blk + 80, blk + blen, &cc);
    if (!cc || !ntx) return 0;
    uint8_t* recs = malloc((size_t)ntx * TXI_REC);
    uint8_t* scratch = malloc(TXIT_BLOCKBUF);
    if (!recs || !scratch){ free(recs); free(scratch); return 0; }
    emit_ctx c = { recs, 0, (uint32_t)h, scratch, 1 };
    int ok = txi_walk_block(blk, blen, txit_emit, &c) && c.ok && c.n == (long)ntx;
    if (ok){
        long want = c.n * TXI_REC;
        ok = write(g_fd, recs, (size_t)want) == want;
    }
    free(recs); free(scratch);
    return ok;
}

/* Scan the existing tail for its highest COMPLETE record's height. A torn
 * final record (crash mid-write) is TRUNCATED AWAY, not just ignored: the
 * next append lands right after it, and a partial record left mid-file
 * would shift every later record off the 20-byte grid the reader walks.
 * The block the torn record belonged to is re-appended by the backfill
 * below. */
static long txit_scan_max(int fd){
    struct stat sb;
    if (fstat(fd, &sb) != 0) return -1;
    long nrec = (long)(sb.st_size / TXI_REC);
    if ((long)sb.st_size != nrec * TXI_REC && ftruncate(fd, nrec * TXI_REC) != 0)
        return -2;                     /* cannot restore the grid -- disable */
    long maxh = -1;
    enum { CHUNK = 4096 };            /* records per read */
    uint8_t* buf = malloc((size_t)CHUNK * TXI_REC);
    if (!buf) return -1;
    for (long i = 0; i < nrec; i += CHUNK){
        long n = nrec - i < CHUNK ? nrec - i : CHUNK;
        if (pread(fd, buf, (size_t)n * TXI_REC, (off_t)i * TXI_REC) != n * TXI_REC) break;
        for (long k = 0; k < n; k++){
            const uint8_t* r = buf + k * TXI_REC;
            uint32_t hh = 0;
            for (int b = 0; b < 4; b++) hh |= (uint32_t)r[8+b] << (8*b);
            if ((long)hh > maxh) maxh = (long)hh;
        }
    }
    free(buf);
    return maxh;
}

/* ---- run-set awareness (2026-09-16, index_runs.h) -------------------------
 * The base is a SET of sorted runs now, built by the daemon behind the
 * applied height during the sync; the tail covers whatever is above the
 * highest run. Two consequences for this file:
 *   - "no base" no longer disables the tail: a fresh sync starts the tail
 *     at genesis and the first run folds it within run_blocks heights, so
 *     the linear scan stays bounded by the run interval, never the chain;
 *   - when a run is committed, the tail's records at or below its to
 *     height are duplicates of sorted ones and are dropped by rewriting the
 *     file (the tail is height-ordered, so this is a prefix). Readers that
 *     mapped the old inode keep a valid mapping; they remap on the next
 *     size change and rescan from zero when the file shrank. */
#include "index_runs.h"
static long txit_runs_to(void){
    static irunset_t s; static int init;
    if (!init){ irs_init(&s, "txindex", TXI_MAGIC, TXI_REC, TXI_SPARSE); init = 1; }
    irs_dirty(&s);
    long to = irs_covered_to(&s);
    irs_close_all(&s);                 /* the writer keeps no mappings */
    return to;
}
/* a run reaching `to` was committed: drop the tail's records at or below it */
void txit_runs_advanced(long to){
    if (g_fd < 0) return;
    struct stat sb; if (fstat(g_fd, &sb) != 0) return;
    long nrec = (long)(sb.st_size / TXI_REC);
    if (nrec == 0) return;
    enum { CHUNK = 4096 };
    uint8_t* buf = malloc((size_t)CHUNK * TXI_REC); if (!buf) return;
    /* records are height-ordered: find the first one above `to` */
    long keep_from = nrec;
    for (long i = 0; i < nrec && keep_from == nrec; i += CHUNK){
        long n = nrec - i < CHUNK ? nrec - i : CHUNK;
        if (pread(g_fd, buf, (size_t)n * TXI_REC, (off_t)i * TXI_REC) != n * TXI_REC) break;
        for (long k = 0; k < n; k++){
            const uint8_t* r = buf + k * TXI_REC; uint32_t hh = 0;
            for (int b = 0; b < 4; b++) hh |= (uint32_t)r[8+b] << (8*b);
            if ((long)hh > to){ keep_from = i + k; break; }
        }
    }
    if (keep_from == 0){ free(buf); return; }             /* nothing to drop */
    const char* tmp = "txindex.tail.rot";
    int nfd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (nfd < 0){ free(buf); return; }
    long ok = 1;
    for (long i = keep_from; i < nrec && ok; i += CHUNK){
        long n = nrec - i < CHUNK ? nrec - i : CHUNK;
        if (pread(g_fd, buf, (size_t)n * TXI_REC, (off_t)i * TXI_REC) != n * TXI_REC){ ok = 0; break; }
        if (write(nfd, buf, (size_t)n * TXI_REC) != n * TXI_REC) ok = 0;
    }
    free(buf);
    if (!ok || fsync(nfd) != 0 || close(nfd) != 0 || rename(tmp, "txindex.tail") != 0){ unlink(tmp); return; }
    int fd = open("txindex.tail", O_RDWR | O_APPEND);
    if (fd < 0) return;                                     /* keep appending to the old inode */
    close(g_fd); g_fd = fd;
    fprintf(stderr, "[txindex] tail rotated: %ld records folded into runs (to %ld), %ld kept\n", keep_from, to, nrec - keep_from);
}

static long txit_base_to(void){ return txit_runs_to(); }

/* Bring the tail up to `tip`, reading missed blocks from the archive.
 * Returns the number of blocks appended, or -1 on a read failure (the
 * covered height stays where the failure left it; the next call retries). */
static long txit_backfill(void* store_buf, long tip){
    if (g_fd < 0) return 0;                /* covered == -1 means "from genesis" now (2026-09-16), not disabled */
    long done = 0;
    static uint8_t* blockbuf;
    if (!blockbuf && !(blockbuf = malloc(TXIT_BLOCKBUF))) return -1;
    while (g_covered < tip){
        long h = g_covered + 1;
        long blen = store_read_at(store_buf, (unsigned long)h, blockbuf, TXIT_BLOCKBUF);
        if (blen < 81 || !txit_append_block(h, blockbuf, blen)){
            fprintf(stderr, "[txindex] tail backfill stopped at height %ld (read %ld)\n", h, blen);
            return -1;
        }
        g_covered = h;
        done++;
    }
    return done;
}

/* Called once in the download worker after its store is initialised.
 * Establishes coverage and closes any gap up to the current tip. */
void txit_boot(void* store_buf){
    long base_to = txit_base_to();
    if (base_to < 0)
        fprintf(stderr, "[txindex] no run yet -- the tail starts at genesis; the trailing builder folds it into runs\n");
    int fd = open(TXI_TAIL_FILE, O_RDWR | O_CREAT | O_APPEND, 0644);
    if (fd < 0){ fprintf(stderr, "[txindex] cannot open %s -- tail disabled\n", TXI_TAIL_FILE); return; }
    long tail_max = txit_scan_max(fd);
    if (tail_max == -2){
        fprintf(stderr, "[txindex] cannot truncate %s's torn record -- tail disabled\n", TXI_TAIL_FILE);
        close(fd); return;
    }
    if (tail_max >= 0 && base_to >= tail_max){
        /* the base was rebuilt past the tail: every tail record is now a
         * duplicate of a sorted one -- drop them */
        if (ftruncate(fd, 0) == 0)
            fprintf(stderr, "[txindex] tail folded into base (to=%ld) -- truncated\n", base_to);
        tail_max = -1;
    }
    g_fd = fd;
    g_covered = tail_max > base_to ? tail_max : base_to;
    long tip = *(int*)((uint8_t*)store_buf + 24);
    long n = txit_backfill(store_buf, tip);
    fprintf(stderr, "[txindex] tail active: base to=%ld covered=%ld (backfilled %ld)\n",
            base_to, g_covered, n < 0 ? 0 : n);
}

/* 1 when the tail is being maintained (base index present, file writable). */
int txit_active(void){ return g_fd >= 0; }

/* Called from the post-truncation index-rebuild callback after a reorg.
 * Records above the new tip are STALE, not harmful -- the reader recomputes
 * every candidate's txid from the CURRENT archive bytes at the recorded
 * location, so a record for a replaced block simply stops matching. What
 * must move is the watermark: with covered rolled back to the truncated
 * tip, the reconnected blocks are re-appended by the next tip advance (or
 * the next boot's backfill) instead of being skipped as already-covered. */
void txit_on_truncate(void* store_buf){
    if (g_fd < 0) return;
    long tip = *(int*)((uint8_t*)store_buf + 24);
    if (tip < g_covered){
        fprintf(stderr, "[txindex] tail watermark rolled back %ld -> %ld (store truncated)\n",
                g_covered, tip);
        g_covered = tip;
    }
}

/* Called at the new-block choke point with the block already in memory.
 * Heights at or below the covered height append nothing (that is what makes
 * a full UTXO replay harmless); a height further ahead than covered+1 first
 * backfills the gap from the archive so coverage stays contiguous. */
void txit_on_block(void* store_buf, long h, const unsigned char* blk, long blen){
    if (g_fd < 0 || h <= g_covered) return;
    if (h > g_covered + 1 && txit_backfill(store_buf, h - 1) < 0) return;
    if (h == g_covered + 1){
        if (txit_append_block(h, blk, blen)) g_covered = h;
        else fprintf(stderr, "[txindex] tail append failed at height %ld\n", h);
    }
}
