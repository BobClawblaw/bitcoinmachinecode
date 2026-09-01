/* daemon/txosp_tail.c -- incremental maintenance of the txo-spender index
 * (txosp_format.h): an append-only, unsorted tail of the same 28-byte
 * records for every block after the base index's to_height. Same design and
 * the same safety argument as tx_index_tail.c: the reader verifies every
 * candidate against the archive, so a torn or duplicate record can only be
 * rejected, never returned wrong; coverage is contiguous (boot backfills);
 * a base rebuilt past the tail truncates it. No base => disabled, loudly. */
#include <stdio.h>
#include "log_ts.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "txosp_format.h"
extern long store_read_at(void* st, unsigned long h, void* out, long cap);
#define TSPT_BLOCKBUF (8u << 20)
static int  g_fd = -1;
static long g_covered = -1;
typedef struct { uint8_t* out; long n; long cap; uint32_t height; int ok; } emit_ctx;
static void tspt_emit(void* ctxv, const uint8_t* prev, uint32_t vout, uint32_t off, uint32_t len){
    emit_ctx* c = ctxv; if (c->n >= c->cap){ c->ok = 0; return; }
    tsp_rec r; memcpy(r.prefix, prev, 12); r.vout = vout; r.height = c->height; r.offset = off; r.len = len;
    tsp_pack(c->out + c->n * TSP_REC, &r); c->n++;
}
static long tspt_count_inputs(const uint8_t* blk, long blen){
    /* upper bound on records: every byte pair could not be an input, but a
     * block of B bytes holds at most B/41 inputs (36 + 1 + 4) */
    (void)blk; return blen / 41 + 1;
}
static int tspt_append_block(long h, const uint8_t* blk, long blen){
    if (blen < 81) return 0;
    long cap = tspt_count_inputs(blk, blen);
    uint8_t* recs = malloc((size_t)cap * TSP_REC); if (!recs) return 0;
    emit_ctx c = { recs, 0, cap, (uint32_t)h, 1 };
    int ok = tsp_walk_block(blk, blen, tspt_emit, &c) && c.ok;
    if (ok && c.n){ long want = c.n * TSP_REC; ok = write(g_fd, recs, (size_t)want) == want; }
    free(recs);
    return ok;
}
static long tspt_scan_max(int fd){
    struct stat sb; if (fstat(fd, &sb) != 0) return -1;
    long nrec = (long)(sb.st_size / TSP_REC);
    if ((long)sb.st_size != nrec * TSP_REC && ftruncate(fd, nrec * TSP_REC) != 0) return -2;
    long maxh = -1; enum { CHUNK = 4096 };
    uint8_t* buf = malloc((size_t)CHUNK * TSP_REC); if (!buf) return -1;
    for (long i = 0; i < nrec; i += CHUNK){
        long n = nrec - i < CHUNK ? nrec - i : CHUNK;
        if (pread(fd, buf, (size_t)n * TSP_REC, (off_t)i * TSP_REC) != n * TSP_REC) break;
        for (long k = 0; k < n; k++){ tsp_rec r; tsp_unpack(&r, buf + k * TSP_REC); if ((long)r.height > maxh) maxh = (long)r.height; }
    }
    free(buf); return maxh;
}
long tspt_base_to(void){
    int fd = open(TSP_BASE_FILE, O_RDONLY); if (fd < 0) return -1;
    uint8_t b[TSP_HDR]; struct stat sb; long to = -1;
    if (fstat(fd, &sb) == 0 && sb.st_size >= TSP_HDR && pread(fd, b, TSP_HDR, 0) == TSP_HDR && memcmp(b, TSP_MAGIC, 8) == 0){
        uint64_t n = 0, so = 0;
        for (int i = 0; i < 8; i++) n  |= (uint64_t)b[8+i]  << (8*i);
        for (int i = 0; i < 8; i++) so |= (uint64_t)b[16+i] << (8*i);
        if (TSP_HDR + n * TSP_REC == so && so <= (uint64_t)sb.st_size){ uint32_t t = 0; for (int i = 0; i < 4; i++) t |= (uint32_t)b[36+i] << (8*i); to = (long)t; }
    }
    close(fd); return to;
}
static long tspt_backfill(void* store_buf, long tip){
    if (g_fd < 0 || g_covered < 0) return 0;
    long done = 0; static uint8_t* blockbuf;
    if (!blockbuf && !(blockbuf = malloc(TSPT_BLOCKBUF))) return -1;
    while (g_covered < tip){
        long h = g_covered + 1;
        long blen = store_read_at(store_buf, (unsigned long)h, blockbuf, TSPT_BLOCKBUF);
        if (blen < 81 || !tspt_append_block(h, blockbuf, blen)){ fprintf(stderr, "[txospender] tail backfill stopped at height %ld (read %ld)\n", h, blen); return -1; }
        g_covered = h; done++;
    }
    return done;
}
void tsp_boot(void* store_buf){
    long base_to = tspt_base_to();
    if (base_to < 0){ fprintf(stderr, "[txospender] no base %s -- index disabled (build one with daemon/build_txospender_index)\n", TSP_BASE_FILE); return; }
    int fd = open(TSP_TAIL_FILE, O_RDWR | O_CREAT | O_APPEND, 0644);
    if (fd < 0){ fprintf(stderr, "[txospender] cannot open %s -- tail disabled\n", TSP_TAIL_FILE); return; }
    long tail_max = tspt_scan_max(fd);
    if (tail_max == -2){ fprintf(stderr, "[txospender] cannot truncate %s's torn record -- tail disabled\n", TSP_TAIL_FILE); close(fd); return; }
    if (tail_max >= 0 && base_to >= tail_max){ if (ftruncate(fd, 0) == 0) fprintf(stderr, "[txospender] tail folded into base (to=%ld) -- truncated\n", base_to); tail_max = -1; }
    g_fd = fd; g_covered = tail_max > base_to ? tail_max : base_to;
    long tip = *(int*)((uint8_t*)store_buf + 24);
    long n = tspt_backfill(store_buf, tip);
    fprintf(stderr, "[txospender] tail active: base to=%ld covered=%ld (backfilled %ld)\n", base_to, g_covered, n < 0 ? 0 : n);
}
int tsp_active(void){ return g_fd >= 0; }
void tsp_on_truncate(void* store_buf){
    if (g_fd < 0) return;
    long tip = *(int*)((uint8_t*)store_buf + 24);
    if (tip < g_covered){ fprintf(stderr, "[txospender] tail watermark rolled back %ld -> %ld (store truncated)\n", g_covered, tip); g_covered = tip; }
}
void tsp_on_block(void* store_buf, long h, const unsigned char* blk, long blen){
    if (g_fd < 0 || h <= g_covered) return;
    if (h > g_covered + 1 && tspt_backfill(store_buf, h - 1) < 0) return;
    if (h == g_covered + 1){ if (tspt_append_block(h, blk, blen)) g_covered = h; else fprintf(stderr, "[txospender] tail append failed at height %ld\n", h); }
}
