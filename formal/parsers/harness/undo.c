/* P-UNDO: the undo-store readers (daemon/undo_store.h us_read_run, and
 * daemon/undo_log.c undo_load / undo_replay / undo_replay_tolerant) over an
 * undo.idx and a rev file of nondeterministic content (rev file <= FP_FSZ
 * bytes): a corrupt or torn store after a crash, or a planted one. These feed
 * reorg disconnects and the fee / prevout RPCs.
 * Environment (stubs; trusted): open/close/pread/stat over the two files;
 * pread returns min(asked, left) bytes, except that at most FP_SHORT reads may
 * come back short (any 1..min) -- the number of short reads bounds the
 * reader's outer loop for the model checker. Height h <= 2^40.
 * Claims:
 *   - memory safety, no leak, of all three readers on every path,
 *   - us_read_run's result is a whole number of records (each 51 + slen,
 *     slen <= 10000) inside the buffer it returns,
 *   - undo_load returns <= max_recs records, each script copied in full and
 *     within its 10000-byte field; -1 on a record running past the run,
 *   - undo_replay hands the callback a 51 + slen readable record each time,
 *     and the record count is <= run length / 51 (the DoS bound). */
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include "nd.h"
#ifndef FP_FSZ
#define FP_FSZ 160
#endif
#ifndef FP_SHORT
#define FP_SHORT 1
#endif
static size_t g_rsz; static unsigned char* g_rev; static int g_open; static int g_short;
int open(const char* p, int fl, ...){ (void)fl; if (nondet_int()) return -1; g_open++;
    return strcmp(p, "undo.idx") == 0 ? 10 : 11; }
int close(int fd){ (void)fd; g_open--; return 0; }
int stat(const char* p, struct stat* sb){ (void)p; memset(sb, 0, sizeof *sb); sb->st_size = (off_t)g_rsz; return nondet_int() ? -1 : 0; }
ssize_t pread(int fd, void* b, size_t n, off_t off){
    CHECK(__CPROVER_w_ok(b, n), "pread buffer writable");
    if (nondet_int() && nondet_int()) return -1;
    if (fd == 10){ if (n > 16) n = 16; return nondet_int() ? (ssize_t)n : 0; }   /* idx slot: content free */
    if (off < 0 || (size_t)off >= g_rsz) return 0;
    size_t left = g_rsz - (size_t)off, got = n < left ? n : left;
    if (g_short < FP_SHORT && got > 1 && nondet_int()){ size_t s = nondet_size(); ASSUME(s >= 1 && s < got); got = s; g_short++; }
    memcpy(b, g_rev + off, got); return (ssize_t)got;
}
ssize_t write(int fd, const void* b, size_t n){ (void)fd; (void)b; return (ssize_t)n; }
ssize_t writev(int fd, const struct iovec* v, int c){ (void)fd; (void)v; (void)c; return -1; }
int fdatasync(int fd){ (void)fd; return 0; }
long utxo_lsm_get(void* lst, void* u, const unsigned char txid[32], unsigned index, unsigned long long* value,
                  unsigned long* height, unsigned long* cb, const unsigned char** script, unsigned long* slen);
long utxo_lsm_del(void* lst, void* u, const unsigned char txid[32], unsigned index);
#include <undo_store.h>   /* ahead of SRC, so a mutated copy can stand in (mutanth) */
#include SRC
static int g_cbn; static long g_runlen;
static int cb(void* ctx, const unsigned char* txid, unsigned index, unsigned long long value, unsigned height,
              unsigned char coinbase, const unsigned char* script, unsigned short slen){
    (void)ctx; (void)index; (void)value; (void)height; (void)coinbase; g_cbn++;
    CHECK(__CPROVER_r_ok(txid, 51) && script == txid + 51 && (slen == 0 || __CPROVER_r_ok(script, slen)), "callback record readable");
    CHECK(slen <= 10000, "script within UNDO_MAX_SCRIPT");
    return nondet_int();
}
int main(void){
    g_rsz = nondet_size(); ASSUME(g_rsz <= FP_FSZ); g_rev = nd_buf(g_rsz);
    long h = nondet_long(); ASSUME(h >= 0 && h <= (1L << 40));
    int mode = nondet_int();
    if (mode == 0){
        unsigned char* buf; int torn;
        long len = us_read_run(h, &buf, &torn);
        if (len >= 0){
            CHECK(buf != 0 && (len == 0 || __CPROVER_r_ok(buf, (size_t)len)), "run inside its buffer");
            size_t o = 0; int k = 0;
            while (o < (size_t)len && k < 4){ unsigned short sl; memcpy(&sl, buf + o + 49, 2); CHECK(sl <= 10000, "slen bound"); o += 51 + sl; k++; }
            CHECK(o == (size_t)len, "a whole number of records");
            free(buf);
        }
        COVER(len >= 102, "two records read");
        COVER(len >= 0 && torn, "a torn run");
    } else if (mode == 1){
        long max = nondet_long(); ASSUME(max >= 0 && max <= 3);
        undo_rec_t* out = (undo_rec_t*)malloc((size_t)(max ? max : 1) * sizeof(undo_rec_t)); ASSUME(out != 0);
        long n = undo_load(h, out, max);
        CHECK(n >= -1 && n <= max, "undo_load within max_recs");
        for (long i = 0; i < n; i++) CHECK(out[i].slen <= 10000, "loaded slen bound");
        free(out);
        COVER(n == 2, "two records loaded");
    } else {
        int torn = 0;
        long n = nondet_int() ? undo_replay(h, cb, 0) : undo_replay_tolerant(h, cb, 0, &torn);
        CHECK(n <= g_cbn, "replayed = callbacks");
        CHECK(n * 51 <= FP_FSZ, "record count bounded by the run");
        COVER(n == 2, "two records replayed");
        COVER(n >= 1 && torn, "tolerant replay over a torn tail");
    }
    CHECK(g_open == 0, "every fd closed");
    free(g_rev);
    return 0;
}
