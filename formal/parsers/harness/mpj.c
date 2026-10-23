/* P-MPJ: the mempool departure journal (daemon/mempool_journal.c) opened on
 * an existing file of nondeterministic content and size <= FP_FSZ (or created
 * when the file is shorter than its header), then read and appended to.
 * Environment (stubs; trusted): open/fstat/pread/pwrite/ftruncate/close; mmap
 * returns a fresh mapping of exactly the requested length with arbitrary
 * contents (so the mapped header need not even agree with the pread one);
 * munmap checks it unmaps that mapping. The configured capacity for a new
 * file is <= 3 (a configuration value, not file data).
 * Claims:
 *   - memory safety of mpj_open, mpj_append, mpj_recent, mpj_lookup (and,
 *     FP_STATS, mpj_stats): every slot touched lies inside the mapping,
 *   - mpj_open adopts only a capacity the file can hold,
 *   - every walk is bounded by the ring's capacity whatever next_seq the file
 *     holds (unwinding assertions at capacity + 2): the DoS bound,
 *   - mpj_recent delivers at most `want` records, each with a valid reason. */
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "nd.h"
#ifndef FP_FSZ
#define FP_FSZ (64 + 152 * 3)
#endif
static size_t g_fsz; static void* g_map; static size_t g_maplen;
int open(const char* p, int fl, ...){ (void)p; (void)fl; return nondet_int() ? -1 : 5; }
int close(int fd){ (void)fd; return 0; }
int fstat(int fd, struct stat* sb){ (void)fd; if (nondet_int()) return -1; memset(sb, 0, sizeof *sb); sb->st_size = (off_t)g_fsz; return 0; }
ssize_t pread(int fd, void* b, size_t n, off_t off){ (void)fd;
    CHECK(__CPROVER_w_ok(b, n), "pread buffer writable");
    if (off < 0 || (size_t)off >= g_fsz) return 0;
    size_t got = n <= g_fsz - (size_t)off ? n : g_fsz - (size_t)off;
    unsigned char* p = b; for (size_t i = 0; i < got && i < 64; i++) p[i] = nondet_uchar();
    return (ssize_t)got; }
ssize_t pwrite(int fd, const void* b, size_t n, off_t off){ (void)fd; (void)off; CHECK(__CPROVER_r_ok(b, n), "pwrite buffer readable"); return nondet_int() ? -1 : (ssize_t)n; }
int ftruncate(int fd, off_t len){ (void)fd; if (nondet_int()) return -1; g_fsz = (size_t)len; return 0; }
void* mmap(void* a, size_t len, int prot, int fl, int fd, off_t off){
    (void)a; (void)prot; (void)fl; (void)fd; (void)off;
    CHECK(len <= g_fsz, "mapping no longer than the file");
    if (nondet_int()) return MAP_FAILED;
    g_map = malloc(len); ASSUME(g_map != 0); g_maplen = len; return g_map; }
int munmap(void* a, size_t len){ CHECK(a == g_map && len == g_maplen, "munmap of the mapping"); free(a); g_map = 0; return 0; }
#include SRC
static int g_cb_n;
static int cb(void* ctx, const mpj_rec* r){ (void)ctx; g_cb_n++; CHECK(r->reason >= 1 && r->reason <= MPJ_REASON_MAX, "delivered record has a valid reason"); return nondet_int(); }
int main(void){
    g_fsz = nondet_size(); ASSUME(g_fsz <= FP_FSZ);
    uint64_t cfgcap = nondet_ull(); ASSUME(cfgcap <= 3);
    if (!mpj_open("j.dat", cfgcap)) return 0;
    CHECK(g_mpj_cap >= 1 && MPJ_HDR_BYTES + g_mpj_cap * MPJ_REC_BYTES <= g_maplen, "capacity fits the mapping");
    mpj_rec r; memset(&r, 0, sizeof r); r.reason = nondet_uint();
    if (nondet_int()) mpj_append(&r);
    long want = nondet_long(); ASSUME(want <= 4);
    long n = mpj_recent(want, cb, 0);
    CHECK(n <= want || want <= 0, "recent delivers at most want");
    CHECK(n <= g_cb_n, "delivered = callbacks that continued");
    unsigned char txid[32]; mpj_rec out;
    if (nondet_int()) (void)mpj_lookup(txid, &out);
#ifdef FP_STATS
    mpj_stats_t st; mpj_stats(&st);
    CHECK(st.held <= st.capacity, "held <= capacity");
#endif
    mpj_close();
    COVER(n >= 2, "two records read back");
    COVER(g_mpj_cap == 3, "a three-slot ring adopted");
    return 0;
}
