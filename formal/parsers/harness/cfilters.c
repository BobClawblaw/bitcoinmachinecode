/* P-CF: serve_cfilters (daemon/serve_cfilters.c), the BIP157 getcfilters /
 * getcfheaders / getcfcheckpt server, on a request of nondeterministic
 * content and length <= 40 from any peer, over a filter index whose files
 * have nondeterministic content.
 * Environment (stubs; trusted): serve_height_of_hash returns any height
 * (or -1); the index header holds FP_K <= 3 filters (the file length bound:
 * cf_read refuses h >= count); filter records hold any offset and any length;
 * p2p_write checks its payload; sha256d checks its input.
 * Claims: memory safety (out/fbuf never overrun whatever lengths the index
 * holds), the range caps are applied before any file is read (no index read
 * at a height outside [start, start + cap - 1], plus start - 1 for the
 * cfheaders chain, or the checkpoint heights), each cfilter / cfheaders /
 * cfcheckpt payload is well formed (type byte, hash, count matching what
 * follows). */
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "nd.h"
#ifndef FP_K
#define FP_K 3
#endif
static long g_start, g_stop; static int g_kind; static long g_count;
int open(const char* p, int fl, ...){ (void)fl; if (nondet_int() && nondet_int()) return -1;
    return !strcmp(p, "bfilters.idx") ? 20 : !strcmp(p, "bfilters.dat") ? 21 : 22; }
int close(int fd){ (void)fd; return 0; }
ssize_t pread(int fd, void* b, size_t n, off_t off){
    CHECK(__CPROVER_w_ok(b, n), "pread buffer writable");
    unsigned char* p = b;
    if (fd == 20 && off == 0){ CHECK(n == 48, "index header");
        memcpy(p, "BMCBFIX1", 8); unsigned long long c = (unsigned long long)g_count; memcpy(p + 8, &c, 8); return nondet_int() ? 48 : -1; }
    if (fd == 20){ long h = (long)((off - 48) / 48);
        CHECK(off >= 48 && (off - 48) % 48 == 0 && h < g_count, "index record of a counted height");
        if (g_kind == 0 || g_kind == 1) CHECK((h >= g_start && h <= g_stop) || (g_kind == 1 && h == g_start - 1), "index read inside the requested range");
        if (g_kind == 2) CHECK(h % 1000 == 0 && h >= 1000 && h <= g_stop, "checkpoint heights only");
        return nondet_int() ? 48 : 0; }
    if (fd == 22){ CHECK(off >= 0 && off % 48 == 0, "index.dat record"); return nondet_int() ? 48 : 0; }
    return nondet_int() ? (ssize_t)n : 0;     /* bfilters.dat: the filter bytes */
}
long serve_height_of_hash(const unsigned char h[32]){ CHECK(__CPROVER_r_ok(h, 32), "hash readable"); long v = nondet_long(); ASSUME(v >= -1 && v <= 0x7fffffffL); g_stop = v; return v; }
void sha256d(unsigned char* out, const void* d, unsigned long n){ CHECK(__CPROVER_r_ok(d, n) && __CPROVER_w_ok(out, 32), "sha256d spans"); }
long p2p_write(int fd, const char* cmd, unsigned cl, const void* pv, unsigned plen){
    (void)fd; (void)cmd; (void)cl; const unsigned char* p = pv;
    CHECK(plen >= 34 && __CPROVER_r_ok(p, plen) && p[0] == 0, "reply: basic type byte, readable");
    return nondet_int() ? (long)plen : -1;
}
#include SRC
int main(void){
    g_count = nondet_long(); ASSUME(g_count >= 0 && g_count <= FP_K);
    size_t len = nondet_size(); ASSUME(len <= 40);
    unsigned char* pl = nd_buf(len);
    g_kind = nondet_int(); ASSUME(g_kind >= 0 && g_kind <= 2);
    if (len >= 5) g_start = (long)((unsigned)pl[1] | ((unsigned)pl[2] << 8) | ((unsigned)pl[3] << 16) | ((unsigned)pl[4] << 24));
    int r = serve_cfilters(3, g_kind, pl, len);
    CHECK(r >= 0, "result");
    free(pl);
    COVER(g_kind == 0 && r >= 2, "two cfilters sent");
    COVER(g_kind == 1 && r == 1, "cfheaders sent");
    COVER(g_kind == 2 && r == 1, "cfcheckpt sent");
    return 0;
}
