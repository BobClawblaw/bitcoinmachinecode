/* P-MPD: mempool_dump_read (daemon/mempool_persist.c), Core's mempool.dat
 * reader (v1 plain / v2 XOR-obfuscated), on a file of nondeterministic content
 * and length <= FP_FSZ (a corrupt file, or one handed over from elsewhere:
 * loadmempool / -persistmempool).
 * Environment: the file (fileio.h); tx_parse (bitcoin_tx.asm) as in P-CMPCT.
 * Claims:
 *   - memory safety, no leak, the file is closed on every path,
 *   - every transaction handed to the sink lies inside the file image and is
 *     followed by its 16 time/delta bytes, in file order without overlap,
 *   - the count loop is bounded by the file (each record takes >= 17 bytes),
 *     whatever count the file claims (the DoS bound),
 *   - a result >= 0 equals the number of sink calls,
 *   - (X-MPD-delta, with --unsigned-overflow-check) the delta-map length
 *     check `pos + nd * 40 > fsz` is computed without wrap-around. */
#include <stdlib.h>
#include <string.h>
#include "nd.h"
#include "fileio.h"
int tx_parse(void* info, const unsigned char* p, unsigned long cap){
    CHECK(cap == 0 || __CPROVER_r_ok(p, cap), "tx_parse: the span it may read is readable");
    if (!nondet_int()) return 0;
    unsigned long long tl = nondet_ull(); ASSUME(tl >= 1 && tl <= cap);
    memcpy(info, &tl, 8); return 1;
}
static unsigned long g_last_end; static long g_sinks;
static int sink(void* ctx, const unsigned char* tx, unsigned long len, long long t, long long d){
    (void)ctx; (void)t; (void)d; g_sinks++;
    /* the read buffer is one malloc of exactly the file size */
    CHECK(len >= 1 && __CPROVER_OBJECT_SIZE(tx) == g_fsz, "tx inside the file image");
    unsigned long off = (unsigned long)__CPROVER_POINTER_OFFSET(tx);
    CHECK(off >= g_last_end && off + len + 16 <= g_fsz, "tx and its 16 trailing bytes inside the file, in order");
    g_last_end = off + len + 16;
    return nondet_int() ? 0 : -1;
}
#include SRC
int main(void){
    fio_init();
    char err[64];
    long r = mempool_dump_read("mempool.dat", sink, 0, err, sizeof err);
    CHECK(g_fopen_n == 0, "file closed on every path");
    CHECK(r == -1 || r == g_sinks, "result = transactions delivered");
    CHECK(g_sinks <= (long)(g_fsz / 17), "records bounded by the file size");
    COVER(r >= 2, "two transactions loaded");
    COVER(r == 0 && g_fsz > 20, "an empty dump loaded");
    COVER(r >= 1 && g_f[0] == 2, "a v2 (obfuscated) dump loaded");
    return 0;
}
