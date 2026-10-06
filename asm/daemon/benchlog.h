/* daemon/benchlog.h -- the [bench] index line and the [ready] finish line
 * (2026-10-04; worklog/2026-10-04-logged-ibd-runs-plan.md parts 2 and 3).
 *
 * Pure formatters and one pure predicate, so the exact text a benchmark
 * report parses is pinned by tests/test_benchlog.c without a daemon. The
 * callers are daemon/main.c's block choke point (the index line, with
 * bmc.benchlog=1) and its download-worker loop (the ready line, once, always).
 * The per-block UTXO line and the flush line live in daemon/utxo_live.c, next
 * to the accumulators they print; the download-chunk line is
 * daemon/dlc_benchlog.c. */
#ifndef BMC_BENCHLOG_H
#define BMC_BENCHLOG_H
#include <stddef.h>

/* ---- the per-block index line ------------------------------------------
 * The work the choke point does for one connected block OUTSIDE the UTXO
 * apply timer, in nanoseconds per index:
 *   [bench] index H: txindex X | txospender X | bfilter X | addr X | zmq X ms
 * X in ms with two decimals. An index that is off costs ~0 and prints 0.00. */
enum { BL_IX_TXINDEX, BL_IX_TXOSPENDER, BL_IX_BFILTER, BL_IX_ADDR, BL_IX_ZMQ, BL_IX_N };
int benchlog_fmt_index(char* out, size_t cap, long h, const unsigned long long ns[BL_IX_N]);

/* ---- the finish line ---------------------------------------------------
 * "Ready to serve RPC with every index at the tip": after initial block
 * download is over, the UTXO set applied to the archive tip, the txid index
 * covering it (runs + tail), the block filter index holding a filter for it,
 * and the coinstats history complete (the base verified, or the repair's
 * "history base complete" check passed) with the fold at the tip. An index
 * that is disabled is skipped and named as skipped, never waited on.
 *
 *   [ready] all indexes at height N (utxo, txindex, bfilter, coinstats history) -- S.Ss
 *   [ready] all indexes at height N (utxo, txindex; skipped: bfilter, coinstats history) -- S.Ss
 *
 * benchlog_ready_eval returns 1 and writes that line (no timestamp, no
 * newline) when every enabled index is there; 0 with the first unmet
 * condition in `out` ("waiting: txindex at 812 of 900") otherwise. */
typedef struct {
    int    ibd_over;          /* the IBD latch has flipped (Core's m_cached_is_ibd false) */
    long   tip;               /* the archive tip (stored height) */
    int    utxo_on;   long utxo_applied;         /* utxo_live_applied_height() */
    int    txindex_on; long txindex_covered;     /* txit_covered(): runs + tail */
    int    bfilter_on; long bfilter_count;       /* bfi_count(): filters for heights 0..count-1 */
    int    coinstats_on; int coinstats_hist_ok;  /* the repair supervisor's state is OK */
    long   coinstats_height;                     /* the fold's watermark (coinstats.dat height) */
    double secs;              /* since process start */
} benchlog_ready_t;
int benchlog_ready_eval(const benchlog_ready_t* r, char* out, size_t cap);

/* ---- the [mem] line (plan M1, 2026-10-06) --------------------------------
 * This process's memory by mapping, proportional set size (Pss: a page
 * shared with a forked child counts once, split between them), largest
 * first, read from /proc/self/smaps:
 *
 *   [mem] at IBD end: pss 18765 MB (anon 8284, file 10409, shmem 72) | utxo-memtable 6791 | hdr-tree 1024 | utxo_lsm_blob.map 1623 | ... | other 212
 *
 * An anonymous region named with benchlog_mem_name_region shows under that
 * name; an unnamed one is "anon"; a file-backed mapping is its basename;
 * entries under 16 MB are summed as "other". The totals come from
 * /proc/self/smaps_rollup. The sampler beside a benchmark run sums Pss_Anon
 * across the tree the same way; summing "Anonymous" counted the worker's
 * inherited copy-on-write pages once per forked child (13 x 1.4 GB on run
 * 39), which is how 27.9 GB of "anonymous memory" got into a report.
 * Returns the length written; when /proc/self/smaps cannot be read the
 * line says so and the return is still its length. */
int benchlog_mem_line(char* out, size_t cap, const char* tag);
/* name an anonymous mapping for /proc/PID/maps, smaps and the line above
 * (prctl PR_SET_VMA_ANON_NAME, Linux 5.17+; a kernel without it, or a
 * region that is not anonymous, is a silent no-op). The name is copied
 * by the kernel: a literal or a static string, at most 79 bytes,
 * [A-Za-z0-9._-] and space. A malloc'd block is fine: the range is
 * trimmed to whole pages (its first and last partial page stay unnamed).
 * Header-only so any file can name what it allocates without a new link
 * dependency. */
#include <sys/syscall.h>
#include <unistd.h>
static __attribute__((unused, access(none, 1))) void benchlog_mem_name_region(const void* p, size_t len, const char* name){
    /* access(none, 1): the pointer is only cast to an address, never read
     * through. Without it gcc 13 -O2 infers a read through the const pointer
     * and reports a caller that names a fresh malloc'd block as "'<unknown>'
     * may be used uninitialized"; under -Werror that fails the daemon link. */
    const unsigned long pg = 4096;
    unsigned long a, e;
    if (!p || !len || !name) return;
    a = ((unsigned long)p + pg - 1) & ~(pg - 1);
    e = ((unsigned long)p + len) & ~(pg - 1);
    if (e <= a) return;
    (void)syscall(SYS_prctl, 0x53564d41L /* PR_SET_VMA */, 0L /* PR_SET_VMA_ANON_NAME */, a, e - a, name);
}

#endif
