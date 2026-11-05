/* fd_limit.h -- make room for an index builder's bucket files.
 *
 * The index builders keep one open FILE per bucket through their first pass:
 * 256 for bmc_build_tx_index, _txospender_index, _addr_index and _addr_hist,
 * and 512 in each forked worker of bmc_build_coinstats_hist (an outpoint and
 * a spend file per bucket). macOS starts a process with a soft RLIMIT_NOFILE
 * of 256, so on the Mac every one of them failed to open its last buckets
 * ("FATAL: open bucket", "cannot open txosp_b2NN.tmp") unless the shell had
 * raised the limit; Linux's usual 1024 hid it.
 *
 * bmc_raise_nofile(need) lifts the soft limit to `need` when it is lower,
 * never past the hard limit (nor, on Darwin, past OPEN_MAX, which setrlimit
 * refuses to exceed), and never lowers it. Where the soft limit already
 * covers `need`, as on Linux, it changes nothing. A failure is left to the
 * fopen that follows, which reports it. */
#ifndef BMC_FD_LIMIT_H
#define BMC_FD_LIMIT_H
#include <limits.h>
#include <sys/resource.h>
static inline void bmc_raise_nofile(rlim_t need){
    struct rlimit r;
    if (getrlimit(RLIMIT_NOFILE, &r) != 0 || r.rlim_cur == RLIM_INFINITY || r.rlim_cur >= need) return;
    rlim_t cap = r.rlim_max;
#ifdef OPEN_MAX
    if (cap == RLIM_INFINITY || cap > OPEN_MAX) cap = OPEN_MAX;
#endif
    rlim_t to = need < cap ? need : cap;
    if (to <= r.rlim_cur) return;
    r.rlim_cur = to;
    (void)setrlimit(RLIMIT_NOFILE, &r);
}
#endif
