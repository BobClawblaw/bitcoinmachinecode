/* daemon/index_runs.h -- a SET of sorted index runs (2026-09-16).
 *
 * WHY: the txid index and the txo-spender index each had ONE sorted base
 * file plus an unsorted tail, and the base could only be produced by an
 * offline walk of the whole archive. That made "build the index during the
 * sync" impossible -- every base rebuild re-read everything -- so the
 * indexes waited for initial block download to finish, and the tails had to
 * be disabled without a base because a from-genesis tail would be a 29 GB
 * linear scan.
 *
 * A run set is the LSM answer: the index is any number of sorted files, each
 * covering a contiguous height range, in EXACTLY the base's on-disk format
 * (so a node's existing base is simply the run that starts at 0), plus the
 * tail for the heights above the highest run. The daemon builds a new run
 * every few thousand blocks behind the applied height, during the sync and
 * after it; the tail is rotated to drop what a run now covers; runs are
 * merged when there are too many. A lookup asks each run (sparse binary
 * search, then the archive verifies every candidate as it always has), then
 * the tail.
 *
 * FILES (chain directory): <name>.dat (the legacy base, optional) and
 * <name>.r<from>-<to>.dat, from/to zero-padded to nine digits so a listing
 * sorts by height. A builder writes <file>.tmp and renames; a merge writes
 * its output the same way and unlinks its inputs afterwards, so a reader
 * that still has an input mapped keeps a valid mapping (the inode lives).
 *
 * HEADER, shared by both formats (48 bytes): magic[8] | u64 n_records |
 * u64 sparse_off | u64 sparse_n | u32 from_height | u32 to_height | u64 rsvd.
 * Record and sparse-entry sizes differ per format and are given at init.
 *
 * This module only DISCOVERS and MAPS runs; the per-format lookup (record
 * comparison, candidate verification) stays with the reader that owns it.
 * Single-threaded by construction, like the readers it serves. */
#ifndef BMC_INDEX_RUNS_H
#define BMC_INDEX_RUNS_H
#include <stddef.h>
#include <sys/types.h>
#include <time.h>

#define IRS_MAX_RUNS 64
#define IRS_HDR      48

typedef struct {
    char path[300];
    const unsigned char* map;      /* whole file, read-only */
    size_t len;
    ino_t ino;
    unsigned long long n, sparse_off, nsparse;
    long from, to;
} irun_t;

typedef struct {
    char name[32];                 /* "txindex" -> txindex.dat, txindex.r*.dat */
    char magic[9];
    int rec, sparse;               /* record and sparse-entry sizes, bytes */
    irun_t r[IRS_MAX_RUNS];        /* sorted by (from, to) */
    int n;
    time_t last_scan;
    long dir_mtime_s, dir_mtime_ns;
} irunset_t;

void irs_init(irunset_t* s, const char* name, const char* magic, int rec_bytes, int sparse_bytes);
/* Rescan the current directory for runs -- at most once per second, and
 * only when the directory changed. Maps new runs, unmaps vanished ones.
 * Returns 1 when the set changed, 0 otherwise, -1 when the directory cannot
 * be read. Safe to call before every lookup. */
int  irs_refresh(irunset_t* s);
/* Force a rescan on the next refresh (tests, and a writer that knows). */
void irs_dirty(irunset_t* s);
/* Highest to_height over all runs, -1 with none. Refreshes first. */
long irs_covered_to(irunset_t* s);
/* Lowest from_height, -1 with none. */
long irs_covered_from(irunset_t* s);
/* The file name a new run over [from, to] must be written to. */
void irs_run_name(const char* name, long from, long to, char* out, size_t cap);
/* Parse one run file's header into r (path already set; maps the file).
 * 1 ok / 0 not a valid run of this format. Exposed for the merge tool. */
int  irs_open_run(const irunset_t* s, irun_t* r);
void irs_close_run(irun_t* r);
/* Drop every mapping (tests; a process about to exec). */
void irs_close_all(irunset_t* s);
#endif
