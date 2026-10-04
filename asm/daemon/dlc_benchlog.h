/* daemon/dlc_benchlog.h -- the per-chunk download line of bmc.benchlog
 * (2026-10-04; worklog/2026-10-04-logged-ibd-runs-plan.md part 2).
 *
 * One line per chunk a parallel-download worker finishes, for the logged
 * IBD runs (the counterpart of what Core's debug=net would let a reader
 * reconstruct per peer):
 *
 *   [bench] chunk w3 peer 203.0.113.7:8333: blocks 800000..800015 (16) | wall 1234 ms | wait 56 ms | 12.34 MB (10.00 MB/s) | inflight max 16
 *
 *   w             the worker index
 *   peer          the peer the chunk came from (as the worker names it)
 *   blocks lo..   the heights, lo .. lo+n-1, and n
 *   wall          getdata sent to the last block stored, ms
 *   wait          getdata sent to the first byte of the first block, ms
 *   MB (MB/s)     block bytes received for the chunk, and bytes / wall
 *   inflight max  the most blocks requested-but-not-received at once
 *
 * The CALLER is the dlc worker in daemon/main.c (wired by the downloader's
 * owner); this file keeps the format in one place and the gate in one
 * place, so that call is a single line. */
#ifndef BMC_DLC_BENCHLOG_H
#define BMC_DLC_BENCHLOG_H
#include <stddef.h>

/* the line, no timestamp, no newline; returns snprintf's count */
int dlc_benchlog_fmt_chunk(char* out, size_t cap, int w, const char* peer, long lo, long n,
                           long wall_ms, long wait_ms, long bytes, int inflight_max);
/* prints it (timestamped, one write) when bmc.benchlog=1; nothing otherwise */
void dlc_benchlog_chunk(int w, const char* peer, long lo, long n, long wall_ms, long wait_ms,
                        long bytes, int inflight_max);

#endif
