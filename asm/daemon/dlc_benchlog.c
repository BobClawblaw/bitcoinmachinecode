/* daemon/dlc_benchlog.c -- see dlc_benchlog.h (2026-10-04). */
#include <stdio.h>
#include "log_ts.h"
#include "node_config.h"
#include "dlc_benchlog.h"

int dlc_benchlog_fmt_chunk(char* out, size_t cap, int w, const char* peer, long lo, long n,
                           long wall_ms, long wait_ms, long bytes, int inflight_max){
    double mb = (double)bytes / 1e6;
    /* a chunk that landed inside one millisecond has no meaningful rate: 0 */
    double rate = wall_ms > 0 ? mb * 1000.0 / (double)wall_ms : 0.0;
    return snprintf(out, cap, "[bench] chunk w%d peer %s: blocks %ld..%ld (%ld) | wall %ld ms | wait %ld ms | %.2f MB (%.2f MB/s) | inflight max %d",
                    w, peer && peer[0] ? peer : "?", lo, lo + n - 1, n, wall_ms, wait_ms, mb, rate, inflight_max);
}

void dlc_benchlog_chunk(int w, const char* peer, long lo, long n, long wall_ms, long wait_ms,
                        long bytes, int inflight_max){
    if (!g_cfg.benchlog) return;
    char line[512];
    dlc_benchlog_fmt_chunk(line, sizeof line, w, peer, lo, n, wall_ms, wait_ms, bytes, inflight_max);
    fprintf(stderr, "%s\n", line);   /* log_ts.h: timestamp + line in one write */
}
