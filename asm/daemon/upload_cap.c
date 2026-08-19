/* daemon/upload_cap.c -- Core -maxuploadtarget.
 *
 * We serve blocks to inbound peers with no cap and, until now, no measurement
 * at all: a peer (or many) could pull the whole chain from us repeatedly and
 * nothing would notice. Core bounds this over a rolling 24h window.
 *
 * Serving happens inside node_serve_loop (assembly) in a forked child per
 * connection, so there is no C call site to count bytes at. Rather than thread
 * counters through the asm, the parent samples each child's real write volume
 * from /proc/<pid>/io -- exactly the technique dl_catchup already uses to spot
 * a dragging peer. That measures what the kernel actually sent, which is
 * harder to get wrong than instrumenting the serialiser.
 *
 * The window is a coarse 24h reset rather than a sliding average: Core's own
 * accounting is approximate for the same reason, and a cap that is slightly
 * generous at a window boundary is far better than one that is wrong in a way
 * nobody can reason about.
 */
#include <stdio.h>
#include "log_ts.h"
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include "node_config.h"

static long long g_window_start = 0;
static long long g_bytes_this_window = 0;
static int       g_capped_logged = 0;

/* Bytes this process has written to sockets+files, from /proc/<pid>/io.
 * write_bytes is storage-bound; wchar counts everything handed to write(),
 * which is what we want for upload volume. Returns -1 if unreadable. */
long long upload_proc_wchar(int pid){
    char path[64]; snprintf(path,sizeof path,"/proc/%d/io",pid);
    FILE* f=fopen(path,"r"); if(!f) return -1;
    char line[128]; long long v=-1;
    while(fgets(line,sizeof line,f)){
        if(!strncmp(line,"wchar:",6)){ v=atoll(line+6); break; }
    }
    fclose(f);
    return v;
}

/* Add observed upload bytes and report whether we are over target.
 * Returns 1 if serving should be refused, 0 if within budget (or no limit).
 * Never blocks and never fails: with maxuploadtarget=0 it is a no-op, which
 * is Core's default and this node's previous behaviour. */
long upload_note_and_check(long bytes_added){
    if(g_cfg.maxuploadtarget_mb <= 0) return 0;      /* 0 == unlimited */

    long long now = (long long)time(0);
    if(g_window_start == 0) g_window_start = now;
    if(now - g_window_start >= 86400){               /* roll the 24h window */
        if(g_bytes_this_window)
            fprintf(stderr,"[upload] 24h window reset (served %lldMB)\n",
                    g_bytes_this_window>>20);
        g_window_start = now;
        g_bytes_this_window = 0;
        g_capped_logged = 0;
    }
    if(bytes_added > 0) g_bytes_this_window += bytes_added;

    long long cap = (long long)g_cfg.maxuploadtarget_mb << 20;
    if(g_bytes_this_window >= cap){
        if(!g_capped_logged){
            fprintf(stderr,"[upload] maxuploadtarget reached: %lldMB of %ldMB in this 24h window -- refusing further inbound serving\n",
                    g_bytes_this_window>>20, g_cfg.maxuploadtarget_mb);
            g_capped_logged = 1;
        }
        return 1;
    }
    return 0;
}

/* Current usage, for the heartbeat. */
long long upload_bytes_this_window(void){ return g_bytes_this_window; }
