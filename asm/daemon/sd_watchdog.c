/* daemon/sd_watchdog.c -- systemd's service watchdog, fed only while the
 * download worker makes progress (2026-11-06).
 *
 * WHY. A dead worker already restarts the unit: the serve parent sees it exit
 * and exits non-zero (reap_children, serve_mux). A worker that is ALIVE but
 * stuck did not, ever:
 *   - 2026-10-19 06:06-06:50Z: the worker spent 42 minutes inside one ZMQ
 *     publishing loop (2,505 "unreadable; not published" lines) with no
 *     heartbeat while its peers hung up.
 *   - 2026-10-30 06:00Z - 11-02 21:18Z: the cgroup was throttled at its
 *     MemoryHigh; heartbeats stretched to 33 minutes, then stopped for 83
 *     hours. The unit stayed "active" until an OOM kill 22 h later.
 * Over 47,133 heartbeats from 2026-09-27 to 11-06 a healthy worker's loop
 * never went more than 174 s between them (p99.9 136 s), so a stall of ten
 * minutes is a stall, not work.
 *
 * HOW. systemd starts a watchdog timer when the unit sets WatchdogSec= and
 * passes WATCHDOG_USEC (and WATCHDOG_PID = the main PID) in the environment;
 * the MAIN process must send "WATCHDOG=1" to $NOTIFY_SOCKET more often than
 * that, or systemd sends WatchdogSignal (SIGABRT: crash_trace.c prints each
 * process's stack, which is the stuck worker's location) and Restart=on-failure
 * starts the unit again. The main process here is the serve parent, which
 * owns no legs and no UTXO set; the work is in the forked download worker. So
 * the worker stamps node_status_t.wd_worker_ms (CLOCK_MONOTONIC, shared) at
 * its progress points -- each rotation of its loop, between blocks of a
 * catch-up pass, each status tick of the parallel downloader -- and the
 * parent's loop (serve_mux, every 300 ms) pings only when that stamp has
 * moved since its last ping. A stuck worker, or a stuck parent loop, both
 * stop the pings. systemd accepts the main PID's messages by default once
 * WatchdogSec= is set (NotifyAccess= defaults to "main"), so the unit needs
 * nothing else.
 *
 * Without WatchdogSec= (every benchmark, test and manual run) nothing here
 * does anything: sdw_init() finds no WATCHDOG_USEC and returns 0.
 *
 * Not covered: the RPC server's own thread in the parent (the 2026-10-07 fd
 * exhaustion left RPC dead while P2P worked); its accept loop does not pass
 * through serve_mux.
 */
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "sd_watchdog.h"
#ifndef SOCK_CLOEXEC                     /* macOS: compiled, never enabled (sdw_init) */
#define SOCK_CLOEXEC 0
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static int  g_fd = -1;
static struct sockaddr_un g_addr;
static socklen_t g_addrlen;
static long long g_timeout_ms;           /* WATCHDOG_USEC / 1000; 0 = off */
static long long g_last_ping_ms = -1;    /* when the parent last pinged */
static long long g_last_beat_pinged = -1;/* the worker stamp that ping carried */
static unsigned long g_pings;

int sdw_should_ping(long long now_ms, long long beat_ms, long long last_ping_ms,
                    long long last_beat_pinged, long long timeout_ms){
    if (timeout_ms <= 0 || beat_ms <= 0) return 0;      /* off, or no stamp yet */
    if (beat_ms == last_beat_pinged) return 0;          /* the worker has not moved */
    /* a few pings per timeout (sd_notify's own advice is half the interval);
     * the first one goes at once */
    if (last_ping_ms >= 0 && now_ms - last_ping_ms < timeout_ms / 4) return 0;
    return 1;
}

long long sdw_parse_usec(const char* s){
    if (!s || !*s) return 0;
    char* end = 0; errno = 0;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno || !end || *end || v == 0) return 0;
    return (long long)(v / 1000ULL);
}

long long sdw_init(void){
    g_timeout_ms = 0;
    if (g_fd >= 0){ close(g_fd); g_fd = -1; }
    g_last_ping_ms = g_last_beat_pinged = -1;
#ifndef __linux__
    return 0;                            /* systemd is Linux's: off on macOS */
#endif
    const char* sock = getenv("NOTIFY_SOCKET");
    long long ms = sdw_parse_usec(getenv("WATCHDOG_USEC"));
    const char* wpid = getenv("WATCHDOG_PID");
    /* systemd names the process it expects pings from; a child exec'd with
     * this environment (an index helper, a test) is not it */
    if (wpid && *wpid && atol(wpid) != (long)getpid()) ms = 0;
    if (!sock || !*sock || ms <= 0) return 0;
    size_t n = strlen(sock);
    if (n >= sizeof g_addr.sun_path) return 0;
    memset(&g_addr, 0, sizeof g_addr);
    g_addr.sun_family = AF_UNIX;
    memcpy(g_addr.sun_path, sock, n);
    if (g_addr.sun_path[0] == '@') g_addr.sun_path[0] = 0;   /* abstract namespace */
    g_addrlen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + n);
    g_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (g_fd < 0) return 0;
    /* the forked children (worker, serve children, exec'd helpers) are not
     * the main PID: they have no business with the socket */
    unsetenv("NOTIFY_SOCKET"); unsetenv("WATCHDOG_USEC"); unsetenv("WATCHDOG_PID");
    g_timeout_ms = ms;
    return ms;
}

void sdw_tick(long long now_ms, long long worker_beat_ms){
    if (g_timeout_ms <= 0) return;
    if (!sdw_should_ping(now_ms, worker_beat_ms, g_last_ping_ms, g_last_beat_pinged, g_timeout_ms)) return;
    static const char msg[] = "WATCHDOG=1";
    if (sendto(g_fd, msg, sizeof msg - 1, MSG_NOSIGNAL, (struct sockaddr*)&g_addr, g_addrlen) < 0){
        static long long last_err_ms = -1;
        if (last_err_ms < 0 || now_ms - last_err_ms > 60000){
            fprintf(stderr, "[watchdog] ping to systemd failed: %s\n", strerror(errno));
            last_err_ms = now_ms;
        }
        return;
    }
    g_last_ping_ms = now_ms; g_last_beat_pinged = worker_beat_ms; g_pings++;
}

unsigned long sdw_pings(void){ return g_pings; }
