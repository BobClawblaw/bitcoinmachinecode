/* daemon/log_phase.h -- tiny elapsed-time helper for startup/steady-state
 * phase logging ("loading chain archive...", "...done in 4.2s"). Pairs with
 * log_ts.h (which timestamps every line) so every phase boundary shows both
 * wall-clock time and duration -- the pair this project's logging was
 * missing for troubleshooting slow boots or stalled catch-up.
 *
 * Usage:
 *   phase_timer_t pt; phase_start(&pt);
 *   ... do the work ...
 *   fprintf(stderr, "[boot] chain archive loaded: tip=%d (%.2fs)\n", tip, phase_elapsed(&pt));
 */
#ifndef DAEMON_LOG_PHASE_H
#define DAEMON_LOG_PHASE_H
#include <time.h>
#include <stdio.h>   /* snprintf, for fmt_uptime */

typedef struct { struct timespec t0; } phase_timer_t;

static inline void phase_start(phase_timer_t* pt){
    clock_gettime(CLOCK_MONOTONIC, &pt->t0);
}
static inline double phase_elapsed(phase_timer_t* pt){
    struct timespec t1; clock_gettime(CLOCK_MONOTONIC, &t1);
    return (double)(t1.tv_sec - pt->t0.tv_sec) + (double)(t1.tv_nsec - pt->t0.tv_nsec) / 1e9;
}

/* fmt_uptime(buf, secs) -- an elapsed second count as DD:HH:MM:SS.
 *
 * For the long-lived counters (the [dl] heartbeat, the shutdown line) where a
 * raw second count stops being readable almost immediately: "uptime=36072s" is
 * 10 hours and nobody works that out at a glance.
 *
 * Days are NOT wrapped at any modulus -- a node up for 400 days prints
 * "400:01:02:03", not "035:...". A rolling field would silently understate a
 * long uptime, which is exactly the number you care about when you are asking
 * how long something has been wrong.
 *
 * Returns buf so it can be used inline in a printf argument list. buf must be
 * at least UPTIME_BUF bytes; two calls in one printf need two buffers.
 */
#define UPTIME_BUF 32
static inline const char* fmt_uptime(char buf[UPTIME_BUF], long long secs){
    if (secs < 0) secs = 0;              /* a clock that went backwards reads 0, not garbage */
    long long d = secs / 86400; secs %= 86400;
    long long h = secs / 3600;  secs %= 3600;
    long long m = secs / 60;
    long long s = secs % 60;
    snprintf(buf, UPTIME_BUF, "%02lld:%02lld:%02lld:%02lld", d, h, m, s);
    return buf;
}

#endif /* DAEMON_LOG_PHASE_H */
