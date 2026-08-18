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

typedef struct { struct timespec t0; } phase_timer_t;

static inline void phase_start(phase_timer_t* pt){
    clock_gettime(CLOCK_MONOTONIC, &pt->t0);
}
static inline double phase_elapsed(phase_timer_t* pt){
    struct timespec t1; clock_gettime(CLOCK_MONOTONIC, &t1);
    return (double)(t1.tv_sec - pt->t0.tv_sec) + (double)(t1.tv_nsec - pt->t0.tv_nsec) / 1e9;
}

#endif /* DAEMON_LOG_PHASE_H */
