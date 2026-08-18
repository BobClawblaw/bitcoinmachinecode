/* daemon/log_ts.h -- transparently prefix every fprintf(stderr, ...) call
 * with a UTC timestamp, without touching the individual call sites.
 *
 * Include AFTER <stdio.h> (needs FILE/vfprintf already declared) and
 * BEFORE any fprintf(stderr, ...) calls in the including file. Redefines
 * fprintf via macro for the REST of that translation unit only -- this
 * codebase's daemon/*.c files call fprintf exclusively on stderr for
 * logging (verified: every fprintf( call site is fprintf(stderr, ...),
 * none write to any other stream), so there's no risk of accidentally
 * timestamping a data write.
 *
 * Format: "YYYY-MM-DD HH:MM:SS.mmm " prefixed to each line, UTC (avoids
 * any local-timezone ambiguity in logs read on a different machine).
 */
#ifndef DAEMON_LOG_TS_H
#define DAEMON_LOG_TS_H

#include <stdarg.h>
#include <time.h>

static void log_ts_prefix(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tmv;
    gmtime_r(&ts.tv_sec, &tmv);
    fprintf(stderr, "%04d-%02d-%02d %02d:%02d:%02d.%03ld ",
            tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
            tmv.tm_hour, tmv.tm_min, tmv.tm_sec, ts.tv_nsec / 1000000);
}

static int log_fprintf(FILE* stream, const char* fmt, ...) {
    log_ts_prefix();
    va_list ap;
    va_start(ap, fmt);
    int r = vfprintf(stream, fmt, ap);
    va_end(ap);
    return r;
}

#define fprintf log_fprintf

#endif /* DAEMON_LOG_TS_H */
