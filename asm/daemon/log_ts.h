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
#include <sys/prctl.h>

/* -logtimestamps / -logtimemicros / -logthreadnames / -logsourcelocations
 * (2026-09-01): one weak definition per flag so every translation unit that
 * includes this header shares it; daemon/main.c sets them from the config. */
int g_log_timestamps      __attribute__((weak)) = 1;
int g_log_timemicros      __attribute__((weak)) = 0;
int g_log_threadnames     __attribute__((weak)) = 0;
int g_log_sourcelocations __attribute__((weak)) = 0;

/* One line = one write. The old version wrote the timestamp prefix and the
 * message as TWO separate stdio operations; with the verify-pool threads and
 * the parent + forked download worker all logging into the one append file
 * (systemd StandardOutput=append:), those interleaved -- producing lines with
 * a DOUBLED timestamp (another logger's prefix landed between ours) or with
 * NONE (our prefix attached to the previous line). Format prefix+message into
 * a single buffer and emit it with one fwrite; stderr is unbuffered and the
 * fd is O_APPEND, so a single write is atomic across threads and processes. */
static int log_vfprintf_at(const char* file, int line, FILE* stream, const char* fmt, va_list ap) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tmv;
    gmtime_r(&ts.tv_sec, &tmv);
    char buf[8192];
    int p = 0;
    if (g_log_timestamps){
        if (g_log_timemicros)
            p = snprintf(buf, sizeof buf, "%04d-%02d-%02d %02d:%02d:%02d.%06ld ",
                         tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
                         tmv.tm_hour, tmv.tm_min, tmv.tm_sec, ts.tv_nsec / 1000);
        else
            p = snprintf(buf, sizeof buf, "%04d-%02d-%02d %02d:%02d:%02d.%03ld ",
                         tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
                         tmv.tm_hour, tmv.tm_min, tmv.tm_sec, ts.tv_nsec / 1000000);
    }
    if (p < 0) p = 0; if (p > (int)sizeof buf) p = (int)sizeof buf;
    if (g_log_threadnames && p < (int)sizeof buf - 24){
        char tn[17] = {0};
        if (prctl(PR_GET_NAME, tn, 0, 0, 0) != 0) tn[0] = 0;   /* the calling thread's comm */
        int q = snprintf(buf + p, sizeof buf - p, "[%s] ", tn[0] ? tn : "-");
        if (q > 0) p += q; if (p > (int)sizeof buf) p = (int)sizeof buf;
    }
    if (g_log_sourcelocations && file && p < (int)sizeof buf - 8){
        const char* base = file; for (const char* c = file; *c; c++) if (*c == '/') base = c + 1;
        int q = snprintf(buf + p, sizeof buf - p, "[%s:%d] ", base, line);
        if (q > 0) p += q; if (p > (int)sizeof buf) p = (int)sizeof buf;
    }
    int m = vsnprintf(buf + p, sizeof buf - p, fmt, ap);
    int total = p + (m > 0 ? m : 0);
    if (total > (int)sizeof buf) total = (int)sizeof buf;   /* rare over-long line: truncate, still atomic+timestamped */
    fwrite(buf, 1, (size_t)total, stream);
    return m;
}

static int log_fprintf_at(const char* file, int line, FILE* stream, const char* fmt, ...) {
    va_list ap; va_start(ap, fmt);
    int m = log_vfprintf_at(file, line, stream, fmt, ap);
    va_end(ap); return m;
}
/* direct callers (a few files log through the function by name) */
static int log_fprintf(FILE* stream, const char* fmt, ...) {
    va_list ap; va_start(ap, fmt);
    int m = log_vfprintf_at(NULL, 0, stream, fmt, ap);
    va_end(ap); return m;
}

#define fprintf(stream, ...) log_fprintf_at(__FILE__, __LINE__, stream, __VA_ARGS__)

#endif /* DAEMON_LOG_TS_H */
