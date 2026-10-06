/* daemon/crash_trace.h -- a fatal signal writes the crashing thread's stack
 * (text-segment addresses only) to the log, then dies of the same signal.
 * See crash_trace.c. */
#ifndef CRASH_TRACE_H
#define CRASH_TRACE_H
int  crash_trace_install(void);      /* once, early in main(); 1 = all handlers installed */
void crash_trace_set_fd(int fd);     /* test seam: where the report goes (default 2) */
#endif
