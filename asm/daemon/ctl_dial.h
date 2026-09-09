/* daemon/ctl_dial.h -- the runtime manual-connection queue behind `addnode`.
 *
 * Core's `addnode <host> add` keeps a manual connection to the host, retried
 * for as long as it is listed; `onetry` dials it once. This node stored the
 * runtime list and never dialed it (2026-09-08: both answered "done" and
 * nothing happened). The queue is pure bookkeeping -- who to dial next and
 * when -- so the worker's dial pass stays a few lines and the rule is
 * testable without sockets. */
#ifndef BMC_CTL_DIAL_H
#define BMC_CTL_DIAL_H
#define CTL_DIAL_MAX      32
#define CTL_DIAL_RETRY_S  60        /* a persistent entry: first retry after a failed or dropped dial */
#define CTL_DIAL_RETRY_MAX_S 600    /* ... doubling up to this */
int  ctl_dial_add(const char* host, int persistent, long long now);   /* 1 queued, 0 duplicate, -1 full */
int  ctl_dial_remove(const char* host);                               /* 1 removed, 0 not listed */
int  ctl_dial_count(void);
/* the next host due for a dial at `now`, or 0. A onetry entry is consumed
 * here; a persistent one waits for ctl_dial_report. */
const char* ctl_dial_next(long long now, int (*connected)(const char* host));
/* the outcome of a dial for a persistent entry: connected resets the backoff,
 * a failure or a later drop (report ok=0) schedules the next try */
void ctl_dial_report(const char* host, int ok, long long now);
int  ctl_dial_listed(const char* host);                               /* is a PERSISTENT entry (for re-dial on drop) */
void ctl_dial_reset(void);                                            /* tests */
#endif
