/* sys/prctl.h -- Darwin stand-in for the osx port (bmc_osx).
 *
 * The daemon touches prctl in exactly two places (bmc_osx Darwin compat,
 * per port/OSX_STRATEGY.md's plan-of-record):
 *
 *   daemon/log_ts.h          prctl(PR_GET_NAME, tn)  -> thread name for logs
 *   daemon/coinstats_index.c prctl(PR_SET_PDEATHSIG, SIGTERM) after fork
 *
 * macOS has neither prctl nor PDEATHSIG.  Mappings:
 *   PR_GET_NAME     -> pthread_getname_np(pthread_self(), buf, 16).  The name
 *                      was set with pthread_setname_np; the daemon's threads
 *                      name themselves, so the log prefix keeps working.
 *   PR_SET_PDEATHSIG-> no-op.  The coinstats builder already re-checks
 *                      getppid() != parent after the fork and stops the
 *                      worker when the parent died, so the orphan-supervision
 *                      property is preserved without the signal.
 * Any other option: -1/EINVAL, so a future prctl use fails loudly instead of
 * silently doing nothing.
 */
#ifndef BMC_DARWIN_SYS_PRCTL_H
#define BMC_DARWIN_SYS_PRCTL_H

#include <pthread.h>
#include <stdarg.h>
#include <errno.h>

#define PR_SET_PDEATHSIG 1
#define PR_GET_NAME     16

static inline int prctl(int option, ...)
{
    switch (option) {
    case PR_GET_NAME: {
        va_list ap;
        va_start(ap, option);
        char* buf = va_arg(ap, char*);
        va_end(ap);
        if (!buf) { errno = EFAULT; return -1; }
        if (pthread_getname_np(pthread_self(), buf, 16) != 0) buf[0] = 0;
        return 0;
    }
    case PR_SET_PDEATHSIG:
        return 0;                        /* see block comment */
    default:
        errno = EINVAL;
        return -1;
    }
}

/* ---- robust process-shared mutexes (mempool_cfg.c, MEM-20) --------------
 * macOS declares neither PTHREAD_MUTEX_ROBUST nor the setrobust/consistent
 * calls.  The mempool code is explicitly best-effort ("a platform without
 * robust process-shared mutexes keeps exactly today's behaviour"): these
 * declarations route setrobust to the ENOTSUP stub in darwin_stubs.c so
 * g_mp_robust stays 0 and the code's own documented fallback is taken.
 * EOWNERDEAD is defined to a value no macOS errno can take so mp_lock's
 * recovery branch never fires. */
#ifndef PTHREAD_MUTEX_ROBUST
#define PTHREAD_MUTEX_ROBUST 1
#endif
#ifndef EOWNERDEAD
#define EOWNERDEAD 0x0F00
#endif
int pthread_mutexattr_setrobust(pthread_mutexattr_t* attr, int robust);
int pthread_mutex_consistent(pthread_mutex_t* m);

/* ---- TCP_INFO (daemon/main.c getpeerinfo counters) ----------------------
 * macOS defines TCP_INFO in netinet/tcp.h with a DIFFERENT struct layout
 * (tcp_connection_info); letting the Linux-shaped read "succeed" would pour
 * garbage into getpeerinfo.  Redefine it to an unassigned option number so
 * the getsockopt fails at runtime and the guarded block skips -- the same
 * degraded-but-clean behaviour as a kernel without the byte counters.
 * This header arrives via daemon/log_ts.h AFTER netinet/tcp.h in every
 * consumer, so the redefinition wins. */
#ifdef TCP_INFO
#undef TCP_INFO
#endif
#define TCP_INFO 0x2CAB   /* unassigned; getsockopt fails, fields stay 0 */

#endif
