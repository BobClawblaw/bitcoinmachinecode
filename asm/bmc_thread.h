/* bmc_thread.h -- one place to create daemon threads with a sane stack.
 *
 * Why this exists (2026-08-22, incident #13): the download worker segfaulted
 * on block 481827 with the fault address == rsp inside ld.so -- a thread
 * stack overflow. Two facts combined:
 *   1. glibc allocates a thread's STATIC TLS inside the thread's stack
 *      mapping, and this binary carries ~12 MB of static TLS (per-thread
 *      script stacks, sighash scratch, the LSM bloom scratch, ...).
 *   2. Under RLIMIT_STACK=unlimited (systemd LimitSTACK=infinity) glibc's
 *      default pthread stack is 2 MB (ARCH_STACK_DEFAULT_SIZE), and when the
 *      static TLS exceeds the default glibc sizes the mapping to
 *      TLS + MINIMAL_REST_STACK -- measured: a 12.0 MB mapping whose thread
 *      starts with rsp at the very bottom. Every verify-pool thread had been
 *      running on a few KB of real stack; the witness-v0 path was merely the
 *      first frame chain deep enough to fall off.
 * Fix: always request an explicit stack. 64 MB is virtual until touched, so
 * 64 workers cost nothing extra in practice; measured usable ~52 MB above
 * the TLS block. BMC_THREAD_STACK_MB overrides (0 = library default attrs,
 * used by the regression test to reproduce the overflow).
 */
#ifndef BMC_THREAD_H
#define BMC_THREAD_H
#include <pthread.h>
#include <stdlib.h>
#define BMC_THREAD_STACK_MB_DEFAULT 64
static inline int bmc_pthread_create(pthread_t* t, void* (*fn)(void*), void* arg){
    pthread_attr_t at; pthread_attr_init(&at);
    long mb = BMC_THREAD_STACK_MB_DEFAULT;
    const char* e = getenv("BMC_THREAD_STACK_MB");
    if (e && *e) mb = atol(e);
    if (mb > 0) pthread_attr_setstacksize(&at, (size_t)mb << 20);
    int r = pthread_create(t, &at, fn, arg);
    pthread_attr_destroy(&at);
    return r;
}
/* Per-thread scratch that used to be `static __thread u8 buf[N]` (static
 * TLS, i.e. carved out of every thread's stack mapping). Lazily heap-
 * allocated once per thread instead; process-lifetime, never freed. A
 * failed 1 MB malloc is fatal in any case. */
#define BMC_TLS_BUF(ptr, size) do { if (!(ptr)) { (ptr) = malloc(size); if (!(ptr)) { abort(); } } } while (0)
#endif
