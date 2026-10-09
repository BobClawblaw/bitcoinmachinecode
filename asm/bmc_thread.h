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
 * allocated once per thread instead. A failed malloc is fatal in any case.
 *
 * FREED WHEN THE THREAD EXITS (2026-10-08). These were "process-lifetime,
 * never freed", which holds only for threads that live as long as the
 * process. txv_verify_all (daemon/tx_verify.c) creates fresh threads for every
 * mempool transaction with TXV_PARALLEL_MIN or more inputs, and each one
 * allocated the interpreter's whole scratch set -- ~11 MB of address space:
 * the 4 MB segwit midstate buffer, the 2.3 MB offset table, three 528 KB
 * stacks, 1 MB of work space... -- and exited without freeing it. On the
 * Mac's mainnet worker that was 185k live blocks, 195 GB of address space
 * and ~0.8 GB resident after two hours, growing ~120 MB an hour.
 *
 * Each buffer now goes on a per-thread list whose pthread key destructor
 * frees it at thread exit. The __thread pointer dies with the thread, so
 * nothing can see the freed block. The key, its once-guard and the
 * live count are weak definitions, so every translation unit that includes
 * this header shares one of each without a .c file to add to every link.
 * Threads that never exit (the main thread, the pools) keep theirs, as
 * before. bmc_tls_live counts the buffers held and bmc_tls_made every one
 * ever allocated, for tests.
 *
 * 2026-10-09: bmc_tls_keep hands the list a block the caller already has,
 * with an optional finaliser run on it before it is freed -- the RPC read
 * lane's private archive handle closes its descriptors that way. A buffer
 * that grows (realloc) lives behind a BMC_TLS_GROW holder, whose finaliser
 * frees whatever block the holder points at by then. */
typedef struct bmc_tls_node { struct bmc_tls_node* next; void* buf; void (*fin)(void*); } bmc_tls_node;
__attribute__((weak)) pthread_key_t bmc_tls_key;
__attribute__((weak)) pthread_once_t bmc_tls_once = PTHREAD_ONCE_INIT;
__attribute__((weak)) long bmc_tls_live;
__attribute__((weak)) long bmc_tls_made;
static inline void bmc_tls_dtor(void* head){
    for (bmc_tls_node* n = (bmc_tls_node*)head; n;){
        bmc_tls_node* next = n->next;
        if (n->fin) n->fin(n->buf);
        free(n->buf); free(n);
        __sync_fetch_and_sub(&bmc_tls_live, 1);
        n = next;
    }
}
static inline void bmc_tls_mkkey(void){ if (pthread_key_create(&bmc_tls_key, bmc_tls_dtor) != 0) abort(); }
/* Takes ownership of p (NULL passes through): freed, after fin(p) if fin
 * is set, when this thread exits. Returns p, or NULL with p freed. */
static inline void* bmc_tls_keep(void* p, void (*fin)(void*)){
    if (!p) return NULL;
    bmc_tls_node* n = (bmc_tls_node*)malloc(sizeof *n);
    if (!n){ free(p); return NULL; }
    pthread_once(&bmc_tls_once, bmc_tls_mkkey);
    n->buf = p; n->fin = fin; n->next = (bmc_tls_node*)pthread_getspecific(bmc_tls_key);
    if (pthread_setspecific(bmc_tls_key, n) != 0) abort();
    __sync_fetch_and_add(&bmc_tls_live, 1);
    __sync_fetch_and_add(&bmc_tls_made, 1);
    return p;
}
static inline void* bmc_tls_alloc(size_t size){
    void* p = bmc_tls_keep(malloc(size), NULL);
    if (!p) abort();
    return p;
}
#define BMC_TLS_BUF(ptr, size) do { if (!(ptr)) { (ptr) = bmc_tls_alloc(size); } } while (0)
/* A per-thread buffer that grows: realloc g->buf and update g->cap as before;
 * the holder is on the list and frees g->buf at thread exit. */
typedef struct { void* buf; size_t cap; } bmc_tls_grow;
static inline void bmc_tls_grow_fin(void* g){ free(((bmc_tls_grow*)g)->buf); }
#define BMC_TLS_GROW(g) do { if (!(g)) { (g) = (bmc_tls_grow*)bmc_tls_keep(calloc(1, sizeof(bmc_tls_grow)), bmc_tls_grow_fin); if (!(g)) abort(); } } while (0)
#endif
