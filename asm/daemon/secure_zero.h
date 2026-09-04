/* daemon/secure_zero.h -- WAL-3 (audit 2026-09-03): a memset the optimiser
 * may not delete.
 *
 * Every wipe in this tree was a plain memset on a buffer that is dead
 * afterwards -- wallet_store.c, wallet_enc_state.c, rpc_wallet_ops.c,
 * wallet_crypter.c. The C standard permits an implementation to elide a store
 * to an object whose value is never read again, and -O2 does exactly that, so
 * a fair number of "we cleared the key" comments described something that did
 * not happen. A grep for explicit_bzero, memset_s or volatile found nothing.
 *
 * The barrier is the point: `asm volatile("" ::: "memory")` tells the
 * compiler that unseen code may observe every byte of memory at that point,
 * so the preceding stores are live and cannot be dropped. This is the same
 * mechanism as Core's memory_cleanse.
 *
 * secure_lock below is the other half: mlock keeps a secret out of swap and
 * off a hibernation image, and MADV_DONTDUMP keeps it out of a core file.
 * Together they cover the three ways a "cleared" secret was still readable.
 *
 * header-only: it must inline into every caller, and a link-time function
 * would be one more thing for a caller to forget to link.
 */
#ifndef SECURE_ZERO_H
#define SECURE_ZERO_H

#include <string.h>
#include <stddef.h>
#include <sys/mman.h>

static inline void secure_zero(void* p, size_t n){
    if (!p || !n) return;
    memset(p, 0, n);
    __asm__ __volatile__("" : : "r"(p) : "memory");
}

/* WAL-3 (rest): keep a secret out of swap, off a hibernation image, and out
 * of a core file.
 *
 * secure_zero closes the in-process case; this closes the three that outlive
 * the process. An attacker with a swap partition or a hibernation image
 * recovers the whole wallet from a node whose operator believes it is locked,
 * and no amount of zeroing on shutdown helps once the page has been paged
 * out. The 2026-09-02 host hardening (LimitCORE=0) removed the core-dump
 * route only, and only for that unit -- MADV_DONTDUMP makes it a property of
 * the memory rather than of the service file.
 *
 * BEST EFFORT, and deliberately so: mlock is bounded by RLIMIT_MEMLOCK, which
 * an operator may have set low, and MADV_DONTDUMP does not exist on every
 * kernel. A wallet that refuses to start because it could not lock a page is
 * worse than one that starts and says so, and the caller logs the failure
 * once rather than silently continuing. Returns 1 if the memory was locked.
 *
 * Both operate on whole pages, so the lock covers whatever else shares the
 * page. That is harmless here -- the neighbours are other wallet statics --
 * and it is the reason the amount locked is a few KB rather than a few
 * hundred bytes. */
static inline int secure_lock(void* p, size_t n){
    if (!p || !n) return 0;
    int locked = (mlock(p, n) == 0);
#ifdef MADV_DONTDUMP
    (void)madvise(p, n, MADV_DONTDUMP);   /* independent of the lock succeeding */
#endif
    return locked;
}

#endif
