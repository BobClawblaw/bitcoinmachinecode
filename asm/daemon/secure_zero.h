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
 * This does NOT address swap or hibernation -- that needs mlock and
 * MADV_DONTDUMP, which are not done here and remain open under WAL-3.
 * It closes the narrower and much more common case: a secret still sitting in
 * a process's own memory long after the code believed it had erased it.
 *
 * header-only: it must inline into every caller, and a link-time function
 * would be one more thing for a caller to forget to link.
 */
#ifndef SECURE_ZERO_H
#define SECURE_ZERO_H

#include <string.h>
#include <stddef.h>

static inline void secure_zero(void* p, size_t n){
    if (!p || !n) return;
    memset(p, 0, n);
    __asm__ __volatile__("" : : "r"(p) : "memory");
}

#endif
