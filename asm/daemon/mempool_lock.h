/* daemon/mempool_lock.h -- the cross-process mempool lock (daemon/mempool_cfg.c)
 * and, since 2026-09-30, its wait/hold log.
 *
 * WHY THE LOG. The RPC execution-lock log (rpc_server.c, 2026-09-29) named its
 * multi-second holders -- getrawmempool 3,467 ms, getmempoolinfo 2,885 ms, the
 * facade's getrawtransaction 2,045 ms at a 78k pool -- and none of them was
 * the handler's own work (measured: 10-640 ms). Each of them consults the
 * mempool under THIS lock, and what they were doing for the rest of the time
 * was waiting for it, held for seconds by the download worker in another
 * process. The 90-second stalls of the whole surface, each within two seconds
 * of a new block, have the same shape one size up: at a block the worker
 * removes thousands of transactions from the pool under this lock. Nothing
 * timed it, so nothing could say which site held it, or for how long.
 *
 * WHAT IS LOGGED. Every take and release is timed on the monotonic clock. A
 * WAIT or a HOLD of BMC_MEMPOOL_LOCK_LOG_MS or longer (default 1000 ms; 0
 * switches it off) is one line each, written by the process that waited or
 * held, after the release, never under the lock:
 *
 *   [mempool] pool lock: getrawmempool (pid 12602) waited 3467 ms; the holder was tx_accept_block_connect_h/remove_marked (pid 12606, held 3450 ms); 0 other take(s) went by during the wait, the longest of them held 3450 ms (tx_accept_block_connect_h/remove_marked); 2 still waiting
 *   [mempool] pool lock: getrawtransaction (pid 12602) waited 1193 ms; the holder was tx_accept_validate (pid 12631, held 3 ms); 101 other take(s) went by during the wait, the longest of them held 5 ms (tx_accept_validate); 0 still waiting
 *   [mempool] pool lock: tx_accept_block_connect_h (pid 12606) held 3450 ms (waited 0 ms): fest_begin 0 ms, mark 118 ms, remove_marked 3330 ms, note 2 ms; 2 waiting behind it
 *
 * The SITE is the name the caller passes to mp_lock_at (its function, or the
 * RPC method when the RPC layer takes the lock through the hooks and passes
 * nothing -- rpc_server.c's thread-local label is used). A site that holds
 * the lock across several steps names them with mp_lock_phase; the hold
 * line then carries the time each step took, and a waiter's line names the
 * step the holder was in when it released. The holder's site and pid live
 * in the same shared page as the lock, so a waiter in one process can name
 * a holder in another. A wait can also be a CONVOY -- many short holds, none
 * over the threshold, as x86's first production lines were -- and the last
 * release cannot tell the two apart: so every take is counted, each release
 * made while anyone waits keeps the convoy's longest hold, and a waiter's
 * line says how many takes went by and names the longest (the second line
 * above: 101 takes of a few ms each, and the surface still waited 1.2 s).
 *
 * The site and phase strings must outlive the hold: pass literals or
 * __func__, not stack buffers. */
#ifndef BMC_MEMPOOL_LOCK_H
#define BMC_MEMPOOL_LOCK_H
#include <stddef.h>

void mp_lock_at(const char* site);        /* take; NULL site = the RPC label, or "(unnamed)" */
void mp_lock(void);                       /* mp_lock_at(NULL): the hooks' function pointer */
void mp_unlock(void);
/* Name the step the holder is in (holder only; a no-op when this thread does
 * not hold the lock or there is no shared pool). At most 16 steps are timed
 * per hold; later ones are folded into the last. */
void mp_lock_phase(const char* phase);

/* Test hooks: the threshold, how many lines this process wrote, the last four. */
void mp_lock_set_log_ms(long ms);
long mp_lock_log_ms(void);
long mp_lock_slow_events(void);
void mp_lock_slow_log(char* out, size_t cap);

#endif
