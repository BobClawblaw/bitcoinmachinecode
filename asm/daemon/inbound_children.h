/* daemon/inbound_children.h -- the serve parent's count of live inbound
 * serve children, kept by pid. Header-only (static), included by
 * daemon/main.c and by tests/test_inbound_children.c, so the test runs the
 * daemon's own code without linking main.c.
 *
 * The reaper used to decrement this for EVERY child that was not the
 * download worker -- a notify hook's intermediate, an RPC-thread helper --
 * so the count drifted low and the inbound cap admitted extra peers; and
 * `g_inbound_n++` in the mux loop raced the decrement in a handler that may
 * run on any thread, so an update could be lost either way.
 *
 * Now the count is the number of PIDS in g_inb_pid, and only a reaped pid
 * found there decrements it. Every update is an atomic RMW/CAS, and a slot
 * is cleared by exactly one compare-and-swap, so the handler (any thread)
 * and the mux loop can never both count one child. A child can exit before
 * the mux loop records its pid; the handler then cannot find it, so it also
 * notes the pid in a small ring of "reaped, not yet registered" pids, and
 * inb_register consults that ring after publishing the slot. With
 * sequentially consistent accesses on both sides (store-then-scan), at
 * least one side sees the other, and the CAS decides which one counts the
 * exit. The table never needs more than the inbound limit (Core's
 * -maxconnections is clamped to 4096 by node_config). A ring entry left by
 * a non-inbound child is harmless unless the kernel hands the same pid to
 * an inbound child within the next INB_RING reaps; that would leave the one
 * child uncounted while it lives (never a lasting drift). */
#ifndef INBOUND_CHILDREN_H
#define INBOUND_CHILDREN_H
#include <sys/types.h>

#define INB_SLOTS 4096
#define INB_RING  64
static int   g_inbound_n = 0;            /* __atomic only */
static pid_t g_inb_pid[INB_SLOTS];       /* 0 = free */
static pid_t g_inb_ring[INB_RING];
static unsigned g_inb_ring_head;
static int inb_count(void){ return __atomic_load_n(&g_inbound_n, __ATOMIC_SEQ_CST); }
/* async-signal-safe: atomics only */
static void inb_reaped(pid_t p){
    unsigned k = __atomic_fetch_add(&g_inb_ring_head, 1, __ATOMIC_SEQ_CST) % INB_RING;
    __atomic_store_n(&g_inb_ring[k], p, __ATOMIC_SEQ_CST);
    for(int i = 0; i < INB_SLOTS; i++){
        pid_t e = p;
        if(__atomic_load_n(&g_inb_pid[i], __ATOMIC_SEQ_CST) == p &&
           __atomic_compare_exchange_n(&g_inb_pid[i], &e, 0, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)){
            __atomic_fetch_sub(&g_inbound_n, 1, __ATOMIC_SEQ_CST);
            pid_t r = p;
            __atomic_compare_exchange_n(&g_inb_ring[k], &r, 0, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
            return;
        }
    }
}
/* the mux loop, right after fork() returned a child pid */
static void inb_register(pid_t p){
    int slot = -1;
    for(int i = 0; i < INB_SLOTS && slot < 0; i++){
        pid_t e = 0;
        if(__atomic_compare_exchange_n(&g_inb_pid[i], &e, p, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) slot = i;
    }
    __atomic_fetch_add(&g_inbound_n, 1, __ATOMIC_SEQ_CST);
    if(slot < 0) return;                 /* unreachable under the inbound limit; counted, never freed */
    for(int k = 0; k < INB_RING; k++){
        pid_t r = p;
        if(__atomic_load_n(&g_inb_ring[k], __ATOMIC_SEQ_CST) == p &&
           __atomic_compare_exchange_n(&g_inb_ring[k], &r, 0, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)){
            pid_t e = p;           /* it exited before we got here: whoever clears the slot counts it */
            if(__atomic_compare_exchange_n(&g_inb_pid[slot], &e, 0, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
                __atomic_fetch_sub(&g_inbound_n, 1, __ATOMIC_SEQ_CST);
            return;
        }
    }
}

#endif
