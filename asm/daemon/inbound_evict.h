/* daemon/inbound_evict.h -- CC-3 (2026-09-06): Core's SelectNodeToEvict /
 * AttemptToEvictConnection. When every inbound slot is taken, protect the
 * peers that are demonstrably useful or diverse, then evict the youngest
 * connection from the most-populated network group. Never a NoBan peer.
 * Returns the slot to evict, or -1 when every candidate is protected (then
 * the new connection is refused, as in Core). */
#ifndef INBOUND_EVICT_H
#define INBOUND_EVICT_H
#include "../rpc_node.h"
int inbound_select_victim(const node_status_t* st, long long now, int first_slot, int last_slot);
#endif
