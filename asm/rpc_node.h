/* rpc_node.h -- live-node-state JSON-RPC methods (peers, network, mempool)
 * served from INSIDE the serve daemon, which owns the live state the standalone
 * bitcoin_rpcd cannot see. See docs/RPC_LIVE_NODE.md for the fork-model design.
 *
 * The serve parent publishes a small POD status region into shared memory
 * (MAP_SHARED, allocated before the download-worker fork) that the children
 * populate and this module reads. rpc_node_set_status() hands the RPC layer a
 * pointer to it, mirroring rpc_commands_set_utxo_store()'s setter idiom. */
#ifndef RPC_NODE_H
#define RPC_NODE_H

#include "rpc_json.h"

/* Shared live-node status. POD, fixed size, lives in a MAP_SHARED region so
 * the forked download worker / inbound children can publish into it and the
 * parent's RPC thread can read it. All fields are single-word so aligned
 * reads/writes are atomic enough for a status snapshot (no torn counters). */
typedef struct {
    volatile int       n_out;        /* live outbound peers  (download worker) */
    volatile int       n_inbound;    /* live inbound peers   (serve parent)    */
    volatile long long tip_height;   /* current chain tip    (download worker) */
    volatile long long start_time;   /* node start, unix secs (parent, once)   */
} node_status_t;

/* Hand the RPC layer the shared status region (call before rpc_server_start).
 * NULL is valid -- methods that need it then report an empty/loading node. */
void rpc_node_set_status(const node_status_t* st);

/* 1 if `method` is a live-node method this module serves. */
int rpc_node_known_method(const char* method);

/* Dispatch a live-node method. Returns 1 (result set), 0 (error: ec and em
 * set), or -1 (not ours -- caller keeps looking). */
int rpc_node_dispatch(const char* method, const rj_val* params,
                      rj_val** result, long* ec, const char** em);

#endif
