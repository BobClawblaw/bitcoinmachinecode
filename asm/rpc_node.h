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

/* One outbound peer, published by the download worker at connect/handshake.
 * Byte/last-send counters Core tracks per-socket are not tracked here (the
 * worker has no per-fd meters); getpeerinfo reports them as 0/-1. */
#define RPC_MAX_PEERS 64
typedef struct {
    volatile int              used;         /* 1 = slot live */
    volatile int              inbound;      /* 0 outbound (all we itemize today) */
    char                      addr[80];     /* "ip:port" */
    volatile unsigned         proto;        /* negotiated protocol version */
    volatile unsigned long long services;   /* peer's advertised services */
    char                      subver[96];   /* peer user-agent */
    volatile int              start_height; /* peer's startingheight */
    volatile long long        conn_time;    /* unix secs at connect */
    volatile long long        bytes_sent;   /* kernel TCP_INFO, per-socket */
    volatile long long        bytes_recv;
    volatile long long        last_send;    /* unix secs of last data sent */
    volatile long long        last_recv;    /* unix secs of last data recv */
} rpc_peer_t;

/* Shared live-node status. POD, fixed size, lives in a MAP_SHARED region so
 * the forked download worker / inbound children can publish into it and the
 * parent's RPC thread can read it. Single-word status fields are atomic enough
 * for a snapshot; the peer table is written slot-at-a-time by the one worker. */
typedef struct {
    volatile int       n_out;        /* live outbound peers  (download worker) */
    volatile int       n_inbound;    /* live inbound peers   (serve parent)    */
    volatile long long tip_height;   /* current chain tip    (download worker) */
    volatile long long start_time;   /* node start, unix secs (parent, once)   */
    rpc_peer_t         peers[RPC_MAX_PEERS];  /* outbound peer table (worker)   */
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
