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
/* Max raw-tx bytes a sendrawtransaction submission can stage. A standard tx is
 * capped at 100k vbytes; 400000 covers the consensus weight bound with room. */
#define RPC_TXSUBMIT_MAX 400000
/* Max serialized block a submitblock can stage: the 4M-weight consensus
 * bound (a block is at most 4MB serialized), with margin. */
#define RPC_BLKSUBMIT_MAX 4100000

/* Peer-control operations carried by the ctl_* channel. */
#define RPC_CTL_ADDNODE        1   /* ctl_arg = host[:port], ctl_num = 0 add / 1 remove / 2 onetry */
#define RPC_CTL_DISCONNECT     2   /* ctl_arg = address, or ctl_num = nodeid when arg is empty */
#define RPC_CTL_SETBAN         3   /* ctl_arg = subnet, ctl_num = absolute unban time (0 = remove) */
#define RPC_CTL_CLEARBANNED    4
#define RPC_CTL_SETNETACTIVE   5   /* ctl_num = 0/1 */
#define RPC_CTL_PING           6
#define RPC_MAX_BANS           64

typedef struct {
    volatile int       n_out;        /* live outbound peers  (download worker) */
    volatile int       n_inbound;    /* live inbound peers   (serve parent)    */
    volatile long long tip_height;   /* current chain tip    (download worker) */
    volatile long long start_time;   /* node start, unix secs (parent, once)   */
    rpc_peer_t         peers[RPC_MAX_PEERS];  /* outbound peer table (worker)   */

    /* sendrawtransaction submission channel (parent RPC thread -> download
     * worker). The parent stages one tx at a time under g_submit_lock: fill
     * tx_submit_buf/len, then bump tx_submit_seq (published last). The worker
     * polls tx_submit_seq at the top of its loop, runs mempool-accept + relays
     * the tx to its peer legs, writes tx_submit_result/reason, then sets
     * tx_submit_ack = tx_submit_seq. result: 1 accepted, 0 rejected (reason
     * set), negative = a Core RPC error code (reason set). */
    volatile unsigned long long tx_submit_seq;   /* parent bumps after filling  */
    volatile unsigned long long tx_submit_ack;   /* worker bumps after handling */
    volatile unsigned long      tx_submit_len;
    volatile int                tx_submit_result;
    /* 1 = testmempoolaccept: the worker runs the SAME validation and policy
     * checks but stops at the mempool commit boundary, so the pool is not
     * mutated and the tx is not relayed. Set by the parent before the seq
     * bump, alongside tx_submit_len. */
    volatile int                tx_submit_test;
    volatile unsigned long long tx_submit_fee;    /* satoshis, dry run only */
    char                        tx_submit_reason[128];
    unsigned char               tx_submit_buf[RPC_TXSUBMIT_MAX];

    /* ==== peer-control channel (parent RPC thread -> download worker) ====
     * The worker owns the peer legs; the parent owns the RPC surface. Before
     * this channel existed, seven RPCs had to refuse outright -- a node you
     * cannot tell to ban a peer is not one you can operate. Same seq/ack
     * discipline as the two channels above: the parent fills ctl_op/ctl_arg/
     * ctl_num under g_submit_lock, bumps ctl_seq last, and waits for
     * ctl_ack; the worker polls ctl_seq at the top of its loop.
     *
     * ctl_result: 1 = done, 0 = "no such peer"/no-op (not an error), and a
     * negative value is an RPC error code with ctl_reason set. */
    volatile unsigned long long ctl_seq;
    volatile unsigned long long ctl_ack;
    volatile int                ctl_op;
    volatile int                ctl_result;
    volatile long long          ctl_num;      /* bantime / nodeid / bool */
    char                        ctl_arg[128]; /* address, subnet, or host:port */
    char                        ctl_reason[128];

    /* Runtime network toggle (setnetworkactive). The worker checks this
     * before dialing; the parent reads it for getnetworkinfo's
     * "networkactive". Not in the control channel proper because it is
     * READ on every dial attempt, not just when it changes. */
    volatile int                net_active;

    /* ==== ban list ====
     * Lives in shared memory rather than behind the channel because BOTH
     * sides need it: the parent serves listbanned straight out of it, and
     * the worker checks it before every dial and on every inbound accept.
     * A ban that only one side could see would be a ban that does not ban. */
    volatile int                n_bans;
    struct {
        char     subnet[64];       /* "1.2.3.4" or "1.2.3.0/24" */
        long long until;           /* unix seconds; 0 = not in use */
        long long created;
    } bans[RPC_MAX_BANS];

    /* submitblock channel (parent RPC thread -> download worker), same
     * seq/ack discipline as the tx channel above. result: 1 = accepted
     * (RPC returns null), 0 = BIP22 reason string in blk_submit_reason. */
    volatile unsigned long long blk_submit_seq;
    volatile unsigned long long blk_submit_ack;
    volatile unsigned long      blk_submit_len;
    volatile int                blk_submit_result;
    char                        blk_submit_reason[64];
    unsigned char               blk_submit_buf[RPC_BLKSUBMIT_MAX];
} node_status_t;

/* Hand the RPC layer the shared status region (call before rpc_server_start).
 * NULL is valid -- methods that need it then report an empty/loading node.
 * The const setter keeps status reads read-only; the writable variant is for
 * sendrawtransaction, which stages into the submission channel above. */
void rpc_node_set_status(const node_status_t* st);
void rpc_node_set_status_rw(node_status_t* st);

/* Hand the RPC layer the SHARED mempool (daemon/mempool_cfg.c's MAP_SHARED
 * pre-fork region) so getrawmempool/getmempoolinfo/getmempoolentry report the
 * real pool instead of this process's empty copy. EVERYTHING is injected as
 * data/function pointers -- rpc_node.o declares no mempool externs, so it
 * never drags bitcoin_mempool.o / mempool_cfg.c / the policy TU into the many
 * test binaries that link it (an extern mpool_count did exactly that once).
 * Every member is optional: NULL members degrade the affected fields to
 * absent/zero bookkeeping; a NULL/all-NULL struct keeps the previous
 * empty-pool reporting (standalone rpcd, static per-process fallback). */
struct mp_entry_info;   /* mempool_entry.h; only implementations need it */
typedef struct {
    void*     mp;             /* structural pool (bitcoin_mempool.asm layout) */
    void*     polstate;       /* tx-accept policy registry (fees, graph) */
    long long maxbytes;       /* configured -maxmempool, bytes */
    long (*count)(void*);                                       /* mpool_count */
    const unsigned char* (*get)(void*, const unsigned char*, unsigned long*); /* mpool_get */
    void (*lock)(void);                                         /* mp_lock */
    void (*unlock)(void);                                       /* mp_unlock */
    long (*time_of)(const unsigned char*);                      /* arrival time */
    long (*pol_entry)(void*, const unsigned char*,
                      unsigned long long*, unsigned long long*);/* fee/size */
    long (*pol_entry_info)(void*, const unsigned char*,
                           struct mp_entry_info*);              /* full graph */
    long (*estimate)(void*, unsigned long long*,
                     unsigned long long*);                      /* fee EMA+samples */
    void (*sha256d)(unsigned char*, const void*, unsigned long);/* for wtxid */
} rpc_mempool_hooks;
void rpc_node_set_mempool(const rpc_mempool_hooks* h);

/* Hand the RPC layer the persistent address book (bitcoin_addrmgr.asm), so
 * getnodeaddresses/getaddrmaninfo report real recorded peers. Injected as
 * pointers for the same no-link-fanout reason as the mempool hooks. */
void rpc_node_set_addrbook(void* ab, long (*count)(void*),
                           int (*get_i)(void*, long, unsigned char*));

/* Hand the RPC layer the operator's addnode= list (node_config's
 * g_cfg.addnode / n_addnode), so getaddednodeinfo reports the real
 * configured nodes and whether each is currently connected. */
/* BORROWED, not copied: the list must outlive the RPC server. The only
 * caller passes node_config's g_cfg.addnode, a long-lived global. Pass
 * (NULL, 0) to detach. */
void rpc_node_set_addednodes(const char (*list)[64], int n);

/* 1 if `method` is a live-node method this module serves. */
int rpc_node_known_method(const char* method);

/* Enumerate the methods this module serves; NULL past the end. `help`
 * builds its list from these tables, so it cannot drift from what the
 * dispatchers actually answer. */
const char* rpc_node_method_at(int i);

/* Dispatch a live-node method. Returns 1 (result set), 0 (error: ec and em
 * set), or -1 (not ours -- caller keeps looking). */
int rpc_node_dispatch(const char* method, const rj_val* params,
                      rj_val** result, long* ec, const char** em);

#endif
