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
/* The P2P message names getpeerinfo breaks bytes down by. Core enumerates
 * every command it knows and buckets the rest under "other"; this is the same
 * list for the messages this node actually exchanges, and "other" catches
 * anything else so a total is never silently lost. Keep RPC_MSG_NAMES in step
 * with the enum -- the test asserts they are the same length. */
#define RPC_MSG_N 27
/* Defined once, in rpc_node.c. It was a guarded `static` in this header
   first, which silently produced nothing: another include pulled rpc_node.h
   before the guard macro was set, the include guard then made the second
   include a no-op, and the table never existed. */
extern const char* const RPC_MSG_NAMES[RPC_MSG_N];
/* the bucket for a command name, or RPC_MSG_N-1 ("other") */
int rpc_msg_index(const char* cmd, unsigned cmdlen);
/* the receive side of the per-message counters; the send side is the
   g_p2p_write_hook installed in main.c */
void rpc_note_msg_recv(int fd, const char* cmd, unsigned plen);

#define RPC_MAX_PEERS 128   /* 0..63 outbound legs (the worker), 64..127 inbound children (2026-09-01) */
/* Shared misbehaviour table size; mirrored by MISBEHAVIOR_SLOTS in
 * daemon/main.c, which asserts the two agree at compile time. */
#define RPC_MISBEHAVIOR_SLOTS 64

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
    /* 2026-09-01 relay policy: the peer's fRelay (Core relaytxes), its
     * permissions (getpeerinfo "permissions"), and for an inbound slot the
     * serve child's pid -- a dead pid means the slot is stale. */
    volatile int              relaytxes;
    volatile unsigned         perms;
    volatile int              pid;
    /* RPC-3 (audit 2026-09-03): the id getpeerinfo publishes and
     * disconnectnode keys on. Core's NodeId is unique for the life of the
     * process and never reused; getpeerinfo used to report a COUNTER over
     * live slots while the worker matched the raw outbound leg index, so the
     * two agreed only while every slot below was occupied. Assigned from
     * next_nodeid at slot claim by both the worker (outbound) and each
     * inbound child. */
    volatile long long        nodeid;
    /* CC-3 (2026-09-06): what Core's AttemptToEvictConnection protects by.
     * Appended so every existing offset is unchanged; nothing in asm indexes
     * this table. min_ping_us stays 0 (unmeasured: this node does not ping
     * inbound peers), so the lowest-ping round protects nobody until it is. */
    volatile unsigned         net_group;      /* Core /16 grouping, 0 = unknown */
    volatile long long        last_tx_time;   /* unix secs: last tx WE ACCEPTED from this peer */
    volatile long long        last_block_time;/* unix secs: last novel block from this peer */
    volatile long long        min_ping_us;    /* 0 = unmeasured */
    volatile int              evict_requested;/* set by the accept path; the child exits on its next tick */
    volatile long             inflight_lo, inflight_hi;   /* download worker: the chunk in flight (hi < lo = none) */
    volatile int              dl_worker;      /* download worker index, -1 for a leg or inbound peer */
    volatile long long        bps_recv;       /* download worker: parent-sampled receive rate, bytes/s (0 = unmeasured). 2026-09-10 */
    volatile int              idle_pct;       /* download worker: share of its chunk wall-clock spent blocked in the socket read, 0..100, -1 unmeasured. 2026-09-11 */
    /* ---- getpeerinfo parity, 2026-09-12 -------------------------------
     * Core v31.1 returns 38 fields here and this node returned 19. These
     * carry the facts a peer's own process knows and the RPC cannot reach:
     * getpeerinfo runs in another process, so everything it reports has to
     * come through this shared table. Each is written by the child that owns
     * the connection. An "unknown" value means the RPC OMITS the field rather
     * than publishing a zero a caller cannot tell from a measurement -- the
     * rule min_ping_us already follows. */
    volatile int              v2transport;    /* 1 = BIP324 v2, 0 = v1 */
    volatile unsigned char    session_id[32]; /* BIP324 session id; all-zero = none */
    volatile char             addrbind[72];   /* our own side of the socket, "ip:port" */
    volatile long long        minfeefilter;   /* the peer's feefilter, sat/kvB; -1 unknown */
    volatile int              hb_to, hb_from; /* BIP152 high-bandwidth, -1 unknown */
    volatile long long        addr_processed, addr_rate_limited;  /* addr relay counters */
    volatile int              addr_relay_enabled;                 /* -1 unknown */
    volatile long long        ping_usec;      /* last measured round trip, 0 = unmeasured */
    volatile long long        inv_to_send, last_inv_sequence;     /* announcement queue */
    volatile long             presynced_headers;                  /* -1 unknown */
    /* Per-message byte counters, Core's bytessent_per_msg / bytesrecv_per_msg.
     * Indexed by RPC_MSG_* below; anything not in the table lands in "other",
     * which is what Core does too. Counted WITH the 24-byte header, as Core
     * counts them. */
    volatile long long        sent_per_msg[RPC_MSG_N];
    volatile long long        recv_per_msg[RPC_MSG_N];
} rpc_peer_t;

/* Shared live-node status. POD, fixed size, lives in a MAP_SHARED region so
 * the forked download worker / inbound children can publish into it and the
 * parent's RPC thread can read it. Single-word status fields are atomic enough
 * for a snapshot; the peer table is written slot-at-a-time by the one worker. */
/* Max raw-tx bytes a sendrawtransaction submission can stage. A standard tx is
 * capped at 100k vbytes; 400000 covers the consensus weight bound with room. */
/* Core's MAX_PACKAGE_WEIGHT is 404000, and weight >= serialized size, so a
 * whole package always fits in this buffer; a single transaction is bounded
 * far below it by MAX_STANDARD_TX_WEIGHT. */
#define RPC_TXSUBMIT_MAX 404000
/* RPC-20 (audit 2026-09-03): tx_txid needs a scratch buffer at least as large
 * as the transaction's UNWITNESSED length (bitcoin_tx.asm). Three call sites
 * in rpc_node.c sized it 2000*81+8 = 162,008 bytes while the staging buffer
 * they read from is RPC_TXSUBMIT_MAX = 404,000 -- so a transaction between
 * those two sizes failed tx_txid and was reported as -22 "TX decode failed"
 * instead of reaching the worker and getting its real policy verdict. Only
 * non-standard sizes are affected, and submitpackage already used a 1 MiB
 * scratch (the correct example, sitting in the same file).
 *
 * Tied to the staging cap so the two cannot drift apart again. */
#define RPC_TXID_SCRATCH (RPC_TXSUBMIT_MAX + 8)
#define RPC_PKG_MAX      25          /* Core MAX_PACKAGE_COUNT */
/* Core MAX_REPLACEMENT_CANDIDATES is the per-transaction ceiling; a package
 * of 25 could in principle displace more, but the list is diagnostic and a
 * flat cap keeps the shared block a fixed size. */
#define RPC_PKG_REPLACED_MAX 100
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
#define RPC_CTL_ADDPEERADDRESS 7   /* ctl_arg = "host:port" (any BIP155 network), ctl_num = tried */
#define RPC_CTL_PB_ABORT       8   /* ctl_arg = txid/wtxid hex; ctl_out = "txid wtxid\n" per removed tx; ctl_result = count */
#define RPC_PB_INFO_CAP  262144    /* the private-broadcast snapshot (txid wtxid time len hex npeers peers...) */
#define RPC_MAX_BANS           64

/* ZMQ transaction notification ring (see zmq_ring at the end of the struct).
 * 16 slots looked generous -- the worker drains every rotation -- but a
 * mempool.dat reload streams hundreds of accepts per second while the worker
 * is busy doing the accepting, and production lapped a 16-slot ring by
 * thousands (2026-08-31). 64 slots is ~26MB of the MAP_SHARED block
 * (404KB payload each) and rides out the bursts; overrun past that is
 * counted and reported, which is all a lossy PUB feed owes anyone. */
#define RPC_ZMQ_RING           64
#define RPC_ANN_RING           1024   /* CC-1 announce ring (see ann_ring) */
/* Coinstats fold ring (see csi_ring): a few blocks' worth of coin records --
 * a heavy block creates/spends ~10k coins, so 64k entries is 5-6 blocks of
 * headroom before the connect thread has to wait for the worker. Entries
 * are 192 bytes (12 MB shared); scripts longer than the inline part spill
 * into continuation entries claimed with the same atomic increment. */
#define RPC_CSI_RING           65536
#define RPC_CSI_BODY           176
#define RPC_CSI_HDR            52     /* key36 | value u64 | code u64 */
#define RPC_CSI_INLINE         (RPC_CSI_BODY - RPC_CSI_HDR)   /* 124 script bytes inline */
#define RPC_ZMQ_TXMAX          RPC_TXSUBMIT_MAX

typedef struct {
    volatile int       n_out;        /* live outbound peers  (download worker) */
    volatile int       n_inbound;    /* live inbound peers   (serve parent)    */
    volatile long long tip_height;   /* current PUBLIC tip = the connected tip (download worker; 3.1) */
    volatile long long start_time;   /* node start, unix secs (parent, once)   */
    rpc_peer_t         peers[RPC_MAX_PEERS];  /* outbound peer table (worker)   */
    /* RPC-3: monotonic source for rpc_peer_t.nodeid. Bumped with an atomic
     * fetch-and-add because inbound children and the worker claim slots
     * concurrently in separate processes sharing this mapping. Starts at 0
     * so the first peer is id 0, as Core's does. */
    volatile long long next_nodeid;

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

    /* ==== package submission (submitpackage) =============================
     * Rides the SAME seq/ack channel: tx_submit_buf carries the package's
     * transactions CONCATENATED (each is self-delimiting, so the worker
     * walks them with tx_parse and no length table is needed) and
     * tx_submit_pkg_n says how many. 0 means an ordinary single
     * transaction and every existing caller keeps its behaviour untouched.
     *
     * Results are per-transaction because Core's submitpackage reports them
     * that way: a package can be partly accepted, and saying only "failed"
     * would hide which member was the problem. pkg_msg carries the
     * package-level verdict ("success", or a package-policy reason). */
    volatile int                tx_submit_pkg_n;          /* 0 = single tx */
    volatile int                pkg_result[RPC_PKG_MAX];  /* 1 ok / 0 rejected */
    volatile unsigned long long pkg_fee[RPC_PKG_MAX];     /* satoshis */
    volatile unsigned long long pkg_vsize[RPC_PKG_MAX];
    char                        pkg_reason[RPC_PKG_MAX][64];
    char                        pkg_msg[128];
    /* the aggregate the package was actually evaluated against, so the RPC can
     * report Core's effective-feerate instead of guessing one */
    volatile unsigned long long pkg_eff_fee, pkg_eff_vsize;
    /* the union of everything the package's members replaced by RBF. Core
     * reports this ONCE at the top level of submitpackage, not per member,
     * which is why it is accumulated across the package rather than kept
     * alongside pkg_result. */
    volatile int                pkg_replaced_n;
    unsigned char               pkg_replaced[RPC_PKG_REPLACED_MAX][32];

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
    char                        ctl_out[4096];  /* larger results (abortprivatebroadcast's removed list) */

    /* -privatebroadcast (Core v30). The parent sets tx_submit_private=1 on a
     * sendrawtransaction so the worker queues the tx for private broadcast
     * instead of mempool+relay (the worker clears it after every submission).
     * pb_enabled/pb_reachable are published by the worker at boot for the RPC
     * gating; pb_info is the worker's snapshot of the queue (pb_info_seq bumps
     * on change), one line per tx, parsed by getprivatebroadcastinfo. */
    volatile int                tx_submit_private;
    volatile int                pb_enabled;
    volatile int                pb_reachable;
    volatile unsigned long long pb_info_seq;
    char                        pb_info[RPC_PB_INFO_CAP];

    /* Runtime network toggle (setnetworkactive). The worker checks this
     * before dialing; the parent reads it for getnetworkinfo's
     * "networkactive". Not in the control channel proper because it is
     * READ on every dial attempt, not just when it changes. */
    volatile int                net_active;

    /* -permitbaremultisig, published here for the same reason net_active is:
     * getmempoolinfo runs in a process that does not link node_config, and it
     * reported a hardcoded 1 while nothing could change the policy. */
    volatile int                permit_bare_multisig;

    /* ---- orphan pool mirror (getorphantxs) ----
     * The pool itself lives in the DOWNLOAD WORKER (daemon/tx_relay.c) and
     * the RPC server runs in the parent, so the parent cannot read it
     * directly. A compact snapshot is published here instead: enough for
     * verbosity 0 and 1, deliberately WITHOUT the transaction bytes, which
     * would be 256 x 100KB and have no business in a status block. */
#define RPC_MAX_ORPHANS 256
    volatile int                n_orphans;
    struct {
        unsigned char txid[32];
        unsigned      len;        /* serialized size in bytes */
        unsigned      nparent;    /* missing parents we are waiting on */
        long long     t_ms;       /* when it entered the pool */
    } orphans[RPC_MAX_ORPHANS];

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
    volatile int                blk_submit_proposal; /* 1 = BIP23 proposal:
                                   evaluate fully (PoW excepted) but NEVER
                                   connect; result/reason as for submit */
    char                        blk_submit_reason[64];
    unsigned char               blk_submit_buf[RPC_BLKSUBMIT_MAX];

    /* ==== ZMQ transaction notification ring ====
     * MANY producers, ONE consumer, and that asymmetry is the whole reason
     * this exists. Transactions are accepted into the mempool by the INBOUND
     * SERVE CHILDREN (bitcoin_serve.asm -> tx_accept_validate), which are
     * separate processes, while the ZMQ publisher owns a listening socket and
     * its subscriber fds and so can live in only ONE process (the download
     * worker). A child cannot write to the worker's sockets, so accepted
     * transactions are staged HERE -- in the pre-fork MAP_SHARED status block
     * every process inherits -- and the worker drains them.
     *
     * Without this, zmqpubrawtx would carry only this node's OWN
     * sendrawtransaction submissions and would miss every transaction
     * arriving from the network, which is the entire point of the topic.
     *
     * A producer claims a slot with an atomic increment on zmq_seq, fills it,
     * and publishes `ready` LAST behind a barrier, so the consumer never sees
     * a half-written slot. Overrun (producers lapping the consumer) is
     * detected by the consumer, which skips ahead and counts what it lost:
     * dropping is correct for a PUB socket, but dropping SILENTLY is not. */
    volatile unsigned long long zmq_seq;    /* slots claimed (producers)       */
    volatile unsigned long long zmq_lost;   /* messages lost to overrun        */
    struct {
        volatile unsigned long long ready;  /* seq+1 once filled; 0 = empty    */
        volatile unsigned long      len;    /* raw tx length                   */
        unsigned char               txid[32];          /* WIRE order           */
        unsigned char               tx[RPC_ZMQ_TXMAX];
    } zmq_ring[RPC_ZMQ_RING];

    /* ---- peer misbehaviour scores (audit finding 7) ----------------------
     * These live HERE, in the pre-fork MAP_SHARED block, for the same reason
     * the zmq ring does: the serve loop that detects protocol violations runs
     * in a FORKED CHILD, and a process-local table dies with it. Scores kept
     * per-process meant a peer could misbehave once per connection forever
     * and never reach the threshold -- the machinery looked like a defence
     * and could not accumulate.
     *
     * `mis_lock` is a cross-process spinlock (0 free, 1 held) taken around
     * slot lookup and update. Without it two children can allocate two slots
     * for the same peer and each accumulate half the evidence, which is the
     * quiet version of the same failure. */
    volatile int              mis_lock;
    struct {
        volatile int          score;
        char                  ip[64];
    } misbehavior[RPC_MISBEHAVIOR_SLOTS];
    /* CC-1 (2026-09-06): the transaction ANNOUNCE ring. Every accept path
     * (tx_accept.c, in whichever process accepted -- the worker for
     * outbound/RPC, a forked serve child for inbound) claims a slot with an
     * atomic increment on ann_seq and fills it; every inbound serve child
     * drains it on its own cursor and announces what it has not seen to its
     * peer, and the worker drains it to feed inbound-origin transactions to
     * the outbound legs. Same producer/consumer shape as zmq_ring above; the
     * entries are 64 bytes, so a lapped consumer resyncs cheaply. */
    volatile unsigned long long ann_seq;
    struct {
        volatile unsigned long long ready;     /* seq+1 once filled; 0 = empty */
        unsigned char               txid[32];
        volatile unsigned long long fee;       /* satoshis; 0 = unknown */
        volatile unsigned long      vsize;     /* vbytes;   0 = unknown */
        volatile int                src_slot;  /* peer-table slot that delivered it; -1 = worker/RPC */
    } ann_ring[RPC_ANN_RING];
    /* 3.1 (UTXO_INLINE_CONNECT_SCOPE, 2026-09-06): the CONNECTED tip, the
     * cap every outward-facing site applies to the stored tip -- the parent's
     * chain RPCs (rpc_chain refresh) and the inbound serve children's
     * getheaders / getblocks / tip-watch announce (serve_public_tip). Seeded
     * by the parent from utxo_applied_height.dat before the fork, then
     * published by the worker on every rotation AND at every block boundary
     * of a catch-up call (the apply hook), so it never lags the truth by more
     * than the block being connected. NODE_TIP_UNTRACKED = live UTXO tracking
     * is off (or the worker has not reported yet): readers use the stored
     * tip, the pre-3.1 behaviour. -1 = tracking on, nothing connected yet. */
    volatile long long connected_tip;
    /* ---- coinstats FOLD ring (2026-09-06, UTXO_INLINE_BUILD_PERF_SCOPE.md:
     * "the MuHash fold is on the bulk connect path", lever 2) -------------
     * Steady state used to fold every created output and spent input into
     * the MuHash accumulators ON the connect thread (~17 ms per heavy block).
     * Now the connect thread pushes a compact coin record here and a forked
     * fold worker (daemon/coinstats_index.c csi_worker_start) drains it into
     * the accumulators, which it alone owns from then on. MuHash is
     * commutative, so order within a block is irrelevant; reorg removals go
     * through the same ring in the same sequence, so they cancel exactly.
     *
     * Same claim/fill/ready discipline as ann_ring above. What differs is
     * that a lost record here is a WRONG DIGEST, not a missed announcement:
     * the producer therefore waits for room (csi_folded_seq is the worker's
     * consumption cursor) up to a bound, and a lap the worker detects on its
     * side is counted AND invalidates the index (re-seeded at the next boot).
     *
     * csi_pushed_height / csi_folded_height: the connect thread's commit
     * marker for the applied height goes through the ring too, and the
     * worker publishes coinstats.dat and then csi_folded_height only after
     * it has folded everything before that marker -- the WATERMARK the
     * parent's gettxoutsetinfo gates on (folded < pushed: wait, then
     * refuse). csi_deferred: bulk catch-up, no index to serve at all. */
    volatile unsigned long long csi_seq;            /* slots claimed (connect thread) */
    volatile unsigned long long csi_folded_seq;     /* slots consumed (fold worker)   */
    volatile long long          csi_pushed_height;  /* last commit marker pushed      */
    volatile long long          csi_folded_height;  /* watermark: file written through here */
    volatile unsigned long long csi_lapped;         /* records lost to overrun (worker side)  */
    volatile unsigned long long csi_overrun;        /* pushes that gave up waiting (producer) */
    volatile unsigned long long csi_folds;          /* elements the worker has folded */
    volatile int                csi_deferred;       /* retired 2026-09-10 (bulk catch-up deferred the index); stays 0, kept for the layout */
    volatile int                csi_pause;          /* test seam: the worker holds its cursor */
    volatile int                csi_worker_pid;     /* 0 = no worker (inline folding) */
    struct {
        volatile unsigned long long ready;          /* seq+1 once filled; 0 = empty */
        volatile unsigned int       kind;           /* CSI_K_* (coinstats_index.c) */
        volatile unsigned int       slen;           /* full script length (head) / chunk length (cont) */
        unsigned char               body[RPC_CSI_BODY];
    } csi_ring[RPC_CSI_RING];
    /* 2026-09-08: the parallel download's peers. Core's getpeerinfo during
     * IBD is where an operator watches the sync -- which peers serve blocks,
     * what is in flight, bytes per peer -- and this node's sixteen download
     * workers are forked processes whose sockets the RPC server never saw.
     * The catch-up parent publishes them here every tick; getpeerinfo
     * appends them, getnettotals counts their bytes. */
    volatile int              n_dlpeers;
    volatile long long        dl_bytes_total;       /* every byte the download has received this run */
    rpc_peer_t                dlpeers[64];
    /* 2026-09-10: the parallel download's AGGREGATE state, for
     * bmcgetdownloadinfo. Core has no counterpart -- its block download is 8
     * outbound peers driven from one message-handler thread, so there is no
     * worker to report and no window state an operator can act on. Here each
     * downloading peer is a forked process, so the mapping worker -> peer ->
     * chunk -> rate is the only way to see what the sync is doing. Published
     * by the catch-up parent on the same tick as dlpeers, cleared when the
     * download ends. Appended: every offset above is unchanged. */
    volatile int              dl_active;          /* 1 while the parallel downloader runs */
    volatile int              dl_workers;         /* workers this run */
    volatile int              dl_pool;            /* live candidate pool */
    volatile int              dl_banned;          /* peers banned for the run */
    volatile int              dl_free_peers;      /* unclaimed and unbanned */
    volatile long long        dl_window;          /* blocks the window allows above the anchor */
    volatile long long        dl_first_hole;      /* the archive's first missing height */
    volatile long long        dl_claim;           /* the claim cursor */
    volatile long long        dl_applied;         /* the connected tip the window anchors to */
    volatile long long        dl_end_h;           /* the span's last height */
    volatile long long        dl_staged;          /* chunks staged, not yet committed */
    volatile long long        dl_stall_timeout_s; /* the adaptive stall timeout right now */
    volatile long long        dl_stall_evictions; /* window-tail evictions this run */
    volatile long long        dl_median_bps;      /* the pool's median receive rate */
    /* Pool OCCUPANCY: the share of all worker wall-clock spent blocked in the
     * socket read (0..100, -1 unmeasured). This is the number that answers
     * "would more peers help?". Low means the peers are filling the pipe and
     * only more of them can help; high means the slots are held by peers that
     * cannot fill it. Measured on run 22 from OUTSIDE the process because the
     * node did not report it: 11-20% per worker while the log said 8/8 active. */
    volatile int              dl_pool_idle_pct;
} node_status_t;
#define NODE_TIP_UNTRACKED (-2LL)

/* Hand the RPC layer the shared status region (call before rpc_server_start).
 * NULL is valid -- methods that need it then report an empty/loading node.
 * The const setter keeps status reads read-only; the writable variant is for
 * sendrawtransaction, which stages into the submission channel above. */
void rpc_node_set_status(const node_status_t* st);
void rpc_node_set_user_agent(const char* ua);   /* -uacomment: getnetworkinfo subversion */
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
    /* every entry's graph in ONE pass: the per-txid call above costs a full
       scan of the node array, so asking it n times is O(n^2). Returns the
       count written, or -1 to say "fall back to the per-txid call". */
    long (*pol_entry_info_all)(void*, struct mp_entry_info*, unsigned char (*)[32], unsigned);
    long (*estimate)(void*, unsigned long long*,
                     unsigned long long*);                      /* fee EMA+samples */
    void (*sha256d)(unsigned char*, const void*, unsigned long);/* for wtxid */
    unsigned long long (*min_fee)(void*);   /* dynamic mempoolminfee, sat/kvB (polstate) */
    /* Core -bytespersigop (DEFAULT_BYTES_PER_SIGOP 20), for the sigops-adjusted
     * weight max(weight, sigop_cost * bytes_per_sigop) that getmempoolentry's
     * vsize_adjusted/chunkweight and getmempoolcluster are computed from. A
     * HOOK rather than a direct call into the policy module: rpc_node.o is
     * linked by 22 test rules that do not pull in bitcoin_mempool_policy.c, and
     * link-check rightly refused the new dependency. Unset means Core's
     * default. */
    unsigned long long (*bytespersigop)(void);
    void*     feeest;         /* shared fee estimator (daemon/fee_estimator.c); NULL = none */
    unsigned long long min_relay_satkvb;    /* -minrelaytxfee, sat/kvB (estimatesmartfee floor) */
} rpc_mempool_hooks;
void rpc_node_set_mempool(const rpc_mempool_hooks* h);

/* Hand the RPC layer the persistent address book (daemon/addrbook.c v2), so
 * getnodeaddresses/getaddrmaninfo report real recorded peers. Injected as
 * pointers for the same no-link-fanout reason as the mempool hooks. */
#include "daemon/addrbook.h"
void rpc_node_set_addrbook(void* ab, long (*count)(void*),
                           int (*get)(void*, long, ab2_rec_t*));
void rpc_node_set_addrbook_dir(const char* dir);
/* live network state for getnetworkinfo: reachability probe (BMC_NET_* id ->
 * 0/1) and our i2p b32 destination, both owned by daemon/dialer.c; the onion
 * hostname once the tor listener is up. All optional -- unset means the
 * pre-transport defaults (ipv4/ipv6 only, no localaddresses). */
void rpc_node_set_net_hooks(int (*reachable)(int), const char* (*i2p_b32)(void));
void rpc_node_set_onion_local(const char* onion, int port);

/* Hand the RPC layer the operator's addnode= list (node_config's
 * g_cfg.addnode / n_addnode), so getaddednodeinfo reports the real
 * configured nodes and whether each is currently connected. */
/* BORROWED, not copied: the list must outlive the RPC server. The only
 * caller passes node_config's g_cfg.addnode, a long-lived global. Pass
 * (NULL, 0) to detach. */
void rpc_node_set_addednodes(const char (*list)[64], int n);
/* The four zmqpub endpoints from bitcoin.conf ("" / NULL = not published),
 * behind getzmqnotifications. Injected like the added-node list above. */
void rpc_node_set_zmq(const char* hashblock, const char* hashtx,
                      const char* rawblock, const char* rawtx);

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

/* bumpfee (rpc_wallet_ops.c): raw bytes of one mempool tx, copied out under
 * the pool lock. Returns length or -1 (absent, or no pool in this process). */
long rpc_node_mempool_rawtx(const unsigned char txid_wire[32], unsigned char* out, unsigned long cap);

/* -persistmempool: the daemon's boot and shutdown hooks. Same code the
 * savemempool/importmempool RPCs use, so the two cannot drift. */
long rpc_node_mempool_save(const char* path);   /* txs written, or -1 */
long rpc_node_mempool_load(const char* path);   /* txs accepted, or -1 */

/* -limitancestorcount / -limitancestorsize, for getmempoolinfo's cluster fields */
void rpc_node_set_ancestor_limits(long count, long size_kvb);
/* Record a connection's own facts -- transport, BIP324 session id, our bound
   address -- from the process that holds the socket. getpeerinfo runs
   elsewhere and can only report what reaches the shared table. */
void rpc_note_peer_socket(int slot, int fd);
#endif
