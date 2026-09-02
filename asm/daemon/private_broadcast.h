/* daemon/private_broadcast.h -- Core's -privatebroadcast (v30+): a transaction
 * submitted over sendrawtransaction is NOT put in the mempool; it is handed to
 * NUM_PER_TX short-lived, anonymous connections over Tor or I2P (or clearnet
 * through the Tor proxy), one transaction per connection, and stays queued
 * until this node hears it back from the network through an ordinary peer.
 *
 * The queue and the wire exchange live here, decoupled from sockets and from
 * the worker's loop, so tests drive both over loopback. daemon/main.c owns
 * the rest: picking a network and an address, forking a helper child per
 * connection (the same shape as its background dials), the reattempt clock,
 * the "received back" check, the RPC snapshot and the abort op.
 *
 * Wire shape, byte for byte what Core's ConnectionType::PRIVATE_BROADCAST does
 * (net_processing.cpp PushNodeVersion / PushPrivateBroadcastTx, net.cpp
 * IsOutboundMessageAllowedInPrivateBroadcast):
 *   version: services 0, time 0, both addresses zero, height 0, relay 0,
 *            user agent "/pynode:0.0.1/" -- nothing that names this node;
 *   after verack: one inv(MSG_TX, txid); the peer's getdata must name
 *            exactly that inv; then the tx, then a ping; the pong is the
 *            receipt. Only version/verack/inv/tx/ping ever go out -- no pong,
 *            no sendaddrv2, no wtxidrelay, nothing the peer could correlate. */
#ifndef BMC_PRIVATE_BROADCAST_H
#define BMC_PRIVATE_BROADCAST_H

#define PB_NUM_PER_TX            3      /* Core NUM_PRIVATE_BROADCAST_PER_TX */
#define PB_MAX_TX                64     /* Core caps at 10,000; a personal node queues a handful */
#define PB_MAX_PEERS_PER_TX      24
#define PB_MAX_CONNECTIONS       8      /* concurrent helper children (Core: 64) */
#define PB_CONN_LIFETIME_S       180    /* Core PRIVATE_BROADCAST_MAX_CONNECTION_LIFETIME 3min */
#define PB_INITIAL_STALE_S       300    /* Core INITIAL_STALE_DURATION 5min */
#define PB_STALE_S               60     /* Core STALE_DURATION 1min */
#define PB_REATTEMPT_MIN_S       120    /* Core: 2min + rand(1min) */
#define PB_REATTEMPT_JITTER_S    60
#define PB_USER_AGENT            "/pynode:0.0.1/"

typedef struct {
    char      addr[96];        /* "host:port" as this node dialled it */
    long long sent;            /* unix seconds the tx was picked for this peer */
    long long received;        /* unix seconds of the pong (0 = not yet) */
} pb_peer_t;

typedef struct {
    int             in_use;
    unsigned char*  tx;        /* full witness serialization, owned */
    unsigned long   len;
    unsigned char   txid[32];
    unsigned char   wtxid[32];
    long long       time_added;
    int             npeers;
    pb_peer_t       peers[PB_MAX_PEERS_PER_TX];
} pb_tx_t;

/* ---- the queue (single-threaded: the worker's main loop) ---- */
void  pb_queue_init(void);
long  pb_queue_count(void);
int   pb_queue_has_pending(void);
/* 1 added / 0 already present / -1 full / -2 bad tx */
int   pb_queue_add(const unsigned char* tx, unsigned long len, long long now);
/* remove by txid; returns the number of peers that acknowledged it, or -1 */
long  pb_queue_remove(const unsigned char txid[32]);
/* remove every tx whose txid OR wtxid equals id; fills removed txids; returns count */
long  pb_queue_abort(const unsigned char id[32], unsigned char (*removed_txids)[32], unsigned char (*removed_wtxids)[32], int cap);
/* Core PickTxForSend: the tx with the fewest sends, then fewest receipts, then
 * the oldest; records a peer entry for `addr` (sent=now). Returns the tx index
 * and *peer_slot, or -1 if nothing is queued. */
int   pb_queue_pick(const char* addr, long long now, int* peer_slot);
void  pb_queue_mark_received(int tx_index, int peer_slot, long long now);
/* forget a send that never completed (dial/handshake failed): the peer entry
 * is dropped so the tx is picked again without counting a phantom attempt */
void  pb_queue_unpick(int tx_index, int peer_slot);
const pb_tx_t* pb_queue_at(int i);
/* indices of stale txs (never sent and older than INITIAL_STALE, or last
 * sent more than STALE ago with no receipt back from the network); returns n */
int   pb_queue_stale(long long now, int* out, int cap);
/* one-line-per-tx snapshot for the RPC parent: "txid wtxid time_added len hex npeers (addr sent received)*" */
long  pb_queue_snapshot(char* out, long cap);

/* ---- the wire exchange on an already-connected socket ----
 * returns 2 confirmed (tx delivered and pong received), 1 delivered (tx sent,
 * no pong before the deadline), 0 failed (why filled). deadline_s bounds the
 * whole conversation (Core: 3 minutes). */
int   pb_exchange(int fd, const unsigned char* tx, unsigned long len,
                  const unsigned char txid[32], int deadline_s, char* why, long whycap);
/* the anonymised version payload (for tests and for pb_exchange) */
long  pb_build_version(unsigned char* out, long cap);

#endif
