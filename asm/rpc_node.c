/* rpc_node.c -- live-node-state RPCs served from the serve daemon.
 *
 * Slice 1 (docs/RPC_LIVE_NODE.md): getconnectioncount + getnetworkinfo, read
 * off the shared node_status_t the serve parent publishes. Later slices add
 * getpeerinfo / getmempoolinfo / getrawmempool / sendrawtransaction.
 *
 * Shapes follow Core v31 (blockchain.cpp / net.cpp). The scratch oracle is
 * bleeding-edge master (31.99, protocol 70017) and cannot be byte-matched --
 * our node has its own wire identity (protocol 70016, subversion
 * /BitcoinMachineCode:0.0.1/) -- so we match the documented v31 field set with
 * values true for THIS node, not the oracle's numbers.
 */
#include "rpc_node.h"
#include "mempool_entry.h"
#include "version_gen.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>   /* atof/atol/atoll -- implicitly declared before 2026-08-25,
                        * which silently corrupted their return values */
#include <pthread.h>
#include <time.h>

static const node_status_t* g_status;
static node_status_t*       g_status_rw;     /* writable handle for submission */
static pthread_mutex_t      g_submit_lock = PTHREAD_MUTEX_INITIALIZER;

void rpc_node_set_status(const node_status_t* st){ g_status = st; }
void rpc_node_set_status_rw(node_status_t* st){ g_status_rw = st; if (!g_status) g_status = st; }

/* txid of a raw tx (BIP141: hash of the no-witness serialization); worker
 * recomputes independently for the mempool. */
extern int tx_txid(unsigned char out[32], const unsigned char* tx, unsigned long txlen,
                   unsigned char* scratch, unsigned long scratchcap);

static int srt_hex1(char c){
    if (c>='0'&&c<='9') return c-'0';
    if (c>='a'&&c<='f') return c-'a'+10;
    if (c>='A'&&c<='F') return c-'A'+10;
    return -1;
}

/* our node advertises NODE_NETWORK(1)|NODE_WITNESS(8) -- it serves witness
 * blocks (see bitcoind.asm's version msg, kept in sync with this) */
#define NODE_LOCAL_SERVICES 0x0000000000000009ULL

/* Core encodes CLIENT_VERSION as 10000*major + 100*minor + patch. */
static long node_client_version(void){
    return 10000L*NODE_VERSION_MAJOR + 100L*NODE_VERSION_MINOR + NODE_VERSION_PATCH;
}

static int cmd_getconnectioncount(rj_val** res){
    int n = g_status ? (g_status->n_out + g_status->n_inbound) : 0;
    *res = rj_numf("%d", n < 0 ? 0 : n);
    return 1;
}

/* one entry of getnetworkinfo.networks */
static rj_val* net_entry(const char* name, int reachable){
    rj_val* o = rj_obj();
    rj_obj_set(o, "name", rj_str(name));
    rj_obj_set(o, "limited", rj_bool(0));
    rj_obj_set(o, "reachable", rj_bool(reachable));
    rj_obj_set(o, "proxy", rj_str(""));
    rj_obj_set(o, "proxy_randomize_credentials", rj_bool(0));
    return o;
}

static int cmd_getnetworkinfo(rj_val** res){
    int n_out = g_status ? g_status->n_out : 0;
    int n_in  = g_status ? g_status->n_inbound : 0;
    if (n_out < 0) n_out = 0;
    if (n_in  < 0) n_in  = 0;

    rj_val* o = rj_obj();
    rj_obj_set(o, "version", rj_numf("%ld", node_client_version()));
    rj_obj_set(o, "subversion", rj_str(NODE_UA_STRING));
    rj_obj_set(o, "protocolversion", rj_numf("%d", NODE_PROTOCOL_VER));
    { char h[17]; snprintf(h, sizeof h, "%016llx", (unsigned long long)NODE_LOCAL_SERVICES);
      rj_obj_set(o, "localservices", rj_str(h)); }
    { rj_val* names = rj_arr(); rj_arr_push(names, rj_str("NETWORK"));
      rj_arr_push(names, rj_str("WITNESS"));
      rj_obj_set(o, "localservicesnames", names); }
    rj_obj_set(o, "localrelay", rj_bool(1));
    rj_obj_set(o, "timeoffset", rj_numf("%d", 0));
    /* the REAL toggle state, not a constant: setnetworkactive changes it and
     * getnetworkinfo must reflect that, or the two disagree about whether
     * the node is talking to anyone. */
    rj_obj_set(o, "networkactive", rj_bool(g_status ? g_status->net_active : 1));
    rj_obj_set(o, "connections", rj_numf("%d", n_out + n_in));
    rj_obj_set(o, "connections_in", rj_numf("%d", n_in));
    rj_obj_set(o, "connections_out", rj_numf("%d", n_out));
    { rj_val* nets = rj_arr();
      rj_arr_push(nets, net_entry("ipv4", 1));
      rj_arr_push(nets, net_entry("ipv6", 1));
      rj_arr_push(nets, net_entry("onion", 0));
      rj_arr_push(nets, net_entry("i2p", 0));
      rj_arr_push(nets, net_entry("cjdns", 0));
      rj_obj_set(o, "networks", nets); }
    rj_obj_set(o, "relayfee", rj_numf("%.8f", 0.00001000));
    rj_obj_set(o, "incrementalfee", rj_numf("%.8f", 0.00001000));
    rj_obj_set(o, "localaddresses", rj_arr());
    rj_obj_set(o, "warnings", rj_arr());
    *res = o;
    return 1;
}

/* service-bit names (Core protocol.h ServiceFlags) */
static void services_names(unsigned long long s, rj_val* arr){
    if (s & (1ULL<<0))  rj_arr_push(arr, rj_str("NETWORK"));
    if (s & (1ULL<<2))  rj_arr_push(arr, rj_str("BLOOM"));
    if (s & (1ULL<<3))  rj_arr_push(arr, rj_str("WITNESS"));
    if (s & (1ULL<<6))  rj_arr_push(arr, rj_str("COMPACT_FILTERS"));
    if (s & (1ULL<<10)) rj_arr_push(arr, rj_str("NETWORK_LIMITED"));
    if (s & (1ULL<<11)) rj_arr_push(arr, rj_str("P2P_V2"));
}

/* getpeerinfo: one entry per live outbound peer from the shared table. Fields
 * Core tracks per-socket but we do not (byte counters, last-send/recv, ping,
 * synced_headers/blocks) are reported as 0/-1 -- a documented gap, not a
 * fabricated value. Inbound peers are counted (getconnectioncount) but not
 * itemized here yet (they are separate forked children). */
static int cmd_getpeerinfo(rj_val** res){
    rj_val* arr = rj_arr();
    if (g_status){
        int id = 0;
        for (int i = 0; i < RPC_MAX_PEERS; i++){
            const rpc_peer_t* p = &g_status->peers[i];
            if (!p->used) continue;
            rj_val* o = rj_obj();
            rj_obj_set(o, "id", rj_numf("%d", id++));
            rj_obj_set(o, "addr", rj_str(p->addr));
            { char h[17]; snprintf(h, sizeof h, "%016llx", (unsigned long long)p->services);
              rj_obj_set(o, "services", rj_str(h)); }
            { rj_val* sn = rj_arr(); services_names(p->services, sn); rj_obj_set(o, "servicesnames", sn); }
            rj_obj_set(o, "relaytxes", rj_bool(1));
            rj_obj_set(o, "lastsend", rj_numf("%lld", (long long)p->last_send));
            rj_obj_set(o, "lastrecv", rj_numf("%lld", (long long)p->last_recv));
            rj_obj_set(o, "bytessent", rj_numf("%lld", (long long)p->bytes_sent));
            rj_obj_set(o, "bytesrecv", rj_numf("%lld", (long long)p->bytes_recv));
            rj_obj_set(o, "conntime", rj_numf("%lld", (long long)p->conn_time));
            rj_obj_set(o, "timeoffset", rj_numf("%d", 0));
            rj_obj_set(o, "version", rj_numf("%u", p->proto));
            rj_obj_set(o, "subver", rj_str(p->subver));
            rj_obj_set(o, "inbound", rj_bool(p->inbound));
            rj_obj_set(o, "startingheight", rj_numf("%d", p->start_height));
            rj_obj_set(o, "synced_headers", rj_numf("%d", -1));
            rj_obj_set(o, "synced_blocks", rj_numf("%d", -1));
            rj_obj_set(o, "network", rj_str("ipv4"));
            rj_arr_push(arr, o);
        }
    }
    *res = arr;
    return 1;
}

/* ==== network / ops RPCs (2026-08-25) ====================================
 * Twelve methods that report or steer the P2P layer. Every one is backed by
 * state this node ALREADY keeps -- the shared peer table (rpc_peer_t, with
 * per-socket byte counters from TCP_INFO) and the persistent address book
 * (bitcoin_addrmgr.asm, 18-byte records) -- so none of them invents data.
 *
 * Where a capability genuinely does not exist here, the method says so
 * rather than pretending: this node has no ban list, no addnode list, and
 * no runtime network-disable switch, so listbanned/getaddednodeinfo return
 * empty (exactly as Core does when nothing is banned or added) while
 * setban/addnode/disconnectnode/setnetworkactive are REAL as of 2026-08-26:
 * they cross the ctl_* channel to the download worker, which owns the peer
 * legs and is the only thing that may touch them. Each reports what it
 * actually did, so a no-op (no such peer, already banned) becomes Core's
 * error rather than a success that changed nothing. */
static long (*g_ab_count)(void*);
static int  (*g_ab_get_i)(void*, long, unsigned char*);
static void* g_ab;

void rpc_node_set_addrbook(void* ab, long (*count)(void*),
                           int (*get_i)(void*, long, unsigned char*)){
    g_ab = ab; g_ab_count = count; g_ab_get_i = get_i;
}

static int cmd_getnettotals(rj_val** res){
    long long sent = 0, recv = 0;
    if (g_status)
        for (int i = 0; i < RPC_MAX_PEERS; i++){
            const rpc_peer_t* p = &g_status->peers[i];
            if (!p->used) continue;
            sent += p->bytes_sent; recv += p->bytes_recv;
        }
    rj_val* o = rj_obj();
    /* Core counts bytes for the process lifetime including closed peers; we
     * sum the LIVE peer table, which is what this node tracks. Documented
     * divergence, not an approximation dressed as a total. */
    rj_obj_set(o, "totalbytesrecv", rj_numf("%lld", recv));
    rj_obj_set(o, "totalbytessent", rj_numf("%lld", sent));
    { struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
      rj_obj_set(o, "timemillis",
                 rj_numf("%lld", (long long)ts.tv_sec*1000 + ts.tv_nsec/1000000)); }
    rj_val* up = rj_obj();
    rj_obj_set(up, "timeframe", rj_numf("%d", 86400));
    rj_obj_set(up, "target", rj_numf("%d", 0));
    rj_obj_set(up, "target_reached", rj_bool(0));
    rj_obj_set(up, "serve_historical_blocks", rj_bool(1));
    rj_obj_set(up, "bytes_left_in_cycle", rj_numf("%d", 0));
    rj_obj_set(up, "time_left_in_cycle", rj_numf("%d", 0));
    rj_obj_set(o, "uploadtarget", up);
    *res = o;
    return 1;
}

/* getnodeaddresses ( count "network" ) -- straight out of the persistent
 * address book. Core's default count is 1 (meaning 1% of known addresses,
 * capped at 2500); 0 means "all". */
static int cmd_getnodeaddresses(const rj_val* params, rj_val** res){
    long want = 1;
    const char* net = NULL;
    if (params && params->typ == RJ_ARR){
        if (params->nitems >= 1 && params->items[0]->typ == RJ_NUM)
            want = atol(params->items[0]->str);
        if (params->nitems >= 2 && params->items[1]->typ == RJ_STR)
            net = params->items[1]->str;
    }
    rj_val* arr = rj_arr();
    /* The book stores IPv4 only, so a filter for any other network is
     * honestly empty rather than IPv4 rows relabelled. */
    if (net && strcmp(net, "ipv4")){ *res = arr; return 1; }
    if (g_ab && g_ab_count && g_ab_get_i){
        long n = g_ab_count(g_ab);
        long cap = (want <= 0) ? n : want;
        if (cap > 2500) cap = 2500;
        for (long i = 0; i < n && (long)arr->nitems < cap; i++){
            unsigned char r[18];
            if (g_ab_get_i(g_ab, i, r) != 1) continue;
            unsigned ip = (unsigned)r[0] | ((unsigned)r[1]<<8) | ((unsigned)r[2]<<16) | ((unsigned)r[3]<<24);
            unsigned port = ((unsigned)r[4]<<8) | (unsigned)r[5];      /* stored BE */
            unsigned long long svc = 0; for (int b=0;b<8;b++) svc |= (unsigned long long)r[6+b] << (8*b);
            unsigned lastseen = (unsigned)r[14] | ((unsigned)r[15]<<8) | ((unsigned)r[16]<<16) | ((unsigned)r[17]<<24);
            rj_val* e = rj_obj();
            rj_obj_set(e, "time", rj_numf("%u", lastseen));
            rj_obj_set(e, "services", rj_numf("%llu", svc));
            { char a[24]; snprintf(a, sizeof a, "%u.%u.%u.%u",
                                   ip & 0xff, (ip>>8)&0xff, (ip>>16)&0xff, (ip>>24)&0xff);
              rj_obj_set(e, "address", rj_str(a)); }
            rj_obj_set(e, "port", rj_numf("%u", port));
            rj_obj_set(e, "network", rj_str("ipv4"));   /* the book stores v4 only */
            rj_arr_push(arr, e);
        }
    }
    *res = arr;
    return 1;
}

/* getaddrmaninfo -- Core reports new/tried/total per network. This node's
 * address book has no new/tried distinction (one flat table), so every
 * record counts as `tried` (they are addresses we have recorded, and the
 * book is fed by successful contact) and `new` is 0. Stated here and in the
 * parity docs rather than split arbitrarily. */
static int cmd_getaddrmaninfo(rj_val** res){
    long n = (g_ab && g_ab_count) ? g_ab_count(g_ab) : 0;
    rj_val* o = rj_obj();
    static const char* nets[] = { "ipv4", "ipv6", "onion", "i2p", "cjdns" };
    for (int i = 0; i < 5; i++){
        rj_val* e = rj_obj();
        long v = (i == 0) ? n : 0;      /* the book is IPv4-only */
        rj_obj_set(e, "new", rj_numf("%d", 0));
        rj_obj_set(e, "tried", rj_numf("%ld", v));
        rj_obj_set(e, "total", rj_numf("%ld", v));
        rj_obj_set(o, nets[i], e);
    }
    { rj_val* e = rj_obj();
      rj_obj_set(e, "new", rj_numf("%d", 0));
      rj_obj_set(e, "tried", rj_numf("%ld", n));
      rj_obj_set(e, "total", rj_numf("%ld", n));
      rj_obj_set(o, "all_networks", e); }
    *res = o;
    return 1;
}

/* getaddednodeinfo ( "node" ) -- this node DOES have an added-node list:
 * `addnode=` in bitcoin.conf, parsed into g_cfg.addnode[] and honoured by
 * the dialer (such peers are preferred and never evicted). Injected here
 * rather than reached directly so rpc_node.c stays free of node_config. */
static const char (*g_addnode)[64];
static int g_n_addnode;

void rpc_node_set_addednodes(const char (*list)[64], int n){
    g_addnode = list; g_n_addnode = n;
}

/* getzmqnotifications -- the four configured publish endpoints, injected the
 * same way as the added-node list so this file stays free of node_config.
 * Core's answer is [{type:"pubhashtx", address, hwm}, ...], one entry per
 * CONFIGURED topic, in Core's own fixed order.
 *
 * hwm is reported as 0, and that is a statement, not a shrug: Core's field
 * is libzmq's send high-water mark (default 1000 queued messages). This
 * publisher has no such queue -- the kernel socket buffer is the only
 * buffering, and a subscriber that falls behind it is dropped (see
 * zmq_pub.c). 0 is ZMQ's own encoding of "no limit set here", which is the
 * closest true description of that behaviour. */
static const char* g_zmq_ep[4];   /* hashblock, hashtx, rawblock, rawtx */

void rpc_node_set_zmq(const char* hashblock, const char* hashtx,
                      const char* rawblock, const char* rawtx){
    g_zmq_ep[0] = hashblock; g_zmq_ep[1] = hashtx;
    g_zmq_ep[2] = rawblock;  g_zmq_ep[3] = rawtx;
}

static int cmd_getzmqnotifications(rj_val** res){
    static const char* const NAMES[4] =
        { "pubhashblock", "pubhashtx", "pubrawblock", "pubrawtx" };
    rj_val* arr = rj_arr();
    for (int i = 0; i < 4; i++){
        if (!g_zmq_ep[i] || !g_zmq_ep[i][0]) continue;
        rj_val* o = rj_obj();
        rj_obj_set(o, "type",    rj_str(NAMES[i]));
        rj_obj_set(o, "address", rj_str(g_zmq_ep[i]));
        rj_obj_set(o, "hwm",     rj_num("0"));
        rj_arr_push(arr, o);
    }
    *res = arr;
    return 1;
}

/* An added node counts as connected when a live peer slot's "ip:port" starts
 * with the configured host. addnode= entries may carry a port or not, so the
 * comparison stops at the configured string's end and then requires a ':' or
 * end-of-string -- otherwise "10.0.0.1" would match "10.0.0.19:8333". */
static int addednode_conn_dir(const char* want, const char** dir){
    if (!g_status) return 0;
    size_t wl = strlen(want);
    for (int i = 0; i < RPC_MAX_PEERS; i++){
        const rpc_peer_t* p = &g_status->peers[i];
        if (!p->used) continue;
        if (strncmp(p->addr, want, wl)) continue;
        if (p->addr[wl] && p->addr[wl] != ':') continue;
        *dir = p->inbound ? "inbound" : "outbound";
        return 1;
    }
    return 0;
}

static int cmd_getaddednodeinfo(const rj_val* params, rj_val** res){
    const char* only = NULL;
    if (params && params->typ == RJ_ARR && params->nitems >= 1 &&
        params->items[0]->typ == RJ_STR) only = params->items[0]->str;
    rj_val* arr = rj_arr();
    int matched = 0;
    for (int i = 0; i < g_n_addnode; i++){
        const char* n = g_addnode[i];
        if (only && strcmp(only, n)) continue;
        matched = 1;
        const char* dir = NULL;
        int up = addednode_conn_dir(n, &dir);
        rj_val* e = rj_obj();
        rj_obj_set(e, "addednode", rj_str(n));
        rj_obj_set(e, "connected", rj_bool(up));
        rj_val* addrs = rj_arr();
        if (up){
            rj_val* a = rj_obj();
            rj_obj_set(a, "address", rj_str(n));
            rj_obj_set(a, "connected", rj_str(dir));
            rj_arr_push(addrs, a);
        }
        rj_obj_set(e, "addresses", addrs);
        rj_arr_push(arr, e);
    }
    if (only && !matched){
        rj_free(arr);
        return -24000;   /* caller maps: Core's RPC_CLIENT_NODE_NOT_ADDED */
    }
    *res = arr;
    return 1;
}

/* listbanned: this node keeps no ban list. Core returns an empty array when
 * nothing is banned, so an empty array here is the SAME answer, not a stub;
 * the divergence is that nothing can ever populate it (see setban). */
static int cmd_empty_array(rj_val** res){ *res = rj_arr(); return 1; }

/* ping -- Core queues a ping to every peer and returns null immediately;
 * the result shows up in getpeerinfo's pingtime. This node's peer legs are
 * driven by the download worker, which sends its own keepalives; there is
 * no RPC-triggered ping path, so this reports unavailable rather than
 * returning null and doing nothing. */
static int cmd_net_unsupported(const char* msg, long* ec, const char** em){
    *ec = -1; *em = msg; return 0;
}

/* getmempoolinfo / getrawmempool.
 *
 * COHERENT since 2026-08-25: daemon/mempool_cfg.c maps the pool MAP_SHARED
 * pre-fork and rpc_node_set_mempool hands it to this layer, so the parent's
 * RPC thread reports the ONE pool the download worker and every inbound serve
 * child write into (previously each process had a divergent copy-on-write
 * pool and these RPCs reported this process's -- always-empty -- copy). With
 * no pool injected (standalone rpcd, static fallback) they still report the
 * empty pool, exactly as before. */
#define MEMPOOL_MAXBYTES   300000000LL     /* 300 MB default (config default) */
#define MEMPOOL_MINFEE_BTC 0.00001000      /* min relay fee, BTC/kvB */

static rpc_mempool_hooks g_mph;      /* zeroed = no pool injected */

void rpc_node_set_mempool(const rpc_mempool_hooks* h){
    if (h) g_mph = *h; else memset(&g_mph, 0, sizeof g_mph);
}
static void mpl(void){ if (g_mph.lock) g_mph.lock(); }
static void mpu(void){ if (g_mph.unlock) g_mph.unlock(); }

/* Copy one mempool transaction's raw bytes out under the pool lock.
 * For the wallet's bumpfee (rpc_wallet_ops.c): the original of a replacement
 * is an UNCONFIRMED wallet tx, and this node's wallet journal deliberately
 * stores metadata, not raw bytes -- the pool is the only place the original
 * still exists. Returns the length, or -1 when the tx is not in the pool (or
 * this process has no pool hooks -- the standalone rpcd). */
long rpc_node_mempool_rawtx(const unsigned char txid_wire[32], unsigned char* out, unsigned long cap){
    if (!g_mph.mp || !g_mph.get) return -1;
    mpl();
    unsigned long len = 0;
    const unsigned char* tx = g_mph.get(g_mph.mp, txid_wire, &len);
    long r = -1;
    if (tx && len > 0 && len <= cap){ memcpy(out, tx, len); r = (long)len; }
    mpu();
    return r;
}

/* Slot layout per bitcoin_mempool.asm's header (same walk daemon/reorg.c
 * uses): +0 n, +8 mask, +16 blob, then 48-byte slots at +40 --
 * [+0 len][+8 txid[32]][+40 blob_off], len==~0 marking empty. */
typedef struct { const unsigned char* txid; const unsigned char* tx; unsigned long len; } mp_ent;
static long mp_slot(void* mp, unsigned long i, mp_ent* e){
    unsigned char* m = (unsigned char*)mp;
    unsigned long long mask; memcpy(&mask, m+8, 8);
    if (i > mask) return -1;
    unsigned char* s = m + 40 + i*48;
    unsigned long long len; memcpy(&len, s, 8);
    if (len == 0xFFFFFFFFFFFFFFFFULL) return 0;
    unsigned char* blob; memcpy(&blob, m+16, 8);
    unsigned long long off; memcpy(&off, s+40, 8);
    e->txid = s+8; e->tx = blob+off; e->len = (unsigned long)len;
    return 1;
}
static unsigned long mp_slot_count(void* mp){
    unsigned long long mask; memcpy(&mask, (unsigned char*)mp+8, 8);
    return (unsigned long)mask + 1;
}

/* BIP141 vsize of a raw tx: weight = base*3 + total, vsize = ceil(weight/4).
 * base is computed by walking the serialization (a local parser instead of
 * linking strip_witness/bitcoin_segwit.c into every rpc_node.o consumer). On
 * any parse anomaly fall back to base=total (legacy layout: vsize == size). */
static unsigned long mp_varint(const unsigned char* p, unsigned long* c){
    if (p[0] < 0xfd){ *c=1; return p[0]; }
    if (p[0] == 0xfd){ *c=3; return (unsigned long)p[1] | ((unsigned long)p[2]<<8); }
    if (p[0] == 0xfe){ *c=5; return (unsigned long)p[1]|((unsigned long)p[2]<<8)|((unsigned long)p[3]<<16)|((unsigned long)p[4]<<24); }
    *c=9; unsigned long v=0; for(int i=0;i<8 && i<4;i++) v |= (unsigned long)p[1+i]<<(8*i); return v;
}
static unsigned long mp_tx_weight(const unsigned char* tx, unsigned long len){
    if (len < 10) return len*4;
    int segwit = (tx[4]==0x00 && tx[5]==0x01);
    if (!segwit) return len*4;                     /* base == total */
    unsigned long p = 6, c;
    unsigned long nin = mp_varint(tx+p,&c); p+=c;
    for (unsigned long i=0;i<nin;i++){ if (p+36>len) return len*4;
        p+=36; unsigned long sl=mp_varint(tx+p,&c); p+=c+sl+4; if (p>len) return len*4; }
    unsigned long nout = mp_varint(tx+p,&c); p+=c;
    for (unsigned long i=0;i<nout;i++){ if (p+8>len) return len*4;
        p+=8; unsigned long sl=mp_varint(tx+p,&c); p+=c+sl; if (p>len) return len*4; }
    unsigned long wit_start = p;
    for (unsigned long i=0;i<nin;i++){
        unsigned long items=mp_varint(tx+p,&c); p+=c;
        for (unsigned long k=0;k<items;k++){ unsigned long il=mp_varint(tx+p,&c); p+=c+il; if (p>len) return len*4; }
    }
    if (p+4 != len) return len*4;                  /* anomaly: fall back */
    unsigned long wit_bytes = p - wit_start;
    unsigned long base = len - 2 - wit_bytes;      /* minus marker+flag+witness */
    return base*3 + len;
}
static unsigned long mp_tx_vsize(const unsigned char* tx, unsigned long len){
    return (mp_tx_weight(tx,len) + 3) / 4;
}

static int cmd_getmempoolinfo(rj_val** res){
    long count = 0; unsigned long long bytes = 0, total_fee = 0, blob_used = 0;
    if (g_mph.mp){
        mpl();
        count = g_mph.count ? g_mph.count(g_mph.mp) : 0;
        unsigned long n = mp_slot_count(g_mph.mp);
        for (unsigned long i=0;i<n;i++){ mp_ent e;
            if (mp_slot(g_mph.mp,i,&e) != 1) continue;
            bytes += mp_tx_vsize(e.tx, e.len);
            blob_used += e.len;
            unsigned long long f,s;
            if (g_mph.polstate && g_mph.pol_entry && g_mph.pol_entry(g_mph.polstate,e.txid,&f,&s)) total_fee += f;
        }
        mpu();
    }
    rj_val* o = rj_obj();
    rj_obj_set(o, "loaded", rj_bool(1));
    rj_obj_set(o, "size", rj_numf("%ld", count));
    rj_obj_set(o, "bytes", rj_numf("%llu", bytes));
    /* Core's usage is its allocator bookkeeping; ours is the honest analog:
     * stored tx bytes + 48B/slot structural overhead for the live entries. */
    rj_obj_set(o, "usage", rj_numf("%llu", blob_used + (unsigned long long)count*48));
    rj_obj_set(o, "total_fee", rj_numf("%llu.%08llu", total_fee/100000000ULL, total_fee%100000000ULL));
    rj_obj_set(o, "maxmempool", rj_numf("%lld", g_mph.maxbytes > 0 ? g_mph.maxbytes : MEMPOOL_MAXBYTES));
    /* mempoolminfee is the DYNAMIC effective floor: max of the static relay
     * fee and the eviction-raised ROLLING floor (mpool_policy_min_fee,
     * sat/kvB -> BTC/kvB). It rises under congestion and decays with Core's
     * half-life schedule. */
    { double dyn_btc = 0.0;
      if (g_mph.polstate && g_mph.min_fee){ unsigned long long satkvb = g_mph.min_fee(g_mph.polstate);
                           dyn_btc = (double)satkvb / 1e8; }
      double eff = dyn_btc > MEMPOOL_MINFEE_BTC ? dyn_btc : MEMPOOL_MINFEE_BTC;
      rj_obj_set(o, "mempoolminfee", rj_numf("%.8f", eff)); }
    rj_obj_set(o, "minrelaytxfee", rj_numf("%.8f", MEMPOOL_MINFEE_BTC));  /* Core's field name */
    rj_obj_set(o, "incrementalrelayfee", rj_numf("%.8f", MEMPOOL_MINFEE_BTC));
    rj_obj_set(o, "unbroadcastcount", rj_numf("%d", 0));
    rj_obj_set(o, "permitbaremultisig", rj_bool(1));       /* standard relay policy */
    rj_obj_set(o, "maxdatacarriersize", rj_numf("%d", 100000));
    /* Master-only cluster-mempool fields (limitclustercount/size, optimal) are
     * deliberately omitted -- bleeding-edge, no released Core has them. */
    *res = o;
    return 1;
}
/* ==== the peer-control channel (parent side) =============================
 * Stage one command, bump the seq, wait for the worker's ack. Same shape as
 * cmd_sendrawtransaction's staging, and the same reason: the worker owns the
 * peer legs and is the only thing that may touch them. */
#define CTL_WAIT_MS 3000
#define CTL_POLL_US 500

static int ctl_send(int op, const char* arg, long long num,
                    long* ec, const char** em, int* result_out){
    static char reason[128];
    if (!g_status_rw){
        *ec = -4;
        *em = "peer control is unavailable: no download worker is attached, so "
              "there is nothing holding the peer legs to command";
        return 0;
    }
    node_status_t* s = g_status_rw;
    pthread_mutex_lock(&g_submit_lock);
    snprintf((char*)s->ctl_arg, sizeof s->ctl_arg, "%s", arg ? arg : "");
    s->ctl_num = num;
    s->ctl_op = op;
    s->ctl_result = 0;
    s->ctl_reason[0] = 0;
    unsigned long long myseq = s->ctl_seq + 1;
    __sync_synchronize();
    s->ctl_seq = myseq;
    int waited = 0, done = 0, result = 0;
    reason[0] = 0;
    while (waited < CTL_WAIT_MS * 1000){
        if (s->ctl_ack == myseq){
            result = s->ctl_result;
            memcpy(reason, (const void*)s->ctl_reason, sizeof reason);
            reason[sizeof reason - 1] = 0;
            done = 1; break;
        }
        struct timespec ts = {0, CTL_POLL_US * 1000L}; nanosleep(&ts, NULL);
        waited += CTL_POLL_US;
    }
    pthread_mutex_unlock(&g_submit_lock);
    if (!done){ *ec = -4; *em = "the download worker did not answer the control request"; return 0; }
    if (result < 0){
        static char embuf[160];
        snprintf(embuf, sizeof embuf, "%s", reason[0] ? reason : "peer control failed");
        *ec = result; *em = embuf;
        return 0;
    }
    if (result_out) *result_out = result;
    return 1;
}

/* addnode "node" "add|remove|onetry" */
static int cmd_addnode(const rj_val* params, rj_val** res, long* ec, const char** em){
    const char* node = (params && params->typ == RJ_ARR && params->nitems >= 1 &&
                        params->items[0]->typ == RJ_STR) ? params->items[0]->str : NULL;
    const char* cmd  = (params && params->typ == RJ_ARR && params->nitems >= 2 &&
                        params->items[1]->typ == RJ_STR) ? params->items[1]->str : NULL;
    if (!node || !cmd){ *ec = -8; *em = "addnode requires a node and a command"; return 0; }
    long long mode;
    if      (!strcmp(cmd, "add"))    mode = 0;
    else if (!strcmp(cmd, "remove")) mode = 1;
    else if (!strcmp(cmd, "onetry")) mode = 2;
    else { *ec = -8; *em = "command must be \"add\", \"remove\" or \"onetry\""; return 0; }
    int r = 0;
    if (!ctl_send(RPC_CTL_ADDNODE, node, mode, ec, em, &r)) return 0;
    if (mode == 1 && r == 0){
        /* Core: removing a node that was never added is an error, not a
         * silent success -- the caller's mental model is wrong either way. */
        *ec = -24; *em = "Error: Node has not been added."; return 0;
    }
    *res = rj_null();
    return 1;
}

static int cmd_disconnectnode(const rj_val* params, rj_val** res, long* ec, const char** em){
    const char* addr = NULL; long long nodeid = -1;
    if (params && params->typ == RJ_ARR){
        if (params->nitems >= 1 && params->items[0]->typ == RJ_STR) addr = params->items[0]->str;
        if (params->nitems >= 2 && params->items[1]->typ == RJ_NUM) nodeid = atoll(params->items[1]->str);
        else if (params->nitems >= 1 && params->items[0]->typ == RJ_NUM)
            nodeid = atoll(params->items[0]->str);
    }
    if ((addr && addr[0] && nodeid >= 0)){
        *ec = -32602; *em = "Only one of address and nodeid should be provided."; return 0; }
    if ((!addr || !addr[0]) && nodeid < 0){
        *ec = -32602; *em = "Only one of address and nodeid should be provided."; return 0; }
    int r = 0;
    if (!ctl_send(RPC_CTL_DISCONNECT, addr ? addr : "", nodeid, ec, em, &r)) return 0;
    if (r == 0){ *ec = -29; *em = "Node not found in connected nodes"; return 0; }
    *res = rj_null();
    return 1;
}

/* setban "subnet" "add|remove" ( bantime absolute ) */
static int cmd_setban(const rj_val* params, rj_val** res, long* ec, const char** em){
    const char* subnet = (params && params->typ == RJ_ARR && params->nitems >= 1 &&
                          params->items[0]->typ == RJ_STR) ? params->items[0]->str : NULL;
    const char* cmd    = (params && params->typ == RJ_ARR && params->nitems >= 2 &&
                          params->items[1]->typ == RJ_STR) ? params->items[1]->str : NULL;
    if (!subnet || !cmd){ *ec = -8; *em = "setban requires a subnet and a command"; return 0; }
    int add;
    if      (!strcmp(cmd, "add"))    add = 1;
    else if (!strcmp(cmd, "remove")) add = 0;
    else { *ec = -8; *em = "command must be \"add\" or \"remove\""; return 0; }
    long long until = 0;
    if (add){
        long long bantime = 0; int absolute = 0;
        if (params->nitems >= 3 && params->items[2]->typ == RJ_NUM) bantime = atoll(params->items[2]->str);
        if (params->nitems >= 4 && params->items[3]->typ == RJ_BOOL) absolute = params->items[3]->str[0] == '1';
        if (bantime <= 0) bantime = 60 * 60 * 24;          /* Core's default: 24h */
        until = absolute ? bantime : (long long)time(NULL) + bantime;
    }
    int r = 0;
    if (!ctl_send(RPC_CTL_SETBAN, subnet, until, ec, em, &r)) return 0;
    if (r == 0){
        *ec = -30;
        *em = add ? "Error: IP/Subnet already banned"
                  : "Error: Unban failed. Requested address/subnet was not previouslyManually banned.";
        return 0;
    }
    *res = rj_null();
    return 1;
}

static int cmd_clearbanned(rj_val** res, long* ec, const char** em){
    if (!ctl_send(RPC_CTL_CLEARBANNED, "", 0, ec, em, NULL)) return 0;
    *res = rj_null();
    return 1;
}

/* listbanned -- straight out of the shared ban list; no channel round trip,
 * because the parent can read what the worker enforces. */
static int cmd_listbanned(rj_val** res){
    rj_val* arr = rj_arr();
    if (g_status){
        long long now = (long long)time(NULL);
        for (int i = 0; i < RPC_MAX_BANS; i++){
            if (!g_status->bans[i].until) continue;
            if (g_status->bans[i].until <= now) continue;   /* expired */
            rj_val* e = rj_obj();
            rj_obj_set(e, "address", rj_str((const char*)g_status->bans[i].subnet));
            rj_obj_set(e, "banned_until", rj_numf("%lld", (long long)g_status->bans[i].until));
            rj_obj_set(e, "ban_created", rj_numf("%lld", (long long)g_status->bans[i].created));
            rj_arr_push(arr, e);
        }
    }
    *res = arr;
    return 1;
}

static int cmd_setnetworkactive(const rj_val* params, rj_val** res, long* ec, const char** em){
    if (!params || params->typ != RJ_ARR || params->nitems < 1 ||
        params->items[0]->typ != RJ_BOOL){
        *ec = -8; *em = "setnetworkactive requires a boolean"; return 0; }
    int on = params->items[0]->str[0] == '1';
    if (!ctl_send(RPC_CTL_SETNETACTIVE, "", on, ec, em, NULL)) return 0;
    *res = rj_bool(on);                       /* Core echoes the new state */
    return 1;
}

static int cmd_ping(rj_val** res, long* ec, const char** em){
    if (!ctl_send(RPC_CTL_PING, "", 0, ec, em, NULL)) return 0;
    *res = rj_null();                         /* Core: queued, returns null */
    return 1;
}

/* ==== gettxspendingprevout ==============================================
 * Core lists it under Blockchain, but it is a pure mempool query and the
 * pool enumeration lives here, so it lives here too. For each outpoint the
 * caller names, report the mempool transaction spending it, if any -- and
 * report the outpoint with no `spendingtxid` when nothing does, which is
 * what Core returns rather than omitting the entry. */
static int gtsp_hex32_wire(const char* h, unsigned char out[32]){
    if (!h || strlen(h) != 64) return 0;
    for (int i = 0; i < 32; i++){
        int hi, lo; char a = h[i*2], b = h[i*2+1];
        if (a>='0'&&a<='9') hi=a-'0'; else if (a>='a'&&a<='f') hi=a-'a'+10;
        else if (a>='A'&&a<='F') hi=a-'A'+10; else return 0;
        if (b>='0'&&b<='9') lo=b-'0'; else if (b>='a'&&b<='f') lo=b-'a'+10;
        else if (b>='A'&&b<='F') lo=b-'A'+10; else return 0;
        out[31-i] = (unsigned char)((hi<<4)|lo);      /* display -> wire */
    }
    return 1;
}

/* Does mempool tx `tx` spend (txid_wire, vout)? Walks the input list only. */
static int gtsp_spends(const unsigned char* tx, unsigned long len,
                       const unsigned char txid_wire[32], unsigned long vout){
    if (len < 10) return 0;
    unsigned long p = 4;
    if (len > 6 && tx[4] == 0x00 && tx[5] == 0x01) p = 6;   /* segwit marker */
    unsigned long cc;
    unsigned long n_in = mp_varint(tx + p, &cc); p += cc;
    if (n_in == 0 || n_in > 100000) return 0;
    for (unsigned long i = 0; i < n_in; i++){
        if (p + 36 > len) return 0;
        unsigned long vo = (unsigned long)tx[p+32] | ((unsigned long)tx[p+33]<<8) |
                           ((unsigned long)tx[p+34]<<16) | ((unsigned long)tx[p+35]<<24);
        if (vo == vout && !memcmp(tx + p, txid_wire, 32)) return 1;
        p += 36;
        unsigned long ssl = mp_varint(tx + p, &cc); p += cc + ssl + 4;
        if (p > len) return 0;
    }
    return 0;
}

static int cmd_gettxspendingprevout(const rj_val* params, rj_val** res,
                                    long* ec, const char** em){
    if (!params || params->typ != RJ_ARR || params->nitems < 1 ||
        params->items[0]->typ != RJ_ARR){
        *ec = -8; *em = "Invalid parameter, outputs is not an array"; return 0; }
    const rj_val* list = params->items[0];
    if (list->nitems == 0){
        *ec = -8; *em = "Invalid parameter, outputs are missing"; return 0; }
    /* validate the whole list before touching the pool, so a bad entry
     * cannot produce a half-answered array */
    for (size_t i = 0; i < list->nitems; i++){
        const rj_val* e = list->items[i];
        unsigned char t[32];
        rj_val* tid = (e->typ == RJ_OBJ) ? rj_obj_get(e, "txid") : NULL;
        rj_val* vo  = (e->typ == RJ_OBJ) ? rj_obj_get(e, "vout") : NULL;
        if (!tid || tid->typ != RJ_STR || !gtsp_hex32_wire(tid->str, t)){
            *ec = -8; *em = "Invalid parameter, expected hex txid"; return 0; }
        if (!vo || vo->typ != RJ_NUM || atol(vo->str) < 0){
            *ec = -8; *em = "Invalid parameter, vout must be a non-negative integer"; return 0; }
    }
    static const char* HEXD = "0123456789abcdef";
    rj_val* arr = rj_arr();
    if (g_mph.mp) mpl();
    for (size_t i = 0; i < list->nitems; i++){
        const rj_val* e = list->items[i];
        unsigned char want[32];
        gtsp_hex32_wire(rj_obj_get((rj_val*)e, "txid")->str, want);
        unsigned long vout = (unsigned long)atol(rj_obj_get((rj_val*)e, "vout")->str);
        rj_val* o = rj_obj();
        rj_obj_set(o, "txid", rj_str(rj_obj_get((rj_val*)e, "txid")->str));
        rj_obj_set(o, "vout", rj_numf("%lu", vout));
        if (g_mph.mp){
            unsigned long n = mp_slot_count(g_mph.mp);
            for (unsigned long k = 0; k < n; k++){
                mp_ent me;
                if (mp_slot(g_mph.mp, k, &me) != 1) continue;
                if (!gtsp_spends(me.tx, me.len, want, vout)) continue;
                char hx[65];
                for (int b = 0; b < 32; b++){
                    unsigned char v = me.txid[31-b];
                    hx[b*2] = HEXD[v>>4]; hx[b*2+1] = HEXD[v&15];
                }
                hx[64] = 0;
                rj_obj_set(o, "spendingtxid", rj_str(hx));
                break;
            }
        }
        rj_arr_push(arr, o);
    }
    if (g_mph.mp) mpu();
    *res = arr;
    return 1;
}

static int cmd_getrawmempool(const rj_val* params, rj_val** res){
    /* verbose (params[0]==true) -> object keyed by txid; else -> array of
     * txids (display byte order). Verbose entries carry the fields this node
     * genuinely tracks: vsize, weight, time (0 if unknown), and fees.base;
     * ancestor/descendant aggregates come with getmempoolentry (next slice). */
    int verbose = 0;
    if (params && params->typ == RJ_ARR && params->nitems >= 1){
        const rj_val* v = params->items[0];
        if (v && v->typ == RJ_BOOL && v->str && v->str[0] == '1') verbose = 1;
    }
    rj_val* out = verbose ? rj_obj() : rj_arr();
    if (g_mph.mp){
        static const char* HEXD = "0123456789abcdef";
        mpl();
        unsigned long n = mp_slot_count(g_mph.mp);
        for (unsigned long i=0;i<n;i++){ mp_ent e;
            if (mp_slot(g_mph.mp,i,&e) != 1) continue;
            char hx[65];
            for (int k=0;k<32;k++){ unsigned char b=e.txid[31-k]; hx[k*2]=HEXD[b>>4]; hx[k*2+1]=HEXD[b&15]; }
            hx[64]=0;
            if (!verbose){ rj_arr_push(out, rj_str(hx)); continue; }
            rj_val* ent = rj_obj();
            unsigned long w = mp_tx_weight(e.tx, e.len);
            rj_obj_set(ent, "vsize", rj_numf("%lu", (w+3)/4));
            rj_obj_set(ent, "weight", rj_numf("%lu", w));
            rj_obj_set(ent, "time", rj_numf("%ld", g_mph.time_of ? g_mph.time_of(e.txid) : 0));
            unsigned long long f=0,s=0;
            rj_val* fees = rj_obj();
            if (g_mph.polstate && g_mph.pol_entry && g_mph.pol_entry(g_mph.polstate,e.txid,&f,&s))
                rj_obj_set(fees, "base", rj_numf("%llu.%08llu", f/100000000ULL, f%100000000ULL));
            rj_obj_set(ent, "fees", fees);
            rj_obj_set(out, hx, ent);
        }
        mpu();
    }
    *res = out;
    return 1;
}

/* getmempoolentry txid (Core rpc/mempool.cpp entryToJSON, documented field
 * set minus master's cluster-mempool extras). Field sources, honestly:
 *   vsize/weight     parsed from the stored tx bytes (BIP141).
 *   wtxid            sha256d over the FULL serialization (== txid for legacy).
 *   time             the accept-path arrival stamp (0 if unknown).
 *   height           NOT tracked at accept time -- reported 0, the same
 *                    documented-gap convention getpeerinfo uses.
 *   counts/fees      the tx-accept policy registry's graph, snapshotted under
 *                    mp_lock; ancestor/descendant SIZES are true BIP141 vsize
 *                    sums (each member's bytes re-read from the pool), unlike
 *                    the registry's raw-length bookkeeping.
 *   fees.modified    == fees.base (no prioritisetransaction).
 *   depends/spentby  direct graph edges, filtered to txs still in the pool.
 * Errors are Core-exact: -8 bad txid (same message shape), -5 not in pool. */
static void mpe_hex(char* dst, const unsigned char* internal){
    static const char* HEXD = "0123456789abcdef";
    for (int k=0;k<32;k++){ unsigned char b=internal[31-k]; dst[k*2]=HEXD[b>>4]; dst[k*2+1]=HEXD[b&15]; }
    dst[64]=0;
}
static rj_val* mpe_entry_obj(const unsigned char* txid, const unsigned char* tx, unsigned long len);
static long long pri_delta_of(const unsigned char txid[32]);
static rj_val* mpe_amount(unsigned long long sat){
    return rj_numf("%llu.%08llu", sat/100000000ULL, sat%100000000ULL);
}
static int cmd_getmempoolentry(const rj_val* params, rj_val** res, long* ec, const char** em){
    static char embuf[128];
    if (!params || params->typ != RJ_ARR || params->nitems < 1 || params->items[0]->typ != RJ_STR){
        *ec = -8; *em = "JSON value of type null is not of expected type string"; return 0; }
    const char* hx = params->items[0]->str;
    size_t hl = strlen(hx);
    if (hl != 64){
        snprintf(embuf, sizeof embuf, "txid must be of length 64 (not %zu, for '%s')", hl, hx);
        *ec = -8; *em = embuf; return 0; }
    unsigned char txid[32];
    for (int i=0;i<32;i++){
        int a=srt_hex1(hx[i*2]), b=srt_hex1(hx[i*2+1]);
        if (a<0||b<0){ snprintf(embuf,sizeof embuf,"txid must be hexadecimal string (not '%s')",hx);
                       *ec=-8; *em=embuf; return 0; }
        txid[31-i]=(unsigned char)((a<<4)|b);           /* display -> internal */
    }
    if (!g_mph.mp || !g_mph.get){ *ec=-5; *em="Transaction not in mempool"; return 0; }

    mpl();
    unsigned long len=0;
    const unsigned char* tx = g_mph.get(g_mph.mp, txid, &len);
    if (!tx){ mpu(); *ec=-5; *em="Transaction not in mempool"; return 0; }
    rj_val* o = mpe_entry_obj(txid, tx, len);
    mpu();
    *res = o;
    return 1;
}

/* Build one getmempoolentry-shaped object (assumes mp_lock HELD; also the
 * per-member body of the verbose getmempoolancestors/-descendants forms). */
static rj_val* mpe_entry_obj(const unsigned char* txid, const unsigned char* tx, unsigned long len){
    rj_val* o = rj_obj();
    unsigned long w = mp_tx_weight(tx, len);
    rj_obj_set(o, "vsize", rj_numf("%lu", (w+3)/4));
    rj_obj_set(o, "weight", rj_numf("%lu", w));
    rj_obj_set(o, "time", rj_numf("%ld", g_mph.time_of ? g_mph.time_of(txid) : 0));
    rj_obj_set(o, "height", rj_numf("%d", 0));   /* documented gap: entry height untracked */

    mp_entry_info inf; int have_inf = 0;
    if (g_mph.polstate && g_mph.pol_entry_info)
        have_inf = (int)g_mph.pol_entry_info(g_mph.polstate, txid, &inf);
    /* ancestor/descendant vsize sums over set members STILL IN THE POOL */
    unsigned long long anc_vs=0, desc_vs=0; int anc_n=0, desc_n=0;
    if (have_inf){
        for (int i=0;i<inf.n_anc;i++){ unsigned long l2=0;
            const unsigned char* t2 = g_mph.get(g_mph.mp, inf.anc[i], &l2);
            if (t2){ anc_vs += (mp_tx_weight(t2,l2)+3)/4; anc_n++; } }
        for (int i=0;i<inf.n_desc;i++){ unsigned long l2=0;
            const unsigned char* t2 = g_mph.get(g_mph.mp, inf.desc[i], &l2);
            if (t2){ desc_vs += (mp_tx_weight(t2,l2)+3)/4; desc_n++; } }
    } else { anc_n=1; desc_n=1; anc_vs=desc_vs=(w+3)/4; }
    rj_obj_set(o, "descendantcount", rj_numf("%d", desc_n));
    rj_obj_set(o, "descendantsize", rj_numf("%llu", desc_vs));
    rj_obj_set(o, "ancestorcount", rj_numf("%d", anc_n));
    rj_obj_set(o, "ancestorsize", rj_numf("%llu", anc_vs));

    { unsigned char wt[32]; char whx[65];
      if (g_mph.sha256d){ g_mph.sha256d(wt, tx, len); mpe_hex(whx, wt); }
      else mpe_hex(whx, txid);                       /* degrade: txid */
      rj_obj_set(o, "wtxid", rj_str(whx)); }

    { rj_val* fees = rj_obj();
      unsigned long long base = have_inf ? inf.fee : 0;
      long long modified = (long long)base + pri_delta_of(txid);   /* prioritisetransaction */
      long long am = modified < 0 ? -modified : modified;
      rj_obj_set(fees, "base", mpe_amount(base));
      rj_obj_set(fees, "modified", rj_numf("%s%lld.%08lld", modified<0?"-":"", am/100000000LL, am%100000000LL));
      rj_obj_set(fees, "ancestor", mpe_amount(have_inf ? inf.anc_fee : base));
      rj_obj_set(fees, "descendant", mpe_amount(have_inf ? inf.desc_fee : base));
      rj_obj_set(o, "fees", fees); }

    { rj_val* dep = rj_arr();
      if (have_inf) for (int i=0;i<inf.n_depends;i++){ unsigned long l2=0;
          if (g_mph.get(g_mph.mp, inf.depends[i], &l2)){ char h2[65]; mpe_hex(h2, inf.depends[i]); rj_arr_push(dep, rj_str(h2)); } }
      rj_obj_set(o, "depends", dep); }
    { rj_val* sb = rj_arr();
      if (have_inf) for (int i=0;i<inf.n_spentby;i++){ unsigned long l2=0;
          if (g_mph.get(g_mph.mp, inf.spentby[i], &l2)){ char h2[65]; mpe_hex(h2, inf.spentby[i]); rj_arr_push(sb, rj_str(h2)); } }
      rj_obj_set(o, "spentby", sb); }
    rj_obj_set(o, "unbroadcast", rj_bool(0));
    return o;
}

/* getmempoolancestors / getmempooldescendants (Core rpc/mempool.cpp): the
 * tx's transitive in-mempool ancestors (txs it depends on) or descendants
 * (txs depending on it), EXCLUDING the tx itself -- verified live on the
 * oracle. Non-verbose: array of txids; verbose: object keyed by txid with
 * the same entry shape as getmempoolentry. Same -8/-5 error parity. The set
 * comes from the same mp_lock'd mpool_policy_entry_info snapshot the entry
 * uses, filtered to members still in the structural pool. */
static int cmd_mpe_relatives(const rj_val* params, rj_val** res, long* ec, const char** em,
                             int want_desc){
    static char embuf[128];
    if (!params || params->typ != RJ_ARR || params->nitems < 1 || params->items[0]->typ != RJ_STR){
        *ec = -8; *em = "JSON value of type null is not of expected type string"; return 0; }
    const char* hx = params->items[0]->str;
    size_t hl = strlen(hx);
    if (hl != 64){
        snprintf(embuf, sizeof embuf, "txid must be of length 64 (not %zu, for '%s')", hl, hx);
        *ec = -8; *em = embuf; return 0; }
    unsigned char txid[32];
    for (int i=0;i<32;i++){
        int a=srt_hex1(hx[i*2]), b=srt_hex1(hx[i*2+1]);
        if (a<0||b<0){ snprintf(embuf,sizeof embuf,"txid must be hexadecimal string (not '%s')",hx);
                       *ec=-8; *em=embuf; return 0; }
        txid[31-i]=(unsigned char)((a<<4)|b);
    }
    int verbose = 0;
    if (params->nitems >= 2 && params->items[1]->typ == RJ_BOOL &&
        params->items[1]->str && params->items[1]->str[0]=='1') verbose = 1;
    if (!g_mph.mp || !g_mph.get){ *ec=-5; *em="Transaction not in mempool"; return 0; }

    mpl();
    unsigned long len=0;
    if (!g_mph.get(g_mph.mp, txid, &len)){ mpu(); *ec=-5; *em="Transaction not in mempool"; return 0; }

    mp_entry_info inf; int have_inf = 0;
    if (g_mph.polstate && g_mph.pol_entry_info)
        have_inf = (int)g_mph.pol_entry_info(g_mph.polstate, txid, &inf);
    rj_val* out = verbose ? rj_obj() : rj_arr();
    if (have_inf){
        int n = want_desc ? inf.n_desc : inf.n_anc;
        unsigned char (*set)[32] = want_desc ? inf.desc : inf.anc;
        for (int i=0;i<n;i++){
            if (!memcmp(set[i], txid, 32)) continue;         /* EXCLUDING self */
            unsigned long l2=0;
            const unsigned char* t2 = g_mph.get(g_mph.mp, set[i], &l2);
            if (!t2) continue;                               /* stale registry entry */
            char h2[65]; mpe_hex(h2, set[i]);
            if (verbose) rj_obj_set(out, h2, mpe_entry_obj(set[i], t2, l2));
            else         rj_arr_push(out, rj_str(h2));
        }
    }
    mpu();
    *res = out;
    return 1;
}
static int cmd_getmempoolancestors(const rj_val* params, rj_val** res, long* ec, const char** em){
    return cmd_mpe_relatives(params, res, ec, em, 0);
}
static int cmd_getmempooldescendants(const rj_val* params, rj_val** res, long* ec, const char** em){
    return cmd_mpe_relatives(params, res, ec, em, 1);
}

/* estimatesmartfee conf_target ("estimate_mode") -- Core rpc/fees.cpp shape
 * and argument validation, over THIS node's estimator. Core's estimator is a
 * confirmed-block bucket tracker; ours is the tx-accept policy layer's EMA of
 * accepted feerates (sat/kB, bitcoin_mempool_policy.c) -- an honest,
 * DIFFERENT estimator, so the NUMBER is ours, only the contract is Core's:
 *   - conf_target outside [1,1008] -> -8, Core's exact message.
 *   - estimate_mode other than unset/economical/conservative (any case) ->
 *     -8, Core's exact message. Both modes return the same EMA (one
 *     estimator; the economical/conservative split is meaningless for it).
 *   - no samples yet -> {"errors":["Insufficient data or no feerate found"],
 *     "blocks":N} exactly like a fresh Core node.
 *   - otherwise {"feerate": BTC/kvB, "blocks": N}, floored at the min relay
 *     fee, with N = the target clamped to >= 2 (Core's minimum horizon --
 *     estimatesmartfee 1 answers with "blocks": 2, verified on the oracle). */
static int cmd_estimatesmartfee(const rj_val* params, rj_val** res, long* ec, const char** em){
    if (!params || params->typ != RJ_ARR || params->nitems < 1 ||
        params->items[0]->typ != RJ_NUM){
        *ec = -3; *em = "JSON value of type null is not of expected type number"; return 0; }
    long target = atol(params->items[0]->str);
    if (target < 1 || target > 1008){
        *ec = -8; *em = "Invalid conf_target, must be between 1 and 1008"; return 0; }
    if (params->nitems >= 2 && params->items[1]->typ == RJ_STR){
        const char* m = params->items[1]->str; char lo[16]; size_t i=0;
        for (; m[i] && i+1<sizeof lo; i++) lo[i] = (char)(m[i]>='A'&&m[i]<='Z' ? m[i]+32 : m[i]);
        lo[i]=0;
        if (strcmp(lo,"unset") && strcmp(lo,"economical") && strcmp(lo,"conservative")){
            *ec = -8; *em = "Invalid estimate_mode parameter, must be one of: \"unset\", \"economical\", \"conservative\"";
            return 0; }
    }
    long blocks = target < 2 ? 2 : target;
    rj_val* o = rj_obj();
    unsigned long long satperkb=0, samples=0; int have=0;
    if (g_mph.polstate && g_mph.estimate){
        mpl();
        have = (int)g_mph.estimate(g_mph.polstate, &satperkb, &samples);
        mpu();
    }
    if (!have || samples == 0){
        rj_val* errs = rj_arr();
        rj_arr_push(errs, rj_str("Insufficient data or no feerate found"));
        rj_obj_set(o, "errors", errs);
    } else {
        unsigned long long floor_satkvb = 1000;   /* min relay fee, 0.00001 BTC/kvB */
        if (satperkb < floor_satkvb) satperkb = floor_satkvb;
        rj_obj_set(o, "feerate", rj_numf("%llu.%08llu", satperkb/100000000ULL, satperkb%100000000ULL));
    }
    rj_obj_set(o, "blocks", rj_numf("%ld", blocks));
    *res = o;
    return 1;
}

/* submitblock (BIP22): decode the hex block and stage it into the shared
 * block channel; the download worker -- the only process that owns chain
 * state -- evaluates it (daemon/blk_submit.c) and acks. Result null on
 * accept, else a BIP22 reason string. -22 "Block decode failed" for
 * malformed hex, exactly like Core. The worker polls at its loop top, so a
 * node deep in catch-up may not answer within the window: reported as an
 * honest timeout (-4), never a fabricated verdict. */
#define SBK_WAIT_MS   90000
#define SBK_POLL_US   3000
/* Shared stager for submitblock AND getblocktemplate's proposal mode: hex ->
 * the cross-process channel, wait for the worker's ack. Returns 1 result-ok
 * (result/reason filled), -2 decode, -1 unavailable, -3 timeout. */
static long sbk_stage(const char* hex, int proposal, int* result,
                      char* reason, unsigned long rcap){
    size_t hl = strlen(hex);
    if ((hl & 1) || hl/2 < 81 || hl/2 > RPC_BLKSUBMIT_MAX) return -2;
    unsigned long n = (unsigned long)(hl/2);
    if (!g_status_rw) return -1;

    pthread_mutex_lock(&g_submit_lock);
    node_status_t* st = g_status_rw;
    for (unsigned long i = 0; i < n; i++){
        int hi = srt_hex1(hex[i*2]), lo = srt_hex1(hex[i*2+1]);
        if (hi < 0 || lo < 0){ pthread_mutex_unlock(&g_submit_lock); return -2; }
        st->blk_submit_buf[i] = (unsigned char)((hi<<4)|lo);
    }
    st->blk_submit_len = n;
    st->blk_submit_result = 0;
    st->blk_submit_proposal = proposal;
    st->blk_submit_reason[0] = 0;
    unsigned long long myseq = st->blk_submit_seq + 1;
    __sync_synchronize();
    st->blk_submit_seq = myseq;

    int waited = 0, done = 0;
    while (waited < SBK_WAIT_MS*1000){
        if (st->blk_submit_ack == myseq){
            *result = st->blk_submit_result;
            if (reason && rcap){
                unsigned long rl = rcap < sizeof st->blk_submit_reason ? rcap : sizeof st->blk_submit_reason;
                memcpy(reason, (const void*)st->blk_submit_reason, rl);
                reason[rl - 1] = 0;
            }
            done = 1; break;
        }
        struct timespec ts = {0, SBK_POLL_US*1000L}; nanosleep(&ts, NULL);
        waited += SBK_POLL_US;
    }
    pthread_mutex_unlock(&g_submit_lock);
    return done ? 1 : -3;
}

/* rpc_chain's getblocktemplate proposal hook (rpc_chain_set_proposal).
 * 1 valid / 0 reason / -2 decode / -3 timeout / -1 unavailable. */
long rpc_node_submit_proposal(const char* hex, char* reason, unsigned long rcap){
    int result = 0;
    long r = sbk_stage(hex, 1, &result, reason, rcap);
    if (r != 1) return r;
    return result == 1 ? 1 : 0;
}

static int cmd_submitblock(const rj_val* params, rj_val** res, long* ec, const char** em){
    if (!params || params->typ != RJ_ARR || params->nitems < 1 ||
        params->items[0]->typ != RJ_STR){
        *ec = -1; *em = "submitblock requires a hex block"; return 0; }
    int result = 0;
    static char reason[64]; reason[0] = 0;
    long r = sbk_stage(params->items[0]->str, 0, &result, reason, sizeof reason);
    if (r == -2){ *ec = -22; *em = "Block decode failed"; return 0; }
    if (r == -1){ *ec = -4; *em = "Block submission unavailable (no download worker)"; return 0; }
    if (r == -3){ *ec = -4; *em = "Block submission timed out (node may be catching up)"; return 0; }
    if (result == 1){ *res = rj_null(); return 1; }          /* Core: null */
    *res = rj_str(reason[0] ? reason : "rejected");
    return 1;
}

/* ---- prioritisetransaction / getprioritisedtransactions ------------------
 * (Core rpc/mining.cpp). A fee-delta map consulted by getmempoolentry's
 * fees.modified. PARENT-LOCAL by design: the deltas only influence what THIS
 * process reports (entry/template views) -- like Core's, they are in-memory
 * operator hints, not consensus state; a restart clears them. Deltas
 * ACCUMULATE across calls and an entry whose sum returns to zero is erased
 * (both oracle-verified). The tx need not be in the mempool (the delta
 * simply waits -- in_mempool:false until it shows up). */
#define PRI_MAX 256
static struct { unsigned char txid[32]; long long delta; int used; } g_pri[PRI_MAX];

static long long pri_delta_of(const unsigned char txid[32]){
    for (int i = 0; i < PRI_MAX; i++)
        if (g_pri[i].used && !memcmp(g_pri[i].txid, txid, 32)) return g_pri[i].delta;
    return 0;
}
/* shared txid-arg validation (Core-exact -8 messages); display -> internal */
static int pri_parse_txid(const rj_val* v, unsigned char txid[32], long* ec, const char** em){
    static char embuf[128];
    if (!v || v->typ != RJ_STR){
        *ec = -8; *em = "JSON value of type null is not of expected type string"; return 0; }
    size_t hl = strlen(v->str);
    if (hl != 64){
        snprintf(embuf, sizeof embuf, "txid must be of length 64 (not %zu, for '%s')", hl, v->str);
        *ec = -8; *em = embuf; return 0; }
    for (int i = 0; i < 32; i++){
        int a = srt_hex1(v->str[i*2]), b = srt_hex1(v->str[i*2+1]);
        if (a < 0 || b < 0){
            snprintf(embuf, sizeof embuf, "txid must be hexadecimal string (not '%s')", v->str);
            *ec = -8; *em = embuf; return 0; }
        txid[31-i] = (unsigned char)((a<<4)|b);
    }
    return 1;
}

static int cmd_prioritisetransaction(const rj_val* params, rj_val** res, long* ec, const char** em){
    if (!params || params->typ != RJ_ARR || params->nitems < 3){
        *ec = -1; *em = "prioritisetransaction requires txid, dummy, fee_delta"; return 0; }
    unsigned char txid[32];
    if (!pri_parse_txid(params->items[0], txid, ec, em)) return 0;
    /* dummy must be 0/null (Core-exact message) */
    { const rj_val* d = params->items[1];
      int zero = (d->typ == RJ_NULL) ||
                 (d->typ == RJ_NUM && atof(d->str) == 0.0);
      if (!zero){
          *ec = -8; *em = "Priority is no longer supported, dummy argument to prioritisetransaction must be 0.";
          return 0; } }
    if (params->items[2]->typ != RJ_NUM){
        *ec = -3; *em = "JSON value of type string is not of expected type number"; return 0; }
    long long delta = atoll(params->items[2]->str);
    int slot = -1;
    for (int i = 0; i < PRI_MAX; i++){
        if (g_pri[i].used && !memcmp(g_pri[i].txid, txid, 32)){ slot = i; break; }
        if (slot < 0 && !g_pri[i].used) slot = i;
    }
    if (slot < 0){ *ec = -1; *em = "prioritisation table full"; return 0; }
    if (!g_pri[slot].used){ memcpy(g_pri[slot].txid, txid, 32); g_pri[slot].delta = 0; g_pri[slot].used = 1; }
    g_pri[slot].delta += delta;                       /* ACCUMULATES (Core) */
    if (g_pri[slot].delta == 0) g_pri[slot].used = 0; /* zero-sum erased (Core) */
    *res = rj_bool(1);
    return 1;
}

static int cmd_getprioritisedtransactions(rj_val** res){
    rj_val* o = rj_obj();
    for (int i = 0; i < PRI_MAX; i++){
        if (!g_pri[i].used) continue;
        char hx[65]; mpe_hex(hx, g_pri[i].txid);
        rj_val* e = rj_obj();
        rj_obj_set(e, "fee_delta", rj_numf("%lld", g_pri[i].delta));
        unsigned long len = 0; int inpool = 0;
        unsigned long long base = 0, fsz = 0;
        if (g_mph.mp && g_mph.get){
            mpl();
            inpool = g_mph.get(g_mph.mp, g_pri[i].txid, &len) != NULL;
            if (inpool && g_mph.polstate && g_mph.pol_entry)
                g_mph.pol_entry(g_mph.polstate, g_pri[i].txid, &base, &fsz);
            mpu();
        }
        rj_obj_set(e, "in_mempool", rj_bool(inpool));
        if (inpool)
            rj_obj_set(e, "modified_fee", rj_numf("%lld", (long long)base + g_pri[i].delta));
        rj_obj_set(o, hx, e);
    }
    *res = o;
    return 1;
}

/* sendrawtransaction: parse the raw-tx hex, stage it into the shared
 * submission channel, and block on the download worker's verdict (mempool
 * accept + relay to peers). Core rpc/rawtransaction.cpp: returns the txid on
 * success; -22 on decode failure, -25 missing inputs, -26 policy/consensus
 * reject (reason surfaced), -27 already known. Only meaningful inside the serve
 * daemon (which has the worker + peer legs); the standalone bitcoin_rpcd has no
 * worker, so g_status_rw is NULL and this reports the node as unavailable. */
#define SRT_WAIT_MS   90000     /* worker pickup can wait behind a 60s leg sync */
#define SRT_POLL_US   3000

static int cmd_sendrawtransaction(const rj_val* params, rj_val** res, long* ec, const char** em){
    if (!params || params->typ != RJ_ARR || params->nitems < 1 ||
        params->items[0]->typ != RJ_STR){
        *ec = -8; *em = "Invalid parameter, hexstring required"; return 0; }
    const char* hex = params->items[0]->str;
    size_t hl = strlen(hex);
    if ((hl & 1) || hl/2 == 0 || hl/2 > RPC_TXSUBMIT_MAX){ *ec = -22; *em = "TX decode failed"; return 0; }
    unsigned long n = (unsigned long)(hl/2);
    static unsigned char stage[RPC_TXSUBMIT_MAX];   /* under g_submit_lock */
    static char          txidhex[65];
    static char          reason[128];

    if (!g_status_rw){ *ec = -4; *em = "Transaction relay unavailable (no download worker)"; return 0; }

    pthread_mutex_lock(&g_submit_lock);
    int okhex = 1;
    for (unsigned long i=0;i<n;i++){ int hi=srt_hex1(hex[i*2]),lo=srt_hex1(hex[i*2+1]); if(hi<0||lo<0){okhex=0;break;} stage[i]=(unsigned char)((hi<<4)|lo); }
    if (!okhex){ pthread_mutex_unlock(&g_submit_lock); *ec=-22; *em="TX decode failed"; return 0; }

    /* txid for the success result (display order) */
    { unsigned char id[32]; static unsigned char scratch[2000*81+8];
      if (!tx_txid(id, stage, n, scratch, sizeof scratch)){ pthread_mutex_unlock(&g_submit_lock); *ec=-22; *em="TX decode failed"; return 0; }
      static const char* HEXD = "0123456789abcdef";
      for (int i=0;i<32;i++){ unsigned char b=id[31-i]; txidhex[i*2]=HEXD[b>>4]; txidhex[i*2+1]=HEXD[b&15]; }
      txidhex[64]=0; }

    /* stage into shared memory: buffer + len published BEFORE the seq bump */
    node_status_t* s = g_status_rw;
    memcpy((void*)s->tx_submit_buf, stage, n);
    s->tx_submit_len = n;
    s->tx_submit_result = 0;
    /* explicit: a stale 1 left by a previous testmempoolaccept would turn a
     * real submission into a dry run and report a txid for a tx that was
     * never accepted or relayed. */
    s->tx_submit_test = 0;
    s->tx_submit_reason[0] = 0;
    unsigned long long myseq = s->tx_submit_seq + 1;
    __sync_synchronize();
    s->tx_submit_seq = myseq;                        /* worker wakes on this */

    /* wait for the worker to ack this exact seq */
    int waited = 0, done = 0, result = 0;
    reason[0] = 0;
    while (waited < SRT_WAIT_MS*1000){
        if (s->tx_submit_ack == myseq){
            result = s->tx_submit_result;
            memcpy(reason, (const void*)s->tx_submit_reason, sizeof reason);
            reason[sizeof reason-1]=0;
            done = 1; break;
        }
        struct timespec ts = {0, SRT_POLL_US*1000L}; nanosleep(&ts, NULL);
        waited += SRT_POLL_US;
    }
    pthread_mutex_unlock(&g_submit_lock);

    if (!done){ *ec=-4; *em="Transaction submission timed out"; return 0; }
    if (result == 1){ *res = rj_str(txidhex); return 1; }
    /* worker put a negative Core error code in result and the reason text */
    static char embuf[160];
    snprintf(embuf, sizeof embuf, "%s", reason[0] ? reason : "transaction rejected");
    *ec = result < 0 ? result : -26; *em = embuf;
    return 0;
}

/* ==== testmempoolaccept ==================================================
 * Rides the SAME parent->worker channel as sendrawtransaction, with
 * tx_submit_test set, so the worker runs tx_accept_test_reason: identical
 * consensus/script validation and identical mempool policy checks, stopping
 * at the policy commit boundary. The verdict therefore comes from the real
 * mempool, not from a parallel copy of its rules.
 *
 * DOCUMENTED DIVERGENCE -- package policy. Core validates the array as a
 * PACKAGE: a child may spend a parent that appears earlier in the same call.
 * This node evaluates each transaction independently against the mempool as
 * it stands, because the dry run deliberately inserts nothing, so an earlier
 * transaction in the array is invisible to a later one. When more than one
 * transaction is passed, every entry therefore carries Core's own
 * `package-error` field saying so. A child spending an in-array parent will
 * report `missing-inputs`, which is the truth about what this node checked.
 */
#define TMA_MAX 25

static int tma_stage(node_status_t* s, const unsigned char* tx, unsigned long n,
                     int* result_out, char reason[128], unsigned long long* fee_out){
    memcpy((void*)s->tx_submit_buf, tx, n);
    s->tx_submit_len = n;
    s->tx_submit_result = 0;
    s->tx_submit_fee = 0;
    s->tx_submit_test = 1;
    s->tx_submit_reason[0] = 0;
    unsigned long long myseq = s->tx_submit_seq + 1;
    __sync_synchronize();
    s->tx_submit_seq = myseq;
    int waited = 0;
    while (waited < SRT_WAIT_MS*1000){
        if (s->tx_submit_ack == myseq){
            *result_out = s->tx_submit_result;
            *fee_out = s->tx_submit_fee;
            memcpy(reason, (const void*)s->tx_submit_reason, 128);
            reason[127] = 0;
            return 1;
        }
        struct timespec ts = {0, SRT_POLL_US*1000L}; nanosleep(&ts, NULL);
        waited += SRT_POLL_US;
    }
    return 0;
}

static int cmd_testmempoolaccept(const rj_val* params, rj_val** res, long* ec, const char** em){
    if (!params || params->typ != RJ_ARR || params->nitems < 1 ||
        params->items[0]->typ != RJ_ARR || params->items[0]->nitems < 1){
        *ec = -8; *em = "Invalid parameter, rawtxs must be a non-empty array"; return 0; }
    const rj_val* list = params->items[0];
    if (list->nitems > TMA_MAX){
        *ec = -8; *em = "Array must contain between 1 and 25 transactions"; return 0; }
    if (!g_status_rw){
        *ec = -4; *em = "Mempool acceptance testing unavailable (no download worker)"; return 0; }

    /* decode every transaction BEFORE staging any of them: a bad hex string
     * in the middle would otherwise leave the caller with a half-length
     * array whose positions no longer line up with the input. */
    static unsigned char stage[TMA_MAX][RPC_TXSUBMIT_MAX];
    unsigned long lens[TMA_MAX];
    for (size_t i = 0; i < list->nitems; i++){
        if (list->items[i]->typ != RJ_STR){ *ec = -22; *em = "TX decode failed"; return 0; }
        const char* hex = list->items[i]->str; size_t hl = strlen(hex);
        if ((hl & 1) || hl/2 < 10 || hl/2 > RPC_TXSUBMIT_MAX){ *ec = -22; *em = "TX decode failed"; return 0; }
        lens[i] = (unsigned long)(hl/2);
        for (unsigned long k = 0; k < lens[i]; k++){
            int hi = srt_hex1(hex[k*2]), lo = srt_hex1(hex[k*2+1]);
            if (hi < 0 || lo < 0){ *ec = -22; *em = "TX decode failed"; return 0; }
            stage[i][k] = (unsigned char)((hi<<4)|lo);
        }
    }

    static const char* HEXD = "0123456789abcdef";
    node_status_t* s = g_status_rw;
    rj_val* arr = rj_arr();
    pthread_mutex_lock(&g_submit_lock);
    for (size_t i = 0; i < list->nitems; i++){
        rj_val* e = rj_obj();
        unsigned char id[32], wid[32];
        static unsigned char scratch[2000*81+8];
        int have_id = tx_txid(id, stage[i], lens[i], scratch, sizeof scratch) == 1;
        char hx[65];
        if (have_id){
            for (int k=0;k<32;k++){ unsigned char b=id[31-k]; hx[k*2]=HEXD[b>>4]; hx[k*2+1]=HEXD[b&15]; }
            hx[64]=0; rj_obj_set(e, "txid", rj_str(hx));
            /* wtxid: sha256d of the full serialization for a segwit tx, else
             * the txid itself */
            int segwit = lens[i] > 6 && stage[i][4] == 0x00 && stage[i][5] == 0x01;
            if (segwit && g_mph.sha256d) g_mph.sha256d(wid, stage[i], lens[i]);
            else memcpy(wid, id, 32);
            for (int k=0;k<32;k++){ unsigned char b=wid[31-k]; hx[k*2]=HEXD[b>>4]; hx[k*2+1]=HEXD[b&15]; }
            hx[64]=0; rj_obj_set(e, "wtxid", rj_str(hx));
        }
        if (list->nitems > 1)
            rj_obj_set(e, "package-error",
                       rj_str("this node validates each transaction independently "
                              "against the current mempool; it does not implement "
                              "package policy, so a child spending a parent that "
                              "appears earlier in this array will report missing-inputs"));
        int result = 0; char reason[128] = {0}; unsigned long long fee = 0;
        if (!have_id){
            rj_obj_set(e, "allowed", rj_bool(0));
            rj_obj_set(e, "reject-reason", rj_str("TX decode failed"));
        } else if (!tma_stage(s, stage[i], lens[i], &result, reason, &fee)){
            /* no verdict: `allowed` is OMITTED, which is exactly how Core
             * marks a transaction it could not fully validate */
            rj_obj_set(e, "reject-reason", rj_str("mempool acceptance test timed out"));
        } else if (result == 1){
            unsigned long w = mp_tx_weight(stage[i], lens[i]);
            unsigned long vsz = (w + 3) / 4;
            rj_obj_set(e, "allowed", rj_bool(1));
            rj_obj_set(e, "vsize", rj_numf("%lu", vsz));
            rj_obj_set(e, "vsize_bip141", rj_numf("%lu", vsz));
            rj_val* fees = rj_obj();
            rj_obj_set(fees, "base", rj_numf("%llu.%08llu", fee/100000000ULL, fee%100000000ULL));
            /* effective-feerate/effective-includes describe package feerate,
             * which this node does not compute -- omitted, not guessed. */
            rj_obj_set(e, "fees", fees);
        } else {
            rj_obj_set(e, "allowed", rj_bool(0));
            rj_obj_set(e, "reject-reason", rj_str(reason[0] ? reason : "transaction rejected"));
        }
        rj_arr_push(arr, e);
    }
    s->tx_submit_test = 0;
    pthread_mutex_unlock(&g_submit_lock);
    *res = arr;
    return 1;
}

static const char* const NODE_METHODS[] = {
    "getconnectioncount", "getnetworkinfo", "getpeerinfo",
    "gettxspendingprevout", "getmempoolcluster", "getblockfrompeer",
    "testmempoolaccept", "submitpackage",
    "getprivatebroadcastinfo", "abortprivatebroadcast",
    "getnettotals", "getnodeaddresses", "getaddrmaninfo", "listbanned",
    "clearbanned", "getaddednodeinfo", "addnode", "disconnectnode",
    "setban", "setnetworkactive", "ping", "getzmqnotifications",
    "getmempoolinfo", "getrawmempool", "getmempoolentry", "getmempoolancestors", "getmempooldescendants", "estimatesmartfee", "prioritisetransaction", "getprioritisedtransactions", "submitblock", "sendrawtransaction", NULL
};

const char* rpc_node_method_at(int i){
    int n = 0;
    while (NODE_METHODS[n]) n++;
    return (i >= 0 && i < n) ? NODE_METHODS[i] : NULL;
}
int rpc_node_known_method(const char* m){
    for (int i = 0; NODE_METHODS[i]; i++) if (!strcmp(m, NODE_METHODS[i])) return 1;
    return 0;
}
int rpc_node_dispatch(const char* m, const rj_val* params, rj_val** res, long* ec, const char** em){
    (void)ec; (void)em;
    if (!strcmp(m, "getconnectioncount")) return cmd_getconnectioncount(res);
    if (!strcmp(m, "getnetworkinfo"))     return cmd_getnetworkinfo(res);
    if (!strcmp(m, "getpeerinfo"))        return cmd_getpeerinfo(res);
    if (!strcmp(m, "gettxspendingprevout")) return cmd_gettxspendingprevout(params, res, ec, em);
    if (!strcmp(m, "testmempoolaccept")) return cmd_testmempoolaccept(params, res, ec, em);
    if (!strcmp(m, "submitpackage"))
        return cmd_net_unsupported(
            "this node has no package validation: transactions are accepted "
            "one at a time against the mempool as it stands, so a child "
            "cannot be validated against an unconfirmed parent in the same "
            "call. Submit the parent first with sendrawtransaction, then the "
            "child", ec, em);
    if (!strcmp(m, "getprivatebroadcastinfo") || !strcmp(m, "abortprivatebroadcast"))
        return cmd_net_unsupported(
            "this node has no private broadcast queue: sendrawtransaction "
            "relays to every live peer leg immediately, so there is no "
            "pending private broadcast to report on or abort", ec, em);
    if (!strcmp(m, "getmempoolcluster"))
        return cmd_net_unsupported(
            "this node's mempool has no cluster linearization: it tracks the "
            "ancestor/descendant graph (see getmempoolancestors) but not "
            "Core's cluster mempool structure, so there are no clusters to "
            "report", ec, em);
    if (!strcmp(m, "getblockfrompeer"))
        return cmd_net_unsupported(
            "peer connections belong to the forked download worker, which "
            "chooses what to fetch from its own headers-first schedule; there "
            "is no parent-to-worker channel for a targeted block request, so "
            "this call would change nothing", ec, em);
    if (!strcmp(m, "getnettotals"))       return cmd_getnettotals(res);
    if (!strcmp(m, "getnodeaddresses"))   return cmd_getnodeaddresses(params, res);
    if (!strcmp(m, "getaddrmaninfo"))     return cmd_getaddrmaninfo(res);
    if (!strcmp(m, "listbanned"))         return cmd_listbanned(res);
    if (!strcmp(m, "getaddednodeinfo")){
        int rc = cmd_getaddednodeinfo(params, res);
        if (rc == -24000){ *ec = -24; *em = "Error: Node has not been added."; return 0; }
        return rc;
    }
    if (!strcmp(m, "clearbanned"))        return cmd_clearbanned(res, ec, em);
    if (!strcmp(m, "addnode"))            return cmd_addnode(params, res, ec, em);
    if (!strcmp(m, "disconnectnode"))     return cmd_disconnectnode(params, res, ec, em);
    if (!strcmp(m, "setban"))             return cmd_setban(params, res, ec, em);
    if (!strcmp(m, "setnetworkactive"))   return cmd_setnetworkactive(params, res, ec, em);
    if (!strcmp(m, "ping"))               return cmd_ping(res, ec, em);
    if (!strcmp(m, "getzmqnotifications")) return cmd_getzmqnotifications(res);
    if (!strcmp(m, "getmempoolinfo"))     return cmd_getmempoolinfo(res);
    if (!strcmp(m, "getrawmempool"))      return cmd_getrawmempool(params, res);
    if (!strcmp(m, "getmempoolentry"))    return cmd_getmempoolentry(params, res, ec, em);
    if (!strcmp(m, "getmempoolancestors"))   return cmd_getmempoolancestors(params, res, ec, em);
    if (!strcmp(m, "getmempooldescendants")) return cmd_getmempooldescendants(params, res, ec, em);
    if (!strcmp(m, "estimatesmartfee"))   return cmd_estimatesmartfee(params, res, ec, em);
    if (!strcmp(m, "prioritisetransaction"))      return cmd_prioritisetransaction(params, res, ec, em);
    if (!strcmp(m, "getprioritisedtransactions")) return cmd_getprioritisedtransactions(res);
    if (!strcmp(m, "submitblock"))        return cmd_submitblock(params, res, ec, em);
    if (!strcmp(m, "sendrawtransaction")) return cmd_sendrawtransaction(params, res, ec, em);
    return -1;
}
