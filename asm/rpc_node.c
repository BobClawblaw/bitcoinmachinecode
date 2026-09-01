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
#include "daemon/asmap.h"   /* mapped_as, when -asmap is loaded */
#include "mempool_entry.h"
#include "version_gen.h"
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>   /* atof/atol/atoll -- implicitly declared before 2026-08-25,
                        * which silently corrupted their return values */
#include <pthread.h>
#include <unistd.h>  /* getcwd -- implicitly declared until 2026-08-27, which on
                      * this ABI means int, truncating the returned pointer */
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

/* live network state (see rpc_node.h): hooks into daemon/dialer.c, set by
 * main.c so standalone links of this file carry no dialer dependency. */
static int         (*g_net_reachable_fn)(int);
static const char* (*g_i2p_b32_fn)(void);
static char g_onion_local[80]; static int g_onion_local_port;
void rpc_node_set_net_hooks(int (*reachable)(int), const char* (*i2p_b32)(void)){
    g_net_reachable_fn = reachable; g_i2p_b32_fn = i2p_b32;
}
void rpc_node_set_onion_local(const char* onion, int port){
    snprintf(g_onion_local, sizeof g_onion_local, "%s", onion ? onion : "");
    g_onion_local_port = port;
}
/* BMC_NET_* ids (daemon/netaddr.h) without the include: 1 ipv4, 2 ipv6,
 * 4 torv3, 5 i2p, 6 cjdns */
static int net_reach(int bmc_id, int dflt){
    return g_net_reachable_fn ? (g_net_reachable_fn(bmc_id) ? 1 : 0) : dflt;
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
      rj_arr_push(nets, net_entry("ipv4",  net_reach(1, 1)));
      rj_arr_push(nets, net_entry("ipv6",  net_reach(2, 1)));
      rj_arr_push(nets, net_entry("onion", net_reach(4, 0)));
      rj_arr_push(nets, net_entry("i2p",   net_reach(5, 0)));
      rj_arr_push(nets, net_entry("cjdns", net_reach(6, 0)));
      rj_obj_set(o, "networks", nets); }
    rj_obj_set(o, "relayfee", rj_numf("%.8f", 0.00001000));
    rj_obj_set(o, "incrementalfee", rj_numf("%.8f", 0.00001000));
    { rj_val* la = rj_arr();
      if (g_onion_local[0]){
          rj_val* e = rj_obj();
          rj_obj_set(e, "address", rj_str(g_onion_local));
          rj_obj_set(e, "port", rj_numf("%d", g_onion_local_port));
          rj_obj_set(e, "score", rj_numf("%d", 1));
          rj_arr_push(la, e);
      }
      { const char* b32 = g_i2p_b32_fn ? g_i2p_b32_fn() : 0;
        if (b32 && b32[0]){
            rj_val* e = rj_obj();
            rj_obj_set(e, "address", rj_str(b32));
            rj_obj_set(e, "port", rj_numf("%d", 0));   /* Core lists i2p with port 0 */
            rj_obj_set(e, "score", rj_numf("%d", 1));
            rj_arr_push(la, e);
        } }
      rj_obj_set(o, "localaddresses", la); }
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
            { bmc_addr_t pa; const char* nn = "ipv4";
              if (bmc_addr_from_string_port(&pa, p->addr, 0)) nn = bmc_net_name(pa.net);
              rj_obj_set(o, "network", rj_str(nn)); }
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
/* ---- the address book, version 2 (2026-08-28): every BIP155 network.
 * Injected as pointers (no-link-fanout, as before), now with the v2 record
 * shape. rpc_node_set_addrbook_dir opens the real book read-only and
 * re-reads it per call (the download worker is the writer). */
#include "daemon/netaddr.h"
#include "daemon/addrbook.h"
static long (*g_ab_count)(void*);
static int  (*g_ab_get)(void*, long, ab2_rec_t*);
static void* g_ab;
static char  g_ab_dir[512];

void rpc_node_set_addrbook(void* ab, long (*count)(void*),
                           int (*get)(void*, long, ab2_rec_t*)){
    g_ab = ab; g_ab_count = count; g_ab_get = get;
}
static long real_ab_count(void* b){ ab2_refresh((ab2_t*)b); return ab2_count((ab2_t*)b); }
static int  real_ab_get(void* b, long i, ab2_rec_t* r){ return ab2_get((const ab2_t*)b, i, r); }
void rpc_node_set_addrbook_dir(const char* dir){
    snprintf(g_ab_dir, sizeof g_ab_dir, "%s", dir);
    ab2_t* b = ab2_open(dir, 0);
    if (b) rpc_node_set_addrbook(b, real_ab_count, real_ab_get);
}
/* the book may not exist yet at boot (created by the worker's first add) */
static void ab_late_open(void){
    if (!g_ab && g_ab_dir[0]){ ab2_t* b = ab2_open(g_ab_dir, 0); if (b) rpc_node_set_addrbook(b, real_ab_count, real_ab_get); }
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
static int cmd_getnodeaddresses(const rj_val* params, rj_val** res, long* ec, const char** em){
    long want = 1;
    const char* net = NULL;
    if (params && params->typ == RJ_ARR){
        if (params->nitems >= 1 && params->items[0]->typ == RJ_NUM)
            want = atol(params->items[0]->str);
        if (params->nitems >= 2 && params->items[1]->typ == RJ_STR)
            net = params->items[1]->str;
    }
    rj_val* arr = rj_arr();
    int want_net = -1;
    if (net){
        want_net = bmc_net_from_name(net);
        /* Core raises on a name it does not know rather than answering an
         * empty list, which would read as "we have none of those" */
        if (want_net < 0){ rj_free(arr); *ec = -8; *em = "Network not recognized: Cannot decode network"; return 0; }
    }
    if (want < 0){ rj_free(arr); *ec = -8; *em = "Address count out of range"; return 0; }
    ab_late_open();
    if (g_ab && g_ab_count && g_ab_get){
        long n = g_ab_count(g_ab);
        long cap = (want <= 0) ? n : want;
        if (cap > 2500) cap = 2500;
        for (long i = 0; i < n && (long)arr->nitems < cap; i++){
            ab2_rec_t r;
            if (g_ab_get(g_ab, i, &r) != 1) continue;
            if (want_net >= 0 && r.a.net != want_net) continue;
            rj_val* e = rj_obj();
            rj_obj_set(e, "time", rj_numf("%u", r.last_seen));
            rj_obj_set(e, "services", rj_numf("%llu", r.services));
            { char a[96]; bmc_addr_to_string(a, sizeof a, &r.a); rj_obj_set(e, "address", rj_str(a)); }
            rj_obj_set(e, "port", rj_numf("%u", r.a.port));
            rj_obj_set(e, "network", rj_str(bmc_net_name(r.a.net)));
            rj_arr_push(arr, e);
        }
    }
    *res = arr;
    return 1;
}
/* getorphantxs ( verbosity ) -- what is sitting in the orphan pool.
 *
 * The pool lives in the download worker; the parent reads the snapshot that
 * worker publishes into shared memory (see node_status_t.orphans). That
 * snapshot deliberately carries no transaction bytes, so:
 *   verbosity 0 -> array of txids            (Core-compatible)
 *   verbosity 1 -> objects with details      (a subset of Core's fields)
 *   verbosity 2 -> Core adds "hex"; REFUSED here rather than silently
 *                  returning verbosity-1 output, because a caller asking for
 *                  hex and getting none without being told is worse than an
 *                  error that says why.
 *
 * Fields Core has that this does not: wtxid, vsize, weight, expiration, and
 * `from` (the peers that sent it). `parents` -- how many inputs we are still
 * missing -- is ours, and is the thing you actually want when asking why a
 * transaction is stuck. */
static int cmd_getorphantxs(const rj_val* params, rj_val** res, long* ec, const char** em){
    long verbosity = 0;
    if (params && params->typ == RJ_ARR && params->nitems >= 1 && params->items[0]->typ == RJ_NUM)
        verbosity = atol(params->items[0]->str);
    if (verbosity < 0 || verbosity > 2){
        *ec = -8; *em = "verbosity must be 0, 1 or 2"; return 0; }
    if (verbosity == 2){
        *ec = -8;
        *em = "verbosity 2 (transaction hex) is not available: the orphan pool lives in "
              "the download worker and only a compact snapshot is shared with the RPC "
              "server. Use verbosity 1.";
        return 0;
    }
    rj_val* arr = rj_arr();
    if (g_status){
        int n = g_status->n_orphans;
        if (n > RPC_MAX_ORPHANS) n = RPC_MAX_ORPHANS;
        long long now_ms; { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);   /* the worker stamps t_ms on this clock */
                            now_ms = (long long)ts.tv_sec*1000 + ts.tv_nsec/1000000; }
        for (int i = 0; i < n; i++){
            char hx[65];
            for (int b = 0; b < 32; b++)
                snprintf(hx + b*2, 3, "%02x", g_status->orphans[i].txid[31-b]);  /* display order */
            if (verbosity == 0){ rj_arr_push(arr, rj_str(hx)); continue; }
            rj_val* o = rj_obj();
            rj_obj_set(o, "txid",    rj_str(hx));
            rj_obj_set(o, "bytes",   rj_numf("%u", g_status->orphans[i].len));
            rj_obj_set(o, "parents", rj_numf("%u", g_status->orphans[i].nparent));
            { long long age = now_ms - g_status->orphans[i].t_ms;
              rj_obj_set(o, "age_ms", rj_numf("%lld", age < 0 ? 0 : age)); }
            rj_arr_push(arr, o);
        }
    }
    *res = arr;
    return 1;
}

/* getrawaddrman -- dump the address book itself.
 *
 * Core keys each entry by "<bucket>/<position>" in its new/tried tables. This
 * node's book is ONE FLAT TABLE (see getaddrmaninfo, which reports the same
 * divergence): there are no buckets to report, so entries are keyed
 * "0/<index>" under `tried`, and `new` is an empty object. Inventing bucket
 * numbers to match Core's shape would be worse than saying so.
 *
 * `source` and `source_network` are OMITTED rather than faked: Core records
 * which peer relayed each address to it and this book does not store that, so
 * there is no honest value to put there.
 *
 * `mapped_as` appears only when -asmap is loaded, exactly as in Core -- and
 * it is the same lookup the bucketing uses, so this doubles as a way to see
 * what the AS grouping is actually doing. */
static int cmd_getrawaddrman(rj_val** res){
    ab_late_open();
    long n = (g_ab && g_ab_count) ? g_ab_count(g_ab) : 0;
    rj_val* tried = rj_obj();
    if (g_ab && g_ab_get) for (long i = 0; i < n; i++){
        ab2_rec_t r;
        if (g_ab_get(g_ab, i, &r) != 1) continue;
        rj_val* e = rj_obj();
        char addr[96]; bmc_addr_to_string(addr, sizeof addr, &r.a);
        rj_obj_set(e, "address", rj_str(addr));
        rj_obj_set(e, "port",    rj_numf("%u", (unsigned)r.a.port));
        rj_obj_set(e, "network", rj_str(bmc_net_name(r.a.net)));
        rj_obj_set(e, "services", rj_numf("%llu", (unsigned long long)r.services));
        rj_obj_set(e, "time",     rj_numf("%u", (unsigned)r.last_seen));
        if (asmap_active()){
            unsigned as = asmap_lookup_net(r.a.net, r.a.addr, r.a.len);
            if (as) rj_obj_set(e, "mapped_as", rj_numf("%u", as));
        }
        char key[32]; snprintf(key, sizeof key, "0/%ld", i);
        rj_obj_set(tried, key, e);
    }
    rj_val* o = rj_obj();
    rj_obj_set(o, "new", rj_obj());          /* no new/tried split in this book */
    rj_obj_set(o, "tried", tried);
    *res = o;
    return 1;
}

/* getaddrmaninfo -- Core reports new/tried/total per network. This node's
 * address book has no new/tried distinction (one flat table), so every
 * record counts as `tried` (they are addresses we have recorded, and the
 * book is fed by successful contact) and `new` is 0. Stated here and in the
 * parity docs rather than split arbitrarily. */
static int cmd_getaddrmaninfo(rj_val** res){
    ab_late_open();
    long n = (g_ab && g_ab_count) ? g_ab_count(g_ab) : 0;
    long per[7] = {0};
    if (g_ab && g_ab_get) for (long i = 0; i < n; i++){ ab2_rec_t r; if (g_ab_get(g_ab, i, &r) == 1 && r.a.net < 7) per[r.a.net]++; }
    rj_val* o = rj_obj();
    static const char* nets[] = { "ipv4", "ipv6", "onion", "i2p", "cjdns" };
    static const int   netid[] = { BMC_NET_IPV4, BMC_NET_IPV6, BMC_NET_TORV3, BMC_NET_I2P, BMC_NET_CJDNS };
    for (int i = 0; i < 5; i++) {
        rj_val* e = rj_obj();
        long v = per[netid[i]];
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
/* The configured relay floors, sat/kvB; main.c sets them from bitcoin.conf
 * (rpc_node_set_relay_floors). Defaults are Core v30's: 100 = 0.1 sat/vB. */
static unsigned long long g_minrelay_satkvb = 100, g_incremental_satkvb = 100;
void rpc_node_set_relay_floors(unsigned long long minrelay_satkvb, unsigned long long incremental_satkvb){
    if (minrelay_satkvb) g_minrelay_satkvb = minrelay_satkvb;
    if (incremental_satkvb) g_incremental_satkvb = incremental_satkvb;
}
#define MEMPOOL_MINFEE_BTC ((double)g_minrelay_satkvb / 1e8)      /* min relay fee, BTC/kvB */

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
    rj_obj_set(o, "incrementalrelayfee", rj_numf("%.8f", (double)g_incremental_satkvb / 1e8));
    rj_obj_set(o, "unbroadcastcount", rj_numf("%d", 0));
    /* the real policy value, not a literal: reporting a setting the
     * operator cannot change was the honesty gap the audit called out */
    rj_obj_set(o, "permitbaremultisig", rj_bool(g_status ? g_status->permit_bare_multisig : 1));  /* standard relay policy */
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

/* addpeeraddress "address" port ( tried ) -- Core's test/ops hook that
 * inserts one address into the address manager. Goes over the control
 * channel because the download worker is the book's only writer (2026-08-28:
 * the version-2 book accepts any BIP155 network, so this is also how an
 * operator seeds an onion/i2p/cjdns peer by hand). Core's result shape:
 * {success: bool, error?: "failed-adding-to-new"}. */
static int cmd_addpeeraddress(const rj_val* params, rj_val** res, long* ec, const char** em){
    const char* addr = (params && params->typ == RJ_ARR && params->nitems >= 1 &&
                        params->items[0]->typ == RJ_STR) ? params->items[0]->str : NULL;
    long port = (params && params->typ == RJ_ARR && params->nitems >= 2 &&
                 params->items[1]->typ == RJ_NUM) ? atol(params->items[1]->str) : -1;
    int tried = (params && params->typ == RJ_ARR && params->nitems >= 3 &&
                 params->items[2]->typ == RJ_BOOL) ? (params->items[2]->str[0] == '1') : 0;
    if (!addr || port < 0){ *ec = -8; *em = "addpeeraddress requires an address and a port"; return 0; }
    if (port > 65535){ *ec = -8; *em = "Invalid port"; return 0; }
    bmc_addr_t a;
    if (!bmc_addr_from_string(&a, addr)){ *ec = -8; *em = "Invalid address"; return 0; }
    char hp[128]; a.port = (unsigned short)port; bmc_addr_to_string_port(hp, sizeof hp, &a);
    int r = 0;
    if (!ctl_send(RPC_CTL_ADDPEERADDRESS, hp, tried, ec, em, &r)) return 0;
    rj_val* o = rj_obj();
    if (r != 1) rj_obj_set(o, "error", rj_str(tried ? "failed-adding-to-tried" : "failed-adding-to-new"));
    rj_obj_set(o, "success", rj_bool(r == 1));
    *res = o;
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

/* the txo-spender index lives in rpc_chain.c; weak so the mempool-only test
 * binaries that do not link the chain side still build (then: unavailable) */
extern int rpc_chain_txospender_available(void) __attribute__((weak));
extern int rpc_chain_txospender_lookup(const unsigned char txid_wire[32], unsigned vout, unsigned char spender_wire[32],
                                       long* height_out, unsigned char blockhash_wire[32], unsigned char* txout, long txcap, long* txlen_out) __attribute__((weak));
static int cmd_gettxspendingprevout(const rj_val* params, rj_val** res,
                                    long* ec, const char** em){
    if (!params || params->typ != RJ_ARR || params->nitems < 1 ||
        params->items[0]->typ != RJ_ARR){
        *ec = -8; *em = "Invalid parameter, outputs is not an array"; return 0; }
    const rj_val* list = params->items[0];
    if (list->nitems == 0){
        *ec = -8; *em = "Invalid parameter, outputs are missing"; return 0; }
    /* options (Core): mempool_only defaults to "true if txospenderindex
     * unavailable, otherwise false"; return_spending_tx defaults to false */
    int index_ok = (rpc_chain_txospender_available && rpc_chain_txospender_available()) ? 1 : 0;
    int mempool_only = !index_ok, return_tx = 0;
    if (params->nitems >= 2 && params->items[1]->typ == RJ_OBJ){
        const rj_val* o = params->items[1];
        rj_val* mo = rj_obj_get((rj_val*)o, "mempool_only"); rj_val* rt = rj_obj_get((rj_val*)o, "return_spending_tx");
        if (mo){ if (mo->typ != RJ_BOOL){ *ec = -3; *em = "JSON value of type string is not of expected type bool"; return 0; } mempool_only = mo->str[0] == '1'; }
        if (rt){ if (rt->typ != RJ_BOOL){ *ec = -3; *em = "JSON value of type string is not of expected type bool"; return 0; } return_tx = rt->str[0] == '1'; }
    } else if (params->nitems >= 2 && params->items[1]->typ != RJ_NULL){
        *ec = -3; *em = "JSON value of type string is not of expected type object"; return 0; }
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
    int* pending = malloc(sizeof(int) * (list->nitems + 1)); int npending = 0;
    if (!pending){ *ec = -7; *em = "oom"; return 0; }
    if (g_mph.mp) mpl();
    for (size_t i = 0; i < list->nitems; i++){
        const rj_val* e = list->items[i];
        unsigned char want[32]; int found_mp = 0;
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
                if (return_tx){ char* th = malloc(me.len * 2 + 1); if (th){ for (unsigned long b = 0; b < me.len; b++){ th[b*2] = HEXD[me.tx[b]>>4]; th[b*2+1] = HEXD[me.tx[b]&15]; } th[me.len*2] = 0; rj_obj_set(o, "spendingtx", rj_str(th)); free(th); } }
                found_mp = 1;
                break;
            }
        }
        if (!found_mp && !mempool_only) pending[npending++] = (int)i;   /* the index answers these below */
        rj_arr_push(arr, o);
    }
    if (g_mph.mp) mpu();
    if (npending){
        /* Core: "Mempool lacks a relevant spend, and txospenderindex is unavailable." */
        if (!index_ok || !rpc_chain_txospender_lookup){ rj_free(arr); free(pending); *ec = -1; *em = "Mempool lacks a relevant spend, and txospenderindex is unavailable."; return 0; }
        static unsigned char txbuf[4u << 20];
        for (int q = 0; q < npending; q++){
            int i = pending[q]; rj_val* o = arr->items[i]; const rj_val* e = list->items[i];
            unsigned char want[32]; gtsp_hex32_wire(rj_obj_get((rj_val*)e, "txid")->str, want);
            unsigned vout = (unsigned)atol(rj_obj_get((rj_val*)e, "vout")->str);
            unsigned char sp[32], bh[32]; long h = -1, tl = 0;
            if (!rpc_chain_txospender_lookup(want, vout, sp, &h, bh, return_tx ? txbuf : NULL, (long)sizeof txbuf, &tl)) continue;
            char hx[65];
            for (int b = 0; b < 32; b++){ unsigned char v = sp[31-b]; hx[b*2] = HEXD[v>>4]; hx[b*2+1] = HEXD[v&15]; } hx[64] = 0;
            rj_obj_set(o, "spendingtxid", rj_str(hx));
            if (return_tx && tl > 0){ char* th = malloc((size_t)tl * 2 + 1); if (th){ for (long b = 0; b < tl; b++){ th[b*2] = HEXD[txbuf[b]>>4]; th[b*2+1] = HEXD[txbuf[b]&15]; } th[tl*2] = 0; rj_obj_set(o, "spendingtx", rj_str(th)); free(th); } }
            for (int b = 0; b < 32; b++){ unsigned char v = bh[31-b]; hx[b*2] = HEXD[v>>4]; hx[b*2+1] = HEXD[v&15]; }
            rj_obj_set(o, "blockhash", rj_str(hx));
        }
    }
    free(pending);
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

/* ==== fee estimation: estimatesmartfee / estimaterawfee =================
 * Core rpc/fees.cpp over daemon/fee_estimator.c (the CBlockPolicyEstimator
 * port). The estimator lives in the mempool hooks' `feeest` region; the
 * functions are WEAK externs so rpc_node.o keeps its no-link-fanout
 * property (test binaries without fee_estimator.c see NULL and answer the
 * way a fresh estimator does: "Insufficient data", blocks 0). */
#include "daemon/fee_estimator.h"
extern unsigned long long fest_estimate_smart(const void*, int, int, int*, fest_result_t*) __attribute__((weak));
extern unsigned long long fest_estimate_raw(const void*, int, double, int, fest_result_t*) __attribute__((weak));
extern unsigned fest_highest_target(const void*, int) __attribute__((weak));

static const char* rj_type_name(const rj_val* v){
    if (!v) return "null";
    switch (v->typ){ case RJ_NULL: return "null"; case RJ_BOOL: return "bool"; case RJ_NUM: return "number";
                     case RJ_STR: return "string"; case RJ_ARR: return "array"; case RJ_OBJ: return "object"; default: return "null"; }
}
/* Core ParseConfirmTarget: "Invalid conf_target, must be between 1 and <max>" */
static int fee_parse_target(const rj_val* params, unsigned max_target, long* ec, const char** em, int* out){
    static char msg[96];
    const rj_val* v = (params && params->typ == RJ_ARR && params->nitems >= 1) ? params->items[0] : 0;
    if (!v || v->typ != RJ_NUM){
        snprintf(msg, sizeof msg, "JSON value of type %s is not of expected type number", rj_type_name(v));
        *ec = -3; *em = msg; return 0; }
    long t = atol(v->str);
    if (t < 1 || (unsigned long)t > max_target){
        snprintf(msg, sizeof msg, "Invalid conf_target, must be between 1 and %u", max_target);
        *ec = -8; *em = msg; return 0; }
    *out = (int)t;
    return 1;
}
static rj_val* fee_btc_per_kvb(unsigned long long satkvb){
    return rj_numf("%llu.%08llu", satkvb / 100000000ULL, satkvb % 100000000ULL);   /* ValueFromAmount */
}
static rj_val* fee_dbl(double v){ return rj_numf("%.16g", v); }   /* UniValue: setprecision(16) */
/* C round(): half away from zero. Beyond 2^53 a double has no fraction to
 * round (the INF bucket bound is 1e99 -- a cast would overflow to 0). */
static double fee_round(double v){
    if (v >= 9007199254740992.0 || v <= -9007199254740992.0) return v;
    return v < 0 ? -(double)(unsigned long long)(-v + 0.5) : (double)(unsigned long long)(v + 0.5);
}

static int cmd_estimatesmartfee(const rj_val* params, rj_val** res, long* ec, const char** em){
    const void* fe = g_mph.feeest;
    unsigned max_target = (fe && fest_highest_target) ? fest_highest_target(fe, FEST_LONG) : 1008u;
    int target = 0;
    if (!fee_parse_target(params, max_target, ec, em, &target)) return 0;
    int conservative = 0;
    if (params->nitems >= 2 && params->items[1]->typ != RJ_NULL){
        const rj_val* mv = params->items[1];
        if (mv->typ != RJ_STR){ *ec = -3; *em = "JSON value is not a string as expected"; return 0; }
        /* FeeModeFromString: case-insensitive over unset/economical/conservative */
        char lo[16]; size_t i = 0;
        for (; mv->str[i] && i + 1 < sizeof lo; i++) lo[i] = (char)(mv->str[i] >= 'A' && mv->str[i] <= 'Z' ? mv->str[i] + 32 : mv->str[i]);
        lo[i] = 0;
        if (mv->str[i] || (strcmp(lo, "unset") && strcmp(lo, "economical") && strcmp(lo, "conservative"))){
            *ec = -8; *em = "Invalid estimate_mode parameter, must be one of: \"unset\", \"economical\", \"conservative\"";
            return 0; }
        conservative = !strcmp(lo, "conservative");
    }
    int returned = 0; unsigned long long feerate = 0;
    if (fe && fest_estimate_smart){
        mpl();
        feerate = fest_estimate_smart(fe, target, conservative, &returned, 0);
        mpu();
    }
    rj_val* o = rj_obj();
    if (feerate != 0){
        /* max(estimate, mempool min fee, min relay feerate) */
        unsigned long long minpool = 0;
        if (g_mph.polstate && g_mph.min_fee){ mpl(); minpool = g_mph.min_fee(g_mph.polstate); mpu(); }
        unsigned long long minrelay = g_mph.min_relay_satkvb ? g_mph.min_relay_satkvb : 100ULL;
        if (minpool > feerate) feerate = minpool;
        if (minrelay > feerate) feerate = minrelay;
        rj_obj_set(o, "feerate", fee_btc_per_kvb(feerate));
    } else {
        rj_val* errs = rj_arr();
        rj_arr_push(errs, rj_str("Insufficient data or no feerate found"));
        rj_obj_set(o, "errors", errs);
    }
    rj_obj_set(o, "blocks", rj_numf("%d", returned));
    *res = o;
    return 1;
}

static rj_val* fee_bucket_obj(const fest_bucket_t* b){
    rj_val* o = rj_obj();
    rj_obj_set(o, "startrange", fee_dbl(fee_round(b->start)));
    rj_obj_set(o, "endrange", fee_dbl(fee_round(b->end)));
    rj_obj_set(o, "withintarget", fee_dbl(fee_round(b->within_target * 100.0) / 100.0));
    rj_obj_set(o, "totalconfirmed", fee_dbl(fee_round(b->total_confirmed * 100.0) / 100.0));
    rj_obj_set(o, "inmempool", fee_dbl(fee_round(b->in_mempool * 100.0) / 100.0));
    rj_obj_set(o, "leftmempool", fee_dbl(fee_round(b->left_mempool * 100.0) / 100.0));
    return o;
}
/* estimaterawfee conf_target (threshold=0.95): one object per horizon that
 * tracks the target -- feerate/decay/scale/pass[/fail], or on no answer
 * decay/scale/fail/errors -- with Core's rounding (rpc/fees.cpp). */
static int cmd_estimaterawfee(const rj_val* params, rj_val** res, long* ec, const char** em){
    const void* fe = g_mph.feeest;
    unsigned max_target = (fe && fest_highest_target) ? fest_highest_target(fe, FEST_LONG) : 1008u;
    int target = 0;
    if (!fee_parse_target(params, max_target, ec, em, &target)) return 0;
    double threshold = 0.95;
    if (params->nitems >= 2 && params->items[1]->typ != RJ_NULL){
        const rj_val* tv = params->items[1];
        if (tv->typ != RJ_NUM){
            static char msg[96]; snprintf(msg, sizeof msg, "JSON value of type %s is not of expected type number", rj_type_name(tv));
            *ec = -3; *em = msg; return 0; }
        threshold = atof(tv->str);
    }
    if (threshold < 0 || threshold > 1){ *ec = -8; *em = "Invalid threshold"; return 0; }
    static const char* const names[3] = { "short", "medium", "long" };
    static const unsigned defaults[3] = { 12u, 48u, 1008u };
    rj_val* o = rj_obj();
    for (int h = 0; h < 3; h++){
        unsigned hi = (fe && fest_highest_target) ? fest_highest_target(fe, h) : defaults[h];
        if ((unsigned)target > hi) continue;
        fest_result_t r; memset(&r, 0, sizeof r);
        r.pass.start = r.pass.end = r.fail.start = r.fail.end = -1;
        unsigned long long feerate = 0;
        if (fe && fest_estimate_raw){ mpl(); feerate = fest_estimate_raw(fe, target, threshold, h, &r); mpu(); }
        else { r.decay = h == 0 ? 0.962 : h == 1 ? 0.9952 : 0.99931; r.scale = h == 0 ? 1 : h == 1 ? 2 : 24; }
        rj_val* ho = rj_obj();
        if (feerate != 0){
            rj_obj_set(ho, "feerate", fee_btc_per_kvb(feerate));
            rj_obj_set(ho, "decay", fee_dbl(r.decay));
            rj_obj_set(ho, "scale", rj_numf("%u", r.scale));
            rj_obj_set(ho, "pass", fee_bucket_obj(&r.pass));
            if (r.fail.start != -1) rj_obj_set(ho, "fail", fee_bucket_obj(&r.fail));
        } else {
            rj_obj_set(ho, "decay", fee_dbl(r.decay));
            rj_obj_set(ho, "scale", rj_numf("%u", r.scale));
            rj_obj_set(ho, "fail", fee_bucket_obj(&r.fail));
            rj_val* errs = rj_arr();
            rj_arr_push(errs, rj_str("Insufficient data or no feerate found which meets threshold"));
            rj_obj_set(ho, "errors", errs);
        }
        rj_obj_set(o, names[h], ho);
    }
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
#define SRT_POLL_US   500       /* was 3000: a 10k-entry mempool.dat reload took ~20 min at the submitter's poll rate (2026-09-01) */

/* ==== savemempool / importmempool -- Core's mempool.dat ====================
 * The pool is shared memory the parent can read directly under the same lock
 * getrawmempool uses, so the DUMP happens here. The LOAD cannot: admitting a
 * transaction is the worker's job, so import re-submits each one through the
 * same channel sendrawtransaction uses and every entry gets the full
 * consensus and policy treatment on the way back in. Core re-validates on
 * load too -- a dump is a hint about what was interesting, never a licence
 * to skip checks.
 *
 * Paths are relative to the process CWD, which is the per-chain datadir (the
 * daemon chdirs there at boot, the same reason bmcwallet.dat resolves), so
 * "mempool.dat" lands beside the chain data exactly as in Core.
 */
extern long mempool_dump_write(const char* path, const unsigned char* const* txs,
                               const unsigned long* lens, const long long* times,
                               const long long* deltas, long n,
                               const unsigned char* extra_txids,
                               const long long* extra_deltas, long n_extra);
extern long mempool_dump_read(const char* path,
                              int (*sink)(void*, const unsigned char*, unsigned long,
                                          long long, long long),
                              void* ctx, char* err, unsigned long errcap);

#define MPD_MAX_DUMP 200000

/* The dump itself, without the RPC wrapper, so the daemon's own
 * -persistmempool path at shutdown and the savemempool RPC cannot drift apart
 * -- two copies of a serialiser is precisely how one of them quietly stops
 * matching the format. Returns transactions written, or -1. */
long rpc_node_mempool_save(const char* path){
    if (!g_mph.mp) return -1;
    static const unsigned char* txs[MPD_MAX_DUMP];
    static unsigned long        lens[MPD_MAX_DUMP];
    static long long            times[MPD_MAX_DUMP], deltas[MPD_MAX_DUMP];
    long n = 0;
    mpl();
    unsigned long slots = mp_slot_count(g_mph.mp);
    for (unsigned long i = 0; i < slots && n < MPD_MAX_DUMP; i++){
        mp_ent e;
        if (mp_slot(g_mph.mp, i, &e) != 1) continue;
        txs[n]    = e.tx;
        lens[n]   = e.len;
        times[n]  = g_mph.time_of ? (long long)g_mph.time_of(e.txid) : 0;
        deltas[n] = (long long)pri_delta_of(e.txid);
        n++;
    }
    /* Written under the pool lock ON PURPOSE: the entry pointers above are
     * into the shared blob, and releasing first would let an eviction move
     * the bytes out from under the writer. */
    long w = mempool_dump_write(path ? path : "mempool.dat",
                                txs, lens, times, deltas, n, NULL, NULL, 0);
    mpu();
    return w;
}

static int cmd_savemempool(rj_val** res, long* ec, const char** em){
    if (!g_mph.mp){ *ec = -4; *em = "no mempool is attached to this RPC server"; return 0; }
    static const unsigned char* txs[MPD_MAX_DUMP];
    static unsigned long        lens[MPD_MAX_DUMP];
    static long long            times[MPD_MAX_DUMP], deltas[MPD_MAX_DUMP];
    long n = 0;
    mpl();
    unsigned long slots = mp_slot_count(g_mph.mp);
    for (unsigned long i = 0; i < slots && n < MPD_MAX_DUMP; i++){
        mp_ent e;
        if (mp_slot(g_mph.mp, i, &e) != 1) continue;
        txs[n]    = e.tx;
        lens[n]   = e.len;
        times[n]  = g_mph.time_of ? (long long)g_mph.time_of(e.txid) : 0;
        deltas[n] = (long long)pri_delta_of(e.txid);
        n++;
    }
    /* The write happens under the pool lock ON PURPOSE: the entry pointers
     * above are into the shared blob, and releasing the lock first would let
     * an eviction move the bytes out from under the writer. */
    long w = mempool_dump_write("mempool.dat", txs, lens, times, deltas, n, NULL, NULL, 0);
    mpu();
    if (w < 0){ *ec = -1; *em = "unable to dump mempool to disk"; return 0; }

    char cwd[1024]; char full[1200];
    if (getcwd(cwd, sizeof cwd)) snprintf(full, sizeof full, "%s/mempool.dat", cwd);
    else snprintf(full, sizeof full, "mempool.dat");
    rj_val* o = rj_obj();
    rj_obj_set(o, "filename", rj_str(full));
    *res = o;
    return 1;
}

typedef struct {
    long accepted, rejected;
    /* entries rejected for MISSING INPUTS are kept for retry passes: the dump
     * is written in pool order, not parent-before-child, so a child ahead of
     * its parent fails on the first pass and succeeds once the parent is in. */
    unsigned char** retry; unsigned long* retry_len; long nretry, retry_cap;
    int collecting;
    int aborted;            /* shutdown requested, or the worker stopped answering */
    int consec_timeouts;    /* entries in a row that drew no ack at all */
    const char* abort_why;
} mpd_import_ctx;
/* The parent's shutdown flag (main.c installs it): a reload that waits 90 s
 * per entry for a worker that is gone would otherwise hold SIGTERM off for
 * hours -- the 2026-09-01 01:07 "deactivating" stall. */
static const volatile sig_atomic_t* g_mpd_shutdown_flag;
void rpc_node_set_shutdown_flag(const volatile sig_atomic_t* f){ g_mpd_shutdown_flag = f; }
static int mpd_import_one(void* vctx, const unsigned char* tx, unsigned long len,
                          long long t, long long d){
    (void)t; (void)d;   /* entry time and fee delta are not restorable here --
                         * see the divergence note at the call site */
    mpd_import_ctx* c = (mpd_import_ctx*)vctx;
    { mpd_import_ctx* c0 = (mpd_import_ctx*)vctx; if (c0->aborted){ c0->rejected++; return 0; } }   /* aborted: drain the rest without waiting */
    if (!g_status_rw) return -1;
    node_status_t* st = g_status_rw;
    pthread_mutex_lock(&g_submit_lock);
    if (len > RPC_TXSUBMIT_MAX){ pthread_mutex_unlock(&g_submit_lock); c->rejected++; return 0; }
    memcpy((void*)st->tx_submit_buf, tx, len);
    st->tx_submit_len = len;
    st->tx_submit_test = 0;
    st->tx_submit_pkg_n = 0;
    st->tx_submit_reason[0] = 0;
    unsigned long long myseq = st->tx_submit_seq + 1;
    __sync_synchronize();
    st->tx_submit_seq = myseq;
    int waited = 0, ok = 0, acked = 0;
    while (waited < SRT_WAIT_MS*1000){
        if (st->tx_submit_ack == myseq){ ok = (st->tx_submit_result == 1); acked = 1; break; }
        if (g_mpd_shutdown_flag && *g_mpd_shutdown_flag){ c->aborted = 1; c->abort_why = "shutdown requested"; break; }
        struct timespec ts = {0, SRT_POLL_US*1000L}; nanosleep(&ts, NULL);
        waited += SRT_POLL_US;
    }
    if (acked) c->consec_timeouts = 0;
    else if (!c->aborted && ++c->consec_timeouts >= 2){ c->aborted = 1; c->abort_why = "the worker is not answering"; }
    int missing = !ok && strstr((const char*)st->tx_submit_reason, "missing") != NULL;
    pthread_mutex_unlock(&g_submit_lock);
    if (ok) c->accepted++;
    else if (missing && c->collecting){
        if (c->nretry == c->retry_cap){
            long ncap = c->retry_cap ? c->retry_cap * 2 : 64;
            unsigned char** nr = realloc(c->retry, (size_t)ncap * sizeof *nr);
            unsigned long* nl = realloc(c->retry_len, (size_t)ncap * sizeof *nl);
            if (!nr || !nl){ free(nr); free(nl); c->rejected++; return 0; }
            c->retry = nr; c->retry_len = nl; c->retry_cap = ncap;
        }
        unsigned char* cp = malloc(len);
        if (!cp){ c->rejected++; return 0; }
        memcpy(cp, tx, len); c->retry[c->nretry] = cp; c->retry_len[c->nretry] = len; c->nretry++;
    } else c->rejected++;
    return 0;                       /* a rejected entry is not a file error */
}
/* Re-offer the missing-input rejects until a pass admits nothing more. Each
 * pass can only shrink the list, so this terminates; in practice 1-2 passes. */
static long mpd_retry_passes(mpd_import_ctx* c){
    long passes = 0, gained = 0;
    c->collecting = 0;
    while (c->nretry){
        long n = c->nretry, before = c->accepted;
        unsigned char** list = c->retry; unsigned long* lens = c->retry_len;
        c->retry = 0; c->retry_len = 0; c->nretry = c->retry_cap = 0; c->collecting = 1;
        long rej0 = c->rejected;
        for (long i = 0; i < n; i++){ mpd_import_one(c, list[i], lens[i], 0, 0); free(list[i]); }
        free(list); free(lens);
        passes++; gained += c->accepted - before;
        c->collecting = 0;
        if (c->accepted == before){ c->rejected = rej0 + c->nretry; break; }   /* no progress: the rest are real rejects */
    }
    for (long i = 0; i < c->nretry; i++) free(c->retry[i]);
    free(c->retry); free(c->retry_len); c->retry = 0; c->retry_len = 0; c->nretry = 0;
    return passes ? gained : 0;
}

/* The load half, likewise shared with the boot path. Returns transactions
 * ACCEPTED, or -1 if the file could not be read at all. A dump that is
 * missing is not an error -- a node that has never saved one, or a fresh
 * datadir, is the ordinary case. */
long rpc_node_mempool_load(const char* path){
    if (!g_status_rw) return -1;
    mpd_import_ctx c; memset(&c, 0, sizeof c); c.collecting = 1;
    char err[160]; err[0] = 0;
    long r = mempool_dump_read(path ? path : "mempool.dat",
                               mpd_import_one, &c, err, sizeof err);
    if (r < 0){ mpd_retry_passes(&c); return -1; }
    long deferred = c.nretry;
    long gained = mpd_retry_passes(&c);
    fprintf(stderr, "[mempool] loaded %s: %ld accepted, %ld rejected of %ld (%ld waited for a parent, %ld of them then accepted)\n",
            path ? path : "mempool.dat", c.accepted, c.rejected, r, deferred, gained);
    return c.accepted;
}

static int cmd_importmempool(const rj_val* params, rj_val** res, long* ec, const char** em){
    const char* path = NULL;
    if (params && params->typ == RJ_ARR && params->nitems > 0 &&
        params->items[0]->typ == RJ_STR) path = params->items[0]->str;
    if (!path || !path[0]){ *ec = -8; *em = "filepath is required"; return 0; }
    if (!g_status_rw){
        *ec = -4; *em = "no download worker is attached, so nothing can admit these transactions"; return 0; }
    mpd_import_ctx c; memset(&c, 0, sizeof c); c.collecting = 1;
    char err[160]; err[0] = 0;
    long r = mempool_dump_read(path, mpd_import_one, &c, err, sizeof err);
    mpd_retry_passes(&c);
    if (r < 0){ static char m[200]; snprintf(m, sizeof m, "Unable to import mempool: %s", err[0]?err:"malformed file");
                *ec = -1; *em = m; return 0; }
    fprintf(stderr, "[rpc] importmempool %s: %ld accepted, %ld rejected of %ld\n",
            path, c.accepted, c.rejected, r);
    *res = rj_obj();               /* Core returns an empty object */
    return 1;
}

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
 * An array of more than one transaction is validated as a PACKAGE, the way
 * Core validates it: a child may spend a parent that appears earlier in the
 * same call, and the members are weighed against the fee floors together.
 * That runs through the SAME staged package path submitpackage uses, stopped
 * after its dry run -- a separate "test" implementation would be a second
 * copy of the rules, free to drift from the one that decides real
 * admissions, which is the one thing this call must never do.
 *
 * Until 2026-08-27 each member was checked independently against the mempool
 * as it stood, so a child spending an in-array parent came back
 * missing-inputs and every entry carried a package-error saying the node did
 * not implement package policy. `package-error` now means what it means in
 * Core: a genuine package-level rejection (bad ordering, an internal
 * conflict, too many transactions).
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

/* ==== submitpackage =========================================================
 * Core's shape: a package-level verdict plus one result per transaction,
 * keyed by WTXID exactly as Core keys them.
 *
 * The whole package rides one staging of the submit channel (concatenated,
 * each transaction self-delimiting) so the worker sees it as a unit -- which
 * is the point. Submitting the members one at a time is what this node could
 * already do, and it cannot accept a parent whose fee only clears the floor
 * because of its child.
 *
 * The result follows Core's schema rather than a reduced one of our own:
 * package_msg, tx-results keyed by wtxid with txid / vsize / vsize_bip141 /
 * fees{base, effective-feerate, effective-includes} / error, and Core's own
 * "package-not-validated" for members that never got an individual verdict
 * because the package was rejected as a whole.
 *
 * effective-feerate is the feerate the package was actually evaluated
 * against -- the aggregate the worker used for the fee floors -- and
 * effective-includes lists every member whose fee and vsize went into it.
 * That is exactly what the number means, so it is reported rather than
 * omitted.
 *
 * "replaced-transactions" is absent, which is Core's own convention: the
 * field is optional there and Core omits it when nothing was replaced. This
 * node does not track package-driven RBF evictions, so it never emits it.
 */
static int cmd_submitpackage(const rj_val* params, rj_val** res, long* ec, const char** em){
    /* VOID: bitcoin_cmpct.asm sets no return value (tests/test_bip152.c has
     * had it right all along). Declaring it int and checking for 1 reads
     * whatever happened to be in rax -- which silently dropped every result.
     *
     * WEAK because many targets link rpc_node.o without bitcoin_cmpct.o, and
     * the same trick bitcoin_mempool_policy.c uses for tx_parse/tx_txid keeps
     * them linking. Core keys tx-results by wtxid, so without it this call
     * cannot answer in Core's shape -- it refuses rather than keying the
     * results by something else. */
    extern void tx_wtxid(unsigned char out[32], const unsigned char* tx, unsigned long txlen)
        __attribute__((weak));
    if (!params || params->typ != RJ_ARR || params->nitems < 1 ||
        params->items[0]->typ != RJ_ARR || params->items[0]->nitems < 1){
        *ec = -8; *em = "Invalid parameter, package must be a non-empty array"; return 0; }
    const rj_val* list = params->items[0];
    if (list->nitems > RPC_PKG_MAX){
        *ec = -8; *em = "Array must contain between 1 and 25 transactions"; return 0; }
    /* AFTER the parameter checks: a malformed call gets Core's -8 whatever
     * this build links. */
    if (!tx_wtxid){
        *ec = -1;
        *em = "submitpackage is unavailable in this build: results are keyed by "
              "wtxid and the wtxid primitive is not linked in";
        return 0;
    }
    if (!g_status_rw){
        *ec = -4; *em = "no download worker is attached, so nothing can validate a package"; return 0; }

    int n = (int)list->nitems;
    static unsigned char raw[RPC_TXSUBMIT_MAX];
    static unsigned long off[RPC_PKG_MAX];
    static unsigned long tlen[RPC_PKG_MAX];
    unsigned long total = 0;
    for (int i = 0; i < n; i++){
        const rj_val* e = list->items[i];
        if (!e || e->typ != RJ_STR || !e->str){
            *ec = -22; *em = "TX decode failed"; return 0; }
        size_t hl = strlen(e->str);
        if (hl % 2 || hl/2 == 0 || total + hl/2 > sizeof raw){
            *ec = -22; *em = "TX decode failed"; return 0; }
        for (size_t k = 0; k < hl/2; k++){
            int a = srt_hex1(e->str[k*2]), b = srt_hex1(e->str[k*2+1]);
            if (a < 0 || b < 0){ *ec = -22; *em = "TX decode failed"; return 0; }
            raw[total + k] = (unsigned char)((a<<4)|b);
        }
        off[i] = total; tlen[i] = hl/2; total += hl/2;
    }

    node_status_t* st = g_status_rw;
    pthread_mutex_lock(&g_submit_lock);
    memcpy((void*)st->tx_submit_buf, raw, total);
    st->tx_submit_len = total;
    st->tx_submit_test = 0;
    st->tx_submit_pkg_n = n;
    st->tx_submit_reason[0] = 0;
    st->pkg_msg[0] = 0;
    unsigned long long myseq = st->tx_submit_seq + 1;
    __sync_synchronize();
    st->tx_submit_seq = myseq;
    int waited = 0, got = 0;
    while (waited < SRT_WAIT_MS*1000){
        if (st->tx_submit_ack == myseq){ got = 1; break; }
        struct timespec ts = {0, SRT_POLL_US*1000L}; nanosleep(&ts, NULL);
        waited += SRT_POLL_US;
    }
    static int  r_result[RPC_PKG_MAX];
    static unsigned long long r_fee[RPC_PKG_MAX], r_vsize[RPC_PKG_MAX];
    static char r_reason[RPC_PKG_MAX][64];
    char pmsg[128]; pmsg[0] = 0;
    unsigned long long eff_fee = 0, eff_vsize = 0;
    static unsigned char replaced[RPC_PKG_REPLACED_MAX][32];
    int n_replaced = 0;
    if (got){
        for (int i = 0; i < n; i++){
            r_result[i] = st->pkg_result[i];
            r_fee[i]    = st->pkg_fee[i];
            r_vsize[i]  = st->pkg_vsize[i];
            snprintf(r_reason[i], sizeof r_reason[i], "%s", (const char*)st->pkg_reason[i]);
        }
        snprintf(pmsg, sizeof pmsg, "%s", (const char*)st->tx_submit_reason);
        eff_fee = st->pkg_eff_fee; eff_vsize = st->pkg_eff_vsize;
        n_replaced = st->pkg_replaced_n;
        if (n_replaced > RPC_PKG_REPLACED_MAX) n_replaced = RPC_PKG_REPLACED_MAX;
        if (n_replaced > 0) memcpy(replaced, (const void*)st->pkg_replaced, (size_t)n_replaced * 32);
    }
    st->tx_submit_pkg_n = 0;          /* leave the channel as a single-tx one */
    pthread_mutex_unlock(&g_submit_lock);

    if (!got){
        *ec = -4; *em = "the download worker did not answer within the submission timeout"; return 0; }

    rj_val* o = rj_obj();
    rj_obj_set(o, "package_msg", rj_str(pmsg[0] ? pmsg : "success"));
    rj_val* results = rj_obj();
    for (int i = 0; i < n; i++){
        unsigned char w[32], t[32]; char whex[65], thex[65];
        tx_wtxid(w, raw + off[i], tlen[i]);
        { static unsigned char sc[1<<20];
          if (tx_txid(t, raw + off[i], tlen[i], sc, sizeof sc) != 1) continue; }
        mpe_hex(whex, w);            /* mpe_hex writes DISPLAY order already */
        mpe_hex(thex, t);
        rj_val* e = rj_obj();
        rj_obj_set(e, "txid", rj_str(thex));
        rj_obj_set(e, "vsize", rj_numf("%llu", (unsigned long long)r_vsize[i]));
        rj_obj_set(e, "vsize_bip141", rj_numf("%llu", (unsigned long long)r_vsize[i]));
        if (r_result[i]){
            rj_val* f = rj_obj();
            rj_obj_set(f, "base", mpe_amount(r_fee[i]));
            if (eff_vsize){
                /* Core reports this per KvB, as an amount */
                unsigned long long per_kvb = eff_fee * 1000ULL / eff_vsize;
                rj_obj_set(f, "effective-feerate", mpe_amount(per_kvb));
                rj_val* inc = rj_arr();
                for (int k = 0; k < n; k++){
                    if (!r_result[k]) continue;
                    unsigned char wk[32]; char wkhex[65];
                    tx_wtxid(wk, raw + off[k], tlen[k]);
                    mpe_hex(wkhex, wk);
                    rj_arr_push(inc, rj_str(wkhex));
                }
                rj_obj_set(f, "effective-includes", inc);
            }
            rj_obj_set(e, "fees", f);
        } else if (r_reason[i][0]){
            rj_obj_set(e, "error", rj_str(r_reason[i]));
        }
        rj_obj_set(results, whex, e);
    }
    rj_obj_set(o, "tx-results", results);
    /* Top level, not per member: a package's replacements are reported once,
     * as the union across its members. Always present, empty array included
     * -- Core pushes it unconditionally on this path, and a caller that
     * checks "did this replace anything" should not have to distinguish
     * "replaced nothing" from "field missing". */
    { rj_val* rep = rj_arr();
      for (int k = 0; k < n_replaced; k++){
          char rhex[65]; mpe_hex(rhex, replaced[k]);
          rj_arr_push(rep, rj_str(rhex));
      }
      rj_obj_set(o, "replaced-transactions", rep); }
    *res = o;
    return 1;
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

    /* ---- package mode: more than one transaction ------------------------
     * Staged as one unit and dry-run by txsub_package, so in-array parents
     * are visible to their children and the fee floors see the aggregate. */
    if (list->nitems > 1){
        int n = (int)list->nitems;
        static unsigned char raw[RPC_TXSUBMIT_MAX];
        unsigned long off[TMA_MAX]; unsigned long total = 0;
        for (int i = 0; i < n; i++){
            if (total + lens[i] > sizeof raw){
                *ec = -22; *em = "TX decode failed"; return 0; }
            memcpy(raw + total, stage[i], lens[i]);
            off[i] = total; total += lens[i];
        }
        pthread_mutex_lock(&g_submit_lock);
        memcpy((void*)s->tx_submit_buf, raw, total);
        s->tx_submit_len   = total;
        s->tx_submit_test  = 1;          /* dry run: pass 1 only, commits nothing */
        s->tx_submit_pkg_n = n;
        s->tx_submit_reason[0] = 0;
        s->pkg_msg[0] = 0;
        unsigned long long myseq = s->tx_submit_seq + 1;
        __sync_synchronize();
        s->tx_submit_seq = myseq;
        int waited = 0, got = 0;
        while (waited < SRT_WAIT_MS*1000){
            if (s->tx_submit_ack == myseq){ got = 1; break; }
            struct timespec ts = {0, SRT_POLL_US*1000L}; nanosleep(&ts, NULL);
            waited += SRT_POLL_US;
        }
        static int r_result[TMA_MAX];
        static unsigned long long r_fee[TMA_MAX], r_vsize[TMA_MAX];
        static char r_reason[TMA_MAX][64];
        char pmsg[128]; pmsg[0] = 0;
        unsigned long long eff_fee = 0, eff_vsize = 0;
        if (got){
            for (int i = 0; i < n; i++){
                r_result[i] = s->pkg_result[i];
                r_fee[i]    = s->pkg_fee[i];
                r_vsize[i]  = s->pkg_vsize[i];
                snprintf(r_reason[i], sizeof r_reason[i], "%s", (const char*)s->pkg_reason[i]);
            }
            snprintf(pmsg, sizeof pmsg, "%s", (const char*)s->tx_submit_reason);
            eff_fee = s->pkg_eff_fee; eff_vsize = s->pkg_eff_vsize;
        }
        s->tx_submit_pkg_n = 0;
        s->tx_submit_test  = 0;
        pthread_mutex_unlock(&g_submit_lock);
        if (!got){
            *ec = -4; *em = "the download worker did not answer within the submission timeout"; return 0; }

        /* a package-level rejection is reported on EVERY entry, because none
         * of them got an individual verdict -- that is what Core's
         * package-error means */
        /* "transaction failed" is the one package_msg that means "the
         * members were each judged, look at their own verdicts". Everything
         * else -- ill-formed package, TRUC violation -- is a statement about
         * the package as a whole, and Core gives no member an `allowed`. */
        int pkg_failed = (pmsg[0] && strcmp(pmsg, "success") != 0);
        int pkg_level  = pkg_failed && strcmp(pmsg, "transaction failed") != 0;
        for (int i = 0; i < n; i++){
            rj_val* e = rj_obj();
            unsigned char id[32], wid[32];
            static unsigned char sc[2000*81+8];
            char hx[65];
            if (tx_txid(id, raw + off[i], lens[i], sc, sizeof sc) == 1){
                for (int k=0;k<32;k++){ unsigned char b=id[31-k]; hx[k*2]=HEXD[b>>4]; hx[k*2+1]=HEXD[b&15]; }
                hx[64]=0; rj_obj_set(e, "txid", rj_str(hx));
                int segwit = lens[i] > 6 && raw[off[i]+4] == 0x00 && raw[off[i]+5] == 0x01;
                if (segwit && g_mph.sha256d) g_mph.sha256d(wid, raw + off[i], lens[i]);
                else memcpy(wid, id, 32);
                for (int k=0;k<32;k++){ unsigned char b=wid[31-k]; hx[k*2]=HEXD[b>>4]; hx[k*2+1]=HEXD[b&15]; }
                hx[64]=0; rj_obj_set(e, "wtxid", rj_str(hx));
            }
            if (pkg_level){
                /* no member was individually validated: `allowed` is OMITTED,
                 * which is exactly how Core marks that */
                rj_obj_set(e, "package-error", rj_str(pmsg));
            } else if (r_result[i]){
                rj_obj_set(e, "allowed", rj_bool(1));
                rj_obj_set(e, "vsize", rj_numf("%llu", (unsigned long long)r_vsize[i]));
                rj_obj_set(e, "vsize_bip141", rj_numf("%llu", (unsigned long long)r_vsize[i]));
                rj_val* f = rj_obj();
                rj_obj_set(f, "base", mpe_amount(r_fee[i]));
                if (eff_vsize){
                    /* the feerate the package was ACTUALLY weighed against,
                     * and the members whose fee and vsize went into it */
                    rj_obj_set(f, "effective-feerate", mpe_amount(eff_fee * 1000ULL / eff_vsize));
                    rj_val* inc = rj_arr();
                    for (int k = 0; k < n; k++){
                        if (!r_result[k]) continue;
                        unsigned char ik[32], wk[32]; char wkhex[65];
                        if (tx_txid(ik, raw + off[k], lens[k], sc, sizeof sc) != 1) continue;
                        int sw = lens[k] > 6 && raw[off[k]+4] == 0x00 && raw[off[k]+5] == 0x01;
                        if (sw && g_mph.sha256d) g_mph.sha256d(wk, raw + off[k], lens[k]);
                        else memcpy(wk, ik, 32);
                        mpe_hex(wkhex, wk);
                        rj_arr_push(inc, rj_str(wkhex));
                    }
                    rj_obj_set(f, "effective-includes", inc);
                }
                rj_obj_set(e, "fees", f);
            } else {
                rj_obj_set(e, "allowed", rj_bool(0));
                rj_obj_set(e, "reject-reason",
                           rj_str(r_reason[i][0] ? r_reason[i] : "transaction rejected"));
            }
            rj_arr_push(arr, e);
        }
        *res = arr;
        return 1;
    }

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
    "testmempoolaccept", "submitpackage", "savemempool", "importmempool",
    "getprivatebroadcastinfo", "abortprivatebroadcast",
    "getnettotals", "getnodeaddresses", "getaddrmaninfo", "getrawaddrman", "getorphantxs", "listbanned",
    "clearbanned", "getaddednodeinfo", "addnode", "addpeeraddress", "disconnectnode",
    "setban", "setnetworkactive", "ping", "getzmqnotifications",
    "getmempoolinfo", "getrawmempool", "getmempoolentry", "getmempoolancestors", "getmempooldescendants", "estimatesmartfee", "estimaterawfee", "prioritisetransaction", "getprioritisedtransactions", "submitblock", "sendrawtransaction", NULL
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
    if (!strcmp(m, "submitpackage")) return cmd_submitpackage(params, res, ec, em);
    if (!strcmp(m, "savemempool"))   return cmd_savemempool(res, ec, em);
    if (!strcmp(m, "importmempool")) return cmd_importmempool(params, res, ec, em);
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
    if (!strcmp(m, "getnodeaddresses"))   return cmd_getnodeaddresses(params, res, ec, em);
    if (!strcmp(m, "getaddrmaninfo"))     return cmd_getaddrmaninfo(res);
    if (!strcmp(m, "getrawaddrman"))      return cmd_getrawaddrman(res);
    if (!strcmp(m, "getorphantxs"))       return cmd_getorphantxs(params, res, ec, em);
    if (!strcmp(m, "listbanned"))         return cmd_listbanned(res);
    if (!strcmp(m, "getaddednodeinfo")){
        int rc = cmd_getaddednodeinfo(params, res);
        if (rc == -24000){ *ec = -24; *em = "Error: Node has not been added."; return 0; }
        return rc;
    }
    if (!strcmp(m, "clearbanned"))        return cmd_clearbanned(res, ec, em);
    if (!strcmp(m, "addnode"))            return cmd_addnode(params, res, ec, em);
    if (!strcmp(m, "addpeeraddress"))     return cmd_addpeeraddress(params, res, ec, em);
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
    if (!strcmp(m, "estimaterawfee"))     return cmd_estimaterawfee(params, res, ec, em);
    if (!strcmp(m, "prioritisetransaction"))      return cmd_prioritisetransaction(params, res, ec, em);
    if (!strcmp(m, "getprioritisedtransactions")) return cmd_getprioritisedtransactions(res);
    if (!strcmp(m, "submitblock"))        return cmd_submitblock(params, res, ec, em);
    if (!strcmp(m, "sendrawtransaction")) return cmd_sendrawtransaction(params, res, ec, em);
    return -1;
}
