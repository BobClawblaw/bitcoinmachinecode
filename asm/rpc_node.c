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
#include "version_gen.h"
#include <string.h>
#include <stdio.h>

static const node_status_t* g_status;

void rpc_node_set_status(const node_status_t* st){ g_status = st; }

/* our node advertises NODE_NETWORK(1) only (see bitcoind.asm version msg) */
#define NODE_LOCAL_SERVICES 0x0000000000000001ULL

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
      rj_obj_set(o, "localservicesnames", names); }
    rj_obj_set(o, "localrelay", rj_bool(1));
    rj_obj_set(o, "timeoffset", rj_numf("%d", 0));
    rj_obj_set(o, "networkactive", rj_bool(1));
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
            rj_obj_set(o, "lastsend", rj_numf("%d", 0));
            rj_obj_set(o, "lastrecv", rj_numf("%d", 0));
            rj_obj_set(o, "bytessent", rj_numf("%d", 0));
            rj_obj_set(o, "bytesrecv", rj_numf("%d", 0));
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

static const char* const NODE_METHODS[] = {
    "getconnectioncount", "getnetworkinfo", "getpeerinfo", NULL
};
int rpc_node_known_method(const char* m){
    for (int i = 0; NODE_METHODS[i]; i++) if (!strcmp(m, NODE_METHODS[i])) return 1;
    return 0;
}
int rpc_node_dispatch(const char* m, const rj_val* params, rj_val** res, long* ec, const char** em){
    (void)params; (void)ec; (void)em;
    if (!strcmp(m, "getconnectioncount")) return cmd_getconnectioncount(res);
    if (!strcmp(m, "getnetworkinfo"))     return cmd_getnetworkinfo(res);
    if (!strcmp(m, "getpeerinfo"))        return cmd_getpeerinfo(res);
    return -1;
}
