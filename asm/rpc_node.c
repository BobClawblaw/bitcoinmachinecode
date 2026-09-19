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
#include <string.h>
#include "mempool_cluster.h"
#include "rpc_node.h"

/* Core's per-message byte breakdown for getpeerinfo. Defined here so exactly
 * one object carries it; the header declares it extern. */
const char* const RPC_MSG_NAMES[RPC_MSG_N] = {
    "addr","addrv2","block","blocktxn","cmpctblock","feefilter","filteradd",
    "filterclear","filterload","getaddr","getblocks","getblocktxn","getdata",
    "getheaders","headers","inv","mempool","notfound","ping","pong",
    "sendaddrv2","sendcmpct","sendheaders","tx","verack","version","other"
};
int rpc_msg_index(const char* cmd, unsigned cmdlen){
    if (!cmd) return RPC_MSG_N - 1;
    char n[13]; unsigned i = 0;
    for (; i < 12 && i < cmdlen && cmd[i]; i++) n[i] = cmd[i];
    n[i] = 0;
    for (int j = 0; j < RPC_MSG_N - 1; j++) if (!strcmp(n, RPC_MSG_NAMES[j])) return j;
    return RPC_MSG_N - 1;
}
#include "daemon/asmap.h"   /* mapped_as, when -asmap is loaded */
#include "mempool_entry.h"
#include "mempool_slot.h"    /* the structural mempool's slot layout */
#include "version_gen.h"
#include "build_gen.h"
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include "daemon/log_ts.h"
#include <stdlib.h>   /* atof/atol/atoll -- implicitly declared before 2026-08-25,
                        * which silently corrupted their return values */
#include <pthread.h>
#include <unistd.h>  /* getcwd -- implicitly declared until 2026-08-27, which on
                      * this ABI means int, truncating the returned pointer */
#include <time.h>
#include "daemon/mempool_journal.h"

/* ---- Core's argument type check -------------------------------------------
 * Measured against Core v31.1 on the oracle, 2026-09-15, for every JSON type.
 * Core distinguishes THREE answers where this file collapsed two of them:
 *
 *   missing required argument -> -1  + the method's full help text
 *   wrong JSON type           -> -3  (RPC_TYPE_ERROR), wrapped as
 *        Wrong type passed:
 *        {
 *            "Position 1 (txid)": "JSON value of type null is not of expected type string"
 *        }
 *   right type, bad value     -> -8  + a specific message ("txid must be of length 64 ...")
 *
 * getmempoolentry, getmempoolancestors, getmempooldescendants and
 * prioritisetransaction answered -8 for the first two cases alike, and named
 * the type as "null" whatever was actually passed -- so a caller that sent a
 * number was told it had sent null. The -8/-3 mismatch matters most: -8 is
 * RPC_INVALID_PARAMETER, and a caller branching on the numeric code (which is
 * what the code is for) takes the wrong branch.
 *
 * The -1 case cannot be matched exactly: this node deliberately carries no
 * per-method usage text (see cmd_help in rpc_commands.c), so it answers -1 with
 * a short usage line -- the code Core uses, with the text it can honestly
 * produce. cmd_prioritisetransaction already did this. */
static int rpc_wrong_type(long* ec, const char** em, char* buf, size_t cap,
                          int position, const char* name,
                          const rj_val* got, const char* expected){
    *ec = -3; *em = rj_wrong_type_msg(buf, cap, position, name, got, expected); return 0;
}


static const node_status_t* g_status;
static node_status_t*       g_status_rw;     /* writable handle for submission */
static pthread_mutex_t      g_submit_lock = PTHREAD_MUTEX_INITIALIZER;

void rpc_node_set_status(const node_status_t* st){ g_status = st; }
/* -uacomment: the runtime user agent main.c built (getnetworkinfo subversion). */
static char g_user_agent[256];
void rpc_node_set_user_agent(const char* ua){ snprintf(g_user_agent, sizeof g_user_agent, "%s", ua ? ua : ""); }
void rpc_node_set_status_rw(node_status_t* st){ g_status_rw = st; if (!g_status) g_status = st; }
/* getnetworkinfo localrelay: false under -blocksonly (Core: !ignore_incoming_txs) */
static int g_localrelay = 1;
void rpc_node_set_localrelay(int on){ g_localrelay = on ? 1 : 0; }

/* txid of a raw tx (BIP141: hash of the no-witness serialization); worker
 * recomputes independently for the mempool. */
/* RPC-20 (audit 2026-09-03): tx_txid's scratch must cover any transaction the
 * staging buffers can hold, or a large-but-valid transaction is reported as
 * "TX decode failed" instead of getting its real policy verdict. Asserted at
 * COMPILE TIME because the failure mode is silent at runtime and the two
 * constants sat in different files: this is the check that would have caught
 * the original 162,008-vs-404,000 mismatch the moment it was written. */
_Static_assert(RPC_TXID_SCRATCH >= RPC_TXSUBMIT_MAX,
               "RPC-20: tx_txid scratch is smaller than the staging cap");

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

/* ---- one definition of "a live connection" (2026-09-16) -------------------
 * getpeerinfo walks the shared peer table and reports every used slot;
 * getconnectioncount and getnetworkinfo used to return g_status->n_out +
 * n_inbound instead, counters that only the serve/leg path maintains. The
 * download worker fills peer slots but never touches those counters, so
 * during initial block download the three disagreed: on run 26, getpeerinfo
 * listed 13 peers, getconnectioncount said 5, and the node was pulling
 * 11 MB/s from 8 download peers the count could not see. A monitor graphing
 * getconnectioncount showed a node with no peers while it saturated the link.
 *
 * In Core these cannot disagree -- getconnectioncount is the size of the same
 * vector getpeerinfo renders -- so they are now derived from one walk with
 * one liveness test. rpc_peer_live() is that test, and getpeerinfo uses it
 * too, so a slot can never be counted and not listed (or the reverse). */
static int rpc_peer_live(const rpc_peer_t* p){
    if (!p->used) return 0;
    /* a serve child that died holding its slot: the pid is gone */
    if (p->inbound && p->pid > 0 && kill((pid_t)p->pid, 0) != 0 && errno == ESRCH) return 0;
    return 1;
}
/* live connections, split in/out. Either pointer may be NULL.
 *
 * getpeerinfo renders TWO arrays and so does this: the leg/inbound table
 * (g_status->peers) and the parallel download's peers (g_status->dlpeers,
 * one per worker holding a connection, added 2026-09-08). Walking only the
 * first is how the first version of this fix still answered 4 while
 * getpeerinfo listed 12 on run 26 -- the 8 download peers were the whole
 * point. Every download peer is outbound. */
static int rpc_conn_counts(int* out_in, int* out_out){
    int n_in = 0, n_out = 0;
    if (g_status){
        for (int i = 0; i < RPC_MAX_PEERS; i++){
            const rpc_peer_t* p = &g_status->peers[i];
            if (!rpc_peer_live(p)) continue;
            if (p->inbound) n_in++; else n_out++;
        }
        int nd = g_status->n_dlpeers; if (nd > 64) nd = 64;
        for (int i = 0; i < nd; i++){
            const rpc_peer_t* p = &g_status->dlpeers[i];
            if (!p->used || !p->addr[0]) continue;   /* getpeerinfo's own test */
            n_out++;
        }
    }
    if (out_in)  *out_in  = n_in;
    if (out_out) *out_out = n_out;
    return n_in + n_out;
}

static int cmd_getconnectioncount(rj_val** res){
    *res = rj_numf("%d", rpc_conn_counts(NULL, NULL));
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

/* one entry of getnetworkinfo.networks.
 *
 * `proxy` and `proxy_randomize_credentials` used to be hardcoded empty/false
 * for every network regardless of the actual config -- Core's own
 * GetProxy(network)->m_tor_stream_isolation reports the REAL configured
 * proxy per network, and per-connection SOCKS5 credential randomization is
 * genuinely active here (daemon/dialer.c) whenever -proxyrandomize is on, so
 * this RPC was misreporting the node's own behaviour (audit finding,
 * 2026-09-03). Matches Core's exact per-network wiring
 * (init.cpp SetProxy calls): -proxyrandomize applies to ipv4/ipv6/onion
 * (each a real SOCKS5 proxy, Tor stream isolation being the point of
 * randomizing credentials); it does NOT apply to i2p (the SAM bridge has no
 * such concept -- Core constructs its Proxy with the plain, non-isolating
 * constructor) or to cjdns (no proxy at all, a direct native network).
 *
 * node_config.c is linked weakly here: bmc_cli (a pure HTTP client)
 * links this whole file but never executes cmd_getnetworkinfo, and does not
 * link node_config.c at all -- the NULL check is what keeps that build
 * working rather than needing a config parser it has no use for. */
extern void node_config_get_proxy_info(const char**, const char**, const char**, int*) __attribute__((weak));
/* RPC-8: the REAL subnet_t, not a hand-mirrored copy -- daemon/subnet.h's own
 * header comment records that two spellings of one rule is how they drift.
 * Redeclared weak after the include for the reason above. */
#include "daemon/subnet.h"
extern int subnet_parse(const char* spec, subnet_t* out) __attribute__((weak));
static rj_val* net_entry(const char* name, int reachable, const char* proxy, int randomize){
    rj_val* o = rj_obj();
    rj_obj_set(o, "name", rj_str(name));
    rj_obj_set(o, "limited", rj_bool(0));
    rj_obj_set(o, "reachable", rj_bool(reachable));
    rj_obj_set(o, "proxy", rj_str(proxy ? proxy : ""));
    rj_obj_set(o, "proxy_randomize_credentials", rj_bool((proxy && proxy[0]) ? randomize : 0));
    return o;
}

/* RPC-9 (audit 2026-09-03): moved up from the mempool section --
 * getnetworkinfo reports these floors too, and used to hardcode them. */
/* The configured relay floors, sat/kvB; main.c sets them from bitcoin.conf
 * (rpc_node_set_relay_floors). Defaults are Core v30's: 100 = 0.1 sat/vB. */
static unsigned long long g_minrelay_satkvb = 100, g_incremental_satkvb = 100;
void rpc_node_set_relay_floors(unsigned long long minrelay_satkvb, unsigned long long incremental_satkvb){
    if (minrelay_satkvb) g_minrelay_satkvb = minrelay_satkvb;
    if (incremental_satkvb) g_incremental_satkvb = incremental_satkvb;
}
#define MEMPOOL_MINFEE_BTC ((double)g_minrelay_satkvb / 1e8)      /* min relay fee, BTC/kvB */

static int cmd_getnetworkinfo(rj_val** res){
    int n_in = 0, n_out = 0;
    rpc_conn_counts(&n_in, &n_out);

    rj_val* o = rj_obj();
    rj_obj_set(o, "version", rj_numf("%ld", node_client_version()));
    rj_obj_set(o, "subversion", rj_str(g_user_agent[0] ? g_user_agent : NODE_UA_STRING));
    rj_obj_set(o, "protocolversion", rj_numf("%d", NODE_PROTOCOL_VER));
    { char h[17]; snprintf(h, sizeof h, "%016llx", (unsigned long long)NODE_LOCAL_SERVICES);
      rj_obj_set(o, "localservices", rj_str(h)); }
    { rj_val* names = rj_arr(); rj_arr_push(names, rj_str("NETWORK"));
      rj_arr_push(names, rj_str("WITNESS"));
      rj_obj_set(o, "localservicesnames", names); }
    /* 2026-09-10: WHICH BUILD is answering. bmcmonitor measured two builds on
     * this box giving different answers to getnettotals and getpeerinfo while
     * both reported subversion "/BitcoinMachineCode:0.0.1/", and concluded
     * that the log banner was the only build attestation available -- so a
     * monitor could not tell a fixed node from a broken one over RPC.
     * subversion cannot carry this: it goes out on the wire in the version
     * message, and Core's semantics for it are the user agent. Extension
     * fields, bmc_ prefixed like getpeerinfo's bmc_download_worker. */
    rj_obj_set(o, "bmc_build_commit", rj_str(BMC_BUILD_COMMIT));
    rj_obj_set(o, "bmc_build_dirty",  rj_bool(BMC_BUILD_DIRTY));
    rj_obj_set(o, "localrelay", rj_bool(g_localrelay));
    rj_obj_set(o, "timeoffset", rj_numf("%d", 0));
    /* the REAL toggle state, not a constant: setnetworkactive changes it and
     * getnetworkinfo must reflect that, or the two disagree about whether
     * the node is talking to anyone. */
    rj_obj_set(o, "networkactive", rj_bool(g_status ? g_status->net_active : 1));
    rj_obj_set(o, "connections", rj_numf("%d", n_out + n_in));
    rj_obj_set(o, "connections_in", rj_numf("%d", n_in));
    rj_obj_set(o, "connections_out", rj_numf("%d", n_out));
    { rj_val* nets = rj_arr();
      const char* proxy = NULL; const char* onion_proxy_raw = NULL; const char* i2psam = NULL; int proxyrandomize = 0;
      if (node_config_get_proxy_info) node_config_get_proxy_info(&proxy, &onion_proxy_raw, &i2psam, &proxyrandomize);
      const char* onion_proxy = (onion_proxy_raw && onion_proxy_raw[0]) ? onion_proxy_raw : proxy;  /* Core: -onion falls back to -proxy */
      rj_arr_push(nets, net_entry("ipv4",  net_reach(1, 1), proxy,        proxyrandomize));
      rj_arr_push(nets, net_entry("ipv6",  net_reach(2, 1), proxy,        proxyrandomize));
      rj_arr_push(nets, net_entry("onion", net_reach(4, 0), onion_proxy,  proxyrandomize));
      rj_arr_push(nets, net_entry("i2p",   net_reach(5, 0), i2psam,       0));  /* SAM: no stream isolation */
      rj_arr_push(nets, net_entry("cjdns", net_reach(6, 0), NULL,         0));  /* direct network, no proxy */
      rj_obj_set(o, "networks", nets); }
    /* RPC-9 (audit 2026-09-03): these were the literal 0.00001000, while the
     * real floors default to 100 sat/kvB -- so getnetworkinfo.relayfee and
     * getmempoolinfo.minrelaytxfee DISAGREED BY 10x ON A STOCK NODE, not only
     * with a non-default floor as the audit states. main.c calls
     * rpc_node_set_relay_floors at boot, so the configured values were
     * available here all along. Rendered exactly as getmempoolinfo does. */
    rj_obj_set(o, "relayfee", rj_numf("%.8f", MEMPOOL_MINFEE_BTC));
    rj_obj_set(o, "incrementalfee", rj_numf("%.8f", (double)g_incremental_satkvb / 1e8));
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
/* The getpeerinfo fields common to a relay leg and a download worker.
 *
 * There are two builders below -- one per kind of peer -- and every field
 * added to one and not the other is a silent divergence in the same call.
 * Anything either of them can answer honestly goes here, once.
 *
 * Only fields with a REAL source are emitted. Core's getpeerinfo has 38
 * fields in v31.1 and this node does not yet track the rest: per-message byte
 * counters, ping round-trip times, the peer's feefilter, its compact-block
 * high-bandwidth state, the BIP324 session id, the bound local address, and
 * the address-relay counters. Emitting any of those as a zero or a guess
 * would be worse than omitting them -- a caller cannot tell an invented zero
 * from a measured one. They are tracked in docs/PARITY_RPC_FIELDS.md. */
int rpc_fmt_addr_v1(const unsigned char a[16], unsigned port, char* out, unsigned cap)
{
    static const unsigned char V4[12]  = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
    static const unsigned char TOR2[6] = {0xfd,0x87,0xd8,0x7e,0xeb,0x43};
    static const unsigned char INTL[6] = {0xfd,0x6b,0x88,0xc0,0x87,0x24};
    if (!out || cap == 0) return 0;
    out[0] = 0;
    if (!memcmp(a, V4, 12)){
        unsigned v = ((unsigned)a[12]<<24)|((unsigned)a[13]<<16)|((unsigned)a[14]<<8)|a[15];
        if (v == 0 || v == 0xffffffffu) return 0;             /* INADDR_ANY, INADDR_NONE */
        snprintf(out, cap, "%u.%u.%u.%u:%u", a[12], a[13], a[14], a[15], port);
        return 1;
    }
    if (!memcmp(a, TOR2, 6) || !memcmp(a, INTL, 6)) return 0;  /* read as ::, or NET_INTERNAL */
    if (a[0]==0x20 && a[1]==0x01 && a[2]==0x0d && a[3]==0xb8) return 0;   /* RFC3849 */
    unsigned g[8]; int allz = 1;
    for (int i = 0; i < 8; i++){ g[i] = ((unsigned)a[2*i]<<8) | a[2*i+1]; if (g[i]) allz = 0; }
    if (allz) return 0;                                        /* :: */
    /* Core's IPv6ToString: the FIRST longest run of zero groups, compressed
     * only when it is two or more long. glibc's inet_ntop differs (it prints
     * ::/96 as a dotted quad), so it is not used here. */
    int bs = 0, bl = 0, cs = 0, cl = 0;
    for (int i = 0; i < 8; i++){
        if (g[i]){ cs = i + 1; cl = 0; continue; }
        if (++cl > bl){ bl = cl; bs = cs; }
    }
    char h[48]; int n = 0;
    for (int i = 0; i < 8; i++){
        if (bl >= 2 && i >= bs && i < bs + bl){ if (i == bs) n += snprintf(h+n, sizeof h - n, "::"); continue; }
        n += snprintf(h+n, sizeof h - n, "%s%x", (n && h[n-1] != ':') ? ":" : "", g[i]);
    }
    snprintf(out, cap, "[%s]:%u", h, port);
    return 1;
}

static void peer_common_fields(rj_val* o, const rpc_peer_t* p)
{
    /* Core emits both UNCONDITIONALLY, as seconds since epoch, and 0 for a
     * peer that has sent neither (rpc/net.cpp pushes count_seconds of the
     * default time_point). This used to omit them at 0 on the belief that
     * Core does too; measured 2026-09-18, Core reports 0. */
    rj_obj_set(o, "last_block", rj_numf("%lld", (long long)(p->last_block_time > 0 ? p->last_block_time : 0)));
    rj_obj_set(o, "last_transaction", rj_numf("%lld", (long long)(p->last_tx_time > 0 ? p->last_tx_time : 0)));
    /* minping in SECONDS, as Core prints it. min_ping_us is 0 when unmeasured
     * -- this node does not ping inbound peers -- and an unmeasured minimum
     * printed as 0.0 would read as a perfect link. Omitted, like Core. */
    if (p->min_ping_us > 0)
        rj_obj_set(o, "minping", rj_numf("%.6f", (double)p->min_ping_us / 1e6));
    /* connection_type: what this node actually runs. Core also has
     * block-relay-only, manual, feeler and addr-fetch; none of those exist
     * here, so none are claimed. */
    rj_obj_set(o, "connection_type", rj_str(p->inbound ? "inbound" : "outbound-full-relay"));
    /* Core's per-message byte breakdown. A peer that has exchanged nothing
     * of a kind gets no entry for it, which is what Core does. The maps
     * themselves are ALWAYS present -- Core pushes both objects even when
     * empty; until 2026-09-18 an empty map was dropped here. */
    { rj_val* s = rj_obj(); rj_val* r = rj_obj();
      for (int i = 0; i < RPC_MSG_N; i++){
          if (p->sent_per_msg[i] > 0) rj_obj_set(s, RPC_MSG_NAMES[i], rj_numf("%lld", (long long)p->sent_per_msg[i]));
          if (p->recv_per_msg[i] > 0) rj_obj_set(r, RPC_MSG_NAMES[i], rj_numf("%lld", (long long)p->recv_per_msg[i]));
      }
      rj_obj_set(o, "bytessent_per_msg", s);
      rj_obj_set(o, "bytesrecv_per_msg", r); }
    /* the transport that carried this connection, and the session both sides
     * derived. Core names them exactly this. */
    rj_obj_set(o, "transport_protocol_type", rj_str(p->v2transport ? "v2" : "v1"));
    { int any = 0; for (int i = 0; i < 32; i++) if (p->session_id[i]) any = 1;
      static const char* HEXD = "0123456789abcdef";
      char sid[65];
      for (int i = 0; i < 32; i++){ unsigned char b = p->session_id[i]; sid[i*2]=HEXD[b>>4]; sid[i*2+1]=HEXD[b&15]; }
      sid[64] = 0;
      /* Core emits an EMPTY session_id on a v1 connection, not no field. */
      rj_obj_set(o, "session_id", rj_str(any ? sid : "")); }
    if (p->addrbind[0]) rj_obj_set(o, "addrbind", rj_str((const char*)p->addrbind));
    /* our address as the peer's version message named it; omitted when the
     * peer sent one Core calls invalid, as Core omits it */
    if (p->addrlocal[0]){
        char al[72]; for (unsigned i = 0; i < sizeof al; i++) al[i] = p->addrlocal[i];
        al[sizeof al - 1] = 0;
        rj_obj_set(o, "addrlocal", rj_str(al));
    }
    /* minfeefilter is a BTC/kvB amount in Core; we hold it in sat/kvB. -1 is
     * "the peer never sent one", which is different from a filter of zero. */
    if (p->minfeefilter >= 0)
        rj_obj_set(o, "minfeefilter", rj_numf("%lld.%08lld",
            (long long)p->minfeefilter / 100000000LL, (long long)p->minfeefilter % 100000000LL));
    if (p->hb_to   >= 0) rj_obj_set(o, "bip152_hb_to",   rj_bool(p->hb_to));
    if (p->hb_from >= 0) rj_obj_set(o, "bip152_hb_from", rj_bool(p->hb_from));
    if (p->addr_relay_enabled >= 0){
        rj_obj_set(o, "addr_relay_enabled", rj_bool(p->addr_relay_enabled));
        rj_obj_set(o, "addr_processed",     rj_numf("%lld", (long long)p->addr_processed));
        rj_obj_set(o, "addr_rate_limited",  rj_numf("%lld", (long long)p->addr_rate_limited));
    }
    if (p->ping_usec > 0) rj_obj_set(o, "pingtime", rj_numf("%.6f", (double)p->ping_usec / 1e6));
    /* Core emits all three unconditionally -- verified against a live node:
     * inv_to_send 0, last_inv_sequence 0, presynced_headers -1 are the values
     * a quiet peer gets, not omissions. Zero really is "nothing queued" here,
     * so publishing it asserts nothing we have not measured. */
    rj_obj_set(o, "inv_to_send",       rj_numf("%lld", (long long)(p->inv_to_send > 0 ? p->inv_to_send : 0)));
    rj_obj_set(o, "last_inv_sequence", rj_numf("%lld", (long long)(p->last_inv_sequence > 0 ? p->last_inv_sequence : 0)));
    /* presynced_headers is -1 in Core whenever the peer is not in the headers
     * PRESYNC phase, which is every peer on a synced node -- the three on the
     * oracle all read -1. This node's header phase holds low-work pages
     * instead of running Core's presync state machine, so it is -1 here for a
     * structural reason as well as the usual one. Emitted, not omitted,
     * because Core emits it. */
    /* > 0, not >= 0. The "unknown" default of -1 is applied where a leg slot
     * is filled, but a slot published by another path -- the download-worker
     * table, or any caller that memsets the record -- arrives as 0, and 0
     * read as a height would claim a presync at genesis that never happened.
     * A presync height of 0 is not a real state, so anything that is not
     * positive is reported as Core's -1. */
    rj_obj_set(o, "presynced_headers", rj_numf("%ld", (long)(p->presynced_headers > 0 ? p->presynced_headers : -1)));
    /* inflight: the block heights requested from this peer and not yet in.
     * A leg requests none, and an empty array is the honest answer there --
     * it is what Core returns for a peer with nothing outstanding. */
    { rj_val* fl = rj_arr();
      if (p->inflight_hi >= p->inflight_lo)
          for (long h = p->inflight_lo; h <= p->inflight_hi && h < p->inflight_lo + 256; h++)
              rj_arr_push(fl, rj_numf("%ld", h));
      rj_obj_set(o, "inflight", fl); }
}

static int cmd_getpeerinfo(rj_val** res){
    rj_val* arr = rj_arr();
    if (g_status){
        for (int i = 0; i < RPC_MAX_PEERS; i++){
            const rpc_peer_t* p = &g_status->peers[i];
            if (!rpc_peer_live(p)) continue;   /* the same test getconnectioncount counts with */
            rj_val* o = rj_obj();
            /* RPC-3 (audit 2026-09-03): report the peer's OWN monotonic
             * nodeid, not a counter over the live slots. The counter and the
             * worker's disconnect matcher (which used the raw outbound leg
             * index) agreed only while every slot below was occupied and no
             * inbound slot came first; after any leg churn an operator who
             * read `id: 5` here and ran `disconnectnode "" 5` dropped a
             * different, healthy peer and got success back. Core's NodeId is
             * unique for the process lifetime and never reused; so is this. */
            rj_obj_set(o, "id", rj_numf("%lld", (long long)p->nodeid));
            rj_obj_set(o, "addr", rj_str(p->addr));
            { char h[17]; snprintf(h, sizeof h, "%016llx", (unsigned long long)p->services);
              rj_obj_set(o, "services", rj_str(h)); }
            { rj_val* sn = rj_arr(); services_names(p->services, sn); rj_obj_set(o, "servicesnames", sn); }
            rj_obj_set(o, "relaytxes", rj_bool(p->relaytxes));
            rj_obj_set(o, "lastsend", rj_numf("%lld", (long long)p->last_send));
            rj_obj_set(o, "lastrecv", rj_numf("%lld", (long long)p->last_recv));
            rj_obj_set(o, "bytessent", rj_numf("%lld", (long long)p->bytes_sent));
            rj_obj_set(o, "bytesrecv", rj_numf("%lld", (long long)p->bytes_recv));
            rj_obj_set(o, "conntime", rj_numf("%lld", (long long)p->conn_time));
            rj_obj_set(o, "timeoffset", rj_numf("%d", 0));
            rj_obj_set(o, "version", rj_numf("%u", p->proto));
            rj_obj_set(o, "subver", rj_str(p->subver));
            rj_obj_set(o, "inbound", rj_bool(p->inbound));
            { /* Core NetPermissions::ToStrings order (net_permissions.cpp) */
              rj_val* pa = rj_arr(); unsigned f = p->perms;
              if (f & (1u<<0)) rj_arr_push(pa, rj_str("noban"));
              if (f & (1u<<2)) rj_arr_push(pa, rj_str("forcerelay"));
              if (f & (1u<<1)) rj_arr_push(pa, rj_str("relay"));
              if (f & (1u<<3)) rj_arr_push(pa, rj_str("mempool"));
              if (f & (1u<<4)) rj_arr_push(pa, rj_str("download"));
              if (f & (1u<<5)) rj_arr_push(pa, rj_str("addr"));
              rj_obj_set(o, "permissions", pa); }
            /* startingheight was REMOVED from Core's getpeerinfo; v31.1 run on
             * regtest does not emit it. Dropped 2026-09-12 for exactness at the
             * operator's call -- it was the only field we returned that Core
             * does not. The handshake height is still kept internally and is on
             * bmcgetdownloadinfo, which is ours to define. */
            rj_obj_set(o, "synced_headers", rj_numf("%d", -1));
            rj_obj_set(o, "synced_blocks", rj_numf("%d", -1));
            { bmc_addr_t pa; const char* nn = "ipv4";
              if (bmc_addr_from_string_port(&pa, p->addr, 0)) nn = bmc_net_name(pa.net);
              rj_obj_set(o, "network", rj_str(nn)); }
            peer_common_fields(o, p);
            rj_arr_push(arr, o);
        }
        /* the parallel download's peers (2026-09-08), one per worker holding a
         * connection; ids from 100000 so they never collide with the legs */
        int nd = g_status->n_dlpeers; if (nd > 64) nd = 64;
        for (int i = 0; i < nd; i++){
            const rpc_peer_t* p = &g_status->dlpeers[i];
            if (!p->used || !p->addr[0]) continue;
            rj_val* o = rj_obj();
            rj_obj_set(o, "id", rj_numf("%lld", 100000LL + i));
            rj_obj_set(o, "addr", rj_str(p->addr));
            { char h[17]; snprintf(h, sizeof h, "%016llx", (unsigned long long)p->services); rj_obj_set(o, "services", rj_str(h)); }
            { rj_val* sn = rj_arr(); services_names(p->services, sn); rj_obj_set(o, "servicesnames", sn); }
            rj_obj_set(o, "relaytxes", rj_bool(0));
            rj_obj_set(o, "lastsend", rj_numf("%lld", (long long)p->last_send));
            rj_obj_set(o, "lastrecv", rj_numf("%lld", (long long)p->last_recv));
            rj_obj_set(o, "bytessent", rj_numf("%lld", (long long)p->bytes_sent));
            rj_obj_set(o, "bytesrecv", rj_numf("%lld", (long long)p->bytes_recv));
            rj_obj_set(o, "conntime", rj_numf("%lld", (long long)p->conn_time));
            rj_obj_set(o, "timeoffset", rj_numf("%d", 0));
            rj_obj_set(o, "version", rj_numf("%u", p->proto));
            rj_obj_set(o, "subver", rj_str(p->subver));
            rj_obj_set(o, "inbound", rj_bool(0));
            rj_obj_set(o, "permissions", rj_arr());
            /* startingheight was REMOVED from Core's getpeerinfo; v31.1 run on
             * regtest does not emit it. Dropped 2026-09-12 for exactness at the
             * operator's call -- it was the only field we returned that Core
             * does not. The handshake height is still kept internally and is on
             * bmcgetdownloadinfo, which is ours to define. */
            rj_obj_set(o, "synced_headers", rj_numf("%d", p->start_height));
            rj_obj_set(o, "synced_blocks", rj_numf("%ld", p->inflight_hi >= p->inflight_lo ? p->inflight_lo - 1 : -1L));
            /* inflight and connection_type now come from peer_common_fields
             * below. They used to be emitted HERE and nowhere else, so the
             * same RPC returned two different field sets depending on whether
             * a peer was a relay leg or a download worker -- the exact
             * divergence the shared helper exists to prevent.
             *
             * bmc_download_worker is gone too. It was an additive key in a
             * Core call, which is the same category as the startingheight we
             * just dropped for exactness; the worker index is on
             * bmcgetdownloadinfo, which is ours to define. */
            { bmc_addr_t pa; const char* nn = "ipv4";
              if (bmc_addr_from_string_port(&pa, p->addr, 0)) nn = bmc_net_name(pa.net);
              rj_obj_set(o, "network", rj_str(nn)); }
            peer_common_fields(o, p);
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
 * rather than pretending.
 *
 * RPC-19 (audit 2026-09-03): this paragraph used to claim "this node has no
 * ban list, no addnode list, and no runtime network-disable switch". All
 * three arrived and the sentence did not move. cmd_listbanned (:935) walks a
 * REAL ban table in shared status (g_status->bans[]) with expiry; the addnode
 * list is g_addnode; setnetworkactive crosses the ctl_* channel like its
 * siblings. listbanned/getaddednodeinfo return empty only when there is
 * genuinely nothing to report -- which is Core's answer too, but for the
 * ordinary reason rather than the absence of the feature. What remains true:
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
    if (g_status) recv += g_status->dl_bytes_total;   /* the parallel download's bytes (2026-09-08): this read 3 KB against a 50 GB archive */
    rj_val* o = rj_obj();
    /* Core counts bytes for the process lifetime including closed peers; we
     * sum the LIVE peer table plus everything the download received this
     * run. Documented divergence for the legs, not an approximation dressed
     * as a total. */
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

/* listbanned: reads the shared ban table (g_status->bans[], expiry-checked)
 * that setban populates over the ctl_* channel.
 *
 * RPC-19: this comment used to say "this node keeps no ban list ... nothing
 * can ever populate it". Both halves were false by the time it was read --
 * setban has crossed to the worker since 2026-08-26 and cmd_listbanned below
 * has always walked the table. An empty array now means nothing is banned,
 * which is exactly Core's meaning. */

/* ping -- Core queues a ping to every peer and returns null immediately;
 * the result shows up in getpeerinfo's pingtime. This node's peer legs are
 * driven by the download worker, which sends its own keepalives.
 *
 * RPC-19: "there is no RPC-triggered ping path" is stale -- cmd_ping (:964)
 * sends RPC_CTL_PING across the ctl_* channel and daemon/main.c:5155 handles
 * it. The comment survived the wiring. */
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

/* Slot layout per mempool_slot.h / bitcoin_mempool.asm's header (same walk
 * daemon/reorg.c uses): +0 n, +8 mask, +16 blob, then MPOOL_SLOT_BYTES slots
 * at +40 -- [+0 len][+8 txid[32]][+40 blob_off][+48 wtxid[32]], len==~0
 * marking empty. */
typedef struct { const unsigned char* txid; const unsigned char* tx; unsigned long len; } mp_ent;
static long mp_slot(void* mp, unsigned long i, mp_ent* e){
    unsigned char* m = (unsigned char*)mp;
    unsigned long long mask; memcpy(&mask, m+8, 8);
    if (i > mask) return -1;
    unsigned char* s = MPOOL_SLOT_AT(m, i);
    unsigned long long len; memcpy(&len, s, 8);
    if (len == MPOOL_SLOT_EMPTY) return 0;
    unsigned char* blob; memcpy(&blob, m+16, 8);
    unsigned long long off; memcpy(&off, s+MPOOL_SLOT_OFF, 8);
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

/* -limitancestorcount / -limitancestorsize, injected by main.c from the
   config; defaults are Core's pre-cluster values. See getmempoolinfo. */
static long g_limit_anc_count = 25, g_limit_anc_size_kvb = 101;
void rpc_node_set_ancestor_limits(long count, long size_kvb){
    if (count > 0) g_limit_anc_count = count;
    if (size_kvb > 0) g_limit_anc_size_kvb = size_kvb;
}
static int cmd_getmempoolinfo(rj_val** res){
    long count = 0; unsigned long long bytes = 0, total_fee = 0, blob_used = 0;
    if (g_mph.mp){
        mpl();
        count = g_mph.count ? g_mph.count(g_mph.mp) : 0;
        /* total_fee in ONE pass over the policy nodes. It used to come from a
         * pol_entry() call per mempool slot, and pol_entry is a linear scan of
         * that same array -- an O(n^2) loop, under the mempool lock AND the
         * single RPC execution lock, on the call every monitoring tool polls
         * every few seconds. Measured with 5,914 transactions: 15 ms against
         * Core's 2 ms; the oracle's 77,736 would be ~6 billion compares. */
        int have_totals = 0;
        if (g_mph.polstate && g_mph.pol_totals){
            /* fees only. `bytes` stays an INDEPENDENT computation (mp_tx_vsize
             * over the pool's own bytes) rather than the policy's vsize sum,
             * on purpose: the two agreeing is a cross-check that caught
             * nothing today but would catch the policy registry drifting from
             * the pool. Verified equal on run 26 at 12,528 transactions --
             * 2,009,040 both ways. */
            if (g_mph.pol_totals(g_mph.polstate, &total_fee, 0) >= 0) have_totals = 1;
        }
        unsigned long n = mp_slot_count(g_mph.mp);
        for (unsigned long i=0;i<n;i++){ mp_ent e;
            if (mp_slot(g_mph.mp,i,&e) != 1) continue;
            bytes += mp_tx_vsize(e.tx, e.len);
            blob_used += e.len;
            if (!have_totals){                       /* no policy module linked */
                unsigned long long f,s;
                if (g_mph.polstate && g_mph.pol_entry && g_mph.pol_entry(g_mph.polstate,e.txid,&f,&s)) total_fee += f;
            }
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
    /* fullrbf: v31.1 has it, master has dropped it. Core's -mempoolfullrbf
     * became unconditional in v28, so the field is true there and here. */
    rj_obj_set(o, "fullrbf", rj_bool(1));
    /* THE CLUSTER FIELDS ARE A DOCUMENTED SEMANTIC DIVERGENCE, not a copy.
     *
     * Core v31.1 replaced the ancestor/descendant limits with CLUSTER limits:
     * a cluster is a whole connected component of the mempool graph, and
     * limitclustercount/limitclustersize bound it. This node still enforces
     * Core's older -limitancestorcount / -limitancestorsize, which bound a
     * transaction's ANCESTOR SET, not its component.
     *
     * The numbers below are therefore the limits this node actually enforces,
     * reported under Core's field names because they are the binding
     * constraint on how large a package here can get. They are NOT cluster
     * limits, and a caller reasoning about connected components from them
     * would be wrong. `optimal` is false for the same reason: it means "the
     * mempool is fully linearised" under cluster mempool, and nothing here
     * linearises anything, so claiming true would be a lie. Recorded in
     * docs/CORE_DIVERGENCES.md. */
    rj_obj_set(o, "limitclustercount", rj_numf("%ld", g_limit_anc_count));
    rj_obj_set(o, "limitclustersize", rj_numf("%ld", g_limit_anc_size_kvb * 1000));
    rj_obj_set(o, "optimal", rj_bool(0));
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
#define CTL_WAIT_MS 10000   /* 2026-09-09: was 3000, shorter than one worker rotation (a 2.5 s poll plus the
                             * per-leg TCP_INFO pass), so a healthy worker "did not answer" addnode twice in a row */
#define CTL_POLL_US 500

static int ctl_send(int op, const char* arg, long long num,
                    long* ec, const char** em, int* result_out, char* out, size_t outcap){
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
            if (out && outcap) snprintf(out, outcap, "%s", (const char*)s->ctl_out);
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
    if (!ctl_send(RPC_CTL_ADDNODE, node, mode, ec, em, &r, NULL, 0)) return 0;
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
    if (!ctl_send(RPC_CTL_ADDPEERADDRESS, hp, tried, ec, em, &r, NULL, 0)) return 0;
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
    if (!ctl_send(RPC_CTL_DISCONNECT, addr ? addr : "", nodeid, ec, em, &r, NULL, 0)) return 0;
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
    /* ---- RPC-8 (audit 2026-09-03): validate the subnet HERE ----
     * The string was never parsed before storage, so `setban "not-an-ip" add`
     * succeeded, appeared in listbanned, and never matched anything. Core's
     * setban runs LookupSubNet first and raises -30.
     *
     * WEAK, following the node_config_get_proxy_info pattern documented above:
     * bmc_cli links this whole file as a pure HTTP client and does not
     * link daemon/subnet.c. A NULL check keeps that build working rather than
     * forcing a subnet parser into a binary that only speaks HTTP -- and
     * tests/test_rpc_node is the one other target that links rpc_node.o
     * without it. Where the parser is absent the old behaviour stands, which
     * is why the worker keeps its own guard too. */
    { subnet_t probe;
      if (subnet_parse){
          if (!subnet_parse(subnet, &probe)){
              *ec = -30; *em = "Error: Invalid IP/Subnet"; return 0; }
      } }
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
    if (!ctl_send(RPC_CTL_SETBAN, subnet, until, ec, em, &r, NULL, 0)) return 0;
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
    if (!ctl_send(RPC_CTL_CLEARBANNED, "", 0, ec, em, NULL, NULL, 0)) return 0;
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
    if (!ctl_send(RPC_CTL_SETNETACTIVE, "", on, ec, em, NULL, NULL, 0)) return 0;
    *res = rj_bool(on);                       /* Core echoes the new state */
    return 1;
}

static int cmd_ping(rj_val** res, long* ec, const char** em){
    if (!ctl_send(RPC_CTL_PING, "", 0, ec, em, NULL, NULL, 0)) return 0;
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
    static char tbuf[256];
    if (!params || params->typ != RJ_ARR || params->nitems < 1){
        *ec = -1; *em = "gettxspendingprevout requires outputs"; return 0; }
    /* Core type-checks EVERY argument before ANY value and reports EVERY
     * failing position in one object: `gettxspendingprevout [] "x"` is
     * Position 2 (options), not the empty-outputs -8, and `["z","q"]` names
     * both positions. Measured against v31.1, 2026-09-15. */
    { rj_typeerrs te; rj_typeerr_init(&te);
      if (params->items[0]->typ != RJ_ARR)
          rj_typeerr_add(&te, 1, "outputs", params->items[0], "array");
      if (params->nitems >= 2 && params->items[1]->typ != RJ_OBJ &&
          params->items[1]->typ != RJ_NULL)
          rj_typeerr_add(&te, 2, "options", params->items[1], "object");
      if (rj_typeerr_fail(&te, ec, em)) return 0; }
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
        /* a field inside an options object gets Core's OTHER -3 shape: no
         * wrapper, no position, the field named inline -- and a null field
         * drops even the field name. See rj_wrong_field_type_msg. */
        if (mo){ if (mo->typ != RJ_BOOL){
            *ec = -3; *em = rj_wrong_field_type_msg(tbuf, sizeof tbuf, "mempool_only", mo, "bool"); return 0; }
            mempool_only = mo->str[0] == '1'; }
        if (rt){ if (rt->typ != RJ_BOOL){
            *ec = -3; *em = rj_wrong_field_type_msg(tbuf, sizeof tbuf, "return_spending_tx", rt, "bool"); return 0; }
            return_tx = rt->str[0] == '1'; }
    }
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

/* ---- vsize cache for the BULK path ---------------------------------------
 * mpe_entry_obj sums ancestor and descendant vsizes by looking up each set
 * member in the pool and PARSING IT. For one transaction that is nothing. For
 * the whole pool it is quadratic in the cluster size: measured 2026-09-11 on
 * 15,302 live entries, the widened getrawmempool took 8.38 s, against Core's
 * 0.38 s for 22,992 -- about 33x per entry. On a node whose RPC server handles
 * one request at a time, an 8 s call is an outage for every other consumer.
 *
 * The fix is to parse each transaction ONCE per call. The bulk path walks the
 * pool anyway, so it records (txid, vsize) as it goes, sorts by txid, and the
 * set sums become binary searches. Single-entry getmempoolentry passes no
 * cache and keeps the old direct path, which is cheaper for one lookup. */
/* vs is the ENTRY size Core reports (GetTxSize, sigops-adjusted) once the
 * graph has supplied the member's sigop cost (inf >= 0), and plain BIP141
 * until then; w is the BIP141 weight either way. rbf: the tx itself signals
 * BIP125, so bip125-replaceable over an ancestor set is lookups too. */
typedef struct { unsigned char id[32]; unsigned long vs, w; long inf; unsigned char rbf; } mpe_vs_t;
static mpe_vs_t* g_mpe_vs; static unsigned long g_mpe_vs_n;
/* the whole graph for this call, filled once by pol_entry_info_all; indexed
   by the same sorted txid order as the vsize cache above */
static mp_entry_info* g_mpe_inf; static unsigned char (*g_mpe_inf_id)[32]; static long g_mpe_inf_n;
/* the per-call chunk cache (2026-09-19), parallel to g_mpe_vs: st 0 = not
 * yet computed, 1 = fee/weight hold this entry's chunk, -1 = no honest answer
 * (component beyond the 64 bound, or a graph that did not build). One cluster
 * linearization fills every member's slot, which is what keeps bulk
 * getrawmempool linear in the pool rather than in pool x cluster size. */
typedef struct { unsigned long long fee, weight; signed char st; } mpe_chunk_t;
static mpe_chunk_t* g_mpe_chunk;
/* clusters linearized since start: the cost model, exported for the tests */
static unsigned long g_mpe_cluster_builds;
unsigned long rpc_node_cluster_builds(void){ return g_mpe_cluster_builds; }
static int mpe_vs_cmp(const void* a, const void* b){
    return memcmp(((const mpe_vs_t*)a)->id, ((const mpe_vs_t*)b)->id, 32);
}
/* the member's vsize, or 0 when it is no longer in the pool -- the same
 * "filtered to txs still in the pool" rule the direct path applies */
static long mpe_vs_find(const unsigned char id[32]){
    unsigned long lo = 0, hi = g_mpe_vs_n;
    while (lo < hi){
        unsigned long mid = lo + (hi - lo) / 2;
        int c = memcmp(g_mpe_vs[mid].id, id, 32);
        if (c == 0) return (long)mid;
        if (c < 0) lo = mid + 1; else hi = mid;
    }
    return -1;
}
static long mpe_inf_lookup(const unsigned char id[32]){
    long k = mpe_vs_find(id);
    return (k >= 0 && g_mpe_inf) ? g_mpe_vs[k].inf : -1;
}
static unsigned long mpe_vs_lookup(const unsigned char id[32]){
    long k = mpe_vs_find(id);
    return k >= 0 ? g_mpe_vs[k].vs : 0;
}

/* Core's entry size, CTxMemPoolEntry::GetTxSize(): the sigops-ADJUSTED
 * vsize, ceil(max(weight, sigop_cost * bytes_per_sigop) / 4)
 * (policy.cpp GetVirtualTransactionSize). v31.1 reports it as `vsize`, and
 * sums it for ancestorsize/descendantsize. */
static unsigned long mpe_adj_vsize(unsigned long w, unsigned sigop_cost){
    unsigned long long bps = g_mph.bytespersigop ? g_mph.bytespersigop() : 20;
    unsigned long long adjw = w, sw = (unsigned long long)sigop_cost * bps;
    if (sw > adjw) adjw = sw;
    return (unsigned long)((adjw + 3) / 4);
}

/* BIP125 signalling (util/rbf.cpp SignalsOptInRBF): any input with
 * nSequence <= 0xfffffffd. A parse anomaly answers "does not signal". */
static int mp_tx_signals_rbf(const unsigned char* tx, unsigned long len){
    if (len < 10) return 0;
    unsigned long p = (tx[4]==0x00 && tx[5]==0x01) ? 6 : 4, c;
    unsigned long nin = mp_varint(tx+p,&c); p+=c;
    for (unsigned long i=0;i<nin;i++){
        if (p+37 > len) return 0;
        p+=36; unsigned long sl=mp_varint(tx+p,&c); p+=c+sl;
        if (p+4 > len) return 0;
        unsigned long seq = (unsigned long)tx[p] | ((unsigned long)tx[p+1]<<8) |
                            ((unsigned long)tx[p+2]<<16) | ((unsigned long)tx[p+3]<<24);
        if (seq <= 0xfffffffdUL) return 1;
        p+=4;
    }
    return 0;
}

/* One ancestor/descendant member's entry size for the set sums, 0 when it
 * is no longer in the pool. The bulk cache holds it once the graph has
 * given the member's sigop cost; otherwise the member's own registry node
 * does (self's is already in hand). */
static unsigned long mpe_member_vsize(const unsigned char id[32], const unsigned char* self,
                                      const mp_entry_info* selfinf){
    unsigned long w2;
    if (g_mpe_vs){
        long k = mpe_vs_find(id);
        if (k < 0) return 0;
        if (g_mpe_vs[k].inf >= 0) return g_mpe_vs[k].vs;
        w2 = g_mpe_vs[k].w;
    } else {
        unsigned long l2=0; const unsigned char* t2 = g_mph.get(g_mph.mp, id, &l2);
        if (!t2) return 0;
        w2 = mp_tx_weight(t2, l2);
    }
    unsigned sc = 0;
    if (!memcmp(id, self, 32)) sc = selfinf->sigop_cost;
    else if (g_mph.polstate && g_mph.pol_entry_info){
        static mp_entry_info mi;             /* ~8 KB: kept off the stack */
        if (g_mph.pol_entry_info(g_mph.polstate, id, &mi) == 1) sc = mi.sigop_cost;
    }
    return mpe_adj_vsize(w2, sc);
}
/* does this member signal BIP125 itself? (-1: not in the pool) */
static int mpe_member_rbf(const unsigned char id[32]){
    if (g_mpe_vs){ long k = mpe_vs_find(id); return k >= 0 ? g_mpe_vs[k].rbf : -1; }
    unsigned long l2=0; const unsigned char* t2 = g_mph.get(g_mph.mp, id, &l2);
    return t2 ? mp_tx_signals_rbf(t2, l2) : -1;
}

/* the per-entry object, shared by getmempoolentry and verbose getrawmempool */
static int mpc_lookup_here(void* ctx, const unsigned char txid[32], mpc_entry* out);
static rj_val* mpe_entry_obj(const unsigned char* txid, const unsigned char* tx, unsigned long len);
static int cmd_getrawmempool(const rj_val* params, rj_val** res){
    /* verbose (params[0]==true) -> object keyed by txid; else -> array of
     * txids (display byte order).
     *
     * 2026-09-11: verbose entries are now the SAME object getmempoolentry
     * returns, which is what Core does. They used to carry four fields --
     * vsize, weight, time, fees.base -- because this was landed as a first
     * slice whose comment said the aggregates would come with
     * getmempoolentry. They did: the accept-path policy registry has held the
     * real ancestor/descendant graph ever since, and getmempoolentry has been
     * serving `depends`, `spentby`, ancestorcount/size and descendantcount/size
     * from it. Nobody came back to widen the bulk call.
     *
     * That gap was load-bearing for a consumer. Building CPFP clusters over
     * the whole pool needs the graph for every entry, and the only way to get
     * it was one getmempoolentry per transaction -- 19,475 calls against an
     * RPC server that handles one request at a time. So bmcmonitor could only
     * show ancestor packages for the block template, via getblocktemplate's
     * own `depends`, and said so rather than pretending otherwise.
     *
     * 2026-09-12: that list is now shorter, and the reason it was long is
     * gone. `vsize_adjusted` and `vsize_bip141` are emitted unconditionally --
     * the registry stores each entry's BIP141 sigop cost and the policy layer
     * knows -bytespersigop, so Core's adjusted weight,
     * max(weight, sigop_cost * bytes_per_sigop) (policy.cpp
     * GetSigOpsAdjustedWeight), is exactly computable here. `chunkweight` and
     * `fees.chunk` are emitted for a SINGLETON cluster only, where they are
     * determined without any linearization: a lone transaction is its own
     * chunk. For a multi-transaction cluster both depend on Core's cluster
     * linearization, which this node does not implement, and they are omitted
     * rather than guessed.
     *
     * 2026-09-19: superseded -- the cluster layer (mempool_cluster.c) does
     * linearize, and every entry now carries both keys on this path too; see
     * mpe_chunk_of and the per-call chunk cache.
     *
     * 2026-09-18: `vsize_adjusted` and `vsize_bip141` are gone again. Both
     * came off the v31.99 development oracle; v31.1 has neither, in any RPC.
     * What v31.1 does have is the adjusted size under the plain name: its
     * `vsize` is CTxMemPoolEntry::GetTxSize(), the sigops-adjusted vsize, and
     * ancestorsize/descendantsize sum the same. So the number vsize_adjusted
     * carried now travels as `vsize`, and `bip125-replaceable` -- a v31.1
     * field this entry lacked -- is emitted. */
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
        /* ONE parse per transaction for the whole call: fill the vsize cache
         * on a first pass, so the ancestor/descendant sums below are binary
         * searches instead of a pool lookup plus a full parse per set member.
         * If the allocation fails the cache stays null and every entry takes
         * the slower direct path -- correct either way, just slower. */
        if (verbose && n){
            g_mpe_vs = (mpe_vs_t*)malloc((size_t)n * sizeof *g_mpe_vs);
            g_mpe_vs_n = 0;
            if (g_mpe_vs){
                for (unsigned long i=0;i<n;i++){ mp_ent e2;
                    if (mp_slot(g_mph.mp,i,&e2) != 1) continue;
                    memcpy(g_mpe_vs[g_mpe_vs_n].id, e2.txid, 32);
                    g_mpe_vs[g_mpe_vs_n].w = mp_tx_weight(e2.tx, e2.len);
                    g_mpe_vs[g_mpe_vs_n].vs = (g_mpe_vs[g_mpe_vs_n].w+3)/4;
                    g_mpe_vs[g_mpe_vs_n].inf = -1;
                    g_mpe_vs[g_mpe_vs_n].rbf = (unsigned char)mp_tx_signals_rbf(e2.tx, e2.len);
                    g_mpe_vs_n++;
                }
                /* the whole graph in one pass; -1 means fall back per entry */
                g_mpe_inf_n = -1;
                if (g_mph.polstate && g_mph.pol_entry_info_all){
                    g_mpe_inf = (mp_entry_info*)malloc((size_t)n * sizeof *g_mpe_inf);
                    g_mpe_inf_id = (unsigned char (*)[32])malloc((size_t)n * 32);
                    if (g_mpe_inf && g_mpe_inf_id)
                        g_mpe_inf_n = g_mph.pol_entry_info_all(g_mph.polstate, g_mpe_inf, g_mpe_inf_id, (unsigned)n);
                    if (g_mpe_inf_n < 0){ free(g_mpe_inf); free(g_mpe_inf_id); g_mpe_inf=0; g_mpe_inf_id=0; }
                }
                qsort(g_mpe_vs, g_mpe_vs_n, sizeof *g_mpe_vs, mpe_vs_cmp);
                for (long q=0;q<g_mpe_inf_n;q++){
                    long k = mpe_vs_find(g_mpe_inf_id[q]);
                    if (k >= 0){ g_mpe_vs[k].inf = q;
                                 g_mpe_vs[k].vs = mpe_adj_vsize(g_mpe_vs[k].w, g_mpe_inf[q].sigop_cost); }
                }
                /* chunk cache: only with the one-pass graph (the lookup it
                 * drives reads g_mpe_inf); without it, per-entry builds */
                if (g_mpe_inf && g_mpe_vs_n)
                    g_mpe_chunk = (mpe_chunk_t*)calloc(g_mpe_vs_n, sizeof *g_mpe_chunk);
            }
        }
        for (unsigned long i=0;i<n;i++){ mp_ent e;
            if (mp_slot(g_mph.mp,i,&e) != 1) continue;
            char hx[65];
            for (int k=0;k<32;k++){ unsigned char b=e.txid[31-k]; hx[k*2]=HEXD[b>>4]; hx[k*2+1]=HEXD[b&15]; }
            hx[64]=0;
            if (!verbose){ rj_arr_push(out, rj_str(hx)); continue; }
            /* the same builder getmempoolentry uses, under the same pool lock */
            rj_obj_set(out, hx, mpe_entry_obj(e.txid, e.tx, e.len));
        }
        free(g_mpe_chunk); g_mpe_chunk = 0;
        free(g_mpe_vs); g_mpe_vs = 0; g_mpe_vs_n = 0;
        free(g_mpe_inf); free(g_mpe_inf_id); g_mpe_inf = 0; g_mpe_inf_id = 0; g_mpe_inf_n = 0;
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
static long long pri_delta_of(const unsigned char txid[32]);
static rj_val* mpe_amount(unsigned long long sat){
    return rj_numf("%llu.%08llu", sat/100000000ULL, sat%100000000ULL);
}
static int cmd_getmempoolentry(const rj_val* params, rj_val** res, long* ec, const char** em){
    static char embuf[256];
    if (!params || params->typ != RJ_ARR || params->nitems < 1){
        *ec = -1; *em = "getmempoolentry requires txid"; return 0; }
    if (params->items[0]->typ != RJ_STR)
        return rpc_wrong_type(ec, em, embuf, sizeof embuf, 1, "txid", params->items[0], "string");
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

/* The cluster layer's view of the pool during a BULK call: the same fields
 * mpc_lookup_here reads (modified fee, sigops-adjusted weight, direct edges),
 * taken from this call's one-pass graph and weight cache instead of one
 * registry walk per member. Edges are filtered to transactions still in the
 * pool -- the rule `depends`/`spentby` already apply -- so a stale registry
 * edge cannot fail the build. */
static int mpc_lookup_bulk(void* ctx, const unsigned char txid[32], mpc_entry* out)
{
    (void)ctx;
    long k = mpe_vs_find(txid);
    if (k < 0 || g_mpe_vs[k].inf < 0) return 0;
    const mp_entry_info* inf = &g_mpe_inf[g_mpe_vs[k].inf];
    memset(out, 0, sizeof *out);
    long long modified = (long long)inf->fee + pri_delta_of(txid);
    out->fee = modified < 0 ? 0 : (uint64_t)modified;
    { unsigned long long bps = g_mph.bytespersigop ? g_mph.bytespersigop() : 20;
      unsigned long long w = g_mpe_vs[k].w;
      unsigned long long sw = (unsigned long long)inf->sigop_cost * bps;
      out->weight = sw > w ? sw : w; }
    for (int i = 0; i < inf->n_depends && out->n_parents < MPC_MAX_CLUSTER; i++)
        if (mpe_vs_find(inf->depends[i]) >= 0)
            memcpy(out->parents[out->n_parents++], inf->depends[i], 32);
    for (int i = 0; i < inf->n_spentby && out->n_children < MPC_MAX_CLUSTER; i++)
        if (mpe_vs_find(inf->spentby[i]) >= 0)
            memcpy(out->children[out->n_children++], inf->spentby[i], 32);
    return 1;
}

/* The chunk `txid` belongs to in its cluster's linearization: Core's
 * GetMainChunkFeerate (txgraph), which entryToJSON reports as chunkweight
 * (sigops-adjusted WEIGHT, not vsize) and fees.chunk (the chunk's summed
 * MODIFIED fee). 1 with *fee and *weight set, 0 when there is no honest answer.
 *
 * Linearization: ancestor-score greedy, then Core's PostLinearize (see
 * mempool_cluster.h). Core v31.1 searches for the optimum with a
 * spanning-forest algorithm; the two agree wherever the greedy+post result is
 * optimal, which PostLinearize guarantees for chains and trees (at most one
 * parent, or at most one child, per member) and which covers the CPFP, chain
 * and diamond shapes pinned in the tests. A cluster where they differ is one
 * where Core found a strictly better chunking than greedy -- the number here
 * would then be a valid chunking, not Core's. Recorded in
 * docs/PARITY_RPC_FIELDS.md.
 *
 * Under the pool lock (the caller holds it). With the bulk chunk cache the
 * first member to ask pays for the cluster and every other member reads the
 * answer: one build per cluster per call. */
static int mpe_chunk_of(const unsigned char txid[32], unsigned long long* fee,
                        unsigned long long* weight)
{
    int bulk = (g_mpe_chunk && g_mpe_inf && g_mpe_vs);
    long self_k = bulk ? mpe_vs_find(txid) : -1;
    if (bulk && self_k >= 0 && g_mpe_chunk[self_k].st){
        if (g_mpe_chunk[self_k].st < 0) return 0;
        *fee = g_mpe_chunk[self_k].fee; *weight = g_mpe_chunk[self_k].weight;
        return 1;
    }
    mpc_cluster cl;                   /* ~4 KB + 1.5 KB, as getmempoolcluster */
    mpc_chunking ch;
    int lin[MPC_MAX_CLUSTER];
    g_mpe_cluster_builds++;
    int ok = mpc_build_cluster(0, (bulk && self_k >= 0) ? mpc_lookup_bulk : mpc_lookup_here,
                               txid, &cl) == 0
          && !cl.truncated && cl.n >= 1
          && mpc_linearize_ancestor_score(&cl, lin) == 0
          && mpc_post_linearize(&cl, lin) == 0
          && mpc_chunk_linearization(&cl, lin, &ch) == 0;
    if (!ok){
        /* mark what was collected, so a >64 component is not rebuilt by
         * each of its members in turn */
        if (bulk){
            if (self_k >= 0) g_mpe_chunk[self_k].st = -1;
            for (int m = 0; m < cl.n; m++){ long k2 = mpe_vs_find(cl.txid[m]);
                if (k2 >= 0 && !g_mpe_chunk[k2].st) g_mpe_chunk[k2].st = -1; }
        }
        return 0;
    }
    int found = 0;
    for (int c = 0; c < ch.n; c++){
        for (int m = 0; m < cl.n; m++){
            if (!(ch.c[c].members & ((uint64_t)1 << m))) continue;
            if (!found && !memcmp(cl.txid[m], txid, 32)){
                *fee = ch.c[c].fee; *weight = ch.c[c].weight; found = 1; }
            if (bulk){ long k2 = mpe_vs_find(cl.txid[m]);
                if (k2 >= 0){ g_mpe_chunk[k2].fee = ch.c[c].fee;
                              g_mpe_chunk[k2].weight = ch.c[c].weight;
                              g_mpe_chunk[k2].st = 1; } }
        }
    }
    return found;
}

/* Build one getmempoolentry-shaped object (assumes mp_lock HELD; also the
 * per-member body of the verbose getmempoolancestors/-descendants forms). */
static rj_val* mpe_entry_obj(const unsigned char* txid, const unsigned char* tx, unsigned long len){
    rj_val* o = rj_obj();
    unsigned long w = mp_tx_weight(tx, len);

    mp_entry_info inf; int have_inf = 0;
    /* Prefer the one-pass graph when this call built one; otherwise ask per
     * txid. The FALLBACK MATTERS: the bulk build is skipped when the node
     * exposes no pol_entry_info_all and refused when its allocation fails, and
     * the first cut of this returned no graph at all in those cases -- it made
     * the per-txid branch conditional on there being no bulk cache, so a
     * verbose call with a cache but no graph silently dropped depends,
     * spentby and both counts. The suite caught it immediately. */
    long myinf = (g_mpe_vs && g_mpe_inf) ? mpe_inf_lookup(txid) : -1;
    if (myinf >= 0){ inf = g_mpe_inf[myinf]; have_inf = 1; }
    else if (g_mph.polstate && g_mph.pol_entry_info)
        have_inf = (int)g_mph.pol_entry_info(g_mph.polstate, txid, &inf);
    if (!have_inf) inf.sigop_cost = 0;
    /* vsize is Core's entry size, the sigops-adjusted one (see
     * mpe_adj_vsize); weight stays BIP141, as in Core. Without the registry
     * the sigop cost is unknown and the two coincide. */
    unsigned long vs = mpe_adj_vsize(w, inf.sigop_cost);
    rj_obj_set(o, "vsize", rj_numf("%lu", vs));
    rj_obj_set(o, "weight", rj_numf("%lu", w));
    rj_obj_set(o, "time", rj_numf("%ld", g_mph.time_of ? g_mph.time_of(txid) : 0));
    rj_obj_set(o, "height", rj_numf("%d", 0));   /* documented gap: entry height untracked */

    /* ancestor/descendant sums of the same entry size, over set members
     * STILL IN THE POOL; bip125-replaceable over the same ancestor set */
    unsigned long long anc_vs=0, desc_vs=0; int anc_n=0, desc_n=0, rbf = 0;
    if (have_inf){
        for (int i=0;i<inf.n_anc;i++){
            unsigned long v = mpe_member_vsize(inf.anc[i], txid, &inf);
            if (!v) continue;
            anc_vs += v; anc_n++;
            if (!rbf && mpe_member_rbf(inf.anc[i]) == 1) rbf = 1;
        }
        for (int i=0;i<inf.n_desc;i++){
            unsigned long v = mpe_member_vsize(inf.desc[i], txid, &inf);
            if (v){ desc_vs += v; desc_n++; } }
    } else { anc_n=1; desc_n=1; anc_vs=desc_vs=vs; }
    /* Core's IsRBFOptIn: the tx signals itself, or an unconfirmed ancestor
     * does (the set above holds self as well). Full-RBF does not enter into
     * it -- v31.1 reports signalling, not replaceability under its policy. */
    if (!rbf) rbf = mp_tx_signals_rbf(tx, len);
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
      /* Core's adjusted weight: max(weight, sigop_cost * bytes_per_sigop)
       * (policy.cpp GetSigOpsAdjustedWeight) -- `vsize` above is this over
       * 4, rounded up. */
      { unsigned long long bps = g_mph.bytespersigop ? g_mph.bytespersigop() : 20;
        unsigned long long adjw = w;
        if (have_inf){ unsigned long long sw = (unsigned long long)inf.sigop_cost * bps;
                       if (sw > adjw) adjw = sw; }
        /* A SINGLETON cluster -- no unconfirmed parents, no unconfirmed
         * children -- is its own chunk, so chunkweight and fees.chunk are
         * determined with no linearization at all. Both counts include the tx
         * itself, so 1 and 1 is the lone-transaction case. */
        if (have_inf && inf.n_anc == 1 && inf.n_desc == 1){
            rj_obj_set(o, "chunkweight", rj_numf("%llu", adjw));
            rj_obj_set(fees, "chunk", rj_numf("%s%lld.%08lld",
                       modified<0?"-":"", am/100000000LL, am%100000000LL));
        } else if (have_inf){
            /* A member of a real cluster: the chunk this transaction lands in
             * when its cluster is linearized and chunked (mpe_chunk_of).
             *
             * 2026-09-19: on BOTH paths. Until today this branch ran only for
             * a single getmempoolentry, and bulk getrawmempool omitted the two
             * keys for every cluster member -- 71,710 of 79,626 production
             * entries -- because building a cluster per entry there would have
             * been quadratic. The bulk call now carries a per-call chunk cache:
             * the first member of a cluster to be rendered linearizes it and
             * records the answer for EVERY member, so the whole call costs one
             * linearization per cluster. The keys are omitted only where no
             * honest answer exists: a component beyond the 64-transaction
             * bound, or a graph that does not build. */
            unsigned long long cf = 0, cw = 0;
            if (mpe_chunk_of(txid, &cf, &cw)){
                rj_obj_set(o, "chunkweight", rj_numf("%llu", cw));
                rj_obj_set(fees, "chunk", mpe_amount(cf));
            }
        } }
      rj_obj_set(o, "fees", fees); }

    { rj_val* dep = rj_arr();
      if (have_inf) for (int i=0;i<inf.n_depends;i++){ unsigned long l2=0;
          int here = g_mpe_vs ? (mpe_vs_lookup(inf.depends[i]) != 0) : (g_mph.get(g_mph.mp, inf.depends[i], &l2) != 0);
          if (here){ char h2[65]; mpe_hex(h2, inf.depends[i]); rj_arr_push(dep, rj_str(h2)); } }
      rj_obj_set(o, "depends", dep); }
    { rj_val* sb = rj_arr();
      if (have_inf) for (int i=0;i<inf.n_spentby;i++){ unsigned long l2=0;
          int here = g_mpe_vs ? (mpe_vs_lookup(inf.spentby[i]) != 0) : (g_mph.get(g_mph.mp, inf.spentby[i], &l2) != 0);
          if (here){ char h2[65]; mpe_hex(h2, inf.spentby[i]); rj_arr_push(sb, rj_str(h2)); } }
      rj_obj_set(o, "spentby", sb); }
    rj_obj_set(o, "bip125-replaceable", rj_bool(rbf));
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
    static char embuf[256];
    if (!params || params->typ != RJ_ARR || params->nitems < 1){
        *ec = -1; *em = want_desc ? "getmempooldescendants requires txid"
                                  : "getmempoolancestors requires txid"; return 0; }
    if (params->items[0]->typ != RJ_STR)
        return rpc_wrong_type(ec, em, embuf, sizeof embuf, 1, "txid", params->items[0], "string");
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

/* Core ParseConfirmTarget: "Invalid conf_target, must be between 1 and <max>" */
/* position 1's arity alone, so a caller can collect a LATER position's type
 * error alongside this one's before any value work (see cmd_estimaterawfee) */
static int fee_parse_target_arity(const rj_val* params, const char* method,
                                  long* ec, const char** em){
    if (!params || params->typ != RJ_ARR || params->nitems < 1){
        static char ubuf[96];
        snprintf(ubuf, sizeof ubuf, "%s requires conf_target", method);
        *ec = -1; *em = ubuf; return 0; }
    return 1;
}
static int fee_parse_target(const rj_val* params, const char* method, unsigned max_target,
                            long* ec, const char** em, int* out){
    static char msg[256];
    if (!fee_parse_target_arity(params, method, ec, em)) return 0;
    const rj_val* v = params->items[0];
    if (v->typ != RJ_NUM){
        rj_typeerrs te; rj_typeerr_init(&te);
        rj_typeerr_add(&te, 1, "conf_target", v, "number");
        rj_typeerr_fail(&te, ec, em); return 0; }
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
    if (!fee_parse_target(params, "estimatesmartfee", max_target, ec, em, &target)) return 0;
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
    /* threshold's TYPE settles before conf_target's RANGE: `estimaterawfee 0
     * "x"` reports Position 2 (threshold), not the out-of-range target.
     * Measured against v31.1, 2026-09-15. fee_parse_target checks position 1's
     * type first (lower position wins) and its range second, so the threshold
     * check sits between the two -- which is why it is not simply hoisted
     * above the call. */
    double threshold = 0.95;
    const rj_val* tv = (params && params->typ == RJ_ARR && params->nitems >= 2 &&
                        params->items[1]->typ != RJ_NULL) ? params->items[1] : 0;
    if (!fee_parse_target_arity(params, "estimaterawfee", ec, em)) return 0;
    { rj_typeerrs te; rj_typeerr_init(&te);
      if (params->items[0]->typ != RJ_NUM)
          rj_typeerr_add(&te, 1, "conf_target", params->items[0], "number");
      if (tv && tv->typ != RJ_NUM)
          rj_typeerr_add(&te, 2, "threshold", tv, "number");
      if (rj_typeerr_fail(&te, ec, em)) return 0; }
    if (!fee_parse_target(params, "estimaterawfee", max_target, ec, em, &target)) return 0;
    if (tv) threshold = atof(tv->str);
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
/* shared txid-arg validation; display -> internal. The caller has already
 * rejected a missing argument with -1, so a non-string here is Core's -3. */
static int pri_parse_txid(const rj_val* v, unsigned char txid[32], long* ec, const char** em){
    static char embuf[256];
    if (!v || v->typ != RJ_STR)
        return rpc_wrong_type(ec, em, embuf, sizeof embuf, 1, "txid", v, "string");
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
    { rj_typeerrs te; rj_typeerr_init(&te);
      if (params->items[0]->typ != RJ_STR)
          rj_typeerr_add(&te, 1, "txid", params->items[0], "string");
      if (params->items[2]->typ != RJ_NUM)
          rj_typeerr_add(&te, 3, "fee_delta", params->items[2], "number");
      if (rj_typeerr_fail(&te, ec, em)) return 0; }
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
        static char dbuf[256];
        return rpc_wrong_type(ec, em, dbuf, sizeof dbuf, 3, "fee_delta", params->items[2], "number"); }
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
    unsigned char** retry; unsigned long* retry_len; long long* retry_time;
    long nretry, retry_cap;
    int collecting;
    int aborted;            /* shutdown requested, or the worker stopped answering */
    int consec_timeouts;    /* entries in a row that drew no ack at all */
    long restored_times;    /* accepts whose persisted arrival time was applied */
    /* WHY entries were refused. The load already orders parents before children
     * (mpd_order_parents_first), so "it arrived before its parent" is not the
     * explanation any more and the old log line saying so was misleading. These
     * count what the worker actually said. */
    long rej_missing, rej_conflict, rej_policy, rej_other, rej_noack;
    long already;           /* in the pool already -- present, not refused */
    const char* abort_why;
} mpd_import_ctx;
/* The parent's shutdown flag (main.c installs it): a reload that waits 90 s
 * per entry for a worker that is gone would otherwise hold SIGTERM off for
 * hours -- the 2026-09-01 01:07 "deactivating" stall. */
static const volatile sig_atomic_t* g_mpd_shutdown_flag;
void rpc_node_set_shutdown_flag(const volatile sig_atomic_t* f){ g_mpd_shutdown_flag = f; }
#define MPD_POLL_US 200      /* reload ack poll: 3 ms per entry was 30 s of pure waiting on a 10k dump */
/* ---- parents-first ordering (2026-09-01) --------------------------------
 * mempool.dat is written in pool order, not parent-before-child, so on a
 * real dump about half the entries were rejected once for a missing input
 * and re-offered in retry passes (8018 entries: 4203 waited). Collect the
 * dump first, then emit every entry after the in-dump parents it spends
 * (Kahn's algorithm, file order preserved among the ready ones). */
typedef struct { unsigned char* tx; unsigned long len; long long t, d; unsigned char txid[32]; } mpd_ent;
typedef struct { mpd_ent* v; long n, cap; int oom; } mpd_collect_ctx;
static int mpd_collect_sink(void* vctx, const unsigned char* tx, unsigned long len, long long t, long long d){
    mpd_collect_ctx* c = (mpd_collect_ctx*)vctx;
    if (c->n == c->cap){ long nc = c->cap ? c->cap * 2 : 256; mpd_ent* nv = realloc(c->v, (size_t)nc * sizeof *nv); if (!nv){ c->oom = 1; return -1; } c->v = nv; c->cap = nc; }
    unsigned char* cp = malloc(len); if (!cp){ c->oom = 1; return -1; }
    memcpy(cp, tx, len);
    static unsigned char scratch[RPC_TXID_SCRATCH];   /* RPC-20 */
    mpd_ent* e = &c->v[c->n]; e->tx = cp; e->len = len; e->t = t; e->d = d;
    if (!tx_txid(e->txid, cp, len, scratch, sizeof scratch)) memset(e->txid, 0, 32);
    c->n++; return 0;
}
/* every prevout txid of `tx`: cb(ctx, txid_wire) per input */
static void mpd_each_prevout(const unsigned char* tx, unsigned long len, void (*cb)(void*, const unsigned char*), void* ctx){
    if (len < 10) return;
    unsigned long p = 4; if (len > 6 && tx[4] == 0x00 && tx[5] == 0x01) p = 6;
    unsigned long cc; unsigned long n_in = mp_varint(tx + p, &cc); p += cc;
    if (n_in == 0 || n_in > 100000) return;
    for (unsigned long i = 0; i < n_in; i++){
        if (p + 36 > len) return;
        cb(ctx, tx + p); p += 36;
        unsigned long ssl = mp_varint(tx + p, &cc); p += cc + ssl + 4;
        if (p > len) return;
    }
}
typedef struct { const mpd_ent* v; long n; const long* slot; unsigned long mask; long* indeg; long self; long* children; long* child_head; long* child_next; long nchild; } mpd_topo_ctx;
static long mpd_find(const mpd_topo_ctx* T, const unsigned char* txid){
    unsigned long h = 0; for (int i = 0; i < 8; i++) h = (h << 8) | txid[i];
    for (unsigned long k = h & T->mask;; k = (k + 1) & T->mask){ long s = T->slot[k]; if (s < 0) return -1; if (!memcmp(T->v[s].txid, txid, 32)) return s; }
}
static void mpd_topo_edge(void* vctx, const unsigned char* prev){
    mpd_topo_ctx* T = (mpd_topo_ctx*)vctx; long p = mpd_find(T, prev);
    if (p < 0 || p == T->self) return;
    T->indeg[T->self]++;
    T->children[T->nchild] = T->self; T->child_next[T->nchild] = T->child_head[p]; T->child_head[p] = T->nchild; T->nchild++;
}
/* fills order[0..n) with entry indexes, parents before children; returns the
 * number placed (entries in a cycle -- impossible for valid txs -- go last) */
long mpd_order_parents_first(const mpd_ent* v, long n, long* order){
    unsigned long cap = 1; while (cap < (unsigned long)n * 2) cap <<= 1;
    long* slot = malloc(cap * sizeof *slot); long* indeg = calloc((size_t)n, sizeof *indeg);
    long total_in = 0; for (long i = 0; i < n; i++){ /* upper bound on edges: count inputs */ unsigned long p = 4; if (v[i].len > 6 && v[i].tx[4] == 0 && v[i].tx[5] == 1) p = 6; unsigned long cc; total_in += (long)mp_varint(v[i].tx + p, &cc); }
    long* children = malloc((size_t)(total_in + 1) * sizeof *children); long* child_next = malloc((size_t)(total_in + 1) * sizeof *child_next); long* child_head = malloc((size_t)n * sizeof *child_head);
    if (!slot || !indeg || !children || !child_next || !child_head){ free(slot); free(indeg); free(children); free(child_next); free(child_head); for (long i = 0; i < n; i++) order[i] = i; return n; }
    for (unsigned long k = 0; k < cap; k++) slot[k] = -1;
    for (long i = 0; i < n; i++){ unsigned long h = 0; for (int b = 0; b < 8; b++) h = (h << 8) | v[i].txid[b]; unsigned long k = h & (cap - 1); while (slot[k] >= 0) k = (k + 1) & (cap - 1); slot[k] = i; child_head[i] = -1; }
    mpd_topo_ctx T = { v, n, slot, cap - 1, indeg, 0, children, child_head, child_next, 0 };
    for (long i = 0; i < n; i++){ T.self = i; mpd_each_prevout(v[i].tx, v[i].len, mpd_topo_edge, &T); }
    long placed = 0, head = 0; long* q = order;
    for (long i = 0; i < n; i++) if (indeg[i] == 0) q[placed++] = i;
    while (head < placed){ long u = q[head++]; for (long e = child_head[u]; e >= 0; e = child_next[e]){ long c = children[e]; if (--indeg[c] == 0) q[placed++] = c; } }
    if (placed < n) for (long i = 0; i < n; i++) if (indeg[i] > 0){ q[placed++] = i; indeg[i] = 0; }
    free(slot); free(indeg); free(children); free(child_next); free(child_head);
    return placed;
}
/* mempool.dat's per-transaction entry_time, applied after the accept succeeds.
 * Weak so the test binaries that link rpc_node.o without daemon/mempool_cfg.c
 * still build; absent, the arrival time simply stays as stamped. */
extern int mempool_restore_accept_time(const unsigned char txid[32], long t) __attribute__((weak));

static int mpd_import_one(void* vctx, const unsigned char* tx, unsigned long len,
                          long long t, long long d){
    (void)d;            /* fee deltas are still not restorable: there is no
                         * prioritisetransaction path to replay one into */
    mpd_import_ctx* c = (mpd_import_ctx*)vctx;
    { mpd_import_ctx* c0 = (mpd_import_ctx*)vctx;
      /* counted as "other": the worker was never asked, so there is no reason
       * to classify -- but it IS a refused entry and has to appear in the
       * histogram, or the parts stop summing to the total */
      if (c0->aborted){ c0->rejected++; c0->rej_other++; return 0; } }   /* aborted: drain the rest */
    if (!g_status_rw) return -1;
    node_status_t* st = g_status_rw;
    pthread_mutex_lock(&g_submit_lock);
    if (len > RPC_TXSUBMIT_MAX){ pthread_mutex_unlock(&g_submit_lock); c->rejected++; c->rej_other++; return 0; }
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
        struct timespec ts = {0, MPD_POLL_US*1000L}; nanosleep(&ts, NULL);   /* the worker acks within ~0.5 ms once it is servicing the stream */
        waited += MPD_POLL_US;
    }
    if (ok && t > 0 && mempool_restore_accept_time){
        /* The worker stamped "now" when it admitted this. Put the time the
         * transaction ACTUALLY arrived back, so a restart does not reset the
         * pool's sense of age -- the departure journal's `waited` and
         * -mempoolexpiry both read this field. The helper vets the value; a
         * future or already-expired time is refused there, not here. */
        unsigned char id[32];
        static unsigned char scratch[RPC_TXSUBMIT_MAX];
        if (tx_txid(id, tx, len, scratch, sizeof scratch) &&
            mempool_restore_accept_time(id, (long)t)) c->restored_times++;
    }
    if (acked) c->consec_timeouts = 0;
    else if (!c->aborted && ++c->consec_timeouts >= 2){ c->aborted = 1; c->abort_why = "the worker is not answering"; }
    int missing = !ok && strstr((const char*)st->tx_submit_reason, "missing") != NULL;
    /* Classify now, while the worker's reason is still in the shared slot, but
     * do NOT count it yet: an entry about to be DEFERRED comes back through
     * here on the retry pass and would be counted twice. The first live
     * histogram showed exactly that -- "16 refused" over a list summing to 23,
     * the gap being the 7 re-offered entries. These counters must describe
     * ENTRIES, not attempts, or they do not reconcile with the total they sit
     * beside. */
    int why_class = 0;              /* 1 noack, 2 missing, 3 conflict, 4 already, 5 policy, 6 other */
    if (!ok){
        const char* why = (const char*)st->tx_submit_reason;
        if (!acked)                       why_class = 1;
        else if (missing)                 why_class = 2;
        else if (strstr(why, "conflict")) why_class = 3;
        else if (strstr(why, "already"))  why_class = 4;
        else if (why[0])                  why_class = 5;
        else                              why_class = 6;
    }
    pthread_mutex_unlock(&g_submit_lock);
    #define MPD_COUNT_REFUSAL() do { switch (why_class){ \
            case 1: c->rej_noack++;    break; case 2: c->rej_missing++;  break; \
            case 3: c->rej_conflict++; break; case 5: c->rej_policy++;   break; \
            default: c->rej_other++;   break; } } while (0)
    /* "already known" is NOT a refusal: the transaction IS in the pool, it just
     * arrived from a peer during boot before the dump was read. Counting it as
     * rejected understated the load badly -- 665 of 753 "refusals" on
     * 2026-09-16 were duplicates, so 17,122 of 17,210 entries were really in
     * the pool while the line claimed 753 had failed. */
    if (why_class == 4){ c->already++; return 0; }      /* present already: not a refusal */
    if (ok) c->accepted++;
    else if (missing && c->collecting){
        if (c->nretry == c->retry_cap){
            long ncap = c->retry_cap ? c->retry_cap * 2 : 64;
            unsigned char** nr = realloc(c->retry, (size_t)ncap * sizeof *nr);
            unsigned long* nl = realloc(c->retry_len, (size_t)ncap * sizeof *nl);
            long long*     nt = realloc(c->retry_time, (size_t)ncap * sizeof *nt);
            if (!nr || !nl || !nt){
                /* keep whatever realloc DID move, or the next free() is on a
                 * stale pointer; only the failed one is discarded */
                if (nr) c->retry = nr;
                if (nl) c->retry_len = nl;
                if (nt) c->retry_time = nt;
                c->rejected++; MPD_COUNT_REFUSAL(); return 0; }
            c->retry = nr; c->retry_len = nl; c->retry_time = nt; c->retry_cap = ncap;
        }
        unsigned char* cp = malloc(len);
        if (!cp){ c->rejected++; MPD_COUNT_REFUSAL(); return 0; }
        memcpy(cp, tx, len); c->retry[c->nretry] = cp; c->retry_len[c->nretry] = len;
        c->retry_time[c->nretry] = t; c->nretry++;
    } else { c->rejected++; MPD_COUNT_REFUSAL(); }
    #undef MPD_COUNT_REFUSAL
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
        /* the persisted time travels with the deferred entry: a child held back
         * for its parent is exactly as old as the file says, and dropping the
         * time here would leave a subset of the pool silently re-aged */
        long long* tms = c->retry_time; c->retry_time = 0;
        for (long i = 0; i < n; i++){ mpd_import_one(c, list[i], lens[i], tms ? tms[i] : 0, 0); free(list[i]); }
        free(list); free(lens); free(tms);
        passes++; gained += c->accepted - before;
        c->collecting = 0;
        if (c->accepted == before){ c->rejected = rej0 + c->nretry; break; }   /* no progress: the rest are real rejects */
    }
    for (long i = 0; i < c->nretry; i++) free(c->retry[i]);
    free(c->retry); free(c->retry_len); free(c->retry_time);
    c->retry = 0; c->retry_len = 0; c->retry_time = 0; c->nretry = 0;
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
    mpd_collect_ctx col; memset(&col, 0, sizeof col);
    long r = mempool_dump_read(path ? path : "mempool.dat", mpd_collect_sink, &col, err, sizeof err);
    if (r < 0 || col.oom){ for (long i = 0; i < col.n; i++) free(col.v[i].tx); free(col.v); return -1; }
    long* order = malloc((size_t)(col.n + 1) * sizeof *order);
    if (order) mpd_order_parents_first(col.v, col.n, order);
    for (long k = 0; k < col.n; k++){ long i = order ? order[k] : k; mpd_import_one(&c, col.v[i].tx, col.v[i].len, col.v[i].t, col.v[i].d); }
    for (long i = 0; i < col.n; i++) free(col.v[i].tx);
    free(col.v); free(order);
    long deferred = c.nretry;
    long gained = mpd_retry_passes(&c);
    /* The old line read "%ld waited for a parent, %ld of them then accepted",
     * which said the refusals were an ORDERING problem. They are not: this
     * function topologically sorts parents before children before submitting
     * anything, so a child's in-dump parent has always been offered first, and
     * the retry passes have recovered ZERO entries on every real load since
     * that sort landed (1,622 deferred on 2026-09-16 03:08 and 3,630 at 06:09,
     * both zero). The refusals are inputs that genuinely are not there. Saying
     * which is the difference between a number and a diagnosis. */
    fprintf(stderr, "[mempool] loaded %s: %ld of %ld in the pool (%ld admitted, %ld already there); "
                    "%ld refused: %ld missing-inputs, %ld conflicting, %ld policy, %ld no-ack, %ld other "
                    "(%ld re-offered, %ld then accepted); %ld arrival time(s) restored\n",
            path ? path : "mempool.dat", c.accepted + c.already, r, c.accepted, c.already,
            c.rejected, c.rej_missing, c.rej_conflict, c.rej_policy, c.rej_noack, c.rej_other,
            deferred, gained, c.restored_times);
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
    { unsigned char id[32]; static unsigned char scratch[RPC_TXID_SCRATCH];   /* RPC-20 */
      if (!tx_txid(id, stage, n, scratch, sizeof scratch)){ pthread_mutex_unlock(&g_submit_lock); *ec=-22; *em="TX decode failed"; return 0; }
      static const char* HEXD = "0123456789abcdef";
      for (int i=0;i<32;i++){ unsigned char b=id[31-i]; txidhex[i*2]=HEXD[b>>4]; txidhex[i*2+1]=HEXD[b&15]; }
      txidhex[64]=0; }

    /* stage into shared memory: buffer + len published BEFORE the seq bump */
    node_status_t* s = g_status_rw;
    /* Core v30 -privatebroadcast: the tx is validated and QUEUED for short-lived
     * Tor/I2P connections instead of entering the mempool; refused up front when
     * neither anonymity network is reachable (Core's exact words). */
    if (s->pb_enabled && !s->pb_reachable){
        pthread_mutex_unlock(&g_submit_lock);
        *ec = -1;
        *em = "-privatebroadcast is enabled, but none of the Tor or I2P networks is "
              "reachable. Maybe the location of the Tor proxy couldn't be retrieved "
              "from the Tor daemon at startup. Check whether the Tor daemon is running "
              "and that -torcontrol, -torpassword and -i2psam are configured properly.";
        return 0;
    }
    memcpy((void*)s->tx_submit_buf, stage, n);
    s->tx_submit_len = n;
    s->tx_submit_result = 0;
    s->tx_submit_private = s->pb_enabled ? 1 : 0;
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
 * package_msg, tx-results keyed by wtxid with txid / vsize /
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

/* Core emits reject-details alongside reject-reason for a refused tx
 * (rpc/mempool.cpp): the value is TxValidationState::ToString(), which is the
 * reject reason on its own when there is no debug message, and "reason, debug"
 * when there is. It is OMITTED for missing-inputs, where Core takes the other
 * branch and pushes only the reason. This node carries no separate debug
 * message, so details equals the reason -- which is precisely Core's output in
 * the no-debug-message case, not an approximation of it. */
static void tma_set_reject(rj_val* e, const char* rsn){
    rj_obj_set(e, "reject-reason", rj_str(rsn));
    if (strcmp(rsn, "missing-inputs") != 0)
        rj_obj_set(e, "reject-details", rj_str(rsn));
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
            static unsigned char sc[RPC_TXID_SCRATCH];   /* RPC-20 */
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
                tma_set_reject(e, r_reason[i][0] ? r_reason[i] : "transaction rejected");
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
        static unsigned char scratch[RPC_TXID_SCRATCH];   /* RPC-20 */
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
            rj_val* fees = rj_obj();
            rj_obj_set(fees, "base", rj_numf("%llu.%08llu", fee/100000000ULL, fee%100000000ULL));
            /* effective-feerate/effective-includes describe package feerate,
             * which this node does not compute -- omitted, not guessed. */
            rj_obj_set(e, "fees", fees);
        } else {
            rj_obj_set(e, "allowed", rj_bool(0));
            tma_set_reject(e, reason[0] ? reason : "transaction rejected");
        }
        rj_arr_push(arr, e);
    }
    s->tx_submit_test = 0;
    pthread_mutex_unlock(&g_submit_lock);
    *res = arr;
    return 1;
}

/* ---- bmcgetdownloadinfo (2026-09-10) ---------------------------------------
 * The parallel download's live state: which worker holds which peer, what
 * each is pulling and at what rate, and the window state that explains why
 * the tail is or is not moving.
 *
 * Core has NO counterpart, by construction. Its block download is 8 outbound
 * peers driven from one ThreadMessageHandler thread, so there is no worker to
 * report; here node_ibd_blocks_s blocks for the length of a chunk and cannot
 * multiplex, so each downloading peer is a forked process and the mapping
 * worker -> peer -> chunk -> rate is the only way to see what the sync is
 * doing. getpeerinfo shows the peers; it cannot show the window, the tail,
 * the adaptive stall timeout or the ban list, which is what an operator (and
 * bmcmonitor) needs when a sync slows down.
 *
 * NAMING (operator's rule, 2026-09-10): every command of ours is prefaced
 * bmc*. That also satisfies the reason the bmc.* config keys carry the
 * prefix -- a Core name must carry Core's exact semantics, so a call Core
 * does not have must not take a name Core might later use.
 *
 * A consumer whose RPC allowlist is default-deny over read-shaped prefixes
 * (bmcmonitor's server/rpc/allowlist.js) admits this by allowing "bmcget"
 * and "bmclist", NOT a bare "bmc": the marker plus a read verb keeps the
 * guard its own comment asks for, since a future bmcset* still fails to
 * match. Fields are plain snake_case and stable; a monitor differences the
 * counters itself.
 *
 * Answers {"active": false} outside a parallel download rather than failing,
 * so a poller can call it unconditionally. */

/* ---- bmcgetmempooljournal (2026-09-16) -------------------------------------
 * The mempool DEPARTURE journal. Core has no counterpart: when a transaction
 * leaves the pool without being mined -- evicted because the pool hit
 * -maxmempool, expired after -mempoolexpiry, or replaced -- Core forgets it,
 * so an explorer built on it cannot say what became of a transaction a user
 * broadcast. It shows a gap, or a "ghost" that was there and then was not.
 * daemon/mempool_journal.c records one bounded row per departure.
 *
 *   bmcgetmempooljournal                 -> stats + the most recent departures
 *   bmcgetmempooljournal <txid>          -> that transaction's latest departure
 *   bmcgetmempooljournal <count>         -> the most recent <count>
 *
 * Amounts are satoshis (this is an extension, not a Core-shaped reply, so it
 * uses the unit the record holds rather than Core's decimal BTC strings). */
static void mpj_hex_rev(char out[65], const unsigned char h[32]){
    static const char* D = "0123456789abcdef";
    for (int i = 0; i < 32; i++){ unsigned char b = h[31-i]; out[i*2] = D[b>>4]; out[i*2+1] = D[b&15]; }
    out[64] = 0;
}
static int mpj_all_zero(const unsigned char* p, int n){ for (int i=0;i<n;i++) if (p[i]) return 0; return 1; }

static rj_val* mpj_row(const mpj_rec* r){
    rj_val* o = rj_obj();
    char h[65];
    mpj_hex_rev(h, r->txid);   rj_obj_set(o, "txid", rj_str(h));
    /* wtxid is not recorded today (see daemon/mempool_cfg.c mempool_depart);
     * an all-zero field is "not recorded", and omitting it is more honest than
     * echoing the txid, which is right only for a non-witness transaction. */
    if (!mpj_all_zero(r->wtxid, 32)){ mpj_hex_rev(h, r->wtxid); rj_obj_set(o, "wtxid", rj_str(h)); }
    rj_obj_set(o, "reason", rj_str(mpj_reason_name(r->reason)));
    if (r->first_seen)  rj_obj_set(o, "firstseen", rj_numf("%lld", (long long)r->first_seen));
    rj_obj_set(o, "departed", rj_numf("%lld", (long long)r->departed_at));
    if (r->first_seen && r->departed_at >= r->first_seen)
        rj_obj_set(o, "waited", rj_numf("%lld", (long long)(r->departed_at - r->first_seen)));
    rj_obj_set(o, "vsize", rj_numf("%llu", (unsigned long long)r->vsize));
    rj_obj_set(o, "fee", rj_numf("%llu", (unsigned long long)r->fee_sat));
    /* sat/kvB, not sat/vB. Integer sat/vB truncates: the FIRST live block this
     * recorded had 188 of 200 rows reporting "feerate": 0, because most real
     * transactions are under 1 sat/vB once the fee is divided by vsize
     * (25 sat over 140 vB is 0.179). A field that reads zero for 94% of rows
     * is worse than no field. sat/kvB is also the unit Core's own fee
     * estimator speaks, so it needs no conversion on the way in. The name
     * carries the unit so a consumer cannot assume the other one. */
    if (r->vsize) rj_obj_set(o, "feerate_satkvb",
                             rj_numf("%llu", (unsigned long long)((r->fee_sat * 1000ULL) / r->vsize)));
    if (r->reason == MPJ_MINED && r->height) rj_obj_set(o, "height", rj_numf("%u", r->height));
    if (!mpj_all_zero(r->aux, 32)){
        mpj_hex_rev(h, r->aux);
        rj_obj_set(o, r->reason == MPJ_REPLACED ? "replaced_by" : "blockhash", rj_str(h));
    }
    return o;
}
typedef struct { rj_val* arr; long cap; } mpj_ctx;
static int mpj_push(void* c, const mpj_rec* r){
    mpj_ctx* x = c;
    if ((long)x->arr->nitems >= x->cap) return 0;
    rj_arr_push(x->arr, mpj_row(r));
    return 1;
}
static int cmd_bmcgetmempooljournal(const rj_val* params, rj_val** res, long* ec, const char** em){
    if (!mpj_is_open()){
        *ec = -1;
        *em = "the mempool departure journal is not enabled -- set bmc.mempooljournal=<records> "
              "(one record is 152 bytes) and restart";
        return 0;
    }
    /* one string argument: a txid to look up */
    if (params && params->typ == RJ_ARR && params->nitems >= 1 && params->items[0]->typ == RJ_STR){
        const char* hx = params->items[0]->str;
        if (strlen(hx) != 64){
            static char eb[96];
            snprintf(eb, sizeof eb, "txid must be of length 64 (not %zu, for '%s')", strlen(hx), hx);
            *ec = -8; *em = eb; return 0;
        }
        unsigned char wire[32];
        for (int i = 0; i < 32; i++){
            int hi = -1, lo = -1; char a = hx[i*2], b = hx[i*2+1];
            if (a>='0'&&a<='9') hi=a-'0'; else if ((a|32)>='a'&&(a|32)<='f') hi=(a|32)-'a'+10;
            if (b>='0'&&b<='9') lo=b-'0'; else if ((b|32)>='a'&&(b|32)<='f') lo=(b|32)-'a'+10;
            if (hi < 0 || lo < 0){
                static char eb2[96];
                snprintf(eb2, sizeof eb2, "txid must be hexadecimal string (not '%s')", hx);
                *ec = -8; *em = eb2; return 0; }
            wire[31-i] = (unsigned char)((hi<<4)|lo);
        }
        mpj_rec r;
        if (!mpj_lookup(wire, &r)){
            /* NOT an error: "the journal has no record of it" is a real and
             * useful answer -- it means the transaction never left the pool
             * here, or left longer ago than the ring holds. */
            rj_val* o = rj_obj();
            rj_obj_set(o, "found", rj_bool(0));
            *res = o; return 1;
        }
        rj_val* o = mpj_row(&r);
        rj_obj_set(o, "found", rj_bool(1));
        *res = o; return 1;
    }
    /* optional numeric argument: how many recent departures to return */
    long want = 10;
    if (params && params->typ == RJ_ARR && params->nitems >= 1 && params->items[0]->typ == RJ_NUM){
        want = atol(params->items[0]->str);
        if (want < 0) want = 0;
        if (want > 5000) want = 5000;        /* one reply, not a database dump */
    }
    mpj_stats_t st; mpj_stats(&st);
    rj_val* o = rj_obj();
    rj_obj_set(o, "capacity", rj_numf("%llu", (unsigned long long)st.capacity));
    rj_obj_set(o, "held",     rj_numf("%llu", (unsigned long long)st.held));
    rj_obj_set(o, "recorded", rj_numf("%llu", (unsigned long long)st.written));
    if (st.held){
        rj_obj_set(o, "oldest", rj_numf("%lld", (long long)st.oldest_departed));
        rj_obj_set(o, "newest", rj_numf("%lld", (long long)st.newest_departed));
    }
    { rj_val* by = rj_obj();
      for (uint32_t i = 1; i <= MPJ_REASON_MAX; i++)
          rj_obj_set(by, mpj_reason_name(i), rj_numf("%llu", (unsigned long long)st.by_reason[i]));
      rj_obj_set(o, "by_reason", by); }
    { rj_val* a = rj_arr(); mpj_ctx cx = { a, want };
      if (want > 0) mpj_recent(want, mpj_push, &cx);
      rj_obj_set(o, "recent", a); }
    *res = o;
    return 1;
}

/* ---- bmcgetcapabilities (2026-09-16) ---------------------------------------
 * ONE call that answers "what is this node, and what can it do that Core
 * cannot". Core has no counterpart; it is an extension, like the rest of the
 * bmc* family.
 *
 * WHY IT EXISTS. A consumer could not tell this node from Core over RPC.
 * blockyard, the monitoring front end, wrote the problem down in
 * server/collect/monitor.js: "both report the same non-Core subversion string.
 * So RPC cannot tell you whether RPC is complete; only the log's build banner
 * can." It therefore has to TAIL THE NODE'S LOG FILE to identify what it is
 * talking to, which is why `log.enabled` is a per-node setting there at all.
 * A monitor should not need file access to a machine it can already reach over
 * RPC.
 *
 * getnetworkinfo already carries bmc_build_commit, and that is not enough on
 * its own: a commit hash makes the consumer keep a commit -> capability map,
 * which is wrong the moment a build lands.
 *
 * EVERY FIELD IS LIVE STATE, NOT A COMPILE-TIME LIST, and that is the whole
 * point. addrindex, the departure journal and the Esplora facade are all
 * opt-in; a build that CAN serve address history is not the same as a node
 * that IS serving it, and reporting the first would mislead a consumer exactly
 * where it matters. Each entry below is read from the running configuration or
 * from the subsystem itself.
 *
 * The reply is deliberately flat and small: it is a handshake, not a status
 * page. Anything that needs numbers has its own call (bmcgetdownloadinfo,
 * bmcgetmempooljournal, getindexinfo). */
/* Weak, so rpc_node.o keeps its no-link-fanout property: the test binaries
 * that link it without the daemon's config or the address history still build,
 * and a capability simply reports as absent there -- which is the truthful
 * answer for a binary that genuinely cannot serve it. */
extern int  ah_available(void) __attribute__((weak));
extern int  node_cfg_addrindex_on(void)   __attribute__((weak));
extern int  node_cfg_esplora_port_get(void) __attribute__((weak));
static int cmd_bmcgetcapabilities(rj_val** res){
    rj_val* o = rj_obj();
    rj_obj_set(o, "node", rj_str("bitcoinmachinecode"));
    rj_obj_set(o, "subversion", rj_str(g_user_agent[0] ? g_user_agent : NODE_UA_STRING));
    { rj_val* b = rj_obj();
      rj_obj_set(b, "commit", rj_str(BMC_BUILD_COMMIT));
      rj_obj_set(b, "dirty",  rj_bool(BMC_BUILD_DIRTY));
      rj_obj_set(o, "build", b); }

    rj_val* x = rj_obj();
    /* address history: Core has NO address index at all, so this is the
     * capability a consumer most needs to know about. ah_available() is the
     * same check the Esplora address routes make before answering. */
    rj_obj_set(x, "addrindex", rj_bool(ah_available && ah_available() ? 1 :
                                       (node_cfg_addrindex_on && node_cfg_addrindex_on())));
    /* the Esplora REST facade: the port, or 0 when it is off. A port is more
     * useful than a bool -- a consumer that gets one can go straight there. */
    rj_obj_set(x, "esploraport", rj_numf("%d",
        node_cfg_esplora_port_get ? node_cfg_esplora_port_get() : 0));
    /* the mempool DEPARTURE journal: why a transaction left the pool, which
     * Core forgets entirely. Reported with its capacity so a consumer can tell
     * how far back the answers reach. */
    if (mpj_is_open()){
        rj_val* j = rj_obj();
        rj_obj_set(j, "enabled",  rj_bool(1));
        rj_obj_set(j, "capacity", rj_numf("%llu", (unsigned long long)mpj_capacity()));
        rj_obj_set(x, "mempooljournal", j);
    } else {
        rj_val* j = rj_obj(); rj_obj_set(j, "enabled", rj_bool(0));
        rj_obj_set(x, "mempooljournal", j);
    }
    /* the forked downloader's worker->peer->chunk map; no Core counterpart */
    rj_obj_set(x, "downloadinfo", rj_bool(1));
    rj_obj_set(o, "extensions", x);

    /* The completeness question blockyard actually hit: one build answered
     * getnettotals 0/0 and getpeerinfo [] while getconnectioncount said 16, so
     * "RPC only" meant no bandwidth and no peer names. Saying so here lets a
     * consumer decide whether it needs the log, instead of discovering the
     * gap from empty charts. */
    { rj_val* c = rj_obj();
      rj_obj_set(c, "peerinfo",   rj_bool(1));
      rj_obj_set(c, "nettotals",  rj_bool(1));
      rj_obj_set(o, "rpc_complete", c); }
    *res = o;
    return 1;
}
static int cmd_bmcgetdownloadinfo(rj_val** res){
    rj_val* o = rj_obj();
    const node_status_t* s = g_status;
    long long total = s ? (long long)s->dl_bytes_total : 0;
    if (!s || !s->dl_active){
        rj_obj_set(o, "active", rj_bool(0));
        rj_obj_set(o, "bytes_total", rj_numf("%lld", total));
        *res = o; return 1;
    }
    rj_obj_set(o, "active", rj_bool(1));
    rj_obj_set(o, "workers",          rj_numf("%d",   s->dl_workers));
    /* the one figure that says whether adding peers would help: see rpc_node.h */
    rj_obj_set(o, "pool_idle_pct",    rj_numf("%d",   s->dl_pool_idle_pct));
    rj_obj_set(o, "pool",             rj_numf("%d",   s->dl_pool));
    rj_obj_set(o, "banned",           rj_numf("%d",   s->dl_banned));
    rj_obj_set(o, "free_peers",       rj_numf("%d",   s->dl_free_peers));
    rj_obj_set(o, "window",           rj_numf("%lld", (long long)s->dl_window));
    rj_obj_set(o, "first_hole",       rj_numf("%lld", (long long)s->dl_first_hole));
    rj_obj_set(o, "claim",            rj_numf("%lld", (long long)s->dl_claim));
    rj_obj_set(o, "applied",          rj_numf("%lld", (long long)s->dl_applied));
    rj_obj_set(o, "end_height",       rj_numf("%lld", (long long)s->dl_end_h));
    rj_obj_set(o, "staged",           rj_numf("%lld", (long long)s->dl_staged));
    rj_obj_set(o, "stall_timeout_s",  rj_numf("%lld", (long long)s->dl_stall_timeout_s));
    rj_obj_set(o, "stall_evictions",  rj_numf("%lld", (long long)s->dl_stall_evictions));
    rj_obj_set(o, "median_bps",       rj_numf("%lld", (long long)s->dl_median_bps));
    rj_obj_set(o, "bytes_total",      rj_numf("%lld", total));
    { rj_val* pa = rj_arr();
      int nd = s->n_dlpeers; if (nd > 64) nd = 64; if (nd < 0) nd = 0;
      for (int i = 0; i < nd; i++){
          const rpc_peer_t* p = &s->dlpeers[i];
          if (!p->used) continue;
          rj_val* w = rj_obj();
          rj_obj_set(w, "worker",     rj_numf("%d", p->dl_worker));
          rj_obj_set(w, "addr",       rj_str((const char*)p->addr));
          rj_obj_set(w, "subver",     rj_str((const char*)p->subver));
          rj_obj_set(w, "services",   rj_numf("%llu", (unsigned long long)p->services));
          rj_obj_set(w, "startingheight", rj_numf("%d", p->start_height));
          rj_obj_set(w, "conntime",   rj_numf("%lld", (long long)p->conn_time));
          rj_obj_set(w, "bytes_recv", rj_numf("%lld", (long long)p->bytes_recv));
          rj_obj_set(w, "bps_recv",   rj_numf("%lld", (long long)p->bps_recv));
          rj_obj_set(w, "idle_pct",   rj_numf("%d", p->idle_pct));
          /* the chunk in flight; hi < lo means the worker holds nothing */
          rj_obj_set(w, "inflight_lo", rj_numf("%lld", (long long)p->inflight_lo));
          rj_obj_set(w, "inflight_hi", rj_numf("%lld", (long long)p->inflight_hi));
          rj_arr_push(pa, w);
      }
      rj_obj_set(o, "peers", pa); }
    *res = o; return 1;
}

static const char* const NODE_METHODS[] = {
    "getconnectioncount", "getnetworkinfo", "getpeerinfo",
    "gettxspendingprevout", "getmempoolcluster", "getblockfrompeer",
    "testmempoolaccept", "submitpackage", "savemempool", "importmempool",
    "getprivatebroadcastinfo", "abortprivatebroadcast",
    "bmcgetdownloadinfo",   /* 2026-09-10: this node's own, no Core counterpart */
    "bmcgetmempooljournal", /* 2026-09-16: the mempool departure journal */
    "bmcgetcapabilities",   /* 2026-09-16: what this node is, and what it can do */
    "getnettotals", "getnodeaddresses", "getaddrmaninfo", "getrawaddrman", "getorphantxs", "listbanned",
    "clearbanned", "getaddednodeinfo", "addnode", "addpeeraddress", "disconnectnode",
    "setban", "setnetworkactive", "ping", "getzmqnotifications",
    "getmempoolinfo", "getrawmempool", "getmempoolentry", "getmempoolancestors", "getmempooldescendants", "estimatesmartfee", "estimaterawfee", "prioritisetransaction", "getprioritisedtransactions", "submitblock", "sendrawtransaction", NULL
};

/* ---- -privatebroadcast RPCs (Core v30) -------------------------------------
 * getprivatebroadcastinfo: the worker's snapshot (pb_info: one line per queued
 * tx, "txid wtxid time_added len hex npeers (addr sent received)*") rendered in
 * Core's shape. abortprivatebroadcast: a ctl op; the worker answers with the
 * removed "txid wtxid" pairs in ctl_out. Both refuse, as Core does, when the
 * option is off. */
static const char* PB_NOT_ENABLED =
    "Private broadcast is not enabled. Ensure you're running Bitcoin Core with -privatebroadcast=1";
static int cmd_getprivatebroadcastinfo(rj_val** res, long* ec, const char** em){
    if (!g_status || !g_status->pb_enabled){ *ec = -32601; *em = PB_NOT_ENABLED; return 0; }
    static char snap[RPC_PB_INFO_CAP];
    memcpy(snap, (const void*)g_status->pb_info, sizeof snap); snap[sizeof snap - 1] = 0;
    rj_val* txs = rj_arr();
    char* save = NULL;
    for (char* line = strtok_r(snap, "\n", &save); line; line = strtok_r(NULL, "\n", &save)){
        char txid[65], wtxid[65]; long long added = 0; unsigned long len = 0; int consumed = 0;
        if (sscanf(line, "%64s %64s %lld %lu %n", txid, wtxid, &added, &len, &consumed) < 4) continue;
        char* hex = line + consumed;
        char* sp = strchr(hex, ' '); if (!sp) continue;
        *sp = 0;
        int npeers = 0; int c2 = 0;
        if (sscanf(sp + 1, "%d %n", &npeers, &c2) < 1) continue;
        rj_val* o = rj_obj();
        rj_obj_set(o, "txid", rj_str(txid));
        rj_obj_set(o, "wtxid", rj_str(wtxid));
        rj_obj_set(o, "hex", rj_str(hex));
        rj_obj_set(o, "time_added", rj_numf("%lld", added));
        rj_val* peers = rj_arr();
        char* q = sp + 1 + c2;
        for (int k = 0; k < npeers; k++){
            char addr[96]; long long sent = 0, recv = 0; int c3 = 0;
            if (sscanf(q, "%95s %lld %lld %n", addr, &sent, &recv, &c3) < 3) break;
            q += c3;
            rj_val* pe = rj_obj();
            rj_obj_set(pe, "address", rj_str(addr));
            rj_obj_set(pe, "sent", rj_numf("%lld", sent));
            if (recv) rj_obj_set(pe, "received", rj_numf("%lld", recv));
            rj_arr_push(peers, pe);
        }
        rj_obj_set(o, "peers", peers);
        rj_arr_push(txs, o);
    }
    rj_val* out = rj_obj();
    rj_obj_set(out, "transactions", txs);
    *res = out; return 1;
}
static int cmd_abortprivatebroadcast(const rj_val* params, rj_val** res, long* ec, const char** em){
    if (!g_status || !g_status->pb_enabled){ *ec = -32601; *em = PB_NOT_ENABLED; return 0; }
    if (!params || params->typ != RJ_ARR || params->nitems < 1 || params->items[0]->typ != RJ_STR ||
        strlen(params->items[0]->str) != 64){
        *ec = -8; *em = "id must be a 64-character hex txid or wtxid"; return 0; }
    for (const char* c = params->items[0]->str; *c; c++) if (srt_hex1(*c) < 0){ *ec = -8; *em = "id must be hex"; return 0; }
    int r = 0; static char out[4096];
    if (!ctl_send(RPC_CTL_PB_ABORT, params->items[0]->str, 0, ec, em, &r, out, sizeof out)) return 0;
    rj_val* removed = rj_arr();
    char* save = NULL;
    for (char* line = strtok_r(out, "\n", &save); line; line = strtok_r(NULL, "\n", &save)){
        char txid[65], wtxid[65];
        if (sscanf(line, "%64s %64s", txid, wtxid) != 2) continue;
        rj_val* o = rj_obj(); rj_obj_set(o, "txid", rj_str(txid)); rj_obj_set(o, "wtxid", rj_str(wtxid));
        rj_arr_push(removed, o);
    }
    rj_val* o = rj_obj(); rj_obj_set(o, "removed_transactions", removed);
    *res = o; return 1;
}

const char* rpc_node_method_at(int i){
    int n = 0;
    while (NODE_METHODS[n]) n++;
    return (i >= 0 && i < n) ? NODE_METHODS[i] : NULL;
}
int rpc_node_known_method(const char* m){
    for (int i = 0; NODE_METHODS[i]; i++) if (!strcmp(m, NODE_METHODS[i])) return 1;
    return 0;
}
/* ---- the cluster layer's view of this mempool -----------------------------
 * mempool_cluster.c knows nothing about this node: it takes a lookup callback.
 * That is deliberate (link-check refused a direct policy dependency here once
 * already), and it is also what lets the cluster tests run with no mempool.
 *
 * The caller must hold the mempool lock across the whole build: the callback is
 * invoked many times and a pool that moves underneath it would produce a
 * cluster assembled from two different mempools. */
static int mpc_lookup_here(void* ctx, const unsigned char txid[32], mpc_entry* out)
{
    (void)ctx;
    if (!g_mph.mp || !g_mph.get) return 0;
    unsigned long len = 0;
    const unsigned char* tx = g_mph.get(g_mph.mp, txid, &len);
    if (!tx) return 0;
    mp_entry_info inf;
    if (!g_mph.pol_entry_info || !g_mph.polstate) return 0;
    if (!(int)g_mph.pol_entry_info(g_mph.polstate, txid, &inf)) return 0;

    memset(out, 0, sizeof *out);
    /* fee is the MODIFIED fee: prioritisetransaction moves a transaction in the
     * block-space competition, so the chunking must see the same number the
     * miner would. */
    long long modified = (long long)inf.fee + pri_delta_of(txid);
    out->fee = modified < 0 ? 0 : (uint64_t)modified;
    /* Core chunks by sigops-ADJUSTED weight (policy.cpp GetSigOpsAdjustedWeight),
     * not raw weight -- a sigop-heavy transaction costs a block more than its
     * bytes suggest, and chunking by bytes would order it wrongly. */
    { unsigned long long bps = g_mph.bytespersigop ? g_mph.bytespersigop() : 20;
      unsigned long long w = mp_tx_weight(tx, len);
      unsigned long long sw = (unsigned long long)inf.sigop_cost * bps;
      out->weight = sw > w ? sw : w; }

    /* edges filtered to transactions still in the pool, as depends/spentby
     * are: a stale registry edge would otherwise fail the whole build */
    for (int i = 0; i < inf.n_depends && out->n_parents < MPC_MAX_CLUSTER; i++){
        unsigned long l2 = 0;
        if (g_mph.get(g_mph.mp, inf.depends[i], &l2))
            memcpy(out->parents[out->n_parents++], inf.depends[i], 32);
    }
    for (int i = 0; i < inf.n_spentby && out->n_children < MPC_MAX_CLUSTER; i++){
        unsigned long l2 = 0;
        if (g_mph.get(g_mph.mp, inf.spentby[i], &l2))
            memcpy(out->children[out->n_children++], inf.spentby[i], 32);
    }
    return 1;
}

/* getmempoolcluster, for the case that needs no linearization.
 *
 * Core returns the transaction's whole cluster in LINEARIZATION order, split
 * into chunks by the cluster's chunk feerates (rpc/mempool.cpp clusterToJSON).
 * This node has no cluster mempool and so no linearization -- but a SINGLETON
 * cluster has only one possible answer. A transaction with no unconfirmed
 * parents and no unconfirmed children is alone in its cluster and is its own
 * single chunk, so clusterweight, txcount and the one chunk are all exactly
 * determined. Verified field for field against Core v31.1 on a live mempool.
 *
 * For a cluster of two or more the chunk boundaries ARE the linearization, and
 * nothing here can recover them: that case still refuses, and says why, rather
 * than inventing an ordering that would differ from Core's silently. */
static int cmd_getmempoolcluster(const rj_val* params, rj_val** res, long* ec, const char** em){
    static char embuf[512];
    /* This had the right CODE for a wrong type and the wrong one for a missing
     * argument, which it folded into the same branch: Core answers -1 there.
     * It also hardcoded the type as "null" whatever was passed. The three
     * sibling sites it used to point at were fixed on 2026-09-15; this one is
     * now the same shape as all of them. */
    if (!params || params->typ != RJ_ARR || params->nitems < 1){
        *ec = -1; *em = "getmempoolcluster requires txid"; return 0; }
    if (params->items[0]->typ != RJ_STR)
        return rpc_wrong_type(ec, em, embuf, sizeof embuf, 1, "txid", params->items[0], "string");
    const char* hx = params->items[0]->str;
    if (strlen(hx) != 64){
        snprintf(embuf, sizeof embuf, "txid must be of length 64 (not %zu, for '%s')", strlen(hx), hx);
        *ec = -8; *em = embuf; return 0; }
    unsigned char txid[32];
    for (int i=0;i<32;i++){
        int a=srt_hex1(hx[i*2]), b=srt_hex1(hx[i*2+1]);
        if (a<0||b<0){ snprintf(embuf,sizeof embuf,"txid must be hexadecimal string (not '%s')",hx);
                       *ec=-8; *em=embuf; return 0; }
        txid[31-i]=(unsigned char)((a<<4)|b);
    }
    if (!g_mph.mp || !g_mph.get){ *ec=-5; *em="Transaction not in mempool"; return 0; }

    /* The whole build under ONE lock hold. mpc_build_cluster calls back many
     * times; a pool that moved underneath it would assemble a cluster from two
     * different mempools and report a competition that never existed. */
    mpl();
    mpc_cluster cl;
    int rc = mpc_build_cluster(0, mpc_lookup_here, txid, &cl);
    mpu();
    if (rc != 0 || cl.n < 1){ *ec=-5; *em="Transaction not in mempool"; return 0; }

    if (cl.truncated){
        /* Core rejects a transaction that would exceed its 64-transaction
         * cluster limit, so a Core cluster always fits. This node's limits are
         * not identical, so a component CAN exceed it -- and a truncated walk is
         * not a cluster. Reporting one would describe a block-space competition
         * with most of its competitors missing. */
        snprintf(embuf, sizeof embuf,
                 "this transaction's cluster exceeds %d transactions, the limit Core "
                 "enforces at acceptance (DEFAULT_CLUSTER_LIMIT). This node accepted a "
                 "larger component, so the cluster cannot be reported without omitting "
                 "members of it.", MPC_MAX_CLUSTER);
        *ec = -1; *em = embuf; return 0;
    }

    int lin[MPC_MAX_CLUSTER];
    if (mpc_linearize_ancestor_score(&cl, lin) != 0){
        *ec = -1; *em = "the cluster could not be linearized (not a DAG?)"; return 0; }
    /* Post-linearization is equal-or-better by construction and makes the chunks
     * CONNECTED, which the greedy alone does not guarantee. A disconnected chunk
     * is not wrong arithmetic, but it is not a chunk Core would report. */
    mpc_post_linearize(&cl, lin);
    mpc_chunking ch;
    if (mpc_chunk_linearization(&cl, lin, &ch) != 0){
        *ec = -1; *em = "the cluster's linearization could not be chunked"; return 0; }

    uint64_t total_w = 0;
    for (int i = 0; i < cl.n; i++) total_w += cl.m[i].weight;

    rj_val* o = rj_obj();
    rj_obj_set(o, "clusterweight", rj_numf("%llu", (unsigned long long)total_w));
    rj_obj_set(o, "txcount", rj_numf("%d", cl.n));
    rj_val* chunks = rj_arr();
    for (int i = 0; i < ch.n; i++){
        rj_val* c = rj_obj();
        unsigned long long fee = (unsigned long long)ch.c[i].fee;
        rj_obj_set(c, "chunkfee", rj_numf("%llu.%08llu", fee/100000000ULL, fee%100000000ULL));
        rj_obj_set(c, "chunkweight", rj_numf("%llu", (unsigned long long)ch.c[i].weight));
        rj_val* txs = rj_arr();
        /* members in LINEARIZATION order, as Core emits them -- a chunk is an
         * ordered run, not a set, and a caller reconstructing the block order
         * from this must get the order. */
        for (int k = 0; k < cl.n; k++){
            int idx = lin[k];
            if (!(ch.c[i].members & ((uint64_t)1 << idx))) continue;
            char h[65];
            mpe_hex(h, cl.txid[idx]);       /* display order, as getblock prints */
            rj_arr_push(txs, rj_str(h));
        }
        rj_obj_set(c, "txs", txs);
        rj_arr_push(chunks, c);
    }
    rj_obj_set(o, "chunks", chunks);
    *res = o;
    return 1;
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
    if (!strcmp(m, "getprivatebroadcastinfo")) return cmd_getprivatebroadcastinfo(res, ec, em);
    if (!strcmp(m, "bmcgetdownloadinfo"))  return cmd_bmcgetdownloadinfo(res);
    if (!strcmp(m, "bmcgetmempooljournal")) return cmd_bmcgetmempooljournal(params, res, ec, em);
    if (!strcmp(m, "bmcgetcapabilities"))  return cmd_bmcgetcapabilities(res);
    if (!strcmp(m, "abortprivatebroadcast"))   return cmd_abortprivatebroadcast(params, res, ec, em);
    if (!strcmp(m, "getmempoolcluster")) return cmd_getmempoolcluster(params, res, ec, em);
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
