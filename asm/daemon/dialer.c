/* daemon/dialer.c -- see dialer.h. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "dialer.h"
#include "socks5.h"
#include "i2psam.h"
#include "node_config.h"
#include "log_ts.h"

extern int tcp_connect_ip(unsigned ip_netorder, unsigned short port_be);

static int      g_ready;
static i2psam_t g_i2p;
static int      g_i2p_ok;
static char     g_sam_ip[64]; static int g_sam_port;
static char     g_onion_ip[64]; static int g_onion_port;   /* SOCKS5 for .onion */
static char     g_proxy_ip[64]; static int g_proxy_port;   /* SOCKS5 for everything else */

/* "1.2.3.4:9050" -> ip + port; returns 1 when both are present */
static int split_hostport(const char* s, char* ip, long cap, int* port){
    if (!s || !*s) return 0;
    const char* c = strrchr(s, ':'); if (!c) return 0;
    long n = c - s; if (n <= 0 || n >= cap) return 0;
    memcpy(ip, s, (size_t)n); ip[n] = 0; *port = atoi(c + 1);
    return *port > 0 && *port < 65536;
}
static int onlynet_allows(int net){
    if (g_cfg.n_onlynet <= 0) return 1;
    const char* want = bmc_net_name(net);
    for (int i = 0; i < g_cfg.n_onlynet; i++) if (!strcmp(g_cfg.onlynet[i], want)) return 1;
    return 0;
}
int dialer_init(void){
    if (g_ready) return g_i2p_ok + (g_onion_ip[0] ? 1 : 0) + (g_cfg.cjdnsreachable ? 1 : 0);
    g_ready = 1;
    split_hostport(g_cfg.proxy, g_proxy_ip, sizeof g_proxy_ip, &g_proxy_port);
    /* Core: -onion defaults to -proxy; "0" disables onion entirely */
    if (!split_hostport(g_cfg.onion_proxy, g_onion_ip, sizeof g_onion_ip, &g_onion_port)){
        if (g_proxy_ip[0] && strcmp(g_cfg.onion_proxy, "0")){
            snprintf(g_onion_ip, sizeof g_onion_ip, "%s", g_proxy_ip); g_onion_port = g_proxy_port;
        }
    }
    if (g_onion_ip[0] && onlynet_allows(BMC_NET_TORV3))
        log_fprintf(stderr, "[dial] onion via SOCKS5 %s:%d\n", g_onion_ip, g_onion_port);
    if (split_hostport(g_cfg.i2psam, g_sam_ip, sizeof g_sam_ip, &g_sam_port) && onlynet_allows(BMC_NET_I2P)){
        if (i2psam_session(&g_i2p, g_sam_ip, g_sam_port, "i2p_private_key", 150000)){
            g_i2p_ok = 1;
            log_fprintf(stderr, "[dial] i2p session up via SAM %s:%d, our address %s\n", g_sam_ip, g_sam_port, g_i2p.b32);
        } else {
            log_fprintf(stderr, "[dial] i2p unavailable: %s\n", g_i2p.err);
        }
    }
    if (g_cfg.cjdnsreachable && onlynet_allows(BMC_NET_CJDNS))
        log_fprintf(stderr, "[dial] cjdns reachable (fc00::/8 dialled directly)\n");
    return g_i2p_ok + (g_onion_ip[0] ? 1 : 0) + (g_cfg.cjdnsreachable ? 1 : 0);
}
int dialer_net_reachable(int net){
    if (!onlynet_allows(net)) return 0;
    switch (net){
    case BMC_NET_IPV4:  return 1;
    case BMC_NET_IPV6:  return 0;                  /* no IPv6 socket path yet (phase 4) */
    case BMC_NET_TORV3: return g_onion_ip[0] != 0;
    case BMC_NET_I2P:   return g_i2p_ok;
    case BMC_NET_CJDNS: return g_cfg.cjdnsreachable;   /* still needs the IPv6 socket path */
    default: return 0;
    }
}
const char* dialer_i2p_b32(void){ return g_i2p_ok ? g_i2p.b32 : ""; }

int dialer_connect(const bmc_addr_t* a, int timeout_ms, const char** why){
    static char err[192];
    const char* dummy; if (!why) why = &dummy;
    *why = "";
    if (!g_ready) dialer_init();
    if (!onlynet_allows(a->net)){
        snprintf(err, sizeof err, "onlynet excludes %s", bmc_net_name(a->net)); *why = err; return -1; }
    char host[96];
    if (!bmc_addr_to_string(host, sizeof host, a)){ *why = "unprintable address"; return -1; }
    switch (a->net){
    case BMC_NET_TORV3: {
        if (!g_onion_ip[0]){ *why = "no tor proxy configured (-proxy / -onion)"; return -1; }
        /* per-connection credentials = stream isolation: tor gives each
         * distinct user/pass its own circuit (Core's -proxyrandomize) */
        char u[32], p[8] = "x";
        static unsigned long ctr;
        snprintf(u, sizeof u, "bmc-%lu", (unsigned long)(++ctr));
        int rep = 0;
        int fd = socks5_connect(g_onion_ip, g_onion_port, host, a->port ? a->port : 8333,
                                g_cfg.proxyrandomize ? u : NULL, g_cfg.proxyrandomize ? p : NULL,
                                timeout_ms, &rep);
        if (fd < 0){ snprintf(err, sizeof err, "socks5 rc=%d rep=%d", fd, rep); *why = err; }
        return fd; }
    case BMC_NET_I2P: {
        if (!g_i2p_ok){ *why = "no i2p session (-i2psam)"; return -1; }
        int fd = i2psam_connect(&g_i2p, g_sam_ip, g_sam_port, host, timeout_ms, err, sizeof err);
        if (fd < 0) *why = err;
        return fd; }
    case BMC_NET_IPV4: {
        if (g_proxy_ip[0]){
            int rep = 0;
            int fd = socks5_connect(g_proxy_ip, g_proxy_port, host, a->port, NULL, NULL, timeout_ms, &rep);
            if (fd < 0){ snprintf(err, sizeof err, "socks5 rc=%d rep=%d", fd, rep); *why = err; }
            return fd;
        }
        unsigned ip; memcpy(&ip, a->addr, 4);
        int fd = tcp_connect_ip(ip, htons(a->port));
        if (fd < 0) *why = "connect failed";
        return fd; }
    case BMC_NET_IPV6: case BMC_NET_CJDNS:
        /* the node has no AF_INET6 socket path yet; refuse here rather than
         * pretend, so the reason in the log is the true one (phase 4) */
        *why = (a->net == BMC_NET_CJDNS) ? "cjdns needs an IPv6 socket (not built yet)"
                                         : "ipv6 not supported yet";
        return -1;
    default:
        *why = "unknown network"; return -1;
    }
}
