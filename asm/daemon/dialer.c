/* daemon/dialer.c -- see dialer.h. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "dialer.h"
#include "socks5.h"
#include "i2psam.h"
#include "node_config.h"
#include "net6.h"
#include "log_ts.h"

extern int tcp_connect_ip(unsigned ip_netorder, unsigned short port_be);

static int      g_ready;
static int      g_have_v6;
static int      g_have_v6_global;   /* ...and a global route exists, not just the stack */
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
    /* Does this host have IPv6 at all? Creating the socket is the only
     * honest test -- the box may have the module loaded and the stack
     * disabled by sysctl. */
    { int t = socket(AF_INET6, SOCK_STREAM, 0);
      if (t >= 0){ g_have_v6 = 1; close(t); }
      else log_fprintf(stderr, "[dial] no IPv6 on this host: ipv6 and cjdns peers are unreachable\n"); }
    /* A v6 socket proves the stack, not a route. Global IPv6 peers need a
     * default route: a UDP connect() to a public address (no packet is
     * sent) fails with ENETUNREACH without one, and a host with only a ULA
     * or a cjdns tun otherwise wasted a 10 s connect timeout on every IPv6
     * candidate (2026-09-01). CJDNS keeps working off the tun interface. */
    g_have_v6_global = 0;
    if (g_have_v6){
        int u = socket(AF_INET6, SOCK_DGRAM, 0);
        if (u >= 0){
            struct sockaddr_in6 sa; memset(&sa, 0, sizeof sa); sa.sin6_family = AF_INET6; sa.sin6_port = htons(53);
            inet_pton(AF_INET6, "2001:4860:4860::8888", &sa.sin6_addr);
            if (connect(u, (struct sockaddr*)&sa, sizeof sa) == 0) g_have_v6_global = 1;
            close(u);
        }
        if (!g_have_v6_global) log_fprintf(stderr, "[dial] no global IPv6 route on this host: ipv6 peers are unreachable (cjdns unaffected)\n");
    }
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
        log_fprintf(stderr, "[dial] cjdns reachable (fc00::/8 over IPv6%s)\n",
                    g_have_v6 ? "" : " -- but this host has no IPv6, so it is not");
    return g_i2p_ok + (g_onion_ip[0] ? 1 : 0) + (g_cfg.cjdnsreachable ? 1 : 0);
}
/* tests drive the predicates with different g_cfg values; the latch has to
 * be releasable for that, and nothing else calls this. */
int dialer_reset_for_test(void){ g_ready = 0; g_i2p_ok = 0; g_onion_ip[0] = 0; g_proxy_ip[0] = 0; return 0; }
/* 8 random bytes from the kernel, hex, as SOCKS5 user and password: tor puts
 * each distinct pair on its own circuit. A counter would be guessable and
 * would reset in every forked child, so two peers could share a circuit. */
int dialer_isolation_creds(char* u, long ucap, char* p, long pcap){
    unsigned char r[16];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return 0;
    long n = read(fd, r, sizeof r); close(fd);
    if (n != (long)sizeof r || ucap < 17 || pcap < 17) return 0;
    static const char* H = "0123456789abcdef";
    for (int i = 0; i < 8; i++){ u[i*2] = H[r[i] >> 4]; u[i*2+1] = H[r[i] & 15]; }
    u[16] = 0;
    for (int i = 0; i < 8; i++){ p[i*2] = H[r[8+i] >> 4]; p[i*2+1] = H[r[8+i] & 15]; }
    p[16] = 0;
    return 1;
}
/* 1 when a SOCKS5 proxy is configured for clearnet: the raw-socket dial
 * paths must stand down, or they would go direct and defeat it. */
int dialer_proxy_configured(void){
    if (!g_ready) dialer_init();
    return g_proxy_ip[0] != 0;
}
int dialer_dns_blocked(void){
    if (!g_ready) dialer_init();
    if (!g_cfg.dns) return 1;                    /* the operator said so */
    if (g_proxy_ip[0]) return 1;                 /* the proxy resolves, not us */
    /* -onlynet naming only anonymity networks makes a clearnet DNS lookup a
     * query for peers we would never dial */
    if (g_cfg.n_onlynet > 0 && !onlynet_allows(BMC_NET_IPV4) && !onlynet_allows(BMC_NET_IPV6)) return 1;
    return 0;
}
int dialer_may_announce_clearnet(void){
    if (!g_ready) dialer_init();
    if (!g_cfg.discover) return 0;
    if (g_cfg.n_onlynet > 0 && !onlynet_allows(BMC_NET_IPV4) && !onlynet_allows(BMC_NET_IPV6)) return 0;
    return 1;
}
int dialer_connect_name(const char* host, int port, int timeout_ms, const char** why){
    static char err[192];
    const char* dummy; if (!why) why = &dummy;
    if (!g_ready) dialer_init();
    if (!g_proxy_ip[0]){ *why = "no proxy configured for name resolution"; return -1; }
    int rep = 0;
    int fd = socks5_connect(g_proxy_ip, g_proxy_port, host, port, NULL, NULL, timeout_ms, &rep);
    if (fd < 0){ snprintf(err, sizeof err, "socks5(name) rc=%d rep=%d", fd, rep); *why = err; }
    return fd;
}
int dialer_net_reachable(int net){
    if (!g_ready) dialer_init();       /* answer from the configured transports, not from unset flags */
    if (!onlynet_allows(net)) return 0;
    switch (net){
    case BMC_NET_IPV4:  return 1;
    case BMC_NET_IPV6:  return g_have_v6_global;
    case BMC_NET_TORV3: return g_onion_ip[0] != 0;
    case BMC_NET_I2P:   return g_i2p_ok;
    /* CJDNS is an fc00::/8 address on a tun interface: it needs the IPv6
     * socket path AND the operator saying the interface is there, exactly
     * as Core requires -cjdnsreachable (it cannot detect it either). */
    case BMC_NET_CJDNS: return g_cfg.cjdnsreachable && g_have_v6;
    default: return 0;
    }
}
const char* dialer_i2p_b32(void){ return g_i2p_ok ? g_i2p.b32 : ""; }
/* inbound: one SAM STREAM ACCEPT on our session (blocks up to timeout_ms;
 * returns the stream fd, or -1). Each accepted stream is its own SAM socket,
 * so this is called again for the next caller. */
int dialer_i2p_accept(char* peer_b32, long cap, int timeout_ms){
    if (!g_i2p_ok) return -1;
    return i2psam_accept(&g_i2p, g_sam_ip, g_sam_port, peer_b32, cap, timeout_ms);
}
int dialer_i2p_ready(void){ return g_i2p_ok; }

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
        /* Core uses RANDOM credentials per connection (-proxyrandomize):
         * tor gives each distinct user/pass its own circuit. An incrementing
         * counter is guessable AND resets in every forked child, so two
         * peers could share a circuit -- read from the kernel instead.
         * (2026-08-28 pre-deploy review.) */
        char u[40], p[40];
        if (!dialer_isolation_creds(u, sizeof u, p, sizeof p)){
            /* never fall back to a predictable value: without randomness we
             * cannot isolate, so fail the dial rather than share a circuit */
            *why = "cannot read /dev/urandom for stream isolation"; return -1; }
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
            /* isolation applies to EVERY proxied connection, not just onion:
             * Core randomises credentials for all of them */
            char u[40], p[40]; int have = dialer_isolation_creds(u, sizeof u, p, sizeof p);
            if (!have){ *why = "cannot read /dev/urandom for stream isolation"; return -1; }
            int rep = 0;
            int fd = socks5_connect(g_proxy_ip, g_proxy_port, host, a->port,
                                    g_cfg.proxyrandomize ? u : NULL, g_cfg.proxyrandomize ? p : NULL, timeout_ms, &rep);
            if (fd < 0){ snprintf(err, sizeof err, "socks5 rc=%d rep=%d", fd, rep); *why = err; }
            return fd;
        }
        unsigned ip; memcpy(&ip, a->addr, 4);
        int fd = tcp_connect_ip(ip, htons(a->port));
        if (fd < 0) *why = "connect failed";
        return fd; }
    case BMC_NET_IPV6: case BMC_NET_CJDNS: {
        /* Core parses a bare -proxy into the proxy for EVERY network
         * (init.cpp) and ConnectNode selects by network, so an operator who
         * sets -proxy expecting all traffic to leave through it must not
         * have IPv6/CJDNS quietly go direct. */
        if (g_proxy_ip[0]){
            int rep2 = 0;
            int pfd = socks5_connect(g_proxy_ip, g_proxy_port, host, a->port, NULL, NULL, timeout_ms, &rep2);
            if (pfd < 0){ snprintf(err, sizeof err, "socks5 rc=%d rep=%d", pfd, rep2); *why = err; }
            return pfd;
        }
        if (!g_have_v6){ *why = "no IPv6 stack on this host"; return -1; }
        if (a->net == BMC_NET_CJDNS && !g_cfg.cjdnsreachable){
            *why = "cjdns not enabled (-cjdnsreachable)"; return -1; }
        /* a CJDNS peer is reached by connecting to its fc00::/8 address over
         * the tun interface -- the same socket as any other IPv6 peer */
        int fd = tcp_connect_ip6(a->addr, a->port);
        if (fd < 0) *why = "connect failed";
        return fd; }
    default:
        *why = "unknown network"; return -1;
    }
}

/* ---- private broadcast (Core PickNetwork / ConnectNode for PRIVATE_BROADCAST) ---- */
int dialer_pb_pick_network(void){
    if (!g_ready) dialer_init();
    int nets[4]; int n = 0;
    int tor = g_onion_ip[0] != 0 && onlynet_allows(BMC_NET_TORV3);
    if (tor){
        nets[n++] = BMC_NET_TORV3;
        if (g_proxy_ip[0]){                       /* clearnet, but only through the proxy */
            if (onlynet_allows(BMC_NET_IPV4)) nets[n++] = BMC_NET_IPV4;
            if (onlynet_allows(BMC_NET_IPV6)) nets[n++] = BMC_NET_IPV6;
        }
    }
    if (g_i2p_ok && onlynet_allows(BMC_NET_I2P)) nets[n++] = BMC_NET_I2P;
    if (n == 0) return 0;
    unsigned char r = 0; int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0){ if (read(fd, &r, 1) != 1) r = 0; close(fd); }
    return nets[r % n];
}
int dialer_connect_private(const bmc_addr_t* a, int timeout_ms, const char** why){
    static char err[192];
    const char* dummy; if (!why) why = &dummy;
    if (!g_ready) dialer_init();
    if (!onlynet_allows(a->net)){ snprintf(err, sizeof err, "onlynet excludes %s", bmc_net_name(a->net)); *why = err; return -1; }
    char host[96];
    if (!bmc_addr_to_string(host, sizeof host, a)){ *why = "unprintable address"; return -1; }
    switch (a->net){
    case BMC_NET_TORV3:
        return dialer_connect(a, timeout_ms, why);          /* SOCKS5 to tor with isolation credentials */
    case BMC_NET_IPV4: case BMC_NET_IPV6: {
        if (!g_proxy_ip[0]){ *why = "private broadcast to clearnet needs -proxy (never direct)"; return -1; }
        char u[40], p[40];
        if (!dialer_isolation_creds(u, sizeof u, p, sizeof p)){ *why = "cannot read /dev/urandom for stream isolation"; return -1; }
        int rep = 0;
        int fd = socks5_connect(g_proxy_ip, g_proxy_port, host, a->port ? a->port : 8333, u, p, timeout_ms, &rep);
        if (fd < 0){ snprintf(err, sizeof err, "socks5 rc=%d rep=%d", fd, rep); *why = err; }
        return fd; }
    case BMC_NET_I2P: {
        if (!g_sam_ip[0]){ *why = "no SAM bridge (-i2psam)"; return -1; }
        /* a TRANSIENT session of its own: the control socket lives in this
         * (helper) process for the stream's lifetime and dies with it */
        static i2psam_t tmp;
        if (!i2psam_session(&tmp, g_sam_ip, g_sam_port, "/nonexistent/private-broadcast-transient", timeout_ms)){
            snprintf(err, sizeof err, "transient i2p session: %.120s", tmp.err); *why = err; return -1; }
        int fd = i2psam_connect(&tmp, g_sam_ip, g_sam_port, host, timeout_ms, err, sizeof err);
        if (fd < 0) *why = err;
        return fd; }
    default:
        snprintf(err, sizeof err, "%s is not a private-broadcast network", bmc_net_name(a->net)); *why = err; return -1;
    }
}
