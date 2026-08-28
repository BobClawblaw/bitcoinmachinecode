/* daemon/dialer.h -- one place that decides HOW to reach a peer, by network.
 *
 * Until 2026-08-28 every dial was tcp_connect_ip() on an IPv4: the node could
 * not reach a Tor, I2P or CJDNS peer even after it learned the address. This
 * routes each network to its transport, the way Core's ConnectNode does:
 *   ipv4/ipv6/cjdns -> a direct socket (or the SOCKS5 proxy if one is set
 *                      for that network)
 *   onion           -> SOCKS5 to the tor proxy, CONNECT to the .onion name
 *                      (tor resolves it; we never do a DNS lookup for it)
 *   i2p             -> SAM STREAM CONNECT through the session
 * `-onlynet` and a missing transport are enforced here too, so a peer this
 * node cannot reach is refused before a socket is opened rather than after a
 * timeout. */
#ifndef BMC_DIALER_H
#define BMC_DIALER_H
#include "netaddr.h"
/* one-time setup from the config (proxies, SAM session, onlynet). Safe to
 * call more than once; returns the number of non-IPv4 networks now usable. */
int  dialer_init(void);
/* is this network reachable at all (transport configured AND allowed by
 * -onlynet)? Core's IsReachable + g_reachable_nets. */
int  dialer_net_reachable(int net);
/* connect to `a`; returns a connected fd or -1 with *why (never NULL). */
int  dialer_connect(const bmc_addr_t* a, int timeout_ms, const char** why);
/* our own I2P address once a SAM session exists ("" if none) */
const char* dialer_i2p_b32(void);
#endif
