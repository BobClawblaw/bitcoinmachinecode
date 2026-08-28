/* daemon/net6.h -- IPv6 sockets.
 *
 * The node's socket layer was AF_INET only: tcp_connect_ip takes a u32 and
 * the listener is a sockaddr_in, so an IPv6 peer -- and therefore every
 * CJDNS peer, since a CJDNS address IS an fc00::/8 IPv6 address on a tun
 * interface -- could not be reached or accepted. This is the v6 half.
 * (2026-08-28) */
#ifndef BMC_NET6_H
#define BMC_NET6_H
/* connect to a 16-byte IPv6 address, port in HOST order. Returns a fd with
 * the same 10s receive timeout tcp_connect_ip sets, or -1. */
int tcp_connect_ip6(const unsigned char addr[16], unsigned short port);
/* a listening socket bound to [addr]:port (addr NULL = in6addr_any). The
 * socket is v6-ONLY: a dual-stack wildcard would silently take over the
 * IPv4 listener's port, which this node binds separately. -1 on failure. */
int lsock6(const unsigned char addr[16], int port, int backlog);
#endif
