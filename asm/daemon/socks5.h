/* daemon/socks5.h -- SOCKS5 client (RFC 1928, RFC 1929 user/pass), the
 * transport for Tor: connect to the proxy, ask it to CONNECT to a hostname
 * (an .onion name is a hostname to tor) and return the tunnelled socket.
 * Byte-for-byte Core's netbase.cpp Socks5(): greeting with NOAUTH (+USER_PASS
 * when credentials are given), CONNECT with ATYP DOMAINNAME, port big-endian.
 * Credentials exist for stream isolation, not security: tor gives each
 * distinct user/pass pair its own circuit (Core's -proxyrandomize). */
#ifndef BMC_SOCKS5_H
#define BMC_SOCKS5_H
/* returns a connected fd, or a negative code:
 *   -1 proxy unreachable  -2 proxy protocol error  -3 proxy refused the
 *   destination (REP != 0; *rep_out gets the code)  -4 auth rejected
 *   -5 timeout / short read */
int socks5_connect(const char* proxy_ip, int proxy_port,
                   const char* dest_host, int dest_port,
                   const char* user, const char* pass,
                   int timeout_ms, int* rep_out);
#endif
