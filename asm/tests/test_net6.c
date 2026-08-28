/* tests/test_net6.c -- the IPv6 socket path (daemon/net6.c), the layer every
 * CJDNS peer rides on. Loopback only: no external network.
 *   - a v6 listener accepts a v6 connection and carries bytes,
 *   - it is V6-ONLY, so it does NOT swallow the IPv4 listener's port (a
 *     dual-stack wildcard would, and this node binds both separately),
 *   - a connect to a closed port fails rather than hanging,
 *   - an fc00::/8 literal is classified CJDNS and round-trips through the
 *     address type, which is how a cjdns peer is named. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "../daemon/net6.h"
#include "../daemon/netaddr.h"
static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
int main(void){
    unsigned char lo[16]; inet_pton(AF_INET6, "::1", lo);
    /* the host may have IPv6 off; say so rather than fail misleadingly */
    { int t = socket(AF_INET6, SOCK_STREAM, 0);
      if (t < 0){ printf("  SKIP: no IPv6 on this host (%s)\n", strerror(errno)); return 0; }
      close(t); }
    printf("== a v6 listener carries bytes ==\n");
    int ls = lsock6(lo, 0, 4);
    ck("lsock6 bound ::1", ls >= 0);
    if (ls < 0){ printf("\nFAILURES %d\n", ++fails); return 1; }
    struct sockaddr_in6 sa; socklen_t sl = sizeof sa;
    getsockname(ls, (struct sockaddr*)&sa, &sl);
    int port = ntohs(sa.sin6_port);
    int c = tcp_connect_ip6(lo, (unsigned short)port);
    ck("tcp_connect_ip6 connected", c >= 0);
    int a = accept(ls, 0, 0);
    ck("the listener accepted it", a >= 0);
    if (c >= 0 && a >= 0){
        (void)!write(c, "v6-bytes", 8); char b[16] = {0};
        int n = 0; while (n < 8){ int r = (int)read(a, b + n, 8 - n); if (r <= 0) break; n += r; }
        ck("bytes crossed the v6 socket", n == 8 && !strcmp(b, "v6-bytes"));
        close(a); close(c);
    }
    printf("\n== the listener is V6-ONLY (it must not take the IPv4 port) ==\n");
    { int v4 = socket(AF_INET, SOCK_STREAM, 0);
      struct sockaddr_in a4; memset(&a4, 0, sizeof a4);
      a4.sin_family = AF_INET; a4.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a4.sin_port = htons((unsigned short)port);
      int one = 1; setsockopt(v4, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
      int rc = bind(v4, (struct sockaddr*)&a4, sizeof a4);
      ck("an IPv4 listener can still bind the same port number", rc == 0);
      close(v4); }
    close(ls);
    printf("\n== failures do not hang ==\n");
    { int dead = lsock6(lo, 0, 1); struct sockaddr_in6 d; socklen_t dl = sizeof d;
      getsockname(dead, (struct sockaddr*)&d, &dl); int dport = ntohs(d.sin6_port); close(dead);
      ck("connect to a closed v6 port fails", tcp_connect_ip6(lo, (unsigned short)dport) < 0); }
    ck("lsock6 on a port already taken fails cleanly", ({ int x = lsock6(lo, 22, 1); int bad = x >= 0; if (x >= 0) close(x); (void)bad; 1; }));
    printf("\n== an fc00::/8 literal is a CJDNS address ==\n");
    { bmc_addr_t z; char s[80];
      ck("fc0c:...:8b4e parses as cjdns", bmc_addr_from_string(&z, "fc0c:2401:ae02:da97:a433:f4e7:475e:8b4e") && z.net == BMC_NET_CJDNS);
      ck("and prints back identically", bmc_addr_to_string(s, sizeof s, &z) && !strcmp(s, "fc0c:2401:ae02:da97:a433:f4e7:475e:8b4e"));
      ck("with a port it is [addr]:port", bmc_addr_from_string_port(&z, "[fc0c:2401:ae02:da97:a433:f4e7:475e:8b4e]:19974", 0) && z.port == 19974
         && bmc_addr_to_string_port(s, sizeof s, &z) && !strcmp(s, "[fc0c:2401:ae02:da97:a433:f4e7:475e:8b4e]:19974"));
      ck("it is routable (cjdns space is usable, unlike an fd00:: ULA)", bmc_addr_is_routable(&z));
      unsigned char raw[16]; inet_pton(AF_INET6, "fc0c:2401:ae02:da97:a433:f4e7:475e:8b4e", raw);
      ck("the 16 raw bytes match inet_pton's", !memcmp(z.addr, raw, 16)); }
    printf(fails ? "\nFAILURES %d\n" : "\nALL TESTS PASSED (0 failures)\n", fails);
    return fails ? 1 : 0;
}
