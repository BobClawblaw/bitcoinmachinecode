/* daemon/socks5.c -- see socks5.h. */
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "socks5.h"

extern int tcp_connect_ip(unsigned ip_netorder, unsigned short port_be);

static int send_all(int fd, const unsigned char* p, long n, int timeout_ms){
    while (n > 0){
        struct pollfd pf = { fd, POLLOUT, 0 };
        if (poll(&pf, 1, timeout_ms) <= 0) return 0;
        long w = write(fd, p, (size_t)n);
        if (w <= 0){ if (errno == EINTR) continue; return 0; }
        p += w; n -= w;
    }
    return 1;
}
static int recv_all(int fd, unsigned char* p, long n, int timeout_ms){
    while (n > 0){
        struct pollfd pf = { fd, POLLIN, 0 };
        if (poll(&pf, 1, timeout_ms) <= 0) return 0;
        long r = read(fd, p, (size_t)n);
        if (r <= 0){ if (r < 0 && errno == EINTR) continue; return 0; }
        p += r; n -= r;
    }
    return 1;
}

int socks5_connect(const char* proxy_ip, int proxy_port,
                   const char* dest_host, int dest_port,
                   const char* user, const char* pass,
                   int timeout_ms, int* rep_out){
    if (rep_out) *rep_out = -1;
    long hl = (long)strlen(dest_host);
    if (hl == 0 || hl > 255) return -2;                    /* Core: strDest.size() > 255 -> fail */
    unsigned ip; if (inet_pton(AF_INET, proxy_ip, &ip) != 1) return -1;
    int fd = tcp_connect_ip(ip, htons((unsigned short)proxy_port));
    if (fd < 0) return -1;
    int with_auth = user && pass && (*user || *pass);
    /* greeting: VER 5, NMETHODS, methods (NOAUTH 0, USER_PASS 2) */
    unsigned char g[4]; long gl = 0;
    g[gl++] = 5;
    if (with_auth){ g[gl++] = 2; g[gl++] = 0; g[gl++] = 2; } else { g[gl++] = 1; g[gl++] = 0; }
    if (!send_all(fd, g, gl, timeout_ms)){ close(fd); return -5; }
    unsigned char r1[2];
    if (!recv_all(fd, r1, 2, timeout_ms)){ close(fd); return -5; }
    if (r1[0] != 5){ close(fd); return -2; }
    if (r1[1] == 2 && with_auth){
        /* RFC 1929: VER 1, ULEN, UNAME, PLEN, PASSWD */
        long ul = (long)strlen(user), pl = (long)strlen(pass);
        if (ul > 255 || pl > 255){ close(fd); return -2; }
        unsigned char a[3 + 255 + 255]; long al = 0;
        a[al++] = 1; a[al++] = (unsigned char)ul; memcpy(a + al, user, (size_t)ul); al += ul;
        a[al++] = (unsigned char)pl; memcpy(a + al, pass, (size_t)pl); al += pl;
        if (!send_all(fd, a, al, timeout_ms)){ close(fd); return -5; }
        unsigned char r2[2];
        if (!recv_all(fd, r2, 2, timeout_ms)){ close(fd); return -5; }
        if (r2[0] != 1 || r2[1] != 0){ close(fd); return -4; }
    } else if (r1[1] != 0){
        close(fd); return -2;                              /* no acceptable method */
    }
    /* request: VER 5, CMD CONNECT 1, RSV 0, ATYP DOMAINNAME 3, LEN, host, port BE */
    unsigned char q[5 + 255 + 2]; long ql = 0;
    q[ql++] = 5; q[ql++] = 1; q[ql++] = 0; q[ql++] = 3; q[ql++] = (unsigned char)hl;
    memcpy(q + ql, dest_host, (size_t)hl); ql += hl;
    q[ql++] = (unsigned char)((dest_port >> 8) & 0xff); q[ql++] = (unsigned char)(dest_port & 0xff);
    if (!send_all(fd, q, ql, timeout_ms)){ close(fd); return -5; }
    /* reply: VER 5, REP, RSV, ATYP, BND.ADDR, BND.PORT */
    unsigned char r3[4];
    if (!recv_all(fd, r3, 4, timeout_ms)){ close(fd); return -5; }
    if (r3[0] != 5){ close(fd); return -2; }
    if (rep_out) *rep_out = r3[1];
    if (r3[1] != 0){ close(fd); return -3; }
    long bl;
    if (r3[3] == 1) bl = 4; else if (r3[3] == 4) bl = 16;
    else if (r3[3] == 3){ unsigned char l; if (!recv_all(fd, &l, 1, timeout_ms)){ close(fd); return -5; } bl = l; }
    else { close(fd); return -2; }
    unsigned char bnd[256 + 2];
    if (!recv_all(fd, bnd, bl + 2, timeout_ms)){ close(fd); return -5; }
    return fd;
}
