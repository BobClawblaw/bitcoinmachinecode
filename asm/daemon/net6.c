/* daemon/net6.c -- see net6.h. */
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "net6.h"
#include "log_ts.h"

int tcp_connect_ip6(const unsigned char addr[16], unsigned short port){
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    /* the same fail-fast read bound tcp_connect_ip applies: a peer that
     * stops replying must not wedge the caller for ever */
    struct timeval tv = { 10, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    struct sockaddr_in6 sa; memset(&sa, 0, sizeof sa);
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(port);
    memcpy(&sa.sin6_addr, addr, 16);
    if (connect(fd, (struct sockaddr*)&sa, sizeof sa) != 0){ close(fd); return -1; }
    return fd;
}
int lsock6(const unsigned char addr[16], int port, int backlog){
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0){ log_fprintf(stderr, "[net6] socket: %s\n", strerror(errno)); return -1; }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    /* v6-only: with dual-stack a wildcard v6 listener also answers IPv4 on
     * the same port, which would collide with the node's own IPv4 listener */
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
    struct sockaddr_in6 sa; memset(&sa, 0, sizeof sa);
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons((unsigned short)port);
    if (addr) memcpy(&sa.sin6_addr, addr, 16); else sa.sin6_addr = in6addr_any;
    if (bind(fd, (struct sockaddr*)&sa, sizeof sa) != 0){
        log_fprintf(stderr, "[net6] bind: %s\n", strerror(errno)); close(fd); return -1; }
    if (listen(fd, backlog) != 0){
        log_fprintf(stderr, "[net6] listen: %s\n", strerror(errno)); close(fd); return -1; }
    return fd;
}
